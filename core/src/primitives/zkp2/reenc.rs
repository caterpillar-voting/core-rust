use crate::foundation::group::Group;
use crate::foundation::hash::{ContextHash, VectorContextHash};
use crate::primitives::zkp2;
use crate::primitives::zkp2::{Challenge, SigmaZKP, SimulableZKP, ZKP};
use rand_core::{CryptoRng, RngCore};

#[derive(Clone)]
pub struct ReEncZKP<G>
where
    G: Group,
{
    pub public_data: ReEncZKPPublicData<G>,
    pub context: Vec<u8>,
}

pub type ReEncZKPWitness<G> = <G as Group>::Scalar;
pub type ReEncZKPContext = Vec<u8>;
pub type ReEncZKPCommit<G> = (<G as Group>::Point, <G as Group>::Point);
pub type ReEncZKPResponse<G> = <G as Group>::Scalar;
pub type ReEncZKPChallenge<G> = zkp2::Challenge<G>;
pub type ReEncZKPState<G> = (<G as Group>::Scalar, <G as Group>::Scalar);

#[derive(Copy, Clone)]
pub struct ReEncZKPProof<G: Group> {
    pub commit: ReEncZKPCommit<G>,
    pub challenge: ReEncZKPChallenge<G>,
    pub response: ReEncZKPResponse<G>,
}

#[derive(Copy, Clone)]
pub struct ReEncZKPPublicData<G>
where
    G: Group,
{
    public_key: G::Point,
    ciphertext: (G::Point, G::Point),
    ciphertext_rnd: (G::Point, G::Point),
}

impl<G> ReEncZKP<G>
where
    G: Group,
{
    pub fn new(public_key: G::Point, ciphertext: (G::Point, G::Point), ciphertext_rnd: (G::Point, G::Point), context: Vec<u8>) -> Self {
        Self {
            public_data: ReEncZKPPublicData {
                public_key,
                ciphertext,
                ciphertext_rnd,
            },
            context,
        }
    }

    fn phi(&self, x: &ReEncZKPWitness<G>) -> ReEncZKPCommit<G> {
        let phi1 = G::basepoint() * x;
        let phi2 = self.public_data.public_key * x;
        (phi1, phi2)
    }
    fn commit<R: RngCore + CryptoRng>(&self, witness: &G::Scalar, rng: &mut R) -> (ReEncZKPCommit<G>, ReEncZKPState<G>) {
        let k = G::scalar_random(rng);
        let phik = self.phi(&k);
        let state = (k, *witness); // TODO, with lifetime, we can remove clone
        (phik, state)
    }
    fn respond(&self, state: &ReEncZKPState<G>, challenge: &ReEncZKPChallenge<G>) -> ReEncZKPResponse<G> {
        state.0 + &(state.1 * challenge)
    }

    fn get_challenge(&self, commit: &ReEncZKPCommit<G>) -> ReEncZKPChallenge<G> {
        let mut buf = VectorContextHash::new(self.context.clone());
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &self.public_data.public_key);
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &self.public_data.ciphertext.0);
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &self.public_data.ciphertext.1);
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &self.public_data.ciphertext_rnd.0);
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &self.public_data.ciphertext_rnd.1);
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &commit.0);
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &commit.1);
        <VectorContextHash as ContextHash<G>>::hash_to_scalar(&buf)
    }

    fn verify(&self, commit: &ReEncZKPCommit<G>, challenge: &ReEncZKPChallenge<G>, response: &ReEncZKPResponse<G>) -> bool {
        let phir = self.phi(response);
        let z0 = self.public_data.ciphertext_rnd.0 - &self.public_data.ciphertext.0;
        let z1 = self.public_data.ciphertext_rnd.1 - &self.public_data.ciphertext.1;
        let cz0 = z0 * challenge;
        let cz1 = z1 * challenge;
        let p0 = cz0 + &commit.0;
        let p1 = cz1 + &commit.1;
        phir.0 == p0 && phir.1 == p1
    }

    fn simulate<R: RngCore + CryptoRng>(&self, rng: &mut R) -> ReEncZKPProof<G> {
        let challenge = G::scalar_random(rng);
        let response = G::scalar_random(rng);
        let z0 = self.public_data.ciphertext_rnd.0 - &self.public_data.ciphertext.0;
        let z1 = self.public_data.ciphertext_rnd.1 - &self.public_data.ciphertext.1;
        let phir = self.phi(&response);
        let com0 = phir.0 - &(z0 * &challenge);
        let com1 = phir.1 - &(z1 * &challenge);
        let commit = (com0, com1);

        ReEncZKPProof { commit, challenge, response }
    }
}

impl<G> ZKP<G> for ReEncZKP<G>
where
    G: Group,
{
    type PublicData = ReEncZKPPublicData<G>;
    type Witness = ReEncZKPWitness<G>;
    type Context = ReEncZKPContext;
    type Proof = ReEncZKPProof<G>;
    fn prove<R: RngCore + CryptoRng>(&self, witness: &Self::Witness, rng: &mut R) -> Self::Proof {
        let (commit, state) = Self::commit(self, witness, rng);
        let chal = Self::get_challenge(self, &commit);
        let response = Self::respond(self, &state, &chal);
        ReEncZKPProof { commit, challenge: chal, response }
    }

    fn verify(&self, proof: &Self::Proof) -> bool {
        let chal = Self::get_challenge(self, &proof.commit);
        proof.challenge == chal && Self::verify(self, &proof.commit, &proof.challenge, &proof.response)
    }
}

impl<G> SigmaZKP<G> for ReEncZKP<G>
where
    G: Group,
{
    type Commit = ReEncZKPCommit<G>;
    //    type Challenge = ReEncZKPChallenge<G>;
    type Response = ReEncZKPResponse<G>;
    type State = ReEncZKPState<G>;
    fn commit<R: RngCore + CryptoRng>(&self, witness: &Self::Witness, rng: &mut R) -> (Self::Commit, Self::State) {
        Self::commit(self, witness, rng)
    }
    fn get_challenge(&self, commit: &Self::Commit) -> zkp2::Challenge<G> {
        Self::get_challenge(self, commit)
    }
    fn respond(&self, state: &Self::State, challenge: &zkp2::Challenge<G>) -> Self::Response {
        Self::respond(self, state, challenge)
    }

    fn interactive_verify(&self, commit: &Self::Commit, challenge: &Challenge<G>, response: &Self::Response) -> bool {
        Self::verify(self, commit, challenge, response)
    }
}

impl<G> SimulableZKP<G> for ReEncZKP<G>
where
    G: Group,
{
    fn simulate<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Self::Proof {
        Self::simulate(self, rng)
    }
}

#[cfg(test)]
mod tests {
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::encryption::el_gamal::ElGamal;
    use crate::primitives::zkp2::ZKP;
    use crate::primitives::zkp2::reenc::ReEncZKP;
    use rand::thread_rng;

    type Curve = RistrettoGroup;

    #[test]
    fn prove_and_verify() {
        let mut rng = thread_rng();

        // Generate public key
        let el_gamal = ElGamal::<Curve>::default();
        let sk = el_gamal.generate_secret_key(&mut rng);
        let pk = el_gamal.derive_public_key(&sk);

        // Generate encrypted message
        let m = Curve::point_random(&mut rng);
        let r = Curve::scalar_random(&mut rng);
        let enc_m = el_gamal.encrypt(&pk, &r, &m);

        // From here, we know only pk, enc_m

        // Generate re_encryption
        let s = Curve::scalar_random(&mut rng);
        let reenc_m = el_gamal.reencrypt(&pk, &s, &enc_m);

        // A ZKP that I re-encrypted
        let ctx = b"renc".to_vec();
        let zkp: ReEncZKP<Curve> = ReEncZKP::new(pk, enc_m, reenc_m, ctx);

        let proof1 = zkp.prove(&s, &mut rng);
        assert!(<ReEncZKP<Curve> as ZKP<Curve>>::verify(&zkp, &proof1));
    }
}
