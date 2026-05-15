use crate::foundation::group::Group;
use crate::foundation::hash::{ContextHash, GroupContextHash, VectorContextHash};
use crate::primitives::zkp2;
use crate::primitives::zkp2::{Challenge, SigmaZKP, SimulableZKP, ZKP};
use rand_core::{CryptoRng, RngCore};

#[derive(Clone)]
pub struct EncZKP<G>
where
    G: Group,
{
    pub public_data: EncZKPPublicData<G>,
    pub context: Vec<u8>,
}

pub type EncZKPWitness<G> = <G as Group>::Scalar;
pub type EncZKPContext = Vec<u8>;
pub type EncZKPCommit<G> = (<G as Group>::Point, <G as Group>::Point);
pub type EncZKPResponse<G> = <G as Group>::Scalar;
pub type EncZKPChallenge<G> = zkp2::Challenge<G>;
pub type EncZKPState<G> = (<G as Group>::Scalar, <G as Group>::Scalar);

#[derive(Copy, Clone)]
pub struct EncZKPProof<G: Group> {
    pub commit: EncZKPCommit<G>,
    pub challenge: EncZKPChallenge<G>,
    pub response: EncZKPResponse<G>,
}

#[derive(Copy, Clone)]
pub struct EncZKPPublicData<G>
where
    G: Group,
{
    public_key: G::Point,
    ciphertext: (G::Point, G::Point),
    message: G::Point,
}

impl<G> EncZKP<G>
where
    G: Group,
{
    pub fn new(public_key: G::Point, ciphertext: (G::Point, G::Point), message: G::Point, context: Vec<u8>) -> Self {
        Self {
            public_data: EncZKPPublicData { public_key, ciphertext, message },
            context,
        }
    }

    fn phi(&self, x: &EncZKPWitness<G>) -> EncZKPCommit<G> {
        let phi1 = G::basepoint() * x;
        let phi2 = self.public_data.public_key * x;
        (phi1, phi2)
    }
    fn commit<R: RngCore + CryptoRng>(&self, witness: &G::Scalar, rng: &mut R) -> (EncZKPCommit<G>, EncZKPState<G>) {
        let k = G::scalar_random(rng);
        let phik = self.phi(&k);
        let state = (k, *witness); // TODO, with lifetime, we can remove clone
        (phik, state)
    }
    fn respond(&self, state: &EncZKPState<G>, challenge: &EncZKPChallenge<G>) -> EncZKPResponse<G> {
        state.0 + &(state.1 * challenge)
    }

    fn get_challenge(&self, commit: &EncZKPCommit<G>) -> EncZKPChallenge<G> {
        let mut buf = VectorContextHash::new(self.context.clone());
        <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &self.public_data.public_key);
        <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &self.public_data.ciphertext.0);
        <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &self.public_data.ciphertext.1);
        <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &self.public_data.message);
        <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &commit.0);
        <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &commit.1);
        G::hash_to_scalar(<VectorContextHash as ContextHash<G>>::get_context(&buf).as_slice())
    }

    fn verify(&self, commit: &EncZKPCommit<G>, challenge: &EncZKPChallenge<G>, response: &EncZKPResponse<G>) -> bool {
        let phir = self.phi(response);
        let z0 = self.public_data.ciphertext.0;
        let z1 = self.public_data.ciphertext.1 - &self.public_data.message;
        let cz0 = z0 * challenge;
        let cz1 = z1 * challenge;
        let p0 = cz0 + &commit.0;
        let p1 = cz1 + &commit.1;
        phir.0 == p0 && phir.1 == p1
    }

    fn simulate<R: RngCore + CryptoRng>(&self, rng: &mut R) -> EncZKPProof<G> {
        let challenge = G::scalar_random(rng);
        let response = G::scalar_random(rng);
        let z0 = self.public_data.ciphertext.0;
        let z1 = self.public_data.ciphertext.1 - &self.public_data.message;
        let phir = self.phi(&response);
        let com0 = phir.0 - &(z0 * &challenge);
        let com1 = phir.1 - &(z1 * &challenge);
        let commit = (com0, com1);

        EncZKPProof { commit, challenge, response }
    }
}

impl<G> ZKP<G> for EncZKP<G>
where
    G: Group,
{
    type PublicData = EncZKPPublicData<G>;
    type Witness = EncZKPWitness<G>;
    type Context = EncZKPContext;
    type Proof = EncZKPProof<G>;
    fn prove<R: RngCore + CryptoRng>(&self, witness: &Self::Witness, rng: &mut R) -> Self::Proof {
        let (commit, state) = Self::commit(self, witness, rng);
        let chal = Self::get_challenge(self, &commit);
        let response = Self::respond(self, &state, &chal);
        EncZKPProof { commit, challenge: chal, response }
    }

    fn verify(&self, proof: &Self::Proof) -> bool {
        let chal = Self::get_challenge(self, &proof.commit);
        proof.challenge == chal && Self::verify(self, &proof.commit, &proof.challenge, &proof.response)
    }
}

impl<G> SigmaZKP<G> for EncZKP<G>
where
    G: Group,
{
    type Commit = EncZKPCommit<G>;
    //    type Challenge = EncZKPChallenge<G>;
    type Response = EncZKPResponse<G>;
    type State = EncZKPState<G>;
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

impl<G> SimulableZKP<G> for EncZKP<G>
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
    use crate::primitives::zkp2::enc::EncZKP;
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

        // From here, we know pk, m, r, enc_m

        // A ZKP that I encrypted m
        let ctx = b"enc_m".to_vec();
        let zkp: EncZKP<Curve> = EncZKP::new(pk, enc_m, m, ctx);

        let proof1 = zkp.prove(&r, &mut rng);
        assert!(<EncZKP<Curve> as ZKP<Curve>>::verify(&zkp, &proof1));
    }
}
