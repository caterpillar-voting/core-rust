use crate::foundation::group::Group;
use crate::foundation::hash::{ContextHash, VectorContextHash};
use crate::primitives::zkp2;
use crate::primitives::zkp2::{Challenge, SigmaZKP, SimulableZKP, ZKP};
use rand_core::{CryptoRng, RngCore};

#[derive(Clone)]
pub struct HTDH2ZKP<G>
where
    G: Group,
{
    pub public_data: HTDH2ZKPPublicData<G>,
    pub context: Vec<u8>,
}

pub type HTDH2ZKPWitness<G> = <G as Group>::Scalar;
pub type HTDH2ZKPContext = Vec<u8>;
pub type HTDH2ZKPCommit<G> = (<G as Group>::Point, <G as Group>::Point);
pub type HTDH2ZKPResponse<G> = <G as Group>::Scalar;
pub type HTDH2ZKPChallenge<G> = zkp2::Challenge<G>;
pub type HTDH2ZKPState<G> = (<G as Group>::Scalar, <G as Group>::Scalar);

#[derive(Copy, Clone)]
pub struct HTDH2ZKPProof<G: Group> {
    pub commit: HTDH2ZKPCommit<G>,
    pub challenge: HTDH2ZKPChallenge<G>,
    pub response: HTDH2ZKPResponse<G>,
}

#[derive(Copy, Clone)]
pub struct HTDH2ZKPPublicData<G>
where
    G: Group,
{
    g_0: G::Point,
    ciphertext: (G::Point, G::Point),
    g_0_r: G::Point,
}

impl<G> HTDH2ZKP<G>
where
    G: Group,
{
    pub fn new(g_0: G::Point, ciphertext: (G::Point, G::Point), g_0_r: G::Point, context: Vec<u8>) -> Self {
        Self {
            public_data: HTDH2ZKPPublicData { g_0, ciphertext, g_0_r },
            context,
        }
    }

    fn phi(&self, x: &HTDH2ZKPWitness<G>) -> HTDH2ZKPCommit<G> {
        let phi1 = G::basepoint() * x;
        let phi2 = self.public_data.g_0 * x;
        (phi1, phi2)
    }
    fn commit<R: RngCore + CryptoRng>(&self, witness: &G::Scalar, rng: &mut R) -> (HTDH2ZKPCommit<G>, HTDH2ZKPState<G>) {
        let s = G::scalar_random(rng);
        let phik = self.phi(&s);
        let state = (s, *witness); // TODO, with lifetime, we can remove clone
        (phik, state)
    }
    fn respond(&self, state: &HTDH2ZKPState<G>, challenge: &HTDH2ZKPChallenge<G>) -> HTDH2ZKPResponse<G> {
        state.0 + &(state.1 * challenge)
    }

    fn get_challenge(&self, commit: &HTDH2ZKPCommit<G>) -> HTDH2ZKPChallenge<G> {
        let mut buf = VectorContextHash::new(self.context.clone());
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &self.public_data.ciphertext.0); // u
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &self.public_data.ciphertext.1); // e
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &commit.0); // w
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &self.public_data.g_0_r); // u_0
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &commit.1); // w_0
        buf.add(&self.context); // L
        <VectorContextHash as ContextHash<G>>::hash_to_scalar(&buf)
    }

    fn verify(&self, commit: &HTDH2ZKPCommit<G>, challenge: &HTDH2ZKPChallenge<G>, response: &HTDH2ZKPResponse<G>) -> bool {
        let phir = self.phi(response); // g^f, g_0^f
        let z0 = self.public_data.ciphertext.0; // u
        let z1 = self.public_data.g_0_r; // u_0
        let cz0 = z0 * challenge;
        let cz1 = z1 * challenge;
        let p0 = cz0 + &commit.0;
        let p1 = cz1 + &commit.1;
        phir.0 == p0 && phir.1 == p1
    }

    fn simulate<R: RngCore + CryptoRng>(&self, rng: &mut R) -> HTDH2ZKPProof<G> {
        let challenge = G::scalar_random(rng);
        let response = G::scalar_random(rng);
        let z0 = self.public_data.ciphertext.0; // u
        let z1 = self.public_data.g_0_r; // u_0
        let phir = self.phi(&response);
        let com0 = phir.0 - &(z0 * &challenge);
        let com1 = phir.1 - &(z1 * &challenge);
        let commit = (com0, com1);

        HTDH2ZKPProof { commit, challenge, response }
    }
}

impl<G> ZKP<G> for HTDH2ZKP<G>
where
    G: Group,
{
    type PublicData = HTDH2ZKPPublicData<G>;
    type Witness = HTDH2ZKPWitness<G>;
    type Context = HTDH2ZKPContext;
    type Proof = HTDH2ZKPProof<G>;
    fn prove<R: RngCore + CryptoRng>(&self, witness: &Self::Witness, rng: &mut R) -> Self::Proof {
        let (commit, state) = Self::commit(self, witness, rng);
        let chal = Self::get_challenge(self, &commit);
        let response = Self::respond(self, &state, &chal);
        HTDH2ZKPProof { commit, challenge: chal, response }
    }

    fn verify(&self, proof: &Self::Proof) -> bool {
        let chal = Self::get_challenge(self, &proof.commit);
        proof.challenge == chal && Self::verify(self, &proof.commit, &proof.challenge, &proof.response)
    }
}

impl<G> SigmaZKP<G> for HTDH2ZKP<G>
where
    G: Group,
{
    type Commit = HTDH2ZKPCommit<G>;
    //    type Challenge = HTDH2ZKPChallenge<G>;
    type Response = HTDH2ZKPResponse<G>;
    type State = HTDH2ZKPState<G>;
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

impl<G> SimulableZKP<G> for HTDH2ZKP<G>
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
    use rand::thread_rng;
    use crate::primitives::zkp2::htdh2::HTDH2ZKP;

    type Curve = RistrettoGroup;

    #[test]
    fn prove_and_verify() {
        let mut rng = thread_rng();
        let g_0 = Curve::independent_generators::<1>(b"HTDH2ZKP")[0];


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
        let ctx = b"apply_htdh2".to_vec();
        let g_0_r = g_0 * r;
        let zkp: HTDH2ZKP<Curve> = HTDH2ZKP::new(g_0, enc_m, g_0_r, ctx);

        let proof1 = zkp.prove(&r, &mut rng);
        assert!(<HTDH2ZKP<Curve> as ZKP<Curve>>::verify(&zkp, &proof1));
    }
}
