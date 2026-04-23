use rand_core::{CryptoRng, RngCore};
use crate::foundation::group::Group;
use crate::foundation::hash::{ContextHash, VectorContextHash};
use crate::primitives::zkp2::{ZKP, SigmaZKP, SimulableZKP};

pub struct ReEncZKP<G> where G: Group {
    public_data: ReEncZKPPublicData<G>,
    context: Vec<u8>,
}

pub type ReEncZKPWitness<G> = <G as Group>::Scalar;
pub type ReEncZKPContext = Vec<u8>;
pub type ReEncZKPCommit<G> = (<G as Group>::Point, <G as Group>::Point);
pub type ReEncZKPResponse<G> = <G as Group>::Scalar;
pub type ReEncZKPChallenge<G> = <G as Group>::Scalar;
pub type ReEncZKPState<G> = (<G as Group>::Scalar, <G as Group>::Scalar);

pub struct ReEncZKPProof<G: Group> {
    commit: ReEncZKPCommit<G>,
    challenge: ReEncZKPChallenge<G>,
    response: ReEncZKPResponse<G>
}

pub struct ReEncZKPPublicData<G> where G: Group {
    public_key : G::Point,
    ciphertext: (G::Point, G::Point),
    ciphertext_rnd: (G::Point, G::Point),
}

impl<G> ReEncZKP<G> where G: Group {
    pub fn new(public_key: G::Point, ciphertext: (G::Point, G::Point), ciphertext_rnd: (G::Point, G::Point), context: Vec<u8>) -> Self {
        Self {
            public_data: ReEncZKPPublicData {
                public_key,
                ciphertext,
                ciphertext_rnd,
            },
            context: context
        }
    }

    fn phi(&self, x: &ReEncZKPWitness<G>) -> ReEncZKPCommit<G> {
        let phi1 = G::basepoint() * &x;
        let phi2 = self.public_data.public_key * &x;
        (phi1, phi2)
    }
    fn commit<R : RngCore + CryptoRng>(&self, witness: &G::Scalar, rng : &mut R)
            -> (ReEncZKPCommit<G>, ReEncZKPState<G>) {
        let k = G::scalar_random(rng);
        let phik = self.phi(&k);
        let state = (k, witness.clone());  // TODO, with lifetime, we can remove clone
        (phik, state)
    }
    fn respond(&self, state: &ReEncZKPState<G>, challenge: &ReEncZKPChallenge<G>) -> ReEncZKPResponse<G> {
        state.0 + &(state.1 * challenge)
    }

    fn get_challenge(&self, public_data: &ReEncZKPPublicData<G>, context: &ReEncZKPContext, commit: &ReEncZKPCommit<G>)
            -> ReEncZKPChallenge<G> {
        let mut buf = VectorContextHash::new(context.clone());
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &public_data.public_key);
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &public_data.ciphertext.0);
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &public_data.ciphertext.1);
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &public_data.ciphertext_rnd.0);
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &public_data.ciphertext_rnd.1);
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &commit.0);
        <VectorContextHash as ContextHash<G>>::add_point(&mut buf, &commit.1);
        <VectorContextHash as ContextHash<G>>::hash_to_scalar(&mut buf)
    }

    fn verify(&self, public_data: &ReEncZKPPublicData<G>, context: &ReEncZKPContext, commit: &ReEncZKPCommit<G>, challenge: &ReEncZKPChallenge<G>, response: &ReEncZKPResponse<G>)
            -> bool {
        let phir = self.phi(&response);
        let z0 = public_data.ciphertext_rnd.0 - &public_data.ciphertext.0;
        let z1 = public_data.ciphertext_rnd.1 - &public_data.ciphertext.1;
        let cz0 = z0 * &challenge;
        let cz1 = z1 * &challenge;
        let p0 = cz0 + &commit.0;
        let p1 = cz1 + &commit.1;
        phir.0 == p0 && phir.1 == p1
    }
}

impl<G> ZKP<G> for ReEncZKP<G> where G: Group{
    type PublicData = ReEncZKPPublicData<G>;
    type Witness = ReEncZKPWitness<G>;
    type Context = ReEncZKPContext;
    type Proof = ReEncZKPProof<G>;
    fn prove<R: RngCore + CryptoRng>(&self, public_data: &Self::PublicData, witness: &Self::Witness, context: &Self::Context, rng: &mut R)
            -> (Self::Proof) {
        let (commit, state) = Self::commit(&self, witness, rng);
        let chal = Self::get_challenge(&self, public_data, context, &commit);
        let response = Self::respond(&self, &state, &chal);
        (
            ReEncZKPProof {
                commit,
                challenge: chal,
                response,
            }
        )
    }

    fn verify(&self, public_data: &Self::PublicData, context: &Self::Context, proof: &Self::Proof) -> bool {
        let chal = Self::get_challenge(&self, public_data, context, &proof.commit);
        proof.challenge == chal &&
        Self::verify(&self, public_data, context, &proof.commit, &proof.challenge, &proof.response)

    }
}
