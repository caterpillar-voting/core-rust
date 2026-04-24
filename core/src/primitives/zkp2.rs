pub mod reenc;
pub mod or;

use rand_core::{CryptoRng, RngCore};
use crate::foundation::group::Group;

pub trait ZKP<G: Group> {
    type PublicData;
    type Witness;
    type Context;
    type Proof;
    fn prove<R: RngCore + CryptoRng>(&self, witness: &Self::Witness, rng: &mut R) -> (Self::Proof);
    fn verify(&self, proof: &Self::Proof) -> bool;
}

pub trait SigmaZKP<G: Group> : ZKP<G> {
    type Commit;    // The data sent by Prover in first step
    type Challenge; // The data sent by Verifier in second step
    type Response;  // The data sent by Prover in third step
    type State;     // The data kept by Prover between steps
    fn commit<R: RngCore + CryptoRng>(&self, witness: &Self::Witness, rng: &mut R) -> (Self::Commit, Self::State);
    fn get_challenge(&self, commit: &Self::Commit) -> (Self::Challenge);
    fn respond(&self, state: &Self::State, challenge: &Self::Challenge) -> (Self::Response);
}

pub trait SimulableZKP<G: Group> : SigmaZKP<G> {
    fn simulate<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (Self::Proof);
}
