pub mod zkp_from_phi;
pub mod combinable_zkp;

use rand_core::{CryptoRng, RngCore};
use crate::foundation::group::Group;

type CipherText<G: Group> = (G::Point, G::Point);

// Types of items that can be involved in the statement of a ZKP (public value or witness)
#[derive(Clone)]
pub enum ZKP_Items<G: Group + Clone> {
    Point(G::Point),
    Scalar(G::Scalar),
    CipherText(CipherText<G>),
}
// A Maurer-Phi function is a function that takes:
//  - a set of public values (the public data)
//  - a set of witness
// and returns
//  - a set of public values (the public output, that can be computed from the public data)
type Maurer_Phi<G: Group + Clone> = fn(&Vec<ZKP_Items<G>>, &Vec<ZKP_Items<G>>) -> Vec<ZKP_Items<G>>;
// For convenience, we need also the following:
type Maurer_Phi_ZeroG1<G: Group + Clone> = fn() -> Vec<ZKP_Items<G>>; // returns a 0-vec of the same type as the witness
type Maurer_Phi_Expected_Output<G: Group + Clone> = fn(&Vec<ZKP_Items<G>>) -> Vec<ZKP_Items<G>>; // computes the expected output from the public data.

pub trait InteractiveGenericZKP<G: Group + Clone> {
    fn commit<R: RngCore + CryptoRng>(&self, witness: &Vec<ZKP_Items<G>>, public_data: &Vec<ZKP_Items<G>>, rng: &mut R) -> (Vec<ZKP_Items<G>>, Vec<ZKP_Items<G>>);
    fn get_challenge(&self, public_data: &Vec<ZKP_Items<G>>, commit: &Vec<ZKP_Items<G>>) -> G::Scalar;
    fn respond(&self, witness: &Vec<ZKP_Items<G>>, challenge: G::Scalar, state: &Vec<ZKP_Items<G>>) -> Vec<ZKP_Items<G>>;
    fn interactive_verify(&self, commit: &Vec<ZKP_Items<G>>, challenge: G::Scalar, response: &Vec<ZKP_Items<G>>, public_data: &Vec<ZKP_Items<G>>) -> bool;
    fn simulate<R: RngCore + CryptoRng>(&self, public_data: &Vec<ZKP_Items<G>>, challenge: Option<G::Scalar>, rng: &mut R) -> (Vec<ZKP_Items<G>>, G::Scalar, Vec<ZKP_Items<G>>);
}