pub mod combinable_zkp;
pub mod zkp_from_phi;

use crate::foundation::group::Group;
use rand_core::{CryptoRng, RngCore};

type CipherText<G: Group> = (G::Point, G::Point);

// Types of items that can be involved in the statement of a ZKP (public value or witness)
#[derive(Clone)]
pub enum ZkpItems<G: Group + Clone> {
    Point(G::Point),
    Scalar(G::Scalar),
    CipherText(CipherText<G>),
}
// A Maurer-Phi function is a function that takes:
//  - a set of public values (the public data)
//  - a set of witness
// and returns
//  - a set of public values (the public output, that can be computed from the public data)
type MaurerPhi<G: Group + Clone> = fn(&Vec<ZkpItems<G>>, &Vec<ZkpItems<G>>) -> Vec<ZkpItems<G>>;
// For convenience, we need also the following:
type MaurerPhiZeroG1<G: Group + Clone> = fn() -> Vec<ZkpItems<G>>; // returns a 0-vec of the same type as the witness
type MaurerPhiExpectedOutput<G: Group + Clone> = fn(&Vec<ZkpItems<G>>) -> Vec<ZkpItems<G>>; // computes the expected output from the public data.

pub trait InteractiveGenericZKP<G: Group + Clone> {
    fn commit<R: RngCore + CryptoRng>(&self, witness: &Vec<ZkpItems<G>>, public_data: &Vec<ZkpItems<G>>, rng: &mut R) -> (Vec<ZkpItems<G>>, Vec<ZkpItems<G>>);
    fn get_challenge(&self, public_data: &Vec<ZkpItems<G>>, commit: &Vec<ZkpItems<G>>) -> G::Scalar;
    fn respond(&self, witness: &Vec<ZkpItems<G>>, challenge: G::Scalar, state: &Vec<ZkpItems<G>>) -> Vec<ZkpItems<G>>;
    fn interactive_verify(&self, commit: &Vec<ZkpItems<G>>, challenge: G::Scalar, response: &Vec<ZkpItems<G>>, public_data: &Vec<ZkpItems<G>>) -> bool;
    fn simulate<R: RngCore + CryptoRng>(&self, public_data: &Vec<ZkpItems<G>>, challenge: Option<G::Scalar>, rng: &mut R) -> (Vec<ZkpItems<G>>, G::Scalar, Vec<ZkpItems<G>>);
}
