use zeroize::{Zeroize, ZeroizeOnDrop};
use zeroize::__internal::AssertZeroize;

#[derive(Debug,Clone)]
pub struct BroadcastMessage<P> {
    pub payload: P,
    pub sender: usize,
}

#[derive(Debug,Clone)]
pub struct Message<P> {
    pub payload: P,
    pub sender: usize,
    pub receiver: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretState<P: AssertZeroize>(pub P);

pub mod dkg;
