// Implementation of the FROST DKG. See Eprint 2020/852.
// Participants are numbered from 1 to n (WARNING: does not start from 0 !)

use crate::foundation::group::Group;
use rand_core::{CryptoRng, RngCore};
use std::marker::PhantomData;

pub struct DKGPubData<G: Group> {
    _marker: PhantomData<G>,
    l: usize,     // width of the multi-ElGamal
    n: usize,     // number of participants
    t: usize,     // threshold (at least t participants are required to decrypt)
    ctx: Vec<u8>, // context
}

pub struct DKGProtocol<G: Group> {
    pub pub_data: DKGPubData<G>,
}

pub struct DKGStateStep1<G: Group> {
    a_is: Vec<G::Scalar>, // the coefficients of the secret polynomial
}

pub struct DKGMessageStep1<G: Group> {
    phi_is: Vec<G::Point>, // commitments to the secret polynomial
    zkp: Vec<G>,           // zkp that one knows the constant coefficient of the polynomial
}

impl<G: Group> DKGProtocol<G> {
    pub fn new(l: usize, n: usize, t: usize, ctx: Vec<u8>) -> Self {
        Self {
            pub_data: DKGPubData {
                _marker: Default::default(),
                l,
                n,
                t,
                ctx,
            },
        }
    }

    // Each participant/trustee generates its polynomial, commits to it, and add a zkp.
    pub fn step_1<R: RngCore + CryptoRng>(&self, trustee: usize, rng: &mut R) -> (DKGStateStep1<G>, DKGMessageStep1<G>) {
        todo!()
    }
}
