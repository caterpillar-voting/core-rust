// Implementation of the FROST DKG. See Eprint 2020/852.

use crate::foundation::group::Group;
use std::marker::PhantomData;

pub struct DKG<G: Group> {
    _marker: PhantomData<G>,
    l: usize,     // width of the multi-ElGamal
    n: usize,     // number of participants
    t: usize,     // threshold (at least t participants are required to decrypt)
    ctx: Vec<u8>, // context
}

impl<G: Group> DKG<G> {
    pub fn new(l: usize, n: usize, t: usize, ctx: Vec<u8>) -> Self {
        Self {
            _marker: Default::default(),
            l,
            n,
            t,
            ctx,
        }
    }
}
