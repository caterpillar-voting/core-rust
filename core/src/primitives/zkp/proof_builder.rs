pub mod el_gamal;

use crate::foundation::group::Group;
use crate::primitives::zkp::proof::{Claim, Knowledge};
use crate::utils::tree::BooleanTree::{And, Or};
use std::marker::PhantomData;

pub trait ProofBuilder<G: Group> {
    fn build(self) -> (Claim<G>, Knowledge<G>);
}

pub struct AndProofBuilder<G: Group, P: ProofBuilder<G>>
where
    P: Sized,
{
    proof_builders: Vec<P>,
    _marker: PhantomData<G>,
}

impl<G: Group, P: ProofBuilder<G>> Default for AndProofBuilder<G, P> {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl<G: Group, P: ProofBuilder<G>> AndProofBuilder<G, P> {
    pub fn new(proof_builders: Vec<P>) -> Self {
        Self {
            proof_builders,
            _marker: PhantomData,
        }
    }

    pub fn and(&mut self, proof_builder: P) -> &mut AndProofBuilder<G, P> {
        self.proof_builders.push(proof_builder);

        self
    }

    fn collect_proof_builders(proof_builders: Vec<P>) -> (Vec<Claim<G>>, Vec<Knowledge<G>>) {
        proof_builders.into_iter().fold(
            (Vec::new(), Vec::new()),
            |(mut claims, mut knowledges), pb| {
                let (claim, knowledge) = pb.build();
                claims.push(claim);
                knowledges.push(knowledge);
                (claims, knowledges)
            },
        )
    }
}

impl<G: Group, P: ProofBuilder<G>> ProofBuilder<G> for AndProofBuilder<G, P> {
    fn build(self) -> (Claim<G>, Knowledge<G>) {
        let (claims, knowledges) = Self::collect_proof_builders(self.proof_builders);

        (And(claims), And(knowledges))
    }
}


pub struct OrProofBuilder<G: Group, P: ProofBuilder<G>>
where
    P: Sized,
{
    proof_builders: Vec<P>,
    _marker: PhantomData<G>,
}

impl<G: Group, P: ProofBuilder<G>> Default for OrProofBuilder<G, P> {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl<G: Group, P: ProofBuilder<G>> OrProofBuilder<G, P> {
    pub fn new(proof_builders: Vec<P>) -> Self {
        Self {
            proof_builders,
            _marker: PhantomData,
        }
    }

    pub fn or(&mut self, proof_builder: P) -> &mut OrProofBuilder<G, P> {
        self.proof_builders.push(proof_builder);

        self
    }
}

impl<G: Group, P: ProofBuilder<G>> ProofBuilder<G> for OrProofBuilder<G, P> {
    fn build(self) -> (Claim<G>, Knowledge<G>) {
        let (claims, knowledges) = AndProofBuilder::collect_proof_builders(self.proof_builders);

        (Or(claims), Or(knowledges))
    }
}
