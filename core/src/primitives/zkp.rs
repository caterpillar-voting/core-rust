use crate::foundation::group::Group;
use crate::foundation::hash::ContextHash;
use crate::primitives::zkp::context::ProofTreeContextHash;
use crate::primitives::zkp::proof::{Claim, Knowledge, PreparedProof, Proof, ProofTree};
use rand_core::{CryptoRng, RngCore};

pub mod proof;
pub mod proof_builder;
pub mod representation;
pub mod statement;

#[cfg(test)]
mod _test_utils;
mod context;

pub struct ZeroKnowledgeProof<G: Group> {
    claim: Claim<G>,
}

impl<G: Group> ZeroKnowledgeProof<G> {
    pub fn prepare<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        knowledge: &Knowledge<G>,
    ) -> PreparedProof<G> {
        ProofTree::prepare(rng, &self.claim, knowledge)
    }

    pub fn finalize<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prepared_proof: &PreparedProof<G>,
        knowledge: &Knowledge<G>,
        c: &G::Scalar,
    ) -> Proof<G> {
        ProofTree::finalize(rng, prepared_proof, &self.claim, knowledge, c)
    }

    pub fn check(&self, proof: &Proof<G>, c: &G::Scalar) -> bool {
        ProofTree::check(&self.claim, proof, c)
    }
}

pub struct NonInteractiveZeroKnowledgeProof<
    G: Group,
    H: ProofTreeContextHash<G> + ContextHash<G> + Clone,
> {
    zero_knowledge_proof: ZeroKnowledgeProof<G>,
    claim_context_hash: H,
}

impl<G: Group, H: ProofTreeContextHash<G> + ContextHash<G> + Clone>
    NonInteractiveZeroKnowledgeProof<G, H>
{
    pub fn new(zero_knowledge_proof: ZeroKnowledgeProof<G>, context_hash: H) -> Self {
        let mut claim_context_hash = context_hash;
        claim_context_hash.add_claim(&zero_knowledge_proof.claim);

        Self {
            zero_knowledge_proof,
            claim_context_hash,
        }
    }

    pub fn proof<R: RngCore + CryptoRng>(&self, rng: &mut R, knowledge: &Knowledge<G>) -> Proof<G> {
        let prepared_proof = self.zero_knowledge_proof.prepare(rng, knowledge);

        let mut context_hash = self.claim_context_hash.clone();
        context_hash.add_prepared_proof(&prepared_proof);
        let c = context_hash.hash_to_scalar();

        ProofTree::finalize(
            rng,
            &prepared_proof,
            &self.zero_knowledge_proof.claim,
            knowledge,
            &c,
        )
    }

    pub fn verify(&self, claim: &Claim<G>, proof: &Proof<G>) -> bool {
        let mut context_hash = self.claim_context_hash.clone();
        context_hash.add_proof(proof);
        let c = context_hash.hash_to_scalar();

        ProofTree::check(claim, proof, &c)
    }
}
