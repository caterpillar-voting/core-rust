use crate::foundation::group::Group;
use crate::foundation::hash::ContextHash;
use crate::primitives::zkp::context::ProofTreeContextHash;
use crate::primitives::zkp::proof::{Claim, Knowledge, PreparedProof, Proof, ProofTree};
use crate::primitives::zkp::proof_builder::ProofTreeBuilder;
use crate::utils::tree::BooleanTree::{And, Or};
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

        self.zero_knowledge_proof.finalize(rng, &prepared_proof, knowledge, &c)
    }

    pub fn verify(&self, proof: &Proof<G>) -> bool {
        let mut context_hash = self.claim_context_hash.clone();
        context_hash.add_proof(proof);
        let c = context_hash.hash_to_scalar();

        self.zero_knowledge_proof.check(proof, &c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::zkp::_test_utils::{create_enc0_and_enc1, do_proof};
    use crate::primitives::zkp::proof_builder::ProofBuilder;
    use crate::primitives::zkp::proof_builder::el_gamal::{EncProof, ReEncProof};
    use crate::utils::tree::BooleanTree::Leaf;
    use rand::thread_rng;
    use crate::foundation::hash::VectorContextHash;

    type Curve = RistrettoGroup;

    #[test]
    fn non_interactive_zero_knowledge_proof() {
        let mut rng = thread_rng();

        let (pk, (u, v), (u_enc1, v_enc1, r_enc1)) = create_enc0_and_enc1(&mut rng);

        let enc1 = EncProof::<Curve>::new(pk, (u_enc1, v_enc1), Curve::basepoint(), Some(r_enc1));
        let renenc = ReEncProof::<Curve>::new(pk, (u, v), (u_enc1, v_enc1), None);

        let tree = ProofTreeBuilder::new(Or(vec![Leaf(&enc1), Leaf(&renenc)]));
        let (claim, knowledge) = tree.build();

        let zkp = ZeroKnowledgeProof { claim };
        let nizkp = NonInteractiveZeroKnowledgeProof::new(zkp, VectorContextHash::default());
        let proof = nizkp.proof(&mut rng, &knowledge);

        assert!(nizkp.verify(&proof))
    }
}
