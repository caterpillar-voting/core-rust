use crate::foundation::group::Group;
use crate::foundation::hash::ContextHash;
use crate::primitives::zkp::context::ProofTreeContextHash;
use crate::primitives::zkp::proof::{Claim, GetProofCommit, Proof, ProofResponse, ProofState};
use crate::primitives::zkp::representation::SecretKnowledge;
use rand_core::{CryptoRng, RngCore};

pub mod context;
pub mod proof;
pub mod proof_builder;
pub mod representation;
pub mod statement;

#[cfg(test)]
mod _test_utils;

pub struct ZKProof<G: Group> {
    pub claim: Claim<G>,
}

impl<G: Group> ZKProof<G> {
    pub fn commit<R: RngCore + CryptoRng>(&self, rng: &mut R, knowledge: &SecretKnowledge<G>) -> ProofState<G> {
        Proof::commit(rng, &self.claim, &knowledge.0)
    }

    pub fn response<R: RngCore + CryptoRng>(&self, rng: &mut R, proof_state: &ProofState<G>, knowledge: &SecretKnowledge<G>, c: &G::Scalar) -> ProofResponse<G> {
        Proof::response(rng, proof_state, &self.claim, &knowledge.0, c)
    }

    pub fn verify(&self, proof: &ProofResponse<G>, c: &G::Scalar) -> bool {
        Proof::verify(&self.claim, proof, c)
    }
}

pub struct NIZKProof<G: Group, H: ProofTreeContextHash<G> + ContextHash<G>> {
    pub zk_proof: ZKProof<G>,
    claim_context_hash: H,
}

impl<G: Group, H: ProofTreeContextHash<G> + ContextHash<G> + Clone> NIZKProof<G, H> {
    pub fn new(claim: Claim<G>, context_hash: H) -> Self {
        let mut claim_context_hash = context_hash;
        claim_context_hash.add_claim(&claim);

        Self { zk_proof: ZKProof { claim }, claim_context_hash }
    }

    pub fn prove<R: RngCore + CryptoRng>(&self, rng: &mut R, knowledge: &SecretKnowledge<G>) -> ProofResponse<G> {
        let proof_state = self.zk_proof.commit(rng, knowledge);

        let mut context_hash = self.claim_context_hash.clone();
        let proof_commit = <ProofState<G> as GetProofCommit<G>>::get_proof_commit(&proof_state);
        context_hash.add_proof_commit(&proof_commit);
        let c = G::hash_to_scalar(context_hash.get_context().as_slice());

        self.zk_proof.response(rng, &proof_state, knowledge, &c)
    }

    pub fn verify(&self, proof_response: &ProofResponse<G>) -> bool {
        let mut context_hash = self.claim_context_hash.clone();
        let proof_commit = <ProofResponse<G> as GetProofCommit<G>>::get_proof_commit(proof_response);
        context_hash.add_proof_commit(&proof_commit);
        let c = G::hash_to_scalar(context_hash.get_context().as_slice());

        self.zk_proof.verify(proof_response, &c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::foundation::hash::VectorContextHash;
    use crate::primitives::zkp::_test_utils::create_elgamal_enc0_and_enc1;
    use crate::primitives::zkp::proof_builder::el_gamal::{EncProofBuilder};
    use rand::thread_rng;

    type Curve = RistrettoGroup;

    #[test]
    fn nizk_proof() {
        let mut rng = thread_rng();

        let (pk, (uv, r), _) = create_elgamal_enc0_and_enc1(&mut rng);

        let claim_uv1 = EncProofBuilder::build_claim::<Curve>(pk, uv, Curve::identity());
        let knowledge_r1 = EncProofBuilder::build_knowledge::<Curve>(Some(r));

        let nizkp = NIZKProof::new(claim_uv1, VectorContextHash::default());
        let proof = nizkp.prove(&mut rng, &SecretKnowledge(knowledge_r1));

        assert!(nizkp.verify(&proof))
    }
}
