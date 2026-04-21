use crate::foundation::group::Group;
use crate::foundation::hash::ContextHash;
use crate::primitives::zkp::context::ProofTreeContextHash;
use crate::primitives::zkp::proof::{Claim, PreparedProof, Proof, ProofTranscript};
use crate::primitives::zkp::proof_builder::ProofBuilder;
use crate::primitives::zkp::representation::SecretKnowledge;
use rand_core::{CryptoRng, RngCore};

pub mod proof;
pub mod proof_builder;
pub mod representation;
pub mod statement;

#[cfg(test)]
mod _test_utils;
mod context;

pub struct ZKProof<G: Group> {
    claim: Claim<G>,
}

impl<G: Group> ZKProof<G> {
    pub fn from_builder(proof_builder: &dyn ProofBuilder<G>) -> (Self, SecretKnowledge<G>) {
        let (claim, knowledge) = proof_builder.build();
        (Self { claim }, SecretKnowledge(knowledge))
    }

    pub fn prepare<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        knowledge: &SecretKnowledge<G>,
    ) -> PreparedProof<G> {
        Proof::prepare(rng, &self.claim, &knowledge.0)
    }

    pub fn finalize<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prepared_proof: &PreparedProof<G>,
        knowledge: &SecretKnowledge<G>,
        c: &G::Scalar,
    ) -> ProofTranscript<G> {
        Proof::finalize(rng, prepared_proof, &self.claim, &knowledge.0, c)
    }

    pub fn check(&self, proof: &ProofTranscript<G>, c: &G::Scalar) -> bool {
        Proof::check(&self.claim, proof, c)
    }
}

pub struct NIZKProof<G: Group, H: ProofTreeContextHash<G> + ContextHash<G> + Clone> {
    zk_proof: ZKProof<G>,
    claim_context_hash: H,
}

impl<G: Group, H: ProofTreeContextHash<G> + ContextHash<G> + Clone> NIZKProof<G, H> {
    pub fn new(zk_proof: ZKProof<G>, context_hash: H) -> Self {
        let mut claim_context_hash = context_hash;
        claim_context_hash.add_claim(&zk_proof.claim);

        Self {
            zk_proof,
            claim_context_hash,
        }
    }

    pub fn proof<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        knowledge: &SecretKnowledge<G>,
    ) -> ProofTranscript<G> {
        let prepared_proof = self.zk_proof.prepare(rng, knowledge);

        let mut context_hash = self.claim_context_hash.clone();
        context_hash.add_prepared_proof(&prepared_proof);
        let c = context_hash.hash_to_scalar();

        self.zk_proof.finalize(rng, &prepared_proof, knowledge, &c)
    }

    pub fn verify(&self, proof: &ProofTranscript<G>) -> bool {
        let mut context_hash = self.claim_context_hash.clone();
        context_hash.add_proof(proof);
        let c = context_hash.hash_to_scalar();

        self.zk_proof.check(proof, &c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::foundation::hash::VectorContextHash;
    use crate::primitives::zkp::_test_utils::create_elgamal_enc0_and_enc1;
    use crate::primitives::zkp::proof_builder::TreeProofBuilder;
    use crate::primitives::zkp::proof_builder::el_gamal::{EncProofBuilder, ReEncProofBuilder};
    use crate::utils::tree::BooleanTree::{Leaf, Or};
    use rand::thread_rng;

    type Curve = RistrettoGroup;

    #[test]
    fn nizk_proof() {
        let mut rng = thread_rng();

        let (pk, (uv, _), (uv_enc1, r_enc1)) = create_elgamal_enc0_and_enc1(&mut rng);

        let enc1 = EncProofBuilder::<Curve>::new(pk, uv_enc1, Curve::basepoint(), Some(r_enc1));
        let renenc = ReEncProofBuilder::<Curve>::new(pk, uv, uv_enc1, None);

        let tree: TreeProofBuilder<Curve> = Or(vec![Leaf(&enc1), Leaf(&renenc)]);
        let (zk_proof, knowledge) = ZKProof::from_builder(&tree);

        let nizkp = NIZKProof::new(zk_proof, VectorContextHash::default());
        let proof = nizkp.proof(&mut rng, &knowledge);

        assert!(nizkp.verify(&proof))
    }
}
