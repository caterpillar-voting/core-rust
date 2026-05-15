pub mod el_gamal;

#[cfg(test)]
mod tests {
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::zkp::_test_utils::{create_elgamal_enc0_and_enc1, proof_claims};
    use crate::primitives::zkp::proof::{Claim, Knowledge};
    use crate::primitives::zkp::proof_builder::el_gamal::{EncProofBuilder, HTDH2ProofBuilder, ReEncProofBuilder};
    use crate::utils::tree::BooleanTree::{And, Or};
    use rand::thread_rng;

    type Curve = RistrettoGroup;

    #[test]
    fn proof_builder_tree() {
        let mut rng = thread_rng();

        let (pk, (uv, r), (uv1, r1)) = create_elgamal_enc0_and_enc1(&mut rng);

        let claim_uv1 = EncProofBuilder::build_claim::<Curve>(pk, uv1, Curve::basepoint());
        let knowledge_r1 = EncProofBuilder::build_knowledge::<Curve>(Some(r1));

        let claim_reenc = ReEncProofBuilder::build_claim::<Curve>(pk, uv, uv1);
        let knowledge_reenc = ReEncProofBuilder::build_knowledge::<Curve>(None);

        let g_0 = Curve::independent_generators::<1>(b"HTDH2ZKP")[0];
        let g_0_r = g_0 * r;
        let claim_htdh2 = HTDH2ProofBuilder::build_claim::<Curve>(g_0, uv, g_0_r);
        let knowledge_htdh2 = HTDH2ProofBuilder::build_knowledge::<Curve>(Some(r));

        let claim: Claim<Curve> = And(vec![Or(vec![claim_uv1, claim_reenc]), claim_htdh2]);
        let knowledge: Knowledge<Curve> = And(vec![Or(vec![knowledge_r1, knowledge_reenc]), knowledge_htdh2]);

        proof_claims(&mut rng, claim, knowledge);
    }
}
