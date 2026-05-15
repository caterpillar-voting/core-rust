use crate::foundation::group::Group;
use crate::primitives::zkp::proof::{Claim, Knowledge};
use crate::primitives::zkp::statement::Statement;
use crate::utils::tree::BooleanTree::Leaf;

pub struct ReEncProofBuilder {}

impl ReEncProofBuilder {
    pub fn build_claim<G: Group>(pk: G::Point, uv: (G::Point, G::Point), uv_dash: (G::Point, G::Point)) -> Claim<G> {
        let rerand_u = Statement::<G>::new(G::basepoint(), uv_dash.0 - &uv.0);
        let rerand_v = Statement::<G>::new(pk, uv_dash.1 - &uv.1);

        let claim: Claim<G> = Leaf(Box::new([rerand_u, rerand_v]));

        claim
    }

    pub fn build_knowledge<G: Group>(r: Option<G::Scalar>) -> Knowledge<G> {
        Leaf(r)
    }
}

pub struct EncProofBuilder {}

impl EncProofBuilder {
    pub fn build_claim<G: Group>(pk: G::Point, uv: (G::Point, G::Point), message: G::Point) -> Claim<G> {
        let encm_u = Statement::<G>::new(G::basepoint(), uv.0);
        let encm_v = Statement::<G>::new(pk, uv.1 - &message);

        let claim: Claim<G> = Leaf(Box::new([encm_u, encm_v]));

        claim
    }

    pub fn build_knowledge<G: Group>(r: Option<G::Scalar>) -> Knowledge<G> {
        Leaf(r)
    }
}

pub struct HTDH2ProofBuilder {}

impl HTDH2ProofBuilder {
    pub fn build_claim<G: Group>(g0: G::Point, uv: (G::Point, G::Point), g0_r: G::Point) -> Claim<G> {
        let w0 = Statement::<G>::new(G::basepoint(), uv.0);
        let w1 = Statement::<G>::new(g0, g0_r);

        let claim: Claim<G> = Leaf(Box::new([w0, w1]));

        claim
    }

    pub fn build_knowledge<G: Group>(r: Option<G::Scalar>) -> Knowledge<G> {
        Leaf(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::zkp::_test_utils::{create_elgamal_enc0_and_enc1, create_elgamal_enc0_and_reenc, proof_claims};
    use rand::thread_rng;

    type Curve = RistrettoGroup;

    #[test]
    fn reenc_proof() {
        let mut rng = thread_rng();

        let (pk, (uv, _), (uv_dash, r_reenc)) = create_elgamal_enc0_and_reenc(&mut rng);

        let claim = ReEncProofBuilder::build_claim::<Curve>(pk, uv, uv_dash);
        let knowledge = ReEncProofBuilder::build_knowledge::<Curve>(Some(r_reenc));
        proof_claims(&mut rng, claim, knowledge);
    }

    #[test]
    fn enc_proof() {
        let mut rng = thread_rng();

        let (pk, (uv, r), (uv1, r1)) = create_elgamal_enc0_and_enc1(&mut rng);

        let claim = EncProofBuilder::build_claim::<Curve>(pk, uv, Curve::identity());
        let knowledge = EncProofBuilder::build_knowledge::<Curve>(Some(r));
        proof_claims(&mut rng, claim, knowledge);

        let claim = EncProofBuilder::build_claim::<Curve>(pk, uv1, Curve::basepoint());
        let knowledge = EncProofBuilder::build_knowledge::<Curve>(Some(r1));
        proof_claims(&mut rng, claim, knowledge);
    }

    #[test]
    fn htdh2_proof() {
        let mut rng = thread_rng();

        let (_, (uv, r), _) = create_elgamal_enc0_and_enc1(&mut rng);

        let g_0 = Curve::independent_generators::<1>(b"HTDH2ZKP")[0];
        let g_0_r = g_0 * r;
        let claim = HTDH2ProofBuilder::build_claim::<Curve>(g_0, uv, g_0_r);
        let knowledge = HTDH2ProofBuilder::build_knowledge::<Curve>(Some(r));
        proof_claims(&mut rng, claim, knowledge);
    }
}
