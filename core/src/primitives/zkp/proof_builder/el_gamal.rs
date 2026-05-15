use crate::foundation::group::Group;
use crate::primitives::zkp::proof::{Claim, Knowledge};
use crate::primitives::zkp::proof_builder::ProofBuilder;
use crate::primitives::zkp::statement::Statement;
use crate::utils::tree::BooleanTree::Leaf;

pub struct ReEncProofBuilder<G: Group> {
    pk: G::Point,
    uv: (G::Point, G::Point),
    uv_dash: (G::Point, G::Point),
    randomness: Option<G::Scalar>,
}

impl<G: Group> ReEncProofBuilder<G> {
    pub fn new(pk: G::Point, uv: (G::Point, G::Point), uv_dash: (G::Point, G::Point), randomness: Option<G::Scalar>) -> Self {
        Self { pk, uv, uv_dash, randomness }
    }
}

impl<G: Group> ProofBuilder<G> for ReEncProofBuilder<G> {
    fn build(&self) -> (Claim<G>, Knowledge<G>) {
        let rerand_u = Statement::<G>::new(G::basepoint(), self.uv_dash.0 - &self.uv.0);
        let rerand_v = Statement::<G>::new(self.pk, self.uv_dash.1 - &self.uv.1);

        let claim: Claim<G> = Leaf(Box::new([rerand_u, rerand_v]));
        let knowledge = Leaf(self.randomness);

        (claim, knowledge)
    }
}

pub struct EncProofBuilder<G: Group> {
    pk: G::Point,
    uv: (G::Point, G::Point),
    message: G::Point,
    randomness: Option<G::Scalar>,
}

impl<G: Group> EncProofBuilder<G> {
    pub fn new(pk: G::Point, uv: (G::Point, G::Point), message: G::Point, randomness: Option<G::Scalar>) -> Self {
        Self { pk, uv, message, randomness }
    }
}

impl<G: Group> ProofBuilder<G> for EncProofBuilder<G> {
    fn build(&self) -> (Claim<G>, Knowledge<G>) {
        let encm_u = Statement::<G>::new(G::basepoint(), self.uv.0);
        let encm_v = Statement::<G>::new(self.pk, self.uv.1 - &self.message);

        let claim: Claim<G> = Leaf(Box::new([encm_u, encm_v]));
        let knowledge = Leaf(self.randomness);

        (claim, knowledge)
    }
}

pub struct HTDH2ProofBuilder<G: Group> {
    g0: G::Point,
    uv: (G::Point, G::Point),
    g0r: G::Point,
    randomness: Option<G::Scalar>,
}

impl<G: Group> HTDH2ProofBuilder<G> {
    pub fn new(g0: G::Point, uv: (G::Point, G::Point), g0r: G::Point, randomness: Option<G::Scalar>) -> Self {
        Self { g0, uv, g0r, randomness }
    }

    pub fn new_with_r(uv: (G::Point, G::Point), randomness: G::Scalar) -> Self {
        let g0 = G::independent_generators::<1>(b"HTDH2ZKP")[0];
        let g0r = g0 * &randomness;

        Self::new(g0, uv, g0r, Some(randomness))
    }
}

impl<G: Group> ProofBuilder<G> for HTDH2ProofBuilder<G> {
    fn build(&self) -> (Claim<G>, Knowledge<G>) {
        let w0 = Statement::<G>::new(G::basepoint(), self.uv.0);
        let w1 = Statement::<G>::new(self.g0, self.g0r);

        let claim: Claim<G> = Leaf(Box::new([w0, w1]));
        let knowledge = Leaf(self.randomness);

        (claim, knowledge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::foundation::hash::VectorContextHash;
    use crate::primitives::zkp::_test_utils::create_elgamal_enc0_and_enc1;
    use rand::thread_rng;

    type Curve = RistrettoGroup;

    #[test]
    fn htdh2_proof() {
        let mut rng = thread_rng();

        let (pk, (uv, r), _) = create_elgamal_enc0_and_enc1(&mut rng);

        let g_0 = Curve::independent_generators::<1>(b"HTDH2ZKP")[0];
        let g_0_r = g_0 * r;
        let htdh2 = HTDH2ProofBuilder::<Curve>::new(g_0, uv, g_0_r, Some(r));

        let (zk_proof, knowledge) = ZKProof::from_builder(&htdh2);

        let nizkp = NIZKProof::new(zk_proof, VectorContextHash::default());
        let proof = nizkp.prove(&mut rng, &knowledge);

        assert!(nizkp.verify(&proof))
    }
}
