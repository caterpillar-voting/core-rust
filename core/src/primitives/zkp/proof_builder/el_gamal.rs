use crate::foundation::group::Group;
use crate::primitives::zkp::proof::{Claim, Knowledge};
use crate::primitives::zkp::proof_builder::ProofBuilder;
use crate::primitives::zkp::statement::Statement;
use crate::utils::tree::BooleanTree::Leaf;

pub struct ReEncProof<G: Group> {
    pk: G::Point,
    uv: (G::Point, G::Point),
    uv_dash: (G::Point, G::Point),
    randomness: Option<G::Scalar>,
}

impl<G: Group> ReEncProof<G> {
    pub fn new(
        pk: G::Point,
        uv: (G::Point, G::Point),
        uv_dash: (G::Point, G::Point),
        randomness: Option<G::Scalar>,
    ) -> Self {
        Self {
            pk,
            uv,
            uv_dash,
            randomness,
        }
    }
}

impl<G: Group> ProofBuilder<G> for ReEncProof<G> {
    fn build(self) -> (Claim<G>, Knowledge<G>) {
        let rerand_u = Statement::<G>::new(G::basepoint(), self.uv_dash.0 - &self.uv.0);
        let rerand_v = Statement::<G>::new(self.pk, self.uv_dash.1 - &self.uv.1);

        let claim: Claim<G> = Leaf(Box::new([rerand_u, rerand_v]));
        let knowledge = Leaf(self.randomness);

        (claim, knowledge)
    }
}

pub struct EncProof<G: Group> {
    pk: G::Point,
    uv: (G::Point, G::Point),
    message: G::Point,
    randomness: Option<G::Scalar>,
}

impl<G: Group> EncProof<G> {
    pub fn new(
        pk: G::Point,
        uv: (G::Point, G::Point),
        message: G::Point,
        randomness: Option<G::Scalar>,
    ) -> Self {
        Self {
            pk,
            uv,
            message,
            randomness,
        }
    }
}

impl<G: Group> ProofBuilder<G> for EncProof<G> {
    fn build(self) -> (Claim<G>, Knowledge<G>) {
        let encm_u = Statement::<G>::new(G::basepoint(), self.uv.0);
        let encm_v = Statement::<G>::new(self.pk, self.uv.1 - &self.message);

        let claim: Claim<G> = Leaf(Box::new([encm_u, encm_v]));
        let knowledge = Leaf(self.randomness);

        (claim, knowledge)
    }
}
