pub mod el_gamal;

use crate::foundation::group::Group;
use crate::primitives::zkp::proof::{Claim, Knowledge};
use crate::utils::tree::BooleanTree;
use crate::utils::tree::BooleanTree::{And, Leaf, Or};

pub trait ProofBuilder<G: Group> {
    fn build(&self) -> (Claim<G>, Knowledge<G>);
}
#[allow(type_alias_bounds)]
pub type TreeProofBuilder<'a, G: Group> = BooleanTree<&'a dyn ProofBuilder<G>>;

impl<'a, G: Group> ProofBuilder<G> for TreeProofBuilder<'a, G> {
    fn build(&self) -> (Claim<G>, Knowledge<G>) {
        compose(self)
    }
}

fn compose<G: Group>(proof_builder_tree: &TreeProofBuilder<G>) -> (Claim<G>, Knowledge<G>) {
    match proof_builder_tree {
        Leaf(pb) => pb.build(),
        And(proof_builders) => {
            let (claims, knowledges) = collect(proof_builders);
            (And(claims), And(knowledges))
        }
        Or(proof_builders) => {
            let (claims, knowledges) = collect(proof_builders);
            (Or(claims), Or(knowledges))
        }
    }
}

fn collect<G: Group>(proof_builders: &Vec<TreeProofBuilder<G>>) -> (Vec<Claim<G>>, Vec<Knowledge<G>>) {
    proof_builders.iter().fold((Vec::new(), Vec::new()), |(mut claims, mut knowledges), pb| {
        let (claim, knowledge) = compose(pb);
        claims.push(claim);
        knowledges.push(knowledge);
        (claims, knowledges)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::zkp::_test_utils::{create_elgamal_enc0_and_enc1, proof_claims};
    use crate::primitives::zkp::proof_builder::el_gamal::{EncProofBuilder, HTDH2ProofBuilder, ReEncProofBuilder};
    use crate::utils::tree::BooleanTree::Leaf;
    use rand::thread_rng;

    type Curve = RistrettoGroup;

    #[test]
    fn el_gamal_or_proof() {
        let mut rng = thread_rng();

        let (pk, (uv, r), (uv_enc1, r_enc1)) = create_elgamal_enc0_and_enc1(&mut rng);

        let enc1 = EncProofBuilder::<Curve>::new(pk, uv_enc1, Curve::basepoint(), Some(r_enc1));
        let renenc = ReEncProofBuilder::<Curve>::new(pk, uv, uv_enc1, None);
        let htdh2 = HTDH2ProofBuilder::<Curve>::new_with_r(uv, r);
        let tree: TreeProofBuilder<Curve> = And(vec![Or(vec![Leaf(&enc1), Leaf(&renenc)]), Leaf(&enc1), Leaf(&htdh2)]);

        let (claim, knowledge) = tree.build();

        proof_claims(&mut rng, claim, knowledge);
    }
}
