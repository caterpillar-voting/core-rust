pub mod el_gamal;

use crate::foundation::group::Group;
use crate::primitives::zkp::proof::{Claim, Knowledge};
use crate::utils::tree::BooleanTree;
use crate::utils::tree::BooleanTree::{And, Leaf, Or};

pub trait ProofBuilder<G: Group> {
    fn build(&self) -> (Claim<G>, Knowledge<G>);
}
#[allow(type_alias_bounds)]
type ProofTreeBuilderTree<'a, G: Group> = BooleanTree<&'a dyn ProofBuilder<G>>;

struct ProofTreeBuilder<'a, G: Group> {
    tree: ProofTreeBuilderTree<'a, G>,
}

impl<'a, G: Group> ProofTreeBuilder<'a, G> {
    pub fn new(tree: ProofTreeBuilderTree<'a, G>) -> Self {
        Self { tree }
    }

    fn compose(proof_builder_tree: &ProofTreeBuilderTree<G>) -> (Claim<G>, Knowledge<G>) {
        match proof_builder_tree {
            Leaf(pb) => pb.build(),
            And(proof_builders) => {
                let (claims, knowledges) = Self::collect(proof_builders);
                (And(claims), And(knowledges))
            }
            Or(proof_builders) => {
                let (claims, knowledges) = Self::collect(proof_builders);
                (Or(claims), Or(knowledges))
            }
        }
    }

    fn collect(
        proof_builders: &Vec<ProofTreeBuilderTree<G>>,
    ) -> (Vec<Claim<G>>, Vec<Knowledge<G>>) {
        proof_builders.iter().fold(
            (Vec::new(), Vec::new()),
            |(mut claims, mut knowledges), pb| {
                let (claim, knowledge) = Self::compose(pb);
                claims.push(claim);
                knowledges.push(knowledge);
                (claims, knowledges)
            },
        )
    }
}

impl<'a, G: Group> ProofBuilder<G> for ProofTreeBuilder<'a, G> {
    fn build(&self) -> (Claim<G>, Knowledge<G>) {
        Self::compose(&self.tree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::zkp::_test_utils::{create_enc0_and_enc1, do_proof};
    use crate::primitives::zkp::proof_builder::el_gamal::{EncProof, ReEncProof};
    use crate::utils::tree::BooleanTree::Leaf;
    use rand::thread_rng;

    type Curve = RistrettoGroup;

    #[test]
    fn el_gamal_or_proof() {
        let mut rng = thread_rng();

        let (pk, (u, v), (u_enc1, v_enc1, r_enc1)) = create_enc0_and_enc1(&mut rng);

        let enc1 = EncProof::<Curve>::new(pk, (u_enc1, v_enc1), Curve::basepoint(), Some(r_enc1));
        let renenc = ReEncProof::<Curve>::new(pk, (u, v), (u_enc1, v_enc1), None);
        let tree =
            ProofTreeBuilder::new(And(vec![Or(vec![Leaf(&enc1), Leaf(&renenc)]), Leaf(&enc1)]));

        let (claim, knowledge) = tree.build();

        do_proof(&mut rng, claim, knowledge);
    }
}
