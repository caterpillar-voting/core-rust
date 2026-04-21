pub mod el_gamal;

use crate::foundation::group::Group;
use crate::primitives::zkp::proof::{Claim, Knowledge};
use crate::utils::tree::BooleanTree::{And, Or};
use std::marker::PhantomData;

pub trait ProofBuilder<G: Group> {
    fn build(&self) -> (Claim<G>, Knowledge<G>);
}

pub struct OrProofBuilder<'a, G: Group>
{
    proof_builders: Vec<&'a dyn ProofBuilder<G>>,
    _marker: PhantomData<G>,
}

impl<'a, G: Group> Default for OrProofBuilder<'a, G> {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl<'a, G: Group> OrProofBuilder<'a, G> {
    pub fn new(proof_builders: Vec<&'a dyn ProofBuilder<G>>) -> Self {
        Self {
            proof_builders,
            _marker: PhantomData,
        }
    }

    pub fn or(&mut self, proof_builder: &'a dyn ProofBuilder<G>) -> &mut OrProofBuilder<'a, G> {
        self.proof_builders.push(proof_builder);

        self
    }

    fn collect_proof_builders(&self) -> (Vec<Claim<G>>, Vec<Knowledge<G>>) {
        self.proof_builders.iter().fold(
            (Vec::new(), Vec::new()),
            |(mut claims, mut knowledges), pb| {
                let (claim, knowledge) = pb.build();
                claims.push(claim);
                knowledges.push(knowledge);
                (claims, knowledges)
            },
        )
    }
}

impl<'a, G: Group> ProofBuilder<G> for OrProofBuilder<'a, G> {
    fn build(&self) -> (Claim<G>, Knowledge<G>) {
        let (claims, knowledges) = self.collect_proof_builders();

        (Or(claims), Or(knowledges))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use rand::thread_rng;
    use crate::primitives::zkp::proof_builder::el_gamal::{EncProof, ReEncProof};
    use crate::primitives::zkp::_test_utils::{do_proof, create_enc0_and_enc1};

    type Curve = RistrettoGroup;

    #[test]
    fn el_gamal_or_proof() {
        let mut rng = thread_rng();

        let (pk, (u, v), (u_enc1, v_enc1, r_enc1)) = create_enc0_and_enc1(&mut rng);

        let enc1 = EncProof::<Curve>::new(pk, (u_enc1, v_enc1), Curve::basepoint(), Some(r_enc1));
        let renenc = ReEncProof::<Curve>::new(pk, (u, v), (u_enc1, v_enc1), None);
        let (claim, knowledge) = OrProofBuilder::<Curve>::new(vec![&enc1, &renenc]).build();

        do_proof(&mut rng, claim, knowledge);
    }
}