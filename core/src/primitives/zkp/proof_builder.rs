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
    use crate::primitives::encryption::el_gamal::{ElGamal, ExponentialElGamal};
    use rand::thread_rng;
    use rand_core::{CryptoRng, RngCore};
    use crate::primitives::zkp::proof::ZeroKnowledgeProof;
    use crate::primitives::zkp::proof_builder::el_gamal::{EncProof, ReEncProof};

    type Curve = RistrettoGroup;

    type Scalar = <RistrettoGroup as Group>::Scalar;
    type Point = <RistrettoGroup as Group>::Point;

    fn create<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> (Point, (Point, Point), (Point, Point, Scalar)) {
        let el_gamal = ElGamal::<Curve>::default();
        let exponential_el_gamal = ExponentialElGamal(el_gamal);
        let sk = exponential_el_gamal.0.generate_secret_key(rng);
        let pk = exponential_el_gamal.0.derive_public_key(&sk);

        // encrypt 0
        let r = Scalar::random(rng);
        let (u, v) = exponential_el_gamal.encrypt(&pk, &r, &Scalar::ZERO);

        // encrypt 1
        let r_enc1 = Scalar::random(rng);
        let (u_enc1, v_enc1) = exponential_el_gamal.encrypt(&pk, &r_enc1, &Scalar::ONE);

        (pk, (u, v), (u_enc1, v_enc1, r_enc1))
    }

    fn check_proof_valid<R: RngCore + CryptoRng>(
        rng: &mut R,
        claim: Claim<Curve>,
        knowledge: Knowledge<Curve>,
    ) {
        let prepared_proof = ZeroKnowledgeProof::prepare(rng, &claim, &knowledge);
        let challenge = Scalar::random(rng);
        let finalized_proof =
            ZeroKnowledgeProof::finalize(rng, &prepared_proof, &claim, &knowledge, &challenge);

        assert!(ZeroKnowledgeProof::check(
            &claim,
            &finalized_proof,
            &challenge))
    }

    #[test]
    fn zkp_OR_proof() {
        let mut rng = thread_rng();

        let (pk, (u, v), (u_enc1, v_enc1, r_enc1)) = create(&mut rng);

        let enc1 = EncProof::<Curve>::new(pk, (u_enc1, v_enc1), Curve::basepoint(), Some(r_enc1));
        let renenc = ReEncProof::<Curve>::new(pk, (u, v), (u_enc1, v_enc1), None);
        let (claim, knowledge) = OrProofBuilder::<Curve>::new(vec![&enc1, &renenc]).build();

        check_proof_valid(&mut rng, claim, knowledge);
    }
}