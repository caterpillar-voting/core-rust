use crate::foundation::group::Group;
use crate::primitives::zkp::proof::BooleanTree::{And, Leaf, Or};
use crate::primitives::zkp::statement::{Commit, Statement, Transcript};
use rand_core::{CryptoRng, RngCore};

pub enum BooleanTree<T> {
    Leaf(T),
    And(Vec<BooleanTree<T>>),
    Or(Vec<BooleanTree<T>>),
}

pub struct ZeroKnowledgeProof {}

type Claim<G> = BooleanTree<Box<[Statement<G>]>>;
#[allow(type_alias_bounds)]
type Knowledge<G: Group> = BooleanTree<Option<G::Scalar>>;
type CommittedProof<G> = BooleanTree<Box<[Commit<G>]>>;
#[allow(type_alias_bounds)]
type SimulatedProof<G: Group> = BooleanTree<(G::Scalar, Box<[Transcript<G>]>)>;
type PreparedProof<G> = BooleanTree<(Option<CommittedProof<G>>, Option<SimulatedProof<G>>)>;
#[allow(type_alias_bounds)]
type Proof<G: Group> = BooleanTree<(G::Scalar, Box<[Transcript<G>]>)>;

/// https://crypto.ethz.ch/publications/files/Maurer09.pdf
impl ZeroKnowledgeProof {
    pub fn prepare<G: Group, R: RngCore + CryptoRng>(
        rng: &mut R,
        claim: &Claim<G>,
        knowledge: &Knowledge<G>,
    ) -> PreparedProof<G> {
        match (claim, knowledge) {
            (Leaf(statements), Leaf(Some(_))) => {
                let committed = Self::commit(rng, statements);

                Leaf((Some(committed), None))
            }
            (And(nodes), And(knowledge_nodes)) => {
                let committed = nodes
                    .iter()
                    .zip(knowledge_nodes.iter())
                    .map(|(node, knowledge_node)| Self::prepare(rng, node, knowledge_node))
                    .collect();

                And(committed)
            }
            (Or(nodes), Or(knowledge_nodes)) => {
                let simulated = nodes
                    .iter()
                    .zip(knowledge_nodes.iter())
                    .map(|(node, knowledge_node)| {
                        if let Leaf(None) = &knowledge_node {
                            let c = G::scalar_random(rng);

                            return Leaf((None, Some(Self::simulate(rng, node, c))));
                        }

                        Self::prepare(rng, node, knowledge_node)
                    })
                    .collect();

                Or(simulated)
            }
            _ => unreachable!("proof and knowledge trees not synchronized"),
        }
    }

    fn commit<G: Group, R: RngCore + CryptoRng>(
        rng: &mut R,
        statements: &[Statement<G>],
    ) -> CommittedProof<G> {
        let committed = statements
            .iter()
            .map(|statement| statement.commit(rng))
            .collect();

        Leaf(committed)
    }

    fn simulate<G: Group, R: RngCore + CryptoRng>(
        rng: &mut R,
        claim: &Claim<G>,
        c: G::Scalar,
    ) -> SimulatedProof<G> {
        match claim {
            Leaf(statements) => {
                let simulated = statements
                    .iter()
                    .map(|statement| statement.simulate(rng, &c))
                    .collect();

                Leaf((c, simulated))
            }
            And(nodes) => {
                let simulated = nodes
                    .iter()
                    .map(|node| Self::simulate(rng, node, c))
                    .collect();

                And(simulated)
            }
            Or(nodes) => {
                let mut challenges = Vec::with_capacity(nodes.len());
                let mut sum = G::Scalar::from(0);

                for _ in 0..nodes.len().saturating_sub(1) {
                    let challenge = G::scalar_random(rng);
                    sum += challenge;
                    challenges.push(challenge);
                }

                challenges.push(c - &sum);

                let simulated = nodes
                    .iter()
                    .zip(challenges.iter())
                    .map(|(node, c)| Self::simulate(rng, node, *c))
                    .collect();

                Or(simulated)
            }
        }
    }

    pub fn proof<G: Group>(
        _claim: &Claim<G>,
        _prepared_proof: &PreparedProof<G>,
        _knowledge: &Knowledge<G>,
        _c: &G::Scalar,
    ) -> Proof<G> {
        Leaf((
            G::Scalar::from(1u64),
            vec![(G::Scalar::from(1), G::basepoint())]
                .into_iter()
                .collect(),
        ))
        /*
        match claim {
            Leaf(statements) => {
                if let Leaf(committed_or_simulated) = prepared_proof {
                    assert_ne!(committed_or_simulated.0.is_some(), committed_or_simulated.1.is_some());

                    if committed_or_simulated.1.is_some() {
                        assert_eq!(c, committed_or_simulated.1.unwrap());
                        return committed_or_simulated.1
                    }
                }

                unreachable!("proof and knowledge trees not synchronized")
            }
            And(nodes) => {}
            Or(nodes) => {}
        }
        */
    }

    pub fn verify<G: Group>(&self, _claim: &Claim<G>, _proof: &Proof<G>) -> bool {
        false
    }
}

// region: --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::encryption::el_gamal::{ElGamal, ExponentialElGamal};
    use rand::thread_rng;

    type Curve = RistrettoGroup;

    type Scalar = <RistrettoGroup as Group>::Scalar;

    #[test]
    fn prepare_complex_statement() {
        let mut rng = thread_rng();

        let el_gamal = ElGamal::<Curve>::default();
        let exponential_el_gamal = ExponentialElGamal(el_gamal);
        let sk = exponential_el_gamal.0.generate_secret_key(&mut rng);
        let pk = exponential_el_gamal.0.derive_public_key(&sk);

        // encrypt 0
        let r = Scalar::random(&mut rng);
        let (u, v) = exponential_el_gamal.encrypt(&pk, &r, &Scalar::ZERO);

        // re-encrypt
        let r2 = Scalar::random(&mut rng);
        let (u_dash, v_dash) = exponential_el_gamal.0.reencrypt(&pk, &r2, &(u, v));

        // enc proof (simulated) and rerand proof (true)
        let zkp_enc1_u = Statement::<Curve>::new(Curve::basepoint(), u_dash);
        let zkp_enc1_v = Statement::<Curve>::new(pk, v_dash - Curve::basepoint());
        let zkp_rerand_u = Statement::<Curve>::new(Curve::basepoint(), u_dash - u);
        let zkp_rerand_v = Statement::<Curve>::new(pk, v_dash - v);

        let claim: Claim<Curve> = Or(vec![
            Leaf(Box::new([zkp_enc1_u.clone(), zkp_enc1_v.clone()])),
            Leaf(Box::new([zkp_rerand_u.clone(), zkp_rerand_v.clone()])),
        ]);
        let knowledge: Knowledge<Curve> = Or(vec![Leaf(None), Leaf(Some(r2))]);
        let prepared_proof = ZeroKnowledgeProof::prepare(&mut rng, &claim, &knowledge);

        assert!(matches!(prepared_proof, Or(_)));
        if let Or(nodes) = prepared_proof {
            assert_eq!(nodes.len(), 2);
            assert!(matches!(nodes[0], Leaf(_)));
            assert!(matches!(nodes[1], Leaf(_)));
        } else {
            unreachable!()
        }
    }
}

// endregion: --- Tests
