use crate::foundation::group::Group;
use crate::primitives::zkp::proof::BooleanTree::{And, Leaf, Or};
use crate::primitives::zkp::statement::{Commit, Statement, Transcript};
use rand_core::{CryptoRng, RngCore};

#[derive(Clone)]
pub enum BooleanTree<T> {
    Leaf(T),
    And(Vec<BooleanTree<T>>),
    Or(Vec<BooleanTree<T>>),
}

pub struct ZeroKnowledgeProof {}

type Claim<G> = BooleanTree<Box<[Statement<G>]>>;
#[allow(type_alias_bounds)]
type Knowledge<G: Group> = BooleanTree<Option<G::Scalar>>;
type CommittedProof<G> = Box<[Commit<G>]>;
#[allow(type_alias_bounds)]
type SimulatedProof<G: Group> = Box<[Transcript<G>]>;
#[allow(type_alias_bounds)]
type CommittedOrSimulatedProof<G: Group> = (
    Option<CommittedProof<G>>,
    Option<(G::Scalar, SimulatedProof<G>)>,
);
#[allow(type_alias_bounds)]
type PreparedProof<G: Group> = BooleanTree<CommittedOrSimulatedProof<G>>;
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
            // we enforce that claim has the same tree structure than prepared_proof: the claim is also necessary to verify, so no use-case of "optimizing" here
            // we do not care whether knowledge has the same tree structure, i.e., for simulated branches, the knowledge tree may stop at the highest simulated branch
            (Leaf(statements), Leaf(Some(_))) => {
                let committed = Self::commit(rng, statements);

                Leaf((Some(committed), None))
            }
            (Leaf(statements), Leaf(None)) => {
                let c = G::scalar_random(rng);
                let simulated = Self::simulate(rng, statements, c);

                Leaf((None, Some((c, simulated))))
            }
            (And(nodes), And(knowledge_nodes)) => {
                let committed = nodes
                    .iter()
                    .zip(knowledge_nodes.iter())
                    .map(|(node, knowledge_node)| Self::prepare(rng, node, knowledge_node))
                    .collect();

                And(committed)
            }
            (And(nodes), Leaf(None)) => {
                let committed = nodes
                    .iter()
                    .map(|node| Self::prepare(rng, node, &Leaf(None)))
                    .collect();

                And(committed)
            }
            (Or(nodes), Or(knowledge_nodes)) => {
                let simulated = nodes
                    .iter()
                    .zip(knowledge_nodes.iter())
                    .map(|(node, knowledge_node)| Self::prepare(rng, node, knowledge_node))
                    .collect();

                Or(simulated)
            }
            (Or(nodes), Leaf(None)) => {
                let simulated = nodes
                    .iter()
                    .map(|node| Self::prepare(rng, node, &Leaf(None)))
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
        statements
            .iter()
            .map(|statement| statement.commit(rng))
            .collect()
    }

    fn simulate<G: Group, R: RngCore + CryptoRng>(
        rng: &mut R,
        statements: &[Statement<G>],
        c: G::Scalar,
    ) -> SimulatedProof<G> {
        statements
            .iter()
            .map(|statement| statement.simulate(rng, &c))
            .collect()
    }

    pub fn finalize<G: Group, R: RngCore + CryptoRng>(
        rng: &mut R,
        prepared_proof: &PreparedProof<G>,
        claim: &Claim<G>,
        knowledge: &Knowledge<G>,
        c: &G::Scalar,
    ) -> Proof<G> {
        match (prepared_proof, claim, knowledge) {
            // we enforce that claim has the same tree structure than prepared_proof: the claim is also necessary to verify, so no use-case of "optimizing" here
            // we do not care whether knowledge has the same tree structure, i.e., for simulated branches, the knowledge tree may stop at the highest simulated branch
            (Leaf((None, Some((actual_c, simulated)))), Leaf(_), Leaf(_)) => {
                assert_eq!(actual_c, c);

                Leaf((*c, simulated.clone()))
            }
            (Leaf((Some(commits), None)), Leaf(statements), Leaf(Some(x))) => {
                let transcripts = Self::proof(statements, commits, x, c);

                Leaf((*c, transcripts))
            }
            (And(prepared_nodes), And(claim_nodes), And(knowledge_nodes)) => {
                let proofs = prepared_nodes
                    .iter()
                    .zip(claim_nodes.iter())
                    .zip(knowledge_nodes.iter())
                    .map(|((prepared_node, claim_node), knowledge_node)| {
                        Self::finalize(rng, prepared_node, claim_node, knowledge_node, c)
                    })
                    .collect();

                And(proofs)
            }
            (And(prepared_nodes), And(claim_nodes), Leaf(None)) => {
                let simulated_proofs = prepared_nodes
                    .iter()
                    .zip(claim_nodes.iter())
                    .map(|(prepared_node, claim_node)| {
                        Self::finalize(rng, prepared_node, claim_node, &Leaf(None), c)
                    })
                    .collect();

                And(simulated_proofs)
            }
            (Or(prepared_nodes), Or(claim_nodes), Or(knowledge_nodes)) => {
                let finalized_challenges =
                    Self::finalize_challenges::<G, R>(rng, prepared_nodes, c);

                let proofs = prepared_nodes
                    .iter()
                    .zip(claim_nodes.iter())
                    .zip(knowledge_nodes.iter())
                    .zip(finalized_challenges.iter())
                    .map(
                        |(((prepared_node, claim_node), knowledge_node), challenge)| {
                            Self::finalize(
                                rng,
                                prepared_node,
                                claim_node,
                                knowledge_node,
                                challenge,
                            )
                        },
                    )
                    .collect();

                Or(proofs)
            }
            (Or(prepared_nodes), Or(claim_nodes), Leaf(None)) => {
                let finalized_challenges =
                    Self::finalize_challenges::<G, R>(rng, prepared_nodes, c);

                let proofs = prepared_nodes
                    .iter()
                    .zip(claim_nodes.iter())
                    .zip(finalized_challenges.iter())
                    .map(|((prepared_node, claim_node), challenge)| {
                        Self::finalize(rng, prepared_node, claim_node, &Leaf(None), challenge)
                    })
                    .collect();

                Or(proofs)
            }
            _ => unreachable!("proof and knowledge trees not synchronized"),
        }
    }

    fn finalize_challenges<G: Group, R: RngCore + CryptoRng>(
        rng: &mut R,
        prepared_nodes: &Vec<BooleanTree<CommittedOrSimulatedProof<G>>>,
        c: &G::Scalar,
    ) -> Vec<G::Scalar> {
        let challenges: Vec<Option<G::Scalar>> = prepared_nodes
            .iter()
            .map(|prepared_node| Self::get_simulated_challenge::<G>(prepared_node))
            .collect();

        let simulated_challenges: Vec<G::Scalar> = challenges
            .iter()
            .filter_map(|challenge| *challenge)
            .collect();
        let mut current_missing_challenges = prepared_nodes.len() - simulated_challenges.len();
        let mut current_challenge_sum = simulated_challenges
            .iter()
            .fold(G::Scalar::from(0), |current, next| current + next);
        assert!(
            current_missing_challenges > 0 || current_challenge_sum == *c,
            "challenges do not sum up to c"
        );

        challenges
            .iter()
            .map(|challenge| {
                if let Some(predefined) = challenge {
                    *predefined
                } else {
                    if current_missing_challenges > 1 {
                        let challenge = G::scalar_random(rng);
                        current_missing_challenges -= 1;
                        current_challenge_sum += challenge;

                        challenge
                    } else {
                        current_challenge_sum - c
                    }
                }
            })
            .collect()
    }

    fn get_simulated_challenge<G: Group>(prepared_proof: &PreparedProof<G>) -> Option<G::Scalar> {
        match prepared_proof {
            Leaf((None, Some((challenge, _)))) => Some(*challenge),
            And(prepared_nodes) => prepared_nodes
                .iter()
                .filter_map(|node| Self::get_simulated_challenge::<G>(node))
                .next(),
            Or(prepared_nodes) => {
                let challenges: Vec<G::Scalar> = prepared_nodes
                    .iter()
                    .filter_map(|node| Self::get_simulated_challenge::<G>(node))
                    .collect();

                if challenges.len() == prepared_nodes.len() {
                    Some(
                        challenges
                            .iter()
                            .fold(G::Scalar::from(0), |acc, challenge| acc + challenge),
                    )
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn proof<G: Group>(
        statements: &[Statement<G>],
        commits: &[Commit<G>],
        x: &G::Scalar,
        c: &G::Scalar,
    ) -> Box<[Transcript<G>]> {
        statements
            .iter()
            .zip(commits.iter())
            .map(|(statement, (k, t))| {
                let r = statement.proof(k, x, c);

                (r, *t)
            })
            .collect()
    }

    pub fn check<G: Group>(claim: &Claim<G>, proof: &Proof<G>, c: &G::Scalar) -> bool {
        let recovered = Self::verify(claim, proof);

        recovered == Some(*c)
    }

    fn verify<G: Group>(claim: &Claim<G>, proof: &Proof<G>) -> Option<G::Scalar> {
        match (claim, proof) {
            (Leaf(statements), Leaf((c, transcripts))) => {
                if statements
                    .iter()
                    .zip(transcripts.iter())
                    .all(|(statement, (r, t))| statement.verify(r, t, c)) {
                    Some(*c)
                } else {
                    None
                }
            }
            (And(nodes), And(proofs)) => {
                let mut candidate: Option<G::Scalar> = None;

                for (node, proof) in nodes.iter().zip(proofs.iter()) {
                    let c = Self::verify(node, proof)?;

                    match candidate {
                        Some(first) if first == c => { /* if equal, do nothing */ }
                        Some(_) => return None,
                        None => candidate = Some(c),
                    }
                }

                candidate
            }
            (Or(nodes), Or(proofs)) => {
                let mut sum: Option<G::Scalar> = None;

                for (node, proof) in nodes.iter().zip(proofs.iter()) {
                    let c = Self::verify(node, proof)?;

                    sum = Some(match sum {
                        Some(acc) => acc + &c,
                        None => c,
                    });
                }

                sum
            }
            _ => unreachable!("claim and proof trees not synchronized"),
        }
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
        let challenge = Scalar::random(&mut rng);
        let finalized_proof =
            ZeroKnowledgeProof::finalize(&mut rng, &prepared_proof, &claim, &knowledge, &challenge);

        assert!(matches!(prepared_proof, Or(_)));
        if let Or(nodes) = prepared_proof {
            assert_eq!(nodes.len(), 2);
            assert!(matches!(nodes[0], Leaf(_)));
            assert!(matches!(nodes[1], Leaf(_)));
        } else {
            unreachable!()
        }

        assert!(ZeroKnowledgeProof::check(&claim, &finalized_proof, &challenge))
    }
}

// endregion: --- Tests
