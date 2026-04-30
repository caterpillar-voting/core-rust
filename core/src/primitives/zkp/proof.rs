use crate::foundation::group::Group;
use crate::primitives::zkp::proof::BooleanTree::{And, Leaf, Or};
use crate::primitives::zkp::statement::{Commit, Statement, Transcript};
use crate::utils::tree::BooleanTree;
use rand_core::{CryptoRng, RngCore};

pub type Claim<G> = BooleanTree<Box<[Statement<G>]>>;
#[allow(type_alias_bounds)]
pub type Knowledge<G: Group> = BooleanTree<Option<G::Scalar>>;
#[allow(type_alias_bounds)]
type CommitsOrSimulations<G: Group> = (
    Option<Box<[Commit<G>]>>,                  // committed proofs
    Option<(G::Scalar, Box<[Transcript<G>]>)>, // simulated proofs
);
#[allow(type_alias_bounds)]
pub type ProofCommit<G: Group> = BooleanTree<CommitsOrSimulations<G>>;
#[allow(type_alias_bounds)]
pub type ProofResponse<G: Group> = BooleanTree<(G::Scalar, Box<[Transcript<G>]>)>;

pub struct Proof {}

// we enforce that claim has the same tree structure than prepared_proof: the claim is also necessary to verify, so no use-case of "optimizing" here
// we do not care whether knowledge has the same tree structure, i.e., for simulated branches, the knowledge tree may stop at the highest simulated branch
impl Proof {
    pub fn commit<G: Group, R: RngCore + CryptoRng>(
        rng: &mut R,
        claim: &Claim<G>,
        knowledge: &Knowledge<G>,
    ) -> ProofCommit<G> {
        match (claim, knowledge) {
            // commit to statements with knowledge
            (Leaf(statements), Leaf(Some(_))) => {
                let committed = statements
                    .iter()
                    .map(|statement| statement.commit(rng))
                    .collect();

                Leaf((Some(committed), None))
            }
            // simulate statements without knowledge
            (Leaf(statements), Leaf(None)) => {
                let c = G::scalar_random(rng);
                let simulated = statements
                    .iter()
                    .map(|statement| statement.simulate(rng, &c))
                    .collect();

                Leaf((None, Some((c, simulated))))
            }
            (And(nodes), And(knowledge_nodes)) => {
                let committed = nodes
                    .iter()
                    .zip(knowledge_nodes.iter())
                    .map(|(node, knowledge_node)| Self::commit(rng, node, knowledge_node))
                    .collect();

                And(committed)
            }
            (And(nodes), Leaf(None)) => {
                let committed = nodes
                    .iter()
                    .map(|node| Self::commit(rng, node, &Leaf(None)))
                    .collect();

                And(committed)
            }
            (Or(nodes), Or(knowledge_nodes)) => {
                let simulated = nodes
                    .iter()
                    .zip(knowledge_nodes.iter())
                    .map(|(node, knowledge_node)| Self::commit(rng, node, knowledge_node))
                    .collect();

                Or(simulated)
            }
            (Or(nodes), Leaf(None)) => {
                let simulated = nodes
                    .iter()
                    .map(|node| Self::commit(rng, node, &Leaf(None)))
                    .collect();

                Or(simulated)
            }
            _ => unreachable!("proof and knowledge trees not synchronized"),
        }
    }

    pub fn response<G: Group, R: RngCore + CryptoRng>(
        rng: &mut R,
        prepared_proof: &ProofCommit<G>,
        claim: &Claim<G>,
        knowledge: &Knowledge<G>,
        c: &G::Scalar,
    ) -> ProofResponse<G> {
        match (prepared_proof, claim, knowledge) {
            // create transcripts of statements with knowledge
            (Leaf((Some(commits), None)), Leaf(statements), Leaf(Some(x))) => {
                let transcripts = statements
                    .iter()
                    .zip(commits.iter())
                    .map(|(statement, (k, t))| {
                        let r = statement.response(k, x, c);

                        (r, *t)
                    })
                    .collect();

                Leaf((*c, transcripts))
            }
            // output simulated transcripts of statements without knowledge
            (Leaf((None, Some((actual_c, simulated)))), Leaf(_), Leaf(_)) => {
                assert_eq!(actual_c, c, "simulated challenge does not match actual challenge. this hints at an inconsistency in the proof tree.");

                Leaf((*c, simulated.clone()))
            }
            (And(prepared_nodes), And(claim_nodes), And(knowledge_nodes)) => {
                let proofs = prepared_nodes
                    .iter()
                    .zip(claim_nodes.iter())
                    .zip(knowledge_nodes.iter())
                    .map(|((prepared_node, claim_node), knowledge_node)| {
                        Self::response(rng, prepared_node, claim_node, knowledge_node, c)
                    })
                    .collect();

                And(proofs)
            }
            (And(prepared_nodes), And(claim_nodes), Leaf(None)) => {
                let simulated_proofs = prepared_nodes
                    .iter()
                    .zip(claim_nodes.iter())
                    .map(|(prepared_node, claim_node)| {
                        Self::response(rng, prepared_node, claim_node, &Leaf(None), c)
                    })
                    .collect();

                And(simulated_proofs)
            }
            (Or(prepared_nodes), Or(claim_nodes), Or(knowledge_nodes)) => {
                let challenges = Self::define_challenges_given_sum::<G, R>(rng, prepared_nodes, c);

                let proofs = prepared_nodes
                    .iter()
                    .zip(claim_nodes.iter())
                    .zip(knowledge_nodes.iter())
                    .zip(challenges.iter())
                    .map(
                        |(((prepared_node, claim_node), knowledge_node), challenge)| {
                            Self::response(
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
                let challenges = Self::define_challenges_given_sum::<G, R>(rng, prepared_nodes, c);

                let proofs = prepared_nodes
                    .iter()
                    .zip(claim_nodes.iter())
                    .zip(challenges.iter())
                    .map(|((prepared_node, claim_node), challenge)| {
                        Self::response(rng, prepared_node, claim_node, &Leaf(None), challenge)
                    })
                    .collect();

                Or(proofs)
            }
            _ => unreachable!("proof and knowledge trees not synchronized"),
        }
    }

    fn define_challenges_given_sum<G: Group, R: RngCore + CryptoRng>(
        rng: &mut R,
        prepared_nodes: &[BooleanTree<CommitsOrSimulations<G>>],
        expected_sum: &G::Scalar,
    ) -> Vec<G::Scalar> {
        let challenges: Vec<Option<G::Scalar>> = prepared_nodes
            .iter()
            .map(|prepared_node| Self::try_get_simulated_challenge::<G>(prepared_node))
            .collect();

        let simulated: Vec<G::Scalar> = challenges
            .iter()
            .filter_map(|challenge| *challenge)
            .collect();
        let mut missing_count = prepared_nodes.len() - simulated.len();
        let mut actual_sum = simulated
            .iter()
            .fold(G::Scalar::from(0), |current, next| current + next);
        assert!(
            missing_count > 0 || actual_sum == *expected_sum,
            "challenges do not sum up to c"
        );

        challenges
            .iter()
            .map(|challenge| {
                if let Some(predefined) = challenge {
                    *predefined
                } else {
                    if missing_count > 1 {
                        let challenge = G::scalar_random(rng);
                        missing_count -= 1;
                        actual_sum += challenge;

                        challenge
                    } else {
                        *expected_sum - &actual_sum
                    }
                }
            })
            .collect()
    }

    fn try_get_simulated_challenge<G: Group>(prepared_proof: &ProofCommit<G>) -> Option<G::Scalar> {
        match prepared_proof {
            Leaf((None, Some((challenge, _)))) => Some(*challenge),
            And(prepared_nodes) => prepared_nodes
                .iter()
                .filter_map(|node| Self::try_get_simulated_challenge::<G>(node))
                .next(),
            Or(prepared_nodes) => {
                let challenges: Vec<G::Scalar> = prepared_nodes
                    .iter()
                    .filter_map(|node| Self::try_get_simulated_challenge::<G>(node))
                    .collect();

                if challenges.len() == prepared_nodes.len() {
                    Some(challenges.iter().fold(G::Scalar::from(0), |acc, challenge| acc + challenge))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn verify<G: Group>(claim: &Claim<G>, proof: &ProofResponse<G>, c: &G::Scalar) -> bool {
        let recovered = Self::recover_proven_challenge(claim, proof);

        recovered == Some(*c)
    }

    fn recover_proven_challenge<G: Group>(
        claim: &Claim<G>,
        proof: &ProofResponse<G>,
    ) -> Option<G::Scalar> {
        match (claim, proof) {
            (Leaf(statements), Leaf((c, transcripts))) => {
                if statements.iter().zip(transcripts.iter()).all(|(statement, (r, t))| statement.verify(r, t, c)) {
                    Some(*c)
                } else {
                    None
                }
            }
            (And(nodes), And(proofs)) => {
                let mut candidate: Option<G::Scalar> = None;

                for (node, proof) in nodes.iter().zip(proofs.iter()) {
                    let c = Self::recover_proven_challenge(node, proof)?;

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
                    let c = Self::recover_proven_challenge(node, proof)?;

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
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::zkp::_test_utils::{create_elgamal_enc0_and_enc1, create_elgamal_enc1_reenc_statements, proof_claims};
    use rand::thread_rng;

    type Curve = RistrettoGroup;

    #[test]
    fn check_composition() {
        let mut rng = thread_rng();

        let (pk, (uv, _), (uv_enc1, r_enc1)) = create_elgamal_enc0_and_enc1(&mut rng);
        let ((zkp_enc1_u, zkp_enc1_v), (zkp_rerand_u, zkp_rerand_v)) = create_elgamal_enc1_reenc_statements(pk, uv, uv_enc1);

        /*
        compositions checked:
        - And with Or, Leaf, And inside (all resolving to true)
        - Or with Leaf, And, Or inside (both true and false)
        - Leaf, And, Or with 1 and 1+ statement(s) true
        - Or with 1 and 1+ statement(s) false
        - And, Or with simulated subtree
        */
        let claim: Claim<Curve> = And(vec![
            Leaf(Box::new([zkp_enc1_u.clone(), zkp_enc1_v.clone()])),
            And(vec![Leaf(Box::new([zkp_enc1_u.clone(), zkp_enc1_v.clone()]))]),
            Or(vec![
                Leaf(Box::new([zkp_enc1_u.clone()])),                                    // true
                Leaf(Box::new([zkp_rerand_u.clone()])),                                  // false
                Or(vec![Leaf(Box::new([zkp_enc1_u.clone()]))]),                          // true
                Or(vec![Leaf(Box::new([zkp_rerand_u.clone()]))]),                        // false
                And(vec![Leaf(Box::new([zkp_enc1_u.clone()]))]),                         // true
                And(vec![Leaf(Box::new([zkp_rerand_u.clone(), zkp_rerand_v.clone()]))]), // false
            ]),
        ]);
        let knowledge: Knowledge<Curve> = And(vec![
            Leaf(Some(r_enc1)),
            And(vec![Leaf(Some(r_enc1))]),
            Or(vec![
                Leaf(Some(r_enc1)),
                Leaf(None),
                Or(vec![Leaf(Some(r_enc1))]),
                Leaf(None),
                And(vec![Leaf(Some(r_enc1))]),
                Leaf(None),
            ]),
        ]);

        proof_claims(&mut rng, claim, knowledge);
    }
}

// endregion: --- Tests
