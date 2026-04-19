use crate::foundation::group::Group;
use crate::primitives::zkp::composite::BooleanTree::{And, Leaf, Or};
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
        claim: &Claim<G>,
        knowledge: &Knowledge<G>,
        rng: &mut R,
    ) -> PreparedProof<G> {
        match claim {
            Leaf(statements) => {
                assert!(matches!(knowledge, Leaf(Some(_))));

                let committed = Self::commit(statements, rng);

                Leaf((Some(committed), None))
            }
            And(nodes) => {
                if let And(knowledge_nodes) = knowledge {
                    let committed = nodes
                        .iter()
                        .zip(knowledge_nodes.iter())
                        .map(|(node, knowledge_node)| Self::prepare(node, knowledge_node, rng))
                        .collect();

                    And(committed)
                } else {
                    unreachable!("proof and knowledge trees not synchronized")
                }
            }
            Or(nodes) => {
                assert!(matches!(knowledge, Or(_)));
                if let Or(knowledge_nodes) = knowledge {
                    let simulated = nodes
                        .iter()
                        .zip(knowledge_nodes.iter())
                        .map(|(node, knowledge_node)| {
                            if let Leaf(None) = &knowledge_node {
                                let c = G::scalar_random(rng);

                                return Leaf((None, Some(Self::simulate(node, rng, c))));
                            }

                            if let Leaf(statements) = &node {
                                assert!(matches!(knowledge, Leaf(_)));

                                return Leaf((Some(Self::commit(statements, rng)), None));
                            }

                            Self::prepare(node, knowledge_node, rng)
                        })
                        .collect();

                    Or(simulated)
                } else {
                    unreachable!("proof and knowledge trees not synchronized")
                }
            }
        }
    }

    fn commit<G: Group, R: RngCore + CryptoRng>(
        statements: &[Statement<G>],
        rng: &mut R,
    ) -> CommittedProof<G> {
        let committed = statements
            .iter()
            .map(|statement| statement.commit(rng))
            .collect();

        Leaf(committed)
    }

    fn simulate<G: Group, R: RngCore + CryptoRng>(
        proof: &BooleanTree<Box<[Statement<G>]>>,
        rng: &mut R,
        c: G::Scalar,
    ) -> SimulatedProof<G> {
        match proof {
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
                    .map(|node| Self::simulate(node, rng, c))
                    .collect();

                And(simulated)
            }
            Or(nodes) => {
                let c = G::scalar_random(rng);

                let simulated = nodes
                    .iter()
                    .map(|node| Self::simulate(node, rng, c))
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
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::foundation::group::{ByteSerialize, Group};
    use crate::foundation::hash::{ContextAwareHash, VectorContextHash};
    use crate::primitives::encryption::el_gamal::{ElGamal, ExponentialElGamal};
    use rand::thread_rng;

    type Curve = RistrettoGroup;

    type Scalar = <RistrettoGroup as Group>::Scalar;
    type Point = <RistrettoGroup as Group>::Point;

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
        let prepared_proof = ZeroKnowledgeProof::prepare(&claim, &knowledge, &mut rng);

        assert!(matches!(prepared_proof, Or(_)));
        if let Or(nodes) = prepared_proof {
            assert_eq!(nodes.len(), 2);
            assert!(matches!(nodes[0], Leaf(_)));
            assert!(matches!(nodes[1], Leaf(_)));
        } else {
            unreachable!()
        }
    }

    #[test]
    fn proof_complex_statement() {
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
        let mut context = VectorContextHash::<Curve>::new(vec![u, v, u_dash, v_dash]);

        // enc proof (simulated)
        let zkp_enc1_u = Statement::<Curve>::new(Curve::basepoint(), u_dash);
        let zkp_enc1_v = Statement::<Curve>::new(pk, v_dash - Curve::basepoint());
        let c1 = Curve::scalar_random(&mut rng);
        let (r_enc1_u, t_enc1_u) = zkp_enc1_u.simulate(&mut rng, &c1);
        let (r_enc1_v, t_enc1_v) = zkp_enc1_v.simulate(&mut rng, &c1);
        context.add_context(&t_enc1_u);
        context.add_context(&t_enc1_v);

        // rerand proof (true)
        let zkp_rerand_u = Statement::<Curve>::new(Curve::basepoint(), u_dash - u);
        let zkp_rerand_v = Statement::<Curve>::new(pk, v_dash - v);
        let (k_rerand_u, t_rerand_u) = zkp_rerand_u.commit(&mut rng);
        let (k_rerand_v, t_rerand_v) = zkp_rerand_v.commit(&mut rng);
        context.add_context(&t_rerand_u);
        context.add_context(&t_rerand_v);

        let c = context.hash();
        let c2 = c - c1;

        let r_rerand_u = zkp_rerand_u.proof(&k_rerand_u, &r2, &c2);
        let r_rerand_v = zkp_rerand_v.proof(&k_rerand_v, &r2, &c2);

        assert!(zkp_enc1_u.verify(&r_enc1_u, &t_enc1_u, &c1));
        assert!(zkp_enc1_v.verify(&r_enc1_v, &t_enc1_v, &c1));

        assert!(zkp_rerand_u.verify(&r_rerand_u, &t_rerand_u, &c2));
        assert!(zkp_rerand_v.verify(&r_rerand_v, &t_rerand_v, &c2));
    }

    #[test]
    fn proof_complex_statement_2() {
        let mut rng = thread_rng();

        let el_gamal = ElGamal::<Curve>::default();
        let exponential_el_gamal = ExponentialElGamal(el_gamal);
        let sk = exponential_el_gamal.0.generate_secret_key(&mut rng);
        let pk = exponential_el_gamal.0.derive_public_key(&sk);

        // encrypt 0
        let r = Scalar::random(&mut rng);
        let (u, v) = exponential_el_gamal.encrypt(&pk, &r, &Scalar::ZERO);

        // encrypt 1
        let r2 = Scalar::random(&mut rng);
        let (u_dash, v_dash) = exponential_el_gamal.encrypt(&pk, &r2, &Scalar::ONE);
        let mut context = VectorContextHash::<Curve>::new(vec![u, v, u_dash, v_dash]);

        // enc proof (true)
        let zkp_enc1_u = Statement::<Curve>::new(Curve::basepoint(), u_dash);
        let zkp_enc1_v = Statement::<Curve>::new(pk, v_dash - Curve::basepoint());
        let (k_enc1_u, t_enc1_u) = zkp_enc1_u.commit(&mut rng);
        let (k_enc1_v, t_enc1_v) = zkp_enc1_v.commit(&mut rng);
        context.add_context(&t_enc1_u);
        context.add_context(&t_enc1_v);

        // rerand proof (true)
        let zkp_rerand_u = Statement::<Curve>::new(Curve::basepoint(), u_dash - u);
        let zkp_rerand_v = Statement::<Curve>::new(pk, v_dash - v);
        let c2 = Curve::scalar_random(&mut rng);
        let (r_rerand_u, t_rerand_u) = zkp_rerand_u.simulate(&mut rng, &c2);
        let (r_rerand_v, t_rerand_v) = zkp_rerand_v.simulate(&mut rng, &c2);
        context.add_context(&t_rerand_u);
        context.add_context(&t_rerand_v);

        let c = context.hash();
        let c1 = c - c2;

        let r_enc1_u = zkp_enc1_u.proof(&k_enc1_u, &r2, &c1);
        let r_enc1_v = zkp_enc1_v.proof(&k_enc1_v, &r2, &c1);

        assert!(zkp_enc1_u.verify(&r_enc1_u, &t_enc1_u, &c1));
        assert!(zkp_enc1_v.verify(&r_enc1_v, &t_enc1_v, &c1));

        assert!(zkp_rerand_u.verify(&r_rerand_u, &t_rerand_u, &c2));
        assert!(zkp_rerand_v.verify(&r_rerand_v, &t_rerand_v, &c2));
    }
}

// endregion: --- Tests
