use crate::foundation::group::Group;
use crate::foundation::hash::ContextAwareHash;
use crate::primitives::zkp::zkp::BooleanTree::{And, Leaf, Or};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, PartialEq)]
pub struct Statement<G: Group> {
    g: G::Point,
    z: G::Point,
}

/// https://crypto.ethz.ch/publications/files/Maurer09.pdf
impl<G: Group> Statement<G> {
    pub fn new(g: G::Point, z: G::Point) -> Self {
        Self { g, z }
    }

    pub fn commit<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (G::Scalar, G::Point) {
        let k = G::scalar_random(rng);
        let t = self.g * &k;

        (k, t)
    }

    pub fn proof(&self, k: &G::Scalar, c: &G::Scalar, x: &G::Scalar) -> G::Scalar {
        let r = *k + &(*c * x);

        r
    }

    pub fn verify(&self, r: &G::Scalar, t: &G::Point, c: &G::Scalar) -> bool {
        let left = self.g * r;
        let right = *t + &(self.z * c);

        left == right
    }

    pub fn simulate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        c: &G::Scalar,
    ) -> (G::Scalar, G::Point) {
        let r = G::scalar_random(rng);

        let t = self.g * &r - &(self.z * &c);

        (r, t)
    }
}

pub enum BooleanTree<T> {
    Leaf(T),
    And(Vec<BooleanTree<T>>),
    Or(Vec<BooleanTree<T>>),
}

pub struct ZeroKnowledgeProof<G: Group> {
    proof: BooleanTree<Box<[Statement<G>]>>,
}

type Knowledge<G: Group> = BooleanTree<Option<G::Scalar>>;
type CommittedProof<G: Group> = BooleanTree<Box<[(G::Scalar, G::Point)]>>;
type SimulatedProof<G: Group> = BooleanTree<(G::Scalar, Box<[(G::Scalar, G::Point)]>)>;
type PreparedProof<G: Group> = BooleanTree<(Option<CommittedProof<G>>, Option<SimulatedProof<G>>)>;

pub struct Proof<G: Group>(pub BooleanTree<Option<G::Scalar>>);

/// https://crypto.ethz.ch/publications/files/Maurer09.pdf
impl<G: Group> ZeroKnowledgeProof<G> {
    pub fn new(proof: BooleanTree<Box<[Statement<G>]>>) -> Self {
        Self { proof }
    }

    pub fn prepare<R: RngCore + CryptoRng>(
        proof: &BooleanTree<Box<[Statement<G>]>>,
        knowledge: &Knowledge<G>,
        rng: &mut R,
    ) -> PreparedProof<G> {
        match proof {
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
                        .map(|(node, knowledge_node)| Self::prepare(node, &knowledge_node, rng))
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

                                return Leaf((None, Some(Self::simulate(node, rng, c))))
                            }

                            // otherwise, I MUST commit, correct?
                            // yes, but inside there might still be a simulated proof...
                            if let Leaf(statements) = &node {
                                assert!(matches!(knowledge, Leaf(_)));

                                return Leaf((Some(Self::commit(statements, rng)), None))
                            }

                            return Self::prepare(node, &knowledge_node, rng);
                        })
                        .collect();

                    Or(simulated)
                } else {
                    unreachable!("proof and knowledge trees not synchronized")
                }
            }
        }
    }

    fn commit<R: RngCore + CryptoRng>(
        statements: &Box<[Statement<G>]>,
        rng: &mut R,
    ) -> CommittedProof<G> {
        let committed = statements
            .iter()
            .map(|statement| statement.commit(rng))
            .collect();

        Leaf(committed)
    }

    fn simulate<R: RngCore + CryptoRng>(
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

    pub fn verify(&self, proof: &Proof<G>, hash: &dyn ContextAwareHash<G>) -> bool {
        false
    }
}

// region: --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::foundation::group::{ByteSerialize, Group};
    use crate::foundation::hash::VectorContextHash;
    use crate::primitives::encryption::el_gamal::{ElGamal, ExponentialElGamal};
    use rand::thread_rng;
    use sha2::Sha512;

    type Curve = RistrettoGroup;

    type Scalar = <RistrettoGroup as Group>::Scalar;
    type Point = <RistrettoGroup as Group>::Point;

    #[test]
    fn proof_statement() {
        let mut rng = thread_rng();
        let x = Scalar::random(&mut rng);
        let z = Curve::basepoint() * x;
        let mut context = VectorContextHash::<Curve>::new(vec![z]);

        let zkp = Statement::<Curve>::new(Curve::basepoint(), z);

        let (k, t) = zkp.commit(&mut rng);
        context.add_context(&t);
        let c = context.hash();

        let r = zkp.proof(&k, &c, &x);
        assert!(zkp.verify(&r, &t, &c));
    }

    #[test]
    fn simulate_statement() {
        let mut rng = thread_rng();
        let z = Point::random(&mut rng);
        let zkp = Statement::<Curve>::new(Curve::basepoint(), z);

        let c = Curve::scalar_random(&mut rng);
        let (r, t) = zkp.simulate(&mut rng, &c);
        assert!(zkp.verify(&r, &t, &c));
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

        let r_rerand_u = zkp_rerand_u.proof(&k_rerand_u, &c2, &r2);
        let r_rerand_v = zkp_rerand_v.proof(&k_rerand_v, &c2, &r2);

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

        let r_enc1_u = zkp_enc1_u.proof(&k_enc1_u, &c1, &r2);
        let r_enc1_v = zkp_enc1_v.proof(&k_enc1_v, &c1, &r2);

        assert!(zkp_enc1_u.verify(&r_enc1_u, &t_enc1_u, &c1));
        assert!(zkp_enc1_v.verify(&r_enc1_v, &t_enc1_v, &c1));

        assert!(zkp_rerand_u.verify(&r_rerand_u, &t_rerand_u, &c2));
        assert!(zkp_rerand_v.verify(&r_rerand_v, &t_rerand_v, &c2));
    }
}

// endregion: --- Tests
