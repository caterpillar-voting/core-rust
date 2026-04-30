use crate::foundation::group::Group;
use crate::foundation::group::ristretto::RistrettoGroup;
use crate::primitives::encryption::el_gamal::{ElGamal, ExponentialElGamal};
use crate::primitives::zkp::proof::{Claim, Knowledge, Proof};
use crate::primitives::zkp::statement::Statement;
use rand_core::{CryptoRng, RngCore};

type Curve = RistrettoGroup;

type Scalar = <RistrettoGroup as Group>::Scalar;
type Point = <RistrettoGroup as Group>::Point;

pub fn create_elgamal_enc0_and_enc1<R: RngCore + CryptoRng>(rng: &mut R) -> (Point, ((Point, Point), Scalar), ((Point, Point), Scalar)) {
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

    (pk, ((u, v), r), ((u_enc1, v_enc1), r_enc1))
}

pub fn create_elgamal_enc1_reenc_statements(pk: Point, (u, v): (Point, Point), (u_dash, v_dash): (Point, Point)) -> ((Statement<Curve>, Statement<Curve>), (Statement<Curve>, Statement<Curve>)) {
    let zkp_enc1_u = Statement::<Curve>::new(Curve::basepoint(), u_dash);
    let zkp_enc1_v = Statement::<Curve>::new(pk, v_dash - Curve::basepoint());
    let zkp_rerand_u = Statement::<Curve>::new(Curve::basepoint(), u_dash - u);
    let zkp_rerand_v = Statement::<Curve>::new(pk, v_dash - v);

    ((zkp_enc1_u, zkp_enc1_v), (zkp_rerand_u, zkp_rerand_v))
}

pub fn proof_claims<R: RngCore + CryptoRng>(
    rng: &mut R,
    claim: Claim<Curve>,
    knowledge: Knowledge<Curve>,
) {
    let commit = Proof::commit(rng, &claim, &knowledge);
    let challenge = Scalar::random(rng);
    let response = Proof::response(rng, &commit, &claim, &knowledge, &challenge);

    assert!(Proof::verify(&claim, &response, &challenge))
}
