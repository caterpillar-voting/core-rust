pub mod enc;
pub mod or;
pub mod reenc;

use crate::foundation::group::Group;
use rand_core::{CryptoRng, RngCore};

pub trait ZKP<G: Group> {
    type PublicData;
    type Witness;
    type Context;
    type Proof;
    fn prove<R: RngCore + CryptoRng>(&self, witness: &Self::Witness, rng: &mut R) -> Self::Proof;
    fn verify(&self, proof: &Self::Proof) -> bool;
}

// We force the type of Challenge to be the same as the Scalar type of the group G
pub type Challenge<G> = <G as Group>::Scalar;

pub trait SigmaZKP<G: Group>: ZKP<G> {
    type Commit; // The data sent by Prover in first step
    // type Challenge; // The data sent by Verifier in second step
    type Response; // The data sent by Prover in third step
    type State: Clone + Copy; // The data kept by Prover between steps
    fn commit<R: RngCore + CryptoRng>(&self, witness: &Self::Witness, rng: &mut R) -> (Self::Commit, Self::State);
    fn get_challenge(&self, commit: &Self::Commit) -> Challenge<G>;
    fn respond(&self, state: &Self::State, challenge: &Challenge<G>) -> Self::Response;
    // The following function is used to verify a transcript of an interactive session,
    // where the challenge is sent by the verifier, and not computed as a hash.
    fn interactive_verify(&self, commit: &Self::Commit, challenge: &Challenge<G>, response: &Self::Response) -> bool;
}

pub trait SimulableZKP<G: Group>: SigmaZKP<G> {
    fn simulate<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Self::Proof;
}

#[cfg(test)]
mod tests {
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::encryption::el_gamal::ElGamal;
    use crate::primitives::zkp2::ZKP;
    use crate::primitives::zkp2::or::{OrTwoReEncZKP, OrTwoReEncZKPWitness};
    use crate::primitives::zkp2::reenc::ReEncZKP;
    use rand::thread_rng;

    type Curve = RistrettoGroup;

    #[test]
    fn or_proof() {
        let mut rng = thread_rng();

        // Generate two public keys
        let el_gamal = ElGamal::<Curve>::default();
        let sk1 = el_gamal.generate_secret_key(&mut rng);
        let pk1 = el_gamal.derive_public_key(&sk1);
        let sk2 = el_gamal.generate_secret_key(&mut rng);
        let pk2 = el_gamal.derive_public_key(&sk2);

        // Generate two encrypted messages for these two keys
        let m1 = Curve::point_random(&mut rng);
        let r1 = Curve::scalar_random(&mut rng);
        let enc_m1 = el_gamal.encrypt(&pk1, &r1, &m1);
        let m2 = Curve::point_random(&mut rng);
        let r2 = Curve::scalar_random(&mut rng);
        let enc_m2 = el_gamal.encrypt(&pk2, &r2, &m2);

        // From here, we know only pk1, pk2, enc_m1, enc_m2

        // Generate two re_encryptions
        let s1 = Curve::scalar_random(&mut rng);
        let reenc_m1 = el_gamal.reencrypt(&pk1, &s1, &enc_m1);
        let s2 = Curve::scalar_random(&mut rng);
        let reenc_m2 = el_gamal.reencrypt(&pk2, &s2, &enc_m2);

        // A ZKP that I know either s1 or s2 (s2 in that case)
        let ctx1 = b"first_renc".to_vec();
        let zkp1: ReEncZKP<Curve> = ReEncZKP::new(pk1, enc_m1, reenc_m1, ctx1);
        let ctx2 = b"second_renc".to_vec();
        let zkp2: ReEncZKP<Curve> = ReEncZKP::new(pk2, enc_m2, reenc_m2, ctx2);
        let ctx = b"or_proof".to_vec();
        let zkp_or = OrTwoReEncZKP::new(zkp1, zkp2, ctx);

        let witness = OrTwoReEncZKPWitness {
            zkp1_witness: None,
            zkp2_witness: Some(s2),
        };
        let proof = zkp_or.prove(&witness, &mut rng);
        assert!(zkp_or.verify(&proof));
    }
}
