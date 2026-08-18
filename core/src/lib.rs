extern crate core;

pub mod foundation;
pub mod primitives;
mod utils;

#[cfg(test)]
mod tests {
    use crate::foundation::discrete_log::BruteForceDiscreteLog;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::commitment::Commitment;
    use crate::primitives::encryption::Encryption;
    use crate::primitives::encryption::el_gamal::ExponentialElGamal;
    use rand::thread_rng;

    type Curve = RistrettoGroup;
    type Scalar = <RistrettoGroup as Group>::Scalar;

    #[test]
    fn commitment() {
        let mut rng = thread_rng();

        let commitment = Commitment::<Curve>::default();

        let messages = vec![Scalar::from(2u64)];
        let (commit, opening) = commitment.commit(&mut rng, &messages);

        assert!(commitment.open(&messages, &commit, &opening));
    }

    #[test]
    fn encryption() {
        let mut rng = thread_rng();
        let message = Curve::point_random(&mut rng);

        let encryption = Encryption::<Curve>::default();
        let (secret_key, public_key) = encryption.key_gen(&mut rng);

        let ctx = "test_encrypt".as_bytes().to_vec();
        let ciphertext = encryption.encrypt(&public_key, &ctx, &mut rng, &message);
        let message_recovered = encryption.decrypt(&ctx, &secret_key, &ciphertext);

        assert_eq!(message_recovered, Some(message));
    }

    #[test]
    fn homomorphic_encrypt_and_decrypt() {
        let mut rng = thread_rng();
        let message = Scalar::from(1u64);

        let el_gamal = ExponentialElGamal::default();
        let secret_key = el_gamal.0.generate_secret_key(&mut rng);
        let public_key = el_gamal.0.derive_public_key(&secret_key);

        let ciphertext = el_gamal.encrypt(&public_key, &Curve::scalar_random(&mut rng), &message);
        let ciphertext_reencrypted = el_gamal.0.reencrypt(&public_key, &Curve::scalar_random(&mut rng), &ciphertext);
        let ciphertext_aggregated = (ciphertext_reencrypted.0 + &ciphertext.0, ciphertext_reencrypted.1 + &ciphertext.1);

        let message_decoder = BruteForceDiscreteLog::<Curve>::new(Scalar::from(2u64), None);
        let decoded = el_gamal.decrypt(&secret_key, &ciphertext_aggregated, &message_decoder);

        assert_eq!(decoded, Some(Scalar::from(2u64)));
    }
}
