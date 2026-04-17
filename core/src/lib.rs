pub mod foundation;
pub mod primitives;

#[cfg(test)]
mod tests {
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::foundation::representation::{EncodedMessage, Message};
    use crate::primitives::commitment::CommitmentHiding;
    use crate::primitives::encryption::{Encryption, EncryptionHomomorph};
    use rand::thread_rng;
    use crate::foundation::discrete_log::GreedyDiscreteLog;

    type Curve = RistrettoGroup;
    type Scalar = <RistrettoGroup as Group>::Scalar;

    #[test]
    fn commitment() {
        let mut rng = thread_rng();

        let hiding_commitment = CommitmentHiding::<Curve>::new();

        let messages = [Message::<Curve>::new(Scalar::from(2u8))];
        let (commitment, randomness) = hiding_commitment.commit(&mut rng, &messages);

        assert!(hiding_commitment.open(&messages, &commitment, &randomness));
    }

    #[test]
    fn encryption() {
        let mut rng = thread_rng();
        let message = EncodedMessage::new(Curve::point_random(&mut rng));

        let encryption = Encryption::<Curve>::default();
        let (secret_key, public_key) = encryption.key_gen(&mut rng);

        let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
        let message_recovered = encryption.decrypt(&secret_key, &ciphertext);

        assert_eq!(message_recovered, message);
    }

    #[test]
    fn encryption_homomorph() {
        let mut rng = thread_rng();
        let message = Message::new(Scalar::from(2u8));
        let message_sum = &message + &message;
        let message_range = (Scalar::from(4u8), Scalar::from(4u8));
        let decoder = GreedyDiscreteLog::new(&message_range);

        let encryption = EncryptionHomomorph::<Curve>::default();
        let (secret_key, public_key) = encryption.key_gen(&mut rng);

        let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
        let ciphertext_sum = &ciphertext + &ciphertext;
        let message_recovered = encryption.decrypt(&secret_key, &ciphertext_sum, &decoder);

        assert_eq!(message_recovered, Some(message_sum));
    }
}
