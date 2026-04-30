pub mod foundation;
pub mod primitives;
mod utils;

#[cfg(test)]
mod tests {
    use crate::foundation::discrete_log::GreedyDiscreteLog;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::foundation::hash::VectorContextHash;
    use crate::primitives::commitment::HHomomorphicCommitment;
    use crate::primitives::encryption::{Encryption, EncryptionHomomorph};
    use crate::primitives::zkp::proof_builder::TreeProofBuilder;
    use crate::primitives::zkp::proof_builder::el_gamal::{EncProofBuilder, ReEncProofBuilder};
    use crate::primitives::zkp::{NIZKProof, ZKProof};
    use crate::utils::tree::BooleanTree::{Leaf, Or};
    use rand::thread_rng;

    type Curve = RistrettoGroup;
    type Scalar = <RistrettoGroup as Group>::Scalar;

    #[test]
    fn commitment() {
        let mut rng = thread_rng();

        let homomorphic_commitment = HHomomorphicCommitment::<Curve>::default();

        let messages = [Scalar::from(2u8)];
        let (commitment, opening) = homomorphic_commitment.commit(&mut rng, &messages);

        assert!(homomorphic_commitment.open(&messages, &commitment, &opening));
    }

    #[test]
    fn encryption() {
        let mut rng = thread_rng();
        let message = Curve::point_random(&mut rng);

        let encryption = Encryption::<Curve>::default();
        let (secret_key, public_key) = encryption.key_gen(&mut rng);

        let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
        let message_recovered = encryption.decrypt(&secret_key, &ciphertext);

        assert_eq!(message_recovered, message);
    }

    #[test]
    fn encryption_homomorph() {
        let mut rng = thread_rng();
        let message = Scalar::from(2u8);
        let message_sum = &message + &message;
        let decoder = GreedyDiscreteLog::new(Scalar::from(4u8), None);

        let encryption = EncryptionHomomorph::<Curve>::default();
        let (secret_key, public_key) = encryption.key_gen(&mut rng);

        let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
        let ciphertext_sum = &ciphertext + &ciphertext;
        let message_recovered = encryption.decrypt(&secret_key, &ciphertext_sum, &decoder);

        assert_eq!(message_recovered, Some(message_sum));
    }

    #[test]
    fn zk_proof() {
        let mut rng = thread_rng();
        let message = Curve::point_random(&mut rng);

        let encryption = Encryption::<Curve>::default();
        let (_, public_key) = encryption.key_gen(&mut rng);

        let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
        let randomness = Curve::scalar_random(&mut rng);
        let ciphertext_dash = encryption.el_gamal.reencrypt(&public_key, &randomness, &ciphertext);

        let re_enc = ReEncProofBuilder::<Curve>::new(public_key, ciphertext, ciphertext_dash, Some(randomness));
        let (zk_proof, knowledge) = ZKProof::from_builder(&re_enc);

        let proof_preparation = zk_proof.commit(&mut rng, &knowledge);
        let c = Curve::scalar_random(&mut rng);
        let proof = zk_proof.response(&mut rng, &proof_preparation, &knowledge, &c);

        assert!(zk_proof.verify(&proof, &c))
    }

    #[test]
    fn nizk_proof() {
        let mut rng = thread_rng();
        let message1 = Curve::point_random(&mut rng);
        let message2 = Curve::point_random(&mut rng);

        let encryption = Encryption::<Curve>::default();
        let (_, public_key) = encryption.key_gen(&mut rng);

        let randomness = Curve::scalar_random(&mut rng);
        let ciphertext = encryption.el_gamal.encrypt(&public_key, &randomness, &message1);

        let enc1 = EncProofBuilder::<Curve>::new(public_key, ciphertext, message1, Some(randomness));
        let enc2 = EncProofBuilder::<Curve>::new(public_key, ciphertext, message2, None);
        let tree: TreeProofBuilder<Curve> = Or(vec![Leaf(&enc1), Leaf(&enc2)]);
        let (zk_proof, knowledge) = ZKProof::from_builder(&tree);

        let context_hash = VectorContextHash::new(b"Example".into());
        let nizkp = NIZKProof::new(zk_proof, context_hash);
        let proof = nizkp.prove(&mut rng, &knowledge);

        assert!(nizkp.verify(&proof))
    }
}
