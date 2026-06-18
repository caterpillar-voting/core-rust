pub mod foundation;
pub mod primitives;
mod utils;

#[cfg(test)]
mod tests {
    use crate::foundation::discrete_log::BruteForceDiscreteLog;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::foundation::hash::VectorContextHash;
    use crate::primitives::commitment::Commitment;
    use crate::primitives::encryption::Encryption;
    use crate::primitives::encryption::el_gamal::{ElGamal, ExponentialElGamal};
    use crate::primitives::zkp::proof::{Claim, Knowledge};
    use crate::primitives::zkp::proof_builder::el_gamal::{EncProofBuilder, ReEncProofBuilder};
    use crate::primitives::zkp::representation::SecretKnowledge;
    use crate::primitives::zkp::{NIZKProof, ZKProof};
    use crate::utils::tree::BooleanTree::Or;
    use rand::thread_rng;

    type Curve = RistrettoGroup;
    type Scalar = <RistrettoGroup as Group>::Scalar;

    #[test]
    fn commitment() {
        let mut rng = thread_rng();

        let commitment = Commitment::<Curve>::default();

        let messages = [Scalar::from(2u64)];
        let (commit, opening) = commitment.commit(&mut rng, &messages);

        assert!(commitment.open(&messages, &commit, &opening));
    }

    #[test]
    fn encryption() {
        let mut rng = thread_rng();
        let message = Curve::point_random(&mut rng);

        let encryption = Encryption::<Curve>::default();
        let (secret_key, public_key) = encryption.key_gen(&mut rng);

        let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
        let message_recovered = encryption.decrypt(&secret_key, &ciphertext);

        assert_eq!(message_recovered, Some(message));
    }

    #[test]
    fn homomorphic_encrypt_and_decrypt() {
        let mut rng = thread_rng();
        let message = Scalar::from(1u64);

        let el_gamal = ExponentialElGamal::<Curve>::default();
        let secret_key = el_gamal.0.generate_secret_key(&mut rng);
        let public_key = el_gamal.0.derive_public_key(&secret_key);

        let ciphertext = el_gamal.encrypt(&public_key, &Curve::scalar_random(&mut rng), &message);
        let ciphertext_reencrypted = el_gamal.0.reencrypt(&public_key, &Curve::scalar_random(&mut rng), &ciphertext);
        let ciphertext_aggregated = (ciphertext_reencrypted.0 + ciphertext.0, ciphertext_reencrypted.1 + ciphertext.1);

        let message_decoder = BruteForceDiscreteLog::<Curve>::new(Scalar::from(2u64), None);
        let decoded = el_gamal.decrypt(&secret_key, &ciphertext_aggregated, &message_decoder);

        assert_eq!(decoded, Some(Scalar::from(2u64)));
    }

    #[test]
    fn zk_proof() {
        let mut rng = thread_rng();
        let message = Curve::point_random(&mut rng);

        let el_gamal = ElGamal::<Curve>::default();
        let secret_key = el_gamal.generate_secret_key(&mut rng);
        let public_key = el_gamal.derive_public_key(&secret_key);

        let ciphertext = el_gamal.encrypt(&public_key, &Curve::scalar_random(&mut rng), &message);
        let randomness = Curve::scalar_random(&mut rng);
        let ciphertext_dash = el_gamal.reencrypt(&public_key, &randomness, &ciphertext);

        let claim = ReEncProofBuilder::build_claim::<Curve>(public_key, ciphertext, ciphertext_dash);
        let zk_proof = ZKProof { claim };

        let knowledge = ReEncProofBuilder::build_knowledge::<Curve>(Some(randomness));
        let secret_knowledge = SecretKnowledge(knowledge);

        let proof_preparation = zk_proof.commit(&mut rng, &secret_knowledge);
        let c = Curve::scalar_random(&mut rng);
        let proof = zk_proof.response(&mut rng, &proof_preparation, &secret_knowledge, &c);

        assert!(zk_proof.verify(&proof, &c))
    }

    #[test]
    fn nizk_proof() {
        let mut rng = thread_rng();
        let message1 = Curve::point_random(&mut rng);
        let message2 = Curve::point_random(&mut rng);

        let el_gamal = ElGamal::<Curve>::default();
        let secret_key = el_gamal.generate_secret_key(&mut rng);
        let public_key = el_gamal.derive_public_key(&secret_key);

        let randomness = Curve::scalar_random(&mut rng);
        let ciphertext = el_gamal.encrypt(&public_key, &randomness, &message1);

        let claim1 = EncProofBuilder::build_claim::<Curve>(public_key, ciphertext, message1);
        let claim2 = EncProofBuilder::build_claim::<Curve>(public_key, ciphertext, message2);
        let claim: Claim<Curve> = Or(vec![claim1, claim2]);

        let context_hash = VectorContextHash::new(b"Example".into());
        let nizkp = NIZKProof::new(claim, context_hash);

        let knowledge1 = ReEncProofBuilder::build_knowledge::<Curve>(Some(randomness));
        let knowledge2 = ReEncProofBuilder::build_knowledge::<Curve>(None);
        let knowledge: Knowledge<Curve> = Or(vec![knowledge1, knowledge2]);
        let proof = nizkp.prove(&mut rng, &SecretKnowledge(knowledge));

        assert!(nizkp.verify(&proof))
    }
}
