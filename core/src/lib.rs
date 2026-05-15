pub mod foundation;
pub mod primitives;
mod utils;

#[cfg(test)]
mod tests {
    use crate::foundation::discrete_log::{DiscreteLog, GreedyDiscreteLog};
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::foundation::hash::VectorContextHash;
    use crate::primitives::commitment::HHomomorphicCommitment;
    use crate::primitives::encryption::Encryption;
    use crate::primitives::encryption::el_gamal::ElGamal;
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

        assert_eq!(message_recovered, Some(message));
    }

    #[test]
    fn homomorphic_encrypt_and_decrypt() {
        let mut rng = thread_rng();
        let encoded_message = Curve::basepoint() * Scalar::from(1u8);
        let message_2 = Scalar::from(2u8);
        let message_decoder = GreedyDiscreteLog::<Curve>::new(Scalar::from(2u8), None);

        let el_gamal = ElGamal::<Curve>::default();
        let secret_key = el_gamal.generate_secret_key(&mut rng);
        let public_key = el_gamal.derive_public_key(&secret_key);

        let ciphertext = el_gamal.encrypt(&public_key, &Curve::scalar_random(&mut rng), &encoded_message);
        let ciphertext_reencrypted = el_gamal.reencrypt(&public_key, &Curve::scalar_random(&mut rng), &ciphertext);
        let ciphertext_2 = (ciphertext_reencrypted.0 + ciphertext.0, ciphertext_reencrypted.1 + ciphertext.1);
        let decrypted = el_gamal.decrypt(&secret_key, &ciphertext_2);
        let decoded = message_decoder.log(&Curve::basepoint(), &decrypted);

        assert_eq!(decoded, Some(message_2));
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
        let knowledge = ReEncProofBuilder::build_knowledge::<Curve>(Some(randomness));

        let zk_proof = ZKProof { claim };

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
