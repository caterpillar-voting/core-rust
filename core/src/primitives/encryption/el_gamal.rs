use crate::foundation::group::Group;

/// A Pedersen commitment: `C = [r]H + Σ [mᵢ]Gᵢ`.
#[derive(Clone, Debug, PartialEq)]
pub struct ElGamal<G: Group> {
    generator: G::Point, // blinding base
}

impl<G: Group> ElGamal<G> {
    pub fn new(point: G::Point) -> Self {
        Self { generator: point }
    }

    pub fn generator(&self) -> &G::Point {
        &self.generator
    }

    pub fn encrypt(
        &self,
        public_key: &G::Point,
        randomness: &G::Scalar,
        message: &G::Point,
    ) -> (G::Point, G::Point) {
        let alpha = self.generator * randomness;
        let beta = *public_key * randomness + message;

        (alpha, beta)
    }

    pub fn decrypt(&self, secret_key: &G::Scalar, ciphertext: (&G::Point, &G::Point)) -> G::Point {
        let (alpha, beta) = ciphertext;

        *beta - &(*alpha * secret_key)
    }

    pub fn decrypt_randomness(
        &self,
        public_key: &G::Point,
        randomness: &G::Scalar,
        ciphertext: (&G::Point, &G::Point),
    ) -> G::Point {
        let (_, beta) = ciphertext;
        let hiding_factor = *public_key * randomness;

        *beta - &hiding_factor
    }

    pub fn reencrypt(
        &self,
        public_key: &G::Point,
        randomness: &G::Scalar,
        ciphertext: (&G::Point, &G::Point),
    ) -> (G::Point, G::Point) {
        let (alpha, beta) = ciphertext;

        let alpha = self.generator * randomness + alpha;
        let beta = *public_key * randomness + beta;

        (alpha, beta)
    }

    // todo: add homomorph op; same for exponential_el_gamal
}

// region: --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use rand::{SeedableRng, rngs::StdRng};

    type Curve = RistrettoGroup;

    fn seeded_rng() -> StdRng {
        let mut seed = [0u8; 32];
        seed[..5].copy_from_slice(b"hello");
        StdRng::from_seed(seed)
    }

    fn new_el_gamal(rng: &mut StdRng) -> ElGamal<Curve> {
        let point = Curve::point_random(rng);
        ElGamal::new(point)
    }

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng = seeded_rng();
        let el_gamal = new_el_gamal(&mut rng);

        let secret_key = Curve::scalar_random(&mut rng);
        let public_key = el_gamal.generator * &secret_key;
        let randomness = Curve::scalar_random(&mut rng);
        let message = Curve::point_random(&mut rng);

        let ciphertext = el_gamal.encrypt(&public_key, &randomness, &message);
        let decrypted = el_gamal.decrypt(&secret_key, (&ciphertext.0, &ciphertext.1));

        assert_eq!(decrypted, message);
    }

    #[test]
    fn encrypt_and_decrypt_randomness() {
        let mut rng = seeded_rng();
        let el_gamal = new_el_gamal(&mut rng);

        let secret_key = Curve::scalar_random(&mut rng);
        let public_key = el_gamal.generator * &secret_key;
        let randomness = Curve::scalar_random(&mut rng);
        let message = Curve::point_random(&mut rng);

        let ciphertext = el_gamal.encrypt(&public_key, &randomness, &message);
        let decrypted =
            el_gamal.decrypt_randomness(&public_key, &randomness, (&ciphertext.0, &ciphertext.1));

        assert_eq!(decrypted, message);
    }

    #[test]
    fn reencrypt_and_decrypt() {
        let mut rng = seeded_rng();
        let el_gamal = new_el_gamal(&mut rng);

        let secret_key = Curve::scalar_random(&mut rng);
        let public_key = el_gamal.generator * &secret_key;
        let randomness = Curve::scalar_random(&mut rng);
        let message = Curve::point_random(&mut rng);

        let ciphertext = el_gamal.encrypt(&public_key, &randomness, &message);

        let extra_randomness = Curve::scalar_random(&mut rng);
        let reencrypted = el_gamal.reencrypt(
            &public_key,
            &extra_randomness,
            (&ciphertext.0, &ciphertext.1),
        );

        let decrypted = el_gamal.decrypt(&secret_key, (&reencrypted.0, &reencrypted.1));

        assert_eq!(decrypted, message);
    }

    #[test]
    fn reencrypt_and_decrypt_randomness() {
        let mut rng = seeded_rng();
        let el_gamal = new_el_gamal(&mut rng);

        let secret_key = Curve::scalar_random(&mut rng);
        let public_key = el_gamal.generator * &secret_key;
        let randomness = Curve::scalar_random(&mut rng);
        let message = Curve::point_random(&mut rng);

        let ciphertext = el_gamal.encrypt(&public_key, &randomness, &message);

        let extra_randomness = Curve::scalar_random(&mut rng);
        let reencrypted = el_gamal.reencrypt(
            &public_key,
            &extra_randomness,
            (&ciphertext.0, &ciphertext.1),
        );

        let combined_randomness = randomness + &extra_randomness;
        let decrypted = el_gamal.decrypt_randomness(
            &public_key,
            &combined_randomness,
            (&reencrypted.0, &reencrypted.1),
        );

        assert_eq!(decrypted, message);
    }
}

// endregion: --- Tests
