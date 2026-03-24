use crate::foundation::group::Group;

#[derive(Clone, Debug, PartialEq)]
pub struct ElGamal<G: Group> {
    g: G::Point,
}

impl<G: Group> ElGamal<G> {
    pub fn new(g: G::Point) -> Self {
        Self { g }
    }

    pub fn derive_public_key(&self, secret_key: &G::Scalar) -> G::Point {
        self.g * &secret_key
    }

    pub fn encrypt(
        &self,
        pk: &G::Point,
        r: &G::Scalar,
        m: &G::Point,
    ) -> (G::Point, G::Point) {
        let alpha = self.g * r;
        let beta = *pk * r + m;

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

        let alpha = self.g * randomness + alpha;
        let beta = *public_key * randomness + beta;

        (alpha, beta)
    }
}

#[derive(Debug, PartialEq)]
pub struct ExponentialElGamal<G: Group> {
    el_gamal: ElGamal<G>,
}

impl<G: Group> ExponentialElGamal<G> {
    pub fn new(point: G::Point) -> Self {
        let el_gamal = ElGamal::new(point);
        Self { el_gamal }
    }

    pub fn derive_public_key(&self, secret_key: &G::Scalar) -> G::Point {
        self.el_gamal.derive_public_key(&secret_key)
    }

    pub fn encrypt(
        &self,
        public_key: &G::Point,
        randomness: &G::Scalar,
        message: &G::Scalar,
    ) -> (G::Point, G::Point) {
        let message_point = self.el_gamal.g * message;
        self.el_gamal
            .encrypt(public_key, randomness, &message_point)
    }

    pub fn decrypt(
        &self,
        secret_key: &G::Scalar,
        ciphertext: (&G::Point, &G::Point),
        plaintext_range: (&G::Scalar, &G::Scalar),
    ) -> Option<G::Scalar> {
        let message_point = self.el_gamal.decrypt(secret_key, ciphertext);

        self.decode_point(&message_point, plaintext_range)
    }

    pub fn decrypt_randomness(
        &self,
        public_key: &G::Point,
        randomness: &G::Scalar,
        ciphertext: (&G::Point, &G::Point),
        plaintext_range: (&G::Scalar, &G::Scalar),
    ) -> Option<G::Scalar> {
        let message_point = self
            .el_gamal
            .decrypt_randomness(public_key, randomness, ciphertext);

        self.decode_point(&message_point, plaintext_range)
    }

    fn decode_point(
        &self,
        point: &G::Point,
        plaintext_range: (&G::Scalar, &G::Scalar),
    ) -> Option<G::Scalar> {
        let mut current = *plaintext_range.0;
        loop {
            if self.el_gamal.g * &current == *point {
                return Some(current);
            }

            current = current + &G::Scalar::from(1);
        }
    }

    pub fn reencrypt(
        &self,
        public_key: &G::Point,
        randomness: &G::Scalar,
        ciphertext: (&G::Point, &G::Point),
    ) -> (G::Point, G::Point) {
        self.el_gamal.reencrypt(public_key, randomness, ciphertext)
    }
}

// region: --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use rand::{SeedableRng, rngs::StdRng};

    type Curve = RistrettoGroup;

    type Scalar = <RistrettoGroup as Group>::Scalar;

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
        let public_key = el_gamal.g * &secret_key;
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
        let public_key = el_gamal.g * &secret_key;
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
        let public_key = el_gamal.g * &secret_key;
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
        let public_key = el_gamal.g * &secret_key;
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

    fn new_exponential_el_gamal(rng: &mut StdRng) -> ExponentialElGamal<Curve> {
        let point = Curve::point_random(rng);

        ExponentialElGamal::new(point)
    }

    #[test]
    fn exponential_encrypt_and_decrypt() {
        let mut rng = seeded_rng();
        let exponential_el_gamal = new_exponential_el_gamal(&mut rng);

        let secret_key = Curve::scalar_random(&mut rng);
        let public_key = exponential_el_gamal.el_gamal.g * &secret_key;
        let randomness = Curve::scalar_random(&mut rng);
        let message = Scalar::from(1u64);

        let ciphertext = exponential_el_gamal.encrypt(&public_key, &randomness, &message);
        let decrypted = exponential_el_gamal.decrypt(
            &secret_key,
            (&ciphertext.0, &ciphertext.1),
            (&message, &message),
        );

        assert_eq!(decrypted, Some(message));
    }

    #[test]
    fn exponential_encrypt_and_decrypt_randomness() {
        let mut rng = seeded_rng();
        let exponential_el_gamal = new_exponential_el_gamal(&mut rng);

        let secret_key = Curve::scalar_random(&mut rng);
        let public_key = exponential_el_gamal.derive_public_key(&secret_key);
        let randomness = Curve::scalar_random(&mut rng);
        let message = Scalar::from(2u64);

        let ciphertext = exponential_el_gamal.encrypt(&public_key, &randomness, &message);
        let decrypted = exponential_el_gamal.decrypt_randomness(
            &public_key,
            &randomness,
            (&ciphertext.0, &ciphertext.1),
            (&Scalar::from(0u64), &Scalar::from(10u64)),
        );

        assert_eq!(decrypted, Some(message));
    }

    #[test]
    fn exponential_reencrypt_and_decrypt() {
        let mut rng = seeded_rng();
        let exponential_el_gamal = new_exponential_el_gamal(&mut rng);

        let secret_key = Curve::scalar_random(&mut rng);
        let public_key = exponential_el_gamal.derive_public_key(&secret_key);
        let randomness = Curve::scalar_random(&mut rng);
        let message = Scalar::from(3u64);

        let ciphertext = exponential_el_gamal.encrypt(&public_key, &randomness, &message);

        let extra_randomness = Curve::scalar_random(&mut rng);
        let reencrypted = exponential_el_gamal.reencrypt(
            &public_key,
            &extra_randomness,
            (&ciphertext.0, &ciphertext.1),
        );

        let decrypted = exponential_el_gamal.decrypt(
            &secret_key,
            (&reencrypted.0, &reencrypted.1),
            (&Scalar::from(0u64), &Scalar::from(10u64)),
        );

        assert_eq!(decrypted, Some(message));
    }

    #[test]
    fn exponential_reencrypt_and_decrypt_randomness() {
        let mut rng = seeded_rng();
        let exponential_el_gamal = new_exponential_el_gamal(&mut rng);

        let secret_key = Curve::scalar_random(&mut rng);
        let public_key = exponential_el_gamal.derive_public_key(&secret_key);
        let randomness = Curve::scalar_random(&mut rng);
        let message = Scalar::from(4u64);

        let ciphertext = exponential_el_gamal.encrypt(&public_key, &randomness, &message);

        let extra_randomness = Curve::scalar_random(&mut rng);
        let reencrypted = exponential_el_gamal.reencrypt(
            &public_key,
            &extra_randomness,
            (&ciphertext.0, &ciphertext.1),
        );

        let combined_randomness = randomness + &extra_randomness;
        let decrypted = exponential_el_gamal.decrypt_randomness(
            &public_key,
            &combined_randomness,
            (&reencrypted.0, &reencrypted.1),
            (&Scalar::from(0u64), &Scalar::from(10u64)),
        );

        assert_eq!(decrypted, Some(message));
    }
}

// endregion: --- Tests
