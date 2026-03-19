use crate::foundation::group::Group;
use crate::primitives::encryption::el_gamal::ElGamal;

pub trait ScalarGuesser<G: Group> {
    fn get(&mut self) -> Option<G::Scalar>;
}

pub struct ScalarRangeGuesser<G: Group> {
    pub start: G::Scalar,
    pub next: Option<G::Scalar>,
    pub end: G::Scalar,
}

impl <G: Group> ScalarRangeGuesser<G> {
    pub fn new(start: G::Scalar, end: G::Scalar) -> Self {
        Self { start, next: Some(start), end }
    }
}

impl<G: Group> ScalarGuesser<G> for ScalarRangeGuesser<G> {
    fn get(&mut self) -> Option<G::Scalar> {
        let res = self.next?;
        if res == self.end {
            self.next = None;
        }

        self.next = Some(res + &G::Scalar::from(1));

        Some(res)
    }
}

pub struct ExponentialElGamal<G: Group, SG: ScalarGuesser<G>> {
    pub scalar_guesser: SG,
    pub el_gamal: ElGamal<G>
}

impl<G: Group, SG: ScalarGuesser<G>> ExponentialElGamal<G, SG> {
    pub fn new(point: G::Point, scalar_guesser: SG) -> Self {
        let el_gamal = ElGamal::new(point);
        Self { el_gamal, scalar_guesser }
    }

    pub fn encrypt(
        &self,
        public_key: &G::Point,
        randomness: &G::Scalar,
        message: &G::Scalar,
    ) -> (G::Point, G::Point) {
        let message_point = self.el_gamal.point * message;
        self.el_gamal.encrypt(public_key, randomness, &message_point)
    }

    pub fn decrypt(&self, secret_key: &G::Scalar, ciphertext: (&G::Point, &G::Point)) -> Option<G::Scalar> {
        let message_point = self.el_gamal.decrypt(secret_key, ciphertext);

        self.decode_point(&message_point)
    }

    pub fn decrypt_randomness(
        &self,
        public_key: &G::Point,
        randomness: &G::Scalar,
        ciphertext: (&G::Point, &G::Point),
    ) -> Option<G::Scalar> {
        let message_point = self.el_gamal.decrypt_randomness(public_key, randomness, ciphertext);

        self.decode_point(&message_point)
    }

    fn decode_point(&self, point: &G::Point) -> Option<G::Scalar> {
        loop {
            let guess = self.scalar_guesser.get()?;

            if self.el_gamal.point * &guess == *point {
                return Some(guess);
            }
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

    fn seeded_rng() -> StdRng {
        let mut seed = [0u8; 32];
        seed[..5].copy_from_slice(b"hello");
        StdRng::from_seed(seed)
    }

    fn new_el_gamal(rng: &mut StdRng) -> ExponentialElGamal<Curve> {
        let point = Curve::point_random(rng);

        ExponentialElGamal::new(point,
                                Box::new(move || {
                                    let value = counter.get();
                                    counter.set(value + 1);
                                    Some(Curve::scalar_from(value))
                                }))
    }

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng = seeded_rng();
        let el_gamal = new_el_gamal(&mut rng);

        let secret_key = Curve::scalar_random(&mut rng);
        let public_key = el_gamal.point * &secret_key;
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
        let public_key = el_gamal.point * &secret_key;
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
        let public_key = el_gamal.point * &secret_key;
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
        let public_key = el_gamal.point * &secret_key;
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
