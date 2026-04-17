use caterpillar_voting_core::foundation::group::ristretto::RistrettoGroup;
use caterpillar_voting_core::foundation::representation::EncodedMessage;
use caterpillar_voting_core::primitives::encryption::{
    Ciphertext, Encryption, PublicKey, SecretKey,
};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug)]
pub struct WasmEncryption {
    inner: Encryption<RistrettoGroup>,
}

#[wasm_bindgen]
pub struct WasmSecretKey {
    inner: SecretKey<RistrettoGroup>,
}

#[wasm_bindgen]
pub struct WasmPublicKey {
    inner: PublicKey<RistrettoGroup>,
}

#[wasm_bindgen]
pub struct WasmKeyPair {
    private: WasmSecretKey,
    public: WasmPublicKey,
}

#[wasm_bindgen]
pub struct WasmCiphertext {
    inner: Ciphertext<RistrettoGroup>,
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct WasmEncodedMessage {
    inner: EncodedMessage<RistrettoGroup>,
}

impl Default for WasmEncryption {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl WasmEncryption {
    #[wasm_bindgen(js_name = new)]
    pub fn new() -> Self {
        Self {
            inner: Encryption::<RistrettoGroup>::default(),
        }
    }

    #[wasm_bindgen(js_name = key_gen)]
    pub fn key_gen(&self) -> WasmKeyPair {
        let mut rng = OsRng;
        let (secret_key, public_key) = self.inner.key_gen(&mut rng);

        let wrapped_secret_key = WasmSecretKey { inner: secret_key };

        let wrapped_public_key = WasmPublicKey { inner: public_key };

        WasmKeyPair {
            private: wrapped_secret_key,
            public: wrapped_public_key,
        }
    }

    pub fn encrypt(
        &self,
        public_key: &WasmPublicKey,
        message: &WasmEncodedMessage,
    ) -> WasmCiphertext {
        let mut rng = OsRng;

        WasmCiphertext {
            inner: self
                .inner
                .encrypt(&public_key.inner, &mut rng, &message.inner),
        }
    }

    pub fn decrypt(
        &self,
        secret_key: &WasmSecretKey,
        ciphertext: &WasmCiphertext,
    ) -> WasmEncodedMessage {
        WasmEncodedMessage {
            inner: self.inner.decrypt(&secret_key.inner, &ciphertext.inner),
        }
    }

    pub fn reencrypt(
        &self,
        public_key: &WasmPublicKey,
        ciphertext: &WasmCiphertext,
    ) -> WasmCiphertext {
        let mut rng = OsRng;

        WasmCiphertext {
            inner: self
                .inner
                .reencrypt(&public_key.inner, &mut rng, &ciphertext.inner),
        }
    }
}
