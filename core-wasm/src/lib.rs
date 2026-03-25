use caterpillar_voting_core::foundation::group::ristretto::RistrettoGroup;
use caterpillar_voting_core::primitives::encryption::{
    Ciphertext, Encryption, PublicKey, SecretKey,
};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;
use caterpillar_voting_core::foundation::representation::EncodedMessage;

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
pub struct WasmCiphertext {
    inner: Ciphertext<RistrettoGroup>,
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct WasmEncodedMessage {
    inner: EncodedMessage<RistrettoGroup>,
}

#[wasm_bindgen]
impl WasmEncryption {
    #[wasm_bindgen(js_name = new)]
    pub fn new() -> Self {
        Self {
            inner: Encryption::<RistrettoGroup>::new(),
        }
    }

    #[wasm_bindgen(js_name = generate_secret_key)]
    pub fn generate_secret_key(&self) -> WasmSecretKey {
        let mut rng = OsRng;

        WasmSecretKey {
            inner: self.inner.generate_secret_key(&mut rng),
        }
    }

    #[wasm_bindgen(js_name = derive_public_key)]
    pub fn derive_public_key(&self, secret_key: &WasmSecretKey) -> WasmPublicKey {
        WasmPublicKey {
            inner: self.inner.derive_public_key(&secret_key.inner),
        }
    }

    pub fn encrypt(&self, public_key: &WasmPublicKey, message: &WasmEncodedMessage) -> WasmCiphertext {
        let mut rng = OsRng;

        WasmCiphertext {
            inner: self
                .inner
                .encrypt(&public_key.inner, &mut rng, &message.inner),
        }
    }

    pub fn decrypt(&self, secret_key: &WasmSecretKey, ciphertext: &WasmCiphertext) -> WasmEncodedMessage {
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
