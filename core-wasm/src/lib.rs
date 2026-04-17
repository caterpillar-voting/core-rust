use caterpillar_voting_core::foundation::group::ristretto::RistrettoGroup;
use caterpillar_voting_core::foundation::representation::EncodedMessage;
use caterpillar_voting_core::primitives::encryption::{
    Ciphertext, Encryption, PublicKey, SecretKey,
};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;
use caterpillar_voting_core::foundation::group::{ByteSerialize, Group};

#[wasm_bindgen]
#[derive(Debug)]
pub struct WasmEncryption {
    inner: Encryption<RistrettoGroup>,
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmSecretKey {
    inner: SecretKey<RistrettoGroup>,
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmPublicKey {
    inner: PublicKey<RistrettoGroup>,
}

#[wasm_bindgen]
pub struct WasmKeyPair {
    private: WasmSecretKey,
    public: WasmPublicKey,
}

#[wasm_bindgen]
impl WasmKeyPair {
    #[wasm_bindgen(js_name = "private")]
    pub fn private(&self) -> WasmSecretKey {
        self.private.clone()
    }

    #[wasm_bindgen(js_name = "public")]
    pub fn public(&self) -> WasmPublicKey {
        self.public.clone()
    }
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
impl WasmEncodedMessage {
    pub fn from() -> Self {
        Self { inner: EncodedMessage::new(RistrettoGroup::basepoint()) }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; <RistrettoGroup as Group>::Point::BUFFER_SIZE];
        self.inner.inner.to_bytes(&mut bytes);
        bytes
    }
}

impl Default for WasmEncryption {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl WasmEncryption {
    pub fn new() -> Self {
        Self {
            inner: Encryption::<RistrettoGroup>::default(),
        }
    }

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
