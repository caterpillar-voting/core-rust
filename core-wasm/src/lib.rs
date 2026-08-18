use caterpillar_voting_core::foundation::group::ristretto::RistrettoGroup;
use caterpillar_voting_core::foundation::group::{ByteSerialize, Group};
use caterpillar_voting_core::foundation::representation::EncodedMessage;
use caterpillar_voting_core::primitives::encryption::{Ciphertext, Encryption, PublicKey, SecretKey, Context};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug)]
pub struct WasmEncryption(Encryption<RistrettoGroup>);

#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmSecretKey(SecretKey<RistrettoGroup>);

#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmPublicKey(PublicKey<RistrettoGroup>);

#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmContext(Context);

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
pub struct WasmCiphertext(Ciphertext<RistrettoGroup>);

#[wasm_bindgen]
#[derive(Debug)]
pub struct WasmEncodedMessage(EncodedMessage<RistrettoGroup>);

#[wasm_bindgen]
impl WasmEncodedMessage {
    pub fn from() -> Self {
        Self(RistrettoGroup::basepoint())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = [0u8; <RistrettoGroup as Group>::Point::BUFFER_SIZE];
        self.0.to_bytes(&mut bytes);
        bytes.into()
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
        Self(Encryption::<RistrettoGroup>::default())
    }

    pub fn key_gen(&self) -> WasmKeyPair {
        let mut rng = OsRng;
        let (secret_key, public_key) = self.0.key_gen(&mut rng);

        let wrapped_secret_key = WasmSecretKey(secret_key);

        let wrapped_public_key = WasmPublicKey(public_key);

        WasmKeyPair {
            private: wrapped_secret_key,
            public: wrapped_public_key,
        }
    }

    pub fn encrypt(&self, public_key: &WasmPublicKey, context: &WasmContext, message: &WasmEncodedMessage) -> WasmCiphertext {
        let mut rng = OsRng;

        WasmCiphertext(self.0.encrypt(&public_key.0, &context.0, &mut rng, &message.0))
    }

    pub fn decrypt(&self, secret_key: &WasmSecretKey, context: &WasmContext, ciphertext: &WasmCiphertext) -> WasmEncodedMessage {
        WasmEncodedMessage(self.0.decrypt(&context.0, &secret_key.0, &ciphertext.0).unwrap())
    }
}
