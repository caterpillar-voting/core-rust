use caterpillar_voting_core::foundation::group::ristretto::RistrettoGroup;
use caterpillar_voting_core::foundation::group::{ByteSerialize, Group};
use caterpillar_voting_core::primitives::encryption::el_gamal::ElGamal;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

type GroupPoint = RistrettoPoint;
type GroupScalar = Scalar;

fn el_gamal() -> ElGamal<RistrettoGroup> {
    ElGamal::new(RistrettoGroup::generator())
}

#[wasm_bindgen]
pub struct WasmSecretKey {
    inner: GroupScalar,
}

#[wasm_bindgen]
pub struct WasmPublicKey {
    inner: GroupPoint,
}

#[wasm_bindgen]
pub struct WasmCiphertext {
    alpha: GroupPoint,
    beta: GroupPoint,
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct WasmMessage {
    inner: GroupPoint,
}

#[wasm_bindgen]
impl WasmSecretKey {
    #[wasm_bindgen(js_name = random)]
    pub fn random() -> Result<WasmSecretKey, JsValue> {
        let mut rng = OsRng;
        Ok(Self {
            inner: RistrettoGroup::scalar_random(&mut rng),
        })
    }

    #[wasm_bindgen(js_name = derive_public_key)]
    pub fn derive_public_key(&self) -> WasmPublicKey {
        let public_key = RistrettoGroup::generator() * &self.inner;
        WasmPublicKey { inner: public_key }
    }

    #[wasm_bindgen(js_name = decrypt)]
    pub fn decrypt(&self, ciphertext: &WasmCiphertext) -> Result<WasmMessage, JsValue> {
        let inner = el_gamal().decrypt(&self.inner, (&ciphertext.alpha, &ciphertext.beta));
        Ok(WasmMessage { inner })
    }
}

#[wasm_bindgen]
impl WasmPublicKey {
    #[wasm_bindgen(js_name = encrypt)]
    pub fn encrypt(&self, message: &WasmMessage) -> Result<WasmCiphertext, JsValue> {
        let mut rng = OsRng;
        let randomness = RistrettoGroup::scalar_random(&mut rng);

        let (alpha, beta) = el_gamal().encrypt(&self.inner, &randomness, &message.inner);
        Ok(WasmCiphertext { alpha, beta })
    }
}

#[wasm_bindgen]
impl WasmMessage {
    #[wasm_bindgen(js_name = random)]
    pub fn random() -> Result<WasmMessage, JsValue> {
        let mut rng = OsRng;
        let inner = GroupPoint::random(&mut rng);

        Ok(WasmMessage { inner })
    }

    #[wasm_bindgen(js_name = to_bytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = [0u8; 32];
        ByteSerialize::to_bytes(&self.inner, &mut bytes);
        bytes.to_vec()
    }
}
