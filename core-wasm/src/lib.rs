use std::sync::OnceLock;
use wasm_bindgen::prelude::*;

type Scalar = <Curve as GroupScalar>::Scalar;
const MAX_RECOVERABLE_SCALAR: u16 = u16::MAX;

fn rng() -> Result<ChaCha20Rng, JsValue> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| JsValue::from_str(&format!("randomness error: {e}")))?;
    Ok(ChaCha20Rng::from_seed(seed))
}

fn js_err(msg: &str) -> JsValue {
    JsValue::from_str(msg)
}

fn dlog_table() -> &'static DiscreteLogTable<Curve> {
    static TABLE: OnceLock<DiscreteLogTable<Curve>> = OnceLock::new();
    TABLE.get_or_init(|| DiscreteLogTable::<Curve>::new(1..=u64::from(MAX_RECOVERABLE_SCALAR)))
}

#[wasm_bindgen]
pub struct WasmSecretKey {
    inner: SecretKey<Curve>,
    params: ElGamalParams<Curve>,
}

#[wasm_bindgen]
pub struct WasmPublicKey {
    inner: PublicKey<Curve>,
    params: ElGamalParams<Curve>,
}

#[wasm_bindgen]
pub struct WasmScalar {
    value: u16,
}

#[wasm_bindgen]
pub struct WasmCiphertext {
    inner: Ciphertext<Curve>,
}

#[wasm_bindgen]
impl WasmSecretKey {
    #[wasm_bindgen(js_name = random)]
    pub fn random() -> Result<WasmSecretKey, JsValue> {
        let mut rng = rng()?;
        let params = ElGamalParams::<Curve>::new(&mut rng);
        let inner = SecretKey::<Curve>::new(&mut rng);
        Ok(Self { inner, params })
    }

    #[wasm_bindgen(js_name = derivePublicKey)]
    pub fn derive_public_key(&self) -> WasmPublicKey {
        WasmPublicKey {
            inner: self.inner.to_public(&self.params),
            params: self.params.clone(),
        }
    }

    #[wasm_bindgen(js_name = decryptScalar)]
    pub fn decrypt_scalar(&self, ciphertext: &WasmCiphertext) -> Result<WasmScalar, JsValue> {
        let point = self.inner.decrypt(&ciphertext.inner);
        let value = dlog_table()
            .get(&point)
            .ok_or_else(|| js_err("decrypted scalar is outside the supported range"))?;

        if value > u64::from(MAX_RECOVERABLE_SCALAR) {
            return Err(js_err("decrypted scalar is outside the supported range"));
        }

        Ok(WasmScalar {
            value: value as u16,
        })
    }
}

#[wasm_bindgen]
impl WasmPublicKey {
    #[wasm_bindgen(js_name = encryptScalar)]
    pub fn encrypt_scalar(&self, scalar: &WasmScalar) -> Result<WasmCiphertext, JsValue> {
        let mut rng = rng()?;
        let scalar = Scalar::from(u64::from(scalar.value));
        Ok(WasmCiphertext {
            inner: ExtendedCiphertext::<Curve>::exp_new(
                &scalar,
                &self.inner,
                &self.params,
                &mut rng,
            )
                .to_inner(),
        })
    }
}

#[wasm_bindgen]
impl WasmScalar {
    #[wasm_bindgen(js_name = random)]
    pub fn random() -> Result<WasmScalar, JsValue> {
        let mut rng = rng()?;
        Ok(Self {
            value: (rng.next_u32() % (u32::from(MAX_RECOVERABLE_SCALAR) + 1)) as u16,
        })
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_be_bytes().to_vec()
    }
}