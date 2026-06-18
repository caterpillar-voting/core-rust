use crate::foundation::group::ByteSerialize;
use crate::foundation::group::Group;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use crypto_bigint::{Encoding, U256, U4096, const_monty_params, modular::ConstMontyForm};
use rand_core::{CryptoRng, RngCore};
use sha3::Digest;
use zeroize::Zeroize;
// ElectionGuard group. p of 4096 bits, q of 256 bits.
// p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB17217F7D1CF79ABC9E3B39803F2F6AF40F343267298B62D8A0D175B8BAAFA2BE7B876206DEBAC98559552FB4AFA1B10ED2EAE35C138214427573B291169B8253E96CA16224AE8C51ACBDA11317C387EB9EA9BC3B136603B256FA0EC7657F74B72CE87B19D6548CAF5DFA6BD38303248655FA1872F20E3A2DA2D97C50F3FD5C607F4CA11FB5BFB90610D30F88FE551A2EE569D6DFC1EFA157D2E23DE1400B39617460775DB8990E5C943E732B479CD33CCCC4E659393514C4C1A1E0BD1D6095D25669B333564A3376A9C7F8A5E148E82074DB6015CFE7AA30C480A5417350D2C955D5179B1E17B9DAE313CDB6C606CB1078F735D1B2DB31B5F50B5185064C18B4D162DB3B365853D7598A1951AE273EE5570B6C68F96983496D4E6D330AF889B44A02554731CDC8EA17293D1228A4EF98D6F5177FBCF0755268A5C1F9538B98261AFFD446B1CA3CF5E9222B88C66D3C5422183EDC99421090BBB16FAF3D949F236E02B20CEE886B905C128D53D0BD2F9621363196AF503020060E49908391A0C57339BA2BEBA7D052AC5B61CC4E9207CEF2F0CE2D7373958D762265890445744FB5F2DA4B751005892D356890DEFE9CAD9B9D4B713E06162A2D8FDD0DF2FD608FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
// q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43
// g = 0x36036FED214F3B50DC566D3A312FE4131FEE1C2BCE6D02EA39B477AC05F7F885F38CFE77A7E45ACF4029114C4D7A9BFE058BF2F995D2479D3DDA618FFD910D3C4236AB2CFDD783A5016F7465CF59BBF45D24A22F130F2D04FE93B2D58BB9C1D1D27FC9A17D2AF49A779F3FFBDCA22900C14202EE6C99616034BE35CBCDD3E7BB7996ADFE534B63CCA41E21FF5DC778EBB1B86C53BFBE99987D7AEA0756237FB40922139F90A62F2AA8D9AD34DFF799E33C857A6468D001ACF3B681DB87DC4242755E2AC5A5027DB81984F033C4D178371F273DBB4FCEA1E628C23E52759BC7765728035CEA26B44C49A65666889820A45C33DD37EA4A1D00CB62305CD541BE1E8A92685A07012B1A20A746C3591A2DB3815000D2AACCFE43DC49E828C1ED7387466AFD8E4BF1935593B2A442EEC271C50AD39F733797A1EA11802A2557916534662A6B7E9A9E449A24C8CFF809E79A4D806EB681119330E6C57985E39B200B4893639FDFDEA49F76AD1ACD997EBA13657541E79EC57437E504EDA9DD011061516C643FB30D6D58AFCCD28B73FEDA29EC12B01A5EB86399A593A9D5F450DE39CB92962C5EC6925348DB54D128FD99C14B457F883EC20112A75A6A0581D3D80A3B4EF09EC86F9552FFDA1653F133AA2534983A6F31B0EE4697935A6B1EA2F75B85E7EBA151BA486094D68722B054633FEC51CA3F29B31E77E317B178B6B9D8AE0F

const COFACTOR: U4096 = U4096::from_be_hex(
    "000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000BCB17217F7D1CF79ABC9E3B39803F2F6AF40F343267298B62D8A0D175B8BAB857AE8F428165418806C62B0EA36355A3A73E0C741985BF6A0E3130179BF2F0B43E33AD862923861B8C9F768C4169519600BAD06093F964B27E02D86831231A9160DE48F4DA53D8AB5E69E386B694BEC1AE722D47579249D5424767C5C33B9151E07C5C11D106AC446D330B47DB59D352E47A53157DE04461900F6FE360DB897DF5316D87C94AE71DAD0BE84B647C4BCF818C23A2D4EBB53C702A5C8062D19F5E9B5033A94F7FF732F54129712869D97B8C96C412921A9D8679770F499A041C297CFF79D4C9149EB6CAF67B9EA3DC563D965F3AAD1377FF22DE9C3E62068DD0ED6151C37B4F74634C2BD09DA912FD599F4333A8D2CC005627DCA37BAD43E64A3963119C0BFE34810A21EE7CFC421D53398CBC7A95B3BF585E5A04B790E2FE1FE9BC264FDA8109F6454A082F5EFB2F37EA237AA29DF320D6EA860C41A9054CCD24876C6253F667BFB0139B5531FF30189961202FD2B0D55A75272C7FD73343F7899BCA0B36A4C470A64A009244C84E77CEBC92417D5BB13BF18167D8033EB6C4DD7879FD4A7F529FD4A7F529FD4A7F529FD4A7F529FD4A7F529FD4A7F529FD4A7F52A",
);

// Internally, everything is stored as Montgomery form.
const_monty_params!(
    EGModulus,
    U4096,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB17217F7D1CF79ABC9E3B39803F2F6AF40F343267298B62D8A0D175B8BAAFA2BE7B876206DEBAC98559552FB4AFA1B10ED2EAE35C138214427573B291169B8253E96CA16224AE8C51ACBDA11317C387EB9EA9BC3B136603B256FA0EC7657F74B72CE87B19D6548CAF5DFA6BD38303248655FA1872F20E3A2DA2D97C50F3FD5C607F4CA11FB5BFB90610D30F88FE551A2EE569D6DFC1EFA157D2E23DE1400B39617460775DB8990E5C943E732B479CD33CCCC4E659393514C4C1A1E0BD1D6095D25669B333564A3376A9C7F8A5E148E82074DB6015CFE7AA30C480A5417350D2C955D5179B1E17B9DAE313CDB6C606CB1078F735D1B2DB31B5F50B5185064C18B4D162DB3B365853D7598A1951AE273EE5570B6C68F96983496D4E6D330AF889B44A02554731CDC8EA17293D1228A4EF98D6F5177FBCF0755268A5C1F9538B98261AFFD446B1CA3CF5E9222B88C66D3C5422183EDC99421090BBB16FAF3D949F236E02B20CEE886B905C128D53D0BD2F9621363196AF503020060E49908391A0C57339BA2BEBA7D052AC5B61CC4E9207CEF2F0CE2D7373958D762265890445744FB5F2DA4B751005892D356890DEFE9CAD9B9D4B713E06162A2D8FDD0DF2FD608FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
);
const_monty_params!(EGOrder, U256, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43");
type FPMgy4096 = ConstMontyForm<EGModulus, 64>;
type FPMgy256 = ConstMontyForm<EGOrder, 4>;

#[derive(Clone, Debug, PartialEq)]
pub struct ElectionGuardGroup(());

#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct FFPoint(FPMgy4096);

#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct ZqElement(FPMgy256);

impl Zeroize for FFPoint {
    fn zeroize(&mut self) {
        self.0 = FPMgy4096::new(&U4096::ZERO);
    }
}

impl Zeroize for ZqElement {
    fn zeroize(&mut self) {
        self.0 = FPMgy256::new(&U256::ZERO);
    }
}
impl Default for ZqElement {
    fn default() -> Self {
        Self(FPMgy256::new(&U256::ZERO))
    }
}

impl ByteSerialize for FFPoint {
    const BUFFER_SIZE: usize = 512;

    fn to_bytes(&self, buffer: &mut [u8]) {
        let x = self.0.retrieve();
        let bytes = x.to_be_bytes();
        buffer.copy_from_slice(&bytes);
    }

    fn from_bytes(buffer: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        let x = U4096::from_be_bytes(buffer.try_into().unwrap());
        let xx = FPMgy4096::new(&x);
        Some(FFPoint(xx))
    }
}

impl ByteSerialize for ZqElement {
    const BUFFER_SIZE: usize = 32;

    fn to_bytes(&self, buffer: &mut [u8]) {
        let x = self.0.retrieve();
        let bytes = x.to_be_bytes();
        buffer.copy_from_slice(&bytes);
    }

    fn from_bytes(buffer: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        let x = U256::from_be_bytes(buffer.try_into().unwrap());
        let xx = FPMgy256::new(&x);
        Some(ZqElement(xx))
    }
}

impl From<u64> for ZqElement {
    fn from(value: u64) -> Self {
        self::ZqElement(FPMgy256::new(&U256::from(value)))
    }
}

// Additive notation for the multiplicative group!
impl Neg for FFPoint {
    type Output = Self;
    fn neg(self) -> Self {
        Self(self.0.invert().unwrap())
    }
}
impl<'a> Add<&'a FFPoint> for FFPoint {
    type Output = Self;
    fn add(self, rhs: &'a Self) -> Self {
        let x = self.0;
        Self(x.mul(&rhs.0))
    }
}

impl Add<FFPoint> for FFPoint {
    type Output = FFPoint;
    fn add(self, rhs: FFPoint) -> FFPoint {
        let x = self.0;
        FFPoint(x.mul(&rhs.0))
    }
}

impl<'a> Add<&'a FFPoint> for &FFPoint {
    type Output = FFPoint;
    fn add(self, rhs:&'a FFPoint) -> FFPoint {
        let x = self.0;
        FFPoint(x.mul(&rhs.0))
    }
}

impl AddAssign for FFPoint {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + &rhs;
    }
}

impl<'a> Sub<&'a FFPoint> for FFPoint {
    type Output = Self;
    fn sub(self, rhs: &'a Self) -> Self {
        let ix = rhs.0.invert().unwrap();
        Self(self.0.mul(&ix))
    }
}
impl SubAssign for FFPoint {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - &rhs;
    }
}

impl<'a> Mul<&'a ZqElement> for FFPoint {
    type Output = Self;
    fn mul(self, rhs: &'a ZqElement) -> Self {
        let x = self.0;
        let n = rhs.0.retrieve();
        let xn = x.pow(&n);
        FFPoint(xn)
    }
}
impl<'a> MulAssign<&'a ZqElement> for FFPoint {
    fn mul_assign(&mut self, rhs: &'a ZqElement) {
        *self = *self * rhs;
    }
}

impl<'a> Mul<&'a FFPoint> for ZqElement {
    type Output = FFPoint;
    fn mul(self, rhs: &'a FFPoint) -> FFPoint {
        rhs.mul(&self)
    }
}

impl<'a> Add<&'a ZqElement> for ZqElement {
    type Output = Self;
    fn add(self, rhs: &'a ZqElement) -> Self::Output {
        ZqElement(self.0.add(&rhs.0))
    }
}
impl AddAssign for ZqElement {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + &rhs;
    }
}

impl<'a> Sub<&'a ZqElement> for ZqElement {
    type Output = Self;
    fn sub(self, rhs: &'a ZqElement) -> Self::Output {
        ZqElement(self.0.sub(&rhs.0))
    }
}
impl SubAssign for ZqElement {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - &rhs;
    }
}

impl<'a> Mul<&'a ZqElement> for ZqElement {
    type Output = Self;
    fn mul(self, rhs: &'a ZqElement) -> Self::Output {
        ZqElement(self.0.mul(&rhs.0))
    }
}
impl MulAssign for ZqElement {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * &rhs;
    }
}

fn map_to_subgroup(point: &FFPoint) -> FFPoint {
    let x = point.0;
    let xn = x.pow(&COFACTOR);
    FFPoint(xn)
}

impl Group for ElectionGuardGroup {
    const GROUP_IDENTIFIER: &'static [u8] = b"ElectionGuard";
    type Point = FFPoint;
    type Scalar = ZqElement; // 256 bits

    fn identity() -> Self::Point {
        FFPoint(FPMgy4096::new(&U4096::ONE))
    }

    fn basepoint() -> Self::Point {
        const BPOINT: &str = "36036FED214F3B50DC566D3A312FE4131FEE1C2BCE6D02EA39B477AC05F7F885F38CFE77A7E45ACF4029114C4D7A9BFE058BF2F995D2479D3DDA618FFD910D3C4236AB2CFDD783A5016F7465CF59BBF45D24A22F130F2D04FE93B2D58BB9C1D1D27FC9A17D2AF49A779F3FFBDCA22900C14202EE6C99616034BE35CBCDD3E7BB7996ADFE534B63CCA41E21FF5DC778EBB1B86C53BFBE99987D7AEA0756237FB40922139F90A62F2AA8D9AD34DFF799E33C857A6468D001ACF3B681DB87DC4242755E2AC5A5027DB81984F033C4D178371F273DBB4FCEA1E628C23E52759BC7765728035CEA26B44C49A65666889820A45C33DD37EA4A1D00CB62305CD541BE1E8A92685A07012B1A20A746C3591A2DB3815000D2AACCFE43DC49E828C1ED7387466AFD8E4BF1935593B2A442EEC271C50AD39F733797A1EA11802A2557916534662A6B7E9A9E449A24C8CFF809E79A4D806EB681119330E6C57985E39B200B4893639FDFDEA49F76AD1ACD997EBA13657541E79EC57437E504EDA9DD011061516C643FB30D6D58AFCCD28B73FEDA29EC12B01A5EB86399A593A9D5F450DE39CB92962C5EC6925348DB54D128FD99C14B457F883EC20112A75A6A0581D3D80A3B4EF09EC86F9552FFDA1653F133AA2534983A6F31B0EE4697935A6B1EA2F75B85E7EBA151BA486094D68722B054633FEC51CA3F29B31E77E317B178B6B9D8AE0F";
        FFPoint(FPMgy4096::new(&U4096::from_be_hex(BPOINT)))
    }

    fn hash_to_point(payload: &[u8]) -> Self::Point {
        let mut hash = sha3::Sha3_512::default();
        hash.update(payload);
        let hash = hash.finalize();
        let p = Self::Point::from_bytes(hash.as_slice()).unwrap();
        map_to_subgroup(&p)
    }

    fn hash_to_scalar(payload: &[u8]) -> Self::Scalar {
        let mut hash = sha3::Sha3_512::default();
        hash.update(payload);
        let hash = hash.finalize();
        Self::Scalar::from_bytes(hash.as_slice()).unwrap()
    }

    fn independent_generators<const N: usize>(prefix: &[u8]) -> Box<[Self::Point; N]> {
        let mut result = Vec::with_capacity(N);

        let shared_prefix_len = prefix.len() + Self::GROUP_IDENTIFIER.len();
        let mut payload = Vec::with_capacity(shared_prefix_len + size_of::<u32>());
        payload.extend_from_slice(prefix);
        payload.extend_from_slice(Self::GROUP_IDENTIFIER);

        for i in 0..N {
            let i = u32::try_from(i).expect("index does not fit in u32");
            payload.truncate(shared_prefix_len);
            payload.extend_from_slice(&i.to_le_bytes());
            result.push(Self::hash_to_point(&payload));
        }
        result.try_into().expect("incorrect number of generators generated")
    }

    fn point_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Point {
        let mut uniform_bytes = [0u8; 64];
        rng.try_fill_bytes(&mut uniform_bytes).unwrap();
        Self::hash_to_point(&uniform_bytes)
    }

    fn scalar_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        let mut uniform_bytes = [0u8; 64];
        rng.try_fill_bytes(&mut uniform_bytes).unwrap();
        Self::hash_to_scalar(&uniform_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Scalar = <ElectionGuardGroup as Group>::Scalar;

    #[test]
    fn scalar_add_and_mul_sanity_checks() {
        let zero = Scalar::from(0u64);
        let one = Scalar::from(1u64);
        let two = Scalar::from(2u64);
        let three = Scalar::from(3u64);
        let four = Scalar::from(4u64);
        let six = Scalar::from(6u64);

        assert_eq!(two + &three, Scalar::from(5u64));
        assert_eq!(two * &three, six);
        assert_eq!(four - &three, one);
        assert_eq!(three + &zero, three);
        assert_eq!(three * &one, three);
        assert_eq!(three * &zero, zero);

        let mut assigned = two;
        assigned += three;
        assert_eq!(assigned, Scalar::from(5u64));

        assigned *= four;
        assert_eq!(assigned, Scalar::from(20u64));

        assigned -= Scalar::from(20u64);
        assert_eq!(assigned, zero);
    }

    #[test]
    fn point_add_and_mul_sanity_checks() {
        let zero = Scalar::from(0u64);
        let one = Scalar::from(1u64);
        let two = Scalar::from(2u64);
        let three = Scalar::from(3u64);
        let five = Scalar::from(5u64);

        let basepoint = ElectionGuardGroup::basepoint();
        let identity = ElectionGuardGroup::identity();

        assert_eq!(basepoint * &zero, identity);
        assert_eq!(basepoint * &one, basepoint);
        assert_eq!((basepoint * &two) + &(basepoint * &three), basepoint * &five);
        assert_eq!((basepoint * &five) - &(basepoint * &three), basepoint * &two);
        assert_eq!(basepoint + &identity, basepoint);
        assert_eq!(identity + &basepoint, basepoint);

        let mut assigned = basepoint * &two;
        assigned += basepoint * &three;
        assert_eq!(assigned, basepoint * &five);

        assigned -= basepoint * &three;
        assert_eq!(assigned, basepoint * &two);

        assigned *= &three;
        assert_eq!(assigned, basepoint * &Scalar::from(6u64));
    }
}
