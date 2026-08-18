use crate::foundation::group::{ByteSerialize, Group};

pub fn hash_default<G: Group>(point: &G::Point, message: &Vec<u8>) -> G::Scalar {
    let mut buf = vec![];
    let mut bytes = vec![0u8; G::Point::BUFFER_SIZE];
    point.to_bytes(&mut bytes[..]);
    buf.append(&mut bytes);
    buf.append(&mut message.clone());
    G::hash_to_scalar(&buf)
}

#[allow(type_alias_bounds)]
pub type Hash<G: Group> = fn(&G::Point, &Vec<u8>) -> G::Scalar;
