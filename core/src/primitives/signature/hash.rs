use crate::foundation::group::{ByteNormalize, Group};

pub fn hash_default<G: Group>(point: &G::Point, message: &Vec<u8>) -> G::Scalar {
    let mut buffer = point.normalize();
    buffer.append(&mut message.clone());
    G::hash_to_scalar(&buffer)
}

#[allow(type_alias_bounds)]
pub type Hash<G: Group> = fn(&G::Point, &Vec<u8>) -> G::Scalar;
