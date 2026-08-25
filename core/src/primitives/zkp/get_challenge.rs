use crate::foundation::group::{ByteNormalize, Group};

pub fn get_challenge_default<G: Group>(points: &[G::Point], context: &[u8]) -> G::Scalar {
    let mut buffer = vec![];
    for x in points {
        let mut bytes = x.normalize();
        buffer.append(&mut bytes);
    }
    buffer.append(&mut context.to_vec());
    G::hash_to_scalar(&buffer)
}

#[allow(type_alias_bounds)]
pub type GetChallenge<G: Group> = fn(&[G::Point], &[u8]) -> G::Scalar;
