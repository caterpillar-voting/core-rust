use crate::foundation::group::{ByteSerialize, Group};

pub fn get_challenge_default<G: Group>(points: &Vec<G::Point>, context: &Vec<u8>) -> G::Scalar {
    let mut buf = vec![];
    for x in points {
        let mut bytes = vec![0u8; G::Point::BUFFER_SIZE];
        x.to_bytes(&mut bytes[..]);
        buf.append(&mut bytes);
    }
    buf.append(&mut context.clone());
    G::hash_to_scalar(&buf)
}

#[allow(type_alias_bounds)]
pub type GetChallenge<G: Group> = fn(&Vec<G::Point>, &Vec<u8>) -> G::Scalar;
