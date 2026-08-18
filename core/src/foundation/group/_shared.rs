use crate::foundation::group::Group;

pub(crate) fn independent_generators_default<G: Group>(size: usize, prefix: &[u8]) -> Vec<G::Point> {
    let mut result = Vec::with_capacity(size);

    let shared_prefix_len = prefix.len() + G::GROUP_IDENTIFIER.len();
    let mut payload = Vec::with_capacity(shared_prefix_len + size_of::<u32>());
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(G::GROUP_IDENTIFIER);

    for i in 0..size {
        let i = u32::try_from(i).expect("index does not fit in u32");
        payload.truncate(shared_prefix_len);
        payload.extend_from_slice(&i.to_le_bytes());
        result.push(G::hash_to_point(&payload));
    }
    result.try_into().expect("incorrect number of generators generated")
}
