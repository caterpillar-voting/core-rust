use crate::foundation::discrete_log::{DiscreteLog, PrecomputedDiscreteLog};
use crate::foundation::group::Group;
use std::marker::PhantomData;

#[allow(type_alias_bounds)]
pub type Message<G: Group> = G::Scalar;

#[allow(type_alias_bounds)]
pub type EncodedMessage<G: Group> = G::Point;

#[derive(Debug)]
pub struct MessageEncoder<G: Group> {
    _marker: PhantomData<G>,
}

impl<G: Group> Default for MessageEncoder<G> {
    fn default() -> Self {
        Self { _marker: Default::default() }
    }
}

struct MessageByteEncoding {
    encoding_size: usize,
    first_counter_bits: u32,
    first_message_size_bits: u32,
    first_reserved_bytes: usize,
    first_available_bytes: usize,
    other_counter_bits: u32,
    other_reserved_bytes: usize,
    other_available_bytes: usize,
}

impl<G: Group> MessageEncoder<G> {
    const COUNTER_BITS: u32 = 7; // how many bits are reserved for the counter
    pub const MESSAGE_LENGTH_BITS: u32 = 13; // how many bits are reserved for the message length; we set to 8k, i.e., 13 bits for now.
    pub fn number_of_points_from_message_length(&self, message_length: usize) -> usize {
        let mbe = self.get_byte_encoding();
        if message_length <= mbe.first_available_bytes {
            return 1;
        }

        let remaining_message_length = message_length - mbe.first_available_bytes;
        1 + remaining_message_length.div_ceil(mbe.other_available_bytes)
    }

    pub fn encode(&self, message: &[u8], number_of_points: usize) -> Vec<G::Point> {
        let mut encoded_values: Vec<G::Point> = vec![];

        let mbe = self.get_byte_encoding();
        assert!(number_of_points <= 1 << mbe.first_message_size_bits);

        let prefix_template = (message.len() << mbe.first_counter_bits) as u32;
        if message.len() <= mbe.first_available_bytes {
            encoded_values.push(self.encode_chunk(message, mbe.encoding_size, mbe.first_reserved_bytes, prefix_template, mbe.first_counter_bits));
        } else {
            let first_chunk = &message[..mbe.first_available_bytes];
            encoded_values.push(self.encode_chunk(first_chunk, mbe.encoding_size, mbe.first_reserved_bytes, prefix_template, mbe.first_counter_bits));

            for chunk in message[mbe.first_available_bytes..].chunks(mbe.other_available_bytes) {
                encoded_values.push(self.encode_chunk(chunk, mbe.encoding_size, mbe.other_reserved_bytes, prefix_template, mbe.other_counter_bits));
            }
        }

        assert!(encoded_values.len() <= number_of_points);
        let l = number_of_points - encoded_values.len();
        encoded_values.extend_from_slice(&vec![G::identity(); l]);
        encoded_values
    }

    fn encode_chunk(&self, chunk: &[u8], encoding_size: usize, prefix_length: usize, prefix_template: u32, counter_bits: u32) -> G::Point {
        let mut encoded_value_bytes = vec![0u8; encoding_size];
        encoded_value_bytes[prefix_length..(prefix_length + chunk.len())].copy_from_slice(chunk);

        let mut encoded_value: Option<G::Point>;
        for counter in 0..(1 << counter_bits) {
            let prefix = prefix_template | counter;
            let prefix_bytes = prefix.to_le_bytes(); // appending 0s does not change the value for little-endian.
            encoded_value_bytes[..prefix_length].copy_from_slice(&prefix_bytes[..prefix_length]);
            encoded_value = G::try_encode(encoded_value_bytes.as_slice());
            if let Some(encoded_value_inner) = encoded_value {
                return encoded_value_inner;
            }
        }

        panic!("The probability of not finding a valid encoding is negligible"); // if this ever occurs, something is wrong with our likelihood computation
    }

    pub fn decode(&self, encoded_message: &[G::Point]) -> Option<Vec<u8>> {
        let mbe = self.get_byte_encoding();
        let mut value = vec![];

        // Extract prefix
        let message_chunk = G::decode(&encoded_message[0]);
        let mut prefix_bytes = message_chunk[..mbe.first_reserved_bytes].to_vec();
        prefix_bytes.resize(4, 0u8);
        let prefix: u32 = u32::from_le_bytes(prefix_bytes.as_slice().try_into().ok()?);
        let message_size = (prefix >> mbe.first_counter_bits) as usize;

        // Extract first chunk
        assert_eq!(message_chunk.len(), mbe.first_reserved_bytes + mbe.first_available_bytes);
        value.extend_from_slice(&message_chunk[mbe.first_reserved_bytes..]);

        // Extract other chunks, or check for padding chunks
        for current in encoded_message.iter().skip(1) {
            if value.len() < message_size {
                let message_chunk = G::decode(current);
                assert_eq!(message_chunk.len(), mbe.other_reserved_bytes + mbe.other_available_bytes);

                value.extend_from_slice(&message_chunk[mbe.other_reserved_bytes..]);
            } else {
                if current != &G::identity() {
                    println!("padding is not done with the neutral element: {:?}", current);
                    return None;
                }
            }
        }

        // Error if too small
        if value.len() < message_size {
            println!("insufficient bytes recovered: {:?} of {:?} recovered.", value.len(), message_size);
            return None;
        }

        // Check for padding
        assert!(value.len() >= message_size);
        let (_, padding) = value.split_at(message_size);
        if padding != vec![0u8; padding.len()] {
            println!("padding is not done with zeros: {:?}", padding);
            return None;
        }

        value.truncate(message_size);
        Some(value)
    }

    // We encode as follows:
    //  - we cut the message into chunks. The first chunk is smaller because one must also reserve y bits for the length of the message.
    //  - to encode a chunk, we must reserve x bits for a counter, because not all byte-sequences correspond to valid points.
    //
    // With a picture (monospace font required):
    //
    //       <----------- G::ENCODING_SIZE ------------------>
    //
    //       <---- first_reserved ---->
    //
    //          other_reserved
    //       <--------->
    //      |-------------------------------------------------|
    //      | counter_0 | message_size |     chunk_0          |     Point_0
    //      |-------------------------------------------------|
    //      | counter_1 |              chunk_1                |     Point_1
    //      |-------------------------------------------------|
    //      | counter_2 |              chunk_2                |     Point_2
    //      |-------------------------------------------------|
    //      | ...                                             |     ...
    //
    // It is possible to enforce a fixed number of points for the encoding, in order to hide the length after encryption.
    // In that case we pad with the neutral element of G.
    fn get_byte_encoding(&self) -> MessageByteEncoding {
        // to make ilog2 computation well-defined
        assert!(G::ENCODING_SIZE.is_power_of_two());
        assert!(G::ENCODING_LIKELIHOOD.is_power_of_two());

        // we choose min_counter_bits such that the probability is low to not be able to encode.
        // concretely, we choose 7 as a constant and add the ENCODING_LIKELIHOOD which captures the fail-probability of the underlying group.
        // example:
        // - for ristretto, the ENCODING_LIKELIHOOD is 16, which results in counter_bits=11.
        // - hence 2048 draws are made, so the probability of non-success is (15/16)^2048 = 2^-190. this is negligible.
        // - setting MAX_MESSAGE_LENGTH_BITS to 13, we get first_reserved_bits=13+7+4=24, which fits nicely in 3 bytes.
        let encoding_size = G::ENCODING_SIZE;
        let adjusted_counter_bits = Self::COUNTER_BITS + G::ENCODING_LIKELIHOOD.ilog2();

        // first chunk: reserved bits are for the counter and the length of the message.
        let first_reserved_bytes = (Self::MESSAGE_LENGTH_BITS + adjusted_counter_bits).div_ceil(8).try_into().unwrap();
        assert!(first_reserved_bytes <= 4); // must fit in a u32.
        let first_available_bytes = encoding_size - first_reserved_bytes;
        let first_counter_bits = (first_reserved_bytes * 8) as u32 - Self::MESSAGE_LENGTH_BITS;
        // other chunks: reserved bits are just for the counter.
        let other_reserved_bytes = adjusted_counter_bits.div_ceil(8).try_into().unwrap();
        let other_available_bytes = encoding_size - other_reserved_bytes;
        let other_counter_bits = (other_reserved_bytes * 8) as u32;

        MessageByteEncoding {
            encoding_size,
            first_counter_bits,
            first_message_size_bits: Self::MESSAGE_LENGTH_BITS,
            first_reserved_bytes,
            first_available_bytes,
            other_counter_bits,
            other_reserved_bytes,
            other_available_bytes,
        }
    }
}

pub struct ScalarMessageEncoder<G: Group> {
    pub decoder: Box<dyn DiscreteLog<G>>,
}

impl<G: Group + 'static> ScalarMessageEncoder<G> {
    pub fn new(range: (G::Scalar, usize)) -> Self {
        let log = PrecomputedDiscreteLog::<G>::new(range);
        Self { decoder: Box::new(log) }
    }

    pub fn encode(&self, value: &G::Scalar) -> EncodedMessage<G> {
        G::basepoint() * value
    }
    pub fn decode(&self, value: &EncodedMessage<G>) -> Option<G::Scalar> {
        self.decoder.log(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::foundation::message::{MessageEncoder, ScalarMessageEncoder};
    use std::vec;

    type G = RistrettoGroup;
    type Scalar = <G as Group>::Scalar;

    #[test]
    fn scalar_encoder_reversible() {
        let encoder = ScalarMessageEncoder::<G>::new((Scalar::from(0u64), 2));

        let value = Scalar::from(0u64);
        let encoded = encoder.encode(&value);
        let recovered_value = encoder.decode(&encoded);

        assert_eq!(Some(value), recovered_value);
    }

    #[test]
    fn byte_encoder_reversible() {
        let encoder = MessageEncoder::<G>::default();
        // messages of various sizes
        for size in [1, 2, 28, 29, 30, 31, 32, 1000, 5000] {
            let message = vec![1u8; size];
            let encoded = encoder.encode(&message, encoder.number_of_points_from_message_length(size));
            let recovered_value = encoder.decode(&encoded);
            assert_eq!(Some(message), recovered_value);
        }
        // test with fixed length
        for size in [1, 2, 28, 29, 30, 31, 32, 40] {
            let message = vec![1u8; size];
            let encoded = encoder.encode(&message, 5);
            let recovered_value = encoder.decode(&encoded);
            assert_eq!(Some(message), recovered_value);
        }
    }

    /*
    // This test is not so easy to automate. The output should be close to G::ENCODING_LIKELIHOOD, but "close" is hard to define unless we take a very large n.
    // We disable it for now, because we rely on a println! and the human having a look.
    #[test]
    fn check_likelihood() {
        let mut rng = rand::thread_rng();
        let mut counter = 0;
        let n = 1000;
        for _ in 0..n {
            let mut bytes = vec![0u8; G::ENCODING_SIZE];
            rng.fill_bytes(&mut bytes);
            let p = G::try_encode(bytes.as_slice());
            if p.is_some() {
                counter += 1;
            }
        }
        let g_str = std::str::from_utf8(G::GROUP_IDENTIFIER).unwrap();
        println!("estimated (inverse) likelihood for group {}: {}", g_str, n as f64 / counter as f64);
    }
     */
}
