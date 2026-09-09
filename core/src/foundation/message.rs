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

impl<G: Group> MessageEncoder<G> {
    const MIN_COUNTER_BITS: u32 = 8; // how many bits are reserved for the counter
    const MAX_MESSAGE_LENGTH_BITS: u32 = 13; // how many bits are reserved for the message length; we set to 8k, i.e., 13 bits for now.
    pub fn number_of_points_from_message_length(message_length: usize) -> usize {
        // Copy what is used in encode().
        let size_bits = G::ENCODING_SIZE.ilog2();
        let min_counter_bits = Self::MIN_COUNTER_BITS + G::ENCODING_LIKELIHOOD.ilog2();
        let reserved_bytes: usize = (size_bits + min_counter_bits).div_ceil(8).try_into().unwrap();
        let available_bytes = G::ENCODING_SIZE - reserved_bytes;
        message_length.div_ceil(available_bytes)
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

    pub fn encode(&self, message: &[u8], fixed_length: Option<usize>) -> Option<Vec<G::Point>> {
        // to make ilog2 computation well-defined
        assert!(G::ENCODING_SIZE.is_power_of_two());
        assert!(G::ENCODING_LIKELIHOOD.is_power_of_two());

        // we choose min_counter_bits such that the probability is low to not be able to encode.
        // concretely, we choose 8 as a constant and add the ENCODING_LIKELIHOOD which captures the fail-probability of the underlying group.
        // example:
        //  - for ristretto, the ENCODING_LIKELIHOOD is 8, which results in counter_bits=11.
        // - hence 2048 draws are made, so the probability of non-success is (7/8)^2048 = 1.7 * 10^-119. this is negligible.
        // - for ristretto, observe how counter_bits + size_bits = 16. this fits neatly into two bytes.
        let min_counter_bits = Self::MIN_COUNTER_BITS + G::ENCODING_LIKELIHOOD.ilog2();

        // first chunk: reserved bits are for the counter and the length of the message.
        let first_reserved_bytes = (Self::MAX_MESSAGE_LENGTH_BITS + min_counter_bits).div_ceil(8).try_into().ok()?;
        assert!(first_reserved_bytes <= 4); // must fit in a u32.
        let first_available_bytes = G::ENCODING_SIZE - first_reserved_bytes;
        let first_counter_bits: u32 = (first_reserved_bytes * 8) as u32 - Self::MAX_MESSAGE_LENGTH_BITS;
        // other chunks: reserved bits are just for the counter.
        let other_reserved_bytes = min_counter_bits.div_ceil(8).try_into().ok()?;
        let other_available_bytes = G::ENCODING_SIZE - other_reserved_bytes;
        let other_counter_bits: u32 = (other_reserved_bytes * 8) as u32;

        let mut encoded_values: Vec<G::Point> = vec![];

        if message.len() > 1 << Self::MAX_MESSAGE_LENGTH_BITS {
            // message too long.
            return None;
        }

        // Handle the first chunk of the message.
        let first_chunk = if message.len() <= first_available_bytes { message } else { &message[..first_available_bytes] };
        let prefix_template = (message.len() << first_counter_bits) as u32;
        let mut encoded_value: Option<G::Point> = None;
        for counter in 0..(1 << first_counter_bits) {
            let prefix = prefix_template | counter;
            let prefix_bytes = prefix.to_le_bytes(); // appending 0s does not change the value for little-endian.
            for i in first_reserved_bytes..prefix_bytes.len() {
                assert_eq!(prefix_bytes[i], 0u8);
            }
            let mut encoded_value_bytes = vec![0u8; G::ENCODING_SIZE];
            encoded_value_bytes[..first_reserved_bytes].copy_from_slice(&prefix_bytes[..first_reserved_bytes]);
            encoded_value_bytes[first_reserved_bytes..(first_reserved_bytes + first_chunk.len())].copy_from_slice(first_chunk);
            encoded_value = G::try_encode(encoded_value_bytes.as_slice());
            if encoded_value.is_some() {
                encoded_values.push(encoded_value.unwrap());
                break;
            }
        }
        assert!(encoded_value.is_some()); // This should never occur, or something is wrong with our likelihood computation.

        if message.len() > first_available_bytes {
            // Handle the remaining chunks of the message.
            for chunk in message[first_available_bytes..].chunks(other_available_bytes) {
                encoded_value = None;
                for counter in 0..(1u32 << other_counter_bits) {
                    let prefix_bytes = counter.to_le_bytes(); // appending 0s does not change the value for little-endian.
                    for i in other_reserved_bytes..prefix_bytes.len() {
                        assert_eq!(prefix_bytes[i], 0u8);
                    }
                    let mut encoded_value_bytes = vec![0u8; G::ENCODING_SIZE];
                    encoded_value_bytes[..other_reserved_bytes].copy_from_slice(&prefix_bytes[..other_reserved_bytes]);
                    encoded_value_bytes[other_reserved_bytes..(other_reserved_bytes + chunk.len())].copy_from_slice(chunk);
                    encoded_value = G::try_encode(encoded_value_bytes.as_slice());
                    if encoded_value.is_some() {
                        encoded_values.push(encoded_value.unwrap());
                        break;
                    }
                }
                assert!(encoded_value.is_some()); // This should never occur, or something is wrong with our likelihood computation.
            }
        }
        if fixed_length.is_some() && encoded_values.len() != fixed_length.unwrap() {
            if encoded_values.len() > fixed_length.unwrap() {
                return None; // message too long for the given fixed length.
            } else {
                let l = fixed_length.unwrap() - encoded_values.len();
                encoded_values.extend_from_slice(&vec![G::identity(); l]);
                return Some(encoded_values);
            }
        } else {
            Some(encoded_values)
        }
    }
    pub fn decode(&self, encoded_message: &Vec<G::Point>) -> Option<Vec<u8>> {
        // See encode() for comments about these constants.
        assert!(G::ENCODING_SIZE.is_power_of_two());
        assert!(G::ENCODING_LIKELIHOOD.is_power_of_two());
        let min_counter_bits = Self::MIN_COUNTER_BITS + G::ENCODING_LIKELIHOOD.ilog2();
        let first_reserved_bytes = (Self::MAX_MESSAGE_LENGTH_BITS + min_counter_bits).div_ceil(8).try_into().ok()?;
        let first_available_bytes = G::ENCODING_SIZE - first_reserved_bytes;
        let first_counter_bits: u32 = (first_reserved_bytes * 8) as u32 - Self::MAX_MESSAGE_LENGTH_BITS;
        let other_reserved_bytes = min_counter_bits.div_ceil(8).try_into().ok()?;
        let other_available_bytes = G::ENCODING_SIZE - other_reserved_bytes;

        let mut value = vec![];

        // Handle the first chunk
        let message_chunk = G::decode(&encoded_message[0]);
        let mut prefix_bytes = message_chunk[..first_reserved_bytes].to_vec();
        prefix_bytes.resize(4, 0u8);
        let prefix: u32 = u32::from_le_bytes(prefix_bytes.as_slice().try_into().unwrap());
        let message_length = (prefix >> first_counter_bits) as usize;
        if message_length > first_available_bytes {
            value.extend_from_slice(&message_chunk[first_reserved_bytes..]);
        } else {
            value.extend_from_slice(&message_chunk[first_reserved_bytes..(first_reserved_bytes + message_length)]);
            let expected_zeros = &message_chunk[first_reserved_bytes + message_length..];
            if expected_zeros != vec![0u8; G::ENCODING_SIZE - first_reserved_bytes - message_length] {
                println!("padding is not done with zeros: {:?}", expected_zeros);
                return None; // The padding was not done with zeros.
            }
            for m in &encoded_message[1..] {
                if m != &G::identity() {
                    println!("padding is not done with the neutral element: {:?}", m);
                    return None; // The padding was not done with the neutral element.
                }
            }
            return Some(value);
        }
        let mut remaining_bytes = message_length - first_available_bytes;
        // Handle the remaining chunks
        for i in 1..encoded_message.len() {
            let chunk = &encoded_message[i];
            let message_chunk = G::decode(chunk);

            if remaining_bytes > other_available_bytes {
                value.extend_from_slice(&message_chunk[other_reserved_bytes..]);
                remaining_bytes -= other_available_bytes;
            } else {
                value.extend_from_slice(&message_chunk[other_reserved_bytes..(other_reserved_bytes + remaining_bytes)]);
                let expected_zeros = &message_chunk[other_reserved_bytes + remaining_bytes..];
                if expected_zeros != vec![0u8; G::ENCODING_SIZE - other_reserved_bytes - remaining_bytes] {
                    println!("padding is not done with zeros in point {i}: {:?}", expected_zeros);
                    return None; // The padding was not done with zeros.
                }
                for m in &encoded_message[i + 1..] {
                    if m != &G::identity() {
                        println!("padding is not done with the neutral element: {:?}", m);
                        return None; // The padding was not done with the neutral element.
                    }
                }
                return Some(value);
            }
        }
        assert!(false); // Encoded size does not match the number of chunks.
        None
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
            let encoded = encoder.encode(&message, None);
            assert!(encoded.is_some());

            let recovered_value = encoder.decode(&encoded.unwrap());
            assert_eq!(Some(message), recovered_value);
        }
        // test with fixed length
        for size in [1, 2, 28, 29, 30, 31, 32, 40] {
            let message = vec![1u8; size];
            let encoded = encoder.encode(&message, Some(5));
            assert!(encoded.is_some());

            let recovered_value = encoder.decode(&encoded.unwrap());
            assert_eq!(Some(message), recovered_value);
        }
    }
}
