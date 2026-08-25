use crate::foundation::discrete_log::{DiscreteLog, PrecomputedDiscreteLog};
use crate::foundation::group::Group;
use std::marker::PhantomData;

#[allow(type_alias_bounds)]
pub type Message<G: Group> = G::Scalar;

#[allow(type_alias_bounds)]
pub type EncodedMessage<G: Group> = G::Point;

#[derive(Default)]
pub struct MessageEncoder<G: Group> {
    _marker: PhantomData<G>,
}

impl<G: Group> MessageEncoder<G> {
    const MIN_COUNTER_BITS: u32 = 8; // how many bits are reserved for the counter
    pub fn encode(&self, message: &[u8]) -> Option<Vec<G::Point>> {
        // to make ilog2 computation well-defined
        assert!(G::ENCODING_SIZE.is_power_of_two());
        assert!(G::ENCODING_LIKELIHOOD.is_power_of_two());

        let size_bits = G::ENCODING_SIZE.ilog2();
        assert!(size_bits > 0); // assumption (A1) for simpler prefix computation

        // we choose min_counter_bits such that the probability is low to not be able to encode.
        // concretely, we choose 8 as a constant and add the ENCODING_LIKELIHOOD which captures the fail-probability of the underlying group.
        // example:
        //  - for ristretto, the ENCODING_LIKELIHOOD is 8, which results in counter_bits=11.
        // - hence 2048 draws are made, so the probability of non-success is (7/8)^2048 = 1.7 * 10^-119. this is negligible.
        // - for ristretto, observe how counter_bits + size_bits = 16. this fits neatly into two bytes.
        let min_counter_bits = Self::MIN_COUNTER_BITS + G::ENCODING_LIKELIHOOD.ilog2();
        let reserved_bytes: usize = (size_bits + min_counter_bits).div_ceil(8).try_into().ok()?;
        let available_bytes = G::ENCODING_SIZE - reserved_bytes;
        // invariant (1): log2(available_bytes) <= size_bits
        let counter_bits: u32 = (reserved_bytes * 8) as u32 - size_bits;
        // invariant (2): counter_bits + size_bits = reserved_bytes

        assert!(counter_bits + size_bits < 32); // assumption (A2) for simpler prefix computation
        let max_counter: u32 = 1u32 << counter_bits; // by (A1), size_bits > 0; and therefore by (A2), counter_bits < 31; hence this cannot overflow
        let mut encoded_values: Vec<G::Point> = vec![];
        for chunk in message.chunks(available_bytes) {
            let mut encoded_value: Option<G::Point> = None;

            let chunk_size = chunk.len(); // invariant (3): chunk_size <= available_bytes
            let prefix_template = (chunk_size << counter_bits) as u32; // by (1) and (3), log2(chunk_size) <= size_bits. by A2, size_bits + counter_bits cannot overflow
            for counter in 0..max_counter {
                let prefix = prefix_template | counter;
                let prefix_bytes = prefix.to_be_bytes();
                let prefix_offset = prefix_bytes.len() - reserved_bytes;

                let mut encoded_value_bytes = vec![0u8; G::ENCODING_SIZE];
                encoded_value_bytes[..reserved_bytes].copy_from_slice(&prefix_bytes[prefix_offset..]); // prefix of 0 for big-endian does not change value
                encoded_value_bytes[reserved_bytes..(reserved_bytes + chunk_size)].copy_from_slice(chunk); // extend chunk starting from reserved_bytes
                // as encoded value initialized to 0, the rest of encoded_value is 0

                encoded_value = G::try_encode(encoded_value_bytes.as_slice());
                if encoded_value.is_some() {
                    break;
                }
            }

            if let Some(unwrapped) = encoded_value {
                encoded_values.push(unwrapped);
            } else {
                return None;
            }
        }

        Some(encoded_values)
    }
    pub fn decode(&self, encoded_message: &Vec<G::Point>) -> Option<Vec<u8>> {
        // to make ilog2 computation well-defined
        assert!(G::ENCODING_SIZE.is_power_of_two());
        assert!(G::ENCODING_LIKELIHOOD.is_power_of_two());

        let size_bits = G::ENCODING_SIZE.ilog2();
        assert!(size_bits > 0); // assumption (A1) for simpler prefix computation

        let min_counter_bits = Self::MIN_COUNTER_BITS + G::ENCODING_LIKELIHOOD.ilog2();
        let reserved_bytes: usize = (size_bits + min_counter_bits).div_ceil(8).try_into().ok()?;
        let available_bytes = G::ENCODING_SIZE - reserved_bytes;
        let counter_bits: u32 = (reserved_bytes * 8) as u32 - size_bits;

        let mut value = vec![];
        for chunk in encoded_message {
            let message_chunk = G::decode(chunk);

            let mut prefix_bytes = [0u8; 4]; // by (A2), sufficient
            let start = 4 - reserved_bytes;

            prefix_bytes[start..].copy_from_slice(&message_chunk[..reserved_bytes]);

            let prefix = u32::from_be_bytes(prefix_bytes);
            let chunk_size = (prefix >> counter_bits) as usize;

            if chunk_size > available_bytes {
                return None;
            }

            let payload_size = reserved_bytes + chunk_size;
            let expected_zeros = &message_chunk[payload_size..];
            if expected_zeros != vec![0u8; G::ENCODING_SIZE - payload_size] {
                return None;
            }

            value.extend_from_slice(&message_chunk[reserved_bytes..payload_size]);
        }

        Some(value)
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

        let value = vec![1u8];
        let encoded = encoder.encode(&value);
        assert!(encoded.is_some());

        let recovered_value = encoder.decode(&encoded.unwrap());
        assert_eq!(Some(value), recovered_value);
    }
}
