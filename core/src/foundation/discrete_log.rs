use crate::foundation::group::Group;

pub trait DiscreteLog<G: Group> {
    fn log(&self, point: &G::Point) -> Option<G::Scalar>;
}

pub struct BruteForceDiscreteLog<G: Group> {
    start: G::Scalar,
    end: Option<G::Scalar>,
}

impl<G: Group> Default for BruteForceDiscreteLog<G> {
    fn default() -> Self {
        Self { start: G::Scalar::from(0), end: None }
    }
}

impl<G: Group> BruteForceDiscreteLog<G> {
    pub fn new(start: G::Scalar, end: Option<G::Scalar>) -> Self {
        Self { start, end }
    }
}

impl<G: Group> DiscreteLog<G> for BruteForceDiscreteLog<G> {
    fn log(&self, point: &G::Point) -> Option<G::Scalar> {
        let mut current = self.start;
        loop {
            if G::basepoint() * &current == *point {
                return Some(current);
            }

            if self.end.is_some() && current == self.end.unwrap() {
                return None;
            }

            current = current + &G::Scalar::from(1);
        }
    }
}

pub struct PrecomputedDiscreteLog<G: Group> {
    range: (G::Scalar, usize),
    table: Box<[G::Point]>,
}

impl<G: Group> PrecomputedDiscreteLog<G> {
    pub fn new(range: (G::Scalar, usize)) -> Self {
        let mut table = Vec::with_capacity(range.1);

        let mut point = G::basepoint() * &range.0;
        table.push(point);

        let mut current = 1;
        while current < range.1 {
            point = point + &G::basepoint();
            table.push(point);

            current += 1;
        }

        Self {
            range,
            table: table.into_boxed_slice(),
        }
    }
}

impl<G: Group> DiscreteLog<G> for PrecomputedDiscreteLog<G> {
    fn log(&self, point: &G::Point) -> Option<G::Scalar> {
        self.table.iter().position(|candidate| candidate == point).map(|index| self.range.0 + &G::Scalar::from(index as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::ristretto::RistrettoGroup;

    type G = RistrettoGroup;
    type Scalar = <G as Group>::Scalar;

    #[test]
    fn greedy_discrete_log_finds_values_in_range() {
        let g = G::basepoint();

        let start = Scalar::from(0u64);
        let end = Scalar::from(3u64);
        let dlog = BruteForceDiscreteLog::<G>::new(start, Some(end));

        let expected_start = Scalar::from(0u64);
        assert_eq!(dlog.log(&(g * &expected_start)), Some(expected_start));

        let expected_end = Scalar::from(3u64);
        assert_eq!(dlog.log(&(g * &expected_end)), Some(expected_end));

        let expected_middle = Scalar::from(2u64);
        assert_eq!(dlog.log(&(g * &expected_middle)), Some(expected_middle));

        let out_of_range = Scalar::from(4u64);
        assert_eq!(dlog.log(&(g * &out_of_range)), None);
    }

    #[test]
    fn precomputed_discrete_log_returns_none_for_non_members() {
        let g = G::basepoint();

        let range = (Scalar::from(0u64), 4);
        let dlog = PrecomputedDiscreteLog::<G>::new(range);

        let expected_start = Scalar::from(0u64);
        assert_eq!(dlog.log(&(g * &expected_start)), Some(expected_start));

        let expected_end = Scalar::from(3u64);
        assert_eq!(dlog.log(&(g * &expected_end)), Some(expected_end));

        let expected_middle = Scalar::from(2u64);
        assert_eq!(dlog.log(&(g * &expected_middle)), Some(expected_middle));

        let out_of_range = Scalar::from(4u64);
        assert_eq!(dlog.log(&(g * &out_of_range)), None);
    }
}
