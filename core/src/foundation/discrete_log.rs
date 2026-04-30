use crate::foundation::group::Group;

pub trait DiscreteLog<G: Group> {
    fn log(&self, g: &G::Point, point: &G::Point) -> Option<G::Scalar>;
}

pub struct GreedyDiscreteLog<G: Group> {
    start: G::Scalar,
    end: Option<G::Scalar>,
}

impl<G: Group> Default for GreedyDiscreteLog<G> {
    fn default() -> Self {
        Self {
            start: G::Scalar::from(0),
            end: None,
        }
    }
}

impl<G: Group> GreedyDiscreteLog<G> {
    pub fn new(start: G::Scalar, end: Option<G::Scalar>) -> Self {
        Self { start, end }
    }
}

impl<G: Group> DiscreteLog<G> for GreedyDiscreteLog<G> {
    fn log(&self, g: &G::Point, point: &G::Point) -> Option<G::Scalar> {
        let mut current = self.start;
        loop {
            if *g * &current == *point {
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
    g: G::Point,
    table: Box<[G::Point]>, // TODO: consider hash map for O(1) access, but would require to hash over G::Scalar
}

impl<G: Group> PrecomputedDiscreteLog<G> {
    pub fn new(range: (G::Scalar, usize), g: G::Point) -> Self {
        let mut table = Vec::with_capacity(range.1);

        let mut point = g * &range.0;
        table.push(point);

        let mut current = 1;
        while current < range.1 {
            point += g;
            table.push(point);

            current += 1;
        }

        Self {
            range,
            g,
            table: table.into_boxed_slice(),
        }
    }
}

impl<G: Group> DiscreteLog<G> for PrecomputedDiscreteLog<G> {
    fn log(&self, g: &G::Point, point: &G::Point) -> Option<G::Scalar> {
        assert_eq!(*g, self.g);

        self.table
            .iter()
            .position(|candidate| candidate == point)
            .map(|index| self.range.0 + &G::Scalar::from(index as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::ristretto::RistrettoGroup;

    type Curve = RistrettoGroup;
    type Scalar = <Curve as Group>::Scalar;

    #[test]
    fn greedy_discrete_log_finds_values_in_range() {
        let g = Curve::basepoint();

        let start = Scalar::from(0u8);
        let end = Scalar::from(3u8);
        let dlog = GreedyDiscreteLog::<Curve>::new(start, Some(end));

        let expected_start = Scalar::from(0u8);
        assert_eq!(dlog.log(&g, &(g * &expected_start)), Some(expected_start));

        let expected_end = Scalar::from(3u8);
        assert_eq!(dlog.log(&g, &(g * &expected_end)), Some(expected_end));

        let expected_middle = Scalar::from(2u8);
        assert_eq!(dlog.log(&g, &(g * &expected_middle)), Some(expected_middle));

        let out_of_range = Scalar::from(4u8);
        assert_eq!(dlog.log(&g, &(g * &out_of_range)), None);
    }

    #[test]
    fn precomputed_discrete_log_returns_none_for_non_members() {
        let g = Curve::basepoint();

        let range = (Scalar::from(0u8), 4);
        let dlog = PrecomputedDiscreteLog::<Curve>::new(range, g);

        let expected_start = Scalar::from(0u8);
        assert_eq!(dlog.log(&g, &(g * &expected_start)), Some(expected_start));

        let expected_end = Scalar::from(3u8);
        assert_eq!(dlog.log(&g, &(g * &expected_end)), Some(expected_end));

        let expected_middle = Scalar::from(2u8);
        assert_eq!(dlog.log(&g, &(g * &expected_middle)), Some(expected_middle));

        let out_of_range = Scalar::from(4u8);
        assert_eq!(dlog.log(&g, &(g * &out_of_range)), None);
    }

    #[test]
    fn precomputed_discrete_log_requires_same_generator() {
        let g = Curve::basepoint();

        let range = (Scalar::from(0u8), 1);
        let dlog = PrecomputedDiscreteLog::<Curve>::new(range, g);

        let other_g = g + &g;
        let result = std::panic::catch_unwind(|| dlog.log(&other_g, &g));
        assert!(result.is_err());
    }
}
