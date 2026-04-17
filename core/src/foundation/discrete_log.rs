use crate::foundation::group::Group;

pub trait DiscreteLog<G: Group> {
    fn log(&self, g: &G::Point, point: &G::Point) -> Option<G::Scalar>;
}

pub struct GreedyDiscreteLog<G: Group> {
    range: (G::Scalar, G::Scalar)
}

impl<G: Group> GreedyDiscreteLog<G> {
    pub(crate) fn new(range: (G::Scalar, G::Scalar)) -> Self {
        Self { range }
    }
}

impl<G: Group> DiscreteLog<G> for GreedyDiscreteLog<G> {
    fn log(&self, g: &G::Point, point: &G::Point) -> Option<G::Scalar> {
        let mut current = self.range.0;
        loop {
            if *g * &current == *point {
                return Some(current);
            }

            current = current + &G::Scalar::from(1);
        }
    }
}

pub struct PrecomputedDiscreteLog<G: Group> {
    range: (G::Scalar, G::Scalar),
    g: G::Point,
    table: Vec<G::Point>
}

impl<G: Group> PrecomputedDiscreteLog<G> where usize: From<<G as Group>::Scalar> {
    pub(crate) fn new(range: (G::Scalar, G::Scalar), g: G::Point) -> Self {
        let range_size: usize = (range.1 - &range.0).into();
        let mut table = Vec::with_capacity(range_size + 1);

        let mut point = g * &range.0;
        table.push(point);

        let mut current = 0;
        while current < range_size {
            current += 1;
            point += g;
            table.push(point);
        }

        Self {
            range,
            g,
            table,
        }
    }
}

impl<G: Group> DiscreteLog<G> for PrecomputedDiscreteLog<G> {
    fn log(&self, g: &G::Point, point: &G::Point) -> Option<G::Scalar> {
        assert_eq!(*g, self.g);

        self.table.iter().position(|candidate| candidate == point).map(|index| {
            self.range.0 + &G::Scalar::from(index as u64)
        })
    }
}