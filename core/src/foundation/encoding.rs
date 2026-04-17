use crate::foundation::group::Group;

pub trait DiscreteLog<G: Group> {
    fn log(&self, g: &G::Point, point: &G::Point) -> Option<G::Scalar>;
}

pub struct DiscreteLogRange<'a, G: Group> {
    range: &'a (G::Scalar, G::Scalar)
}

impl<'a, G: Group> DiscreteLogRange<'a, G> {
    pub(crate) fn new(m_range: &'a (G::Scalar, G::Scalar)) -> Self {
        Self { range: m_range }
    }
}

impl<'a, G: Group> DiscreteLog<G> for DiscreteLogRange<'a, G> {
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