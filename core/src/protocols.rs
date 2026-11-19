#[derive(Debug,Clone)]
pub struct BroadcastMessage<P> {
    pub payload: P,
    pub sender: usize,
}

#[derive(Debug,Clone)]
pub struct Message<P> {
    pub payload: P,
    pub sender: usize,
    pub receiver: Vec<usize>,
}

pub mod dkg;
