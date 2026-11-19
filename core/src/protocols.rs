#[derive(Debug)]
pub struct BroadcastMessage<P> {
    pub payload: P,
    pub sender: usize,
}

pub mod dkg;
