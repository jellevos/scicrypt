use ocelot::ot::{Sender, NaorPinkasSender, NaorPinkasReceiver};
use crate::randomness::SecureRng;

trait ObliviousTransfer<R: rand_core::RngCore + rand_core::CryptoRng> {
    type Request;
    type Response;

    fn send(choice: bool, rng: &mut SecureRng<R>) -> Self::Request;
    fn receive(request: &Self::Request, rng: &mut SecureRng<R>) -> Self::Response;
}

struct NPRequest {

}

struct NPResponse {

}

struct NaorPinkas;

impl NaorPinkas {
    fn new<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut SecureRng<R>) -> Self {
        let channel = Channel::new();

        NaorPinkas {
            channel,
            sender: NaorPinkasSender::init(&mut channel, rng.rng()).unwrap()
        }
    }
}

impl ObliviousTransfer for NaorPinkas {
    type Request = NPRequest;
    type Response = NPResponse;

    fn send<R: rand_core::RngCore + rand_core::CryptoRng>(choice: bool, rng: &mut SecureRng<R>) -> Self::Request {
        let channel = Channel::new();
        let mut sender = NaorPinkasSender::init(&mut channel, rng.rng()).unwrap();
        sender.send(&mut channel, inputs, rng.rng());
        channel.finish_vec()
    }

    fn receive(request: &Self::Request) -> Self::Response {
        NaorPinkasReceiver::init()
    }
}