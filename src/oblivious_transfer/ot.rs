use crate::oblivious_transfer::{ObliviousTransfer, OTReceiver, OTSender, TemporaryChannel};
use crate::BitsOfSecurity;
use ocelot::ot::{naor_pinkas, Receiver};
use ocelot::ot::Sender;
use scuttlebutt::Block;
use crate::randomness::SecureRng;

struct NaorPinkasOT {

}

struct NaorPinkasSender {
    sender: naor_pinkas::Sender,
}

struct NaorPinkasReceiver {
    receiver: naor_pinkas::Receiver,
}

struct NaorPinkasRequest {
    bytes: Vec<u8>,
}

struct NaorPinkasResponse {
    bytes: Vec<u8>,
}

impl<R: rand_core::RngCore + rand_core::CryptoRng> ObliviousTransfer<R> for NaorPinkasOT {
    type OTSetup = ();
    type OTRequest = NaorPinkasRequest;
    type OTResponse = NaorPinkasResponse;
    type OTSender = NaorPinkasSender;
    type OTReceiver = NaorPinkasReceiver;
}

impl<R: rand_core::RngCore + rand_core::CryptoRng> OTSender<(), NaorPinkasRequest, NaorPinkasResponse, R> for NaorPinkasSender {
    fn new(security_param: &BitsOfSecurity) -> (Self, ()) {
        (NaorPinkasSender {
            sender: naor_pinkas::Sender {},
        }, ())
    }

    fn respond(&mut self, request: NaorPinkasRequest, message_pairs: &[([u8; 16], [u8; 16])], rng: &mut SecureRng<R>) -> NaorPinkasResponse {
        let mut channel = TemporaryChannel::filled(request.bytes);

        self.sender.send(&mut channel,
                         message_pairs.iter()
                             .map(|(a, b)| (Block::from(a), Block::from(b)))
                             .collect(), rng.rng());

        NaorPinkasResponse {
            bytes: channel.finish_vec(),
        }
    }
}

impl<R: rand_core::RngCore + rand_core::CryptoRng> OTReceiver<(), NaorPinkasRequest, NaorPinkasResponse, R> for NaorPinkasReceiver {
    fn new(_setup: &()) -> Self {
        NaorPinkasReceiver {
            receiver: naor_pinkas::Receiver {},
        }
    }

    fn request(&mut self, bits: &[bool], rng: &mut SecureRng<R>) -> NaorPinkasRequest {
        let mut channel = TemporaryChannel::empty();

        self.receiver.receive(&mut channel, bits, rng.rng());

        NaorPinkasRequest {
            bytes: channel.finish_vec(),
        }
    }

    fn finalize(&mut self, response: NaorPinkasResponse, rng: &mut SecureRng<R>) -> Vec<[u8; 16]> {
        let mut channel = TemporaryChannel::filled(response.bytes);

        self.sender.send(&mut channel,
                         message_pairs.iter()
                             .map(|(a, b)| (Block::from(a), Block::from(b)))
                             .collect(), rng.rng());

        NaorPinkasResponse {
            bytes: channel.finish_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::randomness::SecureRng;
    use rand::rngs::OsRng;

    #[test]
    fn test_naor_pinkas_exchange() {
        let mut rng = SecureRng::new(OsRng);

    }
}
