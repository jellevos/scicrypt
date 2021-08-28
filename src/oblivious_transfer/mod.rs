use scuttlebutt::AbstractChannel;
use std::io::Error;
use ocelot::ot::Sender;
use crate::BitsOfSecurity;
use crate::randomness::SecureRng;

mod ot;

type Block = [u8; 16];

trait ObliviousTransfer<R: rand_core::RngCore + rand_core::CryptoRng> {
    type OTSetup;
    type OTRequest;
    type OTResponse;

    type OTSender: OTSender<Self::OTSetup, Self::OTRequest, Self::OTResponse, R>;
    type OTReceiver: OTReceiver<Self::OTSetup, Self::OTRequest, Self::OTResponse, R>;
}

trait OTSender<STP, REQ, RSP, R: rand_core::RngCore + rand_core::CryptoRng> {
    fn new(security_param: &BitsOfSecurity) -> (Self, STP);

    fn respond(&mut self, request: REQ, message_pairs: &[(Block, Block)], rng: &mut SecureRng<R>) -> RSP;
}

trait OTReceiver<STP, REQ, RSP, R: rand_core::RngCore + rand_core::CryptoRng> {
    fn new(setup: &STP) -> Self;

    fn request(&mut self, bits: &[bool], rng: &mut SecureRng<R>) -> REQ;

    fn finalize(&mut self, response: RSP, rng: &mut SecureRng<R>) -> Vec<Block>;
}




struct TemporaryChannel {
    bytes: Vec<u8>
}

impl TemporaryChannel {
    fn empty() -> Self {
        TemporaryChannel {
            bytes: vec![],
        }
    }

    fn filled(bytes: Vec<u8>) -> Self {
        TemporaryChannel {
            bytes
        }
    }

    fn finish_vec(self) -> Vec<u8> {
        self.bytes
    }
}

impl AbstractChannel for TemporaryChannel {
    fn read_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        for (byte_buffer, byte_channel) in bytes.iter_mut().zip(&self.bytes) {
            *byte_buffer = *byte_channel
        }?
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.bytes.extend_from_slice(bytes)?
    }

    fn flush(&mut self) -> Result<(), Error> {
        Result::Ok(())
    }

    fn clone(&self) -> Self where
        Self: Sized {
        TemporaryChannel {
            bytes: self.bytes.clone(),
        }
    }
}
