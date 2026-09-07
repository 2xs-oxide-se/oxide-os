#![no_std]
#![no_main]

use rustlet_runtime::{
    Algorithm, Apdu, ApduHeader, ApduStatus, Cipher, CipherMode, CryptoBackend, Mac, MacAlgorithm,
    RandomAlgorithm, RandomData, Rustlet, RustletCtx, declare_app,
};

const INS_SET_KEY: u8 = 0x80;
const INS_CYPHER_PAYLOAD: u8 = 0x82;
const INS_DECYPHER_PAYLOAD: u8 = 0x84;
const INS_CYPHER_CONTENT: u8 = 0x86;
const INS_SET_MASTER_KEY128: u8 = 0x88;
const INS_SET_MASTER_KEY256: u8 = 0x8A;
const INS_RANDOM: u8 = 0x8C;
const INS_SET_AUTH_KEY: u8 = 0x50;
const INS_CMAC_PAYLOAD: u8 = 0x52;
const INS_VERIFY_CMAC_PAYLOAD: u8 = 0x54;
const AES_BLOCK_SIZE: usize = 16;
const MAC_TAG_SIZE: usize = 16;
const INTERNAL_CONTENT: &[u8; 32] = b"hello aes cyphered world!.......";
const MASTER_KEY128: &[u8; 16] = b"master key 128!!";
const MASTER_KEY256: &[u8; 32] = b"master key 256!!master key 256!!";

declare_app!(CryptoTestRustlet);

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct CryptoTestRustlet {
    key: [u8; 32],
    key_len: u8,
    auth_key: [u8; 32],
    auth_key_len: u8,
    master_key_len: u8,
}

impl Rustlet for CryptoTestRustlet {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let mut crypto = ctx.crypto();
        let apdu = Apdu::new(ctx);

        match apdu.ins() {
            INS_SET_KEY => self.set_key(apdu),
            INS_CYPHER_PAYLOAD => self.cypher_payload(apdu, CipherMode::Encrypt, &mut crypto),
            INS_DECYPHER_PAYLOAD => self.cypher_payload(apdu, CipherMode::Decrypt, &mut crypto),
            INS_CYPHER_CONTENT => self.cypher_content(apdu, &mut crypto),
            INS_SET_MASTER_KEY128 => self.set_master_key(apdu, MASTER_KEY128),
            INS_SET_MASTER_KEY256 => self.set_master_key(apdu, MASTER_KEY256),
            INS_RANDOM => self.random(apdu),
            INS_SET_AUTH_KEY => self.set_auth_key(apdu),
            INS_CMAC_PAYLOAD => self.cmac_payload(apdu, &mut crypto),
            INS_VERIFY_CMAC_PAYLOAD => self.verify_cmac_payload(apdu, &mut crypto),
            _ => apdu.reject(ApduStatus::instruction_not_supported()),
        }
    }
}

impl CryptoTestRustlet {
    fn algorithm(&self, mode_selector: u8) -> Result<Algorithm, ApduStatus> {
        match (self.key_len as usize, mode_selector) {
            (16, 0x00) => Ok(Algorithm::Aes128CbcNoPadding),
            (32, 0x00) => Ok(Algorithm::Aes256CbcNoPadding),
            (16, 0x01) => Ok(Algorithm::Aes128CbcIso9797M2),
            (32, 0x01) => Ok(Algorithm::Aes256CbcIso9797M2),
            (16, 0x02) => Ok(Algorithm::Aes128EcbNoPadding),
            (32, 0x02) => Ok(Algorithm::Aes256EcbNoPadding),
            _ => Err(ApduStatus::conditions_not_satisfied()),
        }
    }

    fn key(&self) -> &[u8] {
        match self.master_key_len {
            16 => MASTER_KEY128,
            32 => MASTER_KEY256,
            _ => &self.key[..self.key_len as usize],
        }
    }

    fn set_key(&mut self, apdu: Apdu<rustlet_runtime::Command>) -> ApduStatus {
        let rx = apdu.as_receiving();
        let key = rx.data();
        if key.len() != 16 && key.len() != 32 {
            return rx.reject(ApduStatus::wrong_length());
        }

        self.key = [0; 32];
        self.key[..key.len()].copy_from_slice(key);
        self.key_len = key.len() as u8;
        self.master_key_len = 0;
        rx.accept()
    }

    fn set_master_key(
        &mut self,
        apdu: Apdu<rustlet_runtime::Command>,
        key: &'static [u8],
    ) -> ApduStatus {
        self.key_len = key.len() as u8;
        self.master_key_len = key.len() as u8;
        apdu.accept()
    }

    fn set_auth_key(&mut self, apdu: Apdu<rustlet_runtime::Command>) -> ApduStatus {
        let rx = apdu.as_receiving();
        let key = rx.data();
        if key.len() != 16 && key.len() != 32 {
            return rx.reject(ApduStatus::wrong_length());
        }

        self.auth_key = [0; 32];
        self.auth_key[..key.len()].copy_from_slice(key);
        self.auth_key_len = key.len() as u8;
        rx.accept()
    }

    fn cypher_payload(
        &mut self,
        apdu: Apdu<rustlet_runtime::Command>,
        mode: CipherMode,
        crypto: &mut dyn CryptoBackend,
    ) -> ApduStatus {
        let mode_selector = apdu.p1();
        let algorithm = match self.algorithm(mode_selector) {
            Ok(algorithm) => algorithm,
            Err(status) => return apdu.reject(status),
        };

        let rx = apdu.as_receiving();
        let input = rx.data();
        if mode_selector != 0x01 && input.len() % AES_BLOCK_SIZE != 0 {
            return rx.reject(ApduStatus::wrong_length());
        }

        let mut output = [0u8; 256];
        match self.do_final(input, &mut output, mode, algorithm, crypto) {
            Ok(len) => rx.accept_and_send(&output[..len]),
            Err(_) => rx.reject(ApduStatus::internal_error()),
        }
    }

    fn cypher_content(
        &mut self,
        apdu: Apdu<rustlet_runtime::Command>,
        crypto: &mut dyn CryptoBackend,
    ) -> ApduStatus {
        let algorithm = match self.algorithm(apdu.p1()) {
            Ok(algorithm) => algorithm,
            Err(status) => return apdu.reject(status),
        };

        let tx = apdu.as_sending();
        let mut output = [0u8; 64];
        match self.do_final(
            INTERNAL_CONTENT,
            &mut output,
            CipherMode::Encrypt,
            algorithm,
            crypto,
        ) {
            Ok(len) => tx.send(&output[..len]),
            Err(_) => tx.reject(ApduStatus::internal_error()),
        }
    }

    fn random(&mut self, apdu: Apdu<rustlet_runtime::Command>) -> ApduStatus {
        let tx = apdu.as_sending();
        let mut random = [0u8; 16];
        let mut generator = match RandomData::get_instance(RandomAlgorithm::SecureRandom) {
            Ok(generator) => generator,
            Err(_) => return tx.reject(ApduStatus::internal_error()),
        };
        match generator.generate_data(&mut random) {
            Ok(()) => tx.send(&random),
            Err(_) => tx.reject(ApduStatus::internal_error()),
        }
    }

    fn do_final(
        &self,
        input: &[u8],
        output: &mut [u8],
        mode: CipherMode,
        algorithm: Algorithm,
        crypto: &mut dyn CryptoBackend,
    ) -> Result<usize, rustlet_runtime::CryptoError> {
        if is_ecb(algorithm) {
            let iv = [0u8; AES_BLOCK_SIZE];
            let cipher = Cipher::new(crypto).init(self.key(), &iv, mode, algorithm)?;
            return cipher.finish(input, output);
        }

        if mode == CipherMode::Encrypt {
            if output.len() < AES_BLOCK_SIZE {
                return Err(rustlet_runtime::CryptoError::InvalidOutputLength);
            }
            let mut iv = [0u8; AES_BLOCK_SIZE];
            let mut generator = RandomData::get_instance(RandomAlgorithm::SecureRandom)?;
            generator.generate_data(&mut iv)?;
            output[..AES_BLOCK_SIZE].copy_from_slice(&iv);
            let cipher = Cipher::new(crypto).init(self.key(), &iv, mode, algorithm)?;
            let len = cipher.finish(input, &mut output[AES_BLOCK_SIZE..])?;
            return Ok(AES_BLOCK_SIZE + len);
        }

        if input.len() < AES_BLOCK_SIZE {
            return Err(rustlet_runtime::CryptoError::InvalidBufferLength);
        }
        let mut iv = [0u8; AES_BLOCK_SIZE];
        iv.copy_from_slice(&input[..AES_BLOCK_SIZE]);
        let cipher = Cipher::new(crypto).init(self.key(), &iv, mode, algorithm)?;
        cipher.finish(&input[AES_BLOCK_SIZE..], output)
    }

    fn cmac_payload(
        &self,
        apdu: Apdu<rustlet_runtime::Command>,
        crypto: &mut dyn CryptoBackend,
    ) -> ApduStatus {
        let header = apdu.header();
        let rx = apdu.as_receiving();
        let tag = match self.compute_cmac(crypto, header, rx.data()) {
            Ok(tag) => tag,
            Err(_) => return rx.reject(ApduStatus::internal_error()),
        };
        rx.accept_and_send(tag.as_ref())
    }

    fn verify_cmac_payload(
        &self,
        apdu: Apdu<rustlet_runtime::Command>,
        crypto: &mut dyn CryptoBackend,
    ) -> ApduStatus {
        let header = apdu.header();
        let rx = apdu.as_receiving();
        let data = rx.data();
        if data.len() < MAC_TAG_SIZE {
            return rx.reject(ApduStatus::wrong_length());
        }

        let expected = &data[..MAC_TAG_SIZE];
        let payload = &data[MAC_TAG_SIZE..];
        let verified = match self.verify_cmac(crypto, header, payload, expected) {
            Ok(verified) => verified,
            Err(_) => return rx.reject(ApduStatus::internal_error()),
        };
        let result = [if verified { 1 } else { 0 }];
        rx.accept_and_send(&result)
    }

    fn compute_cmac(
        &self,
        crypto: &mut dyn CryptoBackend,
        header: ApduHeader,
        payload: &[u8],
    ) -> Result<rustlet_runtime::MacTag, rustlet_runtime::CryptoError> {
        let mut mac = Mac::new(crypto).init(self.auth_key(), MacAlgorithm::AesCmac)?;
        mac.update(&[header.cla, header.ins, header.p1, header.p2])?;
        mac.update(payload)?;
        mac.compute()
    }

    fn verify_cmac(
        &self,
        crypto: &mut dyn CryptoBackend,
        header: ApduHeader,
        payload: &[u8],
        expected: &[u8],
    ) -> Result<bool, rustlet_runtime::CryptoError> {
        let mut mac = Mac::new(crypto).init(self.auth_key(), MacAlgorithm::AesCmac)?;
        mac.update(&[header.cla, header.ins, header.p1, header.p2])?;
        mac.update(payload)?;
        mac.verify(expected)
    }

    fn auth_key(&self) -> &[u8] {
        &self.auth_key[..self.auth_key_len as usize]
    }
}

fn is_ecb(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::Aes128EcbNoPadding | Algorithm::Aes256EcbNoPadding
    )
}
