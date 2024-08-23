use openssl::{
    error::ErrorStack,
    pkey::{PKey, Private, Public},
};
use rand::RngCore;

use crate::{
    decrypt_message, encrypt_message, DecryptionError, EncryptionError, Message, ServerMessage,
    User,
};

struct AuthenticationRequest {
    id: u64,
    service: i32,
    user: User,
}

pub struct Server {
    key: PKey<Private>,
    requests: Vec<AuthenticationRequest>,
}

#[derive(Debug)]
pub enum Error {
    InvalidPublicKey(ErrorStack),
    DecryptionError(DecryptionError),
    EncryptionError(EncryptionError),
    DecodeError(base64_url::base64::DecodeError),
    DeserializationError(bincode::Error),
}

impl Server {
    pub fn new(key: &[u8]) -> Result<Self, ErrorStack> {
        Ok(Self {
            key: PKey::private_key_from_pem(key)?,
            requests: Vec::new(),
        })
    }

    pub fn process_message(&mut self, msg: Message, key: &[u8]) -> Result<Message, Error> {
        let service = msg.service;
        let public_key = PKey::public_key_from_pem(key).map_err(Error::InvalidPublicKey)?;
        let mut decrypted = Vec::new();
        let msg = decrypt_message(msg, &mut decrypted, &public_key, &self.key, None)
            .map_err(Error::DecryptionError)?;

        match msg {
            ServerMessage::QueryAuthenticationRequest(id) => {
                self.query_authentication_request(service, id, &public_key)
            }
        }
    }

    fn query_authentication_request(
        &mut self,
        service: i32,
        id: u64,
        public_key: &PKey<Public>,
    ) -> Result<Message, Error> {
        let message = self
            .requests
            .iter()
            .position(|r| r.id == id && r.service == service)
            .map(|i| self.requests.swap_remove(i).user);
        encrypt_message(message, public_key, &self.key, service).map_err(Error::EncryptionError)
    }

    pub fn answer_authentication_request(&mut self, service: i32, user: User) -> u64 {
        let mut id;

        loop {
            id = rand::thread_rng().next_u64();

            if !self
                .requests
                .iter()
                .any(|r| r.id == id && r.service == service)
            {
                break;
            }
        }

        self.requests
            .push(AuthenticationRequest { id, service, user });

        id
    }
}
