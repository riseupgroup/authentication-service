use {
    openssl::{
        error::ErrorStack,
        pkey::{PKey, Private, Public},
    },
    std::fmt,
};

use crate::{
    decrypt_message, encrypt_message, DecryptionError, EncryptionError, ServerMessage, User,
};

pub struct Client {
    service_id: u32,
    http_client: reqwest::Client,
    key: PKey<Private>,
    host: String,
    host_key: PKey<Public>,
}

impl Client {
    pub const fn service_id(&self) -> u32 {
        self.service_id
    }

    pub const fn host(&self) -> &String {
        &self.host
    }
}

#[derive(Debug, Clone)]
pub enum CreationError {
    InvalidPrivateKey(ErrorStack),
    InvalidPublicHostKey(ErrorStack),
}

impl fmt::Display for CreationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidPrivateKey(err) => write!(f, "Invalid private key: {err}"),
            Self::InvalidPublicHostKey(err) => write!(f, "Invalid public host key: {err}"),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    DecryptionError(DecryptionError),
    EncryptionError(EncryptionError),
    SerializationError(bincode::Error),
    DeserializationError(bincode::Error),
    ReqwestError(reqwest::Error),
    DecodeError(base64_url::base64::DecodeError),
    NoDataReturned,
}

impl Client {
    pub fn new(
        service_id: u32,
        key: &[u8],
        host: String,
        host_key: &[u8],
    ) -> Result<Self, CreationError> {
        Ok(Self {
            service_id,
            http_client: reqwest::Client::new(),
            key: PKey::private_key_from_pem(key)
                .map_err(CreationError::InvalidPrivateKey)?,
            host,
            host_key: PKey::public_key_from_pem(host_key)
                .map_err(CreationError::InvalidPublicHostKey)?,
        })
    }

    pub fn get_redirect_url(&self) -> String {
        format!("https://{}/service/{}/login", self.host, self.service_id)
    }

    pub async fn query_authentication_request(&self, id: u64) -> Result<User, Error> {
        let msg = encrypt_message(
            ServerMessage::QueryAuthenticationRequest(id),
            &self.host_key,
            &self.key,
            self.service_id,
        )
        .map_err(Error::EncryptionError)?;

        let res = self
            .http_client
            .post(format!("https://{}/api/authentication_service", self.host))
            .body(bincode::serialize(&msg).map_err(Error::SerializationError)?)
            .send()
            .await
            .map_err(Error::ReqwestError)?;

        let bytes = res.bytes().await.map_err(Error::ReqwestError)?;
        let message = bincode::deserialize(&bytes).map_err(Error::DeserializationError)?;

        let mut decrypted = Vec::new();
        let user: Option<User> = decrypt_message::<Option<User>>(
            message,
            &mut decrypted,
            &self.host_key,
            &self.key,
            Some(self.service_id),
        )
        .map_err(Error::DecryptionError)?;

        user.ok_or(Error::NoDataReturned)
    }
}
