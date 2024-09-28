use {
    chrono::{DateTime, Duration, Utc},
    openssl::{
        encrypt::{Decrypter, Encrypter},
        error::ErrorStack,
        hash::MessageDigest,
        pkey::{PKey, Private, Public},
        rsa::Padding,
        sign::{Signer, Verifier},
    },
    serde::{Deserialize, Serialize},
};

pub mod client;
pub mod server;

pub use client::Client;
pub use server::Server;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: u32,
    pub name: String,
    pub display_name: String,
    pub picture: String,
    pub email: Option<String>,
    pub created: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct Message {
    service: u32,
    message: Vec<u8>,
    signature: Vec<u8>,
}

impl Message {
    pub fn service(&self) -> u32 {
        self.service
    }
}

#[derive(Serialize, Deserialize)]
pub struct BinaryMessage {
    pub data: String,
}

#[derive(Serialize, Deserialize)]
enum ServerMessage {
    QueryAuthenticationRequest(u64),
}

#[derive(Serialize, Deserialize)]
enum AuthenticationRequestAnswer {
    NotFound,
    None,
    Some(User),
}

#[derive(Serialize, Deserialize)]
struct InnerMessage<T> {
    now: DateTime<Utc>,
    service: u32,
    message: T,
}

#[derive(Debug)]
pub enum EncryptionError {
    SerializationError(bincode::ErrorKind),
    OpensslError(ErrorStack),
}

fn encrypt_message<T: Serialize>(
    message: T,
    public_key: &PKey<Public>,
    private_key: &PKey<Private>,
    service: u32,
) -> Result<Message, EncryptionError> {
    let data = bincode::serialize(&InnerMessage {
        now: Utc::now(),
        service,
        message,
    })
    .map_err(|err| EncryptionError::SerializationError(*err))?;

    let mut encrypter = Encrypter::new(public_key).map_err(EncryptionError::OpensslError)?;
    encrypter
        .set_rsa_padding(Padding::PKCS1)
        .map_err(EncryptionError::OpensslError)?;

    let buffer_len = encrypter
        .encrypt_len(&data)
        .map_err(EncryptionError::OpensslError)?;

    let mut message = vec![0; buffer_len];

    let encrypted_len = encrypter
        .encrypt(&data, &mut message)
        .map_err(EncryptionError::OpensslError)?;

    message.truncate(encrypted_len);

    let mut signer =
        Signer::new(MessageDigest::sha256(), private_key).map_err(EncryptionError::OpensslError)?;

    signer
        .update(&data)
        .map_err(EncryptionError::OpensslError)?;

    let signature = signer
        .sign_to_vec()
        .map_err(EncryptionError::OpensslError)?;

    Ok(Message {
        service,
        message,
        signature,
    })
}

#[derive(Debug)]
pub enum DecryptionError {
    WrongService,
    ServiceMissmatch,
    InvalidTimestamp,
    TimestampVerificationError,
    InvalidVerification,
    OpensslError(ErrorStack),
    DeserializationError(bincode::ErrorKind),
}

fn decrypt_message<'a, T: Deserialize<'a>>(
    message: Message,
    decrypted: &'a mut Vec<u8>,
    public_key: &PKey<Public>,
    private_key: &PKey<Private>,
    service: Option<u32>,
) -> Result<T, DecryptionError> {
    if let Some(service) = service {
        if service != message.service {
            return Err(DecryptionError::WrongService);
        }
    }

    let mut decrypter = Decrypter::new(private_key).map_err(DecryptionError::OpensslError)?;
    decrypter
        .set_rsa_padding(Padding::PKCS1)
        .map_err(DecryptionError::OpensslError)?;

    let buffer_len = decrypter
        .decrypt_len(&message.message)
        .map_err(DecryptionError::OpensslError)?;
    *decrypted = vec![0; buffer_len];

    let decrypted_len = decrypter
        .decrypt(&message.message, decrypted)
        .map_err(DecryptionError::OpensslError)?;
    decrypted.truncate(decrypted_len);

    let mut verifier = Verifier::new(MessageDigest::sha256(), public_key)
        .map_err(DecryptionError::OpensslError)?;

    verifier
        .update(decrypted)
        .map_err(DecryptionError::OpensslError)?;

    if !verifier
        .verify(&message.signature)
        .map_err(DecryptionError::OpensslError)?
    {
        return Err(DecryptionError::InvalidVerification);
    }

    let inner_message = bincode::deserialize::<InnerMessage<T>>(decrypted)
        .map_err(|err| DecryptionError::DeserializationError(*err))?;

    if inner_message.service != message.service {
        return Err(DecryptionError::ServiceMissmatch);
    }

    let duration = Utc::now().signed_duration_since(inner_message.now);
    let max_duration = Duration::from_std(std::time::Duration::from_secs(15))
        .map_err(|_| DecryptionError::TimestampVerificationError)?;

    if duration > max_duration || duration < Duration::zero() {
        return Err(DecryptionError::InvalidTimestamp);
    }

    Ok(inner_message.message)
}

impl TryFrom<Message> for BinaryMessage {
    type Error = bincode::Error;

    fn try_from(value: Message) -> Result<Self, Self::Error> {
        Ok(Self {
            data: base64_url::escape(&base64_url::encode(&bincode::serialize(&value)?))
                .into_owned(),
        })
    }
}

#[derive(Debug)]
pub enum BinaryMessageDeserializationError {
    Bincode(bincode::Error),
    Base64(base64_url::base64::DecodeError),
}

impl TryInto<Message> for BinaryMessage {
    type Error = BinaryMessageDeserializationError;

    fn try_into(self) -> Result<Message, Self::Error> {
        bincode::deserialize(
            &base64_url::decode(&base64_url::unescape(&self.data).into_owned())
                .map_err(BinaryMessageDeserializationError::Base64)?,
        )
        .map_err(BinaryMessageDeserializationError::Bincode)
    }
}
