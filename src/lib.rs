use serde::{Serialize, Deserialize};
use base64_url;
use serde_json;
use hmac;
use hmac::{NewMac, Mac, Hmac};
use hmac::crypto_mac::{Output, InvalidKeyLength};
use sha2::Sha256;
use std::fmt::{Display, Formatter};
use std::result;
use base64_url::base64::DecodeError;

static HEADER: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9";

#[derive(Debug)]
pub enum Error{
    JsonError(serde_json::error::Error),
    InvalidKeyLength(InvalidKeyLength),
    Base64UrlDecodeError(DecodeError),
    InvalidHeader,
    InvalidChecksum,
    MissingPart
}

pub type Result<T> = result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &*self{
            Self::JsonError(error) => error.fmt(f),
            Self::Base64UrlDecodeError(error) => error.fmt(f),
            Self::InvalidKeyLength(error) => error.fmt(f),
            Self::InvalidHeader => f.write_str("Unsupported header values"),
            Self::InvalidChecksum => f.write_str("Checksum does not match"),
            Self::MissingPart => f.write_str(
                "Expected 3 base 64 url encoded parts seperated by dots"
            )
        }
    }
}

impl std::error::Error for Error{}

fn decode_part(part: Option<&str>) -> Result<Vec<u8>> {
    match part {
        Some(base64) => match base64_url::decode(base64){
            Ok(result) => Ok(result),
            Err(err) => {
                Err(Error::Base64UrlDecodeError(err))
            }
        },
        None => Err(Error::MissingPart)
    }
}

fn calc_checksum(secret: &str, value: &[u8]) -> Result<Output<Hmac<Sha256>>>{
    match hmac::Hmac::<Sha256>::new_from_slice(
        secret.as_bytes()
    ){
        Ok(mut hasher) => {
            hasher.update(value);
            Ok(hasher.finalize())
        },
        Err(error) => Err(Error::InvalidKeyLength(error))
    }
}

pub fn parse<T>(secret: &str, token: &str) -> Result<T>
    where T: Serialize + for<'a> Deserialize<'a> {
    let mut parts = token.split('.');
    match parts.next(){
        Some(header) => {
            if header != HEADER{
                return Err(Error::InvalidHeader)
            }
        },
        None => return Err(Error::InvalidHeader)
    }
    let claims = decode_part(parts.next())?;
    let hash = decode_part(parts.next())?;
    if calc_checksum(secret, claims.as_slice())?.into_bytes().as_slice() != hash.as_slice() {
        return Err(Error::InvalidChecksum);
    }
    match serde_json::from_slice::<T>(claims.as_slice()){
        Ok(claims) => Ok(claims),
        Err(error) => {
            Err(Error::JsonError(error))
        }
    }
}

pub fn create<T>(secret: &str, claims: &T) -> Result<String>
    where T: Serialize + for<'a> Deserialize<'a> {
    match serde_json::to_string(claims){
        Ok(json) => Ok(format!(
            "{}.{}.{}",
            HEADER,
            base64_url::encode(json.as_bytes()),
            base64_url::encode(
                calc_checksum(secret, json.as_bytes())?.into_bytes().as_slice()
            )
        )),
        Err(error) => Err(Error::JsonError(error))
    }
}

#[cfg(test)]
mod tests {
    use crate::{create, parse};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Test{
        value: String
    }

    #[test]
    fn it_works() {
        let secret = "I'm a secret";
        let test = Test{
            value: "Testing".to_string()
        };
        let token = create(secret, &test).unwrap();
        assert_eq!(parse::<Test>(secret, &token).unwrap().value, test.value);
    }
}
