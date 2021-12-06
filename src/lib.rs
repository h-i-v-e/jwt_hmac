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
            Self::InvalidHeader => f.write_str("unsupported header values"),
            Self::InvalidChecksum => f.write_str("checksum does not match"),
            Self::MissingPart => f.write_str(
                "expected 3 base 64 url encoded parts seperated by dots"
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

fn calc_checksum(secret: &[u8], value: &[u8]) -> Result<Output<Hmac<Sha256>>>{
    match hmac::Hmac::<Sha256>::new_from_slice(secret){
        Ok(mut hasher) => {
            hasher.update(value);
            Ok(hasher.finalize())
        },
        Err(error) => Err(Error::InvalidKeyLength(error))
    }
}

/// Deserialize the claims struct from a jwt token
///
/// #Example
///
/// ```
/// use jwt_hmac;
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
///  struct Claims{
///     sub: String
///  }
///
///  fn main(){
///     let secret = "I'm a secret".as_bytes();
///     match jwt_hmac::parse::<Claims>(
///         secret,
///         "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.azXPRJHeWcZ_B5WHtA98gsnowX5gifvMJX2hoH_4YPs"
///     ){
///         Ok(claims) => println!("Sub: {}", claims.sub),
///         Err(error) => match error{
///             jwt_hmac::Error::InvalidChecksum => println!("Secret doesn't match"),
///             _ => println!("Probably not a valid JWT: {}", error)
///         }
///     }
///  }
/// ```
pub fn parse<T>(secret: &[u8], token: &str) -> Result<T> where T: for<'a> Deserialize<'a> {
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

/// Generate a JWT token with the provided claims using the given secret
///
/// #Example
///
/// ```
/// use jwt_hmac;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
///  struct Claims{
///     sub: String,
///     name: String,
///     admin: bool
///  }
///
///  fn main(){
///     let secret = "I'm a secret".as_bytes();
///     let claims = Claims{
///         sub: "1234567890".to_string(),
///         name: "John Doe".to_string(),
///         admin: true
///     };
///     match jwt_hmac::create(secret, &claims) {
///         Ok(token) => println!("Token: {}", token),
///         Err(error) => println!("This can't be happening {}", error)
///     }
///  }
/// ```
pub fn create<T>(secret: &[u8], claims: &T) -> Result<String> where T: Serialize {
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
    use crate::{create, parse, Error};
    use serde::{Deserialize, Serialize};

    static SERIALIZED: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.azXPRJHeWcZ_B5WHtA98gsnowX5gifvMJX2hoH_4YPs";
    static BAD_CHECKSUM: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.azXPRJHeWcZ_B5aHtA98gsnowX5gifvMJX2hoH_4YPs";
    static NAME: &str = "John Doe";
    static SECRET: &str = "I'm a secret";

    #[derive(Serialize)]
    struct OutClaims{
        sub: String,
        name: String,
        admin: bool
    }

    #[derive(Deserialize)]
    struct InClaims{
        name: String
    }

    #[test]
    fn can_create() {
        let test = OutClaims{
            sub: "1234567890".to_string(),
            name: NAME.to_string(),
            admin: true
        };
        match create(SECRET.as_bytes(), &test){
            Ok(token) => assert_eq!(token.as_str(), SERIALIZED),
            Err(error) => panic!("{}", error)
        }
    }

    #[test]
    fn can_parse(){
        match parse::<InClaims>(SECRET.as_bytes(), SERIALIZED){
            Ok(claims) => assert_eq!(claims.name, NAME),
            Err(error) => panic!("{}", error)
        }
    }

    #[test]
    fn recognizes_bad_checksum(){
        match parse::<InClaims>(SECRET.as_bytes(), BAD_CHECKSUM){
            Ok(_) => assert!(false, "Should not recognize checksum"),
            Err(error) => match error {
                Error::InvalidChecksum => return,
                _ => assert!(false, "Should have produced Error::InvalidChecksum")
            }
        }
    }
}
