use serde::{Serialize, Deserialize};
use base64_url;
use serde_json;
use hmac;
use hmac::{Mac, HmacCore};
use sha2::Sha256;
use std::fmt::{Display, Formatter};
use std::result;
use std::str::{from_utf8, Utf8Error};
use base64_url::base64::DecodeError;
use hmac::digest::{CtOutput, InvalidLength};
use hmac::digest::core_api::CoreWrapper;

static HEADER: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9";
static HEADER_LENGTH: usize = HEADER.len();
static SIGNATURE_LENGTH: usize = 43;
static MIN_TOKEN_LENGTH: usize = HEADER_LENGTH + SIGNATURE_LENGTH + 3;

#[derive(Debug)]
pub enum Error{
    JsonError(serde_json::error::Error),
    InvalidKeyLength(InvalidLength),
    Base64UrlDecodeError(DecodeError),
    Utf8Error(Utf8Error),
    InvalidHeader,
    InvalidChecksum,
    TooShort
}

pub type Result<T> = result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &*self{
            Self::JsonError(error) => error.fmt(f),
            Self::Base64UrlDecodeError(error) => error.fmt(f),
            Self::InvalidKeyLength(error) => error.fmt(f),
            Self::Utf8Error(error) => error.fmt(f),
            Self::InvalidHeader => f.write_str("unsupported header values"),
            Self::InvalidChecksum => f.write_str("checksum does not match"),
            Self::TooShort => f.write_str("token is too short")
        }
    }
}

impl std::error::Error for Error{}

impl From<Utf8Error> for Error{
    fn from(value: Utf8Error) -> Self {
        Self::Utf8Error(value)
    }
}

impl From<DecodeError> for Error{
    fn from(value: DecodeError) -> Self {
        Self::Base64UrlDecodeError(value)
    }
}

impl From<serde_json::error::Error> for Error{
    fn from(value: serde_json::Error) -> Self {
        Self::JsonError(value)
    }
}

impl From<InvalidLength> for Error{
    fn from(value: InvalidLength) -> Self {
        Self::InvalidKeyLength(value)
    }
}

fn calc_checksum(secret: &[u8], value: &[u8]) -> Result<CtOutput<CoreWrapper<HmacCore<Sha256>>>>{
    let mut hasher = hmac::Hmac::<Sha256>::new_from_slice(secret)?;
    hasher.update(value);
    Ok(hasher.finalize())
}

fn body_with_header<T>(claims: &T) -> Result<String> where T: Serialize {
    let serialized = base64_url::encode(serde_json::to_string(&claims)?.as_bytes());
    let mut output = String::with_capacity(serialized.len() + MIN_TOKEN_LENGTH);
    output.push_str(HEADER);
    output.push('.');
    output.push_str(serialized.as_str());
    Ok(output)
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
///         "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.6ekn8MWtOmVT6FMqbAlVQQmretopbWpef_lHV9dYMf4"
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
    let len = token.len();
    if len < MIN_TOKEN_LENGTH{
        return Err(Error::TooShort);
    }
    let bytes = token.as_bytes();
    if &bytes[..HEADER_LENGTH] != HEADER.as_bytes() {
        return Err(Error::InvalidHeader)
    }
    let sig_offset = len - SIGNATURE_LENGTH;
    let checksum = calc_checksum(secret, &bytes[..sig_offset - 1])?;
    let signature = base64_url::decode(from_utf8(&bytes[sig_offset..])?)?;
    if &*checksum.into_bytes() != signature.as_slice(){
        return Err(Error::InvalidChecksum);
    }
    Ok(serde_json::from_slice::<T>(
        base64_url::decode(&bytes[HEADER_LENGTH + 1 .. sig_offset - 1])?.as_slice()
    )?)
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
    let mut main = body_with_header(claims)?;
    let hash = base64_url::encode(
        &*calc_checksum(secret, main.as_bytes())?.into_bytes()
    );
    main.push('.');
    main.push_str(hash.as_str());
    Ok(main)
}

#[cfg(test)]
mod tests {
    use crate::{create, parse, Error};
    use serde::{Deserialize, Serialize};

    static SERIALIZED: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.6ekn8MWtOmVT6FMqbAlVQQmretopbWpef_lHV9dYMf4";
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
            Ok(token) => {
                assert_eq!(token.as_str(), SERIALIZED)
            },
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
