use serde::de::DeserializeOwned;
use serde::{Serialize, Deserialize};
use base64_url;
use serde_json;
use hmac;
use hmac::{Mac, HmacCore};
use sha2::Sha256;
use thiserror::Error;
use std::str::{from_utf8, Utf8Error};
use base64_url::base64::DecodeError;
use hmac::digest::{CtOutput, InvalidLength};
use hmac::digest::core_api::CoreWrapper;

static HEADER: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9";
static HEADER_LENGTH: usize = HEADER.len();
static SIGNATURE_LENGTH: usize = 43;
static MIN_TOKEN_LENGTH: usize = HEADER_LENGTH + SIGNATURE_LENGTH + 3;

#[derive(Debug, Error)]
pub enum Error{
    #[error(transparent)]
    JsonError(#[from] serde_json::error::Error),
    #[error(transparent)]
    InvalidKeyLength(#[from] InvalidLength),
    #[error("{0}")]
    Base64UrlDecodeError(DecodeError),
    #[error(transparent)]
    Utf8Error(#[from] Utf8Error),
    #[error("unsupported header values")]
    InvalidHeader,
    #[error("signature does not match")]
    SignatureDoesNotMatch,
    #[error("too short to be a valid JWT")]
    TooShort
}

impl From<DecodeError> for Error{
    fn from(value: DecodeError) -> Self {
        Self::Base64UrlDecodeError(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn calc_signature(secret: &[u8], value: &[u8]) -> Result<CtOutput<CoreWrapper<HmacCore<Sha256>>>>{
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

/// A decoded JWT split into the pieces needed for payload extraction and
/// signature verification.
///
/// This type parses tokens produced by this crate's fixed HS256 header format.
/// Use [`TryFrom<&str>`] to decode the token, [`DecodedJwtHmac::check_signature`]
/// to verify it against a secret, and
/// [`DecodedJwtHmac::try_extract_claims`] to deserialize the payload.
pub struct DecodedJwtHmac<'a>{
    /// The original `header.payload` bytes used as the HMAC input.
    pub encoded_header_and_body: &'a [u8],
    /// The decoded JWT payload bytes.
    pub decoded_body: Vec<u8>,
    /// The decoded JWT signature bytes.
    pub decoded_signature: Vec<u8>
}

impl<'a> TryFrom<&'a str> for DecodedJwtHmac<'a>{
    type Error = Error;

    fn try_from(token: &'a str) -> std::result::Result<Self, Self::Error> {
        let len = token.len();
        if len < MIN_TOKEN_LENGTH{
            return Err(Error::TooShort);
        }
        let bytes = token.as_bytes();
        if &bytes[..HEADER_LENGTH] != HEADER.as_bytes() {
            return Err(Error::InvalidHeader)
        }
        let sig_offset = len - SIGNATURE_LENGTH;
        Ok(Self{
            encoded_header_and_body: &bytes[..sig_offset - 1],
            decoded_body: base64_url::decode(&bytes[HEADER_LENGTH + 1 .. sig_offset - 1])?,
            decoded_signature: base64_url::decode(from_utf8(&bytes[sig_offset..])?)?
        })
    }
}

impl DecodedJwtHmac<'_>{
    /// Deserialize the decoded payload into a claims type.
    pub fn try_extract_claims<T: DeserializeOwned>(&self) -> Result<T>{
        Ok(serde_json::from_slice(&self.decoded_body.as_slice())?)
    }

    /// Verify that the decoded signature matches `secret`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SignatureDoesNotMatch`] when the signature is validly
    /// decoded but does not match the HMAC-SHA256 signature computed from
    /// `secret`.
    pub fn check_signature(&self, secret: &[u8]) -> Result<()>{
         let signature = calc_signature(secret, self.encoded_header_and_body)?;
         if &*signature.into_bytes() == self.decoded_signature.as_slice(){
            Ok(())
         }
         else {
            Err(Error::SignatureDoesNotMatch)
         }
    }
}

/// Deserialize the claims struct from a jwt token
///
/// #Example
///
/// ```
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
///             jwt_hmac::Error::SignatureDoesNotMatch => println!("Secret doesn't match"),
///             _ => println!("Probably not a valid JWT: {}", error)
///         }
///     }
///  }
/// ```
pub fn parse<T>(secret: &[u8], token: &str) -> Result<T> where T: for<'a> Deserialize<'a> {
    let hmac = DecodedJwtHmac::try_from(token)?;
    hmac.check_signature(secret)?;
    hmac.try_extract_claims()
}

/// Generate a JWT token with the provided claims using the given secret
///
/// #Example
///
/// ```
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
        &*calc_signature(secret, main.as_bytes())?.into_bytes()
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
                Error::SignatureDoesNotMatch => return,
                _ => assert!(false, "Should have produced Error::InvalidChecksum")
            }
        }
    }
}
