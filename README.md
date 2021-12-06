A simple library for generating and parsing JWT tokens using HMAC SHA256
as per https://jwt.io/introduction

###Encoding example

```rust
use jwt_hmac;
use serde::Serialize;

#[derive(Serialize)]
struct Claims{
    sub: String,
    name: String,
    admin: bool
}

fn main(){
    let secret = "I'm a secret".as_bytes();
    let claims = Claims{
        sub: "1234567890".to_string(),
        name: "John Doe".to_string(),
        admin: true
    };
    match jwt_hmac::create(secret, &claims) {
        Ok(token) => println!("Token: {}", token),
        Err(error) => println!("This can't be happening {}", error)
    }
}
```

###Decoding example

```rust
use jwt_hmac;
use serde::Deserialize;

#[derive(Deserialize)]
struct Claims{
   sub: String
}

fn main(){
   let secret = "I'm a secret".as_bytes();
   match jwt_hmac::parse::<Claims>(
       secret,
       "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.azXPRJHeWcZ_B5WHtA98gsnowX5gifvMJX2hoH_4YPs"
  ){
         Ok(claims) => println!("Sub: {}", claims.sub),
         Err(error) => match error{
             jwt_hmac::Error::InvalidChecksum => println!("Secret doesn't match"),
             _ => println!("Probably not a valid JWT: {}", error)
         }
     }
}
 ```

As illustrated in the examples above you can fill your claims with bloat for the client and
have the back end only extract the useful bits when parsing.
