# cyber-rs

![crates.io](https://img.shields.io/crates/v/cyber.svg)
![docs.rs](https://docs.rs/cyber/badge.svg)

Library for cyber blockchain

## Seed phrase
Seed phrase generation function

```rust
use cyber::mnemonic::*;
let phrase = generate_phrase();
```

## Wallet
Wallet generation function

```rust
let phrase = String::from("soap weird dutch gap region blossom antique economy legend loan ugly boring");
let sk = PrivateKeyWallet::from_seed(phrase, None);
let pk = PublicKeyWallet::from_private_key(sk.to_secret_key());
pk.to_address()
```
