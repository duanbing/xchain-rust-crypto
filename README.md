# xchain-rust-crypto
[XuperChain](https://github.com/xuperchain/xuperchain) Rust Crypto;
deeply depends on [ring](https://github.com/briansmith/ring).

## Test
```
git clone https://github.com/duanbing/xchain-rust-crypto
cd xchain-rust-crypto
export  LANGS=$PWD/hdwallet
cargo test
```

## Design
[xchain-rust-crypto-intro](./xchain-rust-crypto-intrro.pdf)

## TODO
* [x] hash/aes/encoder
* [x] address and mnemonic
* [x] ecdsa
* [x] ecies, supported but is not compatible with go-ecies due to different AES used.
* [ ] schnorr and BLS multi-sig
* [ ] bulletproofs
* [ ] HD Wallet(BIP32)

