# Ark Go - Crypto

<p align="center">
    <img src="https://github.com/ArkEcosystem/go-crypto/blob/master/banner.png" />
</p>

> A simple Cryptography Implementation in Go for the Ark Blockchain.

[![Build Status](https://img.shields.io/travis/ArkEcosystem/go-crypto/master.svg?style=flat-square)](https://travis-ci.org/ArkEcosystem/go-crypto)
[![Latest Version](https://img.shields.io/github/release/ArkEcosystem/go-crypto.svg?style=flat-square)](https://github.com/ArkEcosystem/go-crypto/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## TO-DO

### AIP11 Serialization
- [x] Transfer
- [x] Second Signature Registration
- [x] Delegate Registration
- [x] Vote
- [x] Multi Signature Registration
- [x] IPFS
- [x] Timelock Transfer
- [x] Multi Payment
- [x] Delegate Resignation

### AIP11 Deserialization
- [x] Transfer
- [x] Second Signature Registration
- [x] Delegate Registration
- [x] Vote
- [x] Multi Signature Registration
- [ ] IPFS
- [ ] Timelock Transfer
- [ ] Multi Payment
- [ ] Delegate Resignation

### Transaction Signing
- [x] Transfer
- [x] Second Signature Registration
- [x] Delegate Registration
- [x] Vote
- [x] Multi Signature Registration

### Transaction Verifying
- [x] Transfer
- [x] Second Signature Registration
- [x] Delegate Registration
- [x] Vote
- [x] Multi Signature Registration

### Transaction
- [x] getId
- [x] sign
- [x] secondSign
- [x] verify
- [x] secondVerify
- [x] parseSignatures
- [x] serialize
- [ ] deserialize
- [x] toBytes
- [x] toArray
- [x] toJson

### Message
- [x] sign
- [x] verify
- [x] toArray
- [x] toJson

### Address
- [x] fromPassphrase
- [x] fromPublicKey
- [x] fromPrivateKey
- [x] validate

### Private Key
- [x] fromPassphrase
- [x] fromHex

### Public Key
- [x] fromPassphrase
- [x] fromHex

### WIF
- [x] fromPassphrase

### Configuration
- [x] getNetwork
- [x] setNetwork
- [ ] getFee
- [ ] setFee

### Slot
- [x] time
- [x] epoch

### Networks (Mainnet, Devnet & Testnet)
- [x] epoch
- [x] version
- [x] nethash
- [x] wif

## Installation

```bash
go get github.com/ArkEcosystem/go-crypto/crypto
```

## Documentation

Have a look at the [official documentation](https://docs.ark.io/v1.0/docs/cryptography-go) for advanced examples and features.

## Security

If you discover a security vulnerability within this package, please send an e-mail to security@ark.io. All security vulnerabilities will be promptly addressed.

## Credits

- [Brian Faust](https://github.com/faustbrian)
- [All Contributors](../../../../contributors)

## License

[MIT](LICENSE) © [ArkEcosystem](https://ark.io)
