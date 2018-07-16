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
- [ ] Transfer
- [ ] Second Signature Registration
- [ ] Delegate Registration
- [ ] Vote
- [ ] Multi Signature Registration
- [ ] IPFS
- [ ] Timelock Transfer
- [ ] Multi Payment
- [ ] Delegate Resignation

### AIP11 Deserialization
- [ ] Transfer
- [ ] Second Signature Registration
- [ ] Delegate Registration
- [ ] Vote
- [ ] Multi Signature Registration
- [ ] IPFS
- [ ] Timelock Transfer
- [ ] Multi Payment
- [ ] Delegate Resignation

### Transaction Signing
- [ ] Transfer
- [ ] Second Signature Registration
- [ ] Delegate Registration
- [ ] Vote
- [ ] Multi Signature Registration

### Transaction Verifying
- [ ] Transfer
- [ ] Second Signature Registration
- [ ] Delegate Registration
- [ ] Vote
- [ ] Multi Signature Registration

### Transaction Entity
- [ ] getId
- [ ] sign
- [ ] secondSign
- [ ] parseSignatures
- [ ] serialize
- [ ] deserialize
- [ ] toBytes
- [ ] toArray
- [ ] toJson

### Message
- [ ] sign
- [ ] verify
- [ ] toArray
- [ ] toJson

### Address Identity
- [ ] fromPassphrase
- [ ] fromPublicKey
- [ ] fromPrivateKey
- [ ] validate

### Private Key Identity
- [ ] fromPassphrase
- [ ] fromHex

### Public Key Identity
- [ ] fromPassphrase
- [ ] fromHex

### WIF Identity
- [ ] fromPassphrase

### Configuration
- [ ] getNetwork
- [ ] setNetwork
- [ ] getFee
- [ ] setFee

### Slot
- [ ] time
- [ ] epoch

### Networks (Mainnet, Devnet & Testnet)
- [ ] epoch
- [ ] version
- [ ] nethash
- [ ] wif

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
