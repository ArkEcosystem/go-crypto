# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## Unreleased

## 1.0.0 - 2019-02-11

### Added

- Implement AIP11
- Implement AIP18

### Fixed

- Set transaction timestamp type as int32 instead of uint32, to cater for possible old transactions that have a negative timestamp.

## 0.2.1

### Fixed

- Skip recipient id in `ToBytes` for type 1 and 4 transactions.

## 0.2.0 - 2018-07-18

Several files and folders have been moved around for guideline compliance - see the [diff](https://github.com/ArkEcosystem/go-crypto/compare/0.1.0...0.2.0) for more details

### Fixed

- Multi Payment Serialisation & Deserialisation

### Added

- Slot helper
- Get Public Key from Hex
- Get Private Key from Hex
- Transaction to Map
- Transaction to JSON
- Fee Configuration
- Multi Signature Registration Signing
- Multi Signature Registration Verifying

### Removed

- Dropped `nethash` from networks as it was not used

## 0.1.2 - 2018-07-04

### Changed

- Return raw bytes from `SerialiseTransaction` _(instead of hex)_
- Renamed `createSignedTransaction` to `buildSignedTransaction`

## 0.1.0 - 2018-07-04

- Initial Release
