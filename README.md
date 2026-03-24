# Ergo Sigma-Rust (PiggyTrade Extended Fork)

**This is a customized fork of [ergoplatform/sigma-rust](https://github.com/ergoplatform/sigma-rust) maintained for the [PiggyTrade](https://github.com/FlyingPig5/piggy-trade) project.**

Branch: `extended-bindings` (based on upstream `develop`)

### Why this exists
The official `ergo-lib-jni` (Java/Kotlin) bindings in the upstream repository provide low-level access to Ergo's core features. However, for a mobile-first application like PiggyTrade, we require high-performance, higher-level abstractions implemented directly in the Rust layer to ensure security and speed.

### Key Enhancements
This fork extends the official bindings with the following features:

#### Extended JNI (Kotlin/Java) Bindings
We have significantly expanded `bindings/ergo-lib-jni` to include three new JNI entry points exposed via the `WalletLib` Kotlin object:

##### `mnemonicToAddress`
Secure derivation of Ergo P2PK addresses from BIP39 mnemonics using EIP-3 derivation paths (`m/44'/429'/0'/0/{index}`) directly in Rust, avoiding sensitive data exposure in the JVM layer.

| Parameter | Type | Description |
|-----------|------|-------------|
| `mnemonic` | `String` | BIP39 mnemonic phrase |
| `mnemonicPass` | `String` | Optional passphrase (empty string for none) |
| `index` | `Int` | EIP-3 child index (0 = primary address) |
| `isMainnet` | `Boolean` | `true` for mainnet, `false` for testnet |
| **Returns** | `String` | Base58-encoded Ergo P2PK address |

##### `buildReducedTxBytes`
Simplified construction of `ReducedTransaction` objects, optimized for integration with the **ErgoPay (EIP-20)** protocol. Returns a base64url-encoded byte array suitable for embedding in `ergopay:` URIs.

| Parameter | Type | Description |
|-----------|------|-------------|
| `inputBoxesJson` | `String` | JSON array of sanitized input box objects |
| `dataInputBoxesJson` | `String` | JSON array of data input box objects (`"[]"` if none) |
| `outputCandidatesJson` | `String` | JSON array of output candidates in ergo-lib JSON format |
| `feeNano` | `Long` | Miner fee in nanoERGs |
| `changeAddress` | `String` | Change address (base58) |
| `currentHeight` | `Int` | Current blockchain height |
| `lastBlockHeadersJson` | `String` | JSON array of last 10 block headers |
| `contextExtensionsJson` | `String` | JSON map of `{input_index: {key: hex_value}}` (`"{}"` if none) |
| **Returns** | `String` | Base64url-encoded `ReducedTransaction` bytes |

##### `signTransactionJson`
A unified signing entry point that handles input boxes, data inputs, output candidates, context extensions, and miner fees in a single native call. Derives EIP-3 signing keys dynamically based on the `derivationCount` parameter.

| Parameter | Type | Description |
|-----------|------|-------------|
| `mnemonic` | `String` | BIP39 mnemonic phrase |
| `mnemonicPass` | `String` | Optional passphrase (empty string for none) |
| `inputBoxesJson` | `String` | JSON array of sanitized input box objects |
| `dataInputBoxesJson` | `String` | JSON array of data input box objects (`"[]"` if none) |
| `outputCandidatesJson` | `String` | JSON array of output candidates |
| `feeNano` | `Long` | Miner fee in nanoERGs |
| `changeAddress` | `String` | Change address (base58) |
| `currentHeight` | `Int` | Current blockchain height |
| `lastBlockHeadersJson` | `String` | JSON array of last 10 block headers |
| `contextExtensionsJson` | `String` | JSON map of `{input_index: {key: hex_value}}` (`"{}"` if none) |
| `derivationCount` | `Int` | Number of EIP-3 addresses to derive keys for (= wallet address count) |
| **Returns** | `String` | JSON-serialized signed transaction |

##### `signReducedTxBytes`
Signs an ErgoPay `ReducedTransaction` (received as base64-encoded bytes) using mnemonic-derived keys. This is the counterpart to `signTransactionJson` for ErgoPay (EIP-20) flows where the dApp provides a pre-built reduced transaction rather than raw inputs/outputs.

| Parameter | Type | Description |
|-----------|------|-------------|
| `reducedTxBase64` | `String` | Base64-encoded `ReducedTransaction` bytes (supports URL-safe and standard encodings) |
| `mnemonic` | `String` | BIP39 mnemonic phrase |
| `mnemonicPass` | `String` | Optional passphrase (empty string for none) |
| `derivationCount` | `Int` | Number of EIP-3 addresses to derive signing keys for |
| **Returns** | `String` | JSON-serialized signed transaction |

##### `parseReducedTxBytes`
Parses a base64-encoded `ReducedTransaction` to extract human-readable transaction details without signing. Used for displaying transaction previews in the wallet UI before the user approves signing.

| Parameter | Type | Description |
|-----------|------|-------------|
| `reducedTxBase64` | `String` | Base64-encoded `ReducedTransaction` bytes |
| **Returns** | `String` | JSON object with `inputs` (array of box ID strings), `outputs` (array of `{address, value, tokens}`), `inputCount`, and `outputCount` |

**Return format:**
```json
{
  "inputs": ["boxId1", "boxId2"],
  "outputs": [
    {
      "address": "9f...",
      "value": 1000000000,
      "tokens": [{"tokenId": "abc...", "amount": 100}]
    }
  ],
  "inputCount": 2,
  "outputCount": 1
}
```

#### Multi-Address Signing (EIP-3)
`signTransactionJson` and `signReducedTxBytes` derive secret keys for `derivationCount` derivation indices (`m/44'/429'/0'/0/0` through `m/44'/429'/0'/0/{n-1}`), allowing the wallet to sign transaction inputs belonging to **any** of the wallet's EIP-3 derived addresses. The Kotlin caller passes `walletAddresses.size`, so there is no hardcoded limit — wallets with 1 address or 100+ addresses are both supported.

#### ErgoPay (EIP-20) Support
Full support for the ErgoPay protocol flow:
- `parseReducedTxBytes` enables tx preview (showing inputs, outputs, values, tokens, addresses)
- `signReducedTxBytes` signs the reduced tx with the wallet's mnemonic-derived keys
- Base64 decoding supports all common variants: URL-safe (with/without padding) and standard (with/without padding)

#### Data Inputs Support
Both `buildReducedTxBytes` and `signTransactionJson` accept a `dataInputBoxesJson` parameter for read-only data inputs. These are included in the `TransactionContext` for script evaluation but not consumed as transaction inputs.

#### Context Extensions Support
Both functions accept `contextExtensionsJson` — a JSON map of `{input_index: {key: hex_value}}` — enabling custom context variables for individual inputs. This is essential for interacting with smart contracts that require auxiliary data (e.g., stablecoin protocols, DEX contracts).

#### Optimized SDK Workspace
We maintain a tailored workspace for JNI bindings with added dependencies:
- `indexmap` (for ordered context extension maps)
- `base64` (for ErgoPay encoding)


### Changes from Upstream

| Area | Upstream (`develop`) | This fork (`extended-bindings`) |
|------|---------------------|--------------------------------|
| JNI Functions | `addressFromTestNet`, `addressDelete` | + `mnemonicToAddress`, `buildReducedTxBytes`, `signTransactionJson`, `signReducedTxBytes`, `parseReducedTxBytes` |
| ErgoPay (EIP-20) | N/A | Full support: parse and sign reduced transactions |
| Key Derivation | N/A | EIP-3 derivation for N indices (dynamic, passed from caller) |
| Data Inputs | N/A | Full support in both build and sign |
| Context Extensions | N/A | Full support via JSON map |
| Cargo Dependencies | `jni`, `ergo-lib`, `ergo-lib-c-core`, `base64`, `serde_json` | + `indexmap` |
| Kotlin Bindings | Minimal (`addressFromTestNet`, `addressDelete`) | Full API surface with KDoc |

---

[![Coverage Status](https://coveralls.io/repos/github/ergoplatform/sigma-rust/badge.svg)](https://coveralls.io/github/ergoplatform/sigma-rust)

Rust implementation of [ErgoScript](https://github.com/ScorexFoundation/sigmastate-interpreter) cryptocurrency scripting language.

See [Architecture](docs/architecture.md) for high-level overview.

## Crates

[ergo-lib](https://github.com/ergoplatform/sigma-rust/tree/develop/ergo-lib) [![Latest Version](https://img.shields.io/crates/v/ergo-lib.svg)](https://crates.io/crates/ergo-lib) [![Documentation](https://docs.rs/ergo-lib/badge.svg)](https://docs.rs/crate/ergo-lib)

Overarching crate exposing wallet-related features: chain types (transactions, boxes, etc.), JSON serialization, box selection for tx inputs, tx builder and signing. Exports other crates API, probably the only crate you'd need to import.

[ergotree-interpreter](https://github.com/ergoplatform/sigma-rust/tree/develop/ergotree-interpreter) [![Latest Version](https://img.shields.io/crates/v/ergotree-interpreter.svg)](https://crates.io/crates/ergotree-interpreter) [![Documentation](https://docs.rs/ergotree-interpreter/badge.svg)](https://docs.rs/crate/ergotree-interpreter)

ErgoTree interpreter

[ergotree-ir](https://github.com/ergoplatform/sigma-rust/tree/develop/ergotree-ir) [![Latest Version](https://img.shields.io/crates/v/ergotree-ir.svg)](https://crates.io/crates/ergotree-ir) [![Documentation](https://docs.rs/ergotree-ir/badge.svg)](https://docs.rs/crate/ergotree-ir)

ErgoTree IR and serialization.

[ergoscript-compiler](https://github.com/ergoplatform/sigma-rust/tree/develop/ergoscript-compiler) [![Latest Version](https://img.shields.io/crates/v/ergoscript-compiler.svg)](https://crates.io/crates/ergoscript-compiler) [![Documentation](https://docs.rs/ergoscript-compiler/badge.svg)](https://docs.rs/crate/ergoscript-compiler)

ErgoScript compiler.

[sigma-ser](https://github.com/ergoplatform/sigma-rust/tree/develop/sigma-ser) [![Latest Version](https://img.shields.io/crates/v/sigma-ser.svg)](https://crates.io/crates/sigma-ser) [![Documentation](https://docs.rs/sigma-ser/badge.svg)](https://docs.rs/crate/sigma-ser)

Ergo binary serialization primitives.

Bindings:

- [ergo-lib-wasm(Wasm)](https://github.com/ergoplatform/sigma-rust/tree/develop/bindings/ergo-lib-wasm) [![Latest Version](https://img.shields.io/crates/v/ergo-lib-wasm.svg)](https://crates.io/crates/ergo-lib-wasm) [![Documentation](https://docs.rs/ergo-lib-wasm/badge.svg)](https://docs.rs/crate/ergo-lib-wasm) 
- [ergo-lib-wasm-browser(JS/TS)](https://github.com/ergoplatform/sigma-rust/tree/develop/bindings/ergo-lib-wasm) [![Latest version](https://img.shields.io/npm/v/ergo-lib-wasm-browser)](https://www.npmjs.com/package/ergo-lib-wasm-browser)
- [ergo-lib-wasm-nodejs(JS/TS)](https://github.com/ergoplatform/sigma-rust/tree/develop/bindings/ergo-lib-wasm) [![Latest version](https://img.shields.io/npm/v/ergo-lib-wasm-nodejs)](https://www.npmjs.com/package/ergo-lib-wasm-nodejs)
- [ergo-lib-ios(Swift)](https://github.com/ergoplatform/sigma-rust/tree/develop/bindings/ergo-lib-ios)
- [ergo-lib-jni(Java)](https://github.com/ergoplatform/sigma-rust/tree/develop/bindings/ergo-lib-jni) [![Latest Version](https://img.shields.io/crates/v/ergo-lib-jni.svg)](https://crates.io/crates/ergo-lib-jni) [![Documentation](https://docs.rs/ergo-lib-jni/badge.svg)](https://docs.rs/crate/ergo-lib-jni)
- [ergo-lib-c (C)](https://github.com/ergoplatform/sigma-rust/tree/develop/bindings/ergo-lib-c) [![Latest Version](https://img.shields.io/crates/v/ergo-lib-c.svg)](https://crates.io/crates/ergo-lib-c) [![Documentation](https://docs.rs/ergo-lib-c/badge.svg)](https://docs.rs/crate/ergo-lib-c)
- [ergo-lib-go (Go)](https://github.com/sigmaspace-io/ergo-lib-go) [![Go Reference](https://pkg.go.dev/badge/github.com/sigmaspace-io/ergo-lib-go.svg)](https://pkg.go.dev/github.com/sigmaspace-io/ergo-lib-go)
- [sigma_rb(Ruby)](https://github.com/thedlop/sigma_rb)[![Gem Version](https://badge.fury.io/rb/sigma_rb.svg)](https://badge.fury.io/rb/sigma_rb)
- [ergo-lib-python](https://github.com/ergoplatform/sigma-rust/tree/develop/bindings/ergo-lib-python)
[![PyPI version](https://badge.fury.io/py/ergo-lib-python.svg)](https://badge.fury.io/py/ergo-lib-python)
[![Documentation](https://readthedocs.org/projects/ergo-lib-python/badge/?version=latest&style=flat)](https://ergo-lib-python.readthedocs.io)

## Changelog

See [CHANGELOG.md](ergo-lib/CHANGELOG.md).

## Usage Examples

To get better understanding on how to use it in your project check out how its being used in the following projects:

Rust:

- [Oracle Core](https://github.com/ergoplatform/oracle-core);
- [Ergo Headless dApp Framework](https://github.com/Emurgo/ergo-headless-dapp-framework);
- [Ergo Node Interface Library](https://github.com/Emurgo/ergo-node-interface);
- [Spectrum Off-Chain Services for Ergo](https://github.com/spectrum-finance/spectrum-offchain-ergo);
- [AgeUSD Stablecoin Protocol](https://github.com/Emurgo/age-usd);
- [ErgoNames SDKs](https://github.com/ergonames/sdk/tree/master/rust)

TS/JS:

- [Ergo SDK](https://github.com/ergolabs/ergo-sdk-js) (Wasm bindings);
- [Yoroi wallet](https://github.com/Emurgo/yoroi-frontend) (Wasm bindings);
- [Ergo Desktop Wallet](https://github.com/ErgoWallet/ergowallet-desktop) (Wasm bindings);

Examples:

- [Create transaction demo](https://github.com/ergoplatform/sigma-rust/tree/develop/bindings/ergo-lib-wasm/examples/create-transaction-demo) (TS)
- [Address generation demo](https://github.com/ergoplatform/sigma-rust/tree/develop/bindings/ergo-lib-wasm/examples/address-generation-demo) (TS)

Also take a look at tests where various usage scenarios were implemented.

## Contributing

See [Contributing](CONTRIBUTING.md) guide.

Feel free to join the [Ergo Discord](https://discord.gg/kj7s7nb) and ask questions on `#sigma-rust` channel.
