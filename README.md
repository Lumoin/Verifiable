<img style="display: block; margin-inline-start: auto; margin-inline-end: auto;" src="resources/verifiable-github-logo.svg" width="800" height="400" alt="Verifiable project logo: A shield in blue hues with a rounded top that narrows downwards in a 'V' like shape. In the center there is the tip of white 'V' that elongates across the left corner of the shield to white background. Underneath the lower side of 'V' there is a stylistic key handle also elongating over the edge of the shield.">

# Verifiable

**An integrated .NET stack for decentralized identity: DIDs, verifiable credentials, selective disclosure, and hardware-backed cryptography.**

![Main build workflow](https://github.com/lumoin/Verifiable/actions/workflows/main.yml/badge.svg)
[![Mutation testing badge](https://img.shields.io/endpoint?style=for-the-badge&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2Flumoin%2FVerifiable%2Fmain)](https://dashboard.stryker-mutator.io/reports/github.com/lumoin/Verifiable/main)

---

## What is Verifiable?

Verifiable is a comprehensive .NET library implementing the [W3C Decentralized Identifiers](https://www.w3.org/TR/did-core/) and [Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/) specifications, along with associated protocols from the [Decentralized Identity Foundation](https://identity.foundation/). The library provides an integrated stack where cryptographic primitives, serialization, credential management, and hardware security work together cohesively.

The core value proposition is documents that can be distinctly identified, cryptographically signed, linked, timestamped, and selectively disclosed without requiring a central governing party while remaining compatible with regulated ecosystems like [eIDAS](https://en.wikipedia.org/wiki/EIDAS).

## Libraries

| Library | Purpose | NuGet |
|---------|---------|:-----:|
| **Verifiable** | CLI tool for library functionality | [![NuGet](https://img.shields.io/nuget/v/Verifiable.svg?style=flat)](https://www.nuget.org/packages/Verifiable/) |
| **Verifiable.Core** | DIDs, verifiable credentials, and data integrity proofs | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Core.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Core/) |
| **Verifiable.Cryptography** | Cryptographic primitives: salt generation, memory-safe key handling, hash functions | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Cryptography.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Cryptography/) |
| **Verifiable.JCose** | JOSE and COSE structures including SD-JWT and selective disclosure | [![NuGet](https://img.shields.io/nuget/v/Verifiable.JCose.svg?style=flat)](https://www.nuget.org/packages/Verifiable.JCose/) |
| **Verifiable.Json** | JSON serialization converters | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Json.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Json/) |
| **Verifiable.Cbor** | CBOR serialization for COSE envelopes | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Cbor.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Cbor/) |-->
| **Verifiable.BouncyCastle** | Cross-platform cryptography via BouncyCastle | [![NuGet](https://img.shields.io/nuget/v/Verifiable.BouncyCastle.svg?style=flat)](https://www.nuget.org/packages/Verifiable.BouncyCastle/) |
| **Verifiable.NSec** | High-performance cryptography via NSec | [![NuGet](https://img.shields.io/nuget/v/Verifiable.NSec.svg?style=flat)](https://www.nuget.org/packages/Verifiable.NSec/) |
| **Verifiable.Microsoft** | .NET standard cryptographic functions | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Microsoft.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Microsoft/) |
| **Verifiable.Tpm** | Trusted Platform Module integration | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Tpm.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Tpm/) |
| **Verifiable.Sidetree** | Sidetree protocol implementation | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Sidetree.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Sidetree/) |
| **Verifiable.Jwt** | JWT integration | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Jwt.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Jwt/) |
| **Verifiable.Security.DataStorage** | Secure storage utilities | [![NuGet](https://img.shields.io/nuget/v/Verifiable.DataStorage.svg?style=flat)](https://www.nuget.org/packages/Verifiable.DataStorage/) |

## Key capabilities

**Decentralized identifiers and credentials.** Full implementation of the W3C DID Core and Verifiable Credentials Data Model 2.0 specifications, including data integrity proofs with EdDSA-RDFC-2022, EdDSA-JCS-2022, and ECDSA-SD-2023 cryptosuites.

**Selective disclosure.** Support for privacy-preserving credential presentation through SD-JWT (RFC 9901), ECDSA-SD-2023 for JSON-LD credentials, and foundations for SD-CWT. Wallet operations include minimum disclosure computation, maximum disclosure bounds, and optimal selection algorithms.

**Multiple cryptographic backends.** Delegate-based architecture allows plugging in BouncyCastle for cross-platform support, NSec for high performance, .NET cryptographic functions, or hardware security modules.

**Hardware security.** TPM 2.0 integration for hardware-backed key storage, PCR reading, event log parsing,attestations and other TPM functionality to come. The architecture extends to HSMs and cloud KMS services through the delegate pattern.

**Serialization flexibility.** Core types remain agnostic to serialization format. JSON support via System.Text.Json and CBOR support via System.Formats.Cbor are provided in separate packages, enabling the same credential logic to work across both formats or any other.

**Memory-safe key handling.** Sensitive cryptographic material is ring-fenced using dedicated types with support for custom memory allocation through `MemoryPool<T>`, enabling scenarios like mlocked memory regions.

## Architecture principles

The library follows data-oriented programming principles where code is separate from immutable data, favoring generic data structures and general-purpose functions implemented as extension methods. Domain types contain raw cryptographic material without encoding artifacts, with encoding handled at serialization boundaries.

Cryptographic operations use a delegate-based extensibility model rather than direct implementations. This allows the same high-level API to work with software keys, TPM-backed keys, HSM keys, or cloud KMS without changing calling code. The `SensitiveMemoryPool` provides exact-size memory allocation for cryptographic material.

The three-party credential flow (Issuer → Holder → Verifier) is modeled explicitly, with clear separation between what each party knows and computes. Internal computation state is not passed between parties; instead, each party derives what it needs from the credential and proof structures.

## Specifications implemented (not exhaustive and updated)

Coming... See tests in the meanwhile.

## Getting started

Install the packages relevant to your use case:

```bash
# Core functionality
dotnet add package Verifiable.Core

# For JSON serialization
dotnet add package Verifiable.Json

# For BouncyCastle cryptography (cross-platform)
dotnet add package Verifiable.BouncyCastle

# For TPM integration
dotnet add package Verifiable.Tpm
```

## Development

The codebase runs on Windows, Linux, and macOS. Some hardware-specific functionality such as TPM operations may only work on certain platforms.

Press **.** on the repository page to open the codebase in VS Code web editor for quick exploration.

## Vulnerability disclosure

For secure disclosure of security vulnerabilities, please see the [security policy](.github/SECURITY.md).

## Contributing

Please read the [contribution guidelines](.github/contributing.md) for technical details.

The [TPM.DEV](https://developers.tpm.dev/) community provides excellent TPM-related study materials and discussions.

### Ways to contribute

- Open issues for bugs, suggestions, or improvements.
- Create pull requests following the contribution guidelines.
- Add tests, especially those using test vectors from other implementations for cross-checking.
- Expand TPM functionality including signing, encryption, and permissions.
- Add more cryptographic and security capabilities.
- Support additional protocols from the [Decentralized Identity Foundation](https://identity.foundation/).
- Improve threat and privacy modeling using frameworks like [LINDDUN](https://www.linddun.org/).

## License

See the LICENSE file for details.

---

> **Note:** This is an early version under active development. APIs may change between versions.