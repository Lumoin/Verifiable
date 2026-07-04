<img style="display: block; margin-inline-start: auto; margin-inline-end: auto;" src="resources/lumoin-verifiable-github-logo.svg" width="800" height="151" alt="Verifiable wordmark: a circular emblem in gradient blue-to-cyan hues followed by the project name in matching lettering.">

# Verifiable

**An integrated .NET stack for decentralized identity: DIDs, verifiable credentials, selective disclosure, secure messaging, and hardware-backed cryptography.**

![Main build workflow](https://github.com/lumoin/Verifiable/actions/workflows/main.yml/badge.svg)
[![Mutation testing badge](https://img.shields.io/endpoint?style=for-the-badge&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2Flumoin%2FVerifiable%2Fmain)](https://dashboard.stryker-mutator.io/reports/github.com/lumoin/Verifiable/main)

---

## What is Verifiable?

Verifiable is a comprehensive .NET library implementing the [W3C Decentralized Identifiers](https://www.w3.org/TR/did-core/) and [Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/) specifications, along with associated protocols from the [Decentralized Identity Foundation](https://identity.foundation/) and the [OpenID Foundation](https://openid.net/). The library provides an integrated stack where cryptographic primitives, serialization, credential management, and hardware security work together cohesively.

The core value proposition is documents that can be distinctly identified, cryptographically signed, linked, timestamped, and selectively disclosed without requiring a central governing party while remaining compatible with regulated ecosystems like [eIDAS](https://en.wikipedia.org/wiki/EIDAS).

## Libraries

| Library | Purpose | NuGet |
|---------|---------|:-----:|
| **Verifiable** | CLI and MCP server: DID/VC utilities, TPM info, CBOM emission | [![NuGet](https://img.shields.io/nuget/v/Verifiable.svg?style=flat)](https://www.nuget.org/packages/Verifiable/) |
| **Verifiable.Core** | DIDs, verifiable credentials, and data integrity proofs | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Core.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Core/) |
| **Verifiable.Foundation** | Domain-neutral primitives: pushdown automata and the `SensitiveMemory` abstraction | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Foundation.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Foundation/) |
| **Verifiable.Cryptography** | Cryptographic primitives: salt generation, memory-safe key handling, hash functions | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Cryptography.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Cryptography/) |
| **Verifiable.JCose** | JOSE and COSE structures including SD-JWT and selective disclosure | [![NuGet](https://img.shields.io/nuget/v/Verifiable.JCose.svg?style=flat)](https://www.nuget.org/packages/Verifiable.JCose/) |
| **Verifiable.OAuth** | OAuth 2.0 / OpenID protocol flows: OpenID4VCI, OpenID4VP, HAIP, SIOPv2, OpenID Federation, Shared Signals, AuthZEN | [![NuGet](https://img.shields.io/nuget/v/Verifiable.OAuth.svg?style=flat)](https://www.nuget.org/packages/Verifiable.OAuth/) |
| **Verifiable.Server** | Transport-neutral endpoint host for credential service HTTP APIs | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Server.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Server/) |
| **Verifiable.WebFinger** | WebFinger (RFC 7033) handle discovery: a client and a capability-gated `/.well-known/webfinger` endpoint over the multi-tenant host | [![NuGet](https://img.shields.io/nuget/v/Verifiable.WebFinger.svg?style=flat)](https://www.nuget.org/packages/Verifiable.WebFinger/) |
| **Verifiable.Vcalm** | W3C Verifiable Credential API for Lifecycle Management (VCALM 1.0) | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Vcalm.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Vcalm/) |
| **Verifiable.DidComm** | DIDComm Messaging v2.1: signed/encrypted messages, routing, out-of-band, discover features, pluggable transport | [![NuGet](https://img.shields.io/nuget/v/Verifiable.DidComm.svg?style=flat)](https://www.nuget.org/packages/Verifiable.DidComm/) |
| **Verifiable.Json** | JSON serialization converters | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Json.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Json/) |
| **Verifiable.Cbor** | CBOR serialization for COSE envelopes | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Cbor.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Cbor/) |
| **Verifiable.JsonPointer** | JSON Pointer (RFC 6901) resolution and JSONata query evaluation | [![NuGet](https://img.shields.io/nuget/v/Verifiable.JsonPointer.svg?style=flat)](https://www.nuget.org/packages/Verifiable.JsonPointer/) |
| **Verifiable.BouncyCastle** | Cross-platform cryptography via BouncyCastle | [![NuGet](https://img.shields.io/nuget/v/Verifiable.BouncyCastle.svg?style=flat)](https://www.nuget.org/packages/Verifiable.BouncyCastle/) |
| **Verifiable.NSec** | High-performance cryptography via NSec | [![NuGet](https://img.shields.io/nuget/v/Verifiable.NSec.svg?style=flat)](https://www.nuget.org/packages/Verifiable.NSec/) |
| **Verifiable.Microsoft** | .NET standard cryptographic functions | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Microsoft.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Microsoft/) |
| **Verifiable.Tpm** | Trusted Platform Module integration | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Tpm.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Tpm/) |
| **Verifiable.Apdu** | ISO/IEC 7816-4 APDUs and ICAO 9303 eMRTD reading | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Apdu.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Apdu/) |
| **Verifiable.Cesr** | Composable Event Streaming Representation (CESR): text and binary codec for the KERI, ACDC, and did:webs suite | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Cesr.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Cesr/) |
| **Verifiable.Keri** | KERI protocol layer over CESR: key event log (KEL) framing and key-state processing | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Keri.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Keri/) |
| **Verifiable.Acdc** | Authentic Chained Data Containers (ACDC): SAID-anchored credentials with selective disclosure | [![NuGet](https://img.shields.io/nuget/v/Verifiable.Acdc.svg?style=flat)](https://www.nuget.org/packages/Verifiable.Acdc/) |
| **Verifiable.DidWebs** | KERI-backed did:webs DID method: identifier resolution and key-state verification | [![NuGet](https://img.shields.io/nuget/v/Verifiable.DidWebs.svg?style=flat)](https://www.nuget.org/packages/Verifiable.DidWebs/) |

## Key capabilities

**Decentralized identifiers and credentials.** Full implementation of the W3C DID Core and Verifiable Credentials Data Model 2.0 specifications, including data integrity proofs with EdDSA-RDFC-2022, EdDSA-JCS-2022, ECDSA-SD-2023, and BBS-2023 cryptosuites. DID methods include did:key, did:web, did:peer, and did:webvh, resolved through a multi-method resolver with a W3C DID Resolution HTTP binding.

**Secure agent messaging.** A [DIDComm Messaging v2.1](https://identity.foundation/didcomm-messaging/spec/v2.1/) implementation: signed and encrypted (anoncrypt and authcrypt) messages, nested sign-then-encrypt, DID rotation, routing and mediation, out-of-band invitations, acknowledgements and problem reports, and the Discover Features protocol. Trust comes from the envelope rather than the connection, so the transport is a host-supplied delegate — an HTTPS binding ships, and WebSocket, Bluetooth, or libp2p plug in unchanged.

**Selective disclosure.** Support for privacy-preserving credential presentation through SD-JWT (RFC 9901), ECDSA-SD-2023 and unlinkable BBS-2023 for JSON-LD credentials, and SD-CWT. Wallet operations include minimum disclosure computation, maximum disclosure bounds, and optimal selection algorithms.

**Protocol flows.** Issuer, verifier, and wallet implementations of OpenID for Verifiable Credential Issuance, OpenID for Verifiable Presentations and the high-assurance interoperability profile, Self-Issued OpenID Provider v2, OAuth 2.0 / OpenID Connect, OpenID Federation, and Shared Signals. See [Implemented flows](#implemented-flows).

**Multiple cryptographic backends.** Delegate-based architecture allows plugging in BouncyCastle for cross-platform support, NSec for high performance, .NET cryptographic functions, or hardware security modules.

**Hardware security.** TPM 2.0 integration for hardware-backed key storage, PCR reading, event log parsing, attestations, and other TPM functionality to come. The architecture extends to HSMs and cloud KMS services through the delegate pattern.

**Serialization flexibility.** Core types remain agnostic to serialization format. JSON support via System.Text.Json and CBOR support via System.Formats.Cbor are provided in separate packages, enabling the same credential logic to work across both formats or any other.

**Memory-safe key handling.** Sensitive cryptographic material is ring-fenced using dedicated types with support for custom memory allocation through `MemoryPool<T>`, enabling scenarios like mlocked memory regions.

**Cryptographic observability.** Each cryptographic operation emits OpenTelemetry spans tagged with the algorithm, key role, entropy source, and backend. From these the library builds a CycloneDX 1.6 cryptographic bill of materials (CBOM): a declarative view of available algorithms and an observed view of what ran. Serializing it to JSON and wiring a backend are left to the application; the `verifiable` CLI and MCP server do this for `cbom --declarative` and `--observe`.

## Architecture principles

The library follows data-oriented programming principles where code is separate from immutable data, favoring generic data structures and general-purpose functions implemented as extension methods. Domain types contain raw cryptographic material without encoding artifacts, with encoding handled at serialization boundaries.

Cryptographic operations use a delegate-based extensibility model rather than direct implementations. This allows the same high-level API to work with software keys, TPM-backed keys, HSM keys, or cloud KMS without changing calling code.

The three-party credential flow (Issuer → Holder → Verifier) is modeled explicitly, with clear separation between what each party knows and computes. Internal computation state is not passed between parties; instead, each party derives what it needs from the credential and proof structures.

## Implemented flows

The library includes the following protocol flows, each with tests. The test suite is the authoritative list.

- **Credential issuance ([OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html))** — issuer and wallet sides: authorization code and pre-authorized code grants, credential offers (by value and by reference), the credential, deferred, notification, and nonce endpoints, issuer metadata, request and response encryption, holder-binding proof validation (`jwt`, `attestation`, and `di_vp` proof types), key attestations, and DPoP-bound credential access tokens.
- **Credential presentation ([OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html))** — verifier and wallet sides, for cross-device, same-device, and same-device app-to-app interactions. Supports the OpenID4VP client identifier schemes, both `direct_post` and encrypted `direct_post.jwt` responses, and DCQL credential queries.
- **Self-issued identity ([SIOPv2 1.0](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html))** — the relying-party flow with signed request objects served at `request_uri`, encrypted and combined `id_token` + `vp_token` responses, and nonce-replay defense, plus OP-side request validation, provider metadata, and self-issued ID token minting.
- **High-assurance profile ([HAIP 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html))** — the OpenID4VP profile used by EUDI-style deployments: encrypted responses and X.509-based request signing.
- **Credential formats in presentation** — [SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/), [ISO mdoc](https://www.iso.org/standard/69084.html) (ISO/IEC 18013-5), and [SD-CWT](https://datatracker.ietf.org/doc/draft-ietf-spice-sd-cwt/), with holder key binding and selective disclosure.
- **Verifiable credential data integrity** — issuing and verifying credentials with [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/) proofs: EdDSA-RDFC-2022, EdDSA-JCS-2022, ECDSA-SD-2023, and [BBS-2023](https://www.w3.org/TR/vc-di-bbs/) for unlinkable selective disclosure.
- **Credential lifecycle API ([W3C VCALM 1.0](https://www.w3.org/TR/vcalm-1.0/))** — issuer, verifier, and holder HTTP services over a transport-neutral host: issuing credentials (§3.2), verifying credentials and presentations (§3.3), verifiable presentation requests and DID Authentication (§3.4), deriving selectively-disclosed credentials and creating presentations (§3.5), exchanges with multi-step workflows (§3.6), interactions (§3.7), the §3.8 problem-details error model, and Bitstring Status List status management (Appendix C).
- **DIDComm Messaging ([v2.1](https://identity.foundation/didcomm-messaging/spec/v2.1/))** — the full message layer (plaintext, signed, anoncrypt, authcrypt, and nested sign-then-encrypt over ECDH-ES / ECDH-1PU JWE), DID rotation via `from_prior`, routing/forward and mediation, out-of-band invitations, ACKs and problem reports, attachment resolution, the Discover Features 2.0 protocol, and a channel-pluggable transport (an HTTPS binding plus the seam any non-HTTP channel plugs into).
- **DID resolution** — a multi-method resolver for did:key, did:web, did:peer, [did:webvh](https://identity.foundation/didwebvh/) (DID Log replay, SCID and key pre-rotation, witness verification, portability, version queries, and DID-URL dereferencing), and [did:webs](https://trustoverip.github.io/kswg-did-method-webs-specification/) (KERI-backed: resolution to the `did.json` and `keri.cesr` URLs, with the CESR event stream replayed to a verified KERI key state), with a [DID Resolution](https://w3c-ccg.github.io/did-resolution/) HTTP binding.
- **WebFinger ([RFC 7033](https://www.rfc-editor.org/rfc/rfc7033))** — handle-to-resource discovery: a client that resolves a query target to a JSON Resource Descriptor over the guarded outbound path, and a capability-gated `/.well-known/webfinger` endpoint on the multi-tenant host, used to discover a subject's DID from an `acct:` handle.
- **OAuth 2.0 / OpenID Connect** — authorization code with [PKCE](https://www.rfc-editor.org/rfc/rfc7636), [pushed authorization requests](https://www.rfc-editor.org/rfc/rfc9126), [signed request objects](https://www.rfc-editor.org/rfc/rfc9101), [DPoP](https://www.rfc-editor.org/rfc/rfc9449), [rich authorization requests](https://www.rfc-editor.org/rfc/rfc9396) with a per-type handler registry, [JWT-secured authorization responses](https://openid.net/specs/oauth-v2-jarm.html), [token introspection](https://www.rfc-editor.org/rfc/rfc7662) with [JWT responses](https://www.rfc-editor.org/rfc/rfc9701), token refresh and revocation, [dynamic client registration](https://www.rfc-editor.org/rfc/rfc7591), and [server](https://www.rfc-editor.org/rfc/rfc8414) and [protected-resource](https://www.rfc-editor.org/rfc/rfc9728) metadata, including the [FAPI 2.0](https://openid.net/specs/fapi-2_0-security-profile.html) security profile and [message signing](https://openid.net/specs/fapi-2_0-message-signing.html) constraints.
- **[OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)** — entity configurations, trust chain resolution, metadata policy, trust marks, and client registration.
- **Shared Signals ([SSF](https://openid.net/specs/openid-sharedsignals-framework-1_0.html), [CAEP](https://openid.net/specs/openid-caep-1_0.html), RISC)** — transmitter and receiver, with push and poll delivery and stream management.
- **[AuthZEN](https://openid.net/specs/authorization-api-1_0.html)** — access evaluation, single and batch.

## Getting started

Install the packages relevant to your use case:

```bash
# Core functionality
dotnet add package Verifiable.Core

# For JSON serialization
dotnet add package Verifiable.Json

# For OAuth / OpenID protocol flows (OpenID4VP, Federation, and others)
dotnet add package Verifiable.OAuth

# For the W3C VCALM 1.0 credential lifecycle HTTP API (issuer, verifier, holder)
dotnet add package Verifiable.Vcalm

# For BouncyCastle cryptography (cross-platform)
dotnet add package Verifiable.BouncyCastle

# For TPM integration
dotnet add package Verifiable.Tpm

# For ISO 7816 smart card and eMRTD reading
dotnet add package Verifiable.Apdu
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
