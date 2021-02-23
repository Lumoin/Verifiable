<img style="display: block; margin-inline-start: auto; margin-inline-end: auto;" src="resources/verifiable-github-logo.svg" width="800" height="400" alt="Verifiable project logo: A shield in blue hues with a rounded top that narrows downwards in a 'V' like shape. In the center there is the tip of white 'V' that elongates across the left corner of the shield to white background. Undernath the lower side of 'V' there is a stylistic key handle also elongating over the edge of the shield.">

#### Decentralized identifiers, verifiable credentials, associated protocols and key management with hardware security elements.

![Main build workflow](https://github.com/lumoin/Verifiable/actions/workflows/main.yml/badge.svg)
[![NuGet](https://img.shields.io/nuget/v/Verifiable.svg?style=flat)](http://www.nuget.org/profiles/Verifiable)

<hr>

This repository contains projects that implement .NET libraries for [W3C decentralized identifier specification (DID)](https://www.w3.org/TR/did-core/), [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) and related technologies from [Decentralized Identity Foundation (DIF)](https://identity.foundation/).

In simple terms these libraries implement a specification for documents that have distinquishing identifier, can be signed, linked, timestamped, managed and combined into representations without the necessity of a central, governing party but can also function well with such parties ([eIDAS](https://en.wikipedia.org/wiki/EIDAS) may be one).

Since this technology and its likely applications rely on cryptography, these libraries include basic implementation for management of secrets such as the created documents and their material. Technologies include _trusted platform modules_ (TPM), _hardware security modules_ (HSM) and other potential technology such secure enclaves.

<hr>

## Features

- Decentralized identifiers (DID).
- Verifiable credentials (VC).
- Various related protocols to DIDs and VCs.
- Key and secrets management.

<hr>

## The design principles

- **Agnostic to serialization and deserialization library.** The design principles for DIDs and VCs and other data elements do not rely to specific libraries for deserialization and serialization (e.g. no library specific attributes on types). Current implementation uses [System.Text.Json](https://www.nuget.org/packages/System.Text.Json/) converters.
- **Sensitive memory is ring-fenced using types.** The goal is to recognize sensitive key material and handle it appropriately (noting security practices and regulations). Currently public, private and other key material is ring-fenced to types. The types are wrappes that know how to point to and and unwrap material to operations. The material can be allocated using [MemoryPool&lt;T&gt;](https://docs.microsoft.com/en-us/dotnet/api/system.buffers.memorypool-1) and so a custom allocator can be provided (e.g. for [mlocked](https://man7.org/linux/man-pages/man2/mlock.2.html) memory regions).
- **Agnostic to underlying cryptographic implementation**. The design should allow using external, special libraries. Currently [BouncyCastle](https://www.nuget.org/packages/Portable.BouncyCastle/), [NSec.Cryptography](https://www.nuget.org/packages/NSec.Cryptography) and [.NET standard cryptography](https://docs.microsoft.com/en-us/dotnet/standard/security/cryptography-model) are included (TPM is progress).
- **Hardware security elements**. It should be possible to use hardware security elements, such as [trusted platform modules](https://en.wikipedia.org/wiki/Trusted_Platform_Module).
- **Developer experience**. Writing against an evolving specification or some specific specifications can be difficult. It takes time to learn. So code shoud link in comments to W3C and RFCs where approprite (see code for examples).
- **Tests and tests that use real data**. There should be as much tests as possible. Also thests that use as test vectors data from other implementations to cross-check.

## Contributing

Please, read [contribution guidelines](.github/contributing.md).

You need .NET 5 (soon .NET 6). Also see community at [TPM.DEV](https://developers.tpm.dev/) for TPM related discussion, they have also great people and resources there. Do propose other communitis too.

Taking something from contribution guide and adding specific ideas.

:eyes: Please, do write issues.

:raised_hands: By all means, do create pull requests (see [contribution guidelines](.github/contributing.md)).

:star: Stars also help.

:white_check_mark: Adding tests is really good, of course.

:computer: adding TPM functionality (signing, encryption, permissions) &ndash; and tests.

:closed_lock_with_key: Add more cryptographic and security capabilities.

:memo: Threat modelling diagrams and explanations!

:key: As a corollary, add X509 related functionality.

:blue_book: Support for more protocols (see at https://identity.foundation/).

:book: More [eIDAS](https://en.wikipedia.org/wiki/EIDAS) related support, some other similar standards would be interesting too. Introducing relevant standards document and draft plans is OK too (hey, also blockchain time stamps qualify as simple seals).

:thought_balloon: Issue templates and other improvements to project.

:rocket: improve continuous integration automation is always good!

## Repository visualization

![Visualization of this repo](./resources/diagram.svg)