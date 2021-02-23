# Verifable library

Blend of _verifiable_ and _fable_. For the good, bad and ugly stories in life.

<hr>

This repository contains projects that implement .NET libraries for [W3C decentralized identifier specification (DID)](https://www.w3.org/TR/did-core/), [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) and related technologies from [Decentralized Identity Foundation (DIF)](https://identity.foundation/).

In simple terms these libraries implement a specification for documents that have distinquishing identifier, can be signed, linked, timestamped, managed and combined into representations without the necessity of a central, governing party but can also function well with such parties.

Since this technology and its likely applications rely on cryptography, these libraries include basic implementation for management of secrets such as the created documents and their material. Technologies include _trusted platform modules_ (TPM), _hardware security modules_ (HSM) and other potential technology such secure enclaves.

<hr>

## Features

- Decentralize identifiers.
- Verifiable credentials.
- Key and secrets management.

<hr>

## Contributing

Hold on a bit! This Readme and repository are currently being created. Check back soon for more.

Likely:

- You need .NET 6

Then

- give stars :star:
- write issues :eyes:
- create pull requests :raised_hands: :muscle:
- adding unit tests (also test files for other implementations) :white_check_mark:
- adding performance tests :white_check_mark:
- adding TPM functionality (signing, encryption, permissions) and tests :computer:
- add more cryptographic capabilities :closed_lock_with_key:
- add X509 related functionality :key:
- add support for more protocols (see at https://identity.foundation/) :blue_book: :pushpin:
- add more eIDAS related support :book: :memo:
- add threat modelling diagrams and explanations :memo: :newspaper:
- improve continuous integration automation :shipit: :rocket:

## Repository visualization

![Visualization of this repo](./resources/diagram.svg)