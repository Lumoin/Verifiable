# Verifiable CLI

A command line tool for system security elements, decentralized identifiers (DIDs) and verifiable credentials (VCs).

## Installation

```shell
dotnet tool install --global Verifiable
```

## Usage

```shell
verifiable --help
```

## Features

- Decentralized Identifiers (DIDs) — create, resolve and verify DID documents
- Verifiable Credentials (VCs) — issue and verify credentials
- Data Integrity Proofs — sign and verify using W3C Data Integrity
- TPM 2.0 — interact with Trusted Platform Module hardware and simulators
- MCP server — expose DID/VC operations as a Model Context Protocol tool

## Standards

Implements [W3C DID Core](https://www.w3.org/TR/did-core/), [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/), and [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/).

## License

Apache 2.0.
