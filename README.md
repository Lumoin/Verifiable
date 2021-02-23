# DotDecentralized library

This is a work in progress implementation of [W3C decentralized identifier specification (DID)](https://www.w3.org/TR/did-core/). It consists of .NET Standard 2.1 libraries. The class hierarchy should be deserialization agnostic, while the current implementation is based on [System.Text.Json](https://docs.microsoft.com/en-us/dotnet/api/system.text.json).

At the moment mirrored between https://github.com/veikkoeeva/DotDecentralized and https://github.com/lumoin/DotDecentralized – becoming a startup project too (as we need it at some point). :)


## Guiding ideas

- A typed system that can operate on any decentralized identifier and verifiable credentials.

- Allow mixing and matching cryptograhic libraries in verification methods and relationships without recompiling the library and allowing choosing library preferably dynamically.

- Provide light facilities for handling of encrypted key material: key rotation, key management and data management. The key material
  may be and may be handled in remote mahcines, enclaves os HSMs. It should be possible to implement key encryption (e.g. data encryption keys,
  key encryption keys, key usage counting) and memory protection (e.g. memory locked pages) when needed, even if not always making sense as such
  (e.g. due to regulation).

- Allow composing and inheriting specialized implementations using core classes while maintaining security, performance,
developer experience etc. The main is to build a bare core and layer these on top of the core (e.g. extension methods).

- Do not throw exception and stop processing if a strongly typed class is not available.

- Implement specification specific rule checking as methods that operate on the typed system.

- Does not aim to implement JSON-LD processing rules (expanded, N-Quads, Framed etc.), works only on compated form.

- Implement a large number of tests using real data from other implementations.

- Add project files for VS Code.


## References

The following specifications and guidelines are referenced:

- [DID Implementation Guide v1.0: An implementation guide for DID software developers](https://w3c.github.io/did-imp-guide/)
- [Decentralized Identifiers (DIDs) v1.0: Core architecture, data model, and representations](https://www.w3.org/TR/did-core/)
- [DID Specification Registries: The interoperability registry for Decentralized Identifiers](https://www.w3.org/TR/did-spec-registries/)
- [Verifiable Credentials Data Model Implementation Report 1.0:Implementation Report for the Verifiable Credentials Data Model](https://w3c.github.io/vc-test-suite/implementations/)
- [Verifiable Credentials Data Model 1.0: Expressing verifiable information on the Web](https://www.w3.org/TR/vc-data-model/)

The aim is also to make possible or implement some other works listed in [Decentralized Identity Foundation (DIF)](https://identity.foundation/#wgs)