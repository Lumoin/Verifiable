# Cryptographic Libraries as Drivers

## Context

In the Verifiable library, cryptographic operations such as signing, verification, and key management are essential components. These operations need to be flexible, secure, and extensible to support diverse use cases, including:

- **Local Key Management**: Operations with in-memory keys using software-based cryptographic libraries (e.g., BouncyCastle, Microsoft CNG).
- **Hardware Security Modules (HSMs)**: Integration with systems like Azure KeyVault or remote HSMs for secure key storage and cryptographic operations.
- **Trusted Platform Modules (TPMs)**: Support for TPM-based cryptographic operations, either with in-memory keys or TPM-resident handles.

Key material may be produced or consumed in different formats, depending on the libraries or hardware systems used. To accommodate these diverse scenarios, the cryptographic system must provide a consistent interface for higher-level operations while abstracting the underlying implementation details of different cryptographic providers.

## Decision

- **Driver-Based Design**: Cryptographic libraries and hardware systems are treated as drivers, registered and accessed through a convention-based interface. Drivers implement cryptographic primitives such as signing, verification, and key creation.

- **BCL-Compatible Delegates**: Low-level cryptographic operations use .NET primitive types (e.g., `ReadOnlyMemory<byte>`) and optionally accept a context (`Dictionary<string, object>?`) for extensibility. This approach avoids dependencies between the core library and driver libraries, ensuring modularity and flexibility.

- **Mapping and Resolution Layer**: A resolution layer maps algorithm, purpose, and context parameters to the correct low-level driver function. This allows higher-level operations to remain agnostic of the specific cryptographic provider.

- **Per-Call Context**: A `Dictionary<string, object>?` context parameter is provided for every cryptographic operation. This context can influence routing through the resolution layer and be used directly by the driver for implementation-specific details (e.g., choosing between multiple HSM instances or TPM handles).

- **Registration API**: Drivers are registered with unique identifiers and mapped to higher-level functions using a consistent API. For example:
  
-```csharp
  CryptoFunctionRegistry.RegisterLowLevelFunction("SignP256", MicrosoftCryptographicFunctions.SignP256Async);
  CryptoFunctionRegistry.RegisterLowLevelFunction("VerifyP256", MicrosoftCryptographicFunctions.VerifyP256Async);
```