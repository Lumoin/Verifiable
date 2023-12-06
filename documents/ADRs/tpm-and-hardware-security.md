# Implementing a TPM Library

## Context

The TPM part of Verifiable is designed to interact with TPM hardware using byte buffers and consequently platform specific APIs to use them. This design is aimed at simplifying the construction, debugging, reasoning, and reuse of TPM interactions.

Additionally, there is a need to consider compatibility with other hardware acceleration systems like TEEs and HSMs, especially for secure key management and cryptographic functions.

Therefore, the library builds on .NET delegatesto manage key material with hardware, due to their compatibility. This should be efficient in various environments and allow secure memeory management.

## Decision

- **Byte Buffer Utilization**: Use byte buffers and named .NET structures for packets (e.g. classes) for TPM interactions to enhance developer experience, debuggability and maintainability.

- **Structured Packet Design**: Implement a structured approach to constructing and parsing byte buffers, turning them into classes or other structures.

- **Cross-Platform Interface**: Utilize P/Invoke in Windows and file descriptors in Linux for native TPM interaction, ensuring cross-platform compatibility.

- **Testing on Real Hardware**: Test the library on various machines with real TPM hardware to ensure reliability and discover potential bugs.

- **Foundation for Software TPM**: Lay groundwork for future development of a software-based TPM by developing the byte buffer encoder and decoder at the same time and test both the software and hardware implementation.

- **Use of C# Delegates**: Leverage C# delegates to interface with TPM, TEEs, and HSMs, accommodating `Span` types for performance and memory efficiency.

- **Delegate Design for Hardware Interactions**: Design delegates to handle specific interactions with TPM, TEEs, and HSMs, facilitating secure and efficient execution of operations.

## Consequences

- **Improved Maintainability and Scalability**: Enhanced understanding and scalability for future development.

- **Cross-Platform Compatibility**: Usable in diverse operating environments.

- **Enhanced Security and Reliability**: Structured data packets and secure delegate interfaces reduce errors and increase security.

- **Facilitated Debugging and Development**: Easier issue identification and resolution.

- **Support for Software TPMs**: Extends the library for purposes other than hardware security. As for an instance, developing tooling.

- **Enhanced Performance and Memory Efficiency**: Utilizing delegates with Spans for optimized operations.

- **Flexibility in Hardware Interactions**: Adaptable design for various hardware systems.

- **Increased Complexity in Delegate Management**: Complexity in managing hardware-specific implementations securely and efficiently.

## Trade-offs and Challenges

- **Balancing Security and Complexity**: Managing the added complexity due to the integration of TEEs, HSMs, and delegates, while maintaining security.

- **Hardware-Specific Integrations**: Need for hardware-dependent code paths for TEEs and HSMs, affecting portability and maintainability.

- **Delegate Management and Security**: Ensuring secure implementation and management of delegates, especially in sensitive cryptographic operations.

- **Hardware Abstraction and Compatibility**: Designing delegates to abstract underlying hardware sufficiently, allowing for compatibility across various systems.

## Status

Accepted.

## References

None.

## Revision History

None.
