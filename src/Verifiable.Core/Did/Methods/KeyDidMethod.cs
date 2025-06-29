using System;

namespace Verifiable.Core.Did.Methods
{
    /// <summary>
    /// Represents a <c>did:key</c> DID method implementation that creates DID documents
    /// deterministically from cryptographic key material without requiring external infrastructure.
    /// This method is defined by the DID Key specification and enables offline DID generation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <c>did:key</c> method generates DID identifiers by encoding public key material
    /// using multibase encoding with Base58-BTC and appropriate multicodec headers.
    /// The resulting DID can be resolved to a DID document containing a single verification
    /// method derived from the original key material.
    /// </para>
    /// <para>
    /// This method is particularly useful for scenarios requiring:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Offline DID generation without network dependencies</description></item>
    /// <item><description>Deterministic DID creation from known key material</description></item>
    /// <item><description>Simplified testing and development workflows</description></item>
    /// <item><description>Peer-to-peer applications with minimal infrastructure requirements</description></item>
    /// </list>
    /// <para>
    /// The <c>did:key</c> method supports various cryptographic algorithms including Ed25519,
    /// X25519, secp256k1, NIST P-curves (P-256, P-384, P-521), and BLS12-381, with each
    /// algorithm having its own multicodec header for proper identification and encoding.
    /// </para>
    /// <para>
    /// <strong>Security and Long-term Usage Considerations:</strong>
    /// </para>
    /// <list type="bullet">
    /// <item><description>Key rotation is not supported within the same DID identifier - new keys require new DID identifiers</description></item>
    /// <item><description>Deactivation is not supported - compromised keys cannot be revoked</description></item>
    /// <item><description>Long-term usage (weeks to months) is strongly discouraged due to inability to recover from security compromise</description></item>
    /// <item><description>Use of <c>did:key</c> for long-lived use cases is only recommended when accompanied with high confidence in hardware isolation</description></item>
    /// </list>
    /// <para>
    /// This library provides TPM (Trusted Platform Module) integration for hardware-backed key protection.
    /// //TODO: Add proper reference to TPM utilities class when available: <see cref="TpmUtilities"/>
    /// For scenarios requiring long-term <c>did:key</c> usage, consider utilizing hardware security modules
    /// or TPM-backed key storage to meet the hardware isolation requirements specified in the DID Key specification.
    /// </para>
    /// <para>
    /// For detailed specification information, see
    /// <see href="https://w3c-ccg.github.io/did-key-spec/">DID Key Specification</see>.
    /// </para>
    /// </remarks>
    public record KeyDidMethod: GenericDidMethod
    {
        /// <summary>
        /// The prefix of <c>did:key</c> method, including suffix <c>':'</c>.
        /// </summary>
        /// <remarks>This is <see cref="WellKnownDidMethodPrefixes.KeyDidMethodPrefix"/> with colon.</remarks>
        public static new string Prefix { get; } = $"{WellKnownDidMethodPrefixes.KeyDidMethodPrefix}:";


        /// <summary>
        /// Initializes a new instance of the <see cref="KeyDidMethod"/> class using the specified DID string.
        /// </summary>
        /// <param name="didString">The DID string to associate with this instance. The string must start <see cref="WellKnownDidMethodPrefixes.KeyDidMethodPrefix"/>.</param>
        /// <exception cref="ArgumentException">Thrown if <paramref name="didString"/> does not start with <see cref="WellKnownDidMethodPrefixes.KeyDidMethodPrefix"/>.</exception>
        public KeyDidMethod(string didString): base(didString)
        {
            if(!didString.StartsWith(Prefix))
            {
                throw new ArgumentException($"The DID string must start with '{Prefix}'.", nameof(didString));
            }
        }


        /// <summary>
        /// Implicit conversion from <see cref="KeyDidMethod"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
        public static implicit operator string(KeyDidMethod didId) => didId.Id;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="KeyDidMethod"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator KeyDidMethod(string didId) => new(didId);
    }
}
