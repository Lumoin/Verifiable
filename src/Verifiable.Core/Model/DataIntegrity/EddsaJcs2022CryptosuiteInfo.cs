using System.Collections.Generic;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core.Model.DataIntegrity
{
    /// <summary>
    /// The <c>eddsa-jcs-2022</c> cryptosuite using Ed25519 signatures with JCS canonicalization.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This cryptosuite is designed for use cases where JSON-LD processing is not available
    /// or not desired. It uses JSON Canonicalization Scheme (JCS, RFC 8785) to produce a
    /// canonical JSON representation before hashing with SHA-256 and signing with Ed25519.
    /// </para>
    /// <para>
    /// <strong>Algorithm Details:</strong>
    /// </para>
    /// <list type="number">
    /// <item><description>Canonicalize the JSON document using JCS (RFC 8785).</description></item>
    /// <item><description>Hash the canonical form using SHA-256.</description></item>
    /// <item><description>Sign the hash using Ed25519.</description></item>
    /// <item><description>Encode the signature using multibase (base58-btc).</description></item>
    /// </list>
    /// <para>
    /// <strong>When to Use:</strong>
    /// </para>
    /// <para>
    /// Use this cryptosuite when JSON-LD processing is unavailable or when simpler
    /// implementation is preferred over full semantic preservation. JCS is easier to
    /// implement but does not preserve JSON-LD semantic equivalence across different
    /// serializations.
    /// </para>
    /// <para>
    /// <strong>Trade-offs:</strong>
    /// </para>
    /// <list type="bullet">
    /// <item><description>Simpler implementation without JSON-LD library dependency.</description></item>
    /// <item><description>Faster processing without RDF conversion.</description></item>
    /// <item><description>Does not preserve semantic equivalence for JSON-LD documents.</description></item>
    /// <item><description>Whitespace and key ordering changes will invalidate signatures.</description></item>
    /// </list>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022">
    /// EdDSA Cryptosuites §3.2 eddsa-jcs-2022</see>.
    /// </para>
    /// </remarks>
    public sealed class EddsaJcs2022CryptosuiteInfo: CryptosuiteInfo
    {
        private static readonly IReadOnlyList<string> ContextsArray =
            new[] { "https://w3id.org/security/data-integrity/v2" }.AsReadOnly();

        /// <summary>
        /// The singleton instance of the <c>eddsa-jcs-2022</c> cryptosuite information.
        /// </summary>
        public static EddsaJcs2022CryptosuiteInfo Instance { get; } = new()
        {
            CryptosuiteName = "eddsa-jcs-2022",
            Canonicalization = CanonicalizationAlgorithm.Jcs,
            HashAlgorithm = "SHA-256",
            SignatureAlgorithm = CryptoAlgorithm.Ed25519,
            Contexts = ContextsArray,
            IsCompatibleWith = vm =>
                vm.TypeName == MultikeyVerificationMethodTypeInfo.Instance.TypeName ||
                vm.TypeName == Ed25519VerificationKey2020VerificationMethodTypeInfo.Instance.TypeName
        };
    }
}