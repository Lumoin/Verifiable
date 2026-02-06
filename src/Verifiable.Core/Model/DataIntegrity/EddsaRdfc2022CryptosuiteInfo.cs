using System.Collections.Generic;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core.Model.DataIntegrity
{
    /// <summary>
    /// The <c>eddsa-rdfc-2022</c> cryptosuite using Ed25519 signatures with RDFC-1.0 canonicalization.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This cryptosuite is designed for use cases requiring full JSON-LD semantic preservation.
    /// It uses RDF Dataset Canonicalization (RDFC-1.0) to produce a canonical N-Quads representation
    /// of the document before hashing with SHA-256 and signing with Ed25519.
    /// </para>
    /// <para>
    /// <strong>Algorithm Details:</strong>
    /// </para>
    /// <list type="number">
    /// <item><description>Parse the document as JSON-LD and convert to RDF dataset.</description></item>
    /// <item><description>Canonicalize using RDFC-1.0 to produce canonical N-Quads.</description></item>
    /// <item><description>Hash the canonical form using SHA-256.</description></item>
    /// <item><description>Sign the hash using Ed25519.</description></item>
    /// <item><description>Encode the signature using multibase (base58-btc).</description></item>
    /// </list>
    /// <para>
    /// <strong>When to Use:</strong>
    /// </para>
    /// <para>
    /// Use this cryptosuite when JSON-LD processing is available and semantic equivalence
    /// must be preserved. This is the recommended suite for Verifiable Credentials that
    /// use JSON-LD contexts extensively.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-di-eddsa/#eddsa-rdfc-2022">
    /// EdDSA Cryptosuites §3.1 eddsa-rdfc-2022</see>.
    /// </para>
    /// </remarks>
    public sealed class EddsaRdfc2022CryptosuiteInfo: CryptosuiteInfo
    {
        private static readonly IReadOnlyList<string> ContextsArray =
            new[] { "https://w3id.org/security/data-integrity/v2" }.AsReadOnly();

        /// <summary>
        /// The singleton instance of the <c>eddsa-rdfc-2022</c> cryptosuite information.
        /// </summary>
        public static EddsaRdfc2022CryptosuiteInfo Instance { get; } = new()
        {
            CryptosuiteName = "eddsa-rdfc-2022",
            Canonicalization = CanonicalizationAlgorithm.Rdfc10,
            HashAlgorithm = "SHA-256",
            SignatureAlgorithm = CryptoAlgorithm.Ed25519,
            Contexts = ContextsArray,
            IsCompatibleWith = vm =>
                vm.TypeName == MultikeyVerificationMethodTypeInfo.Instance.TypeName ||
                vm.TypeName == Ed25519VerificationKey2020VerificationMethodTypeInfo.Instance.TypeName
        };
    }
}