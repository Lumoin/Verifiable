using System;
using System.Collections.Generic;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// The <c>ecdsa-sd-2023</c> cryptosuite providing selective disclosure with ECDSA P-256 signatures.
/// </summary>
/// <remarks>
/// <para>
/// This cryptosuite enables selective disclosure of individual claims within a credential.
/// Unlike full-disclosure suites, it operates in two phases with different proof types:
/// </para>
/// <list type="number">
///   <item>
///     <term>Base Proof (Issuer → Holder)</term>
///     <description>
///       Contains individual signatures for each non-mandatory claim, allowing the holder
///       to later selectively reveal claims without issuer involvement.
///       See <see cref="EcdsaSdBaseProof"/> for the parsed structure.
///     </description>
///   </item>
///   <item>
///     <term>Derived Proof (Holder → Verifier)</term>
///     <description>
///       Contains only the signatures for claims the holder chooses to disclose.
///       The verifier cannot learn anything about undisclosed claims.
///       See <see cref="EcdsaSdDerivedProof"/> for the parsed structure.
///     </description>
///   </item>
/// </list>
/// <para>
/// <strong>Comparison with Other Selective Disclosure Mechanisms:</strong>
/// </para>
/// <list type="bullet">
///   <item>
///     <term>SD-JWT (JOSE)</term>
///     <description>
///       Uses hash-based redaction with <c>_sd</c> arrays. See <see cref="Verifiable.JCose.Sd.SdJwtToken"/>.
///       Simpler implementation but reveals claim structure even when redacted.
///     </description>
///   </item>
///   <item>
///     <term>SD-CWT (COSE)</term>
///     <description>
///       CBOR-based selective disclosure per draft-ietf-spice-sd-cwt.
///       Similar to SD-JWT but uses COSE envelopes.
///     </description>
///   </item>
///   <item>
///     <term>BBS-2023</term>
///     <description>
///       Provides unlinkability through zero-knowledge proofs.
///       Requires pairing-friendly curves (BLS12-381).
///     </description>
///   </item>
/// </list>
/// <para>
/// <strong>Algorithm Details:</strong>
/// </para>
/// <list type="number">
///   <item><description>Parse the document as JSON-LD and convert to RDF dataset.</description></item>
///   <item><description>Canonicalize using RDFC-1.0 with HMAC-based blank node relabeling.</description></item>
///   <item><description>Group N-Quads into mandatory and non-mandatory based on JSON pointers.</description></item>
///   <item><description>Hash mandatory statements with SHA-256 to produce mandatory hash.</description></item>
///   <item><description>Sign each non-mandatory statement individually with ephemeral P-256 key.</description></item>
///   <item><description>Sign the proof options hash + public key + mandatory hash with issuer key.</description></item>
///   <item><description>Encode base proof value using CBOR with header 0xd9 0x5d 0x00.</description></item>
/// </list>
/// <para>
/// <strong>Limitations:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>Only supports P-256 curve (not P-384 like other ECDSA suites).</description></item>
///   <item><description>Does not provide unlinkability - same credential produces same base signature.</description></item>
///   <item><description>Larger proof sizes due to individual statement signatures.</description></item>
/// </list>
/// <para>
/// For unlinkable selective disclosure, consider the BBS-based <c>bbs-2023</c> cryptosuite.
/// </para>
/// <para>
/// See <see href="https://w3c.github.io/vc-di-ecdsa/#ecdsa-sd-2023">
/// W3C VC DI ECDSA §3.3 ecdsa-sd-2023</see>.
/// </para>
/// </remarks>
/// <seealso cref="EcdsaSdBaseProof"/>
/// <seealso cref="EcdsaSdDerivedProof"/>
/// <seealso cref="EcdsaSd2023ProofSerializer"/>
public sealed class EcdsaSd2023CryptosuiteInfo: CryptosuiteInfo
{
    private static readonly IReadOnlyList<string> ContextsArray =
        new[] { "https://w3id.org/security/data-integrity/v2" }.AsReadOnly();


    /// <summary>
    /// The singleton instance of the <c>ecdsa-sd-2023</c> cryptosuite information.
    /// </summary>
    public static EcdsaSd2023CryptosuiteInfo Instance { get; } = new()
    {
        CryptosuiteName = "ecdsa-sd-2023",
        Canonicalization = CanonicalizationAlgorithm.Rdfc10,
        HashAlgorithm = "SHA-256",
        SignatureAlgorithm = CryptoAlgorithm.P256,
        Contexts = ContextsArray,
        IsCompatibleWith = vm =>
            vm.TypeName == MultikeyVerificationMethodTypeInfo.Instance.TypeName
    };


    /// <summary>
    /// Gets a value indicating this is a selective disclosure cryptosuite.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Selective disclosure cryptosuites allow holders to reveal only specific claims
    /// from a credential without disclosing the entire content.
    /// </para>
    /// <para>
    /// See <see href="https://w3c.github.io/vc-di-ecdsa/#selective-disclosure">
    /// W3C VC DI ECDSA §3.3.1 Selective Disclosure</see>.
    /// </para>
    /// </remarks>
    public static bool SupportsSelectiveDisclosure => true;


    /// <summary>
    /// Gets the CBOR header bytes for base proof values.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Base proofs from the issuer use header <c>0xd9 0x5d 0x00</c>.
    /// This is a CBOR tag in the range 256-65535 (major type 6, additional info 25).
    /// </para>
    /// <para>
    /// See <see href="https://w3c.github.io/vc-di-ecdsa/#serializebaseproofvalue">
    /// W3C VC DI ECDSA §3.3.13 serializeBaseProofValue</see>: "Initialize a byte array,
    /// proofValue, that starts with the ECDSA-SD base proof header bytes 0xd9, 0x5d, and 0x00."
    /// </para>
    /// </remarks>
    public static ReadOnlySpan<byte> BaseProofHeader => [0xd9, 0x5d, 0x00];


    /// <summary>
    /// Gets the CBOR header bytes for derived proof values.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Derived proofs from the holder use header <c>0xd9 0x5d 0x01</c>.
    /// </para>
    /// <para>
    /// See <see href="https://w3c.github.io/vc-di-ecdsa/#serializederivedproofvalue">
    /// W3C VC DI ECDSA §3.3.18 serializeDerivedProofValue</see>: "Initialize a byte array,
    /// proofValue, that starts with the ECDSA-SD disclosure proof header bytes 0xd9, 0x5d, and 0x01."
    /// </para>
    /// </remarks>
    public static ReadOnlySpan<byte> DerivedProofHeader => [0xd9, 0x5d, 0x01];


    /// <summary>
    /// Gets the expected HMAC key length in bytes (256 bits for SHA-256).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Per RFC 2104, the HMAC key should be the same length as the digest size.
    /// For SHA-256, this is 256 bits (32 bytes).
    /// </para>
    /// <para>
    /// See <see href="https://w3c.github.io/vc-di-ecdsa/#base-proof-transformation-ecdsa-sd-2023">
    /// W3C VC DI ECDSA §3.3.6</see>: "Per the recommendations of RFC2104, the HMAC key
    /// MUST be the same length as the digest size; for SHA-256, this is 256 bits or 32 bytes."
    /// </para>
    /// </remarks>
    public static int HmacKeyLength => 32;


    /// <summary>
    /// Gets the P-256 signature length in IEEE P1363 format.
    /// </summary>
    /// <remarks>
    /// <para>
    /// P-256 ECDSA signatures in IEEE P1363 format are exactly 64 bytes (r || s, each 32 bytes).
    /// </para>
    /// <para>
    /// See <see href="https://w3c.github.io/vc-di-ecdsa/#algorithms">
    /// W3C VC DI ECDSA §3 Algorithms</see>: "proofBytes will be exactly 64 bytes in size for a P-256 key."
    /// </para>
    /// </remarks>
    public static int SignatureLength => 64;


    /// <summary>
    /// Gets the multikey-encoded public key length for P-256.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Format: 2-byte varint header (0x80, 0x24 for multicodec 0x1200 = P-256 public key)
    /// + 33-byte compressed public key = 35 bytes total.
    /// </para>
    /// <para>
    /// See <see href="https://w3c.github.io/vc-di-ecdsa/#base-proof-serialization-ecdsa-sd-2023">
    /// W3C VC DI ECDSA §3.3.9</see>: "Initialize publicKey to the multikey expression of the
    /// public key... an array of bytes starting with the bytes 0x80 and 0x24."
    /// </para>
    /// </remarks>
    public static int MultikeyPublicKeyLength => 35;
}