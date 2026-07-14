using System;
using System.Collections.Generic;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// The <c>bbs-2023</c> cryptosuite providing unlinkable selective disclosure with BBS signatures
/// over the BLS12-381 G2 group.
/// </summary>
/// <remarks>
/// <para>
/// This cryptosuite enables selective disclosure of individual claims within a credential and,
/// unlike <see cref="EcdsaSd2023CryptosuiteInfo"/>, provides unlinkability: a different,
/// unlinkable BBS proof can be derived from the same base proof for each presentation. It operates
/// in two phases with different proof types:
/// </para>
/// <list type="number">
///   <item>
///     <term>Base Proof (Issuer → Holder)</term>
///     <description>
///       Contains a single BBS signature over the mandatory statements (folded into the header) and
///       the non-mandatory statements (the BBS messages), allowing the holder to later selectively
///       reveal claims without issuer involvement. See <see cref="BbsBaseProof"/> for the parsed structure.
///     </description>
///   </item>
///   <item>
///     <term>Derived Proof (Holder → Verifier)</term>
///     <description>
///       Contains a BBS proof disclosing only the claims the holder chooses to reveal.
///       The verifier learns nothing about undisclosed claims and cannot link the derived proof
///       back to the base signature. See <see cref="BbsDerivedProof"/> for the parsed structure.
///     </description>
///   </item>
/// </list>
/// <para>
/// <strong>Algorithm Details:</strong>
/// </para>
/// <list type="number">
///   <item><description>Parse the document as JSON-LD and convert to RDF dataset.</description></item>
///   <item><description>Canonicalize using RDFC-1.0 with HMAC-shuffled blank node relabeling.</description></item>
///   <item><description>Group N-Quads into mandatory and non-mandatory based on JSON pointers.</description></item>
///   <item><description>Hash mandatory statements with SHA-256 to produce the mandatory hash.</description></item>
///   <item><description>Hash the canonicalized proof options with SHA-256 to produce the proof hash.</description></item>
///   <item><description>Sign the non-mandatory statements with the BBS header (proofHash || mandatoryHash).</description></item>
///   <item><description>Encode the base proof value using CBOR with header 0xd9 0x5d 0x02.</description></item>
/// </list>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-bbs/#bbs-2023">W3C VC DI BBS §3.4 bbs-2023</see>.
/// </para>
/// </remarks>
/// <seealso cref="BbsBaseProof"/>
/// <seealso cref="BbsDerivedProof"/>
public sealed class Bbs2023CryptosuiteInfo: CryptosuiteInfo
{
    private static IReadOnlyList<string> ContextsArray { get; } =
        new[] { "https://w3id.org/security/data-integrity/v2" }.AsReadOnly();


    /// <summary>
    /// The singleton instance of the <c>bbs-2023</c> cryptosuite information.
    /// </summary>
    public static Bbs2023CryptosuiteInfo Instance { get; } = new()
    {
        CryptosuiteName = "bbs-2023",
        Canonicalization = CanonicalizationAlgorithm.Rdfc10,
        HashAlgorithm = "SHA-256",
        SignatureAlgorithm = CryptoAlgorithm.Bls12381G2,
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
    /// See <see href="https://www.w3.org/TR/vc-di-bbs/#selective-disclosure-functions">
    /// W3C VC DI BBS §3.2 Selective Disclosure Functions</see>.
    /// </para>
    /// </remarks>
    public static bool SupportsSelectiveDisclosure => true;


    /// <summary>
    /// Gets the CBOR header bytes for baseline base proof values.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Baseline base proofs from the issuer use header <c>0xd9 0x5d 0x02</c>.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-di-bbs/#serializebaseproofvalue">
    /// W3C VC DI BBS §3.3.1 serializeBaseProofValue</see>.
    /// </para>
    /// </remarks>
    public static ReadOnlySpan<byte> BaseProofHeader => [0xd9, 0x5d, 0x02];


    /// <summary>
    /// Gets the CBOR header bytes for baseline derived proof values.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Baseline derived proofs from the holder use header <c>0xd9 0x5d 0x03</c>.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-di-bbs/#serializederivedproofvalue">
    /// W3C VC DI BBS §3.3.6 serializeDerivedProofValue</see>.
    /// </para>
    /// </remarks>
    public static ReadOnlySpan<byte> DerivedProofHeader => [0xd9, 0x5d, 0x03];


    /// <summary>
    /// Gets the expected HMAC key length in bytes (256 bits for SHA-256).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Per RFC 2104, the HMAC key MUST be the same length as the digest size; for SHA-256
    /// this is 256 bits or 32 bytes.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-di-bbs/#base-proof-transformation-bbs-2023">
    /// W3C VC DI BBS §3.4.2</see>.
    /// </para>
    /// </remarks>
    public static int HmacKeyLength => 32;


    /// <summary>
    /// Gets the BBS signature length in bytes for the BLS12-381-SHA-256 ciphersuite.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A BBS signature is the concatenation of a G1 point (48 bytes) and a scalar (32 bytes),
    /// for a total of 80 bytes.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/info/rfc9591">The BBS Signature Scheme</see>.
    /// </para>
    /// </remarks>
    public static int SignatureLength => 80;


    /// <summary>
    /// Gets the BBS header length in bytes.
    /// </summary>
    /// <remarks>
    /// The BBS header is the concatenation of the proof hash (32 bytes) and the mandatory hash
    /// (32 bytes), for a total of 64 bytes.
    /// </remarks>
    public static int BbsHeaderLength => 64;
}