using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Verifies a CAdES baseline (CAdES-B-B, ETSI EN 319 122-1) signature: a CMS SignedData whose signature
/// covers the mandatory signed attributes that bind the signer and the content. This layers on the neutral
/// <see cref="VerifyCmsSignedDataDelegate"/> CMS core (which verifies the signature and the
/// <c>message-digest</c> binding of the content) and adds the CAdES rules — the <c>content-type</c> attribute
/// is present and the <c>signing-certificate-v2</c> attribute (ESS, RFC 5035) binds the signer certificate,
/// so a substituted certificate cannot be passed off as the signer.
/// </summary>
/// <remarks>
/// <para>
/// This is the EU advanced-signature consumer of the same CMS core eMRTD Passive Authentication uses: the
/// signature and content binding are verified once by the shared seam, and CAdES adds only its
/// signed-attribute rules here, in neutral code. The signer certificate's signature on the content is
/// established by the seam; building trust in that certificate (a chain to a trusted anchor) is a separate
/// step through <see cref="ValidateCertificateChainAsyncDelegate"/>, as for Passive Authentication.
/// </para>
/// <para>
/// The baseline level B is the signed-attribute set only; the timestamp (level T) and long-term validation
/// material (levels LT and LTA) are later additions. The optional <c>signing-time</c> attribute is surfaced
/// when present. RSA and elliptic-curve signers are both handled because the CMS core verifies the signature;
/// the <c>signing-certificate-v2</c> hash uses the algorithm the attribute declares (SHA-256 by default).
/// </para>
/// </remarks>
public static class CAdESVerification
{
    /// <summary>The content-type signed attribute (RFC 5652 §11.1).</summary>
    private const string ContentTypeOid = "1.2.840.113549.1.9.3";

    /// <summary>The signing-time signed attribute (RFC 5652 §11.3).</summary>
    private const string SigningTimeOid = "1.2.840.113549.1.9.5";

    /// <summary>The signing-certificate-v2 signed attribute (ESS, RFC 5035 §3).</summary>
    private const string SigningCertificateV2Oid = "1.2.840.113549.1.9.16.2.47";

    /// <summary>The signature-time-stamp-token unsigned attribute (CAdES-T, RFC 3161 / ETSI EN 319 122-1 §5.3).</summary>
    private const string SignatureTimeStampTokenOid = "1.2.840.113549.1.9.16.2.14";


    /// <summary>
    /// Verifies a CAdES-B-B signature.
    /// </summary>
    /// <param name="signedData">The CMS SignedData carrier (with encapsulated content).</param>
    /// <param name="pool">The memory pool for the verified content and the certificate-hash computation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The verification result; on success it owns the verified content and the caller disposes it. On failure it carries no content.</returns>
    /// <exception cref="InvalidOperationException">Thrown when no <see cref="VerifyCmsSignedDataDelegate"/> is registered.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the verified content transfers to a successful result, which the caller disposes; every failure path disposes it before returning.")]
    public static async ValueTask<CAdESVerificationResult> VerifyAsync(
        CmsSignedData signedData,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(pool);

        VerifyCmsSignedDataDelegate verifyCms = CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate))
            ?? throw new InvalidOperationException("No VerifyCmsSignedDataDelegate has been registered.");

        CmsVerifiedContent content;
        try
        {
            content = await verifyCms(signedData, pool, cancellationToken).ConfigureAwait(false);
        }
        catch(CryptographicException)
        {
            //The CMS signature (over the signed attributes, including the message-digest binding) did not verify.
            return CAdESVerificationResult.Failed(CAdESVerificationStatus.InvalidSignature);
        }

        return await VerifyAttributesAsync(signedData, content, verifyCms, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies a CAdES-B-B signature whose CMS SignedData encapsulates no content of its own (RFC 5652 §5.2) —
    /// the shape every PAdES signature takes (ETSI EN 319 142-1 clause 5.3, PA-4.1-01/PA-6.3-h) and the shape
    /// every CAdES object inside an Associated Signature Container takes (ETSI EN 319 162-1 clause 4.4.4.2 item
    /// 3 a)). The same CAdES-B rules <see cref="VerifyAsync"/> applies, over the detached-content counterpart of
    /// the CMS core.
    /// </summary>
    /// <param name="signedData">The CMS SignedData carrier, encapsulating no content of its own.</param>
    /// <param name="detachedContent">The octets the signature is detached over — for PAdES, the document's own <c>ByteRange</c>-gapped bytes.</param>
    /// <param name="pool">The memory pool for the verified content and the certificate-hash computation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The verification result; on success it owns the verified content (the supplied detached octets) and the caller disposes it. On failure it carries no content.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/>, <paramref name="detachedContent"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the verified content transfers to a successful result, which the caller disposes; every failure path disposes it before returning.")]
    public static async ValueTask<CAdESVerificationResult> VerifyDetachedAsync(
        CmsSignedData signedData,
        SignedContentMemory detachedContent,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(detachedContent);
        ArgumentNullException.ThrowIfNull(pool);

        //The detached counterpart is optional to register: a host that supplies one chooses the backend a
        //detached signature verifies on, and a host that supplies none keeps the library's own managed backend —
        //the same registry-with-fallback shape CAdESSignatureFacts.VerifyCryptographyAsync already applies.
        VerifyDetachedCmsSignedDataDelegate verifyDetachedCms =
            CryptographicKeyFactory.GetFunction<VerifyDetachedCmsSignedDataDelegate>(typeof(VerifyDetachedCmsSignedDataDelegate))
            ?? ManagedCmsVerification.VerifyDetachedCmsSignedDataAsync;

        CmsVerifiedContent content;
        try
        {
            content = await verifyDetachedCms(signedData, detachedContent, pool, cancellationToken).ConfigureAwait(false);
        }
        catch(CryptographicException)
        {
            //The CMS signature (over the signed attributes, including the message-digest binding against the
            //supplied detached content) did not verify.
            return CAdESVerificationResult.Failed(CAdESVerificationStatus.InvalidSignature);
        }

        return await VerifyAttributesAsync(signedData, content, verifyCms: null, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Applies the CAdES-B baseline signed-attribute rules and the CAdES-T signature-timestamp check to CMS
    /// content the core has already verified — shared between <see cref="VerifyAsync"/>'s encapsulated path and
    /// <see cref="VerifyDetachedAsync"/>'s detached path, which differ only in how the core verification below
    /// them was reached.
    /// </summary>
    /// <param name="verifyCms">
    /// <see cref="VerifyAsync"/>'s own already-resolved <see cref="VerifyCmsSignedDataDelegate"/>, or
    /// <see langword="null"/> from <see cref="VerifyDetachedAsync"/>, which registers no requirement of its own on
    /// this delegate. Never resolved here: a present signature-time-stamp is the only reason this method's own
    /// callee ever needs it, so resolution — and the <see cref="InvalidOperationException"/> an unregistered
    /// delegate throws — is deferred to <see cref="VerifyTimestampAsync"/>, reached only when a token is actually
    /// present. <see cref="VerifyDetachedAsync"/>'s documented registry-with-fallback therefore holds even with
    /// nothing registered, for the common case of a signature carrying no timestamp.
    /// </param>
    private static async ValueTask<CAdESVerificationResult> VerifyAttributesAsync(
        CmsSignedData signedData, CmsVerifiedContent content, VerifyCmsSignedDataDelegate? verifyCms, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        try
        {
            //CAdES-B baseline: the content-type attribute is mandatory whenever signed attributes are present.
            if(!content.TryGetSignedAttribute(ContentTypeOid, out _))
            {
                content.Dispose();

                return CAdESVerificationResult.Failed(CAdESVerificationStatus.MissingContentType);
            }

            //The signing-certificate-v2 attribute binds the signer certificate into the signed data.
            if(!content.TryGetSignedAttribute(SigningCertificateV2Oid, out CmsSignedAttribute? signingCertificate))
            {
                content.Dispose();

                return CAdESVerificationResult.Failed(CAdESVerificationStatus.MissingSigningCertificate);
            }

            CAdESVerificationStatus bindingStatus = await VerifySigningCertificateBindingAsync(
                signingCertificate, content.SignerCertificate.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
            if(bindingStatus != CAdESVerificationStatus.Valid)
            {
                content.Dispose();

                return CAdESVerificationResult.Failed(bindingStatus);
            }

            DateTimeOffset? signingTime = ReadSigningTime(content);

            //CAdES-T: an optional signature timestamp over the signature value, raising the level to T.
            (AdESBaselineLevel level, DateTimeOffset? timestampTime, CAdESVerificationStatus timestampStatus) =
                await VerifyTimestampAsync(signedData, verifyCms, pool, cancellationToken).ConfigureAwait(false);
            if(timestampStatus != CAdESVerificationStatus.Valid)
            {
                content.Dispose();

                return CAdESVerificationResult.Failed(timestampStatus);
            }

            return CAdESVerificationResult.Valid(content, signingTime, level, timestampTime);
        }
        catch(AsnContentException)
        {
            //A signed attribute was not well-formed DER.
            content.Dispose();

            return CAdESVerificationResult.Failed(CAdESVerificationStatus.Malformed);
        }
    }


    /// <summary>
    /// Verifies the optional CAdES-T signature timestamp: the signature-time-stamp-token unsigned attribute,
    /// when present, is itself a CMS SignedData (an RFC 3161 timestamp token) whose encapsulated TSTInfo binds
    /// the CAdES signature value through its message imprint. The token's own signature is verified through the
    /// CMS seam, and its message imprint is checked against the hash of the CAdES signature value.
    /// </summary>
    /// <returns>The level reached (Baseline when no timestamp is present, Timestamp when a valid one is), the timestamp time, and the status (a non-<see cref="CAdESVerificationStatus.Valid"/> status when a present timestamp fails).</returns>
    /// <exception cref="InvalidOperationException">A signature-time-stamp token is present, <paramref name="verifyCms"/> is <see langword="null"/>, and no <see cref="VerifyCmsSignedDataDelegate"/> is registered — resolved lazily here, the one place this method's own work actually needs it.</exception>
    private static async ValueTask<(AdESBaselineLevel Level, DateTimeOffset? Time, CAdESVerificationStatus Status)> VerifyTimestampAsync(
        CmsSignedData signedData, VerifyCmsSignedDataDelegate? verifyCms, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        (ReadOnlyMemory<byte> signatureValue, IReadOnlyList<(string Oid, ReadOnlyMemory<byte> Value)> unsignedAttributes) =
            ManagedCmsVerification.ParseSignerExtras(signedData.AsReadOnlySpan());

        ReadOnlyMemory<byte>? token = null;
        foreach((string oid, ReadOnlyMemory<byte> value) in unsignedAttributes)
        {
            if(string.Equals(oid, SignatureTimeStampTokenOid, StringComparison.Ordinal))
            {
                token = value;
                break;
            }
        }

        if(token is null)
        {
            //No signature timestamp: a valid CAdES-B-B (baseline) signature. VerifyCmsSignedDataDelegate is never
            //resolved on this path, so a caller with nothing registered still reaches this success.
            return (AdESBaselineLevel.BB, null, CAdESVerificationStatus.Valid);
        }

        VerifyCmsSignedDataDelegate resolvedVerifyCms = verifyCms
            ?? CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate))
            ?? throw new InvalidOperationException("No VerifyCmsSignedDataDelegate has been registered.");

        using CmsSignedData tokenCarrier = CmsSignedData.FromBytes(token.Value.Span, pool);
        CmsVerifiedContent timestamp;
        try
        {
            timestamp = await resolvedVerifyCms(tokenCarrier, pool, cancellationToken).ConfigureAwait(false);
        }
        catch(CryptographicException)
        {
            return (AdESBaselineLevel.BB, null, CAdESVerificationStatus.InvalidTimestamp);
        }

        using(timestamp)
        {
            using TimestampTokenInfo tokenInfo = TimestampTokenInfo.Read(timestamp.Content, pool);
            if(tokenInfo.Status == TimestampTokenInfoStatus.UnsupportedMessageImprintAlgorithm)
            {
                return (AdESBaselineLevel.BB, null, CAdESVerificationStatus.UnsupportedHashAlgorithm);
            }

            if(!tokenInfo.IsRead)
            {
                //The TSTInfo is not well-formed DER, which is the same Malformed outcome a signed attribute that
                //does not parse produces.
                return (AdESBaselineLevel.BB, null, CAdESVerificationStatus.Malformed);
            }

            if(!await tokenInfo.VerifyMessageImprintAsync(signatureValue, pool, cancellationToken).ConfigureAwait(false))
            {
                //The timestamp does not bind this signature.
                return (AdESBaselineLevel.BB, null, CAdESVerificationStatus.TimestampImprintMismatch);
            }

            return (AdESBaselineLevel.BT, tokenInfo.GenerationTime, CAdESVerificationStatus.Valid);
        }
    }


    /// <summary>
    /// Verifies that the signing-certificate-v2 attribute's first ESSCertIDv2 hash matches the signer
    /// certificate under the hash algorithm it declares (SHA-256 by default).
    /// </summary>
    private static async ValueTask<CAdESVerificationStatus> VerifySigningCertificateBindingAsync(
        CmsSignedAttribute signingCertificate, ReadOnlyMemory<byte> signerCertificate, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        (string hashOid, byte[] certificateHash) = ParseFirstEssCertId(signingCertificate.AsReadOnlyMemory());

        PkiDigestAlgorithm? algorithm = PkiDigestAlgorithm.FromOid(hashOid);
        if(algorithm is null)
        {
            return CAdESVerificationStatus.UnsupportedHashAlgorithm;
        }

        using DigestValue computed = await CryptographicKeyEvents.ComputeDigestAsync(
            signerCertificate, algorithm.Value.OutputByteLength, algorithm.Value.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return computed.AsReadOnlySpan().SequenceEqual(certificateHash)
            ? CAdESVerificationStatus.Valid
            : CAdESVerificationStatus.SigningCertificateMismatch;
    }


    /// <summary>
    /// Parses the first ESSCertIDv2 of a SigningCertificateV2 attribute value (RFC 5035 §3), returning the
    /// declared hash-algorithm object identifier (SHA-256 when omitted) and the certificate hash.
    /// </summary>
    private static (string HashOid, byte[] CertificateHash) ParseFirstEssCertId(ReadOnlyMemory<byte> signingCertificateV2)
    {
        var reader = new AsnReader(signingCertificateV2, AsnEncodingRules.DER);
        AsnReader signingCertificate = reader.ReadSequence();
        AsnReader certificates = signingCertificate.ReadSequence();
        AsnReader essCertId = certificates.ReadSequence();

        //hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256}: present when the next element is the
        //AlgorithmIdentifier SEQUENCE, omitted (default SHA-256) when the certHash OCTET STRING comes first.
        string hashOid = WellKnownOids.Sha256;
        if(essCertId.PeekTag() == new Asn1Tag(UniversalTagNumber.Sequence, isConstructed: true))
        {
            AsnReader hashAlgorithm = essCertId.ReadSequence();
            hashOid = hashAlgorithm.ReadObjectIdentifier();
        }

        byte[] certificateHash = essCertId.ReadOctetString();

        return (hashOid, certificateHash);
    }


    /// <summary>
    /// Reads the optional signing-time signed attribute (a UTCTime or GeneralizedTime), or
    /// <see langword="null"/> when it is absent or unparsable.
    /// </summary>
    private static DateTimeOffset? ReadSigningTime(CmsVerifiedContent content)
    {
        if(!content.TryGetSignedAttribute(SigningTimeOid, out CmsSignedAttribute? signingTime))
        {
            return null;
        }

        try
        {
            var reader = new AsnReader(signingTime.AsReadOnlyMemory(), AsnEncodingRules.DER);
            Asn1Tag tag = reader.PeekTag();

            if(tag == new Asn1Tag(UniversalTagNumber.UtcTime))
            {
                return reader.ReadUtcTime();
            }

            if(tag == new Asn1Tag(UniversalTagNumber.GeneralizedTime))
            {
                return reader.ReadGeneralizedTime();
            }

            return null;
        }
        catch(AsnContentException)
        {
            return null;
        }
    }
}


/// <summary>
/// The outcome of a CAdES-B-B verification. <see cref="CAdESVerificationStatus.Valid"/> is the only success;
/// every other value is the rule that failed.
/// </summary>
public enum CAdESVerificationStatus
{
    /// <summary>The signature and all CAdES-B baseline signed-attribute rules verified.</summary>
    Valid,

    /// <summary>The CMS signature over the signed attributes did not verify.</summary>
    InvalidSignature,

    /// <summary>The mandatory content-type signed attribute is absent.</summary>
    MissingContentType,

    /// <summary>The signing-certificate-v2 signed attribute is absent.</summary>
    MissingSigningCertificate,

    /// <summary>The signing-certificate-v2 hash does not match the signer certificate.</summary>
    SigningCertificateMismatch,

    /// <summary>The signing-certificate-v2 hash algorithm is not supported.</summary>
    UnsupportedHashAlgorithm,

    /// <summary>A signature timestamp is present but its own signature does not verify.</summary>
    InvalidTimestamp,

    /// <summary>A signature timestamp is present but its message imprint does not bind the signature.</summary>
    TimestampImprintMismatch,

    /// <summary>A signed attribute could not be parsed.</summary>
    Malformed
}


/// <summary>
/// The result of <see cref="CAdESVerification.VerifyAsync"/>. On success it owns the verified CMS content and
/// surfaces the signer certificate and the optional signing time; the caller disposes it. On failure it owns
/// nothing.
/// </summary>
public sealed class CAdESVerificationResult: IDisposable
{
    private CmsVerifiedContent? VerifiedContent { get; }
    private bool disposed;


    private CAdESVerificationResult(CAdESVerificationStatus status, CmsVerifiedContent? verifiedContent, DateTimeOffset? signingTime, AdESBaselineLevel level, DateTimeOffset? timestampTime)
    {
        Status = status;
        this.VerifiedContent = verifiedContent;
        SigningTime = signingTime;
        Level = level;
        TimestampTime = timestampTime;
    }


    /// <summary>Gets the verification status; <see cref="CAdESVerificationStatus.Valid"/> is the only success.</summary>
    public CAdESVerificationStatus Status { get; }

    /// <summary>Gets a value indicating whether the signature verified against all CAdES-B baseline rules.</summary>
    public bool IsValid => Status == CAdESVerificationStatus.Valid;

    /// <summary>Gets the CAdES level the signature reached: <see cref="AdESBaselineLevel.BB"/>, or <see cref="AdESBaselineLevel.BT"/> when a valid signature timestamp is present.</summary>
    public AdESBaselineLevel Level { get; }

    /// <summary>Gets the signing time from the optional signing-time attribute, or <see langword="null"/> when absent.</summary>
    public DateTimeOffset? SigningTime { get; }

    /// <summary>Gets the trusted time the signature timestamp asserts, or <see langword="null"/> when no timestamp is present.</summary>
    public DateTimeOffset? TimestampTime { get; }

    /// <summary>Gets the verified, encapsulated content; valid only when <see cref="IsValid"/>.</summary>
    public ReadOnlyMemory<byte> Content => VerifiedContent is null ? ReadOnlyMemory<byte>.Empty : VerifiedContent.Content;

    /// <summary>Gets the signer certificate the signing-certificate-v2 attribute bound; <see langword="null"/> on failure.</summary>
    public PkiCertificateMemory? SignerCertificate => VerifiedContent?.SignerCertificate;


    /// <summary>Creates a successful result owning the verified content.</summary>
    internal static CAdESVerificationResult Valid(CmsVerifiedContent verifiedContent, DateTimeOffset? signingTime, AdESBaselineLevel level, DateTimeOffset? timestampTime) =>
        new(CAdESVerificationStatus.Valid, verifiedContent, signingTime, level, timestampTime);

    /// <summary>Creates a failed result that owns nothing.</summary>
    internal static CAdESVerificationResult Failed(CAdESVerificationStatus status) =>
        new(status, null, null, AdESBaselineLevel.BB, null);


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            VerifiedContent?.Dispose();
            disposed = true;
        }
    }
}
