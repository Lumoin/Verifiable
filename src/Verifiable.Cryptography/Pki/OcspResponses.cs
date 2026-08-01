using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>OCSPResponseStatus</c> values (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1">RFC
/// 6960 §4.2.1</see>). Value <c>4</c> is unused (reserved) in the RFC, so this enum deliberately has no
/// member for it.
/// </summary>
public enum OcspResponseStatus
{
    /// <summary>The response has valid confirmations.</summary>
    Successful = 0,

    /// <summary>The request did not conform to the OCSP syntax.</summary>
    MalformedRequest = 1,

    /// <summary>The responder reached an internal error condition.</summary>
    InternalError = 2,

    /// <summary>The responder is currently unable to return a response; the client should try again later.</summary>
    TryLater = 3,

    /// <summary>The responder requires the client to sign the request.</summary>
    SigRequired = 5,

    /// <summary>The client is not authorized to make this query to this responder.</summary>
    Unauthorized = 6
}


/// <summary>
/// The revocation status a <c>SingleResponse</c>'s <c>CertStatus</c> choice carries
/// (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1">RFC 6960 §4.2.1</see>).
/// </summary>
/// <remarks>
/// <see cref="Unknown"/> is deliberately the first (default) member, mirroring
/// <see cref="CertificateRevocationStatus.Unknown"/>: an unset or default-initialised status is the
/// fail-closed value rather than <see cref="Good"/>, so code that neglects to set this cannot accidentally
/// report a certificate as not revoked.
/// </remarks>
public enum OcspCertificateStatus
{
    /// <summary>The responder does not know about the certificate being requested. This is the default value.</summary>
    Unknown,

    /// <summary>A positive response to the status inquiry: the certificate is not revoked.</summary>
    Good,

    /// <summary>The certificate has been revoked (either permanently or temporarily, i.e. on hold).</summary>
    Revoked
}


/// <summary>
/// The facts a matched <c>SingleResponse</c> carries (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1">RFC 6960 §4.2.1</see>).
/// </summary>
[DebuggerDisplay("OcspSingleResponseFacts: {Status}, ThisUpdate={ThisUpdate}, NextUpdate={NextUpdate}")]
public sealed record OcspSingleResponseFacts
{
    /// <summary>Gets the <c>CertStatus</c>.</summary>
    public required OcspCertificateStatus Status { get; init; }

    /// <summary>Gets the <c>RevokedInfo.revocationTime</c>, or <see langword="null"/> when <see cref="Status"/> is not <see cref="OcspCertificateStatus.Revoked"/>.</summary>
    public required DateTimeOffset? RevocationTime { get; init; }

    /// <summary>Gets the <c>RevokedInfo.revocationReason</c> <c>CRLReason</c> numeric value, or <see langword="null"/> when absent or <see cref="Status"/> is not <see cref="OcspCertificateStatus.Revoked"/>.</summary>
    public required int? RevocationReason { get; init; }

    /// <summary>Gets the <c>thisUpdate</c> instant.</summary>
    public required DateTimeOffset ThisUpdate { get; init; }

    /// <summary>Gets the optional <c>nextUpdate</c> instant, or <see langword="null"/> when absent.</summary>
    public required DateTimeOffset? NextUpdate { get; init; }
}


/// <summary>
/// The outcome of <see cref="OcspResponseVerification.VerifyAsync"/>'s RFC 6960 §3.2 client checks.
/// </summary>
/// <remarks>
/// <see cref="NotVerified"/> is deliberately the first (default) member — mirroring
/// <see cref="CertificateRevocationStatus.Unknown"/> — so an unset or default-initialised outcome is
/// fail-closed rather than <see cref="Verified"/>.
/// </remarks>
public enum OcspResponseVerificationOutcome
{
    /// <summary>No verification outcome has been determined. This is the default value.</summary>
    NotVerified,

    /// <summary>The <c>OCSPResponseStatus</c> was not <c>successful</c> (RFC 6960 §4.2.1); see <see cref="OcspResponseVerificationResult.ResponseStatus"/>.</summary>
    NotSuccessful,

    /// <summary>The response bytes were not a well-formed <c>OCSPResponse</c>, or its <c>responseType</c> was not <c>id-pkix-ocsp-basic</c>.</summary>
    MalformedResponse,

    /// <summary>No <c>SingleResponse</c>, or more than one, or none whose <c>CertID</c> DER-equals the request's <c>CertID</c>.</summary>
    UnmatchedCertificateId,

    /// <summary>The request carried a nonce, the response carried a different one.</summary>
    NonceMismatch,

    /// <summary>The request carried a nonce, the response carried none, and <c>allowResponsesWithoutNonce</c> was not set.</summary>
    MissingRequiredNonce,

    /// <summary>The <c>tbsResponseData</c> signature did not verify under the resolved signer's public key.</summary>
    SignatureInvalid,

    /// <summary>No candidate certificate's identity matches the response's <c>responderID</c>.</summary>
    ResponderNotAuthorized,

    /// <summary>A candidate certificate matched the <c>responderID</c> but was not issued by the supplied issuer, lacks the <c>id-kp-OCSPSigning</c> Extended Key Usage, or is outside its own validity window at <c>validationTime</c>.</summary>
    ResponderCertificateInvalid,

    /// <summary><c>validationTime</c> is before <c>thisUpdate</c>, after <c>nextUpdate</c>, or <c>nextUpdate</c> is absent and <c>allowResponsesWithoutNextUpdate</c> was not set.</summary>
    StaleOrNotYetValid,

    /// <summary>Every check passed.</summary>
    Verified
}


/// <summary>
/// The result of <see cref="OcspResponseVerification.VerifyAsync"/>.
/// </summary>
[DebuggerDisplay("OcspResponseVerificationResult: {Outcome}, ResponseStatus={ResponseStatus}")]
public sealed record OcspResponseVerificationResult
{
    /// <summary>Gets the verification outcome.</summary>
    public required OcspResponseVerificationOutcome Outcome { get; init; }

    /// <summary>Gets the response's <c>OCSPResponseStatus</c>, when the envelope could be parsed far enough to read it.</summary>
    public required OcspResponseStatus? ResponseStatus { get; init; }

    /// <summary>Gets the matched <c>SingleResponse</c>'s facts; set only when <see cref="Outcome"/> is <see cref="OcspResponseVerificationOutcome.Verified"/>.</summary>
    public required OcspSingleResponseFacts? Single { get; init; }
}


/// <summary>
/// Verifies an RFC 6960 <c>OCSPResponse</c> against the RFC 6960 §3.2 client checks, with
/// <see cref="System.Formats.Asn1"/> parsing and the managed signature-verification idiom of
/// <see cref="ManagedCmsVerification"/> (<see cref="ManagedCertificate"/> plus
/// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>). No certificate library, no HTTP
/// client: the transport is <see cref="FetchOcspResponseAsyncDelegate"/>.
/// </summary>
/// <remarks>
/// <strong>Attacker-reachable input.</strong> An OCSP response arrives from an untrusted network responder,
/// so every structure below the outermost <c>OCSPResponse</c> sequence is read with
/// <see cref="AsnEncodingRules.DER"/> through <see cref="AsnReader"/>'s bounds-checked cursors; malformed
/// content anywhere in the walk throws <see cref="AsnContentException"/>, and
/// <see cref="OcspResponseVerification.VerifyAsync"/> catches it at a single top-level seam and reports
/// <see cref="OcspResponseVerificationOutcome.MalformedResponse"/> — never a raw parsing exception escaping to
/// the caller.
/// </remarks>
public static class OcspResponseVerification
{
    /// <summary>The ecdsa-with-SHA256 signature algorithm OID (RFC 5758 §3.2).</summary>
    private const string EcdsaWithSha256Oid = "1.2.840.10045.4.3.2";

    /// <summary>The ecdsa-with-SHA384 signature algorithm OID (RFC 5758 §3.2).</summary>
    private const string EcdsaWithSha384Oid = "1.2.840.10045.4.3.3";

    /// <summary>The ecdsa-with-SHA512 signature algorithm OID (RFC 5758 §3.2).</summary>
    private const string EcdsaWithSha512Oid = "1.2.840.10045.4.3.4";

    /// <summary>The SHA-1 digest output length in bytes (FIPS 180-4).</summary>
    private const int Sha1DigestByteLength = 20;

    /// <summary>The only RSA public exponent the registered RSA verification seam supports (RFC 8017), matching the constraint <see cref="ManagedCmsVerification"/> enforces for the same reason.</summary>
    private static ReadOnlySpan<byte> Exponent65537 => [0x01, 0x00, 0x01];

    /// <summary>The smallest RSA modulus bit length a responder key is verified at, the same band <see cref="ManagedCmsVerification"/> verifies under for the same reason.</summary>
    private static int MinimumRsaModulusBitLength => 2048;

    /// <summary>The largest RSA modulus bit length a responder key is verified at, the same band <see cref="ManagedCmsVerification"/> verifies under for the same reason.</summary>
    private static int MaximumRsaModulusBitLength => 16384;

    /// <summary>The ML-DSA-44 public key length in octets (NIST FIPS 204 Table 2), enforced exactly as <see cref="ManagedCmsVerification"/> enforces it.</summary>
    private static int MlDsa44PublicKeyLength => 1312;

    /// <summary>The ML-DSA-65 public key length in octets (NIST FIPS 204 Table 2), enforced exactly as <see cref="ManagedCmsVerification"/> enforces it.</summary>
    private static int MlDsa65PublicKeyLength => 1952;

    /// <summary>The ML-DSA-87 public key length in octets (NIST FIPS 204 Table 2), enforced exactly as <see cref="ManagedCmsVerification"/> enforces it.</summary>
    private static int MlDsa87PublicKeyLength => 2592;

    /// <summary>
    /// The SHA-1 digest tag — composed inline because the convenience digest tags in <see cref="CryptoTags"/>
    /// omit SHA-1 by design. Carries no qualifier: the registered <see cref="ComputeDigestDelegate"/> default
    /// (<c>MicrosoftCryptographicFunctions.ComputeDigestAsync</c>) dispatches the algorithm from the
    /// <see cref="HashAlgorithmName"/> this tag carries, mirroring the eMRTD BAC idiom
    /// (<c>BasicAccessControl.ComputeSha1Async</c>).
    /// </summary>
    private static Tag Sha1DigestTag { get; } = Tag.Create(HashAlgorithmName.SHA1).With(Purpose.Digest).With(EncodingScheme.Raw);


    /// <summary>
    /// Verifies <paramref name="response"/> against <paramref name="request"/> under the RFC 6960 §3.2 client
    /// checks: response status and type, signature, responder authorisation, request/response matching
    /// (<c>CertID</c> and nonce), and the validity time window.
    /// </summary>
    /// <param name="response">The DER-encoded <c>OCSPResponse</c>, tagged <see cref="PkiCertificateTags.OcspResponse"/>.</param>
    /// <param name="request">The request this response is answering, from <see cref="OcspRequests.CreateAsync"/>.</param>
    /// <param name="issuerCertificate">The target certificate's issuer — the direct signer, or the issuer of a delegated OCSP responder certificate.</param>
    /// <param name="validationTime">The instant at which the response's validity window is evaluated.</param>
    /// <param name="pool">The memory pool for every allocation this call performs.</param>
    /// <param name="allowResponsesWithoutNextUpdate">
    /// Whether a matched <c>SingleResponse</c> that omits the optional <c>nextUpdate</c> field is accepted.
    /// Secure default is <see langword="false"/>, mirroring <c>CrlRevocationChecker</c>'s
    /// <c>allowCrlsWithoutNextUpdate</c>: such a response has no freshness bound and could mask a later
    /// revocation indefinitely.
    /// </param>
    /// <param name="allowResponsesWithoutNonce">
    /// Whether a response that omits the nonce the request carried is accepted. Secure default is
    /// <see langword="false"/>; set <see langword="true"/> only for a deployment that legitimately serves
    /// RFC 5019-profile pre-produced responses, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9654#section-2.1">RFC 9654 §2.1</see>'s policy note on
    /// nonce-less responses.
    /// </param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The <see cref="OcspResponseVerificationResult"/>.</returns>
    /// <exception cref="ArgumentException">When <paramref name="response"/> does not carry an OCSP response, or <paramref name="issuerCertificate"/> does not carry an X.509 certificate.</exception>
    public static async ValueTask<OcspResponseVerificationResult> VerifyAsync(
        PkiCertificateMemory response,
        OcspRequestContent request,
        PkiCertificateMemory issuerCertificate,
        DateTimeOffset validationTime,
        MemoryPool<byte> pool,
        bool allowResponsesWithoutNextUpdate = false,
        bool allowResponsesWithoutNonce = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(issuerCertificate);
        ArgumentNullException.ThrowIfNull(pool);
        if(!response.IsOcspResponse)
        {
            throw new ArgumentException("The carrier must hold a DER-encoded OCSP response.", nameof(response));
        }

        if(!issuerCertificate.IsX509Certificate)
        {
            throw new ArgumentException("The carrier must hold an X.509 certificate.", nameof(issuerCertificate));
        }

        try
        {
            ManagedCertificate issuer = ManagedCertificate.Parse(issuerCertificate.AsReadOnlyMemory());

            return await VerifyParsedAsync(
                response, request, issuer, validationTime, pool,
                allowResponsesWithoutNextUpdate, allowResponsesWithoutNonce, cancellationToken).ConfigureAwait(false);
        }
        catch(AsnContentException)
        {
            //Hostile or malformed bytes: every DER-parsing failure anywhere in the walk — the envelope, the
            //BasicOCSPResponse, a SingleResponse, an embedded certificate, or a signature's own DER encoding
            //— is caught at this single seam (RFC 6960 §3.2).
            return new OcspResponseVerificationResult
            {
                Outcome = OcspResponseVerificationOutcome.MalformedResponse,
                ResponseStatus = null,
                Single = null
            };
        }
    }


    /// <summary>
    /// Runs the RFC 6960 §3.2 checks once the response envelope has been confirmed parseable enough to
    /// attempt them; may itself throw <see cref="AsnContentException"/>, caught by the caller's single seam.
    /// </summary>
    private static async ValueTask<OcspResponseVerificationResult> VerifyParsedAsync(
        PkiCertificateMemory response,
        OcspRequestContent request,
        ManagedCertificate issuer,
        DateTimeOffset validationTime,
        MemoryPool<byte> pool,
        bool allowResponsesWithoutNextUpdate,
        bool allowResponsesWithoutNonce,
        CancellationToken cancellationToken)
    {
        (OcspResponseStatus? responseStatus, ReadOnlyMemory<byte>? basicResponseBytes) = ReadResponseEnvelope(response.AsReadOnlyMemory());
        if(responseStatus is null)
        {
            return BuildResult(OcspResponseVerificationOutcome.MalformedResponse, null, null);
        }

        if(responseStatus != OcspResponseStatus.Successful)
        {
            return BuildResult(OcspResponseVerificationOutcome.NotSuccessful, responseStatus, null);
        }

        if(basicResponseBytes is null)
        {
            return BuildResult(OcspResponseVerificationOutcome.MalformedResponse, responseStatus, null);
        }

        ParsedBasicResponse basic = ParseBasicResponse(basicResponseBytes.Value);

        ManagedCertificate? signer = await ResponderIdMatches(issuer, basic.ResponderName, basic.ResponderKeyHash, pool, cancellationToken).ConfigureAwait(false)
            ? issuer
            : null;

        if(signer is null)
        {
            List<ManagedCertificate> identityMatches = await FindMatchingIdentities(basic.EmbeddedCertificates, basic.ResponderName, basic.ResponderKeyHash, pool, cancellationToken).ConfigureAwait(false);
            if(identityMatches.Count == 0)
            {
                return BuildResult(OcspResponseVerificationOutcome.ResponderNotAuthorized, responseStatus, null);
            }

            //certs [0] is outside tbsResponseData and therefore not signature-covered (RFC 6960 §4.2.1), so an
            //on-path attacker can freely prepend a decoy certificate sharing the genuine responder's identity.
            //Every identity match is tried in order — not just the first — so a decoy can only be stepped over,
            //never veto a later, genuinely authorised candidate; this also lets a responder embed two
            //certificates under the same subject Name across a key rollover.
            ManagedCertificate? authorized = null;
            foreach(ManagedCertificate candidate in identityMatches)
            {
                //id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1) is why a delegated responder candidate's own
                //revocation is not itself checked here — this checker's unconditional policy accepts that risk
                //rather than reading the extension, so the risk applies uniformly regardless of whether a given
                //CA actually asserts it.
                bool issuedByIssuer = candidate.IssuerDer.Span.SequenceEqual(issuer.SubjectDer.Span)
                    && await VerifySignatureAsync(candidate.TbsCertificateDer, candidate.SignatureAlgorithmOid, candidate.SignatureValue, issuer, pool, cancellationToken).ConfigureAwait(false);
                bool hasOcspSigningEku = HasKeyPurpose(candidate.ExtendedKeyUsageOids, WellKnownOids.OcspSigningKeyPurpose);
                bool withinValidity = validationTime >= candidate.NotBefore && validationTime <= candidate.NotAfter;

                if(issuedByIssuer && hasOcspSigningEku && withinValidity)
                {
                    authorized = candidate;
                    break;
                }
            }

            if(authorized is null)
            {
                return BuildResult(OcspResponseVerificationOutcome.ResponderCertificateInvalid, responseStatus, null);
            }

            signer = authorized;
        }

        bool signatureVerified = await VerifySignatureAsync(basic.TbsResponseDataDer, basic.SignatureAlgorithmOid, basic.SignatureValue, signer, pool, cancellationToken).ConfigureAwait(false);
        if(!signatureVerified)
        {
            return BuildResult(OcspResponseVerificationOutcome.SignatureInvalid, responseStatus, null);
        }

        //RFC 6960 §3.2(1) requires only that the CertID identified in the response CORRESPOND to the one
        //identified in the request — the four decoded fields, not a raw DER byte match (which would spuriously
        //reject a responder that re-encodes hashAlgorithm's tolerated NULL-parameters form instead of echoing
        //the request's absent-parameters encoding) — and does not require the response to carry exactly one
        //SingleResponse (some responders answer with an extra entry, e.g. for the issuer alongside the leaf).
        CertIdFields requestCertId = ReadRequestCertIdFields(request.Request);
        ParsedSingleResponse? matchedOrNull = null;
        foreach(ParsedSingleResponse candidate in basic.SingleResponses)
        {
            if(CertIdFieldsMatch(candidate.CertId, requestCertId))
            {
                matchedOrNull = candidate;
                break;
            }
        }

        if(matchedOrNull is not { } matched)
        {
            return BuildResult(OcspResponseVerificationOutcome.UnmatchedCertificateId, responseStatus, null);
        }

        if(request.RequestNonce is not null)
        {
            if(basic.NonceExtensionValue is null)
            {
                if(!allowResponsesWithoutNonce)
                {
                    return BuildResult(OcspResponseVerificationOutcome.MissingRequiredNonce, responseStatus, null);
                }
            }
            else if(!basic.NonceExtensionValue.Value.Span.SequenceEqual(request.RequestNonce.AsReadOnlySpan()))
            {
                return BuildResult(OcspResponseVerificationOutcome.NonceMismatch, responseStatus, null);
            }
        }

        if(validationTime < matched.ThisUpdate)
        {
            return BuildResult(OcspResponseVerificationOutcome.StaleOrNotYetValid, responseStatus, null);
        }

        if(matched.NextUpdate is { } nextUpdate)
        {
            if(validationTime > nextUpdate)
            {
                return BuildResult(OcspResponseVerificationOutcome.StaleOrNotYetValid, responseStatus, null);
            }
        }
        else if(!allowResponsesWithoutNextUpdate)
        {
            return BuildResult(OcspResponseVerificationOutcome.StaleOrNotYetValid, responseStatus, null);
        }

        var facts = new OcspSingleResponseFacts
        {
            Status = matched.Status,
            RevocationTime = matched.RevocationTime,
            RevocationReason = matched.RevocationReason,
            ThisUpdate = matched.ThisUpdate,
            NextUpdate = matched.NextUpdate
        };

        return BuildResult(OcspResponseVerificationOutcome.Verified, responseStatus, facts);


        //Composes the result record; a one-off helper reused at every early-exit above.
        static OcspResponseVerificationResult BuildResult(OcspResponseVerificationOutcome outcome, OcspResponseStatus? status, OcspSingleResponseFacts? facts) =>
            new() { Outcome = outcome, ResponseStatus = status, Single = facts };
    }


    /// <summary>
    /// Reads the outermost <c>OCSPResponse ::= SEQUENCE { responseStatus, responseBytes [0] EXPLICIT
    /// ResponseBytes OPTIONAL }</c> (RFC 6960 §4.2.1), unwrapping <c>ResponseBytes</c> to the embedded
    /// <c>BasicOCSPResponse</c> bytes when <c>responseType</c> is <c>id-pkix-ocsp-basic</c>.
    /// </summary>
    /// <returns>
    /// The response status (<see langword="null"/> when the ENUMERATED value is outside RFC 6960's defined
    /// range), and the <c>BasicOCSPResponse</c> bytes (<see langword="null"/> when absent, or present under
    /// an unrecognised <c>responseType</c>).
    /// </returns>
    private static (OcspResponseStatus? Status, ReadOnlyMemory<byte>? BasicResponseBytes) ReadResponseEnvelope(ReadOnlyMemory<byte> response)
    {
        var reader = new AsnReader(response, AsnEncodingRules.DER);
        AsnReader ocspResponse = reader.ReadSequence();
        reader.ThrowIfNotEmpty();

        BigInteger statusValue = ReadEnumeratedAsBigInteger(ocspResponse);
        OcspResponseStatus? status = MapResponseStatus(statusValue);
        if(status is null)
        {
            return (null, null);
        }

        if(status != OcspResponseStatus.Successful || !ocspResponse.HasData
            || !ocspResponse.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            return (status, null);
        }

        AsnReader responseBytesWrapper = ocspResponse.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        AsnReader responseBytes = responseBytesWrapper.ReadSequence();
        string responseType = responseBytes.ReadObjectIdentifier();
        if(!string.Equals(responseType, WellKnownOids.OcspBasicResponseType, StringComparison.Ordinal))
        {
            return (status, null);
        }

        ReadOnlyMemory<byte> basicResponseBytes = responseBytes.ReadOctetString();
        responseBytes.ThrowIfNotEmpty();
        responseBytesWrapper.ThrowIfNotEmpty();
        ocspResponse.ThrowIfNotEmpty();

        return (status, basicResponseBytes);
    }


    /// <summary>
    /// Reads a DER <c>ENUMERATED</c> value's content as a <see cref="BigInteger"/> — <c>OCSPResponseStatus</c>
    /// (RFC 6960 §4.2.1) and <c>CRLReason</c> (RFC 6960 §4.4.5) are both <c>ENUMERATED</c>, whose content
    /// encoding is byte-identical to <c>INTEGER</c> but whose universal class tag number (10) differs from
    /// <c>INTEGER</c>'s (2); <see cref="AsnReader.ReadInteger(Asn1Tag?)"/> rejects an explicit
    /// <see cref="UniversalTagNumber.Enumerated"/> tag override precisely because a <see cref="TagClass.Universal"/>
    /// override must name the operation's own natural tag, so the dedicated
    /// <see cref="AsnReader.ReadEnumeratedBytes(Asn1Tag?)"/> reader is the correct primitive here.
    /// </summary>
    /// <param name="reader">The reader positioned at the <c>ENUMERATED</c> value.</param>
    /// <returns>The value.</returns>
    private static BigInteger ReadEnumeratedAsBigInteger(AsnReader reader) =>
        new(reader.ReadEnumeratedBytes().Span, isUnsigned: false, isBigEndian: true);


    /// <summary>Maps an <c>OCSPResponseStatus</c> ENUMERATED value to <see cref="OcspResponseStatus"/>; <see langword="null"/> for value <c>4</c> (unused) or any other undefined value.</summary>
    private static OcspResponseStatus? MapResponseStatus(BigInteger value)
    {
        if(value < 0 || value > 6)
        {
            return null;
        }

        return (int)value switch
        {
            0 => OcspResponseStatus.Successful,
            1 => OcspResponseStatus.MalformedRequest,
            2 => OcspResponseStatus.InternalError,
            3 => OcspResponseStatus.TryLater,
            5 => OcspResponseStatus.SigRequired,
            6 => OcspResponseStatus.Unauthorized,
            _ => null
        };
    }


    /// <summary>
    /// Parses a <c>BasicOCSPResponse</c> (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1">RFC
    /// 6960 §4.2.1</see>): the exact <c>tbsResponseData</c> bytes (captured before descending, for signature
    /// verification), the <c>responderID</c>, every <c>SingleResponse</c>, the <c>id-pkix-ocsp-nonce</c>
    /// <c>responseExtensions</c> entry when present, the outer signature, and any embedded certificates.
    /// </summary>
    private static ParsedBasicResponse ParseBasicResponse(ReadOnlyMemory<byte> basicResponseBytes)
    {
        var basicReader = new AsnReader(basicResponseBytes, AsnEncodingRules.DER);
        AsnReader basic = basicReader.ReadSequence();

        ReadOnlyMemory<byte> tbsResponseDataDer = basic.ReadEncodedValue();
        AsnReader tbsResponseData = new AsnReader(tbsResponseDataDer, AsnEncodingRules.DER).ReadSequence();

        //version [0] EXPLICIT INTEGER DEFAULT v1.
        if(tbsResponseData.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            _ = tbsResponseData.ReadEncodedValue();
        }

        (ReadOnlyMemory<byte>? responderName, ReadOnlyMemory<byte>? responderKeyHash) = ReadResponderId(tbsResponseData);

        _ = tbsResponseData.ReadGeneralizedTime();                     //producedAt, structurally validated only.

        var singleResponses = new List<ParsedSingleResponse>();
        AsnReader responses = tbsResponseData.ReadSequence();
        while(responses.HasData)
        {
            singleResponses.Add(ReadSingleResponse(responses));
        }

        responses.ThrowIfNotEmpty();

        ReadOnlyMemory<byte>? nonceExtensionValue = ReadNonceExtension(tbsResponseData);

        tbsResponseData.ThrowIfNotEmpty();

        AsnReader signatureAlgorithm = basic.ReadSequence();
        string signatureAlgorithmOid = signatureAlgorithm.ReadObjectIdentifier();
        if(!basic.TryReadPrimitiveBitString(out _, out ReadOnlyMemory<byte> signatureValue))
        {
            throw new AsnContentException("A BasicOCSPResponse must carry its signature as a primitive BIT STRING in DER (RFC 6960 §4.2.1).");
        }

        var embeddedCertificates = new List<ManagedCertificate>();
        if(basic.HasData && basic.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            AsnReader certsWrapper = basic.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            AsnReader certs = certsWrapper.ReadSequence();
            while(certs.HasData)
            {
                embeddedCertificates.Add(ManagedCertificate.Parse(certs.ReadEncodedValue()));
            }

            certs.ThrowIfNotEmpty();
            certsWrapper.ThrowIfNotEmpty();
        }

        basic.ThrowIfNotEmpty();

        //ResponseBytes.response is an OCTET STRING (RFC 6960 §4.2.1) whose content is exactly this
        //BasicOCSPResponse's DER encoding; bytes appended after the SEQUENCE closes, still inside that OCTET
        //STRING, are unread here — rejecting them is this reader's own responsibility, not the envelope
        //reader's, since the two live in different AsnReader instances.
        basicReader.ThrowIfNotEmpty();

        return new ParsedBasicResponse(
            tbsResponseDataDer, responderName, responderKeyHash, singleResponses, nonceExtensionValue,
            signatureAlgorithmOid, signatureValue, embeddedCertificates);
    }


    /// <summary>
    /// Reads a <c>ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash }</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1">RFC 6960 §4.2.1</see>).
    /// </summary>
    private static (ReadOnlyMemory<byte>? Name, ReadOnlyMemory<byte>? KeyHash) ReadResponderId(AsnReader tbsResponseData)
    {
        Asn1Tag responderTag = tbsResponseData.PeekTag();
        if(responderTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            AsnReader byNameWrapper = tbsResponseData.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            ReadOnlyMemory<byte> name = byNameWrapper.ReadEncodedValue();
            byNameWrapper.ThrowIfNotEmpty();

            return (name, null);
        }

        if(responderTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
        {
            AsnReader byKeyWrapper = tbsResponseData.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            ReadOnlyMemory<byte> keyHash = byKeyWrapper.ReadOctetString();
            byKeyWrapper.ThrowIfNotEmpty();

            return (null, keyHash);
        }

        throw new AsnContentException("A ResponseData responderID must be byName [1] or byKey [2] (RFC 6960 §4.2.1).");
    }


    /// <summary>
    /// Reads and validates a <c>SingleResponse</c>'s <c>CertID</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1">RFC 6960 §4.1.1</see>) as its decoded
    /// fields, for the request/response matching step.
    /// </summary>
    private static CertIdFields ReadCertIdFieldsAndValidate(AsnReader singleResponse)
    {
        ReadOnlyMemory<byte> certIdDer = singleResponse.ReadEncodedValue();
        AsnReader certId = new AsnReader(certIdDer, AsnEncodingRules.DER).ReadSequence();

        return ReadCertIdFields(certId);
    }


    /// <summary>
    /// Reads a <c>CertID</c>'s fields from a reader positioned at its content
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1">RFC 6960 §4.1.1</see>), accepting
    /// either an absent or a NULL <c>hashAlgorithm</c> parameters field and rejecting anything else — the same
    /// reader serves both a <c>SingleResponse</c>'s <c>CertID</c> and a request's <c>reqCert</c>.
    /// </summary>
    private static CertIdFields ReadCertIdFields(AsnReader certId)
    {
        AsnReader hashAlgorithm = certId.ReadSequence();
        string hashAlgorithmOid = hashAlgorithm.ReadObjectIdentifier();
        if(hashAlgorithm.HasData)
        {
            if(hashAlgorithm.PeekTag() != Asn1Tag.Null)
            {
                throw new AsnContentException("A CertID hashAlgorithm's parameters must be absent or NULL (RFC 3279 / RFC 5754 §2).");
            }

            hashAlgorithm.ReadNull();
        }

        hashAlgorithm.ThrowIfNotEmpty();
        ReadOnlyMemory<byte> issuerNameHash = certId.ReadOctetString();
        ReadOnlyMemory<byte> issuerKeyHash = certId.ReadOctetString();
        ReadOnlyMemory<byte> serialNumber = certId.ReadIntegerBytes();
        certId.ThrowIfNotEmpty();

        return new CertIdFields(hashAlgorithmOid, issuerNameHash, issuerKeyHash, serialNumber);
    }


    /// <summary>
    /// Reports whether two <see cref="CertIdFields"/> name the same certificate — the RFC 6960 §3.2(1)
    /// request/response correspondence check — comparing the hash algorithm OID and the three hashed/copied
    /// fields, never the CertID's raw DER encoding (which two conformant encoders can legitimately differ on,
    /// e.g. an absent versus an explicit NULL <c>hashAlgorithm</c> parameters field).
    /// </summary>
    private static bool CertIdFieldsMatch(CertIdFields a, CertIdFields b) =>
        string.Equals(a.HashAlgorithmOid, b.HashAlgorithmOid, StringComparison.Ordinal)
        && a.IssuerNameHash.Span.SequenceEqual(b.IssuerNameHash.Span)
        && a.IssuerKeyHash.Span.SequenceEqual(b.IssuerKeyHash.Span)
        && a.SerialNumber.Span.SequenceEqual(b.SerialNumber.Span);


    /// <summary>
    /// Reads a <c>SingleResponse</c> (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1">RFC
    /// 6960 §4.2.1</see>): its <c>CertID</c>, its <c>CertStatus</c> choice, and the update times.
    /// <c>singleExtensions</c> is structurally skipped, not read as a fact.
    /// </summary>
    private static ParsedSingleResponse ReadSingleResponse(AsnReader responses)
    {
        AsnReader singleResponse = responses.ReadSequence();
        CertIdFields certId = ReadCertIdFieldsAndValidate(singleResponse);

        //CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo, unknown [2] IMPLICIT NULL }.
        Asn1Tag statusTag = singleResponse.PeekTag();
        OcspCertificateStatus status;
        DateTimeOffset? revocationTime = null;
        int? revocationReason = null;

        if(statusTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            singleResponse.ReadNull(new Asn1Tag(TagClass.ContextSpecific, 0));
            status = OcspCertificateStatus.Good;
        }
        else if(statusTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            AsnReader revokedInfo = singleResponse.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            revocationTime = revokedInfo.ReadGeneralizedTime();
            if(revokedInfo.HasData && revokedInfo.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                AsnReader reasonWrapper = revokedInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                BigInteger reasonValue = ReadEnumeratedAsBigInteger(reasonWrapper);
                reasonWrapper.ThrowIfNotEmpty();
                revocationReason = reasonValue >= int.MinValue && reasonValue <= int.MaxValue ? (int)reasonValue : null;
            }

            revokedInfo.ThrowIfNotEmpty();
            status = OcspCertificateStatus.Revoked;
        }
        else if(statusTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
        {
            singleResponse.ReadNull(new Asn1Tag(TagClass.ContextSpecific, 2));
            status = OcspCertificateStatus.Unknown;
        }
        else
        {
            throw new AsnContentException("A SingleResponse certStatus must be good [0], revoked [1], or unknown [2] (RFC 6960 §4.2.1).");
        }

        DateTimeOffset thisUpdate = singleResponse.ReadGeneralizedTime();
        DateTimeOffset? nextUpdate = null;
        if(singleResponse.HasData && singleResponse.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            AsnReader nextUpdateWrapper = singleResponse.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            nextUpdate = nextUpdateWrapper.ReadGeneralizedTime();
            nextUpdateWrapper.ThrowIfNotEmpty();
        }

        if(singleResponse.HasData && singleResponse.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            _ = singleResponse.ReadEncodedValue();                     //singleExtensions — not read as a fact.
        }

        singleResponse.ThrowIfNotEmpty();

        return new ParsedSingleResponse(certId, status, revocationTime, revocationReason, thisUpdate, nextUpdate);
    }


    /// <summary>
    /// Reads the <c>id-pkix-ocsp-nonce</c> entry from an optional <c>responseExtensions [1] EXPLICIT
    /// Extensions</c> (<see href="https://www.rfc-editor.org/rfc/rfc9654#section-2.1">RFC 9654 §2.1</see>),
    /// unwrapping <c>extnValue</c>'s <c>Nonce ::= OCTET STRING</c> content.
    /// </summary>
    private static ReadOnlyMemory<byte>? ReadNonceExtension(AsnReader tbsResponseData)
    {
        if(!tbsResponseData.HasData || !tbsResponseData.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            return null;
        }

        AsnReader extensionsWrapper = tbsResponseData.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
        AsnReader extensions = extensionsWrapper.ReadSequence();
        ReadOnlyMemory<byte>? nonceValue = null;
        while(extensions.HasData)
        {
            AsnReader extension = extensions.ReadSequence();
            string extensionId = extension.ReadObjectIdentifier();
            if(extension.PeekTag() == Asn1Tag.Boolean)
            {
                _ = extension.ReadBoolean();
            }

            if(!extension.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> extensionValue))
            {
                throw new AsnContentException("A responseExtensions entry's value must be a primitive OCTET STRING in DER (RFC 5280 §4.1.2.9).");
            }

            if(string.Equals(extensionId, WellKnownOids.OcspNonce, StringComparison.Ordinal) && nonceValue is null)
            {
                var nonceValueReader = new AsnReader(extensionValue, AsnEncodingRules.DER);
                nonceValue = nonceValueReader.ReadOctetString();
                nonceValueReader.ThrowIfNotEmpty();
            }

            extension.ThrowIfNotEmpty();
        }

        extensionsWrapper.ThrowIfNotEmpty();

        return nonceValue;
    }


    /// <summary>
    /// Reads the request carrier's own <c>reqCert CertID</c> fields
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1">RFC 6960 §4.1.1</see>), for the
    /// request/response matching step. The request carrier is bytes this library minted
    /// (<see cref="OcspRequests.CreateAsync"/>), so this reads the exact shape that method writes: no
    /// <c>version</c>, an optional <c>requestorName</c> (tolerated though never written), exactly one
    /// <c>Request</c>.
    /// </summary>
    private static CertIdFields ReadRequestCertIdFields(PkiCertificateMemory request)
    {
        var reader = new AsnReader(request.AsReadOnlyMemory(), AsnEncodingRules.DER);
        AsnReader ocspRequest = reader.ReadSequence();
        AsnReader tbsRequest = ocspRequest.ReadSequence();

        if(tbsRequest.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            _ = tbsRequest.ReadEncodedValue();                         //version.
        }

        if(tbsRequest.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            _ = tbsRequest.ReadEncodedValue();                         //requestorName.
        }

        AsnReader requestList = tbsRequest.ReadSequence();
        AsnReader singleRequest = requestList.ReadSequence();
        AsnReader certId = new AsnReader(singleRequest.ReadEncodedValue(), AsnEncodingRules.DER).ReadSequence();

        return ReadCertIdFields(certId);                               //reqCert CertID.
    }


    /// <summary>
    /// Reports whether <paramref name="candidate"/>'s identity (subject Name, or SHA-1 of its public key)
    /// matches a <c>ResponderID</c>'s <c>byName</c> or <c>byKey</c> choice
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1">RFC 6960 §4.2.1</see>). The
    /// <c>byKey</c> arm awaits the async digest seam (see <see cref="Sha1DigestTag"/>'s remarks), so this is
    /// itself async even though the <c>byName</c> arm never suspends.
    /// </summary>
    /// <param name="candidate">The certificate whose identity is being matched.</param>
    /// <param name="responderName">The <c>ResponderID</c>'s <c>byName</c> choice value, or <see langword="null"/>.</param>
    /// <param name="responderKeyHash">The <c>ResponderID</c>'s <c>byKey</c> choice value, or <see langword="null"/>.</param>
    /// <param name="pool">The memory pool the <c>byKey</c> arm's digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token observed by the <c>byKey</c> arm's digest computation.</param>
    /// <returns><see langword="true"/> when <paramref name="candidate"/>'s identity matches.</returns>
    private static async ValueTask<bool> ResponderIdMatches(
        ManagedCertificate candidate, ReadOnlyMemory<byte>? responderName, ReadOnlyMemory<byte>? responderKeyHash, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(responderName is { } name)
        {
            return candidate.SubjectDer.Span.SequenceEqual(name.Span);
        }

        if(responderKeyHash is { } keyHash)
        {
            using DigestValue candidateKeyHash = await CryptographicKeyEvents.ComputeDigestAsync(
                candidate.SubjectPublicKeyBitStringContent, Sha1DigestByteLength, Sha1DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            return candidateKeyHash.AsReadOnlySpan().SequenceEqual(keyHash.Span);
        }

        return false;
    }


    /// <summary>
    /// Finds every embedded certificate whose identity matches the <c>responderID</c>, in certificate order;
    /// empty when none does. More than one candidate can match — <c>certs</c> is unsigned (RFC 6960 §4.2.1), so
    /// the caller must try each match rather than trusting the first.
    /// </summary>
    /// <param name="embeddedCertificates">The candidates to test, in certificate order.</param>
    /// <param name="responderName">The <c>ResponderID</c>'s <c>byName</c> choice value, or <see langword="null"/>.</param>
    /// <param name="responderKeyHash">The <c>ResponderID</c>'s <c>byKey</c> choice value, or <see langword="null"/>.</param>
    /// <param name="pool">The memory pool a <c>byKey</c> match's digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token observed by each candidate's digest computation.</param>
    /// <returns>The matching candidates, in certificate order; empty when none match.</returns>
    private static async ValueTask<List<ManagedCertificate>> FindMatchingIdentities(
        IReadOnlyList<ManagedCertificate> embeddedCertificates, ReadOnlyMemory<byte>? responderName, ReadOnlyMemory<byte>? responderKeyHash, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        List<ManagedCertificate> matches = [];
        foreach(ManagedCertificate candidate in embeddedCertificates)
        {
            if(await ResponderIdMatches(candidate, responderName, responderKeyHash, pool, cancellationToken).ConfigureAwait(false))
            {
                matches.Add(candidate);
            }
        }

        return matches;
    }


    /// <summary>Reports whether <paramref name="keyPurposeOids"/> contains <paramref name="keyPurposeOid"/>.</summary>
    private static bool HasKeyPurpose(IReadOnlyList<string> keyPurposeOids, string keyPurposeOid)
    {
        foreach(string oid in keyPurposeOids)
        {
            if(string.Equals(oid, keyPurposeOid, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Verifies <paramref name="signatureValue"/> over <paramref name="message"/> under <paramref name="signer"/>'s
    /// public key, dispatching on the key's algorithm exactly as <see cref="ManagedCmsVerification"/> does: an
    /// elliptic-curve key by its own curve (rejecting an <paramref name="signatureAlgorithmOid"/> that does
    /// not name that curve's canonical signature algorithm), an RSA key restricted to
    /// RSASSA-PKCS1-v1_5 with SHA-256, SHA-384 or SHA-512, or an ML-DSA key under its own parameter-set
    /// identifier. Any other key form fails closed to <see langword="false"/>.
    /// </summary>
    private static async ValueTask<bool> VerifySignatureAsync(
        ReadOnlyMemory<byte> message, string signatureAlgorithmOid, ReadOnlyMemory<byte> signatureValue, ManagedCertificate signer, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(signer.EllipticCurve != EllipticCurveTypes.None)
        {
            return await VerifyEllipticCurveAsync(message, signatureAlgorithmOid, signatureValue, signer, pool, cancellationToken).ConfigureAwait(false);
        }

        if(signer.RsaModulus.Length > 0)
        {
            return await VerifyRsaAsync(message, signatureAlgorithmOid, signatureValue, signer, cancellationToken).ConfigureAwait(false);
        }

        if(signer.MlDsaPublicKey.Length > 0)
        {
            return await VerifyMlDsaAsync(message, signatureAlgorithmOid, signatureValue, signer, cancellationToken).ConfigureAwait(false);
        }

        return false;
    }


    /// <summary>
    /// Verifies an ML-DSA (NIST FIPS 204) signature against the signer's raw ML-DSA public key, exactly as
    /// <see cref="ManagedCmsVerification"/>'s ML-DSA arm does: the stated signature algorithm must equal the
    /// certificate key's own parameter-set identifier — a signature claimed under a different set is the
    /// substitution shape and fails closed — and the pure signature is verified through the registered seam.
    /// </summary>
    private static async ValueTask<bool> VerifyMlDsaAsync(
        ReadOnlyMemory<byte> message, string signatureAlgorithmOid, ReadOnlyMemory<byte> signatureValue, ManagedCertificate signer, CancellationToken cancellationToken)
    {
        if(!string.Equals(signatureAlgorithmOid, signer.MlDsaAlgorithmOid, StringComparison.Ordinal))
        {
            return false;
        }

        (CryptoAlgorithm Algorithm, int PublicKeyLength)? resolved = signer.MlDsaAlgorithmOid switch
        {
            WellKnownOids.MlDsa44 => (CryptoAlgorithm.MlDsa44, MlDsa44PublicKeyLength),
            WellKnownOids.MlDsa65 => (CryptoAlgorithm.MlDsa65, MlDsa65PublicKeyLength),
            WellKnownOids.MlDsa87 => (CryptoAlgorithm.MlDsa87, MlDsa87PublicKeyLength),
            _ => ((CryptoAlgorithm, int)?)null
        };

        if(resolved is null)
        {
            return false;
        }

        //An ML-DSA public key has one exact length per parameter set, so any other length fails closed here
        //rather than reaching the registered backend, whose own malformed-encoding failure would escape this
        //file's no-raw-exception seam on attacker-controlled responder bytes.
        if(signer.MlDsaPublicKey.Length != resolved.Value.PublicKeyLength)
        {
            return false;
        }

        VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(resolved.Value.Algorithm, Purpose.Verification);
        (bool isVerified, CryptoEvent? evt) = await verify(message, signatureValue, signer.MlDsaPublicKey, null, cancellationToken).ConfigureAwait(false);
        CryptographicKeyEvents.Emit(evt);

        return isVerified;
    }


    /// <summary>Verifies an ECDSA signature: the DER <c>SEQUENCE {r, s}</c> is converted to fixed width and verified against the signer's public point.</summary>
    private static async ValueTask<bool> VerifyEllipticCurveAsync(
        ReadOnlyMemory<byte> message, string signatureAlgorithmOid, ReadOnlyMemory<byte> signatureValue, ManagedCertificate signer, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        CryptoAlgorithm? algorithm = EcdsaAlgorithmForOidAndCurve(signatureAlgorithmOid, signer.EllipticCurve);
        if(algorithm is null)
        {
            return false;
        }

        VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm.Value, Purpose.Verification);
        int fieldWidth = (signer.PublicPoint.Length - 1) / 2;
        using IMemoryOwner<byte> signature = ConvertDerSignatureToFixedWidth(signatureValue.Span, fieldWidth, pool);

        (bool isVerified, CryptoEvent? evt) = await verify(
            message, signature.Memory[..(fieldWidth * 2)], signer.PublicPoint, null, cancellationToken).ConfigureAwait(false);
        CryptographicKeyEvents.Emit(evt);

        return isVerified;
    }


    /// <summary>Maps a signature algorithm OID paired with a certificate's own curve to the registered <see cref="CryptoAlgorithm"/>; <see langword="null"/> when the OID does not name that curve's canonical signature algorithm.</summary>
    private static CryptoAlgorithm? EcdsaAlgorithmForOidAndCurve(string signatureAlgorithmOid, EllipticCurveTypes curve) => (signatureAlgorithmOid, curve) switch
    {
        (EcdsaWithSha256Oid, EllipticCurveTypes.P256) => CryptoAlgorithm.P256,
        (EcdsaWithSha384Oid, EllipticCurveTypes.P384) => CryptoAlgorithm.P384,
        (EcdsaWithSha512Oid, EllipticCurveTypes.P521) => CryptoAlgorithm.P521,
        _ => null
    };


    /// <summary>Verifies an RSASSA-PKCS1-v1_5 signature under SHA-256, SHA-384 or SHA-512 — the registered hash-parameterized RSA verification seam's profile — against the signer's RSA public key.</summary>
    private static async ValueTask<bool> VerifyRsaAsync(
        ReadOnlyMemory<byte> message, string signatureAlgorithmOid, ReadOnlyMemory<byte> signatureValue, ManagedCertificate signer, CancellationToken cancellationToken)
    {
        //An OCSP signature algorithm is the combined identifier naming both the hash and RSA (RFC 6960 §4.3
        //through RFC 5754 §3.2), so the bare rsaEncryption form the CMS layer also admits has no counterpart
        //here; an identifier outside the three combined forms fails closed.
        CryptoAlgorithm? algorithm = signatureAlgorithmOid switch
        {
            WellKnownOids.Sha256WithRsaEncryption => CryptoAlgorithm.RsaSha256,
            WellKnownOids.Sha384WithRsaEncryption => CryptoAlgorithm.RsaSha384,
            WellKnownOids.Sha512WithRsaEncryption => CryptoAlgorithm.RsaSha512,
            _ => (CryptoAlgorithm?)null
        };

        if(algorithm is null)
        {
            return false;
        }

        //The registered RSA verification seam hard-codes public exponent 65537 (RFC 8017) regardless of what a
        //certificate's own subjectPublicKey states, exactly as ManagedCmsVerification.VerifyRsaAsync documents;
        //a certificate declaring any other exponent must fail closed here rather than being verified against a
        //key it does not actually name.
        if(!signer.RsaExponent.Span.SequenceEqual(Exponent65537))
        {
            return false;
        }

        //The modulus is accepted by the same policy band ManagedCmsVerification.VerifyRsaAsync verifies under
        //rather than a 2048-/4096-bit whitelist: any non-degenerate RSA public key between the bounds, so a
        //3072-bit responder key is inside the band.
        if(!RsaUtilities.IsValidPublicKey(signer.RsaModulus.Span, signer.RsaExponent.Span, MinimumRsaModulusBitLength, MaximumRsaModulusBitLength))
        {
            return false;
        }

        VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm.Value, Purpose.Verification);
        (bool isVerified, CryptoEvent? evt) = await verify(message, signatureValue, signer.RsaModulus, null, cancellationToken).ConfigureAwait(false);
        CryptographicKeyEvents.Emit(evt);

        return isVerified;
    }


    /// <summary>
    /// Converts a DER <c>ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }</c> to the fixed-width
    /// <c>r ‖ s</c> form the verification seam expects, left-padding each coordinate to the field width.
    /// </summary>
    private static IMemoryOwner<byte> ConvertDerSignatureToFixedWidth(ReadOnlySpan<byte> derSignature, int fieldWidth, MemoryPool<byte> pool)
    {
        var reader = new AsnReader(derSignature.ToArray(), AsnEncodingRules.DER);
        AsnReader sequence = reader.ReadSequence();
        ReadOnlySpan<byte> r = StripLeadingZero(sequence.ReadIntegerBytes().Span);
        ReadOnlySpan<byte> s = StripLeadingZero(sequence.ReadIntegerBytes().Span);
        sequence.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();

        if(r.Length > fieldWidth || s.Length > fieldWidth)
        {
            throw new AsnContentException("An ECDSA signature's coordinates exceed the curve field width.");
        }

        IMemoryOwner<byte> owner = pool.Rent(fieldWidth * 2);
        try
        {
            Span<byte> span = owner.Memory.Span[..(fieldWidth * 2)];
            span.Clear();
            r.CopyTo(span[(fieldWidth - r.Length)..fieldWidth]);
            s.CopyTo(span[(fieldWidth * 2 - s.Length)..]);

            return owner;
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>Strips a single leading <c>0x00</c> sign octet from a DER INTEGER's two's-complement encoding.</summary>
    private static ReadOnlySpan<byte> StripLeadingZero(ReadOnlySpan<byte> integer) =>
        integer.Length > 1 && integer[0] == 0x00 ? integer[1..] : integer;


    /// <summary>
    /// A <c>CertID</c>'s decoded fields
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1">RFC 6960 §4.1.1</see>), for the
    /// request/response matching step (<see cref="CertIdFieldsMatch"/>).
    /// </summary>
    private readonly record struct CertIdFields(
        string HashAlgorithmOid,
        ReadOnlyMemory<byte> IssuerNameHash,
        ReadOnlyMemory<byte> IssuerKeyHash,
        ReadOnlyMemory<byte> SerialNumber);


    /// <summary>A parsed <c>SingleResponse</c>: its decoded <c>CertID</c> fields and the facts <see cref="OcspSingleResponseFacts"/> carries.</summary>
    private readonly record struct ParsedSingleResponse(
        CertIdFields CertId,
        OcspCertificateStatus Status,
        DateTimeOffset? RevocationTime,
        int? RevocationReason,
        DateTimeOffset ThisUpdate,
        DateTimeOffset? NextUpdate);


    /// <summary>A parsed <c>BasicOCSPResponse</c>.</summary>
    private readonly record struct ParsedBasicResponse(
        ReadOnlyMemory<byte> TbsResponseDataDer,
        ReadOnlyMemory<byte>? ResponderName,
        ReadOnlyMemory<byte>? ResponderKeyHash,
        IReadOnlyList<ParsedSingleResponse> SingleResponses,
        ReadOnlyMemory<byte>? NonceExtensionValue,
        string SignatureAlgorithmOid,
        ReadOnlyMemory<byte> SignatureValue,
        IReadOnlyList<ManagedCertificate> EmbeddedCertificates);
}
