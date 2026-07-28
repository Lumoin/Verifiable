using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// An online <see cref="CheckCertificateRevocationStatusAsyncDelegate"/> backed by RFC 6960 OCSP: it selects
/// the target certificate's issuer from the supplied candidates, reads the target's Authority Information
/// Access OCSP responder URIs (<see cref="RevocationSourceFactsExtractor"/>), builds and sends a request
/// (<see cref="OcspRequests"/>) through the caller-supplied <see cref="FetchOcspResponseAsyncDelegate"/>
/// transport, and verifies the response (<see cref="OcspResponseVerification"/>) fail-closed.
/// </summary>
/// <remarks>
/// <para>
/// This is the "revocation source" a caller configures and passes as the <c>checkRevocation</c> parameter of
/// <see cref="ValidateCertificateChainAsyncDelegate"/>, mirroring <c>CrlRevocationChecker</c>'s role for the
/// offline CRL source. Because it is a configured object holding the transport delegate and the request
/// options, the caller supplies its data explicitly at construction rather than a closure capturing it.
/// </para>
/// <para>
/// A responder is authoritative only when <see cref="OcspResponseVerification.VerifyAsync"/> reports
/// <see cref="OcspResponseVerificationOutcome.Verified"/>; the result is fail-closed exactly like
/// <c>CrlRevocationChecker</c>: <see cref="CertificateRevocationStatus.Revoked"/> as soon as any responder
/// reports it, <see cref="CertificateRevocationStatus.Good"/> only when a verified response affirmatively says
/// so, and <see cref="CertificateRevocationStatus.Unknown"/> when the issuer cannot be located, the target
/// carries no OCSP responder URI, every responder is unreachable, or no response verifies. Any non-<see
/// cref="OcspCertificateStatus.Revoked"/>, non-verified, or unreachable outcome for one responder URI moves on
/// to the next configured URI rather than failing the whole check — a single bad responder does not deny
/// revocation checking through a working one.
/// </para>
/// </remarks>
[DebuggerDisplay("OcspRevocationChecker(CertIdDigest={CertIdDigestAlgorithm})")]
public sealed class OcspRevocationChecker
{
    /// <summary>The transport delegate this checker sends requests through.</summary>
    private FetchOcspResponseAsyncDelegate FetchResponse { get; }

    /// <summary>The <c>CertID</c> hash algorithm requests are built with.</summary>
    private OcspCertIdDigestAlgorithm CertIdDigestAlgorithm { get; }

    /// <summary>The nonce length in octets for requests this checker builds.</summary>
    private int NonceByteLength { get; }

    /// <summary>Whether requests this checker builds carry a nonce.</summary>
    private bool IncludeNonce { get; }

    /// <summary>Whether a response without a <c>nextUpdate</c> is accepted.</summary>
    private bool AllowResponsesWithoutNextUpdate { get; }

    /// <summary>Whether a response without the request's nonce is accepted.</summary>
    private bool AllowResponsesWithoutNonce { get; }


    /// <summary>
    /// Initializes a new <see cref="OcspRevocationChecker"/> over a supplied transport.
    /// </summary>
    /// <param name="fetchResponse">The transport this checker sends requests through and reads responses from.</param>
    /// <param name="certIdDigestAlgorithm">The <c>CertID</c> hash algorithm requests are built with. Defaults to <see cref="OcspCertIdDigestAlgorithm.Sha256"/>, the sound default.</param>
    /// <param name="nonceByteLength">The nonce length in octets (RFC 9654 §2.1: <c>SIZE(1..128)</c>). Defaults to 32.</param>
    /// <param name="includeNonce">Whether requests carry a nonce. Defaults to <see langword="true"/>.</param>
    /// <param name="allowResponsesWithoutNextUpdate">Whether a response without <c>nextUpdate</c> is accepted. Secure default is <see langword="false"/>.</param>
    /// <param name="allowResponsesWithoutNonce">Whether a response without the request's nonce is accepted. Secure default is <see langword="false"/>.</param>
    public OcspRevocationChecker(
        FetchOcspResponseAsyncDelegate fetchResponse,
        OcspCertIdDigestAlgorithm certIdDigestAlgorithm = OcspCertIdDigestAlgorithm.Sha256,
        int nonceByteLength = 32,
        bool includeNonce = true,
        bool allowResponsesWithoutNextUpdate = false,
        bool allowResponsesWithoutNonce = false)
    {
        ArgumentNullException.ThrowIfNull(fetchResponse);

        FetchResponse = fetchResponse;
        CertIdDigestAlgorithm = certIdDigestAlgorithm;
        NonceByteLength = nonceByteLength;
        IncludeNonce = includeNonce;
        AllowResponsesWithoutNextUpdate = allowResponsesWithoutNextUpdate;
        AllowResponsesWithoutNonce = allowResponsesWithoutNonce;
    }


    /// <summary>
    /// Implements <see cref="CheckCertificateRevocationStatusAsyncDelegate"/>. Reports <paramref name="certificate"/>'s
    /// revocation status via OCSP, fail-closed.
    /// </summary>
    /// <param name="certificate">The certificate whose revocation status is being determined.</param>
    /// <param name="issuerCandidates">The certificates that may be <paramref name="certificate"/>'s issuer.</param>
    /// <param name="validationTime">The instant at which a response's validity window is evaluated.</param>
    /// <param name="pool">The memory pool for every allocation this call performs.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The certificate's <see cref="CertificateRevocationStatus"/>.</returns>
    public async ValueTask<CertificateRevocationStatus> CheckAsync(
        PkiCertificateMemory certificate,
        IReadOnlyList<PkiCertificateMemory> issuerCandidates,
        DateTimeOffset validationTime,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(issuerCandidates);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            PkiCertificateMemory? issuer = SelectIssuer(certificate, issuerCandidates);
            if(issuer is null)
            {
                return CertificateRevocationStatus.Unknown;
            }

            RevocationSourceFacts facts = RevocationSourceFactsExtractor.Extract(certificate);
            if(facts.OcspResponderUris.Count == 0)
            {
                return CertificateRevocationStatus.Unknown;
            }

            foreach(string responderUri in facts.OcspResponderUris)
            {
                CertificateRevocationStatus? status = await CheckAgainstResponderAsync(
                    certificate, issuer, responderUri, validationTime, pool, cancellationToken).ConfigureAwait(false);
                if(status == CertificateRevocationStatus.Revoked)
                {
                    return CertificateRevocationStatus.Revoked;
                }

                if(status == CertificateRevocationStatus.Good)
                {
                    return CertificateRevocationStatus.Good;
                }

                //Unreachable responder, an unverified response, or an affirmed-Unknown status: try the next URI.
            }

            return CertificateRevocationStatus.Unknown;
        }
        catch(AsnContentException)
        {
            //A malformed target or issuer candidate cannot be checked; fail closed rather than throw a parsing
            //exception out of a revocation-status seam.
            return CertificateRevocationStatus.Unknown;
        }
        catch(InvalidOperationException)
        {
            //A byKey responderID needs the SHA-1 digest seam (CryptographicKeyEvents.ComputeDigest under the
            //SHA1 qualifier) to compare against the candidate's key hash; a composition that never registered
            //it cannot resolve that comparison. CheckCertificateRevocationStatusAsyncDelegate's contract is to
            //return a status rather than throw, so a missing registration fails closed to Unknown exactly like
            //an unreachable responder, rather than escaping as a raw registry exception.
            return CertificateRevocationStatus.Unknown;
        }
    }


    /// <summary>
    /// Builds a request for one responder URI, sends it, and verifies the response, disposing every carrier
    /// this call creates.
    /// </summary>
    /// <returns>
    /// <see cref="CertificateRevocationStatus.Good"/> or <see cref="CertificateRevocationStatus.Revoked"/> when
    /// the response verifies with that status; otherwise <see langword="null"/> (unreachable responder, an
    /// unverified response, or an affirmed <see cref="OcspCertificateStatus.Unknown"/> status), signalling the
    /// caller to try the next configured responder URI.
    /// </returns>
    private async ValueTask<CertificateRevocationStatus?> CheckAgainstResponderAsync(
        PkiCertificateMemory certificate, PkiCertificateMemory issuer, string responderUri, DateTimeOffset validationTime, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using OcspRequestContent request = OcspRequests.Create(certificate, issuer, CertIdDigestAlgorithm, pool, NonceByteLength, IncludeNonce);
        var fetchContext = new OcspFetchContext { ResponderUri = responderUri, Request = request.Request };

        PkiCertificateMemory? response = await FetchResponse(fetchContext, pool, cancellationToken).ConfigureAwait(false);
        if(response is null)
        {
            return null;
        }

        using(response)
        {
            OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
                response, request, issuer, validationTime, pool, AllowResponsesWithoutNextUpdate, AllowResponsesWithoutNonce, cancellationToken).ConfigureAwait(false);

            if(result.Outcome != OcspResponseVerificationOutcome.Verified)
            {
                return null;
            }

            //An affirmed Unknown status (the discard arm) yields null so the caller tries the next responder.
            return result.Single!.Status switch
            {
                OcspCertificateStatus.Good => CertificateRevocationStatus.Good,
                OcspCertificateStatus.Revoked => CertificateRevocationStatus.Revoked,
                _ => (CertificateRevocationStatus?)null
            };
        }
    }


    /// <summary>
    /// Selects the candidate whose subject Name DER-equals <paramref name="certificate"/>'s issuer Name, or
    /// <see langword="null"/> when none does.
    /// </summary>
    private static PkiCertificateMemory? SelectIssuer(PkiCertificateMemory certificate, IReadOnlyList<PkiCertificateMemory> issuerCandidates)
    {
        ReadOnlyMemory<byte> targetIssuerNameDer = ReadIssuerNameDer(certificate);
        foreach(PkiCertificateMemory candidate in issuerCandidates)
        {
            if(!candidate.IsX509Certificate)
            {
                continue;
            }

            ReadOnlyMemory<byte> candidateSubjectNameDer = ReadSubjectNameDer(candidate);
            if(candidateSubjectNameDer.Span.SequenceEqual(targetIssuerNameDer.Span))
            {
                return candidate;
            }
        }

        return null;
    }


    /// <summary>Reads a certificate's <c>issuer</c> Name, full encoded value.</summary>
    private static ReadOnlyMemory<byte> ReadIssuerNameDer(PkiCertificateMemory certificate)
    {
        AsnReader tbs = ReadTbsCertificate(certificate);
        SkipToName(tbs);

        return tbs.ReadEncodedValue();
    }


    /// <summary>Reads a certificate's <c>subject</c> Name, full encoded value.</summary>
    private static ReadOnlyMemory<byte> ReadSubjectNameDer(PkiCertificateMemory certificate)
    {
        AsnReader tbs = ReadTbsCertificate(certificate);
        SkipToName(tbs);
        _ = tbs.ReadEncodedValue();                                    //issuer Name.
        _ = tbs.ReadSequence();                                        //validity.

        return tbs.ReadEncodedValue();                                 //subject Name.
    }


    /// <summary>Positions a reader at the start of <c>tbsCertificate</c>'s content.</summary>
    private static AsnReader ReadTbsCertificate(PkiCertificateMemory certificate)
    {
        var reader = new AsnReader(certificate.AsReadOnlyMemory(), AsnEncodingRules.DER);

        return reader.ReadSequence().ReadSequence();
    }


    /// <summary>Skips <c>version</c>, <c>serialNumber</c>, and <c>signature</c> so the reader sits at the <c>issuer</c> Name.</summary>
    private static void SkipToName(AsnReader tbs)
    {
        if(tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            _ = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        }

        _ = tbs.ReadIntegerBytes();                                    //serialNumber.
        _ = tbs.ReadSequence();                                        //signature AlgorithmIdentifier.
    }
}
