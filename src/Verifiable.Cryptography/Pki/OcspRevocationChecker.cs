using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The outcome of a revocation check that kept the response it decided from: the status, and — when a
/// responder's answer verified — the DER-encoded <c>OCSPResponse</c> those octets are.
/// </summary>
/// <remarks>
/// <para>
/// Placing validation material into a signature needs the response itself, not only what it said: ETSI EN 319
/// 122-1 Table 1 requirement o) has a generator include "the full set of revocation data ... used in the
/// validation of the signature", and clause 5.4.2.2 places an OCSP response into <c>SignedData.crls.other</c>
/// as octets. A checker that answers only Good, Revoked, or Unknown cannot supply them, which is why this
/// carrier exists beside <see cref="OcspRevocationChecker.CheckAsync"/>'s status-only contract.
/// </para>
/// <para>
/// <see cref="Response"/> is <see langword="null"/> whenever no responder's answer verified — an unreachable
/// responder, a response that failed the RFC 6960 §3.2 checks, or a certificate carrying no responder URI —
/// which is every case in which <see cref="Status"/> is <see cref="CertificateRevocationStatus.Unknown"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("RetainedOcspResponse({Status}, {Response is null ? \"no response\" : \"response retained\",nq})")]
public sealed class RetainedOcspResponse: IDisposable
{
    /// <summary>Gets the certificate's revocation status.</summary>
    public CertificateRevocationStatus Status { get; }

    /// <summary>Gets the verified response the status was decided from, or <see langword="null"/> when none verified.</summary>
    public PkiCertificateMemory? Response { get; }


    /// <summary>
    /// Initializes a new <see cref="RetainedOcspResponse"/>. Ownership of a non-<see langword="null"/> response
    /// transfers to this instance.
    /// </summary>
    /// <param name="status">The certificate's revocation status.</param>
    /// <param name="response">The verified response, or <see langword="null"/>.</param>
    public RetainedOcspResponse(CertificateRevocationStatus status, PkiCertificateMemory? response)
    {
        Status = status;
        Response = response;
    }


    /// <inheritdoc/>
    public void Dispose() => Response?.Dispose();
}


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
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        using RetainedOcspResponse retained = await CheckRetainingResponseAsync(
            certificate, issuerCandidates, validationTime, pool, cancellationToken).ConfigureAwait(false);

        return retained.Status;
    }


    /// <summary>
    /// Performs exactly the check <see cref="CheckAsync"/> performs and keeps the verified response the status
    /// was decided from, for a caller that has to place those octets into a signature as long-term validation
    /// material (ETSI EN 319 122-1 Table 1 requirement o, clause 5.4.2.2).
    /// </summary>
    /// <param name="certificate">The certificate whose revocation status is being determined.</param>
    /// <param name="issuerCandidates">The certificates that may be <paramref name="certificate"/>'s issuer.</param>
    /// <param name="validationTime">The instant at which a response's validity window is evaluated.</param>
    /// <param name="pool">The memory pool for every allocation this call performs.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The status and, when one verified, the response. The caller owns and disposes the result.</returns>
    /// <remarks>
    /// This is the same walk over the same responders with the same fail-closed rules — <see cref="CheckAsync"/>
    /// is this method with the response dropped — so a caller collecting material and a caller deciding a chain
    /// never see two different answers.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the retained response transfers to the returned result, which the caller disposes.")]
    public async ValueTask<RetainedOcspResponse> CheckRetainingResponseAsync(
        PkiCertificateMemory certificate,
        IReadOnlyList<PkiCertificateMemory> issuerCandidates,
        DateTimeOffset validationTime,
        BaseMemoryPool pool,
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
                return Undetermined();
            }

            RevocationSourceFacts facts = RevocationSourceFactsExtractor.Extract(certificate);
            if(facts.OcspResponderUris.Count == 0)
            {
                return Undetermined();
            }

            foreach(string responderUri in facts.OcspResponderUris)
            {
                RetainedOcspResponse answer = await CheckAgainstResponderAsync(
                    certificate, issuer, responderUri, validationTime, pool, cancellationToken).ConfigureAwait(false);
                if(answer.Status is CertificateRevocationStatus.Revoked or CertificateRevocationStatus.Good)
                {
                    return answer;
                }

                //Unreachable responder, an unverified response, or an affirmed-Unknown status: try the next URI.
                answer.Dispose();
            }

            return Undetermined();
        }
        catch(AsnContentException)
        {
            //A malformed target or issuer candidate cannot be checked; fail closed rather than throw a parsing
            //exception out of a revocation-status seam.
            return Undetermined();
        }
        catch(InvalidOperationException)
        {
            //A byKey responderID needs the registered async digest seam (CryptographicKeyEvents.ComputeDigestAsync's
            //default ComputeDigestDelegate, dispatched by the SHA-1 Tag — see OcspResponseVerification's
            //Sha1DigestTag remarks) to compare against the candidate's key hash; a composition that never
            //registered a default ComputeDigestDelegate cannot resolve that comparison.
            //CheckCertificateRevocationStatusAsyncDelegate's contract is to return a status rather than throw,
            //so a missing registration fails closed to Unknown exactly like an unreachable responder, rather
            //than escaping as a raw registry exception.
            return Undetermined();
        }

        //Builds the outcome of every path that decided nothing, so no branch has to repeat the absent response.
        static RetainedOcspResponse Undetermined() => new(CertificateRevocationStatus.Unknown, response: null);
    }


    /// <summary>
    /// Builds a request for one responder URI, sends it, and verifies the response, keeping the response when
    /// it verified with a status and disposing every carrier this call created otherwise.
    /// </summary>
    /// <param name="certificate">The certificate whose revocation status is being determined.</param>
    /// <param name="issuer">The certificate's issuer.</param>
    /// <param name="responderUri">The responder to contact.</param>
    /// <param name="validationTime">The instant at which the response's validity window is evaluated.</param>
    /// <param name="pool">The memory pool for every allocation this call performs.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// <see cref="CertificateRevocationStatus.Good"/> or <see cref="CertificateRevocationStatus.Revoked"/> with
    /// the verified response when the response verifies with that status; otherwise
    /// <see cref="CertificateRevocationStatus.Unknown"/> with no response (unreachable responder, an unverified
    /// response, or an affirmed <see cref="OcspCertificateStatus.Unknown"/> status), signalling the caller to
    /// try the next configured responder URI.
    /// </returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the fetched response transfers to the returned result on the verified path; every other path disposes it here.")]
    private async ValueTask<RetainedOcspResponse> CheckAgainstResponderAsync(
        PkiCertificateMemory certificate, PkiCertificateMemory issuer, string responderUri, DateTimeOffset validationTime, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using OcspRequestContent request = await OcspRequests.CreateAsync(certificate, issuer, CertIdDigestAlgorithm, pool, NonceByteLength, IncludeNonce, cancellationToken).ConfigureAwait(false);
        var fetchContext = new OcspFetchContext { ResponderUri = responderUri, Request = request.Request };

        PkiCertificateMemory? response = await FetchResponse(fetchContext, pool, cancellationToken).ConfigureAwait(false);
        if(response is null)
        {
            return new RetainedOcspResponse(CertificateRevocationStatus.Unknown, response: null);
        }

        bool retained = false;
        try
        {
            OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
                response, request, issuer, validationTime, pool, AllowResponsesWithoutNextUpdate, AllowResponsesWithoutNonce, cancellationToken).ConfigureAwait(false);

            if(result.Outcome != OcspResponseVerificationOutcome.Verified)
            {
                return new RetainedOcspResponse(CertificateRevocationStatus.Unknown, response: null);
            }

            //An affirmed Unknown status (the discard arm) keeps nothing, so the caller tries the next responder.
            CertificateRevocationStatus status = result.Single!.Status switch
            {
                OcspCertificateStatus.Good => CertificateRevocationStatus.Good,
                OcspCertificateStatus.Revoked => CertificateRevocationStatus.Revoked,
                _ => CertificateRevocationStatus.Unknown
            };
            if(status == CertificateRevocationStatus.Unknown)
            {
                return new RetainedOcspResponse(CertificateRevocationStatus.Unknown, response: null);
            }

            retained = true;

            return new RetainedOcspResponse(status, response);
        }
        finally
        {
            if(!retained)
            {
                response.Dispose();
            }
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
