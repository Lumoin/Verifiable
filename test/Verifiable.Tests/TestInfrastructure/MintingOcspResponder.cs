using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A <see cref="FetchOcspResponseAsyncDelegate"/> test double that answers like an OCSP responder over a small,
/// configured certificate database: it decodes the <c>OCSPRequest</c> it is handed for the target
/// <c>CertID.serialNumber</c> and the optional <c>id-pkix-ocsp-nonce</c> extension
/// (<see href="https://www.rfc-editor.org/rfc/rfc9654#section-2.1">RFC 9654 §2.1</see>), matches the serial
/// number against <see cref="Subjects"/>, and mints a genuine <c>BasicOCSPResponse</c>-carrying
/// <c>OCSPResponse</c> through the independent BouncyCastle OCSP oracle
/// (<see cref="OcspTestFixtures.MintOcspResponse"/>), echoing the request's nonce when it carried one. The RFC
/// 3161 sibling is <see cref="MintingTimestampResponder"/>.
/// </summary>
/// <remarks>
/// <para>
/// The decode is written here from the request syntax
/// (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1">RFC 6960 §4.1.1</see>) rather than reusing
/// <see cref="OcspRequests.CreateAsync"/>'s writer — what this responder answers is a fact about the octets that
/// crossed the seam, not about the object the library built.
/// </para>
/// <para>
/// A caller checking the certificate chain of a CAdES signature's own signer AND the chain of a time-stamp
/// token's own signer needs status for TWO distinct certificates against the same responder — this is why
/// <see cref="Subjects"/> is a list matched by serial number, not a single fixed target: one Kestrel-hosted
/// responder answers for every certificate the caller's Authority Information Access extensions point at it.
/// </para>
/// <para>
/// A configured object, not a closure over test state, mirroring <see cref="MintingTimestampResponder"/>.
/// </para>
/// </remarks>
internal sealed class MintingOcspResponder
{
    /// <summary>The certificates this responder can answer about, matched by <c>CertID.serialNumber</c>.</summary>
    private IReadOnlyList<X509Certificate2> Subjects { get; }

    /// <summary>Every subject's issuer — the shared <c>CertID</c> hash input.</summary>
    private X509Certificate2 Issuer { get; }

    /// <summary>The certificate whose key signs the response.</summary>
    private X509Certificate2 SignerCertificate { get; }

    /// <summary>The signer's private key.</summary>
    private ECDsa SignerKey { get; }

    /// <summary>The <c>CertStatus</c> every minted response reports.</summary>
    private OcspCertificateStatus Status { get; }

    /// <summary>The <c>thisUpdate</c> every minted response states.</summary>
    private DateTimeOffset ThisUpdate { get; }

    /// <summary>The <c>nextUpdate</c> every minted response states.</summary>
    private DateTimeOffset NextUpdate { get; }

    /// <summary>The revocation instant a <see cref="OcspCertificateStatus.Revoked"/> response states, or <see langword="null"/>.</summary>
    private DateTimeOffset? RevocationTime { get; }

    /// <summary>The <c>CRLReason</c> a <see cref="OcspCertificateStatus.Revoked"/> response states, or <see langword="null"/>.</summary>
    private int? RevocationReason { get; }


    /// <summary>
    /// Initializes a new <see cref="MintingOcspResponder"/>.
    /// </summary>
    /// <param name="subjects">The certificates this responder can answer about, all issued by <paramref name="issuer"/>.</param>
    /// <param name="issuer">Every subject's issuer.</param>
    /// <param name="signerCertificate">The certificate whose key signs the response — the issuer itself for a direct response.</param>
    /// <param name="signerKey">The signer's private key.</param>
    /// <param name="status">The <c>CertStatus</c> to report.</param>
    /// <param name="thisUpdate">The <c>thisUpdate</c> instant.</param>
    /// <param name="nextUpdate">The <c>nextUpdate</c> instant.</param>
    /// <param name="revocationTime">The revocation instant, required when <paramref name="status"/> is <see cref="OcspCertificateStatus.Revoked"/>.</param>
    /// <param name="revocationReason">The optional <c>CRLReason</c> value.</param>
    internal MintingOcspResponder(
        IReadOnlyList<X509Certificate2> subjects,
        X509Certificate2 issuer,
        X509Certificate2 signerCertificate,
        ECDsa signerKey,
        OcspCertificateStatus status,
        DateTimeOffset thisUpdate,
        DateTimeOffset nextUpdate,
        DateTimeOffset? revocationTime = null,
        int? revocationReason = null)
    {
        ArgumentNullException.ThrowIfNull(subjects);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(signerCertificate);
        ArgumentNullException.ThrowIfNull(signerKey);

        Subjects = subjects;
        Issuer = issuer;
        SignerCertificate = signerCertificate;
        SignerKey = signerKey;
        Status = status;
        ThisUpdate = thisUpdate;
        NextUpdate = nextUpdate;
        RevocationTime = revocationTime;
        RevocationReason = revocationReason;
    }


    /// <summary>
    /// Implements <see cref="FetchOcspResponseAsyncDelegate"/>: matches the request's <c>CertID.serialNumber</c>
    /// against <see cref="Subjects"/> and mints a response for the match, echoing the request's nonce when it
    /// carried one.
    /// </summary>
    /// <param name="context">The responder address and the request octets.</param>
    /// <param name="pool">The memory pool the returned response is rented from.</param>
    /// <param name="cancellationToken">A cancellation token; unused, as this double performs no input or output.</param>
    /// <returns>The response, or <see langword="null"/> when the request names no configured subject.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the response carrier transfers to the caller via the returned ValueTask.")]
    internal ValueTask<PkiCertificateMemory?> FetchAsync(OcspFetchContext context, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);

        (byte[] requestedSerialNumber, Nonce? echoNonce) = ReadRequest(context.Request.AsReadOnlyMemory(), pool);
        using(echoNonce)
        {
            X509Certificate2? subject = null;
            for(int i = 0; i < Subjects.Count; ++i)
            {
                if(SerialNumberMatches(Subjects[i], requestedSerialNumber))
                {
                    subject = Subjects[i];
                    break;
                }
            }

            if(subject is null)
            {
                return ValueTask.FromResult<PkiCertificateMemory?>(null);
            }

            PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
                subject, Issuer, OcspCertIdDigestAlgorithm.Sha256, SignerCertificate, SignerKey,
                responderIdByKey: false, embeddedCertificates: [Issuer],
                Status, ThisUpdate, NextUpdate, RevocationTime, RevocationReason, echoNonce);

            return ValueTask.FromResult<PkiCertificateMemory?>(response);
        }
    }


    /// <summary>
    /// Decodes the <c>CertID.serialNumber</c> of an <c>OCSPRequest</c>'s single <c>Request</c> entry (the shape
    /// <see cref="OcspRequests.CreateAsync"/> always writes: one target, no <c>requestorName</c>) and its
    /// optional <c>id-pkix-ocsp-nonce</c> <c>requestExtensions</c> entry
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1">RFC 6960 §4.1.1</see>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9654#section-2.1">RFC 9654 §2.1</see>).
    /// </summary>
    /// <param name="request">The DER-encoded <c>OCSPRequest</c>.</param>
    /// <param name="pool">The memory pool the nonce's bytes are rented from.</param>
    /// <returns>The requested serial number's content octets, and the nonce this request carried (or <see langword="null"/> when it carried none).</returns>
    private static (byte[] SerialNumber, Nonce? Nonce) ReadRequest(ReadOnlyMemory<byte> request, MemoryPool<byte> pool)
    {
        var outer = new AsnReader(request, AsnEncodingRules.DER);
        AsnReader ocspRequest = outer.ReadSequence();

        AsnReader tbsRequest = ocspRequest.ReadSequence();

        //version [0] EXPLICIT Version DEFAULT v1 — never written by OcspRequests.CreateAsync, skipped if present.
        if(tbsRequest.HasData && tbsRequest.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            _ = tbsRequest.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        }

        //requestorName [1] EXPLICIT GeneralName OPTIONAL — never written by OcspRequests.CreateAsync, skipped if present.
        if(tbsRequest.HasData && tbsRequest.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))
        {
            _ = tbsRequest.ReadEncodedValue();
        }

        AsnReader requestList = tbsRequest.ReadSequence();                //requestList SEQUENCE OF Request.
        AsnReader singleRequest = requestList.ReadSequence();              //Request ::= SEQUENCE { reqCert CertID, singleRequestExtensions [0] OPTIONAL }.
        AsnReader certId = singleRequest.ReadSequence();                   //CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }.
        _ = certId.ReadSequence();                                         //hashAlgorithm AlgorithmIdentifier.
        _ = certId.ReadOctetString();                                      //issuerNameHash — not needed, this responder matches by serialNumber alone.
        _ = certId.ReadOctetString();                                      //issuerKeyHash.
        byte[] serialNumber = certId.ReadIntegerBytes().ToArray();

        Nonce? nonce = null;
        if(tbsRequest.HasData && tbsRequest.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 2, isConstructed: true))
        {
            AsnReader requestExtensionsWrapper = tbsRequest.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            AsnReader extensions = requestExtensionsWrapper.ReadSequence();
            while(extensions.HasData)
            {
                AsnReader extension = extensions.ReadSequence();
                string extnId = extension.ReadObjectIdentifier();
                if(extension.HasData && extension.PeekTag() == Asn1Tag.Boolean)
                {
                    _ = extension.ReadBoolean();                          //critical DEFAULT FALSE.
                }

                byte[] extnValue = extension.ReadOctetString();
                if(!string.Equals(extnId, WellKnownOids.OcspNonce, StringComparison.Ordinal))
                {
                    continue;
                }

                var nonceReader = new AsnReader(extnValue, AsnEncodingRules.DER);
                byte[] nonceBytes = nonceReader.ReadOctetString();        //Nonce ::= OCTET STRING.

                IMemoryOwner<byte> owner = pool.Rent(nonceBytes.Length);
                nonceBytes.CopyTo(owner.Memory.Span);
                nonce = new Nonce(owner, Tag.Create(Purpose.Nonce));
            }
        }

        return (serialNumber, nonce);
    }


    /// <summary>Whether a certificate's own DER <c>serialNumber</c> content octets equal a requested value.</summary>
    /// <param name="candidate">The candidate certificate.</param>
    /// <param name="requestedSerialNumber">The <c>CertID.serialNumber</c> content octets a request carried.</param>
    private static bool SerialNumberMatches(X509Certificate2 candidate, ReadOnlySpan<byte> requestedSerialNumber)
    {
        var reader = new AsnReader(candidate.RawData, AsnEncodingRules.DER);
        AsnReader certificateSequence = reader.ReadSequence();
        AsnReader tbs = certificateSequence.ReadSequence();

        //version [0] EXPLICIT INTEGER DEFAULT v1 (RFC 5280 §4.1.2.1), present in practically every certificate.
        if(tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            _ = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        }

        ReadOnlyMemory<byte> serialNumber = tbs.ReadIntegerBytes();

        return serialNumber.Span.SequenceEqual(requestedSerialNumber);
    }
}
