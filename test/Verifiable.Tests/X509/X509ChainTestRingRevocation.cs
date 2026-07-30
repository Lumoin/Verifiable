using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.X509;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;
using PkiAlgorithmIdentifier = Verifiable.Cryptography.Pki.AlgorithmIdentifier;

namespace Verifiable.Tests.X509;

/// <summary>
/// Mints dated revocation material for the nodes of an <see cref="X509ChainTestRing"/> chain: Certificate
/// Revocation Lists (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-5">RFC 5280 §5</see>) whose
/// <c>thisUpdate</c>, <c>nextUpdate</c> and per-entry revocation instants a caller places wherever a timeline
/// needs them, and OCSP responses (<see href="https://www.rfc-editor.org/rfc/rfc6960">RFC 6960</see>) bound to
/// the same nodes.
/// </summary>
/// <remarks>
/// <para>
/// The CRL encoder and signer are the independent BouncyCastle <see cref="X509V2CrlGenerator"/> and
/// <see cref="Asn1SignatureFactory"/> — a DER writer and an ECDSA signer distinct from every reader under test —
/// and the OCSP responses come from <see cref="OcspTestFixtures.MintOcspResponse"/>, which is the same
/// independent-oracle arrangement one step further along. Nothing here re-implements a check: where a fact about
/// minted material is needed as a validation input, it is read back through a shipped library method
/// (<see cref="CrlRevocationChecker"/>, <see cref="OcspResponseVerification"/>) rather than asserted from the
/// minting parameters alone.
/// </para>
/// <para>
/// Every instant a caller passes is expected to be derived from <see cref="TestClock.CanonicalEpoch"/>; nothing
/// here reads a clock.
/// </para>
/// </remarks>
internal static class X509ChainTestRingRevocation
{
    /// <summary>
    /// The <c>CRLReason</c> value <c>keyCompromise</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1">RFC 5280 §5.3.1</see>), the reason the
    /// validation examples of ETSI EN 319 102-1 Annex A assume for a compromising event.
    /// </summary>
    internal const int KeyCompromiseReason = 1;


    /// <summary>
    /// One entry of a minted Certificate Revocation List: the ring node whose certificate is revoked, the
    /// instant the revocation took effect and the <c>CRLReason</c> stated for it.
    /// </summary>
    /// <param name="Certificate">The revoked node; only its certificate's serial number reaches the list.</param>
    /// <param name="RevocationTime">The <c>revocationDate</c> of the entry.</param>
    /// <param name="Reason">The RFC 5280 §5.3.1 <c>CRLReason</c> value.</param>
    internal sealed record RevokedCertificateEntry(
        X509ChainTestRingNode Certificate,
        DateTimeOffset RevocationTime,
        int Reason = KeyCompromiseReason);


    /// <summary>
    /// Mints a Certificate Revocation List issued by <paramref name="issuer"/> over the supplied entries.
    /// </summary>
    /// <param name="issuer">The node whose key signs the list; its subject name becomes the list's issuer name.</param>
    /// <param name="thisUpdate">The <c>thisUpdate</c> instant — when the issuer states the list was produced.</param>
    /// <param name="nextUpdate">The <c>nextUpdate</c> instant; a list without one is never authoritative for the shipped checker, so it is required here.</param>
    /// <param name="revokedCertificates">The entries, in list order; an empty list mints a clean CRL.</param>
    /// <param name="deltaCrlIndicatorBaseNumber">The <c>BaseCRLNumber</c> a Delta CRL states (RFC 5280 §5.2.4); <see langword="null"/> mints a complete list.</param>
    /// <returns>The pooled DER-encoded list, tagged <see cref="PkiCertificateTags.X509Crl"/>; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    internal static PkiCertificateMemory MintCertificateRevocationList(
        X509ChainTestRingNode issuer,
        DateTimeOffset thisUpdate,
        DateTimeOffset nextUpdate,
        IReadOnlyList<RevokedCertificateEntry> revokedCertificates,
        int? deltaCrlIndicatorBaseNumber = null)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(revokedCertificates);

        BcX509Certificate bcIssuer = OcspTestFixtures.ToBouncyCastleCertificate(issuer.Certificate);
        AsymmetricKeyParameter issuerPrivateKey = OcspTestFixtures.ToBouncyCastlePrivateKey(issuer.SigningKey);

        var generator = new X509V2CrlGenerator();
        generator.SetIssuerDN(bcIssuer.SubjectDN);
        generator.SetThisUpdate(thisUpdate.UtcDateTime);
        generator.SetNextUpdate(nextUpdate.UtcDateTime);

        for(int i = 0; i < revokedCertificates.Count; ++i)
        {
            RevokedCertificateEntry entry = revokedCertificates[i];
            BcX509Certificate revoked = OcspTestFixtures.ToBouncyCastleCertificate(entry.Certificate.Certificate);
            generator.AddCrlEntry(revoked.SerialNumber, entry.RevocationTime.UtcDateTime, entry.Reason);
        }

        //RFC 5280 §5.2.3: a conforming CRL issuer includes a monotonically increasing CRL number. The draw goes
        //through the entropy seam the ring already uses for serial numbers, so it carries the same provenance;
        //monotonicity across a fixture's lists is not asserted by any reader this suite exercises.
        using Salt crlNumber = X509ChainTestRing.CreateSerialNumber();
        generator.AddExtension(X509Extensions.CrlNumber, critical: false, new CrlNumber(ToPositiveInteger(crlNumber)));

        if(deltaCrlIndicatorBaseNumber is int baseNumber)
        {
            //RFC 5280 §5.2.4: the deltaCRLIndicator is a critical extension whose value is the BaseCRLNumber the
            //delta is computed against. Its presence is what makes a list a Delta CRL to any reader.
            generator.AddExtension(X509Extensions.DeltaCrlIndicator, critical: true, new CrlNumber(BcBigInteger.ValueOf(baseNumber)));
        }

        X509Crl crl = generator.Generate(new Asn1SignatureFactory(X509ChainTestRing.EcdsaWithSha256SignatureName, issuerPrivateKey));

        return ToRevocationListCarrier(crl.GetEncoded());
    }


    /// <summary>
    /// Mints an OCSP response about <paramref name="subject"/>, signed directly by its issuer, through the
    /// independent OCSP oracle of <see cref="OcspTestFixtures"/>.
    /// </summary>
    /// <param name="subject">The node the single response answers for.</param>
    /// <param name="issuer">The subject's issuer — the <c>CertID</c> hash input and the direct signer.</param>
    /// <param name="status">The <c>CertStatus</c> to report.</param>
    /// <param name="thisUpdate">The <c>thisUpdate</c> instant.</param>
    /// <param name="nextUpdate">The <c>nextUpdate</c> instant.</param>
    /// <param name="revocationTime">The revocation instant, required when <paramref name="status"/> is <see cref="OcspCertificateStatus.Revoked"/>.</param>
    /// <param name="revocationReason">The RFC 5280 §5.3.1 <c>CRLReason</c> value, when one is stated.</param>
    /// <param name="echoNonce">The nonce of the request this response answers, when the request carried one.</param>
    /// <returns>The pooled DER-encoded response, tagged <see cref="PkiCertificateTags.OcspResponse"/>; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    internal static PkiCertificateMemory MintOcspResponse(
        X509ChainTestRingNode subject,
        X509ChainTestRingNode issuer,
        OcspCertificateStatus status,
        DateTimeOffset thisUpdate,
        DateTimeOffset nextUpdate,
        DateTimeOffset? revocationTime = null,
        int? revocationReason = null,
        Nonce? echoNonce = null)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(issuer);

        return OcspTestFixtures.MintOcspResponse(
            subject.Certificate,
            issuer.Certificate,
            OcspCertIdDigestAlgorithm.Sha256,
            issuer.Certificate,
            issuer.SigningKey,
            responderIdByKey: false,
            embeddedCertificates: [issuer.Certificate],
            status,
            thisUpdate,
            nextUpdate,
            revocationTime,
            revocationReason,
            echoNonce);
    }


    /// <summary>
    /// Builds the request an OCSP response about <paramref name="subject"/> answers, through the shipped
    /// <see cref="OcspRequests"/> writer, so a caller can round-trip a minted response through the shipped
    /// <see cref="OcspResponseVerification"/> reader.
    /// </summary>
    /// <param name="subject">The node the request asks about.</param>
    /// <param name="issuer">The subject's issuer.</param>
    /// <param name="pool">The memory pool the request is rented from.</param>
    /// <param name="includeNonce">Whether the request carries a nonce, which the response then has to echo.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The request; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    internal static async ValueTask<OcspRequestContent> CreateOcspRequestAsync(
        X509ChainTestRingNode subject,
        X509ChainTestRingNode issuer,
        MemoryPool<byte> pool,
        bool includeNonce = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(pool);

        using PkiCertificateMemory subjectCarrier = OcspTestFixtures.ToCertificateCarrier(subject.Certificate);
        using PkiCertificateMemory issuerCarrier = OcspTestFixtures.ToCertificateCarrier(issuer.Certificate);

        return await OcspRequests.CreateAsync(
            subjectCarrier, issuerCarrier, OcspCertIdDigestAlgorithm.Sha256, pool,
            includeNonce: includeNonce, cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Describes a minted Certificate Revocation List as the neutral
    /// <see cref="RevocationStatusInformation"/> the validation algorithm of ETSI EN 319 102-1 reasons over —
    /// the facts NOTE 7 of its clause 5.2.6.4 assumes a Driving Application supplies.
    /// </summary>
    /// <remarks>
    /// The status itself is not asserted from the minting parameters: it is read back out of the DER by the
    /// shipped <see cref="CrlRevocationChecker"/>, so a description can never disagree with the bytes it
    /// describes. The revocation instant and reason are the caller's, because that checker's three-valued
    /// contract does not surface them.
    /// </remarks>
    /// <param name="certificateRevocationList">The minted list; referenced, not owned.</param>
    /// <param name="subject">The node the status is about.</param>
    /// <param name="issuer">The node that issued both the subject's certificate and the list.</param>
    /// <param name="validationTime">The instant the list's own validity window is judged at.</param>
    /// <param name="thisUpdate">The list's <c>thisUpdate</c>.</param>
    /// <param name="nextUpdate">The list's <c>nextUpdate</c>.</param>
    /// <param name="revocationTime">The instant the subject's certificate was revoked, when it is listed.</param>
    /// <param name="revocationReason">The RFC 5280 §5.3.1 <c>CRLReason</c> stated for it, when it is listed.</param>
    /// <param name="pool">The memory pool the read rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The revocation status information; its carriers are the ones passed in.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    internal static async ValueTask<RevocationStatusInformation> DescribeRevocationListStatusAsync(
        PkiCertificateMemory certificateRevocationList,
        PkiCertificateMemory subject,
        PkiCertificateMemory issuer,
        DateTimeOffset validationTime,
        DateTimeOffset thisUpdate,
        DateTimeOffset nextUpdate,
        DateTimeOffset? revocationTime,
        int? revocationReason,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificateRevocationList);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(pool);

        var checker = new CrlRevocationChecker([certificateRevocationList]);
        CertificateRevocationStatus status = await checker.CheckAsync(
            subject, [issuer], validationTime, pool, cancellationToken).ConfigureAwait(false);

        return new RevocationStatusInformation
        {
            RevocationData = certificateRevocationList,
            SubjectCertificate = subject,
            Status = status,
            ThisUpdate = thisUpdate,
            NextUpdate = nextUpdate,
            RevocationTime = status == CertificateRevocationStatus.Revoked ? revocationTime : null,
            RevocationReason = status == CertificateRevocationStatus.Revoked ? revocationReason : null,
            SignatureAlgorithm = new PkiAlgorithmIdentifier(X509ChainTestRing.EcdsaWithSha256SignatureOid),
            SignatureKeySizeBits = X509ChainTestRing.SigningKeySizeBits,
            IssuerCertificate = issuer
        };
    }


    /// <summary>
    /// Describes a minted OCSP response as the neutral <see cref="RevocationStatusInformation"/>, reading every
    /// fact out of the DER through the shipped <see cref="OcspResponseVerification"/> reader — whose
    /// <see cref="OcspSingleResponseFacts"/> maps onto that record field for field, including the
    /// <c>producedAt</c>-versus-<c>thisUpdate</c> distinction NOTE 3 of clause 5.2.5.4 draws.
    /// </summary>
    /// <param name="response">The minted response; referenced, not owned.</param>
    /// <param name="request">The request it answers, whose <c>CertID</c> and nonce it is matched against.</param>
    /// <param name="subject">The node the status is about.</param>
    /// <param name="issuer">The node that issued both the subject's certificate and the response.</param>
    /// <param name="validationTime">The instant the response's own validity window is judged at.</param>
    /// <param name="pool">The memory pool the read rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The revocation status information; its carriers are the ones passed in.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the minted response does not verify, which would make every fact read out of it meaningless.</exception>
    internal static async ValueTask<RevocationStatusInformation> DescribeOcspStatusAsync(
        PkiCertificateMemory response,
        OcspRequestContent request,
        PkiCertificateMemory subject,
        PkiCertificateMemory issuer,
        DateTimeOffset validationTime,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(pool);

        OcspResponseVerificationResult verification = await OcspResponseVerification.VerifyAsync(
            response, request, issuer, validationTime, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
        if(verification.Outcome != OcspResponseVerificationOutcome.Verified || verification.Single is not OcspSingleResponseFacts facts)
        {
            throw new InvalidOperationException(
                $"The minted OCSP response did not verify at the stated validation time ({verification.Outcome}).");
        }

        return new RevocationStatusInformation
        {
            RevocationData = response,
            SubjectCertificate = subject,
            Status = facts.Status switch
            {
                OcspCertificateStatus.Good => CertificateRevocationStatus.Good,
                OcspCertificateStatus.Revoked => CertificateRevocationStatus.Revoked,
                _ => CertificateRevocationStatus.Unknown
            },
            ThisUpdate = facts.ThisUpdate,
            NextUpdate = facts.NextUpdate,
            ProducedAt = facts.ThisUpdate,
            RevocationTime = facts.RevocationTime,
            RevocationReason = facts.RevocationReason,
            SignatureAlgorithm = new PkiAlgorithmIdentifier(X509ChainTestRing.EcdsaWithSha256SignatureOid),
            SignatureKeySizeBits = X509ChainTestRing.SigningKeySizeBits,
            IssuerCertificate = issuer
        };
    }


    /// <summary>Copies DER bytes into a pooled carrier tagged as a Certificate Revocation List.</summary>
    /// <param name="revocationListBytes">The DER-encoded <c>CertificateList</c>.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToRevocationListCarrier(byte[] revocationListBytes)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(revocationListBytes.Length);
        revocationListBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Crl);
    }


    /// <summary>Reads an entropy draw as a positive big integer, for a field whose ASN.1 type is an INTEGER.</summary>
    /// <param name="draw">The drawn bytes.</param>
    /// <returns>The value, always positive regardless of the top bit of the draw.</returns>
    private static BcBigInteger ToPositiveInteger(Salt draw) => new(1, draw.AsReadOnlySpan().ToArray());
}
