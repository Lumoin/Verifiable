using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Verifiable.Tests.X509;

/// <summary>
/// Mints RFC 3161 time-stamp tokens for the Time-Stamping Authority leg of an <see cref="X509ChainTestRing"/>
/// chain, through the independent BouncyCastle time-stamp protocol implementation
/// (<c>Org.BouncyCastle.Tsp</c>) — a <c>TSTInfo</c> encoder, a CMS <c>SignedData</c> writer and an ECDSA signer
/// none of which is the library's own reader under test.
/// </summary>
/// <remarks>
/// <para>
/// The oracle arrangement mirrors <see cref="OcspTestFixtures"/> exactly: the platform certificate factory mints
/// the authority's certificate, its private key is bridged to a BouncyCastle key parameter solely to drive the
/// independent generator, and the resulting bytes are that generator's own DER and signature. What the library
/// then reads back — <see cref="TimestampTokenInfo"/>, <see cref="TimestampValidation"/> — has never seen this
/// code.
/// </para>
/// <para>
/// The message imprint is taken through the registered digest seam
/// (<see cref="CryptographicKeyEvents.ComputeDigestAsync(ReadOnlyMemory{byte}, int, Tag, BaseMemoryPool, System.Collections.Frozen.FrozenDictionary{string, object}?, CancellationToken)"/>),
/// never a direct framework hash, so a minted token carries the same provenance events as production material.
/// Every instant a caller passes is expected to be derived from <see cref="TestClock.CanonicalEpoch"/>; nothing
/// here reads a clock.
/// </para>
/// </remarks>
internal static class X509ChainTestRingTimestamping
{
    /// <summary>
    /// The TSA policy object identifier every token minted here states. RFC 3161 §2.4.1 requires a policy under
    /// which a token was produced; no registered policy applies to fixture material, so an arbitrary
    /// non-colliding identifier stands in, mirroring what the CAdES fixtures already write.
    /// </summary>
    internal static string TestPolicyOid { get; } = "1.2.3.4.1";

    /// <summary>The SHA-256 digest length in bytes — the message imprint length a token minted here states unless a caller names another algorithm.</summary>
    private const int Sha256Length = 32;


    /// <summary>
    /// Mints a time-stamp token whose message imprint is the SHA-256 digest of
    /// <paramref name="timestampedOctets"/>, generated at <paramref name="generationTime"/> and signed by
    /// <paramref name="authority"/>.
    /// </summary>
    /// <param name="authority">The Time-Stamping Authority node, minted by <see cref="X509ChainTestRing.CreateTimeStampingAuthority"/> so that it carries the Extended Key Usage RFC 3161 §2.3 requires.</param>
    /// <param name="embeddedCertificates">The certificates the token carries in its own <c>certificates</c> field — at least the authority's own, plus whatever a validator needs to build a chain from it offline.</param>
    /// <param name="timestampedOctets">The octets the token's message imprint is taken over. For a signature time-stamp of a CAdES signature these are the signature value; for the archive time-stamp of this fixture family they are the Signed Data Object.</param>
    /// <param name="generationTime">The <c>genTime</c> the authority states.</param>
    /// <param name="pool">The memory pool the digest is rented from.</param>
    /// <param name="accuracy">The <c>accuracy</c> the authority states, in whole seconds; omitted from the token when <see langword="null"/>.</param>
    /// <param name="isOrdered">Whether the token sets the <c>ordering</c> field, which RFC 3161 §2.4.2 makes the authority assert that its tokens are ordered on <c>genTime</c> alone.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The pooled DER-encoded token, tagged <see cref="PkiCertificateTags.TimestampToken"/>; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    internal static async ValueTask<PkiCertificateMemory> MintTimestampTokenAsync(
        X509ChainTestRingNode authority,
        IReadOnlyList<X509ChainTestRingNode> embeddedCertificates,
        ReadOnlyMemory<byte> timestampedOctets,
        DateTimeOffset generationTime,
        BaseMemoryPool pool,
        TimeSpan? accuracy = null,
        bool isOrdered = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(embeddedCertificates);
        ArgumentNullException.ThrowIfNull(pool);

        using DigestValue messageImprint = await CryptographicKeyEvents.ComputeDigestAsync(
            timestampedOctets, Sha256Length, CryptoTags.Sha256Digest, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return MintTimestampTokenOverImprint(
            authority, embeddedCertificates, messageImprint.AsReadOnlySpan(), generationTime, requestNonce: default, accuracy, isOrdered);
    }


    /// <summary>
    /// Mints a time-stamp token over an already-computed message imprint, which is what a Time-Stamping
    /// Authority answering an RFC 3161 <c>TimeStampReq</c> does: the request carries the imprint, never the data
    /// it was taken over.
    /// </summary>
    /// <param name="authority">The Time-Stamping Authority node, minted by <see cref="X509ChainTestRing.CreateTimeStampingAuthority"/> so that it carries the Extended Key Usage RFC 3161 §2.3 requires.</param>
    /// <param name="embeddedCertificates">The certificates the token carries in its own <c>certificates</c> field.</param>
    /// <param name="messageImprintDigest">The digest the token's <c>messageImprint</c> states, under <paramref name="messageImprintAlgorithm"/>.</param>
    /// <param name="generationTime">The <c>genTime</c> the authority states.</param>
    /// <param name="requestNonce">The nonce the request carried, which the token echoes; empty when the request carried none.</param>
    /// <param name="accuracy">The <c>accuracy</c> the authority states, in whole seconds; omitted from the token when <see langword="null"/>.</param>
    /// <param name="isOrdered">Whether the token sets the <c>ordering</c> field.</param>
    /// <param name="messageImprintAlgorithm">The algorithm the imprint was computed under, or <see langword="null"/> for SHA-256.</param>
    /// <param name="policyOid">The TSA policy object identifier the token states, or <see langword="null"/> for <see cref="TestPolicyOid"/> — a real authority answers under the request's <c>reqPolicy</c> (RFC 3161 §2.4.2), which the responder threads through here.</param>
    /// <returns>The pooled DER-encoded token, tagged <see cref="PkiCertificateTags.TimestampToken"/>; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="messageImprintDigest"/> is not the stated algorithm's digest length, or that algorithm is one this fixture does not mint under.</exception>
    /// <remarks>
    /// The imprint algorithm is a parameter because a real authority answers under the algorithm the request
    /// states, and a caller renewing an archive under a new hash algorithm — RFC 4998 clause 5.2's Hash-Tree
    /// Renewal — asks for exactly that. The token's own signature and its <c>ESSCertIDv2</c> certificate
    /// reference stay SHA-256 whatever the imprint algorithm is; those are the authority's own choices and
    /// independent of what it is asked to bind.
    /// </remarks>
    internal static PkiCertificateMemory MintTimestampTokenOverImprint(
        X509ChainTestRingNode authority,
        IReadOnlyList<X509ChainTestRingNode> embeddedCertificates,
        ReadOnlySpan<byte> messageImprintDigest,
        DateTimeOffset generationTime,
        ReadOnlySpan<byte> requestNonce = default,
        TimeSpan? accuracy = null,
        bool isOrdered = false,
        PkiDigestAlgorithm? messageImprintAlgorithm = null,
        string? policyOid = null)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(embeddedCertificates);

        PkiDigestAlgorithm imprintAlgorithm = messageImprintAlgorithm ?? PkiDigestAlgorithm.Sha256;
        DerObjectIdentifier imprintAlgorithmOid = ToBouncyCastleDigestOid(imprintAlgorithm);
        if(messageImprintDigest.Length != imprintAlgorithm.OutputByteLength)
        {
            throw new ArgumentException(
                $"The message imprint of a token minted under {imprintAlgorithm.Identifier.Oid} is a {imprintAlgorithm.OutputByteLength}-byte digest.", nameof(messageImprintDigest));
        }

        BcX509Certificate bcAuthority = OcspTestFixtures.ToBouncyCastleCertificate(authority.Certificate);
        AsymmetricKeyParameter authorityPrivateKey = OcspTestFixtures.ToBouncyCastlePrivateKey(authority.SigningKey);

        //The signing-certificate reference the generator writes is an ESSCertIDv2 under SHA-256 (RFC 5816),
        //because the certificate digest calculator it is handed names SHA-256. The alternative the library
        //offers — the RFC 2634 ESSCertID under SHA-1 — would be unresolvable through the shipped digest
        //algorithm mapping and would leave a token no validator could bind to its own authority.
        SignerInfoGenerator signerInfoGenerator = new SignerInfoGeneratorBuilder()
            .Build(new Asn1SignatureFactory(X509ChainTestRing.EcdsaWithSha256SignatureName, authorityPrivateKey), bcAuthority);
        var tokenGenerator = new TimeStampTokenGenerator(
            signerInfoGenerator,
            Asn1DigestFactory.Get(NistObjectIdentifiers.IdSha256),
            new DerObjectIdentifier(policyOid ?? TestPolicyOid),
            isIssuerSerialIncluded: false);

        List<BcX509Certificate> carried = [];
        for(int i = 0; i < embeddedCertificates.Count; ++i)
        {
            carried.Add(OcspTestFixtures.ToBouncyCastleCertificate(embeddedCertificates[i].Certificate));
        }

        tokenGenerator.SetCertificates(CollectionUtilities.CreateStore(carried));
        if(accuracy is TimeSpan stated)
        {
            tokenGenerator.SetAccuracySeconds((int)stated.TotalSeconds);
        }

        if(isOrdered)
        {
            tokenGenerator.SetOrdering(true);
        }

        var requestGenerator = new TimeStampRequestGenerator();
        requestGenerator.SetCertReq(true);

        //The generator copies the request's nonce into the TSTInfo it signs, which is how an authority answers
        //a request that carried one (RFC 3161 §2.4.2).
        TimeStampRequest request = requestNonce.IsEmpty
            ? requestGenerator.Generate(imprintAlgorithmOid, messageImprintDigest.ToArray())
            : requestGenerator.Generate(imprintAlgorithmOid, messageImprintDigest.ToArray(), new BcBigInteger(1, requestNonce.ToArray()));

        using Salt serialNumber = X509ChainTestRing.CreateSerialNumber();
        TimeStampToken token = tokenGenerator.Generate(
            request,
            new BcBigInteger(1, serialNumber.AsReadOnlySpan().ToArray()),
            generationTime.UtcDateTime);

        return ToTimestampTokenCarrier(token.GetEncoded());

        //Maps a digest algorithm to the object identifier the independent generator names it by. Only the
        //SHA-2 family is minted here, which is what the shipped surfaces request.
        static DerObjectIdentifier ToBouncyCastleDigestOid(PkiDigestAlgorithm algorithm) => algorithm.Identifier.Oid switch
        {
            "2.16.840.1.101.3.4.2.1" => NistObjectIdentifiers.IdSha256,
            "2.16.840.1.101.3.4.2.2" => NistObjectIdentifiers.IdSha384,
            "2.16.840.1.101.3.4.2.3" => NistObjectIdentifiers.IdSha512,
            _ => throw new ArgumentException($"A token minted here states a SHA-2 message imprint, not one under {algorithm.Identifier.Oid}.", nameof(algorithm))
        };
    }


    /// <summary>
    /// Mints a time-stamp token signed by an RSA authority under the named combined RSA signature algorithm —
    /// the authority shape
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119300_119399/119312/01.04.03_60/ts_119312v010403p.pdf">
    /// ETSI TS 119 312 V1.4.3</see> clause A.9 Table A.8 obliges a token requester to support (RSA with
    /// SHA-256 or SHA-512) — through the same independent BouncyCastle generator as the ECDSA mints. The
    /// message imprint stays SHA-256, and the <c>ESSCertIDv2</c> certificate reference stays SHA-256, exactly
    /// as the ECDSA mints above; only the token's own signature is the authority's RSA choice.
    /// </summary>
    /// <param name="authorityCertificate">The authority's certificate, embedded in the token's own <c>certificates</c> field.</param>
    /// <param name="authorityKey">The authority's RSA signing key.</param>
    /// <param name="timestampedOctets">The octets the token's SHA-256 message imprint is taken over.</param>
    /// <param name="generationTime">The <c>genTime</c> the authority states.</param>
    /// <param name="pool">The memory pool the digest is rented from.</param>
    /// <param name="signatureAlgorithm">The BouncyCastle name of the combined RSA signature algorithm the token is signed under.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The pooled DER-encoded token, tagged <see cref="PkiCertificateTags.TimestampToken"/>; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    internal static async ValueTask<PkiCertificateMemory> MintTimestampTokenWithRsaAuthorityAsync(
        X509Certificate2 authorityCertificate,
        RSA authorityKey,
        ReadOnlyMemory<byte> timestampedOctets,
        DateTimeOffset generationTime,
        BaseMemoryPool pool,
        string signatureAlgorithm = "SHA512WITHRSA",
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authorityCertificate);
        ArgumentNullException.ThrowIfNull(authorityKey);
        ArgumentNullException.ThrowIfNull(pool);

        using DigestValue messageImprint = await CryptographicKeyEvents.ComputeDigestAsync(
            timestampedOctets, Sha256Length, CryptoTags.Sha256Digest, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        BcX509Certificate bcAuthority = OcspTestFixtures.ToBouncyCastleCertificate(authorityCertificate);
        AsymmetricKeyParameter authorityPrivateKey = OcspTestFixtures.ToBouncyCastlePrivateKey(authorityKey);

        SignerInfoGenerator signerInfoGenerator = new SignerInfoGeneratorBuilder()
            .Build(new Asn1SignatureFactory(signatureAlgorithm, authorityPrivateKey), bcAuthority);
        var tokenGenerator = new TimeStampTokenGenerator(
            signerInfoGenerator,
            Asn1DigestFactory.Get(NistObjectIdentifiers.IdSha256),
            new DerObjectIdentifier(TestPolicyOid),
            isIssuerSerialIncluded: false);

        tokenGenerator.SetCertificates(CollectionUtilities.CreateStore(new List<BcX509Certificate> { bcAuthority }));

        var requestGenerator = new TimeStampRequestGenerator();
        requestGenerator.SetCertReq(true);
        TimeStampRequest request = requestGenerator.Generate(NistObjectIdentifiers.IdSha256, messageImprint.AsReadOnlySpan().ToArray());

        using Salt serialNumber = X509ChainTestRing.CreateSerialNumber();
        TimeStampToken token = tokenGenerator.Generate(
            request,
            new BcBigInteger(1, serialNumber.AsReadOnlySpan().ToArray()),
            generationTime.UtcDateTime);

        return ToTimestampTokenCarrier(token.GetEncoded());
    }


    /// <summary>
    /// Checks a minted token against its authority's certificate with the independent BouncyCastle validator —
    /// the oracle side of the same material the library's own <see cref="TimestampValidation"/> consumes.
    /// </summary>
    /// <param name="token">The minted token.</param>
    /// <param name="authority">The authority whose certificate is expected to have signed it.</param>
    /// <returns><see langword="true"/> when the independent validator accepts the token.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    internal static bool VerifiesUnderAuthorityCertificate(PkiCertificateMemory token, X509ChainTestRingNode authority)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(authority);

        try
        {
            new TimeStampToken(new Org.BouncyCastle.Cms.CmsSignedData(token.AsReadOnlySpan().ToArray()))
                .Validate(OcspTestFixtures.ToBouncyCastleCertificate(authority.Certificate));

            return true;
        }
        catch(TspException)
        {
            //The independent validator rejects the token: a wrong authority, a broken signature, or a token
            //whose own certificate reference does not bind the certificate offered.
            return false;
        }
    }


    /// <summary>Copies DER bytes into a pooled carrier tagged as a time-stamp token.</summary>
    /// <param name="tokenBytes">The DER-encoded RFC 3161 <c>TimeStampToken</c>.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToTimestampTokenCarrier(byte[] tokenBytes)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(tokenBytes.Length);
        tokenBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
    }
}
