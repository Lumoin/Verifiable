using System;
using System.Buffers;
using System.Collections.Generic;
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
/// (<see cref="CryptographicKeyEvents.ComputeDigestAsync(ReadOnlyMemory{byte}, int, Tag, MemoryPool{byte}, System.Collections.Frozen.FrozenDictionary{string, object}?, CancellationToken)"/>),
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

    /// <summary>The SHA-256 digest length in bytes — the message imprint length of every token minted here.</summary>
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
        MemoryPool<byte> pool,
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
    /// Mints a time-stamp token over an already-computed SHA-256 message imprint, which is what a Time-Stamping
    /// Authority answering an RFC 3161 <c>TimeStampReq</c> does: the request carries the imprint, never the data
    /// it was taken over.
    /// </summary>
    /// <param name="authority">The Time-Stamping Authority node, minted by <see cref="X509ChainTestRing.CreateTimeStampingAuthority"/> so that it carries the Extended Key Usage RFC 3161 §2.3 requires.</param>
    /// <param name="embeddedCertificates">The certificates the token carries in its own <c>certificates</c> field.</param>
    /// <param name="messageImprintDigest">The SHA-256 digest the token's <c>messageImprint</c> states.</param>
    /// <param name="generationTime">The <c>genTime</c> the authority states.</param>
    /// <param name="requestNonce">The nonce the request carried, which the token echoes; empty when the request carried none.</param>
    /// <param name="accuracy">The <c>accuracy</c> the authority states, in whole seconds; omitted from the token when <see langword="null"/>.</param>
    /// <param name="isOrdered">Whether the token sets the <c>ordering</c> field.</param>
    /// <returns>The pooled DER-encoded token, tagged <see cref="PkiCertificateTags.TimestampToken"/>; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="messageImprintDigest"/> is not a SHA-256 digest length.</exception>
    internal static PkiCertificateMemory MintTimestampTokenOverImprint(
        X509ChainTestRingNode authority,
        IReadOnlyList<X509ChainTestRingNode> embeddedCertificates,
        ReadOnlySpan<byte> messageImprintDigest,
        DateTimeOffset generationTime,
        ReadOnlySpan<byte> requestNonce = default,
        TimeSpan? accuracy = null,
        bool isOrdered = false)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(embeddedCertificates);
        if(messageImprintDigest.Length != Sha256Length)
        {
            throw new ArgumentException($"The message imprint of a token minted here is a {Sha256Length}-byte SHA-256 digest.", nameof(messageImprintDigest));
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
            new DerObjectIdentifier(TestPolicyOid),
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
            ? requestGenerator.Generate(NistObjectIdentifiers.IdSha256, messageImprintDigest.ToArray())
            : requestGenerator.Generate(NistObjectIdentifiers.IdSha256, messageImprintDigest.ToArray(), new BcBigInteger(1, requestNonce.ToArray()));

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
