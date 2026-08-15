using System;
using System.Buffers;
using System.Formats.Asn1;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The embedded-material substrate: <see cref="TimestampTokenInfo.EmbeddedCertificates"/>, <see
/// cref="TimestampTokenInfo.SignerCertificate"/> and <see cref="TimestampTokenInfo.EmbeddedCrls"/>, read through
/// <see cref="CmsEmbeddedMaterial"/> — a managed parse of a time-stamp token's own bytes, independent of whichever
/// <see cref="VerifyCmsSignedDataDelegate"/> backend verifies the token's signature.
/// </summary>
[TestClass]
internal sealed class TimestampTokenEmbeddedMaterialTests
{
    /// <summary>The Root CA and Time-Stamping Authority certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The Root CA and Time-Stamping Authority certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The <c>genTime</c> every token minted in these tests carries.</summary>
    private static DateTimeOffset TokenTime { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The octets every token in these tests time-stamps.</summary>
    private static ReadOnlyMemory<byte> TimestampedContent { get; } = new("the embedded-material test content"u8.ToArray());

    /// <summary>The id-signedData content type (RFC 5652 §5.1).</summary>
    private const string SignedDataOid = "1.2.840.113549.1.7.2";

    /// <summary>The id-data content type (RFC 5652 §4).</summary>
    private const string DataOid = "1.2.840.113549.1.7.1";


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A time-stamp token minted by the in-process TSA fixture, over the real BouncyCastle protocol oracle,
    /// carries the authority's own certificate in its <c>certificates</c> field; the token's own
    /// <c>SignerInfo</c> identity resolves to that certificate, and its digest — computed through the
    /// registered digest delegates — is byte-identical to a digest of the fixture's own minting certificate,
    /// never a raw byte comparison of the two.
    /// </summary>
    [TestMethod]
    public async Task SignerCertificateIsExtractedAndDigestMatchesTheMintingCertificate()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);

        using var metered = new MeteredHousePool();
        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            authority, [authority], TimestampedContent, TokenTime, metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(
            token, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TimestampTokenInfoStatus.Read, info.Status, "A well-formed token minted by the genuine TSA fixture reads cleanly.");
        Assert.HasCount(1, info.EmbeddedCertificates, "The token was minted carrying exactly the authority's own certificate.");
        Assert.IsNotNull(info.SignerCertificate, "The SignerInfo identity resolves to the one embedded certificate, which is the authority's own.");

        using(DigestValue mintedDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            authority.Certificate.RawData, 32, CryptoTags.Sha256Digest, metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        using(DigestValue signerDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            info.SignerCertificate!.AsReadOnlyMemory(), 32, CryptoTags.Sha256Digest, metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(mintedDigest.AsReadOnlySpan().SequenceEqual(signerDigest.AsReadOnlySpan()),
                "The surfaced signer certificate is byte-identical to the certificate the fixture minted the authority with, proven through the registered digest delegates.");
        }

        info.Dispose();
        Assert.AreEqual(0, metered.OutstandingCount, "Every carrier the accessor rented — the message imprint and the embedded certificate — returns to the pool once the token info is disposed.");
    }


    /// <summary>
    /// A token whose <c>certificates</c> field carries the signer's own untagged <c>Certificate</c> alongside a
    /// <c>v2AttrCert [2]</c> tagged <c>CertificateChoices</c> alternative still attributes the signer — the
    /// regression for the false-<see cref="CmsEmbeddedMaterialStatus.Malformed"/> collapse a reader that does
    /// not tag-discriminate <c>CertificateChoices</c> (RFC 5652 §10.2.2) would produce by feeding the tagged
    /// alternative's bytes to <see cref="ManagedCertificate.Parse"/>.
    /// </summary>
    [TestMethod]
    public async Task SignerCertificateIsAttributedWhenCertificatesFieldAlsoCarriesAV2AttrCert()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);

        using var metered = new MeteredHousePool();
        using PkiCertificateMemory bareToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            authority, [authority], TimestampedContent, TokenTime, metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        byte[] decoy = BuildTaggedCertificateChoice(root.Certificate.RawData, tagNumber: 2);
        using PkiCertificateMemory tokenWithDecoy = RebuildTokenWithCertificatesField(bareToken, authority.Certificate.RawData, decoy);

        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(
            tokenWithDecoy, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TimestampTokenInfoStatus.Read, info.Status, "A v2AttrCert [2] tagged alternative alongside the signer's untagged Certificate is legal content per RFC 5652 §10.2.2, not malformation.");
        Assert.AreEqual(CmsEmbeddedMaterialStatus.Read, info.EmbeddedMaterialStatus, "The embedded-material parse succeeds despite the tagged alternative sitting in the same certificates SET.");
        Assert.HasCount(1, info.EmbeddedCertificates, "Only the untagged Certificate alternative is surfaced; the v2AttrCert [2] alternative is skipped, never counted.");
        Assert.IsNotNull(info.SignerCertificate, "The signer's own certificate is still attributed even though a tagged CertificateChoices alternative sits alongside it in the certificates SET.");

        info.Dispose();
        Assert.AreEqual(0, metered.OutstandingCount, "Every carrier rented across the certificate accessors returns to the pool once the token info is disposed.");
    }


    /// <summary>
    /// A <c>certificates</c> field whose sole member is a tag-valid untagged <c>SEQUENCE</c> that nonetheless
    /// fails <see cref="ManagedCertificate.Parse"/> collapses the whole embedded-material read to
    /// <see cref="CmsEmbeddedMaterialStatus.Malformed"/>, and that status is observable through
    /// <see cref="TimestampTokenInfo.EmbeddedMaterialStatus"/> — never laundered into the "embeds nothing"
    /// shape <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/> reports for a genuinely empty field.
    /// Rerouted through <see cref="ManagedCmsVerification.VerifyCmsSignedDataAsync"/> for the test's duration,
    /// proving the split platform-independently: the Managed backend's member-tolerant <c>certificates</c> walk
    /// still lets the token's own signature verify, while the independent <see cref="CmsEmbeddedMaterial"/>
    /// re-parse this accessor exposes still collapses to <c>Malformed</c> — verification tolerance never leaks
    /// into the observation channel.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task BrokenCertificateMemberIsObservableAsMalformedThroughTheAccessor()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);

        using var metered = new MeteredHousePool();
        using PkiCertificateMemory bareToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            authority, [authority], TimestampedContent, TokenTime, metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory tokenWithBrokenCertificate = RebuildTokenWithCertificatesField(
            bareToken, authority.Certificate.RawData, BuildBrokenCertificateMember());

        VerifyCmsSignedDataDelegate? original = CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate));
        try
        {
            CryptographicKeyFactory.RegisterFunction(typeof(VerifyCmsSignedDataDelegate), (VerifyCmsSignedDataDelegate)ManagedCmsVerification.VerifyCmsSignedDataAsync);

            using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(
                tokenWithBrokenCertificate, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TimestampTokenInfoStatus.Read, info.Status, "certificates is not covered by the token's own signature (RFC 5652 §5.4), so splicing it leaves the TSTInfo signature verifiable.");
            Assert.AreEqual(CmsEmbeddedMaterialStatus.Malformed, info.EmbeddedMaterialStatus, "A tag-valid untagged-SEQUENCE member whose content fails ManagedCertificate.Parse keeps collapsing the read to Malformed.");
            Assert.IsFalse(info.HasEmbeddedCertificates, "A Malformed embedded-material read carries no certificates.");
            Assert.IsNull(info.SignerCertificate, "No signer can be attributed once the embedded-material read is Malformed.");

            info.Dispose();
            Assert.AreEqual(0, metered.OutstandingCount, "A Malformed embedded-material parse disposes anything it rented before TimestampTokenInfo.ReadFromTokenAsync returns; no leak.");
        }
        finally
        {
            if(original is not null)
            {
                CryptographicKeyFactory.RegisterFunction(typeof(VerifyCmsSignedDataDelegate), original);
            }
        }
    }


    /// <summary>
    /// A token whose own <c>SignedData.crls</c> field carries a Certificate Revocation List surfaces it through
    /// <see cref="TimestampTokenInfo.EmbeddedCrls"/>, byte-identical to the minted list — the arcTst half of
    /// CB-6.3-28 carries the revocation-half gap under.
    /// </summary>
    [TestMethod]
    public async Task EmbeddedCrlIsSurfacedWhenTheTokenCarriesOne()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);

        using var metered = new MeteredHousePool();
        using PkiCertificateMemory bareToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            authority, [authority], TimestampedContent, TokenTime, metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory crl = X509ChainTestRingRevocation.MintCertificateRevocationList(
            root, TokenTime, TokenTime.AddDays(30), []);
        using PkiCertificateMemory tokenWithCrl = EmbedCrlInToken(bareToken, crl);

        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(
            tokenWithCrl, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TimestampTokenInfoStatus.Read, info.Status, "Splicing a crls field does not touch the signature, which the CMS seam still verifies.");
        Assert.HasCount(1, info.EmbeddedCrls, "The spliced token carries exactly the one list embedded into its crls field.");
        Assert.IsTrue(crl.AsReadOnlySpan().SequenceEqual(info.EmbeddedCrls[0].AsReadOnlySpan()),
            "The surfaced list is the same DER CertificateList that was embedded, read back verbatim rather than re-derived.");

        info.Dispose();
        Assert.AreEqual(0, metered.OutstandingCount, "Every carrier rented across the certificate and CRL accessors returns to the pool once the token info is disposed.");
    }


    /// <summary>
    /// A token minted without a <c>crls</c> field at all reports an empty <see cref="TimestampTokenInfo.EmbeddedCrls"/>
    /// — an absent fact, not a failure: <see cref="TimestampTokenInfo.Status"/> still reads
    /// <see cref="TimestampTokenInfoStatus.Read"/>.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.3-28.
    /// </remarks>
    [TestMethod]
    public async Task NoEmbeddedCrlIsAnAbsentFactNotAnError()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);

        using var metered = new MeteredHousePool();
        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            authority, [authority], TimestampedContent, TokenTime, metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(
            token, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TimestampTokenInfoStatus.Read, info.Status, "The token reads cleanly; carrying no CRL is not a parse failure.");
        Assert.IsEmpty(info.EmbeddedCrls, "The fixture never embedded a crls field, so the accessor reports the empty set rather than an error.");

        info.Dispose();
        Assert.AreEqual(0, metered.OutstandingCount, "The certificate carrier the token does embed still returns to the pool once disposed.");
    }


    /// <summary>
    /// Bytes that are not well-formed DER at all fail closed: <see cref="CmsEmbeddedMaterial.Parse"/> reports
    /// <see cref="CmsEmbeddedMaterialStatus.Malformed"/> with empty carriers rather than throwing.
    /// </summary>
    [TestMethod]
    public void MalformedBytesFailClosedWithoutThrowing()
    {
        ReadOnlyMemory<byte> garbage = new byte[] { 0x30, 0x7F, 0x01, 0x02 };

        using var metered = new MeteredHousePool();
        using CmsEmbeddedMaterial material = CmsEmbeddedMaterial.Parse(garbage, metered.Pool);

        Assert.AreEqual(CmsEmbeddedMaterialStatus.Malformed, material.Status, "The bytes declare a length exceeding what follows, so the DER walk fails closed rather than reading past the input.");
        Assert.IsFalse(material.IsRead, "A malformed parse never reports IsRead.");
        Assert.IsEmpty(material.Certificates, "No carrier is produced for input that never parsed as a SignedData.");
        Assert.IsEmpty(material.Crls, "No carrier is produced for input that never parsed as a SignedData.");
        Assert.IsNull(material.SignerCertificate, "No signer can be identified without a parsed structure.");

        Assert.AreEqual(0, metered.OutstandingCount, "A parse that fails before renting anything leaves the pool untouched.");
    }


    /// <summary>
    /// A token whose outer <c>ContentInfo</c> SEQUENCE is re-encoded with BER's indefinite-length form — legal
    /// under <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5">RFC 5652</see> (CMS is BER; DER is a
    /// stricter subset) but rejected by a DER-only reader — still reads, proving the outer CMS walk in
    /// <see cref="CmsEmbeddedMaterial.Parse"/> never re-parses more strictly than a verifying backend accepted.
    /// </summary>
    [TestMethod]
    public async Task IndefiniteLengthOuterSequenceReadsUnderBerRules()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);

        using var metered = new MeteredHousePool();
        using PkiCertificateMemory bareToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            authority, [authority], TimestampedContent, TokenTime, metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory berToken = ToIndefiniteLengthOuterSequence(bareToken);

        using CmsEmbeddedMaterial material = CmsEmbeddedMaterial.Parse(berToken.AsReadOnlyMemory(), metered.Pool);

        Assert.AreEqual(CmsEmbeddedMaterialStatus.Read, material.Status, "Every nested element stays byte-identical, valid DER; only the outer wrapper's length form changes to indefinite, which AsnEncodingRules.BER admits.");
        Assert.HasCount(1, material.Certificates, "The BER re-shaping touches only the outer length form; the embedded certificate is unaffected.");
        Assert.IsNotNull(material.SignerCertificate, "The signer identity still resolves under the BER-shaped wrapper.");
    }


    /// <summary>
    /// A structure whose <c>certificates</c> field parses but whose <c>signerInfos</c> is truncated fails closed
    /// after already renting a carrier for the embedded certificate — the metered-pool custody every new failure
    /// path in this substrate must observe: the certificate already collected is disposed before
    /// <see cref="CmsEmbeddedMaterial.Parse"/> returns the failed result, not leaked.
    /// </summary>
    [TestMethod]
    public void PartialFailureAfterCertificatesDisposesTheAlreadyRentedCarrier()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        byte[] truncated = BuildSignedDataWithCertificateButNoSignerInfos(root.Certificate.RawData);

        using var metered = new MeteredHousePool();
        using CmsEmbeddedMaterial material = CmsEmbeddedMaterial.Parse(truncated, metered.Pool);

        Assert.AreEqual(CmsEmbeddedMaterialStatus.Malformed, material.Status, "The signerInfos SET OF is entirely absent, which the DER walk reports as malformed rather than tolerating.");
        Assert.IsEmpty(material.Certificates, "The certificate rented while walking the (well-formed) certificates field is disposed on the later failure, not surfaced as a half-built result.");
        Assert.AreEqual(0, metered.OutstandingCount, "The rental made for the embedded certificate before the failure is returned to the pool, proving the failure path carries no leak.");
    }


    /// <summary>
    /// Splices a Certificate Revocation List into an already-minted token's own <c>SignedData.crls</c> field,
    /// with its own <see cref="AsnWriter"/>/<see cref="AsnReader"/> assembly independent of
    /// <see cref="CmsEmbeddedMaterial"/> — the reader under test never produced this input. The token's
    /// signature does not cover <c>certificates</c> or <c>crls</c> (RFC 5652 §5.4), so splicing this field
    /// leaves the signature verifiable.
    /// </summary>
    /// <param name="token">The already-minted token, carrying no <c>crls</c> field.</param>
    /// <param name="crl">The DER-encoded <c>CertificateList</c> to embed.</param>
    /// <returns>The doctored token; the caller disposes it.</returns>
    private static PkiCertificateMemory EmbedCrlInToken(PkiCertificateMemory token, PkiCertificateMemory crl)
    {
        var outer = new AsnReader(token.AsReadOnlySpan().ToArray(), AsnEncodingRules.DER);
        AsnReader contentInfo = outer.ReadSequence();
        string contentType = contentInfo.ReadObjectIdentifier();
        AsnReader explicitContent = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        AsnReader signedData = explicitContent.ReadSequence();

        ReadOnlyMemory<byte> version = signedData.ReadEncodedValue();
        ReadOnlyMemory<byte> digestAlgorithms = signedData.ReadEncodedValue();
        ReadOnlyMemory<byte> encapContentInfo = signedData.ReadEncodedValue();

        ReadOnlyMemory<byte>? certificates = null;
        if(signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            certificates = signedData.ReadEncodedValue();
        }

        ReadOnlyMemory<byte> signerInfos = signedData.ReadEncodedValue();
        signedData.ThrowIfNotEmpty();

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteObjectIdentifier(contentType);
            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                using(writer.PushSequence())
                {
                    writer.WriteEncodedValue(version.Span);
                    writer.WriteEncodedValue(digestAlgorithms.Span);
                    writer.WriteEncodedValue(encapContentInfo.Span);
                    if(certificates is ReadOnlyMemory<byte> certificateSet)
                    {
                        writer.WriteEncodedValue(certificateSet.Span);
                    }

                    using(writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 1)))
                    {
                        writer.WriteEncodedValue(crl.AsReadOnlySpan());
                    }

                    writer.WriteEncodedValue(signerInfos.Span);
                }
            }
        }

        byte[] encoded = writer.Encode();
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(encoded.Length);
        encoded.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
    }


    /// <summary>
    /// Hand-assembles a <c>SignedData</c> carrying one real certificate in its <c>certificates</c> field but no
    /// <c>signerInfos</c> at all — a field RFC 5652 §5.1 makes mandatory — so a reader that walks
    /// <c>certificates</c> before <c>signerInfos</c> collects one carrier and then fails on the missing field.
    /// </summary>
    /// <param name="certificateDer">The DER-encoded certificate to place in the <c>certificates</c> field.</param>
    /// <returns>The DER-encoded, deliberately incomplete structure.</returns>
    private static byte[] BuildSignedDataWithCertificateButNoSignerInfos(ReadOnlySpan<byte> certificateDer)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteObjectIdentifier(SignedDataOid);
            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                using(writer.PushSequence())
                {
                    writer.WriteInteger(1);
                    using(writer.PushSetOf())
                    {
                    }

                    using(writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier(DataOid);
                    }

                    using(writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    {
                        writer.WriteEncodedValue(certificateDer);
                    }
                }
            }
        }

        return writer.Encode();
    }


    /// <summary>
    /// Decomposes an already-minted token's own <c>SignedData</c> and rebuilds it with its <c>certificates</c>
    /// field's <c>SET OF CertificateChoices</c> content replaced verbatim by <paramref name="certificateEntries"/>
    /// — each already a complete TLV. The token's signature does not cover <c>certificates</c> (RFC 5652 §5.4),
    /// so splicing this field leaves the signature verifiable, mirroring <see cref="EmbedCrlInToken"/>'s approach
    /// for <c>crls</c>.
    /// </summary>
    /// <param name="token">The already-minted token.</param>
    /// <param name="certificateEntries">The raw TLV bytes of every <c>CertificateChoices</c> entry the rebuilt field carries, in order.</param>
    /// <returns>The doctored token; the caller disposes it.</returns>
    private static PkiCertificateMemory RebuildTokenWithCertificatesField(PkiCertificateMemory token, params ReadOnlyMemory<byte>[] certificateEntries)
    {
        var outer = new AsnReader(token.AsReadOnlySpan().ToArray(), AsnEncodingRules.DER);
        AsnReader contentInfo = outer.ReadSequence();
        string contentType = contentInfo.ReadObjectIdentifier();
        AsnReader explicitContent = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        AsnReader signedData = explicitContent.ReadSequence();

        ReadOnlyMemory<byte> version = signedData.ReadEncodedValue();
        ReadOnlyMemory<byte> digestAlgorithms = signedData.ReadEncodedValue();
        ReadOnlyMemory<byte> encapContentInfo = signedData.ReadEncodedValue();

        if(signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            //The token's own certificates field, discarded: the rebuilt field below replaces it entirely with
            //certificateEntries rather than preserving it.
            _ = signedData.ReadEncodedValue();
        }

        ReadOnlyMemory<byte> signerInfos = signedData.ReadEncodedValue();
        signedData.ThrowIfNotEmpty();

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteObjectIdentifier(contentType);
            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                using(writer.PushSequence())
                {
                    writer.WriteEncodedValue(version.Span);
                    writer.WriteEncodedValue(digestAlgorithms.Span);
                    writer.WriteEncodedValue(encapContentInfo.Span);
                    using(writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    {
                        foreach(ReadOnlyMemory<byte> entry in certificateEntries)
                        {
                            writer.WriteEncodedValue(entry.Span);
                        }
                    }

                    writer.WriteEncodedValue(signerInfos.Span);
                }
            }
        }

        byte[] encoded = writer.Encode();
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(encoded.Length);
        encoded.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
    }


    /// <summary>
    /// Wraps arbitrary DER content in a context-specific constructed tag — the shape of a tagged
    /// <c>CertificateChoices</c> alternative (<c>extendedCertificate [0]</c>, <c>v1AttrCert [1]</c>,
    /// <c>v2AttrCert [2]</c>, <c>other [3]</c>) a tag-discriminating reader must skip rather than feed to
    /// <see cref="ManagedCertificate.Parse"/>. <paramref name="content"/>'s own semantics are irrelevant: the
    /// skip path never interprets what it consumes.
    /// </summary>
    /// <param name="content">The bytes to wrap.</param>
    /// <param name="tagNumber">The context-specific tag number (0 through 3).</param>
    /// <returns>The tagged TLV.</returns>
    private static byte[] BuildTaggedCertificateChoice(ReadOnlySpan<byte> content, int tagNumber)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, tagNumber, isConstructed: true)))
        {
            writer.WriteEncodedValue(content);
        }

        return writer.Encode();
    }


    /// <summary>
    /// Builds a structurally otherwise well-formed X.509 certificate — the shape a genuine <c>Certificate</c>
    /// CertificateChoices alternative takes, decodable by a generic ASN.1 certificate reader that does not range
    /// -check field values — whose <c>[0]</c> EXPLICIT version wrapper carries <c>5</c>, a value RFC 5280
    /// §4.1.2.1 admits only 0, 1, or 2 for. <see cref="ManagedCertificate.Parse"/> rejects it on that one
    /// narrower check while the outer tag still passes tag discrimination as a legal untagged-Certificate
    /// candidate, mirroring <c>CertificateValidityPeriodTests.BuildCertificateWithNullIssuer</c>'s stand-in-field
    /// shape for every other field.
    /// </summary>
    /// <returns>The broken member's TLV.</returns>
    private static byte[] BuildBrokenCertificateMember()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                        //Certificate.
        {
            using(writer.PushSequence())                                    //tbsCertificate.
            {
                using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    writer.WriteInteger(5);                                 //RFC 5280 §4.1.2.1 admits only 0, 1, 2.
                }

                writer.WriteInteger(1);                                     //serialNumber stand-in.
                using(writer.PushSequence())                                //signature AlgorithmIdentifier stand-in.
                {
                    writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
                }

                using(writer.PushSequence())                                //issuer -- an empty Name suffices.
                {
                }

                using(writer.PushSequence())                                //validity.
                {
                    writer.WriteUtcTime(NotBefore);
                    writer.WriteUtcTime(NotAfter);
                }

                using(writer.PushSequence())                                //subject -- an empty Name suffices.
                {
                }

                using(writer.PushSequence())                                //subjectPublicKeyInfo.
                {
                    using(writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
                    }

                    writer.WriteBitString([0x00]);
                }
            }

            using(writer.PushSequence())                                    //signatureAlgorithm stand-in.
            {
                writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
            }

            writer.WriteBitString([]);                                      //signatureValue stand-in.
        }

        return writer.Encode();
    }


    /// <summary>
    /// Rewraps an already DER-encoded token's outer <c>ContentInfo</c> SEQUENCE in BER's indefinite-length form:
    /// the tag byte, a single <c>0x80</c> length octet, the original content verbatim, then the two-byte
    /// end-of-contents marker. Every nested element stays byte-identical, valid DER — only the outer wrapper's
    /// length form changes.
    /// </summary>
    /// <param name="token">The already DER-encoded token.</param>
    /// <returns>The BER-reshaped token; the caller disposes it.</returns>
    private static PkiCertificateMemory ToIndefiniteLengthOuterSequence(PkiCertificateMemory token)
    {
        ReadOnlySpan<byte> original = token.AsReadOnlySpan();
        byte firstLengthOctet = original[1];
        int headerLength = (firstLengthOctet & 0x80) == 0 ? 2 : 2 + (firstLengthOctet & 0x7F);
        ReadOnlySpan<byte> content = original[headerLength..];

        byte[] reshaped = new byte[content.Length + 4];
        reshaped[0] = 0x30;
        reshaped[1] = 0x80;
        content.CopyTo(reshaped.AsSpan(2));

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(reshaped.Length);
        reshaped.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
    }
}
