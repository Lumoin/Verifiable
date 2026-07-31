using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using PkiAlgorithmIdentifier = Verifiable.Cryptography.Pki.AlgorithmIdentifier;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The multi-server Kestrel wire end-to-end leg for Associated Signature Containers (contract R-9.5): a
/// Time-Stamping Authority and an OCSP responder each run on their own loopback Kestrel host, and every
/// <c>TimeStampReq</c>/<c>TimeStampResp</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc3161#section-3.4">IETF RFC 3161 §3.4</see>) and
/// <c>OCSPRequest</c>/<c>OCSPResponse</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc6960#appendix-A">IETF RFC 6960 Appendix A</see>) of the whole
/// container flow crosses those real sockets as DER wire bytes — the signature's time-stamp, the OCSP response
/// placed as B-LT material, the token applied to the <c>ASiCArchiveManifest</c> of Annex A.7 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see>, the Evidence Record's own initial Archive Timestamp, and its Timestamp
/// Renewal of <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.2">IETF RFC 4998 clause 5.2</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Host A (TSA)</strong> answers every <c>TimeStampReq</c> with a genuine token minted through the
/// independent BouncyCastle Time-Stamp Protocol oracle (<see cref="MintingTimestampResponder"/>), and is
/// RECONFIGURED between the phases of the flow so that each token states its own generation time — an authority
/// that answered every request at one instant could not be asked for a renewal at all, since RFC 4998 clause 5.1
/// requires ascending times and the shipped renewal refuses a token that does not advance.
/// <strong>Host B (OCSP)</strong> answers every <c>OCSPRequest</c> with a genuine response minted through the
/// independent BouncyCastle OCSP oracle (<see cref="MintingOcspResponder"/>). Both are the binary-body
/// <see cref="BinaryHttpHost"/>.
/// </para>
/// <para>
/// <strong>Live, OCSP-driven revocation checking on both sides.</strong> The archiving party decides the
/// signer's status through a real round trip to Host B and places the RETAINED response as the CAdES object's
/// B-LT material; the verifying party decides revocation for the signer's AND the Time-Stamping Authority's
/// certificates through its OWN live round trips during validation, which is why the responder answers for a
/// certificate set matched by serial number rather than one fixed target.
/// </para>
/// <para>
/// <strong>Object-lifetime discipline.</strong> As in the CAdES wire leg, the archiving party's certificates
/// and keys cannot be released before the verifying party runs, because Host B must keep answering correctly
/// through the verifier's own live call. The firewall demonstrated here is therefore the contract's own — the
/// verifier reconstructs from the container's wire bytes and the trust anchor's octets and touches nothing else
/// — enforced at the level of what the VERIFYING code path reads, never at the level of process memory
/// lifetime, which a live second network peer cannot honour.
/// </para>
/// </remarks>
[TestClass]
internal sealed class AsicMultiServerWireFlowTests
{
    /// <summary>The <c>Content-Type</c> RFC 3161 §3.4 gives a <c>TimeStampReq</c>.</summary>
    private const string TimestampQueryContentType = "application/timestamp-query";

    /// <summary>The <c>Content-Type</c> RFC 3161 §3.4 gives a <c>TimeStampResp</c>.</summary>
    private const string TimestampReplyContentType = "application/timestamp-reply";

    /// <summary>The <c>Content-Type</c> RFC 6960 Appendix A gives an <c>OCSPRequest</c>.</summary>
    private const string OcspRequestContentType = "application/ocsp-request";

    /// <summary>The <c>Content-Type</c> RFC 6960 Appendix A gives an <c>OCSPResponse</c>.</summary>
    private const string OcspResponseContentType = "application/ocsp-response";

    /// <summary>The first data object the container carries.</summary>
    private static byte[] FirstDataObject { get; } = [.. "the first data object of the wire flow"u8];

    /// <summary>The second data object the container carries.</summary>
    private static byte[] SecondDataObject { get; } = [.. "the second data object of the wire flow"u8];

    /// <summary>The entry names the two data objects are carried under, which are also what the Evidence Record protects.</summary>
    private static string[] DataObjectEntryNames { get; } = ["first.txt", "records/second.bin"];


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Creates an ASiC-E container, signs it, raises it to B-LT with a live OCSP response, starts the Annex A.7
    /// chain by time-stamping the archive manifest, attaches an Evidence Record and renews that record by
    /// Timestamp Renewal — every one of those exchanges crossing a real socket to its own Kestrel host — and a
    /// verifying party reconstructed from the FINAL container's bytes alone reaches
    /// <c>AsicContainerValidationStatus.Valid</c> with the embedded CAdES object at <c>TOTAL-PASSED</c> and its
    /// revocation decided by the verifier's own live OCSP round trip.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "authorityMinted.Certificate/.Key ownership transfers immediately into the X509ChainTestRingNode wrapping them (authority, below); MintedCertificate itself holds no resource beyond those two properties, so nothing is leaked by not calling its own Dispose separately.")]
    public async Task CreatesAugmentsAndRenewsAcrossTwoKestrelHostsAndTheContainerBytesValidateWithLiveOcsp()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset containerInstant = signingTime;
        DateTimeOffset signatureTimestampTime = signingTime.AddHours(1);
        DateTimeOffset validationDataTime = signingTime.AddHours(2);
        DateTimeOffset containerArchiveTimestampTime = signingTime.AddHours(3);
        DateTimeOffset evidenceRecordArchiveTime = signingTime.AddHours(4);
        DateTimeOffset evidenceRecordRenewalTime = signingTime.AddHours(5);
        DateTimeOffset validationTime = signingTime.AddDays(30);
        DateTimeOffset notBefore = signingTime.AddYears(-1);
        DateTimeOffset notAfter = signingTime.AddYears(9);
        DateTimeOffset revocationThisUpdate = validationDataTime.AddMinutes(-30);
        DateTimeOffset revocationNextUpdate = signingTime.AddYears(1);

        //Host B (OCSP) starts first: the signer's and the Time-Stamping Authority's own certificates each need
        //its real address baked into an Authority Information Access entry before they can be minted.
        var ocspAdapter = new BinaryOcspHostAdapter();
        await using BinaryHttpHost ocspHost = await BinaryHttpHost.StartAsync(
            ocspAdapter.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string ocspResponderUri = new Uri(ocspHost.BaseAddress, "/ocsp").AbsoluteUri;
        X509Extension aia = OcspTestFixtures.CreateAuthorityInfoAccessExtension(
            OcspTestFixtures.UriAiaEntry(WellKnownOids.AccessMethodOcsp, ocspResponderUri));

        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);

        //The Time-Stamping Authority certificate needs the RFC 3161 §2.3 id-kp-timeStamping extended key usage
        //(which the shared minting helper does not add on its own) plus the Authority Information Access entry
        //above, so it is minted here rather than through X509ChainTestRing.CreateTimeStampingAuthority.
        var timeStampingEku = new X509EnhancedKeyUsageExtension(
            [new Oid(X509ChainTestRing.TimeStampingKeyPurposeOid)], critical: true);
        MintedCertificate authorityMinted = OcspTestFixtures.MintCertificate(
            root.Certificate, root.SigningKey, "asic-wire-tsa.example.test", notBefore, notAfter, [timeStampingEku, aia]);
        using X509ChainTestRingNode authority = new(X509ChainNodeRole.Leaf, authorityMinted.Certificate, authorityMinted.Key);

        using MintedCertificate signer = OcspTestFixtures.MintCertificate(
            root.Certificate, root.SigningKey, "asic-wire-signer.example.test", notBefore, notAfter, [aia]);

        ocspAdapter.Configure(new MintingOcspResponder(
            [signer.Certificate, authority.Certificate], root.Certificate, root.Certificate, root.SigningKey,
            OcspCertificateStatus.Good, revocationThisUpdate, revocationNextUpdate).FetchAsync);

        //Host A (TSA), reconfigured between phases so that each token states its own generation time.
        var tsaAdapter = new BinaryTsaHostAdapter();
        await using BinaryHttpHost tsaHost = await BinaryHttpHost.StartAsync(
            tsaAdapter.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string tsaUri = new Uri(tsaHost.BaseAddress, "/tsa").AbsoluteUri;

        using HttpClient tsaHttpClient = LoopbackTls.CreatePinnedHttpClient(tsaHost.Certificate);
        using HttpClient ocspHttpClient = LoopbackTls.CreatePinnedHttpClient(ocspHost.Certificate);
        var wireTsa = new WireTimestampTransport(tsaHttpClient);
        var wireOcsp = new WireOcspTransport(ocspHttpClient);

        using PkiCertificateMemory signerCertificate = OcspTestFixtures.ToCertificateCarrier(signer.Certificate);
        using PkiCertificateMemory rootCertificateForMinting = OcspTestFixtures.ToCertificateCarrier(root.Certificate);

        //=== The ASiC-E container, through the data-to-sign/signature-value split: the leaf's own bare platform
        //key signs phase one's output, the shape a remote signer uses. ===
        using AsicContainerSignaturePreparation preparation = await AsicContainerCreation.PrepareSignatureAsync(
            new AsicContainerSignatureContext
            {
                Shape = AsicContainerShape.Extended,
                DataObjects =
                [
                    new AsicDataObject { Name = DataObjectEntryNames[0], Content = FirstDataObject, MediaType = "text/plain" },
                    new AsicDataObject { Name = DataObjectEntryNames[1], Content = SecondDataObject }
                ],
                SignerCertificate = signerCertificate,
                SigningTime = signingTime,
                LastModified = containerInstant,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        byte[] signatureValueP1363 = signer.Key.SignData(
            preparation.SignaturePreparation.SigningInput.AsReadOnlySpan().ToArray(), HashAlgorithmName.SHA256);
        using IMemoryOwner<byte> signatureValueDer = EcdsaSignatureEncoding.ConvertP1363ToDer(
            signatureValueP1363, BaseMemoryPool.Shared, out int derLength);
        using AsicContainerCreationResult created = AsicContainerCreation.CompleteSignature(
            preparation, signerCertificate, CryptoAlgorithm.P256, signatureValueDer.Memory[..derLength],
            additionalCertificates: null, BaseMemoryPool.Shared);

        //=== B-T: a real TimeStampReq/TimeStampResp round trip to Host A. ===
        tsaAdapter.Configure(new MintingTimestampResponder(authority, [authority, root], signatureTimestampTime).FetchAsync);
        using AsicContainerAugmentationResult timestamped = await AsicContainerAugmentation.AddSignatureTimestampsAsync(
            new AsicContainerSignatureTimestampContext
            {
                Container = created.Container.AsReadOnlyMemory(),
                LastModified = containerInstant,
                TsaUri = tsaUri,
                FetchTimestampResponse = wireTsa.FetchAsync,
                SigningCertificate = signerCertificate
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        //=== B-LT: a real OCSPRequest/OCSPResponse round trip to Host B, whose RETAINED verified response
        //becomes the CAdES object's validation material (Annex A.7 item 1 b)'s SignedData route). ===
        var mintTimeRevocationChecker = new OcspRevocationChecker(wireOcsp.FetchAsync);
        using RetainedOcspResponse retained = await mintTimeRevocationChecker.CheckRetainingResponseAsync(
            signerCertificate, [rootCertificateForMinting], revocationThisUpdate.AddMinutes(5), BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(CertificateRevocationStatus.Good, retained.Status,
            "The signer's certificate is Good, decided through a real OCSPRequest/OCSPResponse round trip against Host B.");
        Assert.IsNotNull(retained.Response, "A verified response retains its DER octets for placement as B-LT material.");

        using AsicContainerAugmentationResult longTerm = AsicContainerAugmentation.AddSignatureValidationData(
            new AsicContainerValidationDataContext
            {
                Container = timestamped.Container.AsReadOnlyMemory(),
                LastModified = containerInstant,
                ValidationMaterial = new CAdESValidationMaterial
                {
                    Certificates = [rootCertificateForMinting],
                    OcspResponses = [retained.Response!]
                }
            },
            BaseMemoryPool.Shared);

        //=== Annex A.7: the ASiCArchiveManifest is written and a token over IT crosses the wire to Host A. ===
        tsaAdapter.Configure(new MintingTimestampResponder(authority, [authority, root], containerArchiveTimestampTime).FetchAsync);
        using AsicContainerAugmentationResult archiveChain = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            new AsicContainerArchiveTimestampContext
            {
                Container = longTerm.Container.AsReadOnlyMemory(),
                LastModified = containerInstant,
                TsaUri = tsaUri,
                FetchTimestampResponse = wireTsa.FetchAsync,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync,
                ParseManifest = AsicManifestXmlBinding.ParseAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(containerArchiveTimestampTime, archiveChain.ArchiveTimestampTime,
            "The token the container-level chain committed to is the one Host A minted over the wire.");

        //=== The Evidence Record over the two data files, its initial Archive Timestamp acquired over the wire. ===
        tsaAdapter.Configure(new MintingTimestampResponder(authority, [authority, root], evidenceRecordArchiveTime).FetchAsync);
        AsicAttachedEvidenceRecord attachment = await AsicEvidenceRecordAttaching.AttachAsync(
            new AsicEvidenceRecordAttachmentContext
            {
                Container = archiveChain.Container.AsReadOnlyMemory(),
                ProtectedEntryNames = DataObjectEntryNames,
                LastModified = containerInstant,
                TsaUri = tsaUri,
                FetchTimestampResponse = wireTsa.FetchAsync,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        using(attachment.Container)
        using(attachment.EvidenceRecord)
        {
            Assert.AreEqual(evidenceRecordArchiveTime, attachment.ArchiveTime,
                "The record's initial Archive Timestamp is the token Host A minted for it over the wire.");

            //=== The Timestamp Renewal of RFC 4998 clause 5.2, its token acquired over the same socket. ===
            tsaAdapter.Configure(new MintingTimestampResponder(authority, [authority, root], evidenceRecordRenewalTime).FetchAsync);
            using EvidenceRecordRenewal renewal = await EvidenceRecords.RenewTimestampAsync(
                new EvidenceRecordTimestampRenewalContext
                {
                    EvidenceRecords = [attachment.EvidenceRecord],
                    TsaUri = tsaUri,
                    FetchTimestampResponse = wireTsa.FetchAsync
                },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(evidenceRecordRenewalTime, renewal.ArchiveTime,
                "The renewal's own Archive Timestamp is the one Host A minted at the later instant it was reconfigured to.");

            using PooledMemory finalContainer = AsicEvidenceRecordAttaching.ReplaceEntry(
                attachment.Container.AsReadOnlyMemory(), attachment.EvidenceRecordEntryName,
                renewal.EvidenceRecords[0].AsReadOnlyMemory(), containerInstant, BaseMemoryPool.Shared);

            byte[] containerBytes = finalContainer.AsReadOnlySpan().ToArray();
            byte[] trustAnchorBytes = root.Certificate.RawData;

            //=== Verifying party: it reads the final container's octets and the trust anchor's octets and nothing
            //else, and decides revocation for the signer's AND the authority's certificates through its own live
            //OCSPRequest/OCSPResponse round trips to Host B. ===
            using PkiCertificateMemory trustAnchor = ToCarrier(trustAnchorBytes, PkiCertificateTags.X509Certificate);
            var x509Constraints = new X509ValidationConstraints
            {
                TrustAnchors = [new TrustAnchorConstraint(trustAnchor, SunsetDate: null)]
            };
            var cryptographicConstraints = new CryptographicConstraints
            {
                Entries =
                [
                    new AlgorithmReliabilityEntry(
                        new PkiAlgorithmIdentifier(X509ChainTestRing.EcdsaWithSha256SignatureOid),
                        MinimumKeySizeBits: X509ChainTestRing.SigningKeySizeBits,
                        TrustedUntil: null),
                    new AlgorithmReliabilityEntry(PkiAlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, TrustedUntil: null)
                ]
            };
            var constraints = new SignatureValidationConstraints
            {
                Identifier = SignatureValidationPolicyIdentifier.CallerSuppliedConstraints,
                X509 = x509Constraints,
                Cryptographic = cryptographicConstraints,
                SignatureElements = SignatureElementsConstraints.None
            };

            var completer = new CertificateChainCompleter([trustAnchor]);
            var verifyTimeRevocationChecker = new OcspRevocationChecker(wireOcsp.FetchAsync);
            var seams = new SignatureValidationSeams
            {
                Format = CAdESSignatureFacts.Seam,
                CompleteCertificateChain = completer.CompleteAsync,
                ValidateCertificateChain = MicrosoftX509Functions.ValidateChainAsync,
                CheckRevocation = verifyTimeRevocationChecker.CheckAsync
            };

            //The container layer replaces the Signed Data Object, the Signer's Documents and the Evidence Records
            //per embedded object; the trust anchor stands in as the template's placeholder.
            var inputs = new SignatureValidationInputs
            {
                SignedDataObject = trustAnchor,
                Constraints = constraints,
                TimestampConstraints = constraints,
                CertificateValidationData = [trustAnchor]
            };

            using AsicContainerValidationResult result = await AsicContainerValidation.ValidateAsync(
                new AsicContainerValidationContext
                {
                    Container = containerBytes,
                    CurrentTime = validationTime,
                    ParseManifest = AsicManifestXmlBinding.ParseAsync,
                    SignatureInputs = inputs,
                    SignatureSeams = seams
                },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(AsicContainerValidationStatus.Valid, result.Status,
                $"A container created, augmented and renewed over two real Kestrel hosts validates from its own wire octets ({result.FailureReason}).");
            Assert.AreEqual(SignatureValidationIndication.TotalPassed, result.Signatures.Single().Outcome!.Conclusion.Indication,
                "The embedded CAdES object reaches TOTAL-PASSED with revocation decided by a live OCSP round trip over a real socket.");

            AsicEvidenceRecordValidation record = result.EvidenceRecords.Single();
            Assert.AreEqual(AsicContainerValidationStatus.Valid, record.Status, $"The renewed Evidence Record proves what the container states it protects ({record.FailureReason}).");
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, record.VerificationStatus, "RFC 4998 clause 5.3 held across the renewal.");
            Assert.AreEqual(evidenceRecordArchiveTime, record.InitialArchiveTime,
                "The instant the record proves its targets existed at is its initial Archive Timestamp's, which Host A minted before the renewal.");
            Assert.AreSequenceEqual(DataObjectEntryNames, record.ProtectedEntryNames.ToArray(), "The record proves the manifest's DataObjectReference targets.");

            AsicArchiveManifestChainLink link = result.ArchiveManifestChain.Single();
            Assert.AreEqual(AsicManifestNaming.FixedArchiveManifestEntryName, link.EntryName, "Annex A.7 item 1 c a): the first link carries the fixed name.");
            AsicTimeAssertionValidation archiveToken = result.TimeAssertions.Single(t => t.EntryName == link.TimestampEntryName);
            Assert.AreEqual(AsicContainerValidationStatus.Valid, archiveToken.Status, $"The archive manifest's token binds it ({archiveToken.FailureReason}).");
            Assert.AreEqual(containerArchiveTimestampTime, archiveToken.GenerationTime,
                "The instant the chain asserts is the one Host A stated in the token that crossed the wire.");
        }
    }


    /// <summary>
    /// Negative leg over a real socket: a Time-Stamping Authority that answers a renewal request with a genuine,
    /// correctly-signed token whose <c>genTime</c> lies BEFORE the Archive Timestamp being renewed — a real
    /// authority misbehaviour that nothing in RFC 3161 precludes — is refused, because
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.1">RFC 4998 clause 5.1</see> orders an
    /// <c>ArchiveTimeStampChain</c> ascending by time of time-stamp, so a record built on such a token could
    /// never verify. Nothing is written: the record the renewal was asked to renew is byte-for-byte unchanged.
    /// </summary>
    [TestMethod]
    public async Task ARenewalTokenPredatingTheArchiveTimestampItRenewsIsRefusedOverTheWire()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset archiveTime = timeProvider.GetUtcNow().AddHours(4);
        DateTimeOffset backwardsTime = timeProvider.GetUtcNow().AddHours(1);
        DateTimeOffset notBefore = timeProvider.GetUtcNow().AddYears(-1);
        DateTimeOffset notAfter = timeProvider.GetUtcNow().AddYears(9);

        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: notBefore, notAfter: notAfter);

        var tsaAdapter = new BinaryTsaHostAdapter();
        await using BinaryHttpHost tsaHost = await BinaryHttpHost.StartAsync(
            tsaAdapter.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string tsaUri = new Uri(tsaHost.BaseAddress, "/tsa").AbsoluteUri;
        using HttpClient tsaHttpClient = LoopbackTls.CreatePinnedHttpClient(tsaHost.Certificate);
        var wireTsa = new WireTimestampTransport(tsaHttpClient);

        tsaAdapter.Configure(new MintingTimestampResponder(authority, [authority, root], archiveTime).FetchAsync);
        using EvidenceRecordCreation creation = await EvidenceRecords.CreateInitialAsync(
            new EvidenceRecordCreationContext
            {
                DataObjectGroups = [new EvidenceRecordDataObjectGroup { DataObjects = [new ReadOnlyMemory<byte>(FirstDataObject)] }],
                DigestAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = tsaUri,
                FetchTimestampResponse = wireTsa.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        byte[] recordBeforeTheAttempt = creation.EvidenceRecords[0].AsReadOnlySpan().ToArray();

        //The authority is reconfigured to answer at an instant BEFORE the one it already answered at, which is
        //exactly what a renewal may not accept.
        tsaAdapter.Configure(new MintingTimestampResponder(authority, [authority, root], backwardsTime).FetchAsync);
        EvidenceRecordCreationException exception = await Assert.ThrowsExactlyAsync<EvidenceRecordCreationException>(
            async () => await EvidenceRecords.RenewTimestampAsync(
                new EvidenceRecordTimestampRenewalContext
                {
                    EvidenceRecords = [creation.EvidenceRecords[0]],
                    TsaUri = tsaUri,
                    FetchTimestampResponse = wireTsa.FetchAsync
                },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordCreationFailureKind.RenewalNotAfterSource, exception.FailureKind,
            "RFC 4998 clause 5.1: the Archive Timestamps of a chain ascend in time, so a renewal token predating what it renews is refused for exactly that reason.");
        Assert.AreSequenceEqual(recordBeforeTheAttempt, creation.EvidenceRecords[0].AsReadOnlySpan().ToArray(),
            "A refused renewal writes nothing: the record it was asked to renew is byte-for-byte unchanged.");
    }


    /// <summary>Copies received DER octets into a pooled carrier of the stated kind.</summary>
    /// <param name="derBytes">The octets to copy.</param>
    /// <param name="tag">The kind discriminator the carrier states.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToCarrier(byte[] derBytes, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>
    /// Bridges a <see cref="BinaryHttpHost"/> to a <see cref="FetchTimestampResponseAsyncDelegate"/>-shaped
    /// responder that the flow RECONFIGURES between phases, so one authority host can state a different
    /// generation time for each token the flow asks it for. Answers <c>503</c> for any request received before
    /// <see cref="Configure"/> runs. A configured object holding the responder delegate, not a closure over test
    /// state.
    /// </summary>
    private sealed class BinaryTsaHostAdapter
    {
        /// <summary>The responder every request is currently answered through, or <see langword="null"/> before the first configuration.</summary>
        private FetchTimestampResponseAsyncDelegate? responder;


        /// <summary>Sets the responder every subsequent request is answered through.</summary>
        /// <param name="value">The RFC 3161 responder.</param>
        internal void Configure(FetchTimestampResponseAsyncDelegate value)
        {
            responder = value;
        }


        /// <summary>Implements <see cref="BinaryHttpHandlerDelegate"/>.</summary>
        /// <param name="request">The buffered request.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response.</returns>
        internal async Task<BinaryHttpResponse> HandleAsync(BinaryHttpRequest request, CancellationToken cancellationToken)
        {
            if(responder is not { } configured)
            {
                return new BinaryHttpResponse { StatusCode = 503 };
            }

            using PkiCertificateMemory requestCarrier = ToCarrier(request.Body, PkiCertificateTags.TimestampRequest);
            PkiCertificateMemory? response = await configured(
                new TimestampFetchContext { TsaUri = request.Path, Request = requestCarrier },
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            if(response is null)
            {
                return new BinaryHttpResponse { StatusCode = 502 };
            }

            using(response)
            {
                return new BinaryHttpResponse
                {
                    StatusCode = 200,
                    ContentType = TimestampReplyContentType,
                    Body = response.AsReadOnlySpan().ToArray()
                };
            }
        }
    }


    /// <summary>
    /// Bridges a <see cref="BinaryHttpHost"/> to a <see cref="FetchOcspResponseAsyncDelegate"/>-shaped
    /// responder, configured AFTER the host starts (its own certificates' Authority Information Access entries
    /// need the host's real, only-known-once-bound address). Answers <c>503</c> for any request received before
    /// <see cref="Configure"/> runs.
    /// </summary>
    private sealed class BinaryOcspHostAdapter
    {
        /// <summary>The responder every request is currently answered through, or <see langword="null"/> before the first configuration.</summary>
        private FetchOcspResponseAsyncDelegate? responder;


        /// <summary>Sets the responder every subsequent request is answered through.</summary>
        /// <param name="value">The RFC 6960 responder.</param>
        internal void Configure(FetchOcspResponseAsyncDelegate value)
        {
            responder = value;
        }


        /// <summary>Implements <see cref="BinaryHttpHandlerDelegate"/>.</summary>
        /// <param name="request">The buffered request.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response.</returns>
        internal async Task<BinaryHttpResponse> HandleAsync(BinaryHttpRequest request, CancellationToken cancellationToken)
        {
            if(responder is not { } configured)
            {
                return new BinaryHttpResponse { StatusCode = 503 };
            }

            using PkiCertificateMemory requestCarrier = ToCarrier(request.Body, PkiCertificateTags.OcspRequest);
            PkiCertificateMemory? response = await configured(
                new OcspFetchContext { ResponderUri = request.Path, Request = requestCarrier },
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            if(response is null)
            {
                return new BinaryHttpResponse { StatusCode = 502 };
            }

            using(response)
            {
                return new BinaryHttpResponse
                {
                    StatusCode = 200,
                    ContentType = OcspResponseContentType,
                    Body = response.AsReadOnlySpan().ToArray()
                };
            }
        }
    }


    /// <summary>
    /// The client-side RFC 3161 §3.4 HTTP binding: implements <see cref="FetchTimestampResponseAsyncDelegate"/>
    /// over a real <see cref="HttpClient"/> POST. A configured object holding the client, not a closure.
    /// </summary>
    private sealed class WireTimestampTransport
    {
        /// <summary>The client, already pinned to the Time-Stamping Authority host's certificate.</summary>
        private readonly HttpClient httpClient;


        /// <summary>Initializes a new <see cref="WireTimestampTransport"/> over a pinned client.</summary>
        /// <param name="httpClient">The client, already pinned to the Time-Stamping Authority host's certificate.</param>
        internal WireTimestampTransport(HttpClient httpClient)
        {
            this.httpClient = httpClient;
        }


        /// <summary>Implements <see cref="FetchTimestampResponseAsyncDelegate"/>.</summary>
        /// <param name="context">The authority address and the request bytes.</param>
        /// <param name="pool">The memory pool the returned response is rented from.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response, or <see langword="null"/> on a transport failure.</returns>
        internal async ValueTask<PkiCertificateMemory?> FetchAsync(TimestampFetchContext context, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            using var content = new ByteArrayContent(context.Request.AsReadOnlySpan().ToArray());
            content.Headers.ContentType = new MediaTypeHeaderValue(TimestampQueryContentType);

            HttpResponseMessage httpResponse;
            try
            {
                httpResponse = await httpClient.PostAsync(new Uri(context.TsaUri), content, cancellationToken).ConfigureAwait(false);
            }
            catch(HttpRequestException)
            {
                return null;
            }

            using(httpResponse)
            {
                if(!httpResponse.IsSuccessStatusCode)
                {
                    return null;
                }

                byte[] bytes = await httpResponse.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
                IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
                bytes.CopyTo(owner.Memory.Span);

                return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampResponse);
            }
        }
    }


    /// <summary>
    /// The client-side RFC 6960 Appendix A HTTP binding: implements <see cref="FetchOcspResponseAsyncDelegate"/>
    /// over a real <see cref="HttpClient"/> POST. A configured object holding the client, not a closure.
    /// </summary>
    private sealed class WireOcspTransport
    {
        /// <summary>The client, already pinned to the OCSP responder host's certificate.</summary>
        private readonly HttpClient httpClient;


        /// <summary>Initializes a new <see cref="WireOcspTransport"/> over a pinned client.</summary>
        /// <param name="httpClient">The client, already pinned to the OCSP responder host's certificate.</param>
        internal WireOcspTransport(HttpClient httpClient)
        {
            this.httpClient = httpClient;
        }


        /// <summary>Implements <see cref="FetchOcspResponseAsyncDelegate"/>.</summary>
        /// <param name="context">The responder address (the certificate's own Authority Information Access entry) and the request bytes.</param>
        /// <param name="pool">The memory pool the returned response is rented from.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response, or <see langword="null"/> on a transport failure.</returns>
        internal async ValueTask<PkiCertificateMemory?> FetchAsync(OcspFetchContext context, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            using var content = new ByteArrayContent(context.Request.AsReadOnlySpan().ToArray());
            content.Headers.ContentType = new MediaTypeHeaderValue(OcspRequestContentType);

            HttpResponseMessage httpResponse;
            try
            {
                httpResponse = await httpClient.PostAsync(new Uri(context.ResponderUri), content, cancellationToken).ConfigureAwait(false);
            }
            catch(HttpRequestException)
            {
                return null;
            }

            using(httpResponse)
            {
                if(!httpResponse.IsSuccessStatusCode)
                {
                    return null;
                }

                byte[] bytes = await httpResponse.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
                IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
                bytes.CopyTo(owner.Memory.Span);

                return new PkiCertificateMemory(owner, PkiCertificateTags.OcspResponse);
            }
        }
    }
}
