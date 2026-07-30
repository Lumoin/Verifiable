using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
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
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using PkiAlgorithmIdentifier = Verifiable.Cryptography.Pki.AlgorithmIdentifier;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The multi-server Kestrel wire e2e leg for CAdES creation and long-term augmentation (contract R-9.5 / DoD
/// 2a, the amendment's exemplar shape): a Time-Stamping Authority and an OCSP responder each run on their own
/// loopback Kestrel host, and the signer's and verifier's own <c>TimeStampReq</c>/<c>TimeStampResp</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc3161#section-3.4">RFC 3161 §3.4</see>) and
/// <c>OCSPRequest</c>/<c>OCSPResponse</c> (<see href="https://www.rfc-editor.org/rfc/rfc6960#appendix-A">RFC
/// 6960 Appendix A</see>) exchanges cross those real sockets as DER wire bytes.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Host A (TSA)</strong> answers every <c>TimeStampReq</c> it receives with a genuine token minted
/// through the independent BouncyCastle TSP oracle (<see cref="MintingTimestampResponder"/>, stage 5's whole
/// TSA behaviour minus the socket — unmodified, now driven by a real HTTP POST rather than an in-process call).
/// <strong>Host B (OCSP)</strong> answers every <c>OCSPRequest</c> with a genuine response minted through the
/// independent BouncyCastle OCSP oracle (<see cref="MintingOcspResponder"/>, the OCSP sibling this leg adds).
/// Both hosts are the binary-body <see cref="BinaryHttpHost"/> sibling of <see cref="MinimalHttpHost"/>.
/// </para>
/// <para>
/// <strong>Live, OCSP-driven revocation checking (closes stage-8 flag 2).</strong> The stage-8 capstone's
/// verifying party decided revocation status from CRL material embedded in the received Signed Data Object. The
/// verifying party here decides it through a real <see cref="OcspRevocationChecker"/> that makes its own live
/// <c>OCSPRequest</c> to Host B during validation — the certificate chains of the CAdES signer AND of the
/// Time-Stamping Authority (both certificates <see cref="BasicSignatureValidation"/> chain-validates) are
/// checked this way, which is why <see cref="MintingOcspResponder"/> answers for a small certificate set
/// matched by serial number rather than one fixed target.
/// </para>
/// <para>
/// <strong>Object-lifetime discipline.</strong> Unlike the stage-8 in-process capstone, the signing party's
/// certificates and keys cannot be released before the verifying party runs: Host B must keep answering
/// correctly through the verifying party's OWN live OCSP call, which needs the same signing-key material the
/// responder was configured with. The firewall this leg demonstrates is therefore the one the contract's own
/// wording names — "the verifier reconstructs from wire bytes only... no shared objects/keys/salts" — enforced
/// at the level of what the VERIFYING CODE PATH touches (a byte array for the Signed Data Object, a byte array
/// for the trust anchor certificate, and the network), never at the level of process memory lifetime, which a
/// live second network peer cannot honour the way a capstone with only embedded material can.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CAdESMultiServerWireFlowTests
{
    /// <summary>The <c>Content-Type</c> RFC 3161 §3.4 gives a <c>TimeStampReq</c>.</summary>
    private const string TimestampQueryContentType = "application/timestamp-query";

    /// <summary>The <c>Content-Type</c> RFC 3161 §3.4 gives a <c>TimeStampResp</c>.</summary>
    private const string TimestampReplyContentType = "application/timestamp-reply";

    /// <summary>The <c>Content-Type</c> RFC 6960 Appendix A gives an <c>OCSPRequest</c>.</summary>
    private const string OcspRequestContentType = "application/ocsp-request";

    /// <summary>The <c>Content-Type</c> RFC 6960 Appendix A gives an <c>OCSPResponse</c>.</summary>
    private const string OcspResponseContentType = "application/ocsp-response";

    /// <summary>The content every minted signature encapsulates and covers.</summary>
    private static ReadOnlyMemory<byte> Content { get; } = new("the CAdES multi-server wire content"u8.ToArray());


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Mints B-B → B-T → B-LT → B-LTA with every <c>TimeStampReq</c>/<c>TimeStampResp</c> and
    /// <c>OCSPRequest</c>/<c>OCSPResponse</c> crossing a real socket to its own Kestrel host, then a verifying
    /// party reconstructed from the resulting wire bytes runs the full clause 5.5/5.6 processes with revocation
    /// decided by a LIVE OCSP round trip to Host B, reaching <c>TOTAL-PASSED</c>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "authorityMinted.Certificate/.Key ownership transfers immediately into the X509ChainTestRingNode wrapping them (authority, below); MintedCertificate itself holds no resource beyond those two properties, so nothing is leaked by not calling its own Dispose separately.")]
    public async Task CreatesAugmentsToBLtaAndReachesTotalPassedAcrossTwoKestrelHostsWithLiveOcspDrivenRevocation()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset signatureTimestampTime = signingTime.AddHours(1);
        DateTimeOffset validationDataTime = signingTime.AddHours(2);
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

        //The Time-Stamping Authority certificate needs the RFC 3161 §2.3 id-kp-timeStamping EKU (which the
        //shared OcspTestFixtures.MintCertificate helper does not add on its own) plus the AIA entry above, so it
        //is minted here rather than through X509ChainTestRing.CreateTimeStampingAuthority.
        var timeStampingEku = new X509EnhancedKeyUsageExtension(
            [new Oid(X509ChainTestRing.TimeStampingKeyPurposeOid)], critical: true);
        MintedCertificate authorityMinted = OcspTestFixtures.MintCertificate(
            root.Certificate, root.SigningKey, "cades-wire-tsa.example.test", notBefore, notAfter, [timeStampingEku, aia]);
        using X509ChainTestRingNode authority = new(X509ChainNodeRole.Leaf, authorityMinted.Certificate, authorityMinted.Key);

        using MintedCertificate signer = OcspTestFixtures.MintCertificate(
            root.Certificate, root.SigningKey, "cades-wire-signer.example.test", notBefore, notAfter, [aia]);

        ocspAdapter.Configure(new MintingOcspResponder(
            [signer.Certificate, authority.Certificate], root.Certificate, root.Certificate, root.SigningKey,
            OcspCertificateStatus.Good, revocationThisUpdate, revocationNextUpdate).FetchAsync);

        //Host A (TSA), answering every request with a genuine token minted through stage 5's independent oracle.
        var tsaResponder = new MintingTimestampResponder(authority, [authority, root], signatureTimestampTime);
        await using BinaryHttpHost tsaHost = await BinaryHttpHost.StartAsync(
            new BinaryTsaHostAdapter(tsaResponder.FetchAsync).HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string tsaUri = new Uri(tsaHost.BaseAddress, "/tsa").AbsoluteUri;

        using HttpClient tsaHttpClient = LoopbackTls.CreatePinnedHttpClient(tsaHost.Certificate);
        using HttpClient ocspHttpClient = LoopbackTls.CreatePinnedHttpClient(ocspHost.Certificate);
        var wireTsa = new WireTimestampTransport(tsaHttpClient);
        var wireOcsp = new WireOcspTransport(ocspHttpClient);

        using PkiCertificateMemory signerCertificate = OcspTestFixtures.ToCertificateCarrier(signer.Certificate);
        using PkiCertificateMemory rootCertificateForMinting = OcspTestFixtures.ToCertificateCarrier(root.Certificate);

        //=== B-B, through the data-to-sign/signature-value split (R-3): phase (1)'s output is signed by the
        //leaf's own bare platform key, the shape a remote signer (CSC, ETSI TS 119 432) uses. ===
        using CAdESSignaturePreparation preparation = await CAdESSignatureCreation.PrepareAsync(
            signerCertificate, Content, null, PkiDigestAlgorithm.Sha256, signingTime, algorithmConstraints: null,
            cmsAlgorithmProtectionSignatureAlgorithmOid: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] signatureValueP1363 = signer.Key.SignData(preparation.SigningInput.AsReadOnlySpan().ToArray(), HashAlgorithmName.SHA256);
        using IMemoryOwner<byte> signatureValueDer = EcdsaSignatureEncoding.ConvertP1363ToDer(signatureValueP1363, BaseMemoryPool.Shared, out int derLength);
        using CmsSignedData baseline = CAdESSignatureCreation.Complete(
            preparation, signerCertificate, CryptoAlgorithm.P256, signatureValueDer.Memory[..derLength], additionalCertificates: null, BaseMemoryPool.Shared);

        //=== B-T: a real TimeStampReq/TimeStampResp round trip to Host A. ===
        using CmsSignedData timestamped = await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new CAdESSignatureTimestampContext
            {
                SignedData = baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = tsaUri,
                FetchResponse = wireTsa.FetchAsync,
                SigningCertificate = signerCertificate
            },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //=== B-LT: a real OCSPRequest/OCSPResponse round trip to Host B; the RETAINED, verified response bytes
        //(stage 5's CheckRetainingResponseAsync surface, now fed by a real socket) become the B-LT material. ===
        var mintTimeRevocationChecker = new OcspRevocationChecker(wireOcsp.FetchAsync);
        using RetainedOcspResponse retained = await mintTimeRevocationChecker.CheckRetainingResponseAsync(
            signerCertificate, [rootCertificateForMinting], revocationThisUpdate.AddMinutes(5), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(CertificateRevocationStatus.Good, retained.Status,
            "The signer's certificate is Good, decided through a real OCSPRequest/OCSPResponse round trip against Host B.");
        Assert.IsNotNull(retained.Response, "A verified response retains its DER octets for placement as B-LT material.");

        using CmsSignedData longTerm = CAdESSignatureAugmentation.AddValidationData(
            timestamped, signerIndex: 0,
            new CAdESValidationMaterial { Certificates = [rootCertificateForMinting], OcspResponses = [retained.Response!] },
            BaseMemoryPool.Shared);

        //=== B-LTA: a second real TimeStampReq/TimeStampResp round trip to Host A. ===
        using CmsSignedData archived = await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new CAdESArchiveTimestampContext
            {
                SignedData = longTerm,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = tsaUri,
                FetchResponse = wireTsa.FetchAsync,
                ValidationMaterial = CAdESValidationMaterial.None,
                SigningCertificate = signerCertificate
            },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] sdoBytes = archived.AsReadOnlySpan().ToArray();
        byte[] trustAnchorBytes = root.Certificate.RawData;

        //=== Verifying party: reconstructs from the wire bytes alone (SignedDataObject + trust anchor octets);
        //revocation is decided by the verifier's OWN live OCSPRequest/OCSPResponse round trip to Host B for
        //BOTH the signer's certificate and the Time-Stamping Authority's own certificate — OCSP-DRIVEN, not
        //read from embedded material (closes stage-8 flag 2). ===
        using CmsSignedData received = CmsSignedData.FromBytes(sdoBytes, BaseMemoryPool.Shared);
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

            //Clause 5.6.3.4 step 3): with this left false the current-time process alone (already Passed here)
            //would short-circuit the whole demonstration; asserting it exercises the archive time-stamp's own
            //coverage and proof-of-existence extraction for real, mirroring the stage-8 capstone's own finding.
            SignatureElements = new SignatureElementsConstraints { RequireLongTermAvailabilityAttributeValidity = true }
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

        var inputs = new SignatureValidationInputs
        {
            SignedDataObject = received,
            Constraints = constraints,
            TimestampConstraints = constraints
        };

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            inputs, seams, SignatureValidationProcessSelection.LongTermAvailability, SignatureValidationCapabilities.All,
            validationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.TotalPassed, outcome.Conclusion.Indication,
            "Creation and augmentation to B-LTA over two real Kestrel hosts, verified with live OCSP-driven revocation over a real socket, reaches TOTAL_PASSED.");
    }


    /// <summary>
    /// The genuine offline/archived case: a signature raised to B-LTA over the live Time-Stamping Authority host
    /// carries an OCSP response as its B-LT validation material, and a verifying party reconstructed from the
    /// wire bytes decides the signer's revocation status <em>from that embedded response</em>, through the
    /// shipped <see cref="OcspRevocationChecker"/>, with no OCSP responder reachable at all. The response the
    /// decision is read out of is the one the shipped <see cref="CAdESSignatureFacts"/> surfaces from
    /// <c>SignedData.crls.other</c> (RFC 5940 §2's <c>id-ri-ocsp-response</c>, clause 5.4.2.2) — the mirror of
    /// the live-responder leg above, and the leg a reader recognising only <c>id-pkix-ocsp-basic</c> could never
    /// pass, since it would surface nothing for the offline checker to decide from.
    /// </summary>
    [TestMethod]
    public async Task ARevocationDecisionIsMadeFromTheEmbeddedResponseWithNoLiveResponder()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset signatureTimestampTime = signingTime.AddHours(1);
        DateTimeOffset notBefore = signingTime.AddYears(-1);
        DateTimeOffset notAfter = signingTime.AddYears(9);
        DateTimeOffset revocationThisUpdate = signingTime.AddMinutes(-30);
        DateTimeOffset revocationNextUpdate = signingTime.AddYears(1);
        DateTimeOffset validationTime = signingTime.AddDays(30);

        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: notBefore, notAfter: notAfter);

        //The signer carries an OCSP Authority Information Access entry so a checker has a responder URI to try,
        //but that address is never bound to a live host — the whole point of this leg is that none answers.
        X509Extension aia = OcspTestFixtures.CreateAuthorityInfoAccessExtension(
            OcspTestFixtures.UriAiaEntry(WellKnownOids.AccessMethodOcsp, "http://ocsp.offline.example.test/"));
        using MintedCertificate signer = OcspTestFixtures.MintCertificate(
            root.Certificate, root.SigningKey, "cades-wire-offline-signer.example.test", notBefore, notAfter, [aia]);
        using PkiCertificateMemory signerCertificate = OcspTestFixtures.ToCertificateCarrier(signer.Certificate);
        using PkiCertificateMemory rootCertificateForMinting = OcspTestFixtures.ToCertificateCarrier(root.Certificate);

        //The OCSP response is minted directly through the independent oracle — there is no OCSP host in this
        //test — and embedded as B-LT material: the archived response a long-preserved signature travels with.
        using PkiCertificateMemory embeddedOcsp = OcspTestFixtures.MintOcspResponse(
            signer.Certificate, root.Certificate, OcspCertIdDigestAlgorithm.Sha256, root.Certificate, root.SigningKey,
            responderIdByKey: false, embeddedCertificates: [root.Certificate],
            OcspCertificateStatus.Good, revocationThisUpdate, revocationNextUpdate);

        //Host A (TSA) is the only server this leg runs; both time-stamps cross a real socket to it.
        var tsaResponder = new MintingTimestampResponder(authority, [authority, root], signatureTimestampTime);
        await using BinaryHttpHost tsaHost = await BinaryHttpHost.StartAsync(
            new BinaryTsaHostAdapter(tsaResponder.FetchAsync).HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string tsaUri = new Uri(tsaHost.BaseAddress, "/tsa").AbsoluteUri;
        using HttpClient tsaHttpClient = LoopbackTls.CreatePinnedHttpClient(tsaHost.Certificate);
        var wireTsa = new WireTimestampTransport(tsaHttpClient);

        //B-B → B-T (live TSA) → B-LT (embedding the archived response) → B-LTA (live TSA).
        using CAdESSignaturePreparation preparation = await CAdESSignatureCreation.PrepareAsync(
            signerCertificate, Content, null, PkiDigestAlgorithm.Sha256, signingTime, algorithmConstraints: null,
            cmsAlgorithmProtectionSignatureAlgorithmOid: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] signatureValueP1363 = signer.Key.SignData(preparation.SigningInput.AsReadOnlySpan().ToArray(), HashAlgorithmName.SHA256);
        using IMemoryOwner<byte> signatureValueDer = EcdsaSignatureEncoding.ConvertP1363ToDer(signatureValueP1363, BaseMemoryPool.Shared, out int derLength);
        using CmsSignedData baseline = CAdESSignatureCreation.Complete(
            preparation, signerCertificate, CryptoAlgorithm.P256, signatureValueDer.Memory[..derLength], additionalCertificates: null, BaseMemoryPool.Shared);

        using CmsSignedData timestamped = await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new CAdESSignatureTimestampContext
            {
                SignedData = baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = tsaUri,
                FetchResponse = wireTsa.FetchAsync,
                SigningCertificate = signerCertificate
            },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using CmsSignedData longTerm = CAdESSignatureAugmentation.AddValidationData(
            timestamped, signerIndex: 0,
            new CAdESValidationMaterial { Certificates = [rootCertificateForMinting], OcspResponses = [embeddedOcsp] },
            BaseMemoryPool.Shared);

        using CmsSignedData archived = await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new CAdESArchiveTimestampContext
            {
                SignedData = longTerm,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = tsaUri,
                FetchResponse = wireTsa.FetchAsync,
                ValidationMaterial = CAdESValidationMaterial.None,
                SigningCertificate = signerCertificate
            },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] sdoBytes = archived.AsReadOnlySpan().ToArray();

        //=== Verifying party: reconstruct from the wire bytes, then decide revocation from the embedded response
        //surfaced out of them — no OCSP host runs in this test at all. ===
        using CmsSignedData received = CmsSignedData.FromBytes(sdoBytes, BaseMemoryPool.Shared);
        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = received }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.HasCount(1, facts.EmbeddedOcspResponses,
            "The archived response placed under RFC 5940 §2's id-ri-ocsp-response is surfaced back out of the wire bytes; a reader recognising only id-pkix-ocsp-basic would surface nothing for the offline decision below to read.");
        Assert.IsNotNull(facts.SigningCertificate, "The signer's own certificate travels in the Signed Data Object.");

        using PkiCertificateMemory trustAnchor = ToCarrier(root.Certificate.RawData, PkiCertificateTags.X509Certificate);
        var replay = new ReplayOcspTransport(facts.EmbeddedOcspResponses[0].AsReadOnlySpan());
        var offlineChecker = new OcspRevocationChecker(replay.FetchAsync, includeNonce: false, allowResponsesWithoutNonce: true);

        CertificateRevocationStatus status = await offlineChecker.CheckAsync(
            facts.SigningCertificate!, [trustAnchor], validationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Good, status,
            "The signer's revocation status is decided Good from the embedded, wire-surfaced OCSP response through the shipped checker — no OCSP responder was ever reachable in this test.");
    }


    /// <summary>
    /// Negative leg: a Time-Stamping Authority that returns a genuine, correctly-signed token minted over a
    /// message imprint that does NOT match the request's own — a real TSA misbehaviour shape RFC 3161 §2.4.2
    /// does not itself preclude — is rejected with a typed <see cref="TimestampAcquisitionException"/> before
    /// anything is attached; the signature the augmentation was asked to raise is left byte-for-byte unchanged.
    /// </summary>
    [TestMethod]
    public async Task ATimestampingAuthorityReturningATokenOverAMismatchedImprintIsRejectedAndNothingIsAttached()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset notBefore = signingTime.AddYears(-1);
        DateTimeOffset notAfter = signingTime.AddYears(9);

        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode signer = X509ChainTestRing.CreateLeaf(root, "cades-wire-mismatch-signer.example.test", timeProvider, notBefore: notBefore, notAfter: notAfter);
        using PkiCertificateMemory signerCertificate = OcspTestFixtures.ToCertificateCarrier(signer.Certificate);

        var mismatchedResponder = new MismatchedImprintTsaResponder(authority, [authority, root], signingTime.AddHours(1));
        await using BinaryHttpHost tsaHost = await BinaryHttpHost.StartAsync(
            new BinaryTsaHostAdapter(mismatchedResponder.FetchAsync).HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string tsaUri = new Uri(tsaHost.BaseAddress, "/tsa").AbsoluteUri;
        using HttpClient tsaHttpClient = LoopbackTls.CreatePinnedHttpClient(tsaHost.Certificate);
        var wireTsa = new WireTimestampTransport(tsaHttpClient);

        using CAdESSignaturePreparation preparation = await CAdESSignatureCreation.PrepareAsync(
            signerCertificate, Content, null, PkiDigestAlgorithm.Sha256, signingTime, algorithmConstraints: null,
            cmsAlgorithmProtectionSignatureAlgorithmOid: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] signatureValueP1363 = signer.SigningKey.SignData(preparation.SigningInput.AsReadOnlySpan().ToArray(), HashAlgorithmName.SHA256);
        using IMemoryOwner<byte> signatureValueDer = EcdsaSignatureEncoding.ConvertP1363ToDer(signatureValueP1363, BaseMemoryPool.Shared, out int derLength);
        using CmsSignedData baseline = CAdESSignatureCreation.Complete(
            preparation, signerCertificate, CryptoAlgorithm.P256, signatureValueDer.Memory[..derLength], additionalCertificates: null, BaseMemoryPool.Shared);
        byte[] baselineBytesBeforeTheAttempt = baseline.AsReadOnlySpan().ToArray();

        TimestampAcquisitionException exception = await Assert.ThrowsExactlyAsync<TimestampAcquisitionException>(
            async () => await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CAdESSignatureTimestampContext
                {
                    SignedData = baseline,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = tsaUri,
                    FetchResponse = wireTsa.FetchAsync,
                    SigningCertificate = signerCertificate
                },
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(TimestampAcquisitionFailureKind.MessageImprintMismatch, exception.FailureKind,
            "A token whose message imprint does not match the digest the request carried is refused for exactly that reason (RFC 3161 §2.4.2).");
        Assert.AreSequenceEqual(baselineBytesBeforeTheAttempt, baseline.AsReadOnlySpan().ToArray(),
            "A rejected token is never attached: the signature the augmentation was asked to raise is byte-for-byte unchanged.");
    }


    /// <summary>
    /// Negative leg: an OCSP responder that answers with a genuine, correctly-signed response whose
    /// <c>thisUpdate</c>/<c>nextUpdate</c> window has already elapsed at the validation instant — over a real
    /// socket — never verifies (RFC 6960 §3.2), so <see cref="OcspRevocationChecker"/> fails closed to
    /// <see cref="CertificateRevocationStatus.Unknown"/> rather than trusting it.
    /// </summary>
    [TestMethod]
    public async Task AStaleOcspResponseFromTheWireFailsRevocationCheckingClosed()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset notBefore = signingTime.AddYears(-1);
        DateTimeOffset notAfter = signingTime.AddYears(9);
        DateTimeOffset staleThisUpdate = signingTime.AddYears(-2);
        DateTimeOffset staleNextUpdate = signingTime.AddYears(-1);
        DateTimeOffset validationTime = signingTime;

        var ocspAdapter = new BinaryOcspHostAdapter();
        await using BinaryHttpHost ocspHost = await BinaryHttpHost.StartAsync(
            ocspAdapter.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string ocspResponderUri = new Uri(ocspHost.BaseAddress, "/ocsp").AbsoluteUri;

        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);
        X509Extension aia = OcspTestFixtures.CreateAuthorityInfoAccessExtension(
            OcspTestFixtures.UriAiaEntry(WellKnownOids.AccessMethodOcsp, ocspResponderUri));
        using MintedCertificate signer = OcspTestFixtures.MintCertificate(
            root.Certificate, root.SigningKey, "cades-wire-stale-signer.example.test", notBefore, notAfter, [aia]);

        ocspAdapter.Configure(new MintingOcspResponder(
            [signer.Certificate], root.Certificate, root.Certificate, root.SigningKey,
            OcspCertificateStatus.Good, staleThisUpdate, staleNextUpdate).FetchAsync);

        using PkiCertificateMemory signerCertificate = OcspTestFixtures.ToCertificateCarrier(signer.Certificate);
        using PkiCertificateMemory rootCertificate = OcspTestFixtures.ToCertificateCarrier(root.Certificate);
        using HttpClient ocspHttpClient = LoopbackTls.CreatePinnedHttpClient(ocspHost.Certificate);
        var wireOcsp = new WireOcspTransport(ocspHttpClient);
        var checker = new OcspRevocationChecker(wireOcsp.FetchAsync);

        CertificateRevocationStatus status = await checker.CheckAsync(
            signerCertificate, [rootCertificate], validationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Unknown, status,
            "A genuinely signed but stale response, fetched over a real socket, still fails the RFC 6960 §3.2 freshness check; the checker fails closed rather than trusting it.");
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
    /// responder: wraps the received request octets as a <see cref="TimestampRequest"/>-tagged carrier, calls
    /// the responder, and returns its answer as the <c>application/timestamp-reply</c> body. A configured
    /// object holding the responder delegate, not a closure over test state.
    /// </summary>
    private sealed class BinaryTsaHostAdapter
    {
        private readonly FetchTimestampResponseAsyncDelegate responder;


        /// <summary>Initializes a new <see cref="BinaryTsaHostAdapter"/> over a responder.</summary>
        /// <param name="responder">The RFC 3161 responder this host answers every request through.</param>
        internal BinaryTsaHostAdapter(FetchTimestampResponseAsyncDelegate responder)
        {
            this.responder = responder;
        }


        /// <summary>Implements <see cref="BinaryHttpHandlerDelegate"/>.</summary>
        /// <param name="request">The buffered request.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response.</returns>
        internal async Task<BinaryHttpResponse> HandleAsync(BinaryHttpRequest request, CancellationToken cancellationToken)
        {
            using PkiCertificateMemory requestCarrier = ToCarrier(request.Body, PkiCertificateTags.TimestampRequest);
            PkiCertificateMemory? response = await responder(
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
    /// responder, configured AFTER the host starts (its own certificate's Authority Information Access entry
    /// needs the host's real, only-known-once-bound address). Answers <c>503</c> for any request received
    /// before <see cref="Configure"/> runs.
    /// </summary>
    private sealed class BinaryOcspHostAdapter
    {
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
        private readonly HttpClient httpClient;


        /// <summary>Initializes a new <see cref="WireOcspTransport"/> over a pinned client.</summary>
        /// <param name="httpClient">The client, already pinned to the OCSP responder host's certificate.</param>
        internal WireOcspTransport(HttpClient httpClient)
        {
            this.httpClient = httpClient;
        }


        /// <summary>Implements <see cref="FetchOcspResponseAsyncDelegate"/>.</summary>
        /// <param name="context">The responder address (the certificate's own AIA entry) and the request bytes.</param>
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


    /// <summary>
    /// An <see cref="FetchOcspResponseAsyncDelegate"/> that replays one archived OCSP response for every request,
    /// contacting no network at all — the offline/archived transport a verifying party uses when the response it
    /// decides revocation from is the one embedded in the signature rather than one fetched live. A configured
    /// object holding the response octets, not a closure over test state.
    /// </summary>
    private sealed class ReplayOcspTransport
    {
        private readonly byte[] response;


        /// <summary>Initializes a new <see cref="ReplayOcspTransport"/> over the archived response's octets.</summary>
        /// <param name="response">The DER-encoded <c>OCSPResponse</c> this transport replays.</param>
        internal ReplayOcspTransport(ReadOnlySpan<byte> response)
        {
            this.response = response.ToArray();
        }


        /// <summary>Implements <see cref="FetchOcspResponseAsyncDelegate"/> by handing back the archived response.</summary>
        /// <param name="context">The responder address and request bytes; both ignored — the archived response is fixed.</param>
        /// <param name="pool">The memory pool the returned response is rented from.</param>
        /// <param name="cancellationToken">A cancellation token; unused, as this transport performs no input or output.</param>
        /// <returns>The archived response. The caller disposes it.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the response carrier transfers to the caller via the returned ValueTask.")]
        internal ValueTask<PkiCertificateMemory?> FetchAsync(OcspFetchContext context, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            IMemoryOwner<byte> owner = pool.Rent(response.Length);
            response.CopyTo(owner.Memory.Span);

            return ValueTask.FromResult<PkiCertificateMemory?>(new PkiCertificateMemory(owner, PkiCertificateTags.OcspResponse));
        }
    }


    /// <summary>
    /// A <see cref="FetchTimestampResponseAsyncDelegate"/> test double that mints a genuine, correctly-signed
    /// token — through the same independent BouncyCastle TSP oracle every other fixture in this wave uses — but
    /// over a FIXED imprint that never matches what a real request states, for the mismatched-imprint negative
    /// leg. A configured object, not a closure over test state.
    /// </summary>
    private sealed class MismatchedImprintTsaResponder
    {
        /// <summary>
        /// A deterministic 32-octet value that is never a real SHA-256 digest of this test's own content: the
        /// message imprint every token this responder mints states, regardless of what a request's own imprint
        /// says.
        /// </summary>
        private static byte[] WrongImprint { get; } = new byte[32];

        private readonly X509ChainTestRingNode authority;
        private readonly IReadOnlyList<X509ChainTestRingNode> embeddedCertificates;
        private readonly DateTimeOffset generationTime;


        /// <summary>Initializes a new <see cref="MismatchedImprintTsaResponder"/>.</summary>
        /// <param name="authority">The Time-Stamping Authority node whose key signs the token.</param>
        /// <param name="embeddedCertificates">The certificates the token carries in its own <c>certificates</c> field.</param>
        /// <param name="generationTime">The <c>genTime</c> the token states.</param>
        internal MismatchedImprintTsaResponder(
            X509ChainTestRingNode authority,
            IReadOnlyList<X509ChainTestRingNode> embeddedCertificates,
            DateTimeOffset generationTime)
        {
            this.authority = authority;
            this.embeddedCertificates = embeddedCertificates;
            this.generationTime = generationTime;
        }


        /// <summary>Implements <see cref="FetchTimestampResponseAsyncDelegate"/>.</summary>
        /// <param name="context">The authority address and the request bytes; the request's own imprint is deliberately never read.</param>
        /// <param name="pool">The memory pool the returned response is rented from.</param>
        /// <param name="cancellationToken">A cancellation token; unused, as this double performs no input or output.</param>
        /// <returns>The response. The caller disposes it.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the response carrier transfers to the caller via the returned ValueTask.")]
        internal ValueTask<PkiCertificateMemory?> FetchAsync(TimestampFetchContext context, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            using PkiCertificateMemory token = X509ChainTestRingTimestamping.MintTimestampTokenOverImprint(
                authority, embeddedCertificates, WrongImprint, generationTime);

            return ValueTask.FromResult<PkiCertificateMemory?>(WrapGrantedResponse(token.AsReadOnlySpan(), pool));
        }


        /// <summary>Wraps a token in a granted <c>TimeStampResp</c> (RFC 3161 §2.4.2).</summary>
        /// <param name="token">The DER-encoded token.</param>
        /// <param name="pool">The memory pool the response is rented from.</param>
        /// <returns>The response carrier. The caller disposes it.</returns>
        private static PkiCertificateMemory WrapGrantedResponse(ReadOnlySpan<byte> token, MemoryPool<byte> pool)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            using(writer.PushSequence())
            {
                using(writer.PushSequence())                                //PKIStatusInfo — status alone.
                {
                    writer.WriteInteger(0);                                 //PKIStatus granted.
                }

                writer.WriteEncodedValue(token);
            }

            int encodedLength = writer.GetEncodedLength();
            IMemoryOwner<byte> owner = pool.Rent(encodedLength);
            _ = writer.TryEncode(owner.Memory.Span, out _);

            return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampResponse);
        }
    }
}
