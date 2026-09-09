using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.JCose;

/// <summary>
/// The multi-server loopback-HTTP wire e2e leg for CB-AdES B-T/B-LT augmentation and level-aware validation
/// (mirroring <c>Verifiable.Tests.Cryptography.CAdESMultiServerWireFlowTests</c>):
/// a Time-Stamping Authority and an OCSP responder each run on their own loopback HTTP host, and the
/// signer's own <c>TimeStampReq</c>/<c>TimeStampResp</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc3161#section-3.4">RFC 3161 §3.4</see>) and
/// <c>OCSPRequest</c>/<c>OCSPResponse</c> (<see href="https://www.rfc-editor.org/rfc/rfc6960#appendix-A">RFC
/// 6960 Appendix A</see>) exchanges cross those real sockets as DER wire bytes, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Host A (TSA)</strong> answers every <c>TimeStampReq</c> it receives with a genuine token minted
/// through the independent BouncyCastle TSP oracle (<see cref="MintingTimestampResponder"/>, the SAME
/// double the CAdES exemplar drives, unmodified, now signing a CB-AdES COSE signature value's
/// message imprint instead of a CAdES <c>SignatureValue</c>'s). <strong>Host B (OCSP)</strong> answers every
/// <c>OCSPRequest</c> with a genuine response minted through the independent BouncyCastle OCSP oracle
/// (<see cref="MintingOcspResponder"/>). Both hosts are the binary-body <see cref="BinaryHttpHost"/>.
/// </para>
/// <para>
/// <strong>Two independent signer identities, by design (certificate-path
/// neutrality).</strong> The COSE signing key pair is minted through the repo's BouncyCastle key-material
/// creator (<see cref="BouncyCastleKeyMaterialCreator.CreateP256Keys"/>) directly — the "BC-minted signer"
/// — and is registry-resolved into <see cref="CBAdESSignatureCreation.SignAsync"/>/
/// <see cref="CBAdESSignatureValidation.ValidateAsync"/> exactly like every other CB-AdES flow test in this
/// suite. The "signer chain" placed into <c>valData</c> and checked live over Host B is a SEPARATE, platform-
/// ECDsa-backed <see cref="X509Certificate2"/> minted through <see cref="OcspTestFixtures.MintCertificate"/> —
/// the same oracle machinery the CAdES exemplar uses. Nothing in <see cref="CBAdESSignatureValidation"/>'s
/// level-aware surface ties these two identities together (its own class remarks: "certificate-path trust and
/// revocation are never resolved, chained, or validated ... it does not even require a signing certificate");
/// the X.509 certificate's digest is asserted as the signed <c>x5t</c> header purely as a non-authoritative
/// hint (clause 5.1.5, CB-5.1.4-04's kid-is-a-hint rationale applies identically to <c>x5t</c>), and its DER
/// bytes are the material a live OCSP round trip and <c>valData</c> placement exercise for real.
/// </para>
/// <para>
/// <strong>Live OCSP round trip, one subject only.</strong> Unlike the CAdES exemplar's positive leg — which
/// checks BOTH the signer's AND the Time-Stamping Authority's own certificates via OCSP, because its
/// verifying party chain-validates both — this leg's verifying party never resolves a certificate chain for
/// either party (the level-aware validation surface stays certificate-path-neutral at every level), so <see cref="MintingOcspResponder"/> is
/// configured for the signer's certificate alone, and the Time-Stamping Authority is minted through the plain
/// <see cref="X509ChainTestRing.CreateTimeStampingAuthority"/> helper (no Authority Information Access entry
/// needed, since nothing ever queries one for it).
/// </para>
/// <para>
/// <strong>Object-lifetime discipline, mirroring the CAdES exemplar.</strong> The certificates and keys minted
/// for the OCSP responder's own answers cannot be released before the augmentation's live
/// <c>OCSPRequest</c>/<c>OCSPResponse</c> round trip runs, since Host B must keep answering correctly through
/// that live call. The firewall this leg demonstrates is therefore the one enforced at the level of what the
/// VALIDATING CALL touches: <see cref="CBAdESSignatureValidation.ValidateAsync"/> is handed only a plain
/// <c>byte[]</c> (<c>wireCopy</c>) reconstructed from the augmented signature's own wire bytes, plus the
/// verifying party's own, independently-known public key — never a creation-side model, message, or decoded
/// fact — never at the level of process/host lifetime, which a live second network peer cannot honour the way
/// an in-process capstone with only embedded material can.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CBAdESMultiServerWireFlowTests
{
    /// <summary>The <c>Content-Type</c> RFC 3161 §3.4 gives a <c>TimeStampReq</c>.</summary>
    private const string TimestampQueryContentType = "application/timestamp-query";

    /// <summary>The <c>Content-Type</c> RFC 3161 §3.4 gives a <c>TimeStampResp</c>.</summary>
    private const string TimestampReplyContentType = "application/timestamp-reply";

    /// <summary>The <c>Content-Type</c> RFC 6960 Appendix A gives an <c>OCSPRequest</c>.</summary>
    private const string OcspRequestContentType = "application/ocsp-request";

    /// <summary>The <c>Content-Type</c> RFC 6960 Appendix A gives an <c>OCSPResponse</c>.</summary>
    private const string OcspResponseContentType = "application/ocsp-response";


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Mints a CB-AdES B-B signature (attached, over a BouncyCastle-minted signing key), raises it to B-T with
    /// a real <c>TimeStampReq</c>/<c>TimeStampResp</c> round trip to Host A, then to B-LT with a real
    /// <c>OCSPRequest</c>/<c>OCSPResponse</c> round trip to Host B feeding <c>valData</c> alongside the
    /// signer's own X.509 certificate chain, then a verifying party reconstructed from the resulting wire
    /// bytes runs the level-aware <see cref="CBAdESSignatureValidation.ValidateAsync"/> at
    /// <see cref="AdESBaselineLevel.BLT"/> and reaches a valid result — proof the COSE signature value, the
    /// <c>sigTst</c> token's message-imprint binding, and the B-LT validation-data-for-time-stamps service are
    /// all independently re-verified from wire bytes alone.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-6.3-26, CB-6.3-27.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call, which this " +
            "test disposes via 'using creationResult' -- the identical pattern CBAdESSignatureFlowTests uses.")]
    [TestMethod]
    public async Task CreatesAugmentsToBLTAcrossTwoLoopbackHttpHostsAndReachesLevelAwareValidSignatureWithLiveOcsp()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset signatureTimestampTime = signingTime.AddHours(1);
        DateTimeOffset notBefore = signingTime.AddYears(-1);
        DateTimeOffset notAfter = signingTime.AddYears(9);
        DateTimeOffset revocationThisUpdate = signingTime.AddMinutes(-30);
        DateTimeOffset revocationNextUpdate = signingTime.AddYears(1);

        //Host B (OCSP) starts first: the signer's own certificate needs its real address baked into an
        //Authority Information Access entry before it can be minted (mirrors the CAdES exemplar exactly).
        var ocspAdapter = new BinaryOcspHostAdapter();
        await using BinaryHttpHost ocspHost = await BinaryHttpHost.StartAsync(
            ocspAdapter.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string ocspResponderUri = new Uri(ocspHost.BaseAddress, "/ocsp").AbsoluteUri;
        X509Extension aia = OcspTestFixtures.CreateAuthorityInfoAccessExtension(
            OcspTestFixtures.UriAiaEntry(WellKnownOids.AccessMethodOcsp, ocspResponderUri));

        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: notBefore, notAfter: notAfter);
        using MintedCertificate signer = OcspTestFixtures.MintCertificate(
            root.Certificate, root.SigningKey, "cbades-wire-signer.example.test", notBefore, notAfter, [aia]);

        ocspAdapter.Configure(new MintingOcspResponder(
            [signer.Certificate], root.Certificate, root.Certificate, root.SigningKey,
            OcspCertificateStatus.Good, revocationThisUpdate, revocationNextUpdate).FetchAsync);

        //Host A (TSA), answering every request with a genuine token minted through the independent oracle.
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

        //=== The COSE signing key: BC-minted directly through the repo's BouncyCastle key-material creator,
        //independent of the X.509 signer identity above -- see
        //the class remarks for why that independence is sound under the certificate-path-neutral scope. ===
        var keyPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        DigestValue signerCertificateDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            signer.Certificate.RawData, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), signerCertificateDigest);

        byte[] payloadBytes = "CB-AdES multi-server wire content"u8.ToArray();

        //=== B-B: attached, over the BC-minted signer. ===
        var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(signingTime), x5t: thumbprint);
        var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

        using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
            headers, payloadInput, unsignedHeaders: null,
            CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
            CoseSerialization.BuildSigStructure, privateKey,
            dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using EncodedCoseSign1 bbWire = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);

        //=== B-T: a real TimeStampReq/TimeStampResp round trip to Host A. ===
        using EncodedCoseSign1 btWire = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new CBAdESSignatureTimestampContext
            {
                WireBytes = bbWire.AsReadOnlyMemory(),
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = tsaUri,
                FetchResponse = wireTsa.FetchAsync,
                SigningCertificate = signerCertificate,
                TargetLevel = AdESBaselineLevel.BT
            },
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CBAdESSignatureSerialization.SerializeCBAdESSign1,
            CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //=== B-LT: a real OCSPRequest/OCSPResponse round trip to Host B, then valData carries the signer's own
        //X.509 chain plus the RETAINED, verified response bytes (the same OcspRevocationChecker surface the
        //CAdES exemplar uses, now fed by a real socket). ===
        var mintTimeRevocationChecker = new OcspRevocationChecker(wireOcsp.FetchAsync);
        using RetainedOcspResponse retained = await mintTimeRevocationChecker.CheckRetainingResponseAsync(
            signerCertificate, [rootCertificateForMinting], revocationThisUpdate.AddMinutes(5), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(CertificateRevocationStatus.Good, retained.Status,
            "The signer's certificate is Good, decided through a real OCSPRequest/OCSPResponse round trip against Host B.");
        Assert.IsNotNull(retained.Response, "A verified response retains its DER octets for placement as B-LT material.");

        using EncodedCoseSign1 bltWire = await CBAdESSignatureAugmentation.AddValidationDataAsync(
            new CBAdESValidationDataContext
            {
                WireBytes = btWire.AsReadOnlyMemory(),
                Material = new CBAdESValidationMaterial { Certificates = [signerCertificate, rootCertificateForMinting], OcspResponses = [retained.Response!] },
                TargetLevel = AdESBaselineLevel.BLT
            },
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CBAdESSignatureSerialization.SerializeCBAdESSign1,
            CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wireCopy = bltWire.AsReadOnlySpan().ToArray();

        //=== Verifying party: reconstructs from the wire bytes alone plus its own independently-known public
        //key -- never a creation-side object. A successful result here proves the sigTst token's message
        //imprint verified against the ACTUAL COSE signature value bytes, which the Time-Stamping Authority
        //could only have echoed correctly by decoding the genuine HTTP POST body it received over the socket. ===
        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            AdESBaselineLevel.BLT,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid,
            "Creation and augmentation to B-LT over two real loopback HTTP hosts, verified from wire bytes alone, must reach a valid level-aware result.");
        Assert.IsFalse(result.Verified!.Value.Value.PayloadIsDetached, "The attached flow's payload must decode as not detached.");
        Assert.IsNotNull(result.Verified.Value.Value.UnsignedHeaders, "sigTst and valData were both appended; uHeaders must decode back out of the wire bytes.");

        bool sawSignatureTimestamp = false;
        bool sawValidationData = false;
        for(int i = 0; i < result.Verified.Value.Value.UnsignedHeaders!.Count; ++i)
        {
            switch(result.Verified.Value.Value.UnsignedHeaders[i])
            {
                case CBAdESUnsignedHeaderElementSignatureTimestamp:
                    sawSignatureTimestamp = true;
                    break;

                case CBAdESUnsignedHeaderElementValidationData:
                    sawValidationData = true;
                    break;
            }
        }

        Assert.IsTrue(sawSignatureTimestamp, "The sigTst element raised over the real TSA round trip must decode back out of the wire bytes.");
        Assert.IsTrue(sawValidationData, "The valData element placed over the real OCSP round trip must decode back out of the wire bytes.");
    }


    /// <summary>
    /// Extends the B-LT wire leg above with the B-LTA leg -- a THIRD,
    /// independent loopback HTTP host (Host C) genuinely minting an <c>arcTst</c> electronic time-stamp over
    /// a real <c>TimeStampReq</c>/<c>TimeStampResp</c> round trip, exactly mirroring Host A's own real-wire
    /// pattern for <c>sigTst</c>. A non-empty externally-supplied-data value (a deliberate trap: clause 5.3.5.3
    /// step 5 binds it into the message imprint) crosses this leg's real socket inside the <c>arcTst</c>
    /// message imprint the Time-Stamping Authority attests over, and the resulting B-LTA wire bytes reach a
    /// valid level-aware result at <see cref="AdESBaselineLevel.BLTA"/> from wire bytes alone.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.3.5.2-03, CB-5.3.5.3-06.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call, which this " +
            "test disposes via 'using creationResult' -- the identical pattern CBAdESSignatureFlowTests uses.")]
    [TestMethod]
    public async Task CreatesAugmentsToBLTAAcrossThreeLoopbackHostsAndReachesLevelAwareValidSignatureAtBLTA()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset signatureTimestampTime = signingTime.AddHours(1);
        DateTimeOffset archiveTimestampTime = signingTime.AddHours(2);
        DateTimeOffset notBefore = signingTime.AddYears(-1);
        DateTimeOffset notAfter = signingTime.AddYears(9);
        DateTimeOffset revocationThisUpdate = signingTime.AddMinutes(-30);
        DateTimeOffset revocationNextUpdate = signingTime.AddYears(1);

        //Host B (OCSP) starts first: the signer's own certificate needs its real address baked into an
        //Authority Information Access entry before it can be minted (mirrors the B-LT leg exactly).
        var ocspAdapter = new BinaryOcspHostAdapter();
        await using BinaryHttpHost ocspHost = await BinaryHttpHost.StartAsync(
            ocspAdapter.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string ocspResponderUri = new Uri(ocspHost.BaseAddress, "/ocsp").AbsoluteUri;
        X509Extension aia = OcspTestFixtures.CreateAuthorityInfoAccessExtension(
            OcspTestFixtures.UriAiaEntry(WellKnownOids.AccessMethodOcsp, ocspResponderUri));

        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: notBefore, notAfter: notAfter);
        using MintedCertificate signer = OcspTestFixtures.MintCertificate(
            root.Certificate, root.SigningKey, "cbades-blta-wire-signer.example.test", notBefore, notAfter, [aia]);

        ocspAdapter.Configure(new MintingOcspResponder(
            [signer.Certificate], root.Certificate, root.Certificate, root.SigningKey,
            OcspCertificateStatus.Good, revocationThisUpdate, revocationNextUpdate).FetchAsync);

        //Host A (TSA, sigTst), answering every request with a genuine token minted through the independent oracle.
        var tsaResponder = new MintingTimestampResponder(authority, [authority, root], signatureTimestampTime);
        await using BinaryHttpHost tsaHost = await BinaryHttpHost.StartAsync(
            new BinaryTsaHostAdapter(tsaResponder.FetchAsync).HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string tsaUri = new Uri(tsaHost.BaseAddress, "/tsa").AbsoluteUri;

        //Host C (TSA, arcTst): a THIRD, independent loopback HTTP host, extending this leg's harness.
        var archiveTimestampResponder = new MintingTimestampResponder(authority, [authority, root], archiveTimestampTime);
        await using BinaryHttpHost archiveTimestampHost = await BinaryHttpHost.StartAsync(
            new BinaryTsaHostAdapter(archiveTimestampResponder.FetchAsync).HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string archiveTimestampTsaUri = new Uri(archiveTimestampHost.BaseAddress, "/arctst").AbsoluteUri;

        using HttpClient tsaHttpClient = LoopbackTls.CreatePinnedHttpClient(tsaHost.Certificate);
        using HttpClient ocspHttpClient = LoopbackTls.CreatePinnedHttpClient(ocspHost.Certificate);
        using HttpClient archiveTimestampHttpClient = LoopbackTls.CreatePinnedHttpClient(archiveTimestampHost.Certificate);
        var wireTsa = new WireTimestampTransport(tsaHttpClient);
        var wireOcsp = new WireOcspTransport(ocspHttpClient);
        var wireArchiveTimestampTsa = new WireTimestampTransport(archiveTimestampHttpClient);

        using PkiCertificateMemory signerCertificate = OcspTestFixtures.ToCertificateCarrier(signer.Certificate);
        using PkiCertificateMemory rootCertificateForMinting = OcspTestFixtures.ToCertificateCarrier(root.Certificate);

        var keyPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        DigestValue signerCertificateDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            signer.Certificate.RawData, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), signerCertificateDigest);

        byte[] payloadBytes = "CB-AdES multi-server wire content -- B-LTA leg"u8.ToArray();

        //=== B-B: attached, over the BC-minted signer. ===
        var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(signingTime), x5t: thumbprint);
        var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

        using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
            headers, payloadInput, unsignedHeaders: null,
            CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
            CoseSerialization.BuildSigStructure, privateKey,
            dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using EncodedCoseSign1 bbWire = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);

        //=== B-T: a real TimeStampReq/TimeStampResp round trip to Host A. ===
        using EncodedCoseSign1 btWire = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new CBAdESSignatureTimestampContext
            {
                WireBytes = bbWire.AsReadOnlyMemory(),
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = tsaUri,
                FetchResponse = wireTsa.FetchAsync,
                SigningCertificate = signerCertificate,
                TargetLevel = AdESBaselineLevel.BT
            },
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CBAdESSignatureSerialization.SerializeCBAdESSign1,
            CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //=== B-LT: a real OCSPRequest/OCSPResponse round trip to Host B, then valData carries the signer's own
        //X.509 chain plus the RETAINED, verified response bytes. ===
        var mintTimeRevocationChecker = new OcspRevocationChecker(wireOcsp.FetchAsync);
        using RetainedOcspResponse retained = await mintTimeRevocationChecker.CheckRetainingResponseAsync(
            signerCertificate, [rootCertificateForMinting], revocationThisUpdate.AddMinutes(5), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(CertificateRevocationStatus.Good, retained.Status,
            "The signer's certificate is Good, decided through a real OCSPRequest/OCSPResponse round trip against Host B.");
        Assert.IsNotNull(retained.Response, "A verified response retains its DER octets for placement as B-LT material.");

        using EncodedCoseSign1 bltWire = await CBAdESSignatureAugmentation.AddValidationDataAsync(
            new CBAdESValidationDataContext
            {
                WireBytes = btWire.AsReadOnlyMemory(),
                Material = new CBAdESValidationMaterial { Certificates = [signerCertificate, rootCertificateForMinting], OcspResponses = [retained.Response!] },
                TargetLevel = AdESBaselineLevel.BLT
            },
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CBAdESSignatureSerialization.SerializeCBAdESSign1,
            CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //=== B-LTA: a real TimeStampReq/TimeStampResp round trip to Host C, extending the leg above. A non-empty
        //externally-supplied-data value crosses this leg's real socket inside the arcTst message imprint. ===
        byte[] externallySuppliedData = "CB-AdES multi-server wire content -- arcTst externally-supplied data"u8.ToArray();

        using EncodedCoseSign1 bltaWire = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new CBAdESArchiveTimestampContext
            {
                WireBytes = bltWire.AsReadOnlyMemory(),
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                ExternallySuppliedData = externallySuppliedData,
                TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = archiveTimestampTsaUri, FetchResponse = wireArchiveTimestampTsa.FetchAsync }],
                SigningCertificate = signerCertificate,
                ChainCompletenessAttested = true,
                TargetLevel = AdESBaselineLevel.BLTA
            },
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CBAdESSignatureSerialization.SerializeCBAdESSign1,
            CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wireCopy = bltaWire.AsReadOnlySpan().ToArray();

        //=== Verifying party: reconstructs from the wire bytes alone plus its own independently-known public
        //key -- never a creation-side object. A successful result here proves the arcTst token's message
        //imprint verified against the ACTUAL wire uHeaders bytes, which Host C could only have echoed correctly
        //by decoding the genuine HTTP POST body it received over the socket. ===
        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            AdESBaselineLevel.BLTA,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
            BaseMemoryPool.Shared, externallySuppliedData, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid,
            "Creation and augmentation to B-LTA over three real loopback HTTP hosts, verified from wire bytes alone, must reach a valid level-aware result.");
        Assert.IsNotNull(result.Verified!.Value.Value.UnsignedHeaders, "sigTst, valData, and arcTst were all appended; uHeaders must decode back out of the wire bytes.");

        bool sawArchiveTimestamp = false;
        for(int i = 0; i < result.Verified.Value.Value.UnsignedHeaders!.Count; ++i)
        {
            if(result.Verified.Value.Value.UnsignedHeaders[i] is CBAdESUnsignedHeaderElementArchiveTimestamp)
            {
                sawArchiveTimestamp = true;
            }
        }

        Assert.IsTrue(sawArchiveTimestamp, "The arcTst element raised over the real Host C TimeStampReq/TimeStampResp round trip must decode back out of the wire bytes.");
    }


    /// <summary>
    /// Extends the three-host B-LTA leg above with a genuine RFC 9338
    /// counter signature (abbreviated, label 12), spliced into <c>uHeaders</c> immediately after B-B creation,
    /// present through the SAME real <c>sigTst</c> (Host A)/OCSP (Host B)/<c>arcTst</c> (Host C) round trips --
    /// through the FIRST <c>arcTst</c>, with CB-5.3.5.1-02's material-completeness gate satisfied so the mint
    /// is allowed to proceed. The verifying party reconstructs from the final wire bytes and the two
    /// independently-known public keys alone (the primary signer's and the countersigner's own) and reaches a
    /// valid level-aware result at B-LTA with the counter signature CRYPTOGRAPHICALLY VERIFIED, never merely
    /// structurally accepted.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call, which this " +
            "test disposes via 'using creationResult' -- the identical pattern CBAdESSignatureFlowTests uses.")]
    [TestMethod]
    public async Task CreatesCountersignsAugmentsToBLTAAcrossThreeLoopbackHostsAndVerifiesTheCounterSignatureCryptographically()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset signatureTimestampTime = signingTime.AddHours(1);
        DateTimeOffset archiveTimestampTime = signingTime.AddHours(2);
        DateTimeOffset notBefore = signingTime.AddYears(-1);
        DateTimeOffset notAfter = signingTime.AddYears(9);
        DateTimeOffset revocationThisUpdate = signingTime.AddMinutes(-30);
        DateTimeOffset revocationNextUpdate = signingTime.AddYears(1);

        //Host B (OCSP) starts first: the signer's own certificate needs its real address baked into an
        //Authority Information Access entry before it can be minted (mirrors the B-LTA leg exactly).
        var ocspAdapter = new BinaryOcspHostAdapter();
        await using BinaryHttpHost ocspHost = await BinaryHttpHost.StartAsync(
            ocspAdapter.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string ocspResponderUri = new Uri(ocspHost.BaseAddress, "/ocsp").AbsoluteUri;
        X509Extension aia = OcspTestFixtures.CreateAuthorityInfoAccessExtension(
            OcspTestFixtures.UriAiaEntry(WellKnownOids.AccessMethodOcsp, ocspResponderUri));

        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: notBefore, notAfter: notAfter);
        using MintedCertificate signer = OcspTestFixtures.MintCertificate(
            root.Certificate, root.SigningKey, "cbades-countersigned-wire-signer.example.test", notBefore, notAfter, [aia]);

        ocspAdapter.Configure(new MintingOcspResponder(
            [signer.Certificate], root.Certificate, root.Certificate, root.SigningKey,
            OcspCertificateStatus.Good, revocationThisUpdate, revocationNextUpdate).FetchAsync);

        //Host A (TSA, sigTst).
        var tsaResponder = new MintingTimestampResponder(authority, [authority, root], signatureTimestampTime);
        await using BinaryHttpHost tsaHost = await BinaryHttpHost.StartAsync(
            new BinaryTsaHostAdapter(tsaResponder.FetchAsync).HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string tsaUri = new Uri(tsaHost.BaseAddress, "/tsa").AbsoluteUri;

        //Host C (TSA, arcTst): a third, independent loopback HTTP host.
        var archiveTimestampResponder = new MintingTimestampResponder(authority, [authority, root], archiveTimestampTime);
        await using BinaryHttpHost archiveTimestampHost = await BinaryHttpHost.StartAsync(
            new BinaryTsaHostAdapter(archiveTimestampResponder.FetchAsync).HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string archiveTimestampTsaUri = new Uri(archiveTimestampHost.BaseAddress, "/arctst").AbsoluteUri;

        using HttpClient tsaHttpClient = LoopbackTls.CreatePinnedHttpClient(tsaHost.Certificate);
        using HttpClient ocspHttpClient = LoopbackTls.CreatePinnedHttpClient(ocspHost.Certificate);
        using HttpClient archiveTimestampHttpClient = LoopbackTls.CreatePinnedHttpClient(archiveTimestampHost.Certificate);
        var wireTsa = new WireTimestampTransport(tsaHttpClient);
        var wireOcsp = new WireOcspTransport(ocspHttpClient);
        var wireArchiveTimestampTsa = new WireTimestampTransport(archiveTimestampHttpClient);

        using PkiCertificateMemory signerCertificate = OcspTestFixtures.ToCertificateCarrier(signer.Certificate);
        using PkiCertificateMemory rootCertificateForMinting = OcspTestFixtures.ToCertificateCarrier(root.Certificate);

        //=== The COSE signing key AND the countersigner's own key: both BC-minted, independent of each other
        //and of the X.509 signer identity above (certificate-path neutrality). ===
        var keyPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var counterSignerKeyPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory counterSignerPublicKey = counterSignerKeyPair.PublicKey;
        using PrivateKeyMemory counterSignerPrivateKey = counterSignerKeyPair.PrivateKey;

        DigestValue signerCertificateDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            signer.Certificate.RawData, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), signerCertificateDigest);

        byte[] payloadBytes = "CB-AdES multi-server wire content -- countersigned B-LTA leg"u8.ToArray();

        //=== B-B: attached, over the BC-minted signer. ===
        var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(signingTime), x5t: thumbprint);
        var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

        using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
            headers, payloadInput, unsignedHeaders: null,
            CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
            CoseSerialization.BuildSigStructure, privateKey,
            dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //=== Countersign the B-B signature's own body-layer protected header/payload/signature (abbreviated,
        //label 12) and splice the element in as the sole uHeaders entry, over the shipped CoseCounterSign verb --
        //never a hand-rolled signature. ===
        byte[] bbWireWithCounterSignature = await CountersignAndSerializeAsync(
            creationResult.Message, counterSignerPrivateKey, TestContext.CancellationToken).ConfigureAwait(false);

        //=== B-T: a real TimeStampReq/TimeStampResp round trip to Host A. The counter-signature element rides
        //along untouched -- the append-only splice every augmentation verb uses never re-encodes it. ===
        using EncodedCoseSign1 btWire = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new CBAdESSignatureTimestampContext
            {
                WireBytes = bbWireWithCounterSignature,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = tsaUri,
                FetchResponse = wireTsa.FetchAsync,
                SigningCertificate = signerCertificate,
                TargetLevel = AdESBaselineLevel.BT
            },
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CBAdESSignatureSerialization.SerializeCBAdESSign1,
            CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //=== B-LT: a real OCSPRequest/OCSPResponse round trip to Host B, then valData. ===
        var mintTimeRevocationChecker = new OcspRevocationChecker(wireOcsp.FetchAsync);
        using RetainedOcspResponse retained = await mintTimeRevocationChecker.CheckRetainingResponseAsync(
            signerCertificate, [rootCertificateForMinting], revocationThisUpdate.AddMinutes(5), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(CertificateRevocationStatus.Good, retained.Status,
            "The signer's certificate is Good, decided through a real OCSPRequest/OCSPResponse round trip against Host B.");
        Assert.IsNotNull(retained.Response, "A verified response retains its DER octets for placement as B-LT material.");

        using EncodedCoseSign1 bltWire = await CBAdESSignatureAugmentation.AddValidationDataAsync(
            new CBAdESValidationDataContext
            {
                WireBytes = btWire.AsReadOnlyMemory(),
                Material = new CBAdESValidationMaterial { Certificates = [signerCertificate, rootCertificateForMinting], OcspResponses = [retained.Response!] },
                TargetLevel = AdESBaselineLevel.BLT
            },
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CBAdESSignatureSerialization.SerializeCBAdESSign1,
            CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //=== B-LTA: a real TimeStampReq/TimeStampResp round trip to Host C -- the FIRST arcTst, minted with
        //CB-5.3.5.1-02's material-completeness gate satisfied (a resolver decoding and confirming the
        //counter signature's own completeness before the mint is allowed to proceed). ===
        using EncodedCoseSign1 bltaWire = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new CBAdESArchiveTimestampContext
            {
                WireBytes = bltWire.AsReadOnlyMemory(),
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = archiveTimestampTsaUri, FetchResponse = wireArchiveTimestampTsa.FetchAsync }],
                SigningCertificate = signerCertificate,
                ChainCompletenessAttested = true,
                TargetLevel = AdESBaselineLevel.BLTA
            },
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CBAdESSignatureSerialization.SerializeCBAdESSign1,
            CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
            BaseMemoryPool.Shared,
            parseCounterSignatureHeaderValue: CoseSerialization.ParseCounterSignatureHeaderValue,
            isCounterSignatureMaterialComplete: _ => true,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wireCopy = bltaWire.AsReadOnlySpan().ToArray();

        //=== Verifying party: reconstructs from the wire bytes alone plus its own independently-known public
        //keys (the primary signer's and the countersigner's own) -- never a creation-side object. A successful
        //result here proves the arcTst token's message imprint AND the counter signature's own cryptographic
        //signature both verified against material only a genuine round trip over the real sockets could have
        //produced. ===
        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            AdESBaselineLevel.BLTA,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
            BaseMemoryPool.Shared,
            archiveTimestampExternallySuppliedData: default,
            parseCounterSignatureHeaderValue: CoseSerialization.ParseCounterSignatureHeaderValue,
            buildCountersignStructure: CoseSerialization.BuildCountersignStructure,
            resolveCounterSignaturePublicKey: _ => counterSignerPublicKey,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid,
            "Creation, countersigning, and augmentation to B-LTA over three real loopback HTTP hosts, verified from wire bytes alone, must reach a valid level-aware result with the counter signature cryptographically verified.");
        Assert.IsNotNull(result.Verified!.Value.Value.UnsignedHeaders, "The counter signature, sigTst, valData, and arcTst were all incorporated; uHeaders must decode back out of the wire bytes.");

        bool sawCounterSignature = false;
        bool sawArchiveTimestamp = false;
        for(int i = 0; i < result.Verified.Value.Value.UnsignedHeaders!.Count; ++i)
        {
            switch(result.Verified.Value.Value.UnsignedHeaders[i])
            {
                case CBAdESUnsignedHeaderElementAbbreviatedCounterSignature:
                    sawCounterSignature = true;
                    break;

                case CBAdESUnsignedHeaderElementArchiveTimestamp:
                    sawArchiveTimestamp = true;
                    break;
            }
        }

        Assert.IsTrue(sawCounterSignature, "The counter-signature element spliced in right after B-B creation must ride, byte-preserved, all the way through B-LTA.");
        Assert.IsTrue(sawArchiveTimestamp, "The arcTst element raised over the real Host C TimeStampReq/TimeStampResp round trip must decode back out of the wire bytes.");
    }


    /// <summary>
    /// Negative leg over the socket: a Time-Stamping Authority that returns a genuine, correctly-signed token
    /// minted over a message imprint that does NOT match the request's own — a real TSA misbehaviour shape RFC
    /// 3161 §2.4.2 does not itself preclude — is rejected with a typed
    /// <see cref="TimestampAcquisitionException"/> before anything is attached; the signature the augmentation
    /// was asked to raise is left byte-for-byte unchanged. Mirrors the CAdES exemplar's own negative leg shape
    /// exactly (see the class remarks for the shared oracle this double drives).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call, which this " +
            "test disposes via 'using creationResult' -- the identical pattern CBAdESSignatureFlowTests uses.")]
    [TestMethod]
    public async Task ATimeStampingAuthorityReturningATokenOverAMismatchedImprintIsRejectedAndNothingIsAttached()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset notBefore = signingTime.AddYears(-1);
        DateTimeOffset notAfter = signingTime.AddYears(9);

        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: notBefore, notAfter: notAfter);

        var mismatchedResponder = new MismatchedImprintTsaResponder(authority, [authority, root], signingTime.AddHours(1));
        await using BinaryHttpHost tsaHost = await BinaryHttpHost.StartAsync(
            new BinaryTsaHostAdapter(mismatchedResponder.FetchAsync).HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string tsaUri = new Uri(tsaHost.BaseAddress, "/tsa").AbsoluteUri;
        using HttpClient tsaHttpClient = LoopbackTls.CreatePinnedHttpClient(tsaHost.Certificate);
        var wireTsa = new WireTimestampTransport(tsaHttpClient);

        var keyPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        DigestValue placeholderDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            "CBAdESMultiServerWireFlowTests mismatched-imprint placeholder signing certificate"u8.ToArray(),
            32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), placeholderDigest);

        var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(signingTime), x5t: thumbprint);
        var payloadInput = new CBAdESAttachedPayloadInput("CB-AdES wire mismatched-imprint payload"u8.ToArray());

        using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
            headers, payloadInput, unsignedHeaders: null,
            CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
            CoseSerialization.BuildSigStructure, privateKey,
            dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using EncodedCoseSign1 baselineWire = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);
        byte[] baselineBytesBeforeTheAttempt = baselineWire.AsReadOnlySpan().ToArray();

        TimestampAcquisitionException exception = await Assert.ThrowsExactlyAsync<TimestampAcquisitionException>(
            async () => await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CBAdESSignatureTimestampContext
                {
                    WireBytes = baselineWire.AsReadOnlyMemory(),
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = tsaUri,
                    FetchResponse = wireTsa.FetchAsync,
                    EnforceSigningCertificateValidity = false,
                    TargetLevel = AdESBaselineLevel.BT
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1,
                CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(TimestampAcquisitionFailureKind.MessageImprintMismatch, exception.FailureKind,
            "A token whose message imprint does not match the digest the request carried is refused for exactly that reason (RFC 3161 §2.4.2).");
        Assert.AreSequenceEqual(baselineBytesBeforeTheAttempt, baselineWire.AsReadOnlySpan().ToArray(),
            "A rejected token is never attached: the signature the augmentation was asked to raise is byte-for-byte unchanged.");
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
    /// Countersigns <paramref name="primary"/>'s own body-layer protected header/payload/signature (abbreviated,
    /// label 12, RFC 9338) with <paramref name="counterSignerPrivateKey"/> through <see cref="CoseCounterSign"/>,
    /// splices the resulting element in as the sole <c>uHeaders</c> entry, and re-serializes around the SAME
    /// protected header, payload, and signature carriers -- mirroring
    /// <c>CBAdESCounterSignatureVisibilityTests.SpliceElementAndSerialize</c>'s exact pattern.
    /// </summary>
    /// <param name="primary">The already-signed B-B message. Not disposed here.</param>
    /// <param name="counterSignerPrivateKey">The countersigner's private key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The wire bytes, the counter-signature element already incorporated.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "message borrows primary's own ProtectedHeader/Payload/Signature carriers verbatim -- " +
            "read-only, never disposed here, matching CBAdESSignatureAugmentation.EncodeAndSerialize's own " +
            "documented relationship to the carriers it borrows.")]
    private static async Task<byte[]> CountersignAndSerializeAsync(
        CoseSign1Message primary, PrivateKeyMemory counterSignerPrivateKey, CancellationToken cancellationToken)
    {
        var target = new CoseSign1CountersignTarget(
            primary.ProtectedHeader.AsReadOnlyMemory(), primary.Payload, primary.Signature.AsReadOnlyMemory());

        using CounterSignature0V2 counterSignature = await CoseCounterSign.CountersignAbbreviatedAsync(
            target, externalAad: ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
            counterSignerPrivateKey, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        using EncodedCoseCounterSignature encoded = CoseSerialization.WriteCounterSignature0V2(counterSignature, BaseMemoryPool.Shared);
        var element = new CBAdESUnsignedHeaderElementAbbreviatedCounterSignature(encoded.AsReadOnlyMemory().ToArray());

        bool spliced = CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader(
            rawUnsignedHeaders: null, decodedElementCount: 0, skipDecodedIndexes: null, newElement: element,
            BaseMemoryPool.Shared, out IReadOnlyDictionary<int, object>? unprotectedHeader);
        Assert.IsTrue(spliced, "Splicing a single new element into an absent uHeaders must always succeed.");

        var message = new CoseSign1Message(primary.ProtectedHeader, unprotectedHeader, primary.Payload, primary.Signature);

        using EncodedCoseSign1 wireBytes = CBAdESSignatureSerialization.SerializeCBAdESSign1(message, payloadIsDetached: false, BaseMemoryPool.Shared);

        return wireBytes.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// Bridges a <see cref="BinaryHttpHost"/> to a <see cref="FetchTimestampResponseAsyncDelegate"/>-shaped
    /// responder: wraps the received request octets as a <see cref="TimestampRequest"/>-tagged carrier, calls
    /// the responder, and returns its answer as the <c>application/timestamp-reply</c> body. A configured
    /// object holding the responder delegate, not a closure over test state.
    /// </summary>
    private sealed class BinaryTsaHostAdapter
    {
        private FetchTimestampResponseAsyncDelegate Responder { get; }


        /// <summary>Initializes a new <see cref="BinaryTsaHostAdapter"/> over a responder.</summary>
        /// <param name="responder">The RFC 3161 responder this host answers every request through.</param>
        internal BinaryTsaHostAdapter(FetchTimestampResponseAsyncDelegate responder)
        {
            this.Responder = responder;
        }


        /// <summary>Implements <see cref="BinaryHttpHandlerDelegate"/>.</summary>
        /// <param name="request">The buffered request.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response.</returns>
        internal async Task<BinaryHttpResponse> HandleAsync(BinaryHttpRequest request, CancellationToken cancellationToken)
        {
            using PkiCertificateMemory requestCarrier = ToCarrier(request.Body, PkiCertificateTags.TimestampRequest);
            PkiCertificateMemory? response = await Responder(
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
        private HttpClient WireClient { get; }


        /// <summary>Initializes a new <see cref="WireTimestampTransport"/> over a pinned client.</summary>
        /// <param name="httpClient">The client, already pinned to the Time-Stamping Authority host's certificate.</param>
        internal WireTimestampTransport(HttpClient httpClient)
        {
            this.WireClient = httpClient;
        }


        /// <summary>Implements <see cref="FetchTimestampResponseAsyncDelegate"/>.</summary>
        /// <param name="context">The authority address and the request bytes.</param>
        /// <param name="pool">The memory pool the returned response is rented from.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response, or <see langword="null"/> on a transport failure.</returns>
        internal async ValueTask<PkiCertificateMemory?> FetchAsync(TimestampFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken)
        {
            using var content = new ByteArrayContent(context.Request.AsReadOnlySpan().ToArray());
            content.Headers.ContentType = new MediaTypeHeaderValue(TimestampQueryContentType);

            HttpResponseMessage httpResponse;
            try
            {
                httpResponse = await WireClient.PostAsync(new Uri(context.TsaUri), content, cancellationToken).ConfigureAwait(false);
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
        private HttpClient WireClient { get; }


        /// <summary>Initializes a new <see cref="WireOcspTransport"/> over a pinned client.</summary>
        /// <param name="httpClient">The client, already pinned to the OCSP responder host's certificate.</param>
        internal WireOcspTransport(HttpClient httpClient)
        {
            this.WireClient = httpClient;
        }


        /// <summary>Implements <see cref="FetchOcspResponseAsyncDelegate"/>.</summary>
        /// <param name="context">The responder address (the certificate's own AIA entry) and the request bytes.</param>
        /// <param name="pool">The memory pool the returned response is rented from.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response, or <see langword="null"/> on a transport failure.</returns>
        internal async ValueTask<PkiCertificateMemory?> FetchAsync(OcspFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken)
        {
            using var content = new ByteArrayContent(context.Request.AsReadOnlySpan().ToArray());
            content.Headers.ContentType = new MediaTypeHeaderValue(OcspRequestContentType);

            HttpResponseMessage httpResponse;
            try
            {
                httpResponse = await WireClient.PostAsync(new Uri(context.ResponderUri), content, cancellationToken).ConfigureAwait(false);
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
    /// A <see cref="FetchTimestampResponseAsyncDelegate"/> test double that mints a genuine, correctly-signed
    /// token — through the same independent BouncyCastle TSP oracle every other fixture in this file uses — but
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

        private X509ChainTestRingNode Authority { get; }
        private IReadOnlyList<X509ChainTestRingNode> EmbeddedCertificates { get; }
        private DateTimeOffset GenerationTime { get; }


        /// <summary>Initializes a new <see cref="MismatchedImprintTsaResponder"/>.</summary>
        /// <param name="authority">The Time-Stamping Authority node whose key signs the token.</param>
        /// <param name="embeddedCertificates">The certificates the token carries in its own <c>certificates</c> field.</param>
        /// <param name="generationTime">The <c>genTime</c> the token states.</param>
        internal MismatchedImprintTsaResponder(
            X509ChainTestRingNode authority,
            IReadOnlyList<X509ChainTestRingNode> embeddedCertificates,
            DateTimeOffset generationTime)
        {
            this.Authority = authority;
            this.EmbeddedCertificates = embeddedCertificates;
            this.GenerationTime = generationTime;
        }


        /// <summary>Implements <see cref="FetchTimestampResponseAsyncDelegate"/>.</summary>
        /// <param name="context">The authority address and the request bytes; the request's own imprint is deliberately never read.</param>
        /// <param name="pool">The memory pool the returned response is rented from.</param>
        /// <param name="cancellationToken">A cancellation token; unused, as this double performs no input or output.</param>
        /// <returns>The response. The caller disposes it.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the response carrier transfers to the caller via the returned ValueTask.")]
        internal ValueTask<PkiCertificateMemory?> FetchAsync(TimestampFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken)
        {
            using PkiCertificateMemory token = X509ChainTestRingTimestamping.MintTimestampTokenOverImprint(
                Authority, EmbeddedCertificates, WrongImprint, GenerationTime);

            return ValueTask.FromResult<PkiCertificateMemory?>(WrapGrantedResponse(token.AsReadOnlySpan(), pool));
        }


        /// <summary>Wraps a token in a granted <c>TimeStampResp</c> (RFC 3161 §2.4.2).</summary>
        /// <param name="token">The DER-encoded token.</param>
        /// <param name="pool">The memory pool the response is rented from.</param>
        /// <returns>The response carrier. The caller disposes it.</returns>
        private static PkiCertificateMemory WrapGrantedResponse(ReadOnlySpan<byte> token, BaseMemoryPool pool)
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
