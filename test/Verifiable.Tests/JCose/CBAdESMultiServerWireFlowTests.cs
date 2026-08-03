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
/// The multi-server Kestrel wire e2e leg for CB-AdES B-T/B-LT augmentation and level-aware validation (wavecb
/// S4 coordinator ruling (7); the amendment's exemplar shape, <c>Verifiable.Tests.Cryptography.CAdESMultiServerWireFlowTests</c>):
/// a Time-Stamping Authority and an OCSP responder each run on their own loopback Kestrel host, and the
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
/// wavecb-S3-era double the CAdES exemplar drives, unmodified, now signing a CB-AdES COSE signature value's
/// message imprint instead of a CAdES <c>SignatureValue</c>'s). <strong>Host B (OCSP)</strong> answers every
/// <c>OCSPRequest</c> with a genuine response minted through the independent BouncyCastle OCSP oracle
/// (<see cref="MintingOcspResponder"/>). Both hosts are the binary-body <see cref="BinaryHttpHost"/>.
/// </para>
/// <para>
/// <strong>Two independent signer identities, by design (S4 coordinator ruling (2), certificate-path
/// neutrality).</strong> The COSE signing key pair is minted through the repo's BouncyCastle key-material
/// creator (<see cref="BouncyCastleKeyMaterialCreator.CreateP256Keys"/>) directly — the "BC-minted signer"
/// this leg's contract names — and is registry-resolved into <see cref="CBAdESSignatureCreation.SignAsync"/>/
/// <see cref="CBAdESSignatureValidation.ValidateAsync"/> exactly like every other CB-AdES flow test in this
/// wave. The "signer chain" placed into <c>valData</c> and checked live over Host B is a SEPARATE, platform-
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
/// either party (S4 stays certificate-path-neutral at every level), so <see cref="MintingOcspResponder"/> is
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
    /// <see cref="CBAdESBaselineLevel.BLT"/> and reaches a valid result — proof the COSE signature value, the
    /// <c>sigTst</c> token's message-imprint binding, and the B-LT validation-data-for-time-stamps service are
    /// all independently re-verified from wire bytes alone.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call, which this " +
            "test disposes via 'using creationResult' -- the identical pattern CBAdESSignatureFlowTests uses.")]
    [TestMethod]
    public async Task CreatesAugmentsToBLTAcrossTwoKestrelHostsAndReachesLevelAwareValidSignatureWithLiveOcsp()
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

        //=== The COSE signing key: BC-minted directly through the repo's BouncyCastle key-material creator (the
        //contract's explicit instruction for this leg), independent of the X.509 signer identity above -- see
        //the class remarks for why that independence is sound under S4's certificate-path-neutral scope. ===
        var keyPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        DigestValue signerCertificateDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            signer.Certificate.RawData, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var thumbprint = new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), signerCertificateDigest);

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
                TargetLevel = CBAdESBaselineLevel.BT
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

        using EncodedCoseSign1 bltWire = await CBAdESSignatureAugmentation.AddValidationData(
            new CBAdESValidationDataContext
            {
                WireBytes = btWire.AsReadOnlyMemory(),
                Material = new CBAdESValidationMaterial { Certificates = [signerCertificate, rootCertificateForMinting], OcspResponses = [retained.Response!] },
                TargetLevel = CBAdESBaselineLevel.BLT
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
            CBAdESBaselineLevel.BLT,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid,
            "Creation and augmentation to B-LT over two real Kestrel hosts, verified from wire bytes alone, must reach a valid level-aware result.");
        Assert.IsFalse(result.PayloadIsDetached, "The attached flow's payload must decode as not detached.");
        Assert.IsNotNull(result.UnsignedHeaders, "sigTst and valData were both appended; uHeaders must decode back out of the wire bytes.");

        bool sawSignatureTimestamp = false;
        bool sawValidationData = false;
        for(int i = 0; i < result.UnsignedHeaders!.Count; ++i)
        {
            switch(result.UnsignedHeaders[i])
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
        var thumbprint = new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), placeholderDigest);

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
                    TargetLevel = CBAdESBaselineLevel.BT
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
        internal async ValueTask<PkiCertificateMemory?> FetchAsync(TimestampFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken)
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
        internal async ValueTask<PkiCertificateMemory?> FetchAsync(OcspFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken)
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
        internal ValueTask<PkiCertificateMemory?> FetchAsync(TimestampFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken)
        {
            using PkiCertificateMemory token = X509ChainTestRingTimestamping.MintTimestampTokenOverImprint(
                authority, embeddedCertificates, WrongImprint, generationTime);

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
