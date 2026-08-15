using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.JCose;

/// <summary>
/// The multi-server loopback-HTTP wire e2e leg for JAdES B-T/B-LTA augmentation and LEVEL-AWARE validation
/// (the family harness pattern <c>CBAdESMultiServerWireFlowTests</c> establishes,
/// transposed to JWS/JSON): TWO independent Time-Stamping Authorities each run on their own loopback HTTP host,
/// and the signer's own <c>TimeStampReq</c>/<c>TimeStampResp</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc3161#section-3.4">RFC 3161 §3.4</see>) exchanges cross those
/// real sockets as DER wire bytes, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Host A</strong> mints the <c>sigTst</c> token (B-T); <strong>Host B</strong>, a SECOND, independent
/// loopback host, mints the <c>arcTst</c> token (B-LTA) — mirroring the CB-AdES exemplar's own Host A/Host C
/// split, minus the OCSP leg (B-LT here is reached synthetically, since JA-6.3-38/j's service is satisfied by
/// an <c>anyValData</c> element's own presence, needing no live network round trip to prove independently of
/// what <c>JAdESSignatureAugmentationTests</c> already covers for that verb in isolation).
/// </para>
/// <para>
/// <strong>Object-lifetime discipline.</strong> Every step a signer performs runs inside its own nested block
/// scope, copying ONLY the serialized wire bytes into an independent <c>byte[]</c> that crosses to the next
/// step — the verifying party's final level-aware <see cref="JAdESSignatureValidation.ValidateAsync(ReadOnlyMemory{byte}, TryParseJAdESMessageDelegate, DecodeJAdESProtectedHeaderDelegate, DetectJAdESX5tPresenceDelegate, TryParseJAdESEtsiUDelegate, PublicKeyMemory, DecodeDelegate, EncodeDelegate, JAdESDetachedObjectDereferenceDelegate?, JAdESDetachedObjectDereferenceContext?, ReadOnlyMemory{byte}?, JAdESHttpHeadersCanonicalizationContext?, JAdESUnknownDetachedObjectMechanismDelegate?, AdESBaselineLevel, JAdESCanonicalizeUnsignedElementDelegate, BaseMemoryPool, CancellationToken)"/>
/// call is handed only a plain <c>byte[]</c> reconstructed from the augmented signature's own wire bytes plus
/// the verifying party's own, independently-known public key — never a creation-side model, message, or
/// decoded fact.
/// </para>
/// </remarks>
[TestClass]
internal sealed class JAdESMultiServerWireFlowTests
{
    /// <summary>The <c>Content-Type</c> RFC 3161 §3.4 gives a <c>TimeStampReq</c>.</summary>
    private const string TimestampQueryContentType = "application/timestamp-query";

    /// <summary>The <c>Content-Type</c> RFC 3161 §3.4 gives a <c>TimeStampResp</c>.</summary>
    private const string TimestampReplyContentType = "application/timestamp-reply";


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Mints a JAdES B-B signature, raises it to B-T with a real <c>TimeStampReq</c>/<c>TimeStampResp</c> round
    /// trip to Host A, to B-LT with an <c>anyValData</c> element, then to B-LTA with a SECOND real round trip to
    /// an INDEPENDENT Host B — a verifying party reconstructed from the resulting wire bytes alone then runs the
    /// level-aware <see cref="JAdESSignatureValidation.ValidateAsync(ReadOnlyMemory{byte}, TryParseJAdESMessageDelegate, DecodeJAdESProtectedHeaderDelegate, DetectJAdESX5tPresenceDelegate, TryParseJAdESEtsiUDelegate, PublicKeyMemory, DecodeDelegate, EncodeDelegate, JAdESDetachedObjectDereferenceDelegate?, JAdESDetachedObjectDereferenceContext?, ReadOnlyMemory{byte}?, JAdESHttpHeadersCanonicalizationContext?, JAdESUnknownDetachedObjectMechanismDelegate?, AdESBaselineLevel, JAdESCanonicalizeUnsignedElementDelegate, BaseMemoryPool, CancellationToken)"/>
    /// at <see cref="AdESBaselineLevel.BLTA"/> and reaches a valid result — proof the JWS signature value, the
    /// <c>sigTst</c> token's message-imprint binding, and the <c>arcTst</c> token's own prefix-bound
    /// message-imprint binding are ALL independently re-verified from wire bytes alone, the <c>sigTst</c>/
    /// <c>arcTst</c> tokens having crossed two SEPARATE real sockets neither this test process nor the other
    /// hand-wrote.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-42.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult; " +
            "every caller disposes that return value via its own 'using' declaration.")]
    [TestMethod]
    public async Task CreatesAugmentsToBLTAAcrossTwoLoopbackHttpHostsAndReachesLevelAwareValidSignatureAtBLTA()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset signatureTimestampTime = signingTime.AddHours(1);
        DateTimeOffset archiveTimestampTime = signingTime.AddHours(2);
        DateTimeOffset notBefore = signingTime.AddYears(-1);
        DateTimeOffset notAfter = signingTime.AddYears(9);

        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: notBefore, notAfter: notAfter);

        //Host A (TSA, sigTst): answers every request with a genuine token minted through the independent oracle.
        var sigTstResponder = new MintingTimestampResponder(authority, [authority, root], signatureTimestampTime);
        await using BinaryHttpHost sigTstHost = await BinaryHttpHost.StartAsync(
            new BinaryTsaHostAdapter(sigTstResponder.FetchAsync).HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string sigTstTsaUri = new Uri(sigTstHost.BaseAddress, "/sigtst").AbsoluteUri;

        //Host B (TSA, arcTst): a SECOND, independent loopback host.
        var arcTstResponder = new MintingTimestampResponder(authority, [authority, root], archiveTimestampTime);
        await using BinaryHttpHost arcTstHost = await BinaryHttpHost.StartAsync(
            new BinaryTsaHostAdapter(arcTstResponder.FetchAsync).HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string arcTstTsaUri = new Uri(arcTstHost.BaseAddress, "/arctst").AbsoluteUri;

        using HttpClient sigTstHttpClient = LoopbackTls.CreatePinnedHttpClient(sigTstHost.Certificate);
        using HttpClient arcTstHttpClient = LoopbackTls.CreatePinnedHttpClient(arcTstHost.Certificate);
        var wireSigTstTsa = new WireTimestampTransport(sigTstHttpClient);
        var wireArcTstTsa = new WireTimestampTransport(arcTstHttpClient);

        using PkiCertificateMemory signingCertificate = OcspTestFixtures.ToCertificateCarrier(root.Certificate);

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        byte[] payloadBytes = "JAdES multi-server wire content"u8.ToArray();

        //=== B-B: attached. ===
        byte[] bbWireCopy;
        {
            using JAdESSignatureCreationResult created = await SignAsync(
                ConformantHeaders(signingTime), new JAdESAttachedPayloadInput(payloadBytes), privateKey, TestContext.CancellationToken).ConfigureAwait(false);
            bbWireCopy = Serialize(created, JoseSerializationFormat.FlattenedJson);
        }

        //=== B-T: a real TimeStampReq/TimeStampResp round trip to Host A. ===
        byte[] btWireCopy = await JAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new JAdESSignatureTimestampContext
            {
                WireBytes = bbWireCopy,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = sigTstTsaUri,
                FetchResponse = wireSigTstTsa.FetchAsync,
                SigningCertificate = signingCertificate,
                TargetLevel = AdESBaselineLevel.BT
            },
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //=== B-LT: anyValData satisfies JA-6.3-38/j by construction (no live round trip needed for this SPO;
        //JAdESSignatureAugmentationTests already covers OCSP/CRL round trips for xVals/rVals in isolation). ===
        byte[] bltWireCopy = await JAdESSignatureAugmentation.AddValidationDataAsync(
            new JAdESValidationDataContext
            {
                WireBytes = btWireCopy,
                Material = new JAdESValidationMaterial { Certificates = [signingCertificate] },
                Placement = JAdESValidationDataPlacement.AnyValData,
                TargetLevel = AdESBaselineLevel.BLT
            },
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //=== B-LTA: a SECOND real TimeStampReq/TimeStampResp round trip, to the INDEPENDENT Host B. ===
        byte[] bltaWireCopy = await JAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new JAdESArchiveTimestampContext
            {
                WireBytes = bltWireCopy,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                PayloadSource = new JAdESBase64UrlPayloadImprintSource(Encoding.ASCII.GetBytes(TestSetup.Base64UrlEncoder(payloadBytes))),
                TsaLegs = [new JAdESArchiveTimestampTsaLeg { TsaUri = arcTstTsaUri, FetchResponse = wireArcTstTsa.FetchAsync }],
                SigningCertificate = signingCertificate,
                ChainCompletenessAttested = true,
                CanonAlg = "urn:test:canon",
                Canonicalize = StubCanonicalizeAsync,
                TargetLevel = AdESBaselineLevel.BLTA
            },
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //=== Verifying party: reconstructs from the wire bytes alone plus its own independently-known public key
        //-- never a creation-side object. A successful result here proves the sigTst/arcTst tokens' message
        //imprints verified against the ACTUAL JWS Signature Value/etsiU prefix bytes, which the two Time-
        //Stamping Authorities could only have echoed correctly by decoding the genuine HTTP POST bodies they
        //each received over their own real socket. ===
        using JAdESValidationResult result = await JAdESSignatureValidation.ValidateAsync(
            bltaWireCopy,
            JAdESMessageJson.TryParse,
            JAdESProtectedHeaderJson.Decode,
            JAdESProtectedHeaderJson.DetectX5tPresence,
            JAdESEtsiUJson.TryParse,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null,
            httpHeadersContext: null, unknownMechanismHandler: null,
            AdESBaselineLevel.BLTA, StubCanonicalizeAsync,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid,
            "Creation and augmentation to B-LTA over two independent loopback HTTP hosts, verified from wire bytes alone, must reach a valid level-aware result.");
        Assert.AreEqual(AdESBaselineLevel.BLTA, result.Level);

        bool sawSignatureTimestamp = false;
        bool sawArchiveTimestamp = false;
        JAdESUnsignedHeaders unsignedHeaders = result.Verified!.Value.Value.UnsignedHeaders!;
        for(int i = 0; i < unsignedHeaders.Count; ++i)
        {
            switch(unsignedHeaders[i])
            {
                case JAdESUnsignedHeaderElementSignatureTimestamp:
                    sawSignatureTimestamp = true;
                    break;

                case JAdESUnsignedHeaderElementArchiveTimestamp:
                    sawArchiveTimestamp = true;
                    break;
            }
        }

        Assert.IsTrue(sawSignatureTimestamp, "The sigTst element raised over Host A's real round trip must decode back out of the wire bytes.");
        Assert.IsTrue(sawArchiveTimestamp, "The arcTst element raised over Host B's real round trip must decode back out of the wire bytes.");
    }


    /// <summary>
    /// Negative leg over the socket: a Time-Stamping Authority that returns a genuine, correctly-signed token
    /// minted over a message imprint that does NOT match the request's own is rejected with a typed
    /// <see cref="TimestampAcquisitionException"/> before anything is attached; the signature the augmentation
    /// was asked to raise is left byte-for-byte unchanged. Mirrors the CB-AdES exemplar's own negative leg shape.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult; " +
            "every caller disposes that return value via its own 'using' declaration.")]
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

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        keyPair.PublicKey.Dispose();

        using PkiCertificateMemory signingCertificate = OcspTestFixtures.ToCertificateCarrier(root.Certificate);

        byte[] baselineWireCopy;
        {
            using JAdESSignatureCreationResult created = await SignAsync(
                ConformantHeaders(signingTime), new JAdESAttachedPayloadInput("JAdES wire mismatched-imprint payload"u8.ToArray()), privateKey, TestContext.CancellationToken).ConfigureAwait(false);
            baselineWireCopy = Serialize(created, JoseSerializationFormat.FlattenedJson);
        }

        TimestampAcquisitionException exception = await Assert.ThrowsExactlyAsync<TimestampAcquisitionException>(
            async () => await JAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new JAdESSignatureTimestampContext
                {
                    WireBytes = baselineWireCopy,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = tsaUri,
                    FetchResponse = wireTsa.FetchAsync,
                    SigningCertificate = signingCertificate,
                    TargetLevel = AdESBaselineLevel.BT
                },
                JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
                TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.AreEqual(TimestampAcquisitionFailureKind.MessageImprintMismatch, exception.FailureKind,
            "A token whose message imprint does not match the digest the request carried is refused for exactly that reason (RFC 3161 §2.4.2).");

        bool parsed = JAdESMessageJson.TryParse(baselineWireCopy, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out UnverifiedJAdESMessage? message, out _);
        Assert.IsTrue(parsed);
        using(message)
        {
            Assert.IsNull(message!.EtsiURawBytes, "A rejected token is never attached: the baseline signature must carry no etsiU member at all.");
        }
    }


    private static ValueTask<JAdESSignatureCreationResult> SignAsync(
        JAdESProtectedHeaders headers, JAdESSigningPayloadInput payloadInput, PrivateKeyMemory privateKey, CancellationToken cancellationToken) =>
        JAdESSignatureCreation.SignAsync(
            headers, payloadInput, unsignedHeaders: null,
            JAdESProtectedHeaderJson.Encode, JAdESEtsiUJson.Encode, TestSetup.Base64UrlEncoder,
            privateKey, MicrosoftCryptographicFunctions.SignP256Async,
            dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, cancellationToken: cancellationToken);


    private static byte[] Serialize(JAdESSignatureCreationResult result, JoseSerializationFormat format) =>
        JAdESSignatureCreation.Serialize(result, format, TestSetup.Base64UrlEncoder, JsonSerialize);


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TestDigest()'s ownership transfers into the returned JAdESProtectedHeaders; every " +
            "caller disposes that return value via its own 'using' declaration.")]
    private static JAdESProtectedHeaders ConformantHeaders(DateTimeOffset signingTime) =>
        new(WellKnownJwaValues.Es256, issuedAt: new JAdESClaimedSigningTime(signingTime), x5tHashS256: TestDigest());


    private static DigestValue TestDigest()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(32);
        new byte[32].CopyTo(owner.Memory);

        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }


    /// <summary>A content-sensitive canonicalization stub — see <c>JAdESLifecycleFlowTests.StubCanonicalizeAsync</c>'s identical rationale.</summary>
    private static ValueTask<PooledMemory> StubCanonicalizeAsync(string canonAlg, JAdESUnsignedHeaderElement element, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        byte[] fingerprint = element switch
        {
            JAdESUnsignedHeaderElementSignatureTimestamp e => Fingerprint(e.Kind, e.Carriage),
            JAdESUnsignedHeaderElementArchiveTimestamp e => Fingerprint(e.Kind, e.Carriage),
            JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp e => Fingerprint(e.Kind, e.Carriage),
            JAdESUnsignedHeaderElementReferencesTimestamp e => Fingerprint(e.Kind, e.Carriage),
            _ => Encoding.UTF8.GetBytes(element.Kind)
        };

        return ValueTask.FromResult(PooledMemory.FromBytes(fingerprint, pool, CryptoTags.JAdESMessageImprintInput));

        static byte[] Fingerprint(string kind, JAdESUnsignedValue<AdESTimestampContainer> carriage)
        {
            if(carriage is not JAdESClearUnsignedValue<AdESTimestampContainer> clear)
            {
                return Encoding.UTF8.GetBytes(kind);
            }

            using var buffer = new System.IO.MemoryStream();
            buffer.Write(Encoding.UTF8.GetBytes(kind));
            for(int i = 0; i < clear.Value.TstTokens.Count; ++i)
            {
                buffer.Write(clear.Value.TstTokens[i].Val.Span);
            }

            return buffer.ToArray();
        }
    }


    //UnsafeRelaxedJsonEscaping: kept consistent with JAdESLifecycleFlowTests's own choice, though this file's own
    //tests do not themselves search wire text for base64 substrings -- shared convention, not a requirement here.
    private static readonly JsonSerializerOptions RelaxedJsonOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };


    private static byte[] JsonSerialize(object value) => JsonSerializer.SerializeToUtf8Bytes(value, RelaxedJsonOptions);


    /// <summary>
    /// Bridges a <see cref="BinaryHttpHost"/> to a <see cref="FetchTimestampResponseAsyncDelegate"/>-shaped
    /// responder: wraps the received request octets as a <see cref="TimestampRequest"/>-tagged carrier, calls
    /// the responder, and returns its answer as the <c>application/timestamp-reply</c> body. Mirrors
    /// <c>CBAdESMultiServerWireFlowTests.BinaryTsaHostAdapter</c> exactly (transport is format-agnostic).
    /// </summary>
    private sealed class BinaryTsaHostAdapter
    {
        private readonly FetchTimestampResponseAsyncDelegate responder;


        internal BinaryTsaHostAdapter(FetchTimestampResponseAsyncDelegate responder)
        {
            this.responder = responder;
        }


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


    /// <summary>Copies received DER octets into a pooled carrier of the stated kind.</summary>
    private static PkiCertificateMemory ToCarrier(byte[] derBytes, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>
    /// The client-side RFC 3161 §3.4 HTTP binding: implements <see cref="FetchTimestampResponseAsyncDelegate"/>
    /// over a real <see cref="HttpClient"/> POST. Mirrors <c>CBAdESMultiServerWireFlowTests.WireTimestampTransport</c>.
    /// </summary>
    private sealed class WireTimestampTransport
    {
        private readonly HttpClient httpClient;


        internal WireTimestampTransport(HttpClient httpClient)
        {
            this.httpClient = httpClient;
        }


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
    /// A <see cref="FetchTimestampResponseAsyncDelegate"/> test double that mints a genuine, correctly-signed
    /// token — through the independent BouncyCastle TSP oracle — but over a FIXED imprint that never matches
    /// what a real request states, for the mismatched-imprint negative leg. Mirrors
    /// <c>CBAdESMultiServerWireFlowTests.MismatchedImprintTsaResponder</c>.
    /// </summary>
    private sealed class MismatchedImprintTsaResponder
    {
        private static byte[] WrongImprint { get; } = new byte[32];

        private readonly X509ChainTestRingNode authority;
        private readonly System.Collections.Generic.IReadOnlyList<X509ChainTestRingNode> embeddedCertificates;
        private readonly DateTimeOffset generationTime;


        internal MismatchedImprintTsaResponder(
            X509ChainTestRingNode authority,
            System.Collections.Generic.IReadOnlyList<X509ChainTestRingNode> embeddedCertificates,
            DateTimeOffset generationTime)
        {
            this.authority = authority;
            this.embeddedCertificates = embeddedCertificates;
            this.generationTime = generationTime;
        }


        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the response carrier transfers to the caller via the returned ValueTask.")]
        internal ValueTask<PkiCertificateMemory?> FetchAsync(TimestampFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken)
        {
            using PkiCertificateMemory token = X509ChainTestRingTimestamping.MintTimestampTokenOverImprint(
                authority, embeddedCertificates, WrongImprint, generationTime);

            return ValueTask.FromResult<PkiCertificateMemory?>(WrapGrantedResponse(token.AsReadOnlySpan(), pool));
        }


        private static PkiCertificateMemory WrapGrantedResponse(ReadOnlySpan<byte> token, BaseMemoryPool pool)
        {
            var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
            using(writer.PushSequence())
            {
                using(writer.PushSequence())
                {
                    writer.WriteInteger(0);
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
