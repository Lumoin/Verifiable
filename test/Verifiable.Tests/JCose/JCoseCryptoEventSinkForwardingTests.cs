using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Linq;
using System.Text;
using System.Text.Json;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Coverage for the wave-7 <see cref="CryptoEventSink"/> widening of the JOSE/COSE explicit-delegate call
/// sites (<c>Cose.cs</c>/<c>Jose.cs</c>/<c>JwtSigningExtensions.cs</c>): each site that resolves and invokes
/// a <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/> directly (rather than through a bound
/// <see cref="PrivateKey"/>/<see cref="PublicKey"/>) forwards the produced <see cref="CryptoEvent"/> through
/// its trailing <c>CryptoEventSink? eventSink</c> parameter — to the caller's explicit sink when supplied,
/// or to <see cref="CryptographicKeyEvents.DefaultSink"/> (the global <see cref="CryptographicKeyEvents.Events"/>
/// stream) otherwise. Also smoke-tests the resolver/binder generic overloads (the second sanctioned route
/// design item 5 keeps) so they are no longer untested surface.
/// </summary>
[TestClass]
internal sealed class JCoseCryptoEventSinkForwardingTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly JwtPartDecoder PartDecoder =
        static bytes => JsonSerializer.Deserialize<Dictionary<string, object>>(bytes, TestSetup.DefaultSerializationOptions)
            ?? throw new FormatException("JWT part parsed to null.");


    /// <summary>
    /// <see cref="Cose.SignAsync(EncodedCoseProtectedHeader, IReadOnlyDictionary{int, object}?, ReadOnlyMemory{byte}, BuildSigStructureDelegate, PrivateKeyMemory, SigningDelegate, MemoryPool{byte}, CancellationToken, CryptoEventSink?)"/>
    /// forwards the <see cref="SignatureProducedEvent"/> to an explicit sink instead of the global stream.
    /// </summary>
    [TestMethod]
    public async Task CoseSignAsyncExplicitDelegateForwardsToExplicitSink()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 };
        EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(headerMap), BaseMemoryPool.Shared);
        byte[] payload = BuildCborPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var observed = new List<CryptoEvent>();

        using CoseSign1Message message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            eventSink: observed.Add,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        SignatureProducedEvent produced = Assert.ContainsSingle(observed.OfType<SignatureProducedEvent>());
        Assert.AreEqual(CryptoAlgorithm.P256, produced.Algorithm);
        Assert.IsGreaterThan(0, produced.SignatureLength);
    }


    /// <summary>
    /// <see cref="Cose.VerifyAsync(CoseSign1Message, BuildSigStructureDelegate, PublicKeyMemory, VerificationDelegate, CancellationToken, CryptoEventSink?)"/>
    /// forwards the <see cref="VerificationCompletedEvent"/> to an explicit sink.
    /// </summary>
    [TestMethod]
    public async Task CoseVerifyAsyncExplicitDelegateForwardsToExplicitSink()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 };
        EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(headerMap), BaseMemoryPool.Shared);
        byte[] payload = BuildCborPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using CoseSign1Message message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader, unprotectedHeader: null, payload, CoseSerialization.BuildSigStructure,
            privateKey, MicrosoftCryptographicFunctions.SignP256Async, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var observed = new List<CryptoEvent>();

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            message,
            CoseSerialization.BuildSigStructure,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            eventSink: observed.Add,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid);
        VerificationCompletedEvent produced = Assert.ContainsSingle(observed.OfType<VerificationCompletedEvent>());
        Assert.AreEqual(VerificationOutcome.Valid, produced.Outcome);
    }


    /// <summary>
    /// <see cref="Jws.SignAsync{TJwtPart}(TJwtPart, TJwtPart, JwtPartEncoder{TJwtPart}, EncodeDelegate, PrivateKeyMemory, SigningDelegate, MemoryPool{byte}, CancellationToken, CryptoEventSink?)"/>
    /// (the typed explicit-delegate overload) forwards the <see cref="SignatureProducedEvent"/> to an
    /// explicit sink.
    /// </summary>
    [TestMethod]
    public async Task JwsSignAsyncTypedForwardsToExplicitSink()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256 };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "wave7-jws-sign-typed" };

        var observed = new List<CryptoEvent>();

        using JwsMessage message = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            eventSink: observed.Add,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsGreaterThan(0, message.Signatures[0].SignatureBytes.Length);
        SignatureProducedEvent produced = Assert.ContainsSingle(observed.OfType<SignatureProducedEvent>());
        Assert.AreEqual(CryptoAlgorithm.P256, produced.Algorithm);
    }


    /// <summary>
    /// <see cref="Jws.SignAsync{TJwtPart}(TJwtPart, ReadOnlyMemory{byte}, JwtPartEncoder{TJwtPart}, EncodeDelegate, PrivateKeyMemory, SigningDelegate, MemoryPool{byte}, IReadOnlyDictionary{string, object}?, CancellationToken, CryptoEventSink?)"/>
    /// (the raw-payload overload <c>DidCommSignedExtensions.PackSignedAsync</c> reaches) forwards to an
    /// explicit sink, and — the DIDComm symmetry property — reaches <see cref="CryptographicKeyEvents.DefaultSink"/>
    /// (the global stream) when no sink is supplied, matching what <see cref="Jws.VerifySignatureAsync(string, ReadOnlyMemory{byte}, bool, ReadOnlyMemory{byte}, EncodeDelegate, VerificationDelegate, ReadOnlyMemory{byte}, MemoryPool{byte}, CancellationToken, CryptoEventSink?)"/>
    /// (the sibling <c>UnpackSignedAsync</c> reaches) already does on the verify side.
    /// </summary>
    [TestMethod]
    public async Task JwsSignAsyncRawPayloadForwardsToExplicitSinkAndDefaultsToGlobalStream()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var protectedHeader = new JwtHeader
        {
            [WellKnownJoseHeaderNames.Typ] = "application/didcomm-signed+json",
            [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256
        };
        byte[] rawPayload = Encoding.UTF8.GetBytes("""{"id":"raw-payload-wave7"}""");

        var observed = new List<CryptoEvent>();

        using(JwsMessage explicitSinkMessage = await Jws.SignAsync(
            protectedHeader,
            rawPayload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            unprotectedHeader: null,
            eventSink: observed.Add,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.ContainsSingle(observed.OfType<SignatureProducedEvent>());
        }

        //No explicit sink this time: the event must still reach the process-wide global stream by default.
        var globalObserver = new TestObserver<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(globalObserver))
        using(JwsMessage defaultRouteMessage = await Jws.SignAsync(
            protectedHeader,
            rawPayload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            unprotectedHeader: null,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.Contains(
                (SignatureProducedEvent e) => e.Algorithm == CryptoAlgorithm.P256,
                globalObserver.Received.OfType<SignatureProducedEvent>(),
                "The raw-payload SignAsync overload must publish to the global stream by default when no explicit sink is supplied.");
        }
    }


    /// <summary>
    /// <see cref="Jws.VerifyAsync(JwsMessage, EncodeDelegate, PublicKeyMemory, VerificationDelegate, MemoryPool{byte}, CancellationToken, CryptoEventSink?)"/>
    /// forwards the <see cref="VerificationCompletedEvent"/> to an explicit sink.
    /// </summary>
    [TestMethod]
    public async Task JwsVerifyAsyncMessageOverloadForwardsToExplicitSink()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256 };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "wave7-jws-verify-message" };

        using JwsMessage message = await Jws.SignAsync(
            header, payload, JwtWireFixtures.EncodeJwtPart, TestSetup.Base64UrlEncoder,
            privateKey, MicrosoftCryptographicFunctions.SignP256Async, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var observed = new List<CryptoEvent>();

        bool isValid = await Jws.VerifyAsync(
            message,
            TestSetup.Base64UrlEncoder,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            BaseMemoryPool.Shared,
            eventSink: observed.Add,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid);
        Assert.ContainsSingle(observed.OfType<VerificationCompletedEvent>());
    }


    /// <summary>
    /// <see cref="Jws.VerifySignatureAsync(string, ReadOnlyMemory{byte}, bool, ReadOnlyMemory{byte}, EncodeDelegate, VerificationDelegate, ReadOnlyMemory{byte}, MemoryPool{byte}, CancellationToken, CryptoEventSink?)"/>
    /// (the overload <c>DidCommSignedExtensions.UnpackSignedAsync</c> reaches) forwards to an explicit sink.
    /// </summary>
    [TestMethod]
    public async Task JwsVerifySignatureAsyncForwardsToExplicitSink()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var protectedHeader = new JwtHeader { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256 };
        byte[] rawPayload = Encoding.UTF8.GetBytes("""{"id":"verify-signature-wave7"}""");

        using JwsMessage signed = await Jws.SignAsync(
            protectedHeader, rawPayload, JwtWireFixtures.EncodeJwtPart, TestSetup.Base64UrlEncoder,
            privateKey, MicrosoftCryptographicFunctions.SignP256Async, BaseMemoryPool.Shared,
            unprotectedHeader: null, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        JwsSignatureComponent signature = signed.Signatures[0];
        var observed = new List<CryptoEvent>();

        bool isValid = await Jws.VerifySignatureAsync(
            signature.Protected,
            rawPayload,
            base64UrlPayload: true,
            signature.SignatureBytes,
            TestSetup.Base64UrlEncoder,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            publicKey.AsReadOnlyMemory(),
            BaseMemoryPool.Shared,
            eventSink: observed.Add,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid);
        Assert.ContainsSingle(observed.OfType<VerificationCompletedEvent>());
    }


    /// <summary>
    /// <see cref="Jws.VerifyAsync(string, DecodeDelegate, MemoryPool{byte}, PublicKeyMemory, VerificationDelegate, int, CancellationToken, CryptoEventSink?)"/>
    /// (compact serialization) forwards to an explicit sink.
    /// </summary>
    [TestMethod]
    public async Task JwsVerifyAsyncCompactStringForwardsToExplicitSink()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256 };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "wave7-jws-verify-compact" };

        using JwsMessage message = await Jws.SignAsync(
            header, payload, JwtWireFixtures.EncodeJwtPart, TestSetup.Base64UrlEncoder,
            privateKey, MicrosoftCryptographicFunctions.SignP256Async, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compact = JwsSerialization.SerializeCompact(message, TestSetup.Base64UrlEncoder);
        var observed = new List<CryptoEvent>();

        bool isValid = await Jws.VerifyAsync(
            compact,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            Jws.DefaultMaxJwsLength,
            eventSink: observed.Add,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid);
        Assert.ContainsSingle(observed.OfType<VerificationCompletedEvent>());
    }


    /// <summary>
    /// <see cref="Jws.VerifyAndDecodeAsync(string, DecodeDelegate, JwtPartDecoder, MemoryPool{byte}, PublicKeyMemory, VerificationDelegate, int, CancellationToken, CryptoEventSink?)"/>
    /// forwards to an explicit sink.
    /// </summary>
    [TestMethod]
    public async Task JwsVerifyAndDecodeAsyncForwardsToExplicitSink()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256 };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "wave7-jws-verify-and-decode" };

        using JwsMessage message = await Jws.SignAsync(
            header, payload, JwtWireFixtures.EncodeJwtPart, TestSetup.Base64UrlEncoder,
            privateKey, MicrosoftCryptographicFunctions.SignP256Async, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compact = JwsSerialization.SerializeCompact(message, TestSetup.Base64UrlEncoder);
        var observed = new List<CryptoEvent>();

        JwsVerificationResult result = await Jws.VerifyAndDecodeAsync(
            compact,
            TestSetup.Base64UrlDecoder,
            PartDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            Jws.DefaultMaxJwsLength,
            eventSink: observed.Add,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.ContainsSingle(observed.OfType<VerificationCompletedEvent>());
    }


    /// <summary>
    /// <see cref="JwtSigningExtensions.SignAsync(UnsignedJwt, PrivateKeyMemory, JwtHeaderSerializer, JwtPayloadSerializer, EncodeDelegate, SigningDelegate, MemoryPool{byte}, CancellationToken, CryptoEventSink?)"/>
    /// (the primitive <c>DidCommFromPriorExtensions.PackFromPriorAsync</c> calls) forwards to an explicit sink.
    /// </summary>
    [TestMethod]
    public async Task UnsignedJwtSignAsyncForwardsToExplicitSink()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var header = new JwtHeader
        {
            [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt,
            [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256
        };
        var payload = new JwtPayload { [WellKnownJwtClaimNames.Iss] = "did:example:wave7-prior" };
        var unsigned = new UnsignedJwt(header, payload);

        JwtHeaderSerializer headerSerializer = static h => Encoding.UTF8.GetBytes(JsonSerializer.Serialize((Dictionary<string, object>)h, TestSetup.DefaultSerializationOptions));
        JwtPayloadSerializer payloadSerializer = static p => Encoding.UTF8.GetBytes(JsonSerializer.Serialize((Dictionary<string, object>)p, TestSetup.DefaultSerializationOptions));

        var observed = new List<CryptoEvent>();

        using JwsMessage message = await unsigned.SignAsync(
            privateKey,
            headerSerializer,
            payloadSerializer,
            TestSetup.Base64UrlEncoder,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            eventSink: observed.Add,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsGreaterThan(0, message.Signatures[0].SignatureBytes.Length);
        Assert.ContainsSingle(observed.OfType<SignatureProducedEvent>());
    }


    /// <summary>
    /// The resolver/binder <see cref="Cose.SignAsync{TResolverState, TBinderState}"/>/<see cref="Cose.VerifyAsync{TResolverState, TBinderState}"/>
    /// overloads (design item 5's second sanctioned route) construct a <see cref="PrivateKey"/>/<see cref="PublicKey"/>
    /// internally, so they emit through the key-object choke point to the global stream — no
    /// <see cref="CryptoEventSink"/> parameter exists on this route by design (see <see cref="CryptoEventSink"/>).
    /// This smoke test proves the round trip works and that both events reach <see cref="CryptographicKeyEvents.Events"/>.
    /// </summary>
    [TestMethod]
    public async Task CoseResolverBinderOverloadsEmitToGlobalStream()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 };
        EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(headerMap), BaseMemoryPool.Shared);
        byte[] payload = BuildCborPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKeyMemory = keyPair.PublicKey;
        using PrivateKeyMemory privateKeyMemory = keyPair.PrivateKey;

        var resolverState = new CoseResolverBinderState(privateKeyMemory.AsReadOnlySpan().ToArray(), publicKeyMemory.AsReadOnlySpan().ToArray());

        var globalObserver = new TestObserver<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(globalObserver))
        {
            using CoseSign1Message message = await Verifiable.JCose.Cose.SignAsync(
                protectedHeader, unprotectedHeader: null, payload, CoseSerialization.BuildSigStructure,
                BaseMemoryPool.Shared, resolverState, ResolvePrivateKeyMaterial, 0, BindPrivateKey, TestContext.CancellationToken).ConfigureAwait(false);

            bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
                message, CoseSerialization.BuildSigStructure, BaseMemoryPool.Shared,
                resolverState, ResolvePublicKeyMaterial, 0, BindPublicKey, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(isValid, "The resolver/binder round trip must verify.");
        }

        Assert.Contains(
            (SignatureProducedEvent e) => e.Algorithm == CryptoAlgorithm.P256,
            globalObserver.Received.OfType<SignatureProducedEvent>(),
            "The resolver/binder SignAsync overload must emit via the PrivateKey choke point to the global stream.");
        Assert.Contains(
            (VerificationCompletedEvent e) => e.Outcome == VerificationOutcome.Valid,
            globalObserver.Received.OfType<VerificationCompletedEvent>(),
            "The resolver/binder VerifyAsync overload must emit via the PublicKey choke point to the global stream.");
    }


    /// <summary>
    /// The resolver/binder <see cref="Jws.SignAsync{TResolverState, TBinderState}"/>/<see cref="Jws.VerifyAsync{TResolverState, TBinderState}"/>
    /// overloads — zero-caller surface design item 5 keeps as the intentional second sanctioned route — round
    /// trip correctly and emit via the key-object choke point to the global stream. Previously untested.
    /// </summary>
    [TestMethod]
    public async Task JwsResolverBinderOverloadsRoundTripAndEmitToGlobalStream()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKeyMemory = keyPair.PublicKey;
        using PrivateKeyMemory privateKeyMemory = keyPair.PrivateKey;

        var resolverState = new JwsResolverBinderState(privateKeyMemory.AsReadOnlySpan().ToArray(), publicKeyMemory.AsReadOnlySpan().ToArray());

        var header = new JwtHeader { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256 };
        var payload = new JwtPayload { [WellKnownJwtClaimNames.Sub] = "wave7-jws-resolver-binder" };

        var globalObserver = new TestObserver<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(globalObserver))
        {
            using JwsMessage message = await Jws.SignAsync(
                header, payload, JwtWireFixtures.EncodeJwtPart, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared,
                resolverState, ResolveJwsPrivateKeyMaterial, 0, BindJwsPrivateKey, TestContext.CancellationToken).ConfigureAwait(false);

            string compact = JwsSerialization.SerializeCompact(message, TestSetup.Base64UrlEncoder);

            bool isValid = await Jws.VerifyAsync(
                compact, TestSetup.Base64UrlDecoder, PartDecoder, BaseMemoryPool.Shared,
                resolverState, ResolveJwsPublicKeyMaterial, 0, BindJwsPublicKey, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(isValid, "The Jws resolver/binder round trip must verify.");

            JwsVerificationResult decodeResult = await Jws.VerifyAndDecodeAsync(
                compact, TestSetup.Base64UrlDecoder, PartDecoder, BaseMemoryPool.Shared,
                resolverState, ResolveJwsPublicKeyMaterial, 0, BindJwsPublicKey, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(decodeResult.IsValid, "The Jws resolver/binder VerifyAndDecodeAsync round trip must verify.");
        }

        Assert.Contains(
            (SignatureProducedEvent e) => e.Algorithm == CryptoAlgorithm.P256,
            globalObserver.Received.OfType<SignatureProducedEvent>(),
            "The resolver/binder SignAsync overload must emit via the PrivateKey choke point to the global stream.");
        Assert.IsGreaterThanOrEqualTo(
            2, globalObserver.Received.OfType<VerificationCompletedEvent>().Count(e => e.Outcome == VerificationOutcome.Valid),
            "Both the VerifyAsync and VerifyAndDecodeAsync resolver/binder overloads must emit via the PublicKey choke point.");
    }


    /// <summary>Builds a minimal CBOR map payload for the COSE_Sign1 tests.</summary>
    private static byte[] BuildCborPayload()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("wave7");
        writer.WriteTextString("jose-cose-forwarding");
        writer.WriteEndMap();
        return writer.Encode();
    }


    /// <summary>Resolver/binder test state carrying the raw P-256 key bytes for the COSE smoke test.</summary>
    private sealed record CoseResolverBinderState(byte[] PrivateKeyBytes, byte[] PublicKeyBytes);


    /// <summary>Resolves the COSE resolver/binder test state's private key bytes into pooled key material.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned PrivateKeyMemory transfers to the caller which disposes via PrivateKey.")]
    private static ValueTask<PrivateKeyMemory?> ResolvePrivateKeyMaterial(CoseKeyContext context, MemoryPool<byte> pool, CoseResolverBinderState state, CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> owner = pool.Rent(state.PrivateKeyBytes.Length);
        state.PrivateKeyBytes.CopyTo(owner.Memory.Span);
        return ValueTask.FromResult<PrivateKeyMemory?>(new PrivateKeyMemory(owner, CryptoTags.P256PrivateKey));
    }


    /// <summary>Resolves the COSE resolver/binder test state's public key bytes into pooled key material.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned PublicKeyMemory transfers to the caller which disposes via PublicKey.")]
    private static ValueTask<PublicKeyMemory?> ResolvePublicKeyMaterial(CoseKeyContext context, MemoryPool<byte> pool, CoseResolverBinderState state, CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> owner = pool.Rent(state.PublicKeyBytes.Length);
        state.PublicKeyBytes.CopyTo(owner.Memory.Span);
        return ValueTask.FromResult<PublicKeyMemory?>(new PublicKeyMemory(owner, CryptoTags.P256PublicKey));
    }


    /// <summary>Binds the resolved private key material to the Microsoft P-256 signing function.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned PrivateKey transfers to the caller.")]
    private static ValueTask<PrivateKey> BindPrivateKey(PrivateKeyMemory material, int state, CancellationToken cancellationToken) =>
        ValueTask.FromResult(new PrivateKey(material, "wave7-cose-key", MicrosoftCryptographicFunctions.SignP256Async));


    /// <summary>Binds the resolved public key material to the Microsoft P-256 verification function.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned PublicKey transfers to the caller.")]
    private static ValueTask<PublicKey> BindPublicKey(PublicKeyMemory material, int state, CancellationToken cancellationToken) =>
        ValueTask.FromResult(new PublicKey(material, "wave7-cose-key", MicrosoftCryptographicFunctions.VerifyP256Async));


    /// <summary>Resolver/binder test state carrying the raw P-256 key bytes for the Jws smoke test.</summary>
    private sealed record JwsResolverBinderState(byte[] PrivateKeyBytes, byte[] PublicKeyBytes);


    /// <summary>Resolves the Jws resolver/binder test state's private key bytes into pooled key material.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned PrivateKeyMemory transfers to the caller which disposes via PrivateKey.")]
    private static ValueTask<PrivateKeyMemory?> ResolveJwsPrivateKeyMaterial(JoseKeyContext context, MemoryPool<byte> pool, JwsResolverBinderState state, CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> owner = pool.Rent(state.PrivateKeyBytes.Length);
        state.PrivateKeyBytes.CopyTo(owner.Memory.Span);
        return ValueTask.FromResult<PrivateKeyMemory?>(new PrivateKeyMemory(owner, CryptoTags.P256PrivateKey));
    }


    /// <summary>Resolves the Jws resolver/binder test state's public key bytes into pooled key material.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned PublicKeyMemory transfers to the caller which disposes via PublicKey.")]
    private static ValueTask<PublicKeyMemory?> ResolveJwsPublicKeyMaterial(JoseKeyContext context, MemoryPool<byte> pool, JwsResolverBinderState state, CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> owner = pool.Rent(state.PublicKeyBytes.Length);
        state.PublicKeyBytes.CopyTo(owner.Memory.Span);
        return ValueTask.FromResult<PublicKeyMemory?>(new PublicKeyMemory(owner, CryptoTags.P256PublicKey));
    }


    /// <summary>Binds the resolved private key material to the Microsoft P-256 signing function.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned PrivateKey transfers to the caller.")]
    private static ValueTask<PrivateKey> BindJwsPrivateKey(PrivateKeyMemory material, int state, CancellationToken cancellationToken) =>
        ValueTask.FromResult(new PrivateKey(material, "wave7-jws-key", MicrosoftCryptographicFunctions.SignP256Async));


    /// <summary>Binds the resolved public key material to the Microsoft P-256 verification function.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned PublicKey transfers to the caller.")]
    private static ValueTask<PublicKey> BindJwsPublicKey(PublicKeyMemory material, int state, CancellationToken cancellationToken) =>
        ValueTask.FromResult(new PublicKey(material, "wave7-jws-key", MicrosoftCryptographicFunctions.VerifyP256Async));
}
