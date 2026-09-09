using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Throw-posture and sigD-mechanism coverage for <see cref="JAdESSignatureCreation"/> and the shared
/// <see cref="JAdESHeaderRules"/> rule surface it composes, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Key material.</strong> Every signing key is P-256, minted through
/// <see cref="TestKeyMaterialProvider.CreateP256KeyMaterial"/>, signed via the explicit-delegate
/// <see cref="JAdESSignatureCreation.SignAsync"/> overload with <see cref="MicrosoftCryptographicFunctionsAdapter.SignP256Async"/> —
/// mirroring <c>CBAdESSignatureCreationTests</c>'s own explicit-delegate composition pattern.
/// </para>
/// <para>
/// <strong>No closure capture (dereference/unknown-mechanism seams).</strong> <see cref="DereferenceFromStoreAsync"/>
/// and <see cref="HandleUnknownMechanismAsync"/> are plain <see langword="static"/> methods reaching the fixed
/// URI-reference-to-bytes store exclusively through the explicit, per-call
/// <see cref="JAdESDetachedObjectDereferenceContext.State"/> (an <see cref="ObjectStore"/> instance) — call
/// counting for the sigD-mechanism tests is a <see cref="CountingObjectStore"/> wrapper reached the same way.
/// </para>
/// </remarks>
[TestClass]
internal sealed class JAdESSignatureCreationTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>Full-house creation over an attached payload serializes through all three JWS forms.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-4-03, JA-4-07.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult " +
            "on a successful SignCreateAsync call, disposed here via 'using result'; Roslyn cannot trace ownership " +
            "across the SignCreateAsync call boundary.")]
    [TestMethod]
    public async Task AttachedPayloadCreationSerializesThroughAllThreeForms()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using JAdESSignatureCreationResult result = await SignCreateAsync(
            ConformantHeaders(),
            new JAdESAttachedPayloadInput(new byte[] { 0x01, 0x02, 0x03 }),
            unsignedHeaders: null,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            dereference: null,
            dereferenceContext: null,
            unknownMechanismHandler: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        byte[] compact = JAdESSignatureCreation.Serialize(result, JoseSerializationFormat.Compact, TestSetup.Base64UrlEncoder, JsonSerialize);
        byte[] flattened = JAdESSignatureCreation.Serialize(result, JoseSerializationFormat.FlattenedJson, TestSetup.Base64UrlEncoder, JsonSerialize);
        byte[] general = JAdESSignatureCreation.Serialize(result, JoseSerializationFormat.GeneralJson, TestSetup.Base64UrlEncoder, JsonSerialize);

        Assert.IsGreaterThan(0, compact.Length);
        Assert.IsGreaterThan(0, flattened.Length);
        Assert.IsGreaterThan(0, general.Length);
        Assert.AreEqual(WellKnownJwaValues.Es256, result.Headers.Algorithm);
    }


    /// <summary>A non-empty JWS Unprotected Header forbids Compact serialization (JA-4-05).</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult; " +
            "unsignedHeaders is never taken ownership of by SignAsync (only projected via EncodeJAdESUnprotectedHeaderDelegate) " +
            "and is disposed explicitly below.")]
    [TestMethod]
    public async Task UnprotectedHeaderForbidsCompactSerialization()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using var unsignedHeaders = new JAdESUnsignedHeaders(
            JAdESEtsiUIncorporationMode.Base64Url,
            [new JAdESUnsignedHeaderElementCounterSignature(PooledMemory.FromBytes("\"opaque\""u8, BaseMemoryPool.Shared, Tag.Create(Purpose.Data)))]);

        using JAdESSignatureCreationResult result = await SignCreateAsync(
            ConformantHeaders(),
            new JAdESAttachedPayloadInput(new byte[] { 0x01 }),
            unsignedHeaders,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            dereference: null,
            dereferenceContext: null,
            unknownMechanismHandler: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => JAdESSignatureCreation.Serialize(result, JoseSerializationFormat.Compact, TestSetup.Base64UrlEncoder, JsonSerialize));

        Assert.Contains("JA-4-05", exception.Message);
    }


    /// <summary>Creation with none of the four signing-certificate-identification options throws, citing JA-5.1.7-04 (PASS 1, before any dereferencing).</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.1.11-08.
    /// </remarks>
    [TestMethod]
    public async Task CreationWithNoSigningCertificateIdentificationThrows()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using var headers = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256,
            issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch));

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
            SignCreateAsync(
                headers,
                new JAdESAttachedPayloadInput(new byte[] { 0x01 }),
                unsignedHeaders: null,
                privateKey,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async,
                dereference: null,
                dereferenceContext: null,
                unknownMechanismHandler: null,
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.Contains("JA-5.1.7-04", exception.Message);
    }


    /// <summary>A caller-supplied non-null <see cref="JAdESProtectedHeaders.SigD"/> is refused: this orchestrator is the sole producer.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.8.1-02.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TestDigest()'s ownership transfers into the JAdESProtectedHeaders constructed here, " +
            "disposed via the outer 'using headers' declaration.")]
    [TestMethod]
    public async Task CreationRefusesCallerSuppliedSigD()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using var headers = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256,
            criticalLabels: ["sigD"],
            b64: false,
            issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch),
            x5tHashS256: TestDigest(),
            sigD: new JAdESHttpHeadersReference(["digest"]));

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
            SignCreateAsync(
                headers,
                new JAdESDetachedExternalPayloadInput(new byte[] { 0x01 }),
                unsignedHeaders: null,
                privateKey,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async,
                dereference: null,
                dereferenceContext: null,
                unknownMechanismHandler: null,
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.Contains("sole producer", exception.Message);
    }


    /// <summary>
    /// The <c>HttpHeaders</c> mechanism: creation auto-adds <c>"sigD"</c> to <c>crit</c>, canonicalizes purely
    /// in-library (no dereference delegate invoked), and the resulting <see cref="JAdESHttpHeadersReference"/>
    /// carries the wire-order header names.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.1.9-04, JA-5.1.9-05.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TestDigest()'s ownership transfers into the JAdESProtectedHeaders constructed here, " +
            "which in turn transfers into the returned JAdESSignatureCreationResult on a successful " +
            "SignCreateAsync call, disposed here via 'using result'.")]
    [TestMethod]
    public async Task HttpHeadersMechanismCanonicalizesInLibraryAndAutoAddsCriticalLabel()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using var headers = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256,
            b64: false,
            issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch),
            x5tHashS256: TestDigest());

        var context = new JAdESHttpHeadersCanonicalizationContext(
            RequestTargetValue: null,
            ResponseStatusValue: null,
            HeaderFieldValues: new Dictionary<string, IReadOnlyList<string>> { ["digest"] = ["sha-256=abc"] });

        using JAdESSignatureCreationResult result = await SignCreateAsync(
            headers,
            new JAdESDetachedHttpHeadersPayloadInput(["digest"], context),
            unsignedHeaders: null,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            dereference: null,
            dereferenceContext: null,
            unknownMechanismHandler: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<JAdESHttpHeadersReference>(result.Headers.SigD);
        Assert.Contains("sigD", result.Headers.CriticalLabels!);
        Assert.IsTrue(result.Message.IsDetachedPayload);
    }


    /// <summary>The <c>ObjectIdByURI</c> mechanism dereferences every reference exactly once, in order, and defaults to base64url-encoding each retrieved object (JA-5.2.8.3.2-C4).</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.8.3.2-C2.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult " +
            "on a successful SignCreateAsync call, disposed here via 'using result'.")]
    [TestMethod]
    public async Task ObjectIdByUriDereferencesEachReferenceExactlyOnce()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var store = new ObjectStore(new Dictionary<string, byte[]>
        {
            ["urn:test:a"] = "object-a"u8.ToArray(),
            ["urn:test:b"] = "object-b"u8.ToArray()
        });
        var counting = new CountingObjectStore(store);
        var context = new JAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: counting);

        using JAdESSignatureCreationResult result = await SignCreateAsync(
            ConformantHeaders(),
            new JAdESDetachedObjectIdByUriPayloadInput([
                new JAdESDetachedObjectReferenceInput("urn:test:a", null),
                new JAdESDetachedObjectReferenceInput("urn:test:b", null)
            ]),
            unsignedHeaders: null,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            DereferenceFromStoreAsync,
            context,
            unknownMechanismHandler: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(2, counting.CallCount);
        Assert.IsInstanceOfType<JAdESObjectIdByUriReference>(result.Headers.SigD);
    }


    /// <summary>
    /// The <c>ObjectIdByURIHash</c> mechanism dereferences each reference once and computes a <c>hashV</c>
    /// digest through the registered digest delegate matching an independently computed oracle digest — the
    /// JWS Payload contributes as an empty stream (JA-5.2.8.3.3-05).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult " +
            "on a successful SignCreateAsync call, disposed here via 'using result'.")]
    [TestMethod]
    public async Task ObjectIdByUriHashComputesDigestsMatchingOracleAndSignsEmptyPayload()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        byte[] objectA = "object-a"u8.ToArray();
        var store = new ObjectStore(new Dictionary<string, byte[]> { ["urn:test:a"] = objectA });
        var counting = new CountingObjectStore(store);
        var context = new JAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: counting);

        using DigestValue expectedDigest = await CreateDigestAsync(objectA, TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESSignatureCreationResult result = await SignCreateAsync(
            ConformantHeaders(),
            new JAdESDetachedObjectIdByUriHashPayloadInput(WellKnownHashAlgorithms.Sha256, [new JAdESDetachedObjectReferenceInput("urn:test:a", null)]),
            unsignedHeaders: null,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            DereferenceFromStoreAsync,
            context,
            unknownMechanismHandler: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, counting.CallCount);
        var reference = (JAdESObjectIdByUriHashReference)result.Headers.SigD!;
        Assert.AreSequenceEqual(expectedDigest.AsReadOnlySpan().ToArray(), reference.References[0].Digest!.AsReadOnlySpan().ToArray());
        Assert.IsTrue(result.Message.IsDetachedPayload);
        Assert.IsEmpty(result.Message.Payload.ToArray());
    }


    /// <summary>An unrecognized <c>mId</c> with no handler throws citing JA-5.2.8.1-C1.</summary>
    [TestMethod]
    public async Task UnknownMechanismWithNoHandlerThrows()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using var headers = ConformantHeaders();
        var context = new JAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: null);

        NotSupportedException exception = await Assert.ThrowsExactlyAsync<NotSupportedException>(() =>
            SignCreateAsync(
                headers,
                new JAdESDetachedUnknownMechanismPayloadInput("urn:example:custom", [new JAdESDetachedObjectReferenceInput("urn:test:a", null)]),
                unsignedHeaders: null,
                privateKey,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async,
                dereference: null,
                context,
                unknownMechanismHandler: null,
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.Contains("JA-5.2.8.1-C1", exception.Message);
    }


    /// <summary>An unrecognized <c>mId</c> with a caller-supplied handler resolves the payload through it.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult " +
            "on a successful SignCreateAsync call, disposed here via 'using result'.")]
    [TestMethod]
    public async Task UnknownMechanismWithHandlerResolvesPayload()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var store = new ObjectStore(new Dictionary<string, byte[]> { ["urn:test:a"] = "custom-object"u8.ToArray() });
        var context = new JAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);

        using JAdESSignatureCreationResult result = await SignCreateAsync(
            ConformantHeaders(),
            new JAdESDetachedUnknownMechanismPayloadInput("urn:example:custom", [new JAdESDetachedObjectReferenceInput("urn:test:a", null)]),
            unsignedHeaders: null,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            dereference: null,
            context,
            HandleUnknownMechanismAsync,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<JAdESUnknownDetachedDataObjectReference>(result.Headers.SigD);
        Assert.AreEqual("urn:example:custom", ((JAdESUnknownDetachedDataObjectReference)result.Headers.SigD!).MechanismIdentifier);
    }


    /// <summary>
    /// A PASS-2-only violation (the <c>HttpHeaders</c> mechanism resolved without <c>b64:false</c> on
    /// <c>headers</c> — unreachable at PASS 1, since <c>SigD</c> is still <see langword="null"/> there) still
    /// leaves zero outstanding pool rentals after a genuine in-library canonicalization: the canonicalized
    /// payload's pool rental is returned via the <c>finally</c> clause on the throw path, never leaked.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.1.10-04.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TestDigest()'s ownership transfers into the JAdESProtectedHeaders constructed here, " +
            "disposed via the outer 'using headers' declaration.")]
    [TestMethod]
    public async Task CreationDisposesCanonicalizedPayloadOnPass2ViolationLeavingNoOutstandingPoolRentals()
    {
        using var meteredPool = new MeteredHousePool();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using var headers = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256,
            issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch),
            x5tHashS256: TestDigest());

        var context = new JAdESHttpHeadersCanonicalizationContext(
            RequestTargetValue: null,
            ResponseStatusValue: null,
            HeaderFieldValues: new Dictionary<string, IReadOnlyList<string>> { ["digest"] = ["sha-256=abc"] });

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
            JAdESSignatureCreation.SignAsync(
                headers,
                new JAdESDetachedHttpHeadersPayloadInput(["digest"], context),
                unsignedHeaders: null,
                JAdESProtectedHeaderJson.Encode,
                JAdESEtsiUJson.Encode,
                TestSetup.Base64UrlEncoder,
                privateKey,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async,
                dereference: null,
                dereferenceContext: null,
                unknownMechanismHandler: null,
                meteredPool.Pool,
                cancellationToken: TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.Contains("JA-5.1.10-04", exception.Message);
        Assert.AreEqual(0, meteredPool.OutstandingCount,
            "The canonicalized HttpHeaders payload's pool rental must be returned on the PASS 2 throw, not leaked.");
    }


    private static ValueTask<JAdESSignatureCreationResult> SignCreateAsync(
        JAdESProtectedHeaders headers,
        JAdESSigningPayloadInput payloadInput,
        JAdESUnsignedHeaders? unsignedHeaders,
        PrivateKeyMemory privateKey,
        SigningDelegate signingDelegate,
        JAdESDetachedObjectDereferenceDelegate? dereference,
        JAdESDetachedObjectDereferenceContext? dereferenceContext,
        JAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        CancellationToken cancellationToken) =>
        JAdESSignatureCreation.SignAsync(
            headers,
            payloadInput,
            unsignedHeaders,
            JAdESProtectedHeaderJson.Encode,
            JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlEncoder,
            privateKey,
            signingDelegate,
            dereference,
            dereferenceContext,
            unknownMechanismHandler,
            BaseMemoryPool.Shared,
            cancellationToken: cancellationToken);


    /// <summary>
    /// A reflection-based (non-source-generated) JSON serializer for the general-purpose object graphs
    /// <see cref="JwsSerialization"/>'s Flattened/General JSON forms build (nested
    /// <c>Dictionary&lt;string, object&gt;</c>/<c>List&lt;object&gt;</c>) — this test project disables the
    /// trim/AOT analyzers, so reflection-based <see cref="System.Text.Json.JsonSerializer"/> is fine here even
    /// though the library's own STJ-body firewall keeps <c>Verifiable.JCose</c> itself off the source-generated
    /// <see cref="JwtClaimsJson.Options"/> converter, whose narrower <c>DictionaryStringObjectJsonConverter</c>
    /// does not recurse into a nested <c>List&lt;Dictionary&lt;string, object&gt;&gt;</c> (the <c>signatures</c>
    /// array General JSON needs).
    /// </summary>
    private static byte[] JsonSerialize(object value) => System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(value);


    private static async ValueTask<DigestValue> CreateDigestAsync(byte[] input, CancellationToken cancellationToken) =>
        await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>(input), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TestDigest()'s ownership transfers into the returned JAdESProtectedHeaders; every " +
            "caller disposes that return value via its own 'using' declaration.")]
    private static JAdESProtectedHeaders ConformantHeaders() =>
        new(
            WellKnownJwaValues.Es256,
            issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch),
            x5tHashS256: TestDigest());


    private static DigestValue TestDigest()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(32);
        new byte[32].CopyTo(owner.Memory);
        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }


    /// <summary>Dereferences a URI-reference against a fixed <see cref="ObjectStore"/> or <see cref="CountingObjectStore"/> reached exclusively through <paramref name="context"/> (no closure capture).</summary>
    private static ValueTask<JAdESDetachedObjectDereferenceResult> DereferenceFromStoreAsync(
        string uriReference,
        JAdESDetachedObjectDereferenceContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ObjectStore store = context.State switch
        {
            CountingObjectStore counting => counting.Increment(),
            ObjectStore direct => direct,
            _ => throw new InvalidOperationException("Unexpected context state.")
        };

        if(!store.ObjectsByReference.TryGetValue(uriReference, out byte[]? content))
        {
            return ValueTask.FromResult<JAdESDetachedObjectDereferenceResult>(
                new JAdESDetachedObjectDereferenceFailure($"No test fixture object registered for reference '{uriReference}'."));
        }

        return ValueTask.FromResult<JAdESDetachedObjectDereferenceResult>(
            new JAdESDetachedObjectDereferenceSuccess(PooledMemory.FromBytes(content, pool, Tag.Create(Purpose.Data))));
    }


    /// <summary>Retrieves the JWS Payload for a third-party <c>sigD.mId</c> by concatenating referenced objects looked up in a fixed <see cref="ObjectStore"/> reached exclusively through <paramref name="context"/>.</summary>
    private static ValueTask<PooledMemory> HandleUnknownMechanismAsync(
        string mechanismIdentifier,
        IReadOnlyList<JAdESDetachedObjectReferenceInput> references,
        string? hashAlgorithm,
        JAdESDetachedObjectDereferenceContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        var store = (ObjectStore)context.State!;

        var buffers = new byte[references.Count][];
        int totalLength = 0;
        for(int i = 0; i < references.Count; ++i)
        {
            buffers[i] = store.ObjectsByReference[references[i].Reference];
            totalLength += buffers[i].Length;
        }

        byte[] concatenated = new byte[totalLength];
        int offset = 0;
        for(int i = 0; i < buffers.Length; ++i)
        {
            buffers[i].CopyTo(concatenated, offset);
            offset += buffers[i].Length;
        }

        return ValueTask.FromResult(PooledMemory.FromBytes(concatenated, pool, Tag.Create(Purpose.Data)));
    }


    /// <summary>The explicit, no-closure-capture per-call state <see cref="DereferenceFromStoreAsync"/>/<see cref="HandleUnknownMechanismAsync"/> read through <see cref="JAdESDetachedObjectDereferenceContext.State"/>.</summary>
    private sealed record ObjectStore(IReadOnlyDictionary<string, byte[]> ObjectsByReference);


    /// <summary>Wraps an <see cref="ObjectStore"/> with a per-fixture dereference call counter — the delegate call-counting the sigD-mechanism tests need, reached exclusively through <see cref="JAdESDetachedObjectDereferenceContext.State"/>, never a captured variable.</summary>
    private sealed class CountingObjectStore(ObjectStore inner)
    {
        private int callCount;

        public int CallCount => callCount;

        public ObjectStore Increment()
        {
            Interlocked.Increment(ref callCount);

            return inner;
        }
    }
}
