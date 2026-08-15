using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
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
/// Coverage for <see cref="JAdESSignatureValidation"/> — B-B validation over the three JWS serializations, the
/// fail-closed parse posture, the collect-posture rule surface, and the promotion-to-verified template, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>.
/// </summary>
/// <remarks>
/// Every signing key is P-256, minted through <see cref="TestKeyMaterialProvider.CreateP256KeyMaterial"/>, wired
/// through <see cref="MicrosoftCryptographicFunctions.SignP256Async"/>/<see cref="MicrosoftCryptographicFunctions.VerifyP256Async"/> —
/// mirroring <c>JAdESSignatureCreationTests</c>'s own explicit-delegate composition pattern. E2E round trips are
/// FIREWALLED per serialization form: creation produces wire bytes only, and validation is handed nothing but
/// those bytes plus the public key — never a shared in-memory object.
/// </remarks>
[TestClass]
internal sealed class JAdESSignatureValidationTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>An attached-payload B-B signature round-trips through all three JWS forms and promotes the verified facts.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-4-03.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult on a successful CreateAsync call, disposed here via 'using created'.")]
    [TestMethod]
    public async Task AttachedPayloadRoundTripsThroughAllThreeFormsAndPromotesVerifiedFacts()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        byte[] payload = [0x01, 0x02, 0x03];
        using JAdESSignatureCreationResult created = await CreateAsync(
            ConformantHeaders(sigT: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch)),
            new JAdESAttachedPayloadInput(payload), unsignedHeaders: null, privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        foreach(JoseSerializationFormat format in (JoseSerializationFormat[])[JoseSerializationFormat.Compact, JoseSerializationFormat.FlattenedJson, JoseSerializationFormat.GeneralJson])
        {
            byte[] wireBytes = JAdESSignatureCreation.Serialize(created, format, TestSetup.Base64UrlEncoder, JsonSerialize);

            using JAdESValidationResult result = await ValidateAsync(wireBytes, publicKey, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsValid, $"Expected {format} to validate.");
            Assert.IsNotNull(result.Verified);
            Assert.AreEqual(WellKnownJwaValues.Es256, result.Verified.Value.Value.Headers.Algorithm);
            Assert.IsFalse(result.Verified.Value.Value.PayloadIsDetached);
            Assert.AreEqual(TestClock.CanonicalEpoch.ToUnixTimeSeconds(), result.Verified.Value.Value.Headers.SigT?.Value.ToUnixTimeSeconds());
        }
    }


    /// <summary>A detached payload with no <c>sigD</c> validates against the caller-supplied out-of-band bytes.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-4-07.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult on a successful CreateAsync call, disposed here via 'using created'.")]
    [TestMethod]
    public async Task DetachedPayloadWithNoSigDValidatesAgainstExternalPayload()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        byte[] payload = [0x0a, 0x0b];
        using JAdESSignatureCreationResult created = await CreateAsync(
            ConformantHeaders(), new JAdESDetachedExternalPayloadInput(payload), unsignedHeaders: null, privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wireBytes = JAdESSignatureCreation.Serialize(created, JoseSerializationFormat.FlattenedJson, TestSetup.Base64UrlEncoder, JsonSerialize);

        using JAdESValidationResult missingExternal = await ValidateAsync(wireBytes, publicKey, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(missingExternal.IsValid);
        Assert.IsInstanceOfType<JAdESDetachedObjectUnresolvableFailure>(missingExternal.Failure);

        using JAdESValidationResult withExternal = await ValidateAsync(
            wireBytes, publicKey, TestContext.CancellationToken, externalDetachedPayload: payload).ConfigureAwait(false);
        Assert.IsTrue(withExternal.IsValid);
        Assert.IsTrue(withExternal.Verified!.Value.Value.PayloadIsDetached);
    }


    /// <summary>The <c>HttpHeaders</c> mechanism validates by re-canonicalizing from the caller-supplied context, in-library, no dereferencing.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TestDigest()'s ownership transfers into the JAdESProtectedHeaders constructed here, disposed via the outer 'using headers' declaration.")]
    [TestMethod]
    public async Task HttpHeadersMechanismValidatesByReCanonicalizing()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using var headers = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256, b64: false, issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch), x5tHashS256: TestDigest());

        var context = new JAdESHttpHeadersCanonicalizationContext(
            RequestTargetValue: null, ResponseStatusValue: null,
            HeaderFieldValues: new Dictionary<string, IReadOnlyList<string>> { ["digest"] = ["sha-256=abc"] });

        using JAdESSignatureCreationResult created = await CreateAsync(
            headers, new JAdESDetachedHttpHeadersPayloadInput(["digest"], context), unsignedHeaders: null, privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wireBytes = JAdESSignatureCreation.Serialize(created, JoseSerializationFormat.FlattenedJson, TestSetup.Base64UrlEncoder, JsonSerialize);

        using JAdESValidationResult noContext = await ValidateAsync(wireBytes, publicKey, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(noContext.IsValid);

        using JAdESValidationResult result = await ValidateAsync(
            wireBytes, publicKey, TestContext.CancellationToken, httpHeadersContext: context).ConfigureAwait(false);
        Assert.IsTrue(result.IsValid, result.Failure?.Message);
    }


    /// <summary>The <c>ObjectIdByURI</c> mechanism validates by dereferencing every reference and reconstructing the payload identically to creation.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult on a successful CreateAsync call, disposed here via 'using created'.")]
    [TestMethod]
    public async Task ObjectIdByUriMechanismValidatesByDereferencingEachReference()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var store = new ObjectStore(new Dictionary<string, byte[]>
        {
            ["urn:test:a"] = "object-a"u8.ToArray(),
            ["urn:test:b"] = "object-b"u8.ToArray()
        });
        var context = new JAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);

        using JAdESSignatureCreationResult created = await CreateAsync(
            ConformantHeaders(),
            new JAdESDetachedObjectIdByUriPayloadInput([
                new JAdESDetachedObjectReferenceInput("urn:test:a", null),
                new JAdESDetachedObjectReferenceInput("urn:test:b", null)
            ]),
            unsignedHeaders: null, privateKey, TestContext.CancellationToken,
            dereference: DereferenceFromStoreAsync, dereferenceContext: context).ConfigureAwait(false);

        byte[] wireBytes = JAdESSignatureCreation.Serialize(created, JoseSerializationFormat.FlattenedJson, TestSetup.Base64UrlEncoder, JsonSerialize);

        using JAdESValidationResult result = await ValidateAsync(
            wireBytes, publicKey, TestContext.CancellationToken, dereference: DereferenceFromStoreAsync, dereferenceContext: context).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, result.Failure?.Message);
    }


    /// <summary>The <c>ObjectIdByURIHash</c> mechanism validates by re-verifying every <c>hashV</c> entry, and a tampered referenced object is caught as a digest mismatch.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult on a successful CreateAsync call, disposed here via 'using created'.")]
    [TestMethod]
    public async Task ObjectIdByUriHashMechanismValidatesDigestsAndCatchesTampering()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        byte[] objectA = "object-a"u8.ToArray();
        var store = new ObjectStore(new Dictionary<string, byte[]> { ["urn:test:a"] = objectA });
        var context = new JAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);

        using JAdESSignatureCreationResult created = await CreateAsync(
            ConformantHeaders(),
            new JAdESDetachedObjectIdByUriHashPayloadInput(WellKnownHashAlgorithms.Sha256, [new JAdESDetachedObjectReferenceInput("urn:test:a", null)]),
            unsignedHeaders: null, privateKey, TestContext.CancellationToken,
            dereference: DereferenceFromStoreAsync, dereferenceContext: context).ConfigureAwait(false);

        byte[] wireBytes = JAdESSignatureCreation.Serialize(created, JoseSerializationFormat.FlattenedJson, TestSetup.Base64UrlEncoder, JsonSerialize);

        using JAdESValidationResult result = await ValidateAsync(
            wireBytes, publicKey, TestContext.CancellationToken, dereference: DereferenceFromStoreAsync, dereferenceContext: context).ConfigureAwait(false);
        Assert.IsTrue(result.IsValid, result.Failure?.Message);

        store.ObjectsByReference["urn:test:a"] = "tampered-object"u8.ToArray();

        using JAdESValidationResult tampered = await ValidateAsync(
            wireBytes, publicKey, TestContext.CancellationToken, dereference: DereferenceFromStoreAsync, dereferenceContext: context).ConfigureAwait(false);
        Assert.IsFalse(tampered.IsValid);
        Assert.IsInstanceOfType<JAdESDetachedObjectDigestMismatchFailure>(tampered.Failure);
    }


    /// <summary>An unrecognized <c>mId</c> dispatches to the caller-supplied unknown-mechanism handler for validation, mirroring creation.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult on a successful CreateAsync call, disposed here via 'using created'.")]
    [TestMethod]
    public async Task UnknownMechanismDispatchesToHandler()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var store = new ObjectStore(new Dictionary<string, byte[]> { ["urn:test:a"] = "custom-object"u8.ToArray() });
        var context = new JAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);

        using JAdESSignatureCreationResult created = await CreateAsync(
            ConformantHeaders(),
            new JAdESDetachedUnknownMechanismPayloadInput("urn:example:custom", [new JAdESDetachedObjectReferenceInput("urn:test:a", null)]),
            unsignedHeaders: null, privateKey, TestContext.CancellationToken,
            unknownMechanismHandler: HandleUnknownMechanismAsync, dereferenceContext: context).ConfigureAwait(false);

        byte[] wireBytes = JAdESSignatureCreation.Serialize(created, JoseSerializationFormat.FlattenedJson, TestSetup.Base64UrlEncoder, JsonSerialize);

        using JAdESValidationResult noHandler = await ValidateAsync(wireBytes, publicKey, TestContext.CancellationToken, dereferenceContext: context).ConfigureAwait(false);
        Assert.IsFalse(noHandler.IsValid);

        using JAdESValidationResult result = await ValidateAsync(
            wireBytes, publicKey, TestContext.CancellationToken, unknownMechanismHandler: HandleUnknownMechanismAsync, dereferenceContext: context).ConfigureAwait(false);
        Assert.IsTrue(result.IsValid, result.Failure?.Message);
    }


    /// <summary>An <c>etsiU</c> unsigned-header set round-trips into the promoted facts (Flattened JSON — Compact structurally forbids an unprotected header, JA-4-05).</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.3.1-08.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The PooledMemory constructed inline transfers ownership into the JAdESUnsignedHeaderElementCounterSignature, then into unsignedHeaders (disposed via its own 'using' declaration); ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult, disposed via 'using created'.")]
    [TestMethod]
    public async Task EtsiUUnsignedHeadersRoundTripIntoVerifiedFacts()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        //A base64url-mode cSig element's WireText is the base64url TEXT that itself decodes to a
        //{"cSig": ...} JSON object (JAdESEtsiUJson's own opaque-carrier contract) -- unlike
        //JAdESSignatureCreationTests' identically-shaped fixture, THIS test round-trips through validation's
        //own etsiU re-parse, so the fixture must be genuinely well-formed, not merely opaque.
        string cSigBase64Url = TestSetup.Base64UrlEncoder("{\"cSig\":\"opaque\"}"u8);
        using var unsignedHeaders = new JAdESUnsignedHeaders(
            JAdESEtsiUIncorporationMode.Base64Url,
            [new JAdESUnsignedHeaderElementCounterSignature(PooledMemory.FromBytes(Encoding.ASCII.GetBytes(cSigBase64Url), BaseMemoryPool.Shared, Tag.Create(Purpose.Data)))]);

        using JAdESSignatureCreationResult created = await CreateAsync(
            ConformantHeaders(), new JAdESAttachedPayloadInput(new byte[] { 0x01 }), unsignedHeaders, privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wireBytes = JAdESSignatureCreation.Serialize(created, JoseSerializationFormat.FlattenedJson, TestSetup.Base64UrlEncoder, JsonSerialize);

        using JAdESValidationResult result = await ValidateAsync(wireBytes, publicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, result.Failure?.Message);
        Assert.IsNotNull(result.Verified!.Value.Value.UnsignedHeaders);
        Assert.AreEqual(1, result.Verified.Value.Value.UnsignedHeaders!.Count);
    }


    /// <summary>A tampered payload byte fails signature verification, never the parse or rule steps.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult on a successful CreateAsync call, disposed here via 'using created'.")]
    [TestMethod]
    public async Task TamperedPayloadFailsSignatureVerification()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using JAdESSignatureCreationResult created = await CreateAsync(
            ConformantHeaders(), new JAdESAttachedPayloadInput(new byte[] { 0x01, 0x02, 0x03 }), unsignedHeaders: null, privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wireBytes = JAdESSignatureCreation.Serialize(created, JoseSerializationFormat.Compact, TestSetup.Base64UrlEncoder, JsonSerialize);
        byte[] tamperedWire = FlipLastCharOfSegment(wireBytes, segmentIndex: 1);

        using JAdESValidationResult result = await ValidateAsync(tamperedWire, publicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<JAdESSignatureInvalidFailure>(result.Failure);
    }


    /// <summary>Validating with the wrong public key fails signature verification.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult on a successful CreateAsync call, disposed here via 'using created'.")]
    [TestMethod]
    public async Task WrongKeyFailsSignatureVerification()
    {
        var signingKeyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = signingKeyPair.PrivateKey;
        signingKeyPair.PublicKey.Dispose();

        //CreateP256KeyMaterial returns copies of ONE cached key pair (test speed); a genuinely different key
        //requires CreateFreshP256KeyMaterial (TestKeyMaterialProvider's own documented distinction).
        var otherKeyPair = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wrongPublicKey = otherKeyPair.PublicKey;
        otherKeyPair.PrivateKey.Dispose();

        using JAdESSignatureCreationResult created = await CreateAsync(
            ConformantHeaders(), new JAdESAttachedPayloadInput(new byte[] { 0x01 }), unsignedHeaders: null, privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wireBytes = JAdESSignatureCreation.Serialize(created, JoseSerializationFormat.Compact, TestSetup.Base64UrlEncoder, JsonSerialize);

        using JAdESValidationResult result = await ValidateAsync(wireBytes, wrongPublicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<JAdESSignatureInvalidFailure>(result.Failure);
    }


    /// <summary>Malformed wire bytes fail closed as a malformed-encoding failure, never a thrown exception.</summary>
    [TestMethod]
    public async Task MalformedWireBytesFailCosedAsMalformedEncoding()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;

        using JAdESValidationResult result = await ValidateAsync("not-a-jws"u8.ToArray(), publicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<JAdESMalformedEncodingFailure>(result.Failure);
        Assert.IsNull(result.Headers);
    }


    /// <summary>
    /// A regression: the JSON-form exploit string -- a structurally well-formed Flattened JSON
    /// Serialization JWS whose <c>protected</c> member is not valid base64url text -- fails closed as
    /// <see cref="JAdESMalformedEncodingFailure"/>. <see cref="Verifiable.Json.JAdESMessageJson.TryParse"/> never
    /// decodes/validates the <c>protected</c> member itself (it is carried as a raw string, mirroring the compact
    /// form's own <see cref="UnverifiedJwsSignature.Protected"/> carriage), so the base64url decode of it inside
    /// <c>JAdESSignatureValidation.ValidateAsync</c> is the ONLY place this malformation is ever caught for the
    /// JSON forms -- unlike Compact, where <c>JwsParsing.ParseCompact</c> decodes the protected segment eagerly
    /// during <c>parse</c> itself and a malformed one never reaches that later decode at all.
    /// </summary>
    [TestMethod]
    public async Task JsonFormMalformedProtectedFailsClosedAsMalformedEncoding()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;

        byte[] wireBytes = """{"protected":"@@@@","signature":"AAAA","payload":"AAAA"}"""u8.ToArray();

        using JAdESValidationResult result = await ValidateAsync(wireBytes, publicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<JAdESMalformedEncodingFailure>(result.Failure);
        Assert.IsNull(result.Headers);
    }


    /// <summary>
    /// The empty-protected variant: <c>{"protected":"","signature":"AAAA","payload":"AAAA"}</c>
    /// fails closed. An empty <c>protected</c> member reads as a valid (empty) JSON string at parse time, so the
    /// base64url decoder's own empty-input <see cref="ArgumentException"/> is what this envelope must catch.
    /// </summary>
    [TestMethod]
    public async Task JsonFormEmptyProtectedFailsClosedAsMalformedEncoding()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;

        byte[] wireBytes = """{"protected":"","signature":"AAAA","payload":"AAAA"}"""u8.ToArray();

        using JAdESValidationResult result = await ValidateAsync(wireBytes, publicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<JAdESMalformedEncodingFailure>(result.Failure);
        Assert.IsNull(result.Headers);
    }


    /// <summary>A General JSON message carrying more than one signature is out of scope and fails closed at parse.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult on a successful CreateAsync call, disposed here via 'using created'.")]
    [TestMethod]
    public async Task GeneralJsonWithMultipleSignaturesFailsClosed()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using JAdESSignatureCreationResult created = await CreateAsync(
            ConformantHeaders(), new JAdESAttachedPayloadInput(new byte[] { 0x01 }), unsignedHeaders: null, privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] general = JAdESSignatureCreation.Serialize(created, JoseSerializationFormat.GeneralJson, TestSetup.Base64UrlEncoder, JsonSerialize);

        JsonNode root = JsonNode.Parse(general)!;
        JsonArray signatures = root["signatures"]!.AsArray();
        signatures.Add(JsonNode.Parse(signatures[0]!.ToJsonString()));
        byte[] multiSignerWire = JsonSerializer.SerializeToUtf8Bytes(root);

        using JAdESValidationResult result = await ValidateAsync(multiSignerWire, publicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<JAdESMalformedEncodingFailure>(result.Failure);
    }


    /// <summary>A wire-present <c>x5t</c> member collects JA-5.1.6-01 at decode time, in collect posture.</summary>
    [TestMethod]
    public async Task X5tOnWireCollectsForbiddenViolation()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using JAdESProtectedHeaders headers = ConformantHeaders();
        byte[] payload = [0x01];
        (string protectedSegment, byte[] signatureBytes) = await SignRawAsync(headers, payload, privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        using IMemoryOwner<byte> decodedHeader = TestSetup.Base64UrlDecoder(protectedSegment, BaseMemoryPool.Shared);
        string headerJson = Encoding.UTF8.GetString(decodedHeader.Memory.Span);
        string tamperedJson = "{\"x5t\":\"QUFBQQ\"," + headerJson[1..];
        string tamperedProtected = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(tamperedJson));

        string compact = $"{tamperedProtected}.{TestSetup.Base64UrlEncoder(payload)}.{TestSetup.Base64UrlEncoder(signatureBytes)}";
        byte[] wireBytes = Encoding.ASCII.GetBytes(compact);

        using JAdESValidationResult result = await ValidateAsync(wireBytes, publicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        var failure = (JAdESRuleViolationsFailure)result.Failure!;
        Assert.Contains(static (JAdESRuleViolation v) => v is JAdESX5tForbiddenViolation, failure.Violations);
        Assert.IsNotNull(result.Headers, "Decoded facts must survive a post-decode rule-violation failure.");
    }


    /// <summary>
    /// A hand-signed message whose headers violate JA-5.1.7-04 (unreachable through <see cref="JAdESSignatureCreation"/>,
    /// which refuses it) reports the violation in collect posture, carrying the decoded facts on the failure.
    /// </summary>
    [TestMethod]
    public async Task NonConformantHeadersReportRuleViolationCarryingDecodedFacts()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using var headers = new JAdESProtectedHeaders(WellKnownJwaValues.Es256, issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch));
        byte[] payload = [0x01];
        (string protectedSegment, byte[] signatureBytes) = await SignRawAsync(headers, payload, privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        string compact = $"{protectedSegment}.{TestSetup.Base64UrlEncoder(payload)}.{TestSetup.Base64UrlEncoder(signatureBytes)}";
        byte[] wireBytes = Encoding.ASCII.GetBytes(compact);

        using JAdESValidationResult result = await ValidateAsync(wireBytes, publicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        var failure = (JAdESRuleViolationsFailure)result.Failure!;
        Assert.Contains(static (JAdESRuleViolation v) => v is JAdESSigningCertificateIdentificationViolation, failure.Violations);
        Assert.IsNotNull(result.Headers);
        Assert.AreEqual(WellKnownJwaValues.Es256, result.Headers!.Algorithm);
    }


    /// <summary>
    /// Every failure arm — malformed encoding, rule violation, unresolvable payload, signature-invalid — and the
    /// success arm leave zero outstanding pool rentals once the result is disposed.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Every JAdESValidationResult constructed here is disposed via its own 'using' declaration before meteredPool.OutstandingCount is asserted.")]
    [TestMethod]
    public async Task EveryValidationArmLeavesNoOutstandingPoolRentals()
    {
        using var meteredPool = new MeteredHousePool();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using JAdESSignatureCreationResult created = await CreateAsync(
            ConformantHeaders(), new JAdESAttachedPayloadInput(new byte[] { 0x01, 0x02 }), unsignedHeaders: null, privateKey, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = JAdESSignatureCreation.Serialize(created, JoseSerializationFormat.Compact, TestSetup.Base64UrlEncoder, JsonSerialize);

        using(JAdESValidationResult malformed = await ValidateAsync("garbage"u8.ToArray(), publicKey, TestContext.CancellationToken, pool: meteredPool.Pool).ConfigureAwait(false))
        {
            Assert.IsFalse(malformed.IsValid);
        }

        Assert.AreEqual(0, meteredPool.OutstandingCount, "malformed-encoding arm leaked a rental.");

        byte[] tamperedWire = FlipLastCharOfSegment(wireBytes, segmentIndex: 1);

        using(JAdESValidationResult invalidSignature = await ValidateAsync(tamperedWire, publicKey, TestContext.CancellationToken, pool: meteredPool.Pool).ConfigureAwait(false))
        {
            Assert.IsFalse(invalidSignature.IsValid);
        }

        Assert.AreEqual(0, meteredPool.OutstandingCount, "signature-invalid arm leaked a rental.");

        using(JAdESValidationResult success = await ValidateAsync(wireBytes, publicKey, TestContext.CancellationToken, pool: meteredPool.Pool).ConfigureAwait(false))
        {
            Assert.IsTrue(success.IsValid, success.Failure?.Message);
        }

        Assert.AreEqual(0, meteredPool.OutstandingCount, "success arm leaked a rental.");
    }


    private static ValueTask<JAdESSignatureCreationResult> CreateAsync(
        JAdESProtectedHeaders headers,
        JAdESSigningPayloadInput payloadInput,
        JAdESUnsignedHeaders? unsignedHeaders,
        PrivateKeyMemory privateKey,
        CancellationToken cancellationToken,
        JAdESDetachedObjectDereferenceDelegate? dereference = null,
        JAdESDetachedObjectDereferenceContext? dereferenceContext = null,
        JAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler = null) =>
        JAdESSignatureCreation.SignAsync(
            headers,
            payloadInput,
            unsignedHeaders,
            JAdESProtectedHeaderJson.Encode,
            JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            dereference,
            dereferenceContext,
            unknownMechanismHandler,
            BaseMemoryPool.Shared,
            cancellationToken: cancellationToken);


    private static ValueTask<JAdESValidationResult> ValidateAsync(
        byte[] wireBytes,
        PublicKeyMemory publicKey,
        CancellationToken cancellationToken,
        JAdESDetachedObjectDereferenceDelegate? dereference = null,
        JAdESDetachedObjectDereferenceContext? dereferenceContext = null,
        ReadOnlyMemory<byte>? externalDetachedPayload = null,
        JAdESHttpHeadersCanonicalizationContext? httpHeadersContext = null,
        JAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler = null,
        BaseMemoryPool? pool = null) =>
        JAdESSignatureValidation.ValidateAsync(
            wireBytes,
            JAdESMessageJson.TryParse,
            JAdESProtectedHeaderJson.Decode,
            JAdESProtectedHeaderJson.DetectX5tPresence,
            JAdESEtsiUJson.TryParse,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            dereference,
            dereferenceContext,
            externalDetachedPayload,
            httpHeadersContext,
            unknownMechanismHandler,
            pool ?? BaseMemoryPool.Shared,
            cancellationToken: cancellationToken);


    /// <summary>Signs <paramref name="payload"/> over <paramref name="headers"/> directly, bypassing <see cref="JAdESSignatureCreation"/>'s own B-B rule enforcement — the seam that lets a test construct a well-formed-but-non-conformant JAdES message.</summary>
    private static async ValueTask<(string ProtectedSegment, byte[] SignatureBytes)> SignRawAsync(
        JAdESProtectedHeaders headers, byte[] payload, PrivateKeyMemory privateKey, CancellationToken cancellationToken)
    {
        using EncodedJoseProtectedHeader encoded = JAdESProtectedHeaderJson.Encode(headers, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string protectedSegment = Encoding.ASCII.GetString(encoded.AsReadOnlySpan()[..encoded.Length]);

        //Verifiable.Tests carries InternalsVisibleTo access to Verifiable.JCose (Directory.Build.props), so the
        //library's own internal RentSigningInput overload is reused here rather than hand-rolling the RFC 7515
        //§5.1 concatenation a second time.
        using IMemoryOwner<byte> signingInput = Jws.RentSigningInput(
            protectedSegment, payload, true, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared, out int length);
        (Signature signature, _) = await MicrosoftCryptographicFunctions.SignP256Async(
            privateKey.AsReadOnlyMemory(), signingInput.Memory[..length], BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);

        using(signature)
        {
            return (protectedSegment, signature.AsReadOnlySpan().ToArray());
        }
    }


    private static byte[] JsonSerialize(object value) => JsonSerializer.SerializeToUtf8Bytes(value);


    private const string Base64UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";


    /// <summary>
    /// Flips the last character of a Compact-serialization segment (0-indexed: header/payload/signature) by
    /// XOR-ing its base64url alphabet index's top bit (value 32) — the MSB of every base64 sextet is always
    /// data-bearing regardless of how many low-order padding bits the final character carries, so this always
    /// produces a genuine content change, unlike swapping to an arbitrary different character (which can land
    /// entirely within padding bits for a 1- or 2-byte-remainder segment and silently decode unchanged).
    /// </summary>
    private static byte[] FlipLastCharOfSegment(byte[] compactWireBytes, int segmentIndex)
    {
        string compact = Encoding.ASCII.GetString(compactWireBytes);
        string[] parts = compact.Split('.');
        int index = Base64UrlAlphabet.IndexOf(parts[segmentIndex][^1], StringComparison.Ordinal);
        parts[segmentIndex] = parts[segmentIndex][..^1] + Base64UrlAlphabet[index ^ 0b100000];

        return Encoding.ASCII.GetBytes(string.Join('.', parts));
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TestDigest()'s ownership transfers into the returned JAdESProtectedHeaders; every caller disposes that return value via its own 'using' declaration.")]
    private static JAdESProtectedHeaders ConformantHeaders(JAdESClaimedSigningTime? sigT = null) =>
        new(
            WellKnownJwaValues.Es256,
            issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch),
            sigT: sigT,
            x5tHashS256: TestDigest());


    private static DigestValue TestDigest()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(32);
        new byte[32].CopyTo(owner.Memory);
        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }


    private static ValueTask<JAdESDetachedObjectDereferenceResult> DereferenceFromStoreAsync(
        string uriReference, JAdESDetachedObjectDereferenceContext context, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        var store = (ObjectStore)context.State!;
        if(!store.ObjectsByReference.TryGetValue(uriReference, out byte[]? content))
        {
            return ValueTask.FromResult<JAdESDetachedObjectDereferenceResult>(
                new JAdESDetachedObjectDereferenceFailure($"No test fixture object registered for reference '{uriReference}'."));
        }

        return ValueTask.FromResult<JAdESDetachedObjectDereferenceResult>(
            new JAdESDetachedObjectDereferenceSuccess(PooledMemory.FromBytes(content, pool, Tag.Create(Purpose.Data))));
    }


    private static ValueTask<PooledMemory> HandleUnknownMechanismAsync(
        string mechanismIdentifier, IReadOnlyList<JAdESDetachedObjectReferenceInput> references, string? hashAlgorithm,
        JAdESDetachedObjectDereferenceContext context, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        var store = (ObjectStore)context.State!;
        byte[] content = store.ObjectsByReference[references[0].Reference];

        return ValueTask.FromResult(PooledMemory.FromBytes(content, pool, Tag.Create(Purpose.Data)));
    }


    /// <summary>The fixed URI-reference-to-bytes store <see cref="DereferenceFromStoreAsync"/>/<see cref="HandleUnknownMechanismAsync"/> read through <see cref="JAdESDetachedObjectDereferenceContext.State"/>. Mutable so a test can tamper the referenced content after signing.</summary>
    private sealed record ObjectStore(Dictionary<string, byte[]> ObjectsByReference);
}
