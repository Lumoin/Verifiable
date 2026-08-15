using System.Formats.Cbor;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cose;

/// <summary>
/// Tests for COSE_Sign multi-signer operations: the message model, the "Signature"-context
/// Sig_structure, fail-closed tagged/untagged parse, canonical serialize, and multi-signer
/// sign/verify through the existing crypto delegate seams.
/// </summary>
[TestClass]
internal sealed class CoseSignTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task SignAndVerifyMultiSignerWithMixedAlgorithmsSucceeds()
    {
        EncodedCoseProtectedHeader bodyProtectedHeader = BuildEmptyProtectedHeader();
        byte[] payload = BuildTestPayload();

        var p256 = TestKeyMaterialProvider.CreateP256KeyMaterial();
        var p384 = TestKeyMaterialProvider.CreateP384KeyMaterial();
        using var p256PublicKey = p256.PublicKey;
        using var p256PrivateKey = p256.PrivateKey;
        using var p384PublicKey = p384.PublicKey;
        using var p384PrivateKey = p384.PrivateKey;

        CoseSignerInput[] signers =
        [
            new CoseSignerInput(BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256), null, p256PrivateKey),
            new CoseSignerInput(BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es384), null, p384PrivateKey)
        ];

        using CoseSignMessage message = await CoseSign.SignAsync(
            bodyProtectedHeader,
            bodyUnprotectedHeader: null,
            payload,
            signers,
            CoseSerialization.BuildCoseSignatureSigStructure,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, message.Signatures);

        bool firstIsValid = await CoseSign.VerifyAsync(
            message, 0, CoseSerialization.BuildCoseSignatureSigStructure, p256PublicKey, TestContext.CancellationToken).ConfigureAwait(false);
        bool secondIsValid = await CoseSign.VerifyAsync(
            message, 1, CoseSerialization.BuildCoseSignatureSigStructure, p384PublicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(firstIsValid, "The P-256 signer must verify against its own key.");
        Assert.IsTrue(secondIsValid, "The P-384 signer must verify against its own key.");

        bool allValid = await CoseSign.VerifyAllAsync(
            message, [p256PublicKey, p384PublicKey], CoseSerialization.BuildCoseSignatureSigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(allValid, "VerifyAllAsync must succeed when every signer's own key is supplied in order.");
    }


    [TestMethod]
    public async Task VerifyIndexedSignerWithWrongKeyFails()
    {
        EncodedCoseProtectedHeader bodyProtectedHeader = BuildEmptyProtectedHeader();
        byte[] payload = BuildTestPayload();

        var signingKeyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var signingPrivateKey = signingKeyPair.PrivateKey;
        signingKeyPair.PublicKey.Dispose();

        var wrongKeyPair = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var wrongPublicKey = wrongKeyPair.PublicKey;
        wrongKeyPair.PrivateKey.Dispose();

        CoseSignerInput[] signers = [new CoseSignerInput(BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256), null, signingPrivateKey)];

        using CoseSignMessage message = await CoseSign.SignAsync(
            bodyProtectedHeader, null, payload, signers, CoseSerialization.BuildCoseSignatureSigStructure,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool isValid = await CoseSign.VerifyAsync(
            message, 0, CoseSerialization.BuildCoseSignatureSigStructure, wrongPublicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isValid, "Verification against the wrong key must fail.");
    }


    [TestMethod]
    public async Task VerifyAllAsyncFailsWhenOneSignerKeyIsWrong()
    {
        EncodedCoseProtectedHeader bodyProtectedHeader = BuildEmptyProtectedHeader();
        byte[] payload = BuildTestPayload();

        var p256 = TestKeyMaterialProvider.CreateP256KeyMaterial();
        var p384 = TestKeyMaterialProvider.CreateP384KeyMaterial();
        using var p256PublicKey = p256.PublicKey;
        using var p256PrivateKey = p256.PrivateKey;
        using var p384PrivateKey = p384.PrivateKey;
        p384.PublicKey.Dispose();

        var wrongP384KeyPair = TestKeyMaterialProvider.CreateFreshP384KeyMaterial();
        using var wrongP384PublicKey = wrongP384KeyPair.PublicKey;
        wrongP384KeyPair.PrivateKey.Dispose();

        CoseSignerInput[] signers =
        [
            new CoseSignerInput(BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256), null, p256PrivateKey),
            new CoseSignerInput(BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es384), null, p384PrivateKey)
        ];

        using CoseSignMessage message = await CoseSign.SignAsync(
            bodyProtectedHeader, null, payload, signers, CoseSerialization.BuildCoseSignatureSigStructure,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool allValid = await CoseSign.VerifyAllAsync(
            message, [p256PublicKey, wrongP384PublicKey], CoseSerialization.BuildCoseSignatureSigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(allValid, "VerifyAllAsync must fail closed when any single signer's key is wrong.");
    }


    [TestMethod]
    public async Task VerifyNamedSignerBySelectorSucceeds()
    {
        EncodedCoseProtectedHeader bodyProtectedHeader = BuildEmptyProtectedHeader();
        byte[] payload = BuildTestPayload();

        var alice = TestKeyMaterialProvider.CreateP256KeyMaterial();
        var bob = TestKeyMaterialProvider.CreateP384KeyMaterial();
        using var alicePublicKey = alice.PublicKey;
        using var alicePrivateKey = alice.PrivateKey;
        using var bobPrivateKey = bob.PrivateKey;
        bob.PublicKey.Dispose();

        var aliceUnprotected = new Dictionary<int, object> { [CoseHeaderParameters.Kid] = "alice"u8.ToArray() };
        var bobUnprotected = new Dictionary<int, object> { [CoseHeaderParameters.Kid] = "bob"u8.ToArray() };

        CoseSignerInput[] signers =
        [
            new CoseSignerInput(BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es384), bobUnprotected, bobPrivateKey),
            new CoseSignerInput(BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256), aliceUnprotected, alicePrivateKey)
        ];

        using CoseSignMessage message = await CoseSign.SignAsync(
            bodyProtectedHeader, null, payload, signers, CoseSerialization.BuildCoseSignatureSigStructure,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool isValid = await CoseSign.VerifyAsync(
            message,
            static component => component.UnprotectedHeader is not null
                && component.UnprotectedHeader.TryGetValue(CoseHeaderParameters.Kid, out object? kid)
                && kid is byte[] kidBytes
                && "alice"u8.SequenceEqual(kidBytes),
            CoseSerialization.BuildCoseSignatureSigStructure,
            alicePublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "The selector must find Alice's entry (index 1) and verify it against her own key.");
    }


    [TestMethod]
    public async Task VerifyNamedSignerThrowsWhenSelectorMatchesNoSigner()
    {
        EncodedCoseProtectedHeader bodyProtectedHeader = BuildEmptyProtectedHeader();
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        CoseSignerInput[] signers = [new CoseSignerInput(BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256), null, privateKey)];

        using CoseSignMessage message = await CoseSign.SignAsync(
            bodyProtectedHeader, null, payload, signers, CoseSerialization.BuildCoseSignatureSigStructure,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
            await CoseSign.VerifyAsync(
                message, static _ => false, CoseSerialization.BuildCoseSignatureSigStructure, publicKey, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task VerifyAsyncThrowsForOutOfRangeSignerIndex()
    {
        EncodedCoseProtectedHeader bodyProtectedHeader = BuildEmptyProtectedHeader();
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        CoseSignerInput[] signers = [new CoseSignerInput(BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256), null, privateKey)];

        using CoseSignMessage message = await CoseSign.SignAsync(
            bodyProtectedHeader, null, payload, signers, CoseSerialization.BuildCoseSignatureSigStructure,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(async () =>
            await CoseSign.VerifyAsync(
                message, 1, CoseSerialization.BuildCoseSignatureSigStructure, publicKey, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task SignAsyncThrowsForEmptySignerList()
    {
        EncodedCoseProtectedHeader bodyProtectedHeader = BuildEmptyProtectedHeader();

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await CoseSign.SignAsync(
                bodyProtectedHeader, null, BuildTestPayload(), [], CoseSerialization.BuildCoseSignatureSigStructure,
                BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        bodyProtectedHeader.Dispose();
    }


    [TestMethod]
    public async Task SerializeAndParseRoundTripByteExactForMultiSigner()
    {
        EncodedCoseProtectedHeader bodyProtectedHeader = BuildEmptyProtectedHeader();
        byte[] payload = BuildTestPayload();

        var p256 = TestKeyMaterialProvider.CreateP256KeyMaterial();
        var p521 = TestKeyMaterialProvider.CreateP521KeyMaterial();
        using var p256PublicKey = p256.PublicKey;
        using var p256PrivateKey = p256.PrivateKey;
        using var p521PublicKey = p521.PublicKey;
        using var p521PrivateKey = p521.PrivateKey;

        CoseSignerInput[] signers =
        [
            new CoseSignerInput(BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256), null, p256PrivateKey),
            new CoseSignerInput(BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es512), null, p521PrivateKey)
        ];

        using CoseSignMessage message = await CoseSign.SignAsync(
            bodyProtectedHeader, null, payload, signers, CoseSerialization.BuildCoseSignatureSigStructure,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using EncodedCoseSign encoded = CoseSerialization.SerializeCoseSign(message, BaseMemoryPool.Shared);

        using CoseSignParseResult parseResult = CoseSerialization.ParseCoseSign(encoded.AsReadOnlyMemory(), BaseMemoryPool.Shared);
        Assert.IsTrue(parseResult.IsSuccess, "A canonically serialized COSE_Sign message must parse successfully.");

        CoseSignMessage parsed = parseResult.Message!;
        Assert.IsTrue(message.ProtectedHeader.AsReadOnlySpan().SequenceEqual(parsed.ProtectedHeader.AsReadOnlySpan()), "Body protected header must round-trip.");
        Assert.IsTrue(message.Payload.Span.SequenceEqual(parsed.Payload.Span), "Payload must round-trip.");
        Assert.HasCount(2, parsed.Signatures);

        for(int i = 0; i < message.Signatures.Count; i++)
        {
            Assert.IsTrue(message.Signatures[i].ProtectedHeader.AsReadOnlySpan().SequenceEqual(parsed.Signatures[i].ProtectedHeader.AsReadOnlySpan()), $"Signer {i} protected header must round-trip.");
            Assert.IsTrue(message.Signatures[i].Signature.AsReadOnlySpan().SequenceEqual(parsed.Signatures[i].Signature.AsReadOnlySpan()), $"Signer {i} signature must round-trip.");
        }

        //Re-serializing the parsed message must reproduce byte-identical wire bytes (canonical
        //encoding is deterministic — RFC 9052 §9).
        using EncodedCoseSign reEncoded = CoseSerialization.SerializeCoseSign(parsed, BaseMemoryPool.Shared);
        Assert.IsTrue(encoded.AsReadOnlySpan().SequenceEqual(reEncoded.AsReadOnlySpan()), "Re-serializing a parsed COSE_Sign message must reproduce byte-identical wire bytes.");

        bool firstIsValid = await CoseSign.VerifyAsync(parsed, 0, CoseSerialization.BuildCoseSignatureSigStructure, p256PublicKey, TestContext.CancellationToken).ConfigureAwait(false);
        bool secondIsValid = await CoseSign.VerifyAsync(parsed, 1, CoseSerialization.BuildCoseSignatureSigStructure, p521PublicKey, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(firstIsValid, "The parsed P-256 signer must still verify.");
        Assert.IsTrue(secondIsValid, "The parsed P-521 signer must still verify.");
    }


    [TestMethod]
    public async Task ParseAcceptsUntaggedForm()
    {
        EncodedCoseProtectedHeader bodyProtectedHeader = BuildEmptyProtectedHeader();
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var privateKey = keyPair.PrivateKey;
        keyPair.PublicKey.Dispose();

        CoseSignerInput[] signers = [new CoseSignerInput(BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256), null, privateKey)];

        using CoseSignMessage message = await CoseSign.SignAsync(
            bodyProtectedHeader, null, payload, signers, CoseSerialization.BuildCoseSignatureSigStructure,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using EncodedCoseSign encoded = CoseSerialization.SerializeCoseSign(message, BaseMemoryPool.Shared);

        var reader = new CborReader(encoded.AsReadOnlyMemory(), CborConformanceMode.Lax);
        reader.ReadTag();
        byte[] untaggedBytes = reader.ReadEncodedValue().ToArray();

        using CoseSignParseResult parseResult = CoseSerialization.ParseCoseSign(untaggedBytes, BaseMemoryPool.Shared);

        Assert.IsTrue(parseResult.IsSuccess, "RFC 9052 §4.1 admits an untagged COSE_Sign; the parser must accept it.");
        Assert.IsTrue(message.Payload.Span.SequenceEqual(parseResult.Message!.Payload.Span));
    }


    [TestMethod]
    public void ParseRejectsWrongTag()
    {
        EncodedCoseProtectedHeader bodyProtectedHeader = BuildEmptyProtectedHeader();

        //Build a structurally valid COSE_Sign body but wrap it in the COSE_Sign1 tag (18)
        //instead of COSE_Sign's own tag (98) -- must fail closed, never silently accepted.
        var bodyWriter = new CborWriter(CborConformanceMode.Canonical);
        bodyWriter.WriteStartArray(4);
        bodyWriter.WriteByteString(bodyProtectedHeader.AsReadOnlySpan());
        bodyWriter.WriteStartMap(0);
        bodyWriter.WriteEndMap();
        bodyWriter.WriteByteString(BuildTestPayload());
        bodyWriter.WriteStartArray(0);
        bodyWriter.WriteEndArray();
        bodyWriter.WriteEndArray();
        byte[] untaggedBody = bodyWriter.Encode();

        bodyProtectedHeader.Dispose();

        var wrongTagWriter = new CborWriter(CborConformanceMode.Canonical);
        wrongTagWriter.WriteTag((CborTag)CoseTags.Sign1);
        wrongTagWriter.WriteEncodedValue(untaggedBody);
        byte[] wrongTaggedBytes = wrongTagWriter.Encode();

        using CoseSignParseResult parseResult = CoseSerialization.ParseCoseSign(wrongTaggedBytes, BaseMemoryPool.Shared);

        Assert.IsFalse(parseResult.IsSuccess, "A tag other than 98 must fail closed.");
    }


    [TestMethod]
    public void ParseFailsClosedOnMalformedBytesNeverThrows()
    {
        byte[] malformed = [0x00, 0x01, 0x02, 0x03];

        using CoseSignParseResult parseResult = CoseSerialization.ParseCoseSign(malformed, BaseMemoryPool.Shared);

        Assert.IsFalse(parseResult.IsSuccess, "Malformed COSE_Sign bytes must fail closed to an unsuccessful result, not throw.");
    }


    [TestMethod]
    public void ParseRejectsEmptySignaturesArray()
    {
        EncodedCoseProtectedHeader bodyProtectedHeader = BuildEmptyProtectedHeader();

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag((CborTag)CoseTags.Sign);
        writer.WriteStartArray(4);
        writer.WriteByteString(bodyProtectedHeader.AsReadOnlySpan());
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString(BuildTestPayload());
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteEndArray();
        byte[] wireBytes = writer.Encode();

        bodyProtectedHeader.Dispose();

        using CoseSignParseResult parseResult = CoseSerialization.ParseCoseSign(wireBytes, BaseMemoryPool.Shared);

        Assert.IsFalse(parseResult.IsSuccess, "RFC 9052 §4.1 types signatures as [+ COSE_Signature]: an empty array must fail closed.");
    }


    /// <summary>
    /// RFC 9338 §4 / RFC 9052 §9: every bstr in a deterministically encoded COSE structure
    /// is definite-length. <see cref="CoseSerialization.ParseCoseSign"/> reads under
    /// <see cref="CborConformanceMode.Lax"/> (for reasons that method's own remarks give), which would
    /// otherwise silently concatenate an indefinite-length-chunked byte string's chunks rather than
    /// rejecting it; this proves the body-layer protected-header bstr site fails closed instead.
    /// </summary>
    [TestMethod]
    public void ParseCoseSignRejectsIndefiniteLengthChunkedBodyProtectedHeaderByteString()
    {
        EncodedCoseProtectedHeader signerProtectedHeader = BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256);

        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteTag((CborTag)CoseTags.Sign);
        writer.WriteStartArray(4);
        writer.WriteStartIndefiniteLengthByteString();
        writer.WriteByteString([0xA0]);
        writer.WriteEndIndefiniteLengthByteString();
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString(BuildTestPayload());
        writer.WriteStartArray(1);
        writer.WriteStartArray(3);
        writer.WriteByteString(signerProtectedHeader.AsReadOnlySpan());
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString([1, 2, 3, 4]);
        writer.WriteEndArray();
        writer.WriteEndArray();
        writer.WriteEndArray();
        byte[] wireBytes = writer.Encode();

        signerProtectedHeader.Dispose();

        using CoseSignParseResult parseResult = CoseSerialization.ParseCoseSign(wireBytes, BaseMemoryPool.Shared);

        Assert.IsFalse(parseResult.IsSuccess,
            "An indefinite-length-chunked body-protected-header bstr must fail closed, never silently concatenate its chunks.");
    }


    [TestMethod]
    public async Task ParseRejectsTrailingBytes()
    {
        EncodedCoseProtectedHeader bodyProtectedHeader = BuildEmptyProtectedHeader();
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        keyPair.PublicKey.Dispose();
        using var privateKey = keyPair.PrivateKey;

        CoseSignerInput[] signers = [new CoseSignerInput(BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256), null, privateKey)];

        using CoseSignMessage message = await CoseSign.SignAsync(
            bodyProtectedHeader, null, payload, signers, CoseSerialization.BuildCoseSignatureSigStructure,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using EncodedCoseSign encoded = CoseSerialization.SerializeCoseSign(message, BaseMemoryPool.Shared);

        byte[] withTrailingGarbage = [.. encoded.AsReadOnlySpan().ToArray(), 0x00];

        using CoseSignParseResult parseResult = CoseSerialization.ParseCoseSign(withTrailingGarbage, BaseMemoryPool.Shared);

        Assert.IsFalse(parseResult.IsSuccess, "Trailing bytes after the COSE_Sign structure must fail closed.");
    }


    /// <summary>
    /// RFC 9052 Appendix C.1.1 ("Single Signature", within a <c>COSE_Sign</c> structure) as a
    /// byte-exact parse and round-trip KAT — the vector's own stated "103 bytes" size is
    /// asserted directly against the hand-assembled oracle before it ever reaches the parser.
    /// Beyond the structural round-trip, the vector's OWN
    /// signature value is verified cryptographically against the kid-"11" P-256 public key from
    /// RFC 9052 Appendix C.7.1 over <see cref="CoseSerialization.BuildCoseSignatureSigStructure"/>'s
    /// output -- the cross-implementation oracle, not merely a byte-exact re-serialization.
    /// </summary>
    [TestMethod]
    public async Task ParseRfc9052AppendixC11SingleSignerWithinCoseSignMatchesSpecVector()
    {
        byte[] oracle = BuildRfc9052AppendixC11Bytes();
        Assert.HasCount(103, oracle, "RFC 9052 Appendix C.1.1 states the example's encoded size is 103 bytes.");

        using CoseSignParseResult parseResult = CoseSerialization.ParseCoseSign(oracle, BaseMemoryPool.Shared);
        Assert.IsTrue(parseResult.IsSuccess);

        CoseSignMessage message = parseResult.Message!;
        Assert.IsTrue(message.ProtectedHeader.AsReadOnlySpan().IsEmpty);
        Assert.IsNull(message.UnprotectedHeader);
        Assert.AreEqual("This is the content.", System.Text.Encoding.ASCII.GetString(message.Payload.Span));
        Assert.HasCount(1, message.Signatures);

        CoseSignatureComponent signer = message.Signatures[0];
        IReadOnlyDictionary<int, object> signerProtected = CoseSerialization.ParseProtectedHeader(signer.ProtectedHeader.AsReadOnlySpan());
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, signerProtected[CoseHeaderParameters.Alg]);
        Assert.IsNotNull(signer.UnprotectedHeader);
        Assert.IsTrue(((byte[])signer.UnprotectedHeader![CoseHeaderParameters.Kid]).AsSpan().SequenceEqual("11"u8));
        Assert.HasCount(64, signer.Signature.AsReadOnlySpan().ToArray());

        using EncodedCoseSign reEncoded = CoseSerialization.SerializeCoseSign(message, BaseMemoryPool.Shared);
        Assert.IsTrue(oracle.AsSpan().SequenceEqual(reEncoded.AsReadOnlySpan()), "Re-serializing must reproduce the RFC 9052 example byte-for-byte (canonical encoding).");

        byte[] sigStructure = CoseSerialization.BuildCoseSignatureSigStructure(
            message.ProtectedHeader.AsReadOnlySpan(), signer.ProtectedHeader.AsReadOnlySpan(), message.Payload.Span, []);
        byte[] kid11PublicKey = BuildKid11P256UncompressedPublicKeyBytes();
        (bool isValid, _) = await MicrosoftCryptographicFunctions.VerifyP256Async(
            sigStructure, signer.Signature.AsReadOnlyMemory(), kid11PublicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "RFC 9052 Appendix C.1.1's own signature value must verify against the kid-\"11\" P-256 public key (RFC 9052 Appendix C.7.1).");
    }


    /// <summary>
    /// RFC 9052 Appendix C.1.2 ("Multiple Signers") as a byte-exact parse and round-trip KAT.
    /// Beyond the structural round-trip, BOTH signers' own
    /// signature values are verified cryptographically against their RFC 9052 Appendix C.7.1
    /// public keys over <see cref="CoseSerialization.BuildCoseSignatureSigStructure"/>'s output.
    /// </summary>
    [TestMethod]
    public async Task ParseRfc9052AppendixC12MultipleSignersMatchesSpecVector()
    {
        byte[] oracle = BuildRfc9052AppendixC12Bytes();
        Assert.HasCount(277, oracle, "RFC 9052 Appendix C.1.2 states the example's encoded size is 277 bytes.");

        using CoseSignParseResult parseResult = CoseSerialization.ParseCoseSign(oracle, BaseMemoryPool.Shared);
        Assert.IsTrue(parseResult.IsSuccess);

        CoseSignMessage message = parseResult.Message!;
        Assert.HasCount(2, message.Signatures);

        IReadOnlyDictionary<int, object> firstProtected = CoseSerialization.ParseProtectedHeader(message.Signatures[0].ProtectedHeader.AsReadOnlySpan());
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, firstProtected[CoseHeaderParameters.Alg]);
        Assert.HasCount(64, message.Signatures[0].Signature.AsReadOnlySpan().ToArray());

        IReadOnlyDictionary<int, object> secondProtected = CoseSerialization.ParseProtectedHeader(message.Signatures[1].ProtectedHeader.AsReadOnlySpan());
        Assert.AreEqual(WellKnownCoseAlgorithms.Es512, secondProtected[CoseHeaderParameters.Alg]);
        Assert.IsTrue(((byte[])message.Signatures[1].UnprotectedHeader![CoseHeaderParameters.Kid]).AsSpan().SequenceEqual("bilbo.baggins@hobbiton.example"u8));
        Assert.HasCount(132, message.Signatures[1].Signature.AsReadOnlySpan().ToArray());

        using EncodedCoseSign reEncoded = CoseSerialization.SerializeCoseSign(message, BaseMemoryPool.Shared);
        Assert.IsTrue(oracle.AsSpan().SequenceEqual(reEncoded.AsReadOnlySpan()), "Re-serializing must reproduce the RFC 9052 example byte-for-byte (canonical encoding).");

        byte[] firstSigStructure = CoseSerialization.BuildCoseSignatureSigStructure(
            message.ProtectedHeader.AsReadOnlySpan(), message.Signatures[0].ProtectedHeader.AsReadOnlySpan(), message.Payload.Span, []);
        byte[] kid11PublicKey = BuildKid11P256UncompressedPublicKeyBytes();
        (bool firstIsValid, _) = await MicrosoftCryptographicFunctions.VerifyP256Async(
            firstSigStructure, message.Signatures[0].Signature.AsReadOnlyMemory(), kid11PublicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(firstIsValid, "The first signer's own signature value must verify against the kid-\"11\" P-256 public key.");

        byte[] secondSigStructure = CoseSerialization.BuildCoseSignatureSigStructure(
            message.ProtectedHeader.AsReadOnlySpan(), message.Signatures[1].ProtectedHeader.AsReadOnlySpan(), message.Payload.Span, []);
        byte[] bilboP521PublicKey = BuildBilboP521UncompressedPublicKeyBytes();
        (bool secondIsValid, _) = await MicrosoftCryptographicFunctions.VerifyP521Async(
            secondSigStructure, message.Signatures[1].Signature.AsReadOnlyMemory(), bilboP521PublicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(secondIsValid, "The second signer's own signature value must verify against Bilbo's P-521 public key (RFC 9052 Appendix C.7.1).");
    }


    /// <summary>
    /// Proves <see cref="CoseSerialization.BuildCoseSignatureSigStructure"/> produces the exact
    /// bytes RFC 9052 §4.4 defines, independent of the delegate: the signature it lets
    /// <see cref="CoseSign.SignOneAsync"/> produce is verified here against a hand-assembled
    /// Sig_structure built without calling that delegate at all.
    /// </summary>
    [TestMethod]
    public async Task SignOneAsyncProducesSignatureVerifiableAgainstIndependentlyBuiltSigStructure()
    {
        EncodedCoseProtectedHeader bodyProtectedHeader = BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256);
        EncodedCoseProtectedHeader signerProtectedHeader = BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256);
        byte[] payload = "independent oracle payload"u8.ToArray();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using CoseSignatureComponent component = await CoseSign.SignOneAsync(
            bodyProtectedHeader,
            signerProtectedHeader,
            signerUnprotectedHeader: null,
            payload,
            CoseSerialization.BuildCoseSignatureSigStructure,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Independent oracle: hand-assemble the Sig_structure per RFC 9052 §4.4, without calling
        //CoseSerialization.BuildCoseSignatureSigStructure.
        var oracleWriter = new CborWriter(CborConformanceMode.Canonical);
        oracleWriter.WriteStartArray(5);
        oracleWriter.WriteTextString("Signature");
        oracleWriter.WriteByteString(bodyProtectedHeader.AsReadOnlySpan());
        oracleWriter.WriteByteString(signerProtectedHeader.AsReadOnlySpan());
        oracleWriter.WriteByteString([]);
        oracleWriter.WriteByteString(payload);
        oracleWriter.WriteEndArray();
        byte[] oracleToBeSigned = oracleWriter.Encode();

        byte[] delegateToBeSigned = CoseSerialization.BuildCoseSignatureSigStructure(
            bodyProtectedHeader.AsReadOnlySpan(), signerProtectedHeader.AsReadOnlySpan(), payload, []);
        Assert.IsTrue(oracleToBeSigned.AsSpan().SequenceEqual(delegateToBeSigned), "The delegate must produce exactly the independently assembled Sig_structure bytes.");

        (bool isValid, _) = await MicrosoftCryptographicFunctions.VerifyP256Async(
            oracleToBeSigned, component.Signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory(), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "The signature must verify against an independently assembled Sig_structure.");
    }


    [TestMethod]
    public async Task MultiSignerSignSerializeParseVerifyIsMeteredPoolBalanced()
    {
        using var metered = new MeteredHousePool();

        EncodedCoseProtectedHeader bodyProtectedHeader = EncodedCoseProtectedHeader.FromBytes(
            CoseSerialization.SerializeProtectedHeader(new Dictionary<int, object>()), metered.Pool);
        byte[] payload = BuildTestPayload();

        var p256 = TestKeyMaterialProvider.CreateP256KeyMaterial();
        var p384 = TestKeyMaterialProvider.CreateP384KeyMaterial();
        using var p256PublicKey = p256.PublicKey;
        using var p256PrivateKey = p256.PrivateKey;
        using var p384PublicKey = p384.PublicKey;
        using var p384PrivateKey = p384.PrivateKey;

        CoseSignerInput[] signers =
        [
            new CoseSignerInput(EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 }), metered.Pool), null, p256PrivateKey),
            new CoseSignerInput(EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es384 }), metered.Pool), null, p384PrivateKey)
        ];

        using(CoseSignMessage message = await CoseSign.SignAsync(
            bodyProtectedHeader, null, payload, signers, CoseSerialization.BuildCoseSignatureSigStructure,
            metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            using EncodedCoseSign encoded = CoseSerialization.SerializeCoseSign(message, metered.Pool);
            using CoseSignParseResult parseResult = CoseSerialization.ParseCoseSign(encoded.AsReadOnlyMemory(), metered.Pool);
            Assert.IsTrue(parseResult.IsSuccess);

            bool firstIsValid = await CoseSign.VerifyAsync(parseResult.Message!, 0, CoseSerialization.BuildCoseSignatureSigStructure, p256PublicKey, TestContext.CancellationToken).ConfigureAwait(false);
            bool secondIsValid = await CoseSign.VerifyAsync(parseResult.Message!, 1, CoseSerialization.BuildCoseSignatureSigStructure, p384PublicKey, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(firstIsValid);
            Assert.IsTrue(secondIsValid);
        }

        Assert.IsGreaterThan(0, metered.RentedCount, "metered.Pool must have been exercised, or the balance assertion below is vacuous.");
        Assert.AreEqual(0, metered.OutstandingCount, "Sign, serialize, parse, and dispose must not leak a single pooled carrier.");
    }


    /// <summary>
    /// Metered custody on the multi-signer failure path: <see cref="CoseSign.SignAsync"/>
    /// consumes EVERY entry of <c>signers</c> on a mid-loop failure, not only the ones that already succeeded --
    /// the already-signed first signer's component is disposed via its own carriers, and the second (never
    /// reached, because its algorithm/purpose combination is unregistered for Signing -- Exchange only) signer's
    /// own caller-supplied protected header is ALSO disposed by <see cref="CoseSign.SignAsync"/> itself. The
    /// caller disposes nothing from <c>signers</c> either way; only <c>bodyProtectedHeader</c> remains
    /// caller-owned on this path (SignAsync's own contract never claims it on failure).
    /// </summary>
    [TestMethod]
    public async Task SignAsyncPartialFailureDisposesEverySignerInputMeteredPoolBalanced()
    {
        using var metered = new MeteredHousePool();

        EncodedCoseProtectedHeader bodyProtectedHeader = EncodedCoseProtectedHeader.FromBytes(
            CoseSerialization.SerializeProtectedHeader(new Dictionary<int, object>()), metered.Pool);
        byte[] payload = BuildTestPayload();

        var p256 = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var p256PublicKey = p256.PublicKey;
        using var p256PrivateKey = p256.PrivateKey;

        var x25519 = TestKeyMaterialProvider.CreateX25519KeyMaterial();
        using var x25519PublicKey = x25519.PublicKey;
        using var x25519PrivateKey = x25519.PrivateKey;

        CoseSignerInput[] signers =
        [
            new CoseSignerInput(EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 }), metered.Pool), null, p256PrivateKey),
            new CoseSignerInput(EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(new Dictionary<int, object>()), metered.Pool), null, x25519PrivateKey)
        ];

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await CoseSign.SignAsync(
                bodyProtectedHeader, null, payload, signers, CoseSerialization.BuildCoseSignatureSigStructure,
                metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        //bodyProtectedHeader alone remains caller-owned on this path -- it is not one of signers' own inputs,
        //so SignAsync's failure-path contract never claims it.
        bodyProtectedHeader.Dispose();

        Assert.IsGreaterThan(0, metered.RentedCount, "metered.Pool must have been exercised, or the balance assertion below is vacuous.");
        Assert.AreEqual(0, metered.OutstandingCount, "SignAsync must consume every signer input on a mid-loop failure, leaving nothing else for the caller to dispose.");
    }


    /// <summary>
    /// The parts-taking <see cref="CoseSign.VerifyAsync(ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, BuildCoseSignatureSigStructureDelegate, PublicKeyMemory, CancellationToken)"/>
    /// core and the message-shaped <see cref="CoseSign.VerifyAsync(CoseSignMessage, int, BuildCoseSignatureSigStructureDelegate, PublicKeyMemory, CancellationToken)"/>
    /// overload built on top of it must verify identically over the same inputs -- the message-shaped
    /// overload does nothing but unpack a <see cref="CoseSignMessage"/> entry's own carriers into the same
    /// parts before delegating (see that overload's own remarks). Both accept the same genuine signature
    /// and both reject the same tampered one.
    /// </summary>
    [TestMethod]
    public async Task PartsTakingVerifyAsyncCoreMatchesMessageShapedOverloadForGenuineAndTamperedSignature()
    {
        EncodedCoseProtectedHeader bodyProtectedHeader = BuildEmptyProtectedHeader();
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        CoseSignerInput[] signers = [new CoseSignerInput(BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256), null, privateKey)];

        using CoseSignMessage message = await CoseSign.SignAsync(
            bodyProtectedHeader, null, payload, signers, CoseSerialization.BuildCoseSignatureSigStructure,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        CoseSignatureComponent signer = message.Signatures[0];

        bool messageShapedGenuine = await CoseSign.VerifyAsync(
            message, 0, CoseSerialization.BuildCoseSignatureSigStructure, publicKey, TestContext.CancellationToken).ConfigureAwait(false);
        bool partsTakingGenuine = await CoseSign.VerifyAsync(
            message.ProtectedHeader.AsReadOnlyMemory(),
            signer.ProtectedHeader.AsReadOnlyMemory(),
            message.Payload,
            signer.Signature.AsReadOnlyMemory(),
            CoseSerialization.BuildCoseSignatureSigStructure,
            publicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(messageShapedGenuine, "The message-shaped overload must verify the genuine signature.");
        Assert.IsTrue(partsTakingGenuine, "The parts-taking core must verify the same genuine signature identically to the message-shaped overload.");

        byte[] tamperedSignature = signer.Signature.AsReadOnlySpan().ToArray();
        tamperedSignature[0] ^= 0xFF;

        bool partsTakingTampered = await CoseSign.VerifyAsync(
            message.ProtectedHeader.AsReadOnlyMemory(),
            signer.ProtectedHeader.AsReadOnlyMemory(),
            message.Payload,
            tamperedSignature,
            CoseSerialization.BuildCoseSignatureSigStructure,
            publicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        using Signature tamperedSignatureCarrier = BuildSignatureFromBytes(tamperedSignature);
        using CoseSignatureComponent tamperedComponent = new(
            BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256), null, tamperedSignatureCarrier);
        using CoseSignMessage tamperedMessage = new(BuildEmptyProtectedHeader(), null, payload, [tamperedComponent]);

        bool messageShapedTampered = await CoseSign.VerifyAsync(
            tamperedMessage, 0, CoseSerialization.BuildCoseSignatureSigStructure, publicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(partsTakingTampered, "The parts-taking core must reject a tampered signature.");
        Assert.IsFalse(messageShapedTampered, "The message-shaped overload must reject the same tampered signature identically.");
    }


    private static byte[] BuildTestPayload() => "This is the content."u8.ToArray();


    /// <summary>
    /// Builds a pool-rented <see cref="Signature"/> carrier from raw bytes, for tests that assemble a
    /// <see cref="CoseSignMessage"/> by hand rather than through <see cref="CoseSign.SignAsync"/>.
    /// </summary>
    private static Signature BuildSignatureFromBytes(byte[] bytes)
    {
        var owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new Signature(owner, CryptoTags.AlgorithmAgnosticSignature);
    }


    private static EncodedCoseProtectedHeader BuildEmptyProtectedHeader() =>
        EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(new Dictionary<int, object>()), BaseMemoryPool.Shared);


    private static EncodedCoseProtectedHeader BuildAlgProtectedHeader(int algorithm) =>
        EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(new Dictionary<int, object> { [CoseHeaderParameters.Alg] = algorithm }), BaseMemoryPool.Shared);


    /// <summary>
    /// Hand-assembles RFC 9052 Appendix C.1.1's exact wire bytes, independent of
    /// <see cref="CoseSerialization.SerializeCoseSign"/>.
    /// </summary>
    private static byte[] BuildRfc9052AppendixC11Bytes()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag((CborTag)98);
        writer.WriteStartArray(4);
        writer.WriteByteString([]);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString("This is the content."u8);
        writer.WriteStartArray(1);
        WriteRfc9052C11FirstSigner(writer);
        writer.WriteEndArray();
        writer.WriteEndArray();

        return writer.Encode();
    }


    /// <summary>
    /// Hand-assembles RFC 9052 Appendix C.1.2's exact wire bytes, independent of
    /// <see cref="CoseSerialization.SerializeCoseSign"/>.
    /// </summary>
    private static byte[] BuildRfc9052AppendixC12Bytes()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag((CborTag)98);
        writer.WriteStartArray(4);
        writer.WriteByteString([]);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString("This is the content."u8);
        writer.WriteStartArray(2);
        WriteRfc9052C11FirstSigner(writer);

        writer.WriteStartArray(3);
        writer.WriteByteString(Convert.FromHexString("a1013823"));
        writer.WriteStartMap(1);
        writer.WriteInt32(CoseHeaderParameters.Kid);
        writer.WriteByteString("bilbo.baggins@hobbiton.example"u8);
        writer.WriteEndMap();
        writer.WriteByteString(Convert.FromHexString(
            "00a2d28a7c2bdb1587877420f65adf7d0b9a06635dd1de64bb62974c863f0b160dd2163734034e6ac003b01e8705524c5c4ca479a952f0247ee8cb0b4fb7397ba08d009e0c8bf482270cc5771aa143966e5a469a09f613488030c5b07ec6d722e3835adb5b2d8c44e95ffb13877dd2582866883535de3bb03d01753f83ab87bb4f7a0297"));
        writer.WriteEndArray();

        writer.WriteEndArray();
        writer.WriteEndArray();

        return writer.Encode();
    }


    /// <summary>
    /// The kid-"11" P-256 public key from RFC 9052 Appendix C.7.1 (the same key whose private
    /// half produced the Appendix C.1.1/C.1.2 first-signer signature values), as a SEC1
    /// uncompressed point (<c>0x04 || X || Y</c>) -- the encoding
    /// <see cref="MicrosoftCryptographicFunctions.VerifyP256Async"/> accepts directly as
    /// <c>publicKeyMaterial</c>.
    /// </summary>
    private static byte[] BuildKid11P256UncompressedPublicKeyBytes()
    {
        byte[] x = Convert.FromHexString("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff");
        byte[] y = Convert.FromHexString("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e");

        byte[] point = new byte[1 + x.Length + y.Length];
        point[0] = 0x04;
        x.CopyTo(point, 1);
        y.CopyTo(point, 1 + x.Length);

        return point;
    }


    /// <summary>
    /// Bilbo Baggins's P-521 public key from RFC 9052 Appendix C.7.1 (the same key whose private
    /// half produced the Appendix C.1.2 second-signer signature value), as a SEC1 uncompressed
    /// point (<c>0x04 || X || Y</c>).
    /// </summary>
    private static byte[] BuildBilboP521UncompressedPublicKeyBytes()
    {
        byte[] x = Convert.FromHexString(
            "0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad");
        byte[] y = Convert.FromHexString(
            "01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475");

        byte[] point = new byte[1 + x.Length + y.Length];
        point[0] = 0x04;
        x.CopyTo(point, 1);
        y.CopyTo(point, 1 + x.Length);

        return point;
    }


    /// <summary>
    /// Writes the one <c>COSE_Signature</c> entry shared verbatim by RFC 9052 Appendix C.1.1
    /// and C.1.2 (the P-256/ES256 signer).
    /// </summary>
    private static void WriteRfc9052C11FirstSigner(CborWriter writer)
    {
        writer.WriteStartArray(3);
        writer.WriteByteString(Convert.FromHexString("a10126"));
        writer.WriteStartMap(1);
        writer.WriteInt32(CoseHeaderParameters.Kid);
        writer.WriteByteString("11"u8);
        writer.WriteEndMap();
        writer.WriteByteString(Convert.FromHexString(
            "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a"));
        writer.WriteEndArray();
    }
}
