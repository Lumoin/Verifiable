using Lumoin.Veritas.Cbor;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cose;

/// <summary>
/// Tests for COSE_Sign1 operations using explicit delegate, resolver/binder, and serialization round-trip APIs.
/// </summary>
[TestClass]
internal sealed class CoseTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task SignAndVerifyWithExplicitDelegateSucceeds()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 };
        EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(headerMap), BaseMemoryPool.Shared);
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(message);
        Assert.IsGreaterThan(0, message.Signature.Length);
        Assert.IsTrue(payload.AsSpan().SequenceEqual(message.Payload.Span));

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            message,
            CoseSerialization.BuildSigStructure,
            publicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "COSE_Sign1 signature verification must succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithResolverBinderSucceeds()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 };
        EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(headerMap), BaseMemoryPool.Shared);
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var resolverState = new TestResolverState(
            privateKey.AsReadOnlySpan().ToArray(),
            publicKey.AsReadOnlySpan().ToArray());

        var message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            BaseMemoryPool.Shared,
            resolverState,
            ResolvePrivateKeyMaterial,
            0,
            BindPrivateKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(message);

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            message,
            CoseSerialization.BuildSigStructure,
            BaseMemoryPool.Shared,
            resolverState,
            ResolvePublicKeyMaterial,
            0,
            BindPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "COSE_Sign1 verification with resolver/binder must succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithP384ExplicitDelegateSucceeds()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es384 };
        EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(headerMap), BaseMemoryPool.Shared);
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP384KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP384Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            message,
            CoseSerialization.BuildSigStructure,
            publicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP384Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "P-384 COSE_Sign1 signature verification must succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithP521ExplicitDelegateSucceeds()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es512 };
        EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(headerMap), BaseMemoryPool.Shared);
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP521KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP521Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            message,
            CoseSerialization.BuildSigStructure,
            publicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP521Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "P-521 COSE_Sign1 signature verification must succeed.");
    }


    [TestMethod]
    public async Task VerifyWithWrongKeyFails()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 };
        EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(headerMap), BaseMemoryPool.Shared);
        byte[] payload = BuildTestPayload();

        var signingKeyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var signingPublicKey = signingKeyPair.PublicKey;
        using var signingPrivateKey = signingKeyPair.PrivateKey;

        var wrongKeyPair = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var wrongPublicKey = wrongKeyPair.PublicKey;
        using var wrongPrivateKey = wrongKeyPair.PrivateKey;

        var message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            signingPrivateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            message,
            CoseSerialization.BuildSigStructure,
            wrongPublicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isValid, "Verification with wrong key must fail.");
    }


    [TestMethod]
    public async Task SerializeAndParseRoundTripSucceeds()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 };
        EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(headerMap), BaseMemoryPool.Shared);
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using EncodedCoseSign1 coseBytes = CoseSerialization.SerializeCoseSign1(message, BaseMemoryPool.Shared);
        using CoseSign1Message parsed = CoseSerialization.ParseCoseSign1(coseBytes.AsReadOnlyMemory(), BaseMemoryPool.Shared);

        Assert.IsTrue(message.ProtectedHeader.AsReadOnlySpan().SequenceEqual(parsed.ProtectedHeader.AsReadOnlySpan()), "Protected header must round-trip.");
        Assert.IsTrue(message.Payload.Span.SequenceEqual(parsed.Payload.Span), "Payload must round-trip.");
        Assert.IsTrue(message.Signature.AsReadOnlySpan().SequenceEqual(parsed.Signature.AsReadOnlySpan()), "Signature must round-trip.");

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            parsed,
            CoseSerialization.BuildSigStructure,
            publicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "Parsed COSE_Sign1 must verify successfully.");
    }


    /// <summary>
    /// RFC 9052 §3's <c>empty_or_serialized_map</c> CDDL (<c>bstr
    /// .cbor header_map / bstr .size 0</c>) admits a genuinely zero-length protected header, distinct from a
    /// serialized empty map (<c>{}</c> encodes to <c>0xa0</c>, a one-byte bstr payload). <see cref="BaseMemoryPool.Rent(int)"/>
    /// refuses a zero-length rental, so <see cref="CoseSerialization.ParseCoseSign1"/> must route this through
    /// the <c>EncodedCoseProtectedHeader.FromBytes</c> <c>EmptyMemoryOwner</c> idiom rather than a bare rental,
    /// or this KAT throws instead of round-tripping.
    /// </summary>
    [TestMethod]
    public async Task ParseCoseSign1AcceptsGenuinelyZeroLengthProtectedHeader()
    {
        EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared);
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, message.ProtectedHeader.Length, "Precondition: the signed message's own protected header is genuinely zero-length.");

        using EncodedCoseSign1 coseBytes = CoseSerialization.SerializeCoseSign1(message, BaseMemoryPool.Shared);
        using CoseSign1Message parsed = CoseSerialization.ParseCoseSign1(coseBytes.AsReadOnlyMemory(), BaseMemoryPool.Shared);

        Assert.AreEqual(0, parsed.ProtectedHeader.Length, "A genuinely zero-length protected header must parse, not throw on a zero-length pool rental.");

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            parsed,
            CoseSerialization.BuildSigStructure,
            publicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "The parsed message with a zero-length protected header must still verify.");
    }


    /// <summary>The <see cref="CoseSerialization.ParseCoseSign1AllowingNilPayload"/> sibling of the test above.</summary>
    [TestMethod]
    public void ParseCoseSign1AllowingNilPayloadAcceptsGenuinelyZeroLengthProtectedHeader()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteTag(new CborTag(CoseTags.Sign1));
        writer.WriteStartArray(4);
        writer.WriteByteString([]);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteNull();
        writer.WriteByteString([1, 2, 3, 4]);
        writer.WriteEndArray();
        byte[] wireBytes = writerBuffer.WrittenSpan.ToArray();

        using CoseSign1Message parsed = CoseSerialization.ParseCoseSign1AllowingNilPayload(wireBytes, BaseMemoryPool.Shared);

        Assert.AreEqual(0, parsed.ProtectedHeader.Length, "A genuinely zero-length protected header must parse, not throw on a zero-length pool rental.");
        Assert.IsTrue(parsed.Payload.IsEmpty, "The nil payload sentinel must still decode to the detached (empty) form.");
    }


    [TestMethod]
    public async Task VerifyAndDecodeReturnsValidResultForGenuineSignature()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 };
        EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(headerMap), BaseMemoryPool.Shared);
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using EncodedCoseSign1 coseBytes = CoseSerialization.SerializeCoseSign1(message, BaseMemoryPool.Shared);

        CoseVerificationResult result = await CoseVerification.VerifyAndDecodeAsync(
            coseBytes.AsReadOnlyMemory(),
            publicKey,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A genuine COSE_Sign1 signature must verify.");
        Assert.IsTrue(payload.AsSpan().SequenceEqual(result.Payload.Span), "The decoded payload must equal the signed payload.");
        Assert.IsNotNull(result.Algorithm);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, result.Algorithm.Value, "The decoded algorithm must be ES256.");
    }


    [TestMethod]
    public async Task VerifyAndDecodeReturnsInvalidForWrongKey()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 };
        EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(headerMap), BaseMemoryPool.Shared);
        byte[] payload = BuildTestPayload();

        var signingKeyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var signingPublicKey = signingKeyPair.PublicKey;
        using var signingPrivateKey = signingKeyPair.PrivateKey;

        var wrongKeyPair = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var wrongPublicKey = wrongKeyPair.PublicKey;
        using var wrongPrivateKey = wrongKeyPair.PrivateKey;

        var message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            signingPrivateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using EncodedCoseSign1 coseBytes = CoseSerialization.SerializeCoseSign1(message, BaseMemoryPool.Shared);

        CoseVerificationResult result = await CoseVerification.VerifyAndDecodeAsync(
            coseBytes.AsReadOnlyMemory(),
            wrongPublicKey,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A COSE_Sign1 verified against the wrong key must not be valid.");
    }


    [TestMethod]
    public async Task VerifyAndDecodeFailsClosedOnMalformedBytes()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        byte[] malformed = [0x00, 0x01, 0x02, 0x03];

        CoseVerificationResult result = await CoseVerification.VerifyAndDecodeAsync(
            malformed,
            publicKey,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Malformed COSE bytes must fail closed to an invalid result, not throw.");
    }


    [TestMethod]
    public void ProtectedHeaderSerializationRoundTripSucceeds()
    {
        var headerMap = new Dictionary<int, object>
        {
            [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256,
            [CoseHeaderParameters.Typ] = "application/vc+cose"
        };

        byte[] serialized = CoseSerialization.SerializeProtectedHeader(headerMap);
        IReadOnlyDictionary<int, object> parsed = CoseSerialization.ParseProtectedHeader(serialized);

        Assert.HasCount(2, parsed);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, parsed[CoseHeaderParameters.Alg]);
        Assert.AreEqual("application/vc+cose", parsed[CoseHeaderParameters.Typ]?.ToString());
    }


    /// <summary>
    /// A protected bucket whose map carries one label twice is refused as malformed, judged on the decoded
    /// label: <c>alg</c> twice in minimal form, <c>alg</c> twice with the second label in a two-byte width,
    /// <c>alg</c> twice with the same value, and one text-string label twice.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "Labels in each of
    /// the maps MUST be unique. When processing messages, if a label appears multiple times, the message MUST be
    /// rejected as malformed."
    /// </summary>
    /// <param name="protectedHeader">The serialized protected bucket.</param>
    [TestMethod]
    [DataRow(new byte[] { 0xA2, 0x01, 0x26, 0x01, 0x38, 0x22 }, DisplayName = "alg twice, minimal form")]
    [DataRow(new byte[] { 0xA2, 0x01, 0x26, 0x18, 0x01, 0x38, 0x22 }, DisplayName = "alg twice, second label in two widths")]
    [DataRow(new byte[] { 0xA2, 0x01, 0x26, 0x01, 0x26 }, DisplayName = "alg twice, same value")]
    [DataRow(new byte[] { 0xA2, 0x61, 0x78, 0x01, 0x61, 0x78, 0x02 }, DisplayName = "text label twice")]
    public void ParseProtectedHeaderRefusesARepeatedLabel(byte[] protectedHeader)
    {
        _ = Assert.ThrowsExactly<CborContentException>(() => CoseSerialization.ParseProtectedHeader(protectedHeader));
    }


    /// <summary>
    /// A correctly signed COSE_Sign1 whose protected bucket carries <c>alg</c> twice (ES384, then ES256,
    /// the public key's own algorithm) is NOT verified: the message is malformed, so neither the last
    /// algorithm nor an absent one may stand in for the refused header.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "When
    /// processing messages, if a label appears multiple times, the message MUST be rejected as malformed."
    /// </summary>
    [TestMethod]
    public async Task VerifyAndDecodeRefusesACorrectlySignedMessageWithARepeatedAlgorithm()
    {
        byte[] repeatedAlgorithmHeader = [0xA2, 0x01, 0x38, 0x22, 0x01, 0x26];
        EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(repeatedAlgorithmHeader, BaseMemoryPool.Shared);
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //The library's serializer refuses to write a protected bucket repeating a label, so the wire form is assembled as given.
        using EncodedCoseSign1 coseBytes = CoseWireFixtures.SerializeCoseSign1AsGiven(message, BaseMemoryPool.Shared);

        CoseVerificationResult result = await CoseVerification.VerifyAndDecodeAsync(
            coseBytes.AsReadOnlyMemory(),
            publicKey,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A COSE_Sign1 whose protected bucket repeats alg is malformed and must not verify.");
        Assert.IsNull(result.Algorithm, "No algorithm may be reported for a refused protected bucket.");
    }


    /// <summary>
    /// A COSE_Sign1 whose unprotected bucket carries one label twice (in one width, or in two widths), or whose
    /// protected bucket carries one label twice while the unprotected bucket is empty, is refused as malformed by
    /// both COSE_Sign1 parsers. <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>:
    /// "Labels in each of the maps MUST be unique. When processing messages, if a label appears multiple times,
    /// the message MUST be rejected as malformed."
    /// </summary>
    /// <param name="wireBytes">The tagged COSE_Sign1 wire bytes.</param>
    /// <param name="isNilPayloadParser">Whether the row drives <see cref="CoseSerialization.ParseCoseSign1AllowingNilPayload"/> rather than <see cref="CoseSerialization.ParseCoseSign1"/>.</param>
    [TestMethod]
    [DataRow(new byte[] { 0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA2, 0x04, 0x41, 0x01, 0x04, 0x41, 0x02, 0x41, 0x00, 0x41, 0x00 }, false, DisplayName = "ParseCoseSign1: unprotected kid twice")]
    [DataRow(new byte[] { 0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA2, 0x04, 0x41, 0x01, 0x18, 0x04, 0x41, 0x02, 0x41, 0x00, 0x41, 0x00 }, false, DisplayName = "ParseCoseSign1: unprotected kid twice, two widths")]
    [DataRow(new byte[] { 0xD2, 0x84, 0x45, 0xA2, 0x01, 0x26, 0x01, 0x26, 0xA0, 0x41, 0x00, 0x41, 0x00 }, false, DisplayName = "ParseCoseSign1: protected alg twice, unprotected empty")]
    [DataRow(new byte[] { 0xD2, 0x84, 0x47, 0xA2, 0x61, 0x78, 0x01, 0x61, 0x78, 0x02, 0xA0, 0x41, 0x00, 0x41, 0x00 }, false, DisplayName = "ParseCoseSign1: protected text label twice")]
    [DataRow(new byte[] { 0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA2, 0x04, 0x41, 0x01, 0x04, 0x41, 0x02, 0x41, 0x00, 0x41, 0x00 }, true, DisplayName = "AllowingNilPayload: unprotected kid twice")]
    [DataRow(new byte[] { 0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA2, 0x04, 0x41, 0x01, 0x18, 0x04, 0x41, 0x02, 0x41, 0x00, 0x41, 0x00 }, true, DisplayName = "AllowingNilPayload: unprotected kid twice, two widths")]
    [DataRow(new byte[] { 0xD2, 0x84, 0x45, 0xA2, 0x01, 0x26, 0x01, 0x26, 0xA0, 0xF6, 0x41, 0x00 }, true, DisplayName = "AllowingNilPayload: protected alg twice, unprotected empty")]
    [DataRow(new byte[] { 0xD2, 0x84, 0x47, 0xA2, 0x61, 0x78, 0x01, 0x61, 0x78, 0x02, 0xA0, 0xF6, 0x41, 0x00 }, true, DisplayName = "AllowingNilPayload: protected text label twice")]
    public void ParseCoseSign1RefusesARepeatedLabel(byte[] wireBytes, bool isNilPayloadParser)
    {
        ParseCoseSign1Delegate parse = SelectCoseSign1Parser(isNilPayloadParser);

        _ = Assert.ThrowsExactly<CborContentException>(() => parse(wireBytes, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A COSE_Sign1 whose protected and unprotected buckets hold the same label is refused as malformed by both
    /// COSE_Sign1 parsers. <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>:
    /// "Applications SHOULD verify that the same label does not occur in both the protected and unprotected
    /// header parameters."
    /// </summary>
    /// <param name="wireBytes">The tagged COSE_Sign1 wire bytes.</param>
    /// <param name="isNilPayloadParser">Whether the row drives <see cref="CoseSerialization.ParseCoseSign1AllowingNilPayload"/> rather than <see cref="CoseSerialization.ParseCoseSign1"/>.</param>
    [TestMethod]
    [DataRow(new byte[] { 0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA1, 0x01, 0x26, 0x41, 0x00, 0x41, 0x00 }, false, DisplayName = "ParseCoseSign1: alg in both buckets")]
    [DataRow(new byte[] { 0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA1, 0x01, 0x26, 0x41, 0x00, 0x41, 0x00 }, true, DisplayName = "AllowingNilPayload: alg in both buckets")]
    public void ParseCoseSign1RefusesALabelInBothBuckets(byte[] wireBytes, bool isNilPayloadParser)
    {
        ParseCoseSign1Delegate parse = SelectCoseSign1Parser(isNilPayloadParser);

        _ = Assert.ThrowsExactly<CborContentException>(() => parse(wireBytes, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A well-formed label the parsed header dictionary does not carry (a text string, or an integer beyond the
    /// 32 bits of the dictionary's own label) is read as a label of its own and passed over with its value: the
    /// message is accepted and the integer label beside it is carried.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052 Section 1.5</see>: "label = int / tstr".
    /// </summary>
    /// <param name="wireBytes">The tagged COSE_Sign1 wire bytes.</param>
    /// <param name="isNilPayloadParser">Whether the row drives <see cref="CoseSerialization.ParseCoseSign1AllowingNilPayload"/> rather than <see cref="CoseSerialization.ParseCoseSign1"/>.</param>
    /// <param name="carriedLabel">The one integer label the unprotected bucket carries in the parsed message.</param>
    [TestMethod]
    [DataRow(new byte[] { 0xD2, 0x84, 0x46, 0xA2, 0x01, 0x26, 0x61, 0x78, 0x01, 0xA1, 0x04, 0x41, 0x01, 0x41, 0x00, 0x41, 0x00 }, false, 4, DisplayName = "ParseCoseSign1: text label in the protected bucket")]
    [DataRow(new byte[] { 0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA2, 0x04, 0x41, 0x01, 0x61, 0x78, 0x01, 0x41, 0x00, 0x41, 0x00 }, false, 4, DisplayName = "ParseCoseSign1: text label in the unprotected bucket")]
    [DataRow(new byte[] { 0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA2, 0x18, 0x21, 0x41, 0x00, 0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x21, 0x41, 0x01, 0x41, 0x00, 0x41, 0x00 }, false, 33, DisplayName = "ParseCoseSign1: label 33 and label 4294967329")]
    [DataRow(new byte[] { 0xD2, 0x84, 0x46, 0xA2, 0x01, 0x26, 0x61, 0x78, 0x01, 0xA1, 0x04, 0x41, 0x01, 0xF6, 0x41, 0x00 }, true, 4, DisplayName = "AllowingNilPayload: text label in the protected bucket")]
    [DataRow(new byte[] { 0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA2, 0x04, 0x41, 0x01, 0x61, 0x78, 0x01, 0xF6, 0x41, 0x00 }, true, 4, DisplayName = "AllowingNilPayload: text label in the unprotected bucket")]
    [DataRow(new byte[] { 0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA2, 0x18, 0x21, 0x41, 0x00, 0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x21, 0x41, 0x01, 0xF6, 0x41, 0x00 }, true, 33, DisplayName = "AllowingNilPayload: label 33 and label 4294967329")]
    public void ParseCoseSign1PassesOverAWellFormedLabelItDoesNotCarry(byte[] wireBytes, bool isNilPayloadParser, int carriedLabel)
    {
        ParseCoseSign1Delegate parse = SelectCoseSign1Parser(isNilPayloadParser);

        using CoseSign1Message message = parse(wireBytes, BaseMemoryPool.Shared);

        Assert.IsNotNull(message.UnprotectedHeader, "The unprotected bucket carries one integer label the dictionary holds.");
        Assert.HasCount(1, message.UnprotectedHeader, "RFC 9052 Section 1.5: the label the dictionary does not carry is passed over, never read as another label.");
        Assert.IsTrue(message.UnprotectedHeader.ContainsKey(carriedLabel), "The integer label beside the passed-over label is carried.");
    }


    /// <summary>
    /// A COSE_Sign1 whose unprotected bucket is keyed by a byte string is refused by both COSE_Sign1 parsers with
    /// the CBOR reader's own failure. <see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052
    /// Section 1.5</see>: "In a CBOR map defined by this specification, the presence a label that is neither a text
    /// string nor an integer is an error."
    /// </summary>
    /// <param name="isNilPayloadParser">Whether the row drives <see cref="CoseSerialization.ParseCoseSign1AllowingNilPayload"/> rather than <see cref="CoseSerialization.ParseCoseSign1"/>.</param>
    [TestMethod]
    [DataRow(false, DisplayName = "ParseCoseSign1")]
    [DataRow(true, DisplayName = "AllowingNilPayload")]
    public void ParseCoseSign1RefusesAByteStringLabel(bool isNilPayloadParser)
    {
        byte[] wireBytes = [0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA1, 0x41, 0x01, 0x01, 0x41, 0x00, 0x41, 0x00];
        ParseCoseSign1Delegate parse = SelectCoseSign1Parser(isNilPayloadParser);

        _ = Assert.ThrowsExactly<CborContentException>(() => parse(wireBytes, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A correctly signed COSE_Sign1 whose protected bucket carries <c>alg</c> and a text-string label verifies, and
    /// its algorithm is read: the text-string label is well-formed and passed over.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052 Section 1.5</see>: "label = int / tstr".
    /// </summary>
    [TestMethod]
    public async Task VerifyAndDecodeReadsTheAlgorithmBesideATextLabel()
    {
        CoseVerificationResult result = await SignAndVerifyOverProtectedBucketAsync(
            [0xA2, 0x01, 0x26, 0x61, 0x78, 0x01]).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "RFC 9052 Section 1.5: a text-string label is well-formed, so the correctly signed message verifies.");
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, result.Algorithm, "The algorithm is read from the protected bucket beside the text-string label.");
    }


    /// <summary>
    /// A correctly signed COSE_Sign1 whose protected bucket carries a map value keyed by CBOR null fails the
    /// verification and answers a result, never an exception: the decoded dictionary cannot carry a null map
    /// key, so the bucket is refused as one the reader cannot represent.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-5.6">RFC 8949 Section 5.6</see>: "The encoding and
    /// decoding applications need to agree on what types of keys are going to be used in maps."
    /// </summary>
    [TestMethod]
    public async Task VerifyAndDecodeRefusesANullMapKeyInTheProtectedBucket()
    {
        CoseVerificationResult result = await SignAndVerifyOverProtectedBucketAsync(
            [0xA1, 0x01, 0xA1, 0xF6, 0x00]).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A protected bucket the reader refuses fails the verification.");
    }


    /// <summary>
    /// The COSE_Key labels -2 (<c>x</c>) and 4294967294 share their low 32 bits and are two labels: the COSE_Key
    /// carrying both is read, and <c>x</c> is the value under -2.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052 Section 1.5</see>: "label = int / tstr".
    /// </summary>
    [TestMethod]
    public void CoseKeyReaderReadsTwoLabelsOfOneLowWordAsTwo()
    {
        byte[] x = [.. Enumerable.Repeat((byte)0x11, 32)];
        byte[] coseKey = [0xA3, 0x01, 0x02, 0x21, 0x58, 0x20, .. x, 0x1A, 0xFF, 0xFF, 0xFF, 0xFE, 0x41, 0x00];

        CoseKey read = MdocCborCoseKeyReader.Read(coseKey);

        Assert.IsNotNull(read.X, "The x coordinate rides label -2.");
        Assert.IsTrue(read.X.Value.Span.SequenceEqual(x), "x is the value under -2, never the value under 4294967294.");
    }


    /// <summary>
    /// A COSE_Key carrying 32 bytes under label 4294967294 and nothing under -2 has no <c>x</c> coordinate: a label
    /// beyond 32 bits is its own label and is never read as the label of its low 32 bits.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052 Section 1.5</see>: "label = int / tstr".
    /// </summary>
    [TestMethod]
    public void CoseKeyReaderNeverReadsALabelBeyondThirtyTwoBitsAsX()
    {
        byte[] coseKey = [0xA2, 0x01, 0x02, 0x1A, 0xFF, 0xFF, 0xFF, 0xFE, 0x58, 0x20, .. Enumerable.Repeat((byte)0x11, 32)];

        CoseKey read = MdocCborCoseKeyReader.Read(coseKey);

        Assert.IsNull(read.X, "The value under 4294967294 is not the x coordinate.");
    }


    /// <summary>
    /// The COSE_Sign1 and COSE_Sign serializers refuse a protected bucket whose bytes carry one label twice, in
    /// the COSE_Sign1 layer, the COSE_Sign body layer and a COSE_Sign signer layer, with the caller's own
    /// <see cref="ArgumentException"/>. <see href="https://www.rfc-editor.org/rfc/rfc9052#section-9">RFC 9052
    /// Section 9</see>: "Applications MUST NOT generate messages with the same label used twice as a key in a
    /// single map."
    /// </summary>
    /// <param name="layer">The layer the protected bucket belongs to.</param>
    [TestMethod]
    [DataRow(SerializedLayer.CoseSign1, DisplayName = "COSE_Sign1")]
    [DataRow(SerializedLayer.CoseSignBody, DisplayName = "COSE_Sign body")]
    [DataRow(SerializedLayer.CoseSignSigner, DisplayName = "COSE_Sign signer")]
    public async Task SerializersRefuseAProtectedBucketRepeatingALabel(SerializedLayer layer)
    {
        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(
            () => WriteThroughSerializerAsync(layer, [0xA2, 0x01, 0x26, 0x01, 0x26], unprotectedHeader: null)).ConfigureAwait(false);
    }


    /// <summary>
    /// The COSE_Sign1 and COSE_Sign serializers refuse a protected bucket keyed by a byte string, in every layer,
    /// with the caller's own <see cref="ArgumentException"/>. <see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052
    /// Section 1.5</see>: "Applications can either fail processing or process messages by ignoring incorrect labels;
    /// however, they MUST NOT create messages with incorrect labels."
    /// </summary>
    /// <param name="layer">The layer the protected bucket belongs to.</param>
    [TestMethod]
    [DataRow(SerializedLayer.CoseSign1, DisplayName = "COSE_Sign1")]
    [DataRow(SerializedLayer.CoseSignBody, DisplayName = "COSE_Sign body")]
    [DataRow(SerializedLayer.CoseSignSigner, DisplayName = "COSE_Sign signer")]
    public async Task SerializersRefuseAProtectedLabelOfAnotherKind(SerializedLayer layer)
    {
        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(
            () => WriteThroughSerializerAsync(layer, [0xA1, 0x41, 0x01, 0x26], unprotectedHeader: null)).ConfigureAwait(false);
    }


    /// <summary>
    /// The COSE_Sign1 and COSE_Sign serializers refuse a layer whose protected and unprotected buckets hold the
    /// same label, with the caller's own <see cref="ArgumentException"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "Applications SHOULD
    /// verify that the same label does not occur in both the protected and unprotected header parameters."
    /// </summary>
    /// <param name="layer">The layer whose buckets share the label.</param>
    [TestMethod]
    [DataRow(SerializedLayer.CoseSign1, DisplayName = "COSE_Sign1")]
    [DataRow(SerializedLayer.CoseSignBody, DisplayName = "COSE_Sign body")]
    [DataRow(SerializedLayer.CoseSignSigner, DisplayName = "COSE_Sign signer")]
    public async Task SerializersRefuseALabelInBothBuckets(SerializedLayer layer)
    {
        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(() => WriteThroughSerializerAsync(
            layer, [0xA1, 0x01, 0x26], new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 })).ConfigureAwait(false);
    }


    /// <summary>The COSE layer a serializer row writes its buckets into.</summary>
    internal enum SerializedLayer
    {
        /// <summary>The one layer of a COSE_Sign1.</summary>
        CoseSign1,

        /// <summary>The body layer of a COSE_Sign.</summary>
        CoseSignBody,

        /// <summary>The layer of a COSE_Sign's one signer.</summary>
        CoseSignSigner
    }


    /// <summary>Selects one of the two COSE_Sign1 parsers.</summary>
    /// <param name="isNilPayloadParser">Whether the parser that admits a nil payload is selected.</param>
    /// <returns>The selected parser.</returns>
    private static ParseCoseSign1Delegate SelectCoseSign1Parser(bool isNilPayloadParser)
    {
        return isNilPayloadParser switch
        {
            true => CoseSerialization.ParseCoseSign1AllowingNilPayload,
            false => CoseSerialization.ParseCoseSign1
        };
    }


    /// <summary>
    /// Signs a P-256 COSE_Sign1 over <paramref name="protectedHeader"/> as given, assembles its wire form as given and
    /// runs <see cref="CoseVerification.VerifyAndDecodeAsync"/> over it with the signing key's public half.
    /// </summary>
    /// <param name="protectedHeader">The serialized protected bucket the signature covers.</param>
    /// <returns>The verification result.</returns>
    private async Task<CoseVerificationResult> SignAndVerifyOverProtectedBucketAsync(byte[] protectedHeader)
    {
        EncodedCoseProtectedHeader protectedHeaderCarrier = EncodedCoseProtectedHeader.FromBytes(protectedHeader, BaseMemoryPool.Shared);
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using CoseSign1Message message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeaderCarrier,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using EncodedCoseSign1 coseBytes = CoseWireFixtures.SerializeCoseSign1AsGiven(message, BaseMemoryPool.Shared);

        return await CoseVerification.VerifyAndDecodeAsync(
            coseBytes.AsReadOnlyMemory(),
            publicKey,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Signs a message with a P-256 key and writes it through <see cref="CoseSerialization.SerializeCoseSign1"/> or
    /// <see cref="CoseSerialization.SerializeCoseSign"/> with <paramref name="protectedHeader"/> and
    /// <paramref name="unprotectedHeader"/> in <paramref name="layer"/>; every other bucket is well-formed.
    /// </summary>
    /// <param name="layer">The layer the two buckets belong to.</param>
    /// <param name="protectedHeader">The serialized protected bucket.</param>
    /// <param name="unprotectedHeader">The unprotected bucket, or <see langword="null"/> for an empty one.</param>
    /// <returns>A task that completes when the message has been written.</returns>
    private async Task WriteThroughSerializerAsync(SerializedLayer layer, byte[] protectedHeader, Dictionary<int, object>? unprotectedHeader)
    {
        byte[] wellFormedHeader = [0xA1, 0x01, 0x26];
        Task write = layer switch
        {
            SerializedLayer.CoseSign1 => WriteCoseSign1Async(protectedHeader, unprotectedHeader),
            SerializedLayer.CoseSignBody => WriteCoseSignAsync(protectedHeader, unprotectedHeader, wellFormedHeader, signerUnprotectedHeader: null),
            _ => WriteCoseSignAsync(wellFormedHeader, bodyUnprotectedHeader: null, protectedHeader, unprotectedHeader)
        };

        await write.ConfigureAwait(false);
    }


    /// <summary>Signs a COSE_Sign1 with the given buckets and writes it through <see cref="CoseSerialization.SerializeCoseSign1"/>.</summary>
    /// <param name="protectedHeader">The serialized protected bucket.</param>
    /// <param name="unprotectedHeader">The unprotected bucket, or <see langword="null"/>.</param>
    /// <returns>A task that completes when the message has been written.</returns>
    private async Task WriteCoseSign1Async(byte[] protectedHeader, Dictionary<int, object>? unprotectedHeader)
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using CoseSign1Message message = await Verifiable.JCose.Cose.SignAsync(
            EncodedCoseProtectedHeader.FromBytes(protectedHeader, BaseMemoryPool.Shared),
            unprotectedHeader,
            new byte[] { 0x00 },
            CoseSerialization.BuildSigStructure,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using EncodedCoseSign1 written = CoseSerialization.SerializeCoseSign1(message, BaseMemoryPool.Shared);
    }


    /// <summary>Signs a COSE_Sign with one signer and the given buckets and writes it through <see cref="CoseSerialization.SerializeCoseSign"/>.</summary>
    /// <param name="bodyProtectedHeader">The body layer's serialized protected bucket.</param>
    /// <param name="bodyUnprotectedHeader">The body layer's unprotected bucket, or <see langword="null"/>.</param>
    /// <param name="signerProtectedHeader">The signer layer's serialized protected bucket.</param>
    /// <param name="signerUnprotectedHeader">The signer layer's unprotected bucket, or <see langword="null"/>.</param>
    /// <returns>A task that completes when the message has been written.</returns>
    private async Task WriteCoseSignAsync(
        byte[] bodyProtectedHeader,
        Dictionary<int, object>? bodyUnprotectedHeader,
        byte[] signerProtectedHeader,
        Dictionary<int, object>? signerUnprotectedHeader)
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        CoseSignerInput[] signers =
        [
            new CoseSignerInput(EncodedCoseProtectedHeader.FromBytes(signerProtectedHeader, BaseMemoryPool.Shared), signerUnprotectedHeader, privateKey)
        ];

        using CoseSignMessage message = await CoseSign.SignAsync(
            EncodedCoseProtectedHeader.FromBytes(bodyProtectedHeader, BaseMemoryPool.Shared),
            bodyUnprotectedHeader,
            new byte[] { 0x00 },
            signers,
            CoseSerialization.BuildCoseSignatureSigStructure,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using EncodedCoseSign written = CoseSerialization.SerializeCoseSign(message, BaseMemoryPool.Shared);
    }


    [TestMethod]
    public void DefaultTagToCoseConverterMapsP256Correctly()
    {
        int coseAlg = CryptoFormatConversions.DefaultTagToCoseConverter(CryptoTags.P256PrivateKey);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, coseAlg);
    }


    [TestMethod]
    public void DefaultTagToCoseConverterMapsP384Correctly()
    {
        int coseAlg = CryptoFormatConversions.DefaultTagToCoseConverter(CryptoTags.P384PrivateKey);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es384, coseAlg);
    }


    [TestMethod]
    public void DefaultTagToCoseConverterMapsP521Correctly()
    {
        int coseAlg = CryptoFormatConversions.DefaultTagToCoseConverter(CryptoTags.P521PrivateKey);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es512, coseAlg);
    }


    [TestMethod]
    public void DefaultTagToCoseConverterMapsEd25519Correctly()
    {
        int coseAlg = CryptoFormatConversions.DefaultTagToCoseConverter(CryptoTags.Ed25519PrivateKey);
        Assert.AreEqual(WellKnownCoseAlgorithms.EdDsa, coseAlg);
    }


    [TestMethod]
    public void DefaultTagToCoseConverterThrowsForUnsupported()
    {
        _ = Assert.Throws<NotSupportedException>(() =>
            CryptoFormatConversions.DefaultTagToCoseConverter(CryptoTags.X25519PublicKey));
    }


    [TestMethod]
    public void DefaultCoseToTagConverterRoundTripsWithTagToCose()
    {
        int coseAlg = CryptoFormatConversions.DefaultTagToCoseConverter(CryptoTags.P256PrivateKey);
        Tag roundTripped = CryptoFormatConversions.DefaultCoseToTagConverter(coseAlg, Purpose.Signing);
        Assert.AreEqual(CryptoTags.P256PrivateKey, roundTripped);
    }


    /// <summary>
    /// Builds a simple CWT-style test payload with issuer and issued-at claims.
    /// </summary>
    private static byte[] BuildTestPayload()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(WellKnownCwtClaimNames.Iss);
        writer.WriteTextString("did:example:issuer");
        writer.WriteInt32(WellKnownCwtClaimNames.Iat);
        writer.WriteInt64(1718452800);
        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }


    private sealed record TestResolverState(byte[] PrivateKeyBytes, byte[] PublicKeyBytes);


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller which disposes via PrivateKey.")]
    private static ValueTask<PrivateKeyMemory?> ResolvePrivateKeyMaterial(
        CoseKeyContext context,
        BaseMemoryPool pool,
        TestResolverState state,
        CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> memoryOwner = pool.Rent(state.PrivateKeyBytes.Length);
        state.PrivateKeyBytes.CopyTo(memoryOwner.Memory.Span);
        return ValueTask.FromResult<PrivateKeyMemory?>(new PrivateKeyMemory(memoryOwner, CryptoTags.P256PrivateKey));
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller which disposes via PublicKey.")]
    private static ValueTask<PublicKeyMemory?> ResolvePublicKeyMaterial(
        CoseKeyContext context,
        BaseMemoryPool pool,
        TestResolverState state,
        CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> memoryOwner = pool.Rent(state.PublicKeyBytes.Length);
        state.PublicKeyBytes.CopyTo(memoryOwner.Memory.Span);
        return ValueTask.FromResult<PublicKeyMemory?>(new PublicKeyMemory(memoryOwner, CryptoTags.P256PublicKey));
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller which disposes the returned PrivateKey.")]
    private static ValueTask<PrivateKey> BindPrivateKey(
        PrivateKeyMemory material,
        int state,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(new PrivateKey(material, "test-key", MicrosoftCryptographicFunctionsAdapter.SignP256Async));
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller which disposes the returned PublicKey.")]
    private static ValueTask<PublicKey> BindPublicKey(
        PublicKeyMemory material,
        int state,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(new PublicKey(material, "test-key", MicrosoftCryptographicFunctionsAdapter.VerifyP256Async));
    }
}
