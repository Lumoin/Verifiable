using System.Text.Json;
using Verifiable.Core.Model.Credentials;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Jose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// Tests for JWS credential signing with JwsMessage POCO.
/// </summary>
[TestClass]
internal sealed class JwsMessageTests
{
    public TestContext TestContext { get; set; } = null!;

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    private const string Ed25519PublicKeyMultibase = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
    private const string Ed25519SecretKeyMultibase = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";
    private const string Ed25519VerificationMethodId = "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";

    private const string UnsignedCredentialJson = /*lang=json,strict*/ """
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential"],
            "issuer": {
                "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
                "name": "Example University"
            },
            "validFrom": "2010-01-01T19:23:24Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                    "type": "ExampleBachelorDegree",
                    "name": "Bachelor of Science and Arts"
                }
            }
        }
        """;


    [TestMethod]
    public async ValueTask SignJwsReturnsJwsMessageWithCorrectStructure()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;
        using PrivateKeyMemory privateKeyMemory = CreateEd25519PrivateKey();

        using JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKeyMemory,
            Ed25519VerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(jwsMessage);
        Assert.HasCount(1, jwsMessage.Signatures);
        Assert.IsFalse(jwsMessage.IsDetachedPayload);
        Assert.IsGreaterThan(0, jwsMessage.Payload.Length);

        var protectedHeader = jwsMessage.Signatures[0].ProtectedHeader;
        Assert.IsTrue(protectedHeader.ContainsKey(JwkProperties.Alg));
        Assert.IsTrue(protectedHeader.ContainsKey(JwkProperties.Typ));
        Assert.IsTrue(protectedHeader.ContainsKey(JwkProperties.Kid));
        Assert.AreEqual(WellKnownJwaValues.EdDsa, protectedHeader[JwkProperties.Alg]);
        Assert.AreEqual(Ed25519VerificationMethodId, protectedHeader[JwkProperties.Kid]);
    }


    [TestMethod]
    public async ValueTask JwsMessageSerializesToCompactAndVerifies()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;
        using PrivateKeyMemory privateKeyMemory = CreateEd25519PrivateKey();

        using JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKeyMemory,
            Ed25519VerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compact = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        Assert.IsNotNull(compact);
        string[] parts = compact.Split('.');
        Assert.HasCount(3, parts);

        using PublicKeyMemory publicKeyMemory = CreateEd25519PublicKey();
        var verificationResult = await CredentialJwsExtensions.VerifyJwsAsync(
            compact,
            publicKeyMemory,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verificationResult.IsValid, "JWS signature verification must succeed.");
        Assert.IsNotNull(verificationResult.Credential);
        Assert.AreEqual(credential.Id, verificationResult.Credential.Id);
    }


    [TestMethod]
    public async ValueTask JwsMessageVerifiesDirectlyWithoutSerialization()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;
        using PrivateKeyMemory privateKeyMemory = CreateEd25519PrivateKey();

        using JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKeyMemory,
            Ed25519VerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using PublicKeyMemory publicKeyMemory = CreateEd25519PublicKey();
        var verificationResult = await CredentialJwsExtensions.VerifyJwsAsync(
            jwsMessage,
            publicKeyMemory,
            TestSetup.Base64UrlEncoder,
            CredentialDeserializer,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verificationResult.IsValid, "JWS message verification must succeed.");
        Assert.IsNotNull(verificationResult.Credential);
        Assert.AreEqual(credential.Id, verificationResult.Credential.Id);
    }


    [TestMethod]
    public async ValueTask CompactJwsRoundTripsToUnverifiedJwsMessage()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;
        using PrivateKeyMemory privateKeyMemory = CreateEd25519PrivateKey();

        using JwsMessage originalMessage = await credential.SignJwsAsync(
            privateKeyMemory,
            Ed25519VerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compact = JwsSerialization.SerializeCompact(originalMessage, TestSetup.Base64UrlEncoder);

        using UnverifiedJwsMessage parsedMessage = JwsParsing.ParseCompact(
            compact,
            TestSetup.Base64UrlDecoder,
            bytes => JsonSerializer.Deserialize<Dictionary<string, object>>(bytes)!,
            SensitiveMemoryPool<byte>.Shared);

        Assert.IsNotNull(parsedMessage);
        Assert.HasCount(1, parsedMessage.Signatures);
        Assert.IsFalse(parsedMessage.IsDetachedPayload);
        Assert.IsTrue(originalMessage.Payload.Span.SequenceEqual(parsedMessage.Payload.Span));
        Assert.IsTrue(parsedMessage.Signatures[0].SignatureBytes.Memory.Span.SequenceEqual(
            originalMessage.Signatures[0].Signature.AsReadOnlySpan()));
    }


    [TestMethod]
    public void JwsMessageEqualityComparesCorrectly()
    {
        var header = new Dictionary<string, object> { [JwkProperties.Alg] = WellKnownJwaValues.Es256 };
        byte[] payload = [1, 2, 3, 4];
        byte[] signatureBytes = [5, 6, 7, 8];

        using var sig1 = signatureBytes.ToSignature(CryptoTags.P256Signature, SensitiveMemoryPool<byte>.Shared);
        using var sig2 = signatureBytes.ToSignature(CryptoTags.P256Signature, SensitiveMemoryPool<byte>.Shared);

        using var component1 = new JwsSignatureComponent("encoded", header, sig1);
        using var component2 = new JwsSignatureComponent("encoded", header, sig2);

        using var msg1 = new JwsMessage(payload, component1);
        using var msg2 = new JwsMessage(payload, component2);

        Assert.AreEqual(msg1, msg2);
        Assert.IsTrue(msg1 == msg2);
        Assert.IsFalse(msg1 != msg2);
    }


    [TestMethod]
    public void CompactSerializationThrowsForMultipleSignatures()
    {
        var header = new Dictionary<string, object> { [JwkProperties.Alg] = WellKnownJwaValues.Es256 };
        byte[] payload = [1, 2, 3, 4];
        byte[] signatureBytes = [5, 6, 7, 8];

        using var sig1 = signatureBytes.ToSignature(CryptoTags.P256Signature, SensitiveMemoryPool<byte>.Shared);
        using var sig2 = signatureBytes.ToSignature(CryptoTags.P256Signature, SensitiveMemoryPool<byte>.Shared);

        using var component1 = new JwsSignatureComponent("encoded1", header, sig1);
        using var component2 = new JwsSignatureComponent("encoded2", header, sig2);

        using var message = new JwsMessage(payload, [component1, component2]);

        Assert.Throws<InvalidOperationException>(() => JwsSerialization.SerializeCompact(message, TestSetup.Base64UrlEncoder));
    }


    [TestMethod]
    public void CompactSerializationThrowsForDetachedPayload()
    {
        var header = new Dictionary<string, object> { [JwkProperties.Alg] = WellKnownJwaValues.Es256 };
        byte[] payload = [1, 2, 3, 4];
        byte[] signatureBytes = [5, 6, 7, 8];

        using var sig = signatureBytes.ToSignature(CryptoTags.P256Signature, SensitiveMemoryPool<byte>.Shared);
        using var component = new JwsSignatureComponent("encoded", header, sig);
        using var message = new JwsMessage(payload, component, isDetachedPayload: true);

        Assert.Throws<InvalidOperationException>(() => JwsSerialization.SerializeCompact(message, TestSetup.Base64UrlEncoder));
    }


    [TestMethod]
    public void JwsMessageConstructorThrowsForEmptySignaturesList()
    {
        byte[] payload = [1, 2, 3, 4];

        Assert.Throws<ArgumentException>(() =>
            new JwsMessage(payload, Array.Empty<JwsSignatureComponent>().ToList()));
    }


    private static PrivateKeyMemory CreateEd25519PrivateKey()
    {
        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase,
            MulticodecHeaders.Ed25519PrivateKey.Length,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);
        return new PrivateKeyMemory(privateKeyBytes, CryptoTags.Ed25519PrivateKey);
    }


    private static PublicKeyMemory CreateEd25519PublicKey()
    {
        var publicKeyBytes = MultibaseSerializer.Decode(
            Ed25519PublicKeyMultibase,
            MulticodecHeaders.Ed25519PublicKey.Length,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);
        return new PublicKeyMemory(publicKeyBytes, CryptoTags.Ed25519PublicKey);
    }


    private static ReadOnlySpan<byte> CredentialSerializer(VerifiableCredential credential) => JsonSerializer.SerializeToUtf8Bytes(credential, JsonOptions);

    private static ReadOnlySpan<byte> HeaderSerializer(Dictionary<string, object> header) => JsonSerializer.SerializeToUtf8Bytes(header);

    private static Dictionary<string, object>? HeaderDeserializer(ReadOnlySpan<byte> headerBytes) => JsonSerializer.Deserialize<Dictionary<string, object>>(headerBytes);

    private static VerifiableCredential CredentialDeserializer(ReadOnlySpan<byte> credentialBytes) => JsonSerializer.Deserialize<VerifiableCredential>(credentialBytes, JsonOptions)!;
}