using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core.Model.Credentials;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cose;

/// <summary>
/// Tests for COSE_Sign1 credential envelope securing and verification.
/// </summary>
/// <remarks>
/// <para>
/// These are Layer 2 tests that verify the credential-level COSE API. They test:
/// </para>
/// <list type="bullet">
/// <item><description>Credential serialization to COSE_Sign1 payload.</description></item>
/// <item><description>Protected header construction with algorithm, key ID, content type, and type parameters.</description></item>
/// <item><description>Signing via <see cref="CredentialCoseExtensions.SignCoseAsync"/>.</description></item>
/// <item><description>Verification via <see cref="CredentialCoseExtensions.VerifyCoseAsync"/>.</description></item>
/// <item><description>CBOR wire format round-trip via <see cref="CoseSerialization"/>.</description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class CoseCredentialSecuringTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task SignCoseAndVerifyWithRegistrySucceeds()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        using var publicKey = CredentialSecuringMaterial.DecodeEd25519PublicKey();

        CoseSign1Message message = await credential.SignCoseAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            CredentialToCborBytes,
            CoseProtectedHeaderToCborBytes,
            CoseSerialization.BuildSigStructure,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(message);
        Assert.IsGreaterThan(0, message.Payload.Length);
        Assert.IsGreaterThan(0, message.Signature.Length);

        CoseCredentialVerificationResult result = await CredentialCoseExtensions.VerifyCoseAsync(
            message,
            CoseSerialization.BuildSigStructure,
            publicKey,
            CredentialFromJsonBytes,
            CoseSerialization.ParseProtectedHeader,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "COSE credential verification must succeed.");
        Assert.IsNotNull(result.Credential);
        Assert.AreEqual(WellKnownCoseAlgorithms.EdDsa, result.Algorithm);
        Assert.AreEqual(CredentialSecuringMaterial.VerificationMethodId, result.KeyId);
    }


    [TestMethod]
    public async Task SignCoseContainsCorrectProtectedHeaderMetadata()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        CoseSign1Message message = await credential.SignCoseAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            CredentialToCborBytes,
            CoseProtectedHeaderToCborBytes,
            CoseSerialization.BuildSigStructure,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyDictionary<int, object> header = CoseSerialization.ParseProtectedHeader(message.ProtectedHeaderBytes.Span);

        Assert.AreEqual(WellKnownCoseAlgorithms.EdDsa, header[CoseHeaderParameters.Alg]);
        Assert.AreEqual(CredentialSecuringMaterial.VerificationMethodId, header[CoseHeaderParameters.Kid]);
        Assert.AreEqual(WellKnownMediaTypes.Application.ApplicationVc, header[CoseHeaderParameters.ContentType]?.ToString());
        Assert.AreEqual(WellKnownMediaTypes.Application.VcCose, header[CoseHeaderParameters.Typ]?.ToString());
    }


    [TestMethod]
    public async Task SignCosePayloadDeserializesToOriginalCredential()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        CoseSign1Message message = await credential.SignCoseAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            CredentialToCborBytes,
            CoseProtectedHeaderToCborBytes,
            CoseSerialization.BuildSigStructure,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        VerifiableCredential deserialized = CredentialFromJsonBytes(message.Payload.Span);

        Assert.AreEqual(credential.Id, deserialized.Id);
        Assert.AreEqual(credential.Issuer?.Id, deserialized.Issuer?.Id);
        Assert.AreEqual(credential.ValidFrom, deserialized.ValidFrom);
    }


    [TestMethod]
    public async Task CborWireFormatRoundTripPreservesSignature()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        using var publicKey = CredentialSecuringMaterial.DecodeEd25519PublicKey();

        CoseSign1Message message = await credential.SignCoseAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            CredentialToCborBytes,
            CoseProtectedHeaderToCborBytes,
            CoseSerialization.BuildSigStructure,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] coseBytes = CoseSerialization.SerializeCoseSign1(message);
        CoseSign1Message parsed = CoseSerialization.ParseCoseSign1(coseBytes);

        Assert.IsTrue(message.ProtectedHeaderBytes.Span.SequenceEqual(parsed.ProtectedHeaderBytes.Span), "Protected header must survive CBOR round-trip.");
        Assert.IsTrue(message.Payload.Span.SequenceEqual(parsed.Payload.Span), "Payload must survive CBOR round-trip.");
        Assert.IsTrue(message.Signature.Span.SequenceEqual(parsed.Signature.Span), "Signature must survive CBOR round-trip.");

        CoseCredentialVerificationResult result = await CredentialCoseExtensions.VerifyCoseAsync(
            parsed,
            CoseSerialization.BuildSigStructure,
            publicKey,
            CredentialFromJsonBytes,
            CoseSerialization.ParseProtectedHeader,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "Parsed COSE_Sign1 credential must verify successfully.");
    }


    [TestMethod]
    public async Task VerifyWithWrongKeyFails()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        CoseSign1Message message = await credential.SignCoseAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            CredentialToCborBytes,
            CoseProtectedHeaderToCborBytes,
            CoseSerialization.BuildSigStructure,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Use a different P-256 key for verification.
        var wrongKeyPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);
        using var wrongPublicKey = wrongKeyPair.PublicKey;
        using var wrongPrivateKey = wrongKeyPair.PrivateKey;

        CoseCredentialVerificationResult result = await CredentialCoseExtensions.VerifyCoseAsync(
            message,
            CoseSerialization.BuildSigStructure,
            wrongPublicKey,
            CredentialFromJsonBytes,
            CoseSerialization.ParseProtectedHeader,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Verification with wrong key must fail.");
        Assert.IsNull(result.Credential);
    }


    [TestMethod]
    public async Task CustomContentTypeAppearsInHeader()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        const string customContentType = "application/vc+cwt";

        CoseSign1Message message = await credential.SignCoseAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            CredentialToCborBytes,
            CoseProtectedHeaderToCborBytes,
            CoseSerialization.BuildSigStructure,
            SensitiveMemoryPool<byte>.Shared,
            contentType: customContentType,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyDictionary<int, object> header = CoseSerialization.ParseProtectedHeader(message.ProtectedHeaderBytes.Span);

        Assert.AreEqual(customContentType, header[CoseHeaderParameters.ContentType]?.ToString());
    }


    private static ReadOnlySpan<byte> CredentialToCborBytes(VerifiableCredential credential) =>
        JsonSerializer.SerializeToUtf8Bytes(credential, CredentialSecuringMaterial.JsonOptions);

    private static ReadOnlySpan<byte> CoseProtectedHeaderToCborBytes(IReadOnlyDictionary<int, object> header) =>
        CoseSerialization.SerializeProtectedHeader(header);

    private static VerifiableCredential CredentialFromJsonBytes(ReadOnlySpan<byte> bytes) =>
        JsonSerializer.Deserialize<VerifiableCredential>(bytes, CredentialSecuringMaterial.JsonOptions)!;
}