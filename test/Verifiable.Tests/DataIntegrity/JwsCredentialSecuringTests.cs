using System.Buffers;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core.Model.Credentials;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Jose;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests for JWS credential envelope securing and verification.
/// </summary>
/// <remarks>
/// <para>
/// These are Layer 2 tests that verify the credential-level JOSE API. They test:
/// </para>
/// <list type="bullet">
/// <item><description>Credential serialization to JWS payload.</description></item>
/// <item><description>Protected header construction with algorithm, type, key ID, and content type parameters.</description></item>
/// <item><description>Signing via <see cref="CredentialJwsExtensions.SignJwsAsync"/>.</description></item>
/// <item><description>Verification via <see cref="CredentialJwsExtensions.VerifyJwsAsync(string, PublicKeyMemory, DecodeDelegate, JwtHeaderDeserializer, CredentialFromJsonBytesDelegate, System.Buffers.MemoryPool{byte}, System.Threading.CancellationToken)"/>.</description></item>
/// <item><description>Compact serialization round-trip via <see cref="JwsSerialization"/>.</description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class JwsCredentialSecuringTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task SignJwsAndVerifyFromCompactSerializationSucceeds()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        using var publicKey = CredentialSecuringMaterial.DecodeEd25519PublicKey();

        JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        Assert.IsNotNull(jws);
        string[] parts = jws.Split('.');
        Assert.HasCount(3, parts);

        JwsCredentialVerificationResult result = await CredentialJwsExtensions.VerifyJwsAsync(
            jws,
            publicKey,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            SensitiveMemoryPool<byte>.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "JWS credential verification must succeed.");
        Assert.IsNotNull(result.Credential);
        Assert.AreEqual(credential.Id, result.Credential!.Id);
    }


    [TestMethod]
    public async Task SignJwsAndVerifyFromMessageSucceeds()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        using var publicKey = CredentialSecuringMaterial.DecodeEd25519PublicKey();

        JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        JwsCredentialVerificationResult result = await CredentialJwsExtensions.VerifyJwsAsync(
            jwsMessage,
            publicKey,
            TestSetup.Base64UrlEncoder,
            CredentialDeserializer,
            SensitiveMemoryPool<byte>.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "JWS message verification must succeed.");
        Assert.IsNotNull(result.Credential);
        Assert.AreEqual(credential.Id, result.Credential!.Id);
    }


    [TestMethod]
    public async Task SignJwsContainsCorrectHeaderMetadata()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);
        string[] parts = jws.Split('.');

        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(parts[0], SensitiveMemoryPool<byte>.Shared);
        Dictionary<string, object>? header = HeaderDeserializer(headerBytes.Memory.Span);

        Assert.IsNotNull(header);
        Assert.AreEqual("EdDSA", header[JwkProperties.Alg].ToString());
        Assert.AreEqual(WellKnownMediaTypes.Jwt.VcJwt, header[JwkProperties.Typ].ToString());
        Assert.AreEqual(CredentialSecuringMaterial.VerificationMethodId, header[JwkProperties.Kid].ToString());
        Assert.AreEqual(WellKnownMediaTypes.Application.Vc, header[JwkProperties.Cty].ToString());
    }


    [TestMethod]
    public async Task SignJwsPayloadDeserializesToOriginalCredential()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        VerifiableCredential deserialized = CredentialDeserializer(jwsMessage.Payload.Span);

        Assert.AreEqual(credential.Id, deserialized.Id);
        Assert.AreEqual(credential.Issuer?.Id, deserialized.Issuer?.Id);
        Assert.AreEqual(credential.ValidFrom, deserialized.ValidFrom);
    }


    [TestMethod]
    public async Task CompactSerializationRoundTripPreservesSignature()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        using var publicKey = CredentialSecuringMaterial.DecodeEd25519PublicKey();

        JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        JwsCredentialVerificationResult result = await CredentialJwsExtensions.VerifyJwsAsync(
            jws,
            publicKey,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            SensitiveMemoryPool<byte>.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "Compact serialization round-trip must verify successfully.");
    }


    [TestMethod]
    public async Task VerifyWithWrongKeyFails()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        //Use a different P-256 key for verification.
        var wrongKeyPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);
        using var wrongPublicKey = wrongKeyPair.PublicKey;
        using var wrongPrivateKey = wrongKeyPair.PrivateKey;

        JwsCredentialVerificationResult result = await CredentialJwsExtensions.VerifyJwsAsync(
            jws,
            wrongPublicKey,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            SensitiveMemoryPool<byte>.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Verification with wrong key must fail.");
    }


    [TestMethod]
    public async Task CustomMediaTypeAppearsInHeader()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            mediaType: WellKnownMediaTypes.Jwt.VcLdJwt,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);
        string[] parts = jws.Split('.');

        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(parts[0], SensitiveMemoryPool<byte>.Shared);
        Dictionary<string, object>? header = HeaderDeserializer(headerBytes.Memory.Span);

        Assert.IsNotNull(header);
        Assert.AreEqual(WellKnownMediaTypes.Jwt.VcLdJwt, header[JwkProperties.Typ].ToString());
    }


    [TestMethod]
    public async Task CustomContentTypeAppearsInHeader()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            contentType: WellKnownMediaTypes.Application.Vp,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);
        string[] parts = jws.Split('.');

        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(parts[0], SensitiveMemoryPool<byte>.Shared);
        Dictionary<string, object>? header = HeaderDeserializer(headerBytes.Memory.Span);

        Assert.IsNotNull(header);
        Assert.AreEqual(WellKnownMediaTypes.Application.Vp, header[JwkProperties.Cty].ToString());
    }


    private static ReadOnlySpan<byte> CredentialSerializer(VerifiableCredential credential) =>
        JsonSerializer.SerializeToUtf8Bytes(credential, CredentialSecuringMaterial.JsonOptions);

    private static ReadOnlySpan<byte> HeaderSerializer(Dictionary<string, object> header) =>
        JsonSerializer.SerializeToUtf8Bytes(header);

    private static Dictionary<string, object>? HeaderDeserializer(ReadOnlySpan<byte> headerBytes) =>
        JsonSerializer.Deserialize<Dictionary<string, object>>(headerBytes);

    private static VerifiableCredential CredentialDeserializer(ReadOnlySpan<byte> credentialBytes) =>
        JsonSerializer.Deserialize<VerifiableCredential>(credentialBytes, CredentialSecuringMaterial.JsonOptions)!;
}