using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;
using Verifiable.Jose;
using Verifiable.Json.Sd;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Tests for VC-specific SD-JWT issuance using <see cref="SdJwtIssuance.IssueAsync"/>
/// with <c>vc+sd-jwt</c> media type.
/// </summary>
[TestClass]
internal sealed class SdJwtVcIssuanceTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private static HashSet<CredentialPath> DisclosablePaths { get; } =
    [
        CredentialPath.FromJsonPointer("/credentialSubject/degree"),
        CredentialPath.FromJsonPointer("/credentialSubject/id")
    ];


    [TestMethod]
    public async Task SignSdJwtProducesValidToken()
    {
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        SdToken<string> token = await SignCredentialAsync(privateKey).ConfigureAwait(false);

        Assert.IsNotNull(token);
        Assert.IsNotNull(token.IssuerSigned);
        Assert.HasCount(2, token.Disclosures);
    }


    [TestMethod]
    public async Task SignSdJwtHeaderContainsVcSdJwtMediaType()
    {
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        SdToken<string> token = await SignCredentialAsync(privateKey).ConfigureAwait(false);

        string[] jwtParts = token.IssuerSigned.Split('.');
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(jwtParts[0], Pool);
        Dictionary<string, object>? header = JsonSerializer.Deserialize<Dictionary<string, object>>(headerBytes.Memory.Span, CredentialSecuringMaterial.JsonOptions);

        Assert.IsNotNull(header);
        Assert.AreEqual("EdDSA", header[JwkProperties.Alg].ToString());
        Assert.AreEqual(WellKnownMediaTypes.Jwt.VcSdJwt, header[JwkProperties.Typ].ToString(),
            "VC SD-JWT must use vc+sd-jwt media type per VC-JOSE-COSE Section 6.1.3.");
        Assert.AreEqual(CredentialSecuringMaterial.VerificationMethodId, header[JwkProperties.Kid].ToString());
    }


    [TestMethod]
    public async Task SignSdJwtEmbedsSdArrayInsideCredentialSubject()
    {
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        SdToken<string> token = await SignCredentialAsync(privateKey).ConfigureAwait(false);

        JsonElement payload = ParsePayload(token);

        Assert.IsTrue(payload.TryGetProperty(SdConstants.SdAlgorithmClaimName, out JsonElement sdAlg), "Payload must contain _sd_alg at root.");
        Assert.AreEqual(WellKnownHashAlgorithms.Sha256Iana, sdAlg.GetString());

        Assert.IsFalse(payload.TryGetProperty(SdConstants.SdClaimName, out _), "Root must not have _sd when no root claims are disclosable.");

        Assert.IsTrue(payload.TryGetProperty("credentialSubject", out JsonElement credSubject), "Payload must contain credentialSubject.");
        Assert.IsTrue(credSubject.TryGetProperty(SdConstants.SdClaimName, out JsonElement sdArray), "CredentialSubject must contain _sd digest array.");
        Assert.HasCount(2, sdArray.EnumerateArray().ToList());
    }


    [TestMethod]
    public async Task SignSdJwtMandatoryClaimsRemainInPayload()
    {
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        SdToken<string> token = await SignCredentialAsync(privateKey).ConfigureAwait(false);

        JsonElement payload = ParsePayload(token);

        Assert.IsTrue(payload.TryGetProperty("@context", out _), "Context must remain in mandatory payload.");
        Assert.IsTrue(payload.TryGetProperty("type", out _), "Type must remain in mandatory payload.");
        Assert.IsTrue(payload.TryGetProperty("issuer", out _), "Issuer must remain in mandatory payload.");
        Assert.IsTrue(payload.TryGetProperty("validFrom", out _), "ValidFrom must remain in mandatory payload.");
    }


    /// <summary>
    /// Serializes a VC to JSON, encodes into a <see cref="SensitiveMemoryPool{T}"/> rental,
    /// and issues via <see cref="SdJwtIssuance.IssueAsync"/> with <c>vc+sd-jwt</c> media type.
    /// </summary>
    private async ValueTask<SdToken<string>> SignCredentialAsync(PrivateKeyMemory privateKey)
    {
        VerifiableCredential credential = JsonSerializer.Deserialize<VerifiableCredential>(
            CredentialSecuringMaterial.UnsignedCredentialJson,
            CredentialSecuringMaterial.JsonOptions)!;

        string json = JsonSerializer.Serialize(credential, CredentialSecuringMaterial.JsonOptions);
        int byteCount = Encoding.UTF8.GetByteCount(json);
        using IMemoryOwner<byte> rental = Pool.Rent(byteCount);
        int written = Encoding.UTF8.GetBytes(json, rental.Memory.Span);

        SdTokenResult result = await SdJwtIssuance.IssueAsync(
            rental.Memory[..written], DisclosablePaths,
            SaltGenerator.Create,
            privateKey, CredentialSecuringMaterial.VerificationMethodId,
            Pool,
            mediaType: WellKnownMediaTypes.Jwt.VcSdJwt,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        return new SdToken<string>(compactJws, result.Disclosures.ToList());
    }


    /// <summary>
    /// Decodes the JWT payload from the issuer-signed compact serialization for assertion purposes.
    /// </summary>
    private static JsonElement ParsePayload(SdToken<string> token)
    {
        string[] jwtParts = token.IssuerSigned.Split('.');
        using IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(jwtParts[1], Pool);
        using JsonDocument doc = JsonDocument.Parse(payloadBytes.Memory);

        return doc.RootElement.Clone();
    }
}