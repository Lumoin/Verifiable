using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;
using Verifiable.Jose;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Tests for SD-JWT credential envelope securing per
/// <see href="https://www.w3.org/TR/vc-jose-cose/#with-sd-jwt">W3C VC-JOSE-COSE Section 3.2</see>.
/// </summary>
/// <remarks>
/// <para>
/// These tests exercise the VC-specific SD-JWT path using the university credential from
/// <see href="https://www.w3.org/TR/vc-data-model-2.0/#example-usage-of-the-credentialsubject-property">
/// VC Data Model 2.0</see>. Unlike <see cref="SdJwtClaimRedactionTests"/> which operates
/// at the <see href="https://datatracker.ietf.org/doc/rfc9901/">RFC 9901</see> level with
/// any JSON payload, these tests exercise the full VC pipeline via
/// <see cref="CredentialSdJwtExtensions.SignSdJwtAsync"/>:
/// </para>
/// <list type="bullet">
/// <item><description>Credential serialization.</description></item>
/// <item><description>Redaction with nested <c>_sd</c> placement inside <c>credentialSubject</c>.</description></item>
/// <item><description>Signing with <c>vc+sd-jwt</c> media type.</description></item>
/// <item><description>Round-trip extraction back to <see cref="CredentialPath"/> values.</description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class SdJwtCredentialSecuringTests
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

        SdJwtToken token = await SignCredentialAsync(privateKey).ConfigureAwait(false);

        Assert.IsNotNull(token);
        Assert.IsNotNull(token.IssuerSigned);
        Assert.HasCount(2, token.Disclosures);
    }


    [TestMethod]
    public async Task SignSdJwtIssuerSignatureVerifies()
    {
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        using var publicKey = CredentialSecuringMaterial.DecodeEd25519PublicKey();

        SdJwtToken token = await SignCredentialAsync(privateKey).ConfigureAwait(false);

        string[] jwtParts = token.IssuerSigned.Split('.');
        byte[] verificationInput = Encoding.ASCII.GetBytes($"{jwtParts[0]}.{jwtParts[1]}");
        using IMemoryOwner<byte> signatureBytes = TestSetup.Base64UrlDecoder(jwtParts[2], Pool);
        using var signature = new Signature(signatureBytes, CryptoTags.Ed25519Signature);

        bool isValid = await publicKey.VerifyAsync(
            verificationInput, signature,
            BouncyCastleCryptographicFunctions.VerifyEd25519Async).ConfigureAwait(false);

        Assert.IsTrue(isValid, "Issuer JWT signature must verify.");
    }


    [TestMethod]
    public async Task SignSdJwtHeaderContainsCorrectMetadata()
    {
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        SdJwtToken token = await SignCredentialAsync(privateKey).ConfigureAwait(false);

        string[] jwtParts = token.IssuerSigned.Split('.');
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(jwtParts[0], Pool);
        Dictionary<string, object>? header = JsonSerializer.Deserialize<Dictionary<string, object>>(headerBytes.Memory.Span);

        Assert.IsNotNull(header);
        Assert.AreEqual("EdDSA", header[JwkProperties.Alg].ToString());
        Assert.AreEqual(WellKnownMediaTypes.Jwt.VcSdJwt, header[JwkProperties.Typ].ToString());
        Assert.AreEqual(CredentialSecuringMaterial.VerificationMethodId, header[JwkProperties.Kid].ToString());
    }


    [TestMethod]
    public async Task SignSdJwtEmbedsSdArrayInsideCredentialSubject()
    {
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        SdJwtToken token = await SignCredentialAsync(privateKey).ConfigureAwait(false);

        JsonElement payload = ParsePayload(token);

        Assert.IsTrue(payload.TryGetProperty(SdConstants.SdAlgorithmClaimName, out JsonElement sdAlg), "Payload must contain _sd_alg at root.");
        Assert.AreEqual(WellKnownHashAlgorithms.Sha256Iana, sdAlg.GetString());

        //Root must NOT have _sd because no root-level claims are disclosable.
        Assert.IsFalse(payload.TryGetProperty(SdConstants.SdClaimName, out _), "Root must not have _sd when no root claims are disclosable.");

        //The _sd array must be inside credentialSubject.
        Assert.IsTrue(payload.TryGetProperty("credentialSubject", out JsonElement credSubject), "Payload must contain credentialSubject.");
        Assert.IsTrue(credSubject.TryGetProperty(SdConstants.SdClaimName, out JsonElement sdArray), "CredentialSubject must contain _sd digest array.");
        Assert.HasCount(2, sdArray.EnumerateArray().ToList());

        Assert.IsFalse(credSubject.TryGetProperty("degree", out _), "Disclosable claim degree must not appear in credentialSubject.");
        Assert.IsFalse(credSubject.TryGetProperty("id", out _), "Disclosable claim id must not appear in credentialSubject.");
    }


    [TestMethod]
    public async Task SignSdJwtMandatoryClaimsRemainInPayload()
    {
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        SdJwtToken token = await SignCredentialAsync(privateKey).ConfigureAwait(false);

        JsonElement payload = ParsePayload(token);

        Assert.IsTrue(payload.TryGetProperty("@context", out _), "Context must remain in mandatory payload.");
        Assert.IsTrue(payload.TryGetProperty("type", out _), "Type must remain in mandatory payload.");
        Assert.IsTrue(payload.TryGetProperty("issuer", out JsonElement issuerElement), "Issuer must remain in mandatory payload.");
        Assert.IsTrue(payload.TryGetProperty("validFrom", out _), "ValidFrom must remain in mandatory payload.");

        Assert.AreEqual("did:example:76e12ec712ebc6f1c221ebfeb1f", issuerElement.GetProperty("id").GetString());
    }


    [TestMethod]
    public async Task SignSdJwtDisclosurePathsRoundTrip()
    {
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        SdJwtToken token = await SignCredentialAsync(privateKey).ConfigureAwait(false);

        IReadOnlyDictionary<SdDisclosure, CredentialPath> extractedPaths = SdJwtPathExtraction.ExtractPaths(
            token, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool);

        Assert.HasCount(2, extractedPaths);

        var pathValues = new HashSet<CredentialPath>(extractedPaths.Values);
        Assert.Contains(CredentialPath.FromJsonPointer("/credentialSubject/degree"), pathValues);
        Assert.Contains(CredentialPath.FromJsonPointer("/credentialSubject/id"), pathValues);
    }


    [TestMethod]
    public async Task SignSdJwtWireFormatSerializesCorrectly()
    {
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        SdJwtToken token = await SignCredentialAsync(privateKey).ConfigureAwait(false);

        string wireFormat = SdJwtSerializer.SerializeToken(token, TestSetup.Base64UrlEncoder);

        Assert.IsNotNull(wireFormat);
        Assert.Contains("~", wireFormat);
        Assert.EndsWith("~", wireFormat, "SD-JWT without key binding must end with tilde separator.");

        SdJwtToken parsed = SdJwtSerializer.ParseToken(wireFormat, TestSetup.Base64UrlDecoder, Pool);
        Assert.AreEqual(token.IssuerSigned, parsed.IssuerSigned);
        Assert.HasCount(2, parsed.Disclosures);
    }


    //Delegate wiring — same pattern used by DcqlPresentationFlowTests.

    private static string SerializeDisclosure(SdDisclosure disclosure, EncodeDelegate encoder)
    {
        return SdJwtSerializer.SerializeDisclosure(disclosure, encoder);
    }

    private static string ComputeDigest(string encodedDisclosure, EncodeDelegate encoder)
    {
        return SdJwtPathExtraction.ComputeDisclosureDigest(
            encodedDisclosure, WellKnownHashAlgorithms.Sha256Iana, encoder);
    }

    private static JsonElement ParsePayload(SdJwtToken token)
    {
        string[] jwtParts = token.IssuerSigned.Split('.');
        using IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(jwtParts[1], Pool);
        using JsonDocument doc = JsonDocument.Parse(payloadBytes.Memory);

        return doc.RootElement.Clone();
    }

    private async ValueTask<SdJwtToken> SignCredentialAsync(PrivateKeyMemory privateKey)
    {
        VerifiableCredential credential = JsonSerializer.Deserialize<VerifiableCredential>(
            CredentialSecuringMaterial.UnsignedCredentialJson,
            CredentialSecuringMaterial.JsonOptions)!;

        return await credential.SignSdJwtAsync(
            DisclosablePaths,
            cred => JsonSerializer.Serialize(cred, CredentialSecuringMaterial.JsonOptions),
            SdJwtClaimRedaction.Redact,
            () => SaltGenerator.Create(SdConstants.DefaultSaltLengthBytes),
            SerializeDisclosure, ComputeDigest,
            privateKey, CredentialSecuringMaterial.VerificationMethodId,
            WellKnownHashAlgorithms.Sha256Iana,
            header => JsonSerializer.SerializeToUtf8Bytes(header),
            payload => JsonSerializer.SerializeToUtf8Bytes(payload),
            TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }
}