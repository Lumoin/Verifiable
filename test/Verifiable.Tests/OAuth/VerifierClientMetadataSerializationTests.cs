using System.Text.Json;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Reproduces and then guards the OID4VP 1.0 §11 <c>client_metadata</c> wire shape.
/// The Verifier serializes this object onto the JAR; a conformant peer (e.g. the
/// French iDAKTO sandbox) expects snake_case members per §11.1 — not the camelCase
/// the default naming policy would otherwise produce — and expects
/// <c>vp_formats_supported</c> to be a bare format map and <c>jwks</c> to be a JSON
/// object, not a quoted string.
/// </summary>
/// <remarks>
/// These exercise the SAME options instance the production verifier/wallet wire onto
/// the JAR (<see cref="TestSetup.DefaultSerializationOptions"/>); the closed-world
/// camelCase round-trip previously hid the defect because both our sides agreed.
/// </remarks>
[TestClass]
internal sealed class VerifierClientMetadataSerializationTests
{
    private static JsonSerializerOptions Options => TestSetup.DefaultSerializationOptions;

    //A compact JWKS (no insignificant whitespace) so the raw round-trip is byte-stable.
    private const string JwksJson = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"a\",\"y\":\"b\"}]}";

    private static VerifierClientMetadata Sample() =>
        HaipProfile.CreateVerifierClientMetadata("x509_hash:abc123", JwksJson);


    [TestMethod]
    public void MembersSerializeAsSnakeCase()
    {
        string json = JsonSerializerExtensions.Serialize(Sample(), Options);

        //vp_formats_supported MUST be snake_case per OID4VP 1.0 §11.1.
        Assert.Contains("\"vp_formats_supported\"", json, StringComparison.Ordinal);
        Assert.Contains("\"encrypted_response_enc_values_supported\"", json, StringComparison.Ordinal);
        Assert.Contains("\"encrypted_response_alg_values_supported\"", json, StringComparison.Ordinal);

        Assert.IsFalse(json.Contains("vpFormatsSupported", StringComparison.Ordinal),
            "Must not emit camelCase member names; a conformant peer reads snake_case.");
        Assert.IsFalse(json.Contains("encryptedResponseEncValuesSupported", StringComparison.Ordinal));
    }


    [TestMethod]
    public void VpFormatsSerializeAsBareMapNotFormatsWrapper()
    {
        string json = JsonSerializerExtensions.Serialize(Sample(), Options);

        //Verify the SHAPE structurally (robust to JSON string escaping of '+' in the
        //format id): the vp_formats_supported value is a bare object whose keys ARE the
        //format identifiers — not the C# 'Formats' wrapper property.
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement vpFormats = document.RootElement.GetProperty(
            Oid4VpClientMetadataParameterNames.VpFormatsSupported);

        Assert.AreEqual(JsonValueKind.Object, vpFormats.ValueKind,
            "vp_formats_supported must be a bare object map.");
        Assert.IsTrue(vpFormats.TryGetProperty(WellKnownMediaTypes.Jwt.DcSdJwt, out _),
            "The format identifier must be a direct key of vp_formats_supported.");
        Assert.IsFalse(vpFormats.TryGetProperty("formats", out _),
            "vp_formats_supported must not be nested under a 'formats' wrapper.");
    }


    [TestMethod]
    public void JwksSerializesAsJsonObjectNotString()
    {
        string json = JsonSerializerExtensions.Serialize(Sample(), Options);

        //jwks must be emitted as a JSON object, not a quoted string.
        Assert.Contains("\"jwks\":{", json, StringComparison.Ordinal);
        Assert.IsFalse(json.Contains("\"jwks\":\"", StringComparison.Ordinal),
            "jwks must NOT be a quoted JSON string.");
    }


    [TestMethod]
    public void RoundTripsThroughTheSnakeWire()
    {
        VerifierClientMetadata original = Sample();

        string json = JsonSerializerExtensions.Serialize(original, Options);
        VerifierClientMetadata? back =
            JsonSerializerExtensions.Deserialize<VerifierClientMetadata>(json, Options);

        Assert.IsNotNull(back);
        Assert.AreEqual(original, back,
            "client_id, jwks, and the encrypted_response_* arrays must survive the snake wire round-trip.");
        Assert.IsNotNull(back!.VpFormatsSupported);
        Assert.IsTrue(back.VpFormatsSupported!.Formats.ContainsKey(WellKnownMediaTypes.Jwt.DcSdJwt),
            "vp_formats_supported must round-trip the format map.");
    }
}
