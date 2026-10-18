using System.Runtime.InteropServices;
using System.Text.Json;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Dpop;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Shared System.Text.Json-backed serializer/parser bundles for the DPoP
/// primitive tests. Mirrors the
/// <c>JoseTests.EncodeJwtPart</c> / <c>DecodeJwtPart</c> pattern from the
/// JOSE test surface.
/// </summary>
internal static class DpopTestSupport
{
    public static DpopJwsPartSerializer Serializer { get; } = DpopJwsPartSerializerJson.Default;


    /// <summary>
    /// The ES256 verification over P-256 keys the DPoP and resource-server tests verify proofs and access tokens under, the
    /// function bound to the one algorithm it performs.
    /// </summary>
    public static JwsAlgorithmVerification Es256Verification { get; } =
        new(WellKnownJwaValues.Es256, MicrosoftCryptographicFunctionsAdapter.VerifyP256Async);


    public static DpopJwsPartParser Parser { get; } = new()
    {
        ParseHeader = ParseHeaderJson,
        ParseClaims = ParseClaimsJson
    };


    public static DpopProofHeader ParseHeaderJson(ReadOnlyMemory<byte> bytes)
    {
        using JsonDocument doc = JsonDocument.Parse(bytes);
        JsonElement root = doc.RootElement;

        string alg = root.GetProperty(WellKnownJwkMemberNames.Alg).GetString()
            ?? throw new FormatException("DPoP header is missing 'alg'.");
        string typ = root.TryGetProperty(WellKnownJoseHeaderNames.Typ, out JsonElement typElement)
            ? typElement.GetString() ?? string.Empty
            : string.Empty;

        if(!root.TryGetProperty(WellKnownJoseHeaderNames.Jwk, out JsonElement jwkElement))
        {
            throw new FormatException("DPoP header is missing 'jwk'.");
        }

        Dictionary<string, string> jwk = new(StringComparer.Ordinal);
        foreach(JsonProperty prop in jwkElement.EnumerateObject())
        {
            string? value = prop.Value.GetString();
            if(value is not null)
            {
                jwk[prop.Name] = value;
            }
        }

        return new DpopProofHeader { Alg = alg, Typ = typ, Jwk = jwk };
    }


    public static DpopProofClaims ParseClaimsJson(ReadOnlyMemory<byte> bytes)
    {
        using JsonDocument doc = JsonDocument.Parse(bytes);
        JsonElement root = doc.RootElement;

        string htm = root.GetProperty(WellKnownJwtClaimNames.Htm).GetString()
            ?? throw new FormatException("DPoP claims are missing 'htm'.");
        string htu = root.GetProperty(WellKnownJwtClaimNames.Htu).GetString()
            ?? throw new FormatException("DPoP claims are missing 'htu'.");
        var issuedAtElement = root.GetProperty(WellKnownJwtClaimNames.Iat);
        var issuedAt = (issuedAtElement.ValueKind == JsonValueKind.Number ? NumericDate.FromJsonNumber(JsonMarshal.GetRawUtf8Value(issuedAtElement)) : null)
            ?? throw new FormatException("DPoP claims carry no NumericDate 'iat'.");
        string jti = root.GetProperty(WellKnownJwtClaimNames.Jti).GetString()
            ?? throw new FormatException("DPoP claims are missing 'jti'.");

        string? nonce = root.TryGetProperty(WellKnownJwtClaimNames.Nonce, out JsonElement nonceElement)
            ? nonceElement.GetString()
            : null;
        string? ath = root.TryGetProperty(WellKnownJwtClaimNames.Ath, out JsonElement athElement)
            ? athElement.GetString()
            : null;

        return new DpopProofClaims
        {
            Htm = htm,
            Htu = htu,
            Iat = issuedAt,
            Jti = jti,
            Nonce = nonce,
            Ath = ath
        };
    }
}
