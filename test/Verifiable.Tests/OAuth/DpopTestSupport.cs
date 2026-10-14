using System.Text.Json;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Dpop;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Shared System.Text.Json-backed serializer/parser bundles for the DPoP
/// primitive tests. Mirrors the
/// <c>JoseTests.EncodeJwtPart</c> / <c>DecodeJwtPart</c> pattern from the
/// JOSE test surface.
/// </summary>
internal static class DpopTestSupport
{
    /// <summary>
    /// The library's <see cref="DpopJwsPartSerializerJson.Default"/>, the serializer every proof the tests build is
    /// written with.
    /// </summary>
    public static DpopJwsPartSerializer Serializer { get; } = DpopJwsPartSerializerJson.Default;


    /// <summary>
    /// The library's <see cref="DpopJwsPartParserJson.Default"/>, the parser the test hosts pass to
    /// <see cref="DpopProofValidator"/>'s <c>ValidateAsync</c> where they wire their DPoP proof validation and the parser
    /// their codecs carry for the library default, so every proof a host receives is read as the library reads it.
    /// </summary>
    public static DpopJwsPartParser Parser { get; } = DpopJwsPartParserJson.Default;


    /// <summary>
    /// Reads a decoded DPoP proof header the way a test inspects what a proof builder wrote: <c>alg</c>, <c>typ</c>
    /// (the empty string when absent) and the string members of <c>jwk</c>.
    /// </summary>
    /// <param name="bytes">The UTF-8 JSON of the decoded header segment.</param>
    /// <returns>The header.</returns>
    public static DpopProofHeader ParseHeaderJson(ReadOnlyMemory<byte> bytes)
    {
        using JsonDocument doc = JsonDocument.Parse(bytes);
        JsonElement root = doc.RootElement;

        string alg = root.GetProperty(WellKnownJoseHeaderNames.Alg).GetString()
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


    /// <summary>
    /// Reads a decoded DPoP proof payload the way a test inspects what a proof builder wrote: <c>htm</c>, <c>htu</c>,
    /// <c>iat</c> as whole seconds, <c>jti</c>, and <c>nonce</c> and <c>ath</c> when present.
    /// </summary>
    /// <param name="bytes">The UTF-8 JSON of the decoded payload segment.</param>
    /// <returns>The claims.</returns>
    public static DpopProofClaims ParseClaimsJson(ReadOnlyMemory<byte> bytes)
    {
        using JsonDocument doc = JsonDocument.Parse(bytes);
        JsonElement root = doc.RootElement;

        string htm = root.GetProperty(WellKnownJwtClaimNames.Htm).GetString()
            ?? throw new FormatException("DPoP claims are missing 'htm'.");
        string htu = root.GetProperty(WellKnownJwtClaimNames.Htu).GetString()
            ?? throw new FormatException("DPoP claims are missing 'htu'.");
        long iatSeconds = root.GetProperty(WellKnownJwtClaimNames.Iat).GetInt64();
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
            Iat = DateTimeOffset.FromUnixTimeSeconds(iatSeconds),
            Jti = jti,
            Nonce = nonce,
            Ath = ath
        };
    }
}
