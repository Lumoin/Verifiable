using System.Text;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;

namespace Verifiable.Tests.OAuth.Dpop;

/// <summary>
/// Shared System.Text.Json-backed serializer/parser bundles for the DPoP
/// primitive tests. Mirrors the
/// <c>JoseTests.EncodeJwtPart</c> / <c>DecodeJwtPart</c> pattern from the
/// JOSE test surface.
/// </summary>
internal static class DpopTestSupport
{
    public static DpopJwsPartSerializer Serializer { get; } = new()
    {
        SerializeHeader = SerializeHeader,
        SerializePayload = SerializePayload,
        EncodePart = EncodeDictionaryPart
    };


    public static DpopJwsPartParser Parser { get; } = new()
    {
        ParseHeader = ParseHeaderJson,
        ParseClaims = ParseClaimsJson
    };


    public static IReadOnlyDictionary<string, object> SerializeHeader(DpopProofHeader header)
    {
        Dictionary<string, object> dict = new(StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Alg] = header.Alg,
            [WellKnownJoseHeaderNames.Typ] = header.Typ,
            [WellKnownJoseHeaderNames.Jwk] = ToObjectDictionary(header.Jwk)
        };
        return dict;
    }


    public static IReadOnlyDictionary<string, object> SerializePayload(DpopProofClaims claims)
    {
        Dictionary<string, object> dict = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Htm] = claims.Htm,
            [WellKnownJwtClaimNames.Htu] = claims.Htu,
            [WellKnownJwtClaimNames.Iat] = claims.Iat.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Jti] = claims.Jti
        };
        if(claims.Nonce is not null)
        {
            dict[WellKnownJwtClaimNames.Nonce] = claims.Nonce;
        }
        if(claims.Ath is not null)
        {
            dict[WellKnownJwtClaimNames.Ath] = claims.Ath;
        }
        return dict;
    }


    public static TaggedMemory<byte> EncodeDictionaryPart(IReadOnlyDictionary<string, object> part)
    {
        Dictionary<string, object> dict = part is Dictionary<string, object> d
            ? d
            : new Dictionary<string, object>(part);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(dict);
        return new TaggedMemory<byte>(bytes, BufferTags.Json);
    }


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


    private static Dictionary<string, object> ToObjectDictionary(IReadOnlyDictionary<string, string> source)
    {
        Dictionary<string, object> dict = new(source.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, string> entry in source)
        {
            dict[entry.Key] = entry.Value;
        }
        return dict;
    }
}
