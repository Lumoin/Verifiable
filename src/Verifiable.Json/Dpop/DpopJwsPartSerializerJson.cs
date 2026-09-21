using System.Text.Json;
using Verifiable.JCose;
using Verifiable.Json.Converters;
using Verifiable.OAuth.Dpop;

namespace Verifiable.Json;

/// <summary>
/// The concrete <c>System.Text.Json</c> implementation of <see cref="DpopJwsPartSerializer"/> — the
/// JSON-side binding for the
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see> DPoP proof
/// header and claim set, plugging the serialization-agnostic <see cref="DpopProofConstruction"/> and
/// <see cref="DpopProofValidator"/> into this leaf's JSON edge exactly as
/// <see cref="JwtClaimsJson"/> plugs the DID-rotation <c>from_prior</c> JWT and
/// <see cref="DidCommSignedMessageJson.ProtectedHeaderEncoder"/> plugs the DIDComm signed envelope.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="DpopProofHeader.Jwk"/> arrives already Base64Url-encoded — <see cref="Default"/>'s
/// header/payload projection needs no encoder of its own — and <see cref="JwtPartEncoder{TJwtPart}"/>'s
/// <see cref="TaggedMemory{T}"/> return shape is a GC-backed wrapper by design (see its own remarks:
/// short-lived JWS signing buffers are cheaper wrapped than copied into pooled memory), so
/// <see cref="Default"/> takes no pool either; both are the SAME reasons <see cref="JwtClaimsJson"/>'s
/// and <see cref="DidCommSignedMessageJson"/>'s equivalent members take neither.
/// </para>
/// </remarks>
public static class DpopJwsPartSerializerJson
{
    /// <summary>
    /// The serialization options <see cref="Default"/> uses: the source-generated
    /// <see cref="VerifiableJsonContext"/> resolver plus the
    /// <see cref="DictionaryStringObjectJsonConverter"/> for the header/claims object graph. Kept
    /// private — <see cref="Default"/> is this class's one public surface.
    /// </summary>
    private static JsonSerializerOptions Options { get; } = CreateOptions();


    /// <summary>
    /// The default <see cref="DpopJwsPartSerializer"/>: projects a <see cref="DpopProofHeader"/> and
    /// <see cref="DpopProofClaims"/> to their RFC 9449 §4.2 property-dictionary shape and encodes each
    /// to UTF-8 JSON bytes, so an application wires this instead of hand-writing the same dictionaries
    /// <see cref="DpopProofConstruction.BuildAsync"/> and <see cref="DpopProofValidator"/> otherwise
    /// require by hand.
    /// </summary>
    public static DpopJwsPartSerializer Default { get; } = new()
    {
        SerializeHeader = SerializeHeader,
        SerializePayload = SerializePayload,
        EncodePart = EncodePart
    };


    /// <summary>
    /// Projects the RFC 9449 §4.2 JOSE header members (<c>typ</c>, <c>alg</c>, <c>jwk</c>) to the
    /// property-dictionary shape the signing call's generic part parameter consumes.
    /// </summary>
    /// <param name="header">The proof header to project.</param>
    /// <returns>The header as an ordinal property dictionary.</returns>
    private static Dictionary<string, object> SerializeHeader(DpopProofHeader header)
    {
        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Alg] = header.Alg,
            [WellKnownJoseHeaderNames.Typ] = header.Typ,
            [WellKnownJoseHeaderNames.Jwk] = ToObjectDictionary(header.Jwk)
        };
    }


    /// <summary>
    /// Projects the RFC 9449 §4.2 payload claims (<c>jti</c>, <c>htm</c>, <c>htu</c>, <c>iat</c>) plus
    /// the conditional <c>nonce</c> and <c>ath</c> claims to the property-dictionary shape the signing
    /// call's generic part parameter consumes.
    /// </summary>
    /// <param name="claims">The proof claims to project.</param>
    /// <returns>The claims as an ordinal property dictionary; an absent conditional claim is omitted.</returns>
    private static Dictionary<string, object> SerializePayload(DpopProofClaims claims)
    {
        Dictionary<string, object> dictionary = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Htm] = claims.Htm,
            [WellKnownJwtClaimNames.Htu] = claims.Htu,
            [WellKnownJwtClaimNames.Iat] = claims.Iat.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Jti] = claims.Jti
        };

        if(claims.Nonce is not null)
        {
            dictionary[WellKnownJwtClaimNames.Nonce] = claims.Nonce;
        }

        if(claims.Ath is not null)
        {
            dictionary[WellKnownJwtClaimNames.Ath] = claims.Ath;
        }

        return dictionary;
    }


    /// <summary>
    /// Encodes a serialized header or payload dictionary to its UTF-8 JSON bytes, tagged
    /// <see cref="BufferTags.Json"/> — the <see cref="JwtPartEncoder{TJwtPart}"/> shape the signing
    /// call consumes immediately and never disposes, matching <see cref="TaggedMemory{T}"/>'s own
    /// documented non-pooled contract.
    /// </summary>
    /// <param name="part">The header or payload dictionary to encode.</param>
    /// <returns>The UTF-8 JSON bytes of <paramref name="part"/>.</returns>
    private static TaggedMemory<byte> EncodePart(IReadOnlyDictionary<string, object> part)
    {
        Dictionary<string, object> dictionary = part is Dictionary<string, object> existing
            ? existing
            : new Dictionary<string, object>(part, StringComparer.Ordinal);

        byte[] bytes = JsonSerializerExtensions.SerializeToUtf8Bytes(dictionary, Options);

        return new TaggedMemory<byte>(bytes, BufferTags.Json);
    }


    /// <summary>
    /// Copies a JWK's string members into an object-valued dictionary, the shape the shared
    /// <see cref="DictionaryStringObjectJsonConverter"/> writes as a nested JSON object.
    /// </summary>
    /// <param name="jwk">The JWK's members.</param>
    /// <returns>The members as an ordinal object-valued dictionary.</returns>
    private static Dictionary<string, object> ToObjectDictionary(IReadOnlyDictionary<string, string> jwk)
    {
        Dictionary<string, object> dictionary = new(jwk.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, string> member in jwk)
        {
            dictionary[member.Key] = member.Value;
        }

        return dictionary;
    }


    /// <summary>
    /// Builds the serializer options <see cref="Options"/> holds: the source-generated resolver and
    /// the dictionary converter the header and claims graphs need.
    /// </summary>
    /// <returns>The configured options.</returns>
    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            TypeInfoResolver = VerifiableJsonContext.Default
        };

        options.Converters.Add(new DictionaryStringObjectJsonConverter(VerifiableJsonContext.Default));

        return options;
    }
}
