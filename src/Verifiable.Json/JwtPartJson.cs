using System.Text.Json;
using Verifiable.JCose;

namespace Verifiable.Json;

/// <summary>
/// The library's general-purpose <see cref="JwtPartDecoder"/> default — decodes a JWT header or
/// payload's UTF-8 JSON bytes (per
/// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-3">RFC 7515 §3</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-3">RFC 7519 §3</see>) into its claim
/// dictionary for <see cref="Jws.VerifyAndDecodeAsync(string, DecodeDelegate, JwtPartDecoder, System.Buffers.MemoryPool{byte}, Cryptography.PublicKeyMemory, System.Threading.CancellationToken)"/>
/// and its sibling overloads.
/// </summary>
/// <remarks>
/// <para>
/// Reuses <see cref="JwtClaimsJson.Options"/> — the same source-generated resolver plus
/// <see cref="Converters.DictionaryStringObjectJsonConverter"/> the <c>from_prior</c> rotation JWT
/// decoder already applies — and the same <see cref="JsonException"/> → <see cref="FormatException"/>
/// firewall, generalized to any JWT part rather than one named segment. This is the concrete binding
/// <c>Verifiable.JCose</c> declares the <see cref="JwtPartDecoder"/> seam for but does not implement
/// itself, keeping that package serialization-agnostic; <c>Verifiable.Json</c> is where JSON binding
/// for JOSE/JWT types lives.
/// </para>
/// </remarks>
public static class JwtPartJson
{
    /// <summary>
    /// The default <see cref="JwtPartDecoder"/>: parses a JWT part's UTF-8 JSON bytes as a
    /// <see cref="Dictionary{TKey, TValue}"/> of <see cref="string"/> to <see cref="object"/>.
    /// </summary>
    public static JwtPartDecoder Default { get; } = Decode;


    //Deserializes a JWT part's UTF-8 JSON bytes, translating System.Text.Json's JsonException (and a
    //JSON-null result) into FormatException so no System.Text.Json type escapes this leaf into the
    //serialization-agnostic Verifiable.JCose verify path — the same firewall JwtClaimsJson.
    //DeserializeObject applies for the from_prior JWT, generalized to any JWT part.
    private static IReadOnlyDictionary<string, object> Decode(ReadOnlySpan<byte> partBytes)
    {
        Dictionary<string, object>? value;
        try
        {
            value = JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(partBytes, JwtClaimsJson.Options);
        }
        catch(JsonException exception)
        {
            throw new FormatException("The JWT part is not valid JSON.", exception);
        }

        return value ?? throw new FormatException("A JWT part MUST NOT be JSON null.");
    }
}
