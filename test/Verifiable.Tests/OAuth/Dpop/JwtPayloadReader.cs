using System.Buffers;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth.Dpop;

/// <summary>
/// Wire-level JWT payload inspection for tests. Splits a compact JWS by
/// <c>.</c>, base64url-decodes the middle segment, parses the result as
/// JSON, and returns claim values. Used by phase 8's wire-level tests to
/// assert what the AS actually emitted on the wire rather than trusting a
/// host-side accessor.
/// </summary>
/// <remarks>
/// The helper is intentionally test-side only. Production validation of
/// access tokens goes through <see cref="DpopProofValidation"/> or the
/// application's JOSE layer — both of which verify the signature first.
/// This helper does not verify the signature; it only reads what the AS
/// emitted. Use it to assert <strong>presence and value</strong> of
/// claims the AS is contractually obliged to emit.
/// </remarks>
internal static class JwtPayloadReader
{
    /// <summary>
    /// Parses the JWT payload (middle segment) as a <see cref="JsonDocument"/>.
    /// Caller owns the returned <see cref="JsonDocument"/> and must dispose it.
    /// </summary>
    /// <remarks>
    /// Copies the decoded bytes into a fresh <c>byte[]</c> before parsing —
    /// <see cref="JsonDocument.Parse(ReadOnlyMemory{byte}, JsonDocumentOptions)"/>
    /// holds a reference to the supplied memory and the pooled
    /// <see cref="IMemoryOwner{T}"/> is disposed before this method returns.
    /// </remarks>
    public static JsonDocument ParsePayloadJson(string compactJws)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(compactJws);

        string[] parts = compactJws.Split('.');
        if(parts.Length != 3)
        {
            throw new FormatException(
                $"Expected a 3-part compact JWS, got {parts.Length} parts.");
        }

        byte[] payloadBytes;
        using(IMemoryOwner<byte> decoded = TestSetup.Base64UrlDecoder(
            parts[1], SensitiveMemoryPool<byte>.Shared))
        {
            //Find the actual decoded length — the decoder may have rented a
            //larger buffer than the base64url-decoded payload occupies.
            int decodedLength = ComputeBase64UrlDecodedLength(parts[1]);
            payloadBytes = decoded.Memory.Span[..decodedLength].ToArray();
        }
        return JsonDocument.Parse(payloadBytes);
    }


    private static int ComputeBase64UrlDecodedLength(string base64Url)
    {
        //Standard base64url length: each 4 chars = 3 bytes, with the trailing
        //group truncated by 1 (3 chars → 2 bytes) or 2 (2 chars → 1 byte).
        int n = base64Url.Length;
        int fullGroups = n / 4;
        int rem = n % 4;
        int extra = rem switch
        {
            0 => 0,
            2 => 1,
            3 => 2,
            _ => throw new FormatException($"Invalid base64url length: {n}.")
        };
        return fullGroups * 3 + extra;
    }


    /// <summary>
    /// Reads the <c>cnf.jkt</c> value from an access-token JWT, or
    /// <see langword="null"/> when the <c>cnf</c> claim is absent or has no
    /// <c>jkt</c> member.
    /// </summary>
    public static string? ReadCnfJkt(string accessTokenJwt)
    {
        using JsonDocument doc = ParsePayloadJson(accessTokenJwt);
        if(!doc.RootElement.TryGetProperty(WellKnownJwtClaimNames.Cnf, out JsonElement cnf))
        {
            return null;
        }
        if(!cnf.TryGetProperty(WellKnownJwtClaimNames.JwkThumbprint, out JsonElement jkt))
        {
            return null;
        }
        return jkt.GetString();
    }


    /// <summary>
    /// Reads the <c>iss</c> claim value from a JWT.
    /// </summary>
    public static string? ReadIssuer(string compactJws)
    {
        using JsonDocument doc = ParsePayloadJson(compactJws);
        return doc.RootElement.TryGetProperty(WellKnownJwtClaimNames.Iss, out JsonElement iss)
            ? iss.GetString() : null;
    }


    /// <summary>
    /// Returns whether the JWT carries any <c>cnf</c> claim at all.
    /// </summary>
    public static bool HasCnfClaim(string compactJws)
    {
        using JsonDocument doc = ParsePayloadJson(compactJws);
        return doc.RootElement.TryGetProperty(WellKnownJwtClaimNames.Cnf, out _);
    }
}
