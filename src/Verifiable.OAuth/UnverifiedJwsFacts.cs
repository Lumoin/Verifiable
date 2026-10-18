using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth;

/// <summary>
/// The identifiers a compact JWS (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-7.1">RFC 7515 §7.1</see>) carries,
/// read once from its protected header and its payload before its signature is verified: the header's <c>typ</c>,
/// <c>alg</c> and <c>kid</c> the verification is chosen by, and the claims a client names the token by - <c>iss</c>,
/// <c>aud</c>, <c>client_id</c> and <c>jti</c>. Nothing here is verified: a value is what the token's sender wrote, and a
/// reader that records one treats it as text its sender chose.
/// </summary>
/// <param name="Type">The header's <c>typ</c>, or <see langword="null"/> where absent or no string.</param>
/// <param name="Algorithm">The header's <c>alg</c>, or <see langword="null"/>.</param>
/// <param name="KeyId">The header's <c>kid</c>, or <see langword="null"/>.</param>
/// <param name="Issuer">The payload's <c>iss</c>, or <see langword="null"/>.</param>
/// <param name="Audience">The payload's <c>aud</c> where it is one string or an array of exactly one, or <see langword="null"/>.</param>
/// <param name="ClientId">The payload's <c>client_id</c>, or <see langword="null"/>.</param>
/// <param name="TokenId">The payload's <c>jti</c>, or <see langword="null"/>.</param>
[DebuggerDisplay("UnverifiedJwsFacts Type={Type} Algorithm={Algorithm} KeyId={KeyId}")]
public sealed record UnverifiedJwsFacts(
    string? Type, string? Algorithm, string? KeyId, string? Issuer, string? Audience, string? ClientId, string? TokenId)
{
    /// <summary>The separator between the parts of a compact serialization (RFC 7515 §7.1).</summary>
    private const char PartSeparator = '.';

    /// <summary>The parts a compact JWS has: the protected header, the payload and the signature.</summary>
    private const int CompactJwsPartCount = 3;


    /// <summary>The facts of a token no part of which could be read: every member <see langword="null"/>.</summary>
    public static UnverifiedJwsFacts None { get; } = new(
        Type: null, Algorithm: null, KeyId: null, Issuer: null, Audience: null, ClientId: null, TokenId: null);


    /// <summary>
    /// Reads a compact JWS's identifiers: its three parts, the header and the payload each base64url-decoded
    /// (RFC 7515 §7.2) and each a well-formed JSON document (<see cref="JwkJsonReader.IsWellFormedJsonDocument"/>), every
    /// member read by its name as a string.
    /// </summary>
    /// <param name="compact">The compact serialization.</param>
    /// <param name="base64UrlDecoder">The base64url decoder.</param>
    /// <param name="pool">The pool the decoded parts are rented from, released before this returns.</param>
    /// <returns>The facts, or <see langword="null"/> for a text that is no compact JWS whose header and payload are JSON.</returns>
    public static UnverifiedJwsFacts? Read(string compact, DecodeDelegate base64UrlDecoder, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(compact);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        var parts = compact.Split(PartSeparator);

        if(parts.Length != CompactJwsPartCount || parts[0].Length == 0 || parts[1].Length == 0)
        {
            return null;
        }

        try
        {
            using IMemoryOwner<byte> header = base64UrlDecoder(parts[0], pool);
            using IMemoryOwner<byte> payload = base64UrlDecoder(parts[1], pool);
            var headerJson = header.Memory.Span;
            var payloadJson = payload.Memory.Span;

            if(!JwkJsonReader.IsWellFormedJsonDocument(headerJson) || !JwkJsonReader.IsWellFormedJsonDocument(payloadJson))
            {
                return null;
            }

            return new UnverifiedJwsFacts(
                JwkJsonReader.ExtractStringValue(headerJson, WellKnownJoseHeaderNames.TypUtf8),
                JwkJsonReader.ExtractStringValue(headerJson, WellKnownJoseHeaderNames.AlgUtf8),
                JwkJsonReader.ExtractStringValue(headerJson, WellKnownJwkMemberNames.KidUtf8),
                JwkJsonReader.ExtractStringValue(payloadJson, WellKnownJwtClaimNames.IssUtf8),
                JwkJsonReader.ExtractStringValue(payloadJson, WellKnownJwtClaimNames.AudUtf8)
                    ?? (JwkJsonReader.ExtractStringArrayProperty(payloadJson, WellKnownJwtClaimNames.AudUtf8) is [var sole] ? sole : null),
                JwkJsonReader.ExtractStringValue(payloadJson, WellKnownJwtClaimNames.ClientIdUtf8),
                JwkJsonReader.ExtractStringValue(payloadJson, WellKnownJwtClaimNames.JtiUtf8));
        }
        catch(Exception unreadable) when(unreadable is FormatException or ArgumentException)
        {
            return null;
        }
    }
}
