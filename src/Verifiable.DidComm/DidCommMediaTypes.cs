using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography.Text;
using Verifiable.JCose;

namespace Verifiable.DidComm;

/// <summary>
/// The IANA media types for the three DIDComm Messaging v2 message formats, as defined in
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#iana-media-types">DIDComm Messaging v2.1 §IANA Media Types</see>.
/// </summary>
/// <remarks>
/// <para>
/// Each value is both the HTTP <c>Content-Type</c> and the JOSE <c>typ</c> header value for the
/// corresponding format. Per RFC 7515 §4.1.9 a recipient MUST treat a media type without a
/// <c>/</c> as having the <c>application/</c> prefix present; DIDComm always uses the full form.
/// </para>
/// <para>
/// Each constant declares its single source as a <c>ReadOnlySpan&lt;byte&gt;</c> UTF-8 literal and
/// derives the interned string view through <see cref="Utf8Constants.ToInternedString"/>, matching
/// the well-known-constant convention used across the library.
/// </para>
/// </remarks>
public static class DidCommMediaTypes
{
    /// <summary>The UTF-8 source literal of <see cref="Plaintext"/>.</summary>
    public static ReadOnlySpan<byte> PlaintextUtf8 => "application/didcomm-plain+json"u8;

    /// <summary>
    /// A DIDComm plaintext message (<c>application/didcomm-plain+json</c>) — a JWM with no
    /// protective envelope. The media type a conformant implementation MUST report for a generic
    /// plaintext message (DIDComm v2.1 §DIDComm Plaintext Messages).
    /// </summary>
    public static string Plaintext { get; } = Utf8Constants.ToInternedString(PlaintextUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Signed"/>.</summary>
    public static ReadOnlySpan<byte> SignedUtf8 => "application/didcomm-signed+json"u8;

    /// <summary>
    /// A DIDComm signed message (<c>application/didcomm-signed+json</c>) — a signed JWM that adds
    /// non-repudiation to the plaintext it wraps (DIDComm v2.1 §DIDComm Signed Messages).
    /// </summary>
    public static string Signed { get; } = Utf8Constants.ToInternedString(SignedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Encrypted"/>.</summary>
    public static ReadOnlySpan<byte> EncryptedUtf8 => "application/didcomm-encrypted+json"u8;

    /// <summary>
    /// A DIDComm encrypted message (<c>application/didcomm-encrypted+json</c>) — an encrypted JWM.
    /// All encryption wrappings (anoncrypt, authcrypt, and their nested combinations) share this
    /// one media type, because only the recipient should care about the difference
    /// (DIDComm v2.1 §DIDComm Encrypted Messages / §IANA Media Types).
    /// </summary>
    public static string Encrypted { get; } = Utf8Constants.ToInternedString(EncryptedUtf8);


    /// <summary>Whether <paramref name="mediaType"/> is the plaintext media type.</summary>
    /// <param name="mediaType">The media type or <c>typ</c> value.</param>
    /// <returns><see langword="true"/> when <paramref name="mediaType"/> is <see cref="Plaintext"/>.</returns>
    public static bool IsPlaintext([NotNullWhen(true)] string? mediaType) => Equals(mediaType, Plaintext);

    /// <summary>Whether <paramref name="mediaType"/> is the signed media type.</summary>
    /// <param name="mediaType">The media type or <c>typ</c> value.</param>
    /// <returns><see langword="true"/> when <paramref name="mediaType"/> is <see cref="Signed"/>.</returns>
    public static bool IsSigned([NotNullWhen(true)] string? mediaType) => Equals(mediaType, Signed);

    /// <summary>Whether <paramref name="mediaType"/> is the encrypted media type.</summary>
    /// <param name="mediaType">The media type or <c>typ</c> value.</param>
    /// <returns><see langword="true"/> when <paramref name="mediaType"/> is <see cref="Encrypted"/>.</returns>
    public static bool IsEncrypted([NotNullWhen(true)] string? mediaType) => Equals(mediaType, Encrypted);


    /// <summary>
    /// Compares two media type values through the one
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 §4.1.9</see>
    /// comparison every <c>typ</c> check in the library shares: case insensitive, with the implicit
    /// <c>application/</c> prefix for a candidate carrying no <c>/</c> of its own, which is the
    /// recipient rule DIDComm v2.1 §Message Types states as well. Span based and allocation free.
    /// </summary>
    /// <param name="mediaTypeA">The candidate, a media type or a <c>typ</c> value, possibly absent.</param>
    /// <param name="mediaTypeB">The DIDComm media type constant to compare against.</param>
    /// <returns><see langword="true"/> when both name the same media type; otherwise, <see langword="false"/>.</returns>
    private static bool Equals(string? mediaTypeA, string mediaTypeB) =>
        mediaTypeA is not null && WellKnownMediaTypes.Jwt.Equals(mediaTypeA, mediaTypeB);
}
