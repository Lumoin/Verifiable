using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography.Text;

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
    public static readonly string Plaintext = Utf8Constants.ToInternedString(PlaintextUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Signed"/>.</summary>
    public static ReadOnlySpan<byte> SignedUtf8 => "application/didcomm-signed+json"u8;

    /// <summary>
    /// A DIDComm signed message (<c>application/didcomm-signed+json</c>) — a signed JWM that adds
    /// non-repudiation to the plaintext it wraps (DIDComm v2.1 §DIDComm Signed Messages).
    /// </summary>
    public static readonly string Signed = Utf8Constants.ToInternedString(SignedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Encrypted"/>.</summary>
    public static ReadOnlySpan<byte> EncryptedUtf8 => "application/didcomm-encrypted+json"u8;

    /// <summary>
    /// A DIDComm encrypted message (<c>application/didcomm-encrypted+json</c>) — an encrypted JWM.
    /// All encryption wrappings (anoncrypt, authcrypt, and their nested combinations) share this
    /// one media type, because only the recipient should care about the difference
    /// (DIDComm v2.1 §DIDComm Encrypted Messages / §IANA Media Types).
    /// </summary>
    public static readonly string Encrypted = Utf8Constants.ToInternedString(EncryptedUtf8);


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


    //The 'application/' prefix every DIDComm media-type constant carries (RFC 7515 §4.1.9).
    private const string ApplicationPrefix = "application/";

    //Media type comparison is case-insensitive per RFC 2045 / RFC 9110 §8.3.1. Per RFC 7515 §4.1.9 and
    //DIDComm v2.1 §Message Types (the recipient "MUST treat media types not containing / as having the
    //application/ prefix present"), a candidate with no '/' matches the full constant once the prefix is
    //restored. Comparison against the constant's post-prefix span keeps the check allocation-free.
    private static bool Equals(string? mediaTypeA, string mediaTypeB)
    {
        if(ReferenceEquals(mediaTypeA, mediaTypeB))
        {
            return true;
        }

        if(mediaTypeA is null)
        {
            return false;
        }

        if(StringComparer.OrdinalIgnoreCase.Equals(mediaTypeA, mediaTypeB))
        {
            return true;
        }

        return !mediaTypeA.Contains('/', StringComparison.Ordinal)
            && mediaTypeB.AsSpan(ApplicationPrefix.Length).Equals(mediaTypeA, StringComparison.OrdinalIgnoreCase);
    }
}
