using Verifiable.Cryptography.Text;

namespace Verifiable.JCose;

/// <summary>
/// The JSON member NAMES of the JWS and JWE JSON serializations — the keys of a General/Flattened JWS object per
/// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-7.2">RFC 7515 §7.2</see> and of a General/Flattened JWE
/// object per <see href="https://www.rfc-editor.org/rfc/rfc7516#section-7.2">RFC 7516 §7.2</see>, as distinct from the
/// header-parameter names in <see cref="WellKnownJoseHeaderNames"/> and the JWK member names in
/// <see cref="WellKnownJwkMemberNames"/>.
/// </summary>
/// <remarks>
/// Each name declares its single UTF-8 source literal as a <c>ReadOnlySpan&lt;byte&gt;</c> property and derives the
/// interned string view through <see cref="Utf8Constants.ToInternedString"/>, matching
/// <see cref="WellKnownJoseHeaderNames"/>. The span form backs the allocation-free wire reads
/// (<c>JwkJsonReader.ExtractStringValue</c>/<c>ContainsKey</c>) in the JWE parse and classification paths; the interned
/// string backs the dictionary-keyed JWS serialization. These are the same literals that
/// <see cref="GeneralJweParsing"/>, <see cref="JoseTokenClassifier"/> and the JWS serializer would otherwise inline.
/// </remarks>
public static class WellKnownJoseSerializationNames
{
    /// <summary>The UTF-8 source literal of <see cref="Protected"/>.</summary>
    public static ReadOnlySpan<byte> ProtectedUtf8 => "protected"u8;

    /// <summary>The <c>protected</c> member — the base64url-encoded protected header (RFC 7515 §7.2 / RFC 7516 §7.2).</summary>
    public static readonly string Protected = Utf8Constants.ToInternedString(ProtectedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Header"/>.</summary>
    public static ReadOnlySpan<byte> HeaderUtf8 => "header"u8;

    /// <summary>The <c>header</c> member — the per-signature/per-recipient unprotected header (RFC 7515 §7.2 / RFC 7516 §7.2).</summary>
    public static readonly string Header = Utf8Constants.ToInternedString(HeaderUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Payload"/>.</summary>
    public static ReadOnlySpan<byte> PayloadUtf8 => "payload"u8;

    /// <summary>The <c>payload</c> member — the base64url-encoded JWS payload (RFC 7515 §7.2).</summary>
    public static readonly string Payload = Utf8Constants.ToInternedString(PayloadUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Signature"/>.</summary>
    public static ReadOnlySpan<byte> SignatureUtf8 => "signature"u8;

    /// <summary>The <c>signature</c> member — the base64url-encoded signature of a Flattened JWS (RFC 7515 §7.2.2).</summary>
    public static readonly string Signature = Utf8Constants.ToInternedString(SignatureUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Signatures"/>.</summary>
    public static ReadOnlySpan<byte> SignaturesUtf8 => "signatures"u8;

    /// <summary>The <c>signatures</c> member — the signature array of a General JWS (RFC 7515 §7.2.1).</summary>
    public static readonly string Signatures = Utf8Constants.ToInternedString(SignaturesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Recipients"/>.</summary>
    public static ReadOnlySpan<byte> RecipientsUtf8 => "recipients"u8;

    /// <summary>The <c>recipients</c> member — the recipient array of a General JWE (RFC 7516 §7.2.1).</summary>
    public static readonly string Recipients = Utf8Constants.ToInternedString(RecipientsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EncryptedKey"/>.</summary>
    public static ReadOnlySpan<byte> EncryptedKeyUtf8 => "encrypted_key"u8;

    /// <summary>The <c>encrypted_key</c> member — the base64url-encoded encrypted content-encryption key (RFC 7516 §7.2).</summary>
    public static readonly string EncryptedKey = Utf8Constants.ToInternedString(EncryptedKeyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Iv"/>.</summary>
    public static ReadOnlySpan<byte> IvUtf8 => "iv"u8;

    /// <summary>The <c>iv</c> member — the base64url-encoded initialization vector (RFC 7516 §7.2).</summary>
    public static readonly string Iv = Utf8Constants.ToInternedString(IvUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Ciphertext"/>.</summary>
    public static ReadOnlySpan<byte> CiphertextUtf8 => "ciphertext"u8;

    /// <summary>The <c>ciphertext</c> member — the base64url-encoded ciphertext (RFC 7516 §7.2).</summary>
    public static readonly string Ciphertext = Utf8Constants.ToInternedString(CiphertextUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Tag"/>.</summary>
    public static ReadOnlySpan<byte> TagUtf8 => "tag"u8;

    /// <summary>The <c>tag</c> member — the base64url-encoded authentication tag (RFC 7516 §7.2).</summary>
    public static readonly string Tag = Utf8Constants.ToInternedString(TagUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Aad"/>.</summary>
    public static ReadOnlySpan<byte> AadUtf8 => "aad"u8;

    /// <summary>The <c>aad</c> member — the base64url-encoded additional authenticated data of a General/Flattened JWE (RFC 7516 §7.2).</summary>
    public static readonly string Aad = Utf8Constants.ToInternedString(AadUtf8);
}
