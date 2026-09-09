using System;
using System.Buffers.Text;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>KeyIdentifier</c> contents of an X.509 certificate's AuthorityKeyIdentifier extension, per
/// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1">RFC 5280 section 4.2.1.1</see> — the
/// value an OID4VP 1.0 <c>trusted_authorities</c> entry of type <c>aki</c> matches against, per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.1">OID4VP 1.0
/// section 6.1.1.1</see>: "The raw byte representation of this element MUST match with the
/// AuthorityKeyIdentifier element of an X.509 certificate in the certificate chain present in the Credential."
/// </summary>
/// <remarks>
/// <para>
/// Public certificate metadata, not sensitive key material — the same class of value as
/// <see cref="ManagedCertificate.SubjectKeyIdentifier"/>, carried as a plain <see cref="ReadOnlyMemory{T}"/>
/// rather than through a pooled, disposable carrier.
/// </para>
/// <para>
/// Equality compares the identifier's raw bytes, never its base64url transport form: a padded, unpadded, or
/// otherwise differently-encoded string that decodes to the same bytes identifies the same authority.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly struct AuthorityKeyIdentifier: IEquatable<AuthorityKeyIdentifier>
{
    /// <summary>
    /// The AuthorityKeyIdentifier extension's <c>keyIdentifier</c> OCTET STRING contents
    /// (RFC 5280 section 4.2.1.1), exactly as the certificate encodes them.
    /// </summary>
    public ReadOnlyMemory<byte> KeyIdentifier { get; }


    /// <summary>
    /// Initializes a new <see cref="AuthorityKeyIdentifier"/> from its raw <c>keyIdentifier</c> bytes.
    /// </summary>
    /// <param name="keyIdentifier">The AuthorityKeyIdentifier extension's <c>keyIdentifier</c> OCTET STRING contents.</param>
    public AuthorityKeyIdentifier(ReadOnlyMemory<byte> keyIdentifier)
    {
        KeyIdentifier = keyIdentifier;
    }


    /// <summary>
    /// Encodes <see cref="KeyIdentifier"/> as canonical, unpadded base64url — the transport form an OID4VP
    /// 1.0 §6.1.1.1 <c>aki</c> query value carries.
    /// </summary>
    /// <returns>The canonical unpadded base64url encoding of <see cref="KeyIdentifier"/>.</returns>
    [SuppressMessage("Design", "CA1055:URI-like return values should not be strings",
        Justification = "The base64url encoding of a KeyIdentifier is a transport-form text value compared byte-for-byte, not a URI; routing it through System.Uri adds no value.")]
    public string ToBase64Url()
    {
        return Base64Url.EncodeToString(KeyIdentifier.Span);
    }


    /// <summary>
    /// Parses a base64url-encoded <c>keyIdentifier</c> into an <see cref="AuthorityKeyIdentifier"/>. Both the
    /// canonical unpadded form and a padded form of the same bytes are accepted, since a base64url string is
    /// only a transport form of the underlying bytes the MUST in OID4VP 1.0 §6.1.1.1 compares.
    /// </summary>
    /// <param name="base64Url">The base64url text to parse.</param>
    /// <param name="identifier">The parsed <see cref="AuthorityKeyIdentifier"/> when parsing succeeds; <see langword="default"/> otherwise.</param>
    /// <returns><see langword="true"/> when <paramref name="base64Url"/> is valid base64url; <see langword="false"/> for anything else, including <see langword="null"/> or empty input.</returns>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "The base64url encoding of a KeyIdentifier is a transport-form text value compared byte-for-byte, not a URI; routing it through System.Uri adds no value.")]
    public static bool TryParse(string? base64Url, out AuthorityKeyIdentifier identifier)
    {
        identifier = default;
        if(string.IsNullOrEmpty(base64Url))
        {
            return false;
        }

        //A trusted_authorities value is attacker-controlled Verifier input, so a malformed one MUST match
        //nothing rather than fault the evaluator (OID4VP 1.0 §6.1.1.1). Base64Url.IsValid is the
        //non-throwing validator: Base64Url.GetMaxDecodedLength throws on a length that cannot be valid
        //base64url and TryDecodeFromChars can throw on some malformed content, so the length and content
        //are validated here before any decode is attempted.
        if(!Base64Url.IsValid(base64Url, out int decodedLength))
        {
            return false;
        }

        byte[] buffer = new byte[decodedLength];
        if(!Base64Url.TryDecodeFromChars(base64Url, buffer, out int bytesWritten))
        {
            return false;
        }

        identifier = new AuthorityKeyIdentifier(bytesWritten == buffer.Length ? buffer : buffer.AsMemory(0, bytesWritten));

        return true;
    }


    /// <inheritdoc/>
    public bool Equals(AuthorityKeyIdentifier other)
    {
        return KeyIdentifier.Span.SequenceEqual(other.KeyIdentifier.Span);
    }


    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is AuthorityKeyIdentifier other && Equals(other);
    }


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.AddBytes(KeyIdentifier.Span);

        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    public override string ToString()
    {
        return ToBase64Url();
    }


    /// <summary>Reports whether two identifiers carry the same <see cref="KeyIdentifier"/> bytes.</summary>
    public static bool operator ==(AuthorityKeyIdentifier left, AuthorityKeyIdentifier right)
    {
        return left.Equals(right);
    }


    /// <summary>Reports whether two identifiers carry different <see cref="KeyIdentifier"/> bytes.</summary>
    public static bool operator !=(AuthorityKeyIdentifier left, AuthorityKeyIdentifier right)
    {
        return !left.Equals(right);
    }


    private string DebuggerDisplay => $"AuthorityKeyIdentifier[{ToBase64Url()}]";
}
