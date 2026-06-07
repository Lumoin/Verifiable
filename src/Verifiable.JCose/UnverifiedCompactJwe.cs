using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// A compact-form JWE that has been structurally validated and had its
/// protected header parsed, but whose AEAD authentication has not yet been
/// performed.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why this type exists.</strong>
/// A compact-form JWE on the wire is a five-segment Base64Url-and-dots
/// string per RFC 7516 §7.1. Treating it as a naked
/// <see cref="string"/> at API boundaries throws away its structural
/// identity — every consumer would re-establish the five-segment invariant
/// and re-extract the protected header on its own. This type captures both
/// the original wire bytes and the parsed header in one validated bundle so
/// downstream code reads them through a typed surface.
/// </para>
/// <para>
/// This wrapper is the JWE counterpart to <see cref="UnverifiedJwsMessage"/>
/// at the classifier layer. It is intentionally narrower in scope than
/// <see cref="UnverifiedJwsMessage"/> — JWE message representation in this
/// library has not yet been unified across the three serialization formats
/// (compact, flattened JSON, general JSON), and this type covers only the
/// compact form, the only format the classifier produces today.
/// </para>
/// <para>
/// <strong>Trust state.</strong>
/// The structural shape has been verified — five segments, header parses to
/// a JSON object containing <c>enc</c>. Nothing else has been verified. The
/// AEAD authentication tag has not been checked, which means
/// <see cref="Header"/> is unauthenticated: every value in it is
/// attacker-controlled until decryption succeeds. The
/// <see cref="UnverifiedJwtHeader"/> type carries that warning at the type
/// level. Consumers that read <see cref="Header"/> values to drive policy
/// decisions (for example, fast-failing on an unsupported <c>alg</c> before
/// calling <see cref="JweParsing.ParseCompact"/>) are reading
/// attacker-controlled data and must treat any conclusions as unverified
/// until decryption authenticates the header via the AAD binding.
/// </para>
/// <para>
/// <strong>Composition with <see cref="JweParsing"/>.</strong>
/// Consumers that intend to decrypt the JWE call
/// <see cref="JweParsing.ParseCompact"/> with <see cref="Value"/>, supplying
/// the <em>expected</em> algorithm and content-encryption identifiers as
/// policy. <see cref="JweParsing.ParseCompact"/> rejects mismatches and
/// returns an <see cref="Verifiable.Cryptography.Aead.AeadMessage"/> ready
/// for AEAD decryption. The classifier-produced
/// <see cref="UnverifiedCompactJwe"/> and the consumer-driven
/// <see cref="Verifiable.Cryptography.Aead.AeadMessage"/> are complementary
/// — the former says <em>"this is structurally a JWE"</em>, the latter says
/// <em>"this is a JWE that the consumer has agreed to decrypt with these
/// parameters"</em>.
/// </para>
/// </remarks>
[DebuggerDisplay("UnverifiedCompactJwe({Header.Count} header parameters)")]
public sealed class UnverifiedCompactJwe: IEquatable<UnverifiedCompactJwe>
{
    /// <summary>
    /// The original compact-form JWE wire string. Length-bounded only by
    /// upstream input limits; structural validity has been checked
    /// (five segments).
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// The parsed protected header. The bytes have been Base64Url-decoded
    /// and JSON-parsed; <c>enc</c> is known to be present (otherwise the
    /// classifier would have produced <see cref="MalformedShape"/> rather
    /// than a successful classification). All values remain attacker-
    /// controlled until AEAD decryption succeeds and authenticates the
    /// header via the AAD binding.
    /// </summary>
    public UnverifiedJwtHeader Header { get; }


    /// <summary>
    /// Creates a new <see cref="UnverifiedCompactJwe"/> from a previously
    /// validated wire string and parsed header.
    /// </summary>
    /// <remarks>
    /// This constructor is intended for use by the classifier and other
    /// JCose-internal code that has already performed the structural
    /// validation. It does not re-validate <paramref name="value"/>'s
    /// segment count or <paramref name="header"/>'s contents — the caller
    /// is responsible for those invariants.
    /// </remarks>
    /// <param name="value">The original compact-form JWE wire string.</param>
    /// <param name="header">The parsed protected header.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="value"/> or <paramref name="header"/>
    /// is <see langword="null"/>.
    /// </exception>
    public UnverifiedCompactJwe(string value, UnverifiedJwtHeader header)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(header);

        Value = value;
        Header = header;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(UnverifiedCompactJwe? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(Value, other.Value, StringComparison.Ordinal)
            && Header.Equals(other.Header);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is UnverifiedCompactJwe other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => HashCode.Combine(Value, Header);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(UnverifiedCompactJwe? left, UnverifiedCompactJwe? right) =>
        left is null ? right is null : left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(UnverifiedCompactJwe? left, UnverifiedCompactJwe? right) =>
        !(left == right);
}
