using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth;

/// <summary>
/// The bearer token an authorization server issues alongside a successful
/// RFC 7591 dynamic client registration response. Used to authenticate
/// subsequent RFC 7592 read, update, and delete calls against the
/// registration management endpoint.
/// </summary>
/// <remarks>
/// <para>
/// Per <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2">RFC 7592 §2</see>,
/// the token is presented as an HTTP <c>Authorization: Bearer</c> header on
/// management calls. The token is opaque to the client — its lifetime,
/// revocability, and rotation behaviour are entirely AS-controlled.
/// </para>
/// <para>
/// Carries the same handling caution as any bearer credential: it grants
/// management authority over the registration to whoever holds it.
/// Applications persist it alongside the registration's <c>client_id</c>,
/// transmit it only over the secure transport their infrastructure
/// supplies, and treat the in-memory string value as sensitive.
/// </para>
/// <para>
/// The wrapper enforces the non-empty invariant at construction time so
/// that downstream call sites can rely on having a usable bearer value.
/// </para>
/// </remarks>
[DebuggerDisplay("RegistrationAccessToken Length={Value.Length}")]
public readonly struct RegistrationAccessToken: IEquatable<RegistrationAccessToken>
{
    /// <summary>Gets the bearer token's wire-format string value.</summary>
    public string Value { get; }


    /// <summary>
    /// Constructs a <see cref="RegistrationAccessToken"/> from a non-empty,
    /// non-whitespace string.
    /// </summary>
    /// <param name="value">The bearer token value returned by the AS.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="value"/> is <see langword="null"/>, empty,
    /// or whitespace-only.
    /// </exception>
    public RegistrationAccessToken(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value;
    }


    /// <summary>
    /// Returns a redacted form suitable for logging. The first four
    /// characters are preserved to aid correlation across log lines; the
    /// remainder is masked.
    /// </summary>
    /// <remarks>
    /// Comparison and equality are not derived from this representation.
    /// <see cref="ToString"/> intentionally does not return the full value
    /// so a stray log line does not leak the credential.
    /// </remarks>
    public override string ToString()
    {
        if(Value is null)
        {
            return string.Empty;
        }
        return Value.Length <= 4 ? "****" : $"{Value[..4]}****";
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(RegistrationAccessToken other) =>
        string.Equals(Value, other.Value, StringComparison.Ordinal);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is RegistrationAccessToken other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() =>
        Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(RegistrationAccessToken left, RegistrationAccessToken right) =>
        left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(RegistrationAccessToken left, RegistrationAccessToken right) =>
        !left.Equals(right);
}
