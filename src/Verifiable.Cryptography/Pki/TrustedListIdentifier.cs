using System;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The identifier of an ETSI Trusted List, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.3.16</see> (a list's own distribution-point URIs) and clause 5.3.13 item a
/// (the <c>TSLLocation</c> a pointer names) — the value an OID4VP 1.0 <c>trusted_authorities</c> entry of type
/// <c>etsi_tl</c> carries, per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">OID4VP 1.0
/// section 6.1.1.2</see>.
/// </summary>
/// <remarks>
/// <para>
/// An absolute http or https URI: <see cref="Uri.TryCreate(string, UriKind, out Uri)"/> plus an explicit
/// scheme-and-host check closes the cross-platform trap whereby a scheme-relative or path-only value is
/// otherwise accepted as an absolute URI on some platforms. Unlike
/// <c>Verifiable.Core.Model.Federation.EntityIdentifier</c>, a query or fragment is NOT rejected: the value
/// is a Trusted List identifier — a scheme-information URI or distribution point per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612</see> clause 5.3.16 — which may legitimately carry a query, so rejecting one would fail a
/// valid <c>etsi_tl</c> value closed.
/// </para>
/// <para>
/// Equality and hashing are ordinal string comparison on the original value — per
/// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.1">RFC 3986 section 6.2.1</see>'s
/// simple-string-comparison scheme normalization, so two textually different spellings of what a browser
/// would treat as the same resource compare unequal here. A false negative fails a <c>etsi_tl</c> match
/// closed rather than risking a false positive from a normalization the specification does not require.
/// </para>
/// </remarks>
[DebuggerDisplay("{Value,nq}")]
public readonly struct TrustedListIdentifier: IEquatable<TrustedListIdentifier>
{
    /// <summary>
    /// The absolute http or https URL value identifying the Trusted List. Canonical identity; equality and
    /// hashing compare on this string with <see cref="StringComparison.Ordinal"/>.
    /// </summary>
    public string Value { get; }


    /// <summary>
    /// Constructs a Trusted List identifier from an absolute http or https URL string.
    /// </summary>
    /// <param name="value">The identifier. Required to be non-null, non-whitespace, an absolute URL with the http or https scheme and a host.</param>
    /// <exception cref="ArgumentException">When <paramref name="value"/> is null, whitespace, not an absolute URL, not http/https, or lacks a host.</exception>
    public TrustedListIdentifier(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if(!IsHttpOrHttpsUrlWithHost(value))
        {
            throw new ArgumentException(
                $"Trusted List identifier must be an absolute http or https URL with a host; got '{value}'.",
                nameof(value));
        }

        Value = value;
    }


    /// <summary>
    /// Attempts to construct a Trusted List identifier from an arbitrary string, failing closed rather than
    /// throwing when the value is not a well-formed identifier — the shape a wire reader or a distribution-point
    /// walk needs, since an unparseable value simply contributes nothing rather than aborting evaluation.
    /// </summary>
    /// <param name="value">The candidate identifier text.</param>
    /// <param name="identifier">The parsed identifier when <paramref name="value"/> is a well-formed absolute http/https URL with a host; <see langword="default"/> otherwise.</param>
    /// <returns><see langword="true"/> when parsing succeeds; otherwise <see langword="false"/>.</returns>
    public static bool TryCreate(string? value, out TrustedListIdentifier identifier)
    {
        identifier = default;
        if(string.IsNullOrWhiteSpace(value) || !IsHttpOrHttpsUrlWithHost(value))
        {
            return false;
        }

        identifier = new TrustedListIdentifier(value);

        return true;
    }


    /// <summary>
    /// Reports whether <paramref name="value"/> is an absolute URL using the http or https scheme with a
    /// non-empty host component.
    /// </summary>
    /// <param name="value">The candidate URL text.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> qualifies; otherwise <see langword="false"/>.</returns>
    private static bool IsHttpOrHttpsUrlWithHost(string value)
    {
        if(!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri))
        {
            return false;
        }

        bool isHttpOrHttps = string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
            || string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal);

        return isHttpOrHttps && !string.IsNullOrEmpty(uri.Host);
    }


    /// <inheritdoc/>
    public bool Equals(TrustedListIdentifier other)
    {
        return string.Equals(Value, other.Value, StringComparison.Ordinal);
    }


    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is TrustedListIdentifier other && Equals(other);
    }


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);
    }


    /// <inheritdoc/>
    public override string ToString()
    {
        return Value ?? string.Empty;
    }


    /// <summary>Reports whether two identifiers carry the same value.</summary>
    public static bool operator ==(TrustedListIdentifier left, TrustedListIdentifier right)
    {
        return left.Equals(right);
    }


    /// <summary>Reports whether two identifiers carry a different value.</summary>
    public static bool operator !=(TrustedListIdentifier left, TrustedListIdentifier right)
    {
        return !(left == right);
    }
}
