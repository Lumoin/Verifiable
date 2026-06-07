using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Identifies a Client Identifier Prefix per OpenID for Verifiable
/// Presentations 1.0 §5.9.3. The prefix appears before the first <c>:</c>
/// in the <c>client_id</c> Authorization Request parameter and dictates
/// how the Wallet obtains and validates the Verifier's public key for JAR
/// signature verification.
/// </summary>
/// <remarks>
/// <para>
/// Value-type wrapper around the prefix string (e.g. <c>x509_san_dns</c>,
/// <c>openid_federation</c>). Canonical identity is ordinal-string
/// equality on <see cref="Value"/>. Same shape as
/// <see cref="Verifiable.OAuth.Federation.EntityIdentifier"/>,
/// <see cref="Verifiable.OAuth.Federation.EntityTypeIdentifier"/>,
/// <see cref="Verifiable.OAuth.Server.CapabilityIdentifier"/>, and
/// <see cref="Verifiable.OAuth.Federation.MetadataPolicyOperator"/> —
/// semantic-type-over-string-keys, with constructor validation forbidding
/// the trailing colon (which is a separator, not part of the prefix
/// identity).
/// </para>
/// <para>
/// Library-shipped well-known instances live on
/// <see cref="WellKnownClientIdPrefixes"/>; deployments register custom
/// prefixes via the constructor.
/// </para>
/// </remarks>
[DebuggerDisplay("{Value,nq}")]
public readonly struct ClientIdPrefix: IEquatable<ClientIdPrefix>
{
    /// <summary>
    /// The prefix value (without trailing colon). Canonical identity;
    /// equality and hashing compare on this string with
    /// <see cref="StringComparison.Ordinal"/>.
    /// </summary>
    public string Value { get; }


    /// <summary>
    /// Constructs a prefix from its bare wire string (no trailing colon).
    /// </summary>
    /// <param name="value">The prefix value, e.g. <c>x509_san_dns</c>.</param>
    /// <exception cref="ArgumentException">
    /// When <paramref name="value"/> is null, whitespace, or contains a
    /// colon character (the colon is a separator in the wire form, not
    /// part of the prefix identity).
    /// </exception>
    public ClientIdPrefix(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);

        if(value.Contains(':', StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "ClientIdPrefix value must not contain ':' — the colon is a separator in the wire form, not part of the prefix.",
                nameof(value));
        }

        Value = value;
    }


    /// <inheritdoc/>
    public bool Equals(ClientIdPrefix other) =>
        string.Equals(Value, other.Value, StringComparison.Ordinal);


    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is ClientIdPrefix other && Equals(other);


    /// <inheritdoc/>
    public override int GetHashCode() =>
        Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);


    /// <inheritdoc/>
    public override string ToString() => Value ?? string.Empty;


    /// <summary>Equality operator.</summary>
    public static bool operator ==(ClientIdPrefix left, ClientIdPrefix right) => left.Equals(right);


    /// <summary>Inequality operator.</summary>
    public static bool operator !=(ClientIdPrefix left, ClientIdPrefix right) => !left.Equals(right);
}
