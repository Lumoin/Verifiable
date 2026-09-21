using System.Diagnostics;

namespace Verifiable.Core;

/// <summary>
/// A tenant's public identifier: the name it is known by on the wire — the segment of its URLs, the
/// tenant-specific part of its issuer identifier — and the only tenant-shaped value the library
/// writes to telemetry or delivers in an event. Opaque to the library, which never derives it.
/// </summary>
/// <remarks>
/// <para>
/// A tenant has two identifiers. <see cref="TenantId"/> is the internal key every stored record
/// hangs off and must never change; <see cref="TenantHandle"/> is the public one, chosen by the
/// application to be seen: a random or pseudonymous label, or a name, as the deployment prefers.
/// Because the stores are keyed by <see cref="TenantId"/>, a tenant can be given a fresh handle —
/// after a key compromise, a reorganisation, a move to a custom domain — and keep every
/// registration, flow and key it ever had. A single identifier could not do both jobs: used on the
/// wire it would expose the storage key, and used as the storage key it could never be replaced.
/// </para>
/// <para>
/// An application sets the handle on <c>ClientRecord.TenantHandle</c> at registration time, exactly
/// as it sets <see cref="TenantId"/>; the library performs no lookup, hashing or truncation to
/// produce one. A registration with no handle produces no tenant-shaped tag on the dispatch span and
/// carries <see langword="null"/> on its registration events — the library fails closed rather than
/// falling back to the key.
/// </para>
/// </remarks>
[DebuggerDisplay("TenantHandle={Value}")]
public readonly struct TenantHandle: IEquatable<TenantHandle>
{
    /// <summary>
    /// The display value. Opaque to the library; chosen by the application.
    /// </summary>
    public string Value { get; }


    /// <summary>
    /// Initialises a <see cref="TenantHandle"/> with the specified display value.
    /// </summary>
    /// <param name="value">The display value. Must not be null or whitespace.</param>
    public TenantHandle(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value;
    }


    /// <inheritdoc />
    public bool Equals(TenantHandle other) => string.Equals(Value, other.Value, StringComparison.Ordinal);


    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is TenantHandle other && Equals(other);


    /// <inheritdoc />
    public override int GetHashCode() => Value.GetHashCode(StringComparison.Ordinal);


    /// <inheritdoc />
    public override string ToString() => Value;


    /// <summary>Compares two tenant handles for equality by their ordinal <see cref="Value"/>.</summary>
    /// <param name="left">The first tenant handle.</param>
    /// <param name="right">The second tenant handle.</param>
    /// <returns><see langword="true"/> when <paramref name="left"/> and <paramref name="right"/> carry the same value.</returns>
    public static bool operator ==(TenantHandle left, TenantHandle right) => left.Equals(right);


    /// <summary>Compares two tenant handles for inequality by their ordinal <see cref="Value"/>.</summary>
    /// <param name="left">The first tenant handle.</param>
    /// <param name="right">The second tenant handle.</param>
    /// <returns><see langword="true"/> when <paramref name="left"/> and <paramref name="right"/> carry different values.</returns>
    public static bool operator !=(TenantHandle left, TenantHandle right) => !(left == right);


    /// <summary>
    /// Implicitly converts a <see cref="string"/> to a <see cref="TenantHandle"/>.
    /// </summary>
    public static implicit operator TenantHandle(string value) => new(value);


    /// <summary>
    /// Implicitly converts a <see cref="TenantHandle"/> to its underlying
    /// <see cref="string"/> value.
    /// </summary>
    public static implicit operator string(TenantHandle tenantHandle) => tenantHandle.Value;
}
