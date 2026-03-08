using System;
using System.Diagnostics;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Options controlling DID URL dereferencing behavior per W3C DID Resolution v0.3 §5.1.
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://w3c.github.io/did-resolution/#did-url-dereferencing-options">DID Resolution §5.1</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("Accept={Accept,nq} VerificationRelationship={VerificationRelationship,nq}")]
public sealed class DidDereferencingOptions: IEquatable<DidDereferencingOptions>
{
    /// <summary>
    /// Empty options instance. Passing this is equivalent to passing no options.
    /// </summary>
    public static DidDereferencingOptions Empty { get; } = new();

    /// <summary>
    /// The media type the caller prefers for the dereferenced resource.
    /// The value MUST follow the <c>Accept</c> header format defined in RFC 9110 §12.5.1.
    /// </summary>
    public string? Accept { get; init; }

    /// <summary>
    /// The verification relationship for which the caller expects the verification method
    /// dereferenced from the DID URL to be authorized. When present, the value MUST be an
    /// ASCII string identifying a verification relationship (e.g., <c>authentication</c>,
    /// <c>assertionMethod</c>).
    /// </summary>
    /// <remarks>
    /// If the DID URL does not dereference to a verification method, or the DID document
    /// does not authorize the verification method for the specified relationship, an error
    /// MUST be raised.
    /// </remarks>
    public string? VerificationRelationship { get; init; }

    /// <inheritdoc />
    public bool Equals(DidDereferencingOptions? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(Accept, other.Accept, StringComparison.Ordinal)
            && string.Equals(VerificationRelationship, other.VerificationRelationship, StringComparison.Ordinal);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is DidDereferencingOptions other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(Accept, VerificationRelationship);

    /// <inheritdoc />
    public static bool operator ==(DidDereferencingOptions? left, DidDereferencingOptions? right) =>
        left is null ? right is null : left.Equals(right);

    /// <inheritdoc />
    public static bool operator !=(DidDereferencingOptions? left, DidDereferencingOptions? right) => !(left == right);
}
