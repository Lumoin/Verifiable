using System;
using System.Diagnostics;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Options controlling DID resolution behavior, passed to the <c>resolve</c> function
/// per W3C DID Resolution v0.3 §4.1.
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://w3c.github.io/did-resolution/#did-resolution-options">DID Resolution §4.1</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("Accept={Accept,nq} ExpandRelativeUrls={ExpandRelativeUrls} VersionId={VersionId,nq} VersionTime={VersionTime}")]
public sealed class DidResolutionOptions: IEquatable<DidResolutionOptions>
{
    /// <summary>
    /// Empty options instance. Passing this is equivalent to passing no options.
    /// </summary>
    public static DidResolutionOptions Empty { get; } = new();

    /// <summary>
    /// The media type the caller prefers for the DID document representation.
    /// The value MUST follow the <c>Accept</c> header format defined in RFC 9110 §12.5.1.
    /// </summary>
    public string? Accept { get; init; }

    /// <summary>
    /// When <see langword="true"/>, the resolver expands all relative DID URLs in services,
    /// verification methods, and verification relationships to absolute DID URLs before
    /// returning the document.
    /// </summary>
    /// <remarks>
    /// Note: PR #299 against the W3C DID Resolution editor's draft proposes extending
    /// this expansion to cover extension properties beyond the three named document
    /// sections. The current implementation expands only services, verification methods,
    /// and verification relationships as specified in the December 2025 Working Draft.
    /// </remarks>
    public bool? ExpandRelativeUrls { get; init; }

    /// <summary>
    /// Resolve the DID document at a specific version identifier.
    /// </summary>
    public string? VersionId { get; init; }

    /// <summary>
    /// Resolve the DID document as it existed at a specific point in time.
    /// The value MUST be an XML datetime normalized to UTC without sub-second precision,
    /// for example <c>2021-05-10T17:00:00Z</c>.
    /// </summary>
    public DateTimeOffset? VersionTime { get; init; }

    /// <inheritdoc />
    public bool Equals(DidResolutionOptions? other)
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
            && ExpandRelativeUrls == other.ExpandRelativeUrls
            && string.Equals(VersionId, other.VersionId, StringComparison.Ordinal)
            && VersionTime == other.VersionTime;
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is DidResolutionOptions other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(Accept, ExpandRelativeUrls, VersionId, VersionTime);

    /// <inheritdoc />
    public static bool operator ==(DidResolutionOptions? left, DidResolutionOptions? right) =>
        left is null ? right is null : left.Equals(right);

    /// <inheritdoc />
    public static bool operator !=(DidResolutionOptions? left, DidResolutionOptions? right) => !(left == right);
}
