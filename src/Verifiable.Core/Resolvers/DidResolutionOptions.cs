using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Options controlling DID resolution behavior, passed to the <c>resolve</c> function
/// per W3C DID Resolution v0.3 §4.1.
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://www.w3.org/TR/did-resolution/#did-resolution-options">DID Resolution §4.1</see>.
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
    /// When <see langword="true"/>, a method that supports deriving an encryption (key agreement)
    /// verification method from a signature key derives it and includes it in the resolved document.
    /// </summary>
    /// <remarks>
    /// This is the <c>did:key</c> <c>options.enableEncryptionKeyDerivation</c> option: for an Ed25519
    /// <c>did:key</c> the resolver derives the birationally-equivalent X25519 public key and adds it as a
    /// <c>keyAgreement</c> verification method. A method that does not support derivation ignores this option.
    /// See <see href="https://w3c-ccg.github.io/did-key-spec/#document-creation-algorithm">did:key §Document Creation Algorithm</see>.
    /// </remarks>
    public bool? EnableEncryptionKeyDerivation { get; init; }

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

    /// <summary>
    /// Resolve the DID document at a specific integer version number. This is the did:webvh-specific
    /// <c>versionNumber</c> resolution parameter, which is not part of the [DID-CORE] specification.
    /// </summary>
    public int? VersionNumber { get; init; }

    /// <summary>
    /// Alternative DID Log source URLs (for example known Watcher URLs) the resolver MAY try when the DID's
    /// designated HTTPS location returns a not-found condition. Each URL is the full location a watcher serves
    /// the DID Log from; the resolver fetches and verifies the retrieved log exactly as it would the primary,
    /// so a tampered alternative source still fails verification. A method that does not support watcher
    /// fallback ignores this option.
    /// </summary>
    public IReadOnlyList<string>? WatcherUrls { get; init; }

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
            && EnableEncryptionKeyDerivation == other.EnableEncryptionKeyDerivation
            && string.Equals(VersionId, other.VersionId, StringComparison.Ordinal)
            && VersionTime == other.VersionTime
            && VersionNumber == other.VersionNumber
            && WatcherUrlsEqual(WatcherUrls, other.WatcherUrls);
    }


    private static bool WatcherUrlsEqual(IReadOnlyList<string>? left, IReadOnlyList<string>? right)
    {
        if(left is null || right is null)
        {
            return left is null && right is null;
        }

        return left.SequenceEqual(right, StringComparer.Ordinal);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is DidResolutionOptions other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(Accept, ExpandRelativeUrls, EnableEncryptionKeyDerivation, VersionId, VersionTime, VersionNumber);

    /// <inheritdoc />
    public static bool operator ==(DidResolutionOptions? left, DidResolutionOptions? right) =>
        left is null ? right is null : left.Equals(right);

    /// <inheritdoc />
    public static bool operator !=(DidResolutionOptions? left, DidResolutionOptions? right) => !(left == right);
}
