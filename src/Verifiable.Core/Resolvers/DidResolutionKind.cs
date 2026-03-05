using System;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Discriminates the kind of a successful <see cref="DidResolutionResult"/>.
/// </summary>
/// <remarks>
/// <para>
/// Well-known values are defined as static properties. Callers may define additional
/// values by constructing an instance with an integer identifier.
/// </para>
/// </remarks>
public readonly struct DidResolutionKind: IEquatable<DidResolutionKind>
{
    private int Value { get; }

    /// <summary>
    /// Initializes a new <see cref="DidResolutionKind"/> with the given integer value.
    /// </summary>
    public DidResolutionKind(int value)
    {
        Value = value;
    }

    /// <summary>
    /// The result represents a failed resolution. No document or URL is populated.
    /// </summary>
    public static DidResolutionKind Error { get; } = new(0);

    /// <summary>
    /// The result contains a fully resolved <see cref="DidDocument"/>.
    /// </summary>
    public static DidResolutionKind Document { get; } = new(1);

    /// <summary>
    /// The result contains only an HTTPS URL at which the DID document can be fetched.
    /// Used by methods such as <c>did:web</c> and <c>did:cheqd</c> that compute a
    /// redirect URL rather than returning a document directly.
    /// </summary>
    public static DidResolutionKind DocumentUrl { get; } = new(2);

    /// <summary>
    /// The result contains an HTTPS URL pointing to a verifiable history log
    /// (e.g., a <c>did.jsonl</c> endpoint for <c>did:webvh</c>).
    /// </summary>
    public static DidResolutionKind VerifiedLog { get; } = new(3);

    /// <inheritdoc/>
    public bool Equals(DidResolutionKind other) => Value == other.Value;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is DidResolutionKind other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => Value.GetHashCode();

    /// <inheritdoc/>
    public override string ToString() => Value switch
    {
        0 => nameof(Error),
        1 => nameof(Document),
        2 => nameof(DocumentUrl),
        3 => nameof(VerifiedLog),
        _ => $"DidResolutionKind({Value})"
    };

    /// <inheritdoc/>
    public static bool operator ==(DidResolutionKind left, DidResolutionKind right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(DidResolutionKind left, DidResolutionKind right) => !left.Equals(right);
}