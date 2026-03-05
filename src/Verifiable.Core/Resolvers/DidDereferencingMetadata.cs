using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Metadata about the DID URL dereferencing process. This metadata typically changes
/// between invocations as it represents data about the dereferencing process itself,
/// not the content.
/// </summary>
/// <remarks>
/// <para>
/// The <see cref="Error"/> property carries an RFC 9457 Problem Details object when
/// dereferencing fails. The type URI within the error object MUST be one of the values
/// defined in <see cref="DidErrorTypes"/>. Pre-built instances for all standard errors
/// are available in <see cref="DidResolutionErrors"/>.
/// </para>
/// <para>
/// See <see href="https://w3c.github.io/did-resolution/#did-url-dereferencing-metadata">DID Resolution §5.2</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("Error={Error.Type.AbsoluteUri,nq} ContentType={ContentType,nq}")]
public sealed class DidDereferencingMetadata: IEquatable<DidDereferencingMetadata>
{
    /// <summary>
    /// The media type of the returned content stream. MUST be an ASCII string when present.
    /// </summary>
    public string? ContentType { get; init; }

    /// <summary>
    /// The RFC 9457 error object describing the failure condition, or <see langword="null"/>
    /// when dereferencing was successful. The <see cref="DidProblemDetails.Type"/> MUST be one
    /// of the URIs in <see cref="DidErrorTypes"/>.
    /// </summary>
    public DidProblemDetails? Error { get; init; }

    /// <summary>
    /// Proofs added by the DID URL dereferencer, if any. Each item is an opaque map whose
    /// interpretation is DID method-independent.
    /// </summary>
    /// <remarks>
    /// Note: PR #295 against the W3C DID Resolution editor's draft proposes removing the
    /// claim that this proof enables independent verifiability of dereferencing. The property
    /// itself is retained; only the strength of the associated normative language is under
    /// revision.
    /// </remarks>
    public IReadOnlyList<IReadOnlyDictionary<string, object>>? Proof { get; init; }

    /// <inheritdoc />
    public bool Equals(DidDereferencingMetadata? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(ContentType, other.ContentType, StringComparison.Ordinal)
            && Error == other.Error;
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is DidDereferencingMetadata other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(ContentType, Error);

    /// <inheritdoc />
    public static bool operator ==(DidDereferencingMetadata? left, DidDereferencingMetadata? right) =>
        left is null ? right is null : left.Equals(right);

    /// <inheritdoc />
    public static bool operator !=(DidDereferencingMetadata? left, DidDereferencingMetadata? right) => !(left == right);
}