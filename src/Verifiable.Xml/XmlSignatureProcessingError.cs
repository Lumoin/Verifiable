using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The refusal a reference-processing operation produced: the reason, where it was determined, and — when
/// the refusal surfaced through a well-formed-parse failure of the section 4.3.3.2 octets-to-node-set
/// default conversion — the inner <see cref="XmlReadError"/> the parse itself reported.
/// </summary>
/// <remarks>
/// Reference processing is result-shaped: refused input is reported through this type, never through an
/// exception, the <see cref="XmlReadError"/>/<see cref="XmlCanonicalizationError"/> idiom extended
/// with the one addition reference processing needs — an optional inner read error — because a mid-chain
/// re-parse (<see cref="XmlSignatureProcessingFailure.ReferenceParseFailed"/>) fails for a reason the
/// reading surface, not the reference-processing surface, determines.
/// </remarks>
/// <seealso cref="XmlSignatureProcessingFailure"/>
public readonly struct XmlSignatureProcessingError: IEquatable<XmlSignatureProcessingError>
{
    /// <summary>
    /// The reason reference processing was refused.
    /// </summary>
    public XmlSignatureProcessingFailure Failure { get; }

    /// <summary>
    /// The zero-based offset at which the refusal was determined; zero when the refusal is a property of
    /// the whole operation rather than one position.
    /// </summary>
    public long ByteOffset { get; }

    /// <summary>
    /// The inner read error a mid-chain re-parse failure reported, for
    /// <see cref="XmlSignatureProcessingFailure.ReferenceParseFailed"/>; <see langword="null"/> for every
    /// other reason.
    /// </summary>
    public XmlReadError? InnerReadError { get; }


    /// <summary>
    /// Creates a reference-processing error with no inner read error.
    /// </summary>
    /// <param name="failure">The reason reference processing was refused.</param>
    /// <param name="byteOffset">The zero-based offset at which the refusal was determined, or zero.</param>
    public XmlSignatureProcessingError(XmlSignatureProcessingFailure failure, long byteOffset)
        : this(failure, byteOffset, innerReadError: null)
    {
    }


    /// <summary>
    /// Creates a reference-processing error carrying the read error a mid-chain re-parse reported.
    /// </summary>
    /// <param name="failure">The reason reference processing was refused.</param>
    /// <param name="byteOffset">The zero-based offset at which the refusal was determined, or zero.</param>
    /// <param name="innerReadError">The re-parse's own refusal, or <see langword="null"/>.</param>
    public XmlSignatureProcessingError(XmlSignatureProcessingFailure failure, long byteOffset, XmlReadError? innerReadError)
    {
        Failure = failure;
        ByteOffset = byteOffset;
        InnerReadError = innerReadError;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlSignatureProcessingError other) =>
        Failure == other.Failure
        && ByteOffset == other.ByteOffset
        && Nullable.Equals(InnerReadError, other.InnerReadError);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlSignatureProcessingError other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => HashCode.Combine(Failure, ByteOffset, InnerReadError);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlSignatureProcessingError left, XmlSignatureProcessingError right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlSignatureProcessingError left, XmlSignatureProcessingError right) => !left.Equals(right);
}
