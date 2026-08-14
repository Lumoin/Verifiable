using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The refusal a canonicalization operation produced: the reason and the position in the source document
/// octets it concerns.
/// </summary>
/// <remarks>
/// Canonicalization is result-shaped: a refused request is reported through this type, never through an
/// exception. The offset locates the refusal in the document octets the node table was read from; a refusal
/// that is not tied to a document position, such as an invalid prefix-list parameter, carries offset zero.
/// </remarks>
/// <seealso cref="XmlCanonicalizationFailure"/>
public readonly struct XmlCanonicalizationError: IEquatable<XmlCanonicalizationError>
{
    /// <summary>
    /// The reason the canonicalization was refused.
    /// </summary>
    public XmlCanonicalizationFailure Failure { get; }

    /// <summary>
    /// The zero-based offset into the source document octets the refusal concerns, or zero when the refusal
    /// is not tied to a document position.
    /// </summary>
    public long ByteOffset { get; }


    /// <summary>
    /// Creates a canonicalization error.
    /// </summary>
    /// <param name="failure">The reason the canonicalization was refused.</param>
    /// <param name="byteOffset">The zero-based offset into the source document octets the refusal concerns.</param>
    public XmlCanonicalizationError(XmlCanonicalizationFailure failure, long byteOffset)
    {
        Failure = failure;
        ByteOffset = byteOffset;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlCanonicalizationError other) => Failure == other.Failure && ByteOffset == other.ByteOffset;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlCanonicalizationError other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => HashCode.Combine(Failure, ByteOffset);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlCanonicalizationError left, XmlCanonicalizationError right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlCanonicalizationError left, XmlCanonicalizationError right) => !left.Equals(right);
}
