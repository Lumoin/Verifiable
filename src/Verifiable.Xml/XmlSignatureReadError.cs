using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The refusal a <c>ds:Signature</c> structural read produced: the reason and where in the document octets
/// it was determined.
/// </summary>
/// <remarks>
/// Reading is result-shaped: refused input is reported through this type, never through an exception. The
/// offset names the position in the document octets — the same octets an <see cref="XmlNodeTable"/> was
/// parsed from — at which the <see cref="XmlSignatureReadFailure"/> was established, the
/// <see cref="XmlReadError"/> idiom carried forward for the structural signature model.
/// </remarks>
/// <seealso cref="XmlSignatureReadFailure"/>
public readonly struct XmlSignatureReadError: IEquatable<XmlSignatureReadError>
{
    /// <summary>
    /// The reason the structural read was refused.
    /// </summary>
    public XmlSignatureReadFailure Failure { get; }

    /// <summary>
    /// The zero-based offset into the document octets at which the refusal was determined.
    /// </summary>
    public long ByteOffset { get; }


    /// <summary>
    /// Creates a structural read error.
    /// </summary>
    /// <param name="failure">The reason the structural read was refused.</param>
    /// <param name="byteOffset">The zero-based offset into the document octets at which the refusal was determined.</param>
    public XmlSignatureReadError(XmlSignatureReadFailure failure, long byteOffset)
    {
        Failure = failure;
        ByteOffset = byteOffset;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlSignatureReadError other) => Failure == other.Failure && ByteOffset == other.ByteOffset;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlSignatureReadError other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => HashCode.Combine(Failure, ByteOffset);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlSignatureReadError left, XmlSignatureReadError right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlSignatureReadError left, XmlSignatureReadError right) => !left.Equals(right);
}
