using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The refusal an XML reading operation produced: the reason and where in the document octets it was
/// determined.
/// </summary>
/// <remarks>
/// Reading is result-shaped: refused input is reported through this type, never through an exception. The
/// offset makes a refusal actionable — for a UTF-8 document it names the position in the input octets at
/// which the <see cref="XmlReadFailure"/> was established. For a UTF-16 document, refusals from the
/// encoding front end name the position in the input octets, while refusals established after the single
/// transcoding step name the position in the document's once-transcoded UTF-8 form.
/// </remarks>
/// <seealso cref="XmlReadFailure"/>
public readonly struct XmlReadError: IEquatable<XmlReadError>
{
    /// <summary>
    /// The reason the document was refused.
    /// </summary>
    public XmlReadFailure Failure { get; }

    /// <summary>
    /// The zero-based offset into the document octets at which the refusal was determined.
    /// </summary>
    public long ByteOffset { get; }


    /// <summary>
    /// Creates a read error.
    /// </summary>
    /// <param name="failure">The reason the document was refused.</param>
    /// <param name="byteOffset">The zero-based offset into the document octets at which the refusal was determined.</param>
    public XmlReadError(XmlReadFailure failure, long byteOffset)
    {
        Failure = failure;
        ByteOffset = byteOffset;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlReadError other) => Failure == other.Failure && ByteOffset == other.ByteOffset;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlReadError other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => HashCode.Combine(Failure, ByteOffset);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlReadError left, XmlReadError right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlReadError left, XmlReadError right) => !left.Equals(right);
}
