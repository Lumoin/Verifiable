using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The refusal a XAdES-level processing operation produced: the reason, where it was determined, and — when
/// the refusal surfaced through a sub-operation this leaf reuses rather than reimplements — that
/// sub-operation's own error.
/// </summary>
/// <remarks>
/// XAdES processing is result-shaped: a refusal is reported through this type, never through an exception,
/// the same <see cref="XmlSignatureProcessingError"/> idiom carried forward at the XAdES layer. At most one
/// of <see cref="InnerReadError"/>, <see cref="InnerProcessingError"/> and
/// <see cref="InnerQualifyingPropertiesReadError"/> is ever set, and only for the
/// <see cref="XAdESProcessingFailure"/> members whose own doc comments name it —
/// <see cref="XAdESProcessingFailure.MalformedReferenceTarget"/> wraps a structural XMLDSIG read refusal,
/// <see cref="XAdESProcessingFailure.ReferenceProcessingFailed"/>,
/// <see cref="XAdESProcessingFailure.SignedPropertiesReferenceDereferenceFailed"/> and
/// <see cref="XAdESProcessingFailure.MessageImprintReferenceProcessingFailed"/> wrap the XMLDSIG
/// reference-processing/dereferencing engine's own refusal, and
/// <see cref="XAdESProcessingFailure.MalformedQualifyingProperties"/>/
/// <see cref="XAdESProcessingFailure.MalformedQualifyingPropertiesReference"/>/
/// <see cref="XAdESProcessingFailure.CounterSignatureChainMalformedEntry"/> wrap a structural XAdES
/// container read refusal — because the discovery and <c>Include</c>-processing engines sit above all three
/// surfaces and can fail by delegating to any of them.
/// </remarks>
/// <seealso cref="XAdESProcessingFailure"/>
public readonly struct XAdESProcessingError: IEquatable<XAdESProcessingError>
{
    /// <summary>
    /// The reason the processing operation was refused.
    /// </summary>
    public XAdESProcessingFailure Failure { get; }

    /// <summary>
    /// The zero-based offset at which the refusal was determined; zero when the refusal is a property of the
    /// whole operation rather than one position.
    /// </summary>
    public long ByteOffset { get; }

    /// <summary>
    /// The structural read refusal <see cref="XAdESProcessingFailure.MalformedReferenceTarget"/> wraps;
    /// <see langword="null"/> for every other reason.
    /// </summary>
    public XmlSignatureReadError? InnerReadError { get; }

    /// <summary>
    /// The XMLDSIG reference-processing/dereferencing engine's own refusal
    /// <see cref="XAdESProcessingFailure.ReferenceProcessingFailed"/>,
    /// <see cref="XAdESProcessingFailure.SignedPropertiesReferenceDereferenceFailed"/> and
    /// <see cref="XAdESProcessingFailure.MessageImprintReferenceProcessingFailed"/> wrap;
    /// <see langword="null"/> for every other reason.
    /// </summary>
    public XmlSignatureProcessingError? InnerProcessingError { get; }

    /// <summary>
    /// The structural XAdES container read refusal
    /// <see cref="XAdESProcessingFailure.MalformedQualifyingProperties"/> and
    /// <see cref="XAdESProcessingFailure.MalformedQualifyingPropertiesReference"/> wrap;
    /// <see langword="null"/> for every other reason.
    /// </summary>
    public XAdESReadError? InnerQualifyingPropertiesReadError { get; }


    /// <summary>
    /// Creates a processing error with no inner error.
    /// </summary>
    /// <param name="failure">The reason the processing operation was refused.</param>
    /// <param name="byteOffset">The zero-based offset at which the refusal was determined, or zero.</param>
    public XAdESProcessingError(XAdESProcessingFailure failure, long byteOffset)
        : this(failure, byteOffset, innerReadError: null, innerProcessingError: null, innerQualifyingPropertiesReadError: null)
    {
    }


    /// <summary>
    /// Creates a processing error carrying the structural XMLDSIG read refusal that produced it.
    /// </summary>
    /// <param name="failure">The reason the processing operation was refused.</param>
    /// <param name="byteOffset">The zero-based offset at which the refusal was determined, or zero.</param>
    /// <param name="innerReadError">The structural read's own refusal.</param>
    public XAdESProcessingError(XAdESProcessingFailure failure, long byteOffset, XmlSignatureReadError innerReadError)
        : this(failure, byteOffset, innerReadError, innerProcessingError: null, innerQualifyingPropertiesReadError: null)
    {
    }


    /// <summary>
    /// Creates a processing error carrying the reference-processing/dereferencing engine refusal that produced it.
    /// </summary>
    /// <param name="failure">The reason the processing operation was refused.</param>
    /// <param name="byteOffset">The zero-based offset at which the refusal was determined, or zero.</param>
    /// <param name="innerProcessingError">The reference-processing/dereferencing engine's own refusal.</param>
    public XAdESProcessingError(XAdESProcessingFailure failure, long byteOffset, XmlSignatureProcessingError innerProcessingError)
        : this(failure, byteOffset, innerReadError: null, innerProcessingError, innerQualifyingPropertiesReadError: null)
    {
    }


    /// <summary>
    /// Creates a processing error carrying the structural XAdES container read refusal that produced it.
    /// </summary>
    /// <param name="failure">The reason the processing operation was refused.</param>
    /// <param name="byteOffset">The zero-based offset at which the refusal was determined, or zero.</param>
    /// <param name="innerQualifyingPropertiesReadError">The container read's own refusal.</param>
    public XAdESProcessingError(XAdESProcessingFailure failure, long byteOffset, XAdESReadError innerQualifyingPropertiesReadError)
        : this(failure, byteOffset, innerReadError: null, innerProcessingError: null, innerQualifyingPropertiesReadError)
    {
    }


    private XAdESProcessingError(
        XAdESProcessingFailure failure,
        long byteOffset,
        XmlSignatureReadError? innerReadError,
        XmlSignatureProcessingError? innerProcessingError,
        XAdESReadError? innerQualifyingPropertiesReadError)
    {
        Failure = failure;
        ByteOffset = byteOffset;
        InnerReadError = innerReadError;
        InnerProcessingError = innerProcessingError;
        InnerQualifyingPropertiesReadError = innerQualifyingPropertiesReadError;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESProcessingError other) =>
        Failure == other.Failure
        && ByteOffset == other.ByteOffset
        && Nullable.Equals(InnerReadError, other.InnerReadError)
        && Nullable.Equals(InnerProcessingError, other.InnerProcessingError)
        && Nullable.Equals(InnerQualifyingPropertiesReadError, other.InnerQualifyingPropertiesReadError);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESProcessingError other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => HashCode.Combine(Failure, ByteOffset, InnerReadError, InnerProcessingError, InnerQualifyingPropertiesReadError);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESProcessingError left, XAdESProcessingError right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESProcessingError left, XAdESProcessingError right) => !left.Equals(right);
}
