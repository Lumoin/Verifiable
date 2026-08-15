using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The <c>SigningTime</c> qualifying property of clause 5.2.1: a signed qualifying property whose whole
/// content is one <c>xsd:dateTime</c> value — "the time at which the signer claims to having performed the
/// signing process," a signer-side claim distinct from <c>SignatureTimeStamp</c>'s independent, TSA-issued
/// proof (clause 5.3). The acquired v132 XSD declares it as a bare typed element with no complex type of its
/// own: <c>&lt;xsd:element name="SigningTime" type="xsd:dateTime"/&gt;</c>.
/// </summary>
/// <remarks>
/// Carries no owned pooled content of its own — <see cref="Value"/> is a plain, self-contained
/// <see cref="XAdESDateTime"/> — so no <see cref="IDisposable"/> surface is needed, the same posture
/// <see cref="XAdESObjectIdentifier"/> takes.
/// </remarks>
public readonly struct XAdESSigningTime: IEquatable<XAdESSigningTime>
{
    /// <summary>The table the value reads from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>SigningTime</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>The parsed <c>xsd:dateTime</c> value.</summary>
    public XAdESDateTime Value { get; }


    private XAdESSigningTime(XmlNodeTable table, int elementIndex, XAdESDateTime value)
    {
        Table = table;
        ElementIndex = elementIndex;
        Value = value;
    }


    /// <summary>
    /// Reads a <c>SigningTime</c> element: no attributes, and simple content matching the strict
    /// <c>xsd:dateTime</c> lexical grammar per <see cref="XAdESDateTime.TryParse"/>.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>SigningTime</c> element — typically obtained from a
    /// <see cref="XAdESSignedSignaturePropertyEntry"/> whose <see cref="XAdESSignedSignaturePropertyEntry.Name"/>
    /// is <see cref="XAdESSignedSignaturePropertyName.SigningTime"/>.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.UnknownCoreAttribute"/> for any attribute (the type declares none);
    /// <see cref="XAdESReadFailure.UnexpectedElementContent"/> for an element child or split simple content;
    /// <see cref="XAdESReadFailure.InvalidDateTimeLexicalForm"/> when the content — including empty content —
    /// does not match the <c>xsd:dateTime</c> lexical grammar.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESSigningTime value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        value = default;
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, elementIndex, out int textNodeIndex, out grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ReadOnlySpan<byte> content = textNodeIndex >= 0 ? table.ValueOf(textNodeIndex) : ReadOnlySpan<byte>.Empty;
        if(!XAdESDateTime.TryParse(content, out XAdESDateTime dateTime))
        {
            error = new XAdESReadError(XAdESReadFailure.InvalidDateTimeLexicalForm, 0);

            return false;
        }

        value = new XAdESSigningTime(table, elementIndex, dateTime);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESSigningTime other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESSigningTime other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESSigningTime left, XAdESSigningTime right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESSigningTime left, XAdESSigningTime right) => !left.Equals(right);
}
