using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// Which family of clause 5.4 validation-data properties one of Annex A.1.1/A.1.2/A.1.3/A.1.4's own closing
/// conditional-<c>shall</c> paragraphs gates on: <see cref="Certificate"/> for <c>CompleteCertificateRefsV2</c>
/// (A.1.1) and <c>AttributeCertificateRefsV2</c> (A.1.3), or <see cref="Revocation"/> for
/// <c>CompleteRevocationRefs</c> (A.1.2) and <c>AttributeRevocationRefs</c> (A.1.4).
/// </summary>
public enum XAdESValidationDataFamily
{
    /// <summary>Gates on <c>CertificateValues</c>, <c>AttrAuthoritiesCertValues</c>, and <c>AnyValidationData</c>'s <c>CertificateValues</c> child.</summary>
    Certificate,

    /// <summary>Gates on <c>RevocationValues</c>, <c>AttributeRevocationValues</c>, and <c>AnyValidationData</c>'s <c>RevocationValues</c> child.</summary>
    Revocation
}


/// <summary>
/// The structural half of one Annex A "if at least one of ... is incorporated into the signature ... shall be
/// present elsewhere in the signature" closing conditional (A.1.1/A.1.3 for certificates, A.1.2/A.1.4 for
/// revocation data): which of the paragraph's four alternative trigger conditions hold, computed from
/// structure alone. <see cref="IsTriggered"/> is the paragraph's own "if at least one of" disjunction.
/// </summary>
/// <remarks>
/// Matching each certificate/revocation-data reference the *Refs property names against its actual value
/// elsewhere in the signature — the paragraph's own consequent — needs digest computation over decoded DER
/// content, crypto this leaf never performs. <see cref="XAdESValidationDataTrigger.TryDetermine"/>
/// delivers only the antecedent (this type); <c>Verifiable.Cryptography.Pki.XAdESLevelRules.CheckReferencesResolveToValidationDataAsync</c>
/// composes with it above the leaf, adding nothing structural of its own.
/// </remarks>
public readonly struct XAdESValidationDataTriggerResult: IEquatable<XAdESValidationDataTriggerResult>
{
    /// <summary>Whether the plain values property (<c>CertificateValues</c>/<c>RevocationValues</c>) is incorporated at least once.</summary>
    public bool HasValuesProperty { get; }

    /// <summary>Whether the attribute-certificate values property (<c>AttrAuthoritiesCertValues</c>/<c>AttributeRevocationValues</c>) is incorporated at least once.</summary>
    public bool HasAttributeValuesProperty { get; }

    /// <summary>
    /// Whether at least one <c>AnyValidationData</c> instance is incorporated whose matching child
    /// (<c>CertificateValues</c> or <c>RevocationValues</c>, per the <see cref="XAdESValidationDataFamily"/>
    /// <see cref="XAdESValidationDataTrigger.TryDetermine"/> was called with) is present AND structurally
    /// non-empty — Annex A's own "with a non empty <c>CertificateValues</c> child element" qualifier,
    /// checked at the immediate-child level (at least one element child of the matching child), never by
    /// decoding its content.
    /// </summary>
    public bool HasNonEmptyAnyValidationDataChild { get; }

    /// <summary>Whether at least one v1.4.1-namespace <c>ArchiveTimeStamp</c> is incorporated.</summary>
    public bool HasArchiveTimeStamp { get; }

    /// <summary>
    /// The closing paragraph's own "if at least one of [...]" disjunction: <see langword="true"/> when any of
    /// the four trigger conditions holds.
    /// </summary>
    public bool IsTriggered => HasValuesProperty || HasAttributeValuesProperty || HasNonEmptyAnyValidationDataChild || HasArchiveTimeStamp;


    internal XAdESValidationDataTriggerResult(bool hasValuesProperty, bool hasAttributeValuesProperty, bool hasNonEmptyAnyValidationDataChild, bool hasArchiveTimeStamp)
    {
        HasValuesProperty = hasValuesProperty;
        HasAttributeValuesProperty = hasAttributeValuesProperty;
        HasNonEmptyAnyValidationDataChild = hasNonEmptyAnyValidationDataChild;
        HasArchiveTimeStamp = hasArchiveTimeStamp;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESValidationDataTriggerResult other) =>
        HasValuesProperty == other.HasValuesProperty
        && HasAttributeValuesProperty == other.HasAttributeValuesProperty
        && HasNonEmptyAnyValidationDataChild == other.HasNonEmptyAnyValidationDataChild
        && HasArchiveTimeStamp == other.HasArchiveTimeStamp;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESValidationDataTriggerResult other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => HashCode.Combine(HasValuesProperty, HasAttributeValuesProperty, HasNonEmptyAnyValidationDataChild, HasArchiveTimeStamp);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESValidationDataTriggerResult left, XAdESValidationDataTriggerResult right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESValidationDataTriggerResult left, XAdESValidationDataTriggerResult right) => !left.Equals(right);
}


/// <summary>
/// Determines the structural half of Annex A.1.1/A.1.2/A.1.3/A.1.4's closing conditional-<c>shall</c>
/// paragraph — see <see cref="XAdESValidationDataTriggerResult"/>'s own remarks for the crypto-side half
/// <c>Verifiable.Cryptography.Pki.XAdESLevelRules.CheckReferencesResolveToValidationDataAsync</c> performs
/// above this leaf.
/// </summary>
public static class XAdESValidationDataTrigger
{
    private enum TriggerSignal
    {
        None,
        ValuesProperty,
        AttributeValuesProperty,
        UnrecognizedCandidate
    }


    /// <summary>
    /// Walks an already-read <c>UnsignedSignatureProperties</c> entry list and reports which of the closing
    /// paragraph's four trigger conditions hold for the given <paramref name="family"/>.
    /// </summary>
    /// <param name="table">The document <paramref name="unsignedSignatureProperties"/> was read from.</param>
    /// <param name="unsignedSignatureProperties">The already-read <c>UnsignedSignatureProperties</c> container
    /// whose entries are inspected; every entry is visited once, so multiple instances of any trigger
    /// property (legal — clause 4.3.6's own content model repeats freely) are all accounted for.</param>
    /// <param name="family">Which closing paragraph's trigger set to check — certificates or revocation data.</param>
    /// <param name="result">The trigger fact on success.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> is not the identical
    /// instance <paramref name="unsignedSignatureProperties"/> was read from.</param>
    /// <returns><see langword="true"/> when the trigger fact was determined — this engine never refuses over
    /// document content, only over a caller-supplied table mismatch.</returns>
    public static bool TryDetermine(
        XmlNodeTable table,
        XAdESUnsignedSignatureProperties unsignedSignatureProperties,
        XAdESValidationDataFamily family,
        out XAdESValidationDataTriggerResult result,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        result = default;
        if(!ReferenceEquals(unsignedSignatureProperties.Table, table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        bool hasValuesProperty = false;
        bool hasAttributeValuesProperty = false;
        bool hasNonEmptyAnyValidationDataChild = false;
        bool hasArchiveTimeStamp = false;
        ReadOnlySpan<byte> matchingChildLocalName = family == XAdESValidationDataFamily.Certificate ? "CertificateValues"u8 : "RevocationValues"u8;

        for(int i = 0; i < unsignedSignatureProperties.Properties.Count; ++i)
        {
            XAdESUnsignedSignaturePropertyEntry entry = unsignedSignatureProperties.Properties[i];
            _ = Classify(entry.Name, family) switch
            {
                TriggerSignal.ValuesProperty => hasValuesProperty = true,
                TriggerSignal.AttributeValuesProperty => hasAttributeValuesProperty = true,
                //The innermost arm is kept as "condition ? flag = true : false" rather than the
                //algebraically equivalent "condition && (flag = true)": the ternary keeps the assignment
                //visible as its own branch rather than folding it into a boolean operand.
                TriggerSignal.UnrecognizedCandidate => XmlSignatureModelGrammar.IsElement(table, entry.ElementIndex, XAdESIdentifiers.XAdESNamespaceV141Utf8, "ArchiveTimeStamp"u8)
                    ? hasArchiveTimeStamp = true
                    : XmlSignatureModelGrammar.IsElement(table, entry.ElementIndex, XAdESIdentifiers.XAdESNamespaceV141Utf8, "AnyValidationData"u8)
                        && HasNonEmptyMatchingChild(table, entry.ElementIndex, matchingChildLocalName)
                        ? hasNonEmptyAnyValidationDataChild = true
                        : false,
                _ => false
            };
        }

        result = new XAdESValidationDataTriggerResult(hasValuesProperty, hasAttributeValuesProperty, hasNonEmptyAnyValidationDataChild, hasArchiveTimeStamp);
        error = default;

        return true;
    }


    private static TriggerSignal Classify(XAdESUnsignedSignaturePropertyName name, XAdESValidationDataFamily family) => (name, family) switch
    {
        (XAdESUnsignedSignaturePropertyName.CertificateValues, XAdESValidationDataFamily.Certificate) => TriggerSignal.ValuesProperty,
        (XAdESUnsignedSignaturePropertyName.AttrAuthoritiesCertValues, XAdESValidationDataFamily.Certificate) => TriggerSignal.AttributeValuesProperty,
        (XAdESUnsignedSignaturePropertyName.RevocationValues, XAdESValidationDataFamily.Revocation) => TriggerSignal.ValuesProperty,
        (XAdESUnsignedSignaturePropertyName.AttributeRevocationValues, XAdESValidationDataFamily.Revocation) => TriggerSignal.AttributeValuesProperty,
        (XAdESUnsignedSignaturePropertyName.Unrecognized, _) => TriggerSignal.UnrecognizedCandidate,
        _ => TriggerSignal.None
    };


    /// <summary>
    /// Tells whether <paramref name="parentElementIndex"/> (an <c>AnyValidationData</c> element) has a child
    /// named <paramref name="childLocalName"/> (v1.3.2 namespace) that itself carries at least one element
    /// child — the structural notion of "non empty" this engine applies, never a full decode of the child's
    /// content (<c>CertificateValues</c>'s entries are the <c>EncapsulatedX509Certificate</c>/
    /// <c>OtherCertificate</c> choice, <c>RevocationValues</c>'s are its own three sub-lists — either way, at
    /// least one element child is present exactly when the property is non-empty). Malformed content at or
    /// under the candidate child (a text node where only elements are permitted) is reported as "not found"
    /// here rather than refused — this engine's own fact-shaped, never-refuses-over-content posture, matching
    /// <see cref="XAdESTimeStampValidationDataPlacement"/>'s.
    /// </summary>
    private static bool HasNonEmptyMatchingChild(XmlNodeTable table, int parentElementIndex, ReadOnlySpan<byte> childLocalName)
    {
        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, parentElementIndex, out int child);
        while(scan == ElementScanResult.Found)
        {
            if(XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, childLocalName))
            {
                return XmlSignatureModelGrammar.TryFindFirstElementChild(table, child, out _) == ElementScanResult.Found;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
        }

        return false;
    }
}
