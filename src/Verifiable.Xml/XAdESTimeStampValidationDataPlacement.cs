namespace Verifiable.Xml;

/// <summary>
/// The outcome clause 5.5.1.2's placement/<c>URI</c> protocol resolves to when checking whether one already-
/// read <c>TimeStampValidationData</c> instance is bound to one specific candidate time-stamp-container element
/// (<c>SignatureTimeStamp</c>/<c>RefsOnlyTimeStampV2</c>/<c>SigAndRefsTimeStampV2</c>/<c>ArchiveTimeStamp</c>
/// under Case A, or <c>IndividualDataObjectsTimeStamp</c>/<c>AllDataObjectsTimeStamp</c> under Case B — the
/// clause's own printed "<c>AllDataObjectTimeStamp</c>" singular names the plural clause
/// 5.2.8.1 property, honored here, <see cref="XAdESAllDataObjectsTimeStamp"/>).
/// </summary>
public enum XAdESTimeStampValidationDataBindingDisposition
{
    /// <summary>
    /// Neither adjacency nor a matching <c>URI</c> binds this <c>TimeStampValidationData</c> to the candidate.
    /// Clause 5.5.1.2's validation-time rule: the application shall ignore whatever <c>URI</c> value is present
    /// (or its absence) and MAY still attempt to use the validation material by other means — this is a fact
    /// about ONE candidate, never a refusal; a caller checks every candidate it holds in turn.
    /// </summary>
    NotBound,

    /// <summary>
    /// Case A only: this <c>TimeStampValidationData</c> is the entry immediately following the candidate within
    /// <c>UnsignedSignatureProperties</c> — the binding holds by adjacency alone. Clause 5.5.1.2's validation-time
    /// rule for this shape makes a present, non-matching <c>URI</c> value IGNORED, never a refusal, so this
    /// disposition is returned regardless of what (if anything) <c>URI</c> carries.
    /// </summary>
    BoundByAdjacency,

    /// <summary>
    /// <c>URI</c> is present, a same-document bare-name reference, and resolves to the candidate exactly — the
    /// binding both cases share once adjacency does not already establish it (Case A non-adjacent; Case B
    /// unconditionally, since its target never lives inside <c>UnsignedSignatureProperties</c> and so can never
    /// be adjacent in the sense <see cref="BoundByAdjacency"/> checks).
    /// </summary>
    BoundByUri
}


/// <summary>
/// The clause 5.5.1.2 "Use of <c>URI</c> attribute" placement/binding protocol: given one already-read
/// <c>TimeStampValidationData</c> instance, its position within the discovered <c>UnsignedSignatureProperties</c>
/// entry list (order preserved end-to-end from the container read), and one candidate time-stamp-container
/// element, determines which of Case A's adjacency shortcut or the <c>URI</c>-reference rule — shared,
/// mechanically, by Case A's non-adjacent branch and Case B — binds them, or that neither does. Every outcome is
/// a fact (<see cref="XAdESTimeStampValidationDataBindingDisposition"/>), never a refusal: clause 5.5.1.2 itself
/// states the "shall ignore" outcome for a non-matching or absent <c>URI</c>, so this engine reports it as data
/// rather than as an <see cref="XAdESProcessingError"/>. Only a caller-supplied table mismatch refuses.
/// </summary>
public static class XAdESTimeStampValidationDataPlacement
{
    /// <summary>
    /// Determines the clause 5.5.1.2 binding disposition of one <c>TimeStampValidationData</c> instance against
    /// one candidate time-stamp-container element.
    /// </summary>
    /// <param name="table">The document every table-scoped argument was read from.</param>
    /// <param name="unsignedSignatureProperties">
    /// <paramref name="timeStampValidationData"/>'s own owning <c>UnsignedSignatureProperties</c> — Case A
    /// adjacency is computed against its own <see cref="XAdESUnsignedSignatureProperties.Properties"/> document
    /// order (the XA-4.3.6-3 <c>xsd:choice maxOccurs="unbounded"</c> content model preserves it end-to-end).
    /// </param>
    /// <param name="timeStampValidationDataOrdinal">
    /// <paramref name="timeStampValidationData"/>'s own position within
    /// <paramref name="unsignedSignatureProperties"/>'s <see cref="XAdESUnsignedSignatureProperties.Properties"/> —
    /// the caller's own discovery already knows this, since it is how the value was located in the first place.
    /// </param>
    /// <param name="timeStampValidationData">The already-read <c>TimeStampValidationData</c> instance to check.</param>
    /// <param name="candidateElementIndex">
    /// The specific time-stamp-container element instance under validation — one of
    /// <c>SignatureTimeStamp</c>/<c>RefsOnlyTimeStampV2</c>/<c>SigAndRefsTimeStampV2</c>/<c>ArchiveTimeStamp</c>
    /// (Case A, a sibling entry of <paramref name="unsignedSignatureProperties"/>) or
    /// <c>IndividualDataObjectsTimeStamp</c>/<c>AllDataObjectsTimeStamp</c> (Case B, elsewhere in the document,
    /// under <c>SignedDataObjectProperties</c>) — the caller identifies which by the candidate's own element
    /// identity before calling; this engine needs only its index.
    /// </param>
    /// <param name="disposition">The binding disposition on success.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match
    /// <paramref name="timeStampValidationData"/>'s own table or <paramref name="unsignedSignatureProperties"/>'s
    /// own table — the identity guard, extended to every table-scoped argument here rather than
    /// only the value type that happens to carry a settable <c>Table</c> field.</param>
    /// <returns><see langword="true"/> when the disposition was determined — this engine never refuses over
    /// document content, only over a caller-supplied table mismatch; every other input combination yields a
    /// disposition, per this clause's own fact-shaped ignore semantics.</returns>
    public static bool TryDetermineBinding(
        XmlNodeTable table,
        XAdESUnsignedSignatureProperties unsignedSignatureProperties,
        int timeStampValidationDataOrdinal,
        XAdESValidationData timeStampValidationData,
        int candidateElementIndex,
        out XAdESTimeStampValidationDataBindingDisposition disposition,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(timeStampValidationData);
        disposition = default;
        if(!ReferenceEquals(timeStampValidationData.Table, table) || !ReferenceEquals(unsignedSignatureProperties.Table, table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        ArgumentOutOfRangeException.ThrowIfNegative(timeStampValidationDataOrdinal);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(timeStampValidationDataOrdinal, unsignedSignatureProperties.Properties.Count);

        if(timeStampValidationDataOrdinal > 0 && unsignedSignatureProperties.Properties[timeStampValidationDataOrdinal - 1].ElementIndex == candidateElementIndex)
        {
            disposition = XAdESTimeStampValidationDataBindingDisposition.BoundByAdjacency;
            error = default;

            return true;
        }

        if(timeStampValidationData.HasUri && TryResolveBareNameUri(table, timeStampValidationData.Uri, out int resolvedElementIndex) && resolvedElementIndex == candidateElementIndex)
        {
            disposition = XAdESTimeStampValidationDataBindingDisposition.BoundByUri;
            error = default;

            return true;
        }

        disposition = XAdESTimeStampValidationDataBindingDisposition.NotBound;
        error = default;

        return true;
    }


    /// <summary>
    /// Resolves a <c>URI</c> value as a same-document bare-name (shortname) XPointer, the only form clause
    /// 5.5.1.2 exercises: an ambiguous or unresolvable fragment, or any non-bare-name shape (including a
    /// non-same-document URI), simply does not reference anything this engine can bind to — never a refusal,
    /// per <see cref="XAdESTimeStampValidationDataBindingDisposition.NotBound"/>'s own fact-shaped semantics.
    /// </summary>
    private static bool TryResolveBareNameUri(XmlNodeTable table, ReadOnlySpan<byte> uri, out int elementIndex)
    {
        elementIndex = -1;
        if(uri.IsEmpty || uri[0] != (byte)'#')
        {
            return false;
        }

        ReadOnlySpan<byte> fragment = uri[1..];

        return XmlReferenceDereferencer.IsNcNameFragment(fragment) && table.TryFindElementById(fragment, out elementIndex, out _);
    }
}
