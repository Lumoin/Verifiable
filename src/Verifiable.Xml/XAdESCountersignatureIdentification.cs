namespace Verifiable.Xml;

/// <summary>
/// The clause 5.2.7.1 detached-countersignature identification convention: a <c>ds:Reference</c> whose
/// <c>Type</c> attribute equals <see cref="XAdESIdentifiers.CountersignedSignatureTypeUri"/> marks its
/// OWNING signature as a countersignature of whatever signature that reference's own <c>URI</c> dereferences
/// to. Clause 5.2.7.1's own wording — "A XAdES signature containing a <c>ds:Reference</c> element whose
/// <c>Type</c> attribute has this value shall indicate that it is a countersignature of the signature
/// referenced by this element" — is a reading obligation on the marker's MEANING, not a generation obligation
/// that every countersignature carry one (5.2.7.2's <c>CounterSignature</c> qualifying property is a wholly
/// independent, mandatory-content mechanism that needs no <c>Type</c> marker at all). This type is therefore a
/// pure fact recognizer: it asserts nothing about digest correctness, dereference success, or trust —
/// "All the XMLDSIG rules shall apply in the processing of the aforementioned <c>ds:Reference</c> element"
/// keeps that entirely XMLDSIG's own reference-processing concern, unaffected by recognizing the marker.
/// </summary>
public static class XAdESCountersignatureIdentification
{
    /// <summary>
    /// Tells whether a single <c>ds:Reference</c> carries the clause 5.2.7.1 countersignature identifier.
    /// </summary>
    /// <param name="reference">The reference to test.</param>
    /// <returns><see langword="true"/> when <paramref name="reference"/>'s <c>Type</c> attribute is present
    /// and equals <see cref="XAdESIdentifiers.CountersignedSignatureTypeUri"/>, exact-character.</returns>
    public static bool IsCountersignatureReference(XmlReference reference)
    {
        return reference.HasType && reference.Type.SequenceEqual(XAdESIdentifiers.CountersignedSignatureTypeUriUtf8);
    }


    /// <summary>
    /// Tells whether a signature is, per clause 5.2.7.1's convention, itself a countersignature: carrying at
    /// least one <c>ds:Reference</c> within its own <c>ds:SignedInfo</c> that identifies the signature it
    /// countersigns.
    /// </summary>
    /// <param name="signature">The signature to inspect.</param>
    /// <returns><see langword="true"/> when at least one of <paramref name="signature"/>'s own
    /// <c>ds:SignedInfo</c> references carries the marker.</returns>
    public static bool IsCountersignature(XmlSignature signature)
    {
        ArgumentNullException.ThrowIfNull(signature);
        foreach(XmlReference reference in signature.SignedInfo.References)
        {
            if(IsCountersignatureReference(reference))
            {
                return true;
            }
        }

        return false;
    }
}
