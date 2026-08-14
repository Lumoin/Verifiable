namespace Verifiable.Xml;

/// <summary>
/// The shared <c>ObjectReference</c> resolution clauses 5.2.3 (<c>CommitmentTypeIndication</c>) and 5.2.4
/// (<c>DataObjectFormat</c>) both state in near-identical wording: an <c>anyURI</c> value that "shall
/// reference one <c>ds:Reference</c> element within the <c>ds:SignedInfo</c> element or within a signed
/// <c>ds:Manifest</c> element" — bare-name (shortname) XPointer dereference to a <c>ds:Reference</c>'s own
/// <c>Id</c>, per the same mechanism <see cref="XAdESQualifyingPropertiesDiscovery.TryVerifyTargetBinding"/>
/// and <see cref="XAdESIncludeUriProcessing"/> already use for their own bare-name resolutions.
/// </summary>
internal static class XAdESObjectReferenceResolution
{
    /// <summary>
    /// Resolves an <c>ObjectReference</c> value to the <c>ds:Reference</c> element it identifies.
    /// </summary>
    /// <param name="table">The document <paramref name="signature"/> was read from.</param>
    /// <param name="signature">The signature whose <c>ds:SignedInfo</c>/signed <c>ds:Manifest</c>s the target must be within.</param>
    /// <param name="objectReferenceUri">The <c>ObjectReference</c> value: an <c>anyURI</c> expected to be a bare-name XPointer.</param>
    /// <param name="referenceElementIndex">The identified <c>ds:Reference</c> element's own index on success.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.UnsupportedObjectReferenceUriForm"/> when the value carries no
    /// <c>#</c> or its fragment is not a well-formed <c>NCName</c>;
    /// <see cref="XAdESProcessingFailure.ObjectReferenceTargetIdNotFound"/>/
    /// <see cref="XAdESProcessingFailure.DuplicateObjectReferenceTargetId"/> when the fragment names zero or
    /// more than one <c>Id</c>-typed attribute value;
    /// <see cref="XAdESProcessingFailure.ObjectReferenceTargetNotReference"/> when the identified element is
    /// not a <c>ds:Reference</c>;
    /// <see cref="XAdESProcessingFailure.ObjectReferenceNotWithinSignedInfoOrSignedManifest"/> when it is a
    /// <c>ds:Reference</c> but neither a direct child of <c>ds:SignedInfo</c> nor of a signed
    /// <c>ds:Manifest</c>.</param>
    /// <returns><see langword="true"/> when the target resolved and passed the containment check.</returns>
    internal static bool TryResolve(XmlNodeTable table, XmlSignature signature, ReadOnlySpan<byte> objectReferenceUri, out int referenceElementIndex, out XAdESProcessingError error)
    {
        referenceElementIndex = -1;
        if(objectReferenceUri.IsEmpty || objectReferenceUri[0] != (byte)'#')
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.UnsupportedObjectReferenceUriForm, 0);

            return false;
        }

        ReadOnlySpan<byte> fragment = objectReferenceUri[1..];
        if(!XmlReferenceDereferencer.IsNcNameFragment(fragment))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.UnsupportedObjectReferenceUriForm, 0);

            return false;
        }

        if(!table.TryFindElementById(fragment, out int targetElementIndex, out XmlSignatureProcessingError idError))
        {
            error = new XAdESProcessingError(
                idError.Failure == XmlSignatureProcessingFailure.DuplicateId ? XAdESProcessingFailure.DuplicateObjectReferenceTargetId : XAdESProcessingFailure.ObjectReferenceTargetIdNotFound, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.IsDsElement(table, targetElementIndex, "Reference"u8))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.ObjectReferenceTargetNotReference, 0);

            return false;
        }

        if(!IsWithinSignedInfoOrSignedManifest(table, signature, targetElementIndex))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.ObjectReferenceNotWithinSignedInfoOrSignedManifest, 0);

            return false;
        }

        referenceElementIndex = targetElementIndex;
        error = default;

        return true;
    }


    /// <summary>
    /// Tells whether a <c>ds:Reference</c> element is a direct child of <paramref name="signature"/>'s own
    /// <c>ds:SignedInfo</c> or of a <c>ds:Manifest</c> that is itself signed — the shared two-way allowlist
    /// clauses 5.2.3/5.2.4's "within the <c>ds:SignedInfo</c> element or within a signed <c>ds:Manifest</c>
    /// element" wording states, and clause 5.2.8.2 step 2 states identically for
    /// <c>IndividualDataObjectsTimeStamp</c>'s own <c>Include</c>-selected <c>ds:Reference</c> set
    /// (<see cref="XAdESIndividualDataObjectsTimeStampImprint"/>).
    /// </summary>
    internal static bool IsWithinSignedInfoOrSignedManifest(XmlNodeTable table, XmlSignature signature, int referenceElementIndex)
    {
        int parentElementIndex = table.ParentOf(referenceElementIndex);
        bool isWithinSignedInfo = parentElementIndex == signature.SignedInfo.ElementIndex;
        bool isWithinSignedManifest = !isWithinSignedInfo
            && XmlSignatureModelGrammar.IsDsElement(table, parentElementIndex, "Manifest"u8)
            && IsManifestSignedBySignedInfo(table, signature, parentElementIndex);

        return isWithinSignedInfo || isWithinSignedManifest;
    }


    /// <summary>
    /// Tells whether a <c>ds:Manifest</c> is "signed" in the sense clauses 5.2.3/5.2.4 rely on: directly
    /// referenced, by bare-name XPointer, from some <c>ds:Reference</c> within the signature's own
    /// <c>ds:SignedInfo</c> — so that manifest's digest is checked as part of core signature validation, per
    /// XMLDSIG section 5.1.
    /// </summary>
    private static bool IsManifestSignedBySignedInfo(XmlNodeTable table, XmlSignature signature, int manifestElementIndex)
    {
        foreach(XmlReference reference in signature.SignedInfo.References)
        {
            if(!reference.HasUri)
            {
                continue;
            }

            ReadOnlySpan<byte> uri = reference.Uri;
            if(uri.IsEmpty || uri[0] != (byte)'#')
            {
                continue;
            }

            ReadOnlySpan<byte> fragment = uri[1..];
            if(!XmlReferenceDereferencer.IsNcNameFragment(fragment))
            {
                continue;
            }

            if(table.TryFindElementById(fragment, out int candidateElementIndex, out _) && candidateElementIndex == manifestElementIndex)
            {
                return true;
            }
        }

        return false;
    }
}
