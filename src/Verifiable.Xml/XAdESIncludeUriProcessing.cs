namespace Verifiable.Xml;

/// <summary>
/// The processing model of clause 5.1.4.4.2.2 for an <c>Include</c>'s <c>URI</c> attribute: same-document
/// bare-name (shortname) XPointer dereference only — no other same-document form, and no non-same-document
/// (external) retrieval. This is EXACTLY the shipped machinery
/// <see cref="XmlReferenceDereferencer"/>'s own bare-name path already uses for XMLDSIG same-document
/// references: <see cref="XmlNodeTable.TryFindElementById"/> to locate the element the fragment names
/// (XA-5.1.4.4.2.2-2 step 1: "use as XPointer evaluation context the root node ... and derive a XPath
/// node-set"), then <see cref="XmlNodeSet.ElementSubtree"/> plus <see cref="XmlNodeSet.WithoutComments"/> to
/// produce "E plus all descendants ... and all namespace and attribute nodes ... [with] all comment nodes
/// [deleted]" (XA-5.1.4.4.2.2-2 step 2). No XPath evaluator runs anywhere in this leaf to produce this
/// result — it never needed one, and the XPath-evaluator deferral stands untouched.
/// </summary>
/// <remarks>
/// <c>Include</c>'s own <c>URI</c> rule (XA-5.1.4.4.2.1-4) is narrower than the general XMLDSIG same-document
/// reference: it recognizes ONLY the bare-name form for the same-document case (an empty non-fragment part
/// plus a bare-name fragment) — never the null URI, and never either scheme-based <c>#xpointer(...)</c> form
/// XMLDSIG's own <c>ds:Reference URI</c> additionally permits. A non-empty non-fragment part identifies a
/// non-same-document target, out of this leaf's retrieval scope entirely (no network or filesystem access
/// occurs in this library).
/// </remarks>
internal static class XAdESIncludeUriProcessing
{
    /// <summary>
    /// Retrieves the same-document node-set an <c>Include</c>'s <c>URI</c> attribute identifies.
    /// </summary>
    /// <param name="table">The document the <c>Include</c> element was read from.</param>
    /// <param name="uri">The <c>Include</c>'s <c>URI</c> attribute value, exact-character.</param>
    /// <param name="targetElementIndex">The identified element's own index on success.</param>
    /// <param name="targetNodeSet">The retrieved node-set on success: the identified element, its
    /// descendants, and the attribute and namespace axes of it and its descendants, with comment nodes
    /// deleted.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.NonSameDocumentIncludeUnresolved"/> when <paramref name="uri"/>'s
    /// non-fragment part is non-empty;
    /// <see cref="XAdESProcessingFailure.UnsupportedIncludeUriForm"/> when the same-document fragment is not
    /// a bare-name XPointer;
    /// <see cref="XAdESProcessingFailure.IncludeTargetIdNotFound"/>/<see cref="XAdESProcessingFailure.DuplicateIncludeTargetId"/>
    /// when the fragment names zero or more than one <c>Id</c>-typed attribute value.</param>
    /// <returns><see langword="true"/> when the target retrieved.</returns>
    public static bool TryRetrieve(XmlNodeTable table, ReadOnlySpan<byte> uri, out int targetElementIndex, out XmlNodeSet targetNodeSet, out XAdESProcessingError error)
    {
        targetElementIndex = -1;
        targetNodeSet = default;
        if(uri.IsEmpty)
        {
            //Include's own rule (XA-5.1.4.4.2.1-4) always requires a fragment for the same-document case;
            //the empty URI (XMLDSIG's own "whole document" convention) carries none, so it is malformed for
            //Include specifically rather than a legitimate same-document form.
            error = new XAdESProcessingError(XAdESProcessingFailure.UnsupportedIncludeUriForm, 0);

            return false;
        }

        if(uri[0] != (byte)'#')
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.NonSameDocumentIncludeUnresolved, 0);

            return false;
        }

        ReadOnlySpan<byte> fragment = uri[1..];
        if(!XmlReferenceDereferencer.IsNcNameFragment(fragment))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.UnsupportedIncludeUriForm, 0);

            return false;
        }

        if(!table.TryFindElementById(fragment, out targetElementIndex, out XmlSignatureProcessingError idError))
        {
            error = new XAdESProcessingError(
                idError.Failure == XmlSignatureProcessingFailure.DuplicateId ? XAdESProcessingFailure.DuplicateIncludeTargetId : XAdESProcessingFailure.IncludeTargetIdNotFound,
                0);

            return false;
        }

        targetNodeSet = XmlNodeSet.ElementSubtree(table, targetElementIndex).WithoutComments();
        error = default;

        return true;
    }
}
