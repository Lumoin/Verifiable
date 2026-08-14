namespace Verifiable.Xml;

/// <summary>
/// The clause 5.2.7.2 digest-rule shape check: "The content of this qualifying property shall be a XMLDSIG
/// [1] or XAdES signature whose <c>ds:SignedInfo</c> shall contain one <c>ds:Reference</c> element referencing
/// the <c>ds:SignatureValue</c> element of the embedding and countersigned XAdES signature." This type locates
/// that reference STRUCTURALLY — by dereferencing every same-document, bare-name-XPointer reference of the
/// countersignature's own <c>ds:SignedInfo</c> and testing which one (if any) resolves to the countersigned
/// signature's <see cref="XmlSignature.SignatureValueElementIndex"/> — never by a <c>Type</c> marker (that is
/// clause 5.2.7.1's wholly independent, detached-countersignature convention,
/// <see cref="XAdESCountersignatureIdentification"/>, which 5.2.7.2 needs none of).
/// </summary>
/// <remarks>
/// Crypto-free: this type never digests or compares anything. The digest
/// comparison itself — "the content of the <c>ds:DigestValue</c> in the aforementioned <c>ds:Reference</c>
/// element ... shall be the base-64 encoded digest of the complete (and canonicalized)
/// <c>ds:SignatureValue</c> element" — is the composition root's job: pass the located reference's own ordinal
/// to <see cref="XmlReferenceProcessing.TryComputeDigestInput(XmlNodeTable, XmlSignature, int, XmlReferenceResolver?, Lumoin.Base.BaseMemoryPool, out Verifiable.Foundation.PooledMemory?, out XmlSignatureProcessingError)"/>
/// (rooted at the countersignature's OWN <see cref="XAdESCounterSignature.Signature"/>) to obtain the
/// canonicalized candidate octets, then hand the reference's own <c>DigestMethod</c>/<c>DigestValue</c>
/// alongside those octets up to <c>Verifiable.Cryptography.Pki.XAdESLevelRules.CheckCounterSignatureDigestAsync</c>.
/// </remarks>
public static class XAdESCounterSignatureDigestRule
{
    /// <summary>
    /// Locates the single <c>ds:Reference</c> of <paramref name="counterSignature"/>'s own embedded
    /// <see cref="XAdESCounterSignature.Signature"/> whose <c>URI</c> — a same-document, bare-name XPointer
    /// fragment — dereferences to <paramref name="countersignedSignature"/>'s own
    /// <see cref="XmlSignature.SignatureValueElementIndex"/>. A reference with no <c>URI</c>, a non-fragment or
    /// non-<c>NCName</c> <c>URI</c>, or a fragment that resolves to no element or a DIFFERENT element (including
    /// the countersignature's own <c>ds:SignatureValue</c> — the self-referencing shape) is never a candidate;
    /// clause 5.2.7.2 permits "other <c>ds:Reference</c> elements referencing other data objects" alongside the
    /// one this method must find, so those are silently skipped rather than causing a refusal on their own.
    /// </summary>
    /// <param name="table">The document both <paramref name="countersignedSignature"/> and <paramref name="counterSignature"/> were read from.</param>
    /// <param name="countersignedSignature">The outer signature <paramref name="counterSignature"/> counter-signs — the reference's required target.</param>
    /// <param name="counterSignature">The already-read <c>CounterSignature</c> qualifying property.</param>
    /// <param name="reference">The located reference on success.</param>
    /// <param name="referenceOrdinal">The located reference's ordinal into <paramref name="counterSignature"/>'s own <see cref="XmlSignature.SignedInfo"/> references — the ordinal <see cref="XmlReferenceProcessing.TryComputeDigestInput(XmlNodeTable, XmlSignature, int, XmlReferenceResolver?, Lumoin.Base.BaseMemoryPool, out Verifiable.Foundation.PooledMemory?, out XmlSignatureProcessingError)"/> needs.</param>
    /// <param name="error">The refusal on failure: <see cref="XAdESProcessingFailure.TableMismatch"/> when
    /// <paramref name="table"/> does not match both arguments' own table;
    /// <see cref="XAdESProcessingFailure.CounterSignatureSignatureValueReferenceNotFound"/> when no reference
    /// resolves to the required target (dangling, wrong-target, or self-referencing alike);
    /// <see cref="XAdESProcessingFailure.CounterSignatureSignatureValueReferenceAmbiguous"/> when more than one
    /// does.</param>
    /// <returns><see langword="true"/> when exactly one reference was located.</returns>
    public static bool TryLocateSignatureValueReference(
        XmlNodeTable table,
        XmlSignature countersignedSignature,
        XAdESCounterSignature counterSignature,
        out XmlReference reference,
        out int referenceOrdinal,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(countersignedSignature);
        ArgumentNullException.ThrowIfNull(counterSignature);
        reference = default;
        referenceOrdinal = -1;
        if(!countersignedSignature.IsOver(table) || !counterSignature.IsOver(table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        int targetElementIndex = countersignedSignature.SignatureValueElementIndex;
        int matchCount = 0;
        XmlReference candidate = default;
        int candidateOrdinal = -1;
        IReadOnlyList<XmlReference> references = counterSignature.Signature.SignedInfo.References;
        for(int i = 0; i < references.Count; ++i)
        {
            XmlReference current = references[i];
            if(!current.HasUri)
            {
                continue;
            }

            ReadOnlySpan<byte> uri = current.Uri;
            if(uri.Length == 0 || uri[0] != (byte)'#')
            {
                continue;
            }

            ReadOnlySpan<byte> fragment = uri[1..];
            if(!XmlReferenceDereferencer.IsNcNameFragment(fragment) || !table.TryFindElementById(fragment, out int resolvedElementIndex, out _))
            {
                continue;
            }

            if(resolvedElementIndex != targetElementIndex)
            {
                continue;
            }

            candidate = current;
            candidateOrdinal = i;
            ++matchCount;
        }

        if(matchCount == 0)
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.CounterSignatureSignatureValueReferenceNotFound, 0);

            return false;
        }

        if(matchCount > 1)
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.CounterSignatureSignatureValueReferenceAmbiguous, 0);

            return false;
        }

        reference = candidate;
        referenceOrdinal = candidateOrdinal;
        error = default;

        return true;
    }
}
