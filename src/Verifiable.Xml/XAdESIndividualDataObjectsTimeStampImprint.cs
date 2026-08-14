using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The clause 5.2.8.2 message-imprint input engine for <see cref="XAdESIndividualDataObjectsTimeStamp"/>:
/// "Take all the <c>ds:Reference</c> elements within <c>ds:SignedInfo</c> or within a signed <c>ds:Manifest</c>
/// which are referenced within the <c>Include</c> element. Process each one in their ORDER OF APPEARANCE
/// WITHIN THE <c>INCLUDE</c> ELEMENT" — the ordering key that differs from
/// <see cref="XAdESAllDataObjectsTimeStampImprint"/>'s <c>ds:SignedInfo</c> document order. Each
/// <c>Include</c>'s <c>URI</c> resolves through the same bare-name-XPointer machinery every Include mechanism
/// uses (<see cref="XAdESIncludeUriProcessing"/>) — bare-name resolution locates an <c>Id</c>-typed target
/// anywhere in the document, so the "within <c>ds:SignedInfo</c> or within a signed <c>ds:Manifest</c>" scope
/// is enforced explicitly here via <see cref="XAdESObjectReferenceResolution.IsWithinSignedInfoOrSignedManifest"/>,
/// the same two-way allowlist clause 5.2.3/5.2.4's <c>ObjectReference</c> resolution shares — otherwise a
/// <c>ds:Reference</c> sitting inside an UNSIGNED <c>ds:Manifest</c>, or inside a different <c>ds:Signature</c>
/// entirely, would satisfy this engine despite satisfying neither clause. Once located and scope-checked, each
/// target is re-read as a genuine <c>ds:Reference</c> and processed through the SAME shared clause
/// 5.2.8.1/5.2.8.2 steps a)-d) engine <see cref="XAdESAllDataObjectsTimeStampImprint"/> uses
/// (<see cref="XmlReferenceProcessing.TryComputeMessageImprintInputForReferences"/>) — clause 5.2.8.2's own
/// final conversion, which is NOT <see cref="XAdESIncludeProcessing"/>'s generic-frame, XMLDSIG-§4.3.3.2-
/// default final conversion; the two produce different octets for the same <c>Include</c> set whenever a
/// target's transform chain still ends in a node-set. The read-time rule
/// already guarantees every <c>Include</c> carries <c>referencedData="true"</c>
/// (<see cref="XAdESIndividualDataObjectsTimeStamp.TryRead"/>); this engine still verifies each target
/// actually IS a <c>ds:Reference</c> at resolution time, since the reader alone cannot know what a bare-name
/// fragment resolves to before the whole document is available. A zero-<c>Include</c> instance — accepted at
/// read, since <see cref="XAdESTimeStamp"/>'s own clause-5.1.4.3 content model is zero-or-more <c>Include</c>
/// and clause 5.2.8.2 states no floor above it — produces an empty imprint input here: step 1's "initialize the
/// final octet stream as an empty octet stream" is vacuously satisfied by nothing to concatenate.
/// </summary>
public static class XAdESIndividualDataObjectsTimeStampImprint
{
    /// <summary>
    /// Computes the message-imprint input octets for an <c>IndividualDataObjectsTimeStamp</c>.
    /// </summary>
    /// <param name="table">The document both <paramref name="signature"/> and <paramref name="individualDataObjectsTimeStamp"/> were read from.</param>
    /// <param name="signature">The signature whose <c>ds:SignedInfo</c>/signed <c>ds:Manifest</c>s every
    /// <c>Include</c> target must be within.</param>
    /// <param name="individualDataObjectsTimeStamp">The already-read <c>IndividualDataObjectsTimeStamp</c> qualifying property.</param>
    /// <param name="resolver">The external-dereference delegate a non-same-document <c>ds:Reference URI</c>
    /// would need, or <see langword="null"/> when the caller supplies none.</param>
    /// <param name="pool">The pool every intermediate and returned buffer is rented from.</param>
    /// <param name="imprintInput">The message-imprint input octets on success, tagged
    /// <see cref="BufferTags.XmlDigestInput"/>; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match both
    /// <paramref name="signature"/> and <paramref name="individualDataObjectsTimeStamp"/>;
    /// <see cref="XAdESProcessingFailure.AbsentCanonicalizationMethod"/>/
    /// <see cref="XAdESProcessingFailure.UnsupportedCanonicalizationMethod"/> for the property's own
    /// clause-4.5 resolution;
    /// every <see cref="XAdESIncludeUriProcessing.TryRetrieve"/> refusal, per <c>Include</c>;
    /// <see cref="XAdESProcessingFailure.ReferencedDataNotPermittedOnNonReferenceTarget"/> when an
    /// <c>Include</c>'s target is not a <c>ds:Reference</c> element;
    /// <see cref="XAdESProcessingFailure.IndividualDataObjectsTimeStampIncludeTargetNotWithinSignedInfoOrSignedManifest"/>
    /// when a structurally-named <c>ds:Reference</c> target is neither a child of <paramref name="signature"/>'s
    /// own <c>ds:SignedInfo</c> nor of a signed <c>ds:Manifest</c>;
    /// <see cref="XAdESProcessingFailure.MalformedReferenceTarget"/> when a structurally-named
    /// <c>ds:Reference</c> target does not itself read as one;
    /// <see cref="XAdESProcessingFailure.IndividualDataObjectsTimeStampIncludeTargetsSignedPropertiesReference"/>
    /// when an <c>Include</c> resolves to the <c>SignedProperties</c> reference — "shall not include" per
    /// clause 5.2.8.2;
    /// <see cref="XAdESProcessingFailure.MessageImprintReferenceProcessingFailed"/> when processing a
    /// resolved reference itself refuses.</param>
    /// <returns><see langword="true"/> when the imprint input was computed.</returns>
    public static bool TryComputeImprintInput(
        XmlNodeTable table,
        XmlSignature signature,
        XAdESIndividualDataObjectsTimeStamp individualDataObjectsTimeStamp,
        XmlReferenceResolver? resolver,
        BaseMemoryPool pool,
        [NotNullWhen(true)] out PooledMemory? imprintInput,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(individualDataObjectsTimeStamp);
        ArgumentNullException.ThrowIfNull(pool);
        imprintInput = null;
        if(!signature.IsOver(table) || !individualDataObjectsTimeStamp.IsOver(table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        if(!XAdESCanonicalizationManagement.TryResolve(individualDataObjectsTimeStamp.TimeStamp.HasCanonicalizationMethod, individualDataObjectsTimeStamp.TimeStamp.CanonicalizationMethod, out XmlCanonicalizationAlgorithm algorithm, out error))
        {
            return false;
        }

        var owned = new List<PooledMemory>();
        try
        {
            var resolvedReferences = new List<XmlReference>(individualDataObjectsTimeStamp.TimeStamp.Includes.Count);
            foreach(XAdESInclude include in individualDataObjectsTimeStamp.TimeStamp.Includes)
            {
                if(!XAdESIncludeUriProcessing.TryRetrieve(table, include.Uri, out int targetElementIndex, out _, out error))
                {
                    return false;
                }

                if(!XmlSignatureModelGrammar.IsDsElement(table, targetElementIndex, "Reference"u8))
                {
                    error = new XAdESProcessingError(XAdESProcessingFailure.ReferencedDataNotPermittedOnNonReferenceTarget, 0);

                    return false;
                }

                if(!XAdESObjectReferenceResolution.IsWithinSignedInfoOrSignedManifest(table, signature, targetElementIndex))
                {
                    error = new XAdESProcessingError(XAdESProcessingFailure.IndividualDataObjectsTimeStampIncludeTargetNotWithinSignedInfoOrSignedManifest, 0);

                    return false;
                }

                if(!XmlReference.TryRead(table, targetElementIndex, pool, owned, out XmlReference reference, out XmlSignatureReadError readError))
                {
                    error = new XAdESProcessingError(XAdESProcessingFailure.MalformedReferenceTarget, 0, readError);

                    return false;
                }

                if(reference.HasType && reference.Type.SequenceEqual(XAdESIdentifiers.SignedPropertiesTypeUriUtf8))
                {
                    error = new XAdESProcessingError(XAdESProcessingFailure.IndividualDataObjectsTimeStampIncludeTargetsSignedPropertiesReference, 0);

                    return false;
                }

                resolvedReferences.Add(reference);
            }

            if(!XmlReferenceProcessing.TryComputeMessageImprintInputForReferences(
                table, resolvedReferences, algorithm, individualDataObjectsTimeStamp.TimeStamp.CanonicalizationMethod.PrefixList, resolver, pool, out imprintInput, out XmlSignatureProcessingError processingError))
            {
                error = new XAdESProcessingError(XAdESProcessingFailure.MessageImprintReferenceProcessingFailed, 0, processingError);

                return false;
            }

            error = default;

            return true;
        }
        finally
        {
            for(int i = 0; i < owned.Count; ++i)
            {
                owned[i].Dispose();
            }
        }
    }
}
