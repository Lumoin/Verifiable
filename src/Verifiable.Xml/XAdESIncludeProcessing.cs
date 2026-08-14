using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The generic <c>Include</c>-processing frame of clause 5.1.4.4.2.3, implemented and proven standalone:
/// given an ordered <c>Include</c> list and a clause-4.5 canonicalization resolution, produces the
/// concatenated message-imprint INPUT octets the clause's own four-step algorithm (XA-5.1.4.4.2.3-1)
/// describes. Each <c>Include</c> is: (1) retrieved via <see cref="XAdESIncludeUriProcessing"/>; (2) if the
/// retrieval target is a <c>ds:Reference</c> element and <c>referencedData="true"</c>, replaced by the
/// XMLDSIG reference-processing engine's own digest input for that reference
/// (<see cref="XmlReferenceProcessing.TryComputeDigestInputForReference"/>, the XMLDSIG §4.3.3.2 DEFAULT
/// final conversion) — otherwise kept as the retrieved node-set; (3) canonicalized, when the result is
/// still a node-set, per the supplied resolution; (4) concatenated onto the running input, in
/// <c>Include</c> document order (XA-5.1.4.4.2.1-2/XA-5.1.4.4.2.3-4). No landed Part 1 qualifying property
/// composes over this exact final-conversion step: clause 5.2.8.2's own engine,
/// <see cref="XAdESIndividualDataObjectsTimeStampImprint"/>, and the distributed A.1.5 engines
/// (<see cref="XAdESArchiveTimeStampImprint"/>, <see cref="XAdESSigAndRefsTimeStampV2Imprint"/>,
/// <see cref="XAdESRefsOnlyTimeStampV2Imprint"/>) each resolve their own <c>Include</c> targets through the
/// SAME retrieval/canonicalization primitives this frame is built from
/// (<see cref="XAdESIncludeUriProcessing"/>, <see cref="XAdESCanonicalizationManagement"/>) but substitute
/// their own clause-specific final conversion — 5.2.8.x's own clause-4.5 conversion
/// (<see cref="XmlReferenceProcessing.TryComputeMessageImprintInputForReferences"/>) for the former, whole
/// property/<c>ds:SignatureValue</c> node-set canonicalization for the latter — rather than this frame's
/// XMLDSIG-default one. That divergence is deliberate: this frame stands as
/// the clause 5.1.4.4.2.3 reference implementation in its own right, exercised directly by its own test
/// suite.
/// </summary>
public static class XAdESIncludeProcessing
{
    /// <summary>
    /// Computes the concatenated message-imprint input octets for an ordered <c>Include</c> list.
    /// </summary>
    /// <param name="table">The document the <c>Include</c> elements were read from.</param>
    /// <param name="includes">The <c>Include</c> elements, in document order.</param>
    /// <param name="hasCanonicalizationMethod">Whether the time-stamp container's own <c>ds:CanonicalizationMethod</c> is present.</param>
    /// <param name="canonicalizationMethod">The container's <c>ds:CanonicalizationMethod</c>, meaningful only
    /// when <paramref name="hasCanonicalizationMethod"/> is <see langword="true"/>.</param>
    /// <param name="resolver">The external-dereference delegate a <c>referencedData="true"</c> target's OWN
    /// <c>ds:Reference URI</c> may need, or <see langword="null"/> when the caller supplies none.</param>
    /// <param name="pool">The pool every intermediate and returned buffer is rented from.</param>
    /// <param name="imprintInput">The concatenated message-imprint input octets on success, tagged
    /// <see cref="BufferTags.XmlDigestInput"/>; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.AbsentCanonicalizationMethod"/> when
    /// <paramref name="hasCanonicalizationMethod"/> is <see langword="false"/> — clause 4.5 makes the element
    /// generator-mandatory, so its absence at verification time is refused rather than assumed;
    /// <see cref="XAdESProcessingFailure.UnsupportedCanonicalizationMethod"/> when its <c>Algorithm</c> is not
    /// one of the six clause 6.3(d) URIs; every <see cref="XAdESIncludeUriProcessing.TryRetrieve"/> refusal,
    /// per <c>Include</c>; <see cref="XAdESProcessingFailure.ReferencedDataNotPermittedOnNonReferenceTarget"/>
    /// when an <c>Include</c>'s <c>referencedData</c> is present but its target is not a <c>ds:Reference</c>
    /// element; <see cref="XAdESProcessingFailure.MalformedReferenceTarget"/>/
    /// <see cref="XAdESProcessingFailure.ReferenceProcessingFailed"/> for the <c>referencedData="true"</c>
    /// route; <see cref="XAdESProcessingFailure.InvalidCanonicalizationParameter"/> for a malformed or
    /// over-length <c>InclusiveNamespaces PrefixList</c>.</param>
    /// <returns><see langword="true"/> when the imprint input was computed.</returns>
    public static bool TryComputeImprintInput(
        XmlNodeTable table,
        IReadOnlyList<XAdESInclude> includes,
        bool hasCanonicalizationMethod,
        XmlCanonicalizationMethodInfo canonicalizationMethod,
        XmlReferenceResolver? resolver,
        BaseMemoryPool pool,
        [NotNullWhen(true)] out PooledMemory? imprintInput,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(includes);
        ArgumentNullException.ThrowIfNull(pool);
        imprintInput = null;
        if(!XAdESCanonicalizationManagement.TryResolve(hasCanonicalizationMethod, canonicalizationMethod, out XmlCanonicalizationAlgorithm algorithm, out error))
        {
            return false;
        }

        using var output = new PooledStructList<byte>(pool, 256);
        var readTargetReferences = new List<PooledMemory>();
        try
        {
            foreach(XAdESInclude include in includes)
            {
                if(!XAdESIncludeUriProcessing.TryRetrieve(table, include.Uri, out int targetElementIndex, out XmlNodeSet targetNodeSet, out error))
                {
                    return false;
                }

                bool isDsReferenceTarget = XmlSignatureModelGrammar.IsDsElement(table, targetElementIndex, "Reference"u8);
                if(include.HasReferencedData && !isDsReferenceTarget)
                {
                    error = new XAdESProcessingError(XAdESProcessingFailure.ReferencedDataNotPermittedOnNonReferenceTarget, 0);

                    return false;
                }

                if(isDsReferenceTarget && include.HasReferencedData && include.ReferencedData)
                {
                    if(!XmlReference.TryRead(table, targetElementIndex, pool, readTargetReferences, out XmlReference reference, out XmlSignatureReadError readError))
                    {
                        error = new XAdESProcessingError(XAdESProcessingFailure.MalformedReferenceTarget, 0, readError);

                        return false;
                    }

                    if(!XmlReferenceProcessing.TryComputeDigestInputForReference(table, reference, resolver, pool, out PooledMemory? digestInput, out XmlSignatureProcessingError processingError))
                    {
                        error = new XAdESProcessingError(XAdESProcessingFailure.ReferenceProcessingFailed, 0, processingError);

                        return false;
                    }

                    using(digestInput)
                    {
                        output.AddRange(digestInput.AsReadOnlySpan());
                    }

                    continue;
                }

                PooledMemory? canonicalOctets = null;
                try
                {
                    if(!XmlReferenceProcessing.TryCanonicalizeForAlgorithm(table, targetNodeSet, algorithm, canonicalizationMethod.PrefixList, pool, out canonicalOctets, out XmlCanonicalizationError canonicalizationError))
                    {
                        error = XAdESCanonicalizationManagement.MapCanonicalizationFailure(canonicalizationError);

                        return false;
                    }

                    output.AddRange(canonicalOctets.AsReadOnlySpan());
                }
                finally
                {
                    canonicalOctets?.Dispose();
                }
            }

            imprintInput = PooledMemory.FromBytes(output.AsSpan(), pool, BufferTags.XmlDigestInput);
            error = default;

            return true;
        }
        finally
        {
            foreach(PooledMemory buffer in readTargetReferences)
            {
                buffer.Dispose();
            }
        }
    }
}
