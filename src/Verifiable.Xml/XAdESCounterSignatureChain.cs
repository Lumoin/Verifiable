using Lumoin.Base;

namespace Verifiable.Xml;

/// <summary>
/// Walks a nested-<c>CounterSignature</c> chain: clause 5.2.7.2 NOTE 2 ("This allows for building arbitrarily
/// long chains of explicit countersignatures") and NOTE 3 ("an alternative way of constructing arbitrarily
/// long series of countersignatures, each one signing the <c>ds:SignatureValue</c> element of the one where it
/// is directly embedded") both describe a countersignature that may itself carry its OWN <c>CounterSignature</c>
/// qualifying property, recursively. Clause 5.2.7.2 states no numeric bound on this nesting — both NOTEs use
/// the word "arbitrarily" — so an unbounded walk is a genuine, spec-invited resource-exhaustion surface: each
/// hop opens a full nested <c>ds:Signature</c> (<see cref="XAdESCounterSignature.TryRead"/>).
/// </summary>
public static class XAdESCounterSignatureChain
{
    /// <summary>
    /// The maximum total number of <c>CounterSignature</c> occurrences one <see cref="TryWalk"/> call will
    /// read, counted across the WHOLE walk rather than per branch — the walk aborts the instant the running
    /// total exceeds this, so the bound caps total work regardless of whether the excess comes from one deep
    /// linear chain (NOTE 2/NOTE 3's own construction) or from many sibling <c>CounterSignature</c> occurrences
    /// fanning out at one level (Table 2's own unbounded "&#8805;0" cardinality on the property, so width is
    /// never separately capped by the schema either). Because the check runs BEFORE each recursive descent, C#
    /// call-stack depth is also bounded by this same constant, closing a stack-exhaustion avenue alongside the
    /// CPU/memory one. A documented hardening bound, the same defense-in-depth posture
    /// <see cref="XmlReferenceProcessing.MaximumTransformCount"/> and
    /// <see cref="XmlReferenceProcessing.MaximumReparseDepth"/> already take for their own unbounded XMLDSIG-
    /// level constructs — chosen generously above any legitimate nesting a real deployment would produce (NOTE
    /// 2/3's own examples describe chains of a handful of hops) while remaining small enough that a hostile
    /// document refuses well inside a loose ceiling: <c>XAdESCounterSignatureChainTests.DeepHostileChainRefusesWithinTheCeiling</c>
    /// measures a 150-hop hostile chain (well beyond this bound) refusing at hop 65 in well under the test's
    /// own five-second ceiling, dominated by parsing the fixture itself rather than the bounded walk.
    /// </summary>
    public const int MaximumChainNodeCount = 64;


    /// <summary>
    /// Walks <paramref name="rootSignature"/>'s own <c>CounterSignature</c>-classed unsigned-signature-property
    /// entries, and recursively each countersignature's own such entries (when the countersignature is itself a
    /// XAdES signature carrying its own <c>QualifyingProperties</c>), depth-first, in document order, opening
    /// each occurrence through <see cref="XAdESCounterSignature.TryRead"/> and disposing it before moving to the
    /// next — this method never accumulates the chain in memory, since a caller wanting the full nested value
    /// tree already has one (the topmost) and can recurse itself; this is a bounded EXISTENCE/COUNT walk.
    /// </summary>
    /// <param name="table">The document <paramref name="rootSignature"/> was read from.</param>
    /// <param name="rootSignature">The already-read signature to walk from.</param>
    /// <param name="pool">The pool every nested embedded signature's decoded fields are transiently rented from.</param>
    /// <param name="visitedCount">The total number of <c>CounterSignature</c> occurrences visited on success.</param>
    /// <param name="error">The refusal on failure: whatever
    /// <see cref="XAdESQualifyingPropertiesDiscovery.TryDiscover"/> itself can refuse with, at any depth;
    /// <see cref="XAdESProcessingFailure.CounterSignatureChainMalformedEntry"/> when a <c>CounterSignature</c>
    /// occurrence does not itself read structurally; <see cref="XAdESProcessingFailure.CounterSignatureChainLimitExceeded"/>
    /// when <see cref="MaximumChainNodeCount"/> is exceeded.</param>
    /// <returns><see langword="true"/> when the whole reachable chain was walked within bound.</returns>
    public static bool TryWalk(XmlNodeTable table, XmlSignature rootSignature, BaseMemoryPool pool, out int visitedCount, out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(rootSignature);
        ArgumentNullException.ThrowIfNull(pool);

        visitedCount = 0;

        return TryWalkCore(table, rootSignature, pool, ref visitedCount, out error);
    }


    private static bool TryWalkCore(XmlNodeTable table, XmlSignature signature, BaseMemoryPool pool, ref int visitedCount, out XAdESProcessingError error)
    {
        if(!XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult discovery, out error))
        {
            return false;
        }

        if(!discovery.HasQualifyingProperties
            || !discovery.QualifyingProperties.HasUnsignedProperties
            || !discovery.QualifyingProperties.UnsignedProperties.HasUnsignedSignatureProperties)
        {
            error = default;

            return true;
        }

        IReadOnlyList<XAdESUnsignedSignaturePropertyEntry> entries = discovery.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.Properties;
        for(int i = 0; i < entries.Count; ++i)
        {
            if(entries[i].Name != XAdESUnsignedSignaturePropertyName.CounterSignature)
            {
                continue;
            }

            ++visitedCount;
            if(visitedCount > MaximumChainNodeCount)
            {
                error = new XAdESProcessingError(XAdESProcessingFailure.CounterSignatureChainLimitExceeded, 0);

                return false;
            }

            XAdESCounterSignature? counterSignature = null;
            try
            {
                if(!XAdESCounterSignature.TryRead(table, entries[i].ElementIndex, pool, out counterSignature, out XAdESReadError readError))
                {
                    error = new XAdESProcessingError(XAdESProcessingFailure.CounterSignatureChainMalformedEntry, 0, readError);

                    return false;
                }

                if(!TryWalkCore(table, counterSignature!.Signature, pool, ref visitedCount, out error))
                {
                    return false;
                }
            }
            finally
            {
                counterSignature?.Dispose();
            }
        }

        error = default;

        return true;
    }
}
