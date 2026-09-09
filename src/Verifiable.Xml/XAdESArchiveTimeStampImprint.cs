using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The clause 5.5.2.3/5.5.2.4 message-imprint input engine for <see cref="XAdESArchiveTimeStamp"/>: the four
/// variants the clause defines — not-distributed/generation, not-distributed/validation, distributed/generation,
/// distributed/validation — share one base algorithm (steps 2/3/4/6 below) and differ only in step 5. This
/// engine implements the TWO VALIDATION variants (<see cref="TryComputeNotDistributedImprintInput"/>,
/// <see cref="TryComputeDistributedImprintInput"/>); the two generation variants are their recorded duals, never
/// built here (creation-side procedure clauses stay out of implementation,
/// recorded per-statement).
/// </summary>
/// <remarks>
/// <para>
/// The shared base algorithm, clause 5.5.2.3's steps 1)-6) (step 1, <c>RenewedDigestsV2</c> injection, is
/// itself a GENERATION-side precondition step — recorded, never performed here; see
/// <see cref="XAdESRenewedDigestsV2Processing"/> for the property it injects):
/// </para>
/// <list type="number">
/// <item>(GENERATION ONLY, recorded) if the signature carries a signed <c>ds:Manifest</c> referencing detached
/// objects with a near-end-of-life digest algorithm, incorporate a new <c>RenewedDigestsV2</c> qualifying
/// property first.</item>
/// <item>initialize the final octet stream as empty.</item>
/// <item>take ALL <c>ds:Reference</c> elements of <c>ds:SignedInfo</c>, in document order, INCLUDING the one
/// referencing <c>SignedProperties</c> — contrast clause 5.2.8.1/5.2.8.2's exclusion of that one reference —
/// processed per steps a)-d) (<see cref="XmlReferenceProcessing.TryComputeMessageImprintInputForReferences"/>,
/// the same shared reference-list engine <c>XAdESAllDataObjectsTimeStampImprint</c>/
/// <c>XAdESIndividualDataObjectsTimeStampImprint</c> use — this engine
/// needs an additive extension, not a duplicate).</item>
/// <item><c>ds:SignedInfo</c>, <c>ds:SignatureValue</c>, then <c>ds:KeyInfo</c> IF PRESENT, each canonicalized
/// (absent <c>ds:KeyInfo</c> is simply skipped, not an error), in that fixed order.</item>
/// <item>THE VARIANT POINT — see each public method's own remarks.</item>
/// <item>every <c>ds:Object</c> element EXCEPT the one carrying <c>QualifyingProperties</c>, in order of
/// appearance, each canonicalized.</item>
/// </list>
/// <para>
/// Every canonicalization uses <see cref="XAdESArchiveTimeStamp"/>'s own clause-4.5-resolved algorithm
/// (<see cref="XAdESCanonicalizationManagement.TryResolve"/>) and <c>InclusiveNamespaces PrefixList</c>,
/// uniformly across all six steps — the clause states no per-step algorithm variance.
/// </para>
/// </remarks>
public static class XAdESArchiveTimeStampImprint
{
    /// <summary>
    /// Computes the message-imprint input octets for validating an electronic time-stamp placed within a
    /// NOT-DISTRIBUTED <c>ArchiveTimeStamp</c> — clause 5.5.2.3's validation-time step 5: "take the unsigned
    /// signature qualifying properties that PRECEDE (appear BEFORE) the specific <c>ArchiveTimeStamp</c>
    /// containing the time-stamp being validated, in <c>UnsignedSignatureProperties</c> order, canonicalize,
    /// concatenate" — replacing generation-time step 5's "take the unsigned signature qualifying properties
    /// present in the signature in the order they appear" (which is, at generation time, exactly the same set,
    /// since the new <c>ArchiveTimeStamp</c> does not yet exist to be included; the GENERATION variant is this
    /// method's recorded, unbuilt dual). This is the mechanism that makes successive <c>ArchiveTimeStamp</c>
    /// instances individually re-verifiable: each one's imprint is relative to "everything unsigned that existed
    /// strictly before it," reconstructed here by filtering on document order rather than relying on absence.
    /// </summary>
    /// <param name="table">The document every table-scoped argument was read from.</param>
    /// <param name="signature">The signature whose references, <c>SignedInfo</c>/<c>SignatureValue</c>/<c>KeyInfo</c>
    /// and <c>ds:Object</c> elements are processed.</param>
    /// <param name="archiveTimeStamp">The already-read <c>ArchiveTimeStamp</c> under validation.</param>
    /// <param name="unsignedSignatureProperties">
    /// <paramref name="archiveTimeStamp"/>'s own owning <c>UnsignedSignatureProperties</c>'s document-order
    /// entry list — step 5's "precedes" filter is computed against this list's own order.
    /// </param>
    /// <param name="qualifyingPropertiesObjectOrdinal">
    /// The ordinal, into <see cref="XmlSignature.Objects"/>, of the <c>ds:Object</c> carrying
    /// <c>QualifyingProperties</c> — step 6 excludes it; the caller already knows this from discovery
    /// (<see cref="XAdESQualifyingPropertiesDiscoveryResult.ObjectOrdinal"/>).
    /// </param>
    /// <param name="resolver">The external-dereference delegate a non-same-document <c>ds:Reference URI</c>
    /// would need, or <see langword="null"/> when the caller supplies none.</param>
    /// <param name="pool">The pool every intermediate and returned buffer is rented from.</param>
    /// <param name="imprintInput">The message-imprint input octets on success, tagged
    /// <see cref="BufferTags.XmlDigestInput"/>; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match every
    /// table-scoped argument;
    /// <see cref="XAdESProcessingFailure.ArchiveTimeStampNotFoundInUnsignedSignatureProperties"/> when
    /// <paramref name="archiveTimeStamp"/> is not itself an entry of <paramref name="unsignedSignatureProperties"/>;
    /// <see cref="XAdESProcessingFailure.QualifyingPropertiesObjectOrdinalDoesNotCarryQualifyingProperties"/>
    /// when <paramref name="qualifyingPropertiesObjectOrdinal"/> does not name a <c>ds:Object</c> carrying a
    /// <c>QualifyingProperties</c> direct child;
    /// <see cref="XAdESProcessingFailure.AbsentCanonicalizationMethod"/>/
    /// <see cref="XAdESProcessingFailure.UnsupportedCanonicalizationMethod"/>/
    /// <see cref="XAdESProcessingFailure.InvalidCanonicalizationParameter"/> for the property's own clause-4.5
    /// resolution and every canonicalization step;
    /// <see cref="XAdESProcessingFailure.MessageImprintReferenceProcessingFailed"/> when processing a
    /// <c>SignedInfo</c> reference itself refuses.</param>
    /// <returns><see langword="true"/> when the imprint input was computed.</returns>
    public static bool TryComputeNotDistributedImprintInput(
        XmlNodeTable table,
        XmlSignature signature,
        XAdESArchiveTimeStamp archiveTimeStamp,
        XAdESUnsignedSignatureProperties unsignedSignatureProperties,
        int qualifyingPropertiesObjectOrdinal,
        XmlReferenceResolver? resolver,
        BaseMemoryPool pool,
        [NotNullWhen(true)] out PooledMemory? imprintInput,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(archiveTimeStamp);
        ArgumentNullException.ThrowIfNull(pool);
        imprintInput = null;
        if(!signature.IsOver(table) || !archiveTimeStamp.IsOver(table) || !ReferenceEquals(unsignedSignatureProperties.Table, table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        ArgumentOutOfRangeException.ThrowIfNegative(qualifyingPropertiesObjectOrdinal);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(qualifyingPropertiesObjectOrdinal, signature.Objects.Count);

        if(!XAdESCanonicalizationManagement.TryResolve(archiveTimeStamp.TimeStamp.HasCanonicalizationMethod, archiveTimeStamp.TimeStamp.CanonicalizationMethod, out XmlCanonicalizationAlgorithm algorithm, out error))
        {
            return false;
        }

        IReadOnlyList<XAdESUnsignedSignaturePropertyEntry> properties = unsignedSignatureProperties.Properties;
        int archiveTimeStampOrdinal = -1;
        for(int i = 0; i < properties.Count; ++i)
        {
            if(properties[i].ElementIndex == archiveTimeStamp.ElementIndex)
            {
                archiveTimeStampOrdinal = i;

                break;
            }
        }

        if(archiveTimeStampOrdinal < 0)
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.ArchiveTimeStampNotFoundInUnsignedSignatureProperties, 0);

            return false;
        }

        var step5NodeSets = new List<XmlNodeSet>(archiveTimeStampOrdinal);
        for(int i = 0; i < archiveTimeStampOrdinal; ++i)
        {
            step5NodeSets.Add(XmlNodeSet.ElementSubtree(table, properties[i].ElementIndex));
        }

        return TryComputeCore(table, signature, archiveTimeStamp, qualifyingPropertiesObjectOrdinal, algorithm, step5NodeSets, resolver, pool, out imprintInput, out error);
    }


    /// <summary>
    /// Computes the message-imprint input octets for validating an electronic time-stamp placed within a
    /// DISTRIBUTED <c>ArchiveTimeStamp</c> — clause 5.5.2.4's validation-time step 5: "take ALL <c>Include</c>
    /// elements within the <c>ArchiveTimeStamp</c> [...], IN ORDER OF APPEARANCE; for each, retrieve the
    /// referenced unsigned qualifying property present in the signature, DELETE COMMENT NODES, canonicalize,
    /// concatenate" — replacing generation-time step 5's "take the unsigned signature qualifying properties
    /// present in the signature, delete the comment nodes, canonicalize each" (the GENERATION variant is this
    /// method's recorded, unbuilt dual; its own further precondition — one <c>Include</c> per time-stamped
    /// property, in the SAME order used to build the imprint, clause 5.5.2.2 step 6 — is what step 5 here relies
    /// on already having been satisfied at generation time). Each <c>Include</c> resolves through the same
    /// bare-name-XPointer machinery every <c>Include</c> mechanism uses (<see cref="XAdESIncludeUriProcessing"/>),
    /// which already deletes comment nodes as part of its own XA-5.1.4.4.2.2-2 step-2 contract — no separate
    /// comment-deletion step is needed here.
    /// </summary>
    /// <param name="table">The document every table-scoped argument was read from.</param>
    /// <param name="signature">The signature whose references, <c>SignedInfo</c>/<c>SignatureValue</c>/<c>KeyInfo</c>
    /// and <c>ds:Object</c> elements are processed.</param>
    /// <param name="archiveTimeStamp">The already-read <c>ArchiveTimeStamp</c> under validation, whose
    /// <see cref="XAdESTimeStamp.Includes"/> name the time-stamped properties, in the fixed order they
    /// contribute.</param>
    /// <param name="unsignedSignatureProperties">
    /// <paramref name="archiveTimeStamp"/>'s own owning <c>UnsignedSignatureProperties</c>'s document-order
    /// entry list — clause 5.5.2.4 step 5's "present in the XAdES signature" membership check: each
    /// <c>Include</c>'s resolved target must be an entry of THIS list, not merely an element the document-wide
    /// bare-name resolution happens to find somewhere else.
    /// </param>
    /// <param name="qualifyingPropertiesObjectOrdinal">
    /// The ordinal, into <see cref="XmlSignature.Objects"/>, of the <c>ds:Object</c> carrying
    /// <c>QualifyingProperties</c> — step 6 excludes it.
    /// </param>
    /// <param name="resolver">The external-dereference delegate a non-same-document <c>ds:Reference URI</c>
    /// would need, or <see langword="null"/> when the caller supplies none.</param>
    /// <param name="pool">The pool every intermediate and returned buffer is rented from.</param>
    /// <param name="imprintInput">The message-imprint input octets on success, tagged
    /// <see cref="BufferTags.XmlDigestInput"/>; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match every
    /// table-scoped argument;
    /// <see cref="XAdESProcessingFailure.QualifyingPropertiesObjectOrdinalDoesNotCarryQualifyingProperties"/>
    /// when <paramref name="qualifyingPropertiesObjectOrdinal"/> does not name a <c>ds:Object</c> carrying a
    /// <c>QualifyingProperties</c> direct child;
    /// <see cref="XAdESProcessingFailure.AbsentCanonicalizationMethod"/>/
    /// <see cref="XAdESProcessingFailure.UnsupportedCanonicalizationMethod"/>/
    /// <see cref="XAdESProcessingFailure.InvalidCanonicalizationParameter"/> for the property's own clause-4.5
    /// resolution and every canonicalization step;
    /// every <see cref="XAdESIncludeUriProcessing.TryRetrieve"/> refusal, per <c>Include</c>;
    /// <see cref="XAdESProcessingFailure.IncludeTargetNotAnUnsignedQualifyingProperty"/> when a resolved
    /// <c>Include</c> target is not itself an entry of <paramref name="unsignedSignatureProperties"/>;
    /// <see cref="XAdESProcessingFailure.MessageImprintReferenceProcessingFailed"/> when processing a
    /// <c>SignedInfo</c> reference itself refuses.</param>
    /// <returns><see langword="true"/> when the imprint input was computed.</returns>
    public static bool TryComputeDistributedImprintInput(
        XmlNodeTable table,
        XmlSignature signature,
        XAdESArchiveTimeStamp archiveTimeStamp,
        XAdESUnsignedSignatureProperties unsignedSignatureProperties,
        int qualifyingPropertiesObjectOrdinal,
        XmlReferenceResolver? resolver,
        BaseMemoryPool pool,
        [NotNullWhen(true)] out PooledMemory? imprintInput,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(archiveTimeStamp);
        ArgumentNullException.ThrowIfNull(pool);
        imprintInput = null;
        if(!signature.IsOver(table) || !archiveTimeStamp.IsOver(table) || !ReferenceEquals(unsignedSignatureProperties.Table, table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        ArgumentOutOfRangeException.ThrowIfNegative(qualifyingPropertiesObjectOrdinal);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(qualifyingPropertiesObjectOrdinal, signature.Objects.Count);

        if(!XAdESCanonicalizationManagement.TryResolve(archiveTimeStamp.TimeStamp.HasCanonicalizationMethod, archiveTimeStamp.TimeStamp.CanonicalizationMethod, out XmlCanonicalizationAlgorithm algorithm, out error))
        {
            return false;
        }

        var step5NodeSets = new List<XmlNodeSet>(archiveTimeStamp.TimeStamp.Includes.Count);
        foreach(XAdESInclude include in archiveTimeStamp.TimeStamp.Includes)
        {
            if(!XAdESIncludeUriProcessing.TryRetrieve(table, include.Uri, out int targetElementIndex, out XmlNodeSet targetNodeSet, out error))
            {
                return false;
            }

            if(!IsMemberOfContainer(unsignedSignatureProperties, targetElementIndex))
            {
                error = new XAdESProcessingError(XAdESProcessingFailure.IncludeTargetNotAnUnsignedQualifyingProperty, 0);

                return false;
            }

            step5NodeSets.Add(targetNodeSet);
        }

        return TryComputeCore(table, signature, archiveTimeStamp, qualifyingPropertiesObjectOrdinal, algorithm, step5NodeSets, resolver, pool, out imprintInput, out error);
    }


    /// <summary>
    /// Tells whether <paramref name="elementIndex"/> is the <see cref="XAdESUnsignedSignaturePropertyEntry.ElementIndex"/>
    /// of some entry of <paramref name="unsignedSignatureProperties"/> — clause 5.5.2.4 step 5's "present in the
    /// XAdES signature" membership check, the same shape the not-distributed variant's own preceding-boundary
    /// scan already performs against this same entry list.
    /// </summary>
    private static bool IsMemberOfContainer(XAdESUnsignedSignatureProperties unsignedSignatureProperties, int elementIndex)
    {
        IReadOnlyList<XAdESUnsignedSignaturePropertyEntry> properties = unsignedSignatureProperties.Properties;
        for(int i = 0; i < properties.Count; ++i)
        {
            if(properties[i].ElementIndex == elementIndex)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// The shared base algorithm both public methods compose over: steps 2)/3)/4)/6) plus the caller-supplied,
    /// already-ordered step-5 node-set list.
    /// </summary>
    private static bool TryComputeCore(
        XmlNodeTable table,
        XmlSignature signature,
        XAdESArchiveTimeStamp archiveTimeStamp,
        int qualifyingPropertiesObjectOrdinal,
        XmlCanonicalizationAlgorithm algorithm,
        List<XmlNodeSet> step5NodeSets,
        XmlReferenceResolver? resolver,
        BaseMemoryPool pool,
        out PooledMemory? imprintInput,
        out XAdESProcessingError error)
    {
        imprintInput = null;
        if(!ObjectCarriesQualifyingProperties(table, signature.Objects[qualifyingPropertiesObjectOrdinal]))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.QualifyingPropertiesObjectOrdinalDoesNotCarryQualifyingProperties, 0);

            return false;
        }

        ReadOnlySpan<byte> prefixList = archiveTimeStamp.TimeStamp.CanonicalizationMethod.PrefixList;
        using var output = new PooledStructList<byte>(pool, 256);

        //Step 3: every ds:SignedInfo reference, INCLUDING the SignedProperties one, in document order.
        if(!XmlReferenceProcessing.TryComputeMessageImprintInputForReferences(table, signature.SignedInfo.References, algorithm, prefixList, resolver, pool, out PooledMemory? referencesContribution, out XmlSignatureProcessingError referencesError))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.MessageImprintReferenceProcessingFailed, 0, referencesError);

            return false;
        }

        using(referencesContribution)
        {
            output.AddRange(referencesContribution!.AsReadOnlySpan());
        }

        //Step 4: ds:SignedInfo, ds:SignatureValue, then ds:KeyInfo if present, in that fixed order.
        if(!TryAppendCanonicalized(table, XmlNodeSet.ElementSubtree(table, signature.SignedInfo.ElementIndex), algorithm, prefixList, pool, output, out error))
        {
            return false;
        }

        if(!TryAppendCanonicalized(table, XmlNodeSet.ElementSubtree(table, signature.SignatureValueElementIndex), algorithm, prefixList, pool, output, out error))
        {
            return false;
        }

        if(signature.KeyInfo.HasValue && !TryAppendCanonicalized(table, XmlNodeSet.ElementSubtree(table, signature.KeyInfo.Value.ElementIndex), algorithm, prefixList, pool, output, out error))
        {
            return false;
        }

        //Step 5: the variant-specific node-set list, in the order the caller already fixed.
        for(int i = 0; i < step5NodeSets.Count; ++i)
        {
            if(!TryAppendCanonicalized(table, step5NodeSets[i], algorithm, prefixList, pool, output, out error))
            {
                return false;
            }
        }

        //Step 6: every ds:Object EXCEPT the one carrying QualifyingProperties, in order of appearance.
        for(int i = 0; i < signature.Objects.Count; ++i)
        {
            if(i == qualifyingPropertiesObjectOrdinal)
            {
                continue;
            }

            if(!TryAppendCanonicalized(table, XmlNodeSet.ElementSubtree(table, signature.Objects[i].ElementIndex), algorithm, prefixList, pool, output, out error))
            {
                return false;
            }
        }

        imprintInput = PooledMemory.FromBytes(output.AsSpan(), pool, BufferTags.XmlDigestInput);
        error = default;

        return true;
    }


    /// <summary>
    /// Tells whether a <c>ds:Object</c> carries a <c>QualifyingProperties</c> direct child — the same identity
    /// check <see cref="XAdESQualifyingPropertiesDiscovery.TryDiscover"/> uses, applied here to pin the
    /// caller-supplied <c>qualifyingPropertiesObjectOrdinal</c> before step 6 relies on it to decide which
    /// <c>ds:Object</c> is excluded from the imprint.
    /// </summary>
    private static bool ObjectCarriesQualifyingProperties(XmlNodeTable table, XmlSignatureObject signatureObject)
    {
        foreach(int contentIndex in signatureObject.ContentNodeIndices)
        {
            if(table.KindOf(contentIndex) != XmlNodeKind.Element)
            {
                continue;
            }

            if(XmlSignatureModelGrammar.IsElement(table, contentIndex, XAdESIdentifiers.XAdESNamespaceV132Utf8, "QualifyingProperties"u8))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Canonicalizes one node-set with the property's own resolved algorithm/prefix-list and appends the
    /// result to the running message-imprint input, releasing the intermediate buffer immediately.
    /// <c>canonical</c> is bound through <see cref="XmlReferenceProcessing.TryCanonicalizeForAlgorithm"/>'s
    /// <see langword="out"/> parameter, so it is declared <see langword="null"/> and disposed manually in
    /// the <see langword="finally"/> below rather than through a <see langword="using"/> declaration.
    /// </summary>
    private static bool TryAppendCanonicalized(XmlNodeTable table, XmlNodeSet nodeSet, XmlCanonicalizationAlgorithm algorithm, ReadOnlySpan<byte> prefixList, BaseMemoryPool pool, PooledStructList<byte> output, out XAdESProcessingError error)
    {
        PooledMemory? canonical = null;
        try
        {
            if(!XmlReferenceProcessing.TryCanonicalizeForAlgorithm(table, nodeSet, algorithm, prefixList, pool, out canonical, out XmlCanonicalizationError canonicalizationError))
            {
                error = XAdESCanonicalizationManagement.MapCanonicalizationFailure(canonicalizationError);

                return false;
            }

            output.AddRange(canonical!.AsReadOnlySpan());
            error = default;

            return true;
        }
        finally
        {
            canonical?.Dispose();
        }
    }
}
