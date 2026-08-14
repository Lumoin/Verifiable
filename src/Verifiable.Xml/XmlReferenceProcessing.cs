using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The reference-processing/transform-chain engine of section 4.3.3.2 of
/// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see>: dereferencing a <c>ds:Reference</c>'s <c>URI</c> through
/// <see cref="XmlReferenceDereferencer"/>, running the transform chain the <c>Reference</c> names, and
/// producing the two octet streams core validation digests and verifies — per-reference digest input
/// (<see cref="TryComputeDigestInput"/>) and canonical <c>SignedInfo</c> octets
/// (<see cref="TryComputeSignedInfoOctets"/>).
/// </summary>
/// <remarks>
/// Data flowing through a chain is always exactly one of an octet stream or an <see cref="XmlNodeSet"/>,
/// per the section 4.3.3.2 data-type rule. Every conversion between the two shapes is one of the spec's
/// own MUSTs: octets to a node-set is a well-formed parse
/// (<see cref="XmlNodeTable.TryParse"/>, counted against <see cref="MaximumReparseDepth"/>); a node-set to
/// octets is Canonical XML 1.0 rendering the set AS IS — comment emission governed solely by whether the
/// set itself excludes comments (<see cref="XmlNodeSet.WithoutComments"/>, applied by
/// <see cref="XmlReferenceDereferencer"/> at dereference time for the null-URI/bare-name forms per section
/// 4.3.3.3 step 4), never by this conversion — EXCEPT the base64 transform of section
/// 6.6.2, which defines its own node-set-to-octets rule (text-node string-value selection) that this engine
/// applies instead of the generic default whenever base64 is the transform doing the converting, and EXCEPT
/// an EXPLICIT canonicalization <c>Transform</c>, whose own named algorithm variant governs comment
/// emission unchanged. This leaf performs no cryptography: the produced octets are handed
/// to the caller's own digest/verification seam untouched.
/// </remarks>
public static class XmlReferenceProcessing
{
    /// <summary>
    /// The maximum number of <c>Transform</c> elements one <c>Reference</c>'s chain may carry before
    /// <see cref="TryComputeDigestInput"/> refuses with
    /// <see cref="XmlSignatureProcessingFailure.TransformCountExceeded"/> — a documented hardening bound
    /// this library imposes; XML Signature itself sets no such bound.
    /// </summary>
    public const int MaximumTransformCount = 32;

    /// <summary>
    /// The maximum number of octets-to-node-set re-parses — the section 4.3.3.2 default conversion,
    /// performed wherever a transform needs a node-set but octets arrive, including the reference's
    /// initial dereference — one <c>Reference</c>'s chain may perform before <see cref="TryComputeDigestInput"/>
    /// refuses with <see cref="XmlSignatureProcessingFailure.ReparseDepthExceeded"/> — a documented
    /// hardening bound this library imposes.
    /// </summary>
    public const int MaximumReparseDepth = 4;

    /// <summary>
    /// The maximum byte length of one <c>InclusiveNamespaces PrefixList</c> attribute value a
    /// <c>Transform</c> or a <c>SignedInfo</c>'s <c>CanonicalizationMethod</c> may carry before
    /// canonicalization refuses with <see cref="XmlSignatureProcessingFailure.InvalidCanonicalizationParameter"/>
    /// — a documented hardening bound this library imposes; Exclusive XML Canonicalization 1.0 sets no such
    /// bound, and the attribute value is otherwise fully attacker-controlled on the engine's hot path.
    /// </summary>
    public const int MaximumPrefixListByteLength = 4096;


    /// <summary>
    /// One frame of the iterative walk <see cref="CollectBase64SourceText"/> performs to select a
    /// node-set's text nodes in document order, mirroring the frame shape <see cref="XmlCanonicalRenderer"/>
    /// uses for the same reasons: no recursion over caller-controlled document depth, and node-set
    /// membership (excluded subtrees, the element-subtree apex) carried down from parent to child in
    /// constant time rather than re-derived from the ancestor axis at every node.
    /// </summary>
    private struct TextWalkFrame
    {
        /// <summary>The next child of the frame's node to visit, or -1 when exhausted.</summary>
        public int NextChild;

        /// <summary>Whether the frame's node is the element-subtree apex or a descendant of it.</summary>
        public bool IsUnderApex;
    }


    /// <summary>
    /// Computes the digest input octets for one <c>Reference</c> of a <c>Signature</c>'s <c>SignedInfo</c>:
    /// dereferences its <c>URI</c> (<see cref="XmlReferenceDereferencer"/>), runs its <c>Transforms</c> in
    /// order, and converts the chain's final result to octets, tagged
    /// <see cref="BufferTags.XmlDigestInput"/> — the data section 3.2.1 step 2.1 "obtains" and step 2.2
    /// digests with the <c>Reference</c>'s <c>DigestMethod</c>.
    /// </summary>
    /// <param name="table">The document <paramref name="signature"/> was read from — refused with
    /// <see cref="XmlSignatureProcessingFailure.TableMismatch"/> when it is not the
    /// identical <see cref="XmlNodeTable"/> instance <paramref name="signature"/> was read over.</param>
    /// <param name="signature">The signature whose reference's digest input is computed.</param>
    /// <param name="referenceOrdinal">The ordinal of the <c>Reference</c> within
    /// <see cref="XmlSignedInfo.References"/>.</param>
    /// <param name="resolver">The external-dereference delegate for a non-same-document <c>URI</c>, or
    /// <see langword="null"/> when the caller supplies none.</param>
    /// <param name="pool">The pool every intermediate and returned buffer is rented from.</param>
    /// <param name="digestInput">The digest input octets on success; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the digest input was computed.</returns>
    public static bool TryComputeDigestInput(XmlNodeTable table, XmlSignature signature, int referenceOrdinal, XmlReferenceResolver? resolver, BaseMemoryPool pool, [NotNullWhen(true)] out PooledMemory? digestInput, out XmlSignatureProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(pool);
        digestInput = null;
        if(!signature.IsOver(table))
        {
            error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.TableMismatch, 0);

            return false;
        }

        return TryComputeDigestInputCore(table, signature.SignedInfo.References, referenceOrdinal, resolver, pool, out digestInput, out error);
    }


    /// <summary>
    /// Computes the digest input octets for one <c>Reference</c> of a <c>ds:Manifest</c>:
    /// section 5.1's "the digests within such a <c>Manifest</c> are checked at the application's
    /// discretion" needs a way to actually run one of those references through the same engine
    /// <see cref="TryComputeDigestInput(XmlNodeTable, XmlSignature, int, XmlReferenceResolver?, BaseMemoryPool, out PooledMemory?, out XmlSignatureProcessingError)"/>
    /// applies to a <c>SignedInfo</c> reference — dereferencing, the transform chain and the section 4.3.3.2
    /// final conversion are identical either way, so both overloads share
    /// <see cref="TryComputeDigestInputCore"/> rather than duplicating the engine.
    /// </summary>
    /// <param name="table">The document <paramref name="manifest"/> was read from — refused with
    /// <see cref="XmlSignatureProcessingFailure.TableMismatch"/> when it is not the
    /// identical <see cref="XmlNodeTable"/> instance <paramref name="manifest"/> was read over.</param>
    /// <param name="manifest">The manifest whose reference's digest input is computed.</param>
    /// <param name="referenceOrdinal">The ordinal of the <c>Reference</c> within
    /// <see cref="XmlManifest.References"/>.</param>
    /// <param name="resolver">The external-dereference delegate for a non-same-document <c>URI</c>, or
    /// <see langword="null"/> when the caller supplies none.</param>
    /// <param name="pool">The pool every intermediate and returned buffer is rented from.</param>
    /// <param name="digestInput">The digest input octets on success; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the digest input was computed.</returns>
    public static bool TryComputeDigestInput(XmlNodeTable table, XmlManifest manifest, int referenceOrdinal, XmlReferenceResolver? resolver, BaseMemoryPool pool, [NotNullWhen(true)] out PooledMemory? digestInput, out XmlSignatureProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(pool);
        digestInput = null;
        if(!manifest.IsOver(table))
        {
            error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.TableMismatch, 0);

            return false;
        }

        return TryComputeDigestInputCore(table, manifest.References, referenceOrdinal, resolver, pool, out digestInput, out error);
    }


    /// <summary>
    /// The engine core both <see cref="TryComputeDigestInput(XmlNodeTable, XmlSignature, int, XmlReferenceResolver?, BaseMemoryPool, out PooledMemory?, out XmlSignatureProcessingError)"/>
    /// and its <see cref="XmlManifest"/> overload share: dereference, run the transform chain, and convert
    /// the final result to <see cref="BufferTags.XmlDigestInput"/>-tagged octets. The caller has already
    /// proven <paramref name="table"/> is the identical instance <paramref name="references"/> was read
    /// over, so every node-set the chain builds — the dereferenced set, any
    /// <see cref="XmlNodeSet.Excluding"/> composition, any <see cref="TryReparse"/> result — is valid over
    /// a table this method itself controls.
    /// </summary>
    private static bool TryComputeDigestInputCore(XmlNodeTable table, IReadOnlyList<XmlReference> references, int referenceOrdinal, XmlReferenceResolver? resolver, BaseMemoryPool pool, [NotNullWhen(true)] out PooledMemory? digestInput, out XmlSignatureProcessingError error)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(referenceOrdinal);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(referenceOrdinal, references.Count);

        return TryComputeDigestInputForReference(table, references[referenceOrdinal], resolver, pool, out digestInput, out error);
    }


    /// <summary>
    /// Computes the digest input octets for one already-read <c>ds:Reference</c>, independent of any owning
    /// <c>Signature</c>/<c>Manifest</c> aggregate: dereferences its <c>URI</c>, runs its <c>Transforms</c> in
    /// order, and converts the chain's final result to octets, exactly as
    /// <see cref="TryComputeDigestInputCore"/> does for a reference indexed out of a list — the two share
    /// this body rather than duplicating it (the list-indexing overloads exist for callers holding a whole
    /// <c>SignedInfo</c>/<c>Manifest</c>; this one for a XAdES <c>Include</c> mechanism's clause 5.1.4.4.2.3
    /// step 2, which locates a single, standalone <c>ds:Reference</c> element by <c>Include</c>'s own
    /// bare-name XPointer and has no owning aggregate to index into).
    /// </summary>
    /// <param name="table">The document <paramref name="reference"/> was read from — refused with
    /// <see cref="XmlSignatureProcessingFailure.TableMismatch"/> when it is not the identical
    /// <see cref="XmlNodeTable"/> instance <paramref name="reference"/> was read over.</param>
    /// <param name="reference">The reference whose digest input is computed.</param>
    /// <param name="resolver">The external-dereference delegate for a non-same-document <c>URI</c>, or
    /// <see langword="null"/> when the caller supplies none.</param>
    /// <param name="pool">The pool every intermediate and returned buffer is rented from.</param>
    /// <param name="digestInput">The digest input octets on success; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the digest input was computed.</returns>
    internal static bool TryComputeDigestInputForReference(XmlNodeTable table, XmlReference reference, XmlReferenceResolver? resolver, BaseMemoryPool pool, [NotNullWhen(true)] out PooledMemory? digestInput, out XmlSignatureProcessingError error)
    {
        digestInput = null;
        var reparsedTables = new List<XmlNodeTable>();
        PooledMemory? currentOctets = null;
        try
        {
            if(!TryRunReferenceTransformChain(table, reference, resolver, pool, reparsedTables, out bool isNodeSet, out XmlNodeSet currentNodeSet, out currentOctets, out error))
            {
                return false;
            }

            if(isNodeSet)
            {
                //Section 4.3.3.2's own default: the final node-set converts to
                //octets via Canonical XML 1.0 rendered AS IS — comment emission governed solely by whether
                //the set itself excludes comments (its own WithoutComments mark, applied at dereference
                //time), never by this conversion. The with-comments variant is requested unconditionally;
                //the renderer's own gate (isWithComments && !nodeSet.ExcludesComments) then reproduces
                //exactly the set's own mark either way. §4.3.3.3 lines 1947-1960: "when [XML-C14N] ... is
                //passed a node-set, it processes the node-set as is: with or without comments." Every
                //node-set this engine ever builds is valid over its own table by construction (apex/
                //exclusion indices are always element indices this engine itself located, and the
                //table-identity guard on both public entry points rules out the one input-dependent way
                //that could fail), so this conversion cannot be refused by input content. The tag-
                //parameterized overload produces BufferTags.XmlDigestInput octets directly rather than
                //copying a BufferTags.XmlCanonical result solely to retag it.
                if(!XmlCanonicalization.TryCanonicalize(currentNodeSet.Table!, currentNodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10WithComments, pool, BufferTags.XmlDigestInput, out digestInput, out XmlCanonicalizationError finalError))
                {
                    throw new InvalidOperationException($"Converting the final chain node-set to octets must not fail, but failed with {finalError.Failure}.");
                }

                error = default;

                return true;
            }

            digestInput = PooledMemory.FromBytes(currentOctets!.AsReadOnlySpan(), pool, BufferTags.XmlDigestInput);
            error = default;

            return true;
        }
        finally
        {
            currentOctets?.Dispose();
            for(int i = 0; i < reparsedTables.Count; ++i)
            {
                reparsedTables[i].Dispose();
            }
        }
    }


    /// <summary>
    /// Dereferences <paramref name="reference"/>'s <c>URI</c> and runs its <c>Transforms</c> chain in order —
    /// the section 4.3.3.2 dereference-then-transform-chain core <see cref="TryComputeDigestInputForReference"/>
    /// and the clause 5.2.8.1/5.2.8.2 message-imprint variant below share unchanged, leaving only the FINAL
    /// node-set-to-octets conversion (section 4.3.3.2's own fixed default in one case, a caller-supplied
    /// algorithm in the other) to each caller — the two procedures are identical up to that one step, so
    /// the shipped engine needs an ADDITIVE extension, not a duplicate.
    /// </summary>
    private static bool TryRunReferenceTransformChain(
        XmlNodeTable table,
        XmlReference reference,
        XmlReferenceResolver? resolver,
        BaseMemoryPool pool,
        List<XmlNodeTable> reparsedTables,
        out bool isNodeSet,
        out XmlNodeSet currentNodeSet,
        out PooledMemory? currentOctets,
        out XmlSignatureProcessingError error)
    {
        isNodeSet = false;
        currentNodeSet = default;
        currentOctets = null;
        if(!ReferenceEquals(reference.Table, table))
        {
            error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.TableMismatch, 0);

            return false;
        }

        if(reference.Transforms.Count > MaximumTransformCount)
        {
            error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.TransformCountExceeded, 0);

            return false;
        }

        //The dereference itself runs after both cheap checks above, not before them: a resolver-returned
        //PooledMemory (XmlDereferenceResult.ExternalOctets) must never exist outside protection between
        //TryDereference returning and ownership transferring into currentOctets below — the caller's own
        //try/finally around this call provides that protection.
        if(!XmlReferenceDereferencer.TryDereference(table, reference, resolver, pool, out XmlDereferenceResult dereferenced, out error))
        {
            return false;
        }

        isNodeSet = dereferenced.IsNodeSet;
        currentNodeSet = isNodeSet ? dereferenced.NodeSet : default;
        currentOctets = isNodeSet ? null : dereferenced.ExternalOctets;

        int reparseCount = 0;
        foreach(XmlTransform transform in reference.Transforms)
        {
            if(!TryApplyTransform(transform, pool, reparsedTables, ref reparseCount, ref isNodeSet, ref currentNodeSet, ref currentOctets, out error))
            {
                return false;
            }
        }

        error = default;

        return true;
    }


    /// <summary>
    /// Computes one <c>ds:Reference</c>'s contribution to a XAdES message-imprint input, per steps a)-d) of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clauses 5.2.8.1/5.2.8.2 (and the same
    /// lettered steps clause 5.5.2.3/5.5.2.4 restate for <c>ArchiveTimeStamp</c>'s own step 3),
    /// <see cref="XAdESArchiveTimeStampImprint"/>): dereferences <paramref name="reference"/>'s <c>URI</c> and
    /// runs its <c>Transforms</c> chain exactly as
    /// <see cref="TryComputeDigestInputForReference"/> does (<see cref="TryRunReferenceTransformChain"/>), but
    /// converts a leftover node-set using <paramref name="canonicalizationAlgorithm"/> — the qualifying
    /// property's OWN clause-4.5-resolved algorithm ("canonicalize it as specified in clause 4.5 of the
    /// present document," steps b)/c)) — rather than XMLDSIG's fixed section 4.3.3.2 default. This is the one
    /// place the XAdES procedure diverges from the shipped XMLDSIG digest-input engine; octets already (no
    /// node-set left after the chain) pass through untouched either way (step d, "concatenate the resulting
    /// octets").
    /// </summary>
    /// <param name="table">The document <paramref name="reference"/> was read from — refused with
    /// <see cref="XmlSignatureProcessingFailure.TableMismatch"/> when it is not the identical
    /// <see cref="XmlNodeTable"/> instance <paramref name="reference"/> was read over.</param>
    /// <param name="reference">The reference whose message-imprint contribution is computed.</param>
    /// <param name="canonicalizationAlgorithm">The qualifying property's own clause-4.5-resolved
    /// canonicalization algorithm (<see cref="XAdESCanonicalizationManagement.TryResolve"/>), applied only
    /// when the chain's final result is still a node-set.</param>
    /// <param name="prefixList">The exclusive-family <c>InclusiveNamespaces PrefixList</c> the same
    /// resolution carries; ignored by the inclusive algorithm family.</param>
    /// <param name="resolver">The external-dereference delegate for a non-same-document <c>URI</c>, or
    /// <see langword="null"/> when the caller supplies none.</param>
    /// <param name="pool">The pool every intermediate and returned buffer is rented from.</param>
    /// <param name="contributionOctets">The octets to concatenate on success — the caller owns them, copies
    /// them into the running message-imprint input, and disposes them; never returned onward as a final
    /// result by itself.</param>
    /// <param name="error">The refusal on failure: every refusal
    /// <see cref="TryComputeDigestInputForReference"/> can produce, plus
    /// <see cref="XmlSignatureProcessingFailure.InvalidCanonicalizationParameter"/> for a malformed or
    /// over-length <paramref name="prefixList"/>.</param>
    /// <returns><see langword="true"/> when the contribution was computed.</returns>
    internal static bool TryComputeMessageImprintContributionForReference(
        XmlNodeTable table,
        XmlReference reference,
        XmlCanonicalizationAlgorithm canonicalizationAlgorithm,
        ReadOnlySpan<byte> prefixList,
        XmlReferenceResolver? resolver,
        BaseMemoryPool pool,
        [NotNullWhen(true)] out PooledMemory? contributionOctets,
        out XmlSignatureProcessingError error)
    {
        contributionOctets = null;
        var reparsedTables = new List<XmlNodeTable>();
        PooledMemory? currentOctets = null;
        try
        {
            if(!TryRunReferenceTransformChain(table, reference, resolver, pool, reparsedTables, out bool isNodeSet, out XmlNodeSet currentNodeSet, out currentOctets, out error))
            {
                return false;
            }

            if(isNodeSet)
            {
                if(!TryCanonicalizeForAlgorithm(currentNodeSet.Table!, currentNodeSet, canonicalizationAlgorithm, prefixList, pool, out contributionOctets, out XmlCanonicalizationError canonicalizationError))
                {
                    error = new XmlSignatureProcessingError(MapCanonicalizationFailure(canonicalizationError.Failure), canonicalizationError.ByteOffset);

                    return false;
                }

                error = default;

                return true;
            }

            contributionOctets = PooledMemory.FromBytes(currentOctets!.AsReadOnlySpan(), pool, BufferTags.XmlDigestInput);
            error = default;

            return true;
        }
        finally
        {
            currentOctets?.Dispose();
            for(int i = 0; i < reparsedTables.Count; ++i)
            {
                reparsedTables[i].Dispose();
            }
        }
    }


    /// <summary>
    /// Computes a whole XAdES message-imprint input over an ORDERED list of <c>ds:Reference</c> elements: the
    /// shared "initialize an empty octet stream, process each reference per steps a)-d), concatenate" shape
    /// clauses 5.2.8.1 and 5.2.8.2 both state (steps 1)-2) of each), differing only in how each caller selects
    /// and orders <paramref name="references"/> — <c>XAdESAllDataObjectsTimeStampImprint</c> filters
    /// <c>ds:SignedInfo</c>'s own reference list; <c>XAdESIndividualDataObjectsTimeStampImprint</c> resolves
    /// one reference per <c>Include</c>, in <c>Include</c> document order.
    /// </summary>
    /// <param name="table">The document every reference in <paramref name="references"/> was read from.</param>
    /// <param name="references">The references to process, already in the order their contributions must
    /// concatenate in.</param>
    /// <param name="canonicalizationAlgorithm">The qualifying property's own clause-4.5-resolved
    /// canonicalization algorithm.</param>
    /// <param name="prefixList">The exclusive-family <c>InclusiveNamespaces PrefixList</c> the same
    /// resolution carries.</param>
    /// <param name="resolver">The external-dereference delegate for a non-same-document <c>URI</c>, or
    /// <see langword="null"/> when the caller supplies none.</param>
    /// <param name="pool">The pool every intermediate and returned buffer is rented from.</param>
    /// <param name="imprintInput">The concatenated message-imprint input octets on success, tagged
    /// <see cref="BufferTags.XmlDigestInput"/>; the caller owns and must dispose them. An empty
    /// <paramref name="references"/> list produces empty (but non-null) octets — step 1)'s "initialize the
    /// final octet stream as an empty octet stream" is vacuously satisfied when there is nothing to
    /// concatenate.</param>
    /// <param name="error">The refusal on failure: every
    /// <see cref="TryComputeMessageImprintContributionForReference"/> refusal, for the first reference that
    /// fails.</param>
    /// <returns><see langword="true"/> when the imprint input was computed.</returns>
    internal static bool TryComputeMessageImprintInputForReferences(
        XmlNodeTable table,
        IReadOnlyList<XmlReference> references,
        XmlCanonicalizationAlgorithm canonicalizationAlgorithm,
        ReadOnlySpan<byte> prefixList,
        XmlReferenceResolver? resolver,
        BaseMemoryPool pool,
        [NotNullWhen(true)] out PooledMemory? imprintInput,
        out XmlSignatureProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(references);
        ArgumentNullException.ThrowIfNull(pool);
        imprintInput = null;
        using var output = new PooledStructList<byte>(pool, 256);
        for(int i = 0; i < references.Count; ++i)
        {
            PooledMemory? contribution = null;
            try
            {
                if(!TryComputeMessageImprintContributionForReference(table, references[i], canonicalizationAlgorithm, prefixList, resolver, pool, out contribution, out error))
                {
                    return false;
                }

                output.AddRange(contribution.AsReadOnlySpan());
            }
            finally
            {
                contribution?.Dispose();
            }
        }

        imprintInput = PooledMemory.FromBytes(output.AsSpan(), pool, BufferTags.XmlDigestInput);
        error = default;

        return true;
    }


    /// <summary>
    /// Computes the canonical <c>SignedInfo</c> octets core validation signs and verifies: the element
    /// subtree of <paramref name="signature"/>'s <c>SignedInfo</c> — itself, its descendants, and the
    /// attribute and namespace nodes of it and its descendant elements, per section 4.3.1's bullet one MUST
    /// — canonicalized by its own declared <c>CanonicalizationMethod</c>, tagged
    /// <see cref="BufferTags.XmlCanonical"/> (unlike <see cref="TryComputeDigestInput(XmlNodeTable, XmlSignature, int, XmlReferenceResolver?, BaseMemoryPool, out PooledMemory?, out XmlSignatureProcessingError)"/>'s
    /// <see cref="BufferTags.XmlDigestInput"/>: this method's output is never a per-reference digest input).
    /// Section 4.3.3.3's same-document comment-stripping rules do not apply here: comments inside
    /// <c>SignedInfo</c> render or not purely by the algorithm variant.
    /// </summary>
    /// <param name="table">The document <paramref name="signature"/> was read from — refused with
    /// <see cref="XmlSignatureProcessingFailure.TableMismatch"/> when it is not the
    /// identical <see cref="XmlNodeTable"/> instance <paramref name="signature"/> was read over.</param>
    /// <param name="signature">The signature whose <c>SignedInfo</c> is canonicalized.</param>
    /// <param name="pool">The pool every buffer is rented from.</param>
    /// <param name="signedInfoOctets">The canonical octets on success, tagged
    /// <see cref="BufferTags.XmlCanonical"/>; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XmlSignatureProcessingFailure.UnsupportedCanonicalizationMethod"/> when the declared
    /// <c>CanonicalizationMethod Algorithm</c> is not one of the six clause 6.3(d) URIs, or
    /// <see cref="XmlSignatureProcessingFailure.InvalidCanonicalizationParameter"/> for a malformed or
    /// over-length <c>InclusiveNamespaces PrefixList</c>.</param>
    /// <returns><see langword="true"/> when the canonical octets were produced.</returns>
    public static bool TryComputeSignedInfoOctets(XmlNodeTable table, XmlSignature signature, BaseMemoryPool pool, [NotNullWhen(true)] out PooledMemory? signedInfoOctets, out XmlSignatureProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(pool);
        signedInfoOctets = null;
        if(!signature.IsOver(table))
        {
            error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.TableMismatch, 0);

            return false;
        }

        XmlCanonicalizationMethodInfo method = signature.SignedInfo.CanonicalizationMethod;
        if(!TryMapCanonicalizationAlgorithm(method.Algorithm, out XmlCanonicalizationAlgorithm algorithm))
        {
            error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.UnsupportedCanonicalizationMethod, 0);

            return false;
        }

        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, signature.SignedInfo.ElementIndex);
        if(!TryCanonicalizeForAlgorithm(table, nodeSet, algorithm, method.PrefixList, pool, out PooledMemory? canonicalOctets, out XmlCanonicalizationError canonicalizationError))
        {
            error = new XmlSignatureProcessingError(MapCanonicalizationFailure(canonicalizationError.Failure), canonicalizationError.ByteOffset);

            return false;
        }

        signedInfoOctets = canonicalOctets;
        error = default;

        return true;
    }


    /// <summary>
    /// Dispatches one <c>Transform</c> to its family: the six canonicalization algorithms
    /// (<see cref="TryApplyCanonicalizationTransform"/>), base64 (<see cref="TryApplyBase64Transform"/>),
    /// enveloped-signature (<see cref="TryApplyEnvelopedSignatureTransform"/>), or one of the recognized
    /// but unexecuted dispositions.
    /// </summary>
    private static bool TryApplyTransform(XmlTransform transform, BaseMemoryPool pool, List<XmlNodeTable> reparsedTables, ref int reparseCount, ref bool isNodeSet, ref XmlNodeSet currentNodeSet, ref PooledMemory? currentOctets, out XmlSignatureProcessingError error)
    {
        ReadOnlySpan<byte> algorithm = transform.Algorithm;
        if(algorithm.SequenceEqual(XmlSignatureIdentifiers.Base64TransformUriUtf8))
        {
            return TryApplyBase64Transform(pool, ref isNodeSet, ref currentNodeSet, ref currentOctets, out error);
        }

        if(algorithm.SequenceEqual(XmlSignatureIdentifiers.EnvelopedSignatureTransformUriUtf8))
        {
            return TryApplyEnvelopedSignatureTransform(transform, pool, reparsedTables, ref reparseCount, ref isNodeSet, ref currentNodeSet, ref currentOctets, out error);
        }

        if(TryMapCanonicalizationAlgorithm(algorithm, out XmlCanonicalizationAlgorithm canonicalizationAlgorithm))
        {
            return TryApplyCanonicalizationTransform(transform, canonicalizationAlgorithm, pool, reparsedTables, ref reparseCount, ref isNodeSet, ref currentNodeSet, ref currentOctets, out error);
        }

        if(algorithm.SequenceEqual(XmlSignatureIdentifiers.XPathTransformUriUtf8) || algorithm.SequenceEqual(XmlSignatureIdentifiers.XPathFilter2TransformUriUtf8))
        {
            //Section 6.6.3 ("Recommended") and ETSI EN 319 132-1 clause 6.3(g)'s XPath Filter 2.0: both are
            //recognized identifiers this leaf does not yet execute. STAGED (needs the
            //hand-rolled XPath 1.0 evaluator) — not a deviation.
            error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.TransformNotYetSupported, 0);

            return false;
        }

        if(algorithm.SequenceEqual(XmlSignatureIdentifiers.XsltTransformUriUtf8) || algorithm.SequenceEqual(XmlSignatureIdentifiers.RelationshipTransformUriUtf8))
        {
            //Section 6.6.5 XSLT ("Optional") and the OOXML Relationships transform: both are recognized
            //identifiers this leaf refuses to execute. DEVIATION — executing
            //attacker-supplied stylesheets is the section 8.3 "unacceptable processing or memory demand"
            //class this surface's DOCTYPE refusal already closes the door on for the same reason; OPC
            //package signing is outside the document classes this library models.
            error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.TransformRefused, 0);

            return false;
        }

        error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.UnsupportedTransform, 0);

        return false;
    }


    /// <summary>
    /// Applies one of the six canonicalization transforms of section 6.6.1: octets arriving are parsed to
    /// a node-set first (the generic section 4.3.3.2 default, counted toward <see cref="MaximumReparseDepth"/>),
    /// then the (possibly just-reparsed) node-set canonicalizes with the transform's own algorithm and
    /// <c>InclusiveNamespaces PrefixList</c>. The chain's data stays octets afterwards — canonicalization
    /// always produces octets.
    /// </summary>
    private static bool TryApplyCanonicalizationTransform(XmlTransform transform, XmlCanonicalizationAlgorithm algorithm, BaseMemoryPool pool, List<XmlNodeTable> reparsedTables, ref int reparseCount, ref bool isNodeSet, ref XmlNodeSet currentNodeSet, ref PooledMemory? currentOctets, out XmlSignatureProcessingError error)
    {
        if(!isNodeSet)
        {
            if(!TryReparse(pool, reparsedTables, ref reparseCount, ref currentOctets, out currentNodeSet, out error))
            {
                return false;
            }

            isNodeSet = true;
        }

        bool isCanonicalized = TryCanonicalizeForAlgorithm(currentNodeSet.Table!, currentNodeSet, algorithm, transform.PrefixList, pool, out PooledMemory? canonicalOctets, out XmlCanonicalizationError canonicalizationError);
        if(!isCanonicalized)
        {
            error = new XmlSignatureProcessingError(MapCanonicalizationFailure(canonicalizationError.Failure), canonicalizationError.ByteOffset);

            return false;
        }

        currentOctets = canonicalOctets;
        isNodeSet = false;
        error = default;

        return true;
    }


    /// <summary>
    /// Applies the base64 transform of section 6.6.2: octets arriving decode directly; a node-set arriving
    /// converts to octets by the transform's own rule — "applying an XPath transform with expression
    /// <c>self::text()</c>, then taking the string-value of the node-set" — NEVER by canonicalization.
    /// Either way the result then base64-decodes per the XSD <c>base64Binary</c> lexical
    /// space.
    /// </summary>
    private static bool TryApplyBase64Transform(BaseMemoryPool pool, ref bool isNodeSet, ref XmlNodeSet currentNodeSet, ref PooledMemory? currentOctets, out XmlSignatureProcessingError error)
    {
        bool isDecoded;
        PooledMemory? decoded;
        XmlSignatureReadError decodeError;
        if(isNodeSet)
        {
            using var textOctets = new PooledStructList<byte>(pool, 256);
            CollectBase64SourceText(currentNodeSet.Table!, in currentNodeSet, pool, textOctets);
            isDecoded = XmlBase64Content.TryDecode(textOctets.AsSpan(), pool, out decoded, out decodeError);
        }
        else
        {
            isDecoded = XmlBase64Content.TryDecode(currentOctets!.AsReadOnlySpan(), pool, out decoded, out decodeError);
        }

        if(!isDecoded)
        {
            error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.InvalidBase64Content, decodeError.ByteOffset);

            return false;
        }

        currentOctets?.Dispose();
        currentOctets = decoded;
        isNodeSet = false;
        error = default;

        return true;
    }


    /// <summary>
    /// Applies the enveloped-signature transform of section 6.6.4: octets arriving are parsed to a
    /// node-set first (counted toward <see cref="MaximumReparseDepth"/>), then the nearest <c>ds:Signature</c>
    /// ancestor of the <c>Transform</c> element itself — the signature currently being processed — is
    /// excluded via <see cref="XmlNodeSet.Excluding"/>, without an XPath engine, matching the section 6.6.4
    /// MUST that the output be identical to the defining XPath expression's.
    /// </summary>
    /// <remarks>
    /// When the current node-set is over a different table than the one the
    /// <c>Transform</c> element itself lives in — a mid-chain octets-to-node-set re-parse (section 4.3.3.2's
    /// default conversion) produced an unrelated document instance before this transform ran — this REFUSES
    /// with <see cref="XmlSignatureProcessingFailure.EnvelopedSignatureSourceMismatch"/> rather than
    /// silently leaving the node-set unmodified. Section 6.6.4 line 3794: "may only be applied to a node-set
    /// from its parent XML document." Tracing the defining XPath expression itself confirms a refusal, not
    /// a no-op, is the right output: <c>here()</c> (section 6.6.3's function definition, line 3692) "results
    /// in an error if the containing XPath expression does not appear in the same XML document against
    /// which the XPath expression is being evaluated" — exactly this shape, since the <c>Transform</c>
    /// element (where the expression "appears") lives in the signature's original document while the
    /// current node-set is now over the re-parsed one.
    /// </remarks>
    private static bool TryApplyEnvelopedSignatureTransform(XmlTransform transform, BaseMemoryPool pool, List<XmlNodeTable> reparsedTables, ref int reparseCount, ref bool isNodeSet, ref XmlNodeSet currentNodeSet, ref PooledMemory? currentOctets, out XmlSignatureProcessingError error)
    {
        if(!isNodeSet)
        {
            if(!TryReparse(pool, reparsedTables, ref reparseCount, ref currentOctets, out currentNodeSet, out error))
            {
                return false;
            }

            isNodeSet = true;
        }

        if(!ReferenceEquals(currentNodeSet.Table, transform.Table))
        {
            error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.EnvelopedSignatureSourceMismatch, 0);

            return false;
        }

        int nearestAncestorSignatureIndex = FindNearestAncestorSignatureElementIndex(transform.Table, transform.ElementIndex);
        if(nearestAncestorSignatureIndex >= 0)
        {
            currentNodeSet = currentNodeSet.Excluding(nearestAncestorSignatureIndex);
        }

        error = default;

        return true;
    }


    /// <summary>
    /// Parses the current octets into a fresh node-set over a newly parsed <see cref="XmlNodeTable"/> — the
    /// section 4.3.3.2 default octets-to-node-set conversion every canonicalization and
    /// enveloped-signature transform applies when octets arrive instead of a node-set. The consumed octets
    /// are disposed immediately; the new table is added to <paramref name="reparsedTables"/> for the
    /// engine's caller to dispose once the whole chain completes.
    /// </summary>
    private static bool TryReparse(BaseMemoryPool pool, List<XmlNodeTable> reparsedTables, ref int reparseCount, ref PooledMemory? currentOctets, out XmlNodeSet reparsedNodeSet, out XmlSignatureProcessingError error)
    {
        reparsedNodeSet = default;
        if(reparseCount >= MaximumReparseDepth)
        {
            error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.ReparseDepthExceeded, 0);

            return false;
        }

        XmlNodeTable? reparsedTable = null;
        try
        {
            bool isParsed = XmlNodeTable.TryParse(currentOctets!.AsReadOnlyMemory(), pool, out reparsedTable, out XmlReadError parseError);
            currentOctets.Dispose();
            currentOctets = null;
            if(!isParsed)
            {
                error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.ReferenceParseFailed, 0, parseError);

                return false;
            }

            XmlNodeTable ownedTable = reparsedTable!;
            reparsedTables.Add(ownedTable);
            reparsedTable = null;
            ++reparseCount;
            reparsedNodeSet = XmlNodeSet.WholeDocument(ownedTable);
            error = default;

            return true;
        }
        finally
        {
            reparsedTable?.Dispose();
        }
    }


    /// <summary>
    /// Canonicalizes a node-set with one algorithm and one <c>InclusiveNamespaces PrefixList</c> value, the
    /// one dispatch both a <c>Transform</c>'s and a <c>CanonicalizationMethod</c>'s parameters share:
    /// exclusive-family algorithms honor a non-empty <paramref name="prefixList"/> through
    /// <see cref="XmlCanonicalization.TryCanonicalizeExclusive"/>; the inclusive families ignore it.
    /// <paramref name="prefixList"/> is length-capped at
    /// <see cref="MaximumPrefixListByteLength"/> before it is tokenized — the attribute value is fully
    /// attacker-controlled and this dispatch runs on the engine's hot path (once per exclusive-family
    /// canonicalization, up to <see cref="MaximumTransformCount"/> times per reference). Shared with
    /// <see cref="XAdESIncludeProcessing"/>'s clause 5.1.4.4.2.3 step 3 (the
    /// clause-4.5 canonicalization resolution): a XAdES time-stamp container's node-set retrieval reuses this
    /// dispatch rather than a second implementation of the exclusive-family/prefix-list handling.
    /// </summary>
    internal static bool TryCanonicalizeForAlgorithm(XmlNodeTable table, XmlNodeSet nodeSet, XmlCanonicalizationAlgorithm algorithm, ReadOnlySpan<byte> prefixList, BaseMemoryPool pool, [NotNullWhen(true)] out PooledMemory? canonicalOctets, out XmlCanonicalizationError error)
    {
        bool isExclusive = algorithm is XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10 or XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments;
        if(!isExclusive)
        {
            return XmlCanonicalization.TryCanonicalize(table, nodeSet, algorithm, pool, out canonicalOctets, out error);
        }

        bool isWithComments = algorithm == XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments;
        if(prefixList.IsEmpty)
        {
            return XmlCanonicalization.TryCanonicalizeExclusive(table, nodeSet, isWithComments, [], pool, out canonicalOctets, out error);
        }

        if(prefixList.Length > MaximumPrefixListByteLength)
        {
            canonicalOctets = null;
            error = new XmlCanonicalizationError(XmlCanonicalizationFailure.InvalidPrefixList, 0);

            return false;
        }

        List<string> tokens = TokenizePrefixList(prefixList);

        return XmlCanonicalization.TryCanonicalizeExclusive(table, nodeSet, isWithComments, CollectionsMarshal.AsSpan(tokens), pool, out canonicalOctets, out error);
    }


    /// <summary>
    /// Splits an <c>InclusiveNamespaces PrefixList</c> attribute value on XML white space (production
    /// <c>S</c>) into one managed string per token: each token is transcoded on its
    /// own rather than the whole attribute value being materialized as a single managed string first — the
    /// house "no managed-string surfaces" discipline permits the small, individually-bounded per-token
    /// strings <see cref="XmlCanonicalization.TryCanonicalizeExclusive"/>'s own <c>ReadOnlySpan&lt;string&gt;</c>
    /// parameter shape requires, never one string sized to the whole (length-capped, but still
    /// attacker-influenced) attribute value. <see cref="XmlCanonicalization"/>'s own per-entry whitespace
    /// split (<c>TryParsePrefixList</c>) still runs over each returned token, but is a no-op there since
    /// every token here is already whitespace-free.
    /// </summary>
    /// <param name="prefixList">The raw <c>PrefixList</c> attribute value, at most
    /// <see cref="MaximumPrefixListByteLength"/> octets.</param>
    /// <returns>One string per whitespace-delimited token, in document order.</returns>
    private static List<string> TokenizePrefixList(ReadOnlySpan<byte> prefixList)
    {
        var tokens = new List<string>();
        int index = 0;
        while(index < prefixList.Length)
        {
            while(index < prefixList.Length && XmlCharacters.IsWhitespace(prefixList[index]))
            {
                ++index;
            }

            int start = index;
            while(index < prefixList.Length && !XmlCharacters.IsWhitespace(prefixList[index]))
            {
                ++index;
            }

            if(index > start)
            {
                tokens.Add(Encoding.UTF8.GetString(prefixList[start..index]));
            }
        }

        return tokens;
    }


    /// <summary>
    /// Maps a <c>CanonicalizationMethod</c>/<c>Transform Algorithm</c> URI onto its
    /// <see cref="XmlCanonicalizationAlgorithm"/>, exact-character, over the six identifiers
    /// <see cref="XmlSignatureIdentifiers"/> states. Shared with <see cref="XAdESIncludeProcessing"/>'s
    /// clause 4.5 canonicalization-method resolution: the six URIs clause 6.3(d)
    /// requires a XAdES validator to support are the same six this dispatch already recognizes.
    /// </summary>
    internal static bool TryMapCanonicalizationAlgorithm(ReadOnlySpan<byte> algorithmUri, out XmlCanonicalizationAlgorithm algorithm)
    {
        if(algorithmUri.SequenceEqual(XmlSignatureIdentifiers.CanonicalXml10UriUtf8))
        {
            algorithm = XmlCanonicalizationAlgorithm.CanonicalXml10;

            return true;
        }

        if(algorithmUri.SequenceEqual(XmlSignatureIdentifiers.CanonicalXml10WithCommentsUriUtf8))
        {
            algorithm = XmlCanonicalizationAlgorithm.CanonicalXml10WithComments;

            return true;
        }

        if(algorithmUri.SequenceEqual(XmlSignatureIdentifiers.CanonicalXml11UriUtf8))
        {
            algorithm = XmlCanonicalizationAlgorithm.CanonicalXml11;

            return true;
        }

        if(algorithmUri.SequenceEqual(XmlSignatureIdentifiers.CanonicalXml11WithCommentsUriUtf8))
        {
            algorithm = XmlCanonicalizationAlgorithm.CanonicalXml11WithComments;

            return true;
        }

        if(algorithmUri.SequenceEqual(XmlSignatureIdentifiers.ExclusiveCanonicalXml10UriUtf8))
        {
            algorithm = XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10;

            return true;
        }

        if(algorithmUri.SequenceEqual(XmlSignatureIdentifiers.ExclusiveCanonicalXml10WithCommentsUriUtf8))
        {
            algorithm = XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments;

            return true;
        }

        algorithm = default;

        return false;
    }


    /// <summary>
    /// Translates a canonicalization refusal into a reference-processing one. Only
    /// <see cref="XmlCanonicalizationFailure.InvalidPrefixList"/> is reachable from input content this
    /// engine hands to <see cref="XmlCanonicalization"/>: every node-set this engine builds is valid over
    /// its own table by construction, so <see cref="XmlCanonicalizationFailure.UnsupportedNodeSet"/> and
    /// <see cref="XmlCanonicalizationFailure.InvalidNodeIndex"/> would signal an internal invariant
    /// violation rather than a refusable input. That invariant is provably total, not merely believed: both
    /// <see cref="TryComputeDigestInput(XmlNodeTable, XmlSignature, int, XmlReferenceResolver?, BaseMemoryPool, out PooledMemory?, out XmlSignatureProcessingError)"/>
    /// and <see cref="TryComputeSignedInfoOctets"/> refuse with
    /// <see cref="XmlSignatureProcessingFailure.TableMismatch"/> before any node-set this
    /// engine builds could ever be canonicalized against a table it was not built over, so this method's
    /// <see langword="throw"/> branch is unreachable by any caller-supplied argument — an invariant guard,
    /// not an input-validation refusal the house Result-shaped direction would otherwise ask this to become.
    /// </summary>
    private static XmlSignatureProcessingFailure MapCanonicalizationFailure(XmlCanonicalizationFailure failure)
    {
        if(failure == XmlCanonicalizationFailure.InvalidPrefixList)
        {
            return XmlSignatureProcessingFailure.InvalidCanonicalizationParameter;
        }

        throw new InvalidOperationException($"Canonicalizing a node-set this engine constructed itself must not fail with {failure}.");
    }


    /// <summary>
    /// Walks upward from an element to find the nearest ancestor <c>ds:Signature</c> element — the section
    /// 6.6.4 defining XPath expression's <c>here()/ancestor::dsig:Signature[1]</c> term, computed by a
    /// parent-chain walk instead of an XPath evaluator, per the section 6.6.4 footnote's permission.
    /// </summary>
    /// <param name="table">The table the element lives in.</param>
    /// <param name="elementIndex">The element to walk upward from.</param>
    /// <returns>The nearest ancestor <c>ds:Signature</c> element index, or -1 when none exists.</returns>
    private static int FindNearestAncestorSignatureElementIndex(XmlNodeTable table, int elementIndex)
    {
        for(int current = table.ParentOf(elementIndex); current > 0; current = table.ParentOf(current))
        {
            if(XmlSignatureModelGrammar.IsDsElement(table, current, "Signature"u8))
            {
                return current;
            }
        }

        return -1;
    }


    /// <summary>
    /// Collects a node-set's text-node string-value in document order into <paramref name="output"/> —
    /// section 6.6.2's "applying an XPath transform with expression <c>self::text()</c>, then taking the
    /// string-value of the node-set": every text node the set includes contributes its raw, already-resolved
    /// character content (<see cref="XmlNodeTable.ValueOf"/>), never re-escaped as markup, since this is a
    /// semantic value being handed to a base64 decoder, not octets being rendered as XML. An excluded
    /// subtree contributes nothing and is never descended into, matching
    /// <see cref="XmlCanonicalRenderer"/>'s own walk.
    /// </summary>
    private static void CollectBase64SourceText(XmlNodeTable table, in XmlNodeSet nodeSet, BaseMemoryPool pool, PooledStructList<byte> output)
    {
        using var stack = new PooledStructList<TextWalkFrame>(pool, 32);
        stack.Add(new TextWalkFrame { NextChild = table.FirstChildOf(table.RootIndex), IsUnderApex = false });
        while(stack.Count > 0)
        {
            ref TextWalkFrame frame = ref stack[stack.Count - 1];
            if(frame.NextChild < 0)
            {
                stack.Truncate(stack.Count - 1);

                continue;
            }

            int child = frame.NextChild;
            bool isUnderApexHere = frame.IsUnderApex;
            frame.NextChild = table.NextSiblingOf(child);
            switch(table.KindOf(child))
            {
                case XmlNodeKind.Element:
                    if(!nodeSet.IsExcludedElement(child))
                    {
                        bool isChildUnderApex = child == nodeSet.ApexElementIndex || isUnderApexHere;
                        stack.Add(new TextWalkFrame { NextChild = table.FirstChildOf(child), IsUnderApex = isChildUnderApex });
                    }

                    break;

                case XmlNodeKind.Text:
                    if(nodeSet.IsWholeDocument || isUnderApexHere)
                    {
                        output.AddRange(table.ValueOf(child));
                    }

                    break;
            }
        }
    }
}
