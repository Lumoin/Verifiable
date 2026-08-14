using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The clause 5.5.3 processing surface for <see cref="XAdESRenewedDigestsV2"/>: the XA-5.5.3-3 "shall not be
/// used" precondition (<see cref="TryDetermineIsUsePermitted"/>), and the two per-<see cref="XAdESRecomputedDigestValue"/>
/// input-construction primitives the XA-5.5.3-13 validation procedure's steps 3)/4) need
/// (<see cref="TryComputeOriginalRefDigestInput"/>, <see cref="TryComputeNewSDODigestValueInput"/>) plus
/// comparison scaffolding (<see cref="CompareDigest"/>) — this leaf never digests, so
/// every step that would require computing or comparing an actual digest takes the digest as an EXTERNALLY-
/// computed <see cref="ReadOnlySpan{T}"/> rather than performing it.
/// </summary>
/// <remarks>
/// The validation procedure's own step 2) — "retrieve the <c>ds:Reference</c> element referenced by that
/// <c>RecomputedDigestValue</c>'s <c>OriginalRefDigest</c> child" — identifies the target <c>ds:Reference</c> BY
/// DIGEST MATCH, not by URI: <c>OriginalRefDigest</c> is itself a digest VALUE (XA-5.5.3-11/-12 define it as the
/// digest of the candidate <c>ds:Reference</c> element, computed at generation time), so resolving step 2)
/// requires canonicalizing and digesting every candidate <c>ds:Reference</c> within the signature's signed
/// <c>ds:Manifest</c>(s) and comparing against the recorded value — a content-addressed lookup only a
/// crypto-enabled caller can perform. This leaf supplies the per-candidate INPUT that lookup and the subsequent
/// steps need (this type's two <c>TryCompute*Input</c> methods); the lookup itself, and every digest computation
/// and comparison the six-step procedure performs, is verification-side —
/// <c>Verifiable.Cryptography.Pki.XAdESLevelRules.CheckRenewedDigestsV2ReferenceLookupAsync</c> — this
/// crypto-free leaf's own boundary. This scope boundary is recorded, not silently narrowed.
/// </remarks>
public static class XAdESRenewedDigestsV2Processing
{
    /// <summary>
    /// The XA-5.5.3-3 precondition: "shall not be used if the signature contains no [...] signed
    /// <c>ds:Manifest</c> elements referencing detached data objects" — permitted exactly when at least one of
    /// <paramref name="manifests"/> is BOTH referenced by a same-document <c>ds:Reference</c> of
    /// <paramref name="signature"/>'s own <c>ds:SignedInfo</c> ("signed") AND itself carries at least one
    /// <c>ds:Reference</c> whose own <c>URI</c> is non-same-document ("detached" — outside this document, per
    /// the same same-document definition <see cref="XmlReferenceDereferencer"/>'s own remarks state).
    /// </summary>
    /// <param name="table">The document <paramref name="signature"/> and every one of <paramref name="manifests"/> were read from.</param>
    /// <param name="signature">The signature whose <c>ds:SignedInfo</c> is searched for a reference to each manifest.</param>
    /// <param name="manifests">Every <c>ds:Manifest</c> the caller has already read from the signature's own
    /// <c>ds:Object</c> content — this leaf never auto-discovers <c>ds:Manifest</c> elements (the same
    /// "caller reads what it recognizes" posture <see cref="XmlSignature"/>'s own remarks state), so the caller
    /// supplies whichever ones it found.</param>
    /// <param name="isPermitted">Whether the precondition is satisfied on success.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match
    /// <paramref name="signature"/> or any one of <paramref name="manifests"/>.</param>
    /// <returns><see langword="true"/> when the precondition was determined.</returns>
    public static bool TryDetermineIsUsePermitted(XmlNodeTable table, XmlSignature signature, IReadOnlyList<XmlManifest> manifests, out bool isPermitted, out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(manifests);
        isPermitted = false;
        if(!signature.IsOver(table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        for(int i = 0; i < manifests.Count; ++i)
        {
            XmlManifest manifest = manifests[i];
            if(!manifest.IsOver(table))
            {
                error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

                return false;
            }

            if(IsReferencedFromSignedInfo(signature, manifest) && HasDetachedReference(manifest))
            {
                isPermitted = true;
                error = default;

                return true;
            }
        }

        isPermitted = false;
        error = default;

        return true;
    }


    /// <summary>
    /// Tells whether <paramref name="manifest"/> is "signed": named by a same-document, bare-<c>#Id</c>
    /// <c>URI</c> on some <c>ds:Reference</c> of <paramref name="signature"/>'s own <c>ds:SignedInfo</c>.
    /// </summary>
    private static bool IsReferencedFromSignedInfo(XmlSignature signature, XmlManifest manifest)
    {
        if(!manifest.HasId)
        {
            return false;
        }

        foreach(XmlReference reference in signature.SignedInfo.References)
        {
            if(!reference.HasUri)
            {
                continue;
            }

            ReadOnlySpan<byte> uri = reference.Uri;
            if(!uri.IsEmpty && uri[0] == (byte)'#' && uri[1..].SequenceEqual(manifest.Id))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Tells whether <paramref name="manifest"/> carries at least one "detached" (non-same-document)
    /// <c>ds:Reference</c> — a <c>URI</c> that is neither empty nor a bare <c>#</c>-prefixed fragment.
    /// </summary>
    private static bool HasDetachedReference(XmlManifest manifest)
    {
        foreach(XmlReference reference in manifest.References)
        {
            if(reference.HasUri && !reference.Uri.IsEmpty && reference.Uri[0] != (byte)'#')
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Computes <c>OriginalRefDigest</c>'s own input: the candidate <c>ds:Reference</c> element subtree,
    /// canonicalized with <paramref name="renewedDigestsV2"/>'s own <c>ds:CanonicalizationMethod</c> — XA-
    /// 5.5.3-11/-12's "The <c>ds:Reference</c> shall be canonicalized using the canonicalization algorithm
    /// identified in the <c>RenewedDigestsV2</c>'s <c>ds:CanonicalizationMethod</c> child element." The caller
    /// digests the result with <see cref="XAdESRenewedDigestsV2.DigestMethodAlgorithm"/> and compares it against
    /// a recorded entry's <see cref="XAdESRecomputedDigestValue.OriginalRefDigestOctets"/> via
    /// <see cref="CompareDigest"/>.
    /// </summary>
    /// <param name="table">The document both arguments were read from.</param>
    /// <param name="renewedDigestsV2">The already-read <c>RenewedDigestsV2</c> supplying the canonicalization method.</param>
    /// <param name="candidateReference">The candidate <c>ds:Manifest</c> <c>ds:Reference</c> element.</param>
    /// <param name="pool">The pool the returned buffer is rented from.</param>
    /// <param name="input">The canonicalized <c>ds:Reference</c> octets on success, tagged
    /// <see cref="BufferTags.XmlDigestInput"/>; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match both
    /// arguments' own table;
    /// <see cref="XAdESProcessingFailure.UnsupportedCanonicalizationMethod"/> when
    /// <paramref name="renewedDigestsV2"/>'s <c>ds:CanonicalizationMethod Algorithm</c> is not one of the six
    /// clause 6.3(d) URIs;
    /// <see cref="XAdESProcessingFailure.InvalidCanonicalizationParameter"/> for a malformed or over-length
    /// <c>InclusiveNamespaces PrefixList</c>.</param>
    /// <returns><see langword="true"/> when the input was computed.</returns>
    public static bool TryComputeOriginalRefDigestInput(
        XmlNodeTable table,
        XAdESRenewedDigestsV2 renewedDigestsV2,
        XmlReference candidateReference,
        BaseMemoryPool pool,
        [NotNullWhen(true)] out PooledMemory? input,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(renewedDigestsV2);
        ArgumentNullException.ThrowIfNull(pool);
        input = null;
        if(!renewedDigestsV2.IsOver(table) || !ReferenceEquals(candidateReference.Table, table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        if(!XmlReferenceProcessing.TryMapCanonicalizationAlgorithm(renewedDigestsV2.CanonicalizationMethod.Algorithm, out XmlCanonicalizationAlgorithm algorithm))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.UnsupportedCanonicalizationMethod, 0);

            return false;
        }

        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, candidateReference.ElementIndex);
        PooledMemory? canonical = null;
        try
        {
            if(!XmlReferenceProcessing.TryCanonicalizeForAlgorithm(table, nodeSet, algorithm, renewedDigestsV2.CanonicalizationMethod.PrefixList, pool, out canonical, out XmlCanonicalizationError canonicalizationError))
            {
                error = XAdESCanonicalizationManagement.MapCanonicalizationFailure(canonicalizationError);

                return false;
            }

            //TryCanonicalizeForAlgorithm tags its result BufferTags.XmlCanonical; every sibling engine's PUBLIC
            //result carries BufferTags.XmlDigestInput instead, so this single-step engine retags to match rather
            //than leaking the intermediate tag, the same posture XAdESSignatureTimeStampImprint already takes.
            input = PooledMemory.FromBytes(canonical!.AsReadOnlySpan(), pool, BufferTags.XmlDigestInput);
            error = default;

            return true;
        }
        finally
        {
            canonical?.Dispose();
        }
    }


    /// <summary>
    /// Computes <c>NewSDODigestValue</c>'s own input: the candidate detached data object's octets after
    /// retrieval and <c>ds:Transforms</c> processing per XMLDSIG [1] clause 4.4.3.2 — WITHOUT the final digest
    /// step (XA-5.5.3-13 NOTE 2's own clarification: "explicitly not performed here [...] since a different
    /// digest algorithm [...] is used next"), mirroring
    /// <see cref="XmlReferenceProcessing.TryComputeDigestInputForReference"/>'s own digest-INPUT-not-digest
    /// split — this method delegates to it directly, since the two procedures are otherwise identical. The
    /// caller digests the result with <see cref="XAdESRenewedDigestsV2.DigestMethodAlgorithm"/> and compares it
    /// against a recorded entry's <see cref="XAdESRecomputedDigestValue.NewSDODigestValueOctets"/> via
    /// <see cref="CompareDigest"/>.
    /// </summary>
    /// <param name="table">The document <paramref name="candidateReference"/> was read from.</param>
    /// <param name="candidateReference">The candidate <c>ds:Manifest</c> <c>ds:Reference</c> naming the
    /// detached signed data object.</param>
    /// <param name="resolver">The external-dereference delegate the detached object's own <c>URI</c> needs —
    /// unlike every other reference this leaf processes, this one is EXPECTED to be non-same-document, per
    /// <see cref="TryDetermineIsUsePermitted"/>'s own detached-object precondition.</param>
    /// <param name="pool">The pool every intermediate and returned buffer is rented from.</param>
    /// <param name="input">The retrieval-and-transform-chain result octets on success, tagged
    /// <see cref="BufferTags.XmlDigestInput"/>; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match
    /// <paramref name="candidateReference"/>'s own table;
    /// <see cref="XAdESProcessingFailure.RenewedDigestsV2DetachedObjectProcessingFailed"/> — the XA-5.5.3-13
    /// step 3) "notify that retrieval [...] failed" outcome, a Result-shaped notification rather than an
    /// exception — for every dereference/transform-chain refusal
    /// <see cref="XmlReferenceProcessing.TryComputeDigestInputForReference"/> can itself produce, carried via
    /// <see cref="XAdESProcessingError.InnerProcessingError"/>.</param>
    /// <returns><see langword="true"/> when the input was computed.</returns>
    public static bool TryComputeNewSDODigestValueInput(
        XmlNodeTable table,
        XmlReference candidateReference,
        XmlReferenceResolver? resolver,
        BaseMemoryPool pool,
        [NotNullWhen(true)] out PooledMemory? input,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        input = null;
        if(!ReferenceEquals(candidateReference.Table, table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        if(!XmlReferenceProcessing.TryComputeDigestInputForReference(table, candidateReference, resolver, pool, out input, out XmlSignatureProcessingError innerError))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.RenewedDigestsV2DetachedObjectProcessingFailed, 0, innerError);

            return false;
        }

        error = default;

        return true;
    }


    /// <summary>
    /// Compares an externally-computed digest against a recorded value byte-for-byte — this leaf never digests,
    /// so every digest comparison XA-5.5.3-13 steps 4)-5) perform is the caller's own,
    /// using this as the equality primitive; a <see langword="false"/> result is XA-5.5.3-13 step 5)'s "notify a
    /// digest mismatch" outcome.
    /// </summary>
    /// <param name="externallyComputedDigest">The digest the caller computed, with the algorithm
    /// <see cref="XAdESRenewedDigestsV2.DigestMethodAlgorithm"/> names, over the octets
    /// <see cref="TryComputeOriginalRefDigestInput"/>/<see cref="TryComputeNewSDODigestValueInput"/> produced.</param>
    /// <param name="recordedDigestValueOctets">The recorded
    /// <see cref="XAdESRecomputedDigestValue.OriginalRefDigestOctets"/>/<see cref="XAdESRecomputedDigestValue.NewSDODigestValueOctets"/>
    /// value to compare against.</param>
    /// <returns><see langword="true"/> when the two match exactly.</returns>
    public static bool CompareDigest(ReadOnlySpan<byte> externallyComputedDigest, ReadOnlySpan<byte> recordedDigestValueOctets)
    {
        return externallyComputedDigest.SequenceEqual(recordedDigestValueOctets);
    }
}
