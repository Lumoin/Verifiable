using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The clause A.1.5.1.2/A.1.5.1.3 message-imprint input engine for <see cref="XAdESSigAndRefsTimeStampV2"/>: the
/// not-distributed variant (<see cref="TryComputeNotDistributedImprintInput"/>) and the distributed variant
/// (<see cref="TryComputeDistributedImprintInput"/>). Unlike <see cref="XAdESAllDataObjectsTimeStampImprint"/>/
/// <see cref="XAdESIndividualDataObjectsTimeStampImprint"/>/<c>XAdESArchiveTimeStampImprint</c>'s own step 3),
/// A.1.5.1 never processes a <c>ds:Reference</c> list's own dereference/transform-chain steps a)-d)
/// (<see cref="XmlReferenceProcessing.TryComputeMessageImprintInputForReferences"/>): both clauses canonicalize
/// whole qualifying-property (and <c>ds:SignatureValue</c>) element subtrees directly — the divergence recorded
/// here rather than smoothed over a nominal "reuse"
/// (<see cref="XAdESArchiveTimeStampImprint"/>'s own doc comment records the analogous genuine divergence for its
/// step 5). The five covered property TYPES both clauses share — <c>SignatureTimeStamp</c>,
/// <c>CompleteCertificateRefsV2</c>, <c>CompleteRevocationRefs</c>, <c>AttributeCertificateRefsV2</c>,
/// <c>AttributeRevocationRefs</c> — are matched by element identity (namespace + local name), never by the
/// <see cref="XAdESUnsignedSignaturePropertyName"/> enum, since two of the five
/// (<c>CompleteCertificateRefsV2</c>/<c>AttributeCertificateRefsV2</c>) are v1.4.1-namespace elements that enum
/// classifies <see cref="XAdESUnsignedSignaturePropertyName.Unrecognized"/> — the same posture every other Annex A
/// V2 property reader already takes when locating itself within <see cref="XAdESUnsignedSignatureProperties.Properties"/>.
/// </summary>
public static class XAdESSigAndRefsTimeStampV2Imprint
{
    private static (byte[] Namespace, byte[] LocalName)[] CoveredProperties { get; } =
    [
        (XAdESIdentifiers.XAdESNamespaceV132Utf8.ToArray(), "SignatureTimeStamp"u8.ToArray()),
        (XAdESIdentifiers.XAdESNamespaceV141Utf8.ToArray(), "CompleteCertificateRefsV2"u8.ToArray()),
        (XAdESIdentifiers.XAdESNamespaceV132Utf8.ToArray(), "CompleteRevocationRefs"u8.ToArray()),
        (XAdESIdentifiers.XAdESNamespaceV141Utf8.ToArray(), "AttributeCertificateRefsV2"u8.ToArray()),
        (XAdESIdentifiers.XAdESNamespaceV132Utf8.ToArray(), "AttributeRevocationRefs"u8.ToArray()),
    ];


    /// <summary>
    /// Computes the message-imprint input octets for a NOT-DISTRIBUTED <c>SigAndRefsTimeStampV2</c> — clause
    /// A.1.5.1.2's "taking, in order, each of the following, canonicalizing each per clause 4.5, and
    /// concatenating": 1) the <c>ds:SignatureValue</c> element, always first, implicitly (no <c>Include</c>); 2)
    /// those of the five covered property types that appear BEFORE <c>SigAndRefsTimeStampV2</c>, in their order
    /// of appearance within <c>UnsignedSignatureProperties</c> — the same preceding-boundary shape
    /// <c>XAdESArchiveTimeStampImprint.TryComputeNotDistributedImprintInput</c>'s own step 5 proves, but filtered
    /// to the five covered types rather than every unsigned property.
    /// </summary>
    /// <param name="table">The document every table-scoped argument was read from.</param>
    /// <param name="signature">The signature whose <c>ds:SignatureValue</c> contributes first.</param>
    /// <param name="sigAndRefsTimeStampV2">The already-read <c>SigAndRefsTimeStampV2</c> under validation.</param>
    /// <param name="unsignedSignatureProperties">
    /// <paramref name="sigAndRefsTimeStampV2"/>'s own owning <c>UnsignedSignatureProperties</c>'s document-order
    /// entry list — the preceding-boundary filter is computed against this list's own order.
    /// </param>
    /// <param name="pool">The pool every intermediate and returned buffer is rented from.</param>
    /// <param name="imprintInput">The message-imprint input octets on success, tagged
    /// <see cref="BufferTags.XmlDigestInput"/>; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match every
    /// table-scoped argument;
    /// <see cref="XAdESProcessingFailure.SigAndRefsTimeStampV2NotFoundInUnsignedSignatureProperties"/> when
    /// <paramref name="sigAndRefsTimeStampV2"/> is not itself an entry of <paramref name="unsignedSignatureProperties"/>;
    /// <see cref="XAdESProcessingFailure.AbsentCanonicalizationMethod"/>/
    /// <see cref="XAdESProcessingFailure.UnsupportedCanonicalizationMethod"/>/
    /// <see cref="XAdESProcessingFailure.InvalidCanonicalizationParameter"/> for the property's own clause-4.5
    /// resolution and every canonicalization step.</param>
    /// <returns><see langword="true"/> when the imprint input was computed.</returns>
    public static bool TryComputeNotDistributedImprintInput(
        XmlNodeTable table,
        XmlSignature signature,
        XAdESSigAndRefsTimeStampV2 sigAndRefsTimeStampV2,
        XAdESUnsignedSignatureProperties unsignedSignatureProperties,
        BaseMemoryPool pool,
        [NotNullWhen(true)] out PooledMemory? imprintInput,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(sigAndRefsTimeStampV2);
        ArgumentNullException.ThrowIfNull(pool);
        imprintInput = null;
        if(!signature.IsOver(table) || !sigAndRefsTimeStampV2.IsOver(table) || !ReferenceEquals(unsignedSignatureProperties.Table, table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        if(!XAdESCanonicalizationManagement.TryResolve(sigAndRefsTimeStampV2.TimeStamp.HasCanonicalizationMethod, sigAndRefsTimeStampV2.TimeStamp.CanonicalizationMethod, out XmlCanonicalizationAlgorithm algorithm, out error))
        {
            return false;
        }

        IReadOnlyList<XAdESUnsignedSignaturePropertyEntry> properties = unsignedSignatureProperties.Properties;
        int ownOrdinal = -1;
        for(int i = 0; i < properties.Count; ++i)
        {
            if(properties[i].ElementIndex == sigAndRefsTimeStampV2.ElementIndex)
            {
                ownOrdinal = i;

                break;
            }
        }

        if(ownOrdinal < 0)
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.SigAndRefsTimeStampV2NotFoundInUnsignedSignatureProperties, 0);

            return false;
        }

        ReadOnlySpan<byte> prefixList = sigAndRefsTimeStampV2.TimeStamp.CanonicalizationMethod.PrefixList;
        using var output = new PooledStructList<byte>(pool, 256);

        //Step 1: the ds:SignatureValue element, always first, implicitly (no Include names it).
        if(!TryAppendCanonicalized(table, XmlNodeSet.ElementSubtree(table, signature.SignatureValueElementIndex), algorithm, prefixList, pool, output, out error))
        {
            return false;
        }

        //Step 2: the covered properties preceding sigAndRefsTimeStampV2, in document order.
        for(int i = 0; i < ownOrdinal; ++i)
        {
            if(!IsCoveredProperty(table, properties[i].ElementIndex))
            {
                continue;
            }

            if(!TryAppendCanonicalized(table, XmlNodeSet.ElementSubtree(table, properties[i].ElementIndex), algorithm, prefixList, pool, output, out error))
            {
                return false;
            }
        }

        imprintInput = PooledMemory.FromBytes(output.AsSpan(), pool, BufferTags.XmlDigestInput);
        error = default;

        return true;
    }


    /// <summary>
    /// Computes the message-imprint input octets for a DISTRIBUTED <c>SigAndRefsTimeStampV2</c> — clause
    /// A.1.5.1.3's "1) no <c>Include</c> element is added for <c>ds:SignatureValue</c> — its contribution [...]
    /// shall be implicitly assumed" then "3) take each listed unsigned qualifying property in the same order as
    /// its <c>Include</c> element, extract comment nodes, canonicalize per clause 4.5, and concatenate." Step 2 —
    /// "one <c>Include</c> element shall be generated for each covered unsigned qualifying property, in the
    /// LISTED order" — is a GENERATION-side obligation (building the <c>Include</c> elements this method
    /// consumes as already-fixed input), recorded here but never built; this method's own validation-time
    /// contract is step 3's own wording, which
    /// follows each <c>Include</c>'s OWN document order — not the type-listed order step 2 uses to construct
    /// them — the same divergence <c>XAdESArchiveTimeStampImprint.TryComputeDistributedImprintInput</c> records
    /// for its own generation/validation pair. Each <c>Include</c> resolves through the same bare-name-XPointer
    /// machinery every <c>Include</c> mechanism uses (<see cref="XAdESIncludeUriProcessing"/>), which already
    /// deletes comment nodes as part of its own XA-5.1.4.4.2.2-2 step-2 contract — no separate comment-deletion
    /// step is needed here.
    /// </summary>
    /// <param name="table">The document every table-scoped argument was read from.</param>
    /// <param name="signature">The signature whose <c>ds:SignatureValue</c> contributes first.</param>
    /// <param name="sigAndRefsTimeStampV2">The already-read <c>SigAndRefsTimeStampV2</c> under validation, whose
    /// <see cref="XAdESTimeStamp.Includes"/> name the time-stamped properties, in the fixed order they
    /// contribute.</param>
    /// <param name="unsignedSignatureProperties">
    /// <paramref name="sigAndRefsTimeStampV2"/>'s own owning <c>UnsignedSignatureProperties</c>'s document-order
    /// entry list — clause A.1.5.1.3 step 3's "each listed unsigned qualifying property" restriction: each
    /// <c>Include</c>'s resolved target must be both an entry of THIS list and one of the five covered property
    /// types, not merely an element the document-wide bare-name resolution happens to find somewhere else.
    /// </param>
    /// <param name="pool">The pool every intermediate and returned buffer is rented from.</param>
    /// <param name="imprintInput">The message-imprint input octets on success, tagged
    /// <see cref="BufferTags.XmlDigestInput"/>; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match every
    /// table-scoped argument;
    /// <see cref="XAdESProcessingFailure.AbsentCanonicalizationMethod"/>/
    /// <see cref="XAdESProcessingFailure.UnsupportedCanonicalizationMethod"/>/
    /// <see cref="XAdESProcessingFailure.InvalidCanonicalizationParameter"/> for the property's own clause-4.5
    /// resolution and every canonicalization step;
    /// every <see cref="XAdESIncludeUriProcessing.TryRetrieve"/> refusal, per <c>Include</c>;
    /// <see cref="XAdESProcessingFailure.IncludeTargetNotAnUnsignedQualifyingProperty"/> when a resolved
    /// <c>Include</c> target is not an entry of <paramref name="unsignedSignatureProperties"/>, or is one of the
    /// five covered property types.</param>
    /// <returns><see langword="true"/> when the imprint input was computed.</returns>
    public static bool TryComputeDistributedImprintInput(
        XmlNodeTable table,
        XmlSignature signature,
        XAdESSigAndRefsTimeStampV2 sigAndRefsTimeStampV2,
        XAdESUnsignedSignatureProperties unsignedSignatureProperties,
        BaseMemoryPool pool,
        [NotNullWhen(true)] out PooledMemory? imprintInput,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(sigAndRefsTimeStampV2);
        ArgumentNullException.ThrowIfNull(pool);
        imprintInput = null;
        if(!signature.IsOver(table) || !sigAndRefsTimeStampV2.IsOver(table) || !ReferenceEquals(unsignedSignatureProperties.Table, table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        if(!XAdESCanonicalizationManagement.TryResolve(sigAndRefsTimeStampV2.TimeStamp.HasCanonicalizationMethod, sigAndRefsTimeStampV2.TimeStamp.CanonicalizationMethod, out XmlCanonicalizationAlgorithm algorithm, out error))
        {
            return false;
        }

        ReadOnlySpan<byte> prefixList = sigAndRefsTimeStampV2.TimeStamp.CanonicalizationMethod.PrefixList;
        using var output = new PooledStructList<byte>(pool, 256);

        //Step 1: the ds:SignatureValue element, always first, implicitly (no Include names it).
        if(!TryAppendCanonicalized(table, XmlNodeSet.ElementSubtree(table, signature.SignatureValueElementIndex), algorithm, prefixList, pool, output, out error))
        {
            return false;
        }

        //Step 3 (step 2 is generation-only Include construction): each Include target, in Include document
        //order, comment nodes already stripped by TryRetrieve.
        foreach(XAdESInclude include in sigAndRefsTimeStampV2.TimeStamp.Includes)
        {
            if(!XAdESIncludeUriProcessing.TryRetrieve(table, include.Uri, out int targetElementIndex, out XmlNodeSet targetNodeSet, out error))
            {
                return false;
            }

            if(!IsMemberOfContainer(unsignedSignatureProperties, targetElementIndex) || !IsCoveredProperty(table, targetElementIndex))
            {
                error = new XAdESProcessingError(XAdESProcessingFailure.IncludeTargetNotAnUnsignedQualifyingProperty, 0);

                return false;
            }

            if(!TryAppendCanonicalized(table, targetNodeSet, algorithm, prefixList, pool, output, out error))
            {
                return false;
            }
        }

        imprintInput = PooledMemory.FromBytes(output.AsSpan(), pool, BufferTags.XmlDigestInput);
        error = default;

        return true;
    }


    /// <summary>
    /// Tells whether <paramref name="elementIndex"/> is the <see cref="XAdESUnsignedSignaturePropertyEntry.ElementIndex"/>
    /// of some entry of <paramref name="unsignedSignatureProperties"/> — the distributed variant's own
    /// membership half of clause A.1.5.1.3 step 3's "each listed unsigned qualifying property" restriction, the
    /// same shape the not-distributed variant's own preceding-boundary scan already performs against this same
    /// entry list.
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
    /// Tells whether an element's identity is one of the five property types A.1.5.1.1's "shall contain an
    /// electronic time-stamp that time-stamps" list names: <c>SignatureTimeStamp</c>,
    /// <c>CompleteCertificateRefsV2</c>, <c>CompleteRevocationRefs</c>, <c>AttributeCertificateRefsV2</c>,
    /// <c>AttributeRevocationRefs</c>.
    /// </summary>
    private static bool IsCoveredProperty(XmlNodeTable table, int elementIndex)
    {
        for(int i = 0; i < CoveredProperties.Length; ++i)
        {
            if(XmlSignatureModelGrammar.IsElement(table, elementIndex, CoveredProperties[i].Namespace, CoveredProperties[i].LocalName))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Canonicalizes one node-set with the property's own resolved algorithm/prefix-list and appends the result
    /// to the running message-imprint input, releasing the intermediate buffer immediately.
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
