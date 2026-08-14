using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The clause A.1.5.2.2/A.1.5.2.3 message-imprint input engine for <see cref="XAdESRefsOnlyTimeStampV2"/>: the
/// not-distributed variant (<see cref="TryComputeNotDistributedImprintInput"/>) and the distributed variant
/// (<see cref="TryComputeDistributedImprintInput"/>). Narrower than <see cref="XAdESSigAndRefsTimeStampV2Imprint"/>
/// in two ways: the covered property set is the FOUR refs properties only (no <c>SignatureTimeStamp</c>), and
/// there is no <c>ds:SignatureValue</c> implicit-first-contribution step at all — A.1.5.2.1's own scope statement
/// never mentions <c>ds:SignatureValue</c>/<c>SignatureTimeStamp</c> coverage, unlike A.1.5.1.1's. Like its
/// sibling engine, neither variant reaches <see cref="XmlReferenceProcessing.TryComputeMessageImprintInputForReferences"/>:
/// both clauses canonicalize whole qualifying-property element subtrees directly, never a <c>ds:Reference</c>
/// list's own dereference/transform-chain steps a)-d).
/// </summary>
public static class XAdESRefsOnlyTimeStampV2Imprint
{
    private static readonly (byte[] Namespace, byte[] LocalName)[] CoveredProperties =
    [
        (XAdESIdentifiers.XAdESNamespaceV141Utf8.ToArray(), "CompleteCertificateRefsV2"u8.ToArray()),
        (XAdESIdentifiers.XAdESNamespaceV132Utf8.ToArray(), "CompleteRevocationRefs"u8.ToArray()),
        (XAdESIdentifiers.XAdESNamespaceV141Utf8.ToArray(), "AttributeCertificateRefsV2"u8.ToArray()),
        (XAdESIdentifiers.XAdESNamespaceV132Utf8.ToArray(), "AttributeRevocationRefs"u8.ToArray()),
    ];


    /// <summary>
    /// Computes the message-imprint input octets for a NOT-DISTRIBUTED <c>RefsOnlyTimeStampV2</c> — clause
    /// A.1.5.2.2's "taking those of [the four covered properties] that appear before
    /// <c>RefsOnlyTimeStampV2</c> in <c>UnsignedSignatureProperties</c> order, canonicalizing each per clause
    /// 4.5, and concatenating" — the same preceding-boundary shape
    /// <c>XAdESArchiveTimeStampImprint.TryComputeNotDistributedImprintInput</c>'s own step 5 and
    /// <see cref="XAdESSigAndRefsTimeStampV2Imprint.TryComputeNotDistributedImprintInput"/> both prove, filtered
    /// to the four covered types and with no implicit <c>ds:SignatureValue</c> step.
    /// </summary>
    /// <param name="table">The document every table-scoped argument was read from.</param>
    /// <param name="refsOnlyTimeStampV2">The already-read <c>RefsOnlyTimeStampV2</c> under validation.</param>
    /// <param name="unsignedSignatureProperties">
    /// <paramref name="refsOnlyTimeStampV2"/>'s own owning <c>UnsignedSignatureProperties</c>'s document-order
    /// entry list — the preceding-boundary filter is computed against this list's own order.
    /// </param>
    /// <param name="pool">The pool every intermediate and returned buffer is rented from.</param>
    /// <param name="imprintInput">The message-imprint input octets on success, tagged
    /// <see cref="BufferTags.XmlDigestInput"/>; the caller owns and must dispose them. Zero covered properties
    /// preceding <paramref name="refsOnlyTimeStampV2"/> produces empty (but non-null) octets — the clause's own
    /// "concatenating" over an empty selection is vacuously satisfied by nothing to concatenate.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match every
    /// table-scoped argument;
    /// <see cref="XAdESProcessingFailure.RefsOnlyTimeStampV2NotFoundInUnsignedSignatureProperties"/> when
    /// <paramref name="refsOnlyTimeStampV2"/> is not itself an entry of <paramref name="unsignedSignatureProperties"/>;
    /// <see cref="XAdESProcessingFailure.AbsentCanonicalizationMethod"/>/
    /// <see cref="XAdESProcessingFailure.UnsupportedCanonicalizationMethod"/>/
    /// <see cref="XAdESProcessingFailure.InvalidCanonicalizationParameter"/> for the property's own clause-4.5
    /// resolution and every canonicalization step.</param>
    /// <returns><see langword="true"/> when the imprint input was computed.</returns>
    public static bool TryComputeNotDistributedImprintInput(
        XmlNodeTable table,
        XAdESRefsOnlyTimeStampV2 refsOnlyTimeStampV2,
        XAdESUnsignedSignatureProperties unsignedSignatureProperties,
        BaseMemoryPool pool,
        [NotNullWhen(true)] out PooledMemory? imprintInput,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(refsOnlyTimeStampV2);
        ArgumentNullException.ThrowIfNull(pool);
        imprintInput = null;
        if(!refsOnlyTimeStampV2.IsOver(table) || !ReferenceEquals(unsignedSignatureProperties.Table, table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        if(!XAdESCanonicalizationManagement.TryResolve(refsOnlyTimeStampV2.TimeStamp.HasCanonicalizationMethod, refsOnlyTimeStampV2.TimeStamp.CanonicalizationMethod, out XmlCanonicalizationAlgorithm algorithm, out error))
        {
            return false;
        }

        IReadOnlyList<XAdESUnsignedSignaturePropertyEntry> properties = unsignedSignatureProperties.Properties;
        int ownOrdinal = -1;
        for(int i = 0; i < properties.Count; ++i)
        {
            if(properties[i].ElementIndex == refsOnlyTimeStampV2.ElementIndex)
            {
                ownOrdinal = i;

                break;
            }
        }

        if(ownOrdinal < 0)
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.RefsOnlyTimeStampV2NotFoundInUnsignedSignatureProperties, 0);

            return false;
        }

        ReadOnlySpan<byte> prefixList = refsOnlyTimeStampV2.TimeStamp.CanonicalizationMethod.PrefixList;
        using var output = new PooledStructList<byte>(pool, 256);
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
    /// Computes the message-imprint input octets for a DISTRIBUTED <c>RefsOnlyTimeStampV2</c> — clause
    /// A.1.5.2.3's "1) initialize empty final octet stream; 2) take each listed property in <c>Include</c>-
    /// element order, extract comment nodes, canonicalize per clause 4.5, concatenate" — structurally identical
    /// to A.1.5.1.3's steps 1)+3), minus the implicit <c>ds:SignatureValue</c> step this property never covers.
    /// A.1.5.2.3's own lead sentence — "one <c>Include</c> element shall be generated per covered property, in
    /// the LISTED order" — is a GENERATION-side obligation (building the <c>Include</c> elements this method
    /// consumes as already-fixed input), recorded here but never built; this method's own validation-time
    /// contract follows each <c>Include</c>'s OWN document order, not the type-listed order generation uses to
    /// construct them, the same divergence <see cref="XAdESSigAndRefsTimeStampV2Imprint.TryComputeDistributedImprintInput"/>
    /// records for its sibling property. Each <c>Include</c> resolves through the same bare-name-XPointer
    /// machinery every <c>Include</c> mechanism uses (<see cref="XAdESIncludeUriProcessing"/>), which already
    /// deletes comment nodes as part of its own XA-5.1.4.4.2.2-2 step-2 contract — no separate comment-deletion
    /// step is needed here.
    /// </summary>
    /// <param name="table">The document <paramref name="refsOnlyTimeStampV2"/> was read from.</param>
    /// <param name="refsOnlyTimeStampV2">The already-read <c>RefsOnlyTimeStampV2</c> under validation, whose
    /// <see cref="XAdESTimeStamp.Includes"/> name the time-stamped properties, in the fixed order they
    /// contribute.</param>
    /// <param name="unsignedSignatureProperties">
    /// <paramref name="refsOnlyTimeStampV2"/>'s own owning <c>UnsignedSignatureProperties</c>'s document-order
    /// entry list — clause A.1.5.2.3's "each listed property" restriction: each <c>Include</c>'s resolved
    /// target must be both an entry of THIS list and one of the four covered property types, not merely an
    /// element the document-wide bare-name resolution happens to find somewhere else.
    /// </param>
    /// <param name="pool">The pool every intermediate and returned buffer is rented from.</param>
    /// <param name="imprintInput">The message-imprint input octets on success, tagged
    /// <see cref="BufferTags.XmlDigestInput"/>; the caller owns and must dispose them. Zero <c>Include</c>
    /// elements produces empty (but non-null) octets.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> is not the identical
    /// instance <paramref name="refsOnlyTimeStampV2"/> was read from;
    /// <see cref="XAdESProcessingFailure.AbsentCanonicalizationMethod"/>/
    /// <see cref="XAdESProcessingFailure.UnsupportedCanonicalizationMethod"/>/
    /// <see cref="XAdESProcessingFailure.InvalidCanonicalizationParameter"/> for the property's own clause-4.5
    /// resolution and every canonicalization step;
    /// every <see cref="XAdESIncludeUriProcessing.TryRetrieve"/> refusal, per <c>Include</c>;
    /// <see cref="XAdESProcessingFailure.IncludeTargetNotAnUnsignedQualifyingProperty"/> when a resolved
    /// <c>Include</c> target is not an entry of <paramref name="unsignedSignatureProperties"/>, or is not one of
    /// the four covered property types.</param>
    /// <returns><see langword="true"/> when the imprint input was computed.</returns>
    public static bool TryComputeDistributedImprintInput(
        XmlNodeTable table,
        XAdESRefsOnlyTimeStampV2 refsOnlyTimeStampV2,
        XAdESUnsignedSignatureProperties unsignedSignatureProperties,
        BaseMemoryPool pool,
        [NotNullWhen(true)] out PooledMemory? imprintInput,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(refsOnlyTimeStampV2);
        ArgumentNullException.ThrowIfNull(pool);
        imprintInput = null;
        if(!refsOnlyTimeStampV2.IsOver(table) || !ReferenceEquals(unsignedSignatureProperties.Table, table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        if(!XAdESCanonicalizationManagement.TryResolve(refsOnlyTimeStampV2.TimeStamp.HasCanonicalizationMethod, refsOnlyTimeStampV2.TimeStamp.CanonicalizationMethod, out XmlCanonicalizationAlgorithm algorithm, out error))
        {
            return false;
        }

        ReadOnlySpan<byte> prefixList = refsOnlyTimeStampV2.TimeStamp.CanonicalizationMethod.PrefixList;
        using var output = new PooledStructList<byte>(pool, 256);
        foreach(XAdESInclude include in refsOnlyTimeStampV2.TimeStamp.Includes)
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
    /// membership half of clause A.1.5.2.3's "each listed property" restriction, the same shape the
    /// not-distributed variant's own preceding-boundary scan already performs against this same entry list.
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
    /// Tells whether an element's identity is one of the four property types A.1.5.2.1's "shall contain an
    /// electronic time-stamp that time-stamps" list names: <c>CompleteCertificateRefsV2</c>,
    /// <c>CompleteRevocationRefs</c>, <c>AttributeCertificateRefsV2</c>, <c>AttributeRevocationRefs</c>.
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
