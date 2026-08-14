using System.Collections.Generic;

namespace Verifiable.Xml;

/// <summary>
/// Clause 6.3 letter k)'s <c>DataObjectFormat</c> coverage rule, per
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> — XA-6.3-k1/-k2/-k3: one <c>DataObjectFormat</c> per signed data object,
/// except <c>SignedProperties</c>, and — when the signature is, per clause 5.2.7.1's convention
/// (<see cref="XAdESCountersignatureIdentification.IsCountersignature"/>), itself a countersignature — except
/// the <c>ds:Reference</c> carrying the <c>CountersignedSignature</c> marker
/// (<see cref="XAdESCountersignatureIdentification.IsCountersignatureReference"/>) too: k2's SHALL NOT ("if it
/// only signs its own signed properties and the countersigned signature, then it shall not include any
/// <c>DataObjectFormat</c> signed property") and k3's SHALL ("if it signs [...] other data object(s) [...]
/// it shall include one <c>DataObjectFormat</c> signed property for each of these other [...] object(s)") both
/// name the SAME excluded pair regardless of how many other objects exist — unified here as one bijection check
/// between the signature's <c>ds:SignedInfo</c> references outside that excluded pair and the property's own
/// <c>DataObjectFormat</c> entries.
/// </summary>
/// <remarks>
/// Scoped to <see cref="XmlSignedInfo.References"/> membership directly, per this type's own scope: a
/// NOTE-8-permitted <c>ObjectReference</c> into a signed <c>ds:Manifest</c> is chain territory this check does
/// not walk into — a <c>DataObjectFormat</c> resolving there neither satisfies nor violates this bijection,
/// recorded rather than built, since <see cref="XAdESObjectReferenceResolution.TryResolve"/> itself already
/// accepts that shape for <see cref="XAdESDataObjectFormat.TryVerifyConsistency"/>'s own, narrower use.
/// </remarks>
public static class XAdESDataObjectFormatCoverage
{
    /// <summary>
    /// Verifies the letter k) bijection: every <c>ds:SignedInfo</c> reference other than the
    /// <c>SignedProperties</c> reference and — when countersigning — the <c>CountersignedSignature</c>-marked
    /// reference has exactly one <paramref name="dataObjectFormats"/> entry whose <c>ObjectReference</c>
    /// resolves to it, and no entry targets an excluded reference.
    /// </summary>
    /// <param name="table">The document both <paramref name="signature"/> and every entry of <paramref name="dataObjectFormats"/> were read from.</param>
    /// <param name="signature">The signature whose <c>ds:SignedInfo</c> references define the required set.</param>
    /// <param name="dataObjectFormats">The already-read <c>DataObjectFormat</c> entries of the signature's <c>SignedDataObjectProperties</c>, possibly empty.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match <paramref name="signature"/>'s own table;
    /// every <see cref="XAdESObjectReferenceResolution.TryResolve"/> refusal when an entry's <c>ObjectReference</c> itself does not resolve;
    /// <see cref="XAdESProcessingFailure.DataObjectFormatCoverageExcludedTarget"/> when an entry targets the <c>SignedProperties</c> or countersigned-signature reference;
    /// <see cref="XAdESProcessingFailure.DataObjectFormatCoverageDuplicate"/> when more than one entry targets the same required reference;
    /// <see cref="XAdESProcessingFailure.DataObjectFormatCoverageMissing"/> when a required reference has no matching entry.</param>
    /// <returns><see langword="true"/> when the bijection holds.</returns>
    public static bool TryVerify(
        XmlNodeTable table,
        XmlSignature signature,
        IReadOnlyList<XAdESDataObjectFormat> dataObjectFormats,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(dataObjectFormats);
        if(!signature.IsOver(table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        bool isCountersignature = XAdESCountersignatureIdentification.IsCountersignature(signature);
        var excludedElementIndices = new List<int>();
        var requiredElementIndices = new List<int>();
        foreach(XmlReference reference in signature.SignedInfo.References)
        {
            bool isSignedProperties = reference.HasType && reference.Type.SequenceEqual(XAdESIdentifiers.SignedPropertiesTypeUriUtf8);
            bool isCountersignedSignature = isCountersignature && XAdESCountersignatureIdentification.IsCountersignatureReference(reference);
            if(isSignedProperties || isCountersignedSignature)
            {
                excludedElementIndices.Add(reference.ElementIndex);

                continue;
            }

            requiredElementIndices.Add(reference.ElementIndex);
        }

        var matched = new bool[requiredElementIndices.Count];
        foreach(XAdESDataObjectFormat dataObjectFormat in dataObjectFormats)
        {
            if(!XAdESObjectReferenceResolution.TryResolve(table, signature, dataObjectFormat.ObjectReference, out int referenceElementIndex, out error))
            {
                return false;
            }

            if(excludedElementIndices.Contains(referenceElementIndex))
            {
                error = new XAdESProcessingError(XAdESProcessingFailure.DataObjectFormatCoverageExcludedTarget, 0);

                return false;
            }

            int requiredIndex = requiredElementIndices.IndexOf(referenceElementIndex);
            if(requiredIndex < 0)
            {
                //Resolves outside ds:SignedInfo (a signed ds:Manifest, NOTE 8) — this check's own scope is
                //ds:SignedInfo membership only; see the type remarks.
                continue;
            }

            if(matched[requiredIndex])
            {
                error = new XAdESProcessingError(XAdESProcessingFailure.DataObjectFormatCoverageDuplicate, 0);

                return false;
            }

            matched[requiredIndex] = true;
        }

        for(int i = 0; i < matched.Length; ++i)
        {
            if(!matched[i])
            {
                error = new XAdESProcessingError(XAdESProcessingFailure.DataObjectFormatCoverageMissing, 0);

                return false;
            }
        }

        error = default;

        return true;
    }
}
