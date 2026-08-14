using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The clause 5.2.8.1 message-imprint input engine for <see cref="XAdESAllDataObjectsTimeStamp"/>: "the
/// concatenation of all the objects obtained after processing as specified in XMLDSIG [1], clause 4.4.3.2; all
/// the <c>ds:Reference</c> elements within the <c>ds:SignedInfo</c> except the one referencing the
/// <c>SignedProperties</c> element, in their order of appearance" — the SignedProperties reference is located
/// by the same <c>Type</c>-URI dispatch <see cref="XAdESQualifyingPropertiesDiscovery.TryVerifySignedPropertiesReferenceBinding"/>
/// uses ("the substrate models <c>XmlReference.Type</c> but never dispatches on
/// it; the XAdES layer adds that dispatch"), and every remaining reference, in <c>ds:SignedInfo</c> document
/// order, is processed through the shared clause 5.2.8.1/5.2.8.2 steps a)-d) engine
/// (<see cref="XmlReferenceProcessing.TryComputeMessageImprintInputForReferences"/>).
/// </summary>
public static class XAdESAllDataObjectsTimeStampImprint
{
    /// <summary>
    /// Computes the message-imprint input octets for an <c>AllDataObjectsTimeStamp</c>.
    /// </summary>
    /// <param name="table">The document both <paramref name="signature"/> and <paramref name="allDataObjectsTimeStamp"/> were read from.</param>
    /// <param name="signature">The signature whose <c>ds:SignedInfo</c> references are processed.</param>
    /// <param name="allDataObjectsTimeStamp">The already-read <c>AllDataObjectsTimeStamp</c> qualifying property.</param>
    /// <param name="resolver">The external-dereference delegate a non-same-document <c>ds:Reference URI</c>
    /// would need, or <see langword="null"/> when the caller supplies none.</param>
    /// <param name="pool">The pool every intermediate and returned buffer is rented from.</param>
    /// <param name="imprintInput">The message-imprint input octets on success, tagged
    /// <see cref="BufferTags.XmlDigestInput"/>; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match both
    /// arguments' own table;
    /// <see cref="XAdESProcessingFailure.AbsentCanonicalizationMethod"/>/
    /// <see cref="XAdESProcessingFailure.UnsupportedCanonicalizationMethod"/> for the property's own
    /// clause-4.5 resolution;
    /// <see cref="XAdESProcessingFailure.SignedPropertiesReferenceNotFound"/>/
    /// <see cref="XAdESProcessingFailure.MultipleSignedPropertiesReferences"/> when
    /// <c>ds:SignedInfo</c> carries zero or more than one <c>Type</c>-matching reference (clause 4.4.2
    /// assumes exactly one);
    /// <see cref="XAdESProcessingFailure.MessageImprintReferenceProcessingFailed"/> when processing a
    /// selected reference itself refuses.</param>
    /// <returns><see langword="true"/> when the imprint input was computed.</returns>
    public static bool TryComputeImprintInput(
        XmlNodeTable table,
        XmlSignature signature,
        XAdESAllDataObjectsTimeStamp allDataObjectsTimeStamp,
        XmlReferenceResolver? resolver,
        BaseMemoryPool pool,
        [NotNullWhen(true)] out PooledMemory? imprintInput,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(allDataObjectsTimeStamp);
        ArgumentNullException.ThrowIfNull(pool);
        imprintInput = null;
        if(!signature.IsOver(table) || !allDataObjectsTimeStamp.IsOver(table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        if(!XAdESCanonicalizationManagement.TryResolve(allDataObjectsTimeStamp.TimeStamp.HasCanonicalizationMethod, allDataObjectsTimeStamp.TimeStamp.CanonicalizationMethod, out XmlCanonicalizationAlgorithm algorithm, out error))
        {
            return false;
        }

        int signedPropertiesMatchCount = 0;
        var selected = new List<XmlReference>(signature.SignedInfo.References.Count);
        foreach(XmlReference reference in signature.SignedInfo.References)
        {
            if(reference.HasType && reference.Type.SequenceEqual(XAdESIdentifiers.SignedPropertiesTypeUriUtf8))
            {
                ++signedPropertiesMatchCount;

                continue;
            }

            selected.Add(reference);
        }

        if(signedPropertiesMatchCount == 0)
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.SignedPropertiesReferenceNotFound, 0);

            return false;
        }

        if(signedPropertiesMatchCount > 1)
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.MultipleSignedPropertiesReferences, 0);

            return false;
        }

        if(!XmlReferenceProcessing.TryComputeMessageImprintInputForReferences(
            table, selected, algorithm, allDataObjectsTimeStamp.TimeStamp.CanonicalizationMethod.PrefixList, resolver, pool, out imprintInput, out XmlSignatureProcessingError processingError))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.MessageImprintReferenceProcessingFailed, 0, processingError);

            return false;
        }

        error = default;

        return true;
    }
}
