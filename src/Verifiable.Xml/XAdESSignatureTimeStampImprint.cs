using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The clause 5.3 message-imprint input engine for <see cref="XAdESSignatureTimeStamp"/>: the SIMPLEST
/// message-imprint computation in the whole leg — "1) take the <c>ds:SignatureValue</c> element and its
/// contents; and 2) canonicalize it as specified in clause 4.5" — a single element, canonicalized, no
/// concatenation, no reference-processing model dependency, in contrast to every other imprint engine this
/// leaf ships.
/// </summary>
public static class XAdESSignatureTimeStampImprint
{
    /// <summary>
    /// Computes the message-imprint input octets for a <c>SignatureTimeStamp</c>: the element subtree of the
    /// owning signature's <c>ds:SignatureValue</c> — itself, its contents, and the attribute and namespace
    /// nodes of it and its descendants, per XMLDSIG's own element-subtree shape — canonicalized with the
    /// property's own clause-4.5-resolved algorithm (<see cref="XAdESSignatureTimeStamp.TimeStamp"/>'s
    /// <c>ds:CanonicalizationMethod</c>).
    /// </summary>
    /// <param name="table">The document both <paramref name="signature"/> and <paramref name="signatureTimeStamp"/> were read from.</param>
    /// <param name="signature">The signature whose <c>ds:SignatureValue</c> is time-stamped.</param>
    /// <param name="signatureTimeStamp">The already-read <c>SignatureTimeStamp</c> qualifying property.</param>
    /// <param name="pool">The pool every intermediate and returned buffer is rented from.</param>
    /// <param name="imprintInput">The message-imprint input octets on success, tagged
    /// <see cref="BufferTags.XmlDigestInput"/>; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match both
    /// arguments' own table;
    /// <see cref="XAdESProcessingFailure.AbsentCanonicalizationMethod"/> when
    /// <see cref="XAdESSignatureTimeStamp.TimeStamp"/>'s <c>ds:CanonicalizationMethod</c> is absent — clause
    /// 4.5 makes it generator-mandatory, so its absence at verification time is a named refusal;
    /// <see cref="XAdESProcessingFailure.UnsupportedCanonicalizationMethod"/> when its <c>Algorithm</c> is not
    /// one of the six clause 6.3(d) URIs;
    /// <see cref="XAdESProcessingFailure.InvalidCanonicalizationParameter"/> for a malformed or over-length
    /// <c>InclusiveNamespaces PrefixList</c>.</param>
    /// <returns><see langword="true"/> when the imprint input was computed.</returns>
    /// <remarks>
    /// <strong>Manual disposal, not a <see langword="using"/> declaration.</strong> <c>canonicalOctets</c> is
    /// bound through <see cref="XmlReferenceProcessing.TryCanonicalizeForAlgorithm"/>'s <see langword="out"/>
    /// parameter, so it is declared <see langword="null"/> and disposed in the <see langword="finally"/> below.
    /// </remarks>
    public static bool TryComputeImprintInput(
        XmlNodeTable table,
        XmlSignature signature,
        XAdESSignatureTimeStamp signatureTimeStamp,
        BaseMemoryPool pool,
        [NotNullWhen(true)] out PooledMemory? imprintInput,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(signatureTimeStamp);
        ArgumentNullException.ThrowIfNull(pool);
        imprintInput = null;
        if(!signature.IsOver(table) || !signatureTimeStamp.IsOver(table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        if(!XAdESCanonicalizationManagement.TryResolve(signatureTimeStamp.TimeStamp.HasCanonicalizationMethod, signatureTimeStamp.TimeStamp.CanonicalizationMethod, out XmlCanonicalizationAlgorithm algorithm, out error))
        {
            return false;
        }

        XmlNodeSet signatureValueNodeSet = XmlNodeSet.ElementSubtree(table, signature.SignatureValueElementIndex);
        PooledMemory? canonicalOctets = null;
        try
        {
            if(!XmlReferenceProcessing.TryCanonicalizeForAlgorithm(table, signatureValueNodeSet, algorithm, signatureTimeStamp.TimeStamp.CanonicalizationMethod.PrefixList, pool, out canonicalOctets, out XmlCanonicalizationError canonicalizationError))
            {
                error = XAdESCanonicalizationManagement.MapCanonicalizationFailure(canonicalizationError);

                return false;
            }

            //TryCanonicalizeForAlgorithm tags its result BufferTags.XmlCanonical (the shared dispatch has no
            //tag parameter of its own); every sibling imprint engine's PUBLIC result carries
            //BufferTags.XmlDigestInput instead, so this single-step engine retags to match rather than leaking
            //the intermediate tag — the one-element copy is negligible against a SignatureValue's own size.
            imprintInput = PooledMemory.FromBytes(canonicalOctets!.AsReadOnlySpan(), pool, BufferTags.XmlDigestInput);
            error = default;

            return true;
        }
        finally
        {
            canonicalOctets?.Dispose();
        }
    }
}
