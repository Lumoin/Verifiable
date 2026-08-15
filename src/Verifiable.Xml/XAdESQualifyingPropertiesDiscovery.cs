using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The outcome of <see cref="XAdESQualifyingPropertiesDiscovery.TryDiscover"/>: whether a directly-incorporated
/// <c>QualifyingProperties</c> was found, and every indirectly-incorporated <c>QualifyingPropertiesReference</c>
/// present, per clause 4.4.1.
/// </summary>
public readonly struct XAdESQualifyingPropertiesDiscoveryResult: IEquatable<XAdESQualifyingPropertiesDiscoveryResult>
{
    /// <summary>Whether a directly-incorporated <c>QualifyingProperties</c> element was found.</summary>
    public bool HasQualifyingProperties { get; }

    /// <summary>The discovered <c>QualifyingProperties</c>, meaningful only when <see cref="HasQualifyingProperties"/> is <see langword="true"/>.</summary>
    public XAdESQualifyingProperties QualifyingProperties { get; }

    /// <summary>
    /// The ordinal, into the owning <see cref="XmlSignature.Objects"/>, of the single <c>ds:Object</c> every
    /// discovered instance was found within; -1 when neither <see cref="HasQualifyingProperties"/> nor any
    /// <see cref="QualifyingPropertiesReferences"/> entry was found.
    /// </summary>
    public int ObjectOrdinal { get; }

    /// <summary>Every discovered <c>QualifyingPropertiesReference</c>, in document order; possibly empty.</summary>
    public IReadOnlyList<XAdESQualifyingPropertiesReference> QualifyingPropertiesReferences { get; }


    internal XAdESQualifyingPropertiesDiscoveryResult(
        bool hasQualifyingProperties,
        XAdESQualifyingProperties qualifyingProperties,
        int objectOrdinal,
        IReadOnlyList<XAdESQualifyingPropertiesReference> qualifyingPropertiesReferences)
    {
        HasQualifyingProperties = hasQualifyingProperties;
        QualifyingProperties = qualifyingProperties;
        ObjectOrdinal = objectOrdinal;
        QualifyingPropertiesReferences = qualifyingPropertiesReferences;
    }


    /// <summary>
    /// Whether this and <paramref name="other"/> report the same discovery outcome: the same
    /// <see cref="HasQualifyingProperties"/>/<see cref="QualifyingProperties"/>/<see cref="ObjectOrdinal"/>
    /// values and the identical <see cref="QualifyingPropertiesReferences"/> list instance — this type is a
    /// one-shot outcome of a single <see cref="XAdESQualifyingPropertiesDiscovery.TryDiscover"/> call, not an
    /// independent value assembled from elsewhere, so list identity (not a deep element-wise comparison) is
    /// the meaningful notion of "the same result."
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESQualifyingPropertiesDiscoveryResult other) =>
        HasQualifyingProperties == other.HasQualifyingProperties
        && ObjectOrdinal == other.ObjectOrdinal
        && QualifyingProperties.Equals(other.QualifyingProperties)
        && ReferenceEquals(QualifyingPropertiesReferences, other.QualifyingPropertiesReferences);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESQualifyingPropertiesDiscoveryResult other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => HashCode.Combine(HasQualifyingProperties, ObjectOrdinal, QualifyingProperties, QualifyingPropertiesReferences);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESQualifyingPropertiesDiscoveryResult left, XAdESQualifyingPropertiesDiscoveryResult right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESQualifyingPropertiesDiscoveryResult left, XAdESQualifyingPropertiesDiscoveryResult right) => !left.Equals(right);
}


/// <summary>
/// The clause 4.4 incorporation-discovery and binding engine: locates the <c>QualifyingProperties</c>/
/// <c>QualifyingPropertiesReference</c> instances a <c>ds:Signature</c> carries (clause 4.4.1), verifies the
/// discovered <c>QualifyingProperties</c>'s own <c>Target</c> binds to that exact signature (clause 4.3.1),
/// and locates + verifies the <c>ds:Reference</c> that signs its <c>SignedProperties</c> (clause 4.4.2) — the
/// three policy layers that live entirely above the XMLDSIG-core substrate.
/// </summary>
public static class XAdESQualifyingPropertiesDiscovery
{
    /// <summary>
    /// Discovers the <c>QualifyingProperties</c>/<c>QualifyingPropertiesReference</c> instances a
    /// <c>ds:Signature</c> carries, per clause 4.4.1: all such instances shall occur within a single
    /// <c>ds:Object</c>, at most one <c>QualifyingProperties</c> may occur, and zero or more
    /// <c>QualifyingPropertiesReference</c> may occur. A signature carrying neither is not a refusal — it
    /// simply is not, or is not yet, a XAdES signature — reported as <see cref="XAdESQualifyingPropertiesDiscoveryResult.HasQualifyingProperties"/>
    /// <see langword="false"/> with an empty reference list.
    /// </summary>
    /// <param name="table">The document <paramref name="signature"/> was read from.</param>
    /// <param name="signature">The already-read signature to discover XAdES content within.</param>
    /// <param name="result">The discovery outcome on success.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> is not the identical
    /// instance <paramref name="signature"/> was read from;
    /// <see cref="XAdESProcessingFailure.MultipleQualifyingProperties"/> for a second <c>QualifyingProperties</c>
    /// direct child anywhere among the signature's <c>ds:Object</c>s;
    /// <see cref="XAdESProcessingFailure.QualifyingContentScatteredAcrossMultipleObjects"/> when the found
    /// instances are not all children of the same single <c>ds:Object</c>;
    /// <see cref="XAdESProcessingFailure.MalformedQualifyingProperties"/>/
    /// <see cref="XAdESProcessingFailure.MalformedQualifyingPropertiesReference"/> when a found element does
    /// not itself read structurally.</param>
    /// <returns><see langword="true"/> when discovery completed (with or without XAdES content found).</returns>
    public static bool TryDiscover(XmlNodeTable table, XmlSignature signature, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(signature);
        result = default;
        if(!signature.IsOver(table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        int objectOrdinal = -1;
        int qualifyingPropertiesElementIndex = -1;
        bool hasQualifyingProperties = false;
        var qualifyingPropertiesReferenceIndices = new List<int>();
        for(int currentObjectOrdinal = 0; currentObjectOrdinal < signature.Objects.Count; ++currentObjectOrdinal)
        {
            XmlSignatureObject signatureObject = signature.Objects[currentObjectOrdinal];
            bool objectCarriesXadesContent = false;
            foreach(int contentIndex in signatureObject.ContentNodeIndices)
            {
                if(table.KindOf(contentIndex) != XmlNodeKind.Element)
                {
                    continue;
                }

                if(XmlSignatureModelGrammar.IsElement(table, contentIndex, XAdESIdentifiers.XAdESNamespaceV132Utf8, "QualifyingProperties"u8))
                {
                    if(hasQualifyingProperties)
                    {
                        error = new XAdESProcessingError(XAdESProcessingFailure.MultipleQualifyingProperties, 0);

                        return false;
                    }

                    hasQualifyingProperties = true;
                    qualifyingPropertiesElementIndex = contentIndex;
                    objectCarriesXadesContent = true;
                }
                else if(XmlSignatureModelGrammar.IsElement(table, contentIndex, XAdESIdentifiers.XAdESNamespaceV132Utf8, "QualifyingPropertiesReference"u8))
                {
                    qualifyingPropertiesReferenceIndices.Add(contentIndex);
                    objectCarriesXadesContent = true;
                }
            }

            if(!objectCarriesXadesContent)
            {
                continue;
            }

            if(objectOrdinal >= 0 && objectOrdinal != currentObjectOrdinal)
            {
                error = new XAdESProcessingError(XAdESProcessingFailure.QualifyingContentScatteredAcrossMultipleObjects, 0);

                return false;
            }

            objectOrdinal = currentObjectOrdinal;
        }

        if(!hasQualifyingProperties && qualifyingPropertiesReferenceIndices.Count == 0)
        {
            result = new XAdESQualifyingPropertiesDiscoveryResult(hasQualifyingProperties: false, default, objectOrdinal: -1, []);
            error = default;

            return true;
        }

        XAdESQualifyingProperties qualifyingProperties = default;
        if(hasQualifyingProperties)
        {
            if(!XAdESQualifyingProperties.TryRead(table, qualifyingPropertiesElementIndex, out qualifyingProperties, out XAdESReadError readError))
            {
                error = new XAdESProcessingError(XAdESProcessingFailure.MalformedQualifyingProperties, 0, readError);

                return false;
            }
        }

        var references = new List<XAdESQualifyingPropertiesReference>(qualifyingPropertiesReferenceIndices.Count);
        foreach(int referenceElementIndex in qualifyingPropertiesReferenceIndices)
        {
            if(!XAdESQualifyingPropertiesReference.TryRead(table, referenceElementIndex, out XAdESQualifyingPropertiesReference reference, out XAdESReadError referenceReadError))
            {
                error = new XAdESProcessingError(XAdESProcessingFailure.MalformedQualifyingPropertiesReference, 0, referenceReadError);

                return false;
            }

            references.Add(reference);
        }

        result = new XAdESQualifyingPropertiesDiscoveryResult(hasQualifyingProperties, qualifyingProperties, objectOrdinal, references);
        error = default;

        return true;
    }


    /// <summary>
    /// Verifies a discovered <c>QualifyingProperties</c>'s <c>Target</c> attribute (clause 4.3.1) against the
    /// <c>ds:Signature</c> it was discovered within: the bare-name XPointer fragment must resolve, document-wide
    /// by <c>Id</c>, to the exact signature element — and, since every <c>QualifyingProperties</c>
    /// <see cref="TryDiscover"/> locates is direct-incorporated (a descendant of its own <c>ds:Signature</c>
    /// per clause 4.4.1), the non-fragment part must always be empty (XA-4.3.1-6) — the permissive "otherwise"
    /// case of XA-4.3.1-7 never applies to discovery's own output.
    /// </summary>
    /// <param name="table">The document both <paramref name="qualifyingProperties"/> and <paramref name="signature"/> were read from.</param>
    /// <param name="qualifyingProperties">The <c>QualifyingProperties</c> whose <c>Target</c> is verified.</param>
    /// <param name="signature">The signature the <c>Target</c> must identify.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match both
    /// arguments' own table;
    /// <see cref="XAdESProcessingFailure.UnsupportedTargetUriForm"/> when <c>Target</c> carries no <c>#</c>
    /// or its fragment is not a well-formed <c>NCName</c>;
    /// <see cref="XAdESProcessingFailure.TargetNonFragmentPartNotEmpty"/> when the part before <c>#</c> is
    /// non-empty;
    /// <see cref="XAdESProcessingFailure.TargetIdNotFound"/>/<see cref="XAdESProcessingFailure.DuplicateTargetId"/>
    /// when the fragment resolves to zero or more than one element;
    /// <see cref="XAdESProcessingFailure.TargetSignatureMismatch"/> when it resolves to an element other
    /// than <paramref name="signature"/>.</param>
    /// <returns><see langword="true"/> when <c>Target</c> binds to <paramref name="signature"/>.</returns>
    public static bool TryVerifyTargetBinding(XmlNodeTable table, XAdESQualifyingProperties qualifyingProperties, XmlSignature signature, out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(signature);
        if(!ReferenceEquals(qualifyingProperties.Table, table) || !signature.IsOver(table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        ReadOnlySpan<byte> target = qualifyingProperties.Target;
        int hashIndex = target.IndexOf((byte)'#');
        if(hashIndex < 0)
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.UnsupportedTargetUriForm, 0);

            return false;
        }

        ReadOnlySpan<byte> nonFragmentPart = target[..hashIndex];
        if(!nonFragmentPart.IsEmpty)
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TargetNonFragmentPartNotEmpty, 0);

            return false;
        }

        ReadOnlySpan<byte> fragment = target[(hashIndex + 1)..];
        if(!XmlReferenceDereferencer.IsNcNameFragment(fragment))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.UnsupportedTargetUriForm, 0);

            return false;
        }

        if(!table.TryFindElementById(fragment, out int targetElementIndex, out XmlSignatureProcessingError idError))
        {
            error = new XAdESProcessingError(
                idError.Failure == XmlSignatureProcessingFailure.DuplicateId ? XAdESProcessingFailure.DuplicateTargetId : XAdESProcessingFailure.TargetIdNotFound, 0);

            return false;
        }

        if(targetElementIndex != signature.ElementIndex)
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TargetSignatureMismatch, 0);

            return false;
        }

        error = default;

        return true;
    }


    /// <summary>
    /// Locates the <c>ds:Reference</c> that signs a discovered <c>QualifyingProperties</c>'s
    /// <c>SignedProperties</c> child (clause 4.4.2) and verifies it dereferences to that EXACT
    /// <c>SignedProperties</c> element — the table/node-identity pin this library requires, extending
    /// the anti-wrapping discipline: a forged <c>QualifyingProperties</c> in a second
    /// <c>ds:Object</c>, a decoy <c>SignedProperties</c>-shaped element sharing the target's <c>Id</c> shape,
    /// or a <c>Type</c>-matching reference whose <c>URI</c> targets a different signature's own
    /// <c>SignedProperties</c>, all refuse rather than being accepted.
    /// </summary>
    /// <param name="table">The document both <paramref name="signature"/> and <paramref name="signedProperties"/> were read from.</param>
    /// <param name="signature">The signature whose <c>ds:SignedInfo</c> is searched for the <c>Type</c>-matching reference.</param>
    /// <param name="signedProperties">The <c>SignedProperties</c> the located reference must dereference to.</param>
    /// <param name="resolver">The external-dereference delegate a non-same-document <c>URI</c> would need, or
    /// <see langword="null"/> when the caller supplies none — irrelevant on the success path, since a
    /// conformant <c>SignedProperties</c> reference is always same-document.</param>
    /// <param name="pool">The pool <see cref="XmlReferenceDereferencer.TryDereference"/> would rent an
    /// external resolver's octets from.</param>
    /// <param name="matchedReference">The located, verified reference on success.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match both
    /// arguments' own table;
    /// <see cref="XAdESProcessingFailure.SignedPropertiesReferenceNotFound"/>/
    /// <see cref="XAdESProcessingFailure.MultipleSignedPropertiesReferences"/> for zero or more than one
    /// <c>Type</c>-matching reference;
    /// <see cref="XAdESProcessingFailure.SignedPropertiesReferenceDereferenceFailed"/> when dereferencing its
    /// <c>URI</c> itself refuses;
    /// <see cref="XAdESProcessingFailure.SignedPropertiesReferenceTargetsExternalDocument"/> when it
    /// dereferences to external octets rather than a node-set;
    /// <see cref="XAdESProcessingFailure.SignedPropertiesReferenceTargetMismatch"/> when the node-set is not
    /// exactly <paramref name="signedProperties"/>.</param>
    /// <returns><see langword="true"/> when the reference was located and verified.</returns>
    public static bool TryVerifySignedPropertiesReferenceBinding(
        XmlNodeTable table,
        XmlSignature signature,
        XAdESSignedProperties signedProperties,
        XmlReferenceResolver? resolver,
        BaseMemoryPool pool,
        out XmlReference matchedReference,
        out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(pool);
        matchedReference = default;
        if(!signature.IsOver(table) || !ReferenceEquals(signedProperties.Table, table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        int matchCount = 0;
        XmlReference candidate = default;
        foreach(XmlReference reference in signature.SignedInfo.References)
        {
            if(reference.HasType && reference.Type.SequenceEqual(XAdESIdentifiers.SignedPropertiesTypeUriUtf8))
            {
                candidate = reference;
                ++matchCount;
            }
        }

        if(matchCount == 0)
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.SignedPropertiesReferenceNotFound, 0);

            return false;
        }

        if(matchCount > 1)
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.MultipleSignedPropertiesReferences, 0);

            return false;
        }

        if(!XmlReferenceDereferencer.TryDereference(table, candidate, resolver, pool, out XmlDereferenceResult dereferenced, out XmlSignatureProcessingError dereferenceError))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.SignedPropertiesReferenceDereferenceFailed, 0, dereferenceError);

            return false;
        }

        if(!dereferenced.IsNodeSet)
        {
            dereferenced.ExternalOctets?.Dispose();
            error = new XAdESProcessingError(XAdESProcessingFailure.SignedPropertiesReferenceTargetsExternalDocument, 0);

            return false;
        }

        if(dereferenced.NodeSet.IsWholeDocument || dereferenced.NodeSet.ApexElementIndex != signedProperties.ElementIndex)
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.SignedPropertiesReferenceTargetMismatch, 0);

            return false;
        }

        matchedReference = candidate;
        error = default;

        return true;
    }
}
