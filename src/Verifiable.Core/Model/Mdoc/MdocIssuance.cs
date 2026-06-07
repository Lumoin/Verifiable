using Verifiable.Cryptography;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Format-agnostic logical-mdoc issuance — produces an
/// <see cref="MdocLogicalDocument"/> from a doctype, a sequence of
/// <see cref="MdocClaimInput"/> entries, and an entropy-backed salt delegate.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors the params-in / result-out shape of
/// <see cref="Verifiable.Core.SelectiveDisclosure.SdIssuance.IssueAsync"/>:
/// no stateful builder, no fields to wire up, no encoder coupling. The
/// caller decides up-front what claims to commit and binds the salt
/// delegate to its entropy backend; this function generates the random
/// salts and assigns digest identifiers, leaving serialization (CBOR Tag 24
/// wrapping, MSO digest computation, COSE_Sign1 production for
/// <c>issuerAuth</c>) to the downstream pipeline.
/// </para>
/// <para>
/// The returned <see cref="MdocLogicalDocument"/> is the pre-signing
/// build-scaffold shape: items have no <c>WireBytes</c>, and there is no
/// <c>IssuerAuth</c>. ISO/IEC 18013-5 does not model an unsigned mdoc on
/// the wire; the logical type exists purely as the transient between this
/// function and <see cref="Verifiable.Cbor.Mdoc.MdocCborIssuance.SignAsync"/>.
/// </para>
/// <para>
/// Wire-shape extension points the SD-* pipelines reach for —
/// <c>RedactPayloadDelegate</c>, <c>SignPayloadDelegate</c> — have no
/// analogue at this stage because the logical mdoc has no format-specific
/// transformations: the claim shape on the way in is already the claim shape
/// on the way out, just with salts and digest IDs attached. The
/// CBOR-specific encode / MSO-compute / sign steps land in a separate
/// pipeline at the serializer layer and compose with this function.
/// </para>
/// </remarks>
public static class MdocIssuance
{
    /// <summary>
    /// Builds a logical <see cref="MdocLogicalDocument"/> from the supplied
    /// <paramref name="docType"/> and <paramref name="claims"/>, allocating
    /// a fresh salt for each claim through <paramref name="generateRandom"/>
    /// and assigning globally-sequential digest identifiers starting at zero.
    /// </summary>
    /// <param name="docType">
    /// The document type URI — e.g. <c>org.iso.18013.5.1.mDL</c> or
    /// <c>eu.europa.ec.eudi.pid.1</c>. Must be non-empty.
    /// </param>
    /// <param name="claims">
    /// The ordered sequence of issuer claims. The function preserves the
    /// caller's order within each namespace because the MSO digest
    /// commitments key on each item's wire bytes, which depend on insertion
    /// order in the encoded namespaces map. Must contain at least one entry.
    /// </param>
    /// <param name="generateRandom">
    /// Salt-generation delegate bound to the application's entropy backend.
    /// Each invocation must return a freshly-allocated tagged
    /// <see cref="Salt"/> of at least
    /// <see cref="MdocWellKnownKeys.IssuerSignedItemRandomMinimumLength"/>
    /// bytes — ISO/IEC 18013-5 §9.1.2.5. Ownership transfers to the
    /// resulting <see cref="MdocLogicalIssuerSignedItem"/>.
    /// </param>
    /// <returns>
    /// The assembled logical document. The caller owns the returned
    /// document and must dispose it if signing fails; on successful
    /// <see cref="Verifiable.Cbor.Mdoc.MdocCborIssuance.SignAsync"/>,
    /// salt ownership transfers to the signed document and the logical
    /// document must not be disposed.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <paramref name="claims"/> is empty (the MSO must commit to
    /// at least one digest entry) or when <paramref name="generateRandom"/>
    /// returns a salt shorter than
    /// <see cref="MdocWellKnownKeys.IssuerSignedItemRandomMinimumLength"/>.
    /// </exception>
    public static MdocLogicalDocument BuildDocument(
        string docType,
        IEnumerable<MdocClaimInput> claims,
        GenerateMdocItemRandomDelegate generateRandom)
    {
        ArgumentException.ThrowIfNullOrEmpty(docType);
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(generateRandom);

        Dictionary<string, List<MdocLogicalIssuerSignedItem>> namespaceItems = new(StringComparer.Ordinal);
        uint nextDigestId = 0;

        try
        {
            foreach(MdocClaimInput claim in claims)
            {
                ArgumentNullException.ThrowIfNull(claim);
                ArgumentException.ThrowIfNullOrEmpty(claim.NameSpace);
                ArgumentException.ThrowIfNullOrEmpty(claim.ElementIdentifier);

                Salt random = generateRandom();
                try
                {
                    if(random.Length < MdocWellKnownKeys.IssuerSignedItemRandomMinimumLength)
                    {
                        throw new InvalidOperationException(
                            $"GenerateMdocItemRandomDelegate returned {random.Length} bytes; ISO/IEC 18013-5 §9.1.2.5 " +
                            $"requires at least {MdocWellKnownKeys.IssuerSignedItemRandomMinimumLength}.");
                    }
                }
                catch
                {
                    random.Dispose();
                    throw;
                }

                MdocLogicalIssuerSignedItem item = new(
                    digestId: nextDigestId,
                    random: random,
                    elementIdentifier: claim.ElementIdentifier,
                    encodedElementValue: claim.EncodedElementValue);

                nextDigestId++;

                if(!namespaceItems.TryGetValue(claim.NameSpace, out List<MdocLogicalIssuerSignedItem>? items))
                {
                    items = [];
                    namespaceItems[claim.NameSpace] = items;
                }

                items.Add(item);
            }

            if(namespaceItems.Count == 0)
            {
                throw new InvalidOperationException(
                    "Cannot build an mdoc document with zero claims — the MSO must commit " +
                    "to at least one digest entry per ISO/IEC 18013-5 §8.3.2.1.2.");
            }

            Dictionary<string, IReadOnlyList<MdocLogicalIssuerSignedItem>> snapshot =
                new(namespaceItems.Count, StringComparer.Ordinal);
            foreach(KeyValuePair<string, List<MdocLogicalIssuerSignedItem>> entry in namespaceItems)
            {
                snapshot[entry.Key] = entry.Value.ToArray();
            }

            return new MdocLogicalDocument(
                docType: docType,
                issuerSigned: new MdocLogicalIssuerSigned(nameSpaces: snapshot));
        }
        catch
        {
            //Dispose any items already constructed before the failure propagates;
            //ownership has not yet transferred to a wrapping MdocLogicalDocument.
            foreach(List<MdocLogicalIssuerSignedItem> items in namespaceItems.Values)
            {
                foreach(MdocLogicalIssuerSignedItem item in items)
                {
                    item.Dispose();
                }
            }
            throw;
        }
    }
}
