using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The message imprint inputs of the two time-stamps on references to validation data of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clause A.1.5</see>: the <c>time-stamped-certs-crls-references</c> attribute of
/// clause A.1.5.1 and the <c>CAdES-C-timestamp</c> attribute of clause A.1.5.2.
/// </summary>
/// <remarks>
/// <para>
/// <strong>A third imprint convention, kept apart on purpose.</strong> Clause A.1.5 hashes each covered
/// attribute "with the <c>attrType</c> and <c>attrValues</c> (including type and length) but without the type
/// and length of the outer SEQUENCE", and clause A.1.5.2 additionally prefixes the <c>signature</c> field's
/// value octets "without the ASN.1 type or length encoding for that value". That is neither the whole-encoding
/// concatenation of clause 5.5.3 (<see cref="ArchiveTimestampV3"/>) nor the bare-value hashing of clauses 5.2.8
/// and 5.3, so nothing here is shared with either: a helper that conflated the three would compute imprints
/// that verify against the wrong specification.
/// </para>
/// <para>
/// <strong>Recognition only.</strong> Both attributes are <c>shall not be present</c> at every baseline level of
/// clause 6.3, and clause A.2 forbids creating new instances of the reference attributes they cover. Nothing in
/// this library emits them; this computation exists so that a legacy signature carrying one of them can still
/// have what its token protects stated, rather than leaving a validation process to accept a coverage nothing
/// verified.
/// </para>
/// <para>
/// <strong>The result is a claim, not a conclusion.</strong> The octets returned are what the token's
/// <c>messageImprint</c> is asserted to have been computed over; the proof-of-existence extraction building
/// block of ETSI EN 319 102-1 clause 5.6.2.3 hashes them under the token's own algorithm and compares. A claim
/// this computation states too strictly or too loosely therefore costs a proof of existence, never soundness.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> The Signed Data Object arrives from a network location or a
/// document. Every structure is reached through <see cref="CmsSignedDataAugmentation"/>'s bounded, non-recursive
/// walk, and every failure to read one is reported as "nothing stated" rather than thrown, which is what the
/// building block treats as a time-stamp that protects nothing it can name.
/// </para>
/// </remarks>
public static class ValidationDataTimestampCoverage
{
    /// <summary>
    /// States the octets one <c>CAdES-C-timestamp</c> or <c>time-stamped-certs-crls-references</c> token's
    /// <c>messageImprint</c> is computed over, per clause A.1.5.
    /// </summary>
    /// <param name="signedData">The Signed Data Object the attribute was found on.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c> carrying the attribute.</param>
    /// <param name="attributeOid">The attribute the token was carried in — <see cref="CAdESSignatureFacts.EscTimestampAttributeOid"/> or <see cref="CAdESSignatureFacts.CertificateAndCrlTimestampAttributeOid"/>.</param>
    /// <param name="pool">The memory pool the returned carrier is rented from.</param>
    /// <returns>The concatenation, which the caller owns and disposes, or <see langword="null"/> when the signature does not carry the objects the clause names.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative.</exception>
    /// <remarks>
    /// <para>
    /// Clause A.1.5.1 concatenates the <c>complete-certificate-references</c> and
    /// <c>complete-revocation-references</c> attributes "as present within the electronic signature"; clause
    /// A.1.5.2 prefixes them with the <c>signature</c> field's value octets and the <c>signature-time-stamp</c>
    /// attribute. A signature carrying neither reference attribute is not one either token class is defined
    /// over, and an attribute present more than once, or carrying more than the single <c>AttributeValue</c>
    /// both clauses state, leaves which instance the concatenation takes undecided — both yield
    /// <see langword="null"/> rather than one of the possibilities guessed at.
    /// </para>
    /// <para>
    /// The two attribute contributions are re-encoded in DER from the <c>attrType</c> and the single
    /// <c>AttributeValue</c> found. Clause A.1.5 requires the attributes being time-stamped to be DER
    /// ("<em>should</em> be encoded in DER ... if DER is not employed, then the binary encoding ... should be
    /// preserved"), so for a conformant signature the re-encoding reproduces the original octets exactly; for a
    /// non-DER one the claim simply fails the imprint comparison and no proof of existence follows.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the returned carrier transfers to the caller, which disposes it once it has verified the message imprint against it.")]
    public static SignedContentMemory? StateCoverage(
        CmsSignedData signedData,
        int signerIndex,
        string attributeOid,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(attributeOid);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);

        try
        {
            IReadOnlyList<CmsUnsignedAttributeValueLocation> locations = CmsSignedDataAugmentation.LocateUnsignedAttributeValues(signedData, signerIndex);
            byte[]? certificateReferences = EncodeSingleAttribute(signedData, signerIndex, locations, CAdESSignatureFacts.CompleteCertificateReferencesAttributeOid);
            byte[]? revocationReferences = EncodeSingleAttribute(signedData, signerIndex, locations, CAdESSignatureFacts.CompleteRevocationReferencesAttributeOid);
            if(certificateReferences is null && revocationReferences is null)
            {
                //Neither clause's token is defined over a signature carrying no reference attribute at all.
                return null;
            }

            List<ReadOnlyMemory<byte>> parts = [];
            if(string.Equals(attributeOid, CAdESSignatureFacts.EscTimestampAttributeOid, StringComparison.Ordinal))
            {
                //Clause A.1.5.2: the OCTET STRING of the signature field within SignerInfo, without the ASN.1
                //type or length encoding for that value, then the signature-time-stamp attribute, then the two
                //reference attributes. All four objects the clause names are required, since the attribute is
                //defined as covering the CAdES-E-C level in full.
                byte[]? signatureTimestamp = EncodeSingleAttribute(signedData, signerIndex, locations, CAdESSignatureFacts.SignatureTimestampAttributeOid);
                if(signatureTimestamp is null || certificateReferences is null || revocationReferences is null)
                {
                    return null;
                }

                parts.Add(CmsSignedDataAugmentation.ReadSignatureValue(signedData, signerIndex));
                parts.Add(signatureTimestamp);
                parts.Add(certificateReferences);
                parts.Add(revocationReferences);
            }
            else if(string.Equals(attributeOid, CAdESSignatureFacts.CertificateAndCrlTimestampAttributeOid, StringComparison.Ordinal))
            {
                //Clause A.1.5.1: the two reference attributes, as present within the electronic signature.
                AddWhenPresent(parts, certificateReferences);
                AddWhenPresent(parts, revocationReferences);
            }
            else
            {
                //Not one of the two attribute classes clause A.1.5 defines an imprint for.
                return null;
            }

            return Concatenate(parts, pool);
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            //A structure this computation cannot walk states nothing, which is the fail-closed reading step 1)
            //of ETSI EN 319 102-1 clause 5.6.2.3.4 puts on a time-stamp whose coverage is unknown.
            return null;
        }

        //Appends one optional attribute contribution, so neither branch above has to repeat the null test.
        static void AddWhenPresent(List<ReadOnlyMemory<byte>> parts, byte[]? contribution)
        {
            if(contribution is not null)
            {
                parts.Add(contribution);
            }
        }
    }


    /// <summary>
    /// Encodes one unsigned attribute the way clause A.1.5 includes it in the hash: the <c>attrType</c> field
    /// and the <c>attrValues</c> field, each with its own tag and length octets, and without the tag and length
    /// of the enclosing <c>Attribute</c> SEQUENCE.
    /// </summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c>.</param>
    /// <param name="locations">Every unsigned attribute value the signer carries.</param>
    /// <param name="attributeOid">The attribute type to encode.</param>
    /// <returns>The two fields laid end to end, or <see langword="null"/> when the attribute is absent, carried more than once, or carries more than one value.</returns>
    /// <exception cref="AsnContentException">When the attribute's value cannot be read.</exception>
    /// <exception cref="CryptographicException">When the structure is not a CMS SignedData holding that value.</exception>
    private static byte[]? EncodeSingleAttribute(
        CmsSignedData signedData,
        int signerIndex,
        IReadOnlyList<CmsUnsignedAttributeValueLocation> locations,
        string attributeOid)
    {
        int found = 0;
        CmsUnsignedAttributeValueLocation location = default;
        for(int i = 0; i < locations.Count; ++i)
        {
            if(string.Equals(locations[i].AttributeType, attributeOid, StringComparison.Ordinal))
            {
                location = locations[i];
                ++found;
            }
        }

        //Both clauses state the attribute "shall contain exactly one component of AttributeValue type", so more
        //than one value — whether within one attribute or across two attributes of the same type — leaves the
        //concatenation undecided.
        if(found != 1)
        {
            return null;
        }

        ReadOnlyMemory<byte> value = CmsSignedDataAugmentation.ReadUnsignedAttributeValue(
            signedData, signerIndex, location.AttributeIndex, location.ValueIndex);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteObjectIdentifier(attributeOid);
        using(writer.PushSetOf())
        {
            writer.WriteEncodedValue(value.Span);
        }

        return writer.Encode();
    }


    /// <summary>
    /// Lays the parts of a concatenation end to end into one pooled carrier.
    /// </summary>
    /// <param name="parts">The parts, in the order the clause lists them.</param>
    /// <param name="pool">The memory pool the carrier is rented from.</param>
    /// <returns>The carrier. The caller owns and disposes it.</returns>
    private static SignedContentMemory Concatenate(List<ReadOnlyMemory<byte>> parts, MemoryPool<byte> pool)
    {
        int total = 0;
        for(int i = 0; i < parts.Count; ++i)
        {
            total += parts[i].Length;
        }

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            Span<byte> destination = owner.Memory.Span[..total];
            int written = 0;
            for(int i = 0; i < parts.Count; ++i)
            {
                parts[i].Span.CopyTo(destination[written..]);
                written += parts[i].Length;
            }

            return new SignedContentMemory(owner);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }
}
