using System;
using System.Buffers;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// A complete DER-encoded CMS <c>Attribute</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.3">RFC 5652 §5.3</see>) held in pooled
/// memory: the <c>attrType</c> object identifier together with its <c>attrValues SET OF AttributeValue</c>,
/// encoded as the one <c>SEQUENCE</c> that goes into a <c>SignerInfo</c>'s <c>signedAttrs</c> or
/// <c>unsignedAttrs</c> set.
/// </summary>
/// <remarks>
/// <para>
/// This is the creation-side counterpart of <see cref="CmsSignedAttribute"/>: that carrier holds one
/// attribute's decoded <em>value</em> as the verification path surfaces it, this one holds the whole
/// attribute as the octets an encoder emits. Attributes are built once and then spliced verbatim, because
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clause 5.5.3</see> requires an augmentation to preserve the binary encoding of
/// what is already present and to DER-encode what it adds: the bytes this carrier holds are the bytes that
/// reach the wire, so a later <c>ats-hash-index-v3</c> computed over them stays valid.
/// </para>
/// <para>
/// A CMS attribute may carry several values (<c>attrValues</c> is a <c>SET OF</c>), and clause 5.5.2 makes
/// that granularity load bearing — the <c>unsignedAttrValuesHashIndex</c> holds one entry per
/// <c>AttributeValue</c>, not per attribute. Both the single-value and multi-value shapes are therefore
/// first-class here rather than a single-value convenience only.
/// </para>
/// <para>
/// Encoding is pure computation over caller-supplied octets — no cryptographic seam, no I/O — so it is
/// synchronous by nature; the asynchronous surfaces are the ones that reach a digest, signature, or
/// transport seam.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class CmsAttribute: SensitiveMemory, IEquatable<CmsAttribute>
{
    /// <summary>
    /// The largest number of <c>AttributeValue</c> instances one attribute may be built with. The syntax
    /// leaves <c>attrValues</c> unbounded; each value costs the clause 5.5.2 hash index one entry and every
    /// verifier one digest, so the count is bounded here, where the attribute is created.
    /// </summary>
    private const int MaximumAttributeValues = 64;


    /// <summary>
    /// Initialises a new <see cref="CmsAttribute"/> over owned, already-encoded attribute octets.
    /// </summary>
    /// <param name="attributeType">The <c>attrType</c> object identifier in dotted form.</param>
    /// <param name="encodedAttribute">The DER-encoded <c>Attribute</c> SEQUENCE. Ownership transfers to this instance.</param>
    /// <param name="length">The number of valid octets in <paramref name="encodedAttribute"/>.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="attributeType"/> or <paramref name="encodedAttribute"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="length"/> is not positive.</exception>
    public CmsAttribute(string attributeType, IMemoryOwner<byte> encodedAttribute, int length)
        : base(encodedAttribute, CryptoTags.CmsEncodedAttribute)
    {
        ArgumentNullException.ThrowIfNull(attributeType);
        ArgumentNullException.ThrowIfNull(encodedAttribute);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

        AttributeType = attributeType;
        Length = length;
    }


    /// <summary>Gets the <c>attrType</c> object identifier in dotted form (for example <c>0.4.0.19122.1.5</c> for <c>ats-hash-index-v3</c>).</summary>
    public string AttributeType { get; }

    /// <summary>Gets the number of valid octets of the DER-encoded <c>Attribute</c> (the rented buffer may be larger).</summary>
    public int Length { get; }


    /// <summary>
    /// Gets the DER-encoded <c>Attribute</c> as a span, sliced to <see cref="Length"/> (the base member
    /// returns the whole, possibly larger, rented buffer).
    /// </summary>
    /// <returns>A read-only span over exactly the encoded attribute.</returns>
    public new ReadOnlySpan<byte> AsReadOnlySpan() => MemoryOwner.Memory.Span[..Length];


    /// <summary>
    /// Gets the DER-encoded <c>Attribute</c> as memory, sliced to <see cref="Length"/> (the base member
    /// returns the whole, possibly larger, rented buffer).
    /// </summary>
    /// <returns>A read-only memory over exactly the encoded attribute.</returns>
    public new ReadOnlyMemory<byte> AsReadOnlyMemory() => MemoryOwner.Memory[..Length];


    /// <summary>
    /// Encodes a single-valued CMS <c>Attribute</c> (RFC 5652 §5.3) — the shape every CAdES attribute of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause 5</see> other than <c>countersignature</c> uses.
    /// </summary>
    /// <param name="attributeType">The <c>attrType</c> object identifier in dotted form.</param>
    /// <param name="attributeValue">Exactly one DER-encoded <c>AttributeValue</c>, tag and length octets included.</param>
    /// <param name="pool">The memory pool the encoded attribute is rented from.</param>
    /// <returns>The encoded attribute. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentException">When <paramref name="attributeType"/> is not a well-formed object identifier, or <paramref name="attributeValue"/> is empty.</exception>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="AsnContentException">When <paramref name="attributeValue"/> is not exactly one DER-encoded value.</exception>
    public static CmsAttribute Create(string attributeType, ReadOnlySpan<byte> attributeValue, BaseMemoryPool pool)
    {
        ArgumentException.ThrowIfNullOrEmpty(attributeType);
        ArgumentNullException.ThrowIfNull(pool);
        EnsureSingleEncodedValue(attributeValue, nameof(attributeValue));

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteObjectIdentifier(attributeType);
            using(writer.PushSetOf())
            {
                writer.WriteEncodedValue(attributeValue);
            }
        }

        return Materialise(attributeType, writer, pool);
    }


    /// <summary>
    /// Encodes a multi-valued CMS <c>Attribute</c> (RFC 5652 §5.3). The <c>attrValues</c> set is DER, so the
    /// values are emitted in the sorted order DER requires regardless of the order they are supplied in.
    /// </summary>
    /// <param name="attributeType">The <c>attrType</c> object identifier in dotted form.</param>
    /// <param name="attributeValues">The DER-encoded <c>AttributeValue</c> instances, each exactly one encoded value.</param>
    /// <param name="pool">The memory pool the encoded attribute is rented from.</param>
    /// <returns>The encoded attribute. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentException">When <paramref name="attributeType"/> is not a well-formed object identifier, or <paramref name="attributeValues"/> is empty or exceeds the supported count.</exception>
    /// <exception cref="ArgumentNullException">When <paramref name="attributeValues"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="AsnContentException">When a value is not exactly one DER-encoded value.</exception>
    public static CmsAttribute Create(string attributeType, IReadOnlyList<ReadOnlyMemory<byte>> attributeValues, BaseMemoryPool pool)
    {
        ArgumentException.ThrowIfNullOrEmpty(attributeType);
        ArgumentNullException.ThrowIfNull(attributeValues);
        ArgumentNullException.ThrowIfNull(pool);
        if(attributeValues.Count == 0)
        {
            throw new ArgumentException("A CMS attribute carries at least one value (RFC 5652 §5.3: attrValues SET OF AttributeValue).", nameof(attributeValues));
        }

        if(attributeValues.Count > MaximumAttributeValues)
        {
            throw new ArgumentException($"A CMS attribute is built with at most {MaximumAttributeValues} values.", nameof(attributeValues));
        }

        for(int i = 0; i < attributeValues.Count; ++i)
        {
            EnsureSingleEncodedValue(attributeValues[i].Span, nameof(attributeValues));
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteObjectIdentifier(attributeType);
            using(writer.PushSetOf())
            {
                for(int i = 0; i < attributeValues.Count; ++i)
                {
                    writer.WriteEncodedValue(attributeValues[i].Span);
                }
            }
        }

        return Materialise(attributeType, writer, pool);
    }


    /// <summary>
    /// Rents a buffer of the writer's exact encoded length, encodes into it, and wraps it in a carrier.
    /// </summary>
    /// <param name="attributeType">The <c>attrType</c> object identifier the carrier reports.</param>
    /// <param name="writer">The writer holding the completed <c>Attribute</c> SEQUENCE.</param>
    /// <param name="pool">The memory pool the buffer is rented from.</param>
    /// <returns>The encoded attribute carrier.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    private static CmsAttribute Materialise(string attributeType, AsnWriter writer, BaseMemoryPool pool)
    {
        int encodedLength = writer.GetEncodedLength();
        IMemoryOwner<byte> owner = pool.Rent(encodedLength);
        try
        {
            _ = writer.TryEncode(owner.Memory.Span, out int written);

            return new CmsAttribute(attributeType, owner, written);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Verifies that <paramref name="value"/> is exactly one DER-encoded value with no trailing octets — the
    /// hostile-input boundary of the creation side, mirroring how the parse side rejects trailing data.
    /// </summary>
    /// <param name="value">The candidate <c>AttributeValue</c> octets.</param>
    /// <param name="parameterName">The parameter name reported on an argument failure.</param>
    /// <exception cref="ArgumentException">When <paramref name="value"/> is empty.</exception>
    /// <exception cref="AsnContentException">When <paramref name="value"/> is malformed or carries trailing octets.</exception>
    private static void EnsureSingleEncodedValue(ReadOnlySpan<byte> value, string parameterName)
    {
        if(value.IsEmpty)
        {
            throw new ArgumentException("A CMS attribute value is one DER-encoded value (RFC 5652 §5.3).", parameterName);
        }

        AsnDecoder.ReadEncodedValue(value, AsnEncodingRules.DER, out _, out _, out int bytesConsumed);
        if(bytesConsumed != value.Length)
        {
            throw new AsnContentException("A CMS attribute value is exactly one DER-encoded value, with no trailing octets (RFC 5652 §5.3).");
        }
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] CmsAttribute? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(AttributeType, other.AttributeType, StringComparison.Ordinal)
            && AsReadOnlySpan().SequenceEqual(other.AsReadOnlySpan());
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is CmsAttribute other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(AttributeType, StringComparer.Ordinal);
        hash.AddBytes(AsReadOnlySpan());

        return hash.ToHashCode();
    }


    /// <summary>A short debugger string showing the attribute type and encoded length.</summary>
    private string DebuggerDisplay => $"CmsAttribute({AttributeType}, {Length} bytes)";
}
