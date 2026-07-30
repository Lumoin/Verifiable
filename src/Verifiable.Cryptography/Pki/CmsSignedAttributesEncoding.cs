using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The two encodings a CMS <c>SignedAttributes</c> set has
/// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.3">RFC 5652 §5.3</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.4">§5.4</see>): the <c>[0] IMPLICIT</c> form
/// carried inside a <c>SignerInfo</c>, and the universal <c>SET OF</c> form that is the exact octet sequence
/// the signature is computed over.
/// </summary>
/// <remarks>
/// <para>
/// RFC 5652 §5.4 states it as a single rule: "the DER encoding of the <c>SET OF</c> tag, rather than of the
/// <c>IMPLICIT [0]</c> tag, MUST be included in the message digest calculation along with the length and
/// content octets of the <c>SignedAttributes</c> value". The two forms therefore differ in exactly one octet,
/// the first, and share every length and content octet — which is why the verification path can produce the
/// signature input by retagging the octets it read, and why the creation path can produce the embedded form
/// by retagging the octets it signed. This type is the creation direction of that one rule, and
/// <see cref="ToSigningInput"/> is the retagging step itself, the inverse of what the managed verifier does
/// when it reconstructs the signature input from a signature it is reading.
/// </para>
/// <para>
/// <strong>Ordering is DER's, not the caller's.</strong> <c>SignedAttributes</c> is a <c>SET OF</c>, so
/// X.690 clause 11.6 fixes the order of the encoded attributes; <see cref="Create"/> emits that order
/// whatever order the attributes arrive in. This matters for a signature to verify at all: a verifier
/// reconstructs the signature input from the octets it received, so the creation side has to produce the
/// canonical order the standard mandates.
/// </para>
/// <para>
/// <strong>What this does not decide.</strong> Which attributes belong in the set — <c>content-type</c> and
/// <c>message-digest</c> being mandatory whenever signed attributes are present (RFC 5652 §5.3), and the
/// CAdES attributes of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clause 5</see> — is the signature-creation surface's decision. This type is the
/// encoder that surface calls, and it enforces only what the <c>SignedAttributes</c> syntax itself requires:
/// at least one attribute, and no attribute type present more than once.
/// </para>
/// <para>
/// Encoding is pure computation over caller-supplied octets — no cryptographic seam, no I/O — so it is
/// synchronous by nature; the digest and signature steps that consume <see cref="SigningInput"/> are the
/// asynchronous ones.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class CmsSignedAttributesEncoding: IDisposable
{
    /// <summary>
    /// The largest number of attributes one <c>SignedAttributes</c> set is built with. The syntax leaves the
    /// set unbounded; every attribute costs each verifier a parse and, at CAdES baseline levels, a rule
    /// evaluation, so the count is bounded here, where the set is created.
    /// </summary>
    private const int MaximumSignedAttributes = 64;

    /// <summary>The universal <c>SET OF</c> tag octet of the RFC 5652 §5.4 signature input.</summary>
    private const byte SetOfTagOctet = 0x31;

    /// <summary>The <c>[0] IMPLICIT</c> constructed tag octet of <c>SignerInfo.signedAttrs</c> (RFC 5652 §5.3).</summary>
    private const byte SignedAttributesTagOctet = 0xA0;


    /// <summary>
    /// Initialises a new encoding pair, taking ownership of both carriers.
    /// </summary>
    /// <param name="signingInput">The universal <c>SET OF</c> form. Ownership transfers to this instance.</param>
    /// <param name="embeddedForm">The <c>[0] IMPLICIT</c> form. Ownership transfers to this instance.</param>
    /// <exception cref="ArgumentNullException">When either carrier is <see langword="null"/>.</exception>
    public CmsSignedAttributesEncoding(PooledMemory signingInput, PooledMemory embeddedForm)
    {
        ArgumentNullException.ThrowIfNull(signingInput);
        ArgumentNullException.ThrowIfNull(embeddedForm);

        SigningInput = signingInput;
        EmbeddedForm = embeddedForm;
    }


    /// <summary>
    /// Gets the universal <c>SET OF</c> encoding — the exact octets the signature is computed over
    /// (RFC 5652 §5.4). Owned by this instance.
    /// </summary>
    public PooledMemory SigningInput { get; }

    /// <summary>
    /// Gets the <c>[0] IMPLICIT</c> encoding — the octets that occupy <c>SignerInfo.signedAttrs</c> on the
    /// wire (RFC 5652 §5.3). Owned by this instance.
    /// </summary>
    public PooledMemory EmbeddedForm { get; }


    /// <summary>
    /// Encodes a <c>SignedAttributes</c> set into both of its forms.
    /// </summary>
    /// <param name="attributes">The attributes of the set, in any order; DER fixes the encoded order.</param>
    /// <param name="pool">The memory pool both encodings are rented from.</param>
    /// <returns>The two encodings. The caller owns and disposes the result, which disposes both carriers.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="attributes"/>, one of its entries, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the set is empty, exceeds the supported count, or repeats an attribute type.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of both carriers transfers to the returned instance, which the caller disposes; the catch disposes the first when the second fails.")]
    public static CmsSignedAttributesEncoding Create(IReadOnlyList<CmsAttribute> attributes, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(attributes);
        ArgumentNullException.ThrowIfNull(pool);
        if(attributes.Count == 0)
        {
            throw new ArgumentException("A SignedAttributes set carries at least one attribute (RFC 5652 §5.3: SET SIZE (1..MAX) OF Attribute).", nameof(attributes));
        }

        if(attributes.Count > MaximumSignedAttributes)
        {
            throw new ArgumentException($"A SignedAttributes set is built with at most {MaximumSignedAttributes} attributes.", nameof(attributes));
        }

        var seenAttributeTypes = new HashSet<string>(attributes.Count, StringComparer.Ordinal);
        for(int i = 0; i < attributes.Count; ++i)
        {
            ArgumentNullException.ThrowIfNull(attributes[i], nameof(attributes));
            if(!seenAttributeTypes.Add(attributes[i].AttributeType))
            {
                throw new ArgumentException($"RFC 5652 §5.3: signed attributes include at most one instance of each attribute type; '{attributes[i].AttributeType}' appears more than once.", nameof(attributes));
            }
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
        {
            for(int i = 0; i < attributes.Count; ++i)
            {
                writer.WriteEncodedValue(attributes[i].AsReadOnlySpan());
            }
        }

        PooledMemory embeddedForm = Materialise(writer, pool);
        try
        {
            PooledMemory signingInput = ToSigningInput(embeddedForm.AsReadOnlySpan(), pool);

            return new CmsSignedAttributesEncoding(signingInput, embeddedForm);
        }
        catch
        {
            embeddedForm.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Retags an existing <c>[0] IMPLICIT</c> <c>SignedAttributes</c> encoding into the universal
    /// <c>SET OF</c> form the signature is computed over (RFC 5652 §5.4). Every length and content octet is
    /// copied unchanged; only the tag octet differs, which is the whole of what §5.4 asks for.
    /// </summary>
    /// <param name="embeddedSignedAttributes">The <c>[0] IMPLICIT</c> encoding, exactly one DER value.</param>
    /// <param name="pool">The memory pool the retagged copy is rented from.</param>
    /// <returns>The signature input octets. The caller owns and disposes them.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">When the input does not carry the single-octet <c>[0] IMPLICIT</c> constructed tag a <c>SignerInfo.signedAttrs</c> field has.</exception>
    /// <exception cref="AsnContentException">When the input is malformed or carries trailing octets.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    public static PooledMemory ToSigningInput(ReadOnlySpan<byte> embeddedSignedAttributes, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(embeddedSignedAttributes.IsEmpty || embeddedSignedAttributes[0] != SignedAttributesTagOctet)
        {
            throw new CryptographicException("A SignerInfo signedAttrs field is a [0] IMPLICIT constructed set (RFC 5652 §5.3), so its first octet is 0xA0.");
        }

        AsnDecoder.ReadEncodedValue(embeddedSignedAttributes, AsnEncodingRules.DER, out _, out _, out int bytesConsumed);
        if(bytesConsumed != embeddedSignedAttributes.Length)
        {
            throw new AsnContentException("A SignerInfo signedAttrs field is exactly one DER-encoded value, with no trailing octets (RFC 5652 §5.3).");
        }

        IMemoryOwner<byte> owner = pool.Rent(embeddedSignedAttributes.Length);
        try
        {
            embeddedSignedAttributes.CopyTo(owner.Memory.Span);
            owner.Memory.Span[0] = SetOfTagOctet;

            return new PooledMemory(owner, embeddedSignedAttributes.Length, CryptoTags.CmsEncodedSignedAttributes);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Rents a buffer of the writer's exact encoded length, encodes into it, and wraps it in a carrier.
    /// </summary>
    /// <param name="writer">The writer holding the completed <c>[0] IMPLICIT</c> set.</param>
    /// <param name="pool">The memory pool the buffer is rented from.</param>
    /// <returns>The encoded set carrier.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    private static PooledMemory Materialise(AsnWriter writer, MemoryPool<byte> pool)
    {
        int encodedLength = writer.GetEncodedLength();
        IMemoryOwner<byte> owner = pool.Rent(encodedLength);
        try
        {
            _ = writer.TryEncode(owner.Memory.Span, out int written);

            return new PooledMemory(owner, written, CryptoTags.CmsEncodedSignedAttributes);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        SigningInput.Dispose();
        EmbeddedForm.Dispose();
    }


    /// <summary>A short debugger string showing the shared encoded length of the two forms.</summary>
    private string DebuggerDisplay => $"CmsSignedAttributesEncoding({EmbeddedForm.Length} bytes)";
}
