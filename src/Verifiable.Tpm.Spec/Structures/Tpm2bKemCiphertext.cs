using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// TPM2B_KEM_CIPHERTEXT - a sized buffer carrying a KEM's ciphertext (TPMU_KEM_CIPHERTEXT).
/// </summary>
/// <remarks>
/// <para>
/// Carries the value <c>TPM2_Encapsulate()</c> returns as <c>ciphertext</c> and <c>TPM2_Decapsulate()</c>
/// accepts as its <c>ciphertext</c> parameter (TPM 2.0 Library Part 3, clauses 14.10/14.11) — the public
/// artifact the encapsulator sends the holder of the KEM private key so it can recover the same shared
/// secret. Unlike <see cref="Tpm2bSharedSecret"/>, this value is not sensitive: it is a public ephemeral
/// point (the ECC arm) or a public KEM ciphertext (the ML-KEM arm), so it rides a plain pooled buffer —
/// the same carrier shape <see cref="Tpm2bSignatureCtx"/> uses — rather than <see cref="SensitiveMemory"/>.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                                       // Size of ciphertext.
///     BYTE   ciphertext[size]{:sizeof(TPMU_KEM_CIPHERTEXT)};  // The KEM ciphertext.
/// } TPM2B_KEM_CIPHERTEXT;
/// </code>
/// <para>
/// <b>Bound:</b> Table 101's illustrative <c>TPMU_KEM_CIPHERTEXT</c> union — sized "for the limited
/// purpose of determining the size of a TPM2B_KEM_CIPHERTEXT", every member "a byte array, meaning that
/// marshaling or unmarshaling code does not need to consider the selector" — has arms
/// <c>ecdh[sizeof(TPMS_ECC_POINT)]</c> and <c>mlkem[MAX_MLKEM_CT_SIZE]</c>. Because unmarshaling needs no
/// selector, this library models no <c>TPMU_KEM_CIPHERTEXT</c> type: the union exists only to size the
/// TPM2B, and this <see cref="MaxSize"/> is that sizing's result rather than a materialized structure.
/// <see cref="MaxSize"/> is 1568 octets — Table 205's <c>TPM_MLKEM_1024</c> ciphertext size, the widest
/// value any v185 TPM can place in this field (the ML-KEM-512/768/1024 ciphertexts are 768/1088/1568
/// octets respectively; the shared secret is a fixed 32 octets for all three). It comfortably covers the
/// <c>ecdh</c> arm's <c>sizeof(TPMS_ECC_POINT)</c> — two <c>TPM2B_ECC_PARAMETER</c> coordinates, at most
/// 136 octets for the widest supported curve.
/// </para>
/// <para>
/// <b>Content for the ECC KEM (RFC 9180 DHKEM):</b> per TPM 2.0 Library Part 1, clause 44.4.2 step 3, and
/// <see href="https://www.rfc-editor.org/rfc/rfc9180">RFC 9180</see>'s <c>Encap</c>/<c>Decap</c>, the
/// <c>ecdh</c> ciphertext is <c>pkE_serialized</c> — the ephemeral public key alone, SEC 1 uncompressed
/// encoding (<c>0x04 || X || Y</c>) — <b>not</b> a marshaled <c>TPMS_ECC_POINT</c> (which would carry two
/// length-prefixed <c>TPM2B_ECC_PARAMETER</c> fields). Table 101 sizes the buffer by the union arm; clause
/// 44.4 defines what actually goes in it, and RFC 9180 Appendix A.3's test vectors' <c>enc</c> values are
/// themselves bare SEC 1 points, so conformance to those vectors requires this reading.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clauses 10.3.13 (Table 101) and 10.3.14 (Table 102).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bKemCiphertext: IDisposable, ITpmWireType
{
    /// <summary>
    /// The largest ciphertext a <c>TPM2B_KEM_CIPHERTEXT</c> buffer may carry: 1568 octets, Table 205's
    /// <c>TPM_MLKEM_1024</c> ciphertext size — the widest arm of the illustrative
    /// <c>TPMU_KEM_CIPHERTEXT</c> union (TPM 2.0 Library Part 2, clause 10.3.14, Table 102) any v185 TPM
    /// can emit, and wide enough to cover the ECC arm's <c>sizeof(TPMS_ECC_POINT)</c> as well.
    /// </summary>
    public const int MaxSize = 1568;

    /// <summary>Shared empty instance backed by no pooled storage.</summary>
    private static Tpm2bKemCiphertext EmptyInstance { get; } = new(null, 0);

    /// <summary>The pooled storage backing this ciphertext, or <see langword="null"/> for the shared empty instance.</summary>
    private IMemoryOwner<byte>? Storage { get; }

    /// <summary>The number of valid octets at the head of <see cref="Storage"/>.</summary>
    private int Length { get; }

    /// <summary>Whether <see cref="Dispose"/> has already released <see cref="Storage"/>.</summary>
    private bool Disposed { get; set; }

    /// <summary>
    /// Initializes a new KEM ciphertext with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the ciphertext bytes, or <see langword="null"/> for an empty ciphertext.</param>
    /// <param name="length">The number of valid octets at the head of <paramref name="storage"/>.</param>
    private Tpm2bKemCiphertext(IMemoryOwner<byte>? storage, int length)
    {
        Storage = storage;
        Length = length;
    }

    /// <summary>
    /// Gets an empty KEM ciphertext.
    /// </summary>
    public static Tpm2bKemCiphertext Empty => EmptyInstance;

    /// <summary>
    /// Gets the size of the ciphertext in bytes.
    /// </summary>
    public int Size => Length;

    /// <summary>
    /// Gets whether this ciphertext is empty.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the ciphertext data as a read-only span.
    /// </summary>
    public ReadOnlySpan<byte> Ciphertext
    {
        get
        {
            ObjectDisposedException.ThrowIf(Disposed, this);

            if(Storage is null)
            {
                return ReadOnlySpan<byte>.Empty;
            }

            return Storage.Memory.Span.Slice(0, Length);
        }
    }

    /// <summary>
    /// Gets the serialized size (2-byte size prefix + data).
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Length;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        writer.WriteTpm2b(Ciphertext);
    }

    /// <summary>
    /// Parses a KEM ciphertext from a TPM reader.
    /// </summary>
    /// <remarks>
    /// The declared size is bounded against <see cref="MaxSize"/> (<c>TPM_RC_SIZE</c> semantics) before it
    /// is checked against <see cref="TpmReader.Remaining"/>, so an oversized declaration is rejected as
    /// malformed rather than as truncated, and no pooled buffer is rented for either rejection.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed KEM ciphertext.</returns>
    /// <exception cref="InvalidOperationException">The declared size exceeds <see cref="MaxSize"/> (<c>TPM_RC_SIZE</c>).</exception>
    /// <exception cref="ArgumentOutOfRangeException">The declared size exceeds the octets remaining in <paramref name="reader"/>.</exception>
    public static Tpm2bKemCiphertext Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return EmptyInstance;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"KEM ciphertext size {size} exceeds maximum {MaxSize} (TPM_RC_SIZE).");
        }

        if(size > reader.Remaining)
        {
            throw new ArgumentOutOfRangeException(nameof(reader), size, $"KEM ciphertext size {size} exceeds the {reader.Remaining} octets remaining in the reader.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);

        //Copy ciphertext bytes into owned storage.
        ReadOnlySpan<byte> sourceBytes = reader.ReadBytes(size);
        sourceBytes.CopyTo(storage.Memory.Span.Slice(0, size));

        return new Tpm2bKemCiphertext(storage, size);
    }

    /// <summary>
    /// Creates a KEM ciphertext from the specified bytes.
    /// </summary>
    /// <param name="bytes">The ciphertext bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created KEM ciphertext.</returns>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is longer than <see cref="MaxSize"/>.</exception>
    public static Tpm2bKemCiphertext Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return EmptyInstance;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"KEM ciphertext too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        bytes.CopyTo(storage.Memory.Span);

        return new Tpm2bKemCiphertext(storage, bytes.Length);
    }

    /// <summary>
    /// Releases the memory owned by this structure. The shared <see cref="Empty"/> instance is exempt: it
    /// owns no pooled storage and every consumer holds the same instance, so disposing one of them leaves
    /// it readable and framable for all the others.
    /// </summary>
    public void Dispose()
    {
        if(!Disposed && this != EmptyInstance)
        {
            Storage?.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger's one-line rendering: the ciphertext's octet count, never the octets themselves.</summary>
    private string DebuggerDisplay => $"TPM2B_KEM_CIPHERTEXT({Size} bytes)";
}
