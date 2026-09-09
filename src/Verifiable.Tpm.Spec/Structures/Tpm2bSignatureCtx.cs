using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// TPM2B_SIGNATURE_CTX - a sized buffer carrying a signing scheme's additional context (TPMU_SIGNATURE_CTX).
/// </summary>
/// <remarks>
/// <para>
/// Carries the value <c>TPM2_SignDigest()</c>, <c>TPM2_VerifyDigestSignature()</c>,
/// <c>TPM2_SignSequenceComplete()</c>, and <c>TPM2_VerifySequenceComplete()</c> pass as <c>context</c> — an
/// appropriate value for the type of key being used with the signature or verification operation.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                                       // Size of context.
///     BYTE   context[size]{:sizeof(TPMU_SIGNATURE_CTX)};  // The signature context.
/// } TPM2B_SIGNATURE_CTX;
/// </code>
/// <para>
/// <b>Bound:</b> Table 220's illustrative <c>TPMU_SIGNATURE_CTX</c> union — "defined for the limited purpose of
/// determining the size of a TPM2B_SIGNATURE_CTX" — has arms <c>commitCount[sizeof(UINT16)]</c> (selector
/// <c>TPM_ALG_ECDAA</c>), <c>id[MAX_SM2_ID_BYTES]</c> (<c>TPM_ALG_SM2</c>), <c>buffer[255]</c>
/// (<c>TPM_ALG_MLDSA</c> or <c>TPM_ALG_HASH_MLDSA</c>), and a zero-length <c>empty[0]</c> for every other
/// selector — "all other signature schemes do not support additional context". <see cref="MaxSize"/> is the
/// union's widest arm, the 255-octet ML-DSA <c>buffer</c>.
/// </para>
/// <para>
/// For every signature scheme this library executes — ECDSA, RSASSA, RSAPSS — a conformant <c>context</c> is
/// therefore zero-length. Rejecting a non-empty <c>context</c> under those schemes is a rule about which
/// selector is in play, so it belongs at the command dispatch or transition layer that knows the key's scheme,
/// not in this wire type: <see cref="Parse"/> only bounds <c>size</c> to <see cref="MaxSize"/>, exactly as it
/// would for a key whose scheme does admit a 255-octet context.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clauses 11.3.7 (Table 220) and 11.3.8 (Table 221).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bSignatureCtx: IDisposable, ITpmWireType
{
    /// <summary>
    /// The largest context a <c>TPM2B_SIGNATURE_CTX</c> buffer may carry: <c>sizeof(TPMU_SIGNATURE_CTX)</c>, the
    /// widest member of the illustrative union (255 octets, the ML-DSA <c>buffer[255]</c> arm), which is the
    /// bound Table 221 places on the <c>context</c> field (TPM 2.0 Library Part 2, clause 11.3.8).
    /// </summary>
    public const int MaxSize = 255;

    private static Tpm2bSignatureCtx EmptyInstance { get; } = new(null, 0);

    private IMemoryOwner<byte>? Storage { get; }

    private int Length { get; }

    private bool Disposed { get; set; }

    /// <summary>
    /// Initializes a new signature context with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the context bytes, or <see langword="null"/> for an empty context.</param>
    /// <param name="length">The number of valid octets at the head of <paramref name="storage"/>.</param>
    private Tpm2bSignatureCtx(IMemoryOwner<byte>? storage, int length)
    {
        Storage = storage;
        Length = length;
    }

    /// <summary>
    /// Gets an empty signature context — the conformant value for every scheme this library executes (ECDSA,
    /// RSASSA, RSAPSS), per Table 220's <c>empty[0]</c> arm.
    /// </summary>
    public static Tpm2bSignatureCtx Empty => EmptyInstance;

    /// <summary>
    /// Gets the size of the context in bytes.
    /// </summary>
    public int Size => Length;

    /// <summary>
    /// Gets whether this context is empty.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the context data as a read-only span.
    /// </summary>
    public ReadOnlySpan<byte> Context
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

        writer.WriteTpm2b(Context);
    }

    /// <summary>
    /// Parses a signature context from a TPM reader.
    /// </summary>
    /// <remarks>
    /// The declared size is bounded against <see cref="MaxSize"/> (<c>TPM_RC_SIZE</c> semantics) before it is
    /// checked against <see cref="TpmReader.Remaining"/>, so an oversized declaration is rejected as malformed
    /// rather than as truncated, and no pooled buffer is rented for either rejection.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed signature context.</returns>
    /// <exception cref="InvalidOperationException">The declared size exceeds <see cref="MaxSize"/> (<c>TPM_RC_SIZE</c>).</exception>
    /// <exception cref="ArgumentOutOfRangeException">The declared size exceeds the octets remaining in <paramref name="reader"/>.</exception>
    public static Tpm2bSignatureCtx Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return EmptyInstance;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"Signature context size {size} exceeds maximum {MaxSize} (TPM_RC_SIZE).");
        }

        if(size > reader.Remaining)
        {
            throw new ArgumentOutOfRangeException(nameof(reader), size, $"Signature context size {size} exceeds the {reader.Remaining} octets remaining in the reader.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);

        //Copy context bytes into owned storage.
        ReadOnlySpan<byte> sourceBytes = reader.ReadBytes(size);
        sourceBytes.CopyTo(storage.Memory.Span.Slice(0, size));

        return new Tpm2bSignatureCtx(storage, size);
    }

    /// <summary>
    /// Creates a signature context from the specified bytes.
    /// </summary>
    /// <param name="bytes">The context bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created signature context.</returns>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is longer than <see cref="MaxSize"/>.</exception>
    public static Tpm2bSignatureCtx Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return EmptyInstance;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"Signature context too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        bytes.CopyTo(storage.Memory.Span);

        return new Tpm2bSignatureCtx(storage, bytes.Length);
    }

    /// <summary>
    /// Releases the memory owned by this structure. The shared <see cref="Empty"/> instance is exempt: it owns
    /// no pooled storage and every consumer holds the same instance, so disposing one of them leaves it readable
    /// and framable for all the others.
    /// </summary>
    public void Dispose()
    {
        if(!Disposed && this != EmptyInstance)
        {
            Storage?.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger's one-line rendering: the context's octet count, never the octets themselves.</summary>
    private string DebuggerDisplay => $"TPM2B_SIGNATURE_CTX({Size} bytes)";
}
