using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// TPM2B_SIGNATURE_HINT - a sized buffer carrying a signature-verification scheme's hint value.
/// </summary>
/// <remarks>
/// <para>
/// Carries the value <c>TPM2_VerifySequenceStart()</c> accepts as its <c>hint</c> parameter. TPM 2.0
/// Library Part 3, clause 17.6, Table 89 requires: "hint must be supplied for TPM_ALG_EDDSA, and must be
/// zero-length in all other cases." TPM 2.0 Library Part 2, clause 11.3.9, Table 222 describes the same
/// rule from the field's own definition: "For TPM_ALG_EDDSA, hint contains the encoded R value from the
/// signature. For all other signature algorithms, this buffer must be zero-length." No return code names
/// the zero-length rule, so every scheme this library executes (ECDSA, RSASSA, RSAPSS) carries an empty
/// hint through this type, and refusing a non-empty hint under those schemes is a rule for the command
/// layer, not this wire type — the same posture <see cref="Tpm2bSignatureCtx"/> takes for its own
/// scheme-dependent bound.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                                    // Size of hint.
///     BYTE   hint[size]{:MAX_SIGNATURE_HINT_SIZE};     // The signature hint.
/// } TPM2B_SIGNATURE_HINT;
/// </code>
/// <para>
/// <b>Bound:</b> <c>MAX_SIGNATURE_HINT_SIZE</c> "is an implementation-dependent value that is the maximum
/// hint size across all signature verification algorithms supported by the TPM" (Part 2, clause 11.3.9) —
/// no numeric value is given anywhere in the published v185 text or errata. <see cref="MaxSize"/> is 57
/// octets: the widest hint any v185 verification algorithm defines is EdDSA's encoded R over Curve448 (57
/// octets, <see href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</see> section 5.2; Ed25519's R is
/// 32 octets). The simulator's own executable verification algorithms (ECDSA, RSASSA, RSAPSS) need none.
/// </para>
/// <para>
/// Not <see cref="SensitiveMemory"/>: the hint is a public component of a signature, published alongside
/// it rather than protected from disclosure — the same reasoning that keeps <see cref="Tpm2bSignatureCtx"/>
/// off the sensitive tier.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 11.3.9, Table 222.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bSignatureHint: IDisposable, ITpmWireType
{
    /// <summary>
    /// The largest hint a <c>TPM2B_SIGNATURE_HINT</c> buffer may carry: 57 octets, the encoded R value of
    /// an EdDSA signature over Curve448 (<see href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</see>
    /// section 5.2) — the widest hint any v185 signature verification algorithm defines, since
    /// <c>MAX_SIGNATURE_HINT_SIZE</c> itself carries no published numeric value (TPM 2.0 Library Part 2,
    /// clause 11.3.9).
    /// </summary>
    public const int MaxSize = 57;

    /// <summary>Shared empty instance backed by no pooled storage.</summary>
    private static Tpm2bSignatureHint EmptyInstance { get; } = new(null, 0);

    /// <summary>The pooled storage backing this hint, or <see langword="null"/> for the shared empty instance.</summary>
    private IMemoryOwner<byte>? Storage { get; }

    /// <summary>The number of valid octets at the head of <see cref="Storage"/>.</summary>
    private int Length { get; }

    /// <summary>Whether <see cref="Dispose"/> has already released <see cref="Storage"/>.</summary>
    private bool Disposed { get; set; }

    /// <summary>
    /// Initializes a new signature hint with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the hint bytes, or <see langword="null"/> for an empty hint.</param>
    /// <param name="length">The number of valid octets at the head of <paramref name="storage"/>.</param>
    private Tpm2bSignatureHint(IMemoryOwner<byte>? storage, int length)
    {
        Storage = storage;
        Length = length;
    }

    /// <summary>
    /// Gets an empty signature hint — the conformant value for every scheme this library executes (ECDSA,
    /// RSASSA, RSAPSS), per clause 17.6's zero-length rule.
    /// </summary>
    public static Tpm2bSignatureHint Empty => EmptyInstance;

    /// <summary>
    /// Gets the size of the hint in bytes.
    /// </summary>
    public int Size => Length;

    /// <summary>
    /// Gets whether this hint is empty.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the hint data as a read-only span.
    /// </summary>
    public ReadOnlySpan<byte> Hint
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

        writer.WriteTpm2b(Hint);
    }

    /// <summary>
    /// Parses a signature hint from a TPM reader.
    /// </summary>
    /// <remarks>
    /// The declared size is bounded against <see cref="MaxSize"/> (<c>TPM_RC_SIZE</c> semantics) before it
    /// is checked against <see cref="TpmReader.Remaining"/>, so an oversized declaration is rejected as
    /// malformed rather than as truncated, and no pooled buffer is rented for either rejection.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed signature hint.</returns>
    /// <exception cref="InvalidOperationException">The declared size exceeds <see cref="MaxSize"/> (<c>TPM_RC_SIZE</c>).</exception>
    /// <exception cref="ArgumentOutOfRangeException">The declared size exceeds the octets remaining in <paramref name="reader"/>.</exception>
    public static Tpm2bSignatureHint Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return EmptyInstance;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"Signature hint size {size} exceeds maximum {MaxSize} (TPM_RC_SIZE).");
        }

        if(size > reader.Remaining)
        {
            throw new ArgumentOutOfRangeException(nameof(reader), size, $"Signature hint size {size} exceeds the {reader.Remaining} octets remaining in the reader.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);

        //Copy hint bytes into owned storage.
        ReadOnlySpan<byte> sourceBytes = reader.ReadBytes(size);
        sourceBytes.CopyTo(storage.Memory.Span.Slice(0, size));

        return new Tpm2bSignatureHint(storage, size);
    }

    /// <summary>
    /// Creates a signature hint from the specified bytes.
    /// </summary>
    /// <param name="bytes">The hint bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created signature hint.</returns>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is longer than <see cref="MaxSize"/>.</exception>
    public static Tpm2bSignatureHint Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return EmptyInstance;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"Signature hint too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        bytes.CopyTo(storage.Memory.Span);

        return new Tpm2bSignatureHint(storage, bytes.Length);
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

    /// <summary>The debugger's one-line rendering: the hint's octet count, never the octets themselves.</summary>
    private string DebuggerDisplay => $"TPM2B_SIGNATURE_HINT({Size} bytes)";
}
