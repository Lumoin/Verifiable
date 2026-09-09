using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// RSA public key buffer (TPM2B_PUBLIC_KEY_RSA).
/// </summary>
/// <remarks>
/// <para>
/// Carries the modulus (n) of an RSA public key in the <c>unique</c> member of an RSA
/// <c>TPMT_PUBLIC</c>, and the signature octets of an RSA <c>TPMS_SIGNATURE_RSA</c> — Part 2 gives both the
/// same buffer type. Table 194 bounds it by <c>MAX_RSA_KEY_BYTES</c>, the octet width of the largest RSA key
/// the TPM supports, which this library takes as 4096 bits.
/// </para>
/// <para>
/// The content is public key material, so this carrier holds no
/// <see cref="Verifiable.Cryptography.SensitiveMemory"/> tag; it follows the hand-rolled pooled shape of
/// <see cref="Tpm2bName"/> and <see cref="Tpm2bOperand"/>. Instance identity is ownership identity: two
/// carriers are the same carrier only when they are the same instance, so a record holding one compares it by
/// reference and never reads a possibly-released buffer's content.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                              // Size of the buffer in bytes.
///     BYTE buffer[MAX_RSA_KEY_BYTES];           // The RSA modulus.
/// } TPM2B_PUBLIC_KEY_RSA;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 11.2.4.6, Table 194.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bPublicKeyRsa: IDisposable, ITpmWireType
{
    /// <summary>
    /// Maximum RSA key size in bytes (4096 bits) — Table 194's <c>MAX_RSA_KEY_BYTES</c>.
    /// </summary>
    public const int MaxRsaKeyBytes = 512;

    /// <summary>
    /// The shared zero-length instance backing every empty buffer.
    /// </summary>
    private static Tpm2bPublicKeyRsa EmptyInstance { get; } = new(null, 0);

    /// <summary>
    /// The pooled storage, or <see langword="null"/> for <see cref="Empty"/>.
    /// </summary>
    private IMemoryOwner<byte>? Storage { get; }

    /// <summary>
    /// Whether <see cref="Dispose"/> has already released <see cref="Storage"/>.
    /// </summary>
    private bool disposed;

    /// <summary>
    /// Initializes a new RSA public key buffer over pooled storage, or the empty sentinel when there is none.
    /// </summary>
    /// <param name="storage">The memory owner holding the key octets, or <see langword="null"/> for the empty form.</param>
    /// <param name="size">The number of valid octets at the head of <paramref name="storage"/>.</param>
    private Tpm2bPublicKeyRsa(IMemoryOwner<byte>? storage, int size)
    {
        this.Storage = storage;
        Size = size;
    }

    /// <summary>
    /// Gets the shared empty RSA public key buffer. It owns no pooled storage, so its disposal is a no-op.
    /// </summary>
    public static Tpm2bPublicKeyRsa Empty => EmptyInstance;

    /// <summary>
    /// Gets the size of the public key in bytes.
    /// </summary>
    public int Size { get; }

    /// <summary>
    /// Gets whether this buffer is empty.
    /// </summary>
    public bool IsEmpty => Size == 0;

    /// <summary>
    /// Gets the public key data (RSA modulus) as a read-only span.
    /// </summary>
    public ReadOnlySpan<byte> Buffer
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            if(Storage is null)
            {
                return ReadOnlySpan<byte>.Empty;
            }

            return Storage.Memory.Span.Slice(0, Size);
        }
    }

    /// <summary>
    /// Gets the key octets as read-only memory that aliases this instance's pooled storage — for a borrowing
    /// consumer such as the asynchronous cryptographic seams, valid until <see cref="Dispose"/> and never
    /// copied into an untracked array.
    /// </summary>
    /// <returns>The key octets.</returns>
    public ReadOnlyMemory<byte> AsReadOnlyMemory()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(Storage is null)
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        return Storage.Memory.Slice(0, Size);
    }

    /// <summary>
    /// Gets the serialized size in bytes.
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Size;

    /// <summary>
    /// Writes this structure to a writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt16((ushort)Size);

        if(Size > 0)
        {
            writer.WriteBytes(Buffer);
        }
    }

    /// <summary>
    /// Parses an RSA public key from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>The parsed RSA public key.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">The declared size exceeds <see cref="MaxRsaKeyBytes"/> (<c>TPM_RC_SIZE</c>).</exception>
    public static Tpm2bPublicKeyRsa Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty;
        }

        if(size > MaxRsaKeyBytes)
        {
            throw new InvalidOperationException($"RSA public key size {size} exceeds maximum {MaxRsaKeyBytes}.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);
        try
        {
            reader.ReadBytes(size).CopyTo(storage.Memory.Span);

            return new Tpm2bPublicKeyRsa(storage, size);
        }
        catch
        {
            //A truncated frame must not orphan the rental the declared size already asked for.
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Creates an RSA public key buffer from the given octets.
    /// </summary>
    /// <param name="modulus">The RSA modulus (or RSA signature octets), big-endian.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>The RSA public key buffer; the caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="modulus"/> is longer than <see cref="MaxRsaKeyBytes"/>.</exception>
    public static Tpm2bPublicKeyRsa Create(ReadOnlySpan<byte> modulus, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(modulus.Length > MaxRsaKeyBytes)
        {
            throw new ArgumentException($"RSA modulus size {modulus.Length} exceeds maximum {MaxRsaKeyBytes}.", nameof(modulus));
        }

        if(modulus.IsEmpty)
        {
            return Empty;
        }

        IMemoryOwner<byte> storage = pool.Rent(modulus.Length);
        try
        {
            modulus.CopyTo(storage.Memory.Span);

            return new Tpm2bPublicKeyRsa(storage, modulus.Length);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Adopts an already-filled pooled buffer as this structure's storage: ownership of
    /// <paramref name="storage"/> transfers to the returned instance, with no second rental and no copy — the
    /// zero-copy counterpart of <see cref="Create(ReadOnlySpan{byte}, BaseMemoryPool)"/> for a backend delegate
    /// that rented the octets and wrote the RSAES/OAEP/raw result into them itself (the RSA_Encrypt/RSA_Decrypt
    /// effects wrap <c>outData</c>/<c>message</c> this way, mirroring how the shipped OAEP transports already
    /// wrap their own backend results, for example <c>Tpm2bEncryptedSecret.FromMarshaled</c>).
    /// </summary>
    /// <remarks>
    /// A <paramref name="size"/> of zero yields the shared <see cref="Empty"/> singleton and releases
    /// <paramref name="storage"/> here, since the singleton rents nothing and its <see cref="Dispose"/> is a
    /// no-op. An argument that does not describe a valid buffer likewise releases <paramref name="storage"/>
    /// before the exception leaves, so a rejected adoption never orphans the rental.
    /// </remarks>
    /// <param name="storage">The pooled buffer whose leading octets hold the value; ownership transfers to the returned instance or is released here.</param>
    /// <param name="size">The number of valid octets at the head of <paramref name="storage"/>.</param>
    /// <returns>The adopted value.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="storage"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="size"/> is negative, exceeds <paramref name="storage"/>'s length, or exceeds <see cref="MaxRsaKeyBytes"/>.</exception>
    public static Tpm2bPublicKeyRsa FromMarshaled(IMemoryOwner<byte> storage, int size)
    {
        ArgumentNullException.ThrowIfNull(storage);

        try
        {
            ArgumentOutOfRangeException.ThrowIfNegative(size);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(size, storage.Memory.Length);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(size, MaxRsaKeyBytes);
        }
        catch
        {
            storage.Dispose();
            throw;
        }

        if(size == 0)
        {
            storage.Dispose();

            return Empty;
        }

        return new Tpm2bPublicKeyRsa(storage, size);
    }

    /// <summary>
    /// Zeroes the buffer octets in place ahead of disposal. The content is ordinarily public key material (see
    /// the type remarks), but the same wire structure also carries a recovered plaintext as
    /// <c>TPM2_RSA_Decrypt()</c>'s <c>message</c> response (TPM 2.0 Library Part 3, clause 14.3, Table 47) and
    /// a plaintext being wrapped as <c>TPM2_RSA_Encrypt()</c>'s <c>message</c> parameter (clause 14.2, Table 44)
    /// — the terminal owner of either clears it here before releasing the rental, rather than leaving the
    /// plaintext octets in a freed pooled buffer. The zeroing covers the whole rental rather than the valid
    /// prefix, so an adoption through <see cref="FromMarshaled"/> of a rental wider than <see cref="Size"/>
    /// leaves nothing behind either. A no-op for <see cref="Empty"/>, which owns no storage.
    /// </summary>
    /// <exception cref="ObjectDisposedException">This instance has already been disposed.</exception>
    public void Clear()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(Storage is not null)
        {
            Storage.Memory.Span.Clear();
        }
    }

    /// <summary>
    /// Releases the memory owned by this structure. The shared <see cref="Empty"/> buffer is exempt: it owns no
    /// pooled storage and every consumer holds the same instance, so disposing one of them leaves it readable
    /// and framable for all the others.
    /// </summary>
    public void Dispose()
    {
        if(!disposed && this != EmptyInstance)
        {
            Storage?.Dispose();
            disposed = true;
        }
    }

    /// <summary>
    /// The debugger's one-line rendering: the octet count only, never the octets themselves.
    /// </summary>
    private string DebuggerDisplay => $"TPM2B_PUBLIC_KEY_RSA({Size} bytes)";
}
