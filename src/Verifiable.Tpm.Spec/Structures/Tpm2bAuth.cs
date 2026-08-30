using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// TPM2B_AUTH - a sized buffer for authorization values.
/// </summary>
/// <remarks>
/// <para>
/// This structure holds variable-length authorization data (such as passwords or HMACs)
/// prefixed with a 16-bit size field.
/// </para>
/// <para>
/// <strong>Wire format (big-endian):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-1: Size (uint16) - number of octets in buffer.</description></item>
///   <item><description>Bytes 2+: Buffer - the authorization data.</description></item>
/// </list>
/// <para>
/// <strong>Authorization values:</strong>
/// </para>
/// <para>
/// An authValue can be as small as zero octets but not larger than the digest size
/// of the algorithm used to compute the Name of the object. Trailing octets of zero
/// should be removed from any string before it is used as an authValue.
/// </para>
/// <para>
/// <strong>Empty auth (EmptyAuth):</strong> Use <see cref="CreateEmpty"/> to obtain a shared
/// empty instance backed by <see cref="EmptyMemoryOwner"/>. This avoids pool allocations
/// for zero-length buffers and represents the TPM "EmptyAuth" concept. The shared instance
/// is immune to disposal because <see cref="SensitiveMemory"/> recognizes
/// <see cref="EmptyMemoryOwner"/> and skips the dispose logic for singletons.
/// </para>
/// <para>
/// See TPM 2.0 Part 1, Section 16.6.4 - Authorization Values.
/// See TPM 2.0 Part 2, Section 10.3.5.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bAuth: SensitiveMemory, ITpmWireType
{
    /// <summary>
    /// The largest authorization value a <c>TPM2B_AUTH</c> buffer may carry: <c>sizeof(TPMU_HA)</c>, 64 octets.
    /// The type is defined as a <c>TPM2B_DIGEST</c> whose "size limited to the same as the digest structure"
    /// (TPM 2.0 Library Part 2, clause 10.3.5, Table 93, page 137), and that structure's own table bounds its
    /// buffer field at <c>buffer[size]{:sizeof(TPMU_HA)}</c> (clause 10.3.2, Table 90, page 136). The same
    /// clause states what a wider value answers with: "As with all sized buffers, the size is checked to see if
    /// it is within the prescribed range. If not, the response code is TPM_RC_SIZE".
    /// </summary>
    /// <remarks>
    /// This is the STRUCTURAL bound, not the per-entity one. Clause 10.3.5's own prose adds a second, narrower
    /// rule — "the authValue may be no larger than the size of the digest produced by the object's nameAlg" —
    /// which depends on the entity being authorized and so belongs to the command that installs the value,
    /// not to the carrier. Both layers apply: a value wider than 64 octets is not a well-formed
    /// <c>TPM2B_AUTH</c> at all, and a value within 64 octets may still be too wide for a particular object.
    /// </remarks>
    public const int MaxSize = 64;

    /// <summary>
    /// Shared empty instance (EmptyAuth) backed by <see cref="EmptyMemoryOwner"/>.
    /// </summary>
    private static Tpm2bAuth EmptyInstance { get; } = new(EmptyMemoryOwner.Instance);

    /// <summary>
    /// Initializes a new auth value with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the auth bytes.</param>
    public Tpm2bAuth(IMemoryOwner<byte> storage) : base(storage, TpmTags.Auth)
    {
    }

    /// <summary>
    /// Gets the length of the auth data in bytes.
    /// </summary>
    public int Length => MemoryOwner.Memory.Length;

    /// <summary>
    /// Gets a value indicating whether this auth value is empty.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Parses an auth value from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the auth value.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed auth value.</returns>
    /// <exception cref="InvalidOperationException">The declared size exceeds <see cref="MaxSize"/>, which a TPM answers with <c>TPM_RC_SIZE</c>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The declared size exceeds the octets remaining in <paramref name="reader"/>; checked before any storage is rented, so a truncated frame orphans nothing.</exception>
    public static Tpm2bAuth Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort length = reader.ReadUInt16();

        if(length == 0)
        {
            return EmptyInstance;
        }

        if(length > MaxSize)
        {
            throw new InvalidOperationException($"Auth size {length} exceeds maximum {MaxSize}.");
        }

        if(length > reader.Remaining)
        {
            throw new ArgumentOutOfRangeException(nameof(reader), (int)length, $"Auth size {length} exceeds the {reader.Remaining} octets remaining in the reader.");
        }

        IMemoryOwner<byte> storage = pool.Rent(length, AllocationKind.Pinned);

        //Copy auth bytes into owned storage.
        ReadOnlySpan<byte> sourceBytes = reader.ReadBytes(length);
        sourceBytes.CopyTo(storage.Memory.Span.Slice(0, length));

        return new Tpm2bAuth(storage);
    }

    /// <summary>
    /// Writes this auth value to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteTpm2b(AsReadOnlySpan());
    }

    /// <summary>
    /// Gets the serialized size (2-byte length prefix + data).
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Length;

    /// <summary>
    /// Gets the shared empty auth value (EmptyAuth), for contexts with no pool in scope — the
    /// same dispose-immune instance <see cref="CreateEmpty"/> returns, mirroring
    /// <see cref="Tpm2bSensitiveData.Empty"/>.
    /// </summary>
    public static Tpm2bAuth Empty => EmptyInstance;

    /// <summary>
    /// Creates an empty auth value (EmptyAuth).
    /// </summary>
    /// <param name="pool">The memory pool (unused for empty auth values).</param>
    /// <returns>An empty auth value.</returns>
    public static Tpm2bAuth CreateEmpty(BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        return EmptyInstance;
    }

    /// <summary>
    /// Creates an auth value from the specified bytes.
    /// </summary>
    /// <param name="bytes">The auth bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created auth value.</returns>
    /// <remarks>
    /// <para>
    /// The bytes are copied verbatim, with no trailing-zero trimming. This is the path for
    /// interactive PIN material and any binary authorization value: the caller marshals the secret
    /// into a buffer it controls and clears, and the exact bytes become the authValue. Prefer this
    /// over <see cref="CreateFromPassword"/> whenever the secret must remain zeroable, because a
    /// <see cref="string"/> source cannot be cleared once created.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is longer than <see cref="MaxSize"/>.</exception>
    public static Tpm2bAuth Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return EmptyInstance;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"Auth value too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length, AllocationKind.Pinned);
        bytes.CopyTo(storage.Memory.Span);
        return new Tpm2bAuth(storage);
    }

    /// <summary>
    /// Creates an auth value from a password string.
    /// </summary>
    /// <param name="password">The password string.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created auth value.</returns>
    /// <remarks>
    /// <para>
    /// Per spec Part 1, Section 16.6.4.3, trailing octets of zero are removed
    /// from any string before it is used as an authValue.
    /// </para>
    /// <para>
    /// This overload is intended for configuration passwords, not for interactive PINs. The
    /// temporary UTF-8 buffer is zeroed, but the source <paramref name="password"/> is an immutable
    /// managed string that cannot be cleared and lingers on the heap until garbage collected.
    /// Trailing-zero trimming also means a value ending in <c>0x00</c> would not round-trip. For PIN
    /// material, marshal the entry into a pooled buffer and use
    /// <see cref="Create(ReadOnlySpan{byte}, BaseMemoryPool)"/> instead.
    /// </para>
    /// <para>
    /// The structural bound applies here too, measured after the trailing-zero trim: a password whose UTF-8
    /// encoding is longer than <see cref="MaxSize"/> octets cannot be a <c>TPM2B_AUTH</c> and is refused rather
    /// than truncated. A TPM refuses the same value on the wire, so shortening it here would produce an
    /// authValue no TPM would ever hold. A caller with a longer secret applies the hash-if-too-long convention
    /// itself (TPM 2.0 Library Part 1, clause 16.6.4.3: "The TPM does not enforce this transformation").
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">The trimmed UTF-8 encoding of <paramref name="password"/> is longer than <see cref="MaxSize"/>.</exception>
    public static Tpm2bAuth CreateFromPassword(string password, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(password);
        if(string.IsNullOrEmpty(password))
        {
            return EmptyInstance;
        }

        //Convert to UTF-8 and trim trailing zeros.
        byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
        int length = passwordBytes.Length;
        while(length > 0 && passwordBytes[length - 1] == 0)
        {
            length--;
        }

        if(length == 0)
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(passwordBytes);
            return EmptyInstance;
        }

        if(length > MaxSize)
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(passwordBytes);

            throw new ArgumentException($"Auth value too large. Maximum is {MaxSize} bytes.", nameof(password));
        }

        IMemoryOwner<byte> storage = pool.Rent(length, AllocationKind.Pinned);
        passwordBytes.AsSpan(0, length).CopyTo(storage.Memory.Span);

        //Clear the temporary array.
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(passwordBytes);

        return new Tpm2bAuth(storage);
    }

    private string DebuggerDisplay => $"TPM2B_AUTH({Length} bytes)";
}
