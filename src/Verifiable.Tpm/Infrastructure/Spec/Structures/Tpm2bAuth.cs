using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

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
/// See TPM 2.0 Part 1, Section 17.6.4 - Authorization Values.
/// See TPM 2.0 Part 2, Section 10.4.4.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bAuth: SensitiveMemory, ITpmWireType
{
    /// <summary>
    /// Shared empty instance (EmptyAuth) backed by <see cref="EmptyMemoryOwner"/>.
    /// </summary>
    private static readonly Tpm2bAuth EmptyInstance = new(EmptyMemoryOwner.Instance);

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
    public static Tpm2bAuth Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort length = reader.ReadUInt16();

        if(length == 0)
        {
            return EmptyInstance;
        }

        IMemoryOwner<byte> storage = pool.Rent(length);

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
    /// Creates an empty auth value (EmptyAuth).
    /// </summary>
    /// <param name="pool">The memory pool (unused for empty auth values).</param>
    /// <returns>An empty auth value.</returns>
    public static Tpm2bAuth CreateEmpty(MemoryPool<byte> pool)
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
    public static Tpm2bAuth Create(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return EmptyInstance;
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
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
    /// Per spec Part 1, Section 17.6.4.3, trailing octets of zero are removed
    /// from any string before it is used as an authValue.
    /// </para>
    /// </remarks>
    public static Tpm2bAuth CreateFromPassword(string password, MemoryPool<byte> pool)
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

        IMemoryOwner<byte> storage = pool.Rent(length);
        passwordBytes.AsSpan(0, length).CopyTo(storage.Memory.Span);

        //Clear the temporary array.
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(passwordBytes);

        return new Tpm2bAuth(storage);
    }

    private string DebuggerDisplay => $"TPM2B_AUTH({Length} bytes)";
}