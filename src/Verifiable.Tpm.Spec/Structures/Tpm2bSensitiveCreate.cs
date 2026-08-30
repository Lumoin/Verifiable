using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Sized buffer containing sensitive creation data (TPM2B_SENSITIVE_CREATE).
/// </summary>
/// <remarks>
/// <para>
/// This is a TPM2B wrapper around <see cref="TpmsSensitiveCreate"/>. The size
/// field indicates the total size of the contained TPMS_SENSITIVE_CREATE.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of sensitive in bytes.
///     TPMS_SENSITIVE_CREATE sensitive;         // The sensitive data.
/// } TPM2B_SENSITIVE_CREATE;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.1.16, Table 172.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bSensitiveCreate: IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the sensitive creation data.
    /// </summary>
    public TpmsSensitiveCreate Sensitive { get; }

    /// <summary>
    /// Initializes a new sized sensitive creation buffer.
    /// </summary>
    /// <param name="sensitive">The sensitive data.</param>
    public Tpm2bSensitiveCreate(TpmsSensitiveCreate sensitive)
    {
        Sensitive = sensitive;
    }

    /// <summary>
    /// Creates an empty sensitive creation buffer.
    /// </summary>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>Empty sensitive creation buffer.</returns>
    public static Tpm2bSensitiveCreate CreateEmpty(BaseMemoryPool pool)
    {
        return new Tpm2bSensitiveCreate(TpmsSensitiveCreate.CreateEmpty(pool));
    }

    /// <summary>
    /// Creates a sensitive creation buffer with a password.
    /// </summary>
    /// <param name="password">The password string.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>Sensitive creation buffer with the specified auth.</returns>
    public static Tpm2bSensitiveCreate WithPassword(string password, BaseMemoryPool pool)
    {
        return new Tpm2bSensitiveCreate(TpmsSensitiveCreate.WithPassword(password, pool));
    }

    /// <summary>
    /// Creates a sensitive creation buffer for sealing the supplied secret: an empty authValue and the secret
    /// as the sensitive data. The secret is copied into pooled storage that the returned instance owns and
    /// clears on disposal.
    /// </summary>
    /// <param name="secret">The data to seal.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>Sensitive creation buffer carrying the data to seal.</returns>
    public static Tpm2bSensitiveCreate ForSealedData(ReadOnlySpan<byte> secret, BaseMemoryPool pool)
    {
        return new Tpm2bSensitiveCreate(
            new TpmsSensitiveCreate(Tpm2bAuth.CreateEmpty(pool), Tpm2bSensitiveData.Create(secret, pool)));
    }

    /// <summary>
    /// Creates a sensitive creation buffer for sealing the supplied secret under a real authorization value: the
    /// new object's <c>userAuth</c> plus the secret as the sensitive data (TPM 2.0 Library Part 2, Section 11.1.15).
    /// Both are copied into pooled storage that the returned instance owns and clears on disposal.
    /// </summary>
    /// <param name="secret">The data to seal.</param>
    /// <param name="userAuth">The authorization value the created object's <c>userAuth</c> is set to.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>Sensitive creation buffer carrying the authorization value and the data to seal.</returns>
    /// <exception cref="ArgumentException"><paramref name="secret"/> is wider than <see cref="Tpm2bSensitiveData.MaxSize"/> or <paramref name="userAuth"/> wider than <see cref="Tpm2bAuth.MaxSize"/>; nothing stays rented.</exception>
    public static Tpm2bSensitiveCreate ForSealedData(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> userAuth, BaseMemoryPool pool)
    {
        Tpm2bAuth auth = Tpm2bAuth.Create(userAuth, pool);
        try
        {
            return new Tpm2bSensitiveCreate(new TpmsSensitiveCreate(auth, Tpm2bSensitiveData.Create(secret, pool)));
        }
        catch
        {
            //The authorization carrier is already rented when the data refusal throws; release it.
            auth.Dispose();

            throw;
        }
    }

    /// <summary>
    /// Creates a sensitive creation buffer for an HMAC key: the new object's <c>userAuth</c> plus the caller's
    /// key octets as the sensitive data (TPM 2.0 Library Part 2, Section 11.1.15). This is the identical
    /// TPMS_SENSITIVE_CREATE shape <see cref="ForSealedData(ReadOnlySpan{byte}, ReadOnlySpan{byte}, BaseMemoryPool)"/>
    /// builds for a sealed data object — both a sealed secret and an HMAC key are TPM_ALG_KEYEDHASH sensitive
    /// data, distinguished only by the public area's scheme (<see cref="TpmsKeyedHashParms.Hmac"/> versus
    /// <see cref="TpmsKeyedHashParms.SealedData"/>). Both are copied into pooled storage the returned instance
    /// owns and clears on disposal.
    /// </summary>
    /// <param name="key">The HMAC key octets, or empty to let the TPM generate the key (then the public area's TPMA_OBJECT.sensitiveDataOrigin must be SET).</param>
    /// <param name="userAuth">The authorization value the created object's <c>userAuth</c> is set to.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>Sensitive creation buffer carrying the authorization value and the HMAC key.</returns>
    public static Tpm2bSensitiveCreate ForHmacKey(ReadOnlySpan<byte> key, ReadOnlySpan<byte> userAuth, BaseMemoryPool pool)
    {
        return ForSealedData(key, userAuth, pool);
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Sensitive.SerializedSize;
    

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        int innerSize = Sensitive.SerializedSize;
        writer.WriteUInt16((ushort)innerSize);
        Sensitive.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a sized sensitive creation buffer from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed sensitive creation buffer.</returns>
    public static Tpm2bSensitiveCreate Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return CreateEmpty(pool);
        }

        var sensitive = TpmsSensitiveCreate.Parse(ref reader, pool);
        return new Tpm2bSensitiveCreate(sensitive);
    }

    /// <summary>
    /// Releases resources owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Sensitive.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPM2B_SENSITIVE_CREATE({Sensitive})";
}
