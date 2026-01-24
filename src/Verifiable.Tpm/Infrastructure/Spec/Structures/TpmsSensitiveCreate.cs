using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Sensitive data for object creation (TPMS_SENSITIVE_CREATE).
/// </summary>
/// <remarks>
/// <para>
/// Contains the authorization value and optional data for the object being created.
/// For keys, <c>data</c> is typically empty (the TPM generates the key).
/// For sealed data objects, <c>data</c> contains the data to seal.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM2B_AUTH userAuth;                     // Authorization value for the object.
///     TPM2B_SENSITIVE_DATA data;               // Optional data to seal.
/// } TPMS_SENSITIVE_CREATE;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.1.15, Table 168.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmsSensitiveCreate: IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the authorization value for the created object.
    /// </summary>
    /// <remarks>
    /// This becomes the authValue of the created object. Can be empty for objects
    /// that don't require password authorization.
    /// </remarks>
    public Tpm2bAuth UserAuth { get; }

    /// <summary>
    /// Gets the data to seal (for sealed data objects) or empty for keys.
    /// </summary>
    public Tpm2bSensitiveData Data { get; }

    /// <summary>
    /// Initializes sensitive creation data.
    /// </summary>
    /// <param name="userAuth">The authorization value.</param>
    /// <param name="data">The data to seal (empty for keys).</param>
    public TpmsSensitiveCreate(Tpm2bAuth userAuth, Tpm2bSensitiveData data)
    {
        UserAuth = userAuth;
        Data = data;
    }

    /// <summary>
    /// Creates empty sensitive creation data (no auth, no data).
    /// </summary>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>Empty sensitive creation data.</returns>
    public static TpmsSensitiveCreate CreateEmpty(MemoryPool<byte> pool)
    {
        return new TpmsSensitiveCreate(
            Tpm2bAuth.CreateEmpty(pool),
            Tpm2bSensitiveData.CreateEmpty());
    }

    /// <summary>
    /// Creates sensitive data with only an authorization value.
    /// </summary>
    /// <param name="userAuth">The authorization value.</param>
    /// <returns>Sensitive creation data with the specified auth.</returns>
    public static TpmsSensitiveCreate WithAuth(Tpm2bAuth userAuth)
    {
        return new TpmsSensitiveCreate(userAuth, Tpm2bSensitiveData.CreateEmpty());
    }

    /// <summary>
    /// Creates sensitive data with an authorization value from a password.
    /// </summary>
    /// <param name="password">The password string.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>Sensitive creation data with the specified auth.</returns>
    public static TpmsSensitiveCreate WithPassword(string password, MemoryPool<byte> pool)
    {
        return new TpmsSensitiveCreate(
            Tpm2bAuth.CreateFromPassword(password, pool),
            Tpm2bSensitiveData.CreateEmpty());
    }

    /// <summary>
    /// Gets the serialized size of the inner TPMS_SENSITIVE_CREATE.
    /// </summary>
    public int GetSerializedSize()
    {
        return UserAuth.GetSerializedSize() + Data.GetSerializedSize();
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        UserAuth.WriteTo(ref writer);
        Data.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses sensitive creation data from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed sensitive creation data.</returns>
    public static TpmsSensitiveCreate Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        var userAuth = Tpm2bAuth.Parse(ref reader, pool);
        var data = Tpm2bSensitiveData.Parse(ref reader, pool);

        return new TpmsSensitiveCreate(userAuth, data);
    }

    /// <summary>
    /// Releases resources owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            UserAuth.Dispose();
            Data.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPMS_SENSITIVE_CREATE(auth={UserAuth.Length}, data={Data.Length})";
}