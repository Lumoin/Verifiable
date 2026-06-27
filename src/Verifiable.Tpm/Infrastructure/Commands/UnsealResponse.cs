using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_Unseal command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Part 3, Section 12.7): a single sized buffer.
/// </para>
/// <list type="bullet">
///   <item><description>outData (TPM2B_SENSITIVE_DATA): the recovered sealed data.</description></item>
/// </list>
/// <para>
/// As the first (and only) response parameter is a sized buffer, it is eligible for session-based parameter
/// encryption: when the command runs over an <c>encrypt</c> session the executor decrypts <c>outData</c> only
/// after the response HMAC verifies, so the recovered secret is never exposed in cleartext on the wire.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class UnsealResponse: ITpmWireType, IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the recovered sealed data. Dispose this response to clear and release it.
    /// </summary>
    public Tpm2bSensitiveData OutData { get; }

    private UnsealResponse(Tpm2bSensitiveData outData)
    {
        OutData = outData;
    }

    /// <summary>
    /// Parses a TPM2_Unseal response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed unseal response.</returns>
    public static UnsealResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bSensitiveData outData = Tpm2bSensitiveData.Parse(ref reader, pool);

        return new UnsealResponse(outData);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            OutData.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"UnsealResponse(outData={OutData.Length} bytes)";
}
