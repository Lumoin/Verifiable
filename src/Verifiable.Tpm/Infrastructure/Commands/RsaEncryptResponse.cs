using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_RSA_Encrypt command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Library Part 3, clause 14.2, Table 45): a single sized buffer.
/// </para>
/// <list type="bullet">
///   <item><description>outData (TPM2B_PUBLIC_KEY_RSA): the encrypted output.</description></item>
/// </list>
/// <para>
/// As the first (and only) response parameter is a sized buffer, it is eligible for session-based parameter
/// encryption: when the command runs over an <c>encrypt</c> session the executor decrypts <c>outData</c> only
/// after the response HMAC verifies, so the ciphertext is never exposed unprotected on the wire.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class RsaEncryptResponse: ITpmWireType, IDisposable
{
    /// <summary>
    /// Whether <see cref="Dispose"/> has run.
    /// </summary>
    private bool disposed;

    /// <summary>
    /// Gets the encrypted output. Dispose this response to release it.
    /// </summary>
    public Tpm2bPublicKeyRsa OutData { get; }

    /// <summary>
    /// Wraps an already-parsed <c>outData</c>.
    /// </summary>
    /// <param name="outData">The encrypted output.</param>
    private RsaEncryptResponse(Tpm2bPublicKeyRsa outData)
    {
        OutData = outData;
    }

    /// <summary>
    /// Parses a TPM2_RSA_Encrypt response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed RSA_Encrypt response.</returns>
    public static RsaEncryptResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bPublicKeyRsa outData = Tpm2bPublicKeyRsa.Parse(ref reader, pool);

        return new RsaEncryptResponse(outData);
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

    /// <summary>
    /// The debugger's one-line rendering.
    /// </summary>
    private string DebuggerDisplay => $"RsaEncryptResponse(outData={OutData.Size} bytes)";
}
