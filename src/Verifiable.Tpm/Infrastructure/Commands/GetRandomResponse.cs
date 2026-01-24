using System;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response parameters for TPM2_GetRandom.
/// </summary>
/// <remarks>
/// <para>
/// This type represents the complete response parameter area for the
/// TPM2_GetRandom command.
/// </para>
/// <para>
/// <b>Response parameters (Part 3, Section 16.1):</b>
/// </para>
/// <list type="bullet">
///   <item><description>randomBytes (TPM2B_DIGEST) - the random octets.</description></item>
/// </list>
/// <para>
/// <b>Note:</b> This is a library convenience type that bundles the response
/// parameters. For single-parameter responses, this provides consistency with
/// multi-parameter commands and enables future extension.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class GetRandomResponse: ITpmWireType, IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the random bytes returned by the TPM.
    /// </summary>
    public Tpm2bDigest RandomBytes { get; }

    private GetRandomResponse(Tpm2bDigest randomBytes)
    {
        RandomBytes = randomBytes;
    }

    /// <summary>
    /// Parses the response parameters from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for allocations.</param>
    /// <returns>The parsed response.</returns>
    public static GetRandomResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        Tpm2bDigest randomBytes = Tpm2bDigest.Parse(ref reader, pool);
        return new GetRandomResponse(randomBytes);
    }

    /// <summary>
    /// Releases resources owned by this response.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            RandomBytes.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"GetRandomResponse({RandomBytes.Size} bytes)";
}