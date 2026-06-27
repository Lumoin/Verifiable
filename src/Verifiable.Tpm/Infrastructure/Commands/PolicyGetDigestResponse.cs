using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_PolicyGetDigest command.
/// </summary>
/// <remarks>
/// <para>
/// Response parameters (TPM 2.0 Part 3, Section 23.6):
/// </para>
/// <list type="bullet">
///   <item><description>policyDigest (TPM2B_DIGEST): The current policy digest of the session.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicyGetDigestResponse: IDisposable, ITpmWireType
{
    private bool disposed;

    /// <summary>
    /// Gets the current policy digest of the session.
    /// </summary>
    public Tpm2bDigest PolicyDigest { get; }

    private PolicyGetDigestResponse(Tpm2bDigest policyDigest)
    {
        PolicyDigest = policyDigest;
    }

    /// <summary>
    /// Parses a TPM2_PolicyGetDigest response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for buffer allocation.</param>
    /// <returns>The parsed response.</returns>
    public static PolicyGetDigestResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bDigest policyDigest = Tpm2bDigest.Parse(ref reader, pool);

        return new PolicyGetDigestResponse(policyDigest);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            PolicyDigest.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"PolicyGetDigestResponse(PolicyDigest={PolicyDigest.Size} bytes)";
}
