using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_Decapsulate command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Library Part 3, clause 14.11, Table 63): a single TPM2B_SHARED_SECRET, the
/// same value the KEM key's TPM2_Encapsulate() counterpart produced from the ciphertext this command
/// decapsulates.
/// </para>
/// <list type="bullet">
///   <item><description>sharedSecret (TPM2B_SHARED_SECRET): the recovered shared secret.</description></item>
/// </list>
/// <para>
/// <see cref="SharedSecret"/> is the first (and only) response parameter and carries an explicit size
/// field, so it is eligible for session-based parameter encryption on a real TPM (TPM 2.0 Library Part 1,
/// clause 18.1) — the same encrypt-session mechanism <see cref="EncapsulateResponse.SharedSecret"/>
/// documents for its own copy of this value.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class DecapsulateResponse: IDisposable, ITpmWireType
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the recovered shared secret.
    /// </summary>
    public Tpm2bSharedSecret SharedSecret { get; }

    private DecapsulateResponse(Tpm2bSharedSecret sharedSecret)
    {
        SharedSecret = sharedSecret;
    }

    /// <summary>
    /// Parses a TPM2_Decapsulate response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed response.</returns>
    public static DecapsulateResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bSharedSecret sharedSecret = Tpm2bSharedSecret.Parse(ref reader, pool);

        return new DecapsulateResponse(sharedSecret);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            SharedSecret.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger's one-line rendering: the shared secret's octet count, never the octets themselves.</summary>
    private string DebuggerDisplay => $"DecapsulateResponse(SharedSecret={SharedSecret.Size} bytes)";
}
