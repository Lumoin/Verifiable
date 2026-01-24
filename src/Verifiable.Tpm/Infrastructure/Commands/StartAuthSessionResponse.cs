using System;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_StartAuthSession.
/// </summary>
/// <remarks>
/// <para>
/// This type represents the complete response for the TPM2_StartAuthSession command,
/// including both the response handle and response parameters.
/// </para>
/// <para>
/// <b>Response handle (Part 3, Section 11.1):</b>
/// </para>
/// <list type="bullet">
///   <item><description>sessionHandle (TPMI_SH_AUTH_SESSION) - handle for the newly created session.</description></item>
/// </list>
/// <para>
/// <b>Response parameters:</b>
/// </para>
/// <list type="bullet">
///   <item><description>nonceTPM (TPM2B_NONCE) - the initial nonce from the TPM.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class StartAuthSessionResponse: ITpmWireType, IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the handle for the created session.
    /// </summary>
    /// <remarks>
    /// This handle references the newly created authorization session.
    /// It must be used in subsequent commands that require this session,
    /// and should be flushed via TPM2_FlushContext when no longer needed.
    /// </remarks>
    public TpmiShAuthSession SessionHandle { get; }

    /// <summary>
    /// Gets the TPM's initial nonce for the session.
    /// </summary>
    /// <remarks>
    /// This nonce is used in session key derivation and HMAC computation.
    /// It should be transferred to the session object for ongoing use.
    /// </remarks>
    public Tpm2bNonce NonceTPM { get; }

    private StartAuthSessionResponse(TpmiShAuthSession sessionHandle, Tpm2bNonce nonceTPM)
    {
        SessionHandle = sessionHandle;
        NonceTPM = nonceTPM;
    }

    /// <summary>
    /// Parses the response from handle and parameter data.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="sessionHandle">The session handle from the response handle area.</param>
    /// <param name="pool">The memory pool for allocations.</param>
    /// <returns>The parsed response.</returns>
    public static StartAuthSessionResponse Parse(ref TpmReader reader, TpmiShAuthSession sessionHandle, MemoryPool<byte> pool)
    {
        Tpm2bNonce nonceTPM = Tpm2bNonce.Parse(ref reader, pool);
        return new StartAuthSessionResponse(sessionHandle, nonceTPM);
    }

    /// <summary>
    /// Releases resources owned by this response.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            NonceTPM.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"StartAuthSessionResponse(Handle=0x{SessionHandle.Value:X8}, NonceTPM={NonceTPM.Size} bytes)";
}