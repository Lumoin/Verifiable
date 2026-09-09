using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_RSA_Decrypt command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Library Part 3, clause 14.3, Table 47): a single sized buffer.
/// </para>
/// <list type="bullet">
///   <item><description>message (TPM2B_PUBLIC_KEY_RSA): the decrypted output.</description></item>
/// </list>
/// <para>
/// As the first (and only) response parameter is a sized buffer, it is eligible for session-based parameter
/// encryption: when the command runs over an <c>encrypt</c> session the executor decrypts <c>message</c> only
/// after the response HMAC verifies, so the plaintext is never exposed unprotected on the wire.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class RsaDecryptResponse: ITpmWireType, IDisposable
{
    /// <summary>
    /// Whether <see cref="Dispose"/> has run.
    /// </summary>
    private bool disposed;

    /// <summary>
    /// Gets the decrypted output. Dispose this response to release it.
    /// </summary>
    public Tpm2bPublicKeyRsa Message { get; }

    /// <summary>
    /// Wraps an already-parsed <c>message</c>.
    /// </summary>
    /// <param name="message">The decrypted output.</param>
    private RsaDecryptResponse(Tpm2bPublicKeyRsa message)
    {
        Message = message;
    }

    /// <summary>
    /// Parses a TPM2_RSA_Decrypt response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed RSA_Decrypt response.</returns>
    public static RsaDecryptResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bPublicKeyRsa message = Tpm2bPublicKeyRsa.Parse(ref reader, pool);

        return new RsaDecryptResponse(message);
    }

    /// <summary>
    /// Releases <see cref="Message"/>, zeroing it first — the recovered plaintext is never left in a freed
    /// pooled buffer once the caller is done with this response (the clear-before-dispose discipline for
    /// <c>TPM2_RSA_Decrypt()</c>'s recovered plaintext).
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Message.Clear();
            Message.Dispose();
            disposed = true;
        }
    }

    /// <summary>
    /// The debugger's one-line rendering.
    /// </summary>
    private string DebuggerDisplay => $"RsaDecryptResponse(message={Message.Size} bytes)";
}
