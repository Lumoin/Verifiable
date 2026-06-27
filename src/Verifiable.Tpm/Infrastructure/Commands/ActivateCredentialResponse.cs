using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_ActivateCredential command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Part 3, Section 12.5): a single TPM2B_DIGEST <c>certInfo</c> — the recovered
/// credential secret. Recovering it proves the activate object and the credential key co-reside in one TPM;
/// returning it to the challenger completes attestation-key enrollment. It is confidential, so the codec marks
/// it eligible for session-based parameter encryption.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ActivateCredentialResponse: IDisposable, ITpmWireType
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the recovered credential secret.
    /// </summary>
    public Tpm2bDigest CertInfo { get; }

    private ActivateCredentialResponse(Tpm2bDigest certInfo)
    {
        CertInfo = certInfo;
    }

    /// <summary>
    /// Parses a TPM2_ActivateCredential response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed response.</returns>
    public static ActivateCredentialResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bDigest certInfo = Tpm2bDigest.Parse(ref reader, pool);

        return new ActivateCredentialResponse(certInfo);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            CertInfo.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"ActivateCredentialResponse(CertInfo={CertInfo.Size} bytes)";
}
