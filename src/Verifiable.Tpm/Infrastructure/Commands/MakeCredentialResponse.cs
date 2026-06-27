using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_MakeCredential command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Part 3, Section 12.6):
/// </para>
/// <list type="bullet">
///   <item><description>credentialBlob (TPM2B_ID_OBJECT): the integrity-protected, encrypted credential.</description></item>
///   <item><description>secret (TPM2B_ENCRYPTED_SECRET): the seed encrypted to the credential key's public area.</description></item>
/// </list>
/// <para>
/// Both outputs are opaque to the host and are passed unchanged into <c>TPM2_ActivateCredential</c>.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class MakeCredentialResponse: IDisposable, ITpmWireType
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the integrity-protected, encrypted credential blob.
    /// </summary>
    public Tpm2bIdObject CredentialBlob { get; }

    /// <summary>
    /// Gets the seed encrypted to the credential key's public area.
    /// </summary>
    public Tpm2bEncryptedSecret Secret { get; }

    private MakeCredentialResponse(Tpm2bIdObject credentialBlob, Tpm2bEncryptedSecret secret)
    {
        CredentialBlob = credentialBlob;
        Secret = secret;
    }

    /// <summary>
    /// Parses a TPM2_MakeCredential response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed response.</returns>
    public static MakeCredentialResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bIdObject credentialBlob = Tpm2bIdObject.Parse(ref reader, pool);
        Tpm2bEncryptedSecret secret = Tpm2bEncryptedSecret.Parse(ref reader, pool);

        return new MakeCredentialResponse(credentialBlob, secret);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            CredentialBlob.Dispose();
            Secret.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"MakeCredentialResponse(CredentialBlob={CredentialBlob.Length} bytes, Secret={Secret.Length} bytes)";
}
