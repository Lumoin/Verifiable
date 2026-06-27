using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_MakeCredential command (CC = 0x00000168).
/// </summary>
/// <remarks>
/// <para>
/// Wraps a credential secret so that only a TPM holding the private key referenced by <see cref="Handle"/> (the
/// credential/endorsement key) and loaded with the object whose Name is <see cref="ObjectName"/> (the
/// attestation key) can recover it via <c>TPM2_ActivateCredential</c>. The command uses only the public area of
/// <see cref="Handle"/>, so it requires no authorization and is the operation a privacy CA runs (off-TPM with
/// just the EK public key, or on a TPM as here) to challenge an attestation key's binding to an endorsement key.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 12.6):
/// </para>
/// <list type="bullet">
///   <item><description>handle (TPMI_DH_OBJECT): The credential key (its public area encrypts the seed). No authorization.</description></item>
///   <item><description>credential (TPM2B_DIGEST): The secret to wrap.</description></item>
///   <item><description>objectName (TPM2B_NAME): The Name of the object the credential is bound to (the attestation key).</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class MakeCredentialInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    private Tpm2bDigest Credential { get; }

    private Tpm2bName ObjectNameValue { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_MakeCredential;

    /// <summary>
    /// Gets the handle of the credential key whose public area protects the seed.
    /// </summary>
    public TpmiDhObject Handle { get; }

    /// <summary>
    /// Gets the Name of the object the credential is bound to.
    /// </summary>
    public ReadOnlySpan<byte> ObjectName => ObjectNameValue.Span;

    private MakeCredentialInput(TpmiDhObject handle, Tpm2bDigest credential, Tpm2bName objectName)
    {
        Handle = handle;
        Credential = credential;
        ObjectNameValue = objectName;
    }

    /// <summary>
    /// Creates a TPM2_MakeCredential input.
    /// </summary>
    /// <param name="handle">The credential key handle (its public area encrypts the seed).</param>
    /// <param name="credential">The secret to wrap.</param>
    /// <param name="objectName">The Name of the object the credential is bound to (the attestation key's Name).</param>
    /// <param name="pool">The memory pool for buffer allocation.</param>
    /// <returns>A new <see cref="MakeCredentialInput"/>.</returns>
    public static MakeCredentialInput Create(
        TpmiDhObject handle,
        ReadOnlySpan<byte> credential,
        ReadOnlySpan<byte> objectName,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bDigest credentialBuffer = Tpm2bDigest.Create(credential, pool);
        Tpm2bName objectNameBuffer = Tpm2bName.Create(objectName, pool);

        return new MakeCredentialInput(handle, credentialBuffer, objectNameBuffer);
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +                       //handle (TPMI_DH_OBJECT)
               Credential.SerializedSize +          //credential (TPM2B_DIGEST)
               ObjectNameValue.SerializedSize;      //objectName (TPM2B_NAME)
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        Handle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        Credential.WriteTo(ref writer);
        ObjectNameValue.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            Credential.Dispose();
            ObjectNameValue.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"MakeCredentialInput(Key={Handle}, Credential={Credential.Size} bytes, ObjectName={ObjectNameValue.Size} bytes)";
}
