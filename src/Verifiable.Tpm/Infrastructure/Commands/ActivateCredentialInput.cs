using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_ActivateCredential command (CC = 0x00000147).
/// </summary>
/// <remarks>
/// <para>
/// Recovers a credential wrapped by <c>TPM2_MakeCredential</c>, proving that the attestation key referenced by
/// <see cref="ActivateHandle"/> and the credential/endorsement key referenced by <see cref="KeyHandle"/> are
/// loaded in the same TPM: the key key decrypts the seed and the TPM checks the credential is bound to the
/// activate object's Name. Returning the recovered secret to the challenger completes the attestation-key
/// enrollment.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 12.5):
/// </para>
/// <list type="bullet">
///   <item><description>activateHandle (TPMI_DH_OBJECT): The object the credential is bound to (the attestation key). Requires ADMIN-role authorization.</description></item>
///   <item><description>keyHandle (TPMI_DH_OBJECT): The credential key that decrypts the seed (the endorsement key). Requires authorization.</description></item>
///   <item><description>credentialBlob (TPM2B_ID_OBJECT): The credential from TPM2_MakeCredential.</description></item>
///   <item><description>secret (TPM2B_ENCRYPTED_SECRET): The encrypted seed from TPM2_MakeCredential.</description></item>
/// </list>
/// <para>
/// Both handles require authorization, so the executor is given two authorization sessions in handle order: the
/// activate object's first, the key key's second.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ActivateCredentialInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    private Tpm2bIdObject CredentialBlob { get; }

    private Tpm2bEncryptedSecret SecretValue { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_ActivateCredential;

    /// <summary>
    /// Gets the handle of the object the credential is bound to (the attestation key).
    /// </summary>
    public TpmiDhObject ActivateHandle { get; }

    /// <summary>
    /// Gets the handle of the credential key that decrypts the seed (the endorsement key).
    /// </summary>
    public TpmiDhObject KeyHandle { get; }

    private ActivateCredentialInput(
        TpmiDhObject activateHandle, TpmiDhObject keyHandle, Tpm2bIdObject credentialBlob, Tpm2bEncryptedSecret secret)
    {
        ActivateHandle = activateHandle;
        KeyHandle = keyHandle;
        CredentialBlob = credentialBlob;
        SecretValue = secret;
    }

    /// <summary>
    /// Creates a TPM2_ActivateCredential input from the outputs of TPM2_MakeCredential.
    /// </summary>
    /// <param name="activateHandle">The object the credential is bound to (the attestation key).</param>
    /// <param name="keyHandle">The credential key that decrypts the seed (the endorsement key).</param>
    /// <param name="credentialBlob">The credential blob from TPM2_MakeCredential.</param>
    /// <param name="secret">The encrypted seed from TPM2_MakeCredential.</param>
    /// <param name="pool">The memory pool for buffer allocation.</param>
    /// <returns>A new <see cref="ActivateCredentialInput"/>.</returns>
    public static ActivateCredentialInput Create(
        TpmiDhObject activateHandle,
        TpmiDhObject keyHandle,
        ReadOnlySpan<byte> credentialBlob,
        ReadOnlySpan<byte> secret,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bIdObject credentialBuffer = Tpm2bIdObject.Create(credentialBlob, pool);
        Tpm2bEncryptedSecret secretBuffer = Tpm2bEncryptedSecret.Create(secret, pool);

        return new ActivateCredentialInput(activateHandle, keyHandle, credentialBuffer, secretBuffer);
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return (2 * sizeof(uint)) +                 //activateHandle + keyHandle (TPMI_DH_OBJECT)
               CredentialBlob.SerializedSize +      //credentialBlob (TPM2B_ID_OBJECT)
               SecretValue.SerializedSize;          //secret (TPM2B_ENCRYPTED_SECRET)
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        ActivateHandle.WriteTo(ref writer);
        KeyHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        CredentialBlob.WriteTo(ref writer);
        SecretValue.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            CredentialBlob.Dispose();
            SecretValue.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"ActivateCredentialInput(Activate={ActivateHandle}, Key={KeyHandle}, Blob={CredentialBlob.Length} bytes, Secret={SecretValue.Length} bytes)";
}
