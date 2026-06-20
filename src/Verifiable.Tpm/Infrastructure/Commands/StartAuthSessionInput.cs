using System;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_StartAuthSession command.
/// </summary>
/// <remarks>
/// <para>
/// This command starts an authorization session that can be used for:
/// </para>
/// <list type="bullet">
///   <item><description>HMAC sessions - integrity protection via cpHash/rpHash.</description></item>
///   <item><description>Policy sessions - policy-based authorization.</description></item>
///   <item><description>Trial sessions - policy digest computation without authorization.</description></item>
/// </list>
/// <para>
/// <strong>Wire format:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>tpmKey (TPMI_DH_OBJECT+) - handle of a loaded key for salt encryption, or TPM_RH_NULL.</description></item>
///   <item><description>bind (TPMI_DH_ENTITY+) - handle for binding, or TPM_RH_NULL.</description></item>
///   <item><description>nonceCaller (TPM2B_NONCE) - caller's nonce, or empty for TPM to generate.</description></item>
///   <item><description>encryptedSalt (TPM2B_ENCRYPTED_SECRET) - encrypted salt, or empty if unsalted.</description></item>
///   <item><description>sessionType (TPM_SE) - type of session.</description></item>
///   <item><description>symmetric (TPMT_SYM_DEF) - symmetric algorithm for parameter encryption.</description></item>
///   <item><description>authHash (TPMI_ALG_HASH) - hash algorithm for the session.</description></item>
/// </list>
/// <para>
/// <strong>Factory methods:</strong> Use <see cref="StartAuthSessionInputExtensions"/> for
/// convenient factory methods like <c>CreateUnboundUnsaltedHmacSession</c>.
/// </para>
/// <para>
/// See TPM 2.0 Part 3, Section 11.1 - TPM2_StartAuthSession.
/// </para>
/// </remarks>
public readonly record struct StartAuthSessionInput: ITpmCommandInput
{
    /// <summary>
    /// Handle of a loaded key for salt encryption, or TPM_RH_NULL for unsalted session.
    /// </summary>
    public required uint TpmKey { get; init; }

    /// <summary>
    /// Handle for binding session to an entity, or TPM_RH_NULL for unbound session.
    /// </summary>
    public required uint Bind { get; init; }

    /// <summary>
    /// Caller's nonce. If empty, TPM generates a nonce.
    /// </summary>
    public ReadOnlyMemory<byte> NonceCaller { get; init; }

    /// <summary>
    /// Encrypted salt for salted sessions. Empty for unsalted sessions.
    /// </summary>
    public ReadOnlyMemory<byte> EncryptedSalt { get; init; }

    /// <summary>
    /// Type of session: HMAC, policy, or trial.
    /// </summary>
    public required TpmSeConstants SessionType { get; init; }

    /// <summary>
    /// Hash algorithm for the session.
    /// </summary>
    public required TpmAlgIdConstants AuthHash { get; init; }

    /// <summary>
    /// Symmetric algorithm for session-based parameter encryption (TPMT_SYM_DEF).
    /// </summary>
    /// <remarks>
    /// Defaults to <see cref="TpmtSymDef.Null"/> (no parameter encryption). Set
    /// <see cref="TpmtSymDef.Xor(TpmAlgIdConstants)"/> to negotiate XOR obfuscation. Because the default value
    /// of the underlying struct carries <see cref="TpmAlgIdConstants.TPM_ALG_ERROR"/> rather than
    /// <see cref="TpmAlgIdConstants.TPM_ALG_NULL"/>, the accessor maps an unset value to
    /// <see cref="TpmtSymDef.Null"/> so an input constructed without specifying a symmetric algorithm still
    /// serializes a valid null definition.
    /// </remarks>
    public TpmtSymDef Symmetric
    {
        get => symmetric.Algorithm == TpmAlgIdConstants.TPM_ALG_ERROR ? TpmtSymDef.Null : symmetric;
        init => symmetric = value;
    }

    private readonly TpmtSymDef symmetric;

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_StartAuthSession;

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        //Handles: tpmKey + bind.
        //Parameters: nonceCaller (size + data) + encryptedSalt (size + data) +
        //sessionType + symmetric (TPMT_SYM_DEF) + authHash.
        return sizeof(uint) + sizeof(uint) +
               (sizeof(ushort) + NonceCaller.Length) +
               (sizeof(ushort) + EncryptedSalt.Length) +
               sizeof(byte) + Symmetric.SerializedSize + sizeof(ushort);
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(TpmKey);
        writer.WriteUInt32(Bind);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteTpm2b(NonceCaller.Span);
        writer.WriteTpm2b(EncryptedSalt.Span);
        writer.WriteByte((byte)SessionType);
        Symmetric.WriteTo(ref writer);
        writer.WriteUInt16((ushort)AuthHash);
    }
}
