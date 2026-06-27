using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Sessions;

/// <summary>
/// Base class for TPM session types.
/// </summary>
/// <remarks>
/// <para>
/// This abstract base provides the contract that the executor uses to interact
/// with sessions during command execution. Concrete implementations include
/// <see cref="TpmSession"/> for HMAC/policy sessions and <see cref="TpmPasswordSession"/>
/// for simple password authorization.
/// </para>
/// <para>
/// <b>Session lifecycle:</b>
/// </para>
/// <list type="number">
///   <item><description>Session is created from StartAuthSession response or as password session.</description></item>
///   <item><description>Executor calls <see cref="GetAuthCommandSize"/> to compute buffer size.</description></item>
///   <item><description>Executor calls <see cref="PrepareAuthHmacAsync"/> to precompute the auth HMAC.</description></item>
///   <item><description>Executor calls <see cref="WriteAuthCommand"/> to write TPMS_AUTH_COMMAND using the precomputed HMAC.</description></item>
///   <item><description>Executor calls <see cref="VerifyAndUpdateAsync"/> to verify response and update nonces.</description></item>
/// </list>
/// <para>
/// <b>Why precompute is split from write:</b> HMAC routes through the registered
/// <see cref="Verifiable.Cryptography.ComputeHmacDelegate"/>, which is async to
/// support hardware-bound key backends. <see cref="TpmWriter"/> is a
/// <see langword="ref struct"/> and cannot cross <c>await</c> boundaries, so
/// computation and writing are deliberately separated. Writing is synchronous and
/// consumes the precomputed value.
/// </para>
/// </remarks>
public abstract class TpmSessionBase
{
    /// <summary>
    /// Gets the session handle.
    /// </summary>
    /// <remarks>
    /// For HMAC and policy sessions, this is the handle returned by StartAuthSession.
    /// For password authorization, this is <see cref="TpmRh.TPM_RH_PW"/>.
    /// </remarks>
    public abstract TpmHandle SessionHandle { get; }

    /// <summary>
    /// Gets the hash algorithm for this session.
    /// </summary>
    /// <remarks>
    /// For HMAC sessions, this is the algorithm specified at creation.
    /// For password sessions, this returns <see cref="TpmAlgIdConstants.TPM_ALG_NULL"/>.
    /// </remarks>
    public abstract TpmAlgIdConstants HashAlgorithm { get; }

    /// <summary>
    /// Gets or sets the session attributes (TPMA_SESSION).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The executor reads these to discover which session carries the <c>decrypt</c> and <c>encrypt</c>
    /// attributes for session-based parameter encryption, without downcasting to a concrete session type.
    /// </para>
    /// <para>
    /// Password sessions ignore this value (they always transmit zero attributes), so setting
    /// <see cref="TpmaSession.DECRYPT"/> or <see cref="TpmaSession.ENCRYPT"/> on a password session has no
    /// effect and, because such a session carries no symmetric algorithm, would fail the executor's
    /// admissibility check.
    /// </para>
    /// <para>
    /// See TPM 2.0 Part 2, Section 8.4 - TPMA_SESSION.
    /// </para>
    /// </remarks>
    public TpmaSession SessionAttributes { get; set; }

    /// <summary>
    /// Gets the symmetric algorithm negotiated for session-based parameter encryption (TPMT_SYM_DEF).
    /// </summary>
    /// <remarks>
    /// Defaults to <see cref="TpmtSymDef.Null"/>. HMAC sessions established with a non-null symmetric
    /// definition carry it here so the executor can gate parameter encryption on it. Password sessions are
    /// always <see cref="TpmtSymDef.Null"/>.
    /// </remarks>
    public TpmtSymDef Symmetric { get; protected init; } = TpmtSymDef.Null;

    /// <summary>
    /// Generates a fresh caller nonce for the upcoming command.
    /// </summary>
    /// <param name="pool">The memory pool for allocating the new nonce.</param>
    /// <remarks>
    /// <para>
    /// The caller provides a fresh nonceCaller for each command in a session (TPM 2.0 Part 1, Section 17.6).
    /// The executor calls this once at the start of building each command, before computing the command
    /// parameter encryption, cpHash, and auth HMAC, so all three observe the same caller nonce, and that same
    /// nonce remains available to decrypt the response (which is keyed on the command's caller nonce) until the
    /// next command rolls it.
    /// </para>
    /// <para>
    /// The base implementation is a no-op; sessions without a rolling caller nonce (such as password sessions)
    /// do not override it.
    /// </para>
    /// </remarks>
    public virtual void RollNonceCaller(MemoryPool<byte> pool)
    {
    }

    /// <summary>
    /// Encrypts the data portion of the first command parameter in place, when this session is the command's
    /// decrypt session.
    /// </summary>
    /// <param name="firstParameterData">The data portion (excluding the size field) of the first parameter.</param>
    /// <param name="pool">The memory pool for transient key material.</param>
    /// <param name="cancellationToken">A token observed across the key-derivation computations.</param>
    /// <returns>A task that completes when the parameter has been encrypted.</returns>
    /// <remarks>
    /// Command parameter encryption uses nonceCaller as nonceNewer and nonceTPM as nonceOlder (TPM 2.0 Part 1,
    /// Section 19.2) and runs before cpHash is computed (Section 19.1). The base implementation is a no-op for
    /// sessions that do not perform parameter encryption.
    /// </remarks>
    public virtual ValueTask EncryptFirstParameterAsync(
        Memory<byte> firstParameterData,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Decrypts the data portion of the first response parameter in place, when this session is the command's
    /// encrypt session.
    /// </summary>
    /// <param name="firstParameterData">The data portion (excluding the size field) of the first parameter.</param>
    /// <param name="pool">The memory pool for transient key material.</param>
    /// <param name="cancellationToken">A token observed across the key-derivation computations.</param>
    /// <returns>A task that completes when the parameter has been decrypted.</returns>
    /// <remarks>
    /// Response parameter decryption uses nonceTPM as nonceNewer and nonceCaller as nonceOlder (TPM 2.0 Part 1,
    /// Section 19.2) and runs only after the response HMAC verifies (Section 19.1: rpHash is computed over the
    /// still-encrypted parameter). The executor calls this after <see cref="VerifyAndUpdateAsync"/> has adopted
    /// the new nonceTPM and before the next command rolls nonceCaller, so both nonces are correct. The base
    /// implementation is a no-op for sessions that do not perform parameter encryption.
    /// </remarks>
    public virtual ValueTask DecryptFirstParameterAsync(
        Memory<byte> firstParameterData,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Gets the serialized size of TPMS_AUTH_COMMAND for this session.
    /// </summary>
    /// <returns>The size in bytes.</returns>
    /// <remarks>
    /// <para>
    /// TPMS_AUTH_COMMAND contains:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>sessionHandle (4 bytes).</description></item>
    ///   <item><description>nonce (2 + nonce length).</description></item>
    ///   <item><description>sessionAttributes (1 byte).</description></item>
    ///   <item><description>hmac (2 + digest length).</description></item>
    /// </list>
    /// </remarks>
    public abstract int GetAuthCommandSize();

    /// <summary>
    /// Asynchronously precomputes the auth HMAC for this session, if any.
    /// </summary>
    /// <param name="cpHash">The command parameter hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">Token to observe while awaiting HMAC computation.</param>
    /// <returns>
    /// The precomputed HMAC bytes wrapped in <see cref="Tpm2bAuth"/>, or
    /// <see langword="null"/> for sessions that do not compute an HMAC
    /// (such as password sessions, which transmit the password directly).
    /// Ownership of the returned <see cref="Tpm2bAuth"/> transfers to the caller,
    /// which is responsible for disposal after the corresponding
    /// <see cref="WriteAuthCommand"/> call.
    /// </returns>
    public abstract ValueTask<Tpm2bAuth?> PrepareAuthHmacAsync(
        ReadOnlyMemory<byte> cpHash,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken);

    /// <summary>
    /// Writes TPMS_AUTH_COMMAND to the buffer using the precomputed auth HMAC.
    /// </summary>
    /// <param name="writer">The writer positioned at the auth command location.</param>
    /// <param name="precomputedHmac">
    /// The HMAC produced by a prior call to <see cref="PrepareAuthHmacAsync"/>,
    /// or <see langword="null"/> for sessions that do not compute an HMAC.
    /// </param>
    /// <remarks>
    /// <para>
    /// The session writes its authorization data including:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>sessionHandle.</description></item>
    ///   <item><description>nonceCaller (freshly generated for HMAC sessions, empty for password).</description></item>
    ///   <item><description>sessionAttributes.</description></item>
    ///   <item><description>hmac (the precomputed value for HMAC sessions, the password for password sessions).</description></item>
    /// </list>
    /// </remarks>
    public abstract void WriteAuthCommand(ref TpmWriter writer, Tpm2bAuth? precomputedHmac);

    /// <summary>
    /// Asynchronously verifies the response HMAC and updates session state.
    /// </summary>
    /// <param name="response">The parsed TPMS_AUTH_RESPONSE.</param>
    /// <param name="rpHash">The response parameter hash for HMAC verification.</param>
    /// <param name="pool">The memory pool for allocating new nonces.</param>
    /// <param name="cancellationToken">Token to observe while awaiting HMAC computation.</param>
    /// <returns>True if verification succeeded; false otherwise.</returns>
    /// <remarks>
    /// <para>
    /// On success for HMAC sessions, the session:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>Takes ownership of nonceTPM from response.</description></item>
    ///   <item><description>Generates new nonceCaller for next command.</description></item>
    /// </list>
    /// <para>
    /// Password sessions always return true without verification.
    /// </para>
    /// </remarks>
    public abstract ValueTask<bool> VerifyAndUpdateAsync(
        TpmsAuthResponse response,
        ReadOnlyMemory<byte> rpHash,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken);
}
