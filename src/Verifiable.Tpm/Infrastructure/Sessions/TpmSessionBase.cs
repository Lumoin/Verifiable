using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
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
