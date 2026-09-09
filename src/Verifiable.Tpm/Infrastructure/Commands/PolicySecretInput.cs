using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicySecret command (CC = 0x00000151).
/// </summary>
/// <remarks>
/// <para>
/// Binds a policy session to the requirement that the authorization value of the entity referenced by
/// <see cref="AuthHandle"/> be provided. The command updates the session's policyDigest as
/// <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicySecret || authEntity.Name || policyRef)</c>; for
/// <c>authHandle = TPM_RH_ENDORSEMENT</c> with an empty <see cref="PolicyRef"/> this yields the well-known TCG
/// endorsement-key authorization policy. Unlike TPM2_PolicySigned(), there is no signed digest at all — the
/// caller's proof of knowledge of the secret is the ordinary session authorization (password, HMAC, or a policy
/// session satisfying <c>TPM2_PolicyAuthValue()</c>/<c>TPM2_PolicyPassword()</c>) attached to
/// <see cref="AuthHandle"/> at USER role, checked before this command's own body runs.
/// </para>
/// <para>
/// <see cref="NonceTpm"/>, <see cref="CpHashA"/>, and <see cref="PolicyRef"/> were always part of the command's
/// wire shape; a negative <see cref="Expiration"/> requests a real <c>TPMT_TK_AUTH</c> authorization ticket
/// (TPM 2.0 Library Part 3, clause 23.2.5) instead of the NULL ticket a non-negative expiration produces. A
/// trial policy session still requires <see cref="AuthHandle"/>'s authorization to succeed, but skips this
/// command's own nonceTPM/expiration/cpHashA checks and ticket minting.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 23.4, Table 146):
/// </para>
/// <list type="bullet">
///   <item><description>authHandle (TPMI_DH_ENTITY): The entity whose authorization is required. Requires authorization at USER role.</description></item>
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle being extended. Requires no authorization.</description></item>
///   <item><description>nonceTPM (TPM2B_NONCE): The policy session's retained nonceTPM, or Empty Buffer for a session-unbound authorization.</description></item>
///   <item><description>cpHashA (TPM2B_DIGEST): Digest of the command parameters the session will later authorize, to which this authorization is limited; Empty Buffer if unlimited.</description></item>
///   <item><description>policyRef (TPM2B_NONCE): An opaque qualifier relating to the authorization; Empty Buffer if none.</description></item>
///   <item><description>expiration (INT32): Seconds from nonceTPM's generation until expiry; 0 = no expiry; negative = ticket requested.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicySecretInput: ITpmCommandInput, IDisposable
{
    private bool disposed;

    private IMemoryOwner<byte> NonceTpmOwner { get; }

    private IMemoryOwner<byte> CpHashAOwner { get; }

    private IMemoryOwner<byte> PolicyRefOwner { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicySecret;

    /// <summary>
    /// Gets the entity whose authorization value the policy requires (for example TPM_RH_ENDORSEMENT).
    /// </summary>
    public uint AuthHandle { get; }

    /// <summary>
    /// Gets the policy session handle being extended.
    /// </summary>
    public uint PolicySession { get; }

    /// <summary>
    /// Gets the policy session's retained nonceTPM, or empty for a session-unbound authorization.
    /// </summary>
    public ReadOnlyMemory<byte> NonceTpm { get; }

    /// <summary>
    /// Gets the digest of the command parameters this authorization is limited to, or empty if unlimited.
    /// </summary>
    public ReadOnlyMemory<byte> CpHashA { get; }

    /// <summary>
    /// Gets the opaque policy qualifier, or empty for none.
    /// </summary>
    public ReadOnlyMemory<byte> PolicyRef { get; }

    /// <summary>
    /// Gets the expiration (seconds from nonceTPM's generation until expiry); 0 = no expiry, negative = ticket requested.
    /// </summary>
    public int Expiration { get; }

    /// <summary>
    /// Creates the immediate form of a TPM2_PolicySecret input: nonceTPM, cpHashA, and policyRef are the Empty
    /// Buffer and expiration is zero, so the response carries a NULL ticket. Delegates into <see cref="Create"/>.
    /// </summary>
    /// <param name="authHandle">The entity whose authorization value the policy requires.</param>
    /// <param name="policySession">The policy session handle being extended.</param>
    /// <param name="pool">The memory pool for the parameter buffers.</param>
    /// <returns>A new <see cref="PolicySecretInput"/>.</returns>
    public static PolicySecretInput CreateImmediate(uint authHandle, uint policySession, BaseMemoryPool pool) =>
        Create(authHandle, policySession, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, expiration: 0, pool);

    /// <summary>
    /// Creates a TPM2_PolicySecret input in its full wire shape.
    /// </summary>
    /// <param name="authHandle">The entity whose authorization value the policy requires.</param>
    /// <param name="policySession">The policy session handle being extended.</param>
    /// <param name="nonceTpm">The policy session's retained nonceTPM, or empty for a session-unbound authorization.</param>
    /// <param name="cpHashA">The digest of the command parameters this authorization is limited to, or empty if unlimited.</param>
    /// <param name="policyRef">The opaque policy qualifier, or empty for none.</param>
    /// <param name="expiration">Seconds from nonceTPM's generation until expiry; 0 = no expiry, negative = ticket requested.</param>
    /// <param name="pool">The memory pool for the parameter buffers.</param>
    /// <returns>A new <see cref="PolicySecretInput"/>.</returns>
    public static PolicySecretInput Create(
        uint authHandle,
        uint policySession,
        ReadOnlySpan<byte> nonceTpm,
        ReadOnlySpan<byte> cpHashA,
        ReadOnlySpan<byte> policyRef,
        int expiration,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> nonceTpmOwner = pool.Rent(Math.Max(nonceTpm.Length, 1));
        nonceTpm.CopyTo(nonceTpmOwner.Memory.Span);

        IMemoryOwner<byte> cpHashAOwner = pool.Rent(Math.Max(cpHashA.Length, 1));
        cpHashA.CopyTo(cpHashAOwner.Memory.Span);

        IMemoryOwner<byte> policyRefOwner = pool.Rent(Math.Max(policyRef.Length, 1));
        policyRef.CopyTo(policyRefOwner.Memory.Span);

        return new PolicySecretInput(
            authHandle,
            policySession,
            nonceTpmOwner,
            nonceTpmOwner.Memory[..nonceTpm.Length],
            cpHashAOwner,
            cpHashAOwner.Memory[..cpHashA.Length],
            policyRefOwner,
            policyRefOwner.Memory[..policyRef.Length],
            expiration);
    }

    private PolicySecretInput(
        uint authHandle,
        uint policySession,
        IMemoryOwner<byte> nonceTpmOwner,
        ReadOnlyMemory<byte> nonceTpm,
        IMemoryOwner<byte> cpHashAOwner,
        ReadOnlyMemory<byte> cpHashA,
        IMemoryOwner<byte> policyRefOwner,
        ReadOnlyMemory<byte> policyRef,
        int expiration)
    {
        AuthHandle = authHandle;
        PolicySession = policySession;
        NonceTpmOwner = nonceTpmOwner;
        NonceTpm = nonceTpm;
        CpHashAOwner = cpHashAOwner;
        CpHashA = cpHashA;
        PolicyRefOwner = policyRefOwner;
        PolicyRef = policyRef;
        Expiration = expiration;
    }

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint) + sizeof(uint) +          //authHandle + policySession (handle area).
        sizeof(ushort) + NonceTpm.Length +     //nonceTPM (TPM2B_NONCE).
        sizeof(ushort) + CpHashA.Length +      //cpHashA (TPM2B_DIGEST).
        sizeof(ushort) + PolicyRef.Length +    //policyRef (TPM2B_NONCE).
        sizeof(int);                           //expiration (INT32).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(AuthHandle);
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteTpm2b(NonceTpm.Span);
        writer.WriteTpm2b(CpHashA.Span);
        writer.WriteTpm2b(PolicyRef.Span);
        writer.WriteInt32(Expiration);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            NonceTpmOwner.Dispose();
            CpHashAOwner.Dispose();
            PolicyRefOwner.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay =>
        $"PolicySecretInput(AuthHandle=0x{AuthHandle:X8}, PolicySession=0x{PolicySession:X8}, Expiration={Expiration})";
}
