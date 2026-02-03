using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// TPMS_AUTH_COMMAND - authorization command structure for writing.
/// </summary>
/// <remarks>
/// <para>
/// This ref struct provides a type-safe, non-owning view for writing authorization
/// data to TPM command buffers. It borrows references to the session's nonce and
/// computed HMAC without transferring ownership.
/// </para>
/// <para>
/// <b>Wire format (big-endian):</b>
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-3: sessionHandle (TPMI_SH_AUTH_SESSION).</description></item>
///   <item><description>Bytes 4+: nonce (TPM2B_NONCE) - caller's nonce.</description></item>
///   <item><description>Next 1 byte: sessionAttributes (TPMA_SESSION).</description></item>
///   <item><description>Remaining: hmac (TPM2B_AUTH) - HMAC or password.</description></item>
/// </list>
/// <para>
/// <b>Ownership:</b>
/// </para>
/// <para>
/// This structure does not own any data. The session retains ownership of its nonce
/// (needed for response verification) and the HMAC (typically stack-allocated or
/// short-lived). Since this is a ref struct, it cannot escape the current stack frame.
/// </para>
/// <para>
/// <b>Usage:</b>
/// </para>
/// <code>
/// //Session owns nonceCaller, computes hmac.
/// var authCommand = new TpmsAuthCommand(
///     sessionHandle,
///     new Tpm2bRef&lt;Tpm2bNonce&gt;(nonceCaller),
///     TpmaSession.CONTINUE_SESSION,
///     new Tpm2bRef&lt;Tpm2bAuth&gt;(hmac));
///
/// authCommand.WriteTo(ref writer);
/// //nonceCaller still owned by session for response verification.
/// </code>
/// <para>
/// See TPM 2.0 Library Specification, Part 2: Structures, Section 10.10.1.
/// </para>
/// </remarks>
/// <seealso cref="TpmsAuthResponse"/>
/// <seealso cref="Tpm2bRef{T}"/>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly ref struct TpmsAuthCommand
{
    /// <summary>
    /// Gets the session handle.
    /// </summary>
    /// <remarks>
    /// For HMAC and policy sessions, this is the handle returned by StartAuthSession.
    /// For password authorization, this is <see cref="TpmRh.TPM_RH_PW"/>.
    /// </remarks>
    public TpmHandle SessionHandle { get; }

    /// <summary>
    /// Gets a reference to the caller's nonce.
    /// </summary>
    /// <remarks>
    /// The session retains ownership. This nonce is included in the HMAC computation
    /// and must remain valid until response verification completes.
    /// </remarks>
    public Tpm2bRef<Tpm2bNonce> NonceCaller { get; }

    /// <summary>
    /// Gets the session attributes.
    /// </summary>
    /// <remarks>
    /// See <see cref="TpmaSession"/> for attribute definitions (continueSession, auditExclusive,
    /// auditReset, decrypt, encrypt, audit).
    /// </remarks>
    public TpmaSession SessionAttributes { get; }

    /// <summary>
    /// Gets a reference to the HMAC or password.
    /// </summary>
    /// <remarks>
    /// For HMAC sessions: the computed HMAC over cpHash, nonces, and attributes.
    /// For password authorization: the authorization value (password).
    /// </remarks>
    public Tpm2bRef<Tpm2bAuth> Hmac { get; }

    /// <summary>
    /// Initializes a new authorization command.
    /// </summary>
    /// <param name="sessionHandle">The session handle.</param>
    /// <param name="nonceCaller">Reference to the caller's nonce.</param>
    /// <param name="sessionAttributes">The session attributes.</param>
    /// <param name="hmac">Reference to the HMAC or password.</param>
    public TpmsAuthCommand(
        TpmHandle sessionHandle,
        Tpm2bRef<Tpm2bNonce> nonceCaller,
        TpmaSession sessionAttributes,
        Tpm2bRef<Tpm2bAuth> hmac)
    {
        SessionHandle = sessionHandle;
        NonceCaller = nonceCaller;
        SessionAttributes = sessionAttributes;
        Hmac = hmac;
    }

    /// <summary>
    /// Writes this authorization command to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        SessionHandle.WriteTo(ref writer);
        NonceCaller.WriteTo(ref writer);
        writer.WriteByte((byte)SessionAttributes);
        Hmac.WriteTo(ref writer);
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    /// <returns>The size in bytes.</returns>
    public int GetSerializedSize()
    {
        return sizeof(uint) + NonceCaller.GetSerializedSize() + sizeof(byte) + Hmac.GetSerializedSize();
    }

    private string DebuggerDisplay => $"TPMS_AUTH_COMMAND(0x{SessionHandle.Value:X8}, {SessionAttributes})";
}