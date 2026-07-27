using System;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The simulator's model of a loaded sealed data object: the sensitive data recovered from a wrapped blob by
/// <c>TPM2_Load()</c> and addressed by a transient handle (most-significant octet <c>TPM_HT_TRANSIENT</c>,
/// TPM 2.0 Library Part 2, clause 7.2). It is the smallest object model the seal-then-unseal path needs — the
/// retained sealed octets a subsequent <c>TPM2_Unseal()</c> returns.
/// </summary>
/// <remarks>
/// <para>
/// Like <see cref="TransientKeyState"/> and <see cref="NvIndexState"/>, the data is held as plain
/// <see cref="ReadOnlyMemory{T}"/> rather than pooled buffers: it is durable model state owned by the live
/// automaton for the lifetime of the simulated object, not hot wire-path memory. The sealed data is sensitive,
/// exactly as an object's private key or an NV Index authorization value is.
/// </para>
/// <para>
/// A real TPM recovers the sealed data by unwrapping the parent-encrypted, integrity-protected private blob; the
/// simulator does not model parent-key wrapping (it has no parent symmetric-key custody), so it recovers the data
/// from its own private-blob encoding (TPM 2.0 Library Part 1, clause 24; Part 3, clauses 12.1 / 12.7).
/// </para>
/// </remarks>
/// <param name="Handle">The transient handle assigned to the loaded object.</param>
/// <param name="Name">
/// The object's Name (<c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c>), computed once at <c>TPM2_Load()</c> (TPM 2.0
/// Library Part 1, clause 16). Reused, not recomputed, as the handle-Name term of a command-HMAC's cpHash (Part 1,
/// clause 18.7 equation 15) and as the entity Name compared against a session's <see cref="HmacSessionState.BoundEntityName"/>.
/// </param>
/// <param name="Data">The recovered sealed data returned by <c>TPM2_Unseal()</c>.</param>
/// <param name="AuthPolicy">
/// The object's authorization policy digest, carried in its public area (empty when the object is authorized by
/// its authValue alone). A subsequent <c>TPM2_Unseal()</c> over a policy session is authorized only when the
/// session's accumulated policyDigest reproduces this value (TPM 2.0 Library Part 3, clause 12.7; Part 1, clause
/// 19.7); an empty authPolicy leaves the object outside the policy path.
/// </param>
/// <param name="UserAuth">
/// The object's authorization value, supplied in <c>inSensitive.userAuth</c> at <c>TPM2_Create()</c> and carried
/// through the wrapped private blob to <c>TPM2_Load()</c> (TPM 2.0 Library Part 1, clause 19.6.4; Part 3, clause
/// 12.1). Compared against a password session's supplied value (both sides trailing-zero-stripped, clause 19.4) or
/// folded into an authorizing HMAC session's key (clause 19.6.10 equation 21) unless the bind-omission applies.
/// </param>
/// <param name="NoDa">
/// Whether the object's public area sets <c>TPMA_OBJECT.noDA</c> (TPM 2.0 Library Part 2, clause 8.3.3), re-derived
/// from the caller-supplied <c>inPublic</c> at <c>TPM2_Load()</c> exactly as <see cref="AuthPolicy"/> is (a
/// public-area attribute, not sensitive-area state). See <see cref="IsDaProtected"/>.
/// </param>
/// <param name="UserWithAuth">
/// Whether the object's public area sets <c>TPMA_OBJECT.userWithAuth</c> (TPM 2.0 Library Part 2, clause 8.3.3):
/// SET permits a USER-role action (such as <c>TPM2_Unseal()</c>) to be authorized by an HMAC session or password,
/// as well as a policy session; CLEAR requires a policy session (TPM 2.0 Library Part 3, clause 5.6, check 6).
/// Re-derived from the caller-supplied <c>inPublic</c> at <c>TPM2_Load()</c>, exactly as <see cref="NoDa"/> is.
/// </param>
public sealed record SealedObjectState(
    uint Handle,
    ReadOnlyMemory<byte> Name,
    ReadOnlyMemory<byte> Data,
    ReadOnlyMemory<byte> AuthPolicy,
    ReadOnlyMemory<byte> UserAuth,
    bool NoDa,
    bool UserWithAuth)
{
    /// <summary>
    /// Gets a value indicating whether this object is dictionary-attack protected: an authorization failure
    /// against it feeds the lockout counter and is blocked in lockout, unless <see cref="NoDa"/> is set (TPM 2.0
    /// Library Part 2, clause 8.3.3; Part 1, clause 19.8.1), mirroring <see cref="NvIndexState.IsDaProtected"/>.
    /// </summary>
    public bool IsDaProtected => !NoDa;
}
