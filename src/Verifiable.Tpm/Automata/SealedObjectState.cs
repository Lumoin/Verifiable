using System;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The simulator's model of a loaded sealed data object: the sensitive data recovered from a wrapped blob by
/// <c>TPM2_Load()</c> and addressed by a transient handle (most-significant octet <c>TPM_HT_TRANSIENT</c>,
/// TPM 2.0 Library Part 2, clause 7.2). It is the smallest object model the seal-then-unseal path needs — the
/// retained sealed octets a subsequent <c>TPM2_Unseal()</c> returns.
/// </summary>
/// <remarks>
/// <para>
/// The sealed data and the authorization value live in pinned, zero-on-dispose carriers the record owns
/// (<see cref="Tpm2bSensitiveData"/> and <see cref="Tpm2bAuth"/>): both are rented in the <c>TPM2_Load()</c>
/// effect that unpacks the private blob, their ownership transfers into this record at the installing
/// transition, and they are disposed when the object is evicted (<c>TPM2_FlushContext()</c>, simulator
/// teardown) — the same ownership discipline <see cref="NvIndexState"/> and <see cref="TransientKeyState"/>
/// apply to their own sensitive fields. The sealed data is sensitive, exactly as an object's private key or
/// an NV Index authorization value is.
/// </para>
/// <para>
/// <see cref="Name"/> is owned on the same terms, matching <see cref="TransientKeyState.Name"/>: the
/// <c>TPM2_Load()</c> effect rents a Name carrier for this record separately from the one the response frames,
/// so the two owners have disjoint lifetimes and neither ever disposes the other's buffer — the discipline
/// <c>TPM2_EvictControl()</c>'s persist arm applies when it deep-copies a transient object's Name.
/// </para>
/// <para>
/// A real TPM recovers the sealed data by unwrapping the parent-encrypted, integrity-protected private blob; the
/// simulator does not model parent-key wrapping (it has no parent symmetric-key custody), so it recovers the data
/// from its own private-blob encoding (TPM 2.0 Library Part 1, clause 24; Part 3, clauses 12.1 / 12.7).
/// </para>
/// </remarks>
/// <param name="Handle">The transient handle assigned to the loaded object.</param>
/// <param name="Name">
/// The object's Name (<c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c>) in an owned <c>TPM2B_NAME</c> carrier (TPM 2.0
/// Library Part 2, clause 10.5.3, Table 104), computed once at <c>TPM2_Load()</c> (Part 1, clause 14, Table 6). Reused,
/// not recomputed, as the handle-Name term of a command-HMAC's cpHash (Part 1, clause 16.7 equation 15) and as
/// the entity-Name term of a session's <see cref="HmacSessionState.BoundEntity"/> recomputation, both of which
/// borrow it zero-copy through <see cref="Tpm2bName.AsReadOnlyMemory"/> / <see cref="Tpm2bName.Span"/> and never
/// dispose it.
/// </param>
/// <param name="Data">The recovered sealed data returned by <c>TPM2_Unseal()</c>.</param>
/// <param name="AuthPolicy">
/// The object's authorization policy digest, carried in its public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library
/// Part 2, clause 10.4.2, Table 92), in an owned pooled carrier — the dispose-immune
/// <see cref="Tpm2bDigest.Empty"/> when the object is authorized by its authValue alone. A subsequent
/// <c>TPM2_Unseal()</c> over a policy session is authorized only when the session's accumulated policyDigest
/// reproduces this value (Part 3, clause 12.7; Part 1, clause 17.7); an empty authPolicy leaves the object
/// outside the policy path. Ownership arrives with the loaded object at the installing transition and is
/// released on eviction.
/// </param>
/// <param name="UserAuth">
/// The object's authorization value, supplied in <c>inSensitive.userAuth</c> at <c>TPM2_Create()</c> and carried
/// through the wrapped private blob to <c>TPM2_Load()</c> (TPM 2.0 Library Part 1, clause 17.6.4; Part 3, clause
/// 12.1). Compared against a password session's supplied value (both sides trailing-zero-stripped, clause 17.6.4) or
/// folded into an authorizing HMAC session's key (clause 17.6.10 equation 21) unless the bind-omission applies.
/// </param>
/// <param name="NoDa">
/// Whether the object's public area sets <c>TPMA_OBJECT.noDA</c> (TPM 2.0 Library Part 2, clause 8.3.3), re-derived
/// from the caller-supplied <c>inPublic</c> at <c>TPM2_Load()</c> exactly as <see cref="AuthPolicy"/> is (a
/// public-area attribute, not sensitive-area state). See <see cref="IsDaProtected"/>.
/// </param>
/// <param name="UserWithAuth">
/// Whether the object's public area sets <c>TPMA_OBJECT.userWithAuth</c> (TPM 2.0 Library Part 2, clause 8.3.3):
/// SET permits a USER-role action (such as <c>TPM2_Unseal()</c>) to be authorized by an HMAC session or password,
/// as well as a policy session; CLEAR requires a policy session (TPM 2.0 Library Part 3, clause 5.6, check 7.1).
/// Re-derived from the caller-supplied <c>inPublic</c> at <c>TPM2_Load()</c>, exactly as <see cref="NoDa"/> is.
/// </param>
public sealed record SealedObjectState(
    TpmiDhObject Handle,
    Tpm2bName Name,
    Tpm2bSensitiveData Data,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth UserAuth,
    bool NoDa,
    bool UserWithAuth): IDisposable
{
    /// <summary>
    /// Gets a value indicating whether this object is dictionary-attack protected: an authorization failure
    /// against it feeds the lockout counter and is blocked in lockout, unless <see cref="NoDa"/> is set (TPM 2.0
    /// Library Part 2, clause 8.3.3; Part 1, clause 17.8.1), mirroring <see cref="NvIndexState.IsDaProtected"/>.
    /// </summary>
    public bool IsDaProtected => !NoDa;

    /// <summary>
    /// Releases the object's owned Name, sealed-data, authorization-policy-digest, and authorization-value
    /// carriers. Called when the
    /// object leaves the automaton's dictionary for good (<c>TPM2_FlushContext()</c>, simulator teardown); the
    /// shared empty carriers are dispose-immune, so the walk is safe for an empty-auth object.
    /// </summary>
    public void Dispose()
    {
        Name.Dispose();
        Data.Dispose();
        AuthPolicy.Dispose();
        UserAuth.Dispose();
    }

    /// <summary>
    /// Value equality with OWNERSHIP identity for the owned carriers: two records are equal only when they
    /// share the same <see cref="Name"/>, <see cref="Data"/>, <see cref="AuthPolicy"/>, and
    /// <see cref="UserAuth"/> instances — reference
    /// comparison is ownership identity and never reads carrier content, so a superseded or disposed snapshot
    /// cannot throw here (see <see cref="NvIndexState.Equals(NvIndexState)"/> for the shared rationale).
    /// </summary>
    /// <param name="other">The record to compare against.</param>
    /// <returns><see langword="true"/> when every field matches and the carriers are the same instances.</returns>
    public bool Equals(SealedObjectState? other) =>
        other is not null
        && Handle == other.Handle
        && ReferenceEquals(Name, other.Name)
        && ReferenceEquals(Data, other.Data)
        && ReferenceEquals(AuthPolicy, other.AuthPolicy)
        && ReferenceEquals(UserAuth, other.UserAuth)
        && NoDa == other.NoDa
        && UserWithAuth == other.UserWithAuth;

    /// <summary>
    /// Hashes the object's immutable identity fields, consistent with
    /// <see cref="Equals(SealedObjectState)"/> without ever reading carrier content.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode() => HashCode.Combine(Handle, NoDa, UserWithAuth);
}
