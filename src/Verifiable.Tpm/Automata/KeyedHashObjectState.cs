using System;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The simulator's model of a loaded KEYEDHASH object — a sealed data object (<c>sign</c> and <c>decrypt</c>
/// CLEAR, backing <c>TPM2_Unseal()</c>) or an HMAC signing key (<c>sign</c> SET, backing <c>TPM2_HMAC()</c>,
/// <c>TPM2_HMAC_Start()</c> and the HMAC arm of <c>TPM2_SequenceComplete()</c>) — distinguished by
/// <see cref="IsSealedData"/>/<see cref="IsHmacKey"/> off the retained public area. The sensitive value is
/// recovered from a wrapped blob by <c>TPM2_Load()</c> and the object is addressed by a transient handle
/// (most-significant octet <c>TPM_HT_TRANSIENT</c>, TPM 2.0 Library Part 2, clause 7.2).
/// </summary>
/// <remarks>
/// <para>
/// The sensitive value and the authorization value live in pinned, zero-on-dispose carriers the record owns
/// (<see cref="Tpm2bSensitiveData"/> and <see cref="Tpm2bAuth"/>): both are rented in the <c>TPM2_Load()</c>
/// effect that unpacks the private blob, their ownership transfers into this record at the installing
/// transition, and they are disposed when the object is evicted (<c>TPM2_FlushContext()</c>, <c>TPM2_Clear()</c>,
/// hierarchy disable, <c>TPM2_Startup()</c>, simulator teardown) — the same ownership discipline
/// <see cref="NvIndexState"/> and <see cref="TransientKeyState"/> apply to their own sensitive fields. The sensitive value is protected exactly as an object's private key or
/// an NV Index authorization value is.
/// </para>
/// <para>
/// <see cref="Name"/> is owned on the same terms, matching <see cref="TransientKeyState.Name"/>: the
/// <c>TPM2_Load()</c> effect rents a Name carrier for this record separately from the one the response frames,
/// so the two owners have disjoint lifetimes and neither ever disposes the other's buffer — the discipline
/// <c>TPM2_EvictControl()</c>'s persist arm applies when it deep-copies a transient object's Name.
/// </para>
/// <para>
/// The sensitive value is recovered by unwrapping the parent-encrypted, integrity-protected private blob under the
/// Storage Parent's protection seed, the integrity value verified before anything is decrypted (TPM 2.0 Library
/// Part 1, Clause 19; Part 3, clauses 12.1, 12.2 and 12.7).
/// </para>
/// </remarks>
/// <param name="Handle">The transient handle assigned to the loaded object.</param>
/// <param name="Hierarchy">
/// The permanent hierarchy the object belongs to — that of the Storage Parent it was loaded under, since "the
/// ancestors of an object are the parent keys that connect the object to a TPM Primary Seed" (TPM 2.0 Library
/// Part 1, clause 20.2) and a child's hierarchy is therefore its parent's. Retained so the two hierarchy sweeps
/// can find it: <c>TPM2_Clear()</c> flushes "resident objects (persistent and volatile) in the Storage and
/// Endorsement hierarchies" (Part 3, clause 24.6.1) and <c>TPM2_HierarchyControl()</c> flushes "any transient
/// objects associated with the disabled hierarchy" (Part 3, clause 24.2.1) — "all objects associated with that
/// hierarchy are flushed from TPM memory" (Part 1, clause 27.4), a sealed data object no less than a key.
/// </param>
/// <param name="Name">
/// The object's Name (<c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c>) in an owned <c>TPM2B_NAME</c> carrier (TPM 2.0
/// Library Part 2, clause 10.4.3, Table 105), computed once at <c>TPM2_Load()</c> (Part 1, clause 13, Table 9). Reused,
/// not recomputed, as the handle-Name term of a command-HMAC's cpHash (Part 1, clause 15.7 equation 15) and as
/// the entity-Name term of a session's <see cref="HmacSessionState.BoundEntity"/> recomputation, both of which
/// borrow it zero-copy through <see cref="Tpm2bName.AsReadOnlyMemory"/> / <see cref="Tpm2bName.Span"/> and never
/// dispose it.
/// </param>
/// <param name="Data">
/// The object's <c>TPMT_SENSITIVE.sensitive.bits</c> (TPM 2.0 Library Part 2, clause 12.3.2, Table 240): for a
/// sealed data object the sealed octets <c>TPM2_Unseal()</c> returns; for an HMAC key the key value the HMAC
/// effect keys with — never returned by any command.
/// </param>
/// <param name="AuthPolicy">
/// The object's authorization policy digest, carried in its public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library
/// Part 2, clause 10.3.2, Table 90), in an owned pooled carrier — the dispose-immune
/// <see cref="Tpm2bDigest.Empty"/> when the object is authorized by its authValue alone. A subsequent
/// <c>TPM2_Unseal()</c> over a policy session is authorized only when the session's accumulated policyDigest
/// reproduces this value (Part 3, clause 12.7; Part 1, clause 16.7); an empty authPolicy leaves the object
/// outside the policy path. Ownership arrives with the loaded object at the installing transition and is
/// released on eviction.
/// </param>
/// <param name="UserAuth">
/// The object's authorization value, supplied in <c>inSensitive.userAuth</c> at <c>TPM2_Create()</c> and carried
/// through the wrapped private blob to <c>TPM2_Load()</c> (TPM 2.0 Library Part 1, clause 16.6.4; Part 3, clause
/// 12.1). Compared against a password session's supplied value (both sides trailing-zero-stripped, clause 16.6.4) or
/// folded into an authorizing HMAC session's key (clause 16.6.10 equation 21) unless the bind-omission applies.
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
/// <param name="IsDuplicable">
/// Whether the object's public area carries <c>TPMA_OBJECT.fixedParent</c> CLEAR (TPM 2.0 Library Part 2,
/// clause 8.3.2, Table 37), so the object may leave its parent through <c>TPM2_Duplicate()</c>; re-derived from
/// the caller-supplied <c>inPublic</c> at <c>TPM2_Load()</c> exactly as <see cref="NoDa"/> is.
/// </param>
/// <param name="SeedValue">
/// The object's own protection seed (<c>TPMT_SENSITIVE.seedValue</c> — the obfuscation value of a sealed data
/// object, TPM 2.0 Library Part 2, clause 12.3.2, Table 240; Part 1, Clause 24.7.4), recovered from the wrapped
/// private blob at <c>TPM2_Load()</c> and retained so a later export of the object can rebuild its sensitive
/// area faithfully. Sensitive model state that never leaves the simulator; ownership arrives with the loaded
/// object at the installing transition and is released on eviction.
/// </param>
/// <param name="PublicArea">
/// The object's full public area (<c>TPM2B_PUBLIC</c>, TPM 2.0 Library Part 2, clause 12.2.5, Table 236) — the
/// caller-supplied <c>inPublic</c> whose marshaled <c>TPMT_PUBLIC</c> <see cref="Name"/> was hashed over and
/// whose integrity the blob's outer HMAC bound, retained in the owned carrier the <c>TPM2_Load()</c> request
/// parsed so <c>TPM2_ReadPublic()</c> can "allow access to the public area of a loaded object" (Part 3, clause
/// 12.4.1) octet for octet. Ownership transfers from the load effect at the installing transition and is
/// released on eviction.
/// </param>
/// <param name="QualifiedName">
/// The object's Qualified Name (<c>TPM2B_NAME</c>, TPM 2.0 Library Part 1, clause 23.5:
/// <c>QN = H_nameAlg(QN_parent ‖ Name)</c>, chained from the Storage Parent's own
/// <see cref="TransientKeyState.QualifiedName"/>), computed once at <c>TPM2_Load()</c> in an owned pooled
/// carrier on the same lifecycle as <see cref="Name"/>, and answered verbatim by <c>TPM2_ReadPublic()</c>
/// (Part 3, clause 12.4, Table 25). Retained rather than recomputed because the ancestry it digests is fixed
/// at load: the parent may be flushed afterwards while this object stays loaded.
/// </param>
public sealed record KeyedHashObjectState(
    TpmiDhObject Handle,
    TpmiRhHierarchy Hierarchy,
    Tpm2bName Name,
    Tpm2bSensitiveData Data,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth UserAuth,
    bool NoDa,
    bool UserWithAuth,
    bool IsDuplicable,
    Tpm2bDigest SeedValue,
    Tpm2bPublic PublicArea,
    Tpm2bName QualifiedName): IDisposable
{
    /// <summary>
    /// Gets a value indicating whether this object is dictionary-attack protected: an authorization failure
    /// against it feeds the lockout counter and is blocked in lockout, unless <see cref="NoDa"/> is set (TPM 2.0
    /// Library Part 2, clause 8.3.3; Part 1, clause 16.8.1), mirroring <see cref="NvIndexState.IsDaProtected"/>.
    /// </summary>
    public bool IsDaProtected => !NoDa;

    /// <summary>
    /// Gets the object's public-area attribute word (<c>TPMA_OBJECT</c>, TPM 2.0 Library Part 2, clause 8.3),
    /// read from the retained <see cref="PublicArea"/>. Distinguishes the two shapes a loaded KEYEDHASH object
    /// can take (a sealed data object versus an HMAC signing key) through its <c>sign</c>/<c>decrypt</c>/
    /// <c>restricted</c> bits, which the sealed-object record does not otherwise keep.
    /// </summary>
    public TpmaObject Attributes => PublicArea.PublicArea.ObjectAttributes;

    /// <summary>
    /// Gets a value indicating whether this object is an HMAC signing key: a KEYEDHASH object whose
    /// <c>sign</c> attribute is SET (TPM 2.0 Library Part 2, clause 8.3.3.14: "If sign is SET on an object with
    /// type set to TPM_ALG_KEYEDHASH, it indicates that the object is an HMAC key"). A loaded KEYEDHASH object
    /// with <c>sign</c> SET always has <c>decrypt</c> CLEAR — the create and load gates refuse the both-SET
    /// combination version 185 deprecates (Part 0, clause 3.1.4.1) — so the test on both bits is exact. Such a
    /// key backs <c>TPM2_HMAC()</c>, <c>TPM2_HMAC_Start()</c>, the HMAC arm of <c>TPM2_SequenceComplete()</c>,
    /// and the HMAC row of Part 3, clause 20.1, Table 115 — <c>TPM2_Sign()</c>/<c>TPM2_VerifySignature()</c>
    /// over a digest and the sign/verify sequence commands over a message; a sealed data object (both
    /// attributes CLEAR) backs <c>TPM2_Unseal()</c>.
    /// </summary>
    public bool IsHmacKey => (Attributes & TpmaObject.SIGN_ENCRYPT) != 0 && (Attributes & TpmaObject.DECRYPT) == 0;

    /// <summary>
    /// Gets a value indicating whether this object is a sealed data object: a KEYEDHASH object whose
    /// <c>sign</c> and <c>decrypt</c> attributes are both CLEAR (TPM 2.0 Library Part 1, clause 24.7.5.1). Only
    /// such an object may be unsealed; <c>TPM2_Unseal()</c> refuses any object with <c>restricted</c>,
    /// <c>decrypt</c>, or <c>sign</c> SET (Part 3, clause 12.7).
    /// </summary>
    public bool IsSealedData => (Attributes & (TpmaObject.SIGN_ENCRYPT | TpmaObject.DECRYPT)) == 0;

    /// <summary>
    /// Gets the hash algorithm of this HMAC key's signing scheme (<c>TPMS_SCHEME_HMAC.hashAlg</c>, TPM 2.0
    /// Library Part 2, clause 11.1.20, Table 176), read from the keyed-hash parameters of the retained
    /// <see cref="PublicArea"/>. Meaningful for an <see cref="IsHmacKey"/> object, whose scheme is
    /// <c>TPM_ALG_HMAC</c> with a hash by construction (the creation gate refuses a NULL scheme on a signing
    /// KEYEDHASH key per Part 2, Table 227's version-185 deprecation); any other scheme — the NULL scheme of a
    /// sealed data object, or an XOR scheme — reads back <see cref="TpmAlgIdConstants.TPM_ALG_NULL"/> here.
    /// </summary>
    public TpmiAlgHash SchemeHashAlg =>
        PublicArea.PublicArea.Parameters.KeyedHashDetail is { IsHmac: true } scheme
            ? TpmiAlgHash.FromValue(scheme.HashAlg)
            : TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_NULL);

    /// <summary>
    /// Releases the object's owned Name, sensitive-value, authorization-policy-digest, authorization-value,
    /// protection-seed, public-area, and Qualified Name carriers. Called when the
    /// object leaves the automaton's dictionary for good (<c>TPM2_FlushContext()</c>, <c>TPM2_Clear()</c>, hierarchy
    /// disable, <c>TPM2_Startup()</c>, simulator teardown); the
    /// shared empty carriers are dispose-immune, so the walk is safe for an empty-auth object.
    /// </summary>
    public void Dispose()
    {
        Name.Dispose();
        Data.Dispose();
        AuthPolicy.Dispose();
        UserAuth.Dispose();
        SeedValue.Dispose();
        PublicArea.Dispose();
        QualifiedName.Dispose();
    }

    /// <summary>
    /// Value equality with OWNERSHIP identity for the owned carriers: two records are equal only when they
    /// share the same <see cref="Name"/>, <see cref="Data"/>, <see cref="AuthPolicy"/>,
    /// <see cref="UserAuth"/>, <see cref="SeedValue"/>, <see cref="PublicArea"/>, and <see cref="QualifiedName"/>
    /// instances — reference
    /// comparison is ownership identity and never reads carrier content, so a superseded or disposed snapshot
    /// cannot throw here (see <see cref="NvIndexState.Equals(NvIndexState)"/> for the shared rationale).
    /// </summary>
    /// <param name="other">The record to compare against.</param>
    /// <returns><see langword="true"/> when every field matches and the carriers are the same instances.</returns>
    public bool Equals(KeyedHashObjectState? other) =>
        other is not null
        && Handle == other.Handle
        && Hierarchy == other.Hierarchy
        && ReferenceEquals(Name, other.Name)
        && ReferenceEquals(Data, other.Data)
        && ReferenceEquals(AuthPolicy, other.AuthPolicy)
        && ReferenceEquals(UserAuth, other.UserAuth)
        && ReferenceEquals(SeedValue, other.SeedValue)
        && ReferenceEquals(PublicArea, other.PublicArea)
        && ReferenceEquals(QualifiedName, other.QualifiedName)
        && NoDa == other.NoDa
        && UserWithAuth == other.UserWithAuth
        && IsDuplicable == other.IsDuplicable;

    /// <summary>
    /// Hashes the object's immutable identity fields, consistent with
    /// <see cref="Equals(KeyedHashObjectState)"/> without ever reading carrier content.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode() => HashCode.Combine(Handle, Hierarchy, NoDa, UserWithAuth, IsDuplicable);
}
