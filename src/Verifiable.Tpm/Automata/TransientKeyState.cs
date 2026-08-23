using System;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The simulator's model of a loaded transient object: a signing key created by <c>TPM2_CreatePrimary()</c>
/// and addressed by a transient handle (most-significant octet <c>TPM_HT_TRANSIENT</c>, TPM 2.0 Library
/// Part 2, clause 7.2). It is the smallest object model the create-then-sign path needs — the retained
/// private key plus the fields a subsequent <c>TPM2_Sign()</c> depends on.
/// </summary>
/// <remarks>
/// <para>
/// The private key lives in a pinned, zero-on-dispose <see cref="PrivateKeyMemory"/> carrier the record
/// owns: it is rented in the <c>TPM2_CreatePrimary()</c> effect that generates the key (copied out of the
/// backend's own scoped carrier), its ownership transfers into this record at the installing transition,
/// and it is disposed when the object is evicted (<c>TPM2_FlushContext()</c>, <c>TPM2_EvictControl()</c>'s
/// evict arm, <c>TPM2_Clear()</c>, hierarchy disable, simulator teardown). A persisted copy owns its own
/// deep-copied carrier, so the transient and persistent entries never co-own a buffer. The Name, the
/// authorization policy digest, the authorization value, and the exported public modulus ride owned pooled
/// carriers of their own on the same lifecycle.
/// </para>
/// <para>
/// A real TPM derives a primary key deterministically from the hierarchy's primary seed; the simulator
/// instead retains a backend-generated key, which is sufficient to model creation, export, and signing.
/// <see cref="KeyType"/> selects the signing backend a subsequent <c>TPM2_Sign()</c> drives — elliptic-curve
/// (over <see cref="Curve"/>) or RSA — and which encoding <see cref="PrivateKey"/> carries.
/// </para>
/// </remarks>
/// <param name="Handle">The transient handle assigned to the object.</param>
/// <param name="Hierarchy">
/// The permanent hierarchy handle the object was created under (<c>TPMI_RH_HIERARCHY</c>, TPM 2.0 Library
/// Part 1, clause 14, Table 6). Every object this simulator creates today is a primary directly under a permanent
/// hierarchy, so the hierarchy's own Qualified Name is trivially its 4-octet big-endian handle value;
/// retaining it here lets a later <c>TPM2_Certify()</c> / <c>TPM2_Quote()</c> compute this object's real
/// Qualified Name (<see cref="TpmObjectName.ComputeQualifiedNameAsync"/>) instead of collapsing it to the plain
/// Name.
/// </param>
/// <param name="KeyType">The key's algorithm (<c>TPM_ALG_ECC</c> or <c>TPM_ALG_RSA</c>), selecting the signing backend.</param>
/// <param name="Curve">The ECC curve the key lives on (unused for an RSA key).</param>
/// <param name="PrivateKey">The retained private key in an owned <see cref="PrivateKeyMemory"/> carrier: an ECC scalar (unsigned big-endian at the curve field width) or an RSA private key in the backend's encoding.</param>
/// <param name="Name">
/// The object's Name (<c>TPM2B_NAME</c> over <c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c>, TPM 2.0 Library Part 1,
/// clause 14, Table 6), in an owned pooled carrier. Retained at creation from the Name the by-products already computed,
/// so a later <c>TPM2_Certify()</c> can bind the certified object's Name into <c>TPMS_CERTIFY_INFO</c> without
/// recomputing it. Owned exactly like <see cref="AuthValue"/>: adopted at the installing transition,
/// deep-copied on persist so the transient and persistent entries never co-own it, and released on eviction;
/// the empty <see cref="Tpm2bName.Empty"/> is dispose-immune, standing in until the effect populates it (the
/// storage-parent template retains no key material either).
/// </param>
/// <param name="Attributes">
/// The object attributes (<c>TPMA_OBJECT</c>) carried in the public area, retained verbatim from the creation
/// template. Its <see cref="TpmaObject.USER_WITH_AUTH"/> bit is what every USER-role authorization of this
/// object gates on: CLEAR means only a policy session may authorize the USER role, so a password or HMAC
/// session at such a slot is refused with <c>TPM_RC_POLICY_FAIL</c> before any credential is evaluated
/// (TPM 2.0 Library Part 3, clause 5.6, check 7.1); its <see cref="TpmaObject.NO_DA"/> bit drives
/// <see cref="IsDaProtected"/>.
/// </param>
/// <param name="PublicPoint">
/// The object's exported public point in SEC1 uncompressed form (<c>0x04 ‖ X ‖ Y</c>) for an elliptic-curve key,
/// empty for an RSA key. A real TPM's loaded object carries its full public area (TPM 2.0 Library Part 1, clause
/// 24); the simulator retains the point so a later command that needs the object's public key — the ECDH secret
/// exchange of <c>TPM2_MakeCredential</c> / <c>TPM2_ActivateCredential</c> (Part 1, clause 24; Part 3, clauses 12.6
/// and 12.5) — can use it without reconstructing it from the private scalar. It is deliberately NOT the wire
/// form of any Part 2 structure and so takes no <c>TPM2B</c> type: a <c>TPMS_ECC_POINT</c> frames X and Y as two
/// separate <c>TPM2B_ECC_PARAMETER</c> buffers (Part 2, clause 11.2.5.1, Table 196; the point itself is <c>TPMS_ECC_POINT</c>, clause 11.2.5.2, Table 197), whereas this slot holds the
/// SEC1 uncompressed concatenation the elliptic-curve backends consume. The semantic public-key carrier that
/// would type it belongs to the cryptography surface, not to the TPM structure set.
/// </param>
/// <param name="PublicModulus">
/// The object's exported public modulus for an RSA key in an owned pooled <c>TPM2B_PUBLIC_KEY_RSA</c> carrier
/// (TPM 2.0 Library Part 2, clause 11.2.4.5, Table 193) — the same buffer type an RSA <c>TPMT_PUBLIC</c>'s
/// <c>unique</c> member carries on the wire — and the dispose-immune <see cref="Tpm2bPublicKeyRsa.Empty"/> for
/// an elliptic-curve key. Retained only by the RSA storage-parent effect (a standard RSA endorsement key, TCG EK
/// Credential Profile, Annex B.3.3, Template L-1), so an RSA-OAEP secret-transport command can use it without
/// reconstructing it from the private key; an RSA signing key's exported modulus is not retained here (it needs
/// no OAEP transport). The public exponent is not carried alongside it: every template this simulator builds
/// passes <c>exponent = 0</c> (Part 2, Table 215's wire convention for the default 2^16+1), so a consumer of
/// <see cref="PublicModulus"/> assumes the default exponent rather than threading a fourth field through — a
/// documented modelling simplification, not a spec-mandated one. Owned exactly like <see cref="AuthValue"/>:
/// rented in the creation effect, adopted at the installing transition, deep-copied on persist so the transient
/// and persistent entries never co-own it, and released on eviction.
/// </param>
/// <param name="AuthPolicy">
/// The authorization policy digest carried in the object's public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library
/// Part 2, clause 10.4.2, Table 92; the policy formula itself is Part 1, clause 17.7), in an owned pooled
/// carrier, the dispose-immune <see cref="Tpm2bDigest.Empty"/> when the object is authorized by its authValue
/// alone. Durable model state like <see cref="PrivateKey"/> and <see cref="Name"/>, retained so a USER-role use
/// of the object (for example <c>TPM2_ActivateCredential()</c>'s <c>keyHandle</c>) can be gated on a policy
/// session reproducing it. Owned exactly like <see cref="AuthValue"/>: rented at parse and carried through the
/// creation effect, adopted at the installing transition, deep-copied on persist so the transient and
/// persistent entries never co-own it, and released on eviction.
/// </param>
/// <param name="AuthValue">
/// The object's authorization value (<c>userAuth</c>) in an owned, pinned <see cref="Tpm2bAuth"/> carrier, taken
/// from the <c>inSensitive</c> the creation carried (TPM 2.0 Library Part 1, clause 17.6.4). Retained so a
/// USER-role authorization of the object can be VERIFIED: an HMAC session at a command's signHandle slot
/// (<c>TPM2_NV_Certify()</c>) folds it into the session HMAC key exactly as an NV Index's own authValue is
/// folded (clause 17.6.5), and a session bound to this object folds it into its session key (clause 17.6.10).
/// The dispose-immune <see cref="Tpm2bAuth.Empty"/> sentinel for an object created with an empty authValue.
/// Owned like <see cref="PrivateKey"/>: rented in the creation effect, adopted at the installing transition,
/// deep-copied on persist so the transient and persistent entries never co-own it, and released on eviction.
/// </param>
public sealed record TransientKeyState(
    TpmiDhObject Handle,
    TpmiRhHierarchy Hierarchy,
    TpmiAlgPublic KeyType,
    TpmiEccCurve Curve,
    PrivateKeyMemory PrivateKey,
    Tpm2bName Name,
    TpmaObject Attributes,
    ReadOnlyMemory<byte> PublicPoint,
    Tpm2bPublicKeyRsa PublicModulus,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth AuthValue): IDisposable
{
    /// <summary>
    /// Gets a value indicating whether this object is dictionary-attack protected: an authorization failure
    /// against it feeds the lockout counter and is blocked in lockout, unless <see cref="TpmaObject.NO_DA"/> is
    /// set in <see cref="Attributes"/> (TPM 2.0 Library Part 2, clause 8.3.3.10; Part 1, clause 17.8.1: "The
    /// authValue for an object receives DA protection unless the object's noDA attribute is SET"), mirroring
    /// <see cref="NvIndexState.IsDaProtected"/> and <see cref="SealedObjectState.IsDaProtected"/>.
    /// </summary>
    public bool IsDaProtected => (Attributes & TpmaObject.NO_DA) == 0;

    /// <summary>
    /// Releases the object's owned carriers — its private key, Name, authorization policy digest, authorization
    /// value, and exported public modulus. Called when the object leaves its dictionary for good
    /// (<c>TPM2_FlushContext()</c>, <c>TPM2_EvictControl()</c>'s evict
    /// arm, <c>TPM2_Clear()</c>, hierarchy disable, simulator teardown). A persisted copy owns separate
    /// deep-copied carriers, so disposing one entry never touches the other; the empty-authValue and
    /// empty-modulus sentinels are dispose-immune.
    /// </summary>
    public void Dispose()
    {
        PrivateKey.Dispose();
        Name.Dispose();
        AuthPolicy.Dispose();
        AuthValue.Dispose();
        PublicModulus.Dispose();
    }

    /// <summary>
    /// Value equality with OWNERSHIP identity for the owned carriers: two records are equal only when they
    /// share the same <see cref="PrivateKey"/>, <see cref="Name"/>, <see cref="AuthPolicy"/>,
    /// <see cref="AuthValue"/>, and <see cref="PublicModulus"/> instances — reference comparison
    /// preserves the object-identity semantics the fields had as plain memory and never reads carrier content,
    /// so a superseded or disposed snapshot cannot throw here (see
    /// <see cref="NvIndexState.Equals(NvIndexState)"/> for the shared rationale).
    /// </summary>
    /// <param name="other">The record to compare against.</param>
    /// <returns><see langword="true"/> when every field matches and the carriers are the same instances.</returns>
    public bool Equals(TransientKeyState? other) =>
        other is not null
        && Handle == other.Handle
        && Hierarchy == other.Hierarchy
        && KeyType == other.KeyType
        && Curve == other.Curve
        && ReferenceEquals(PrivateKey, other.PrivateKey)
        && ReferenceEquals(Name, other.Name)
        && Attributes == other.Attributes
        && PublicPoint.Equals(other.PublicPoint)
        && ReferenceEquals(PublicModulus, other.PublicModulus)
        && ReferenceEquals(AuthPolicy, other.AuthPolicy)
        && ReferenceEquals(AuthValue, other.AuthValue);

    /// <summary>
    /// Hashes the object's immutable identity fields, consistent with
    /// <see cref="Equals(TransientKeyState)"/> without ever reading carrier content.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode() => HashCode.Combine(Handle, Hierarchy, KeyType, Curve, Attributes);
}
