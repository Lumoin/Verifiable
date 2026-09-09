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
/// Part 1, clause 13, Table 9). Every object this simulator creates today is a primary directly under a permanent
/// hierarchy, so the hierarchy's own Qualified Name is trivially its 4-octet big-endian handle value;
/// retaining it here lets a later <c>TPM2_Certify()</c> / <c>TPM2_Quote()</c> compute this object's real
/// Qualified Name (<see cref="TpmObjectName.ComputeQualifiedNameAsync"/>) instead of collapsing it to the plain
/// Name.
/// </param>
/// <param name="KeyType">The key's algorithm (<c>TPM_ALG_ECC</c> or <c>TPM_ALG_RSA</c>), selecting the signing backend.</param>
/// <param name="Curve">The ECC curve the key lives on (unused for an RSA key).</param>
/// <param name="SigningScheme">
/// The key's own signing scheme, retained from the creation template's <c>TPMS_ECC_PARMS.scheme</c> /
/// <c>TPMS_RSA_PARMS.scheme</c> field (<c>TPMT_ECC_SCHEME</c> / <c>TPMT_RSA_SCHEME</c>, TPM 2.0 Library Part 2,
/// clauses 12.2.3.5/12.2.3.6, Table 229: "If the sign attribute of the key is SET, then this shall be a valid
/// signing scheme... If the key is a Storage Key, then this field shall be TPM_ALG_NULL"). <c>TPM2_SignDigest()</c>
/// and <c>TPM2_VerifyDigestSignature()</c> carry no <c>inScheme</c> of their own to consult, so this is the value
/// they apply directly (Part 3, clause 20.7.1: "The scheme of keyHandle must be a signing scheme that supports
/// signing a digest"). <see langword="null"/> for a key with no digest-capable signing scheme of its own — a
/// storage parent, an unrestricted ECDH/decrypt key, or any other NULL-scheme template — paired one-to-one with
/// <see cref="SigningSchemeHashAlg"/> being <see langword="null"/> too.
/// </param>
/// <param name="SigningSchemeHashAlg">
/// The hash algorithm <see cref="SigningScheme"/> signs under, from the same <c>TPMS_ECC_PARMS.scheme</c> /
/// <c>TPMS_RSA_PARMS.scheme</c> field's hash parameter (Table 229). <see langword="null"/> exactly when
/// <see cref="SigningScheme"/> is <see langword="null"/>; a digest presented to <c>TPM2_SignDigest()</c> must
/// match this algorithm's digest width (Part 3, clause 20.7.1).
/// </param>
/// <param name="KemKdfScheme">
/// The key's own KDF scheme, retained from the creation template's <c>TPMS_ECC_PARMS.kdf.scheme</c> field
/// (<c>TPMT_KDF_SCHEME</c>, TPM 2.0 Library Part 2, clause 12.2.3.5, Table 229 — v185's KEM admission gate:
/// "if the key is an unrestricted decryption TPM_ALG_ECDH key, an optional key derivation scheme. Shall be
/// NULL in all other cases (TPM_RC_KDF). If this field is not NULL, then this key can be used with
/// TPM2_Encapsulate() and TPM2_Decapsulate()"). Non-<see langword="null"/> is exactly the "is this a KEM
/// key" predicate <c>TPM2_Encapsulate()</c>/<c>TPM2_Decapsulate()</c> gate on (<c>TPM_RC_KEY</c> otherwise,
/// TPM 2.0 Library Part 3, clauses 14.10/14.11). <see langword="null"/> on every non-KEM key — a signing
/// key, a storage parent, or any other NULL-<c>kdf</c> template — paired one-to-one with
/// <see cref="KemKdfHashAlg"/> being <see langword="null"/> too.
/// </param>
/// <param name="KemKdfHashAlg">
/// The DHKEM's KDF hash algorithm, from the same <c>TPMS_ECC_PARMS.kdf.hashAlg</c> field (Table 229:
/// "scheme.details.ecdh.hashAlg is ignored, because kdf specifies all parameters of the KDF"). Together with
/// <see cref="TransientKeyState.Curve"/> this names the DHKEM suite (<c>DHKEM(curveID, kdf)</c> per
/// <see href="https://www.rfc-editor.org/rfc/rfc9180">RFC 9180</see>, TPM 2.0 Library Part 1, clause 44.4)
/// that <c>TPM2_Encapsulate()</c>/<c>TPM2_Decapsulate()</c> apply. <see langword="null"/> exactly when
/// <see cref="KemKdfScheme"/> is <see langword="null"/>.
/// </param>
/// <param name="PrivateKey">
/// The retained private key in an owned <see cref="PrivateKeyMemory"/> carrier: an ECC scalar (unsigned
/// big-endian at the curve field width) or an RSA private key in the backend's encoding. The dispose-immune
/// <see cref="TpmSimulatorState.EmptyPrivateKey"/> sentinel for a public-only object — one <c>TPM2_LoadExternal()</c>
/// loaded from <c>inPublic</c> alone, with no sensitive area (TPM 2.0 Library Part 3, clause 12.3.1) — never
/// <see langword="null"/>, matching every other "can be absent" field on this record (see
/// <see cref="IsPublicOnly"/>).
/// </param>
/// <param name="Name">
/// The object's Name (<c>TPM2B_NAME</c> over <c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c>, TPM 2.0 Library Part 1,
/// clause 13, Table 9), in an owned pooled carrier. Retained at creation from the Name the by-products already computed,
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
/// the dispose-immune <see cref="TpmSimulatorState.EmptyPublicPoint"/> sentinel for an RSA key, in an owned
/// pooled <see cref="EncodedEcPoint"/> carrier — the cryptography surface's own semantic carrier for exactly
/// this shape (<c>0x04 || X || Y</c>, tagged from <see cref="TpmCryptographicProjections.ToExchangePublicKeyTag"/>'s
/// <c>Purpose.Exchange</c>/<c>EncodingScheme.EcUncompressed</c> family). The object's spec-exact public point is
/// the <c>TPMS_ECC_POINT</c> already carried in <see cref="PublicArea"/>'s <c>Unique.Ecc</c> (Part 2, clause
/// 11.2.5.2, Table 198: two separate <c>TPM2B_ECC_PARAMETER</c> buffers, clause 11.2.5.1, Table 197); this field
/// is that point's cached SEC1 view — retained so a later command that needs the object's public key without
/// re-deriving it from the private scalar — the ECDH secret exchange of <c>TPM2_MakeCredential</c> /
/// <c>TPM2_ActivateCredential</c> (Part 1, clause 21; Part 3, clauses 12.6 and 12.5) chief among them — can read
/// it directly (<see cref="EncodedEcPoint.AsReadOnlySpan"/>/<c>AsReadOnlyMemory</c>) rather than re-splitting
/// <see cref="PublicArea"/>'s coordinates on every use. Owned like <see cref="AuthValue"/>: adopted at the
/// installing transition, DEEP-COPIED on persist so the transient and persistent entries never co-own the
/// buffer, and released on eviction.
/// </param>
/// <param name="PublicModulus">
/// The object's exported public modulus for an RSA key in an owned pooled <c>TPM2B_PUBLIC_KEY_RSA</c> carrier
/// (TPM 2.0 Library Part 2, clause 11.2.4.6, Table 194) — the same buffer type an RSA <c>TPMT_PUBLIC</c>'s
/// <c>unique</c> member carries on the wire — and the dispose-immune <see cref="Tpm2bPublicKeyRsa.Empty"/> for
/// an elliptic-curve key. Retained only by the RSA storage-parent effect (a standard RSA endorsement key, TCG EK
/// Credential Profile, Annex B.3.3, Template L-1), so an RSA-OAEP secret-transport command can use it without
/// reconstructing it from the private key; an RSA signing key's exported modulus is not retained here (it needs
/// no OAEP transport). The public exponent is not carried alongside it: every template this simulator builds
/// passes <c>exponent = 0</c> (Part 2, Table 228's wire convention for the default 2^16+1), so a consumer of
/// <see cref="PublicModulus"/> assumes the default exponent rather than threading a fourth field through — a
/// documented modelling simplification, not a spec-mandated one. Owned exactly like <see cref="AuthValue"/>:
/// rented in the creation effect, adopted at the installing transition, deep-copied on persist so the transient
/// and persistent entries never co-own it, and released on eviction.
/// </param>
/// <param name="AuthPolicy">
/// The authorization policy digest carried in the object's public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library
/// Part 2, clause 10.3.2, Table 90; the policy formula itself is Part 1, clause 16.7), in an owned pooled
/// carrier, the dispose-immune <see cref="Tpm2bDigest.Empty"/> when the object is authorized by its authValue
/// alone. Durable model state like <see cref="PrivateKey"/> and <see cref="Name"/>, retained so a USER-role use
/// of the object (for example <c>TPM2_ActivateCredential()</c>'s <c>keyHandle</c>) can be gated on a policy
/// session reproducing it. Owned exactly like <see cref="AuthValue"/>: rented at parse and carried through the
/// creation effect, adopted at the installing transition, deep-copied on persist so the transient and
/// persistent entries never co-own it, and released on eviction.
/// </param>
/// <param name="AuthValue">
/// The object's authorization value (<c>userAuth</c>) in an owned, pinned <see cref="Tpm2bAuth"/> carrier, taken
/// from the <c>inSensitive</c> the creation carried (TPM 2.0 Library Part 1, clause 16.6.4). Retained so a
/// USER-role authorization of the object can be VERIFIED: an HMAC session at a command's signHandle slot
/// (<c>TPM2_NV_Certify()</c>) folds it into the session HMAC key exactly as an NV Index's own authValue is
/// folded (clause 16.6.5), and a session bound to this object folds it into its session key (clause 16.6.10).
/// The dispose-immune <see cref="Tpm2bAuth.Empty"/> sentinel for an object created with an empty authValue.
/// Owned like <see cref="PrivateKey"/>: rented in the creation effect, adopted at the installing transition,
/// deep-copied on persist so the transient and persistent entries never co-own it, and released on eviction.
/// </param>
/// <param name="SeedValue">
/// The symmetric protection seed in the object's sensitive area (<c>TPMT_SENSITIVE.seedValue</c>, TPM 2.0
/// Library Part 2, clause 12.3.2, Table 240), sized to the object's nameAlg digest and generated at creation
/// for a storage parent (Part 1, Clause 24.7.4). It keys the Protected Storage wrap of every child created
/// under this parent: the child blob's symmetric key and HMAC key both derive from it through KDFa with the
/// "STORAGE" and "INTEGRITY" labels (Part 1, Clause 19, equations 33 and 35). Sensitive model state that never
/// leaves the simulator; the dispose-immune <see cref="Tpm2bDigest.Empty"/> for a key that parents nothing (a
/// signing key). Owned like <see cref="AuthValue"/>: rented in the creation effect, adopted at the installing
/// transition, deep-copied on persist so the transient and persistent entries never co-own it, and released on
/// eviction.
/// </param>
/// <param name="PublicArea">
/// The object's full public area (<c>TPM2B_PUBLIC</c>, TPM 2.0 Library Part 2, clause 12.2.5, Table 236) in an
/// owned carrier — "a loaded object" carries it so <c>TPM2_ReadPublic()</c> can "allow access to the public
/// area of a loaded object" (Part 3, clause 12.4.1) octet for octet, and it is the very marshaled
/// <c>TPMT_PUBLIC</c> <see cref="Name"/> was hashed over. A wire-exact copy of the <c>outPublic</c> the creation
/// effect exports: the response frames and releases its own instance, so this record owns a second one on the
/// eviction lifecycle, deep-copied on persist so the transient and persistent entries never co-own it.
/// </param>
/// <param name="QualifiedName">
/// The object's Qualified Name (<c>TPM2B_NAME</c>, TPM 2.0 Library Part 1, clause 23.5: "the digest of all of
/// the Names of all of the ancestor keys back to the handle of the Primary Seed"), computed once at creation —
/// for a primary, <c>H_nameAlg(hierarchy handle ‖ Name)</c>, since "both the Name and Qualified Name for a
/// Primary Seed are the handle of the Primary Seed" — in an owned pooled carrier on the same lifecycle as
/// <see cref="Name"/>. Answered verbatim by <c>TPM2_ReadPublic()</c> (Part 3, clause 12.4, Table 25) and the
/// ancestor term a child loaded under this object chains its own Qualified Name from
/// (<see cref="TpmObjectName.ComputeQualifiedNameAsync"/>); the dispose-immune <see cref="Tpm2bName.Empty"/>
/// stands in until the creation effect populates it alongside <see cref="Name"/>.
/// </param>
public sealed record TransientKeyState(
    TpmiDhObject Handle,
    TpmiRhHierarchy Hierarchy,
    TpmiAlgPublic KeyType,
    TpmiEccCurve Curve,
    TpmiAlgSigScheme? SigningScheme,
    TpmiAlgHash? SigningSchemeHashAlg,
    TpmiAlgKdf? KemKdfScheme,
    TpmiAlgHash? KemKdfHashAlg,
    PrivateKeyMemory PrivateKey,
    Tpm2bName Name,
    TpmaObject Attributes,
    EncodedEcPoint PublicPoint,
    Tpm2bPublicKeyRsa PublicModulus,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth AuthValue,
    Tpm2bDigest SeedValue,
    Tpm2bPublic PublicArea,
    Tpm2bName QualifiedName): IDisposable
{
    /// <summary>
    /// Gets a value indicating whether this object is dictionary-attack protected: an authorization failure
    /// against it feeds the lockout counter and is blocked in lockout, unless <see cref="TpmaObject.NO_DA"/> is
    /// set in <see cref="Attributes"/> (TPM 2.0 Library Part 2, clause 8.3.3.10; Part 1, clause 16.8.1: "The
    /// authValue for an object receives DA protection unless the object's noDA attribute is SET"), mirroring
    /// <see cref="NvIndexState.IsDaProtected"/> and <see cref="KeyedHashObjectState.IsDaProtected"/>.
    /// </summary>
    public bool IsDaProtected => (Attributes & TpmaObject.NO_DA) == 0;

    /// <summary>
    /// Gets a value indicating whether this object carries no sensitive area — loaded by
    /// <c>TPM2_LoadExternal()</c> from <c>inPublic</c> alone (TPM 2.0 Library Part 3, clause 12.3.1: "The
    /// command allows loading of a public area or both a public and sensitive area"). Every <c>@</c>-decorated
    /// authorizing use of such an object is refused <c>TPM_RC_AUTH_UNAVAILABLE</c> (Part 3, clause 5.6, check
    /// 1: "The public and sensitive portions of the object shall be present on the TPM"); the public-key
    /// operations that need no authorization keep working. Reads <see cref="PrivateKey"/>'s own presence
    /// predicate rather than a second, independently-settable field, so the two can never disagree.
    /// </summary>
    public bool IsPublicOnly => PrivateKey.IsEmpty;

    /// <summary>
    /// Releases the object's owned carriers — its private key, Name, authorization policy digest, authorization
    /// value, exported public point, exported public modulus, protection seed, public area, and Qualified Name.
    /// Called when the object leaves its dictionary for good (<c>TPM2_FlushContext()</c>,
    /// <c>TPM2_EvictControl()</c>'s evict arm, <c>TPM2_Clear()</c>, hierarchy disable, simulator teardown). A
    /// persisted copy owns separate deep-copied carriers, so disposing one entry never touches the other; the
    /// empty-authValue, empty-modulus, empty-point, and empty-Name sentinels are dispose-immune.
    /// </summary>
    public void Dispose()
    {
        PrivateKey.Dispose();
        Name.Dispose();
        AuthPolicy.Dispose();
        AuthValue.Dispose();
        PublicPoint.Dispose();
        PublicModulus.Dispose();
        SeedValue.Dispose();
        PublicArea.Dispose();
        QualifiedName.Dispose();
    }

    /// <summary>
    /// Value equality with OWNERSHIP identity for the owned carriers: two records are equal only when they
    /// share the same <see cref="PrivateKey"/>, <see cref="Name"/>, <see cref="AuthPolicy"/>,
    /// <see cref="AuthValue"/>, <see cref="PublicPoint"/>, <see cref="PublicModulus"/>, <see cref="SeedValue"/>,
    /// <see cref="PublicArea"/>, and <see cref="QualifiedName"/> instances — reference comparison
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
        && SigningScheme == other.SigningScheme
        && SigningSchemeHashAlg == other.SigningSchemeHashAlg
        && KemKdfScheme == other.KemKdfScheme
        && KemKdfHashAlg == other.KemKdfHashAlg
        && ReferenceEquals(PrivateKey, other.PrivateKey)
        && ReferenceEquals(Name, other.Name)
        && Attributes == other.Attributes
        && ReferenceEquals(PublicPoint, other.PublicPoint)
        && ReferenceEquals(PublicModulus, other.PublicModulus)
        && ReferenceEquals(AuthPolicy, other.AuthPolicy)
        && ReferenceEquals(AuthValue, other.AuthValue)
        && ReferenceEquals(SeedValue, other.SeedValue)
        && ReferenceEquals(PublicArea, other.PublicArea)
        && ReferenceEquals(QualifiedName, other.QualifiedName);

    /// <summary>
    /// Hashes the object's immutable identity fields, consistent with
    /// <see cref="Equals(TransientKeyState)"/> without ever reading carrier content.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode() =>
        HashCode.Combine(Handle, Hierarchy, KeyType, Curve, SigningScheme, SigningSchemeHashAlg, Attributes, HashCode.Combine(KemKdfScheme, KemKdfHashAlg));
}
