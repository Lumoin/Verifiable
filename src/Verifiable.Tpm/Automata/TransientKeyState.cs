using System;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The simulator's model of a loaded transient object: a signing key created by <c>TPM2_CreatePrimary()</c>
/// and addressed by a transient handle (most-significant octet <c>TPM_HT_TRANSIENT</c>, TPM 2.0 Library
/// Part 2, clause 7.2). It is the smallest object model the create-then-sign path needs — the retained
/// private key plus the fields a subsequent <c>TPM2_Sign()</c> depends on.
/// </summary>
/// <remarks>
/// <para>
/// Like <see cref="NvIndexState"/>, the key material is held as plain <see cref="ReadOnlyMemory{T}"/>
/// rather than pooled buffers: it is durable model state owned by the live automaton for the lifetime of
/// the simulated object, not hot wire-path memory. The private key is sensitive, exactly as an NV Index
/// authorization value is.
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
/// The permanent hierarchy handle the object was created under (TPM 2.0 Library Part 1, clause 16). Every
/// object this simulator creates today is a primary directly under a permanent hierarchy, so the hierarchy's
/// own Qualified Name is trivially its 4-octet big-endian handle value; retaining it here lets a later
/// <c>TPM2_Certify()</c> / <c>TPM2_Quote()</c> compute this object's real Qualified Name
/// (<see cref="TpmObjectName.ComputeQualifiedNameAsync"/>) instead of collapsing it to the plain Name.
/// </param>
/// <param name="KeyType">The key's algorithm (<c>TPM_ALG_ECC</c> or <c>TPM_ALG_RSA</c>), selecting the signing backend.</param>
/// <param name="Curve">The ECC curve the key lives on (unused for an RSA key).</param>
/// <param name="PrivateKey">The retained private key: an ECC scalar (unsigned big-endian at the curve field width) or an RSA private key in the backend's encoding.</param>
/// <param name="Name">
/// The object's Name — <c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c>, the 2-byte-nameAlg-prefixed digest (TPM 2.0
/// Library Part 1, clause 16). Retained at creation from the Name the by-products already computed, so a later
/// <c>TPM2_Certify()</c> can bind the certified object's Name into <c>TPMS_CERTIFY_INFO</c> without recomputing it.
/// Empty until the effect populates it (the storage-parent template retains no key material either).
/// </param>
/// <param name="Attributes">The object attributes (<c>TPMA_OBJECT</c>) carried in the public area.</param>
/// <param name="PublicPoint">
/// The object's exported public point in SEC1 uncompressed form (<c>0x04 ‖ X ‖ Y</c>) for an elliptic-curve key,
/// empty for an RSA key. A real TPM's loaded object carries its full public area (TPM 2.0 Library Part 1, clause
/// 24); the simulator retains the point so a later command that needs the object's public key — the ECDH secret
/// exchange of <c>TPM2_MakeCredential</c> / <c>TPM2_ActivateCredential</c> (Part 1, clause 24; Part 3, clauses 12.6
/// and 12.5) — can use it without reconstructing it from the private scalar.
/// </param>
public sealed record TransientKeyState(
    uint Handle,
    uint Hierarchy,
    TpmAlgIdConstants KeyType,
    TpmEccCurveConstants Curve,
    ReadOnlyMemory<byte> PrivateKey,
    ReadOnlyMemory<byte> Name,
    TpmaObject Attributes,
    ReadOnlyMemory<byte> PublicPoint);
