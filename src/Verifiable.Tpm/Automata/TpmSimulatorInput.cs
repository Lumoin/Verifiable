using System;
using System.Buffers;
using System.Collections.Immutable;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The input alphabet of the TPM simulator's pushdown automaton. Inputs arrive from three sources: the
/// platform (<see cref="TpmInitSignal"/>), the command transport (the command-arrived records, parsed
/// from the wire by <see cref="TpmSimulator"/> before they enter the automaton), and the effectful
/// loop (the action-result records, such as <see cref="TpmRandomGenerated"/>, fed back after a
/// <see cref="TpmAction"/> has been executed by a backend).
/// </summary>
public abstract record TpmSimulatorInput;

/// <summary>
/// The platform <c>_TPM_Init</c> indication (TPM 2.0 Library Part 1, clause 10.2.2). It is not a TPM
/// command and produces no response; it moves the device into <see cref="TpmLifecyclePhase.Initializing"/>
/// and is the only exit from <see cref="TpmLifecyclePhase.FailureMode"/>.
/// </summary>
public sealed record TpmInitSignal: TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Startup()</c> command (TPM 2.0 Library Part 1, clause 10.2.3).
/// </summary>
/// <param name="StartupType">The startup type argument (<c>TPM_SU_CLEAR</c> or <c>TPM_SU_STATE</c>).</param>
public sealed record TpmStartupRequested(TpmSuConstants StartupType): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Shutdown()</c> command (TPM 2.0 Library Part 1, clause 10.2.4).
/// </summary>
/// <param name="ShutdownType">The shutdown type argument (<c>TPM_SU_CLEAR</c> or <c>TPM_SU_STATE</c>).</param>
public sealed record TpmShutdownRequested(TpmSuConstants ShutdownType): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_SelfTest()</c> command (TPM 2.0 Library Part 1, clause 10.3).
/// </summary>
/// <param name="IsFullTest">
/// Whether a full self-test of all algorithms was requested. The lifecycle skeleton does not track
/// per-algorithm test state, so this only records the request.
/// </param>
public sealed record TpmSelfTestRequested(bool IsFullTest): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_GetTestResult()</c> command (TPM 2.0 Library Part 1, clause 10.3). Permitted both
/// operationally and in <see cref="TpmLifecyclePhase.FailureMode"/>.
/// </summary>
public sealed record TpmTestResultRequested: TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_GetRandom()</c> command (TPM 2.0 Library Part 3, clause 16.1). Permitted only while
/// operational; on success it draws random octets through the action layer.
/// </summary>
/// <param name="BytesRequested">
/// The number of octets the caller requested. The transition clamps this to the largest digest the
/// simulated TPM can return before declaring the RNG action (clause 16.1: requesting more than fits
/// in a <c>TPM2B_DIGEST</c> is not an error — the TPM returns only what fits).
/// </param>
public sealed record TpmGetRandomRequested(ushort BytesRequested): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_GetCapability()</c> command (TPM 2.0 Library Part 3, clause 30.2). Permitted while
/// operational and in <see cref="TpmLifecyclePhase.FailureMode"/> (Part 1, clause 10.4).
/// </summary>
/// <param name="Capability">The capability category to query.</param>
/// <param name="Property">The first property (tag) to return.</param>
/// <param name="PropertyCount">The maximum number of properties to return.</param>
public sealed record TpmGetCapabilityRequested(TpmCapConstants Capability, uint Property, uint PropertyCount): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_NV_DefineSpace()</c> command (TPM 2.0 Library Part 3, clause 31.3). Reserves space for an
/// NV Index with the given attributes and authorization value, authorized by the owner hierarchy. Only
/// the index-defining fields the simulator models are carried; the Name algorithm and access policy are
/// consumed during parsing but not retained in this slice.
/// </summary>
/// <param name="AuthHandle">The provisioning hierarchy authorizing the definition (<c>TPM_RH_OWNER</c> in this slice).</param>
/// <param name="OwnerAuthSupplied">The authorization value the caller supplied for the provisioning hierarchy (the password session's plaintext authValue).</param>
/// <param name="NvIndex">The handle of the NV Index to define.</param>
/// <param name="Attributes">The Index attributes (<c>TPMA_NV</c>), whose <c>TPMA_NV_NO_DA</c> bit decides dictionary-attack protection.</param>
/// <param name="IndexAuth">The authorization value assigned to the new Index.</param>
/// <param name="DataSize">The size in octets of the Index data area.</param>
public sealed record TpmNvDefineSpaceRequested(
    uint AuthHandle,
    ReadOnlyMemory<byte> OwnerAuthSupplied,
    uint NvIndex,
    TpmaNv Attributes,
    ReadOnlyMemory<byte> IndexAuth,
    ushort DataSize): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_NV_Read()</c> command (TPM 2.0 Library Part 3, clause 31.13). Reads data from an NV Index
/// after authorizing against it. This slice models Index authorization (the authorization handle equals
/// the Index itself) and owner authorization (<c>TPM_RH_OWNER</c>, gated on <c>TPMA_NV_OWNERREAD</c>);
/// policy-authorized reads arrive later.
/// </summary>
/// <param name="AuthHandle">The authorization handle (<c>TPMI_RH_NV_AUTH</c>); for Index authorization this equals <paramref name="NvIndex"/>, or <c>TPM_RH_OWNER</c> for the owner arm.</param>
/// <param name="NvIndex">The NV Index to read.</param>
/// <param name="AuthSupplied">The authorization value the caller supplied (the password session's plaintext authValue), compared against the Index authValue or the owner authValue.</param>
/// <param name="Size">The number of octets requested.</param>
/// <param name="Offset">The octet offset into the Index data area.</param>
public sealed record TpmNvReadRequested(
    uint AuthHandle,
    uint NvIndex,
    ReadOnlyMemory<byte> AuthSupplied,
    ushort Size,
    ushort Offset): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_NV_Write()</c> command (TPM 2.0 Library Part 3, clause 31.7). Writes data to an NV Index at
/// an offset after authorizing against it, then sets <c>TPMA_NV_WRITTEN</c>. This slice models Index
/// authorization (the authorization handle is the Index itself); owner- and policy-authorized writes
/// arrive later, mirroring <see cref="TpmNvReadRequested"/>.
/// </summary>
/// <param name="AuthHandle">The authorization handle (<c>TPMI_RH_NV_AUTH</c>); for Index authorization this equals <paramref name="NvIndex"/>.</param>
/// <param name="NvIndex">The NV Index to write.</param>
/// <param name="AuthSupplied">The authorization value the caller supplied (the password session's plaintext authValue), compared against the Index authValue.</param>
/// <param name="Data">The octets to write (<c>TPM2B_MAX_NV_BUFFER</c>), already copied into durable memory during parsing.</param>
/// <param name="Offset">The octet offset into the Index data area at which to write.</param>
public sealed record TpmNvWriteRequested(
    uint AuthHandle,
    uint NvIndex,
    ReadOnlyMemory<byte> AuthSupplied,
    ReadOnlyMemory<byte> Data,
    ushort Offset): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_NV_UndefineSpace()</c> command (TPM 2.0 Library Part 3, clause 31.4). Removes an NV Index
/// definition and frees its handle. Owner authorization is modelled; the policy-delete variant
/// (<c>TPM2_NV_UndefineSpaceSpecial()</c>) is not.
/// </summary>
/// <param name="AuthHandle">The provisioning hierarchy authorizing the removal (<c>TPM_RH_OWNER</c> in this slice).</param>
/// <param name="NvIndex">The NV Index to undefine.</param>
/// <param name="AuthSupplied">The authorization value the caller supplied (the password session's plaintext authValue), compared against the owner authValue.</param>
public sealed record TpmNvUndefineSpaceRequested(
    uint AuthHandle,
    uint NvIndex,
    ReadOnlyMemory<byte> AuthSupplied): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_NV_Increment()</c> command (TPM 2.0 Library Part 3, clause 31.8). Increments an NV Counter
/// Index's 8-octet value by one after authorizing against it. This slice models Index authorization (the
/// authorization handle is the Index itself) and owner authorization, mirroring
/// <see cref="TpmNvWriteRequested"/>; policy- and platform-authorized increments arrive later.
/// </summary>
/// <param name="AuthHandle">The authorization handle (<c>TPMI_RH_NV_AUTH</c>); for Index authorization this equals <paramref name="NvIndex"/>, or <c>TPM_RH_OWNER</c> for the owner arm.</param>
/// <param name="NvIndex">The NV Counter Index to increment.</param>
/// <param name="AuthSupplied">The authorization value the caller supplied (the password session's plaintext authValue), compared against the Index authValue or the owner authValue.</param>
public sealed record TpmNvIncrementRequested(
    uint AuthHandle,
    uint NvIndex,
    ReadOnlyMemory<byte> AuthSupplied): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_EvictControl()</c> command (TPM 2.0 Library Part 3, clause 28.5). Persists a loaded transient
/// object to a persistent handle, or evicts a persistent object addressed by that handle.
/// </summary>
/// <param name="AuthHandle">The provisioning hierarchy authorizing the operation (<c>TPM_RH_OWNER</c> in this slice).</param>
/// <param name="ObjectHandle">The transient object to persist, or the persistent handle to evict.</param>
/// <param name="PersistentHandle">The persistent handle to assign (when persisting) or evict (when <paramref name="ObjectHandle"/> is already persistent).</param>
public sealed record TpmEvictControlRequested(
    uint AuthHandle,
    uint ObjectHandle,
    uint PersistentHandle): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmRngAction"/>: the random octets produced by the RNG
/// backend, fed back into the automaton by the effectful loop so the transition can frame the
/// <c>TPM2_GetRandom()</c> response. This input is internal to the effect loop and never arrives from
/// the command transport.
/// </summary>
/// <param name="Bytes">
/// The pooled buffer holding the produced octets. Ownership flows to the <see cref="TpmRandomResponse"/>
/// the transition produces and is released by <see cref="TpmSimulator"/> once the response is framed.
/// </param>
/// <param name="Length">The number of valid octets in <paramref name="Bytes"/> (the clamped count).</param>
public sealed record TpmRandomGenerated(IMemoryOwner<byte> Bytes, int Length): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_CreatePrimary()</c> command (TPM 2.0 Library Part 3, clause 24.1). Creates a primary signing
/// key in a hierarchy and returns its public area. Only the template fields the simulator's ECC signing
/// model carries are retained; the sensitive area, outsideInfo, and creation PCR selection are consumed
/// during parsing but not modelled.
/// </summary>
/// <param name="Hierarchy">The hierarchy authorizing the creation (<c>TPM_RH_OWNER</c> in this slice).</param>
/// <param name="NameAlg">The Name algorithm carried in the public area (the hash whose digest forms the object Name).</param>
/// <param name="Attributes">The object attributes (<c>TPMA_OBJECT</c>) the template requests, echoed into the exported public area.</param>
/// <param name="Curve">The ECC curve the key is generated on.</param>
/// <param name="SchemeHashAlg">The ECDSA signing scheme's hash algorithm.</param>
/// <param name="AuthPolicy">The authorization policy digest carried in the template (empty when the key is authorized by its authValue alone), re-emitted into the exported public area.</param>
public sealed record TpmCreatePrimaryRequested(
    uint Hierarchy,
    TpmAlgIdConstants NameAlg,
    TpmaObject Attributes,
    TpmEccCurveConstants Curve,
    TpmAlgIdConstants SchemeHashAlg,
    ReadOnlyMemory<byte> AuthPolicy): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_CreatePrimary()</c> command for an RSA signing key (TPM 2.0 Library Part 3, clause 24.1) — the
/// RSA counterpart of <see cref="TpmCreatePrimaryRequested"/>. Only the template fields the simulator's RSA
/// signing model carries are retained.
/// </summary>
/// <param name="Hierarchy">The hierarchy authorizing the creation (<c>TPM_RH_OWNER</c> in this slice).</param>
/// <param name="NameAlg">The Name algorithm carried in the public area (the hash whose digest forms the object Name).</param>
/// <param name="Attributes">The object attributes (<c>TPMA_OBJECT</c>) the template requests, echoed into the exported public area.</param>
/// <param name="KeyBits">The RSA modulus size in bits the template requests.</param>
/// <param name="Scheme">The RSA signing scheme carried in the template.</param>
/// <param name="AuthPolicy">The authorization policy digest carried in the template (empty when the key is authorized by its authValue alone), re-emitted into the exported public area.</param>
public sealed record TpmCreateRsaPrimaryRequested(
    uint Hierarchy,
    TpmAlgIdConstants NameAlg,
    TpmaObject Attributes,
    ushort KeyBits,
    TpmtRsaScheme Scheme,
    ReadOnlyMemory<byte> AuthPolicy): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Sign()</c> command (TPM 2.0 Library Part 3, clause 20.2) over an externally-computed digest
/// with a NULL validation ticket. Signs the digest with a loaded transient signing key.
/// </summary>
/// <param name="KeyHandle">The handle of the signing key (a transient object created by <c>TPM2_CreatePrimary()</c>).</param>
/// <param name="Digest">The pre-computed digest to sign (copied into durable model memory).</param>
/// <param name="SignatureScheme">The signing scheme (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm, reported back inside the signature.</param>
public sealed record TpmSignRequested(
    uint KeyHandle,
    ReadOnlyMemory<byte> Digest,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants SchemeHashAlg): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmCreateEccKeyAction"/>: the exported public area and the durable
/// transient-key state the effectful loop produced from the generated key, fed back so the transition can
/// store the object and frame the <c>TPM2_CreatePrimary()</c> response. Internal to the effect loop; never
/// arrives from the command transport.
/// </summary>
/// <param name="OutPublic">
/// The exported public area carrying the generated point. Ownership flows to the
/// <c>TpmCreatePrimaryResponse</c> the transition produces and is released by <see cref="TpmSimulator"/>
/// once the response is framed.
/// </param>
/// <param name="KeyState">The durable transient-key state to store under its handle.</param>
/// <param name="CreationByProducts">
/// The pre-framed creation by-products of the response — the wire bytes of <c>creationData</c>,
/// <c>creationHash</c>, <c>creationTicket</c>, and <c>name</c> (the object Name, creation digest, and ticket
/// the effectful loop computed through the registered digest and HMAC seams). Ownership flows to the
/// <c>TpmCreatePrimaryResponse</c> intent and is released by <see cref="TpmSimulator"/> once the response is framed.
/// </param>
/// <param name="CreationByProductsLength">The number of valid octets in <paramref name="CreationByProducts"/>.</param>
public sealed record TpmPrimaryKeyCreated(
    Tpm2bPublic OutPublic,
    TransientKeyState KeyState,
    IMemoryOwner<byte> CreationByProducts,
    int CreationByProductsLength): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmEccSignAction"/> or <see cref="TpmRsaSignAction"/>: the produced
/// signature, fed back so the transition can frame the <c>TPM2_Sign()</c> response. Internal to the effect
/// loop; never arrives from the command transport.
/// </summary>
/// <param name="Signature">
/// The signature octets — IEEE P1363 (<c>r ‖ s</c>) for ECDSA, or the raw RSA signature for an RSA scheme.
/// Ownership flows to the <c>TpmSignResponse</c> the transition produces and is released by
/// <see cref="TpmSimulator"/> once the response is framed.
/// </param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, reported inside the framed signature.</param>
public sealed record TpmMessageSigned(Signature Signature, TpmAlgIdConstants SignatureScheme, TpmAlgIdConstants HashAlg): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_CreatePrimary()</c> command for an ECC restricted storage key (TPM 2.0 Library Part 3, clause
/// 24.1) — a key that can act as the parent of <c>TPM2_Create()</c>. It is the parent-provisioning half of the
/// seal flow: the simulator models the storage parent as a handle-bearing restricted-storage object so a
/// subsequent <c>TPM2_Create()</c> / <c>TPM2_Load()</c> can resolve its parent and verify the parent's storage
/// attributes. The simulator does not wrap children under a parent key (it has no parent symmetric-key custody),
/// so the parent needs no generated key material; its exported public area is the storage template.
/// </summary>
/// <param name="Hierarchy">The hierarchy authorizing the creation (<c>TPM_RH_OWNER</c> in this slice).</param>
/// <param name="NameAlg">The Name algorithm carried in the exported public area.</param>
/// <param name="Attributes">The object attributes (<c>TPMA_OBJECT</c>) the template requests, including <c>RESTRICTED</c> and <c>DECRYPT</c> (a storage key).</param>
/// <param name="Curve">The ECC curve the storage template names.</param>
/// <param name="NoDa">Whether the template sets <c>TPMA_OBJECT.noDA</c>, re-derived so the exported public area reproduces the caller's template.</param>
/// <param name="AuthPolicy">
/// The authorization policy digest carried in the template (empty for the generic storage parent; a standard
/// endorsement key's "PolicyA" for <see cref="Verifiable.Tpm.Infrastructure.Commands.CreatePrimaryInput.ForEndorsementKey"/>),
/// re-emitted into the exported public area.
/// </param>
public sealed record TpmCreateStorageParentRequested(
    uint Hierarchy,
    TpmAlgIdConstants NameAlg,
    TpmaObject Attributes,
    TpmEccCurveConstants Curve,
    bool NoDa,
    ReadOnlyMemory<byte> AuthPolicy): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_CreatePrimary()</c> command for an RSA restricted storage key (TPM 2.0 Library Part 3, clause 24.1)
/// — the RSA counterpart of <see cref="TpmCreateStorageParentRequested"/>, including the standard RSA
/// endorsement key (TCG EK Credential Profile, Annex B.3.3, Template L-1). Unlike the RSA signing path
/// (<see cref="TpmCreateRsaPrimaryRequested"/>), the effectful loop retains the generated public modulus on the
/// durable key state so a later RSA-OAEP secret-transport command can use it.
/// </summary>
/// <param name="Hierarchy">The hierarchy authorizing the creation (<c>TPM_RH_ENDORSEMENT</c> for the standard EK).</param>
/// <param name="NameAlg">The Name algorithm carried in the exported public area.</param>
/// <param name="Attributes">The object attributes (<c>TPMA_OBJECT</c>) the template requests, including <c>RESTRICTED</c> and <c>DECRYPT</c> (a storage key).</param>
/// <param name="KeyBits">The RSA modulus size in bits the template requests.</param>
/// <param name="NoDa">Whether the template sets <c>TPMA_OBJECT.noDA</c>, re-derived so the exported public area reproduces the caller's template.</param>
/// <param name="AuthPolicy">
/// The authorization policy digest carried in the template (empty for a generic RSA storage parent; a standard
/// RSA endorsement key's "PolicyA" for <see cref="Verifiable.Tpm.Infrastructure.Commands.CreatePrimaryInput.ForRsaEndorsementKey"/>),
/// re-emitted into the exported public area.
/// </param>
public sealed record TpmCreateRsaStorageParentRequested(
    uint Hierarchy,
    TpmAlgIdConstants NameAlg,
    TpmaObject Attributes,
    ushort KeyBits,
    bool NoDa,
    ReadOnlyMemory<byte> AuthPolicy): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Create()</c> command that seals caller-supplied data into a KEYEDHASH object under a loaded storage
/// parent (TPM 2.0 Library Part 3, clause 12.1). The object is returned as a wrapped private blob plus its public
/// area; the TPM stores nothing, so the caller persists the blob and reloads it with <c>TPM2_Load()</c>.
/// </summary>
/// <param name="ParentHandle">The loaded storage parent under which the object is sealed.</param>
/// <param name="NameAlg">The Name algorithm carried in the sealed object's public area.</param>
/// <param name="AuthPolicy">The authorization policy digest bound to the object (empty when the seal is authorized by its authValue alone), re-emitted into the exported public area.</param>
/// <param name="NoDa">Whether the template sets <c>TPMA_OBJECT.noDA</c>, re-derived so the exported public area reproduces the caller's template.</param>
/// <param name="UserWithAuth">Whether the template sets <c>TPMA_OBJECT.userWithAuth</c>, re-derived so the exported public area reproduces the caller's template (TPM 2.0 Library Part 3, clause 5.6, check 6).</param>
/// <param name="SecretData">The data to seal, copied into durable model memory.</param>
/// <param name="UserAuth">The authorization value supplied in <c>inSensitive.userAuth</c> (TPM 2.0 Library Part 1, clause 19.6.4), carried through the wrapped private blob so a later <c>TPM2_Load()</c> recovers it onto the sealed object's state.</param>
public sealed record TpmCreateSealedObjectRequested(
    uint ParentHandle,
    TpmAlgIdConstants NameAlg,
    ReadOnlyMemory<byte> AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    ReadOnlyMemory<byte> SecretData,
    ReadOnlyMemory<byte> UserAuth): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Load()</c> command that brings a wrapped sealed data object back into a transient slot under the
/// storage parent that produced it (TPM 2.0 Library Part 3, clause 12.2). The simulator recovers the sealed data
/// from its own private-blob encoding (it does not model parent-key unwrapping), stores the loaded object, and
/// returns its transient handle and Name.
/// </summary>
/// <param name="ParentHandle">The loaded storage parent that wrapped the object.</param>
/// <param name="ObjectType">The public area's object type; only a sealed <c>TPM_ALG_KEYEDHASH</c> object is modelled this slice.</param>
/// <param name="NameAlg">The Name algorithm carried in the public area, used to compute the object Name.</param>
/// <param name="AuthPolicy">The authorization policy digest carried in the loaded public area (empty when the object is authorized by its authValue alone), retained on the loaded object so a policy-gated <c>TPM2_Unseal()</c> can check it.</param>
/// <param name="NoDa">Whether the loaded public area sets <c>TPMA_OBJECT.noDA</c>, retained on the loaded object to decide dictionary-attack protection (TPM 2.0 Library Part 2, clause 8.3.3).</param>
/// <param name="UserWithAuth">Whether the loaded public area sets <c>TPMA_OBJECT.userWithAuth</c>, retained on the loaded object to decide whether an HMAC session or password may authorize a USER-role action against it (TPM 2.0 Library Part 3, clause 5.6, check 6).</param>
/// <param name="PublicAreaBytes">The marshaled <c>TPMT_PUBLIC</c> the Name is hashed over (copied into durable model memory).</param>
/// <param name="PrivateBlob">The wrapped private blob carrying the authorization value and the sealed data (the simulator's own encoding of the sensitive area).</param>
public sealed record TpmLoadObjectRequested(
    uint ParentHandle,
    TpmAlgIdConstants ObjectType,
    TpmAlgIdConstants NameAlg,
    ReadOnlyMemory<byte> AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    ReadOnlyMemory<byte> PublicAreaBytes,
    ReadOnlyMemory<byte> PrivateBlob): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Unseal()</c> command (TPM 2.0 Library Part 3, clause 12.7) that recovers the data sealed in a loaded
/// KEYEDHASH object, authorized by a plain <c>TPM_RS_PW</c> password session. The object must be loaded (its
/// transient handle is the command handle).
/// </summary>
/// <param name="ItemHandle">The transient handle of the loaded sealed data object.</param>
/// <param name="SuppliedPassword">
/// The plaintext authorization value the caller supplied (the password session's <c>hmac</c> field), compared
/// against the object's retained <see cref="SealedObjectState.UserAuth"/> — both sides trailing-zero-stripped
/// (TPM 2.0 Library Part 1, clause 19.4) — rather than discarded.
/// </param>
public sealed record TpmUnsealRequested(uint ItemHandle, ReadOnlyMemory<byte> SuppliedPassword): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Unseal()</c> command (TPM 2.0 Library Part 3, clause 12.7) whose first session is either a satisfied
/// policy session or a bound HMAC session (the primary authorizer, USER role), optionally carrying a second bound
/// HMAC session with the <c>encrypt</c> attribute that protects the recovered <c>outData</c> (Part 1, clauses 18.7
/// and 19). Session 1's kind is resolved in the transition, not the parser (its handle may name either table):
/// a policy session's accumulated policyDigest authorizes the object directly (empty-HMAC authorization, the
/// policy itself is the authorization, Part 1, clause 19.6, unaffected by this wave); an HMAC session is verified
/// by the shared command-HMAC helper with authValue = the object's <see cref="SealedObjectState.UserAuth"/> (Part
/// 3, clause 5.6). A present session 2 is always a bound HMAC session and is verified the same way, with no entity
/// (it authorizes nothing).
/// </summary>
/// <param name="ItemHandle">The transient handle of the loaded sealed data object.</param>
/// <param name="FirstSession">The first session's handle (a policy session or an HMAC session).</param>
/// <param name="FirstNonceCaller">The first session's caller nonce rolled for this command, copied into durable model memory — the cpHash's per-session nonceNewer when the first session is an HMAC session.</param>
/// <param name="PolicyAttributes">The first session's command session-attributes byte, echoed into its response session entry.</param>
/// <param name="FirstHmac">The first session's supplied <c>hmac</c> field, copied into durable model memory. Ignored when the first session is a policy session (its own command-HMAC verification is out of this wave's scope).</param>
/// <param name="EncryptSession">The bound HMAC session handle whose <c>encrypt</c> attribute protects the recovered <c>outData</c>, or <c>0</c> when the command carried only the first session (the recovered <c>outData</c> is then returned in the clear).</param>
/// <param name="EncryptNonceCaller">The encrypt session's caller nonce rolled for this command, copied into durable model memory; the nonceOlder of the response-direction encryption and the response HMAC (Part 1, clause 19.2). Empty when there is no encrypt session.</param>
/// <param name="EncryptAttributes">The encrypt session's command session-attributes byte, echoed into the response session area and folded into the response HMAC. Zero when there is no encrypt session.</param>
/// <param name="EncryptHmac">The encrypt session's supplied <c>hmac</c> field, copied into durable model memory. Empty when there is no encrypt session.</param>
public sealed record TpmUnsealOverSessionsRequested(
    uint ItemHandle,
    uint FirstSession,
    ReadOnlyMemory<byte> FirstNonceCaller,
    byte PolicyAttributes,
    ReadOnlyMemory<byte> FirstHmac,
    uint EncryptSession,
    ReadOnlyMemory<byte> EncryptNonceCaller,
    byte EncryptAttributes,
    ReadOnlyMemory<byte> EncryptHmac): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmUnsealDataAction"/>: the framed (possibly encrypted) response parameter
/// area and every real session's framed response entry, fed back so the transition can roll each session's stored
/// nonce and frame the response. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <remarks>
/// <see cref="ParameterArea"/> is a pooled buffer the framing step disposes as the terminal owner; each
/// <see cref="TpmUnsealFramedSessionEntry"/> in <see cref="Entries"/> owns its own <c>Hmac</c> buffer the same way.
/// </remarks>
/// <param name="ParameterArea">The framed <c>TPM2B_SENSITIVE_DATA</c> response parameter (<c>outData</c>), its data portion encrypted when a session carries the <c>encrypt</c> attribute; disposed after framing.</param>
/// <param name="ParameterLength">The number of valid octets in <paramref name="ParameterArea"/>.</param>
/// <param name="HasPolicyPlaceholder">Whether session index 0 needs the zero-nonce, empty-HMAC policy placeholder entry, threaded through from the declaring action.</param>
/// <param name="PolicyNonceLength">The width in octets of the policy session's response nonce (its hash digest width), framed as a zero placeholder. Meaningful only when <see cref="HasPolicyPlaceholder"/> is set.</param>
/// <param name="PolicyAttributes">The policy session's response session-attributes byte, framed into its response entry. Meaningful only when <see cref="HasPolicyPlaceholder"/> is set.</param>
/// <param name="Entries">Every real session's framed response entry, in command-session order (after the policy placeholder, when present).</param>
public sealed record TpmUnsealedOverSessions(
    IMemoryOwner<byte> ParameterArea,
    int ParameterLength,
    bool HasPolicyPlaceholder,
    int PolicyNonceLength,
    byte PolicyAttributes,
    ImmutableArray<TpmUnsealFramedSessionEntry> Entries): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmSealDataAction"/>: the wrapped private blob, the exported public area,
/// and the pre-framed creation by-products the effectful loop produced for a sealed object, fed back so the
/// transition can frame the <c>TPM2_Create()</c> response. Internal to the effect loop; never arrives from the
/// command transport.
/// </summary>
/// <param name="PrivateBlob">The pooled buffer holding the wrapped private blob; ownership flows to the <c>TpmCreateResponse</c> and is released by <see cref="TpmSimulator"/> once framed.</param>
/// <param name="PrivateBlobLength">The number of valid octets in <paramref name="PrivateBlob"/>.</param>
/// <param name="OutPublic">The exported public area of the sealed object; ownership flows to the <c>TpmCreateResponse</c> and is released once framed.</param>
/// <param name="CreationByProducts">The pre-framed <c>creationData ‖ creationHash ‖ creationTicket</c> wire bytes (no Name, which <c>TPM2_Create()</c> does not return); ownership flows to the <c>TpmCreateResponse</c> and is released once framed.</param>
/// <param name="CreationByProductsLength">The number of valid octets in <paramref name="CreationByProducts"/>.</param>
public sealed record TpmObjectSealed(
    IMemoryOwner<byte> PrivateBlob,
    int PrivateBlobLength,
    Tpm2bPublic OutPublic,
    IMemoryOwner<byte> CreationByProducts,
    int CreationByProductsLength): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmLoadObjectAction"/>: the object Name the effectful loop computed and
/// the recovered sealed data, fed back so the transition can store the loaded object and frame the
/// <c>TPM2_Load()</c> response. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="Handle">The transient handle the transition allocated for the loaded object.</param>
/// <param name="Name">The pooled buffer holding the object Name (<c>nameAlg ‖ H(TPMT_PUBLIC)</c>); ownership flows to the <c>TpmLoadResponse</c> and is released by <see cref="TpmSimulator"/> once framed.</param>
/// <param name="NameLength">The number of valid octets in <paramref name="Name"/>.</param>
/// <param name="Data">The recovered sealed data to store under the loaded handle (durable model memory).</param>
/// <param name="AuthPolicy">The authorization policy digest carried in the loaded public area (empty for an authValue-only object), retained on the loaded object for a policy-gated <c>TPM2_Unseal()</c>.</param>
/// <param name="NoDa">Whether the loaded public area sets <c>TPMA_OBJECT.noDA</c>, retained on the loaded object to decide dictionary-attack protection.</param>
/// <param name="UserWithAuth">Whether the loaded public area sets <c>TPMA_OBJECT.userWithAuth</c>, retained on the loaded object to decide whether an HMAC session or password may authorize a USER-role action against it.</param>
/// <param name="UserAuth">The object's authorization value, recovered from the wrapped private blob (durable model memory) and retained for a subsequent <c>TPM2_Unseal()</c>'s authorization compare.</param>
public sealed record TpmObjectLoaded(
    uint Handle,
    IMemoryOwner<byte> Name,
    int NameLength,
    ReadOnlyMemory<byte> Data,
    ReadOnlyMemory<byte> AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    ReadOnlyMemory<byte> UserAuth): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Certify()</c> command (TPM 2.0 Library Part 3, clause 18.2): a signing key vouches that an object
/// with a given Name is loaded in the same TPM, over a caller nonce. Both handles require authorization, so the
/// two authorization sessions are consumed by the parser; the objects this slice certifies carry empty auth, so
/// the supplied authorization values are not retained.
/// </summary>
/// <param name="ObjectHandle">The loaded object being certified (its Name is the attested binding).</param>
/// <param name="SignHandle">The loaded signing key that attests, whose retained private key signs the marshaled attestation.</param>
/// <param name="QualifyingData">The caller nonce echoed into the attestation's <c>extraData</c>, copied into durable model memory.</param>
/// <param name="SignatureScheme">The signing scheme algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>, dispatched on the signing key's type).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm.</param>
public sealed record TpmCertifyRequested(
    uint ObjectHandle,
    uint SignHandle,
    ReadOnlyMemory<byte> QualifyingData,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants SchemeHashAlg): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmCertifyAction"/>: the marshaled <c>TPMS_ATTEST</c> the effectful loop
/// built and the signature over its digest, fed back so the transition can frame the <c>TPM2_Certify()</c>
/// response. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="CertifyInfo">The pooled buffer holding the marshaled <c>TPMS_ATTEST</c> (the exact bytes the signature is over); ownership flows to the <c>TpmCertifyResponse</c> and is released by <see cref="TpmSimulator"/> once framed.</param>
/// <param name="CertifyInfoLength">The number of valid octets in <paramref name="CertifyInfo"/>.</param>
/// <param name="Signature">The signature over <c>H_hashAlg(certifyInfo)</c>; ownership flows to the <c>TpmCertifyResponse</c> and is released once framed.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, framed inside the signature.</param>
public sealed record TpmObjectCertified(
    IMemoryOwner<byte> CertifyInfo,
    int CertifyInfoLength,
    Signature Signature,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants HashAlg): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PCR_Read()</c> command (TPM 2.0 Library Part 3, clause 22.4): reads the current values of the
/// selected Platform Configuration Registers. The command takes no handles and no authorization, so only the
/// selection is parsed.
/// </summary>
/// <param name="SelectionBytes">The <c>TPML_PCR_SELECTION</c> wire bytes, captured verbatim to echo back as <c>pcrSelectionOut</c> and decoded against the PCR bank to gather the values.</param>
public sealed record TpmPcrReadRequested(ReadOnlyMemory<byte> SelectionBytes): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Quote()</c> command (TPM 2.0 Library Part 3, clause 18.4): a signing key attests the composite
/// digest of a selected set of Platform Configuration Registers, over a caller nonce. The single handle requires
/// authorization, so the password session is consumed by the parser; a quote is public, so the objects this slice
/// quotes with carry empty auth and the supplied authorization value is not retained.
/// </summary>
/// <param name="SignHandle">The loaded signing key that attests, whose retained private key signs the marshaled attestation.</param>
/// <param name="QualifyingData">The caller nonce echoed into the attestation's <c>extraData</c>, copied into durable model memory.</param>
/// <param name="SignatureScheme">The signing scheme algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>, dispatched on the signing key's type).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm; the simulator computes both the attest digest and the PCR composite digest with it (TPM 2.0 Library Part 3, clause 18.4).</param>
/// <param name="PcrSelection">The <c>TPML_PCR_SELECTION</c> wire bytes, captured verbatim to echo into the attestation and decoded against the PCR bank.</param>
public sealed record TpmQuoteRequested(
    uint SignHandle,
    ReadOnlyMemory<byte> QualifyingData,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants SchemeHashAlg,
    ReadOnlyMemory<byte> PcrSelection): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmQuoteAction"/>: the marshaled <c>TPMS_ATTEST</c> the effectful loop
/// built and the signature over its digest, fed back so the transition can frame the <c>TPM2_Quote()</c>
/// response. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="Quoted">The pooled buffer holding the marshaled <c>TPMS_ATTEST</c> (the exact bytes the signature is over); ownership flows to the <c>TpmQuoteResponse</c> and is released by <see cref="TpmSimulator"/> once framed.</param>
/// <param name="QuotedLength">The number of valid octets in <paramref name="Quoted"/>.</param>
/// <param name="Signature">The signature over <c>H_hashAlg(quoted)</c>; ownership flows to the <c>TpmQuoteResponse</c> and is released once framed.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c>), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, framed inside the signature.</param>
public sealed record TpmObjectQuoted(
    IMemoryOwner<byte> Quoted,
    int QuotedLength,
    Signature Signature,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants HashAlg): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_CertifyCreation()</c> command (TPM 2.0 Library Part 3, clause 18.3): a signing key attests that the
/// object with a given Name was created by the TPM with a given creation hash, re-verified against the
/// caller-supplied creation ticket. Only <see cref="SignHandle"/> requires authorization, so the parser consumes
/// a single password session; <see cref="ObjectHandle"/> carries no session at all.
/// </summary>
/// <param name="SignHandle">The loaded signing key that attests, whose retained private key signs the marshaled attestation.</param>
/// <param name="ObjectHandle">The loaded object whose creation is certified (its Name is the attested binding).</param>
/// <param name="QualifyingData">The caller nonce echoed into the attestation's <c>extraData</c>, copied into durable model memory.</param>
/// <param name="CreationHash">The creation hash the caller supplies, folded into the recomputed creation ticket and attested in <c>TPMS_CREATION_INFO.creationHash</c>.</param>
/// <param name="SignatureScheme">The signing scheme algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>, dispatched on the signing key's type).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm.</param>
/// <param name="TicketDigest">The digest carried by the caller-supplied <c>TPMT_TK_CREATION</c>, compared constant-time against the recomputed ticket.</param>
public sealed record TpmCertifyCreationRequested(
    uint SignHandle,
    uint ObjectHandle,
    ReadOnlyMemory<byte> QualifyingData,
    ReadOnlyMemory<byte> CreationHash,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants SchemeHashAlg,
    ReadOnlyMemory<byte> TicketDigest): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmCertifyCreationAction"/> or <see cref="TpmRsaCertifyCreationAction"/>.
/// Unlike <see cref="TpmObjectCertified"/>, the creation-ticket re-verification (TPM 2.0 Library Part 3, clause
/// 18.3) needs the asynchronous digest/HMAC seam, so it happens inside the effect rather than the pure
/// transition: a mismatched ticket yields <see cref="ResponseCode"/> <c>TPM_RC_TICKET</c> with no attestation
/// data, mirroring <c>TpmCredentialActivated</c>'s integrity-check outcome. Internal to the effect loop; never
/// arrives from the command transport.
/// </summary>
/// <param name="ResponseCode">
/// <c>TPM_RC_SUCCESS</c> when the supplied creation ticket reproduced, in which case <paramref name="CertifyInfo"/>
/// and <paramref name="Signature"/> carry the attestation; otherwise <c>TPM_RC_TICKET</c> with both null.
/// </param>
/// <param name="CertifyInfo">The pooled buffer holding the marshaled <c>TPMS_ATTEST</c> (the exact bytes the signature is over); ownership flows to the <c>TpmCertifyCreationResponse</c> and is released by <see cref="TpmSimulator"/> once framed.</param>
/// <param name="CertifyInfoLength">The number of valid octets in <paramref name="CertifyInfo"/>.</param>
/// <param name="Signature">The signature over <c>H_hashAlg(certifyInfo)</c>; ownership flows to the <c>TpmCertifyCreationResponse</c> and is released once framed.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, framed inside the signature.</param>
public sealed record TpmObjectCreationCertified(
    TpmRcConstants ResponseCode,
    IMemoryOwner<byte>? CertifyInfo,
    int CertifyInfoLength,
    Signature? Signature,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants HashAlg): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_GetTime()</c> command (TPM 2.0 Library Part 3, clause 18.7): a signing key attests the TPM's current
/// time, over a caller nonce. Requires Endorsement authorization on <see cref="PrivacyAdminHandle"/> in addition
/// to <see cref="SignHandle"/>'s own authorization, so the parser consumes two password sessions in handle order.
/// </summary>
/// <param name="PrivacyAdminHandle">The privacy administrator handle (TPMI_RH_ENDORSEMENT); only <c>TPM_RH_ENDORSEMENT</c> is a legal value.</param>
/// <param name="SignHandle">The loaded signing key that attests, whose retained private key signs the marshaled attestation.</param>
/// <param name="QualifyingData">The caller nonce echoed into the attestation's <c>extraData</c>, copied into durable model memory.</param>
/// <param name="SignatureScheme">The signing scheme algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>, dispatched on the signing key's type).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm.</param>
public sealed record TpmGetTimeRequested(
    uint PrivacyAdminHandle,
    uint SignHandle,
    ReadOnlyMemory<byte> QualifyingData,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants SchemeHashAlg): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmGetTimeAction"/> or <see cref="TpmRsaGetTimeAction"/>: the marshaled
/// <c>TPMS_ATTEST</c> the effectful loop built and the signature over its digest, fed back so the transition can
/// frame the <c>TPM2_GetTime()</c> response. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="TimeInfo">The pooled buffer holding the marshaled <c>TPMS_ATTEST</c> (the exact bytes the signature is over); ownership flows to the <c>TpmGetTimeResponse</c> and is released by <see cref="TpmSimulator"/> once framed.</param>
/// <param name="TimeInfoLength">The number of valid octets in <paramref name="TimeInfo"/>.</param>
/// <param name="Signature">The signature over <c>H_hashAlg(timeInfo)</c>; ownership flows to the <c>TpmGetTimeResponse</c> and is released once framed.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, framed inside the signature.</param>
public sealed record TpmTimeAttested(
    IMemoryOwner<byte> TimeInfo,
    int TimeInfoLength,
    Signature Signature,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants HashAlg): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_ReadClock()</c> command (TPM 2.0 Library Part 3, clause 29.1). Reads the current
/// <c>TPMS_TIME_INFO</c> — uncertified, unsigned Time/Clock/resetCount/restartCount — with no handles and no
/// authorization.
/// </summary>
public sealed record TpmReadClockRequested: TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_ClockSet()</c> command (TPM 2.0 Library Part 3, clause 29.2). Advances <c>Clock</c> forward to
/// <see cref="NewTime"/>, authorized by the owner hierarchy; the Platform-hierarchy arm is not modelled this
/// slice.
/// </summary>
/// <param name="AuthHandle">The provisioning hierarchy authorizing the set (<c>TPM_RH_OWNER</c> in this slice).</param>
/// <param name="OwnerAuthSupplied">The authorization value the caller supplied for the provisioning hierarchy (the password session's plaintext authValue).</param>
/// <param name="NewTime">The requested new <c>Clock</c> value, in milliseconds.</param>
public sealed record TpmClockSetRequested(
    uint AuthHandle,
    ReadOnlyMemory<byte> OwnerAuthSupplied,
    ulong NewTime): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_DictionaryAttackLockReset()</c> command (TPM 2.0 Library Part 3, clause 25.2). Resets
/// <c>FailedTries</c> to zero, authorized by the lockout hierarchy; permitted even while the TPM is in general
/// Lockout mode (<see cref="TpmSimulatorState.IsInLockout"/>) — only <see cref="TpmSimulatorState.LockoutAuthEnabled"/>
/// gates it.
/// </summary>
/// <param name="LockHandle">The authorization handle (<c>TPMI_RH_LOCKOUT</c>); for this slice must equal <c>TPM_RH_LOCKOUT</c>.</param>
/// <param name="LockoutAuthSupplied">The authorization value the caller supplied (the password session's plaintext authValue), compared against the lockout hierarchy's authorization value.</param>
public sealed record TpmDictionaryAttackLockResetRequested(
    uint LockHandle,
    ReadOnlyMemory<byte> LockoutAuthSupplied): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_DictionaryAttackParameters()</c> command (TPM 2.0 Library Part 3, clause 25.3). Sets
/// <c>MaxTries</c>/<c>RecoveryTime</c>/<c>LockoutRecovery</c>, authorized by the lockout hierarchy exactly like
/// <see cref="TpmDictionaryAttackLockResetRequested"/>; deliberately does not reset <c>FailedTries</c>
/// (Part 1, clause 17.8.6's errata correction).
/// </summary>
/// <param name="LockHandle">The authorization handle (<c>TPMI_RH_LOCKOUT</c>); for this slice must equal <c>TPM_RH_LOCKOUT</c>.</param>
/// <param name="LockoutAuthSupplied">The authorization value the caller supplied (the password session's plaintext authValue), compared against the lockout hierarchy's authorization value.</param>
/// <param name="NewMaxTries">The new tolerated-failure count before Lockout mode engages.</param>
/// <param name="NewRecoveryTime">The new self-heal interval, in seconds; zero disables dictionary-attack protection.</param>
/// <param name="NewLockoutRecovery">The new lockoutAuth recovery wait, in seconds; zero means only a TPM Reset re-arms lockoutAuth.</param>
public sealed record TpmDictionaryAttackParametersRequested(
    uint LockHandle,
    ReadOnlyMemory<byte> LockoutAuthSupplied,
    uint NewMaxTries,
    uint NewRecoveryTime,
    uint NewLockoutRecovery): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_NV_Certify()</c> command (TPM 2.0 Library Part 3, clause 31.16): a signing key attests the contents
/// of an NV Index at a caller-chosen offset and size, over a caller nonce. Both <see cref="SignHandle"/> and
/// <see cref="AuthHandle"/> require authorization, so the parser consumes two password sessions in handle order;
/// only Index authorization (<see cref="AuthHandle"/> equal to <see cref="NvIndex"/>) is modelled.
/// </summary>
/// <param name="SignHandle">The loaded signing key that attests, whose retained private key signs the marshaled attestation.</param>
/// <param name="AuthHandle">The authorization handle (<c>TPMI_RH_NV_AUTH</c>); for Index authorization this equals <paramref name="NvIndex"/>.</param>
/// <param name="NvIndex">The NV Index whose contents are certified.</param>
/// <param name="AuthSupplied">The authorization value the caller supplied for <paramref name="AuthHandle"/> (the password session's plaintext authValue), compared against the Index authValue.</param>
/// <param name="QualifyingData">The caller nonce echoed into the attestation's <c>extraData</c>, copied into durable model memory.</param>
/// <param name="SignatureScheme">The signing scheme algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>, dispatched on the signing key's type).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm.</param>
/// <param name="Size">The number of octets to certify.</param>
/// <param name="Offset">The octet offset into the Index data area.</param>
public sealed record TpmNvCertifyRequested(
    uint SignHandle,
    uint AuthHandle,
    uint NvIndex,
    ReadOnlyMemory<byte> AuthSupplied,
    ReadOnlyMemory<byte> QualifyingData,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants SchemeHashAlg,
    ushort Size,
    ushort Offset): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmNvCertifyAction"/> or <see cref="TpmRsaNvCertifyAction"/>: the
/// marshaled <c>TPMS_ATTEST</c> the effectful loop built and the signature over its digest, fed back so the
/// transition can frame the <c>TPM2_NV_Certify()</c> response. Internal to the effect loop; never arrives from
/// the command transport.
/// </summary>
/// <param name="CertifyInfo">The pooled buffer holding the marshaled <c>TPMS_ATTEST</c> (the exact bytes the signature is over); ownership flows to the <c>TpmNvCertifyResponse</c> and is released by <see cref="TpmSimulator"/> once framed.</param>
/// <param name="CertifyInfoLength">The number of valid octets in <paramref name="CertifyInfo"/>.</param>
/// <param name="Signature">The signature over <c>H_hashAlg(certifyInfo)</c>; ownership flows to the <c>TpmNvCertifyResponse</c> and is released once framed.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, framed inside the signature.</param>
public sealed record TpmNvIndexCertified(
    IMemoryOwner<byte> CertifyInfo,
    int CertifyInfoLength,
    Signature Signature,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants HashAlg): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_VerifySignature()</c> command (TPM 2.0 Library Part 3, clause 20.1): validate that <see cref="Signature"/>
/// is a valid signature over <see cref="Digest"/> made with the key referenced by <see cref="KeyHandle"/>. This is a
/// public-key operation — <see cref="KeyHandle"/> requires no authorization at all, so the parser consumes no
/// session.
/// </summary>
/// <param name="KeyHandle">The loaded key whose public part verifies the signature.</param>
/// <param name="Digest">The digest the signature is claimed to be over.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>), the <c>TPMU_SIGNATURE</c> selector.</param>
/// <param name="SchemeHashAlg">The hash algorithm carried inside the signature.</param>
/// <param name="Signature">The signature octets: IEEE P1363 r ‖ s for ECDSA, or the raw RSA signature for RSASSA/RSAPSS.</param>
public sealed record TpmVerifySignatureRequested(
    uint KeyHandle,
    ReadOnlyMemory<byte> Digest,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants SchemeHashAlg,
    ReadOnlyMemory<byte> Signature): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmVerifySignatureAction"/> or <see cref="TpmRsaVerifySignatureAction"/>:
/// whether the signature verified and, on success, the octets of the ticket digest the effectful loop computed. A
/// failed verification (TPM 2.0 Library Part 3, clause 20.1: "Otherwise, the TPM shall return TPM_RC_SIGNATURE")
/// carries <c>TPM_RC_SIGNATURE</c> with no ticket, mirroring <see cref="TpmObjectCreationCertified"/>'s
/// success/rejection split. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="ResponseCode"><c>TPM_RC_SUCCESS</c> when the signature verified; otherwise <c>TPM_RC_SIGNATURE</c>.</param>
/// <param name="Hierarchy">The hierarchy containing the verifying key's Name, framed in the ticket's <c>hierarchy</c> field.</param>
/// <param name="TicketDigest">The pooled buffer holding the ticket HMAC digest; ownership flows to the <c>TpmVerifySignatureResponse</c> and is released by <see cref="TpmSimulator"/> once framed. <see langword="null"/> when the signature did not verify.</param>
/// <param name="TicketDigestLength">The number of valid octets in <paramref name="TicketDigest"/>.</param>
public sealed record TpmSignatureVerified(
    TpmRcConstants ResponseCode,
    uint Hierarchy,
    IMemoryOwner<byte>? TicketDigest,
    int TicketDigestLength): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmVerifyPolicySignedAction"/> or
/// <see cref="TpmRsaVerifyPolicySignedAction"/>: whether the recomputed <c>aHash</c> verified against
/// <c>authObject</c>'s signature (TPM 2.0 Library Part 3, Section 23.3). Unlike
/// <see cref="TpmSignatureVerified"/>, no ticket is produced here at all — a NULL <c>TPMT_TK_AUTH</c> is always
/// framed regardless of the outcome (the real ticket mint is deferred to a future wave). A failed verification
/// carries <c>TPM_RC_SIGNATURE</c>; the continuation folds the policyDigest only on success. Internal to the
/// effect loop; never arrives from the command transport.
/// </summary>
/// <param name="ResponseCode"><c>TPM_RC_SUCCESS</c> when the signature verified; otherwise <c>TPM_RC_SIGNATURE</c>.</param>
/// <param name="PolicySession">The policy session to extend on a successful verification.</param>
/// <param name="AuthObjectName">The authorizing key's Name, folded into the policyDigest (<c>arg2</c> of <c>PolicyUpdate</c>).</param>
/// <param name="PolicyRef">The policy qualifier, always folded as the second <c>PolicyUpdate</c> hash.</param>
/// <param name="PolicyHashAlgorithm">The session's own policy hash algorithm, sizing the policyDigest fold — independent of the signature's scheme hash.</param>
public sealed record TpmPolicySignedVerified(
    TpmRcConstants ResponseCode,
    uint PolicySession,
    ReadOnlyMemory<byte> AuthObjectName,
    ReadOnlyMemory<byte> PolicyRef,
    TpmAlgIdConstants PolicyHashAlgorithm): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_StartAuthSession()</c> command (TPM 2.0 Library Part 3, clause 11.1) that starts a policy or trial
/// policy session. The tests start unbound, unsalted sessions (tpmKey and bind both <c>TPM_RH_NULL</c>, empty
/// nonceCaller and encryptedSalt, <c>TPM_ALG_NULL</c> symmetric), so only the fields the session model needs are
/// carried; the salt/bind material is consumed during parsing but not modelled.
/// </summary>
/// <param name="SessionType">The session type (<c>TPM_SE_POLICY</c> or <c>TPM_SE_TRIAL</c>); a trial session accumulates the policyDigest but authorizes nothing.</param>
/// <param name="AuthHash">The session's policy hash algorithm (<c>authHash</c>), whose digest width the policyDigest carries and which sizes the returned nonceTPM.</param>
public sealed record TpmStartAuthSessionRequested(
    TpmSeConstants SessionType,
    TpmAlgIdConstants AuthHash): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmAction"/> that drew a fresh nonceTPM for a newly started policy or
/// trial session: fed back so the transition can record the session (an all-zero initial policyDigest, an
/// unlatched cpHash, and the captured session-start time alongside the drawn nonce) and frame the
/// <c>TPM2_StartAuthSession()</c> response. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <remarks>
/// <see cref="NonceTpm"/> is carried as <see cref="ReadOnlyMemory{T}"/> (copied into durable model memory by the
/// effect) because the transition stores it on the durable <see cref="PolicySessionState"/> for the lifetime of
/// the session — the value <c>TPM2_PolicySigned()</c>'s <c>aHash</c> binds to (TPM 2.0 Library Part 3, Section
/// 23.3) — rather than framing-then-disposing a pooled buffer.
/// </remarks>
/// <param name="SessionHandle">The session handle the transition allocated for the new session.</param>
/// <param name="AuthHash">The session's policy hash algorithm to record on the session.</param>
/// <param name="IsTrial">Whether the session is a trial session, to record on the session.</param>
/// <param name="StartTime">The captured session-start time, to record on the session.</param>
/// <param name="NonceTpm">The freshly generated nonceTPM: recorded on the session and framed verbatim in the response.</param>
public sealed record TpmPolicySessionStarted(
    uint SessionHandle,
    TpmAlgIdConstants AuthHash,
    bool IsTrial,
    ulong StartTime,
    ReadOnlyMemory<byte> NonceTpm): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_StartAuthSession()</c> command (TPM 2.0 Library Part 3, clause 11.1) that starts a bound and/or
/// salted HMAC session with parameter encryption. It is the parameter-encryption counterpart of
/// <see cref="TpmStartAuthSessionRequested"/>: the session key is derived from the bind entity's authorization
/// value and/or the recovered salt plus the two start nonces (Part 1, clause 17.6.10 equations 20/23/25), and
/// the negotiated symmetric definition keys the encryption of the first response parameter.
/// </summary>
/// <param name="Bind">The entity the session binds to, whose authorization value seeds the session key (<c>TPM_RH_NULL</c> for an unbound session).</param>
/// <param name="NonceCaller">The caller nonce sent at start, copied into durable model memory; it is the second context field of the session-key KDFa (Part 1, clause 17.6.10).</param>
/// <param name="Symmetric">The symmetric definition negotiated for parameter encryption (XOR obfuscation, AES-CFB, or <c>TPM_ALG_NULL</c>).</param>
/// <param name="AuthHash">The session hash algorithm (<c>authHash</c>), which drives the KDFa derivations and sizes the returned nonceTPM.</param>
/// <param name="TpmKey">The handle of the key salt is encrypted to (<c>TPM_RH_NULL</c> for an unsalted session).</param>
/// <param name="EncryptedSalt">The wire <c>encryptedSalt</c> (<c>TPM2B_ENCRYPTED_SECRET</c>): an RSA OAEP ciphertext or a marshaled <c>TPMS_ECC_POINT</c>, depending on <see cref="TpmKey"/>'s algorithm; empty when unsalted.</param>
public sealed record TpmStartHmacSessionRequested(
    uint Bind,
    ReadOnlyMemory<byte> NonceCaller,
    TpmtSymDef Symmetric,
    TpmAlgIdConstants AuthHash,
    uint TpmKey,
    ReadOnlyMemory<byte> EncryptedSalt): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmAction"/> that started (or failed to start) a bound and/or salted
/// HMAC session: the freshly generated nonceTPM and the derived session key, fed back so the transition can
/// record the session and frame the <c>TPM2_StartAuthSession()</c> response — or, when salt recovery failed,
/// the failure code to reject with. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <remarks>
/// The nonce and session key are carried as <see cref="ReadOnlyMemory{T}"/> (copied into durable model memory by
/// the effect) because the transition stores them on the durable <see cref="HmacSessionState"/> for the lifetime
/// of the session, rather than framing-then-disposing a pooled buffer.
/// </remarks>
/// <param name="ResponseCode">
/// <c>TPM_RC_SUCCESS</c> when the session key was derived; <c>TPM_RC_VALUE</c> when a salted arm's secret
/// recovery failed internally (bad OAEP padding, an oversize recovered salt, or a malformed/off-curve ECC
/// point — TPM 2.0 Library Part 3, clause 11.1), reported immediately rather than poisoned-and-deferred. Every
/// other field is a meaningless empty placeholder when this is not <c>TPM_RC_SUCCESS</c>.
/// </param>
/// <param name="SessionHandle">The session handle the transition allocated for the new session.</param>
/// <param name="SessionAlg">The session hash algorithm to record on the session.</param>
/// <param name="Symmetric">The negotiated symmetric definition to record on the session.</param>
/// <param name="NonceTpm">The initial nonceTPM: generated from the injected RNG and framed in the response, also the second-to-last context of the response-direction encryption once rolled.</param>
/// <param name="SessionKey">The <c>KDFa</c>-derived session key to record on the session (the HMAC and parameter-encryption key).</param>
/// <param name="BoundEntityName">The bind entity's Name, threaded through unchanged from <see cref="Automata.TpmStartHmacSessionAction"/>, to record on the session.</param>
public sealed record TpmHmacSessionStarted(
    TpmRcConstants ResponseCode,
    uint SessionHandle,
    TpmAlgIdConstants SessionAlg,
    TpmtSymDef Symmetric,
    ReadOnlyMemory<byte> NonceTpm,
    ReadOnlyMemory<byte> SessionKey,
    ReadOnlyMemory<byte> BoundEntityName): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_GetRandom()</c> command (TPM 2.0 Library Part 3, clause 16.1) carried over a bound HMAC session with
/// the <c>encrypt</c> attribute set. Unlike <see cref="TpmGetRandomRequested"/> (the unauthorized, no-session
/// form) this carries the command's authorization-area fields the command-HMAC verification and the response path
/// need: the rolled caller nonce, the session attributes, the supplied <c>hmac</c>, and the raw parameter-area
/// bytes cpHash is computed over (Part 1, clauses 18.7 and 19). <c>GetRandom</c> authorizes no entity, so the
/// verification's HMAC key is the session key alone and no dictionary-attack gate applies.
/// </summary>
/// <param name="SessionHandle">The HMAC session the command runs over.</param>
/// <param name="NonceCaller">The caller nonce rolled for this command, copied into durable model memory; the cpHash-verification nonceNewer and the nonceOlder of the response-direction encryption and the response HMAC (Part 1, clause 19.2).</param>
/// <param name="SessionAttributes">The command's session attributes byte, echoed into the response session area, folded into the command-HMAC verification, and folded into the response HMAC.</param>
/// <param name="Hmac">The supplied command <c>hmac</c> field, copied into durable model memory (no longer discarded) — verified against the session's independently-derived key before the random draw proceeds.</param>
/// <param name="RawParameterArea">The raw <c>bytesRequested</c> wire bytes (the 2-octet <c>UINT16</c>, captured before decode), the cpHash parameter term (Part 1, clause 18.7 equation 15).</param>
/// <param name="BytesRequested">The number of random octets the caller requested (clamped as in the no-session form).</param>
public sealed record TpmGetRandomOverSessionRequested(
    uint SessionHandle,
    ReadOnlyMemory<byte> NonceCaller,
    byte SessionAttributes,
    ReadOnlyMemory<byte> Hmac,
    ReadOnlyMemory<byte> RawParameterArea,
    ushort BytesRequested): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmAction"/> that produced an encrypt-attributed <c>TPM2_GetRandom()</c>
/// response over an HMAC session: the framed (encrypted) response parameter area, the freshly rolled nonceTPM,
/// and the response HMAC, fed back so the transition can roll the session nonce and frame the response. Internal
/// to the effect loop; never arrives from the command transport.
/// </summary>
/// <remarks>
/// <see cref="ParameterArea"/> and <see cref="Hmac"/> are pooled buffers the framing step disposes as the terminal
/// owner. <see cref="NewNonceTpm"/> is carried as <see cref="ReadOnlyMemory{T}"/> because it is both framed into
/// the response session area and stored on the durable session as the rolled nonceTPM.
/// </remarks>
/// <param name="SessionHandle">The HMAC session whose nonceTPM is rolled to <paramref name="NewNonceTpm"/>.</param>
/// <param name="NewNonceTpm">The freshly generated nonceTPM: framed in the response session area (nonceNewer) and stored as the session's rolled nonce.</param>
/// <param name="SessionAttributes">The response session attributes byte, framed and folded into the response HMAC exactly as it was HMAC'd.</param>
/// <param name="ParameterArea">The framed <c>TPM2B_DIGEST</c> response parameter with its data portion encrypted; disposed after framing.</param>
/// <param name="ParameterLength">The number of valid octets in <paramref name="ParameterArea"/>.</param>
/// <param name="Hmac">The response session HMAC over <c>rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes</c>; disposed after framing.</param>
/// <param name="HmacLength">The number of valid octets in <paramref name="Hmac"/>.</param>
public sealed record TpmEncryptedRandomProduced(
    uint SessionHandle,
    ReadOnlyMemory<byte> NewNonceTpm,
    byte SessionAttributes,
    IMemoryOwner<byte> ParameterArea,
    int ParameterLength,
    IMemoryOwner<byte> Hmac,
    int HmacLength): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicyCommandCode()</c> command (TPM 2.0 Library Part 3, clause 23.4): restricts a policy session to
/// a single command, extending its policyDigest by <c>H(policyDigest ‖ TPM_CC_PolicyCommandCode ‖ code)</c>. The
/// policy session is a command handle with no authorization.
/// </summary>
/// <param name="PolicySession">The policy session handle the restriction is applied to.</param>
/// <param name="Code">The command code the policy is restricted to.</param>
public sealed record TpmPolicyCommandCodeRequested(uint PolicySession, TpmCcConstants Code): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicyAuthValue()</c> command (TPM 2.0 Library Part 3, clause 23.18): binds a policy to the
/// authorized object's authorization value, extending its policyDigest by
/// <c>H(policyDigest ‖ TPM_CC_PolicyAuthValue)</c>. The policy session is a command handle with no authorization.
/// </summary>
/// <param name="PolicySession">The policy session handle the assertion is applied to.</param>
public sealed record TpmPolicyAuthValueRequested(uint PolicySession): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicyGetDigest()</c> command (TPM 2.0 Library Part 3, clause 23.6): returns the current policyDigest
/// of a policy or trial session. The policy session is a command handle with no authorization.
/// </summary>
/// <param name="PolicySession">The policy session handle whose digest is read.</param>
public sealed record TpmPolicyGetDigestRequested(uint PolicySession): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicyPCR()</c> command (TPM 2.0 Library Part 3, clause 23.7): binds a policy to a set of PCRs,
/// extending its policyDigest by <c>H(policyDigest ‖ TPM_CC_PolicyPCR ‖ pcrs ‖ pcrDigest)</c>. On a trial session
/// the caller's pcrDigest is used verbatim. The policy session is a command handle with no authorization.
/// </summary>
/// <param name="PolicySession">The policy session handle the assertion is applied to.</param>
/// <param name="PcrDigest">The expected digest of the selected PCR values (used verbatim on a trial session), copied into durable model memory.</param>
/// <param name="PcrSelectionBytes">The marshaled <c>TPML_PCR_SELECTION</c> wire bytes, captured verbatim and folded into the policyDigest exactly as sent.</param>
public sealed record TpmPolicyPcrRequested(
    uint PolicySession,
    ReadOnlyMemory<byte> PcrDigest,
    ReadOnlyMemory<byte> PcrSelectionBytes): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicyOR()</c> command (TPM 2.0 Library Part 3, clause 23.6): authorizes a policy session when its
/// current policyDigest matches one of the branches, then collapses it to
/// <c>H(0…0 ‖ TPM_CC_PolicyOR ‖ branches)</c>. On a trial session the match check is skipped. The policy session
/// is a command handle with no authorization.
/// </summary>
/// <param name="PolicySession">The policy session handle the assertion is applied to.</param>
/// <param name="Branches">The allowed branch policy digests (the OR alternatives), in the order sent.</param>
public sealed record TpmPolicyOrRequested(
    uint PolicySession,
    ImmutableArray<ReadOnlyMemory<byte>> Branches): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicySecret()</c> command in its immediate (no-expiration) form (TPM 2.0 Library Part 3, clause
/// 23.4): binds a policy to the authorization of the entity at <paramref name="AuthHandle"/>, extending its
/// policyDigest by <c>H(policyDigest ‖ TPM_CC_PolicySecret ‖ authName)</c> followed by the (empty) policyRef hash.
/// The authorized entity requires authorization, so its password session is consumed by the parser; the entities
/// this slice authorizes (permanent hierarchies) carry empty auth, so the supplied value is not retained.
/// </summary>
/// <param name="AuthHandle">The entity whose authorization the policy requires (for a permanent hierarchy its Name is its 4-byte handle value).</param>
/// <param name="PolicySession">The policy session handle the assertion is applied to.</param>
public sealed record TpmPolicySecretRequested(uint AuthHandle, uint PolicySession): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicySigned()</c> command (TPM 2.0 Library Part 3, Section 23.3): binds a policy session to a
/// signature over <c>aHash = H_authAlg(nonceTPM ‖ expiration ‖ cpHashA ‖ policyRef)</c> made by the key at
/// <see cref="AuthObject"/>. Neither <see cref="AuthObject"/> nor <see cref="PolicySession"/> requires
/// authorization, so the parser admits only <c>TPM_ST_NO_SESSIONS</c>, exactly as
/// <see cref="TpmVerifySignatureRequested"/> does.
/// </summary>
/// <param name="AuthObject">The handle of the key that validates the signature (any loaded public key — no <c>sign</c>-attribute gate, unlike <c>TPM2_VerifySignature()</c>'s <c>keyHandle</c>).</param>
/// <param name="PolicySession">The policy session handle being extended.</param>
/// <param name="NonceTpm">The caller-supplied nonceTPM: must equal the session's retained nonce when non-empty, or be empty for a session-unbound authorization.</param>
/// <param name="CpHashA">The command-parameter digest being authorized, or empty if unbound.</param>
/// <param name="PolicyRef">The opaque policy qualifier, folded into the policyDigest unconditionally (Part 3, Section 23.2.3).</param>
/// <param name="Expiration">The signed expiration (seconds); 0 = no expiry, negative = ticket requested (the mint itself is deferred this wave).</param>
/// <param name="SignatureScheme">The signing scheme (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>).</param>
/// <param name="SchemeHashAlg">H_authAlg: the hash algorithm carried inside the signature — independent of the session's own policy hash algorithm.</param>
/// <param name="Signature">The signature octets: IEEE P1363 r ‖ s for ECDSA, or the raw RSA signature for RSASSA/RSAPSS.</param>
public sealed record TpmPolicySignedRequested(
    uint AuthObject,
    uint PolicySession,
    ReadOnlyMemory<byte> NonceTpm,
    ReadOnlyMemory<byte> CpHashA,
    ReadOnlyMemory<byte> PolicyRef,
    int Expiration,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants SchemeHashAlg,
    ReadOnlyMemory<byte> Signature): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicyAuthorize()</c> command (TPM 2.0 Library Part 3, Section 23.16): authorizes a policy session
/// when its current policyDigest equals <see cref="ApprovedPolicy"/> and the ticket described by
/// <see cref="CheckTicketHierarchy"/>/<see cref="CheckTicketDigest"/> proves <see cref="KeySign"/> signed
/// <c>H(approvedPolicy || policyRef)</c>, then REPLACES the policyDigest with <c>H(H(0...0 ||
/// TPM_CC_PolicyAuthorize || keySign) || policyRef)</c> — letting an object's fixed authPolicy accept a policy
/// the authority can revise at will. The policy session is a command handle with no authorization.
/// </summary>
/// <param name="PolicySession">The policy session handle being extended.</param>
/// <param name="ApprovedPolicy">The policy digest being approved; must equal the session's current policyDigest (non-trial only).</param>
/// <param name="PolicyRef">The opaque policy qualifier, folded into the replacement policyDigest unconditionally.</param>
/// <param name="KeySign">The Name of the key that signed the approval; its first two octets select aHash's hash algorithm.</param>
/// <param name="CheckTicketHierarchy">The caller-supplied hierarchy the expected ticket's proof is derived from (non-trial only).</param>
/// <param name="CheckTicketDigest">The caller-supplied ticket digest, compared against the recomputed one (non-trial only).</param>
public sealed record TpmPolicyAuthorizeRequested(
    uint PolicySession,
    ReadOnlyMemory<byte> ApprovedPolicy,
    ReadOnlyMemory<byte> PolicyRef,
    ReadOnlyMemory<byte> KeySign,
    uint CheckTicketHierarchy,
    ReadOnlyMemory<byte> CheckTicketDigest): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmVerifyPolicyAuthorizeTicketAction"/>: whether the recomputed ticket
/// matched the caller-supplied checkTicket (TPM 2.0 Library Part 3, Section 23.16). A mismatch carries
/// <c>TPM_RC_VALUE</c> — never <c>TPM_RC_TICKET</c>, never <c>TPM_RC_POLICY</c> (the reference implementation
/// folds both the approvedPolicy mismatch and the ticket mismatch into the same code). The continuation
/// resets-and-folds the policyDigest only on success. Internal to the effect loop; never arrives from the
/// command transport.
/// </summary>
/// <param name="ResponseCode"><c>TPM_RC_SUCCESS</c> when the ticket matched; otherwise <c>TPM_RC_VALUE</c>.</param>
/// <param name="PolicySession">The policy session to reset-and-fold on a successful re-verification.</param>
/// <param name="KeySign">The Name of the key that signed the approval, folded into the policyDigest fold.</param>
/// <param name="PolicyRef">The policy qualifier, always folded as the second <c>PolicyUpdate</c> hash.</param>
/// <param name="PolicyHashAlgorithm">The session's own policy hash algorithm, sizing the policyDigest fold.</param>
public sealed record TpmPolicyAuthorizeVerified(
    TpmRcConstants ResponseCode,
    uint PolicySession,
    ReadOnlyMemory<byte> KeySign,
    ReadOnlyMemory<byte> PolicyRef,
    TpmAlgIdConstants PolicyHashAlgorithm): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicyNV()</c> command (TPM 2.0 Library Part 3, clause 23.9): binds a policy to a comparison against
/// an NV Index's contents, extending its policyDigest by
/// <c>H(policyDigest ‖ TPM_CC_PolicyNV ‖ H(operandB ‖ offset ‖ operation) ‖ nvIndex.Name)</c>. On a REAL (non-trial)
/// session the retained Index data at <see cref="Offset"/> is compared to <see cref="OperandB"/> per
/// <see cref="Operation"/> before the fold, rejecting with <c>TPM_RC_POLICY</c> on a false comparison; a TRIAL
/// session skips the comparison and only the Index Name and the arguments drive the digest. The authorization
/// entity for reading the Index requires authorization, so its password session is consumed by the parser; the
/// supplied value is not retained.
/// </summary>
/// <param name="AuthHandle">The authorization handle for reading the Index (the Index itself, or a hierarchy).</param>
/// <param name="NvIndex">The NV Index whose Name is folded into the policyDigest.</param>
/// <param name="PolicySession">The policy session handle the assertion is applied to.</param>
/// <param name="OperandB">The comparison operand, copied into durable model memory.</param>
/// <param name="Offset">The octet offset into the NV Index data.</param>
/// <param name="Operation">The <c>TPM_EO</c> comparison operation value.</param>
public sealed record TpmPolicyNvRequested(
    uint AuthHandle,
    uint NvIndex,
    uint PolicySession,
    ReadOnlyMemory<byte> OperandB,
    ushort Offset,
    ushort Operation): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicyCounterTimer()</c> command (TPM 2.0 Library Part 3, Section 23.10): binds a policy to a
/// comparison against the TPM's live <c>TPMS_TIME_INFO</c> (Time, Clock, resetCount, restartCount, Safe),
/// extending its policyDigest by
/// <c>H(policyDigest ‖ TPM_CC_PolicyCounterTimer ‖ H(operandB ‖ offset ‖ operation))</c>. The offset/size range
/// checks (<c>TPM_RC_VALUE</c>/<c>TPM_RC_RANGE</c>) run for trial and real sessions alike; only the comparison
/// itself (<c>TPM_RC_POLICY</c> on a false result) is skipped for a trial session. The policy session is a
/// command handle with no authorization.
/// </summary>
/// <param name="PolicySession">The policy session handle the assertion is applied to.</param>
/// <param name="OperandB">The comparison operand, copied into durable model memory.</param>
/// <param name="Offset">The octet offset into the marshaled TPMS_TIME_INFO.</param>
/// <param name="Operation">The <c>TPM_EO</c> comparison operation value.</param>
public sealed record TpmPolicyCounterTimerRequested(
    uint PolicySession,
    ReadOnlyMemory<byte> OperandB,
    ushort Offset,
    ushort Operation): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmComputeNvNameAction"/>: the NV Index's computed Name, fed back with
/// the pending assertion's arguments so the transition can extend the policy session's policyDigest and frame
/// the <c>TPM2_PolicyNV()</c> response. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="PolicySession">The policy session whose policyDigest the assertion extends.</param>
/// <param name="NvName">The pooled buffer holding the NV Index's computed Name; released once the digest extension consumes it.</param>
/// <param name="NvNameLength">The number of valid octets in <paramref name="NvName"/>.</param>
/// <param name="OperandB">The comparison operand the pending assertion carries.</param>
/// <param name="Offset">The octet offset into the NV Index data the pending assertion carries.</param>
/// <param name="Operation">The <c>TPM_EO</c> comparison operation the pending assertion carries.</param>
public sealed record TpmNvNameComputedForPolicy(
    uint PolicySession,
    IMemoryOwner<byte> NvName,
    int NvNameLength,
    ReadOnlyMemory<byte> OperandB,
    ushort Offset,
    ushort Operation): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_FlushContext()</c> command (TPM 2.0 Library Part 3, clause 28.4): removes a loaded policy session or
/// transient object from TPM memory. The handle to flush is carried in the parameter area (not the handle area)
/// and the command takes no authorization.
/// </summary>
/// <param name="FlushHandle">The session or transient-object handle to remove.</param>
public sealed record TpmFlushContextRequested(uint FlushHandle): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_MakeCredential()</c> command (TPM 2.0 Library Part 3, clause 12.6): wraps a credential secret so
/// that only a TPM holding the private key of the credential key (the endorsement key) and loaded with the
/// object whose Name is <paramref name="ObjectName"/> (the attestation key) can recover it. The command uses only
/// the credential key's public area, so it takes no authorization; its single handle is the credential key.
/// </summary>
/// <param name="KeyHandle">The credential key (the endorsement key) whose public area protects the seed.</param>
/// <param name="Credential">The secret to wrap (a <c>TPM2B_DIGEST</c> value), copied into durable model memory.</param>
/// <param name="ObjectName">The Name the credential is bound to (the attestation key's Name), copied into durable model memory.</param>
public sealed record TpmMakeCredentialRequested(
    uint KeyHandle,
    ReadOnlyMemory<byte> Credential,
    ReadOnlyMemory<byte> ObjectName): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmMakeCredentialAction"/>: the integrity-protected, encrypted credential
/// blob and the asymmetrically-protected seed, fed back so the transition can frame the
/// <c>TPM2_MakeCredential()</c> response. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="CredentialBlob">The pooled buffer holding the <c>TPMS_ID_OBJECT</c> (the outer HMAC then the encrypted credential); disposed after framing.</param>
/// <param name="CredentialBlobLength">The number of valid octets in <paramref name="CredentialBlob"/>.</param>
/// <param name="Secret">The pooled buffer holding the seed transport (a marshaled <c>TPMS_ECC_POINT</c>, the ephemeral public point); disposed after framing.</param>
/// <param name="SecretLength">The number of valid octets in <paramref name="Secret"/>.</param>
public sealed record TpmCredentialMade(
    IMemoryOwner<byte> CredentialBlob,
    int CredentialBlobLength,
    IMemoryOwner<byte> Secret,
    int SecretLength): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_ActivateCredential()</c> command (TPM 2.0 Library Part 3, clause 12.5): recovers a credential wrapped
/// by <c>TPM2_MakeCredential()</c>, proving that the activate object (the attestation key) and the credential key
/// (the endorsement key) are loaded in the same TPM. Both handles require authorization; this is the form where
/// <c>keyHandle</c>'s session resolves to <c>TPM_RS_PW</c> — the activate object's session is always password-only
/// in this slice (Part 3, clause 5.6). A policy session on <c>keyHandle</c> instead parses as
/// <see cref="TpmActivateCredentialOverSessionRequested"/>.
/// </summary>
/// <param name="ActivateHandle">The object the credential is bound to (the attestation key); its Name re-keys the credential's integrity.</param>
/// <param name="KeyHandle">The credential key that decrypts the seed (the endorsement key); its private scalar recovers the shared value.</param>
/// <param name="CredentialBlob">The credential blob from <c>TPM2_MakeCredential()</c> (a <c>TPM2B_ID_OBJECT</c> value), copied into durable model memory.</param>
/// <param name="Secret">The encrypted seed from <c>TPM2_MakeCredential()</c> (a <c>TPM2B_ENCRYPTED_SECRET</c> value), copied into durable model memory.</param>
public sealed record TpmActivateCredentialRequested(
    uint ActivateHandle,
    uint KeyHandle,
    ReadOnlyMemory<byte> CredentialBlob,
    ReadOnlyMemory<byte> Secret): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_ActivateCredential()</c> command (TPM 2.0 Library Part 3, clause 12.5) whose <c>keyHandle</c> (the
/// credential key, USER role) is authorized by a policy session rather than a password — the form a standard
/// endorsement key (<see cref="Verifiable.Tpm.Infrastructure.Commands.CreatePrimaryInput.ForEndorsementKey"/>,
/// whose <c>authPolicy</c> is "PolicyA" and whose <c>userWithAuth</c> attribute is CLEAR) requires (Part 3, clause
/// 5.6). <c>activateHandle</c> stays password-authorized in this slice, exactly as in
/// <see cref="TpmActivateCredentialRequested"/>.
/// </summary>
/// <param name="ActivateHandle">The object the credential is bound to (the attestation key), password-authorized (ADMIN role).</param>
/// <param name="KeyHandle">The credential key (the endorsement key) whose <c>authPolicy</c> the policy session must satisfy (USER role).</param>
/// <param name="CredentialBlob">The credential blob from <c>TPM2_MakeCredential()</c> (a <c>TPM2B_ID_OBJECT</c> value), copied into durable model memory.</param>
/// <param name="Secret">The encrypted seed from <c>TPM2_MakeCredential()</c> (a <c>TPM2B_ENCRYPTED_SECRET</c> value), copied into durable model memory.</param>
/// <param name="KeyPolicySession">The policy session handle authorizing <paramref name="KeyHandle"/>.</param>
/// <param name="KeyPolicyAttributes">
/// The policy session's command session-attributes byte. Unused by the response: <c>TPM2_ActivateCredential()</c>'s
/// response is framed <c>TPM_ST_NO_SESSIONS</c> regardless (see <see cref="TpmActivateCredentialResponse"/>), so
/// there is no response session entry to echo it into — the same simplification
/// <see cref="TpmUnsealOverSessionsRequested"/>'s no-encrypt-session branch relies on.
/// </param>
public sealed record TpmActivateCredentialOverSessionRequested(
    uint ActivateHandle,
    uint KeyHandle,
    ReadOnlyMemory<byte> CredentialBlob,
    ReadOnlyMemory<byte> Secret,
    uint KeyPolicySession,
    byte KeyPolicyAttributes): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmActivateCredentialAction"/>: either the recovered credential secret
/// (on success) or a failure code (when the credential's integrity does not verify against the activate object's
/// Name), fed back so the transition can frame the <c>TPM2_ActivateCredential()</c> response. Internal to the
/// effect loop; never arrives from the command transport.
/// </summary>
/// <remarks>
/// On success <paramref name="CertInfo"/> holds the recovered secret and <paramref name="ResponseCode"/> is
/// <c>TPM_RC_SUCCESS</c>; on an integrity mismatch <paramref name="CertInfo"/> is <see langword="null"/> and
/// <paramref name="ResponseCode"/> carries the rejection (<c>TPM_RC_INTEGRITY</c>, TPM 2.0 Library Part 3, clause
/// 12.5). The buffer holds a confidential value, so the framing step zeroes it before releasing it.
/// </remarks>
/// <param name="ResponseCode">The command response code: success, or the integrity-failure rejection.</param>
/// <param name="CertInfo">The pooled buffer holding the recovered credential secret; <see langword="null"/> on rejection; disposed after framing.</param>
/// <param name="CertInfoLength">The number of valid octets in <paramref name="CertInfo"/> (zero on rejection).</param>
public sealed record TpmCredentialActivated(
    TpmRcConstants ResponseCode,
    IMemoryOwner<byte>? CertInfo,
    int CertInfoLength): TpmSimulatorInput;

/// <summary>
/// A command whose code the lifecycle skeleton does not yet model. It is gated by the current phase
/// like any other command (rejected with the phase-appropriate response code).
/// </summary>
/// <param name="CommandCode">The unsupported command code as parsed from the request header.</param>
public sealed record TpmUnsupportedCommandReceived(TpmCcConstants CommandCode): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Create()</c> command (TPM 2.0 Library Part 3, clause 12.1) whose parent authorization is either a
/// bound HMAC session or a <c>TPM_RS_PW</c> password session, optionally paired with a SEPARATE bound HMAC
/// session carrying the <c>decrypt</c> attribute that protects <c>inSensitive</c> (Part 1, clauses 19 and 21).
/// Unlike <see cref="TpmCreateSealedObjectRequested"/> (the plain single-password form, left untouched), NONE of
/// <c>inSensitive</c>/<c>inPublic</c>/<c>outsideInfo</c>/<c>creationPCR</c> is decoded at parse time: every
/// command handle's command-HMAC must verify (Part 3, clause 5.6) strictly BEFORE any parameter is interpreted
/// (clause 5.8), and <c>inPublic</c>'s own start offset within the parameter area depends on <c>inSensitive</c>'s
/// declared size — a value that is itself validated only after decryption (clause 5.7), so trusting it to locate
/// <c>inPublic</c> any earlier would interpret unauthenticated, possibly-still-encrypted content. Only the raw
/// parameter-area bytes are captured; <see cref="Automata.TpmDecryptCreateSensitiveAction"/> decodes everything
/// once every session's command HMAC has verified and (if present) the decrypt session has run.
/// </summary>
/// <param name="ParentHandle">The loaded storage parent under which the object is created.</param>
/// <param name="FirstSession">The parent-authorizing session's handle (<c>TPM_RH_PW</c> or a bound HMAC session).</param>
/// <param name="FirstNonceCaller">The first session's caller nonce rolled for this command, copied into durable model memory. Empty for the password form.</param>
/// <param name="FirstAttributes">The first session's command session-attributes byte.</param>
/// <param name="FirstHmac">The first session's supplied <c>hmac</c> field (the real command HMAC for an HMAC session, or the plaintext password for <c>TPM_RH_PW</c> — discarded exactly as <see cref="TpmCreateSealedObjectRequested"/>'s plain form already does, since the parent carries no retained authValue in this model).</param>
/// <param name="DecryptSession">The bound HMAC session handle whose <c>decrypt</c> attribute protects <c>inSensitive</c>, or <c>0</c> when the command carried only the first session.</param>
/// <param name="DecryptNonceCaller">The decrypt session's caller nonce rolled for this command, copied into durable model memory; the nonceNewer of the command-direction decryption and that session's own command-HMAC verification. Empty when there is no decrypt session.</param>
/// <param name="DecryptAttributes">The decrypt session's command session-attributes byte. Zero when there is no decrypt session.</param>
/// <param name="DecryptHmac">The decrypt session's supplied <c>hmac</c> field, copied into durable model memory. Empty when there is no decrypt session.</param>
/// <param name="RawParameterArea">The raw <c>inSensitive ‖ inPublic ‖ outsideInfo ‖ creationPCR</c> wire bytes exactly as received (still encrypted, if a decrypt session is present) — cpHash's parameter term (Part 1, clause 18.7 equation 15) and the buffer every field is later decoded from.</param>
public sealed record TpmCreateSealedObjectOverSessionsRequested(
    uint ParentHandle,
    uint FirstSession,
    ReadOnlyMemory<byte> FirstNonceCaller,
    byte FirstAttributes,
    ReadOnlyMemory<byte> FirstHmac,
    uint DecryptSession,
    ReadOnlyMemory<byte> DecryptNonceCaller,
    byte DecryptAttributes,
    ReadOnlyMemory<byte> DecryptHmac,
    ReadOnlyMemory<byte> RawParameterArea): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="Automata.TpmDecryptCreateSensitiveAction"/>: <c>inSensitive</c> is
/// decrypted first (if a decrypt session was present, Part 1, clause 21), then <c>inSensitive ‖ inPublic ‖
/// outsideInfo ‖ creationPCR</c> are ALL decoded here — strictly after the command HMAC(s) verified (Part 3,
/// clause 5.6 precedes clause 5.8) — with bounds-checked reads so a wrong decryption key's garbage bytes report
/// a failure code rather than crash the simulator. <see cref="SizeFailureBlamesDecryptSession"/> distinguishes a
/// truncated/oversized <c>inSensitive</c> declared size (session-index-encoded to the decrypt session, since the
/// size problem surfaces only while attempting to decrypt) from every other malformation (reported bare, exactly
/// as the plain password form's parser already does). Internal to the effect loop; never arrives from the
/// command transport.
/// </summary>
/// <param name="ResponseCode"><c>TPM_RC_SUCCESS</c> when every field decoded; otherwise the rejection.</param>
/// <param name="SizeFailureBlamesDecryptSession">
/// Whether <paramref name="ResponseCode"/> is <c>TPM_RC_SIZE</c> caused by <c>inSensitive</c>'s own declared size
/// while a decrypt session was present — the ONE failure this wave session-index-encodes to that session; every
/// other rejection (a generic parameter malformation, or the SAME size problem with no decrypt session to blame)
/// is reported bare.
/// </param>
/// <param name="Request">The original parsed command request, threaded through so the completing transition can resolve the sessions needing a real response entry.</param>
/// <param name="NameAlg">The Name algorithm carried in <c>inPublic</c>. Empty/default on failure.</param>
/// <param name="AuthPolicy">The authorization policy digest carried in <c>inPublic</c> (empty when the seal is authorized by its authValue alone). Empty on failure.</param>
/// <param name="NoDa">Whether <c>inPublic</c> sets <c>TPMA_OBJECT.noDA</c>. Meaningless on failure.</param>
/// <param name="UserWithAuth">Whether <c>inPublic</c> sets <c>TPMA_OBJECT.userWithAuth</c>. Meaningless on failure.</param>
/// <param name="SecretData">The decoded (plaintext) data to seal. Empty on failure.</param>
/// <param name="UserAuth">The decoded (plaintext) authorization value for the new object's <c>userAuth</c>. Empty on failure.</param>
public sealed record TpmCreateSensitiveDecrypted(
    TpmRcConstants ResponseCode,
    bool SizeFailureBlamesDecryptSession,
    TpmCreateSealedObjectOverSessionsRequested Request,
    TpmAlgIdConstants NameAlg,
    ReadOnlyMemory<byte> AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    ReadOnlyMemory<byte> SecretData,
    ReadOnlyMemory<byte> UserAuth): TpmSimulatorInput;

/// <summary>
/// One session's material for framing a real per-session <c>TPM2_Create()</c> response entry over sessions
/// (the request-decrypt counterpart of <see cref="TpmUnsealResponseSession"/>): the effect rolls a fresh
/// nonceTPM and computes a real response HMAC for it, keyed on THE SAME <c>sessionKey ‖ authValue</c> its
/// command-HMAC verification used (Part 1, clause 19.6.8). Response-direction parameter encryption is out of
/// this wave's scope for <c>TPM2_Create()</c>, so every entry's own <c>outPrivate</c>/<c>outPublic</c>/creation
/// by-products are always returned in the clear.
/// </summary>
/// <param name="SessionHandle">The session handle whose nonceTPM is rolled once framed.</param>
/// <param name="SessionAlg">The session hash algorithm driving rpHash and the response HMAC.</param>
/// <param name="SessionKey">The session key.</param>
/// <param name="AuthValue">The authValue folded into the response HMAC key alongside <see cref="SessionKey"/> — the same value (and the same bind-omission decision) the command-HMAC verification used.</param>
/// <param name="NonceCaller">This session's command caller nonce (the response HMAC's nonceOlder).</param>
/// <param name="SessionAttributes">This session's command session-attributes octet, echoed into its response entry.</param>
public sealed record TpmCreateResponseSession(
    uint SessionHandle,
    TpmAlgIdConstants SessionAlg,
    ReadOnlyMemory<byte> SessionKey,
    ReadOnlyMemory<byte> AuthValue,
    ReadOnlyMemory<byte> NonceCaller,
    byte SessionAttributes);

/// <summary>
/// One already-verified session's framed real <c>TPM2_Create()</c> response entry — the rolled nonceTPM and
/// computed response HMAC produced from a <see cref="TpmCreateResponseSession"/> (the request-decrypt
/// counterpart of <see cref="TpmUnsealFramedSessionEntry"/>).
/// </summary>
/// <param name="SessionHandle">The session whose nonceTPM is rolled to <paramref name="NewNonceTpm"/>.</param>
/// <param name="NewNonceTpm">The freshly generated nonceTPM: framed as this entry's nonceNewer and stored as the session's rolled nonce.</param>
/// <param name="SessionAttributes">The response session-attributes octet, framed and folded into the response HMAC exactly as it was HMAC'd.</param>
/// <param name="Hmac">The response HMAC over <c>rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes</c>; disposed after framing.</param>
/// <param name="HmacLength">The number of valid octets in <paramref name="Hmac"/>.</param>
public sealed record TpmCreateFramedSessionEntry(
    uint SessionHandle,
    ReadOnlyMemory<byte> NewNonceTpm,
    byte SessionAttributes,
    IMemoryOwner<byte> Hmac,
    int HmacLength);

/// <summary>
/// The result of executing a <see cref="Automata.TpmSealDataOverSessionsAction"/>: the framed (unencrypted)
/// response parameter area and every real session's framed response entry, fed back so the transition can roll
/// each session's stored nonce and frame the response (the request-decrypt counterpart of
/// <see cref="TpmUnsealedOverSessions"/>). Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <remarks>
/// <see cref="ParameterArea"/> is a pooled buffer the framing step disposes as the terminal owner; each
/// <see cref="TpmCreateFramedSessionEntry"/> in <see cref="Entries"/> owns its own <c>Hmac</c> buffer the same way.
/// </remarks>
/// <param name="ParameterArea">The framed <c>outPrivate ‖ outPublic ‖ creationData ‖ creationHash ‖ creationTicket</c> response parameter area; disposed after framing.</param>
/// <param name="ParameterLength">The number of valid octets in <paramref name="ParameterArea"/>.</param>
/// <param name="HasPasswordPlaceholder">Whether session index 0 is a <c>TPM_RS_PW</c> session needing the empty-nonce, empty-HMAC password placeholder entry (Part 1, clause 19.4).</param>
/// <param name="PasswordPlaceholderAttributes">The password session's command session-attributes byte, framed into its placeholder entry (continueSession is unconditionally SET for a password session, Part 1, clause 19.4). Meaningful only when <see cref="HasPasswordPlaceholder"/> is set.</param>
/// <param name="Entries">Every real session's framed response entry, in command-session order (after the password placeholder, when present).</param>
public sealed record TpmObjectSealedOverSessions(
    IMemoryOwner<byte> ParameterArea,
    int ParameterLength,
    bool HasPasswordPlaceholder,
    byte PasswordPlaceholderAttributes,
    ImmutableArray<TpmCreateFramedSessionEntry> Entries): TpmSimulatorInput;
