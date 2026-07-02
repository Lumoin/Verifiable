using System;
using System.Buffers;
using System.Collections.Immutable;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

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
/// after authorizing against it. This slice models Index authorization (the authorization handle is the
/// Index itself); owner- and policy-authorized reads arrive later.
/// </summary>
/// <param name="AuthHandle">The authorization handle (<c>TPMI_RH_NV_AUTH</c>); for Index authorization this equals <paramref name="NvIndex"/>.</param>
/// <param name="NvIndex">The NV Index to read.</param>
/// <param name="AuthSupplied">The authorization value the caller supplied (the password session's plaintext authValue), compared against the Index authValue.</param>
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
public sealed record TpmNvUndefineSpaceRequested(
    uint AuthHandle,
    uint NvIndex): TpmSimulatorInput;

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
public sealed record TpmCreatePrimaryRequested(
    uint Hierarchy,
    TpmAlgIdConstants NameAlg,
    TpmaObject Attributes,
    TpmEccCurveConstants Curve,
    TpmAlgIdConstants SchemeHashAlg): TpmSimulatorInput;

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
public sealed record TpmCreateRsaPrimaryRequested(
    uint Hierarchy,
    TpmAlgIdConstants NameAlg,
    TpmaObject Attributes,
    ushort KeyBits,
    TpmtRsaScheme Scheme): TpmSimulatorInput;

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
public sealed record TpmCreateStorageParentRequested(
    uint Hierarchy,
    TpmAlgIdConstants NameAlg,
    TpmaObject Attributes,
    TpmEccCurveConstants Curve,
    bool NoDa): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Create()</c> command that seals caller-supplied data into a KEYEDHASH object under a loaded storage
/// parent (TPM 2.0 Library Part 3, clause 12.1). The object is returned as a wrapped private blob plus its public
/// area; the TPM stores nothing, so the caller persists the blob and reloads it with <c>TPM2_Load()</c>.
/// </summary>
/// <param name="ParentHandle">The loaded storage parent under which the object is sealed.</param>
/// <param name="NameAlg">The Name algorithm carried in the sealed object's public area.</param>
/// <param name="AuthPolicy">The authorization policy digest bound to the object (empty when the seal is authorized by its authValue alone), re-emitted into the exported public area.</param>
/// <param name="NoDa">Whether the template sets <c>TPMA_OBJECT.noDA</c>, re-derived so the exported public area reproduces the caller's template.</param>
/// <param name="SecretData">The data to seal, copied into durable model memory.</param>
public sealed record TpmCreateSealedObjectRequested(
    uint ParentHandle,
    TpmAlgIdConstants NameAlg,
    ReadOnlyMemory<byte> AuthPolicy,
    bool NoDa,
    ReadOnlyMemory<byte> SecretData): TpmSimulatorInput;

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
/// <param name="PublicAreaBytes">The marshaled <c>TPMT_PUBLIC</c> the Name is hashed over (copied into durable model memory).</param>
/// <param name="PrivateBlob">The wrapped private blob carrying the sealed data (the simulator's own encoding of the sensitive area).</param>
public sealed record TpmLoadObjectRequested(
    uint ParentHandle,
    TpmAlgIdConstants ObjectType,
    TpmAlgIdConstants NameAlg,
    ReadOnlyMemory<byte> AuthPolicy,
    ReadOnlyMemory<byte> PublicAreaBytes,
    ReadOnlyMemory<byte> PrivateBlob): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Unseal()</c> command (TPM 2.0 Library Part 3, clause 12.7) that recovers the data sealed in a loaded
/// KEYEDHASH object. The object must be loaded (its transient handle is the command handle).
/// </summary>
/// <param name="ItemHandle">The transient handle of the loaded sealed data object.</param>
public sealed record TpmUnsealRequested(uint ItemHandle): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Unseal()</c> command (TPM 2.0 Library Part 3, clause 12.7) authorized by a policy session and carrying
/// a second bound HMAC session with the <c>encrypt</c> attribute — the policy-gated, confidentiality-protected form.
/// The command's authorization area carries two sessions in order: session 1 is the policy session whose accumulated
/// policyDigest authorizes the object (empty-HMAC authorization, the policy itself is the authorization, Part 1,
/// clause 19.6), and session 2 is a bound HMAC session that encrypts the recovered <c>outData</c> (Part 1, clauses
/// 18.7 and 19). The command HMACs are consumed during parsing but not verified — <c>TPM2_Unseal()</c>'s command-side
/// integrity is not the property under test here; the policy gate and the response-side HMAC and parameter
/// encryption are.
/// </summary>
/// <param name="ItemHandle">The transient handle of the loaded sealed data object.</param>
/// <param name="PolicySession">The policy session handle whose accumulated policyDigest must reproduce the object's authPolicy.</param>
/// <param name="PolicyAttributes">The policy session's command session-attributes byte, echoed into its response session entry.</param>
/// <param name="EncryptSession">The bound HMAC session handle whose <c>encrypt</c> attribute protects the recovered <c>outData</c>, or <c>0</c> when the command carried only the policy session (the recovered <c>outData</c> is then returned in the clear).</param>
/// <param name="EncryptNonceCaller">The encrypt session's caller nonce rolled for this command, copied into durable model memory; the nonceOlder of the response-direction encryption and the response HMAC (Part 1, clause 19.2). Empty when there is no encrypt session.</param>
/// <param name="EncryptAttributes">The encrypt session's command session-attributes byte, echoed into the response session area and folded into the response HMAC. Zero when there is no encrypt session.</param>
public sealed record TpmUnsealOverSessionsRequested(
    uint ItemHandle,
    uint PolicySession,
    byte PolicyAttributes,
    uint EncryptSession,
    ReadOnlyMemory<byte> EncryptNonceCaller,
    byte EncryptAttributes): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmUnsealDataAction"/>: the framed (encrypted) response parameter area, the
/// encrypt session's freshly rolled nonceTPM, and the encrypt session's response HMAC, fed back so the transition can
/// roll the session nonce and frame the two-session response. Internal to the effect loop; never arrives from the
/// command transport.
/// </summary>
/// <remarks>
/// <see cref="ParameterArea"/> and <see cref="Hmac"/> are pooled buffers the framing step disposes as the terminal
/// owner. <see cref="NewNonceTpm"/> is carried as <see cref="ReadOnlyMemory{T}"/> because it is both framed into the
/// encrypt session's response entry and stored on the durable session as its rolled nonceTPM.
/// </remarks>
/// <param name="EncryptSessionHandle">The encrypt HMAC session whose nonceTPM is rolled to <paramref name="NewNonceTpm"/>.</param>
/// <param name="NewNonceTpm">The freshly generated nonceTPM: framed in the encrypt session's response entry (nonceNewer) and stored as the session's rolled nonce.</param>
/// <param name="EncryptAttributes">The encrypt session's response session-attributes byte, framed and folded into the response HMAC exactly as it was HMAC'd.</param>
/// <param name="ParameterArea">The framed <c>TPM2B_SENSITIVE_DATA</c> response parameter (<c>outData</c>) with its data portion encrypted; disposed after framing.</param>
/// <param name="ParameterLength">The number of valid octets in <paramref name="ParameterArea"/>.</param>
/// <param name="Hmac">The encrypt session's response HMAC over <c>rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes</c>; disposed after framing.</param>
/// <param name="HmacLength">The number of valid octets in <paramref name="Hmac"/>.</param>
/// <param name="PolicyNonceLength">The width in octets of the policy session's response nonce (its hash digest width), framed as a zero placeholder.</param>
/// <param name="PolicyAttributes">The policy session's response session-attributes byte, framed into its response entry.</param>
public sealed record TpmUnsealedOverSessions(
    uint EncryptSessionHandle,
    ReadOnlyMemory<byte> NewNonceTpm,
    byte EncryptAttributes,
    IMemoryOwner<byte> ParameterArea,
    int ParameterLength,
    IMemoryOwner<byte> Hmac,
    int HmacLength,
    int PolicyNonceLength,
    byte PolicyAttributes): TpmSimulatorInput;

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
public sealed record TpmObjectLoaded(
    uint Handle,
    IMemoryOwner<byte> Name,
    int NameLength,
    ReadOnlyMemory<byte> Data,
    ReadOnlyMemory<byte> AuthPolicy): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Certify()</c> command (TPM 2.0 Library Part 3, clause 18.2): a signing key vouches that an object
/// with a given Name is loaded in the same TPM, over a caller nonce. Both handles require authorization, so the
/// two authorization sessions are consumed by the parser; the objects this slice certifies carry empty auth, so
/// the supplied authorization values are not retained.
/// </summary>
/// <param name="ObjectHandle">The loaded object being certified (its Name is the attested binding).</param>
/// <param name="SignHandle">The loaded signing key that attests, whose retained scalar signs the marshaled attestation.</param>
/// <param name="QualifyingData">The caller nonce echoed into the attestation's <c>extraData</c>, copied into durable model memory.</param>
/// <param name="SignatureScheme">The signing scheme algorithm (<c>TPM_ALG_ECDSA</c> this slice).</param>
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
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c>), selecting how the signature is framed.</param>
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
/// <param name="SignHandle">The loaded signing key that attests, whose retained scalar signs the marshaled attestation.</param>
/// <param name="QualifyingData">The caller nonce echoed into the attestation's <c>extraData</c>, copied into durable model memory.</param>
/// <param name="SignatureScheme">The signing scheme algorithm (<c>TPM_ALG_ECDSA</c> this slice).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm; the simulator also computes the PCR composite digest with it.</param>
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
/// A <c>TPM2_StartAuthSession()</c> command (TPM 2.0 Library Part 3, clause 11.1) that starts a bound, unsalted
/// HMAC session with parameter encryption. It is the parameter-encryption counterpart of
/// <see cref="TpmStartAuthSessionRequested"/>: the session key is derived from the bind entity's authorization
/// value and the two start nonces (Part 1, clause 17.6.10 equation 20), and the negotiated symmetric definition
/// keys the encryption of the first response parameter. The tests bind to a transient object carrying empty auth
/// and negotiate XOR obfuscation or AES-CFB; the tpmKey and salt fields are consumed during parsing but not
/// modelled (this slice is unsalted).
/// </summary>
/// <param name="Bind">The entity the session binds to, whose authorization value seeds the session key (<c>TPM_RH_NULL</c> for an unbound session).</param>
/// <param name="NonceCaller">The caller nonce sent at start, copied into durable model memory; it is the second context field of the session-key KDFa (Part 1, clause 17.6.10).</param>
/// <param name="Symmetric">The symmetric definition negotiated for parameter encryption (XOR obfuscation, AES-CFB, or <c>TPM_ALG_NULL</c>).</param>
/// <param name="AuthHash">The session hash algorithm (<c>authHash</c>), which drives the KDFa derivations and sizes the returned nonceTPM.</param>
public sealed record TpmStartHmacSessionRequested(
    uint Bind,
    ReadOnlyMemory<byte> NonceCaller,
    TpmtSymDef Symmetric,
    TpmAlgIdConstants AuthHash): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmAction"/> that started a bound HMAC session: the freshly generated
/// nonceTPM and the derived session key, fed back so the transition can record the session and frame the
/// <c>TPM2_StartAuthSession()</c> response. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <remarks>
/// The nonce and session key are carried as <see cref="ReadOnlyMemory{T}"/> (copied into durable model memory by
/// the effect) because the transition stores them on the durable <see cref="HmacSessionState"/> for the lifetime
/// of the session, rather than framing-then-disposing a pooled buffer.
/// </remarks>
/// <param name="SessionHandle">The session handle the transition allocated for the new session.</param>
/// <param name="SessionAlg">The session hash algorithm to record on the session.</param>
/// <param name="Symmetric">The negotiated symmetric definition to record on the session.</param>
/// <param name="NonceTpm">The initial nonceTPM: generated from the injected RNG and framed in the response, also the second-to-last context of the response-direction encryption once rolled.</param>
/// <param name="SessionKey">The <c>KDFa</c>-derived session key to record on the session (the HMAC and parameter-encryption key).</param>
public sealed record TpmHmacSessionStarted(
    uint SessionHandle,
    TpmAlgIdConstants SessionAlg,
    TpmtSymDef Symmetric,
    ReadOnlyMemory<byte> NonceTpm,
    ReadOnlyMemory<byte> SessionKey): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_GetRandom()</c> command (TPM 2.0 Library Part 3, clause 16.1) carried over a bound HMAC session with
/// the <c>encrypt</c> attribute set. Unlike <see cref="TpmGetRandomRequested"/> (the unauthorized, no-session
/// form) this carries the command's authorization-area fields the response path needs: the rolled caller nonce
/// and the session attributes. The command HMAC is consumed during parsing but not verified — <c>GetRandom</c>
/// authorizes no entity, so its command-side integrity is not under test; the response-side HMAC and parameter
/// encryption are (Part 1, clauses 18.7 and 19).
/// </summary>
/// <param name="SessionHandle">The HMAC session the command runs over.</param>
/// <param name="NonceCaller">The caller nonce rolled for this command, copied into durable model memory; the nonceOlder of the response-direction encryption and the response HMAC (Part 1, clause 19.2).</param>
/// <param name="SessionAttributes">The command's session attributes byte, echoed into the response session area and folded into the response HMAC.</param>
/// <param name="BytesRequested">The number of random octets the caller requested (clamped as in the no-session form).</param>
public sealed record TpmGetRandomOverSessionRequested(
    uint SessionHandle,
    ReadOnlyMemory<byte> NonceCaller,
    byte SessionAttributes,
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
/// A <c>TPM2_PolicyNV()</c> command (TPM 2.0 Library Part 3, clause 23.9): binds a policy to a comparison against
/// an NV Index's contents, extending its policyDigest by
/// <c>H(policyDigest ‖ TPM_CC_PolicyNV ‖ H(operandB ‖ offset ‖ operation) ‖ nvIndex.Name)</c>. On a trial session
/// no live NV data comparison is performed — only the Index Name and the arguments drive the digest. The
/// authorization entity for reading the Index requires authorization, so its password session is consumed by the
/// parser; the supplied value is not retained.
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
/// (the endorsement key) are loaded in the same TPM. Both handles require authorization, so the parser consumes
/// two password sessions in handle order.
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
