using System;
using System.Buffers;
using System.Collections.Immutable;
using Verifiable.Cryptography;
using Verifiable.Foundation.Automata;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// Base type for the effectful actions a TPM command transition can declare. A
/// <see cref="TpmAction"/> is produced by the pure transition function as part of the next state
/// (carried in <see cref="TpmSimulatorState.NextAction"/>); the effectful loop in
/// <see cref="TpmSimulator"/> dispatches it to a backend and feeds the result back as the next input.
/// </summary>
/// <remarks>
/// The lifecycle commands modelled in V.2 (<c>TPM2_Startup()</c>, <c>TPM2_Shutdown()</c>,
/// <c>TPM2_SelfTest()</c>, <c>TPM2_GetTestResult()</c>) declare no effects and leave
/// <see cref="NullAction.Instance"/> in place. The first command that needs an effect is
/// <c>TPM2_GetRandom()</c>, whose <see cref="TpmRngAction"/> asks the injected RNG backend for octets.
/// </remarks>
public abstract record TpmAction: PdaAction;

/// <summary>
/// Declares that the simulator must draw <paramref name="ByteCount"/> random octets from its RNG
/// backend before the next transition. Emitted by the <c>TPM2_GetRandom()</c> transition; the
/// effectful loop fills a pooled buffer via the injected backend and feeds the bytes back as a
/// <see cref="TpmRandomGenerated"/> input (TPM 2.0 Library Part 3, clause 16.1).
/// </summary>
/// <param name="ByteCount">
/// The number of octets to produce, already clamped to the largest digest the simulated TPM can
/// return (<see cref="TpmLifecycleTransitions.MaxRandomBytes"/>).
/// </param>
public sealed record TpmRngAction(int ByteCount): TpmAction;

/// <summary>
/// Declares that the simulator must generate an ECC signing key before the next transition. Emitted by the
/// <c>TPM2_CreatePrimary()</c> transition; the effectful loop draws a key from the injected
/// <see cref="TpmEccSigningBackend"/>, builds the exported public area and durable key state from it, and
/// feeds them back as a <see cref="TpmPrimaryKeyCreated"/> input (TPM 2.0 Library Part 3, clause 24.1).
/// </summary>
/// <remarks>
/// The action carries the template fields the effect needs to build the exported public area and the
/// transient-key state — the handle the transition allocated, the Name algorithm, the object attributes,
/// and the signing scheme's hash — so no creation context has to be stashed in the automaton state across
/// the effect.
/// </remarks>
/// <param name="Handle">The transient handle the transition allocated for the new object.</param>
/// <param name="Hierarchy">The hierarchy the object is created under (its handle becomes the parent Name and the ticket hierarchy).</param>
/// <param name="NameAlg">The Name algorithm to carry in the exported public area and to compute the object Name with.</param>
/// <param name="Attributes">The object attributes to carry in the exported public area.</param>
/// <param name="Curve">The ECC curve to generate the key on.</param>
/// <param name="SchemeHashAlg">The ECDSA signing scheme's hash algorithm.</param>
/// <param name="AuthPolicy">The authorization policy digest to re-emit into the exported public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92; empty for an authValue-only key), the owned pooled carrier the request parsed; ownership rides this action into the effect, which installs it on the durable key state.</param>
/// <param name="UserAuth">The new object's authorization value (<c>inSensitive.userAuth</c>), the owned <see cref="Tpm2bAuth"/> carrier the request parsed; ownership rides this action into the effect, which installs it on the durable key state. The dispose-immune empty sentinel for an authValue-free key.</param>
public sealed record TpmCreateEccKeyAction(
    TpmiDhObject Handle,
    TpmiRhHierarchy Hierarchy,
    TpmiAlgHash NameAlg,
    TpmaObject Attributes,
    TpmiEccCurve Curve,
    TpmiAlgHash SchemeHashAlg,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth UserAuth): TpmAction;

/// <summary>
/// Declares that the simulator must generate an RSA signing key before the next transition — the RSA
/// counterpart of <see cref="TpmCreateEccKeyAction"/>. Emitted by the <c>TPM2_CreatePrimary()</c> transition
/// for an RSA template; the effectful loop draws a key from the injected <see cref="TpmRsaSigningBackend"/>,
/// builds the exported public area carrying the modulus and the durable key state, and feeds them back as a
/// <see cref="TpmPrimaryKeyCreated"/> input (TPM 2.0 Library Part 3, clause 24.1).
/// </summary>
/// <param name="Handle">The transient handle the transition allocated for the new object.</param>
/// <param name="Hierarchy">The hierarchy the object is created under (its handle becomes the parent Name and the ticket hierarchy).</param>
/// <param name="NameAlg">The Name algorithm to carry in the exported public area and to compute the object Name with.</param>
/// <param name="Attributes">The object attributes to carry in the exported public area.</param>
/// <param name="KeyBits">The RSA modulus size in bits to generate.</param>
/// <param name="Scheme">The RSA signing scheme carried in the template (echoed into the exported public area).</param>
/// <param name="AuthPolicy">The authorization policy digest to re-emit into the exported public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92; empty for an authValue-only key), the owned pooled carrier the request parsed; ownership rides this action into the effect, which installs it on the durable key state.</param>
/// <param name="UserAuth">The new object's authorization value (<c>inSensitive.userAuth</c>), the owned <see cref="Tpm2bAuth"/> carrier the request parsed; ownership rides this action into the effect, which installs it on the durable key state. The dispose-immune empty sentinel for an authValue-free key.</param>
public sealed record TpmCreateRsaKeyAction(
    TpmiDhObject Handle,
    TpmiRhHierarchy Hierarchy,
    TpmiAlgHash NameAlg,
    TpmaObject Attributes,
    TpmiRsaKeyBits KeyBits,
    TpmtRsaScheme Scheme,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth UserAuth): TpmAction;

/// <summary>
/// Declares that the simulator must sign a digest with a retained key before the next transition. Emitted
/// by the <c>TPM2_Sign()</c> transition; the effectful loop signs the digest through the injected
/// <see cref="TpmEccSigningBackend"/> and feeds the signature back as a <see cref="TpmMessageSigned"/>
/// input (TPM 2.0 Library Part 3, clause 20.2).
/// </summary>
/// <param name="Scalar">The signing key's retained private scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="Digest">The pre-computed digest to sign directly (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="Curve">The ECC curve the scalar lives on.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, reported inside the signature.</param>
public sealed record TpmEccSignAction(
    PrivateKeyMemory Scalar,
    Tpm2bDigest Digest,
    TpmiEccCurve Curve,
    TpmiAlgHash HashAlg): TpmAction;

/// <summary>
/// Declares that the simulator must sign a digest with a retained RSA key before the next transition — the RSA
/// counterpart of <see cref="TpmEccSignAction"/>. Emitted by the <c>TPM2_Sign()</c> transition for an RSA key;
/// the effectful loop signs the digest through the injected <see cref="TpmRsaSigningBackend"/> and feeds the
/// signature back as a <see cref="TpmMessageSigned"/> input (TPM 2.0 Library Part 3, clause 20.2).
/// </summary>
/// <param name="PrivateKey">The signing key's retained private key, in the backend's encoding — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="Digest">The pre-computed digest to sign directly (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to apply.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, reported inside the signature.</param>
public sealed record TpmRsaSignAction(
    PrivateKeyMemory PrivateKey,
    Tpm2bDigest Digest,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash HashAlg): TpmAction;

/// <summary>
/// Declares that the simulator must provision an ECC restricted storage key before the next transition. Emitted
/// by the <c>TPM2_CreatePrimary()</c> transition for a storage-parent template; the effectful loop builds the
/// exported storage public area and the durable parent state (no key material — the simulator does not wrap
/// children under a parent key) plus the faithful creation by-products, and feeds them back as a
/// <see cref="TpmPrimaryKeyCreated"/> input (TPM 2.0 Library Part 3, clause 24.1).
/// </summary>
/// <param name="Handle">The transient handle the transition allocated for the new parent.</param>
/// <param name="Hierarchy">The hierarchy the parent is created under (its handle becomes the parent Name and the ticket hierarchy).</param>
/// <param name="NameAlg">The Name algorithm to carry in the exported public area and to compute the object Name with.</param>
/// <param name="Attributes">The storage object attributes to record on the parent (<c>RESTRICTED</c> and <c>DECRYPT</c>).</param>
/// <param name="Curve">The ECC curve the storage template names.</param>
/// <param name="NoDa">Whether the template set <c>TPMA_OBJECT.noDA</c>, so the exported public area reproduces the caller's template.</param>
/// <param name="AuthPolicy">
/// The authorization policy digest to re-emit into the exported public area (<c>TPM2B_DIGEST</c>, TPM 2.0
/// Library Part 2, clause 10.4.2, Table 92; empty for the generic storage parent; a standard endorsement
/// key's "PolicyA" otherwise), the owned pooled carrier the request parsed; ownership rides this action into
/// the effect, which installs it on the durable parent state.
/// </param>
/// <param name="UserAuth">The new object's authorization value (<c>inSensitive.userAuth</c>), the owned <see cref="Tpm2bAuth"/> carrier the request parsed; ownership rides this action into the effect, which installs it on the durable parent state. The dispose-immune empty sentinel for an authValue-free parent.</param>
public sealed record TpmCreateStorageParentAction(
    TpmiDhObject Handle,
    TpmiRhHierarchy Hierarchy,
    TpmiAlgHash NameAlg,
    TpmaObject Attributes,
    TpmiEccCurve Curve,
    bool NoDa,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth UserAuth): TpmAction;

/// <summary>
/// Declares that the simulator must generate an RSA key before the next transition — the RSA counterpart of
/// <see cref="TpmCreateStorageParentAction"/>. Emitted by the <c>TPM2_CreatePrimary()</c> transition for an RSA
/// storage-shaped template (including the standard RSA endorsement key); the effectful loop draws a key from
/// the injected <see cref="TpmRsaSigningBackend"/>, builds the exported storage public area carrying the actual
/// modulus, and retains the modulus on the durable key state (unlike <see cref="TpmCreateRsaKeyAction"/>'s
/// signing path, which does not) so a later RSA-OAEP secret-transport command can use it (TPM 2.0 Library Part
/// 3, clause 24.1).
/// </summary>
/// <param name="Handle">The transient handle the transition allocated for the new parent.</param>
/// <param name="Hierarchy">The hierarchy the parent is created under (its handle becomes the parent Name and the ticket hierarchy).</param>
/// <param name="NameAlg">The Name algorithm to carry in the exported public area and to compute the object Name with.</param>
/// <param name="Attributes">The storage object attributes to record on the parent (<c>RESTRICTED</c> and <c>DECRYPT</c>).</param>
/// <param name="KeyBits">The RSA modulus size in bits to generate.</param>
/// <param name="NoDa">Whether the template set <c>TPMA_OBJECT.noDA</c>, so the exported public area reproduces the caller's template.</param>
/// <param name="AuthPolicy">
/// The authorization policy digest to re-emit into the exported public area (<c>TPM2B_DIGEST</c>, TPM 2.0
/// Library Part 2, clause 10.4.2, Table 92; empty for a generic RSA storage parent; a standard RSA
/// endorsement key's "PolicyA" otherwise), the owned pooled carrier the request parsed; ownership rides this
/// action into the effect, which installs it on the durable parent state.
/// </param>
/// <param name="UserAuth">The new object's authorization value (<c>inSensitive.userAuth</c>), the owned <see cref="Tpm2bAuth"/> carrier the request parsed; ownership rides this action into the effect, which installs it on the durable parent state. The dispose-immune empty sentinel for an authValue-free parent.</param>
public sealed record TpmCreateRsaStorageParentAction(
    TpmiDhObject Handle,
    TpmiRhHierarchy Hierarchy,
    TpmiAlgHash NameAlg,
    TpmaObject Attributes,
    TpmiRsaKeyBits KeyBits,
    bool NoDa,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth UserAuth): TpmAction;

/// <summary>
/// Declares that the simulator must seal caller-supplied data into a KEYEDHASH object before the next transition.
/// Emitted by the <c>TPM2_Create()</c> transition; the effectful loop builds the wrapped private blob, the
/// exported public area, and the creation by-products through the registered digest and HMAC seams, and feeds
/// them back as a <see cref="TpmObjectSealed"/> input (TPM 2.0 Library Part 3, clause 12.1).
/// </summary>
/// <param name="ParentHandle">The storage parent the object is sealed under (its handle binds the creation data).</param>
/// <param name="ParentHierarchy">
/// The hierarchy the storage parent belongs to, which is the hierarchy the created object belongs to and so the
/// one the creation ticket names and whose proof keys its HMAC (<c>TPMI_RH_HIERARCHY+</c>, TPM 2.0 Library
/// Part 2, clause 10.7.3, Table 109: "the hierarchy containing name"; Part 4's <c>TPM2_Create()</c> computes
/// the ticket over <c>EntityGetHierarchy(parentHandle)</c>). Distinct from <see cref="ParentHandle"/>, which
/// binds the creation DATA.
/// </param>
/// <param name="NameAlg">The Name algorithm to carry in the exported public area.</param>
/// <param name="AuthPolicy">The authorization policy digest to re-emit into the exported public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92; empty for an authValue-only seal), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner and releases it in its <c>finally</c> — <c>TPM2_Create()</c> installs no durable object, so the copy the exported public area takes is the digest's only use.</param>
/// <param name="NoDa">Whether the template set <c>TPMA_OBJECT.noDA</c>, so the exported public area reproduces the caller's template.</param>
/// <param name="UserWithAuth">Whether the template set <c>TPMA_OBJECT.userWithAuth</c>, so the exported public area reproduces the caller's template.</param>
/// <param name="SecretData">The data to seal, the owned <see cref="Tpm2bSensitiveData"/> carrier the request parsed; ownership rides this action into the effect, which packs it into the wrapped private blob and releases it.</param>
/// <param name="UserAuth">The new object's authorization value, the owned <see cref="Tpm2bAuth"/> carrier the request parsed; ownership rides this action into the effect, which packs it into the wrapped private blob alongside <see cref="SecretData"/> and releases it (TPM 2.0 Library Part 1, clause 17.6.4).</param>
public sealed record TpmSealDataAction(
    TpmiDhObject ParentHandle,
    TpmiRhHierarchy ParentHierarchy,
    TpmiAlgHash NameAlg,
    Tpm2bDigest AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    Tpm2bSensitiveData SecretData,
    Tpm2bAuth UserAuth): TpmAction;

/// <summary>
/// Declares that the simulator must compute a loaded object's Name before the next transition. Emitted by the
/// <c>TPM2_Load()</c> transition; the effectful loop computes <c>nameAlg ‖ H(TPMT_PUBLIC)</c> through the
/// registered digest seam and feeds it back with the recovered sealed data as a <see cref="TpmObjectLoaded"/>
/// input (TPM 2.0 Library Part 3, clause 12.2; Part 1, clause 14, Table 6).
/// </summary>
/// <param name="Handle">The transient handle the transition allocated for the loaded object.</param>
/// <param name="NameAlg">The Name algorithm to compute the object Name with.</param>
/// <param name="AuthPolicy">The authorization policy digest carried in the loaded public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92; empty for an authValue-only object), the owned pooled carrier the request parsed; ownership rides this action into the effect, which threads it onto the loaded object's state.</param>
/// <param name="NoDa">Whether the loaded public area sets <c>TPMA_OBJECT.noDA</c>, threaded through to the loaded object's state.</param>
/// <param name="UserWithAuth">Whether the loaded public area sets <c>TPMA_OBJECT.userWithAuth</c>, threaded through to the loaded object's state.</param>
/// <param name="InPublic">The public area the caller supplied (<c>TPM2B_PUBLIC</c>, TPM 2.0 Library Part 2, clause 12.2.5, Table 220), whose marshaled <c>TPMT_PUBLIC</c> the Name is hashed over — the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="PrivateBlob">The wrapped private blob to recover the authorization value and the sealed data from.</param>
public sealed record TpmLoadObjectAction(
    TpmiDhObject Handle,
    TpmiAlgHash NameAlg,
    Tpm2bDigest AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    Tpm2bPublic InPublic,
    ReadOnlyMemory<byte> PrivateBlob): TpmAction;

/// <summary>
/// Declares that the simulator must attest a loaded object before the next transition. Emitted by the
/// <c>TPM2_Certify()</c> transition; the effectful loop computes the subject's and the signer's Qualified Names,
/// marshals a <c>TPMS_ATTEST</c> of type <c>TPM_ST_ATTEST_CERTIFY</c> that binds the certified object's Name and
/// the caller nonce, signs <c>H_hashAlg(attest)</c> with the signing key's retained scalar through the injected
/// <see cref="TpmEccSigningBackend"/>, and feeds the marshaled attest and signature back as a
/// <see cref="TpmObjectCertified"/> input (TPM 2.0 Library Part 3, clause 18.2; Part 2, clause 10.12.12).
/// </summary>
/// <remarks>
/// The transition resolves both command handles against the loaded-object table and folds their retained fields
/// into this action — the certified object's Name and hierarchy, and the signing key's Name, hierarchy, scalar,
/// and curve — so the effect needs no automaton state and captures nothing. This slice models an elliptic-curve
/// signing key (ECDSA), as the signing paths do.
/// </remarks>
/// <param name="SubjectName">The certified object's Name (<c>nameAlg ‖ H(TPMT_PUBLIC)</c>), attested in <c>TPMS_CERTIFY_INFO.name</c>.</param>
/// <param name="SubjectHierarchy">The permanent hierarchy the certified object was created under, from which its Qualified Name is derived.</param>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c> this slice), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the attestation's <c>clockInfo</c>.</param>
/// <param name="ResponseSessions">Every session in the command's authorization area, in command-session order, each carrying either a real session's response-HMAC material or the <c>TPM_RS_PW</c> placeholder marker; empty on the all-password arm, whose response carries no session area at all.</param>
public sealed record TpmCertifyAction(
    Tpm2bName SubjectName,
    TpmiRhHierarchy SubjectHierarchy,
    Tpm2bName SignerName,
    TpmiRhHierarchy SignerHierarchy,
    Tpm2bData QualifyingData,
    PrivateKeyMemory SignerPrivateKey,
    TpmiEccCurve SignerCurve,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash HashAlg,
    TpmsClockInfo ClockSnapshot,
    ImmutableArray<TpmAttestResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must attest a loaded object before the next transition, signed with an RSA key —
/// the RSA counterpart of <see cref="TpmCertifyAction"/>. Emitted by the <c>TPM2_Certify()</c> transition when
/// the signing key is RSA; the effectful loop computes the subject's and the signer's Qualified Names, marshals
/// the same <c>TPMS_ATTEST</c> of type <c>TPM_ST_ATTEST_CERTIFY</c>, signs <c>H_hashAlg(attest)</c> with the
/// signing key's retained private key through the injected <see cref="TpmRsaSigningBackend"/> under the
/// requested RSA scheme, and feeds the marshaled attest and signature back as a <see cref="TpmObjectCertified"/>
/// input (TPM 2.0 Library Part 3, clause 18.2; Part 2, clause 10.12.12).
/// </summary>
/// <remarks>
/// The transition resolves both command handles against the loaded-object table and folds their retained fields
/// into this action — the certified object's Name and hierarchy, and the signing key's Name, hierarchy, and
/// private key — so the effect needs no automaton state and captures nothing.
/// </remarks>
/// <param name="SubjectName">The certified object's Name (<c>nameAlg ‖ H(TPMT_PUBLIC)</c>), attested in <c>TPMS_CERTIFY_INFO.name</c>.</param>
/// <param name="SubjectHierarchy">The permanent hierarchy the certified object was created under, from which its Qualified Name is derived.</param>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained private key, in the backend's own encoding — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to apply.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the attestation's <c>clockInfo</c>.</param>
/// <param name="ResponseSessions">Every session in the command's authorization area, in command-session order, each carrying either a real session's response-HMAC material or the <c>TPM_RS_PW</c> placeholder marker; empty on the all-password arm.</param>
public sealed record TpmRsaCertifyAction(
    Tpm2bName SubjectName,
    TpmiRhHierarchy SubjectHierarchy,
    Tpm2bName SignerName,
    TpmiRhHierarchy SignerHierarchy,
    Tpm2bData QualifyingData,
    PrivateKeyMemory SignerPrivateKey,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash HashAlg,
    TpmsClockInfo ClockSnapshot,
    ImmutableArray<TpmAttestResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must quote a set of Platform Configuration Registers before the next transition.
/// Emitted by the <c>TPM2_Quote()</c> transition; the effectful loop computes the PCR composite digest over the
/// selected register values and the signer's Qualified Name, marshals a <c>TPMS_ATTEST</c> of type
/// <c>TPM_ST_ATTEST_QUOTE</c> that binds that composite and the caller nonce, signs <c>H_hashAlg(attest)</c> with
/// the signing key's retained scalar through the injected <see cref="TpmEccSigningBackend"/>, and feeds the
/// marshaled attest and signature back as a <see cref="TpmObjectQuoted"/> input (TPM 2.0 Library Part 3, clause
/// 18.4; Part 2, clauses 10.12.12 and 10.12.1).
/// </summary>
/// <remarks>
/// The transition resolves the signing-key handle against the loaded-object table and gathers the selected PCR
/// values from the durable bank, folding both (plus the signer's hierarchy) into this action, so the effect
/// needs no automaton state and captures nothing. This slice models an elliptic-curve signing key (ECDSA), as
/// the signing paths do.
/// </remarks>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c> this slice), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="PcrSelection">The caller's <c>TPML_PCR_SELECTION</c>, written verbatim into the attested <c>TPMS_QUOTE_INFO.pcrSelect</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="PcrValues">The selected register values in ascending PCR-index order, concatenated and hashed into the attested <c>pcrDigest</c>.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the attestation's <c>clockInfo</c>.</param>
/// <param name="ResponseSessions">Every session in the command's authorization area, in command-session order, each carrying either a real session's response-HMAC material or the <c>TPM_RS_PW</c> placeholder marker; empty on the all-password arm, whose response carries no session area at all.</param>
public sealed record TpmQuoteAction(
    Tpm2bName SignerName,
    TpmiRhHierarchy SignerHierarchy,
    Tpm2bData QualifyingData,
    PrivateKeyMemory SignerPrivateKey,
    TpmiEccCurve SignerCurve,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash HashAlg,
    TpmlPcrSelection PcrSelection,
    ImmutableArray<ReadOnlyMemory<byte>> PcrValues,
    TpmsClockInfo ClockSnapshot,
    ImmutableArray<TpmAttestResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must quote a set of Platform Configuration Registers before the next transition,
/// signed with an RSA key — the RSA counterpart of <see cref="TpmQuoteAction"/>. Emitted by the
/// <c>TPM2_Quote()</c> transition when the signing key is RSA; the effectful loop computes the PCR composite
/// digest over the selected register values and the signer's Qualified Name, marshals the same <c>TPMS_ATTEST</c>
/// of type <c>TPM_ST_ATTEST_QUOTE</c>, signs <c>H_hashAlg(attest)</c> with the signing key's retained private key
/// through the injected <see cref="TpmRsaSigningBackend"/> under the requested RSA scheme, and feeds the
/// marshaled attest and signature back as a <see cref="TpmObjectQuoted"/> input (TPM 2.0 Library Part 3, clause
/// 18.4; Part 2, clauses 10.12.12 and 10.12.1).
/// </summary>
/// <remarks>
/// The transition resolves the signing-key handle against the loaded-object table and gathers the selected PCR
/// values from the durable bank, folding both (plus the signer's hierarchy) into this action, so the effect
/// needs no automaton state and captures nothing.
/// </remarks>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained private key, in the backend's own encoding — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to apply.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="PcrSelection">The caller's <c>TPML_PCR_SELECTION</c>, written verbatim into the attested <c>TPMS_QUOTE_INFO.pcrSelect</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="PcrValues">The selected register values in ascending PCR-index order, concatenated and hashed into the attested <c>pcrDigest</c>.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the attestation's <c>clockInfo</c>.</param>
/// <param name="ResponseSessions">Every session in the command's authorization area, in command-session order, each carrying either a real session's response-HMAC material or the <c>TPM_RS_PW</c> placeholder marker; empty on the all-password arm.</param>
public sealed record TpmRsaQuoteAction(
    Tpm2bName SignerName,
    TpmiRhHierarchy SignerHierarchy,
    Tpm2bData QualifyingData,
    PrivateKeyMemory SignerPrivateKey,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash HashAlg,
    TpmlPcrSelection PcrSelection,
    ImmutableArray<ReadOnlyMemory<byte>> PcrValues,
    TpmsClockInfo ClockSnapshot,
    ImmutableArray<TpmAttestResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must re-verify a creation ticket and, if it reproduces, attest the certified
/// object's creation before the next transition. Emitted by the <c>TPM2_CertifyCreation()</c> transition; the
/// effectful loop re-derives the subject hierarchy's proof, recomputes the creation-ticket digest over
/// <see cref="SubjectName"/> and <see cref="CreationHash"/>, and constant-time compares it to
/// <see cref="TicketDigest"/> — a mismatch feeds back a <see cref="TpmObjectCreationCertified"/> carrying
/// <c>TPM_RC_TICKET</c>. On a match it marshals a <c>TPMS_ATTEST</c> of type <c>TPM_ST_ATTEST_CREATION</c>,
/// signs <c>H_hashAlg(attest)</c> with the signing key's retained scalar through the injected
/// <see cref="TpmEccSigningBackend"/>, and feeds the marshaled attest and signature back as a successful
/// <see cref="TpmObjectCreationCertified"/> input (TPM 2.0 Library Part 3, clause 18.3; Part 2, clause 10.12.7).
/// </summary>
/// <remarks>
/// The transition resolves both command handles against the loaded-object table and folds their retained fields
/// into this action — the certified object's Name and hierarchy, and the signing key's Name, hierarchy, scalar,
/// and curve — so the effect needs no automaton state and captures nothing. This slice models an elliptic-curve
/// signing key (ECDSA), as the signing paths do.
/// </remarks>
/// <param name="SubjectName">The certified object's Name (<c>nameAlg ‖ H(TPMT_PUBLIC)</c>), attested in <c>TPMS_CREATION_INFO.objectName</c> and folded into the recomputed creation-ticket digest.</param>
/// <param name="SubjectHierarchy">The permanent hierarchy the certified object was created under, from which its creation-ticket proof re-derives.</param>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="CreationHash">The caller-supplied creation hash, attested in <c>TPMS_CREATION_INFO.creationHash</c> and folded into the recomputed creation-ticket digest — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="TicketDigest">The digest carried by the caller-supplied creation ticket, compared constant-time against the recomputed one — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c> this slice), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the attestation's <c>clockInfo</c>.</param>
/// <param name="ResponseSessions">Every session in the command's authorization area, in command-session order, each carrying either a real session's response-HMAC material or the <c>TPM_RS_PW</c> placeholder marker; empty on the all-password arm, whose response carries no session area at all.</param>
public sealed record TpmCertifyCreationAction(
    Tpm2bName SubjectName,
    TpmiRhHierarchy SubjectHierarchy,
    Tpm2bName SignerName,
    TpmiRhHierarchy SignerHierarchy,
    Tpm2bData QualifyingData,
    Tpm2bDigest CreationHash,
    Tpm2bDigest TicketDigest,
    PrivateKeyMemory SignerPrivateKey,
    TpmiEccCurve SignerCurve,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash HashAlg,
    TpmsClockInfo ClockSnapshot,
    ImmutableArray<TpmAttestResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must re-verify a creation ticket and, if it reproduces, attest the certified
/// object's creation before the next transition, signed with an RSA key — the RSA counterpart of
/// <see cref="TpmCertifyCreationAction"/>. Emitted by the <c>TPM2_CertifyCreation()</c> transition when the
/// signing key is RSA; the effect performs the same ticket re-verification, and on a match signs
/// <c>H_hashAlg(attest)</c> with the signing key's retained private key through the injected
/// <see cref="TpmRsaSigningBackend"/> under the requested RSA scheme (TPM 2.0 Library Part 3, clause 18.3;
/// Part 2, clause 10.12.7).
/// </summary>
/// <param name="SubjectName">The certified object's Name (<c>nameAlg ‖ H(TPMT_PUBLIC)</c>), attested in <c>TPMS_CREATION_INFO.objectName</c> and folded into the recomputed creation-ticket digest.</param>
/// <param name="SubjectHierarchy">The permanent hierarchy the certified object was created under, from which its creation-ticket proof re-derives.</param>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="CreationHash">The caller-supplied creation hash, attested in <c>TPMS_CREATION_INFO.creationHash</c> and folded into the recomputed creation-ticket digest — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="TicketDigest">The digest carried by the caller-supplied creation ticket, compared constant-time against the recomputed one — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained private key, in the backend's own encoding — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to apply.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the attestation's <c>clockInfo</c>.</param>
/// <param name="ResponseSessions">Every session in the command's authorization area, in command-session order, each carrying either a real session's response-HMAC material or the <c>TPM_RS_PW</c> placeholder marker; empty on the all-password arm.</param>
public sealed record TpmRsaCertifyCreationAction(
    Tpm2bName SubjectName,
    TpmiRhHierarchy SubjectHierarchy,
    Tpm2bName SignerName,
    TpmiRhHierarchy SignerHierarchy,
    Tpm2bData QualifyingData,
    Tpm2bDigest CreationHash,
    Tpm2bDigest TicketDigest,
    PrivateKeyMemory SignerPrivateKey,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash HashAlg,
    TpmsClockInfo ClockSnapshot,
    ImmutableArray<TpmAttestResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must attest the current time before the next transition. Emitted by the
/// <c>TPM2_GetTime()</c> transition; the effectful loop marshals a <c>TPMS_ATTEST</c> of type
/// <c>TPM_ST_ATTEST_TIME</c> whose <c>TPMS_TIME_ATTEST_INFO</c> reports the real Time and the same
/// <c>TPMS_CLOCK_INFO</c>/firmwareVersion every attest builder frames (TPM 2.0 Library Part 3, clause 18.7;
/// clause 36.7 — the envelope and nested copies agree), signs <c>H_hashAlg(attest)</c> with the signing key's
/// retained scalar through the injected <see cref="TpmEccSigningBackend"/>, and feeds the marshaled attest and
/// signature back as a <see cref="TpmTimeAttested"/> input.
/// </summary>
/// <remarks>
/// The transition resolves the signing-key handle against the loaded-object table and folds its Name, hierarchy,
/// scalar, and curve into this action, so the effect needs no automaton state and captures nothing. This slice
/// models an elliptic-curve signing key (ECDSA), as the signing paths do.
/// </remarks>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c> this slice), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="Time">The time in milliseconds since the last startup, folded from state after the per-command advance, framed as the attested <c>TPMS_TIME_ATTEST_INFO.time</c>.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed both as the envelope's <c>clockInfo</c> and inside the attested <c>TPMS_TIME_ATTEST_INFO</c> (TPM 2.0 Library Part 1, clause 36.7 — the two copies agree).</param>
/// <param name="ResponseSessions">Every session in the command's authorization area, in command-session order, each carrying either a real session's response-HMAC material or the <c>TPM_RS_PW</c> placeholder marker; empty on the all-password arm, whose response carries no session area at all.</param>
public sealed record TpmGetTimeAction(
    Tpm2bName SignerName,
    TpmiRhHierarchy SignerHierarchy,
    Tpm2bData QualifyingData,
    PrivateKeyMemory SignerPrivateKey,
    TpmiEccCurve SignerCurve,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash HashAlg,
    ulong Time,
    TpmsClockInfo ClockSnapshot,
    ImmutableArray<TpmAttestResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must attest the current time before the next transition, signed with an RSA
/// key — the RSA counterpart of <see cref="TpmGetTimeAction"/>. Emitted by the <c>TPM2_GetTime()</c>
/// transition when the signing key is RSA; the effect builds the same real-time attestation and signs
/// <c>H_hashAlg(attest)</c> with the signing key's retained private key through the injected
/// <see cref="TpmRsaSigningBackend"/> under the requested RSA scheme (TPM 2.0 Library Part 3, clause 18.7).
/// </summary>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained private key, in the backend's own encoding — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to apply.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="Time">The time in milliseconds since the last startup, folded from state after the per-command advance, framed as the attested <c>TPMS_TIME_ATTEST_INFO.time</c>.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed both as the envelope's <c>clockInfo</c> and inside the attested <c>TPMS_TIME_ATTEST_INFO</c> (TPM 2.0 Library Part 1, clause 36.7 — the two copies agree).</param>
/// <param name="ResponseSessions">Every session in the command's authorization area, in command-session order, each carrying either a real session's response-HMAC material or the <c>TPM_RS_PW</c> placeholder marker; empty on the all-password arm.</param>
public sealed record TpmRsaGetTimeAction(
    Tpm2bName SignerName,
    TpmiRhHierarchy SignerHierarchy,
    Tpm2bData QualifyingData,
    PrivateKeyMemory SignerPrivateKey,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash HashAlg,
    ulong Time,
    TpmsClockInfo ClockSnapshot,
    ImmutableArray<TpmAttestResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must attest an NV Index's contents before the next transition. Emitted by the
/// <c>TPM2_NV_Certify()</c> transition; the effectful loop marshals the Index's <c>TPMS_NV_PUBLIC</c> and computes
/// its Name through the registered digest seam (the same marshal-and-hash mechanism <c>TPM2_PolicyNV()</c> uses),
/// marshals a <c>TPMS_ATTEST</c> of type <c>TPM_ST_ATTEST_NV</c> binding that Name, the requested window of
/// <see cref="NvContents"/>, and the caller nonce, signs <c>H_hashAlg(attest)</c> with the signing key's retained
/// scalar through the injected <see cref="TpmEccSigningBackend"/>, and feeds the marshaled attest and signature
/// back as a <see cref="TpmNvIndexCertified"/> input (TPM 2.0 Library Part 3, clause 31.16; Part 2, clause
/// 10.12.8).
/// </summary>
/// <remarks>
/// <para>
/// The transition resolves the signing-key and NV-Index handles, performs the Index-authorization and
/// written/range checks, and slices the requested window from the Index's retained data area, folding all of it
/// into this action, so the effect needs no automaton state and captures nothing. This slice models an
/// elliptic-curve signing key (ECDSA), as the signing paths do.
/// </para>
/// <para>
/// <see cref="ResponseSessions"/> is what makes this action serve both authorization arms. Empty (the default)
/// is the all-password arm, whose response is the plain <c>TPM_ST_NO_SESSIONS</c> attest-and-signature pair.
/// Non-empty is the session arm, and the effect then additionally frames <c>certifyInfo ‖ signature</c> into a
/// response parameter area, computes rpHash over exactly those octets (TPM 2.0 Library Part 1, clause 16.8
/// equation 16), and produces one response session entry per command session — the attest-family shape
/// (<see cref="TpmAttestResponseSession"/>) every attest action shares, being both parameter-bearing and
/// multi-entry at once, which neither <see cref="TpmFrameNvSessionResponseAction"/> (parameters, one entry) nor
/// <see cref="TpmFrameNvChangeAuthResponseAction"/> (entries, no parameters) can frame.
/// </para>
/// </remarks>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c> this slice), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="NvIndex">The NV Index handle, folded into the marshaled <c>TPMS_NV_PUBLIC</c> the Index's Name is computed from.</param>
/// <param name="NvIndexNameAlg">The Index's own Name algorithm, driving the marshaled <c>TPMS_NV_PUBLIC.nameAlg</c> and the digest the Name is computed with.</param>
/// <param name="NvIndexAttributes">The Index's current attributes (<c>TPMA_NV</c>), folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="NvIndexAuthPolicy">The Index's own access policy digest, folded into the marshaled <c>TPMS_NV_PUBLIC.authPolicy</c> — a field of the structure the Name hashes, so an Index defined with a policy attests a different Name than an otherwise identical Index defined without one. A borrowed reference to the durable Index state's own carrier; the effect reads it and never disposes it.</param>
/// <param name="NvIndexDataSize">The Index's declared data size, folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="NvContents">The requested window of the Index's retained data, attested verbatim in <c>TPMS_NV_CERTIFY_INFO.nvContents</c>. A borrowed slice of the durable Index state's own storage; the effect reads it and never disposes it.</param>
/// <param name="Offset">The octet offset of <paramref name="NvContents"/> within the Index's data area, attested in <c>TPMS_NV_CERTIFY_INFO.offset</c>.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the attestation's <c>clockInfo</c>.</param>
/// <param name="ResponseSessions">Every session in the command's authorization area, in command-session order, each carrying either a real session's response-HMAC material or the <c>TPM_RS_PW</c> placeholder marker; empty on the all-password arm, whose response carries no session area at all.</param>
public sealed record TpmNvCertifyAction(
    Tpm2bName SignerName,
    TpmiRhHierarchy SignerHierarchy,
    Tpm2bData QualifyingData,
    PrivateKeyMemory SignerPrivateKey,
    TpmiEccCurve SignerCurve,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash HashAlg,
    TpmiRhNvIndex NvIndex,
    TpmiAlgHash NvIndexNameAlg,
    TpmaNv NvIndexAttributes,
    Tpm2bDigest NvIndexAuthPolicy,
    ushort NvIndexDataSize,
    ReadOnlyMemory<byte> NvContents,
    ushort Offset,
    TpmsClockInfo ClockSnapshot,
    ImmutableArray<TpmAttestResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must attest an NV Index's contents before the next transition, signed with an RSA
/// key — the RSA counterpart of <see cref="TpmNvCertifyAction"/>. Emitted by the <c>TPM2_NV_Certify()</c>
/// transition when the signing key is RSA; the effect performs the same Index-Name computation and attestation
/// marshaling, and signs <c>H_hashAlg(attest)</c> with the signing key's retained private key through the
/// injected <see cref="TpmRsaSigningBackend"/> under the requested RSA scheme (TPM 2.0 Library Part 3, clause
/// 31.16; Part 2, clause 10.12.8).
/// </summary>
/// <remarks>
/// <see cref="ResponseSessions"/> carries the same both-arms meaning it has on
/// <see cref="TpmNvCertifyAction"/>: empty is the all-password arm's plain response, non-empty is the session
/// arm's framed parameter area plus one entry per command session.
/// </remarks>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained private key, in the backend's own encoding — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to apply.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="NvIndex">The NV Index handle, folded into the marshaled <c>TPMS_NV_PUBLIC</c> the Index's Name is computed from.</param>
/// <param name="NvIndexNameAlg">The Index's own Name algorithm, driving the marshaled <c>TPMS_NV_PUBLIC.nameAlg</c> and the digest the Name is computed with.</param>
/// <param name="NvIndexAttributes">The Index's current attributes (<c>TPMA_NV</c>), folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="NvIndexAuthPolicy">The Index's own access policy digest, folded into the marshaled <c>TPMS_NV_PUBLIC.authPolicy</c> — a field of the structure the Name hashes, so an Index defined with a policy attests a different Name than an otherwise identical Index defined without one. A borrowed reference to the durable Index state's own carrier; the effect reads it and never disposes it.</param>
/// <param name="NvIndexDataSize">The Index's declared data size, folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="NvContents">The requested window of the Index's retained data, attested verbatim in <c>TPMS_NV_CERTIFY_INFO.nvContents</c>. A borrowed slice of the durable Index state's own storage; the effect reads it and never disposes it.</param>
/// <param name="Offset">The octet offset of <paramref name="NvContents"/> within the Index's data area, attested in <c>TPMS_NV_CERTIFY_INFO.offset</c>.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the attestation's <c>clockInfo</c>.</param>
/// <param name="ResponseSessions">Every session in the command's authorization area, in command-session order, each carrying either a real session's response-HMAC material or the <c>TPM_RS_PW</c> placeholder marker; empty on the all-password arm.</param>
public sealed record TpmRsaNvCertifyAction(
    Tpm2bName SignerName,
    TpmiRhHierarchy SignerHierarchy,
    Tpm2bData QualifyingData,
    PrivateKeyMemory SignerPrivateKey,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash HashAlg,
    TpmiRhNvIndex NvIndex,
    TpmiAlgHash NvIndexNameAlg,
    TpmaNv NvIndexAttributes,
    Tpm2bDigest NvIndexAuthPolicy,
    ushort NvIndexDataSize,
    ReadOnlyMemory<byte> NvContents,
    ushort Offset,
    TpmsClockInfo ClockSnapshot,
    ImmutableArray<TpmAttestResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// The POLICY/TRIAL-session-specific context threaded through the shared session-key-derivation ladder
/// (<see cref="TpmStartHmacSessionAction"/>, <see cref="TpmRecoverRsaSessionSaltAction"/>,
/// <see cref="TpmRecoverEccSessionSaltAction"/>) when it is deriving a POLICY or TRIAL session's key rather than
/// an HMAC session's. The <c>KDFa</c> derivation itself is identical for every session type (TPM 2.0 Library
/// Part 3, Section 11.1.1: "For all session types, this command will cause initialization of the sessionKey")
/// — only the session's OWN additional context differs, which is exactly what this record carries so
/// <c>OnHmacSessionStarted</c> can build a <see cref="PolicySessionState"/> instead of an
/// <see cref="HmacSessionState"/> once the key comes back. <see langword="null"/> on every HMAC-session call
/// site.
/// </summary>
/// <param name="IsTrial">Whether the session being started is a trial session (<c>TPM_SE_TRIAL</c>): it accumulates the policyDigest but authorizes nothing.</param>
/// <param name="StartTime">The simulator's <c>Time</c> snapshot at session creation, recorded for a later session-relative expiration deadline.</param>
public sealed record TpmPolicySessionKeyContext(bool IsTrial, ulong StartTime);

/// <summary>
/// Declares that the simulator must establish a bound and/or salted HMAC, POLICY, or TRIAL session before the
/// next transition. Emitted by the <c>TPM2_StartAuthSession()</c> transition whose <c>tpmKey</c> is
/// <c>TPM_RH_NULL</c> (unsalted — a salted arm instead declares <see cref="TpmRecoverRsaSessionSaltAction"/> or
/// <see cref="TpmRecoverEccSessionSaltAction"/>, which recover <see cref="Salt"/> asynchronously before deriving
/// the same way); the effectful loop draws a fresh nonceTPM from the injected RNG, derives the session key via
/// <c>KDFa</c> through the registered HMAC seam, and feeds both back as a <see cref="TpmHmacSessionStarted"/>
/// input (TPM 2.0 Library Part 3, clause 11.1; Part 1, clause 17.6.10 equations 20/25).
/// </summary>
/// <remarks>
/// The session key is <c>KDFa(SessionAlg, BindAuthValue ‖ Salt, "ATH", nonceTPM, NonceCaller, bits)</c> — the
/// same derivation the host performs, so the two keys agree by construction. <paramref name="BindAuthValue"/> is
/// the bind entity's REAL resolved authorization value (empty only for an unbound session or one bound to an
/// entity this model tracks no authValue for), and <paramref name="Salt"/> is empty on this unsalted path.
/// </remarks>
/// <param name="SessionHandle">The session handle the transition allocated for the new session.</param>
/// <param name="SessionAlg">The session hash algorithm driving the KDFa and sizing the nonceTPM.</param>
/// <param name="Symmetric">The negotiated symmetric definition to record on the session.</param>
/// <param name="NonceCaller">The caller nonce sent at start (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94, page 134) — the second context field of the session-key KDFa. Owned: transferred out of the request record by the transition that built this action, and released by the effect that consumes it as its terminal owner.</param>
/// <param name="BindAuthValue">The bind entity's resolved authorization value (the shared empty carrier for an unbound session) — a borrowed reference to the carrier the durable state owns, wire-exact; the effect takes the trailing-zero-stripped view at the KDFa key's leading term (Part 1, clauses 17.6.10 and 17.6.4.3) and never disposes it.</param>
/// <param name="BoundEntityName">The bind entity's Name, resolved synchronously by the transition (empty for an unbound session) — for an HMAC session the effect folds it with <paramref name="BindAuthValue"/> into the <see cref="SessionBoundEntity"/> the session records for the bind-omission check (Part 4, <c>SessionComputeBoundEntity()</c>; Part 1, clause 17.6.10 equations 21/22); unused for a POLICY/TRIAL session, which never applies that optimization.</param>
/// <param name="Salt">Always empty on this unsalted path — the KDFa key's trailing term (Part 1, clause 17.6.12 equation 25) a salted arm instead recovers asynchronously. This is the RECOVERED plaintext salt, never the wire <c>encryptedSalt</c>, so it is not a <c>TPM2B_ENCRYPTED_SECRET</c>; it stays a plain view because nothing on this path ever holds one.</param>
/// <param name="PolicyContext">Non-<see langword="null"/> when this action is starting a POLICY or TRIAL session rather than an HMAC session (see <see cref="TpmPolicySessionKeyContext"/>).</param>
/// <param name="IsBoundEntityDaProtected">Whether the bind entity receives dictionary-attack protection, resolved synchronously by the transition and carried to the session record the effect's result lands on — the state Part 1, clause 17.6.10 requires be recorded in the session context ("The noDA attribute of the bind entity is recorded in the session context").</param>
/// <param name="IsBoundToLockout">Whether the bind entity is <c>TPM_RH_LOCKOUT</c>, whose authValue alone among permanent entities is dictionary-attack protected (Part 1, clause 17.8.1) and whose failed use is one-strike (clause 17.8.5).</param>
public sealed record TpmStartHmacSessionAction(
    TpmiShAuthSession SessionHandle,
    TpmiAlgHash SessionAlg,
    TpmtSymDef Symmetric,
    Tpm2bNonce NonceCaller,
    Tpm2bAuth BindAuthValue,
    TpmHandleName BoundEntityName,
    ReadOnlyMemory<byte> Salt,
    TpmPolicySessionKeyContext? PolicyContext = null,
    bool IsBoundEntityDaProtected = false,
    bool IsBoundToLockout = false): TpmAction;

/// <summary>
/// Declares that the simulator must OAEP-decrypt a salted <c>TPM2_StartAuthSession()</c>'s <c>encryptedSalt</c>
/// against an RSA <c>tpmKey</c>'s retained private key before the next transition — the RSA arm of Part 3,
/// clause 11.1's salted-session establishment (TPM 2.0 Library Part 1, Annex B.10.1/B.10.2). Emitted by the
/// <c>TPM2_StartAuthSession()</c> transition when <c>tpmKey</c> resolves to a loaded RSA key; the effectful loop
/// OAEP-decrypts <see cref="Ciphertext"/> (label <c>"SECRET"</c>) and reports ANY internal failure (bad padding,
/// an oversize recovered salt) immediately as <c>TPM_RC_VALUE</c> — never poisoned-and-deferred the way
/// <c>TPM2_ActivateCredential()</c>'s RSA arm is, since <c>TPM2_StartAuthSession()</c> has no later integrity
/// check to defer to. On success it derives the session key exactly as <see cref="TpmStartHmacSessionAction"/>
/// does and feeds the result back as a <see cref="TpmHmacSessionStarted"/> input.
/// </summary>
/// <param name="SessionHandle">The session handle the transition allocated for the new session.</param>
/// <param name="SessionAlg">The session hash algorithm driving the KDFa and sizing the nonceTPM.</param>
/// <param name="Symmetric">The negotiated symmetric definition to record on the session.</param>
/// <param name="NonceCaller">The caller nonce sent at start (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94, page 134) — the second context field of the session-key KDFa. Owned: transferred out of the request record by the transition that built this action, and released by the effect that consumes it as its terminal owner.</param>
/// <param name="BindAuthValue">The bind entity's resolved authorization value (the shared empty carrier for an unbound session) — a borrowed reference to the carrier the durable state owns, wire-exact; the effect takes the trailing-zero-stripped view at the session-key KDFa's leading term (Part 1, clauses 17.6.12 equation 25 and 17.6.4.3) and never disposes it.</param>
/// <param name="BoundEntityName">The bind entity's Name, resolved synchronously by the transition (empty for an unbound session).</param>
/// <param name="Ciphertext">The wire <c>encryptedSalt</c> (<c>TPM2B_ENCRYPTED_SECRET</c>, Part 2, clause 11.4.3, Table 210, page 180): the OAEP ciphertext, the same octet width as <c>tpmKey</c>'s modulus. Owned: transferred out of the request record by the transition that built this action, and released by the effect that consumes it as its terminal owner.</param>
/// <param name="PrivateKey"><c>tpmKey</c>'s retained RSA private key, in the backend's own encoding — a borrowed reference to the carrier the durable object state owns; the effect reads it at the decrypt primitive and never disposes it.</param>
/// <param name="NameAlg">
/// <c>tpmKey</c>'s own Name algorithm — drives OAEP's <c>lhash</c>/MGF1 and caps the recovered salt's size (TPM
/// 2.0 Library Part 1, Annex B.10.1). NEVER the session's own <c>authHash</c> (a mixed-hash session would
/// otherwise leak the wrong hash into this derivation).
/// </param>
/// <param name="PolicyContext">Non-<see langword="null"/> when this action is starting a POLICY or TRIAL session rather than an HMAC session (see <see cref="TpmPolicySessionKeyContext"/>).</param>
/// <param name="IsBoundEntityDaProtected">Whether the bind entity receives dictionary-attack protection (Part 1, clause 17.6.10's "The noDA attribute of the bind entity is recorded in the session context") — a property of <c>bind</c> alone, independent of the salt this arm recovers, so it rides through unchanged.</param>
/// <param name="IsBoundToLockout">Whether the bind entity is <c>TPM_RH_LOCKOUT</c>, the one permanent entity whose authValue is dictionary-attack protected (Part 1, clause 17.8.1) and whose failed use is one-strike (clause 17.8.5).</param>
public sealed record TpmRecoverRsaSessionSaltAction(
    TpmiShAuthSession SessionHandle,
    TpmiAlgHash SessionAlg,
    TpmtSymDef Symmetric,
    Tpm2bNonce NonceCaller,
    Tpm2bAuth BindAuthValue,
    TpmHandleName BoundEntityName,
    Tpm2bEncryptedSecret Ciphertext,
    PrivateKeyMemory PrivateKey,
    TpmiAlgHash NameAlg,
    TpmPolicySessionKeyContext? PolicyContext = null,
    bool IsBoundEntityDaProtected = false,
    bool IsBoundToLockout = false): TpmAction;

/// <summary>
/// The ECC counterpart of <see cref="TpmRecoverRsaSessionSaltAction"/>: recover a salted
/// <c>TPM2_StartAuthSession()</c>'s session salt via a one-pass ECDH exchange between an ECC <c>tpmKey</c>'s
/// private scalar and the wire ephemeral public point, then <c>KDFe</c> (TPM 2.0 Library Part 1, Annex
/// C.6.1/C.6.2). Emitted when <c>tpmKey</c> resolves to a loaded ECC key; the effectful loop parses
/// <see cref="EncryptedSalt"/> as a marshaled <c>TPMS_ECC_POINT</c>, validates it is a genuine point on the
/// curve (<c>TPM_RC_VALUE</c> on a malformed or off-curve/infinity point, reported immediately, never
/// deferred), computes <c>Z</c>, derives the salt via <c>KDFe</c> keyed on <c>tpmKey</c>'s own Name algorithm —
/// never the session's <c>authHash</c> — and otherwise proceeds exactly as the RSA arm.
/// </summary>
/// <param name="SessionHandle">The session handle the transition allocated for the new session.</param>
/// <param name="SessionAlg">The session hash algorithm driving the KDFa and sizing the nonceTPM.</param>
/// <param name="Symmetric">The negotiated symmetric definition to record on the session.</param>
/// <param name="NonceCaller">The caller nonce sent at start (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94, page 134) — the second context field of the session-key KDFa. Owned: transferred out of the request record by the transition that built this action, and released by the effect that consumes it as its terminal owner.</param>
/// <param name="BindAuthValue">The bind entity's resolved authorization value (the shared empty carrier for an unbound session) — a borrowed reference to the carrier the durable state owns, wire-exact; the effect takes the trailing-zero-stripped view at the session-key KDFa's leading term (Part 1, clauses 17.6.12 equation 25 and 17.6.4.3) and never disposes it.</param>
/// <param name="BoundEntityName">The bind entity's Name, resolved synchronously by the transition (empty for an unbound session).</param>
/// <param name="EncryptedSalt">The wire <c>encryptedSalt</c> (<c>TPM2B_ENCRYPTED_SECRET</c>, Part 2, clause 11.4.3, Table 210, page 180): a marshaled <c>TPMS_ECC_POINT</c> (two size-prefixed coordinates) carrying the caller's ephemeral public point. Owned: transferred out of the request record by the transition that built this action, and released by the effect that consumes it as its terminal owner.</param>
/// <param name="PrivateScalar"><c>tpmKey</c>'s retained ECC private scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the exchange primitive and never disposes it.</param>
/// <param name="PublicPoint"><c>tpmKey</c>'s own exported public point, SEC1 uncompressed — <c>KDFe</c>'s <c>partyVInfo</c> source.</param>
/// <param name="Curve">The ECC curve <c>tpmKey</c> lives on.</param>
/// <param name="NameAlg"><c>tpmKey</c>'s own Name algorithm — <c>KDFe</c>'s hash and the recovered salt's size, never the session's own <c>authHash</c>.</param>
/// <param name="PolicyContext">Non-<see langword="null"/> when this action is starting a POLICY or TRIAL session rather than an HMAC session (see <see cref="TpmPolicySessionKeyContext"/>).</param>
/// <param name="IsBoundEntityDaProtected">Whether the bind entity receives dictionary-attack protection (Part 1, clause 17.6.10's "The noDA attribute of the bind entity is recorded in the session context") — a property of <c>bind</c> alone, independent of the salt this arm recovers, so it rides through unchanged.</param>
/// <param name="IsBoundToLockout">Whether the bind entity is <c>TPM_RH_LOCKOUT</c>, the one permanent entity whose authValue is dictionary-attack protected (Part 1, clause 17.8.1) and whose failed use is one-strike (clause 17.8.5).</param>
public sealed record TpmRecoverEccSessionSaltAction(
    TpmiShAuthSession SessionHandle,
    TpmiAlgHash SessionAlg,
    TpmtSymDef Symmetric,
    Tpm2bNonce NonceCaller,
    Tpm2bAuth BindAuthValue,
    TpmHandleName BoundEntityName,
    Tpm2bEncryptedSecret EncryptedSalt,
    PrivateKeyMemory PrivateScalar,
    ReadOnlyMemory<byte> PublicPoint,
    TpmiEccCurve Curve,
    TpmiAlgHash NameAlg,
    TpmPolicySessionKeyContext? PolicyContext = null,
    bool IsBoundEntityDaProtected = false,
    bool IsBoundToLockout = false): TpmAction;

/// <summary>
/// Declares that the simulator must verify one queued session's command HMAC before the next transition (TPM 2.0
/// Library Part 1, clause 17.6; Part 3, clause 5.6, check 9) — the shared mechanism every session-authorized
/// command transition routes through. Emitted by a command's entry transition (and, while sessions
/// remain queued, re-emitted by <c>OnCommandHmacVerified</c>); the effectful loop recomputes cpHash over
/// <see cref="HandleNames"/>/<see cref="ParameterArea"/> and the expected HMAC for <see cref="Current"/>, then
/// feeds the outcome back as a <see cref="TpmCommandHmacVerified"/> input.
/// </summary>
/// <remarks>
/// Verification never decrypts a request parameter and never mutates dictionary-attack state itself — a mismatch
/// is reported through <see cref="TpmCommandHmacVerified"/> and it is the CONTINUATION transition that applies the
/// dictionary-attack-aware rejection (TPM 2.0 Library Part 3, clause 5.6's state-mutation boundary: only a
/// confirmed <c>AUTH_FAIL</c> may touch <c>FailedTries</c>). Dictionary-attack LOCKOUT itself is checked by the
/// entry transition before this action is ever declared (clause 5.6, check 3, strictly before the HMAC is
/// evaluated at all).
/// </remarks>
/// <param name="CommandCode">The command code, threaded through so a mismatch can frame the rejection.</param>
/// <param name="HandleNames">The command's handle-Name area as its ordered terms (Part 1, clause 16.7 equation 15's <c>Name1..N</c>), empty for a command with no handles. Each term is a BORROW of a Name carrier durable state or the request owns, or a permanent entity's handle value; the effect lays them out in pooled scratch of its own frame.</param>
/// <param name="ParameterArea">The command's raw parameter-area bytes exactly as received (still encrypted, if a decrypt session is present) — cpHash's <c>parameters</c> term. A BORROW of the carrier <see cref="NextRequest"/> owns; the request outlives the whole session-verification queue, and an owned copy here would be re-owned once per queued session.</param>
/// <param name="Current">The session being verified this stage.</param>
/// <param name="Remaining">The still-unverified sessions queued after <see cref="Current"/>, in order.</param>
/// <param name="NextRequest">The original parsed command request to resume once every queued session has verified.</param>
public sealed record TpmVerifyCommandHmacAction(
    TpmCcConstants CommandCode,
    TpmCommandHandleNames HandleNames,
    TpmParameterArea ParameterArea,
    TpmPendingSessionVerification Current,
    ImmutableArray<TpmPendingSessionVerification> Remaining,
    TpmSimulatorInput NextRequest): TpmAction;

/// <summary>
/// Declares that the simulator must produce an encrypt-attributed <c>TPM2_GetRandom()</c> response over a bound
/// HMAC session before the next transition. Emitted by the session-tagged <c>TPM2_GetRandom()</c> transition; the
/// effectful loop draws the random octets and a fresh nonceTPM from the injected RNG, encrypts the first response
/// parameter, computes rpHash over the encrypted parameter area, computes the response HMAC, and feeds the framed
/// pieces back as a <see cref="TpmEncryptedRandomProduced"/> input (TPM 2.0 Library Part 3, clause 16.1; Part 1,
/// clauses 16.7 and 19).
/// </summary>
/// <remarks>
/// The effect encrypts the first response parameter <b>before</b> computing rpHash and keys both the HMAC and the
/// parameter encryption on <c>sessionValue = SessionKey</c> (the bind entity's empty authValue contributes
/// nothing; Part 1, clause 19.1). Response-direction nonces are <c>nonceNewer = </c> the fresh nonceTPM and
/// <c>nonceOlder = NonceCaller</c> (Part 1, clause 19.2), so the host recovers the same keystream after adopting
/// the framed nonceTPM.
/// </remarks>
/// <param name="SessionHandle">The HMAC session the response is produced for (its nonceTPM is rolled).</param>
/// <param name="SessionAlg">The session hash algorithm driving the KDFa, rpHash, and response HMAC.</param>
/// <param name="Symmetric">The negotiated symmetric definition selecting XOR obfuscation or AES-CFB.</param>
/// <param name="SessionKey">The session key (<c>sessionValue</c>): the HMAC key and the parameter-encryption key seed — a borrowed reference to the carrier the durable session record owns; the effect reads it at the primitive and never disposes it.</param>
/// <param name="NonceCaller">This command's caller nonce (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94): the response HMAC's nonceOlder and the encryption's nonceOlder. Owned; transferred out of the request record by the continuation that built this action, and released by the effect as its terminal owner.</param>
/// <param name="SessionAttributes">The command session-attributes octet, echoed into the response and folded into the response HMAC.</param>
/// <param name="ByteCount">The number of random octets to produce (already clamped to the largest digest the simulated TPM returns).</param>
public sealed record TpmEncryptRandomAction(
    TpmiShAuthSession SessionHandle,
    TpmiAlgHash SessionAlg,
    TpmtSymDef Symmetric,
    SymmetricKeyMemory SessionKey,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    int ByteCount): TpmAction;

/// <summary>
/// Declares that the simulator must frame the <c>TPM2_Unseal()</c> response before the next transition. Emitted
/// once every session in the command's authorization area has verified (a satisfied policy session's digest gate,
/// or a real command-HMAC verification); the effectful loop draws a fresh nonceTPM for each real (HMAC-table)
/// session, frames the recovered secret as a <c>TPM2B_SENSITIVE_DATA</c>, encrypts its data portion over whichever
/// session (if any) carries the <c>encrypt</c> attribute, computes rpHash over the (possibly encrypted) parameter
/// area, then computes each real session's own response HMAC, and feeds the framed pieces back as a
/// <see cref="TpmUnsealedOverSessions"/> input (TPM 2.0 Library Part 3, clause 12.7; Part 1, clauses 16.7 and 19).
/// </summary>
/// <remarks>
/// <see cref="HmacResponseSessions"/> holds 0, 1, or 2 entries, in command-session order (an authorizing HMAC
/// session first when present, an encrypt session — which may or may not be the same session — always last): each
/// gets its own real nonce roll and response HMAC over THE SAME rpHash, keyed on its own <c>sessionKey ‖
/// authValue</c> (Part 1, clause 17.6.8: "the TPM will use the same HMAC key it used for the command"). A satisfied
/// plain policy session (Part 1, clause 17.6: no key) instead gets a zero-nonce, empty-HMAC placeholder entry when
/// <see cref="HasPolicyPlaceholder"/> is set, and is always session index 0 when present (a policy session can only
/// ever be Unseal's first, primary-authorizing session).
/// </remarks>
/// <param name="SecretData">The recovered sealed data returned as <c>outData</c> — a borrowed reference to the carrier the stored sealed object owns; the effect reads it at the framing primitive and never disposes it.</param>
/// <param name="HmacResponseSessions">The real (HMAC-table) sessions needing a framed response entry, in command-session order.</param>
/// <param name="HasPolicyPlaceholder">Whether session index 0 is a satisfied plain policy session needing the zero-nonce, empty-HMAC placeholder entry.</param>
/// <param name="PolicyPlaceholderAlg">The policy session hash algorithm, sizing its placeholder entry's zero nonce. Meaningful only when <see cref="HasPolicyPlaceholder"/> is set.</param>
/// <param name="PolicyPlaceholderAttributes">The policy session's command session-attributes octet, echoed into its placeholder entry. Meaningful only when <see cref="HasPolicyPlaceholder"/> is set.</param>
public sealed record TpmUnsealDataAction(
    Tpm2bSensitiveData SecretData,
    ImmutableArray<TpmUnsealResponseSession> HmacResponseSessions,
    bool HasPolicyPlaceholder,
    TpmiAlgHash PolicyPlaceholderAlg,
    TpmaSession PolicyPlaceholderAttributes): TpmAction;

/// <summary>
/// Declares that the simulator must wrap a credential secret for <c>TPM2_MakeCredential()</c> before the next
/// transition. Emitted by the <c>TPM2_MakeCredential()</c> transition; the effectful loop generates an ephemeral
/// key pair, derives the seed through an ECDH exchange with the credential key's public point and <c>KDFe</c>,
/// then produces the AK-Name-bound credential blob (<c>KDFa</c>-derived AES-CFB encryption and outer HMAC) and the
/// encrypted-secret transport, and feeds them back as a <see cref="TpmCredentialMade"/> input (TPM 2.0 Library
/// Part 1, clause 24; Part 3, clause 12.6).
/// </summary>
/// <remarks>
/// The transition resolves the credential-key handle against the loaded-object table and folds its exported public
/// point and curve into this action, so the effect needs no automaton state and captures nothing. The Name
/// algorithm is the simulator's universal <c>TPM_ALG_SHA256</c>.
/// </remarks>
/// <param name="Credential">The secret to wrap (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="ObjectName">The attestation key's Name the credential is bound to (folded into the <c>KDFa</c> derivations and the outer HMAC) — an owned <c>TPM2B_NAME</c> carrier the transition transferred out of the request; the effect is its terminal owner and releases it in the <c>finally</c>.</param>
/// <param name="CredentialKeyPublicPoint">The credential key's exported public point, SEC1 uncompressed (<c>0x04 ‖ X ‖ Y</c>), the ECDH peer point and the <c>KDFe</c> partyVInfo source.</param>
/// <param name="CredentialKeyCurve">The ECC curve the credential key lives on.</param>
/// <param name="NameAlg">The credential key's Name algorithm, driving the <c>KDFe</c> / <c>KDFa</c> / HMAC digests.</param>
public sealed record TpmMakeCredentialAction(
    Tpm2bDigest Credential,
    Tpm2bName ObjectName,
    ReadOnlyMemory<byte> CredentialKeyPublicPoint,
    TpmiEccCurve CredentialKeyCurve,
    TpmiAlgHash NameAlg): TpmAction;

/// <summary>
/// Declares that the simulator must recover a wrapped credential for <c>TPM2_ActivateCredential()</c> before the
/// next transition. Emitted by the <c>TPM2_ActivateCredential()</c> transition; the effectful loop recovers the
/// seed through an ECDH exchange between the credential key's private scalar and the transported ephemeral point
/// (with <c>KDFe</c>), re-derives the credential's symmetric and HMAC keys from the seed <b>and the activate
/// object's Name</b>, verifies the outer HMAC, and on a match decrypts the credential and feeds it back as a
/// <see cref="TpmCredentialActivated"/> input; a mismatch feeds back the integrity-failure rejection (TPM 2.0
/// Library Part 1, clause 24; Part 3, clause 12.5).
/// </summary>
/// <remarks>
/// Because the re-derivation is keyed on the activate object's Name, activating a credential bound to one object
/// against a different object yields different keys, so the outer HMAC does not verify — the binding both the
/// positive and the negative cases turn on.
/// </remarks>
/// <param name="CredentialBlob">The credential blob (<c>TPMS_ID_OBJECT</c>: the outer HMAC then the encrypted credential).</param>
/// <param name="Secret">The encrypted seed transport (a marshaled <c>TPMS_ECC_POINT</c>, the ephemeral public point).</param>
/// <param name="ActivateObjectName">The activate object's Name — re-keys the credential's symmetric and HMAC keys, so a mismatched object fails the integrity check.</param>
/// <param name="CredentialKeyPrivateScalar">The credential key's retained ECC scalar (unsigned big-endian), the ECDH private input that recovers the shared value — a borrowed reference to the carrier the durable object state owns; the effect reads it at the exchange primitive and never disposes it.</param>
/// <param name="CredentialKeyPublicPoint">The credential key's exported public point, SEC1 uncompressed, the <c>KDFe</c> partyVInfo source (matching the make side).</param>
/// <param name="CredentialKeyCurve">The ECC curve the credential key lives on.</param>
/// <param name="NameAlg">The credential key's Name algorithm, driving the <c>KDFe</c> / <c>KDFa</c> / HMAC digests.</param>
public sealed record TpmActivateCredentialAction(
    ReadOnlyMemory<byte> CredentialBlob,
    ReadOnlyMemory<byte> Secret,
    Tpm2bName ActivateObjectName,
    PrivateKeyMemory CredentialKeyPrivateScalar,
    ReadOnlyMemory<byte> CredentialKeyPublicPoint,
    TpmiEccCurve CredentialKeyCurve,
    TpmiAlgHash NameAlg): TpmAction;

/// <summary>
/// Declares that the simulator must wrap a credential secret to an RSA credential key's public modulus via
/// RSA-OAEP before the next transition — the RSA arm of <c>TPM2_MakeCredential()</c> (TPM 2.0 Library Part 1,
/// clause 24; Annex B.4, B.10.3, B.10.4; Part 3, clause 12.6). Emitted by the <c>TPM2_MakeCredential()</c>
/// transition when the resolved credential key is RSA; the effectful loop draws a fresh random seed (no
/// ephemeral key pair — RSA has no ECDH-style split step), OAEP-encrypts it to the credential key's modulus
/// through the injected <see cref="TpmRsaSigningBackend"/>, then produces the AK-Name-bound credential blob
/// exactly as the ECC arm does (the outer wrap, Part 1, clause 24, does not branch on the credential key's
/// algorithm) and feeds it back as a <see cref="TpmCredentialMade"/> input.
/// </summary>
/// <remarks>
/// The transition resolves the credential-key handle against the loaded-object table and folds its exported
/// public modulus into this action, so the effect needs no automaton state and captures nothing. The Name
/// algorithm is the simulator's universal <c>TPM_ALG_SHA256</c>.
/// </remarks>
/// <param name="Credential">The secret to wrap (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="ObjectName">The attestation key's Name the credential is bound to (folded into the <c>KDFa</c> derivations and the outer HMAC) — an owned <c>TPM2B_NAME</c> carrier the transition transferred out of the request; the effect is its terminal owner and releases it in the <c>finally</c>.</param>
/// <param name="CredentialKeyModulus">The credential key's exported public modulus (<c>TPM2B_PUBLIC_KEY_RSA</c>, TPM 2.0 Library Part 2, clause 11.2.4.5, Table 193), unsigned big-endian, the OAEP public-key input — a BORROW of the loaded object's own durable carrier, which outlives this command; the effect reads it and never releases it.</param>
/// <param name="NameAlg">The credential key's Name algorithm, driving the seed size, the OAEP <c>lhash</c>/MGF1 digests (the credential key's scheme is <c>TPM_ALG_NULL</c> for every storage-parent template this simulator builds, so <c>lhash</c> coincides with nameAlg), and the <c>KDFa</c>/HMAC digests.</param>
public sealed record TpmRsaMakeCredentialAction(
    Tpm2bDigest Credential,
    Tpm2bName ObjectName,
    Tpm2bPublicKeyRsa CredentialKeyModulus,
    TpmiAlgHash NameAlg): TpmAction;

/// <summary>
/// Declares that the simulator must recover a credential secret transported by RSA-OAEP for
/// <c>TPM2_ActivateCredential()</c> before the next transition — the RSA arm (TPM 2.0 Library Part 1, clause 24;
/// Annex B.3, B.4, B.10.3, B.10.4; Part 3, clause 12.5). Emitted by the <c>TPM2_ActivateCredential()</c>
/// transition when the resolved credential key is RSA; the effectful loop RSADP-decrypts and OAEP-decodes the
/// transported secret through the injected <see cref="TpmRsaSigningBackend"/> — substituting an all-zero seed
/// on any decode failure rather than reporting it directly (Part 1, Annex B.10.3, imported by B.10.4) — then
/// re-derives the credential's symmetric and HMAC keys from the recovered seed <b>and the activate object's
/// Name</b>, verifies the outer HMAC exactly as the ECC arm does, and on a match decrypts the credential and
/// feeds it back as a <see cref="TpmCredentialActivated"/> input; a mismatch feeds back the integrity-failure
/// rejection.
/// </summary>
/// <remarks>
/// Because the re-derivation is keyed on the activate object's Name, activating a credential bound to one object
/// against a different object yields different keys, so the outer HMAC does not verify — the binding both the
/// positive and the negative cases turn on, identically to the ECC arm.
/// </remarks>
/// <param name="CredentialBlob">The credential blob (<c>TPMS_ID_OBJECT</c>: the outer HMAC then the encrypted credential).</param>
/// <param name="Secret">The encrypted seed transport — already unwrapped from its <c>TPM2B_ENCRYPTED_SECRET</c> framing by the command parser, so this is the raw OAEP ciphertext directly (Part 2, Table 209/210: the RSA arm has no sub-structure, unlike the ECC arm's marshaled <c>TPMS_ECC_POINT</c>).</param>
/// <param name="ActivateObjectName">The activate object's Name — re-keys the credential's symmetric and HMAC keys, so a mismatched object fails the integrity check.</param>
/// <param name="CredentialKeyPrivateKey">The credential key's retained RSA private key, in the backend's own encoding — the RSADP private input that recovers the OAEP-encoded message; a borrowed reference to the carrier the durable object state owns, read at the decrypt primitive and never disposed by the effect.</param>
/// <param name="NameAlg">The credential key's Name algorithm, driving the seed size, the OAEP <c>lhash</c>/MGF1 digests, and the <c>KDFa</c>/HMAC digests.</param>
public sealed record TpmRsaActivateCredentialAction(
    ReadOnlyMemory<byte> CredentialBlob,
    ReadOnlyMemory<byte> Secret,
    Tpm2bName ActivateObjectName,
    PrivateKeyMemory CredentialKeyPrivateKey,
    TpmiAlgHash NameAlg): TpmAction;

/// <summary>
/// Declares that the simulator must compute an NV Index's Name before the next transition, so
/// <c>TPM2_PolicyNV()</c>'s policyDigest extension can bind it (TPM 2.0 Library Part 3, clause 23.9; Part 1,
/// clause 14, Table 6). Emitted by the <c>TPM2_PolicyNV()</c> transition; the effectful loop marshals the Index's
/// <c>TPMS_NV_PUBLIC</c> and computes <c>nameAlg ‖ H_nameAlg(TPMS_NV_PUBLIC)</c> through the registered digest
/// seam, then feeds the Name back with the pending assertion's arguments as a
/// <see cref="TpmNvNameComputedForPolicy"/> input so a second transition can extend the session's policyDigest.
/// </summary>
/// <remarks>
/// <see cref="NameAlg"/> and <see cref="AuthPolicy"/> are the defining Index's own retained fields
/// (<see cref="NvIndexState.NameAlg"/>/<see cref="NvIndexState.AuthPolicy"/>), not a fixed
/// assumption — every Index's Name computation uses the algorithm and policy it was actually defined with.
/// </remarks>
/// <param name="PolicySession">The policy session whose policyDigest the assertion extends.</param>
/// <param name="NvIndex">The NV Index handle, folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="Attributes">The Index's current attributes (<c>TPMA_NV</c>), folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="DataSize">The Index's declared data size, folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="NameAlg">The Index's own Name algorithm, driving the marshaled <c>TPMS_NV_PUBLIC.nameAlg</c> and the digest.</param>
/// <param name="AuthPolicy">The Index's own access policy digest (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92), folded into the marshaled <c>TPMS_NV_PUBLIC.authPolicy</c>. A borrowed reference to the durable Index state's own carrier; the effect reads it and never disposes it.</param>
/// <param name="OperandB">The comparison operand the pending assertion carries (<c>TPM2B_OPERAND</c>, TPM 2.0 Library Part 2, clause 10.4.6, Table 96) — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="Offset">The octet offset into the NV Index data the pending assertion carries.</param>
/// <param name="Operation">The <c>TPM_EO</c> comparison operation the pending assertion carries.</param>
/// <param name="PolicyHashAlgorithm">The policy session's own hash algorithm, sizing the policyDigest fold the effect performs once the Name is in hand — independent of <see cref="NameAlg"/>, which is the Index's.</param>
/// <param name="CurrentPolicyDigest">The session's current accumulated policyDigest — a borrowed reference to the carrier the durable session record owns; the effect reads it as the fold's first term and never disposes it.</param>
public sealed record TpmComputeNvNameAction(
    TpmiShPolicy PolicySession,
    TpmiRhNvIndex NvIndex,
    TpmaNv Attributes,
    ushort DataSize,
    TpmiAlgHash NameAlg,
    Tpm2bDigest AuthPolicy,
    Tpm2bOperand OperandB,
    ushort Offset,
    ushort Operation,
    TpmiAlgHash PolicyHashAlgorithm,
    Tpm2bDigest CurrentPolicyDigest): TpmAction;

/// <summary>
/// Declares that the simulator must marshal an NV Index's public area and compute its Name before the next
/// transition, so <c>TPM2_NV_ReadPublic()</c>'s response can carry both (TPM 2.0 Library Part 3, clause 31.6;
/// Part 1, clause 14 and Table 6). Emitted by the <c>TPM2_NV_ReadPublic()</c> transition; the effectful loop
/// builds the <c>TPMS_NV_PUBLIC</c> from these fields, marshals it, and computes
/// <c>nameAlg ‖ H_nameAlg(TPMS_NV_PUBLIC)</c> through the registered digest seam, then feeds both back as a
/// <see cref="TpmNvPublicNameComputed"/> input.
/// </summary>
/// <param name="NvIndex">The NV Index handle, folded into the marshaled <c>TPMS_NV_PUBLIC</c> and echoed into the framed <c>nvPublic</c>.</param>
/// <param name="NameAlg">The Index's Name algorithm, driving the marshaled <c>TPMS_NV_PUBLIC.nameAlg</c> and the digest.</param>
/// <param name="Attributes">The Index's current attributes (<c>TPMA_NV</c>), folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="AuthPolicy">The Index's access policy digest (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92), folded into the marshaled <c>TPMS_NV_PUBLIC.authPolicy</c>. A borrowed reference to the durable Index state's own carrier; the effect reads it and never disposes it.</param>
/// <param name="DataSize">The Index's declared data size, folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
public sealed record TpmComputeNvPublicNameAction(
    TpmiRhNvIndex NvIndex,
    TpmiAlgHash NameAlg,
    TpmaNv Attributes,
    Tpm2bDigest AuthPolicy,
    ushort DataSize): TpmAction;

/// <summary>
/// Declares that the simulator must marshal an NV Index's public area and compute its Name before the next
/// transition, so a session-authorized NV command's cpHash Name1/Name2 terms and command-HMAC key can be built
/// from the real, hash-based Index Name (TPM 2.0 Library Part 1, clause 16.7 equation 15; clause 17.6.10
/// equations 21/22) — the command-HMAC counterpart of <see cref="TpmComputeNvPublicNameAction"/>, carrying
/// <see cref="Resume"/> through so the pending session-authorized request can be recovered once the Name
/// arrives.
/// </summary>
/// <param name="NvIndex">The NV Index handle, folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="NameAlg">The Index's Name algorithm, driving the marshaled <c>TPMS_NV_PUBLIC.nameAlg</c> and the digest.</param>
/// <param name="Attributes">The Index's current attributes (<c>TPMA_NV</c>), folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="AuthPolicy">The Index's access policy digest (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92), folded into the marshaled <c>TPMS_NV_PUBLIC.authPolicy</c>. A borrowed reference to the durable Index state's own carrier; the effect reads it and never disposes it.</param>
/// <param name="DataSize">The Index's declared data size, folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="Resume">
/// The original session-authorized NV request — <c>TpmNvReadOverSessionRequested</c>,
/// <c>TpmNvWriteOverSessionRequested</c>, <c>TpmNvUndefineSpaceOverSessionRequested</c>,
/// <c>TpmNvIncrementOverSessionRequested</c>, <c>TpmNvCertifyOverSessionRequested</c>, or
/// <c>TpmNvChangeAuthOverSessionRequested</c> — to resume once the Name and, later, the command-HMAC
/// verification complete. The last two take their own continuations out of <c>OnNvIndexNameComputed</c> rather
/// than its shared USER-role body: <c>TPM2_NV_ChangeAuth()</c> because its cpHash has a single handle, and
/// <c>TPM2_NV_Certify()</c> because its cpHash has THREE (Part 1, clause 16.7 equation 15's
/// <c>Name1 ‖ Name2 ‖ Name3</c>) and its authorizing session sits at index 1.
/// </param>
public sealed record TpmComputeNvIndexNameAction(
    TpmiRhNvIndex NvIndex,
    TpmiAlgHash NameAlg,
    TpmaNv Attributes,
    Tpm2bDigest AuthPolicy,
    ushort DataSize,
    TpmSimulatorInput Resume): TpmAction;

/// <summary>
/// Declares that the simulator must roll the authorizing session's nonceTPM and frame a real response session
/// entry for a session-authorized NV command before the next transition — the NV-family generalization of
/// <see cref="TpmFramePolicySecretSessionResponseAction"/>, shared by <c>TPM2_NV_Read()</c>,
/// <c>TPM2_NV_Write()</c>, <c>TPM2_NV_DefineSpace()</c>, <c>TPM2_NV_UndefineSpace()</c>, and
/// <c>TPM2_NV_Increment()</c> since none of them
/// carries more than the one optional response parameter <see cref="ParameterArea"/> represents (TPM 2.0
/// Library Part 3's own response schematics), nor more than the one authorizing session an entry is owed for
/// (Part 1, clause 16.6.1).
/// <c>TPM2_NV_Certify()</c> is the NV command that has both at once — a
/// <c>certifyInfo ‖ signature</c> parameter area AND two authorizing sessions — so it frames through
/// <see cref="TpmNvCertifyAction"/>'s own response-session list instead. The hierarchy and provisioning commands — <c>TPM2_Clear()</c>,
/// <c>TPM2_ClearControl()</c>, <c>TPM2_HierarchyControl()</c>, and <c>TPM2_SetPrimaryPolicy()</c> — share the
/// same shape and so are framed through it too, each with an empty parameter area. Emitted by each command's
/// <c>Continue…OverSession</c> once its command-HMAC
/// has verified and any business-logic checks (range, attribute gates) have already passed; the effectful loop
/// computes rpHash over <see cref="ParameterArea"/>, rolls a fresh nonceTPM, and computes the response HMAC
/// keyed on the SAME <c>sessionKey ‖ authValue</c> the command-HMAC verification used (Part 1, clause 17.6.5),
/// feeding the result back as a <see cref="TpmNvSessionResponseFramed"/> input.
/// </summary>
/// <param name="CommandCode">The command code, folded into rpHash (Part 1, clause 16.8 equation 16).</param>
/// <param name="SessionHandle">The authorizing session whose nonceTPM is rolled once framed.</param>
/// <param name="SessionAlg">The session hash algorithm driving rpHash and the response HMAC.</param>
/// <param name="SessionKey">The session key — a borrowed reference to the carrier the durable session record owns; the effect reads it at the HMAC primitive and never disposes it.</param>
/// <param name="AuthValue">The bind-omission-resolved authValue folded into the response HMAC key alongside <see cref="SessionKey"/> — a borrowed reference to the carrier the durable state owns, carrying the same value the command-HMAC verification used; the effect reads its trailing-zero-stripped view at the HMAC primitive and never disposes it.</param>
/// <param name="NonceCaller">This session's command caller nonce, the response HMAC's nonceOlder (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94) — OWNED by this action, transferred out of the request record by the continuation that declared it, and released by the framing effect's <c>finally</c> once the response HMAC has been computed.</param>
/// <param name="SessionAttributes">This session's command session-attributes octet, echoed into its response entry.</param>
/// <param name="ReadWindow">
/// The single response parameter this command owes, or <see langword="null"/> when it owes none —
/// <c>TPM2_NV_Write()</c>/<c>TPM2_NV_DefineSpace()</c>/<c>TPM2_NV_UndefineSpace()</c>/<c>TPM2_NV_Increment()</c>
/// and the hierarchy commands all frame an empty parameter area. For <c>TPM2_NV_Read()</c> it is the requested
/// window of the Index's data area, BORROWED from the Index that owns it; the effect frames it as a
/// <c>TPM2B_MAX_NV_BUFFER</c> into its own rental and never disposes the borrowed carrier.
/// </param>
public sealed record TpmFrameNvSessionResponseAction(
    TpmCcConstants CommandCode,
    TpmiShAuthSession SessionHandle,
    TpmiAlgHash SessionAlg,
    SymmetricKeyMemory SessionKey,
    Tpm2bAuth AuthValue,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    TpmNvDataWindow? ReadWindow): TpmAction;

/// <summary>
/// Declares that the simulator must verify a digest/signature pair against a loaded ECC key's public point and,
/// on success, produce a <c>TPMT_TK_VERIFIED</c>. Emitted by the <c>TPM2_VerifySignature()</c> transition; the
/// effectful loop calls the injected <see cref="TpmEccDigestVerifyDelegate"/> and, when it returns
/// <see langword="true"/>, re-derives the verifying key's hierarchy proof and computes
/// <c>HMAC(proof, TPM_ST_VERIFIED || digest || keyName)</c> — the mirror image of the creation ticket's
/// <c>name || creationHash</c> field order — feeding the result back as a <see cref="TpmSignatureVerified"/> input
/// (TPM 2.0 Library Part 3, clause 20.1; Part 2, clause 10.7.4).
/// </summary>
/// <remarks>
/// The transition resolves the <c>keyHandle</c> against the loaded-object table and folds its Name, hierarchy,
/// and public point into this action, so the effect needs no automaton state and captures nothing. This slice
/// models an elliptic-curve key (ECDSA), as the signing paths do. Verification is a public-key operation, so
/// unlike every signing action the key's <c>sign</c> attribute is never consulted here.
/// </remarks>
/// <param name="KeyName">The verifying key's Name, folded into the ticket HMAC.</param>
/// <param name="KeyHierarchy">The permanent hierarchy the verifying key was created under, from which its ticket proof re-derives.</param>
/// <param name="PublicPoint">The verifying key's retained public point, SEC1 uncompressed.</param>
/// <param name="Curve">The ECC curve the public point lives on.</param>
/// <param name="Digest">The caller-supplied digest the signature is claimed to be over (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="Signature">The caller-supplied signature, IEEE P1363 <c>r ‖ s</c>.</param>
/// <param name="HashAlg">The hash algorithm carried inside the signature.</param>
public sealed record TpmVerifySignatureAction(
    Tpm2bName KeyName,
    TpmiRhHierarchy KeyHierarchy,
    ReadOnlyMemory<byte> PublicPoint,
    TpmiEccCurve Curve,
    Tpm2bDigest Digest,
    ReadOnlyMemory<byte> Signature,
    TpmiAlgHash HashAlg): TpmAction;

/// <summary>
/// The RSA counterpart of <see cref="TpmVerifySignatureAction"/>: verify a digest/signature pair against a loaded
/// RSA key's retained private key (the simulator retains no standalone RSA public encoding, so the injected
/// <see cref="TpmRsaDigestVerifyDelegate"/> derives the public part from it) under the requested RSA scheme, and
/// on success produce a <c>TPMT_TK_VERIFIED</c> the same way <see cref="TpmVerifySignatureAction"/> does.
/// </summary>
/// <param name="KeyName">The verifying key's Name, folded into the ticket HMAC.</param>
/// <param name="KeyHierarchy">The permanent hierarchy the verifying key was created under, from which its ticket proof re-derives.</param>
/// <param name="PrivateKey">The verifying key's retained private key, in the backend's own encoding — a borrowed reference to the carrier the durable object state owns; the effect reads it at the primitive and never disposes it.</param>
/// <param name="Digest">The caller-supplied digest the signature is claimed to be over (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="Signature">The caller-supplied raw RSA signature octets.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to verify under.</param>
/// <param name="HashAlg">The hash algorithm carried inside the signature.</param>
public sealed record TpmRsaVerifySignatureAction(
    Tpm2bName KeyName,
    TpmiRhHierarchy KeyHierarchy,
    PrivateKeyMemory PrivateKey,
    Tpm2bDigest Digest,
    ReadOnlyMemory<byte> Signature,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash HashAlg): TpmAction;

/// <summary>
/// Declares that the simulator must recompute <c>TPM2_PolicySigned()</c>'s <c>aHash</c> and verify it against a
/// loaded ECC key's public point before the next transition (TPM 2.0 Library Part 3, Section 23.3). Emitted by
/// the <c>TPM2_PolicySigned()</c> transition for a non-trial session whose <c>authObject</c> resolves to an ECC
/// key, after the (non-crypto) nonceTPM/expiration/cpHashA checks have already passed; the effectful loop hashes
/// <c>nonceTPM ‖ expiration ‖ cpHashA ‖ policyRef</c> with <see cref="SchemeHashAlg"/> (the signature scheme's own
/// hash — independent of <see cref="PolicyHashAlgorithm"/>) through the registered async digest seam, calls the
/// injected <see cref="TpmEccDigestVerifyDelegate"/>, and feeds the boolean result back as a
/// <see cref="TpmPolicySignedVerified"/> input. On a successful verification, a non-trial session whose caller
/// requested a ticket (<see cref="Expiration"/> negative) mints a real <c>TPMT_TK_AUTH{TPM_ST_AUTH_SIGNED}</c>
/// per equation 12 (Part 2, Table 111) using <see cref="Hierarchy"/>'s proof; otherwise (no ticket requested, or
/// a trial session, which never reaches this action at all) the response frames a NULL ticket, mirroring
/// <see cref="TpmVerifySignatureAction"/>'s own success/no-ticket split.
/// </summary>
/// <param name="PolicySession">The policy session to extend on a successful verification.</param>
/// <param name="AuthObjectName">The authorizing key's Name, folded into the policyDigest fold (<c>arg2</c> of <c>PolicyUpdate</c>) and into the ticket HMAC's <c>authName</c> term — a borrowed reference to the <c>TPM2B_NAME</c> carrier the durable object state owns; the effect reads it at the digest primitives and never disposes it.</param>
/// <param name="PolicyRef">The policy qualifier, always folded as the second <c>PolicyUpdate</c> hash (Part 3, Section 23.2.3) and, when a ticket is minted, into the ticket HMAC's <c>policyRef</c> term — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="PolicyHashAlgorithm">The session's own policy hash algorithm, sizing the policyDigest fold — independent of <see cref="SchemeHashAlg"/>.</param>
/// <param name="CurrentPolicyDigest">The session's current accumulated policyDigest — a borrowed reference to the carrier the durable session record owns; the effect reads it as the fold's first term and never disposes it.</param>
/// <param name="NonceTpm">The nonceTPM bytes folded into <c>aHash</c> (already validated against the session's retained nonce), in an owned carrier the request record transferred into this action; the effect is its terminal owner once the aHash has bound to it. Also selects the ticket's <c>expiresOnReset</c> flag (empty ⇒ absolute deadline ⇒ expires on reset).</param>
/// <param name="Expiration">The signed expiration folded into <c>aHash</c> as 4 big-endian octets; its sign requests a ticket (negative) or not (zero or positive).</param>
/// <param name="CpHashA">The cpHashA bytes folded into <c>aHash</c> (already size- and latch-checked) and, when a ticket is minted, into the ticket HMAC's <c>cpHash</c> term — an owned carrier the transition transferred out of the request; the effect hands it onward to the continuation, which latches or releases it.</param>
/// <param name="PublicPoint">The authorizing key's retained public point, SEC1 uncompressed.</param>
/// <param name="Curve">The ECC curve the public point lives on.</param>
/// <param name="Signature">The caller-supplied signature, IEEE P1363 <c>r ‖ s</c>.</param>
/// <param name="SchemeHashAlg">H_authAlg: the hash algorithm carried inside the <c>TPMT_SIGNATURE auth</c> parameter — independent of <see cref="PolicyHashAlgorithm"/>.</param>
/// <param name="Hierarchy">The authorizing key's hierarchy, from which the ticket's proof derives when a ticket is minted, and the value framed in the ticket's own <c>hierarchy</c> field.</param>
/// <param name="Timeout">The already-computed deadline magnitude (the value the transition's own inline deadline check produced, never recomputed here); zero when <see cref="Expiration"/> is zero.</param>
/// <param name="TimeEpoch">The TPM's current time epoch, folded into equation 12's conditional <c>[timeEpoch]</c> term when a ticket is minted.</param>
/// <param name="ResetCount">The TPM's current Reset count, folded into equation 12's conditional <c>[resetCount]</c> term when a ticket is minted and it expires on reset.</param>
public sealed record TpmVerifyPolicySignedAction(
    TpmiShPolicy PolicySession,
    Tpm2bName AuthObjectName,
    Tpm2bNonce PolicyRef,
    TpmiAlgHash PolicyHashAlgorithm,
    Tpm2bDigest CurrentPolicyDigest,
    Tpm2bNonce NonceTpm,
    int Expiration,
    Tpm2bDigest CpHashA,
    ReadOnlyMemory<byte> PublicPoint,
    TpmiEccCurve Curve,
    ReadOnlyMemory<byte> Signature,
    TpmiAlgHash SchemeHashAlg,
    TpmiRhHierarchy Hierarchy,
    ulong Timeout,
    uint TimeEpoch,
    uint ResetCount): TpmAction;

/// <summary>
/// The RSA counterpart of <see cref="TpmVerifyPolicySignedAction"/>: recompute <c>TPM2_PolicySigned()</c>'s
/// <c>aHash</c> and verify it against a loaded RSA key's retained private key (the simulator retains no
/// standalone RSA public encoding, so the injected <see cref="TpmRsaDigestVerifyDelegate"/> derives the public
/// part from it) under the requested RSA scheme, the same way <see cref="TpmVerifyPolicySignedAction"/> does,
/// including the same ticket-minting behaviour on success.
/// </summary>
/// <param name="PolicySession">The policy session to extend on a successful verification.</param>
/// <param name="AuthObjectName">The authorizing key's Name, folded into the policyDigest fold (<c>arg2</c> of <c>PolicyUpdate</c>) and into the ticket HMAC's <c>authName</c> term — a borrowed reference to the <c>TPM2B_NAME</c> carrier the durable object state owns; the effect reads it at the digest primitives and never disposes it.</param>
/// <param name="PolicyRef">The policy qualifier, always folded as the second <c>PolicyUpdate</c> hash (Part 3, Section 23.2.3) and, when a ticket is minted, into the ticket HMAC's <c>policyRef</c> term — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="PolicyHashAlgorithm">The session's own policy hash algorithm, sizing the policyDigest fold — independent of <see cref="SchemeHashAlg"/>.</param>
/// <param name="CurrentPolicyDigest">The session's current accumulated policyDigest — a borrowed reference to the carrier the durable session record owns; the effect reads it as the fold's first term and never disposes it.</param>
/// <param name="NonceTpm">The nonceTPM bytes folded into <c>aHash</c> (already validated against the session's retained nonce), in an owned carrier the request record transferred into this action; the effect is its terminal owner once the aHash has bound to it. Also selects the ticket's <c>expiresOnReset</c> flag (empty ⇒ absolute deadline ⇒ expires on reset).</param>
/// <param name="Expiration">The signed expiration folded into <c>aHash</c> as 4 big-endian octets; its sign requests a ticket (negative) or not (zero or positive).</param>
/// <param name="CpHashA">The cpHashA bytes folded into <c>aHash</c> (already size- and latch-checked) and, when a ticket is minted, into the ticket HMAC's <c>cpHash</c> term — an owned carrier the transition transferred out of the request; the effect hands it onward to the continuation, which latches or releases it.</param>
/// <param name="PrivateKey">The authorizing key's retained private key, in the backend's own encoding — a borrowed reference to the carrier the durable object state owns; the effect reads it at the primitive and never disposes it.</param>
/// <param name="Signature">The caller-supplied raw RSA signature octets.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to verify under.</param>
/// <param name="SchemeHashAlg">H_authAlg: the hash algorithm carried inside the <c>TPMT_SIGNATURE auth</c> parameter — independent of <see cref="PolicyHashAlgorithm"/>.</param>
/// <param name="Hierarchy">The authorizing key's hierarchy, from which the ticket's proof derives when a ticket is minted, and the value framed in the ticket's own <c>hierarchy</c> field.</param>
/// <param name="Timeout">The already-computed deadline magnitude (the value the transition's own inline deadline check produced, never recomputed here); zero when <see cref="Expiration"/> is zero.</param>
/// <param name="TimeEpoch">The TPM's current time epoch, folded into equation 12 (Part 2, Table 111)'s conditional <c>[timeEpoch]</c> term when a ticket is minted.</param>
/// <param name="ResetCount">The TPM's current Reset count, folded into equation 12's conditional <c>[resetCount]</c> term when a ticket is minted and it expires on reset.</param>
public sealed record TpmRsaVerifyPolicySignedAction(
    TpmiShPolicy PolicySession,
    Tpm2bName AuthObjectName,
    Tpm2bNonce PolicyRef,
    TpmiAlgHash PolicyHashAlgorithm,
    Tpm2bDigest CurrentPolicyDigest,
    Tpm2bNonce NonceTpm,
    int Expiration,
    Tpm2bDigest CpHashA,
    PrivateKeyMemory PrivateKey,
    ReadOnlyMemory<byte> Signature,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash SchemeHashAlg,
    TpmiRhHierarchy Hierarchy,
    ulong Timeout,
    uint TimeEpoch,
    uint ResetCount): TpmAction;

/// <summary>
/// Declares that the simulator must recompute <c>TPM2_PolicyAuthorize()</c>'s <c>aHash</c> and re-verify
/// <c>checkTicket</c> before the next transition (TPM 2.0 Library Part 3, Section 23.16). Emitted by the
/// <c>TPM2_PolicyAuthorize()</c> transition for a non-trial session, after the (non-crypto) <c>keySign</c>
/// hash-algorithm/size checks and the <c>approvedPolicy</c> equality check have already passed; the effectful
/// loop hashes <c>approvedPolicy ‖ policyRef</c> with <see cref="HashAlg"/> (<c>keySign</c>'s own nameAlg)
/// through the registered async digest seam, derives the hierarchy proof for the CALLER-SUPPLIED
/// <see cref="CheckTicketHierarchy"/> (never independently re-derived from <c>keySign</c> — the caller's claim
/// is exactly what is being checked), recomputes <c>HMAC(proof, TPM_ST_VERIFIED ‖ aHash ‖ keySign)</c> through
/// the existing verified-ticket formula, and constant-time compares it to <see cref="CheckTicketDigest"/>,
/// feeding the boolean result back as a <see cref="TpmPolicyAuthorizeVerified"/> input.
/// </summary>
/// <param name="PolicySession">The policy session to reset-and-fold on a successful ticket re-verification.</param>
/// <param name="ApprovedPolicy">The approved policyDigest, folded into <c>aHash</c> — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="PolicyRef">The policy qualifier, folded into <c>aHash</c> and always folded as the fold's second <c>PolicyUpdate</c> hash — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="KeySign">The Name of the key that signed the approval, folded into the ticket HMAC and the policyDigest fold — an owned <c>TPM2B_NAME</c> carrier the transition transferred out of the request; the effect is its terminal owner, since the fold it feeds runs there.</param>
/// <param name="HashAlg"><c>aHash</c>'s hash algorithm — <c>keySign</c>'s own nameAlg, independent of the session's own policy hash algorithm.</param>
/// <param name="CheckTicketHierarchy">The caller-supplied hierarchy the expected ticket's proof is derived from.</param>
/// <param name="CheckTicketDigest">The caller-supplied ticket digest to compare the recomputed one against — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="PolicyHashAlgorithm">The session's own policy hash algorithm, sizing the policyDigest fold.</param>
public sealed record TpmVerifyPolicyAuthorizeTicketAction(
    TpmiShPolicy PolicySession,
    Tpm2bDigest ApprovedPolicy,
    Tpm2bNonce PolicyRef,
    Tpm2bName KeySign,
    TpmiAlgHash HashAlg,
    TpmiRhHierarchy CheckTicketHierarchy,
    Tpm2bDigest CheckTicketDigest,
    TpmiAlgHash PolicyHashAlgorithm): TpmAction;

/// <summary>
/// Declares that the simulator must recompute a <c>TPM2_PolicyTicket()</c> ticket per equation 12 (Part 2,
/// Table 111) and constant-time compare it to the caller-supplied <see cref="TicketDigest"/> before the next
/// transition (TPM 2.0 Library Part 3, Section 23.5). Emitted after the trial-session, timeout-size,
/// live-clock-expiry, and cpHashA checks have already passed; the effectful loop derives the hierarchy proof
/// for the CALLER-SUPPLIED <see cref="TicketHierarchy"/> (never independently re-derived from anything else —
/// the caller's claim is exactly what is being checked, mirroring
/// <see cref="TpmVerifyPolicyAuthorizeTicketAction"/>), recomputes the ticket HMAC, and constant-time compares
/// it to <see cref="TicketDigest"/>, feeding the boolean result back as a <see cref="TpmPolicyTicketVerified"/>
/// input. The <see cref="TimeEpoch"/> used for the recompute is the TPM's CURRENT epoch, not one carried on
/// the wire — a ticket minted under a since-regenerated epoch fails this comparison and answers
/// <c>TPM_RC_TICKET</c>, which is how this simulator closes equation 12's cross-discontinuity replay defense
/// without a separate per-session epoch field.
/// </summary>
/// <param name="PolicySession">The policy session to extend on a successful re-verification.</param>
/// <param name="Tag">The ticket's own structure tag (<c>TPM_ST_AUTH_SIGNED</c> or <c>TPM_ST_AUTH_SECRET</c>, already legality-checked at parse — Part 2, Table 111's <c>TPM_RC_TAG</c> rule), folded into the recomputed HMAC and selecting the fold (<c>ExtendForSigned</c> vs <c>ExtendForSecret</c>) on success.</param>
/// <param name="TicketHierarchy">The caller-supplied hierarchy the expected ticket's proof is derived from.</param>
/// <param name="TicketDigest">The caller-supplied ticket digest to compare the recomputed one against — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="CpHashA">The command-parameter digest the ticket is limited to, folded into the recomputed HMAC — an owned carrier the transition transferred out of the request; the effect hands it onward to the continuation, which latches or releases it.</param>
/// <param name="PolicyRef">The policy qualifier, folded into the recomputed HMAC and folded again as the fold's second <c>PolicyUpdate</c> hash — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="AuthName">The Name of the object that provided the original authorization, folded into the recomputed HMAC and the policyDigest fold — an owned <c>TPM2B_NAME</c> carrier the transition transferred out of the request; the effect is its terminal owner, since the fold it feeds runs there.</param>
/// <param name="CurrentPolicyDigest">The session's current accumulated policyDigest — a borrowed reference to the carrier the durable session record owns; the effect reads it as the fold's first term and never disposes it.</param>
/// <param name="Timeout">The de-flagged <c>authTimeout</c> magnitude extracted from the wire <c>timeout</c> (bit 63 already cleared), folded into the recomputed HMAC.</param>
/// <param name="ExpiresOnReset">The de-flagged bit 63 of the wire <c>timeout</c>, controlling equation 12's conditional <c>[resetCount]</c> term.</param>
/// <param name="TimeEpoch">The TPM's current time epoch, folded into equation 12's conditional <c>[timeEpoch]</c> term.</param>
/// <param name="ResetCount">The TPM's current Reset count, folded into equation 12's conditional <c>[resetCount]</c> term.</param>
/// <param name="PolicyHashAlgorithm">The session's own policy hash algorithm, sizing the policyDigest fold.</param>
public sealed record TpmVerifyPolicyTicketAction(
    TpmiShPolicy PolicySession,
    ushort Tag,
    TpmiRhHierarchy TicketHierarchy,
    Tpm2bDigest TicketDigest,
    Tpm2bDigest CpHashA,
    Tpm2bNonce PolicyRef,
    Tpm2bName AuthName,
    Tpm2bDigest CurrentPolicyDigest,
    ulong Timeout,
    bool ExpiresOnReset,
    uint TimeEpoch,
    uint ResetCount,
    TpmiAlgHash PolicyHashAlgorithm): TpmAction;

/// <summary>
/// Declares that the simulator must mint a real <c>TPMT_TK_AUTH{TPM_ST_AUTH_SECRET}</c> ticket per equation 12
/// (Part 2, Table 111) before the next transition (TPM 2.0 Library Part 3, Section 23.4). Emitted by the
/// <c>TPM2_PolicySecret()</c> transition for a non-trial session whose caller requested a ticket (a negative
/// expiration), after the authValue/nonceTPM/expiration/cpHashA checks have already passed; the effectful loop
/// derives <see cref="Hierarchy"/>'s proof and recomputes the ticket HMAC, feeding the result back as a
/// <see cref="TpmPolicySecretTicketMinted"/> input. Minting an HMAC has no failure mode of its own (unlike the
/// PolicySigned/PolicyTicket verify actions, which can fail a signature check or a ticket comparison), so
/// there is no rejection response code to carry.
/// </summary>
/// <param name="PolicySession">The policy session to fold on completion.</param>
/// <param name="AuthName">The authorizing entity's Name term — a permanent entity's Name IS its 4-octet handle value (Part 1, clause 14, Table 6) — folded into the ticket HMAC's <c>authName</c> term and the policyDigest fold; the octets are materialized by the effect, which is the frame that holds a memory pool.</param>
/// <param name="PolicyRef">The policy qualifier, folded into the ticket HMAC's <c>policyRef</c> term and, again, as the fold's second <c>PolicyUpdate</c> hash — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="PolicyHashAlgorithm">The session's own policy hash algorithm, sizing the policyDigest fold.</param>
/// <param name="CurrentPolicyDigest">The session's current accumulated policyDigest — a borrowed reference to the carrier the durable session record owns; the effect reads it as the fold's first term and never disposes it.</param>
/// <param name="CpHashA">
/// The cpHashA bytes (already size- and latch-checked), folded into the ticket HMAC's <c>cpHash</c> term — a
/// borrowed reference to the carrier the durable session record owns once the latch of Part 3, Section 23.2.4
/// has run, or the dispose-immune empty sentinel when the caller supplied none. It is a borrow rather than a
/// second rental precisely because the latch already made the session the value's single owner, and the session
/// outlives this effect by construction; the effect reads it at the HMAC primitive and never disposes it.
/// </param>
/// <param name="Hierarchy">The authorizing entity's OWNING hierarchy (the transition's own EntityGetHierarchyForPermanentHandle mapping — Part 1, clause 12.5 — never the raw authHandle, which is not always itself a legal <c>TPMI_RH_HIERARCHY+</c> value), from which the ticket's proof derives, and the value framed in the ticket's own <c>hierarchy</c> field.</param>
/// <param name="Timeout">The already-computed deadline magnitude (the value the transition's own inline deadline check produced, never recomputed here).</param>
/// <param name="ExpiresOnReset">Whether the caller's nonceTPM was empty (an absolute, session-unbound deadline), controlling equation 12's conditional <c>[resetCount]</c> term.</param>
/// <param name="TimeEpoch">The TPM's current time epoch, folded into equation 12's conditional <c>[timeEpoch]</c> term.</param>
/// <param name="ResetCount">The TPM's current Reset count, folded into equation 12's conditional <c>[resetCount]</c> term when the ticket expires on reset.</param>
/// <param name="AuthorizingSession">
/// Non-<see langword="null"/> when authHandle's authorization was proven by an HMAC or POLICY session rather
/// than a password (<see cref="PolicySecretAuthorizingSession"/>) — threaded through unchanged so
/// <c>OnPolicySecretTicketMinted</c> can pass it on to <c>FoldPolicySecret</c>, which then rolls that session's
/// nonceTPM and frames a real response session entry instead of the password arm's plain response.
/// </param>
public sealed record TpmMintPolicySecretTicketAction(
    TpmiShPolicy PolicySession,
    TpmHandleName AuthName,
    Tpm2bNonce PolicyRef,
    TpmiAlgHash PolicyHashAlgorithm,
    Tpm2bDigest CurrentPolicyDigest,
    Tpm2bDigest CpHashA,
    TpmiRhHierarchy Hierarchy,
    ulong Timeout,
    bool ExpiresOnReset,
    uint TimeEpoch,
    uint ResetCount,
    PolicySecretAuthorizingSession? AuthorizingSession = null): TpmAction;

/// <summary>
/// Declares that the simulator must advance a policy session's accumulated policyDigest before the next
/// transition (TPM 2.0 Library Part 1, clause 17.7; Part 3, clause 23). One action serves every assertion whose
/// fold has no effect of its own on its path, keyed by <see cref="Fold"/> — the shape
/// <see cref="TpmDecryptAttestQualifyingDataAction"/> already uses for the five attest commands, since the
/// assertions differ in nothing this step does beyond the term set each formula hashes.
/// </summary>
/// <remarks>
/// <para>
/// The step needs an effect only because the destination must be rented at the session's own digest width, and
/// that width is knowable only once the session has been resolved from state — the digest formula itself is
/// synchronous by construction, with no device round-trip in it. The effect rents at that width, folds, and
/// hands the result back as a <see cref="TpmPolicyDigestFolded"/> input; the resuming transition installs it
/// through <see cref="PolicySessionState.WithPolicyDigest(Tpm2bDigest)"/> and frames the assertion's own
/// response.
/// </para>
/// <para>
/// Every field below serves one or more values of <see cref="Fold"/> and is its type's inert placeholder for
/// the rest — the empty sentinel, <see langword="null"/>, or zero. The owned carriers are released by the
/// effect on every path: the ones the fold consumes in its <c>finally</c>, and the ones it hands onward to the
/// feedback record only when that transfer does not happen.
/// </para>
/// </remarks>
/// <param name="Fold">The <c>PolicyUpdate</c> formula to apply, and with it which of the term fields below are meaningful.</param>
/// <param name="PolicySession">The policy session whose policyDigest advances; the resuming transition installs the result on it.</param>
/// <param name="PolicyHashAlgorithm">The session's own policy hash algorithm, sizing both the destination rental and the fold.</param>
/// <param name="CurrentPolicyDigest">The session's current accumulated policyDigest — a borrowed reference to the carrier the durable session record owns; the effect reads it as the fold's first term and never disposes it. Read by every formula except <see cref="TpmPolicyDigestFold.Or"/> and <see cref="TpmPolicyDigestFold.Authorize"/>, which reset to a Zero Digest instead.</param>
/// <param name="Label">The assertion's own transition label, carried so the resuming transition emits the same one this command has always emitted rather than a fold-shaped substitute.</param>
/// <param name="RestrictedCommand">The command code the policy is restricted to (<see cref="TpmPolicyDigestFold.CommandCode"/>).</param>
/// <param name="NameTerm">The Name term the fold hashes (<see cref="TpmPolicyDigestFold.Secret"/>: the authorizing entity's handle value, which IS its Name; <see cref="TpmPolicyDigestFold.Signed"/>: the authorizing key's Name, borrowed from the carrier the durable object state owns) — nothing is owned here, and the handle form's octets are materialized by the effect.</param>
/// <param name="PolicyRef">The policy qualifier the second <c>PolicyUpdate</c> hash always folds (<see cref="TpmPolicyDigestFold.Secret"/>, <see cref="TpmPolicyDigestFold.Signed"/>, <see cref="TpmPolicyDigestFold.Authorize"/>) — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="KeySign">The approving key's Name (<see cref="TpmPolicyDigestFold.Authorize"/>) — an owned carrier the transition transferred out of the request; the effect is its terminal owner. The dispose-immune empty sentinel for every other formula.</param>
/// <param name="Branches">The OR branch list (<see cref="TpmPolicyDigestFold.Or"/>) — an owned carrier the transition transferred out of the request; the effect is its terminal owner. <see langword="null"/> for every other formula.</param>
/// <param name="PcrSelectionBytes">The marshaled <c>TPML_PCR_SELECTION</c> exactly as sent, folded verbatim (<see cref="TpmPolicyDigestFold.Pcr"/>).</param>
/// <param name="PcrDigest">The caller-supplied expected PCR digest (<see cref="TpmPolicyDigestFold.Pcr"/>) — an owned carrier the transition transferred out of the request; the effect is its terminal owner. Folded verbatim on a trial session; compared against the live composite on a real one.</param>
/// <param name="PcrValues">The currently selected PCR values in ascending index order (<see cref="TpmPolicyDigestFold.Pcr"/>), from which the effect computes the live composite a real session binds to — borrowed references to the durable bank's own memory, never disposed here.</param>
/// <param name="IsTrialSession">Whether the session accumulates without authorizing, which for <see cref="TpmPolicyDigestFold.Pcr"/> selects the caller's digest verbatim over the live composite (Part 3, clause 23.7).</param>
/// <param name="OperandB">The comparison operand the argHash covers (<see cref="TpmPolicyDigestFold.CounterTimer"/>) — an owned <c>TPM2B_OPERAND</c> carrier (TPM 2.0 Library Part 2, clause 10.4.6, Table 96) the transition transferred out of the request; the effect is its terminal owner. The dispose-immune empty sentinel for every other formula.</param>
/// <param name="Offset">The octet offset the argHash covers (<see cref="TpmPolicyDigestFold.CounterTimer"/>).</param>
/// <param name="Operation">The <c>TPM_EO</c> comparison the argHash covers (<see cref="TpmPolicyDigestFold.CounterTimer"/>).</param>
/// <param name="TimeoutMagnitude">The deadline magnitude the session's own tracked timeout ranks under Part 3, Section 23.2.4's min-with-existing rule (<see cref="TpmPolicyDigestFold.Secret"/>, <see cref="TpmPolicyDigestFold.Signed"/>). Every arm that reaches this action frames a NULL ticket and a NULL timeout (Section 23.2.5) — a real ticket is minted in its own effect, which folds there too — so the deadline travels as this magnitude alone.</param>
/// <param name="AuthorizingSession">The HMAC or POLICY session that authorized <c>TPM2_PolicySecret()</c>, or <see langword="null"/> for its password arm; threaded through so the resuming transition frames the same response shape the fold has always framed.</param>
public sealed record TpmFoldPolicyDigestAction(
    TpmPolicyDigestFold Fold,
    TpmiShPolicy PolicySession,
    TpmiAlgHash PolicyHashAlgorithm,
    Tpm2bDigest CurrentPolicyDigest,
    string Label,
    TpmCcConstants RestrictedCommand,
    TpmHandleName NameTerm,
    Tpm2bNonce PolicyRef,
    Tpm2bName KeySign,
    TpmlDigest? Branches,
    ReadOnlyMemory<byte> PcrSelectionBytes,
    Tpm2bDigest PcrDigest,
    ImmutableArray<ReadOnlyMemory<byte>> PcrValues,
    bool IsTrialSession,
    Tpm2bOperand OperandB,
    ushort Offset,
    ushort Operation,
    ulong TimeoutMagnitude,
    PolicySecretAuthorizingSession? AuthorizingSession): TpmAction;

/// <summary>
/// Declares that the simulator must roll the authorizing session's nonceTPM and frame a real response session
/// entry for <c>TPM2_PolicySecret()</c> before the next transition — the command-specific analogue of
/// <see cref="TpmEncryptRandomAction"/>/<see cref="TpmSealDataOverSessionsAction"/> for a command whose response
/// is a timeout/ticket pair rather than an encryptable parameter (TPM 2.0 Library Part 1, clause 16.6.1).
/// Emitted by <c>FoldPolicySecret</c> once the policyDigest fold itself has already been decided (trial fold,
/// immediate no-ticket fold, or the ticket-mint continuation) whenever authHandle's authorization was proven by
/// a real session rather than a password; the effectful loop frames <c>TPM2B_TIMEOUT ‖ TPMT_TK_AUTH</c> via the
/// same helper the password arm's response uses, rolls a fresh nonceTPM, computes rpHash over those framed
/// bytes, and computes the response HMAC keyed on the SAME <c>sessionKey ‖ authValue</c> the command HMAC
/// verification used (Part 1, clause 17.6.5), feeding the result back as a
/// <see cref="TpmPolicySecretSessionResponseFramed"/> input.
/// </summary>
/// <param name="SessionHandle">The authorizing session whose nonceTPM is rolled once framed.</param>
/// <param name="IsPolicySession">Whether <see cref="SessionHandle"/> names a POLICY session (routes the roll to <c>PolicySessions</c>) rather than an HMAC session (<c>HmacSessions</c>).</param>
/// <param name="SessionAlg">The session hash algorithm driving rpHash and the response HMAC.</param>
/// <param name="SessionKey">The session key — a borrowed reference to the carrier the durable session record owns; the effect reads it at the HMAC primitive and never disposes it.</param>
/// <param name="AuthValue">The authValue folded into the response HMAC key alongside <see cref="SessionKey"/> — a borrowed reference to the carrier the durable state owns, carrying the same value (and the same eq. 22 (Part 1, clause 17.6.10)/26/27 (Part 1, clause 17.6.12) decision) the command-HMAC verification used; the effect reads its trailing-zero-stripped view at the HMAC primitive and never disposes it.</param>
/// <param name="NonceCaller">This session's command caller nonce (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94) — the response HMAC's nonceOlder. OWNED: transferred out of the authorizing-session entry the request record fed, and released by this effect's <see langword="finally"/>.</param>
/// <param name="SessionAttributes">This session's command session-attributes octet, echoed into its response entry.</param>
/// <param name="Timeout">The already-decided deadline as a <c>TPM2B_TIMEOUT</c> carrier (Section 23.2.5; TPM 2.0 Library Part 2, clause 10.4.10, Table 100) — owned; the effect is its terminal owner, consuming and disposing it while framing the response parameter bytes. The shared empty carrier when <see cref="TicketDigest"/> is <see langword="null"/>, where a NULL timeout is framed.</param>
/// <param name="Hierarchy">The hierarchy framed in the ticket's own <c>hierarchy</c> field; meaningless when <see cref="TicketDigest"/> is <see langword="null"/>.</param>
/// <param name="TicketDigest">The minted ticket's HMAC digest as a <c>TPM2B_DIGEST</c>, or <see langword="null"/> for a NULL ticket — owned; the effect is its terminal owner, consuming and disposing it while framing the response parameter bytes.</param>
public sealed record TpmFramePolicySecretSessionResponseAction(
    TpmiShAuthSession SessionHandle,
    bool IsPolicySession,
    TpmiAlgHash SessionAlg,
    SymmetricKeyMemory SessionKey,
    Tpm2bAuth AuthValue,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    Tpm2bTimeout Timeout,
    TpmiRhHierarchy Hierarchy,
    Tpm2bDigest? TicketDigest): TpmAction;

/// <summary>
/// Declares that the simulator must decrypt (if a decrypt session is present) and decode <c>TPM2_Create()</c>'s
/// <c>inSensitive</c> before the next transition — the request-direction counterpart of
/// <see cref="TpmEncryptRandomAction"/> (TPM 2.0 Library Part 1, clauses 19 and 21; Part 3, clause 5.7). Emitted
/// once every session in the command's authorization area has verified (Part 3, clause 5.6 precedes clause 5.7);
/// the effectful loop decrypts the data portion of <see cref="RawParameterArea"/>'s first parameter in place when
/// <see cref="HasDecryptSession"/> is set, then decodes <c>userAuth</c>/<c>data</c> with bounds-checked reads (a
/// wrong decryption key's garbage bytes must not crash the simulator) and feeds the result back as a
/// <see cref="TpmCreateSensitiveDecrypted"/> input.
/// </summary>
/// <remarks>
/// Either slot of this command's area may carry the <c>decrypt</c> attribute — "a session with this attribute
/// does not need to be associated with an entity identified in the handle area" (Part 1, clause 16.6.4, Table
/// 12), so it rides the parent's own authorizing session as readily as a separate companion. The claiming slot
/// decides <see cref="EntityAuthValue"/>: the parent's LIVE authValue when the authorizing slot claims it,
/// and the shared empty carrier for a companion, whose <c>sessionValue</c> is then <see cref="SessionKey"/>
/// alone ("if the session is not being used for authorization, sessionValue is sessionKey", clause 19.1).
/// </remarks>
/// <param name="Request">The original parsed command request, threaded through to the continuation so it can resolve the sessions needing a real response entry.</param>
/// <param name="RawParameterArea">The raw parameter-area bytes captured at parse time (still encrypted, if a decrypt session is present); its first parameter's data portion is decrypted in place, then the whole buffer is decoded. A BORROW: the request record owns the carrier and every terminal path releases it there, while the in-place transform writes through <see cref="TpmParameterArea.Memory"/> so the octets cpHash digested as ciphertext are the octets the body decodes as plaintext (Part 3, clause 5.6 before clause 5.7).</param>
/// <param name="HasDecryptSession">Whether a decrypt session is present; when clear the buffer is decoded without any transform.</param>
/// <param name="SessionAlg">The decrypt session's hash algorithm, driving its KDFa. Meaningless when <see cref="HasDecryptSession"/> is clear.</param>
/// <param name="Symmetric">The decrypt session's negotiated symmetric definition, selecting XOR obfuscation or AES-CFB. Meaningless when <see cref="HasDecryptSession"/> is clear.</param>
/// <param name="SessionKey">The decrypt session's session key — a borrowed reference to the carrier the durable session record owns; the effect reads it at the keystream primitive and never disposes it. The shared <see cref="TpmSimulatorState.EmptySessionKey"/> when <see cref="HasDecryptSession"/> is clear.</param>
/// <param name="EntityAuthValue">
/// The authValue of the entity the DECRYPT session itself authorizes, folded into the keystream's
/// <c>sessionValue</c> after <see cref="SessionKey"/> — the entity's LIVE value, UNRESOLVED by the session's
/// bind, because "the binding of the session is ignored" for parameter encryption (Part 1, clause 19.1), unlike
/// the command HMAC key which drops it under equation 22's omission (clause 17.6.10). The shared empty carrier
/// when the decrypt session authorizes no entity — a companion — and the parent's own authValue when the
/// parent's authorizing slot is the one that claimed the attribute. A borrowed reference to the carrier the
/// durable state owns; the effect reads its trailing-zero-stripped view at the keystream primitive and never
/// disposes it.
/// </param>
/// <param name="NonceCaller">The decrypt session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94) — the decryption's nonceNewer (Part 1, clause 19.2). A BORROW of the slot's carrier on the request record, which outlives this step and transfers it into that slot's response-session entry afterwards. Meaningless when <see cref="HasDecryptSession"/> is clear.</param>
/// <param name="NonceTpm">The decrypt session's stored nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94) — the decryption's nonceOlder; a borrowed reference to the carrier the durable session record owns. Meaningless when <see cref="HasDecryptSession"/> is clear.</param>
public sealed record TpmDecryptCreateSensitiveAction(
    TpmCreateSealedObjectOverSessionsRequested Request,
    TpmParameterArea RawParameterArea,
    bool HasDecryptSession,
    TpmiAlgHash SessionAlg,
    TpmtSymDef Symmetric,
    SymmetricKeyMemory SessionKey,
    Tpm2bAuth EntityAuthValue,
    Tpm2bNonce NonceCaller,
    Tpm2bNonce NonceTpm): TpmAction;

/// <summary>
/// Declares that the simulator must decrypt <c>TPM2_NV_DefineSpace()</c>'s <c>auth</c> first command parameter
/// before it becomes the new Index's authorization value (TPM 2.0 Library Part 3, clause 31.3; Part 1, clause
/// 19.1) — emitted only when the authorizing session itself carries the <c>decrypt</c> attribute, strictly after
/// its command HMAC has verified (Part 3, clause 5.6 precedes clause 5.8). The decrypt session and the auth
/// session are ONE and the same here, so the keystream's <c>sessionValue = </c><see cref="SessionKey"/><c> ‖
/// </c><see cref="EntityAuthValue"/> folds in the owner hierarchy's authValue, unlike <c>TPM2_Create()</c>'s
/// separate decrypt companion, whose sessionValue is its session key alone; the effect concatenates the two terms
/// in pooled pinned scratch at the primitive.
/// </summary>
/// <remarks>
/// The effect XOR-obfuscates or AES-CFB-decrypts the data portion of the first sized parameter in place (its
/// 2-octet size field is never itself encrypted, Part 1, clause 19.1), reads back the plaintext <c>auth</c>
/// value, and feeds it to <c>OnNvDefineAuthDecrypted</c>, which strips its trailing zeros (Part 1, clause
/// 17.6.4.3) before storing it as the Index authValue and frames the session-authorized response.
/// </remarks>
/// <param name="Request">The parsed session-authorized <c>TPM2_NV_DefineSpace()</c> request, its command HMAC now verified, threaded to the completing transition.</param>
/// <param name="RawParameterArea">The raw <c>auth ‖ publicInfo</c> wire bytes captured at parse time, still carrying the encrypted <c>auth</c> data portion. A BORROW: the request record owns the carrier and every terminal path releases it there, while the in-place transform writes through <see cref="TpmParameterArea.Memory"/> so the octets cpHash digested as ciphertext are the octets the body decodes as plaintext (Part 3, clause 5.6 before clause 5.7).</param>
/// <param name="SessionAlg">The authorizing session's hash algorithm, driving its KDFa keystream.</param>
/// <param name="Symmetric">The session's negotiated symmetric definition, selecting XOR obfuscation or AES-CFB.</param>
/// <param name="SessionKey">The session's session key — a borrowed reference to the carrier the durable session record owns; the effect reads it at the keystream primitive and never disposes it.</param>
/// <param name="EntityAuthValue">
/// The authValue of the entity this session authorizes — the owner hierarchy's — folded into the keystream's
/// <c>sessionValue</c> after <see cref="SessionKey"/>. It is the hierarchy's LIVE value, UNRESOLVED by the
/// session's bind: "the binding of the session is ignored" for parameter encryption (Part 1, clause 19.1), so a
/// session bound to the very entity it authorizes still folds that entity's authValue into the CIPHER key even
/// though its command HMAC key omits it under equation 22 (clause 17.6.10). A borrowed reference to the carrier
/// the durable state owns; the effect reads its trailing-zero-stripped view at the keystream primitive and never
/// disposes it.
/// </param>
/// <param name="NonceCaller">The session's caller nonce for this command (the decryption's nonceNewer, TPM 2.0 Library Part 1, clause 19.2) — a BORROWED reference to the carrier the in-flight request owns, which outlives this effect; the effect reads it at the keystream and never disposes it.</param>
/// <param name="NonceTpm">The session's stored nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94) — the decryption's nonceOlder; a borrowed reference to the carrier the durable session record owns.</param>
public sealed record TpmDecryptNvDefineAuthAction(
    TpmNvDefineSpaceOverSessionRequested Request,
    TpmParameterArea RawParameterArea,
    TpmiAlgHash SessionAlg,
    TpmtSymDef Symmetric,
    SymmetricKeyMemory SessionKey,
    Tpm2bAuth EntityAuthValue,
    Tpm2bNonce NonceCaller,
    Tpm2bNonce NonceTpm): TpmAction;

/// <summary>
/// Declares that the simulator must decrypt <c>TPM2_NV_ChangeAuth()</c>'s <c>newAuth</c> first command parameter
/// before it replaces the Index's authorization value (TPM 2.0 Library Part 3, clause 31.15; Part 1, clause
/// 19.1) — emitted only when a SEPARATE session in the authorization area carries the <c>decrypt</c> attribute,
/// strictly after every session in that area has had its command HMAC verified (Part 3, clause 5.6 precedes
/// clause 5.8).
/// </summary>
/// <remarks>
/// Unlike <see cref="TpmDecryptNvDefineAuthAction"/>, whose decrypt session and auth session are one and whose
/// <c>sessionValue</c> therefore folds in the authorized entity's authValue, this action's decrypt session
/// authorizes no entity, so <see cref="EntityAuthValue"/> is the shared empty carrier and
/// <see cref="SessionKey"/> is its whole <c>sessionValue</c> (Part 1, clause 19.1: "If the session is not being
/// used for authorization, sessionValue is sessionKey"). That separation is the point: a single session doing
/// both jobs would key the parameter encryption on the very authValue being rotated away from. The effect
/// XOR-obfuscates or AES-CFB-decrypts the data portion of the first sized parameter in place (its 2-octet size
/// field is never itself encrypted, Part 1, clause 19.1), reads back the plaintext, and feeds it to the
/// completing transition, which strips trailing zeros, applies the digest-size check, and stores it.
/// </remarks>
/// <param name="Request">The parsed request, its sessions now verified, threaded to the completing transition.</param>
/// <param name="RawParameterArea">The raw <c>newAuth</c> wire bytes captured at parse time, still carrying the encrypted data portion. A BORROW: the request record owns the carrier and every terminal path releases it there, while the in-place transform writes through <see cref="TpmParameterArea.Memory"/> so the octets cpHash digested as ciphertext are the octets the body decodes as plaintext (Part 3, clause 5.6 before clause 5.7).</param>
/// <param name="SessionAlg">The decrypt session's hash algorithm, driving its KDFa keystream.</param>
/// <param name="Symmetric">The decrypt session's negotiated symmetric definition, selecting XOR obfuscation or AES-CFB.</param>
/// <param name="SessionKey">The decrypt session's session key (its whole <c>sessionValue</c>, since it authorizes no entity) — a borrowed reference to the carrier the durable session record owns; the effect reads it at the keystream primitive and never disposes it.</param>
/// <param name="EntityAuthValue">
/// The authValue of the entity the DECRYPT session itself authorizes, folded into the keystream's
/// <c>sessionValue</c> after <see cref="SessionKey"/> — the entity's LIVE value, UNRESOLVED by the session's
/// bind (Part 1, clause 19.1: "the binding of the session is ignored"). The shared empty carrier when the
/// decrypt session authorizes no entity, which on this command it never does. A borrowed reference to the
/// carrier the durable state owns; the effect never disposes it.
/// </param>
/// <param name="NonceCaller">The decrypt session's caller nonce for this command (the decryption's nonceNewer, TPM 2.0 Library Part 1, clause 19.2) — a BORROWED reference to the carrier the in-flight request owns, which outlives this effect; the effect reads it at the keystream and never disposes it.</param>
/// <param name="NonceTpm">The decrypt session's stored nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94) — the decryption's nonceOlder; a borrowed reference to the carrier the durable session record owns, which the effect reads at the keystream primitive and never disposes.</param>
public sealed record TpmDecryptNvChangeAuthAction(
    TpmNvChangeAuthOverSessionRequested Request,
    TpmParameterArea RawParameterArea,
    TpmiAlgHash SessionAlg,
    TpmtSymDef Symmetric,
    SymmetricKeyMemory SessionKey,
    Tpm2bAuth EntityAuthValue,
    Tpm2bNonce NonceCaller,
    Tpm2bNonce NonceTpm): TpmAction;

/// <summary>
/// Declares that the simulator must roll each authorization-area session's nonceTPM and frame that session's
/// response entry for an authValue rotation — <c>TPM2_NV_ChangeAuth()</c> or <c>TPM2_HierarchyChangeAuth()</c>,
/// named by <see cref="CommandCode"/> — before the next transition (TPM 2.0 Library Part 1, clause 16.6.1).
/// Emitted once the rotation has been committed to its entity; the effectful loop computes rpHash over the empty
/// response parameter area, draws a fresh nonceTPM per session, and computes each session's own response HMAC
/// keyed on its own <c>sessionKey ‖ authValue</c>, feeding the result back as a
/// <see cref="TpmNvChangeAuthResponseFramed"/> input.
/// </summary>
/// <remarks>
/// This is the two-session framing counterpart of the single-entry
/// <see cref="TpmFrameNvSessionResponseAction"/>, shared with the other authValue rotation of the same shape,
/// <c>TPM2_HierarchyChangeAuth()</c> (Part 3, clause 24.8): both admit a second (decrypt) session protecting
/// <c>newAuth</c>, and a response owes one entry per command session
/// (Part 1, clause 17.6). It carries no parameter area because the response has no parameters at all (Part 3,
/// clause 31.15, Table 253). The authorizing session's <c>AuthValue</c> entry is already the POST-rotation value
/// where the policy required one (clause 31.15.1: "Since the NV Index authorization is changed before the
/// response HMAC is calculated, the newAuth value is used when generating the response HMAC key if required"),
/// resolved by the declaring transition rather than here.
/// </remarks>
/// <param name="CommandCode">
/// The command whose response is being framed, folded into rpHash as equation 16's <c>commandCode</c> term
/// (Part 1, clause 16.8). Because this action serves BOTH authValue rotations, the code must be carried rather
/// than assumed: a response framed under one command's code cannot verify against a host that computed rpHash
/// under the other's.
/// </param>
/// <param name="ResponseSessions">Every session in the command's authorization area, in command-session order, each with the key material its own response entry needs.</param>
public sealed record TpmFrameNvChangeAuthResponseAction(
    TpmCcConstants CommandCode,
    ImmutableArray<TpmNvChangeAuthResponseSession> ResponseSessions): TpmAction;

/// <summary>
/// Declares that the simulator must frame the <c>TPM2_Create()</c> response over sessions before the next
/// transition — the request-decrypt counterpart of <see cref="TpmUnsealDataAction"/>. Emitted once
/// <c>inSensitive</c> has been decrypted (if applicable) and decoded; the effectful loop builds the sealed
/// object's wrapped private blob, exported public area, and creation by-products exactly as
/// <see cref="TpmSealDataAction"/> does, then rolls a fresh nonceTPM per real session, computes rpHash over the
/// (unencrypted — response encryption is out of scope for <c>TPM2_Create()</c>) response parameter
/// area, and each real session's own response HMAC keyed on its own <c>sessionKey ‖ authValue</c> (Part 1,
/// clause 17.6.8).
/// </summary>
/// <param name="ParentHandle">The storage parent the object is sealed under (its handle binds the creation data).</param>
/// <param name="ParentHierarchy">
/// The hierarchy the storage parent belongs to, which is the hierarchy the created object belongs to and so the
/// one the creation ticket names and whose proof keys its HMAC (<c>TPMI_RH_HIERARCHY+</c>, TPM 2.0 Library
/// Part 2, clause 10.7.3, Table 109: "the hierarchy containing name"; Part 4's <c>TPM2_Create()</c> computes
/// the ticket over <c>EntityGetHierarchy(parentHandle)</c>). Distinct from <see cref="ParentHandle"/>, which
/// binds the creation DATA.
/// </param>
/// <param name="NameAlg">The Name algorithm to carry in the exported public area.</param>
/// <param name="AuthPolicy">The authorization policy digest to re-emit into the exported public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92; empty for an authValue-only seal), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner and releases it in its <c>finally</c> — <c>TPM2_Create()</c> installs no durable object, so the copy the exported public area takes is the digest's only use.</param>
/// <param name="NoDa">Whether the template set <c>TPMA_OBJECT.noDA</c>, so the exported public area reproduces the caller's template.</param>
/// <param name="UserWithAuth">Whether the template set <c>TPMA_OBJECT.userWithAuth</c>, so the exported public area reproduces the caller's template.</param>
/// <param name="SecretData">The data to seal (<c>TPMS_SENSITIVE_CREATE.data</c>, a <c>TPM2B_SENSITIVE_DATA</c> — TPM 2.0 Library Part 2, clause 11.1.14, Table 167), the owned <see cref="Tpm2bSensitiveData"/> carrier the decrypt step rented; ownership rides this action into the effect, which packs it into the wrapped private blob and releases it.</param>
/// <param name="UserAuth">The new object's authorization value (<c>TPMS_SENSITIVE_CREATE.userAuth</c>, a <c>TPM2B_AUTH</c>), the owned <see cref="Tpm2bAuth"/> carrier the decrypt step rented; ownership rides this action into the effect, which packs it into the wrapped private blob alongside <see cref="SecretData"/> and releases it (TPM 2.0 Library Part 1, clause 17.6.4).</param>
/// <param name="HasPasswordPlaceholder">Whether session index 0 is a <c>TPM_RS_PW</c> session needing the empty-nonce, empty-HMAC password placeholder entry (Part 1, clause 17.6.4).</param>
/// <param name="PasswordPlaceholderAttributes">The password session's command session-attributes octet, framed into its placeholder entry. Meaningful only when <see cref="HasPasswordPlaceholder"/> is set.</param>
/// <param name="ResponseSessions">Every real (HMAC-table) session needing a framed response entry, in command-session order (after the password placeholder, when present).</param>
public sealed record TpmSealDataOverSessionsAction(
    TpmiDhObject ParentHandle,
    TpmiRhHierarchy ParentHierarchy,
    TpmiAlgHash NameAlg,
    Tpm2bDigest AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    Tpm2bSensitiveData SecretData,
    Tpm2bAuth UserAuth,
    bool HasPasswordPlaceholder,
    TpmaSession PasswordPlaceholderAttributes,
    ImmutableArray<TpmCreateResponseSession> ResponseSessions): TpmAction;

/// <summary>
/// Declares that the simulator must decrypt <c>TPM2_HierarchyChangeAuth()</c>'s <c>newAuth</c> first command
/// parameter before the next transition (TPM 2.0 Library Part 3, clause 24.8; Part 1, clause 19.1) — the
/// hierarchy-family counterpart of <see cref="TpmDecryptNvChangeAuthAction"/>, emitted only when a SEPARATE
/// session in the authorization area carried the <c>decrypt</c> attribute and strictly after every session in
/// that area has had its command HMAC verified.
/// </summary>
/// <remarks>
/// The effect XOR-obfuscates or AES-CFB-decrypts the data portion of the sole sized parameter in place (its
/// 2-octet size field is never itself encrypted, Part 1, clause 19.1), reads back the plaintext, and feeds it to
/// the completing transition, which strips trailing zeros, applies the context-integrity digest-size check, and
/// installs it. The keystream is derived from the decrypt session's own session key alone, because that session
/// authorizes no entity — never from the authorizing session's material, whose <c>sessionValue</c> folds in the
/// very authValue being rotated away from.
/// </remarks>
/// <param name="Request">The parsed request, its sessions now verified, threaded to the completing transition.</param>
/// <param name="RawParameterArea">The raw <c>newAuth</c> wire bytes captured at parse time, still carrying the encrypted data portion. A BORROW: the request record owns the carrier and every terminal path releases it there, while the in-place transform writes through <see cref="TpmParameterArea.Memory"/> so the octets cpHash digested as ciphertext are the octets the body decodes as plaintext (Part 3, clause 5.6 before clause 5.7).</param>
/// <param name="SessionAlg">The decrypt session's hash algorithm, driving its KDFa keystream.</param>
/// <param name="Symmetric">The decrypt session's negotiated symmetric definition, selecting XOR obfuscation or AES-CFB.</param>
/// <param name="SessionKey">The decrypt session's session key (its whole <c>sessionValue</c>, since it authorizes no entity) — a borrowed reference to the carrier the durable session record owns; the effect reads it at the keystream primitive and never disposes it.</param>
/// <param name="EntityAuthValue">
/// The authValue of the entity the DECRYPT session itself authorizes, folded into the keystream's
/// <c>sessionValue</c> after <see cref="SessionKey"/> — the entity's LIVE value, UNRESOLVED by the session's
/// bind (Part 1, clause 19.1: "the binding of the session is ignored"). The shared empty carrier when the
/// decrypt session authorizes no entity, which on this command it never does, since the authorizing session is
/// refused the <c>decrypt</c> attribute outright. A borrowed reference to the carrier the durable state owns;
/// the effect never disposes it.
/// </param>
/// <param name="NonceCaller">The decrypt session's caller nonce for this command (the decryption's nonceNewer, TPM 2.0 Library Part 1, clause 19.2) — a BORROWED reference to the carrier the in-flight request owns, which outlives this effect; the effect reads it at the keystream and never disposes it.</param>
/// <param name="NonceTpm">The decrypt session's stored nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94) — the decryption's nonceOlder; a borrowed reference to the carrier the durable session record owns, which the effect reads at the keystream primitive and never disposes.</param>
public sealed record TpmDecryptHierarchyChangeAuthAction(
    TpmHierarchyChangeAuthOverSessionRequested Request,
    TpmParameterArea RawParameterArea,
    TpmiAlgHash SessionAlg,
    TpmtSymDef Symmetric,
    SymmetricKeyMemory SessionKey,
    Tpm2bAuth EntityAuthValue,
    Tpm2bNonce NonceCaller,
    Tpm2bNonce NonceTpm): TpmAction;

/// <summary>
/// Declares that the simulator must recover an attest command's <c>qualifyingData</c> first parameter in
/// plaintext before the next transition — <c>TPM2_Certify()</c>, <c>TPM2_CertifyCreation()</c>,
/// <c>TPM2_Quote()</c>, <c>TPM2_GetTime()</c>, or <c>TPM2_NV_Certify()</c>, named by <see cref="CommandCode"/>,
/// since the five differ in nothing this step does. Declared ALWAYS on the session-authorized arm and emitted
/// only once every session in the authorization area has had its command HMAC verified, because cpHash covers
/// the CIPHERTEXT: "Parameters in commands are encrypted before any cpHash is computed" (TPM 2.0 Library Part 1,
/// clause 19.1), so Part 3's ladder runs clause 5.6's authorization, then clause 5.7's decryption, then clause
/// 5.8's unmarshaling.
/// </summary>
/// <remarks>
/// <para>
/// With <see cref="Decrypts"/> clear the step is a pass-through that only reads the value back: the parameter
/// crossed in the clear, and the same one code path still owns the width check and the carrier rental, so the
/// two shapes cannot drift. With it set, the effect transforms the data portion of the first sized parameter in
/// place — the 2-octet size field is never protected (clause 19.1) — with the command-direction nonce ordering
/// (nonceNewer is <see cref="NonceCaller"/>, nonceOlder is <see cref="NonceTpm"/>, clauses 19.2 and 19.3).
/// </para>
/// <para>
/// The wire parser deliberately leaves <c>qualifyingData</c> undecoded on this arm and captures only
/// <see cref="RawParameterArea"/>, because a separately copied field would not be updated by an in-place
/// transform of that area; the recovered value must be read back out of the decrypted buffer, which is what this
/// effect does.
/// </para>
/// </remarks>
/// <param name="CommandCode">The attest command being resumed, threaded through so the feedback names it.</param>
/// <param name="Request">The parsed session-authorized request, threaded through to the resuming transition, which adopts the recovered carrier into it.</param>
/// <param name="RawParameterArea">The raw parameter-area bytes captured at parse time, still carrying the encrypted <c>qualifyingData</c> data portion when <see cref="Decrypts"/> is set; the transform is in place over this buffer. A BORROW: the request record owns the carrier and every terminal path releases it there, while the in-place transform writes through <see cref="TpmParameterArea.Memory"/> so the octets cpHash digested as ciphertext are the octets the body decodes as plaintext (Part 3, clause 5.6 before clause 5.7).</param>
/// <param name="Decrypts">Whether a slot in the authorization area carried the <c>decrypt</c> attribute; when clear, every keying field below is its inert placeholder and no transform runs.</param>
/// <param name="DecryptSessionIndex">The zero-based slot index of the session carrying <c>decrypt</c>, which a failure is session-index-encoded to (Part 2, clause 6.6.2), or <c>-1</c> when no slot claimed it.</param>
/// <param name="SessionAlg">The decrypt session's hash algorithm, driving its KDFa. Meaningless when <see cref="Decrypts"/> is clear.</param>
/// <param name="Symmetric">The decrypt session's negotiated symmetric definition, selecting XOR obfuscation or AES-CFB. <see cref="TpmtSymDef.Null"/> when <see cref="Decrypts"/> is clear.</param>
/// <param name="SessionKey">The decrypt session's session key — a borrowed reference to the carrier the durable session record owns; the effect reads it at the keystream primitive and never disposes it. The shared <see cref="TpmSimulatorState.EmptySessionKey"/> when <see cref="Decrypts"/> is clear.</param>
/// <param name="EntityAuthValue">
/// The authValue of the entity the DECRYPT session itself authorizes, folded into the keystream's
/// <c>sessionValue</c> after <see cref="SessionKey"/> — the entity's LIVE value, UNRESOLVED by the session's
/// bind, because "the binding of the session is ignored" for parameter encryption (Part 1, clause 19.1), unlike
/// the command HMAC key which drops it under equation 22's omission (clause 17.6.10). The shared empty carrier
/// when the decrypt attribute rides a companion authorizing no entity, whose <c>sessionValue</c> is its session
/// key alone. A borrowed reference to the carrier the durable state owns; the effect reads its
/// trailing-zero-stripped view at the keystream primitive and never disposes it.
/// </param>
/// <param name="NonceCaller">The decrypt session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94) — the decryption's nonceNewer (Part 1, clause 19.2). A BORROW of the slot's carrier on the request record, which outlives this step and transfers it into that slot's response-session entry afterwards. The shared empty carrier when <see cref="Decrypts"/> is clear.</param>
/// <param name="NonceTpm">The decrypt session's stored nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94) — the decryption's nonceOlder; a borrowed reference to the carrier the durable session record owns. The shared empty carrier when <see cref="Decrypts"/> is clear.</param>
public sealed record TpmDecryptAttestQualifyingDataAction(
    TpmCcConstants CommandCode,
    TpmSimulatorInput Request,
    TpmParameterArea RawParameterArea,
    bool Decrypts,
    int DecryptSessionIndex,
    TpmiAlgHash SessionAlg,
    TpmtSymDef Symmetric,
    SymmetricKeyMemory SessionKey,
    Tpm2bAuth EntityAuthValue,
    Tpm2bNonce NonceCaller,
    Tpm2bNonce NonceTpm): TpmAction;

/// <summary>
/// Declares that the simulator must draw a fresh storage primary seed from the injected random-number backend
/// before the next transition — the one effect <c>TPM2_Clear()</c> needs, since a pure transition may not touch
/// randomness (TPM 2.0 Library Part 3, clause 24.6.1: "change the storage primary seed (SPS) to a new value from
/// the TPM's random number generator"). Emitted only after the clear has been authorized and the
/// <c>TPMA_PERMANENT.disableClear</c> gate has passed, so a refused clear never perturbs the random stream; the
/// effectful loop feeds the drawn seed back as a <see cref="TpmStorageProofSeedGenerated"/> input, and the
/// resuming transition applies every one of the clause's effects in one step.
/// </summary>
/// <remarks>
/// Rotating this seed is the whole mechanism by which outstanding owner and endorsement tickets and saved
/// contexts stop verifying (Part 1, clause 12.5): they are HMACs keyed by a proof derived from it, so a new seed
/// invalidates them structurally, with no revocation pass over any list. The platform hierarchy's proof derives
/// from a separate, construction-fixed seed and survives.
/// </remarks>
/// <param name="SeedSize">The number of octets to draw, the proof width of this simulated TPM (<see cref="TpmSimulatorState.ContextIntegrityDigestSize"/>).</param>
/// <param name="Resume">The parsed <c>TPM2_Clear()</c> request to resume, deciding whether the response is header-only or session-framed.</param>
public sealed record TpmGenerateStorageProofSeedAction(
    int SeedSize,
    TpmSimulatorInput Resume): TpmAction;

/// <summary>
/// Declares that the simulator must deep-copy a transient object into its persistent instance for
/// <c>TPM2_EvictControl()</c>'s persist arm before the next transition (TPM 2.0 Library Part 3, clause 28.5).
/// The copy is an effect because it rents a pinned carrier for the persistent instance's own private key: a
/// persisted object is a genuine second instance whose buffers no other dictionary entry co-owns, so evicting
/// either the transient original or the persistent copy can never free memory the other still uses. The
/// effectful loop feeds the copy back as a <see cref="TpmObjectPersisted"/> input and <c>OnObjectPersisted</c>
/// installs it.
/// </summary>
/// <param name="Transient">The resolved transient object to persist — a borrowed reference to the record the live automaton state owns; the effect reads its private key at the copy primitive and never disposes it.</param>
/// <param name="PersistentHandle">The persistent handle the copy is installed under.</param>
public sealed record TpmPersistObjectAction(
    TransientKeyState Transient,
    TpmiDhPersistent PersistentHandle): TpmAction;
