using System;
using System.Collections.Immutable;
using Verifiable.Foundation.Automata;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

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
/// <param name="AuthPolicy">The authorization policy digest to re-emit into the exported public area (empty for an authValue-only key).</param>
public sealed record TpmCreateEccKeyAction(
    uint Handle,
    uint Hierarchy,
    TpmAlgIdConstants NameAlg,
    TpmaObject Attributes,
    TpmEccCurveConstants Curve,
    TpmAlgIdConstants SchemeHashAlg,
    ReadOnlyMemory<byte> AuthPolicy): TpmAction;

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
/// <param name="AuthPolicy">The authorization policy digest to re-emit into the exported public area (empty for an authValue-only key).</param>
public sealed record TpmCreateRsaKeyAction(
    uint Handle,
    uint Hierarchy,
    TpmAlgIdConstants NameAlg,
    TpmaObject Attributes,
    ushort KeyBits,
    TpmtRsaScheme Scheme,
    ReadOnlyMemory<byte> AuthPolicy): TpmAction;

/// <summary>
/// Declares that the simulator must sign a digest with a retained key before the next transition. Emitted
/// by the <c>TPM2_Sign()</c> transition; the effectful loop signs the digest through the injected
/// <see cref="TpmEccSigningBackend"/> and feeds the signature back as a <see cref="TpmMessageSigned"/>
/// input (TPM 2.0 Library Part 3, clause 20.2).
/// </summary>
/// <param name="Scalar">The signing key's retained private scalar, unsigned big-endian.</param>
/// <param name="Digest">The pre-computed digest to sign directly.</param>
/// <param name="Curve">The ECC curve the scalar lives on.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, reported inside the signature.</param>
public sealed record TpmEccSignAction(
    ReadOnlyMemory<byte> Scalar,
    ReadOnlyMemory<byte> Digest,
    TpmEccCurveConstants Curve,
    TpmAlgIdConstants HashAlg): TpmAction;

/// <summary>
/// Declares that the simulator must sign a digest with a retained RSA key before the next transition — the RSA
/// counterpart of <see cref="TpmEccSignAction"/>. Emitted by the <c>TPM2_Sign()</c> transition for an RSA key;
/// the effectful loop signs the digest through the injected <see cref="TpmRsaSigningBackend"/> and feeds the
/// signature back as a <see cref="TpmMessageSigned"/> input (TPM 2.0 Library Part 3, clause 20.2).
/// </summary>
/// <param name="PrivateKey">The signing key's retained private key, in the backend's encoding.</param>
/// <param name="Digest">The pre-computed digest to sign directly.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to apply.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, reported inside the signature.</param>
public sealed record TpmRsaSignAction(
    ReadOnlyMemory<byte> PrivateKey,
    ReadOnlyMemory<byte> Digest,
    TpmAlgIdConstants Scheme,
    TpmAlgIdConstants HashAlg): TpmAction;

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
/// The authorization policy digest to re-emit into the exported public area (empty for the generic storage
/// parent; a standard endorsement key's "PolicyA" otherwise).
/// </param>
public sealed record TpmCreateStorageParentAction(
    uint Handle,
    uint Hierarchy,
    TpmAlgIdConstants NameAlg,
    TpmaObject Attributes,
    TpmEccCurveConstants Curve,
    bool NoDa,
    ReadOnlyMemory<byte> AuthPolicy): TpmAction;

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
/// The authorization policy digest to re-emit into the exported public area (empty for a generic RSA storage
/// parent; a standard RSA endorsement key's "PolicyA" otherwise).
/// </param>
public sealed record TpmCreateRsaStorageParentAction(
    uint Handle,
    uint Hierarchy,
    TpmAlgIdConstants NameAlg,
    TpmaObject Attributes,
    ushort KeyBits,
    bool NoDa,
    ReadOnlyMemory<byte> AuthPolicy): TpmAction;

/// <summary>
/// Declares that the simulator must seal caller-supplied data into a KEYEDHASH object before the next transition.
/// Emitted by the <c>TPM2_Create()</c> transition; the effectful loop builds the wrapped private blob, the
/// exported public area, and the creation by-products through the registered digest and HMAC seams, and feeds
/// them back as a <see cref="TpmObjectSealed"/> input (TPM 2.0 Library Part 3, clause 12.1).
/// </summary>
/// <param name="ParentHandle">The storage parent the object is sealed under (its handle binds the creation by-products).</param>
/// <param name="NameAlg">The Name algorithm to carry in the exported public area.</param>
/// <param name="AuthPolicy">The authorization policy digest to re-emit into the exported public area (empty for an authValue-only seal).</param>
/// <param name="NoDa">Whether the template set <c>TPMA_OBJECT.noDA</c>, so the exported public area reproduces the caller's template.</param>
/// <param name="UserWithAuth">Whether the template set <c>TPMA_OBJECT.userWithAuth</c>, so the exported public area reproduces the caller's template.</param>
/// <param name="SecretData">The data to seal, carried into the wrapped private blob.</param>
/// <param name="UserAuth">The new object's authorization value, carried into the wrapped private blob alongside <see cref="SecretData"/> (TPM 2.0 Library Part 1, clause 19.6.4).</param>
public sealed record TpmSealDataAction(
    uint ParentHandle,
    TpmAlgIdConstants NameAlg,
    ReadOnlyMemory<byte> AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    ReadOnlyMemory<byte> SecretData,
    ReadOnlyMemory<byte> UserAuth): TpmAction;

/// <summary>
/// Declares that the simulator must compute a loaded object's Name before the next transition. Emitted by the
/// <c>TPM2_Load()</c> transition; the effectful loop computes <c>nameAlg ‖ H(TPMT_PUBLIC)</c> through the
/// registered digest seam and feeds it back with the recovered sealed data as a <see cref="TpmObjectLoaded"/>
/// input (TPM 2.0 Library Part 3, clause 12.2; Part 1, clause 16).
/// </summary>
/// <param name="Handle">The transient handle the transition allocated for the loaded object.</param>
/// <param name="NameAlg">The Name algorithm to compute the object Name with.</param>
/// <param name="AuthPolicy">The authorization policy digest carried in the loaded public area (empty for an authValue-only object), threaded through to the loaded object's state.</param>
/// <param name="NoDa">Whether the loaded public area sets <c>TPMA_OBJECT.noDA</c>, threaded through to the loaded object's state.</param>
/// <param name="UserWithAuth">Whether the loaded public area sets <c>TPMA_OBJECT.userWithAuth</c>, threaded through to the loaded object's state.</param>
/// <param name="PublicAreaBytes">The marshaled <c>TPMT_PUBLIC</c> the Name is hashed over.</param>
/// <param name="PrivateBlob">The wrapped private blob to recover the authorization value and the sealed data from.</param>
public sealed record TpmLoadObjectAction(
    uint Handle,
    TpmAlgIdConstants NameAlg,
    ReadOnlyMemory<byte> AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    ReadOnlyMemory<byte> PublicAreaBytes,
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
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c> this slice), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the attestation's <c>clockInfo</c>.</param>
public sealed record TpmCertifyAction(
    ReadOnlyMemory<byte> SubjectName,
    uint SubjectHierarchy,
    ReadOnlyMemory<byte> SignerName,
    uint SignerHierarchy,
    ReadOnlyMemory<byte> QualifyingData,
    ReadOnlyMemory<byte> SignerPrivateKey,
    TpmEccCurveConstants SignerCurve,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants HashAlg,
    TpmsClockInfo ClockSnapshot): TpmAction;

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
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained private key, in the backend's own encoding.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to apply.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the attestation's <c>clockInfo</c>.</param>
public sealed record TpmRsaCertifyAction(
    ReadOnlyMemory<byte> SubjectName,
    uint SubjectHierarchy,
    ReadOnlyMemory<byte> SignerName,
    uint SignerHierarchy,
    ReadOnlyMemory<byte> QualifyingData,
    ReadOnlyMemory<byte> SignerPrivateKey,
    TpmAlgIdConstants Scheme,
    TpmAlgIdConstants HashAlg,
    TpmsClockInfo ClockSnapshot): TpmAction;

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
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c> this slice), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="PcrSelection">The caller's <c>TPML_PCR_SELECTION</c> wire bytes, echoed verbatim into the attested <c>TPMS_QUOTE_INFO.pcrSelect</c>.</param>
/// <param name="PcrValues">The selected register values in ascending PCR-index order, concatenated and hashed into the attested <c>pcrDigest</c>.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the attestation's <c>clockInfo</c>.</param>
public sealed record TpmQuoteAction(
    ReadOnlyMemory<byte> SignerName,
    uint SignerHierarchy,
    ReadOnlyMemory<byte> QualifyingData,
    ReadOnlyMemory<byte> SignerPrivateKey,
    TpmEccCurveConstants SignerCurve,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants HashAlg,
    ReadOnlyMemory<byte> PcrSelection,
    ImmutableArray<ReadOnlyMemory<byte>> PcrValues,
    TpmsClockInfo ClockSnapshot): TpmAction;

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
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained private key, in the backend's own encoding.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to apply.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="PcrSelection">The caller's <c>TPML_PCR_SELECTION</c> wire bytes, echoed verbatim into the attested <c>TPMS_QUOTE_INFO.pcrSelect</c>.</param>
/// <param name="PcrValues">The selected register values in ascending PCR-index order, concatenated and hashed into the attested <c>pcrDigest</c>.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the attestation's <c>clockInfo</c>.</param>
public sealed record TpmRsaQuoteAction(
    ReadOnlyMemory<byte> SignerName,
    uint SignerHierarchy,
    ReadOnlyMemory<byte> QualifyingData,
    ReadOnlyMemory<byte> SignerPrivateKey,
    TpmAlgIdConstants Scheme,
    TpmAlgIdConstants HashAlg,
    ReadOnlyMemory<byte> PcrSelection,
    ImmutableArray<ReadOnlyMemory<byte>> PcrValues,
    TpmsClockInfo ClockSnapshot): TpmAction;

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
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c>.</param>
/// <param name="CreationHash">The caller-supplied creation hash, attested in <c>TPMS_CREATION_INFO.creationHash</c> and folded into the recomputed creation-ticket digest.</param>
/// <param name="TicketDigest">The digest carried by the caller-supplied creation ticket, compared constant-time against the recomputed one.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c> this slice), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the attestation's <c>clockInfo</c>.</param>
public sealed record TpmCertifyCreationAction(
    ReadOnlyMemory<byte> SubjectName,
    uint SubjectHierarchy,
    ReadOnlyMemory<byte> SignerName,
    uint SignerHierarchy,
    ReadOnlyMemory<byte> QualifyingData,
    ReadOnlyMemory<byte> CreationHash,
    ReadOnlyMemory<byte> TicketDigest,
    ReadOnlyMemory<byte> SignerPrivateKey,
    TpmEccCurveConstants SignerCurve,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants HashAlg,
    TpmsClockInfo ClockSnapshot): TpmAction;

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
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c>.</param>
/// <param name="CreationHash">The caller-supplied creation hash, attested in <c>TPMS_CREATION_INFO.creationHash</c> and folded into the recomputed creation-ticket digest.</param>
/// <param name="TicketDigest">The digest carried by the caller-supplied creation ticket, compared constant-time against the recomputed one.</param>
/// <param name="SignerPrivateKey">The signing key's retained private key, in the backend's own encoding.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to apply.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the attestation's <c>clockInfo</c>.</param>
public sealed record TpmRsaCertifyCreationAction(
    ReadOnlyMemory<byte> SubjectName,
    uint SubjectHierarchy,
    ReadOnlyMemory<byte> SignerName,
    uint SignerHierarchy,
    ReadOnlyMemory<byte> QualifyingData,
    ReadOnlyMemory<byte> CreationHash,
    ReadOnlyMemory<byte> TicketDigest,
    ReadOnlyMemory<byte> SignerPrivateKey,
    TpmAlgIdConstants Scheme,
    TpmAlgIdConstants HashAlg,
    TpmsClockInfo ClockSnapshot): TpmAction;

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
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c> this slice), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="Time">The time in milliseconds since the last startup, folded from state after the per-command advance, framed as the attested <c>TPMS_TIME_ATTEST_INFO.time</c>.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed both as the envelope's <c>clockInfo</c> and inside the attested <c>TPMS_TIME_ATTEST_INFO</c> (TPM 2.0 Library Part 1, clause 36.7 — the two copies agree).</param>
public sealed record TpmGetTimeAction(
    ReadOnlyMemory<byte> SignerName,
    uint SignerHierarchy,
    ReadOnlyMemory<byte> QualifyingData,
    ReadOnlyMemory<byte> SignerPrivateKey,
    TpmEccCurveConstants SignerCurve,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants HashAlg,
    ulong Time,
    TpmsClockInfo ClockSnapshot): TpmAction;

/// <summary>
/// Declares that the simulator must attest the current time before the next transition, signed with an RSA
/// key — the RSA counterpart of <see cref="TpmGetTimeAction"/>. Emitted by the <c>TPM2_GetTime()</c>
/// transition when the signing key is RSA; the effect builds the same real-time attestation and signs
/// <c>H_hashAlg(attest)</c> with the signing key's retained private key through the injected
/// <see cref="TpmRsaSigningBackend"/> under the requested RSA scheme (TPM 2.0 Library Part 3, clause 18.7).
/// </summary>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained private key, in the backend's own encoding.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to apply.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="Time">The time in milliseconds since the last startup, folded from state after the per-command advance, framed as the attested <c>TPMS_TIME_ATTEST_INFO.time</c>.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed both as the envelope's <c>clockInfo</c> and inside the attested <c>TPMS_TIME_ATTEST_INFO</c> (TPM 2.0 Library Part 1, clause 36.7 — the two copies agree).</param>
public sealed record TpmRsaGetTimeAction(
    ReadOnlyMemory<byte> SignerName,
    uint SignerHierarchy,
    ReadOnlyMemory<byte> QualifyingData,
    ReadOnlyMemory<byte> SignerPrivateKey,
    TpmAlgIdConstants Scheme,
    TpmAlgIdConstants HashAlg,
    ulong Time,
    TpmsClockInfo ClockSnapshot): TpmAction;

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
/// The transition resolves the signing-key and NV-Index handles, performs the Index-authorization and
/// written/range checks, and slices the requested window from the Index's retained data area, folding all of it
/// into this action, so the effect needs no automaton state and captures nothing. This slice models an
/// elliptic-curve signing key (ECDSA), as the signing paths do.
/// </remarks>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c> this slice), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="NvIndex">The NV Index handle, folded into the marshaled <c>TPMS_NV_PUBLIC</c> the Index's Name is computed from.</param>
/// <param name="NvIndexAttributes">The Index's current attributes (<c>TPMA_NV</c>), folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="NvIndexDataSize">The Index's declared data size, folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="NvContents">The requested window of the Index's retained data, attested verbatim in <c>TPMS_NV_CERTIFY_INFO.nvContents</c>.</param>
/// <param name="Offset">The octet offset of <paramref name="NvContents"/> within the Index's data area, attested in <c>TPMS_NV_CERTIFY_INFO.offset</c>.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the attestation's <c>clockInfo</c>.</param>
public sealed record TpmNvCertifyAction(
    ReadOnlyMemory<byte> SignerName,
    uint SignerHierarchy,
    ReadOnlyMemory<byte> QualifyingData,
    ReadOnlyMemory<byte> SignerPrivateKey,
    TpmEccCurveConstants SignerCurve,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants HashAlg,
    uint NvIndex,
    TpmaNv NvIndexAttributes,
    ushort NvIndexDataSize,
    ReadOnlyMemory<byte> NvContents,
    ushort Offset,
    TpmsClockInfo ClockSnapshot): TpmAction;

/// <summary>
/// Declares that the simulator must attest an NV Index's contents before the next transition, signed with an RSA
/// key — the RSA counterpart of <see cref="TpmNvCertifyAction"/>. Emitted by the <c>TPM2_NV_Certify()</c>
/// transition when the signing key is RSA; the effect performs the same Index-Name computation and attestation
/// marshaling, and signs <c>H_hashAlg(attest)</c> with the signing key's retained private key through the
/// injected <see cref="TpmRsaSigningBackend"/> under the requested RSA scheme (TPM 2.0 Library Part 3, clause
/// 31.16; Part 2, clause 10.12.8).
/// </summary>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained private key, in the backend's own encoding.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to apply.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="NvIndex">The NV Index handle, folded into the marshaled <c>TPMS_NV_PUBLIC</c> the Index's Name is computed from.</param>
/// <param name="NvIndexAttributes">The Index's current attributes (<c>TPMA_NV</c>), folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="NvIndexDataSize">The Index's declared data size, folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="NvContents">The requested window of the Index's retained data, attested verbatim in <c>TPMS_NV_CERTIFY_INFO.nvContents</c>.</param>
/// <param name="Offset">The octet offset of <paramref name="NvContents"/> within the Index's data area, attested in <c>TPMS_NV_CERTIFY_INFO.offset</c>.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the attestation's <c>clockInfo</c>.</param>
public sealed record TpmRsaNvCertifyAction(
    ReadOnlyMemory<byte> SignerName,
    uint SignerHierarchy,
    ReadOnlyMemory<byte> QualifyingData,
    ReadOnlyMemory<byte> SignerPrivateKey,
    TpmAlgIdConstants Scheme,
    TpmAlgIdConstants HashAlg,
    uint NvIndex,
    TpmaNv NvIndexAttributes,
    ushort NvIndexDataSize,
    ReadOnlyMemory<byte> NvContents,
    ushort Offset,
    TpmsClockInfo ClockSnapshot): TpmAction;

/// <summary>
/// Declares that the simulator must establish a bound and/or salted HMAC session before the next transition.
/// Emitted by the <c>TPM2_StartAuthSession()</c> transition for an HMAC session whose <c>tpmKey</c> is
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
/// <param name="NonceCaller">The caller nonce sent at start — the second context field of the session-key KDFa.</param>
/// <param name="BindAuthValue">The bind entity's resolved authorization value (empty for an unbound session) — the KDFa key's leading term (Part 1, clause 17.6.10).</param>
/// <param name="BoundEntityName">The bind entity's Name, resolved synchronously by the transition and threaded through unchanged (empty for an unbound session) — recorded on the session for the bind-omission check (Part 1, clause 17.6.10 equations 21/22).</param>
/// <param name="Salt">Always empty on this unsalted path — the KDFa key's trailing term (Part 1, clause 17.6.12 equation 25) a salted arm instead recovers asynchronously.</param>
public sealed record TpmStartHmacSessionAction(
    uint SessionHandle,
    TpmAlgIdConstants SessionAlg,
    TpmtSymDef Symmetric,
    ReadOnlyMemory<byte> NonceCaller,
    ReadOnlyMemory<byte> BindAuthValue,
    ReadOnlyMemory<byte> BoundEntityName,
    ReadOnlyMemory<byte> Salt): TpmAction;

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
/// <param name="NonceCaller">The caller nonce sent at start — the second context field of the session-key KDFa.</param>
/// <param name="BindAuthValue">The bind entity's resolved authorization value (empty for an unbound session) — the session-key KDFa's leading term (Part 1, clause 17.6.12 equation 25).</param>
/// <param name="BoundEntityName">The bind entity's Name, resolved synchronously by the transition (empty for an unbound session).</param>
/// <param name="Ciphertext">The wire <c>encryptedSalt</c>: the OAEP ciphertext, the same octet width as <c>tpmKey</c>'s modulus.</param>
/// <param name="PrivateKey"><c>tpmKey</c>'s retained RSA private key, in the backend's own encoding.</param>
/// <param name="NameAlg">
/// <c>tpmKey</c>'s own Name algorithm — drives OAEP's <c>lhash</c>/MGF1 and caps the recovered salt's size (TPM
/// 2.0 Library Part 1, Annex B.10.1). NEVER the session's own <c>authHash</c> (a mixed-hash session would
/// otherwise leak the wrong hash into this derivation).
/// </param>
public sealed record TpmRecoverRsaSessionSaltAction(
    uint SessionHandle,
    TpmAlgIdConstants SessionAlg,
    TpmtSymDef Symmetric,
    ReadOnlyMemory<byte> NonceCaller,
    ReadOnlyMemory<byte> BindAuthValue,
    ReadOnlyMemory<byte> BoundEntityName,
    ReadOnlyMemory<byte> Ciphertext,
    ReadOnlyMemory<byte> PrivateKey,
    TpmAlgIdConstants NameAlg): TpmAction;

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
/// <param name="NonceCaller">The caller nonce sent at start — the second context field of the session-key KDFa.</param>
/// <param name="BindAuthValue">The bind entity's resolved authorization value (empty for an unbound session) — the session-key KDFa's leading term (Part 1, clause 17.6.12 equation 25).</param>
/// <param name="BoundEntityName">The bind entity's Name, resolved synchronously by the transition (empty for an unbound session).</param>
/// <param name="EncryptedSalt">The wire <c>encryptedSalt</c>: a marshaled <c>TPMS_ECC_POINT</c> (two size-prefixed coordinates) carrying the caller's ephemeral public point.</param>
/// <param name="PrivateScalar"><c>tpmKey</c>'s retained ECC private scalar, unsigned big-endian.</param>
/// <param name="PublicPoint"><c>tpmKey</c>'s own exported public point, SEC1 uncompressed — <c>KDFe</c>'s <c>partyVInfo</c> source.</param>
/// <param name="Curve">The ECC curve <c>tpmKey</c> lives on.</param>
/// <param name="NameAlg"><c>tpmKey</c>'s own Name algorithm — <c>KDFe</c>'s hash and the recovered salt's size, never the session's own <c>authHash</c>.</param>
public sealed record TpmRecoverEccSessionSaltAction(
    uint SessionHandle,
    TpmAlgIdConstants SessionAlg,
    TpmtSymDef Symmetric,
    ReadOnlyMemory<byte> NonceCaller,
    ReadOnlyMemory<byte> BindAuthValue,
    ReadOnlyMemory<byte> BoundEntityName,
    ReadOnlyMemory<byte> EncryptedSalt,
    ReadOnlyMemory<byte> PrivateScalar,
    ReadOnlyMemory<byte> PublicPoint,
    TpmEccCurveConstants Curve,
    TpmAlgIdConstants NameAlg): TpmAction;

/// <summary>
/// Declares that the simulator must draw a fresh nonceTPM for a newly started policy or trial session before the
/// next transition. Emitted by the <c>TPM2_StartAuthSession()</c> transition for a policy/trial session type
/// (<c>TPM_SE_POLICY</c>/<c>TPM_SE_TRIAL</c>); the effectful loop draws <see cref="AuthHash"/>'s digest width of
/// octets from the injected RNG backend and feeds them back as a <see cref="TpmPolicySessionStarted"/> input (TPM
/// 2.0 Library Part 3, clause 11.1). <c>TPM2_PolicySigned()</c>'s <c>aHash</c> binds to this exact nonceTPM (Part
/// 3, Section 23.3), so it can no longer be a fixed placeholder once that command exists.
/// </summary>
/// <param name="SessionHandle">The session handle the transition allocated for the new session.</param>
/// <param name="AuthHash">The session's policy hash algorithm, sizing the drawn nonceTPM and the policyDigest.</param>
/// <param name="IsTrial">Whether the session is a trial session (<c>TPM_SE_TRIAL</c>): computes the policyDigest but authorizes nothing.</param>
/// <param name="StartTime">The simulator's <c>Time</c> snapshot at session creation, recorded for session-relative expiration deadlines.</param>
public sealed record TpmStartPolicySessionAction(
    uint SessionHandle,
    TpmAlgIdConstants AuthHash,
    bool IsTrial,
    ulong StartTime): TpmAction;

/// <summary>
/// Declares that the simulator must verify one queued session's command HMAC before the next transition (TPM 2.0
/// Library Part 1, clause 19.6; Part 3, clause 5.6, check 8) — the shared mechanism every session-authorized
/// command transition in this wave routes through. Emitted by a command's entry transition (and, while sessions
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
/// <param name="HandleNames">The command's handle-Name area (Part 1, clause 18.7 equation 15's <c>Name1..N</c> term), empty for a command with no handles.</param>
/// <param name="ParameterArea">The command's raw parameter-area bytes exactly as received (still encrypted, if a decrypt session is present) — cpHash's <c>parameters</c> term.</param>
/// <param name="Current">The session being verified this stage.</param>
/// <param name="Remaining">The still-unverified sessions queued after <see cref="Current"/>, in order.</param>
/// <param name="NextRequest">The original parsed command request to resume once every queued session has verified.</param>
public sealed record TpmVerifyCommandHmacAction(
    TpmCcConstants CommandCode,
    ReadOnlyMemory<byte> HandleNames,
    ReadOnlyMemory<byte> ParameterArea,
    TpmPendingSessionVerification Current,
    ImmutableArray<TpmPendingSessionVerification> Remaining,
    TpmSimulatorInput NextRequest): TpmAction;

/// <summary>
/// Declares that the simulator must produce an encrypt-attributed <c>TPM2_GetRandom()</c> response over a bound
/// HMAC session before the next transition. Emitted by the session-tagged <c>TPM2_GetRandom()</c> transition; the
/// effectful loop draws the random octets and a fresh nonceTPM from the injected RNG, encrypts the first response
/// parameter, computes rpHash over the encrypted parameter area, computes the response HMAC, and feeds the framed
/// pieces back as a <see cref="TpmEncryptedRandomProduced"/> input (TPM 2.0 Library Part 3, clause 16.1; Part 1,
/// clauses 18.7 and 19).
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
/// <param name="SessionKey">The session key (<c>sessionValue</c>): the HMAC key and the parameter-encryption key seed.</param>
/// <param name="NonceCaller">This command's caller nonce: the response HMAC's nonceOlder and the encryption's nonceOlder.</param>
/// <param name="SessionAttributes">The command's session attributes byte, echoed into the response and folded into the response HMAC.</param>
/// <param name="ByteCount">The number of random octets to produce (already clamped to the largest digest the simulated TPM returns).</param>
public sealed record TpmEncryptRandomAction(
    uint SessionHandle,
    TpmAlgIdConstants SessionAlg,
    TpmtSymDef Symmetric,
    ReadOnlyMemory<byte> SessionKey,
    ReadOnlyMemory<byte> NonceCaller,
    byte SessionAttributes,
    int ByteCount): TpmAction;

/// <summary>
/// Declares that the simulator must frame the <c>TPM2_Unseal()</c> response before the next transition. Emitted
/// once every session in the command's authorization area has verified (a satisfied policy session's digest gate,
/// or a real command-HMAC verification); the effectful loop draws a fresh nonceTPM for each real (HMAC-table)
/// session, frames the recovered secret as a <c>TPM2B_SENSITIVE_DATA</c>, encrypts its data portion over whichever
/// session (if any) carries the <c>encrypt</c> attribute, computes rpHash over the (possibly encrypted) parameter
/// area, then computes each real session's own response HMAC, and feeds the framed pieces back as a
/// <see cref="TpmUnsealedOverSessions"/> input (TPM 2.0 Library Part 3, clause 12.7; Part 1, clauses 18.7 and 19).
/// </summary>
/// <remarks>
/// <see cref="HmacResponseSessions"/> holds 0, 1, or 2 entries, in command-session order (an authorizing HMAC
/// session first when present, an encrypt session — which may or may not be the same session — always last): each
/// gets its own real nonce roll and response HMAC over THE SAME rpHash, keyed on its own <c>sessionKey ‖
/// authValue</c> (Part 1, clause 19.6.8: "the TPM will use the same HMAC key it used for the command"). A satisfied
/// plain policy session (Part 1, clause 19.6: no key) instead gets a zero-nonce, empty-HMAC placeholder entry when
/// <see cref="HasPolicyPlaceholder"/> is set, and is always session index 0 when present (a policy session can only
/// ever be Unseal's first, primary-authorizing session).
/// </remarks>
/// <param name="SecretData">The recovered sealed data returned as <c>outData</c>.</param>
/// <param name="HmacResponseSessions">The real (HMAC-table) sessions needing a framed response entry, in command-session order.</param>
/// <param name="HasPolicyPlaceholder">Whether session index 0 is a satisfied plain policy session needing the zero-nonce, empty-HMAC placeholder entry.</param>
/// <param name="PolicyPlaceholderAlg">The policy session hash algorithm, sizing its placeholder entry's zero nonce. Meaningful only when <see cref="HasPolicyPlaceholder"/> is set.</param>
/// <param name="PolicyPlaceholderAttributes">The policy session's command session-attributes byte, echoed into its placeholder entry. Meaningful only when <see cref="HasPolicyPlaceholder"/> is set.</param>
public sealed record TpmUnsealDataAction(
    ReadOnlyMemory<byte> SecretData,
    ImmutableArray<TpmUnsealResponseSession> HmacResponseSessions,
    bool HasPolicyPlaceholder,
    TpmAlgIdConstants PolicyPlaceholderAlg,
    byte PolicyPlaceholderAttributes): TpmAction;

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
/// <param name="Credential">The secret to wrap (a <c>TPM2B_DIGEST</c> value).</param>
/// <param name="ObjectName">The attestation key's Name the credential is bound to (folded into the <c>KDFa</c> derivations and the outer HMAC).</param>
/// <param name="CredentialKeyPublicPoint">The credential key's exported public point, SEC1 uncompressed (<c>0x04 ‖ X ‖ Y</c>), the ECDH peer point and the <c>KDFe</c> partyVInfo source.</param>
/// <param name="CredentialKeyCurve">The ECC curve the credential key lives on.</param>
/// <param name="NameAlg">The credential key's Name algorithm, driving the <c>KDFe</c> / <c>KDFa</c> / HMAC digests.</param>
public sealed record TpmMakeCredentialAction(
    ReadOnlyMemory<byte> Credential,
    ReadOnlyMemory<byte> ObjectName,
    ReadOnlyMemory<byte> CredentialKeyPublicPoint,
    TpmEccCurveConstants CredentialKeyCurve,
    TpmAlgIdConstants NameAlg): TpmAction;

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
/// <param name="CredentialKeyPrivateScalar">The credential key's retained ECC scalar (unsigned big-endian), the ECDH private input that recovers the shared value.</param>
/// <param name="CredentialKeyPublicPoint">The credential key's exported public point, SEC1 uncompressed, the <c>KDFe</c> partyVInfo source (matching the make side).</param>
/// <param name="CredentialKeyCurve">The ECC curve the credential key lives on.</param>
/// <param name="NameAlg">The credential key's Name algorithm, driving the <c>KDFe</c> / <c>KDFa</c> / HMAC digests.</param>
public sealed record TpmActivateCredentialAction(
    ReadOnlyMemory<byte> CredentialBlob,
    ReadOnlyMemory<byte> Secret,
    ReadOnlyMemory<byte> ActivateObjectName,
    ReadOnlyMemory<byte> CredentialKeyPrivateScalar,
    ReadOnlyMemory<byte> CredentialKeyPublicPoint,
    TpmEccCurveConstants CredentialKeyCurve,
    TpmAlgIdConstants NameAlg): TpmAction;

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
/// <param name="Credential">The secret to wrap (a <c>TPM2B_DIGEST</c> value).</param>
/// <param name="ObjectName">The attestation key's Name the credential is bound to (folded into the <c>KDFa</c> derivations and the outer HMAC).</param>
/// <param name="CredentialKeyModulus">The credential key's exported public modulus, unsigned big-endian, the OAEP public-key input.</param>
/// <param name="NameAlg">The credential key's Name algorithm, driving the seed size, the OAEP <c>lhash</c>/MGF1 digests (the credential key's scheme is <c>TPM_ALG_NULL</c> for every storage-parent template this simulator builds, so <c>lhash</c> coincides with nameAlg), and the <c>KDFa</c>/HMAC digests.</param>
public sealed record TpmRsaMakeCredentialAction(
    ReadOnlyMemory<byte> Credential,
    ReadOnlyMemory<byte> ObjectName,
    ReadOnlyMemory<byte> CredentialKeyModulus,
    TpmAlgIdConstants NameAlg): TpmAction;

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
/// <param name="Secret">The encrypted seed transport — already unwrapped from its <c>TPM2B_ENCRYPTED_SECRET</c> framing by the command parser, so this is the raw OAEP ciphertext directly (Part 2, Table 190/191: the RSA arm has no sub-structure, unlike the ECC arm's marshaled <c>TPMS_ECC_POINT</c>).</param>
/// <param name="ActivateObjectName">The activate object's Name — re-keys the credential's symmetric and HMAC keys, so a mismatched object fails the integrity check.</param>
/// <param name="CredentialKeyPrivateKey">The credential key's retained RSA private key, in the backend's own encoding — the RSADP private input that recovers the OAEP-encoded message.</param>
/// <param name="NameAlg">The credential key's Name algorithm, driving the seed size, the OAEP <c>lhash</c>/MGF1 digests, and the <c>KDFa</c>/HMAC digests.</param>
public sealed record TpmRsaActivateCredentialAction(
    ReadOnlyMemory<byte> CredentialBlob,
    ReadOnlyMemory<byte> Secret,
    ReadOnlyMemory<byte> ActivateObjectName,
    ReadOnlyMemory<byte> CredentialKeyPrivateKey,
    TpmAlgIdConstants NameAlg): TpmAction;

/// <summary>
/// Declares that the simulator must compute an NV Index's Name before the next transition, so
/// <c>TPM2_PolicyNV()</c>'s policyDigest extension can bind it (TPM 2.0 Library Part 3, clause 23.9; Part 1,
/// clause 16). Emitted by the <c>TPM2_PolicyNV()</c> transition; the effectful loop marshals the Index's
/// <c>TPMS_NV_PUBLIC</c> and computes <c>nameAlg ‖ H_nameAlg(TPMS_NV_PUBLIC)</c> through the registered digest
/// seam, then feeds the Name back with the pending assertion's arguments as a
/// <see cref="TpmNvNameComputedForPolicy"/> input so a second transition can extend the session's policyDigest.
/// </summary>
/// <remarks>
/// The simulator's modelled NV Indexes carry a fixed <c>TPM_ALG_SHA256</c> nameAlg (this model's universal NV
/// Name algorithm) rather than a caller-chosen one, so <see cref="NameAlg"/> is not yet wire-agile — carried
/// here so a future NV nameAlg agility pass only touches this action's construction, not the digest routing.
/// </remarks>
/// <param name="PolicySession">The policy session whose policyDigest the assertion extends.</param>
/// <param name="NvIndex">The NV Index handle, folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="Attributes">The Index's current attributes (<c>TPMA_NV</c>), folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="DataSize">The Index's declared data size, folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="NameAlg">The Name algorithm the marshaled <c>TPMS_NV_PUBLIC</c> carries.</param>
/// <param name="OperandB">The comparison operand the pending assertion carries.</param>
/// <param name="Offset">The octet offset into the NV Index data the pending assertion carries.</param>
/// <param name="Operation">The <c>TPM_EO</c> comparison operation the pending assertion carries.</param>
public sealed record TpmComputeNvNameAction(
    uint PolicySession,
    uint NvIndex,
    TpmaNv Attributes,
    ushort DataSize,
    TpmAlgIdConstants NameAlg,
    ReadOnlyMemory<byte> OperandB,
    ushort Offset,
    ushort Operation): TpmAction;

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
/// <param name="Digest">The caller-supplied digest the signature is claimed to be over.</param>
/// <param name="Signature">The caller-supplied signature, IEEE P1363 <c>r ‖ s</c>.</param>
/// <param name="HashAlg">The hash algorithm carried inside the signature.</param>
public sealed record TpmVerifySignatureAction(
    ReadOnlyMemory<byte> KeyName,
    uint KeyHierarchy,
    ReadOnlyMemory<byte> PublicPoint,
    TpmEccCurveConstants Curve,
    ReadOnlyMemory<byte> Digest,
    ReadOnlyMemory<byte> Signature,
    TpmAlgIdConstants HashAlg): TpmAction;

/// <summary>
/// The RSA counterpart of <see cref="TpmVerifySignatureAction"/>: verify a digest/signature pair against a loaded
/// RSA key's retained private key (the simulator retains no standalone RSA public encoding, so the injected
/// <see cref="TpmRsaDigestVerifyDelegate"/> derives the public part from it) under the requested RSA scheme, and
/// on success produce a <c>TPMT_TK_VERIFIED</c> the same way <see cref="TpmVerifySignatureAction"/> does.
/// </summary>
/// <param name="KeyName">The verifying key's Name, folded into the ticket HMAC.</param>
/// <param name="KeyHierarchy">The permanent hierarchy the verifying key was created under, from which its ticket proof re-derives.</param>
/// <param name="PrivateKey">The verifying key's retained private key, in the backend's own encoding.</param>
/// <param name="Digest">The caller-supplied digest the signature is claimed to be over.</param>
/// <param name="Signature">The caller-supplied raw RSA signature octets.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to verify under.</param>
/// <param name="HashAlg">The hash algorithm carried inside the signature.</param>
public sealed record TpmRsaVerifySignatureAction(
    ReadOnlyMemory<byte> KeyName,
    uint KeyHierarchy,
    ReadOnlyMemory<byte> PrivateKey,
    ReadOnlyMemory<byte> Digest,
    ReadOnlyMemory<byte> Signature,
    TpmAlgIdConstants Scheme,
    TpmAlgIdConstants HashAlg): TpmAction;

/// <summary>
/// Declares that the simulator must recompute <c>TPM2_PolicySigned()</c>'s <c>aHash</c> and verify it against a
/// loaded ECC key's public point before the next transition (TPM 2.0 Library Part 3, Section 23.3). Emitted by
/// the <c>TPM2_PolicySigned()</c> transition for a non-trial session whose <c>authObject</c> resolves to an ECC
/// key, after the (non-crypto) nonceTPM/expiration/cpHashA checks have already passed; the effectful loop hashes
/// <c>nonceTPM ‖ expiration ‖ cpHashA ‖ policyRef</c> with <see cref="SchemeHashAlg"/> (the signature scheme's own
/// hash — independent of <see cref="PolicyHashAlgorithm"/>) through the registered async digest seam, calls the
/// injected <see cref="TpmEccDigestVerifyDelegate"/>, and feeds the boolean result back as a
/// <see cref="TpmPolicySignedVerified"/> input. Unlike <see cref="TpmVerifySignatureAction"/>, no
/// <c>TPMT_TK_VERIFIED</c>/<c>TPMT_TK_AUTH</c> is produced here — PolicySigned's real ticket mint is deferred to a
/// future wave, so the response always frames a NULL ticket regardless of this action's outcome.
/// </summary>
/// <param name="PolicySession">The policy session to extend on a successful verification.</param>
/// <param name="AuthObjectName">The authorizing key's Name, folded into the policyDigest fold (<c>arg2</c> of <c>PolicyUpdate</c>).</param>
/// <param name="PolicyRef">The policy qualifier, always folded as the second <c>PolicyUpdate</c> hash (Part 3, Section 23.2.3).</param>
/// <param name="PolicyHashAlgorithm">The session's own policy hash algorithm, sizing the policyDigest fold — independent of <see cref="SchemeHashAlg"/>.</param>
/// <param name="NonceTpm">The nonceTPM bytes folded into <c>aHash</c> (already validated against the session's retained nonce).</param>
/// <param name="Expiration">The signed expiration folded into <c>aHash</c> as 4 big-endian octets.</param>
/// <param name="CpHashA">The cpHashA bytes folded into <c>aHash</c> (already size- and latch-checked).</param>
/// <param name="PublicPoint">The authorizing key's retained public point, SEC1 uncompressed.</param>
/// <param name="Curve">The ECC curve the public point lives on.</param>
/// <param name="Signature">The caller-supplied signature, IEEE P1363 <c>r ‖ s</c>.</param>
/// <param name="SchemeHashAlg">H_authAlg: the hash algorithm carried inside the <c>TPMT_SIGNATURE auth</c> parameter — independent of <see cref="PolicyHashAlgorithm"/>.</param>
public sealed record TpmVerifyPolicySignedAction(
    uint PolicySession,
    ReadOnlyMemory<byte> AuthObjectName,
    ReadOnlyMemory<byte> PolicyRef,
    TpmAlgIdConstants PolicyHashAlgorithm,
    ReadOnlyMemory<byte> NonceTpm,
    int Expiration,
    ReadOnlyMemory<byte> CpHashA,
    ReadOnlyMemory<byte> PublicPoint,
    TpmEccCurveConstants Curve,
    ReadOnlyMemory<byte> Signature,
    TpmAlgIdConstants SchemeHashAlg): TpmAction;

/// <summary>
/// The RSA counterpart of <see cref="TpmVerifyPolicySignedAction"/>: recompute <c>TPM2_PolicySigned()</c>'s
/// <c>aHash</c> and verify it against a loaded RSA key's retained private key (the simulator retains no
/// standalone RSA public encoding, so the injected <see cref="TpmRsaDigestVerifyDelegate"/> derives the public
/// part from it) under the requested RSA scheme, the same way <see cref="TpmVerifyPolicySignedAction"/> does.
/// </summary>
/// <param name="PolicySession">The policy session to extend on a successful verification.</param>
/// <param name="AuthObjectName">The authorizing key's Name, folded into the policyDigest fold (<c>arg2</c> of <c>PolicyUpdate</c>).</param>
/// <param name="PolicyRef">The policy qualifier, always folded as the second <c>PolicyUpdate</c> hash (Part 3, Section 23.2.3).</param>
/// <param name="PolicyHashAlgorithm">The session's own policy hash algorithm, sizing the policyDigest fold — independent of <see cref="SchemeHashAlg"/>.</param>
/// <param name="NonceTpm">The nonceTPM bytes folded into <c>aHash</c> (already validated against the session's retained nonce).</param>
/// <param name="Expiration">The signed expiration folded into <c>aHash</c> as 4 big-endian octets.</param>
/// <param name="CpHashA">The cpHashA bytes folded into <c>aHash</c> (already size- and latch-checked).</param>
/// <param name="PrivateKey">The authorizing key's retained private key, in the backend's own encoding.</param>
/// <param name="Signature">The caller-supplied raw RSA signature octets.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to verify under.</param>
/// <param name="SchemeHashAlg">H_authAlg: the hash algorithm carried inside the <c>TPMT_SIGNATURE auth</c> parameter — independent of <see cref="PolicyHashAlgorithm"/>.</param>
public sealed record TpmRsaVerifyPolicySignedAction(
    uint PolicySession,
    ReadOnlyMemory<byte> AuthObjectName,
    ReadOnlyMemory<byte> PolicyRef,
    TpmAlgIdConstants PolicyHashAlgorithm,
    ReadOnlyMemory<byte> NonceTpm,
    int Expiration,
    ReadOnlyMemory<byte> CpHashA,
    ReadOnlyMemory<byte> PrivateKey,
    ReadOnlyMemory<byte> Signature,
    TpmAlgIdConstants Scheme,
    TpmAlgIdConstants SchemeHashAlg): TpmAction;

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
/// <param name="ApprovedPolicy">The approved policyDigest, folded into <c>aHash</c>.</param>
/// <param name="PolicyRef">The policy qualifier, folded into <c>aHash</c> and always folded as the fold's second <c>PolicyUpdate</c> hash.</param>
/// <param name="KeySign">The Name of the key that signed the approval, folded into the ticket HMAC and the policyDigest fold.</param>
/// <param name="HashAlg"><c>aHash</c>'s hash algorithm — <c>keySign</c>'s own nameAlg, independent of the session's own policy hash algorithm.</param>
/// <param name="CheckTicketHierarchy">The caller-supplied hierarchy the expected ticket's proof is derived from.</param>
/// <param name="CheckTicketDigest">The caller-supplied ticket digest to compare the recomputed one against.</param>
/// <param name="PolicyHashAlgorithm">The session's own policy hash algorithm, sizing the policyDigest fold.</param>
public sealed record TpmVerifyPolicyAuthorizeTicketAction(
    uint PolicySession,
    ReadOnlyMemory<byte> ApprovedPolicy,
    ReadOnlyMemory<byte> PolicyRef,
    ReadOnlyMemory<byte> KeySign,
    TpmAlgIdConstants HashAlg,
    uint CheckTicketHierarchy,
    ReadOnlyMemory<byte> CheckTicketDigest,
    TpmAlgIdConstants PolicyHashAlgorithm): TpmAction;

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
/// <see cref="SessionValue"/> is the decrypt session's <c>sessionKey</c> ALONE (never <c>sessionKey ‖
/// authValue</c>): the decrypt session in this wave's <c>TPM2_Create()</c> form is always a SEPARATE session that
/// authorizes no entity of its own, so the binding the encryption formula would otherwise fold in never applies
/// (Part 1, clause 21.1 — encryption's inclusion rule is keyed on whether the decrypt session ITSELF authorizes
/// an entity in this command, independent of the command-HMAC bind-omission rule).
/// </remarks>
/// <param name="Request">The original parsed command request, threaded through to the continuation so it can resolve the sessions needing a real response entry.</param>
/// <param name="RawParameterArea">The raw parameter-area bytes captured at parse time (still encrypted, if a decrypt session is present); its first parameter's data portion is decrypted in place, then the whole buffer is decoded.</param>
/// <param name="HasDecryptSession">Whether a decrypt session is present; when clear the buffer is decoded without any transform.</param>
/// <param name="SessionAlg">The decrypt session's hash algorithm, driving its KDFa. Meaningless when <see cref="HasDecryptSession"/> is clear.</param>
/// <param name="Symmetric">The decrypt session's negotiated symmetric definition, selecting XOR obfuscation or AES-CFB. Meaningless when <see cref="HasDecryptSession"/> is clear.</param>
/// <param name="SessionValue">The decrypt session's <c>sessionValue</c> (its session key alone). Meaningless when <see cref="HasDecryptSession"/> is clear.</param>
/// <param name="NonceCaller">The decrypt session's caller nonce for this command (the decryption's nonceNewer, Part 1, clause 19.2). Meaningless when <see cref="HasDecryptSession"/> is clear.</param>
/// <param name="NonceTpm">The decrypt session's stored nonceTPM (the decryption's nonceOlder). Meaningless when <see cref="HasDecryptSession"/> is clear.</param>
public sealed record TpmDecryptCreateSensitiveAction(
    TpmCreateSealedObjectOverSessionsRequested Request,
    ReadOnlyMemory<byte> RawParameterArea,
    bool HasDecryptSession,
    TpmAlgIdConstants SessionAlg,
    TpmtSymDef Symmetric,
    ReadOnlyMemory<byte> SessionValue,
    ReadOnlyMemory<byte> NonceCaller,
    ReadOnlyMemory<byte> NonceTpm): TpmAction;

/// <summary>
/// Declares that the simulator must frame the <c>TPM2_Create()</c> response over sessions before the next
/// transition — the request-decrypt counterpart of <see cref="TpmUnsealDataAction"/>. Emitted once
/// <c>inSensitive</c> has been decrypted (if applicable) and decoded; the effectful loop builds the sealed
/// object's wrapped private blob, exported public area, and creation by-products exactly as
/// <see cref="TpmSealDataAction"/> does, then rolls a fresh nonceTPM per real session, computes rpHash over the
/// (unencrypted — response encryption is out of this wave's scope for <c>TPM2_Create()</c>) response parameter
/// area, and each real session's own response HMAC keyed on its own <c>sessionKey ‖ authValue</c> (Part 1,
/// clause 19.6.8).
/// </summary>
/// <param name="ParentHandle">The storage parent the object is sealed under (its handle binds the creation by-products).</param>
/// <param name="NameAlg">The Name algorithm to carry in the exported public area.</param>
/// <param name="AuthPolicy">The authorization policy digest to re-emit into the exported public area (empty for an authValue-only seal).</param>
/// <param name="NoDa">Whether the template set <c>TPMA_OBJECT.noDA</c>, so the exported public area reproduces the caller's template.</param>
/// <param name="UserWithAuth">Whether the template set <c>TPMA_OBJECT.userWithAuth</c>, so the exported public area reproduces the caller's template.</param>
/// <param name="SecretData">The data to seal, carried into the wrapped private blob.</param>
/// <param name="UserAuth">The new object's authorization value, carried into the wrapped private blob alongside <see cref="SecretData"/> (TPM 2.0 Library Part 1, clause 19.6.4).</param>
/// <param name="HasPasswordPlaceholder">Whether session index 0 is a <c>TPM_RS_PW</c> session needing the empty-nonce, empty-HMAC password placeholder entry (Part 1, clause 19.4).</param>
/// <param name="PasswordPlaceholderAttributes">The password session's command session-attributes byte, framed into its placeholder entry. Meaningful only when <see cref="HasPasswordPlaceholder"/> is set.</param>
/// <param name="ResponseSessions">Every real (HMAC-table) session needing a framed response entry, in command-session order (after the password placeholder, when present).</param>
public sealed record TpmSealDataOverSessionsAction(
    uint ParentHandle,
    TpmAlgIdConstants NameAlg,
    ReadOnlyMemory<byte> AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    ReadOnlyMemory<byte> SecretData,
    ReadOnlyMemory<byte> UserAuth,
    bool HasPasswordPlaceholder,
    byte PasswordPlaceholderAttributes,
    ImmutableArray<TpmCreateResponseSession> ResponseSessions): TpmAction;
