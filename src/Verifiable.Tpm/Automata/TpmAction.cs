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
public sealed record TpmCreateEccKeyAction(
    uint Handle,
    uint Hierarchy,
    TpmAlgIdConstants NameAlg,
    TpmaObject Attributes,
    TpmEccCurveConstants Curve,
    TpmAlgIdConstants SchemeHashAlg): TpmAction;

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
public sealed record TpmCreateRsaKeyAction(
    uint Handle,
    uint Hierarchy,
    TpmAlgIdConstants NameAlg,
    TpmaObject Attributes,
    ushort KeyBits,
    TpmtRsaScheme Scheme): TpmAction;

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
public sealed record TpmCreateStorageParentAction(
    uint Handle,
    uint Hierarchy,
    TpmAlgIdConstants NameAlg,
    TpmaObject Attributes,
    TpmEccCurveConstants Curve,
    bool NoDa): TpmAction;

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
/// <param name="SecretData">The data to seal, carried into the wrapped private blob.</param>
public sealed record TpmSealDataAction(
    uint ParentHandle,
    TpmAlgIdConstants NameAlg,
    ReadOnlyMemory<byte> AuthPolicy,
    bool NoDa,
    ReadOnlyMemory<byte> SecretData): TpmAction;

/// <summary>
/// Declares that the simulator must compute a loaded object's Name before the next transition. Emitted by the
/// <c>TPM2_Load()</c> transition; the effectful loop computes <c>nameAlg ‖ H(TPMT_PUBLIC)</c> through the
/// registered digest seam and feeds it back with the recovered sealed data as a <see cref="TpmObjectLoaded"/>
/// input (TPM 2.0 Library Part 3, clause 12.2; Part 1, clause 16).
/// </summary>
/// <param name="Handle">The transient handle the transition allocated for the loaded object.</param>
/// <param name="NameAlg">The Name algorithm to compute the object Name with.</param>
/// <param name="AuthPolicy">The authorization policy digest carried in the loaded public area (empty for an authValue-only object), threaded through to the loaded object's state.</param>
/// <param name="PublicAreaBytes">The marshaled <c>TPMT_PUBLIC</c> the Name is hashed over.</param>
/// <param name="Data">The recovered sealed data to store under the loaded handle.</param>
public sealed record TpmLoadObjectAction(
    uint Handle,
    TpmAlgIdConstants NameAlg,
    ReadOnlyMemory<byte> AuthPolicy,
    ReadOnlyMemory<byte> PublicAreaBytes,
    ReadOnlyMemory<byte> Data): TpmAction;

/// <summary>
/// Declares that the simulator must attest a loaded object before the next transition. Emitted by the
/// <c>TPM2_Certify()</c> transition; the effectful loop marshals a <c>TPMS_ATTEST</c> of type
/// <c>TPM_ST_ATTEST_CERTIFY</c> that binds the certified object's Name and the caller nonce, signs
/// <c>H_hashAlg(attest)</c> with the signing key's retained scalar through the injected
/// <see cref="TpmEccSigningBackend"/>, and feeds the marshaled attest and signature back as a
/// <see cref="TpmObjectCertified"/> input (TPM 2.0 Library Part 3, clause 18.2; Part 2, clause 10.12.12).
/// </summary>
/// <remarks>
/// The transition resolves both command handles against the loaded-object table and folds their retained fields
/// into this action — the certified object's Name and the signing key's Name, scalar, and curve — so the effect
/// needs no automaton state and captures nothing. This slice models an elliptic-curve signing key (ECDSA), as the
/// signing paths do.
/// </remarks>
/// <param name="SubjectName">The certified object's Name (<c>nameAlg ‖ H(TPMT_PUBLIC)</c>), attested in <c>TPMS_CERTIFY_INFO.name</c>.</param>
/// <param name="SignerName">The signing key's Name, framed as the attestation's <c>qualifiedSigner</c> (a simplification of its Qualified Name, which the verifier does not check; TPM 2.0 Library Part 2, clause 10.12.12).</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c> this slice), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
public sealed record TpmCertifyAction(
    ReadOnlyMemory<byte> SubjectName,
    ReadOnlyMemory<byte> SignerName,
    ReadOnlyMemory<byte> QualifyingData,
    ReadOnlyMemory<byte> SignerPrivateKey,
    TpmEccCurveConstants SignerCurve,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants HashAlg): TpmAction;

/// <summary>
/// Declares that the simulator must quote a set of Platform Configuration Registers before the next transition.
/// Emitted by the <c>TPM2_Quote()</c> transition; the effectful loop computes the PCR composite digest over the
/// selected register values, marshals a <c>TPMS_ATTEST</c> of type <c>TPM_ST_ATTEST_QUOTE</c> that binds that
/// composite and the caller nonce, signs <c>H_hashAlg(attest)</c> with the signing key's retained scalar through
/// the injected <see cref="TpmEccSigningBackend"/>, and feeds the marshaled attest and signature back as a
/// <see cref="TpmObjectQuoted"/> input (TPM 2.0 Library Part 3, clause 18.4; Part 2, clauses 10.12.12 and 10.12.1).
/// </summary>
/// <remarks>
/// The transition resolves the signing-key handle against the loaded-object table and gathers the selected PCR
/// values from the durable bank, folding both into this action, so the effect needs no automaton state and
/// captures nothing. This slice models an elliptic-curve signing key (ECDSA), as the signing paths do.
/// </remarks>
/// <param name="SignerName">The signing key's Name, framed as the attestation's <c>qualifiedSigner</c> (a simplification of its Qualified Name, which the verifier does not check; TPM 2.0 Library Part 1, clause 26.6).</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c> this slice), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="PcrSelection">The caller's <c>TPML_PCR_SELECTION</c> wire bytes, echoed verbatim into the attested <c>TPMS_QUOTE_INFO.pcrSelect</c>.</param>
/// <param name="PcrValues">The selected register values in ascending PCR-index order, concatenated and hashed into the attested <c>pcrDigest</c>.</param>
public sealed record TpmQuoteAction(
    ReadOnlyMemory<byte> SignerName,
    ReadOnlyMemory<byte> QualifyingData,
    ReadOnlyMemory<byte> SignerPrivateKey,
    TpmEccCurveConstants SignerCurve,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants HashAlg,
    ReadOnlyMemory<byte> PcrSelection,
    ImmutableArray<ReadOnlyMemory<byte>> PcrValues): TpmAction;

/// <summary>
/// Declares that the simulator must establish a bound, unsalted HMAC session before the next transition. Emitted
/// by the <c>TPM2_StartAuthSession()</c> transition for an HMAC session; the effectful loop draws a fresh nonceTPM
/// from the injected RNG, derives the session key via <c>KDFa</c> through the registered HMAC seam, and feeds both
/// back as a <see cref="TpmHmacSessionStarted"/> input (TPM 2.0 Library Part 3, clause 11.1; Part 1, clause
/// 17.6.10 equation 20).
/// </summary>
/// <remarks>
/// The session key is <c>KDFa(SessionAlg, BindAuthValue, "ATH", nonceTPM, NonceCaller, bits)</c> — the same
/// derivation the host performs, so the two keys agree by construction. This slice models bind entities with an
/// empty authorization value (its objects carry empty auth), so <paramref name="BindAuthValue"/> is empty and the
/// KDFa key reduces to the salt (also empty here), leaving the derivation keyed on the two start nonces alone.
/// </remarks>
/// <param name="SessionHandle">The session handle the transition allocated for the new session.</param>
/// <param name="SessionAlg">The session hash algorithm driving the KDFa and sizing the nonceTPM.</param>
/// <param name="Symmetric">The negotiated symmetric definition to record on the session.</param>
/// <param name="NonceCaller">The caller nonce sent at start — the second context field of the session-key KDFa.</param>
/// <param name="BindAuthValue">The bind entity's authorization value (empty in this slice) — the KDFa key (Part 1, clause 17.6.10).</param>
public sealed record TpmStartHmacSessionAction(
    uint SessionHandle,
    TpmAlgIdConstants SessionAlg,
    TpmtSymDef Symmetric,
    ReadOnlyMemory<byte> NonceCaller,
    ReadOnlyMemory<byte> BindAuthValue): TpmAction;

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
/// Declares that the simulator must frame the confidentiality-protected response of a policy-gated
/// <c>TPM2_Unseal()</c> before the next transition. Emitted by the two-session <c>TPM2_Unseal()</c> transition once
/// the policy gate has passed; the effectful loop draws a fresh nonceTPM for the encrypt session, frames the
/// recovered secret as a <c>TPM2B_SENSITIVE_DATA</c> and encrypts its data portion over the encrypt session,
/// computes rpHash over the encrypted parameter area and the encrypt session's response HMAC, and feeds the framed
/// pieces back as a <see cref="TpmUnsealedOverSessions"/> input (TPM 2.0 Library Part 3, clause 12.7; Part 1, clauses
/// 18.7 and 19).
/// </summary>
/// <remarks>
/// The effect encrypts <c>outData</c> <b>before</b> computing rpHash and keys both the HMAC and the parameter
/// encryption on <c>sessionValue = EncryptSessionKey</c> (the encrypt session authorizes no entity, so its authValue
/// contributes nothing; Part 1, clause 19.1). Response-direction nonces are <c>nonceNewer = </c> the fresh nonceTPM
/// and <c>nonceOlder = EncryptNonceCaller</c> (Part 1, clause 19.2), so the host recovers the same keystream after
/// adopting the framed nonceTPM. The policy session carries no key, so its response entry needs no HMAC — only its
/// nonce width (<paramref name="PolicySessionAlg"/>) and echoed attributes.
/// </remarks>
/// <param name="SecretData">The recovered sealed data returned as <c>outData</c>.</param>
/// <param name="EncryptSessionHandle">The encrypt HMAC session the response is produced for (its nonceTPM is rolled).</param>
/// <param name="EncryptSessionAlg">The encrypt session hash algorithm driving rpHash and the response HMAC.</param>
/// <param name="EncryptSymmetric">The encrypt session's negotiated symmetric definition selecting XOR obfuscation or AES-CFB.</param>
/// <param name="EncryptSessionKey">The encrypt session key (<c>sessionValue</c>): the HMAC key and the parameter-encryption key seed.</param>
/// <param name="EncryptNonceCaller">The encrypt session's command caller nonce: the response HMAC's nonceOlder and the encryption's nonceOlder.</param>
/// <param name="EncryptAttributes">The encrypt session's command session-attributes byte, echoed into the response and folded into the response HMAC.</param>
/// <param name="PolicySessionAlg">The policy session hash algorithm, sizing the zero placeholder nonce of the policy session's response entry.</param>
/// <param name="PolicyAttributes">The policy session's command session-attributes byte, echoed into its response entry.</param>
public sealed record TpmUnsealDataAction(
    ReadOnlyMemory<byte> SecretData,
    uint EncryptSessionHandle,
    TpmAlgIdConstants EncryptSessionAlg,
    TpmtSymDef EncryptSymmetric,
    ReadOnlyMemory<byte> EncryptSessionKey,
    ReadOnlyMemory<byte> EncryptNonceCaller,
    byte EncryptAttributes,
    TpmAlgIdConstants PolicySessionAlg,
    byte PolicyAttributes): TpmAction;

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
