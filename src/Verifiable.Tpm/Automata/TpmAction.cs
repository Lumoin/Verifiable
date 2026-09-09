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
/// Declares that the simulator must fold <see cref="InData"/> into its RNG reseed state before the next
/// transition — <c>TPM2_StirRandom()</c>'s whole effect (TPM 2.0 Library Part 3, clause 16.2.1; Part 1,
/// clause 8.4.11.2). Emitted by both the plain and the session-authorized transition once every
/// authorization has cleared; the effectful loop folds <c>stir' = SHA-256(stir ‖ InData)</c> into the
/// simulator instance's own reseed state, disposes <see cref="InData"/>, and feeds back a
/// <see cref="TpmRandomStirred"/> input naming the request the resuming transition frames a response for.
/// </summary>
/// <param name="CommandCode">The command being resumed — always <c>TPM_CC_StirRandom</c>, carried like every other action's command code for the uniform rejection/framing helpers.</param>
/// <param name="InData">The additional input to fold (<c>TPM2B_SENSITIVE_DATA</c>, TPM 2.0 Library Part 2, clause 11.1.14, Table 170), bounded at 128 octets on the plaintext (Part 2, clause 11.1.13, Table 169). OWNED: TRANSFERRED from the request that declared this action (the plain form's parse, or the session form's recovered plaintext); the effect is its terminal owner on every path.</param>
/// <param name="Request">The parsed request the resuming transition frames a response for — <see cref="TpmStirRandomRequested"/>, whether it arrived directly or as a no-authorization wrapper's <see cref="TpmNoAuthOverSessionsRequested.Inner"/> — threaded through unread by the effect itself.</param>
public sealed record TpmStirRandomAction(TpmCcConstants CommandCode, Tpm2bSensitiveData InData, TpmSimulatorInput Request): TpmAction;

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
/// <param name="AuthPolicy">The authorization policy digest to re-emit into the exported public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90; empty for an authValue-only key), the owned pooled carrier the request parsed; ownership rides this action into the effect, which installs it on the durable key state.</param>
/// <param name="UserAuth">The new object's authorization value (<c>inSensitive.userAuth</c>), the owned <see cref="Tpm2bAuth"/> carrier the request parsed; ownership rides this action into the effect, which installs it on the durable key state. The dispose-immune empty sentinel for an authValue-free key.</param>
/// <param name="OutsideInfo">The <c>outsideInfo</c> parameter, included in the creation data (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2, clause 10.3.3, Table 91; Part 3, clause 24.1, Table 191, <c>outsideInfo</c> row), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="CreationPcr">The <c>creationPCR</c> parameter the creation data's <c>pcrDigest</c> is computed over (<c>TPML_PCR_SELECTION</c>, TPM 2.0 Library Part 2, clause 10.8.7, Table 128; Part 3, clause 24.1, Table 191, <c>creationPCR</c> row), already filtered to the implemented banks and registers by the declaring transition (<c>RetainImplementedPcrs</c>) — the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="CreationPcrValues">The FILTERED <see cref="CreationPcr"/>'s own register values, gathered from the durable PCR bank in selector order by the declaring transition (<c>GatherSelectedPcrValues</c>) — the same shape <c>TPM2_Quote()</c>'s <see cref="TpmQuoteAction.PcrValues"/> carries; the effect concatenates and hashes them into the creation data's <c>pcrDigest</c> under the object's own nameAlg (Part 2, clause 15.1, Table 261).</param>
public sealed record TpmCreateEccKeyAction(
    TpmiDhObject Handle,
    TpmiRhHierarchy Hierarchy,
    TpmiAlgHash NameAlg,
    TpmaObject Attributes,
    TpmiEccCurve Curve,
    TpmiAlgHash SchemeHashAlg,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth UserAuth,
    Tpm2bData OutsideInfo,
    TpmlPcrSelection CreationPcr,
    ImmutableArray<ReadOnlyMemory<byte>> CreationPcrValues): TpmAction;

/// <summary>
/// Declares that the simulator must generate an ECC KEM key before the next transition — the DHKEM
/// counterpart of <see cref="TpmCreateEccKeyAction"/>. Emitted by the <c>TPM2_CreatePrimary()</c> transition
/// for an unrestricted decryption <c>TPM_ALG_ECDH</c> template whose <c>kdf</c> is <c>TPM_ALG_HKDF</c> (TPM
/// 2.0 Library Part 2, Table 229); the effectful loop draws a key from the injected
/// <see cref="TpmEccSigningBackend"/>, builds the exported public area and durable key state from it —
/// retaining <see cref="KdfHashAlg"/> as the key's <see cref="TransientKeyState.KemKdfScheme"/>/
/// <see cref="TransientKeyState.KemKdfHashAlg"/> rather than a digest-capable
/// <see cref="TransientKeyState.SigningScheme"/> — and feeds them back as a <see cref="TpmPrimaryKeyCreated"/>
/// input, the same fold-back <see cref="TpmCreateEccKeyAction"/> and <see cref="TpmCreateStorageParentAction"/>
/// use (TPM 2.0 Library Part 3, clause 24.1).
/// </summary>
/// <param name="Handle">The transient handle the transition allocated for the new object.</param>
/// <param name="Hierarchy">The hierarchy the object is created under (its handle becomes the parent Name and the ticket hierarchy).</param>
/// <param name="NameAlg">The Name algorithm to carry in the exported public area and to compute the object Name with.</param>
/// <param name="Attributes">The object attributes to carry in the exported public area (an unrestricted decryption key: DECRYPT set, RESTRICTED and SIGN_ENCRYPT clear).</param>
/// <param name="Curve">The ECC curve to generate the key on — the DHKEM's <c>curveID</c> (this simulator's only wired DHKEM suite is P-256).</param>
/// <param name="SchemeHashAlg">
/// The template's <c>TPMS_ECC_PARMS.scheme.details.ecdh.hashAlg</c>, echoed unchanged into the exported
/// public area's ECDH scheme — Part 3, clause 24.1.1: "All of the bits of the template are used in the
/// creation of the Primary Key"; Table 229's "ignored" note names only <c>TPM2_Encapsulate()</c>/
/// <c>TPM2_Decapsulate()</c>, not object creation.
/// </param>
/// <param name="KdfHashAlg">The HKDF hash algorithm — the DHKEM's KDF hash, retained verbatim as the key's <see cref="TransientKeyState.KemKdfHashAlg"/>.</param>
/// <param name="AuthPolicy">The authorization policy digest to re-emit into the exported public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90; empty for an authValue-only key), the owned pooled carrier the request parsed; ownership rides this action into the effect, which installs it on the durable key state.</param>
/// <param name="UserAuth">The new object's authorization value (<c>inSensitive.userAuth</c>), the owned <see cref="Tpm2bAuth"/> carrier the request parsed; ownership rides this action into the effect, which installs it on the durable key state. The dispose-immune empty sentinel for an authValue-free key.</param>
/// <param name="OutsideInfo">The <c>outsideInfo</c> parameter, included in the creation data (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2, clause 10.3.3, Table 91; Part 3, clause 24.1, Table 191, <c>outsideInfo</c> row), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="CreationPcr">The <c>creationPCR</c> parameter the creation data's <c>pcrDigest</c> is computed over (<c>TPML_PCR_SELECTION</c>, TPM 2.0 Library Part 2, clause 10.8.7, Table 128; Part 3, clause 24.1, Table 191, <c>creationPCR</c> row), already filtered to the implemented banks and registers by the declaring transition (<c>RetainImplementedPcrs</c>) — the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="CreationPcrValues">The FILTERED <see cref="CreationPcr"/>'s own register values, gathered from the durable PCR bank in selector order by the declaring transition (<c>GatherSelectedPcrValues</c>) — the same shape <c>TPM2_Quote()</c>'s <see cref="TpmQuoteAction.PcrValues"/> carries; the effect concatenates and hashes them into the creation data's <c>pcrDigest</c> under the object's own nameAlg (Part 2, clause 15.1, Table 261).</param>
public sealed record TpmCreateEccKemKeyAction(
    TpmiDhObject Handle,
    TpmiRhHierarchy Hierarchy,
    TpmiAlgHash NameAlg,
    TpmaObject Attributes,
    TpmiEccCurve Curve,
    TpmiAlgHash SchemeHashAlg,
    TpmiAlgHash KdfHashAlg,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth UserAuth,
    Tpm2bData OutsideInfo,
    TpmlPcrSelection CreationPcr,
    ImmutableArray<ReadOnlyMemory<byte>> CreationPcrValues): TpmAction;

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
/// <param name="AuthPolicy">The authorization policy digest to re-emit into the exported public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90; empty for an authValue-only key), the owned pooled carrier the request parsed; ownership rides this action into the effect, which installs it on the durable key state.</param>
/// <param name="UserAuth">The new object's authorization value (<c>inSensitive.userAuth</c>), the owned <see cref="Tpm2bAuth"/> carrier the request parsed; ownership rides this action into the effect, which installs it on the durable key state. The dispose-immune empty sentinel for an authValue-free key.</param>
/// <param name="OutsideInfo">The <c>outsideInfo</c> parameter, included in the creation data (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2, clause 10.3.3, Table 91; Part 3, clause 24.1, Table 191, <c>outsideInfo</c> row), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="CreationPcr">The <c>creationPCR</c> parameter the creation data's <c>pcrDigest</c> is computed over (<c>TPML_PCR_SELECTION</c>, TPM 2.0 Library Part 2, clause 10.8.7, Table 128; Part 3, clause 24.1, Table 191, <c>creationPCR</c> row), already filtered to the implemented banks and registers by the declaring transition (<c>RetainImplementedPcrs</c>) — the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="CreationPcrValues">The FILTERED <see cref="CreationPcr"/>'s own register values, gathered from the durable PCR bank in selector order by the declaring transition (<c>GatherSelectedPcrValues</c>) — the same shape <c>TPM2_Quote()</c>'s <see cref="TpmQuoteAction.PcrValues"/> carries; the effect concatenates and hashes them into the creation data's <c>pcrDigest</c> under the object's own nameAlg (Part 2, clause 15.1, Table 261).</param>
public sealed record TpmCreateRsaKeyAction(
    TpmiDhObject Handle,
    TpmiRhHierarchy Hierarchy,
    TpmiAlgHash NameAlg,
    TpmaObject Attributes,
    TpmiRsaKeyBits KeyBits,
    TpmtRsaScheme Scheme,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth UserAuth,
    Tpm2bData OutsideInfo,
    TpmlPcrSelection CreationPcr,
    ImmutableArray<ReadOnlyMemory<byte>> CreationPcrValues): TpmAction;

/// <summary>
/// Declares that the simulator must sign a digest with a retained key before the next transition. Emitted
/// by the <c>TPM2_Sign()</c> transition; the effectful loop signs the digest through the injected
/// <see cref="TpmEccSigningBackend"/> and feeds the signature back as a <see cref="TpmMessageSigned"/>
/// input (TPM 2.0 Library Part 3, clause 20.5).
/// </summary>
/// <param name="Scalar">The signing key's retained private scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="Digest">The pre-computed digest to sign directly (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="Curve">The ECC curve the scalar lives on.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, reported inside the signature.</param>
/// <param name="OverSessions">The session-authorized form's response framing (the command code rpHash folds, every slot's response-entry material, and no sequence to flush), or <see langword="null"/> on the password form, whose effect feeds the plain <see cref="TpmMessageSigned"/> back instead (TPM 2.0 Library Part 1, clause 15.6.1).</param>
public sealed record TpmEccSignAction(
    PrivateKeyMemory Scalar,
    Tpm2bDigest Digest,
    TpmiEccCurve Curve,
    TpmiAlgHash HashAlg,
    TpmOverSessionsFraming? OverSessions = null): TpmAction;

/// <summary>
/// Declares that the simulator must sign a digest with a retained RSA key before the next transition — the RSA
/// counterpart of <see cref="TpmEccSignAction"/>. Emitted by the <c>TPM2_Sign()</c> transition for an RSA key;
/// the effectful loop signs the digest through the injected <see cref="TpmRsaSigningBackend"/> and feeds the
/// signature back as a <see cref="TpmMessageSigned"/> input (TPM 2.0 Library Part 3, clause 20.5).
/// </summary>
/// <param name="PrivateKey">The signing key's retained private key, in the backend's encoding — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="Digest">The pre-computed digest to sign directly (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to apply.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, reported inside the signature.</param>
/// <param name="OverSessions">The session-authorized form's response framing (the command code rpHash folds, every slot's response-entry material, and no sequence to flush), or <see langword="null"/> on the password form, whose effect feeds the plain <see cref="TpmMessageSigned"/> back instead (TPM 2.0 Library Part 1, clause 15.6.1).</param>
public sealed record TpmRsaSignAction(
    PrivateKeyMemory PrivateKey,
    Tpm2bDigest Digest,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash HashAlg,
    TpmOverSessionsFraming? OverSessions = null): TpmAction;

/// <summary>
/// Declares that the simulator must recompute a caller-supplied <c>TPMT_TK_HASHCHECK</c> ticket's HMAC (equation
/// 7, TPM 2.0 Library Part 2, clause 10.6.7) and, only if it validates, sign a digest with a retained ECC key —
/// the restricted-key and forged-ticket path of <c>TPM2_SignDigest()</c> (Part 3, clause 20.7). Emitted by
/// <c>OnSignDigest</c> whenever the caller supplied a non-NULL validation ticket (required for a restricted key;
/// optional but still HMAC-checked for an unrestricted one); the effectful loop re-derives
/// <see cref="TicketHierarchy"/>'s proof, recomputes the ticket HMAC over <c>TPM_ST_HASHCHECK || digest</c>, and
/// constant-time compares it to <see cref="TicketDigest"/> before ever reaching the signing primitive, feeding
/// the result back as a <see cref="TpmDigestSigned"/> input.
/// </summary>
/// <param name="TicketDigest">The caller-supplied validation ticket's HMAC octets (<c>TPM2B_DIGEST</c>), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="TicketHierarchy">The validation ticket's own <c>hierarchy</c> field — the hierarchy the ticket's proof re-derives under, independent of the signing key's own hierarchy.</param>
/// <param name="Scalar">The signing key's retained private scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive, only once the ticket has validated, and never disposes it.</param>
/// <param name="Digest">The pre-computed digest to sign directly, and the same digest the ticket HMAC covers (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="Curve">The ECC curve the scalar lives on.</param>
/// <param name="HashAlg">The key's own scheme hash algorithm, reported inside the signature.</param>
/// <param name="OverSessions">The session-authorized form's response framing (the command code rpHash folds, every slot's response-entry material, and no sequence to flush), or <see langword="null"/> on the password form, whose effect feeds the plain <see cref="TpmDigestSigned"/> back instead (TPM 2.0 Library Part 1, clause 15.6.1). A ticket refusal keeps its header-only feedback on both forms.</param>
public sealed record TpmEccSignDigestWithTicketAction(
    Tpm2bDigest TicketDigest,
    TpmiRhHierarchy TicketHierarchy,
    PrivateKeyMemory Scalar,
    Tpm2bDigest Digest,
    TpmiEccCurve Curve,
    TpmiAlgHash HashAlg,
    TpmOverSessionsFraming? OverSessions = null): TpmAction;

/// <summary>
/// The RSA counterpart of <see cref="TpmEccSignDigestWithTicketAction"/>: recompute the caller-supplied
/// <c>TPMT_TK_HASHCHECK</c> ticket's HMAC and, only if it validates, sign the digest with a retained RSA key
/// under the key's own retained scheme.
/// </summary>
/// <param name="TicketDigest">The caller-supplied validation ticket's HMAC octets (<c>TPM2B_DIGEST</c>), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="TicketHierarchy">The validation ticket's own <c>hierarchy</c> field — the hierarchy the ticket's proof re-derives under, independent of the signing key's own hierarchy.</param>
/// <param name="PrivateKey">The signing key's retained private key, in the backend's encoding — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive, only once the ticket has validated, and never disposes it.</param>
/// <param name="Digest">The pre-computed digest to sign directly, and the same digest the ticket HMAC covers (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to apply.</param>
/// <param name="HashAlg">The key's own scheme hash algorithm, reported inside the signature.</param>
/// <param name="OverSessions">The session-authorized form's response framing (the command code rpHash folds, every slot's response-entry material, and no sequence to flush), or <see langword="null"/> on the password form, whose effect feeds the plain <see cref="TpmDigestSigned"/> back instead (TPM 2.0 Library Part 1, clause 15.6.1). A ticket refusal keeps its header-only feedback on both forms.</param>
public sealed record TpmRsaSignDigestWithTicketAction(
    Tpm2bDigest TicketDigest,
    TpmiRhHierarchy TicketHierarchy,
    PrivateKeyMemory PrivateKey,
    Tpm2bDigest Digest,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash HashAlg,
    TpmOverSessionsFraming? OverSessions = null): TpmAction;

/// <summary>
/// Declares that the simulator must deep-copy a signing (or verifying) key's Name into a new sequence context
/// before the next transition — the sequence-command counterpart of <see cref="TpmPersistObjectAction"/>: the
/// copy is an effect because it rents a pooled carrier for <see cref="SequenceObjectState.StartingKeyName"/>,
/// which the declaring transition (<c>OnSignSequenceStart</c> or <c>OnVerifySequenceStart</c>, or their
/// KEYEDHASH arms <c>OnSignSequenceStartKeyedHash</c> and <c>OnVerifySequenceStartKeyedHash</c>) cannot rent
/// itself, being pure. Emitted once every gate of <c>TPM2_SignSequenceStart()</c> or
/// <c>TPM2_VerifySequenceStart()</c> has passed, distinguished by <see cref="Kind"/>; the effectful loop builds
/// the new <see cref="SequenceObjectState"/> and feeds it back as a <see cref="TpmSequenceStarted"/> input,
/// which <c>OnSequenceStarted</c> installs (TPM 2.0 Library Part 3, clauses 17.5 and 17.6).
/// </summary>
/// <param name="Handle">The transient handle the declaring transition allocated for the new sequence.</param>
/// <param name="KeyName">The key's current Name — a borrowed reference to the carrier the live <see cref="TransientKeyState"/> (asymmetric arm) or <see cref="KeyedHashObjectState"/> (KEYEDHASH arm) owns for the duration of the one <c>SubmitAsync</c> call that resolved it; the effect reads it at the deep-copy primitive and never disposes it.</param>
/// <param name="Scheme">The signing scheme resolved from the key, to retain on the new sequence.</param>
/// <param name="HashAlg">The scheme's hash algorithm resolved from the key, to retain on the new sequence.</param>
/// <param name="SequenceAuth">The sequence's own authorization value, the owned pinned carrier the request parsed; ownership rides this action into the effect, which installs it on the new sequence context.</param>
/// <param name="Kind">Which sequence-command family may complete the new sequence — <see cref="TpmSequenceKind.Signing"/> for <c>TPM2_SignSequenceStart()</c>, <see cref="TpmSequenceKind.Verification"/> for <c>TPM2_VerifySequenceStart()</c> — carried straight onto <see cref="SequenceObjectState.Kind"/>.</param>
public sealed record TpmSequenceStartAction(
    TpmiDhObject Handle,
    Tpm2bName KeyName,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash HashAlg,
    Tpm2bAuth SequenceAuth,
    TpmSequenceKind Kind): TpmAction;

/// <summary>
/// Declares that the simulator must hash the accumulated message of an open signing sequence and sign the
/// digest with a retained ECC key before the next transition — the sequence-command counterpart of
/// <see cref="TpmEccSignAction"/>. Emitted by <c>TPM2_SignSequenceComplete()</c> once every gate has passed
/// (including the restricted-key first-block check); the effectful loop chains <see cref="Segments"/> and
/// <see cref="TrailingBuffer"/> into one <c>ReadOnlySequence{byte}</c>
/// (<see cref="SequenceObjectState.BuildMessageSequence"/>), hashes it through the registered digest seam, and
/// signs the digest through the injected <see cref="TpmEccSigningBackend"/> — feeding the signature back as a
/// <see cref="TpmSequenceSigned"/> input the continuation flushes the sequence with (TPM 2.0 Library Part 3,
/// clause 20.6).
/// </summary>
/// <param name="SequenceHandle">The handle of the sequence being completed, so the continuation can flush the correct entry.</param>
/// <param name="Segments">The sequence's accumulated message, BORROWED from the live <see cref="SequenceObjectState"/> — the state remains their owner until the continuation flushes it; the effect only reads their octets to build the hash input.</param>
/// <param name="TrailingBuffer">The completing command's own final block (<c>buffer</c>), OWNED by this action and disposed by the effect once the digest has been computed over it.</param>
/// <param name="PrivateKey">The signing key's retained private scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="Curve">The ECC curve the scalar lives on.</param>
/// <param name="HashAlg">The sequence's own accumulator and signing scheme hash algorithm.</param>
/// <param name="OverSessions">The session-authorized form's response framing — the command code rpHash folds, every slot's response-entry material, and the completed sequence to flush with the response (<c>{F}</c>, TPM 2.0 Library Part 1, clause 29.4.6) — or <see langword="null"/> on the password form, whose effect feeds the plain <see cref="TpmSequenceSigned"/> back instead.</param>
public sealed record TpmEccSignSequenceAction(
    TpmiDhObject SequenceHandle,
    ImmutableList<Tpm2bMaxBuffer> Segments,
    Tpm2bMaxBuffer TrailingBuffer,
    PrivateKeyMemory PrivateKey,
    TpmiEccCurve Curve,
    TpmiAlgHash HashAlg,
    TpmOverSessionsFraming? OverSessions = null): TpmAction;

/// <summary>
/// The RSA counterpart of <see cref="TpmEccSignSequenceAction"/>: hash the accumulated message and sign the
/// digest with a retained RSA key under the sequence's own retained scheme.
/// </summary>
/// <param name="SequenceHandle">The handle of the sequence being completed, so the continuation can flush the correct entry.</param>
/// <param name="Segments">The sequence's accumulated message, BORROWED from the live <see cref="SequenceObjectState"/> — the state remains their owner until the continuation flushes it; the effect only reads their octets to build the hash input.</param>
/// <param name="TrailingBuffer">The completing command's own final block (<c>buffer</c>), OWNED by this action and disposed by the effect once the digest has been computed over it.</param>
/// <param name="PrivateKey">The signing key's retained private key, in the backend's encoding — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="Scheme">The sequence's own retained RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>).</param>
/// <param name="HashAlg">The sequence's own accumulator and signing scheme hash algorithm.</param>
/// <param name="OverSessions">The session-authorized form's response framing — the command code rpHash folds, every slot's response-entry material, and the completed sequence to flush with the response (<c>{F}</c>, TPM 2.0 Library Part 1, clause 29.4.6) — or <see langword="null"/> on the password form, whose effect feeds the plain <see cref="TpmSequenceSigned"/> back instead.</param>
public sealed record TpmRsaSignSequenceAction(
    TpmiDhObject SequenceHandle,
    ImmutableList<Tpm2bMaxBuffer> Segments,
    Tpm2bMaxBuffer TrailingBuffer,
    PrivateKeyMemory PrivateKey,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash HashAlg,
    TpmOverSessionsFraming? OverSessions = null): TpmAction;

/// <summary>
/// Declares that the simulator must digest a message — the accumulated segments of an open hash sequence
/// followed by a trailing block, or a one-shot <c>TPM2_Hash()</c> data buffer alone — and mint the
/// <c>TPMT_TK_HASHCHECK</c> ticket over the result before the next transition. Emitted by
/// <c>TPM2_SequenceComplete()</c> (TPM 2.0 Library Part 3, clause 17.8) once every gate has passed, with the
/// sequence's segments BORROWED and the command's <c>buffer</c> as the trailing block, and by <c>TPM2_Hash()</c>
/// (clause 15.4) with no segments and <c>data</c> as the trailing block. The effectful loop chains the pieces
/// into one <c>ReadOnlySequence{byte}</c> (<see cref="SequenceObjectState.BuildMessageSequence"/>), hashes it
/// through the registered digest seam under <see cref="HashAlg"/>, and then either frames the NULL ticket
/// (<see cref="TicketHierarchy"/> is <c>TPM_RH_NULL</c>, or <see cref="IsSafeToSign"/> is
/// <see langword="false"/>) or mints <c>HMAC(proof_hierarchy, TPM_ST_HASHCHECK ‖ digest)</c> (Part 2, clause
/// 10.6.7, Table 115 — the formula <c>TPM2_SignDigest()</c> re-verifies).
/// </summary>
/// <param name="SequenceHandle">The handle of the hash sequence being completed, so the continuation can flush the correct entry; <see langword="null"/> for the one-shot <c>TPM2_Hash()</c>.</param>
/// <param name="Segments">The sequence's accumulated message, BORROWED from the live <see cref="SequenceObjectState"/> — the state remains their owner until the continuation flushes it; empty for the one-shot command.</param>
/// <param name="TrailingBuffer">The final block — <c>TPM2_SequenceComplete()</c>'s <c>buffer</c> or <c>TPM2_Hash()</c>'s <c>data</c> — OWNED by this action and disposed by the effect once the digest has been computed over it.</param>
/// <param name="HashAlg">The digest algorithm: the sequence's own retained one, or <c>TPM2_Hash()</c>'s <c>hashAlg</c>.</param>
/// <param name="TicketHierarchy">The hierarchy whose proof keys the ticket HMAC (the ticket's own <c>hierarchy</c> field); <c>TPM_RH_NULL</c> yields the NULL ticket.</param>
/// <param name="IsSafeToSign">Whether the hashed octets are safe to sign with a restricted key — the settled first-block verdict (clauses 17.7 and 17.8) for a sequence, the Part 4 <c>Hash.c</c>'s <c>TPM2_Hash()</c> rule for the one-shot; <see langword="false"/> yields the NULL ticket regardless of <paramref name="TicketHierarchy"/>.</param>
public sealed record TpmDigestAction(
    TpmiDhObject? SequenceHandle,
    ImmutableList<Tpm2bMaxBuffer> Segments,
    Tpm2bMaxBuffer TrailingBuffer,
    TpmiAlgHash HashAlg,
    TpmiRhHierarchy TicketHierarchy,
    bool IsSafeToSign): TpmAction;

/// <summary>
/// Declares the HMAC computation a <c>TPM2_HMAC()</c> or the HMAC arm of a <c>TPM2_SequenceComplete()</c> asks
/// for: <c>HMAC_hashAlg(key, Segments ‖ TrailingBuffer)</c> over the accumulated message (TPM 2.0 Library Part
/// 3, clauses 15.5 and 17.8; Part 1, clause 29.4.4). The effect chains <see cref="Segments"/> and
/// <see cref="TrailingBuffer"/> into one message the same way <see cref="TpmDigestAction"/> does, keys the HMAC
/// with <see cref="KeyBits"/>, and reports <see cref="TpmHmacComputed"/>.
/// </summary>
/// <param name="SequenceHandle">
/// The sequence handle to flush when the HMAC completes a <c>TPM2_SequenceComplete()</c>, or <see langword="null"/>
/// for the one-shot <c>TPM2_HMAC()</c> — the same discriminator <see cref="TpmDigestAction.SequenceHandle"/>
/// carries. It decides how <c>OnHmacComputed</c> frames the response: a bare <c>TPM2B_DIGEST</c> for the
/// one-shot, a <c>TPM2B_DIGEST</c> plus a NULL <c>TPMT_TK_HASHCHECK</c> (Table 94) for the sequence arm.
/// </param>
/// <param name="Segments">The accumulated sequence segments, borrowed from the live sequence (empty for the one-shot).</param>
/// <param name="TrailingBuffer">
/// The completing command's own buffer, owned by this action; the effect is its terminal owner and releases it.
/// </param>
/// <param name="HashAlg">The HMAC hash algorithm resolved from the key's scheme through Table 79.</param>
/// <param name="KeyBits">
/// The HMAC key's sensitive value — a BORROWED reference to the carrier the durable
/// <see cref="KeyedHashObjectState"/> (one-shot) or <see cref="SequenceObjectState"/> (sequence arm) owns; that
/// owner outlives this action for the duration of the one <c>SubmitAsync</c> call that resolved it (commands are
/// never interleaved), so the awaited HMAC seam reads live octets and neither this action nor its effect ever
/// disposes it.
/// </param>
/// <param name="ResponseSession">
/// The authorizing session's response-entry material when the one-shot <c>TPM2_HMAC()</c> was authorized by a
/// real session (an HMAC or policy session) rather than <c>TPM_RS_PW</c>, or <see langword="null"/> for the
/// password form and the <c>TPM2_SequenceComplete()</c> arm (a sequence is password-authorized). When present
/// the effect frames the <c>outHMAC</c> parameter area, rolls the session's nonceTPM and computes the response
/// HMAC, reporting <see cref="TpmHmacComputedOverSession"/> instead of <see cref="TpmHmacComputed"/>; its
/// <see cref="TpmHmacResponseSession.NonceCaller"/> is OWNED and released by that effect.
/// </param>
public sealed record TpmHmacAction(
    TpmiDhObject? SequenceHandle,
    ImmutableList<Tpm2bMaxBuffer> Segments,
    Tpm2bMaxBuffer TrailingBuffer,
    TpmiAlgHash HashAlg,
    ReadOnlyMemory<byte> KeyBits,
    TpmHmacResponseSession? ResponseSession = null): TpmAction;

/// <summary>
/// Declares the sequence object a <c>TPM2_HMAC_Start()</c> opens: a KEYEDHASH HMAC sequence bound to a copy of
/// the key's sensitive value (TPM 2.0 Library Part 3, clause 17.2; Part 4 <c>ObjectCreateHMACSequence</c>). The
/// effect deep-copies <see cref="KeyBits"/> into a carrier the new <see cref="SequenceObjectState"/> owns — so
/// the sequence survives the key being flushed before it completes — and transfers ownership of
/// <see cref="SequenceAuth"/> onto that sequence.
/// </summary>
/// <param name="Handle">The transient handle assigned to the new HMAC sequence.</param>
/// <param name="KeyBits">The HMAC key's sensitive value, borrowed from the live loaded key and copied by the effect.</param>
/// <param name="HashAlg">The HMAC hash algorithm resolved from the key's scheme through Table 79.</param>
/// <param name="SequenceAuth">The sequence's own authorization value (Table 80's <c>auth</c>), owned and transferred to the sequence.</param>
/// <param name="ResponseSession">
/// The authorizing session's response-entry material when the command was authorized by a real session (an
/// HMAC or policy session) rather than <c>TPM_RS_PW</c>, or <see langword="null"/> for the password form. When
/// present the effect additionally rolls the session's nonceTPM and computes the response HMAC over the empty
/// parameter area (Table 81 returns only <c>sequenceHandle</c>, which rides the handle area rpHash never
/// covers), reporting <see cref="TpmHmacSequenceStartedOverSession"/> instead of <see cref="TpmSequenceStarted"/>;
/// its <see cref="TpmHmacResponseSession.NonceCaller"/> is OWNED and released by that effect.
/// </param>
public sealed record TpmHmacSequenceStartAction(
    TpmiDhObject Handle,
    ReadOnlyMemory<byte> KeyBits,
    TpmiAlgHash HashAlg,
    Tpm2bAuth SequenceAuth,
    TpmHmacResponseSession? ResponseSession = null): TpmAction;

/// <summary>
/// Declares that the simulator must sign a digest with a loaded KEYEDHASH HMAC key before the next transition —
/// the KEYEDHASH counterpart of <see cref="TpmEccSignAction"/>/<see cref="TpmRsaSignAction"/> for the HMAC row
/// of TPM 2.0 Library Part 3, clause 20.1, Table 115 ("Signs/verifies the digest"). Emitted by the
/// <c>TPM2_Sign()</c> transition for a KEYEDHASH key; the effectful loop computes
/// <c>HMAC_hashAlg(bits, digest)</c> through the registered HMAC seam — an HMAC of a digest, not of a message
/// (clause 20.5) — frames it as <c>TPMT_SIGNATURE(TPM_ALG_HMAC, TPMT_HA(hashAlg, hmac))</c> (Part 2, clause
/// 11.3.6, Table 219), and feeds it back as the same <see cref="TpmMessageSigned"/> input the asymmetric arms
/// feed.
/// </summary>
/// <param name="HashAlg">The key's HMAC scheme hash algorithm (<c>TPMS_SCHEME_HMAC.hashAlg</c>), keying the seam and reported inside the signature's <c>TPMT_HA</c>.</param>
/// <param name="KeyBits">The HMAC key's sensitive value, borrowed from the live loaded <see cref="KeyedHashObjectState"/> — the state remains its owner for the duration of the one <c>SubmitAsync</c> call that resolved it (commands are never interleaved), so the awaited HMAC seam reads live octets and neither this action nor its effect ever disposes it.</param>
/// <param name="Digest">The pre-computed digest to sign directly (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="OverSessions">The session-authorized form's response framing (the command code rpHash folds, every slot's response-entry material, and no sequence to flush), or <see langword="null"/> on the password form, whose effect feeds the plain <see cref="TpmMessageSigned"/> back instead (TPM 2.0 Library Part 1, clause 15.6.1).</param>
public sealed record TpmHmacSignAction(
    TpmiAlgHash HashAlg,
    ReadOnlyMemory<byte> KeyBits,
    Tpm2bDigest Digest,
    TpmOverSessionsFraming? OverSessions = null): TpmAction;

/// <summary>
/// Declares that the simulator must HMAC the accumulated message of an open signing sequence with a loaded
/// KEYEDHASH HMAC key before the next transition — the KEYEDHASH counterpart of
/// <see cref="TpmEccSignSequenceAction"/>/<see cref="TpmRsaSignSequenceAction"/> for Table 115's HMAC row
/// ("Signs/verifies the message"). Emitted by <c>TPM2_SignSequenceComplete()</c> once every gate has passed;
/// the effectful loop chains <see cref="Segments"/> and <see cref="TrailingBuffer"/> into one
/// <c>ReadOnlySequence{byte}</c> (<see cref="SequenceObjectState.BuildMessageSequence"/>), computes
/// <c>HMAC_hashAlg(bits, message)</c> through the registered HMAC seam — the message itself is the HMAC input;
/// no separate digest step exists for this scheme — and feeds the framed <c>TPMT_SIGNATURE</c> back as the
/// same <see cref="TpmSequenceSigned"/> input the asymmetric arms feed, whose continuation flushes the
/// sequence (<c>{F}</c>, TPM 2.0 Library Part 3, clause 20.6).
/// </summary>
/// <param name="SequenceHandle">The handle of the sequence being completed, so the continuation can flush the correct entry.</param>
/// <param name="Segments">The sequence's accumulated message, BORROWED from the live <see cref="SequenceObjectState"/> — the state remains their owner until the continuation flushes it; the effect only reads their octets to build the HMAC input.</param>
/// <param name="TrailingBuffer">The completing command's own final block (<c>buffer</c>), OWNED by this action and disposed by the effect once the HMAC has been computed over it.</param>
/// <param name="HashAlg">The sequence's own retained HMAC scheme hash algorithm, resolved from the key at <c>TPM2_SignSequenceStart()</c>.</param>
/// <param name="KeyBits">The HMAC key's sensitive value, borrowed from the LIVE loaded <see cref="KeyedHashObjectState"/> the completing command re-resolved under its own authorization — the <c>TPM_RC_SIGN_CONTEXT_KEY</c> Name gate has already forced it to be the key the sequence started under; the state remains its owner and the effect never disposes it.</param>
/// <param name="OverSessions">The session-authorized form's response framing — the command code rpHash folds, every slot's response-entry material, and the completed sequence to flush with the response (<c>{F}</c>, TPM 2.0 Library Part 1, clause 29.4.6) — or <see langword="null"/> on the password form, whose effect feeds the plain <see cref="TpmSequenceSigned"/> back instead.</param>
public sealed record TpmHmacSignSequenceAction(
    TpmiDhObject SequenceHandle,
    ImmutableList<Tpm2bMaxBuffer> Segments,
    Tpm2bMaxBuffer TrailingBuffer,
    TpmiAlgHash HashAlg,
    ReadOnlyMemory<byte> KeyBits,
    TpmOverSessionsFraming? OverSessions = null): TpmAction;

/// <summary>
/// Declares that the simulator must recompute a digest's HMAC under a loaded KEYEDHASH HMAC key and
/// constant-time compare it against a caller-supplied HMAC signature before the next transition — the
/// KEYEDHASH counterpart of <see cref="TpmVerifySignatureAction"/>/<see cref="TpmRsaVerifySignatureAction"/>
/// for Table 115's HMAC row. Emitted by the <c>TPM2_VerifySignature()</c> transition for a KEYEDHASH key —
/// the one verification that needs the key's SENSITIVE area loaded ("If keyHandle references a symmetric key,
/// both the public and private portions need to be loaded", TPM 2.0 Library Part 3, clause 20.2) — and fed
/// back as the same <see cref="TpmSignatureVerified"/> input the asymmetric arms feed: a mismatch is
/// <c>TPM_RC_SIGNATURE</c> with no ticket; a match mints <c>TPMT_TK_VERIFIED</c> over
/// <c>HMAC(proof, TPM_ST_VERIFIED || digest || keyName)</c>, with the NULL-hierarchy empty-hmac
/// short-circuit (clause 20.2.1).
/// </summary>
/// <param name="KeyName">The verifying key's Name, BORROWED from the live <see cref="KeyedHashObjectState"/>, folded into the minted ticket's HMAC; never disposed here.</param>
/// <param name="KeyHierarchy">The permanent hierarchy the verifying key was loaded under, from which its ticket proof re-derives — or, when <c>TPM_RH_NULL</c>, the short-circuit to the NULL ticket tuple.</param>
/// <param name="KeyBits">The HMAC key's sensitive value, borrowed from the live loaded <see cref="KeyedHashObjectState"/> — the state remains its owner and the effect never disposes it.</param>
/// <param name="Digest">The caller-supplied digest the signature is claimed to be over (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="Signature">The caller-supplied <c>TPMT_SIGNATURE</c> whose <c>TPMT_HA</c> member carries the claimed HMAC (TPM 2.0 Library Part 2, clause 11.3.6, Table 219), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="HashAlg">The hash algorithm carried inside the signature's <c>TPMT_HA</c> — already gated equal to the key's own scheme hash by the declaring transition (Part 4 <c>CryptHMACVerifySignature</c>'s consistency rule).</param>
public sealed record TpmHmacVerifySignatureAction(
    Tpm2bName KeyName,
    TpmiRhHierarchy KeyHierarchy,
    ReadOnlyMemory<byte> KeyBits,
    Tpm2bDigest Digest,
    TpmtSignature Signature,
    TpmiAlgHash HashAlg): TpmAction;

/// <summary>
/// Declares that the simulator must recompute the HMAC of an open verification sequence's accumulated message
/// under a loaded KEYEDHASH HMAC key and constant-time compare it against a caller-supplied HMAC signature
/// before the next transition — the KEYEDHASH counterpart of <see cref="TpmEccVerifySequenceAction"/>/
/// <see cref="TpmRsaVerifySequenceAction"/> for Table 115's HMAC row ("Signs/verifies the message"). Emitted by
/// <c>TPM2_VerifySequenceComplete()</c> once every gate has passed; the effectful loop chains
/// <see cref="Segments"/> into one <c>ReadOnlySequence{byte}</c> (with no trailing buffer — TPM 2.0 Library
/// Part 3, clause 20.3 carries none), computes <c>HMAC_hashAlg(bits, message)</c>, compares, and on success
/// mints the <c>TPM_ST_MESSAGE_VERIFIED</c> ticket over the RAW accumulated message (Part 2, clause 10.6.5) —
/// feeding the result back as the same <see cref="TpmSequenceSignatureVerified"/> input the asymmetric arms
/// feed, whose continuation flushes the sequence on success and leaves it untouched on <c>TPM_RC_SIGNATURE</c>.
/// </summary>
/// <param name="SequenceHandle">The handle of the sequence being completed, so the continuation can flush the correct entry on success.</param>
/// <param name="Segments">The sequence's accumulated message, BORROWED from the live <see cref="SequenceObjectState"/> — the state remains their owner on every arm; the effect only reads their octets to build the HMAC input and, on success, the raw ticket message.</param>
/// <param name="KeyName">The verifying key's Name, BORROWED from the live <see cref="KeyedHashObjectState"/>, folded into the minted ticket's HMAC; never disposed here.</param>
/// <param name="KeyHierarchy">The permanent hierarchy the verifying key was loaded under, from which its ticket proof re-derives — or, when <c>TPM_RH_NULL</c>, the short-circuit to the NULL ticket tuple.</param>
/// <param name="KeyBits">The HMAC key's sensitive value, borrowed from the live loaded <see cref="KeyedHashObjectState"/> — the state remains its owner and the effect never disposes it.</param>
/// <param name="HashAlg">The sequence's own retained HMAC scheme hash algorithm, resolved from the key at <c>TPM2_VerifySequenceStart()</c>.</param>
/// <param name="Signature">The caller-supplied <c>TPMT_SIGNATURE</c> whose <c>TPMT_HA</c> member carries the claimed HMAC (TPM 2.0 Library Part 2, clause 11.3.6, Table 219), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="OverSessions">The session-authorized form's response framing — the command code rpHash folds, every slot's response-entry material, and the completed sequence to flush with the response (<c>{F}</c>, TPM 2.0 Library Part 1, clause 29.4.6) — or <see langword="null"/> on the password form, whose effect feeds the plain <see cref="TpmSequenceSignatureVerified"/> back instead. A <c>TPM_RC_SIGNATURE</c> outcome keeps its header-only feedback on both forms, the sequence retained.</param>
public sealed record TpmHmacVerifySequenceAction(
    TpmiDhObject SequenceHandle,
    ImmutableList<Tpm2bMaxBuffer> Segments,
    Tpm2bName KeyName,
    TpmiRhHierarchy KeyHierarchy,
    ReadOnlyMemory<byte> KeyBits,
    TpmiAlgHash HashAlg,
    TpmtSignature Signature,
    TpmOverSessionsFraming? OverSessions = null): TpmAction;

/// <summary>
/// Declares that the simulator must extend a SHA-256 PCR register with every SHA-256 entry of a
/// <c>TPM2_PCR_Extend()</c> digest list before the next transition — <c>PCRnew = H(PCRold ‖ digest)</c> per
/// entry, in list order (TPM 2.0 Library Part 1, clause 14.2, equation 13; Part 3, clause 22.2.1). Emitted by
/// <c>OnPcrExtend</c> once the password, the <c>TPM_RH_NULL</c> short-circuit and the locality gate have passed
/// and at least one entry names the modelled bank. The effectful loop folds the register through the registered
/// digest seam and feeds the result back as a <see cref="TpmPcrExtended"/>, whose continuation installs it and
/// moves <c>pcrUpdateCounter</c>.
/// </summary>
/// <param name="PcrHandle">The register being extended.</param>
/// <param name="CurrentValue">The register's value when the command was dispatched, a reference into the immutable bank image — never disposed.</param>
/// <param name="Digests">The parsed digest list, OWNED by this action and disposed by the effect once every entry has been folded; an entry tagged for a bank other than SHA-256 is ignored (clause 22.2.1).</param>
public sealed record TpmPcrExtendAction(
    TpmiDhPcr PcrHandle,
    ReadOnlyMemory<byte> CurrentValue,
    TpmlDigestValues Digests): TpmAction;

/// <summary>
/// Declares that the simulator must digest an event under every implemented hash algorithm and, when a register
/// is named, extend the SHA-256 bank with the SHA-256 digest before the next transition — the effect
/// <c>TPM2_PCR_Event()</c> (TPM 2.0 Library Part 3, clause 22.3) and <c>TPM2_EventSequenceComplete()</c>
/// (clause 17.9) share, exactly as <see cref="TpmDigestAction"/> serves both <c>TPM2_SequenceComplete()</c> and
/// <c>TPM2_Hash()</c>. The message is the chained <see cref="Segments"/> followed by <see cref="TrailingBlock"/>
/// (<see cref="SequenceObjectState.BuildMessageSequence"/>): no segments and the whole <c>eventData</c> for the
/// one-shot command, the accumulated sequence and the command's <c>buffer</c> for the completing one. The effect
/// feeds back a <see cref="TpmPcrEventDigested"/>.
/// </summary>
/// <param name="SequenceHandle">The Event Sequence being completed, so the continuation can flush the correct entry; <see langword="null"/> for the one-shot <c>TPM2_PCR_Event()</c>.</param>
/// <param name="PcrHandle">The register to extend, or <c>TPM_RH_NULL</c> to only return the digests.</param>
/// <param name="CurrentValue">The register's value when the command was dispatched, a reference into the immutable bank image; <see langword="null"/> when <paramref name="PcrHandle"/> is <c>TPM_RH_NULL</c>.</param>
/// <param name="Segments">The sequence's accumulated message, BORROWED from the live <see cref="SequenceObjectState"/> — the state remains their owner until the continuation flushes it; empty for the one-shot command.</param>
/// <param name="TrailingBlock">The final block's octets — <c>TPM2_PCR_Event()</c>'s <c>eventData</c> or <c>TPM2_EventSequenceComplete()</c>'s <c>buffer</c> — a view into <paramref name="TrailingOwner"/>.</param>
/// <param name="TrailingOwner">The carrier owning <paramref name="TrailingBlock"/>'s octets (a <c>TPM2B_EVENT</c> or a <c>TPM2B_MAX_BUFFER</c>), OWNED by this action and disposed by the effect once the digests have been computed over it.</param>
public sealed record TpmPcrEventAction(
    TpmiDhObject? SequenceHandle,
    TpmiDhPcr PcrHandle,
    ReadOnlyMemory<byte>? CurrentValue,
    ImmutableList<Tpm2bMaxBuffer> Segments,
    ReadOnlyMemory<byte> TrailingBlock,
    IDisposable TrailingOwner): TpmAction;

/// <summary>
/// Declares that the simulator must hash the accumulated message of an open verification sequence and verify it
/// against a retained ECC key's public point before the next transition — the sequence-command counterpart of
/// <see cref="TpmVerifyDigestSignatureAction"/>. Emitted by <c>TPM2_VerifySequenceComplete()</c> once every gate
/// has passed; the effectful loop chains <see cref="Segments"/> into one <c>ReadOnlySequence{byte}</c>
/// (<see cref="SequenceObjectState.BuildMessageSequence"/>, with no trailing buffer — clause 20.3 carries none),
/// hashes it through the registered digest seam under <see cref="HashAlg"/>, calls the injected
/// <see cref="TpmEccSigningBackend"/>'s verify delegate, and on success mints the <c>TPM_ST_MESSAGE_VERIFIED</c>
/// ticket over the RAW accumulated message rather than its digest (TPM 2.0 Library Part 2, clause 10.6.5; Part
/// 3, clause 20.3.1) — feeding the result back as a <see cref="TpmSequenceSignatureVerified"/> input, whose
/// continuation flushes the sequence on success (<c>{F}</c>, clause 4.2.7) and leaves it untouched on a
/// rejection (clause 20.3: "the TPM shall return TPM_RC_SIGNATURE").
/// </summary>
/// <param name="SequenceHandle">The handle of the sequence being completed, so the continuation can flush the correct entry on success.</param>
/// <param name="Segments">The sequence's accumulated message, BORROWED from the live <see cref="SequenceObjectState"/> — the state remains their owner on every arm; the effect only reads their octets to build the hash input and, on success, the raw ticket message.</param>
/// <param name="KeyName">The verifying key's Name, BORROWED from the live <see cref="TransientKeyState"/>, folded into the minted ticket's HMAC.</param>
/// <param name="KeyHierarchy">The permanent hierarchy the verifying key was created under, from which its ticket proof re-derives — or, when <c>TPM_RH_NULL</c>, the short-circuit to the NULL ticket tuple.</param>
/// <param name="KeyNameAlg">The verifying key's public-area <c>nameAlg</c>: <c>TPM_ALG_NULL</c> is a second, independent trigger for the NULL-ticket short-circuit alongside <see cref="KeyHierarchy"/> being <c>TPM_RH_NULL</c> (TPM 2.0 Library Part 3, clause 12.3.1).</param>
/// <param name="PublicPoint">The verifying key's retained public point, SEC1 uncompressed.</param>
/// <param name="Curve">The ECC curve the public point lives on.</param>
/// <param name="HashAlg">The sequence's own accumulator and signature hash algorithm, resolved at <c>TPM2_VerifySequenceStart()</c>.</param>
/// <param name="Signature">The caller-supplied <c>TPMT_SIGNATURE</c> (TPM 2.0 Library Part 2, clause 11.3.6, Table 219), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="OverSessions">The session-authorized form's response framing — the command code rpHash folds, every slot's response-entry material, and the completed sequence to flush with the response (<c>{F}</c>, TPM 2.0 Library Part 1, clause 29.4.6) — or <see langword="null"/> on the password form, whose effect feeds the plain <see cref="TpmSequenceSignatureVerified"/> back instead. A <c>TPM_RC_SIGNATURE</c> outcome keeps its header-only feedback on both forms, the sequence retained.</param>
public sealed record TpmEccVerifySequenceAction(
    TpmiDhObject SequenceHandle,
    ImmutableList<Tpm2bMaxBuffer> Segments,
    Tpm2bName KeyName,
    TpmiRhHierarchy KeyHierarchy,
    TpmiAlgHash KeyNameAlg,
    ReadOnlyMemory<byte> PublicPoint,
    TpmiEccCurve Curve,
    TpmiAlgHash HashAlg,
    TpmtSignature Signature,
    TpmOverSessionsFraming? OverSessions = null): TpmAction;

/// <summary>
/// The RSA counterpart of <see cref="TpmEccVerifySequenceAction"/>: verify the accumulated message's digest
/// against a retained RSA key's public modulus and exponent, read from its retained public area, under the
/// sequence's own retained scheme, and on success mint the <c>TPM_ST_MESSAGE_VERIFIED</c> ticket the same way.
/// </summary>
/// <param name="SequenceHandle">The handle of the sequence being completed, so the continuation can flush the correct entry on success.</param>
/// <param name="Segments">The sequence's accumulated message, BORROWED from the live <see cref="SequenceObjectState"/> — the state remains their owner on every arm; the effect only reads their octets to build the hash input and, on success, the raw ticket message.</param>
/// <param name="KeyName">The verifying key's Name, BORROWED from the live <see cref="TransientKeyState"/>, folded into the minted ticket's HMAC.</param>
/// <param name="KeyHierarchy">The permanent hierarchy the verifying key was created under, from which its ticket proof re-derives — or, when <c>TPM_RH_NULL</c>, the short-circuit to the NULL ticket tuple.</param>
/// <param name="KeyNameAlg">The verifying key's public-area <c>nameAlg</c>: <c>TPM_ALG_NULL</c> is a second, independent trigger for the NULL-ticket short-circuit alongside <see cref="KeyHierarchy"/> being <c>TPM_RH_NULL</c> (TPM 2.0 Library Part 3, clause 12.3.1).</param>
/// <param name="Modulus">The verifying key's public modulus, BORROWED from its retained public area's <c>unique</c> (a view into the durable object state's own <c>Tpm2bPublic</c>; the effect never disposes it).</param>
/// <param name="Exponent">The verifying key's public exponent, resolved from its retained public area's parameters (zero already resolved to the default 65537, TPM 2.0 Library Part 2, Table 228's wire convention).</param>
/// <param name="Scheme">The sequence's own retained RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>).</param>
/// <param name="HashAlg">The sequence's own accumulator and signature hash algorithm, resolved at <c>TPM2_VerifySequenceStart()</c>.</param>
/// <param name="Signature">The caller-supplied <c>TPMT_SIGNATURE</c> (TPM 2.0 Library Part 2, clause 11.3.6, Table 219), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="OverSessions">The session-authorized form's response framing — the command code rpHash folds, every slot's response-entry material, and the completed sequence to flush with the response (<c>{F}</c>, TPM 2.0 Library Part 1, clause 29.4.6) — or <see langword="null"/> on the password form, whose effect feeds the plain <see cref="TpmSequenceSignatureVerified"/> back instead. A <c>TPM_RC_SIGNATURE</c> outcome keeps its header-only feedback on both forms, the sequence retained.</param>
public sealed record TpmRsaVerifySequenceAction(
    TpmiDhObject SequenceHandle,
    ImmutableList<Tpm2bMaxBuffer> Segments,
    Tpm2bName KeyName,
    TpmiRhHierarchy KeyHierarchy,
    TpmiAlgHash KeyNameAlg,
    ReadOnlyMemory<byte> Modulus,
    uint Exponent,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash HashAlg,
    TpmtSignature Signature,
    TpmOverSessionsFraming? OverSessions = null): TpmAction;

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
/// Library Part 2, clause 10.3.2, Table 90; empty for the generic storage parent; a standard endorsement
/// key's "PolicyA" otherwise), the owned pooled carrier the request parsed; ownership rides this action into
/// the effect, which installs it on the durable parent state.
/// </param>
/// <param name="UserAuth">The new object's authorization value (<c>inSensitive.userAuth</c>), the owned <see cref="Tpm2bAuth"/> carrier the request parsed; ownership rides this action into the effect, which installs it on the durable parent state. The dispose-immune empty sentinel for an authValue-free parent.</param>
/// <param name="OutsideInfo">The <c>outsideInfo</c> parameter, included in the creation data (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2, clause 10.3.3, Table 91; Part 3, clause 24.1, Table 191, <c>outsideInfo</c> row), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="CreationPcr">The <c>creationPCR</c> parameter the creation data's <c>pcrDigest</c> is computed over (<c>TPML_PCR_SELECTION</c>, TPM 2.0 Library Part 2, clause 10.8.7, Table 128; Part 3, clause 24.1, Table 191, <c>creationPCR</c> row), already filtered to the implemented banks and registers by the declaring transition (<c>RetainImplementedPcrs</c>) — the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="CreationPcrValues">The FILTERED <see cref="CreationPcr"/>'s own register values, gathered from the durable PCR bank in selector order by the declaring transition (<c>GatherSelectedPcrValues</c>) — the same shape <c>TPM2_Quote()</c>'s <see cref="TpmQuoteAction.PcrValues"/> carries; the effect concatenates and hashes them into the creation data's <c>pcrDigest</c> under the object's own nameAlg (Part 2, clause 15.1, Table 261).</param>
public sealed record TpmCreateStorageParentAction(
    TpmiDhObject Handle,
    TpmiRhHierarchy Hierarchy,
    TpmiAlgHash NameAlg,
    TpmaObject Attributes,
    TpmiEccCurve Curve,
    bool NoDa,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth UserAuth,
    Tpm2bData OutsideInfo,
    TpmlPcrSelection CreationPcr,
    ImmutableArray<ReadOnlyMemory<byte>> CreationPcrValues): TpmAction;

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
/// Library Part 2, clause 10.3.2, Table 90; empty for a generic RSA storage parent; a standard RSA
/// endorsement key's "PolicyA" otherwise), the owned pooled carrier the request parsed; ownership rides this
/// action into the effect, which installs it on the durable parent state.
/// </param>
/// <param name="UserAuth">The new object's authorization value (<c>inSensitive.userAuth</c>), the owned <see cref="Tpm2bAuth"/> carrier the request parsed; ownership rides this action into the effect, which installs it on the durable parent state. The dispose-immune empty sentinel for an authValue-free parent.</param>
/// <param name="OutsideInfo">The <c>outsideInfo</c> parameter, included in the creation data (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2, clause 10.3.3, Table 91; Part 3, clause 24.1, Table 191, <c>outsideInfo</c> row), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="CreationPcr">The <c>creationPCR</c> parameter the creation data's <c>pcrDigest</c> is computed over (<c>TPML_PCR_SELECTION</c>, TPM 2.0 Library Part 2, clause 10.8.7, Table 128; Part 3, clause 24.1, Table 191, <c>creationPCR</c> row), already filtered to the implemented banks and registers by the declaring transition (<c>RetainImplementedPcrs</c>) — the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="CreationPcrValues">The FILTERED <see cref="CreationPcr"/>'s own register values, gathered from the durable PCR bank in selector order by the declaring transition (<c>GatherSelectedPcrValues</c>) — the same shape <c>TPM2_Quote()</c>'s <see cref="TpmQuoteAction.PcrValues"/> carries; the effect concatenates and hashes them into the creation data's <c>pcrDigest</c> under the object's own nameAlg (Part 2, clause 15.1, Table 261).</param>
public sealed record TpmCreateRsaStorageParentAction(
    TpmiDhObject Handle,
    TpmiRhHierarchy Hierarchy,
    TpmiAlgHash NameAlg,
    TpmaObject Attributes,
    TpmiRsaKeyBits KeyBits,
    bool NoDa,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth UserAuth,
    Tpm2bData OutsideInfo,
    TpmlPcrSelection CreationPcr,
    ImmutableArray<ReadOnlyMemory<byte>> CreationPcrValues): TpmAction;

/// <summary>
/// Declares that the simulator must create a KEYEDHASH object — a sealed data object around caller-supplied
/// data, or an HMAC key around a caller-supplied or TPM-generated key value — before the next transition.
/// Emitted by the <c>TPM2_Create()</c> transition; the effectful loop builds the wrapped private blob, the
/// exported public area, and the creation by-products through the registered digest and HMAC seams, and feeds
/// them back as a <see cref="TpmKeyedHashCreated"/> input (TPM 2.0 Library Part 3, clause 12.1).
/// </summary>
/// <param name="ParentHandle">The storage parent the object is sealed under, resolved by the declaring transition to authorize the seal; the creation data's <c>parentName</c>/<c>parentQualifiedName</c> instead come from <see cref="ParentName"/> (TPM 2.0 Library Part 2, clause 15.1, Table 261).</param>
/// <param name="ParentHierarchy">
/// The hierarchy the storage parent belongs to, which is the hierarchy the created object belongs to and so the
/// one the creation ticket names and whose proof keys its HMAC (<c>TPMI_RH_HIERARCHY+</c>, TPM 2.0 Library
/// Part 2, clause 10.6.3, Table 110: "the hierarchy containing name"; Part 4's <c>TPM2_Create()</c> computes
/// the ticket over <c>EntityGetHierarchy(parentHandle)</c>). Distinct from <see cref="ParentHandle"/>, which
/// binds the creation DATA.
/// </param>
/// <param name="NameAlg">The Name algorithm to carry in the exported public area.</param>
/// <param name="AuthPolicy">The authorization policy digest to re-emit into the exported public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90; empty for an authValue-only seal), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner and releases it in its <c>finally</c> — <c>TPM2_Create()</c> installs no durable object, so the copy the exported public area takes is the digest's only use.</param>
/// <param name="NoDa">Whether the template set <c>TPMA_OBJECT.noDA</c>, so the exported public area reproduces the caller's template.</param>
/// <param name="UserWithAuth">Whether the template set <c>TPMA_OBJECT.userWithAuth</c>, so the exported public area reproduces the caller's template.</param>
/// <param name="IsDuplicable">Whether the caller's template carries <c>TPMA_OBJECT.fixedTPM</c> and <c>fixedParent</c> CLEAR — the declaring transition has already judged the clause 8.3.3 consistency rows, so this one bit reproduces the caller's duplicability choice on the exported public area (TPM 2.0 Library Part 2, clause 8.3.2, Table 37).</param>
/// <param name="SecretData">The data to seal, the owned <see cref="Tpm2bSensitiveData"/> carrier the request parsed; ownership rides this action into the effect, which packs it into the wrapped private blob and releases it.</param>
/// <param name="UserAuth">The new object's authorization value, the owned <see cref="Tpm2bAuth"/> carrier the request parsed; ownership rides this action into the effect, which packs it into the wrapped private blob alongside <see cref="SecretData"/> and releases it (TPM 2.0 Library Part 1, clause 16.6.4).</param>
/// <param name="OutsideInfo">The <c>outsideInfo</c> parameter, included in the creation data (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2, clause 10.3.3, Table 91; Part 3, clause 12.1, Table 18, <c>outsideInfo</c> row), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="CreationPcr">The <c>creationPCR</c> parameter the creation data's <c>pcrDigest</c> is computed over (<c>TPML_PCR_SELECTION</c>, TPM 2.0 Library Part 2, clause 10.8.7, Table 128; Part 3, clause 12.1, Table 18, <c>creationPCR</c> row), already filtered to the implemented banks and registers by the declaring transition (<c>RetainImplementedPcrs</c>) — the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="CreationPcrValues">The FILTERED <see cref="CreationPcr"/>'s own register values, gathered from the durable PCR bank in selector order by the declaring transition (<c>GatherSelectedPcrValues</c>) — the same shape <c>TPM2_Quote()</c>'s <see cref="TpmQuoteAction.PcrValues"/> carries; the effect concatenates and hashes them into the creation data's <c>pcrDigest</c> under the object's own nameAlg (Part 2, clause 15.1, Table 261).</param>
/// <param name="ParentName">The parent's own Name (<c>TPM2B_NAME</c>), the creation data's <c>parentName</c> row for a loaded (non-hierarchy) parent (TPM 2.0 Library Part 2, clause 15.1, Table 261) — a BORROWED reference to the carrier the parent's durable <see cref="TransientKeyState"/> owns; the parent's state outlives this action for the duration of the one <c>SubmitAsync</c> call that resolved it, so neither this action nor its effect ever disposes it.</param>
/// <param name="ParentSeedValue">The parent's symmetric protection seed (<c>TPMT_SENSITIVE.seedValue</c>, TPM 2.0 Library Part 2, clause 12.3.2, Table 240), from which the child blob's symmetric and HMAC keys derive (Part 1, Clause 19, equations 33 and 35) — a BORROWED reference to the carrier the parent's durable <see cref="TransientKeyState"/> owns, exactly as <see cref="ParentName"/> is; neither this action nor its effect ever disposes it.</param>
/// <param name="ParentNameAlg">The parent's own Name algorithm, read from its Name's two-octet prefix by the declaring transition; it keys and sizes the wrap's KDFa derivations and the outer HMAC (Part 1, Clause 19 — <c>pNameAlg</c>, never the child's).</param>
/// <param name="ShouldGenerateSensitiveBits">Whether the effect draws the sensitive value from the RNG instead of copying <see cref="SecretData"/> — <c>sensitiveDataOrigin</c> SET on a signing or decryption KEYEDHASH key (TPM 2.0 Library Part 3, clause 12.1, keyedHash rule 4).</param>
/// <param name="GeneratedBitsLength">The octet count the effect draws when <see cref="ShouldGenerateSensitiveBits"/> is set — the digest size of <see cref="NameAlg"/> (Part 3, clause 12.1, keyedHash rule 4; Part 1, clause 24.7.5.1); zero otherwise.</param>
/// <param name="TemplateAttributes">The template's exact <c>TPMA_OBJECT</c> word (<see cref="TpmaObject"/>, TPM 2.0 Library Part 2, clause 8.3.2, Table 37), echoed verbatim into the exported public area (Part 3, clause 12.1: <c>outPublic</c> is the template with <c>unique</c> filled).</param>
/// <param name="KeyedHashScheme">The template's <c>TPMT_KEYEDHASH_SCHEME</c> (<see cref="TpmsKeyedHashParms"/>, Part 2, Table 227), echoed verbatim into the exported public area alongside <see cref="TemplateAttributes"/>.</param>
public sealed record TpmCreateKeyedHashAction(
    TpmiDhObject ParentHandle,
    TpmiRhHierarchy ParentHierarchy,
    TpmiAlgHash NameAlg,
    Tpm2bDigest AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    bool IsDuplicable,
    Tpm2bSensitiveData SecretData,
    Tpm2bAuth UserAuth,
    Tpm2bData OutsideInfo,
    TpmlPcrSelection CreationPcr,
    ImmutableArray<ReadOnlyMemory<byte>> CreationPcrValues,
    Tpm2bName ParentName,
    Tpm2bDigest ParentSeedValue,
    TpmiAlgHash ParentNameAlg,
    bool ShouldGenerateSensitiveBits,
    int GeneratedBitsLength,
    TpmaObject TemplateAttributes,
    TpmsKeyedHashParms KeyedHashScheme): TpmAction;

/// <summary>
/// Declares that the simulator must compute a loaded object's Name before the next transition. Emitted by the
/// <c>TPM2_Load()</c> transition; the effectful loop computes <c>nameAlg ‖ H(TPMT_PUBLIC)</c> through the
/// registered digest seam and feeds it back with the recovered sealed data as a <see cref="TpmObjectLoaded"/>
/// input (TPM 2.0 Library Part 3, clause 12.2; Part 1, clause 13, Table 9).
/// </summary>
/// <param name="Handle">The transient handle the transition allocated for the loaded object.</param>
/// <param name="ParentHierarchy">The Storage Parent's permanent hierarchy (<c>TPMI_RH_HIERARCHY</c>), which the loaded object joins — its ancestors connect it to that hierarchy's Primary Seed (TPM 2.0 Library Part 1, clause 20.2) — threaded through to the loaded object's state so a hierarchy sweep can evict it with the parent (Part 1, clause 27.4).</param>
/// <param name="NameAlg">The Name algorithm to compute the object Name with.</param>
/// <param name="AuthPolicy">The authorization policy digest carried in the loaded public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90; empty for an authValue-only object), the owned pooled carrier the request parsed; ownership rides this action into the effect, which threads it onto the loaded object's state.</param>
/// <param name="NoDa">Whether the loaded public area sets <c>TPMA_OBJECT.noDA</c>, threaded through to the loaded object's state.</param>
/// <param name="UserWithAuth">Whether the loaded public area sets <c>TPMA_OBJECT.userWithAuth</c>, threaded through to the loaded object's state.</param>
/// <param name="IsDuplicable">Whether the loaded public area carries <c>TPMA_OBJECT.fixedParent</c> CLEAR, threaded through to the loaded object's state so a later <c>TPM2_Duplicate()</c> can judge it (TPM 2.0 Library Part 2, clause 8.3.2, Table 37).</param>
/// <param name="InPublic">The public area the caller supplied (<c>TPM2B_PUBLIC</c>, TPM 2.0 Library Part 2, clause 12.2.5, Table 236), whose marshaled <c>TPMT_PUBLIC</c> the Name is hashed over — the owned pooled carrier the request parsed; ownership rides this action into the effect, which hands it on whole as the loaded object's own public area (to the stored state on success, to the refusing input's Dispose otherwise).</param>
/// <param name="PrivateBlob">The wrapped private blob to recover the authorization value and the sealed data from — the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner once the authorization value and secret data are recovered from it.</param>
/// <param name="ParentSeedValue">The parent's symmetric protection seed (<c>TPMT_SENSITIVE.seedValue</c>, TPM 2.0 Library Part 2, clause 12.3.2, Table 240), from which the blob's symmetric and HMAC keys re-derive for integrity verification and decryption (Part 1, Clause 19, equations 33 and 35) — a BORROWED reference to the carrier the parent's durable <see cref="TransientKeyState"/> owns; neither this action nor its effect ever disposes it.</param>
/// <param name="ParentNameAlg">The parent's own Name algorithm, read from its Name's two-octet prefix by the declaring transition; it keys and sizes the unwrap's KDFa derivations and the outer-HMAC check (Part 1, Clause 19 — <c>pNameAlg</c>, never the child's).</param>
/// <param name="ParentQualifiedName">The parent's Qualified Name, the ancestor term the loaded object's own Qualified Name chains from — <c>QN = H_nameAlg(QN_parent ‖ Name)</c> (TPM 2.0 Library Part 1, clause 23.5) — a BORROWED reference to the carrier the parent's durable <see cref="TransientKeyState"/> owns, exactly like <paramref name="ParentSeedValue"/>; neither this action nor its effect ever disposes it.</param>
public sealed record TpmLoadObjectAction(
    TpmiDhObject Handle,
    TpmiRhHierarchy ParentHierarchy,
    TpmiAlgHash NameAlg,
    Tpm2bDigest AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    bool IsDuplicable,
    Tpm2bPublic InPublic,
    Tpm2bPrivate PrivateBlob,
    Tpm2bDigest ParentSeedValue,
    TpmiAlgHash ParentNameAlg,
    Tpm2bName ParentQualifiedName): TpmAction;

/// <summary>
/// Declares that the simulator must run <c>TPM2_LoadExternal()</c>'s public/private key-pair consistency checks
/// (TPM 2.0 Library Part 3, clause 12.3.1; Part 4 <c>CryptValidateKeys</c>) and build the loaded object's
/// model record before the next transition. Emitted once every transition-time gate (hierarchy, attribute, and
/// scheme validation) has passed and a free object slot was confirmed; the effect is the terminal owner of
/// <see cref="InPrivate"/> and <see cref="InPublic"/> on every path — TRANSFERRED into the built object record
/// on success, released directly on a cryptographic refusal.
/// </summary>
/// <param name="InPrivate">The caller-supplied sensitive area, or <see langword="null"/> for a public-only load — TRANSFERRED from the accepted request.</param>
/// <param name="InPublic">The public area to load — TRANSFERRED from the accepted request; the effect hands it on whole as the loaded object's own public area.</param>
/// <param name="Hierarchy">The validated hierarchy the loaded object joins (<c>TPM_RH_NULL</c> admitted).</param>
/// <param name="Handle">The transient handle the transition allocated for the loaded object.</param>
/// <param name="Request">The parsed request the resuming transition frames a response for (<see cref="TpmLoadExternalRequested"/>, threaded through unread by the effect itself).</param>
public sealed record TpmLoadExternalAction(
    TpmtSensitive? InPrivate,
    Tpm2bPublic InPublic,
    TpmiRhHierarchy Hierarchy,
    TpmiDhObject Handle,
    TpmSimulatorInput Request): TpmAction;

/// <summary>
/// Declares that the simulator must serialize, fingerprint, encrypt, and integrity-protect a
/// <c>TPM2_ContextSave()</c> resource into a <c>TPMS_CONTEXT</c> before the next transition (TPM 2.0 Library
/// Part 1, clauses 27.3.1 and 27.3.2). Emitted once the transition has resolved the handle against the five
/// loaded-resource tables and stamped its metadata; the effect is never the resource's owner.
/// </summary>
/// <param name="Resource">The resource to save — BORROWED from whichever dictionary the transition found it in (or, for a session, the record the transition is about to remove and dispose itself on success); the effect reads it and never disposes it.</param>
/// <param name="SavedHandle">The <c>savedHandle</c> metadata value (<c>TPMI_DH_SAVED</c>, TPM 2.0 Library Part 2, clause 9.12, Table 58) — a fixed object-kind constant, or the session's own handle.</param>
/// <param name="Hierarchy">The context's hierarchy metadata (<c>TPMI_RH_HIERARCHY+</c>) — the object's own hierarchy, or <c>TPM_RH_NULL</c> for a session or sequence.</param>
/// <param name="Sequence">The context's sequence number, already drawn from <see cref="TpmSimulatorState.ObjectContextId"/> or <see cref="TpmSimulatorState.SessionContextCounter"/> and burned into the state whether or not this effect ultimately succeeds.</param>
/// <param name="IsStClear">Whether <paramref name="SavedHandle"/> is the <c>stClear</c> Transient Object arm (<see cref="Spec.Handles.TpmiDhSaved.StClearTransientObject"/>) — folds <see cref="ClearCount"/> into the integrity HMAC when set (TPM 2.0 Library Part 1, clause 27.3.2: "This value is only included if the handle value is 80 00 00 0216").</param>
/// <param name="TotalResetCount">The Reset epoch (<see cref="TpmSimulatorState.TotalResetCount"/>) folded into both the confidentiality key derivation and the integrity HMAC's <c>resetValue</c> term.</param>
/// <param name="ClearCount">The Restart epoch (<see cref="TpmSimulatorState.ClearCount"/>), read only when <see cref="IsStClear"/> is set.</param>
/// <param name="Request">The parsed request the resuming transition frames a response for.</param>
public sealed record TpmContextSaveAction(
    TpmContextResource Resource,
    TpmiDhSaved SavedHandle,
    TpmiRhHierarchy Hierarchy,
    ulong Sequence,
    bool IsStClear,
    ulong TotalResetCount,
    uint ClearCount,
    TpmSimulatorInput Request): TpmAction;

/// <summary>
/// Declares that the simulator must decrypt, integrity-verify, and deserialize a <c>TPM2_ContextLoad()</c>
/// <c>TPMS_CONTEXT</c> before the next transition (TPM 2.0 Library Part 3, clause 28.3.1; Part 1, clauses
/// 27.3.1 and 27.3.2). Emitted once <c>OnContextLoad</c>'s pre-effect sequence-range gates (clause 14.6.1) have
/// passed; the effect is <see cref="Context"/>'s terminal owner.
/// </summary>
/// <param name="Context">The parsed <c>TPMS_CONTEXT</c> — TRANSFERRED from the accepted <see cref="TpmContextLoadRequested"/>; the effect disposes it once every field it needs has been read out.</param>
/// <param name="TotalResetCount">The Reset epoch (<see cref="TpmSimulatorState.TotalResetCount"/>) folded into both the confidentiality key derivation and the integrity HMAC's <c>resetValue</c> term — this TPM's own current value, read at declare time so a save-then-load within one command still binds to the same epoch.</param>
/// <param name="ClearCount">The Restart epoch (<see cref="TpmSimulatorState.ClearCount"/>), read only when <see cref="Structures.TpmsContext.SavedHandle"/> is the <c>stClear</c> Transient Object arm.</param>
/// <param name="Request">The parsed request the resuming transition frames a response for.</param>
public sealed record TpmContextLoadAction(
    TpmsContext Context,
    ulong TotalResetCount,
    uint ClearCount,
    TpmSimulatorInput Request): TpmAction;

/// <summary>
/// Declares that the simulator must export a loaded sealed object's sensitive area under the duplication
/// protections before the next transition (TPM 2.0 Library Part 3, clause 13.1; Part 1, Clause 20). Emitted by
/// the <c>TPM2_Duplicate()</c> transition once the DUP-role policy session and every attribute gate have
/// passed; the effectful loop rebuilds the marshaled <c>TPM2B_SENSITIVE</c>, protects it to the new parent — a
/// fresh seed transported by ephemeral ECDH-and-KDFe or RSA-OAEP under the "DUPLICATE" label, then the outer
/// wrap's zero-IV encryption and Name-bound HMAC — and feeds the blob and the protected seed back as a
/// <see cref="TpmObjectDuplicated"/> input. A <c>TPM_RH_NULL</c> new parent skips every protection: the
/// duplicate is the bare marshaled sensitive area (Part 1, Clause 20's no-wrapper form).
/// </summary>
/// <param name="ObjectName">The duplicated object's Name — a BORROWED reference to the carrier the durable <see cref="KeyedHashObjectState"/> owns; the object outlives this action for the one <c>SubmitAsync</c> call that resolved it, so neither this action nor its effect ever disposes it.</param>
/// <param name="ObjectNameAlg">The duplicated object's own Name algorithm, read from its Name's two-octet prefix by the declaring transition.</param>
/// <param name="UserAuth">The object's authorization value — a BORROWED reference to the durable state's carrier, re-padded to its maximum size in the marshaled sensitive area (Part 1, clause 24.7.3); never disposed here.</param>
/// <param name="SeedValue">The object's own protection seed (its obfuscation value) — a BORROWED reference to the durable state's carrier; never disposed here.</param>
/// <param name="Data">The sealed data — a BORROWED reference to the durable state's carrier; never disposed here.</param>
/// <param name="HasNewParent">Whether a new parent was named; CLEAR means <c>TPM_RH_NULL</c> and the bare-sensitive form.</param>
/// <param name="NewParentNameAlg">The new parent's Name algorithm (<c>npNameAlg</c>), keying and sizing every outer-wrap derivation; meaningful only when <see cref="HasNewParent"/> is set.</param>
/// <param name="NewParentKeyType">The new parent's asymmetric algorithm, selecting the seed-transport arm; meaningful only when <see cref="HasNewParent"/> is set.</param>
/// <param name="NewParentCurve">The new parent's ECC curve for the ECDH transport; meaningful only for an elliptic-curve new parent.</param>
/// <param name="NewParentPublicPoint">The new parent's SEC1 uncompressed public point for the ECDH transport — a borrowed reference; empty for an RSA new parent.</param>
/// <param name="NewParentModulus">The new parent's public modulus for the RSA-OAEP transport — a BORROWED reference to the durable state's carrier; the dispose-immune empty sentinel for an elliptic-curve new parent.</param>
public sealed record TpmDuplicateObjectAction(
    Tpm2bName ObjectName,
    TpmiAlgHash ObjectNameAlg,
    Tpm2bAuth UserAuth,
    Tpm2bDigest SeedValue,
    Tpm2bSensitiveData Data,
    bool HasNewParent,
    TpmiAlgHash NewParentNameAlg,
    TpmiAlgPublic NewParentKeyType,
    TpmiEccCurve NewParentCurve,
    ReadOnlyMemory<byte> NewParentPublicPoint,
    Tpm2bPublicKeyRsa NewParentModulus): TpmAction;

/// <summary>
/// Declares that the simulator must rewrap a TPM-resident object's sensitive area under a new authorization
/// value before the next transition (TPM 2.0 Library Part 3, clause 12.8; Part 1, clauses 19 and 24.7.3).
/// Emitted by the <c>TPM2_ObjectChangeAuth()</c> transition once the ADMIN-role authorization ladder (Part 3,
/// clause 5.6) has cleared and <see cref="NewAuth"/> has passed its Name-algorithm width rule; the effectful
/// loop recomputes the object's Qualified Name chained from <see cref="Parent"/>'s and compares it, fixed-time,
/// to the object's own retained one — the one gate the command applies to <c>parentHandle</c> (clause 12.8.1),
/// refusing a Primary Object, an external object, a mismatched parent, or a parent that is no Storage Parent
/// alike with <c>TPM_RC_TYPE</c> — then wraps a fresh <c>TPMT_SENSITIVE</c> (the object's retained
/// <c>seedValue</c>/<c>bits</c> alongside the new authorization value) under the parent's protection seed, and
/// feeds the blob back as a <see cref="TpmObjectAuthChanged"/> input, or — over an HMAC session — frames the
/// response directly through the shared over-sessions machinery.
/// </summary>
/// <param name="ObjectName">The object's Name — a BORROW of the durable record's carrier; the recomputation's <c>Name</c> term and the wrap's integrity binding.</param>
/// <param name="ObjectQualifiedName">The object's retained Qualified Name, the recomputation's comparand — a BORROW of the durable record's carrier.</param>
/// <param name="ObjectNameAlg">The object's Name algorithm: the recomputation's hash (Part 1, clause 23.5's <c>H_nameAlg</c>).</param>
/// <param name="SealedObject">The object as a re-wrappable KEYEDHASH record — a BORROW of the durable <see cref="KeyedHashObjectState"/>, never disposed or mutated here (clause 12.8.1: "This command does not change the TPM-resident object") — or <see langword="null"/> when <c>objectHandle</c> named an asymmetric object (a Primary, or one <c>TPM2_LoadExternal()</c> loaded), whose recomputation can only mismatch: the compare still runs so the refusal is the clause's own <c>TPM_RC_TYPE</c>, and a match is unreachable and fails closed to the same code.</param>
/// <param name="Parent">The object at <c>parentHandle</c> — a BORROW of the durable <see cref="TransientKeyState"/>; its Qualified Name is the recomputation's ancestor term, and its protection seed keys the wrap once the compare has proved it the parent.</param>
/// <param name="ParentNameAlg">The parent's Name algorithm (<c>pNameAlg</c>), keying and sizing the wrap's derivations and HMAC.</param>
/// <param name="NewAuth">The replacement authorization value (<c>newAuth</c>, <c>TPM2B_AUTH</c>) in an owned carrier TRANSFERRED from the parsed request; the effect wraps its raw (un-stripped) octets into the new private area exactly as the <c>TPM2_Create()</c> wrap pads a caller-supplied <c>userAuth</c> (Part 2, clause 12.3.7's "the TPM pads the TPM2B_AUTH to its maximum size"), then releases it.</param>
/// <param name="ResponseSessions">The ADMIN slot's response-session material the completing framer needs: empty for a password or a policy session, whose completion frames no response-session entry at all (mirroring <c>TPM2_Duplicate()</c>'s own DUP-role slot, which likewise never earns one), or exactly one real entry for an HMAC session, keyed on the object's own (unrotated) authValue — "the old authValue... is used when generating the response HMAC key" (clause 12.8.1) — its caller nonce TRANSFERRED into the entry and released by the effect.</param>
/// <param name="Request">The original parsed request, its carriers already released by the declaring transition, threaded through to the plain completion's feedback.</param>
public sealed record TpmObjectChangeAuthAction(
    Tpm2bName ObjectName,
    Tpm2bName ObjectQualifiedName,
    TpmiAlgHash ObjectNameAlg,
    KeyedHashObjectState? SealedObject,
    TransientKeyState Parent,
    TpmiAlgHash ParentNameAlg,
    Tpm2bAuth NewAuth,
    ImmutableArray<TpmResponseSession> ResponseSessions,
    TpmSimulatorInput Request): TpmAction;

/// <summary>
/// Declares that the simulator must RSA-encrypt a message to a loaded key's public modulus before the next
/// transition (TPM 2.0 Library Part 3, clause 14.2). Emitted by the <c>TPM2_RSA_Encrypt()</c> transition —
/// reached on both its <c>TPM_ST_NO_SESSIONS</c> form and, once the no-authorization wrapper's authorization
/// area has verified, its routed <c>TPM_ST_SESSIONS</c> form — once the handle, label and Table 42
/// scheme-selection rules have cleared; the effectful loop pads and encrypts <see cref="Message"/> under
/// <see cref="SelectedScheme"/> through the injected <see cref="TpmRsaSigningBackend"/> and feeds the ciphertext
/// back as a <see cref="TpmRsaEncrypted"/> input. A routed success is reframed with sessions afterward by the
/// wrapper's own completion hook, over the plain response that feedback declares.
/// </summary>
/// <param name="Key">The RSA key to encrypt under — a BORROW of the durable <see cref="TransientKeyState"/>; the effect reads its retained public modulus and exponent and never disposes it.</param>
/// <param name="SelectedScheme">The padding scheme Table 42 selected between the key's own scheme and <c>inScheme</c> (<c>TPM_ALG_NULL</c>, <c>TPM_ALG_RSAES</c>, or <c>TPM_ALG_OAEP</c>).</param>
/// <param name="Message">The message to encrypt (<c>TPM2B_PUBLIC_KEY_RSA</c>), an owned pooled carrier TRANSFERRED from the parsed request; the effect is its terminal owner.</param>
/// <param name="Label">The optional label associated with the message (<c>TPM2B_DATA</c>), an owned pooled carrier TRANSFERRED from the parsed request; the effect is its terminal owner.</param>
/// <param name="Request">The original parsed request, threaded through to the feedback so a refusal can be framed for the right form's session slot.</param>
public sealed record TpmRsaEncryptAction(
    TransientKeyState Key,
    TpmtRsaDecrypt SelectedScheme,
    Tpm2bPublicKeyRsa Message,
    Tpm2bData Label,
    TpmSimulatorInput Request): TpmAction;

/// <summary>
/// Declares that the simulator must RSA-decrypt a ciphertext with a loaded key's private exponent before the
/// next transition (TPM 2.0 Library Part 3, clause 14.3). Emitted by the <c>TPM2_RSA_Decrypt()</c> transition
/// once the authorization ladder, the key-type/attribute/label rules and Table 42's scheme selection have
/// cleared; the effectful loop recovers the plaintext under <see cref="SelectedScheme"/> through the injected
/// <see cref="TpmRsaSigningBackend"/> and feeds it back as a <see cref="TpmRsaDecrypted"/> input, or frames the
/// response directly through the shared over-sessions machinery when <see cref="OverSessions"/> is set.
/// </summary>
/// <param name="Key">The RSA key to decrypt with — a BORROW of the durable <see cref="TransientKeyState"/>; the effect reads its retained public modulus and private exponent and never disposes it.</param>
/// <param name="SelectedScheme">The padding scheme Table 42 selected between the key's own scheme and <c>inScheme</c> (<c>TPM_ALG_NULL</c>, <c>TPM_ALG_RSAES</c>, or <c>TPM_ALG_OAEP</c>).</param>
/// <param name="CipherText">The ciphertext to decrypt (<c>TPM2B_PUBLIC_KEY_RSA</c>), an owned pooled carrier TRANSFERRED from the parsed request; the effect is its terminal owner.</param>
/// <param name="Label">The label whose association with the message is to be verified (<c>TPM2B_DATA</c>), an owned pooled carrier TRANSFERRED from the parsed request; the effect is its terminal owner.</param>
/// <param name="OverSessions">The session-authorized form's response framing (the command code rpHash folds and the authorizing/companion slots' response-entry material), or <see langword="null"/> on the password form, whose effect feeds the plain <see cref="TpmRsaDecrypted"/> back instead (TPM 2.0 Library Part 1, clause 15.6.1).</param>
/// <param name="Request">The original parsed request, threaded through to the feedback so a refusal can be framed for the right form.</param>
public sealed record TpmRsaDecryptAction(
    TransientKeyState Key,
    TpmtRsaDecrypt SelectedScheme,
    Tpm2bPublicKeyRsa CipherText,
    Tpm2bData Label,
    TpmOverSessionsFraming? OverSessions,
    TpmSimulatorInput Request): TpmAction;

/// <summary>
/// Declares that the simulator must recover a duplicated object's sensitive area and re-wrap it under the
/// importing Storage Parent before the next transition (TPM 2.0 Library Part 3, clause 13.3; Part 1, Clause
/// 21). Emitted by the <c>TPM2_Import()</c> transition once the parent authorization and every attribute gate
/// have passed; the effectful loop recovers the outer-wrapper seed with the parent's own key (the "DUPLICATE"
/// label; a failed RSA-OAEP decode substitutes an unpredictable seed so the failure surfaces uniformly at the
/// integrity check — the v184 Part 1, clause A.10.3 substitute-seed rule; v185 keeps its rationale at
/// Part 3, clause 13.3.1), verifies and undoes the duplication wrap,
/// re-wraps the sensitive area with the parent's protection seed, and feeds the result back as a
/// <see cref="TpmObjectImported"/> input. An empty <c>inSymSeed</c> selects the bare form a
/// <c>TPM_RH_NULL</c>-parent duplication produced: the duplicate IS the marshaled <c>TPM2B_SENSITIVE</c>.
/// </summary>
/// <param name="InPublic">The duplicated object's public area, whose marshaled <c>TPMT_PUBLIC</c> the Name is hashed over — an owned pooled carrier; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="Duplicate">The duplication blob — an owned pooled carrier; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="InSymSeed">The protected outer-wrapper seed, or the empty sentinel for the bare form — an owned pooled carrier; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="ObjectNameAlg">The duplicated object's Name algorithm, hashing its Name and sizing its obfuscation slot.</param>
/// <param name="ParentSeedValue">The importing parent's protection seed the re-wrap derives its keys from (Part 1, Clause 19) — a BORROWED reference to the carrier the parent's durable <see cref="TransientKeyState"/> owns; never disposed here.</param>
/// <param name="ParentNameAlg">The importing parent's Name algorithm, keying and sizing both the outer unwrap and the re-wrap.</param>
/// <param name="ParentKeyType">The importing parent's asymmetric algorithm, selecting the seed-recovery arm.</param>
/// <param name="ParentCurve">The importing parent's ECC curve for the ECDH recovery; meaningful only for an elliptic-curve parent.</param>
/// <param name="ParentPublicPoint">The importing parent's SEC1 uncompressed public point, the KDFe recovery's partyVInfo — a borrowed reference; empty for an RSA parent.</param>
/// <param name="ParentPrivateKey">The importing parent's private material for the seed recovery — a BORROWED reference to the carrier the durable state owns; never disposed here.</param>
public sealed record TpmImportObjectAction(
    Tpm2bPublic InPublic,
    Tpm2bPrivate Duplicate,
    Tpm2bEncryptedSecret InSymSeed,
    TpmiAlgHash ObjectNameAlg,
    Tpm2bDigest ParentSeedValue,
    TpmiAlgHash ParentNameAlg,
    TpmiAlgPublic ParentKeyType,
    TpmiEccCurve ParentCurve,
    ReadOnlyMemory<byte> ParentPublicPoint,
    PrivateKeyMemory ParentPrivateKey): TpmAction;

/// <summary>
/// Declares that the simulator must attest a loaded object before the next transition. Emitted by the
/// <c>TPM2_Certify()</c> transition; the effectful loop computes the subject's and the signer's Qualified Names,
/// marshals a <c>TPMS_ATTEST</c> of type <c>TPM_ST_ATTEST_CERTIFY</c> that binds the certified object's Name and
/// the caller nonce, signs <c>H_hashAlg(attest)</c> with the signing key's retained scalar through the injected
/// <see cref="TpmEccSigningBackend"/>, and feeds the marshaled attest and signature back as a
/// <see cref="TpmObjectCertified"/> input (TPM 2.0 Library Part 3, clause 18.2; Part 2, clause 10.11.12).
/// </summary>
/// <remarks>
/// The transition resolves both command handles against the loaded-object table and folds their retained fields
/// into this action — the certified object's Name and hierarchy, and the signing key's Name, hierarchy, scalar,
/// and curve — so the effect needs no automaton state and captures nothing. An elliptic-curve
/// signing key (ECDSA) is modelled, as the signing paths do.
/// </remarks>
/// <param name="SubjectName">The certified object's Name (<c>nameAlg ‖ H(TPMT_PUBLIC)</c>), attested in <c>TPMS_CERTIFY_INFO.name</c>.</param>
/// <param name="SubjectHierarchy">The permanent hierarchy the certified object was created under, from which its Qualified Name is derived.</param>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm this ECC action always carries as <c>TPM_ALG_ECDSA</c>, selecting how the signature is framed; an RSA signing key (<c>TPM_ALG_RSASSA</c>/<c>TPM_ALG_RSAPSS</c>) is dispatched to this action's RSA sibling instead.</param>
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
    ImmutableArray<TpmResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must attest a loaded object before the next transition, signed with an RSA key —
/// the RSA counterpart of <see cref="TpmCertifyAction"/>. Emitted by the <c>TPM2_Certify()</c> transition when
/// the signing key is RSA; the effectful loop computes the subject's and the signer's Qualified Names, marshals
/// the same <c>TPMS_ATTEST</c> of type <c>TPM_ST_ATTEST_CERTIFY</c>, signs <c>H_hashAlg(attest)</c> with the
/// signing key's retained private key through the injected <see cref="TpmRsaSigningBackend"/> under the
/// requested RSA scheme, and feeds the marshaled attest and signature back as a <see cref="TpmObjectCertified"/>
/// input (TPM 2.0 Library Part 3, clause 18.2; Part 2, clause 10.11.12).
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
    ImmutableArray<TpmResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must quote a set of Platform Configuration Registers before the next transition.
/// Emitted by the <c>TPM2_Quote()</c> transition; the effectful loop computes the PCR composite digest over the
/// selected register values and the signer's Qualified Name, marshals a <c>TPMS_ATTEST</c> of type
/// <c>TPM_ST_ATTEST_QUOTE</c> that binds that composite and the caller nonce, signs <c>H_hashAlg(attest)</c> with
/// the signing key's retained scalar through the injected <see cref="TpmEccSigningBackend"/>, and feeds the
/// marshaled attest and signature back as a <see cref="TpmObjectQuoted"/> input (TPM 2.0 Library Part 3, clause
/// 18.4; Part 2, clauses 10.11.12 and 10.11.1).
/// </summary>
/// <remarks>
/// The transition resolves the signing-key handle against the loaded-object table and gathers the selected PCR
/// values from the durable bank, folding both (plus the signer's hierarchy) into this action, so the effect
/// needs no automaton state and captures nothing. An elliptic-curve signing key (ECDSA) is modelled, as
/// the signing paths do.
/// </remarks>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm this ECC action always carries as <c>TPM_ALG_ECDSA</c>, selecting how the signature is framed; an RSA signing key (<c>TPM_ALG_RSASSA</c>/<c>TPM_ALG_RSAPSS</c>) is dispatched to this action's RSA sibling instead.</param>
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
    ImmutableArray<TpmResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must quote a set of Platform Configuration Registers before the next transition,
/// signed with an RSA key — the RSA counterpart of <see cref="TpmQuoteAction"/>. Emitted by the
/// <c>TPM2_Quote()</c> transition when the signing key is RSA; the effectful loop computes the PCR composite
/// digest over the selected register values and the signer's Qualified Name, marshals the same <c>TPMS_ATTEST</c>
/// of type <c>TPM_ST_ATTEST_QUOTE</c>, signs <c>H_hashAlg(attest)</c> with the signing key's retained private key
/// through the injected <see cref="TpmRsaSigningBackend"/> under the requested RSA scheme, and feeds the
/// marshaled attest and signature back as a <see cref="TpmObjectQuoted"/> input (TPM 2.0 Library Part 3, clause
/// 18.4; Part 2, clauses 10.11.12 and 10.11.1).
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
    ImmutableArray<TpmResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must re-verify a creation ticket and, if it reproduces, attest the certified
/// object's creation before the next transition. Emitted by the <c>TPM2_CertifyCreation()</c> transition; the
/// effectful loop re-derives the subject hierarchy's proof, recomputes the creation-ticket digest over
/// <see cref="SubjectName"/> and <see cref="CreationHash"/>, and constant-time compares it to
/// <see cref="TicketDigest"/> — a mismatch feeds back a <see cref="TpmObjectCreationCertified"/> carrying
/// <c>TPM_RC_TICKET</c>. On a match it marshals a <c>TPMS_ATTEST</c> of type <c>TPM_ST_ATTEST_CREATION</c>,
/// signs <c>H_hashAlg(attest)</c> with the signing key's retained scalar through the injected
/// <see cref="TpmEccSigningBackend"/>, and feeds the marshaled attest and signature back as a successful
/// <see cref="TpmObjectCreationCertified"/> input (TPM 2.0 Library Part 3, clause 18.3; Part 2, clause 10.11.7).
/// </summary>
/// <remarks>
/// The transition resolves both command handles against the loaded-object table and folds their retained fields
/// into this action — the certified object's Name and hierarchy, and the signing key's Name, hierarchy, scalar,
/// and curve — so the effect needs no automaton state and captures nothing. An elliptic-curve
/// signing key (ECDSA) is modelled, as the signing paths do.
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
/// <param name="SignatureScheme">The signing algorithm this ECC action always carries as <c>TPM_ALG_ECDSA</c>, selecting how the signature is framed; an RSA signing key (<c>TPM_ALG_RSASSA</c>/<c>TPM_ALG_RSAPSS</c>) is dispatched to this action's RSA sibling instead.</param>
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
    ImmutableArray<TpmResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must re-verify a creation ticket and, if it reproduces, attest the certified
/// object's creation before the next transition, signed with an RSA key — the RSA counterpart of
/// <see cref="TpmCertifyCreationAction"/>. Emitted by the <c>TPM2_CertifyCreation()</c> transition when the
/// signing key is RSA; the effect performs the same ticket re-verification, and on a match signs
/// <c>H_hashAlg(attest)</c> with the signing key's retained private key through the injected
/// <see cref="TpmRsaSigningBackend"/> under the requested RSA scheme (TPM 2.0 Library Part 3, clause 18.3;
/// Part 2, clause 10.11.7).
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
    ImmutableArray<TpmResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must attest the current time before the next transition. Emitted by the
/// <c>TPM2_GetTime()</c> transition; the effectful loop marshals a <c>TPMS_ATTEST</c> of type
/// <c>TPM_ST_ATTEST_TIME</c> whose <c>TPMS_TIME_ATTEST_INFO</c> reports the real Time and the same
/// <c>TPMS_CLOCK_INFO</c>/firmwareVersion every attest builder frames (TPM 2.0 Library Part 3, clause 18.7;
/// Part 1, clause 33.7 — the envelope and nested copies agree), signs <c>H_hashAlg(attest)</c> with the signing key's
/// retained scalar through the injected <see cref="TpmEccSigningBackend"/>, and feeds the marshaled attest and
/// signature back as a <see cref="TpmTimeAttested"/> input.
/// </summary>
/// <remarks>
/// The transition resolves the signing-key handle against the loaded-object table and folds its Name, hierarchy,
/// scalar, and curve into this action, so the effect needs no automaton state and captures nothing. An
/// elliptic-curve signing key (ECDSA) is modelled, as the signing paths do.
/// </remarks>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm this ECC action always carries as <c>TPM_ALG_ECDSA</c>, selecting how the signature is framed; an RSA signing key (<c>TPM_ALG_RSASSA</c>/<c>TPM_ALG_RSAPSS</c>) is dispatched to this action's RSA sibling instead.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="Time">The time in milliseconds since the last startup, folded from state after the per-command advance, framed as the attested <c>TPMS_TIME_ATTEST_INFO.time</c>.</param>
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed both as the envelope's <c>clockInfo</c> and inside the attested <c>TPMS_TIME_ATTEST_INFO</c> (TPM 2.0 Library Part 1, clause 33.7 — the two copies agree).</param>
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
    ImmutableArray<TpmResponseSession> ResponseSessions = default): TpmAction;

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
/// <param name="ClockSnapshot">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed both as the envelope's <c>clockInfo</c> and inside the attested <c>TPMS_TIME_ATTEST_INFO</c> (TPM 2.0 Library Part 1, clause 33.7 — the two copies agree).</param>
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
    ImmutableArray<TpmResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must attest an audit session's digest and exclusive status before the next
/// transition. Emitted by the <c>TPM2_GetSessionAuditDigest()</c> transition; the effectful loop marshals a
/// <c>TPMS_ATTEST</c> of type <c>TPM_ST_ATTEST_SESSION_AUDIT</c> whose <c>TPMS_SESSION_AUDIT_INFO</c> reports
/// <see cref="SessionDigest"/> and <see cref="IsExclusiveSession"/> (TPM 2.0 Library Part 3, clause 18.5; Part
/// 2, clause 10.11.6, Table 148), signs <c>H_hashAlg(attest)</c> with the signing key's retained scalar through the injected
/// <see cref="TpmEccSigningBackend"/>, and feeds the marshaled attest and signature back as a
/// <see cref="TpmSessionAuditAttested"/> input.
/// </summary>
/// <remarks>
/// The transition resolves the signing-key handle against the loaded-object table, resolves the audited session
/// against the durable session table, and folds the signer's Name, hierarchy, scalar, and curve — and the
/// audited session's pre-command digest and exclusive status — into this action, so the effect needs no
/// automaton state and captures nothing beyond a borrowed reference into durable state. The signer is an
/// elliptic-curve key (ECDSA); <see cref="TpmRsaSessionAuditAttestAction"/> is the RSA form and
/// <see cref="TpmNullSignedSessionAuditAttestAction"/> the NULL-signer form.
/// </remarks>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c> on this action), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="IsExclusiveSession">Whether the audited session was the TPM's current exclusive audit session at the start of the command (TPM 2.0 Library Part 1, clause 17.2), snapshotted by the transition before this command's own completion could move it.</param>
/// <param name="SessionDigest">
/// The audited session's audit digest as it stood BEFORE this command (TPM 2.0 Library Part 1, clause 17.4) — a
/// BORROWED reference into the durable <see cref="Verifiable.Tpm.Automata.HmacSessionState.AuditDigest"/> carrier
/// the transition snapshotted, not a pooled copy: the transition itself has no memory pool to rent one from, and
/// nothing mutates the durable session table between this action's declaration and the effect reading these
/// octets — the completing transition that could replace the record's digest (through
/// <c>RollHmacSessionNonceAndAudit</c>) runs only after this effect has already returned its feedback, under the
/// simulator's one-command-at-a-time execution contract. The effect never disposes this carrier.
/// </param>
/// <param name="ClockInfo">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the envelope's <c>clockInfo</c>.</param>
/// <param name="ResponseSessions">Every session in the command's authorization area, in command-session order, each carrying either a real session's response-HMAC material or the <c>TPM_RS_PW</c> placeholder marker; empty on the all-password arm, whose response carries no session area at all.</param>
public sealed record TpmSessionAuditAttestAction(
    Tpm2bName SignerName,
    TpmiRhHierarchy SignerHierarchy,
    Tpm2bData QualifyingData,
    PrivateKeyMemory SignerPrivateKey,
    TpmiEccCurve SignerCurve,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash HashAlg,
    bool IsExclusiveSession,
    Tpm2bDigest SessionDigest,
    TpmsClockInfo ClockInfo,
    ImmutableArray<TpmResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must attest an audit session's digest and exclusive status before the next
/// transition, signed with an RSA key — the RSA counterpart of <see cref="TpmSessionAuditAttestAction"/>. Emitted
/// by the <c>TPM2_GetSessionAuditDigest()</c> transition when the signing key is RSA; the effect builds the same
/// real audit-status attestation and signs <c>H_hashAlg(attest)</c> with the signing key's retained private key
/// through the injected <see cref="TpmRsaSigningBackend"/> under the requested RSA scheme (TPM 2.0 Library Part
/// 3, clause 18.5).
/// </summary>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained private key, in the backend's own encoding — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to apply.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, hashed over the marshaled attest and framed inside the signature.</param>
/// <param name="IsExclusiveSession">Whether the audited session was the TPM's current exclusive audit session at the start of the command.</param>
/// <param name="SessionDigest">The audited session's audit digest as it stood BEFORE this command — a BORROWED reference into durable state, per <see cref="TpmSessionAuditAttestAction.SessionDigest"/>'s own documentation.</param>
/// <param name="ClockInfo">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the envelope's <c>clockInfo</c>.</param>
/// <param name="ResponseSessions">Every session in the command's authorization area, in command-session order, each carrying either a real session's response-HMAC material or the <c>TPM_RS_PW</c> placeholder marker; empty on the all-password arm.</param>
public sealed record TpmRsaSessionAuditAttestAction(
    Tpm2bName SignerName,
    TpmiRhHierarchy SignerHierarchy,
    Tpm2bData QualifyingData,
    PrivateKeyMemory SignerPrivateKey,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash HashAlg,
    bool IsExclusiveSession,
    Tpm2bDigest SessionDigest,
    TpmsClockInfo ClockInfo,
    ImmutableArray<TpmResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must attest an audit session's digest and exclusive status before the next
/// transition when <c>signHandle</c> is <c>TPM_RH_NULL</c> — the NULL-signer counterpart of
/// <see cref="TpmSessionAuditAttestAction"/> and <see cref="TpmRsaSessionAuditAttestAction"/>. Every action of
/// the command still runs; only the signing step is skipped (TPM 2.0 Library Part 3, clause 18.1: "the
/// attestation block is 'signed' with the NULL Signature"). Carries no key, curve, or scheme, since there is no
/// signing key to hold one — the marshaled attest's <c>qualifiedSigner</c> is instead the 4-octet
/// <c>TPM_RH_NULL</c> handle Name, built by the effect (TPM 2.0 Library Part 4, <c>Attest_spt.c</c>'s <c>FillInAttestInfo()</c>).
/// </summary>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="IsExclusiveSession">Whether the audited session was the TPM's current exclusive audit session at the start of the command.</param>
/// <param name="SessionDigest">The audited session's audit digest as it stood BEFORE this command — a BORROWED reference into durable state, per <see cref="TpmSessionAuditAttestAction.SessionDigest"/>'s own documentation.</param>
/// <param name="ClockInfo">The Clock/resetCount/restartCount/Safe snapshot folded from state after the per-command advance, framed as the envelope's <c>clockInfo</c>.</param>
/// <param name="ResponseSessions">Every session in the command's authorization area, in command-session order, each carrying either a real session's response-HMAC material or the <c>TPM_RS_PW</c> placeholder marker; empty on the all-password arm.</param>
public sealed record TpmNullSignedSessionAuditAttestAction(
    Tpm2bData QualifyingData,
    bool IsExclusiveSession,
    Tpm2bDigest SessionDigest,
    TpmsClockInfo ClockInfo,
    ImmutableArray<TpmResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must attest an NV Index's contents before the next transition. Emitted by the
/// <c>TPM2_NV_Certify()</c> transition; the effectful loop marshals the Index's <c>TPMS_NV_PUBLIC</c> and computes
/// its Name through the registered digest seam (the same marshal-and-hash mechanism <c>TPM2_PolicyNV()</c> uses),
/// marshals a <c>TPMS_ATTEST</c> of type <c>TPM_ST_ATTEST_NV</c> binding that Name, the requested window of
/// <see cref="NvContents"/>, and the caller nonce, signs <c>H_hashAlg(attest)</c> with the signing key's retained
/// scalar through the injected <see cref="TpmEccSigningBackend"/>, and feeds the marshaled attest and signature
/// back as a <see cref="TpmNvIndexCertified"/> input (TPM 2.0 Library Part 3, clause 31.16; Part 2, clause
/// 10.11.8).
/// </summary>
/// <remarks>
/// <para>
/// The transition resolves the signing-key and NV-Index handles, performs the Index-authorization and
/// written/range checks, and slices the requested window from the Index's retained data area, folding all of it
/// into this action, so the effect needs no automaton state and captures nothing. An elliptic-curve
/// signing key (ECDSA) is modelled, as the signing paths do.
/// </para>
/// <para>
/// <see cref="ResponseSessions"/> is what makes this action serve both authorization arms. Empty (the default)
/// is the all-password arm, whose response is the plain <c>TPM_ST_NO_SESSIONS</c> attest-and-signature pair.
/// Non-empty is the session arm, and the effect then additionally frames <c>certifyInfo ‖ signature</c> into a
/// response parameter area, computes rpHash over exactly those octets (TPM 2.0 Library Part 1, clause 15.8
/// equation 16), and produces one response session entry per command session — the attest-family shape
/// (<see cref="TpmResponseSession"/>) every attest action shares, being both parameter-bearing and
/// multi-entry at once, which neither <see cref="TpmFrameNvSessionResponseAction"/> (parameters, one entry) nor
/// <see cref="TpmFrameTwoSlotResponseAction"/> (entries, no parameters) can frame.
/// </para>
/// </remarks>
/// <param name="SignerName">The signing key's Name.</param>
/// <param name="SignerHierarchy">The permanent hierarchy the signing key was created under, from which its Qualified Name (the attestation's <c>qualifiedSigner</c>) is derived.</param>
/// <param name="QualifyingData">The caller nonce echoed verbatim into the attestation's <c>extraData</c> — OWNED, transferred from the request; the effect is its terminal owner and releases it in its <c>finally</c>.</param>
/// <param name="SignerPrivateKey">The signing key's retained ECC scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the signing primitive and never disposes it.</param>
/// <param name="SignerCurve">The ECC curve the signing scalar lives on.</param>
/// <param name="SignatureScheme">The signing algorithm this ECC action always carries as <c>TPM_ALG_ECDSA</c>, selecting how the signature is framed; an RSA signing key (<c>TPM_ALG_RSASSA</c>/<c>TPM_ALG_RSAPSS</c>) is dispatched to this action's RSA sibling instead.</param>
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
    ImmutableArray<TpmResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// Declares that the simulator must attest an NV Index's contents before the next transition, signed with an RSA
/// key — the RSA counterpart of <see cref="TpmNvCertifyAction"/>. Emitted by the <c>TPM2_NV_Certify()</c>
/// transition when the signing key is RSA; the effect performs the same Index-Name computation and attestation
/// marshaling, and signs <c>H_hashAlg(attest)</c> with the signing key's retained private key through the
/// injected <see cref="TpmRsaSigningBackend"/> under the requested RSA scheme (TPM 2.0 Library Part 3, clause
/// 31.16; Part 2, clause 10.11.8).
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
    ImmutableArray<TpmResponseSession> ResponseSessions = default): TpmAction;

/// <summary>
/// The POLICY/TRIAL-session-specific context threaded through the shared session-key-derivation ladder
/// (<see cref="TpmStartHmacSessionAction"/>, <see cref="TpmRecoverRsaSessionSaltAction"/>,
/// <see cref="TpmRecoverEccSessionSaltAction"/>) when it is deriving a POLICY or TRIAL session's key rather than
/// an HMAC session's. The <c>KDFa</c> derivation itself is identical for every session type (TPM 2.0 Library
/// Part 3, clause 11.1.1: "For all session types, this command will cause initialization of the sessionKey")
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
/// input (TPM 2.0 Library Part 3, clause 11.1; Part 1, clause 16.6.10 equations 20/25).
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
/// <param name="NonceCaller">The caller nonce sent at start (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92, page 134) — the second context field of the session-key KDFa. Owned: transferred out of the request record by the transition that built this action, and released by the effect that consumes it as its terminal owner.</param>
/// <param name="BindAuthValue">The bind entity's resolved authorization value (the shared empty carrier for an unbound session) — a borrowed reference to the carrier the durable state owns, wire-exact; the effect takes the trailing-zero-stripped view at the KDFa key's leading term (Part 1, clauses 16.6.10 and 16.6.4.3) and never disposes it.</param>
/// <param name="BoundEntityName">The bind entity's Name, resolved synchronously by the transition (empty for an unbound session) — for an HMAC session the effect folds it with <paramref name="BindAuthValue"/> into the <see cref="SessionBoundEntity"/> the session records for the bind-omission check (Part 4, <c>SessionComputeBoundEntity()</c>; Part 1, clause 16.6.10 equations 21/22); unused for a POLICY/TRIAL session, which never applies that optimization.</param>
/// <param name="Salt">Always empty on this unsalted path — the KDFa key's trailing term (Part 1, clause 16.6.12 equation 25) a salted arm instead recovers asynchronously. This is the RECOVERED plaintext salt, never the wire <c>encryptedSalt</c>, so it is not a <c>TPM2B_ENCRYPTED_SECRET</c>; it stays a plain view because nothing on this path ever holds one.</param>
/// <param name="PolicyContext">Non-<see langword="null"/> when this action is starting a POLICY or TRIAL session rather than an HMAC session (see <see cref="TpmPolicySessionKeyContext"/>).</param>
/// <param name="IsBoundEntityDaProtected">Whether the bind entity receives dictionary-attack protection, resolved synchronously by the transition and carried to the session record the effect's result lands on — the state Part 1, clause 16.6.10 requires be recorded in the session context ("The noDA attribute of the bind entity is recorded in the session context").</param>
/// <param name="IsBoundToLockout">Whether the bind entity is <c>TPM_RH_LOCKOUT</c>, whose authValue alone among permanent entities is dictionary-attack protected (Part 1, clause 16.8.1) and whose failed use is one-strike (clause 16.8.5).</param>
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
/// clause 11.1's salted-session establishment (TPM 2.0 Library Part 1, clause 43.10.1/16.6.13). Emitted by the
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
/// <param name="NonceCaller">The caller nonce sent at start (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92, page 134) — the second context field of the session-key KDFa. Owned: transferred out of the request record by the transition that built this action, and released by the effect that consumes it as its terminal owner.</param>
/// <param name="BindAuthValue">The bind entity's resolved authorization value (the shared empty carrier for an unbound session) — a borrowed reference to the carrier the durable state owns, wire-exact; the effect takes the trailing-zero-stripped view at the session-key KDFa's leading term (Part 1, clauses 16.6.12 equation 25 and 16.6.4.3) and never disposes it.</param>
/// <param name="BoundEntityName">The bind entity's Name, resolved synchronously by the transition (empty for an unbound session).</param>
/// <param name="Ciphertext">The wire <c>encryptedSalt</c> (<c>TPM2B_ENCRYPTED_SECRET</c>, Part 2, clause 11.4.3, Table 224, page 180): the OAEP ciphertext, the same octet width as <c>tpmKey</c>'s modulus. Owned: transferred out of the request record by the transition that built this action, and released by the effect that consumes it as its terminal owner.</param>
/// <param name="PrivateKey"><c>tpmKey</c>'s retained RSA private key, in the backend's own encoding — a borrowed reference to the carrier the durable object state owns; the effect reads it at the decrypt primitive and never disposes it.</param>
/// <param name="NameAlg">
/// <c>tpmKey</c>'s own Name algorithm — drives OAEP's <c>lhash</c>/MGF1 and caps the recovered salt's size (TPM
/// 2.0 Library Part 1, clause 43.10.1). NEVER the session's own <c>authHash</c> (a mixed-hash session would
/// otherwise leak the wrong hash into this derivation).
/// </param>
/// <param name="PolicyContext">Non-<see langword="null"/> when this action is starting a POLICY or TRIAL session rather than an HMAC session (see <see cref="TpmPolicySessionKeyContext"/>).</param>
/// <param name="IsBoundEntityDaProtected">Whether the bind entity receives dictionary-attack protection (Part 1, clause 16.6.10's "The noDA attribute of the bind entity is recorded in the session context") — a property of <c>bind</c> alone, independent of the salt this arm recovers, so it rides through unchanged.</param>
/// <param name="IsBoundToLockout">Whether the bind entity is <c>TPM_RH_LOCKOUT</c>, the one permanent entity whose authValue is dictionary-attack protected (Part 1, clause 16.8.1) and whose failed use is one-strike (clause 16.8.5).</param>
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
/// private scalar and the wire ephemeral public point, then <c>KDFe</c> (TPM 2.0 Library Part 1, clauses
/// 44.7.1 and 16.6.13). Emitted when <c>tpmKey</c> resolves to a loaded ECC key; the effectful loop parses
/// <see cref="EncryptedSalt"/> as a marshaled <c>TPMS_ECC_POINT</c>, validates it is a genuine point on the
/// curve (<c>TPM_RC_VALUE</c> on a malformed or off-curve/infinity point, reported immediately, never
/// deferred), computes <c>Z</c>, derives the salt via <c>KDFe</c> keyed on <c>tpmKey</c>'s own Name algorithm —
/// never the session's <c>authHash</c> — and otherwise proceeds exactly as the RSA arm.
/// </summary>
/// <param name="SessionHandle">The session handle the transition allocated for the new session.</param>
/// <param name="SessionAlg">The session hash algorithm driving the KDFa and sizing the nonceTPM.</param>
/// <param name="Symmetric">The negotiated symmetric definition to record on the session.</param>
/// <param name="NonceCaller">The caller nonce sent at start (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92, page 134) — the second context field of the session-key KDFa. Owned: transferred out of the request record by the transition that built this action, and released by the effect that consumes it as its terminal owner.</param>
/// <param name="BindAuthValue">The bind entity's resolved authorization value (the shared empty carrier for an unbound session) — a borrowed reference to the carrier the durable state owns, wire-exact; the effect takes the trailing-zero-stripped view at the session-key KDFa's leading term (Part 1, clauses 16.6.12 equation 25 and 16.6.4.3) and never disposes it.</param>
/// <param name="BoundEntityName">The bind entity's Name, resolved synchronously by the transition (empty for an unbound session).</param>
/// <param name="EncryptedSalt">The wire <c>encryptedSalt</c> (<c>TPM2B_ENCRYPTED_SECRET</c>, Part 2, clause 11.4.3, Table 224, page 180): a marshaled <c>TPMS_ECC_POINT</c> (two size-prefixed coordinates) carrying the caller's ephemeral public point. Owned: transferred out of the request record by the transition that built this action, and released by the effect that consumes it as its terminal owner.</param>
/// <param name="PrivateScalar"><c>tpmKey</c>'s retained ECC private scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the exchange primitive and never disposes it.</param>
/// <param name="PublicPoint"><c>tpmKey</c>'s own exported public point, SEC1 uncompressed — <c>KDFe</c>'s <c>partyVInfo</c> source.</param>
/// <param name="Curve">The ECC curve <c>tpmKey</c> lives on.</param>
/// <param name="NameAlg"><c>tpmKey</c>'s own Name algorithm — <c>KDFe</c>'s hash and the recovered salt's size, never the session's own <c>authHash</c>.</param>
/// <param name="PolicyContext">Non-<see langword="null"/> when this action is starting a POLICY or TRIAL session rather than an HMAC session (see <see cref="TpmPolicySessionKeyContext"/>).</param>
/// <param name="IsBoundEntityDaProtected">Whether the bind entity receives dictionary-attack protection (Part 1, clause 16.6.10's "The noDA attribute of the bind entity is recorded in the session context") — a property of <c>bind</c> alone, independent of the salt this arm recovers, so it rides through unchanged.</param>
/// <param name="IsBoundToLockout">Whether the bind entity is <c>TPM_RH_LOCKOUT</c>, the one permanent entity whose authValue is dictionary-attack protected (Part 1, clause 16.8.1) and whose failed use is one-strike (clause 16.8.5).</param>
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
/// Library Part 1, clause 16.6; Part 3, clause 5.6, check 9) — the shared mechanism every session-authorized
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
/// <param name="HandleNames">The command's handle-Name area as its ordered terms (Part 1, clause 15.7 equation 15's <c>Name1..N</c>), empty for a command with no handles. Each term is a BORROW of a Name carrier durable state or the request owns, or a permanent entity's handle value; the effect lays them out in pooled scratch of its own frame.</param>
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
/// Declares that the simulator must frame the <c>TPM2_Unseal()</c> response before the next transition. Emitted
/// once every session in the command's authorization area has verified (a satisfied policy session's digest gate,
/// or a real command-HMAC verification); the effectful loop draws a fresh nonceTPM for each real (HMAC-table)
/// session, frames the recovered secret as a <c>TPM2B_SENSITIVE_DATA</c>, encrypts its data portion over whichever
/// session (if any) carries the <c>encrypt</c> attribute, computes rpHash over the (possibly encrypted) parameter
/// area, then computes each real session's own response HMAC, and feeds the framed pieces back as a
/// <see cref="TpmUnsealedOverSessions"/> input (TPM 2.0 Library Part 3, clause 12.7; Part 1, clauses 15.7 and 18).
/// </summary>
/// <remarks>
/// <see cref="HmacResponseSessions"/> holds 0, 1, or 2 entries, in command-session order (an authorizing HMAC
/// session first when present, an encrypt session — which may or may not be the same session — always last): each
/// gets its own real nonce roll and response HMAC over THE SAME rpHash, keyed on its own <c>sessionKey ‖
/// authValue</c> (Part 1, clause 16.6.10: "If the authorization is for the entity to which the session is bound,
/// the HMAC key is the session's sessionKey"). A satisfied
/// plain policy session (Part 1, clause 16.6: no key) instead gets a zero-nonce, empty-HMAC placeholder entry when
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
/// Part 1, clause 21; Part 3, clause 12.6).
/// </summary>
/// <remarks>
/// The transition resolves the credential-key handle against the loaded-object table and folds its exported public
/// point and curve into this action, so the effect needs no automaton state and captures nothing. The Name
/// algorithm is the simulator's universal <c>TPM_ALG_SHA256</c>.
/// </remarks>
/// <param name="Credential">The secret to wrap (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
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
/// Library Part 1, clause 21; Part 3, clause 12.5).
/// </summary>
/// <remarks>
/// Because the re-derivation is keyed on the activate object's Name, activating a credential bound to one object
/// against a different object yields different keys, so the outer HMAC does not verify — the binding both the
/// positive and the negative cases turn on.
/// </remarks>
/// <param name="CredentialBlob">The credential blob (<c>TPMS_ID_OBJECT</c>: the outer HMAC then the encrypted credential) — the owned pooled <see cref="Tpm2bIdObject"/> carrier the request parsed; ownership rides this action into the effect, which is its terminal owner and releases it once the outer-HMAC split and integrity check have consumed it.</param>
/// <param name="Secret">The encrypted seed transport (a marshaled <c>TPMS_ECC_POINT</c>, the ephemeral public point) — the owned pooled <see cref="Tpm2bEncryptedSecret"/> carrier the request parsed; ownership rides this action into the effect, which releases it once the ephemeral point is recovered from it.</param>
/// <param name="ActivateObjectName">The activate object's Name — re-keys the credential's symmetric and HMAC keys, so a mismatched object fails the integrity check.</param>
/// <param name="CredentialKeyPrivateScalar">The credential key's retained ECC scalar (unsigned big-endian), the ECDH private input that recovers the shared value — a borrowed reference to the carrier the durable object state owns; the effect reads it at the exchange primitive and never disposes it.</param>
/// <param name="CredentialKeyPublicPoint">The credential key's exported public point, SEC1 uncompressed, the <c>KDFe</c> partyVInfo source (matching the make side).</param>
/// <param name="CredentialKeyCurve">The ECC curve the credential key lives on.</param>
/// <param name="NameAlg">The credential key's Name algorithm, driving the <c>KDFe</c> / <c>KDFa</c> / HMAC digests.</param>
public sealed record TpmActivateCredentialAction(
    Tpm2bIdObject CredentialBlob,
    Tpm2bEncryptedSecret Secret,
    Tpm2bName ActivateObjectName,
    PrivateKeyMemory CredentialKeyPrivateScalar,
    ReadOnlyMemory<byte> CredentialKeyPublicPoint,
    TpmiEccCurve CredentialKeyCurve,
    TpmiAlgHash NameAlg): TpmAction;

/// <summary>
/// Declares that the simulator must wrap a credential secret to an RSA credential key's public modulus via
/// RSA-OAEP before the next transition — the RSA arm of <c>TPM2_MakeCredential()</c> (TPM 2.0 Library Part 1,
/// clause 21; clause 43.4, 20.3.2.3, 21.3; Part 3, clause 12.6). Emitted by the <c>TPM2_MakeCredential()</c>
/// transition when the resolved credential key is RSA; the effectful loop draws a fresh random seed (no
/// ephemeral key pair — RSA has no ECDH-style split step), OAEP-encrypts it to the credential key's modulus
/// through the injected <see cref="TpmRsaSigningBackend"/>, then produces the AK-Name-bound credential blob
/// exactly as the ECC arm does (the outer wrap, Part 1, clause 21, does not branch on the credential key's
/// algorithm) and feeds it back as a <see cref="TpmCredentialMade"/> input.
/// </summary>
/// <remarks>
/// The transition resolves the credential-key handle against the loaded-object table and folds its exported
/// public modulus into this action, so the effect needs no automaton state and captures nothing. The Name
/// algorithm is the simulator's universal <c>TPM_ALG_SHA256</c>.
/// </remarks>
/// <param name="Credential">The secret to wrap (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="ObjectName">The attestation key's Name the credential is bound to (folded into the <c>KDFa</c> derivations and the outer HMAC) — an owned <c>TPM2B_NAME</c> carrier the transition transferred out of the request; the effect is its terminal owner and releases it in the <c>finally</c>.</param>
/// <param name="CredentialKeyModulus">The credential key's exported public modulus (<c>TPM2B_PUBLIC_KEY_RSA</c>, TPM 2.0 Library Part 2, clause 11.2.4.6, Table 194), unsigned big-endian, the OAEP public-key input — a BORROW of the loaded object's own durable carrier, which outlives this command; the effect reads it and never releases it.</param>
/// <param name="NameAlg">The credential key's Name algorithm, driving the seed size, the OAEP <c>lhash</c>/MGF1 digests (the credential key's scheme is <c>TPM_ALG_NULL</c> for every storage-parent template this simulator builds, so <c>lhash</c> coincides with nameAlg), and the <c>KDFa</c>/HMAC digests.</param>
public sealed record TpmRsaMakeCredentialAction(
    Tpm2bDigest Credential,
    Tpm2bName ObjectName,
    Tpm2bPublicKeyRsa CredentialKeyModulus,
    TpmiAlgHash NameAlg): TpmAction;

/// <summary>
/// Declares that the simulator must recover a credential secret transported by RSA-OAEP for
/// <c>TPM2_ActivateCredential()</c> before the next transition — the RSA arm (TPM 2.0 Library Part 1, clause 21;
/// clause 43.3, 43.4, 20.3.2.3, 21.3; Part 3, clause 12.5). Emitted by the <c>TPM2_ActivateCredential()</c>
/// transition when the resolved credential key is RSA; the effectful loop RSADP-decrypts and OAEP-decodes the
/// transported secret through the injected <see cref="TpmRsaSigningBackend"/> — substituting an unpredictable
/// seed on any decode failure rather than reporting it directly (the v184 Part 1, clause A.10.3 rule, imported
/// by A.10.4 for credentials; v185 keeps its rationale at Part 3, clause 13.3.1) — then
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
/// <param name="CredentialBlob">The credential blob (<c>TPMS_ID_OBJECT</c>: the outer HMAC then the encrypted credential) — the owned pooled <see cref="Tpm2bIdObject"/> carrier the request parsed; ownership rides this action into the effect, which is its terminal owner and releases it once the outer-HMAC split and integrity check have consumed it.</param>
/// <param name="Secret">The encrypted seed transport — already unwrapped from its <c>TPM2B_ENCRYPTED_SECRET</c> framing by the command parser, so this is the raw OAEP ciphertext directly (Part 2, Table 224: the RSA arm has no sub-structure, unlike the ECC arm's marshaled <c>TPMS_ECC_POINT</c>) — the owned pooled <see cref="Tpm2bEncryptedSecret"/> carrier the request parsed; ownership rides this action into the effect, which releases it once the ciphertext is copied out for the OAEP-decrypt await.</param>
/// <param name="ActivateObjectName">The activate object's Name — re-keys the credential's symmetric and HMAC keys, so a mismatched object fails the integrity check.</param>
/// <param name="CredentialKeyPrivateKey">The credential key's retained RSA private key, in the backend's own encoding — the RSADP private input that recovers the OAEP-encoded message; a borrowed reference to the carrier the durable object state owns, read at the decrypt primitive and never disposed by the effect.</param>
/// <param name="NameAlg">The credential key's Name algorithm, driving the seed size, the OAEP <c>lhash</c>/MGF1 digests, and the <c>KDFa</c>/HMAC digests.</param>
public sealed record TpmRsaActivateCredentialAction(
    Tpm2bIdObject CredentialBlob,
    Tpm2bEncryptedSecret Secret,
    Tpm2bName ActivateObjectName,
    PrivateKeyMemory CredentialKeyPrivateKey,
    TpmiAlgHash NameAlg): TpmAction;

/// <summary>
/// Declares that the simulator must compute an NV Index's Name before the next transition, so
/// <c>TPM2_PolicyNV()</c>'s policyDigest extension can bind it (TPM 2.0 Library Part 3, clause 23.9; Part 1,
/// clause 13, Table 9). Emitted by the <c>TPM2_PolicyNV()</c> transition; the effectful loop marshals the Index's
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
/// <param name="AuthPolicy">The Index's own access policy digest (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90), folded into the marshaled <c>TPMS_NV_PUBLIC.authPolicy</c>. A borrowed reference to the durable Index state's own carrier; the effect reads it and never disposes it.</param>
/// <param name="OperandB">The comparison operand the pending assertion carries (<c>TPM2B_OPERAND</c>, TPM 2.0 Library Part 2, clause 10.3.6, Table 94) — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="Offset">The octet offset into the NV Index data the pending assertion carries.</param>
/// <param name="Operation">The <c>TPM_EO</c> comparison operation the pending assertion carries.</param>
/// <param name="PolicyHashAlgorithm">The policy session's own hash algorithm, sizing the policyDigest fold the effect performs once the Name is in hand — independent of <see cref="NameAlg"/>, which is the Index's.</param>
/// <param name="CurrentPolicyDigest">The session's current accumulated policyDigest — a borrowed reference to the carrier the durable session record owns; the effect reads it as the fold's first term and never disposes it.</param>
/// <param name="Fold">Which Name-folding formula the effect applies once the Name is in hand: <see cref="TpmPolicyDigestFold.Nv"/> for <c>TPM2_PolicyNV()</c> (folds the operand argHash and the Name onto the current digest) or <see cref="TpmPolicyDigestFold.AuthorizeNv"/> for <c>TPM2_PolicyAuthorizeNV()</c> (resets to a Zero Digest, then folds the Name alone; the operand fields are then the empty sentinel and zero).</param>
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
    Tpm2bDigest CurrentPolicyDigest,
    TpmPolicyDigestFold Fold): TpmAction;

/// <summary>
/// Declares that the simulator must marshal an NV Index's public area and compute its Name before the next
/// transition, so <c>TPM2_NV_ReadPublic()</c>'s response can carry both (TPM 2.0 Library Part 3, clause 31.6;
/// Part 1, clause 13 and Table 9). Emitted by the <c>TPM2_NV_ReadPublic()</c> transition; the effectful loop
/// builds the <c>TPMS_NV_PUBLIC</c> from these fields, marshals it, and computes
/// <c>nameAlg ‖ H_nameAlg(TPMS_NV_PUBLIC)</c> through the registered digest seam, then feeds both back as a
/// <see cref="TpmNvPublicNameComputed"/> input.
/// </summary>
/// <param name="NvIndex">The NV Index handle, folded into the marshaled <c>TPMS_NV_PUBLIC</c> and echoed into the framed <c>nvPublic</c>.</param>
/// <param name="NameAlg">The Index's Name algorithm, driving the marshaled <c>TPMS_NV_PUBLIC.nameAlg</c> and the digest.</param>
/// <param name="Attributes">The Index's current attributes (<c>TPMA_NV</c>), folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="AuthPolicy">The Index's access policy digest (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90), folded into the marshaled <c>TPMS_NV_PUBLIC.authPolicy</c>. A borrowed reference to the durable Index state's own carrier; the effect reads it and never disposes it.</param>
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
/// from the real, hash-based Index Name (TPM 2.0 Library Part 1, clause 15.7 equation 15; clause 16.6.10
/// equations 21/22) — the command-HMAC counterpart of <see cref="TpmComputeNvPublicNameAction"/>, carrying
/// <see cref="Resume"/> through so the pending session-authorized request can be recovered once the Name
/// arrives.
/// </summary>
/// <param name="NvIndex">The NV Index handle, folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="NameAlg">The Index's Name algorithm, driving the marshaled <c>TPMS_NV_PUBLIC.nameAlg</c> and the digest.</param>
/// <param name="Attributes">The Index's current attributes (<c>TPMA_NV</c>), folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="AuthPolicy">The Index's access policy digest (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90), folded into the marshaled <c>TPMS_NV_PUBLIC.authPolicy</c>. A borrowed reference to the durable Index state's own carrier; the effect reads it and never disposes it.</param>
/// <param name="DataSize">The Index's declared data size, folded into the marshaled <c>TPMS_NV_PUBLIC</c>.</param>
/// <param name="Resume">
/// The original session-authorized NV request — <c>TpmNvReadOverSessionRequested</c>,
/// <c>TpmNvWriteOverSessionRequested</c>, <c>TpmNvUndefineSpaceOverSessionRequested</c>,
/// <c>TpmNvIncrementOverSessionRequested</c>, <c>TpmNvExtendOverSessionRequested</c>,
/// <c>TpmNvSetBitsOverSessionRequested</c>, <c>TpmNvWriteLockOverSessionRequested</c>,
/// <c>TpmNvReadLockOverSessionRequested</c>, <c>TpmNvCertifyOverSessionRequested</c>,
/// <c>TpmNvChangeAuthOverSessionRequested</c>, or <c>TpmNvUndefineSpaceSpecialRequested</c> — to resume once the
/// Name and, later, the command-HMAC verification complete. The last three take their own continuations out of
/// <c>OnNvIndexNameComputed</c> rather than its shared USER-role body: <c>TPM2_NV_ChangeAuth()</c> because its
/// cpHash has a single handle, <c>TPM2_NV_Certify()</c> because its cpHash has THREE (Part 1, clause 15.7
/// equation 15's <c>Name1 ‖ Name2 ‖ Name3</c>) and its authorizing session sits at index 1, and
/// <c>TPM2_NV_UndefineSpaceSpecial()</c> because its Name1/Name2 pair is the Index's Name and the platform
/// hierarchy's raw handle rather than the shared body's hierarchy-arm/Index-arm shape, and BOTH of its
/// authorizing slots (ADMIN policy at index 0, USER platform at index 1) always queue.
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
/// <c>TPM2_NV_Write()</c>, <c>TPM2_NV_DefineSpace()</c>, <c>TPM2_NV_UndefineSpace()</c>,
/// <c>TPM2_NV_Increment()</c>, <c>TPM2_NV_Extend()</c>, <c>TPM2_NV_SetBits()</c>, <c>TPM2_NV_WriteLock()</c> and
/// <c>TPM2_NV_ReadLock()</c> since none of them
/// carries more than the one optional response parameter <see cref="ParameterArea"/> represents (TPM 2.0
/// Library Part 3's own response schematics), nor more than the one authorizing session an entry is owed for
/// (Part 1, clause 15.6.1).
/// <c>TPM2_NV_Certify()</c> is the NV command that has both at once — a
/// <c>certifyInfo ‖ signature</c> parameter area AND two authorizing sessions — so it frames through
/// <see cref="TpmNvCertifyAction"/>'s own response-session list instead. The hierarchy and provisioning commands — <c>TPM2_Clear()</c>,
/// <c>TPM2_ClearControl()</c>, <c>TPM2_HierarchyControl()</c>, and <c>TPM2_SetPrimaryPolicy()</c> — share the
/// same shape and so are framed through it too, each with an empty parameter area, joined by
/// <c>TPM2_NV_GlobalWriteLock()</c>: an NV-family command whose authorizing entity is a hierarchy rather than an
/// Index, riding this action the way the hierarchy commands do. Emitted by each command's
/// <c>Continue…OverSession</c> once its command-HMAC
/// has verified and any business-logic checks (range, attribute gates) have already passed; the effectful loop
/// computes rpHash over <see cref="ParameterArea"/>, rolls a fresh nonceTPM, and computes the response HMAC
/// keyed on the SAME <c>sessionKey ‖ authValue</c> the command-HMAC verification used (Part 1, clause 16.6.5),
/// feeding the result back as a <see cref="TpmNvSessionResponseFramed"/> input.
/// </summary>
/// <param name="CommandCode">The command code, folded into rpHash (Part 1, clause 15.8 equation 16).</param>
/// <param name="SessionHandle">The authorizing session whose nonceTPM is rolled once framed.</param>
/// <param name="SessionAlg">The session hash algorithm driving rpHash and the response HMAC.</param>
/// <param name="SessionKey">The session key — a borrowed reference to the carrier the durable session record owns; the effect reads it at the HMAC primitive and never disposes it.</param>
/// <param name="AuthValue">The bind-omission-resolved authValue folded into the response HMAC key alongside <see cref="SessionKey"/> — a borrowed reference to the carrier the durable state owns, carrying the same value the command-HMAC verification used; the effect reads its trailing-zero-stripped view at the HMAC primitive and never disposes it.</param>
/// <param name="NonceCaller">This session's command caller nonce, the response HMAC's nonceOlder (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92) — OWNED by this action, transferred out of the request record by the continuation that declared it, and released by the framing effect's <c>finally</c> once the response HMAC has been computed.</param>
/// <param name="SessionAttributes">This session's command session-attributes octet, echoed into its response entry.</param>
/// <param name="ReadWindow">
/// The single response parameter this command owes, or <see langword="null"/> when it owes none —
/// <c>TPM2_NV_Write()</c>/<c>TPM2_NV_DefineSpace()</c>/<c>TPM2_NV_UndefineSpace()</c>/<c>TPM2_NV_Increment()</c>/
/// <c>TPM2_NV_Extend()</c>/<c>TPM2_NV_SetBits()</c>/<c>TPM2_NV_WriteLock()</c>/<c>TPM2_NV_ReadLock()</c>/
/// <c>TPM2_NV_GlobalWriteLock()</c> and the hierarchy commands all frame an empty parameter area. For
/// <c>TPM2_NV_Read()</c> it is the requested
/// window of the Index's data area, BORROWED from the Index that owns it; the effect frames it as a
/// <c>TPM2B_MAX_NV_BUFFER</c> into its own rental and never disposes the borrowed carrier.
/// </param>
/// <param name="IsSuppliedHmacEmpty">
/// Whether the command's own <c>hmac</c> field was the Empty Buffer, read from the request before its carrier
/// was released — the No-HMAC-Authorization rule's command-side half (TPM 2.0 Library Part 1, clause 16.6.16:
/// "if hmac was an Empty Buffer in the command, it will be an Empty Buffer in the response"). Combined with an
/// empty <see cref="SessionKey"/> and a trailing-zero-stripped empty <see cref="AuthValue"/> at the framing
/// effect, an unbound unsalted session authorizing an entity with no live authValue frames <c>Tpm2bAuth.Empty</c>
/// as the response <c>hmac</c> instead of computing one — the same fold the attest family's own
/// <c>RealResponseSession</c> performs for its response sessions.
/// </param>
public sealed record TpmFrameNvSessionResponseAction(
    TpmCcConstants CommandCode,
    TpmiShAuthSession SessionHandle,
    TpmiAlgHash SessionAlg,
    SymmetricKeyMemory SessionKey,
    Tpm2bAuth AuthValue,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    TpmNvDataWindow? ReadWindow,
    bool IsSuppliedHmacEmpty = false): TpmAction;

/// <summary>
/// Declares that the simulator must fold a <c>TPM2_NV_Extend()</c> command's <c>data</c> into an Extend Index's
/// value before the next transition — <c>nvIndex→data_new = H_nameAlg(nvIndex→data_old ‖ data.buffer)</c>
/// (TPM 2.0 Library Part 1, clause 34.2.6.5, equation 56; Part 3, clause 31.9.1), the NV counterpart of
/// <see cref="TpmPcrExtendAction"/> keyed on the Index's own <c>nameAlg</c> rather than a bank's. Emitted by the
/// password arm's transition and by the HMAC-session continuation once authorization, the write-lock gate and
/// the <c>TPM_NT_EXTEND</c> type gate have passed; the effectful loop digests <c>old ‖ data</c> through the
/// registered digest seam and feeds the result back as a <see cref="TpmNvExtended"/>, whose continuation
/// stores it and frames the response.
/// </summary>
/// <param name="NvIndex">The Extend Index being extended.</param>
/// <param name="NameAlg">The Index's <c>nameAlg</c>, which is the extend's hash algorithm and fixes the digest width (Part 2, clause 13.2, Table 247: "The extend will use the nameAlg of the Index").</param>
/// <param name="PreviousValue">The Index's current value when <c>TPMA_NV_WRITTEN</c> is SET — a view into the data area the durable Index state owns, never disposed — or <see langword="null"/> when it is CLEAR, in which case the effect starts from the Zero Digest of <see cref="NameAlg"/>'s width (Part 1, clause 34.2.6.5). The attribute decides, not the data area's written extent: a Startup-cleared Index still holds its previous octets and must restart from zeros.</param>
/// <param name="Data">The command's <c>data</c> parameter (<c>TPM2B_MAX_NV_BUFFER</c>), OWNED by this action — transferred out of the request by the declaring transition — and released by the effect once digested.</param>
/// <param name="Resume">The original request — <c>TpmNvExtendRequested</c> or <c>TpmNvExtendOverSessionRequested</c> — threaded through unchanged so the continuation frames the response for the authorization form the command arrived in; its remaining carriers stay the request's own.</param>
public sealed record TpmNvExtendAction(
    TpmiRhNvIndex NvIndex,
    TpmiAlgHash NameAlg,
    ReadOnlyMemory<byte>? PreviousValue,
    Tpm2bMaxNvBuffer Data,
    TpmSimulatorInput Resume): TpmAction;

/// <summary>
/// Declares that the simulator must verify a digest/signature pair against a loaded ECC key's public point and,
/// on success, produce a <c>TPMT_TK_VERIFIED</c>. Emitted by the <c>TPM2_VerifySignature()</c> transition; the
/// effectful loop calls the injected <see cref="TpmEccDigestVerifyDelegate"/> and, when it returns
/// <see langword="true"/>, re-derives the verifying key's hierarchy proof and computes
/// <c>HMAC(proof, TPM_ST_VERIFIED || digest || keyName)</c> — the mirror image of the creation ticket's
/// <c>name || creationHash</c> field order — feeding the result back as a <see cref="TpmSignatureVerified"/> input
/// (TPM 2.0 Library Part 3, clause 20.2; Part 2, clause 10.6.5).
/// </summary>
/// <remarks>
/// The transition resolves the <c>keyHandle</c> against the loaded-object table and folds its Name, hierarchy,
/// and public point into this action, so the effect needs no automaton state and captures nothing. An
/// elliptic-curve key (ECDSA) is modelled, as the signing paths do. Verification is a public-key operation, so
/// unlike every signing action the key's <c>sign</c> attribute is never consulted here.
/// </remarks>
/// <param name="KeyName">The verifying key's Name, folded into the ticket HMAC.</param>
/// <param name="KeyHierarchy">The permanent hierarchy the verifying key was created under, from which its ticket proof re-derives.</param>
/// <param name="KeyNameAlg">The verifying key's public-area <c>nameAlg</c>: <c>TPM_ALG_NULL</c> is a second, independent trigger for the NULL-ticket short-circuit alongside <see cref="KeyHierarchy"/> being <c>TPM_RH_NULL</c> (TPM 2.0 Library Part 3, clause 12.3.1: "If hierarchy is TPM_RH_NULL or nameAlg is TPM_ALG_NULL, a ticket produced using the object shall be a NULL Ticket").</param>
/// <param name="PublicPoint">The verifying key's retained public point, SEC1 uncompressed.</param>
/// <param name="Curve">The ECC curve the public point lives on.</param>
/// <param name="Digest">The caller-supplied digest the signature is claimed to be over (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="Signature">The caller-supplied <c>TPMT_SIGNATURE</c> (TPM 2.0 Library Part 2, clause 11.3.6, Table 219), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner and reconstructs the IEEE P1363 <c>r ‖ s</c> the verify delegate takes from the union member's separately-stored components.</param>
/// <param name="HashAlg">The hash algorithm carried inside the signature.</param>
public sealed record TpmVerifySignatureAction(
    Tpm2bName KeyName,
    TpmiRhHierarchy KeyHierarchy,
    TpmiAlgHash KeyNameAlg,
    ReadOnlyMemory<byte> PublicPoint,
    TpmiEccCurve Curve,
    Tpm2bDigest Digest,
    TpmtSignature Signature,
    TpmiAlgHash HashAlg): TpmAction;

/// <summary>
/// The RSA counterpart of <see cref="TpmVerifySignatureAction"/>: verify a digest/signature pair against a
/// loaded RSA key's public modulus and exponent, read from its retained public area, under the requested RSA
/// scheme, and on success produce a <c>TPMT_TK_VERIFIED</c> the same way <see cref="TpmVerifySignatureAction"/>
/// does.
/// </summary>
/// <param name="KeyName">The verifying key's Name, folded into the ticket HMAC.</param>
/// <param name="KeyHierarchy">The permanent hierarchy the verifying key was created under, from which its ticket proof re-derives.</param>
/// <param name="KeyNameAlg">The verifying key's public-area <c>nameAlg</c>: <c>TPM_ALG_NULL</c> is a second, independent trigger for the NULL-ticket short-circuit alongside <see cref="KeyHierarchy"/> being <c>TPM_RH_NULL</c> (TPM 2.0 Library Part 3, clause 12.3.1).</param>
/// <param name="Modulus">The verifying key's public modulus, BORROWED from its retained public area's <c>unique</c> (a view into the durable object state's own <c>Tpm2bPublic</c>; the effect never disposes it).</param>
/// <param name="Exponent">The verifying key's public exponent, resolved from its retained public area's parameters (zero already resolved to the default 65537, TPM 2.0 Library Part 2, Table 228's wire convention).</param>
/// <param name="Digest">The caller-supplied digest the signature is claimed to be over (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="Signature">The caller-supplied <c>TPMT_SIGNATURE</c> (TPM 2.0 Library Part 2, clause 11.3.6, Table 219), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner and reads the RSA union member's buffer directly for the verify delegate.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to verify under.</param>
/// <param name="HashAlg">The hash algorithm carried inside the signature.</param>
public sealed record TpmRsaVerifySignatureAction(
    Tpm2bName KeyName,
    TpmiRhHierarchy KeyHierarchy,
    TpmiAlgHash KeyNameAlg,
    ReadOnlyMemory<byte> Modulus,
    uint Exponent,
    Tpm2bDigest Digest,
    TpmtSignature Signature,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash HashAlg): TpmAction;

/// <summary>
/// Declares that the simulator must verify a digest/signature pair against a loaded ECC key's public point for
/// <c>TPM2_VerifyDigestSignature()</c> and, on success, produce a <c>TPM_ST_DIGEST_VERIFIED</c>
/// <c>TPMT_TK_VERIFIED</c> — the digest-only counterpart of <see cref="TpmVerifySignatureAction"/>. Emitted by
/// the <c>TPM2_VerifyDigestSignature()</c> transition, after it has already confirmed the signature's scheme
/// (including hash) equals the key's own scheme (TPM 2.0 Library Part 3, clause 20.4.1: <c>TPM_RC_SCHEME</c>);
/// the effectful loop calls the injected <see cref="TpmEccDigestVerifyDelegate"/> and, when it returns
/// <see langword="true"/>, either short-circuits to the NULL ticket tuple (<see cref="KeyHierarchy"/> is
/// <c>TPM_RH_NULL</c>) or re-derives the verifying key's hierarchy proof and computes
/// <c>HMAC(proof, TPM_ST_DIGEST_VERIFIED || digest || keyName || metadata)</c> (Equation 5, Part 2, clause
/// 10.6.5), <c>metadata</c> being the serialized <see cref="HashAlg"/> — feeding the result back as a
/// <see cref="TpmDigestSignatureVerified"/> input.
/// </summary>
/// <remarks>
/// The transition resolves the <c>keyHandle</c> against the loaded-object table and folds its Name, hierarchy,
/// and public point into this action, so the effect needs no automaton state and captures nothing. Verification
/// is a public-key operation, so the signer's <c>sign</c> attribute is never consulted here, exactly as
/// <see cref="TpmVerifySignatureAction"/>.
/// </remarks>
/// <param name="KeyName">The verifying key's Name, folded into the ticket HMAC.</param>
/// <param name="KeyHierarchy">The permanent hierarchy the verifying key was created under, from which its ticket proof re-derives — or, when <c>TPM_RH_NULL</c>, the short-circuit to the NULL ticket tuple (TPM 2.0 Library Part 3, clause 17).</param>
/// <param name="KeyNameAlg">The verifying key's public-area <c>nameAlg</c>: <c>TPM_ALG_NULL</c> is a second, independent trigger for the NULL-ticket short-circuit alongside <see cref="KeyHierarchy"/> being <c>TPM_RH_NULL</c> (TPM 2.0 Library Part 3, clause 12.3.1).</param>
/// <param name="PublicPoint">The verifying key's retained public point, SEC1 uncompressed.</param>
/// <param name="Curve">The ECC curve the public point lives on.</param>
/// <param name="Digest">The caller-supplied digest the signature is claimed to be over (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="Signature">The caller-supplied <c>TPMT_SIGNATURE</c> (TPM 2.0 Library Part 2, clause 11.3.6, Table 219), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner and reconstructs the IEEE P1363 <c>r ‖ s</c> the verify delegate takes from the union member's separately-stored components.</param>
/// <param name="HashAlg">The hash algorithm carried inside the signature — the same value framed as the minted ticket's <c>digestVerified</c> metadata.</param>
public sealed record TpmVerifyDigestSignatureAction(
    Tpm2bName KeyName,
    TpmiRhHierarchy KeyHierarchy,
    TpmiAlgHash KeyNameAlg,
    ReadOnlyMemory<byte> PublicPoint,
    TpmiEccCurve Curve,
    Tpm2bDigest Digest,
    TpmtSignature Signature,
    TpmiAlgHash HashAlg): TpmAction;

/// <summary>
/// The RSA counterpart of <see cref="TpmVerifyDigestSignatureAction"/>: verify a digest/signature pair against
/// a loaded RSA key's public modulus and exponent, read from its retained public area, under the key's own
/// retained scheme, and on success produce a <c>TPM_ST_DIGEST_VERIFIED</c> <c>TPMT_TK_VERIFIED</c> the same way
/// <see cref="TpmVerifyDigestSignatureAction"/> does.
/// </summary>
/// <param name="KeyName">The verifying key's Name, folded into the ticket HMAC.</param>
/// <param name="KeyHierarchy">The permanent hierarchy the verifying key was created under, from which its ticket proof re-derives — or, when <c>TPM_RH_NULL</c>, the short-circuit to the NULL ticket tuple (TPM 2.0 Library Part 3, clause 17).</param>
/// <param name="KeyNameAlg">The verifying key's public-area <c>nameAlg</c>: <c>TPM_ALG_NULL</c> is a second, independent trigger for the NULL-ticket short-circuit alongside <see cref="KeyHierarchy"/> being <c>TPM_RH_NULL</c> (TPM 2.0 Library Part 3, clause 12.3.1).</param>
/// <param name="Modulus">The verifying key's public modulus, BORROWED from its retained public area's <c>unique</c> (a view into the durable object state's own <c>Tpm2bPublic</c>; the effect never disposes it).</param>
/// <param name="Exponent">The verifying key's public exponent, resolved from its retained public area's parameters (zero already resolved to the default 65537, TPM 2.0 Library Part 2, Table 228's wire convention).</param>
/// <param name="Digest">The caller-supplied digest the signature is claimed to be over (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="Signature">The caller-supplied <c>TPMT_SIGNATURE</c> (TPM 2.0 Library Part 2, clause 11.3.6, Table 219), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner and reads the RSA union member's buffer directly for the verify delegate.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to verify under.</param>
/// <param name="HashAlg">The hash algorithm carried inside the signature — the same value framed as the minted ticket's <c>digestVerified</c> metadata.</param>
public sealed record TpmRsaVerifyDigestSignatureAction(
    Tpm2bName KeyName,
    TpmiRhHierarchy KeyHierarchy,
    TpmiAlgHash KeyNameAlg,
    ReadOnlyMemory<byte> Modulus,
    uint Exponent,
    Tpm2bDigest Digest,
    TpmtSignature Signature,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash HashAlg): TpmAction;

/// <summary>
/// Declares that the simulator must recompute <c>TPM2_PolicySigned()</c>'s <c>aHash</c> and verify it against a
/// loaded ECC key's public point before the next transition (TPM 2.0 Library Part 3, clause 23.3). Emitted by
/// the <c>TPM2_PolicySigned()</c> transition for a non-trial session whose <c>authObject</c> resolves to an ECC
/// key, after the (non-crypto) nonceTPM/expiration/cpHashA checks have already passed; the effectful loop hashes
/// <c>nonceTPM ‖ expiration ‖ cpHashA ‖ policyRef</c> with <see cref="SchemeHashAlg"/> (the signature scheme's own
/// hash — independent of <see cref="PolicyHashAlgorithm"/>) through the registered async digest seam, calls the
/// injected <see cref="TpmEccDigestVerifyDelegate"/>, and feeds the boolean result back as a
/// <see cref="TpmPolicySignedVerified"/> input. On a successful verification, a non-trial session whose caller
/// requested a ticket (<see cref="Expiration"/> negative) mints a real <c>TPMT_TK_AUTH{TPM_ST_AUTH_SIGNED}</c>
/// per equation 12 (Part 2, Table 114) using <see cref="Hierarchy"/>'s proof; otherwise (no ticket requested, or
/// a trial session, which never reaches this action at all) the response frames a NULL ticket, mirroring
/// <see cref="TpmVerifySignatureAction"/>'s own success/no-ticket split.
/// </summary>
/// <param name="PolicySession">The policy session to extend on a successful verification.</param>
/// <param name="AuthObjectName">The authorizing key's Name, folded into the policyDigest fold (<c>arg2</c> of <c>PolicyUpdate</c>) and into the ticket HMAC's <c>authName</c> term — a borrowed reference to the <c>TPM2B_NAME</c> carrier the durable object state owns; the effect reads it at the digest primitives and never disposes it.</param>
/// <param name="PolicyRef">The policy qualifier, always folded as the second <c>PolicyUpdate</c> hash (Part 3, clause 23.2.3) and, when a ticket is minted, into the ticket HMAC's <c>policyRef</c> term — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="PolicyHashAlgorithm">The session's own policy hash algorithm, sizing the policyDigest fold — independent of <see cref="SchemeHashAlg"/>.</param>
/// <param name="CurrentPolicyDigest">The session's current accumulated policyDigest — a borrowed reference to the carrier the durable session record owns; the effect reads it as the fold's first term and never disposes it.</param>
/// <param name="NonceTpm">The nonceTPM bytes folded into <c>aHash</c> (already validated against the session's retained nonce), in an owned carrier the request record transferred into this action; the effect is its terminal owner once the aHash has bound to it. Also selects the ticket's <c>expiresOnReset</c> flag (empty ⇒ absolute deadline ⇒ expires on reset).</param>
/// <param name="Expiration">The signed expiration folded into <c>aHash</c> as 4 big-endian octets; its sign requests a ticket (negative) or not (zero or positive).</param>
/// <param name="CpHashA">The cpHashA bytes folded into <c>aHash</c> (already size- and latch-checked) and, when a ticket is minted, into the ticket HMAC's <c>cpHash</c> term — an owned carrier the transition transferred out of the request; the effect hands it onward to the continuation, which latches or releases it.</param>
/// <param name="PublicPoint">The authorizing key's retained public point, SEC1 uncompressed.</param>
/// <param name="Curve">The ECC curve the public point lives on.</param>
/// <param name="Signature">The caller-supplied <c>TPMT_SIGNATURE auth</c> (TPM 2.0 Library Part 2, clause 11.3.6, Table 219), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner and reconstructs the IEEE P1363 <c>r ‖ s</c> the verify delegate takes from the union member's separately-stored components.</param>
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
    TpmtSignature Signature,
    TpmiAlgHash SchemeHashAlg,
    TpmiRhHierarchy Hierarchy,
    ulong Timeout,
    uint TimeEpoch,
    uint ResetCount): TpmAction;

/// <summary>
/// The RSA counterpart of <see cref="TpmVerifyPolicySignedAction"/>: recompute <c>TPM2_PolicySigned()</c>'s
/// <c>aHash</c> and verify it against a loaded RSA key's public modulus and exponent, read from its retained
/// public area, under the requested RSA scheme, the same way <see cref="TpmVerifyPolicySignedAction"/> does,
/// including the same ticket-minting behaviour on success.
/// </summary>
/// <param name="PolicySession">The policy session to extend on a successful verification.</param>
/// <param name="AuthObjectName">The authorizing key's Name, folded into the policyDigest fold (<c>arg2</c> of <c>PolicyUpdate</c>) and into the ticket HMAC's <c>authName</c> term — a borrowed reference to the <c>TPM2B_NAME</c> carrier the durable object state owns; the effect reads it at the digest primitives and never disposes it.</param>
/// <param name="PolicyRef">The policy qualifier, always folded as the second <c>PolicyUpdate</c> hash (Part 3, clause 23.2.3) and, when a ticket is minted, into the ticket HMAC's <c>policyRef</c> term — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="PolicyHashAlgorithm">The session's own policy hash algorithm, sizing the policyDigest fold — independent of <see cref="SchemeHashAlg"/>.</param>
/// <param name="CurrentPolicyDigest">The session's current accumulated policyDigest — a borrowed reference to the carrier the durable session record owns; the effect reads it as the fold's first term and never disposes it.</param>
/// <param name="NonceTpm">The nonceTPM bytes folded into <c>aHash</c> (already validated against the session's retained nonce), in an owned carrier the request record transferred into this action; the effect is its terminal owner once the aHash has bound to it. Also selects the ticket's <c>expiresOnReset</c> flag (empty ⇒ absolute deadline ⇒ expires on reset).</param>
/// <param name="Expiration">The signed expiration folded into <c>aHash</c> as 4 big-endian octets; its sign requests a ticket (negative) or not (zero or positive).</param>
/// <param name="CpHashA">The cpHashA bytes folded into <c>aHash</c> (already size- and latch-checked) and, when a ticket is minted, into the ticket HMAC's <c>cpHash</c> term — an owned carrier the transition transferred out of the request; the effect hands it onward to the continuation, which latches or releases it.</param>
/// <param name="Modulus">The authorizing key's public modulus, BORROWED from its retained public area's <c>unique</c> (a view into the durable object state's own <c>Tpm2bPublic</c>; the effect never disposes it).</param>
/// <param name="Exponent">The authorizing key's public exponent, resolved from its retained public area's parameters (zero already resolved to the default 65537, TPM 2.0 Library Part 2, Table 228's wire convention).</param>
/// <param name="Signature">The caller-supplied <c>TPMT_SIGNATURE auth</c> (TPM 2.0 Library Part 2, clause 11.3.6, Table 219), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner and reads the RSA union member's buffer directly for the verify delegate.</param>
/// <param name="Scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>) to verify under.</param>
/// <param name="SchemeHashAlg">H_authAlg: the hash algorithm carried inside the <c>TPMT_SIGNATURE auth</c> parameter — independent of <see cref="PolicyHashAlgorithm"/>.</param>
/// <param name="Hierarchy">The authorizing key's hierarchy, from which the ticket's proof derives when a ticket is minted, and the value framed in the ticket's own <c>hierarchy</c> field.</param>
/// <param name="Timeout">The already-computed deadline magnitude (the value the transition's own inline deadline check produced, never recomputed here); zero when <see cref="Expiration"/> is zero.</param>
/// <param name="TimeEpoch">The TPM's current time epoch, folded into equation 12 (Part 2, Table 114)'s conditional <c>[timeEpoch]</c> term when a ticket is minted.</param>
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
    ReadOnlyMemory<byte> Modulus,
    uint Exponent,
    TpmtSignature Signature,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash SchemeHashAlg,
    TpmiRhHierarchy Hierarchy,
    ulong Timeout,
    uint TimeEpoch,
    uint ResetCount): TpmAction;

/// <summary>
/// Declares that the simulator must recompute <c>TPM2_PolicyAuthorize()</c>'s <c>aHash</c> and re-verify
/// <c>checkTicket</c> before the next transition (TPM 2.0 Library Part 3, clause 23.16). Emitted by the
/// <c>TPM2_PolicyAuthorize()</c> transition for a non-trial session, after the (non-crypto) <c>keySign</c>
/// hash-algorithm/size checks and the <c>approvedPolicy</c> equality check have already passed; the effectful
/// loop hashes <c>approvedPolicy ‖ policyRef</c> with <see cref="HashAlg"/> (<c>keySign</c>'s own nameAlg)
/// through the registered async digest seam, derives the hierarchy proof for the CALLER-SUPPLIED
/// <see cref="CheckTicketHierarchy"/> (never independently re-derived from <c>keySign</c> — the caller's claim
/// is exactly what is being checked), recomputes <c>HMAC(proof, checkTicketTag ‖ aHash ‖ keySign ‖
/// checkTicketMetadata)</c> — Equation (5), Part 2, clause 10.6.5 — through the existing verified-ticket formula
/// under the CALLER-SUPPLIED <see cref="CheckTicketTag"/>/<see cref="CheckTicketMetadata"/>, and constant-time
/// compares it to <see cref="CheckTicketDigest"/>, feeding the boolean result back as a
/// <see cref="TpmPolicyAuthorizeVerified"/> input.
/// </summary>
/// <param name="PolicySession">The policy session to reset-and-fold on a successful ticket re-verification.</param>
/// <param name="ApprovedPolicy">The approved policyDigest, folded into <c>aHash</c> — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="PolicyRef">The policy qualifier, folded into <c>aHash</c> and always folded as the fold's second <c>PolicyUpdate</c> hash — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="KeySign">The Name of the key that signed the approval, folded into the ticket HMAC and the policyDigest fold — an owned <c>TPM2B_NAME</c> carrier the transition transferred out of the request; the effect is its terminal owner, since the fold it feeds runs there.</param>
/// <param name="HashAlg"><c>aHash</c>'s hash algorithm — <c>keySign</c>'s own nameAlg, independent of the session's own policy hash algorithm.</param>
/// <param name="CheckTicketTag">The caller-supplied checkTicket structure tag — one of Table 112's three values — folded into the Equation (5) recompute.</param>
/// <param name="CheckTicketHierarchy">The caller-supplied hierarchy the expected ticket's proof is derived from.</param>
/// <param name="CheckTicketMetadata">The caller-supplied checkTicket <c>[tag]metadata</c> field (Table 111), folded into the Equation (5) recompute alongside <see cref="CheckTicketTag"/>.</param>
/// <param name="CheckTicketDigest">The caller-supplied ticket digest to compare the recomputed one against — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="PolicyHashAlgorithm">The session's own policy hash algorithm, sizing the policyDigest fold.</param>
public sealed record TpmVerifyPolicyAuthorizeTicketAction(
    TpmiShPolicy PolicySession,
    Tpm2bDigest ApprovedPolicy,
    Tpm2bNonce PolicyRef,
    Tpm2bName KeySign,
    TpmiAlgHash HashAlg,
    TpmStConstants CheckTicketTag,
    TpmiRhHierarchy CheckTicketHierarchy,
    TpmiAlgHash? CheckTicketMetadata,
    Tpm2bDigest CheckTicketDigest,
    TpmiAlgHash PolicyHashAlgorithm): TpmAction;

/// <summary>
/// Declares that the simulator must recompute a <c>TPM2_PolicyTicket()</c> ticket per equation 12 (Part 2,
/// Table 114) and constant-time compare it to the caller-supplied <see cref="TicketDigest"/> before the next
/// transition (TPM 2.0 Library Part 3, clause 23.5). Emitted after the trial-session, timeout-size,
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
/// <param name="Tag">The ticket's own structure tag (<c>TPM_ST_AUTH_SIGNED</c> or <c>TPM_ST_AUTH_SECRET</c>, already legality-checked at parse — Part 2, Table 114's <c>TPM_RC_TAG</c> rule), folded into the recomputed HMAC and selecting the fold (<c>ExtendForSigned</c> vs <c>ExtendForSecret</c>) on success.</param>
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
/// (Part 2, Table 114) before the next transition (TPM 2.0 Library Part 3, clause 23.4). Emitted by the
/// <c>TPM2_PolicySecret()</c> transition for a non-trial session whose caller requested a ticket (a negative
/// expiration), after the authValue/nonceTPM/expiration/cpHashA checks have already passed; the effectful loop
/// derives <see cref="Hierarchy"/>'s proof and recomputes the ticket HMAC, feeding the result back as a
/// <see cref="TpmPolicySecretTicketMinted"/> input. Minting an HMAC has no failure mode of its own (unlike the
/// PolicySigned/PolicyTicket verify actions, which can fail a signature check or a ticket comparison), so
/// there is no rejection response code to carry.
/// </summary>
/// <param name="PolicySession">The policy session to fold on completion.</param>
/// <param name="AuthName">The authorizing entity's Name term — a permanent entity's Name IS its 4-octet handle value (Part 1, clause 13, Table 9) — folded into the ticket HMAC's <c>authName</c> term and the policyDigest fold; the octets are materialized by the effect, which is the frame that holds a memory pool.</param>
/// <param name="PolicyRef">The policy qualifier, folded into the ticket HMAC's <c>policyRef</c> term and, again, as the fold's second <c>PolicyUpdate</c> hash — an owned carrier the transition transferred out of the request; the effect is its terminal owner.</param>
/// <param name="PolicyHashAlgorithm">The session's own policy hash algorithm, sizing the policyDigest fold.</param>
/// <param name="CurrentPolicyDigest">The session's current accumulated policyDigest — a borrowed reference to the carrier the durable session record owns; the effect reads it as the fold's first term and never disposes it.</param>
/// <param name="CpHashA">
/// The cpHashA bytes (already size- and latch-checked), folded into the ticket HMAC's <c>cpHash</c> term — a
/// borrowed reference to the carrier the durable session record owns once the latch of Part 3, clause 23.2.4
/// has run, or the dispose-immune empty sentinel when the caller supplied none. It is a borrow rather than a
/// second rental precisely because the latch already made the session the value's single owner, and the session
/// outlives this effect by construction; the effect reads it at the HMAC primitive and never disposes it.
/// </param>
/// <param name="Hierarchy">The authorizing entity's OWNING hierarchy (the transition's own EntityGetHierarchyForPermanentHandle mapping — Part 1, clause 11.5 — never the raw authHandle, which is not always itself a legal <c>TPMI_RH_HIERARCHY+</c> value), from which the ticket's proof derives, and the value framed in the ticket's own <c>hierarchy</c> field.</param>
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
/// transition (TPM 2.0 Library Part 1, clause 16.7; Part 3, clause 23). One action serves every assertion whose
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
/// <param name="PcrSelection">The parsed <c>TPML_PCR_SELECTION</c> (<see cref="TpmPolicyDigestFold.Pcr"/>), masked in place to the implemented banks and registers by the declaring transition on a real session and left as the caller sent it on a trial one (<c>RetainImplementedPcrs</c>, Part 3, clause 23.7) — an owned carrier the transition transferred out of the request; the effect re-marshals it for the fold and is its terminal owner. The dispose-immune empty sentinel for every other formula.</param>
/// <param name="PcrDigest">The caller-supplied expected PCR digest (<see cref="TpmPolicyDigestFold.Pcr"/>) — an owned carrier the transition transferred out of the request; the effect is its terminal owner. Folded verbatim on a trial session; compared against the live composite on a real one.</param>
/// <param name="PcrValues">The currently selected PCR values in ascending index order (<see cref="TpmPolicyDigestFold.Pcr"/>), from which the effect computes the live composite a real session binds to — borrowed references to the durable bank's own memory, never disposed here.</param>
/// <param name="IsTrialSession">Whether the session accumulates without authorizing, which for <see cref="TpmPolicyDigestFold.Pcr"/> selects the caller's digest verbatim over the live composite (Part 3, clause 23.7).</param>
/// <param name="OperandB">The comparison operand the argHash covers (<see cref="TpmPolicyDigestFold.CounterTimer"/>) — an owned <c>TPM2B_OPERAND</c> carrier (TPM 2.0 Library Part 2, clause 10.3.6, Table 94) the transition transferred out of the request; the effect is its terminal owner. The dispose-immune empty sentinel for every other formula.</param>
/// <param name="Offset">The octet offset the argHash covers (<see cref="TpmPolicyDigestFold.CounterTimer"/>).</param>
/// <param name="Operation">The <c>TPM_EO</c> comparison the argHash covers (<see cref="TpmPolicyDigestFold.CounterTimer"/>).</param>
/// <param name="TimeoutMagnitude">The deadline magnitude the session's own tracked timeout ranks under Part 3, clause 23.2.4's min-with-existing rule (<see cref="TpmPolicyDigestFold.Secret"/>, <see cref="TpmPolicyDigestFold.Signed"/>). Every arm that reaches this action frames a NULL ticket and a NULL timeout (clause 23.2.5) — a real ticket is minted in its own effect, which folds there too — so the deadline travels as this magnitude alone.</param>
/// <param name="AuthorizingSession">The HMAC or POLICY session that authorized <c>TPM2_PolicySecret()</c>, or <see langword="null"/> for its password arm; threaded through so the resuming transition frames the same response shape the fold has always framed.</param>
/// <param name="BoundDigest">The latched digest the formula folds (<see cref="TpmPolicyDigestFold.CpHash"/>, <see cref="TpmPolicyDigestFold.NameHash"/>, <see cref="TpmPolicyDigestFold.Template"/>): a BORROW of the carrier the session already owns, so the effect reads it and never disposes it. The dispose-immune empty sentinel for every other formula.</param>
/// <param name="Locality">The marshaled <c>TPMA_LOCALITY</c> octet the formula folds as sent (<see cref="TpmPolicyDigestFold.Locality"/>), zero for every other formula.</param>
/// <param name="IsNvWrittenRequired">The <c>writtenSet</c> value the formula folds as one octet (<see cref="TpmPolicyDigestFold.NvWritten"/>), meaningless for every other formula.</param>
/// <param name="ObjectName">The Name of the object to be duplicated (<see cref="TpmPolicyDigestFold.DuplicationSelect"/>) — an owned <c>TPM2B_NAME</c> carrier (TPM 2.0 Library Part 2, clause 10.4.3, Table 105) the transition transferred out of the request; the effect folds it into the policyDigest only when <see cref="IsObjectIncluded"/> is SET, hashes it into the nameHash it latches either way, and is its terminal owner. The dispose-immune empty sentinel for every other formula.</param>
/// <param name="NewParentName">The Name of the new parent (<see cref="TpmPolicyDigestFold.DuplicationSelect"/>) — an owned <c>TPM2B_NAME</c> carrier the transition transferred out of the request; the effect is its terminal owner. The dispose-immune empty sentinel for every other formula.</param>
/// <param name="IsObjectIncluded">Whether <c>includeObject</c> was YES (<see cref="TpmPolicyDigestFold.DuplicationSelect"/>): the object Name is folded into the policyDigest and the octet is folded as 1; otherwise only the new parent Name and a 0 octet are folded (TPM 2.0 Library Part 3, clause 23.15).</param>
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
    TpmlPcrSelection PcrSelection,
    Tpm2bDigest PcrDigest,
    ImmutableArray<ReadOnlyMemory<byte>> PcrValues,
    bool IsTrialSession,
    Tpm2bOperand OperandB,
    ushort Offset,
    ushort Operation,
    ulong TimeoutMagnitude,
    PolicySecretAuthorizingSession? AuthorizingSession,
    Tpm2bDigest BoundDigest,
    byte Locality,
    bool IsNvWrittenRequired,
    Tpm2bName ObjectName,
    Tpm2bName NewParentName,
    bool IsObjectIncluded): TpmAction;

/// <summary>
/// Declares that the simulator must roll the authorizing session's nonceTPM and frame a real response session
/// entry for <c>TPM2_PolicySecret()</c> before the next transition — a command-specific response-framing step,
/// alongside <see cref="TpmCreateKeyedHashOverSessionsAction"/>'s, for a command whose response is a
/// timeout/ticket pair rather than an encryptable parameter (TPM 2.0 Library Part 1, clause 15.6.1).
/// Emitted by <c>FoldPolicySecret</c> once the policyDigest fold itself has already been decided (trial fold,
/// immediate no-ticket fold, or the ticket-mint continuation) whenever authHandle's authorization was proven by
/// a real session rather than a password; the effectful loop frames <c>TPM2B_TIMEOUT ‖ TPMT_TK_AUTH</c> via the
/// same helper the password arm's response uses, rolls a fresh nonceTPM, computes rpHash over those framed
/// bytes, and computes the response HMAC keyed on the SAME <c>sessionKey ‖ authValue</c> the command HMAC
/// verification used (Part 1, clause 16.6.5), feeding the result back as a
/// <see cref="TpmPolicySecretSessionResponseFramed"/> input.
/// </summary>
/// <param name="SessionHandle">The authorizing session whose nonceTPM is rolled once framed.</param>
/// <param name="IsPolicySession">Whether <see cref="SessionHandle"/> names a POLICY session (routes the roll to <c>PolicySessions</c>) rather than an HMAC session (<c>HmacSessions</c>).</param>
/// <param name="SessionAlg">The session hash algorithm driving rpHash and the response HMAC.</param>
/// <param name="SessionKey">The session key — a borrowed reference to the carrier the durable session record owns; the effect reads it at the HMAC primitive and never disposes it.</param>
/// <param name="AuthValue">The authValue folded into the response HMAC key alongside <see cref="SessionKey"/> — a borrowed reference to the carrier the durable state owns, carrying the same value (and the same eq. 22 (Part 1, clause 16.6.10)/26/27 (Part 1, clause 16.6.12) decision) the command-HMAC verification used; the effect reads its trailing-zero-stripped view at the HMAC primitive and never disposes it.</param>
/// <param name="NonceCaller">This session's command caller nonce (<c>TPM2B_NONCE</c>, Part 2, clause 10.3.4, Table 92) — the response HMAC's nonceOlder. OWNED: transferred out of the authorizing-session entry the request record fed, and released by this effect's <see langword="finally"/>.</param>
/// <param name="SessionAttributes">This session's command session-attributes octet, echoed into its response entry.</param>
/// <param name="Timeout">The already-decided deadline as a <c>TPM2B_TIMEOUT</c> carrier (clause 23.2.5; TPM 2.0 Library Part 2, clause 10.3.10, Table 98) — owned; the effect is its terminal owner, consuming and disposing it while framing the response parameter bytes. The shared empty carrier when <see cref="TicketDigest"/> is <see langword="null"/>, where a NULL timeout is framed.</param>
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
/// <c>inSensitive</c> before the next transition — a request-direction decryption step (TPM 2.0 Library Part 1,
/// clauses 18 and 20; Part 3, clause 5.7). Emitted
/// once every session in the command's authorization area has verified (Part 3, clause 5.6 precedes clause 5.7);
/// the effectful loop decrypts the data portion of <see cref="RawParameterArea"/>'s first parameter in place when
/// <see cref="HasDecryptSession"/> is set, then decodes <c>userAuth</c>/<c>data</c> with bounds-checked reads (a
/// wrong decryption key's garbage bytes must not crash the simulator) and feeds the result back as a
/// <see cref="TpmCreateSensitiveDecrypted"/> input.
/// </summary>
/// <remarks>
/// Either slot of this command's area may carry the <c>decrypt</c> attribute — "a session with this attribute
/// does not need to be associated with an entity identified in the handle area" (Part 1, clause 15.6.4, Table
/// 15), so it rides the parent's own authorizing session as readily as a separate companion. The claiming slot
/// decides <see cref="EntityAuthValue"/>: the parent's LIVE authValue when the authorizing slot claims it,
/// and the shared empty carrier for a companion, whose <c>sessionValue</c> is then <see cref="SessionKey"/>
/// alone ("if the session is not being used for authorization, sessionValue is sessionKey", clause 18.1).
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
/// bind, because "the binding of the session is ignored" for parameter encryption (Part 1, clause 18.1), unlike
/// the command HMAC key which drops it under equation 22's omission (clause 16.6.10). The shared empty carrier
/// when the decrypt session authorizes no entity — a companion — and the parent's own authValue when the
/// parent's authorizing slot is the one that claimed the attribute. A borrowed reference to the carrier the
/// durable state owns; the effect reads its trailing-zero-stripped view at the keystream primitive and never
/// disposes it.
/// </param>
/// <param name="NonceCaller">The decrypt session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92) — the decryption's nonceNewer (Part 1, clause 18.2). A BORROW of the slot's carrier on the request record, which outlives this step and transfers it into that slot's response-session entry afterwards. Meaningless when <see cref="HasDecryptSession"/> is clear.</param>
/// <param name="NonceTpm">The decrypt session's stored nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92) — the decryption's nonceOlder; a borrowed reference to the carrier the durable session record owns. Meaningless when <see cref="HasDecryptSession"/> is clear.</param>
public sealed record TpmDecryptCreateSensitiveAction(
    TpmCreateKeyedHashOverSessionsRequested Request,
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
/// </c><see cref="EntityAuthValue"/> folds in the authorizing hierarchy's authValue, unlike <c>TPM2_Create()</c>'s
/// separate decrypt companion, whose sessionValue is its session key alone; the effect concatenates the two terms
/// in pooled pinned scratch at the primitive.
/// </summary>
/// <remarks>
/// The effect XOR-obfuscates or AES-CFB-decrypts the data portion of the first sized parameter in place (its
/// 2-octet size field is never itself encrypted, Part 1, clause 18.1), reads back the plaintext <c>auth</c>
/// value, and feeds it to <c>OnNvDefineAuthDecrypted</c>, which strips its trailing zeros (Part 1, clause
/// 16.6.4.3) before storing it as the Index authValue and frames the session-authorized response.
/// </remarks>
/// <param name="Request">The parsed session-authorized <c>TPM2_NV_DefineSpace()</c> request, its command HMAC now verified, threaded to the completing transition.</param>
/// <param name="RawParameterArea">The raw <c>auth ‖ publicInfo</c> wire bytes captured at parse time, still carrying the encrypted <c>auth</c> data portion. A BORROW: the request record owns the carrier and every terminal path releases it there, while the in-place transform writes through <see cref="TpmParameterArea.Memory"/> so the octets cpHash digested as ciphertext are the octets the body decodes as plaintext (Part 3, clause 5.6 before clause 5.7).</param>
/// <param name="SessionAlg">The authorizing session's hash algorithm, driving its KDFa keystream.</param>
/// <param name="Symmetric">The session's negotiated symmetric definition, selecting XOR obfuscation or AES-CFB.</param>
/// <param name="SessionKey">The session's session key — a borrowed reference to the carrier the durable session record owns; the effect reads it at the keystream primitive and never disposes it.</param>
/// <param name="EntityAuthValue">
/// The authValue of the entity this session authorizes — the owner or the platform hierarchy's — folded into
/// the keystream's <c>sessionValue</c> after <see cref="SessionKey"/>. It is the hierarchy's LIVE value, UNRESOLVED by the
/// session's bind: "the binding of the session is ignored" for parameter encryption (Part 1, clause 18.1), so a
/// session bound to the very entity it authorizes still folds that entity's authValue into the CIPHER key even
/// though its command HMAC key omits it under equation 22 (clause 16.6.10). A borrowed reference to the carrier
/// the durable state owns; the effect reads its trailing-zero-stripped view at the keystream primitive and never
/// disposes it.
/// </param>
/// <param name="NonceCaller">The session's caller nonce for this command (the decryption's nonceNewer, TPM 2.0 Library Part 1, clause 18.2) — a BORROWED reference to the carrier the in-flight request owns, which outlives this effect; the effect reads it at the keystream and never disposes it.</param>
/// <param name="NonceTpm">The session's stored nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92) — the decryption's nonceOlder; a borrowed reference to the carrier the durable session record owns.</param>
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
/// <see cref="SessionKey"/> is its whole <c>sessionValue</c> (Part 1, clause 18.1: "If the session is not being
/// used for authorization, sessionValue is sessionKey"). That separation is the point: a single session doing
/// both jobs would key the parameter encryption on the very authValue being rotated away from. The effect
/// XOR-obfuscates or AES-CFB-decrypts the data portion of the first sized parameter in place (its 2-octet size
/// field is never itself encrypted, Part 1, clause 18.1), reads back the plaintext, and feeds it to the
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
/// bind (Part 1, clause 18.1: "the binding of the session is ignored"). The shared empty carrier when the
/// decrypt session authorizes no entity, which on this command it never does. A borrowed reference to the
/// carrier the durable state owns; the effect never disposes it.
/// </param>
/// <param name="NonceCaller">The decrypt session's caller nonce for this command (the decryption's nonceNewer, TPM 2.0 Library Part 1, clause 18.2) — a BORROWED reference to the carrier the in-flight request owns, which outlives this effect; the effect reads it at the keystream and never disposes it.</param>
/// <param name="NonceTpm">The decrypt session's stored nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92) — the decryption's nonceOlder; a borrowed reference to the carrier the durable session record owns, which the effect reads at the keystream primitive and never disposes.</param>
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
/// response entry for a two-session NV or hierarchy command — <c>TPM2_NV_ChangeAuth()</c>,
/// <c>TPM2_HierarchyChangeAuth()</c>, or <c>TPM2_NV_UndefineSpaceSpecial()</c>, named by
/// <see cref="CommandCode"/> — before the next transition (TPM 2.0 Library Part 1, clause 15.6.1). Emitted once
/// the command's effect on its entity (an authValue rotation, or an Index deletion) has been committed; the
/// effectful loop computes rpHash over the empty response parameter area, draws a fresh nonceTPM per session,
/// and computes each session's own response HMAC keyed on its own <c>sessionKey ‖ authValue</c>, feeding the
/// result back as a <see cref="TpmNvChangeAuthResponseFramed"/> input.
/// </summary>
/// <remarks>
/// This is the two-session framing counterpart of the single-entry <see cref="TpmFrameNvSessionResponseAction"/> —
/// named for the shape every one of its three consumers shares (an ADMIN/policy-authorized entry at slot 0, a
/// platform password-or-HMAC entry at slot 1, no response parameters), not for any one of them, since
/// <c>TPM2_NV_UndefineSpaceSpecial()</c> and <c>TPM2_NV_ChangeAuth()</c> authorize an NV Index rather than a
/// hierarchy. <c>TPM2_NV_ChangeAuth()</c> and <c>TPM2_HierarchyChangeAuth()</c> (Part 3, clause 24.8) both admit a
/// second (decrypt) session protecting <c>newAuth</c>; <c>TPM2_NV_UndefineSpaceSpecial()</c> (clause 31.5) instead
/// carries a SECOND AUTHORIZING slot (<c>@platform</c>), never a decrypt companion — but the wire shape a
/// response entry frames (Part 1, clause 15.6.1's one-entry-per-command-session rule) is identical either way.
/// None of the three commands return parameters (Part 3, clause 31.15, Table 270; Part 3, clause 24.8.1; Part 3, clause 31.5, Table 250),
/// so every response entry's rpHash covers the empty parameter area. The authorizing session's
/// <c>AuthValue</c> entry is resolved by the declaring transition rather than here: the two rotations key it on
/// the POST-rotation value where the policy required one (clause 31.15.1: "Since the NV Index authorization is
/// changed before the response HMAC is calculated, the newAuth value is used when generating the response HMAC
/// key if required"), while the deletion keys its ADMIN policy entry on the Empty Buffer UNCONDITIONALLY
/// (clause 31.5.1: "Since the index is deleted, the Empty Buffer is used as the authValue...") — there is no
/// new value for a deleted Index to key on.
/// </remarks>
/// <param name="CommandCode">
/// The command whose response is being framed, folded into rpHash as equation 16's <c>commandCode</c> term
/// (Part 1, clause 15.8). Because this action serves all three commands, the code must be carried rather than
/// assumed: a response framed under one command's code cannot verify against a host that computed rpHash under
/// another's.
/// </param>
/// <param name="ResponseSessions">Every session in the command's authorization area, in command-session order, each with the key material its own response entry needs.</param>
public sealed record TpmFrameTwoSlotResponseAction(
    TpmCcConstants CommandCode,
    ImmutableArray<TpmNvChangeAuthResponseSession> ResponseSessions): TpmAction;

/// <summary>
/// Declares that the simulator must frame the <c>TPM2_Create()</c> response over sessions before the next
/// transition — the request-decrypt counterpart of <see cref="TpmUnsealDataAction"/>. Emitted once
/// <c>inSensitive</c> has been decrypted (if applicable) and decoded; the effectful loop builds the sealed
/// object's wrapped private blob, exported public area, and creation by-products exactly as
/// <see cref="TpmCreateKeyedHashAction"/> does, then rolls a fresh nonceTPM per real session, computes rpHash over the
/// (unencrypted — response encryption is out of scope for <c>TPM2_Create()</c>) response parameter
/// area, and each real session's own response HMAC keyed on its own <c>sessionKey ‖ authValue</c> (Part 1,
/// clause 16.6.8).
/// </summary>
/// <param name="ParentHandle">The storage parent the object is sealed under, resolved by the declaring transition to authorize the seal; the creation data's <c>parentName</c>/<c>parentQualifiedName</c> instead come from <see cref="ParentName"/> (TPM 2.0 Library Part 2, clause 15.1, Table 261).</param>
/// <param name="ParentHierarchy">
/// The hierarchy the storage parent belongs to, which is the hierarchy the created object belongs to and so the
/// one the creation ticket names and whose proof keys its HMAC (<c>TPMI_RH_HIERARCHY+</c>, TPM 2.0 Library
/// Part 2, clause 10.6.3, Table 110: "the hierarchy containing name"; Part 4's <c>TPM2_Create()</c> computes
/// the ticket over <c>EntityGetHierarchy(parentHandle)</c>). Distinct from <see cref="ParentHandle"/>, which
/// binds the creation DATA.
/// </param>
/// <param name="NameAlg">The Name algorithm to carry in the exported public area.</param>
/// <param name="AuthPolicy">The authorization policy digest to re-emit into the exported public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90; empty for an authValue-only seal), the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner and releases it in its <c>finally</c> — <c>TPM2_Create()</c> installs no durable object, so the copy the exported public area takes is the digest's only use.</param>
/// <param name="NoDa">Whether the template set <c>TPMA_OBJECT.noDA</c>, so the exported public area reproduces the caller's template.</param>
/// <param name="UserWithAuth">Whether the template set <c>TPMA_OBJECT.userWithAuth</c>, so the exported public area reproduces the caller's template.</param>
/// <param name="IsDuplicable">Whether the caller's template carries <c>TPMA_OBJECT.fixedTPM</c> and <c>fixedParent</c> CLEAR — the declaring transition has already judged the clause 8.3.3 consistency rows, so this one bit reproduces the caller's duplicability choice on the exported public area (TPM 2.0 Library Part 2, clause 8.3.2, Table 37).</param>
/// <param name="SecretData">The data to seal (<c>TPMS_SENSITIVE_CREATE.data</c>, a <c>TPM2B_SENSITIVE_DATA</c> — TPM 2.0 Library Part 2, clause 11.1.14, Table 170), the owned <see cref="Tpm2bSensitiveData"/> carrier the decrypt step rented; ownership rides this action into the effect, which packs it into the wrapped private blob and releases it.</param>
/// <param name="UserAuth">The new object's authorization value (<c>TPMS_SENSITIVE_CREATE.userAuth</c>, a <c>TPM2B_AUTH</c>), the owned <see cref="Tpm2bAuth"/> carrier the decrypt step rented; ownership rides this action into the effect, which packs it into the wrapped private blob alongside <see cref="SecretData"/> and releases it (TPM 2.0 Library Part 1, clause 16.6.4).</param>
/// <param name="HasPasswordPlaceholder">Whether session index 0 is a <c>TPM_RS_PW</c> session needing the empty-nonce, empty-HMAC password placeholder entry (Part 1, clause 16.6.4).</param>
/// <param name="PasswordPlaceholderAttributes">The password session's command session-attributes octet, framed into its placeholder entry. Meaningful only when <see cref="HasPasswordPlaceholder"/> is set.</param>
/// <param name="ResponseSessions">Every real (HMAC-table) session needing a framed response entry, in command-session order (after the password placeholder, when present).</param>
/// <param name="OutsideInfo">The decoded <c>outsideInfo</c> parameter, included in the creation data (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2, clause 10.3.3, Table 91; Part 3, clause 12.1, Table 18, <c>outsideInfo</c> row), the owned pooled carrier the decrypt step rented; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="CreationPcr">The decoded <c>creationPCR</c> parameter the creation data's <c>pcrDigest</c> is computed over (<c>TPML_PCR_SELECTION</c>, TPM 2.0 Library Part 2, clause 10.8.7, Table 128; Part 3, clause 12.1, Table 18, <c>creationPCR</c> row), already filtered to the implemented banks and registers by the declaring transition (<c>RetainImplementedPcrs</c>) — the owned pooled carrier the decrypt step rented; ownership rides this action into the effect, which is its terminal owner.</param>
/// <param name="CreationPcrValues">The FILTERED <see cref="CreationPcr"/>'s own register values, gathered from the durable PCR bank in selector order by the declaring transition (<c>GatherSelectedPcrValues</c>) — the same shape <c>TPM2_Quote()</c>'s <see cref="TpmQuoteAction.PcrValues"/> carries; the effect concatenates and hashes them into the creation data's <c>pcrDigest</c> under the object's own nameAlg (Part 2, clause 15.1, Table 261).</param>
/// <param name="ParentName">The parent's own Name (<c>TPM2B_NAME</c>), the creation data's <c>parentName</c> row for a loaded (non-hierarchy) parent (TPM 2.0 Library Part 2, clause 15.1, Table 261) — a BORROWED reference to the carrier the parent's durable <see cref="TransientKeyState"/> owns; the parent's state outlives this action for the duration of the one <c>SubmitAsync</c> call that resolved it, so neither this action nor its effect ever disposes it.</param>
/// <param name="ParentSeedValue">The parent's symmetric protection seed (<c>TPMT_SENSITIVE.seedValue</c>, TPM 2.0 Library Part 2, clause 12.3.2, Table 240), from which the child blob's symmetric and HMAC keys derive (Part 1, Clause 19, equations 33 and 35) — a BORROWED reference to the carrier the parent's durable <see cref="TransientKeyState"/> owns, exactly as <see cref="ParentName"/> is; neither this action nor its effect ever disposes it.</param>
/// <param name="ParentNameAlg">The parent's own Name algorithm, read from its Name's two-octet prefix by the declaring transition; it keys and sizes the wrap's KDFa derivations and the outer HMAC (Part 1, Clause 19 — <c>pNameAlg</c>, never the child's).</param>
/// <param name="ShouldGenerateSensitiveBits">Whether the effect draws the sensitive value from the RNG instead of copying <see cref="SecretData"/> — <c>sensitiveDataOrigin</c> SET on a signing or decryption KEYEDHASH key (TPM 2.0 Library Part 3, clause 12.1, keyedHash rule 4).</param>
/// <param name="GeneratedBitsLength">The octet count the effect draws when <see cref="ShouldGenerateSensitiveBits"/> is set — the digest size of <see cref="NameAlg"/> (Part 3, clause 12.1, keyedHash rule 4; Part 1, clause 24.7.5.1); zero otherwise.</param>
/// <param name="TemplateAttributes">The template's exact <c>TPMA_OBJECT</c> word (<see cref="TpmaObject"/>, TPM 2.0 Library Part 2, clause 8.3.2, Table 37), echoed verbatim into the exported public area (Part 3, clause 12.1: <c>outPublic</c> is the template with <c>unique</c> filled).</param>
/// <param name="KeyedHashScheme">The template's <c>TPMT_KEYEDHASH_SCHEME</c> (<see cref="TpmsKeyedHashParms"/>, Part 2, Table 227), echoed verbatim into the exported public area alongside <see cref="TemplateAttributes"/>.</param>
public sealed record TpmCreateKeyedHashOverSessionsAction(
    TpmiDhObject ParentHandle,
    TpmiRhHierarchy ParentHierarchy,
    TpmiAlgHash NameAlg,
    Tpm2bDigest AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    bool IsDuplicable,
    Tpm2bSensitiveData SecretData,
    Tpm2bAuth UserAuth,
    bool HasPasswordPlaceholder,
    TpmaSession PasswordPlaceholderAttributes,
    ImmutableArray<TpmCreateResponseSession> ResponseSessions,
    Tpm2bData OutsideInfo,
    TpmlPcrSelection CreationPcr,
    ImmutableArray<ReadOnlyMemory<byte>> CreationPcrValues,
    Tpm2bName ParentName,
    Tpm2bDigest ParentSeedValue,
    TpmiAlgHash ParentNameAlg,
    bool ShouldGenerateSensitiveBits,
    int GeneratedBitsLength,
    TpmaObject TemplateAttributes,
    TpmsKeyedHashParms KeyedHashScheme): TpmAction;

/// <summary>
/// Declares that the simulator must decrypt <c>TPM2_HierarchyChangeAuth()</c>'s <c>newAuth</c> first command
/// parameter before the next transition (TPM 2.0 Library Part 3, clause 24.8; Part 1, clause 18.1) — the
/// hierarchy-family counterpart of <see cref="TpmDecryptNvChangeAuthAction"/>, emitted only when a SEPARATE
/// session in the authorization area carried the <c>decrypt</c> attribute and strictly after every session in
/// that area has had its command HMAC verified.
/// </summary>
/// <remarks>
/// The effect XOR-obfuscates or AES-CFB-decrypts the data portion of the sole sized parameter in place (its
/// 2-octet size field is never itself encrypted, Part 1, clause 18.1), reads back the plaintext, and feeds it to
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
/// bind (Part 1, clause 18.1: "the binding of the session is ignored"). The shared empty carrier when the
/// decrypt session authorizes no entity, which on this command it never does, since the authorizing session is
/// refused the <c>decrypt</c> attribute outright. A borrowed reference to the carrier the durable state owns;
/// the effect never disposes it.
/// </param>
/// <param name="NonceCaller">The decrypt session's caller nonce for this command (the decryption's nonceNewer, TPM 2.0 Library Part 1, clause 18.2) — a BORROWED reference to the carrier the in-flight request owns, which outlives this effect; the effect reads it at the keystream and never disposes it.</param>
/// <param name="NonceTpm">The decrypt session's stored nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92) — the decryption's nonceOlder; a borrowed reference to the carrier the durable session record owns, which the effect reads at the keystream primitive and never disposes.</param>
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
/// bind, because "the binding of the session is ignored" for parameter encryption (Part 1, clause 18.1), unlike
/// the command HMAC key which drops it under equation 22's omission (clause 16.6.10). The shared empty carrier
/// when the decrypt attribute rides a companion authorizing no entity, whose <c>sessionValue</c> is its session
/// key alone. A borrowed reference to the carrier the durable state owns; the effect reads its
/// trailing-zero-stripped view at the keystream primitive and never disposes it.
/// </param>
/// <param name="NonceCaller">The decrypt session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92) — the decryption's nonceNewer (Part 1, clause 18.2). A BORROW of the slot's carrier on the request record, which outlives this step and transfers it into that slot's response-session entry afterwards. The shared empty carrier when <see cref="Decrypts"/> is clear.</param>
/// <param name="NonceTpm">The decrypt session's stored nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92) — the decryption's nonceOlder; a borrowed reference to the carrier the durable session record owns. The shared empty carrier when <see cref="Decrypts"/> is clear.</param>
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
/// Declares that the simulator must decrypt the first command parameter of a session-authorized
/// <c>TPM2_HMAC()</c> (<c>buffer</c>, TPM 2.0 Library Part 3, clause 15.5, Table 71) or <c>TPM2_HMAC_Start()</c>
/// (<c>auth</c>, clause 17.2, Table 80) over the authorizing session's own keying material (Part 1, clause 18.1)
/// — emitted only when that session carries the <c>decrypt</c> attribute, strictly after its command HMAC or its
/// <c>TPM2_PolicyPassword()</c> compare has passed, because cpHash covers the ciphertext (Part 3, clause 5.6
/// precedes clause 5.8). The decrypt session and the auth session are ONE here, so the keystream's
/// <c>sessionValue = </c><see cref="SessionKey"/><c> ‖ </c><see cref="EntityAuthValue"/> folds the key's LIVE
/// authorization value, unresolved by the session's bind ("the binding of the session is ignored", clause 18.1),
/// where the command HMAC key omits it under equation 22 (clause 16.6.10). Two keys, one session.
/// </summary>
/// <param name="CommandCode">The command being resumed, so one action shape serves both and a refusal names the right command.</param>
/// <param name="Request">The parsed session-authorized request (<see cref="TpmHmacOverSessionRequested"/> or <see cref="TpmHmacStartOverSessionRequested"/>), threaded through to the resuming transition rebuilt around the recovered plaintext carrier.</param>
/// <param name="RawParameterArea">The parameter-area carrier captured at parse time, which the transform mutates in place through <see cref="TpmParameterArea.Memory"/> so the octets cpHash digested as ciphertext are the octets the command reads as plaintext; a BORROW of the request's own carrier.</param>
/// <param name="SessionAlg">The authorizing session's hash algorithm, driving its KDFa keystream.</param>
/// <param name="Symmetric">The session's negotiated symmetric definition, selecting XOR obfuscation or AES-CFB; never <see cref="TpmtSymDef.Null"/> here, since the session-area gate answers <c>TPM_RC_SYMMETRIC</c> for a decrypt claim over it.</param>
/// <param name="SessionKey">The session's session key — a borrowed reference to the carrier the durable session record owns; the effect reads it at the keystream primitive and never disposes it.</param>
/// <param name="EntityAuthValue">The KEYEDHASH key's LIVE <see cref="KeyedHashObjectState.UserAuth"/>, folded into the keystream's <c>sessionValue</c> after <see cref="SessionKey"/> whatever the session's bind (Part 1, clause 18.1); a borrowed reference to the carrier the durable state owns, read trailing-zero-stripped at the primitive and never disposed here.</param>
/// <param name="NonceCaller">The session's caller nonce for this command — the decryption's nonceNewer (Part 1, clause 18.2); a BORROW of the carrier the in-flight request owns, which outlives this step.</param>
/// <param name="NonceTpm">The session's stored nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92) — the decryption's nonceOlder; a borrowed reference to the carrier the durable session record owns.</param>
public sealed record TpmDecryptKeyedHashParameterAction(
    TpmCcConstants CommandCode,
    TpmSimulatorInput Request,
    TpmParameterArea RawParameterArea,
    TpmiAlgHash SessionAlg,
    TpmtSymDef Symmetric,
    SymmetricKeyMemory SessionKey,
    Tpm2bAuth EntityAuthValue,
    Tpm2bNonce NonceCaller,
    Tpm2bNonce NonceTpm): TpmAction;

/// <summary>
/// The response framing a session-authorized command's effect performs once its work has succeeded (TPM 2.0
/// Library Part 1, clause 15.6.1): the command code every entry's rpHash folds (clause 15.8 equation 16), the
/// response-entry material of every slot in the command's authorization area in command-session order, and —
/// for <c>TPM2_SignSequenceComplete()</c> and <c>TPM2_VerifySequenceComplete()</c> — the completed sequence the
/// framing transition flushes together with the response (<c>{F}</c>, clause 29.4.6). Carried by the signing and
/// verifying actions as their <c>OverSessions</c> field: <see langword="null"/> on the password form, whose effect
/// feeds its plain result back instead.
/// </summary>
/// <param name="CommandCode">The command the response answers — the <c>commandCode</c> term of every entry's rpHash and the transition label's subject.</param>
/// <param name="Sessions">Every slot's response-entry material, in command-session order; each entry owns its slot's caller nonce, released by the framing effect.</param>
/// <param name="FlushedSequenceHandle">The sequence a successful completion flushes in the same transition that installs the response, or <see langword="null"/> when the command completes no sequence.</param>
public sealed record TpmOverSessionsFraming(
    TpmCcConstants CommandCode,
    ImmutableArray<TpmResponseSession> Sessions,
    TpmiDhObject? FlushedSequenceHandle = null);

/// <summary>
/// Declares that the simulator must recover a session-authorized command's FIRST parameter in plaintext before
/// the next transition — <c>TPM2_Sign()</c>'s <c>digest</c>, <c>TPM2_SignDigest()</c>'s <c>context</c>,
/// <c>TPM2_SequenceUpdate()</c>'s and <c>TPM2_SignSequenceComplete()</c>'s <c>buffer</c>,
/// <c>TPM2_StirRandom()</c>'s <c>inData</c>, <c>TPM2_LoadExternal()</c>'s <c>inPrivate</c>, or
/// <c>TPM2_ObjectChangeAuth()</c>'s <c>newAuth</c>, named by <see cref="CommandCode"/>: the one shape they all
/// share, since each is the first sized parameter of its command (TPM 2.0 Library Part 1, clause 18.1: "Any
/// first parameter can be encrypted as long as the parameter has a size field"). Declared ALWAYS on the session-authorized arm and emitted only once every session in the
/// authorization area has had its command HMAC verified, because cpHash covers the CIPHERTEXT ("Parameters in
/// commands are encrypted before any cpHash is computed", clause 18.1) — Part 3's ladder runs clause 5.6's
/// authorization, then clause 5.7's decryption, then clause 5.8's unmarshaling.
/// </summary>
/// <remarks>
/// With <see cref="Decrypts"/> clear the step is a pass-through that reads the value back out of the captured
/// area, so the plaintext and the ciphertext arrival share one origin, one width check, and one carrier rental
/// — the width being the command's own TPM2B bound (<c>sizeof(TPMU_HA)</c>, 255, 1024), judged over the
/// PLAINTEXT. With it set, the effect transforms the data portion in place — the 2-octet size field is never
/// protected — with the command-direction nonce ordering (nonceNewer is <see cref="NonceCaller"/>, nonceOlder is
/// <see cref="NonceTpm"/>, clauses 18.2 and 18.3), then rebuilds the request with the recovered carrier in the
/// place the password form's parse would have put it.
/// </remarks>
/// <param name="CommandCode">The command being resumed, threaded through so the feedback names it.</param>
/// <param name="Request">The parsed session-authorized request, threaded through to the resuming transition; the effect rebuilds it around the recovered carrier.</param>
/// <param name="RawParameterArea">The raw parameter-area octets captured at parse time, still carrying the encrypted data portion when <see cref="Decrypts"/> is set; the transform is in place over this buffer. A BORROW: the request record owns the carrier and every terminal path releases it there, while the in-place transform writes through <see cref="TpmParameterArea.Memory"/> so the octets cpHash digested as ciphertext are the octets the tail decodes as plaintext.</param>
/// <param name="Decrypts">Whether a slot in the authorization area carried the <c>decrypt</c> attribute; when clear, every keying field below is its inert placeholder and no transform runs.</param>
/// <param name="DecryptSessionIndex">The zero-based slot index of the session carrying <c>decrypt</c>, which a failure is session-index-encoded to (Part 2, clause 6.6.2), or <c>-1</c> when no slot claimed it.</param>
/// <param name="SessionAlg">The decrypt session's hash algorithm, driving its KDFa. Meaningless when <see cref="Decrypts"/> is clear.</param>
/// <param name="Symmetric">The decrypt session's negotiated symmetric definition, selecting XOR obfuscation or AES-CFB. <see cref="TpmtSymDef.Null"/> when <see cref="Decrypts"/> is clear.</param>
/// <param name="SessionKey">The decrypt session's session key — a borrowed reference to the carrier the durable session record owns; the effect reads it at the keystream primitive and never disposes it. The shared <see cref="TpmSimulatorState.EmptySessionKey"/> when <see cref="Decrypts"/> is clear.</param>
/// <param name="EntityAuthValue">
/// The authValue of the entity the DECRYPT session itself authorizes — a signing key's, or a SEQUENCE's own
/// authorization value when the sequence slot decrypts (Part 4 <c>EntityGetAuthValue</c>'s sequence arm) — folded
/// into the keystream's <c>sessionValue</c> after <see cref="SessionKey"/> as the entity's LIVE value, UNRESOLVED
/// by the session's bind ("the binding of the session is ignored", Part 1, clause 18.1). The shared empty carrier
/// when the attribute rides a companion authorizing no entity. A borrowed reference to the carrier the durable
/// state owns; the effect reads its trailing-zero-stripped view at the keystream primitive and never disposes it.
/// </param>
/// <param name="NonceCaller">The decrypt session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92) — the decryption's nonceNewer (Part 1, clause 18.2). A BORROW of the slot's carrier on the request record, which outlives this step and transfers it into that slot's response entry afterwards. The shared empty carrier when <see cref="Decrypts"/> is clear.</param>
/// <param name="NonceTpm">The decrypt session's stored nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92) — the decryption's nonceOlder; a borrowed reference to the carrier the durable session record owns. The shared empty carrier when <see cref="Decrypts"/> is clear.</param>
public sealed record TpmDecryptFirstParameterAction(
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
/// Declares that the simulator must parse a no-authorization command's REAL inner request from its already
/// non-decrypting authorization area before the next transition (TPM 2.0 Library Part 3, clause 5.5 precedes
/// clause 5.8) — the no-transform sibling of <see cref="TpmDecryptFirstParameterAction"/>, declared instead of
/// it when no slot in <see cref="Wrapper"/>'s area claims <c>decrypt</c>: <c>TPM2_GetRandom()</c>'s and
/// <c>TPM2_TestParms()</c>'s parameter shapes are not TPM2B-first commands that action's generic size-field
/// preamble could parse at all, and a claim-free <c>TPM2_StirRandom()</c> area still needs the pooled carrier
/// its own core rents. The effectful loop reruns the command's parameter core — the SAME core the plain form
/// runs — over <see cref="TpmNoAuthOverSessionsRequested.RawParameterArea"/>'s octets (genuinely plaintext here,
/// since no slot claims decrypt) and feeds the rebuilt wrapper back as a <see cref="TpmFirstParameterDecrypted"/>
/// input with <c>DecryptSessionIndex: -1</c>, so a core refusal is answered BARE and
/// <c>TpmLifecycleTransitions.OnFirstParameterDecrypted</c>'s existing wrapper arm routes the success onward to
/// <c>CompleteNoAuthOverSessions</c> unchanged.
/// </summary>
/// <param name="Wrapper">The verified no-authorization request whose real inner is parsed.</param>
public sealed record TpmParseNoAuthInnerAction(TpmNoAuthOverSessionsRequested Wrapper): TpmAction;

/// <summary>
/// Declares that the simulator must frame a session-authorized command's response over an EMPTY parameter area
/// before the next transition — <c>TPM2_SequenceUpdate()</c>'s (TPM 2.0 Library Part 3, clause 17.7, Table 92: no
/// response parameters), whose state change is pure and whose only effectful work is the response session area
/// itself (Part 1, clause 15.6.1). The effectful loop rolls every real session's nonceTPM, computes rpHash over the
/// command code and the empty area (clause 15.8 equation 16), computes each real slot's response HMAC keyed as its
/// command HMAC was, and feeds the entries back as a <see cref="TpmResponseFramedOverSessions"/> input.
/// </summary>
/// <param name="Framing">The command code, every slot's response-entry material in command-session order, and no sequence to flush.</param>
public sealed record TpmFrameOverSessionsResponseAction(TpmOverSessionsFraming Framing): TpmAction;

/// <summary>
/// Declares that the simulator must serialize a no-authorization command's plain, unauthorized-form terminal
/// intent and wrap it in its already-built companion-slot framing before the next transition (TPM 2.0 Library
/// Part 3, clause 4.3; Part 1, clause 15.6.1) — the ONE generic framing step every no-authorization
/// session-admitting command shares. Declared only by <see cref="TpmLifecycleTransitions"/>'s
/// <c>ApplyPendingSessionFrame</c> hook, once the wrapped command's own inner dispatch has produced a fresh
/// <c>TPM_RC_SUCCESS</c> terminal intent; the effectful loop serializes <see cref="PlainIntent"/> through the
/// existing plain-form serializer, adopts the octets past its fixed header (and past the response handle, when
/// <see cref="TpmPendingSessionFrame.ResponseCarriesHandle"/>) as the framed parameter area, then runs the
/// shared multi-slot framer over it exactly as every other command's authorization area does, and feeds the
/// result back as a <see cref="TpmResponseFramedOverSessions"/> input.
/// </summary>
/// <param name="Frame">The framing already built for the command's response, and whether it carries a response handle.</param>
/// <param name="PlainIntent">The inner command's own successful plain terminal intent, whose octets past the header become the framed response's parameter area; the framing effect is its terminal owner.</param>
public sealed record TpmFrameNoAuthSessionsAction(TpmPendingSessionFrame Frame, TpmResponseIntent PlainIntent): TpmAction;

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
/// contexts stop verifying (Part 1, clause 11.5): they are HMACs keyed by a proof derived from it, so a new seed
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

/// <summary>
/// Declares that the simulator must run the ECC DHKEM encapsulation side of <c>TPM2_Encapsulate()</c> before
/// the next transition (TPM 2.0 Library Part 3, clause 14.10; Part 1, clause 44.4.2). Emitted by the
/// <c>TPM2_Encapsulate()</c> transition once <see cref="TransientKeyState.KemKdfScheme"/> has confirmed the
/// resolved key is a KEM key; the effectful loop generates a fresh ephemeral key pair
/// (<c>skE</c>, <c>pkE</c>) through the injected <see cref="TpmEccSigningBackend"/>, computes
/// <c>dh = ECDH(skE, pkR)</c> against <see cref="PublicPoint"/>, derives
/// <c>shared_secret = ExtractAndExpand(dh, pkE_serialized ‖ pkR_serialized)</c> through the DHKEM core
/// (<see cref="Verifiable.Cryptography.Dhkem"/>, DHKEM(P-256, HKDF-<see cref="KdfHashAlg"/>), <c>kem_id</c>
/// 0x0010), and feeds the shared secret and the ephemeral SEC 1 point (the ciphertext, clause 44.4.2 step 3)
/// back as a <see cref="TpmEncapsulated"/> input. This effect never fails — the key was already confirmed a
/// KEM key by the declaring transition, and every DHKEM step is unconditional — so, unlike
/// <see cref="TpmDecapsulateAction"/>, its fold-back carries no response-code arm.
/// </summary>
/// <remarks>
/// The transition resolves <c>keyHandle</c> against the loaded-object table and folds its public point and
/// curve into this action, so the effect needs no automaton state and captures nothing. This is a
/// public-key operation (TPM 2.0 Library Part 3, clause 14.10: "The TPM does not verify the
/// objectAttributes of the key") — no private key, no authorization, no attribute check reaches this action.
/// </remarks>
/// <param name="PublicPoint">The KEM key's retained public point, SEC1 uncompressed — <c>pkR_serialized</c>.</param>
/// <param name="Curve">The ECC curve the public point lives on — the DHKEM's <c>curveID</c> (P-256, this simulator's only wired suite).</param>
/// <param name="KdfHashAlg">The key's retained <see cref="TransientKeyState.KemKdfHashAlg"/> — the DHKEM's KDF hash.</param>
public sealed record TpmEncapsulateAction(
    ReadOnlyMemory<byte> PublicPoint,
    TpmiEccCurve Curve,
    TpmiAlgHash KdfHashAlg): TpmAction;

/// <summary>
/// Declares that the simulator must run the ECC DHKEM decapsulation side of <c>TPM2_Decapsulate()</c> before
/// the next transition (TPM 2.0 Library Part 3, clause 14.11; Part 1, clause 44.4.3). Emitted by the
/// <c>TPM2_Decapsulate()</c> transition once every synchronous gate (handle, DA/lockout, USER-role
/// authorization, KEM-key shape, and the clause 14.11.1 restricted-CLEAR/decrypt-SET anti-oracle attribute
/// gate) has passed; the effectful loop validates <see cref="Ciphertext"/> as a conformant SEC 1 uncompressed
/// P-256 point (<c>TPM_RC_ECC_POINT</c> on a malformed prefix/length or an off-curve point, TPM 2.0 Library
/// Part 1, clause 44.5.1), computes <c>dh = ECDH(key.PrivateKey, pkE)</c>, derives the same
/// <c>ExtractAndExpand(dh, pkE_serialized ‖ pkR_serialized)</c> the encapsulation side computed, and feeds
/// the recovered shared secret (or the point-validation failure) back as a <see cref="TpmDecapsulated"/>
/// input.
/// </summary>
/// <remarks>
/// The transition resolves <c>keyHandle</c> against the loaded-object table and folds its private key,
/// public point, and curve into this action, so the effect needs no automaton state and captures nothing.
/// <see cref="Ciphertext"/> is public data (the peer's ephemeral point), so it rides a plain pooled carrier
/// rather than <see cref="Verifiable.Cryptography.SensitiveMemory"/> — mirroring <see cref="Verifiable.Tpm.Spec.Structures.Tpm2bKemCiphertext"/>'s own carrier shape.
/// </remarks>
/// <param name="PrivateKey">The KEM key's retained private scalar, unsigned big-endian — a borrowed reference to the carrier the durable object state owns; the effect reads it at the ECDH primitive and never disposes it.</param>
/// <param name="PublicPoint">The KEM key's retained public point, SEC1 uncompressed — <c>pkR_serialized</c>, folded into <c>kem_context</c> exactly as the encapsulation side folds it.</param>
/// <param name="Curve">The ECC curve the key lives on — the DHKEM's <c>curveID</c> (P-256, this simulator's only wired suite).</param>
/// <param name="KdfHashAlg">The key's retained <see cref="TransientKeyState.KemKdfHashAlg"/> — the DHKEM's KDF hash.</param>
/// <param name="Ciphertext">The caller-supplied <c>TPM2B_KEM_CIPHERTEXT</c> — <c>pkE_serialized</c> — the owned pooled carrier the request parsed; ownership rides this action into the effect, which is its terminal owner.</param>
public sealed record TpmDecapsulateAction(
    PrivateKeyMemory PrivateKey,
    ReadOnlyMemory<byte> PublicPoint,
    TpmiEccCurve Curve,
    TpmiAlgHash KdfHashAlg,
    Tpm2bKemCiphertext Ciphertext): TpmAction;
