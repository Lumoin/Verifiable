using System;
using System.Buffers;
using System.Collections.Immutable;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The logical result of processing a command in the simulator. The pure transition function produces
/// an intent; <see cref="TpmSimulator"/> serializes it to TPM response bytes against the injected
/// memory pool when the response leaves the device.
/// </summary>
/// <remarks>
/// Keeping the response logical — a response code plus an optional typed payload — rather than raw
/// bytes keeps the transition function free of buffer allocation, so all framing happens in one place
/// against a pooled buffer.
/// </remarks>
/// <param name="ResponseCode">The TPM response code carried in the response header.</param>
public abstract record TpmResponseIntent(TpmRcConstants ResponseCode);

/// <summary>
/// A response carrying only the 10-byte header with no parameters. Used for command successes that
/// return no data (<c>TPM2_Startup()</c>, <c>TPM2_Shutdown()</c>, <c>TPM2_SelfTest()</c>) and for
/// every error response.
/// </summary>
/// <param name="ResponseCode">The response code.</param>
public sealed record TpmHeaderOnlyResponse(TpmRcConstants ResponseCode): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_GetTestResult()</c>: an outData buffer (empty in this lifecycle
/// skeleton) followed by the self-test result code.
/// </summary>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="TestResult">
/// The self-test outcome reported in the response body: <c>TPM_RC_SUCCESS</c> when the self-test
/// passed, <c>TPM_RC_FAILURE</c> when it failed (TPM 2.0 Library Part 1, clause 9.4).
/// </param>
public sealed record TpmTestResultResponse(TpmRcConstants ResponseCode, TpmRcConstants TestResult): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_GetRandom()</c>: a <c>TPM2B_DIGEST</c> carrying the random
/// octets (TPM 2.0 Library Part 3, clause 16.1).
/// </summary>
/// <remarks>
/// The octets ride an owned carrier rented by the RNG action executor. <see cref="TpmSimulator"/> writes it
/// through its own <c>WriteTo</c> and then disposes <see cref="RandomBytes"/>; the intent is the terminal
/// owner of that carrier and is consumed exactly once, immediately after the transition.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="RandomBytes">The produced octets as the <c>TPM2B_DIGEST</c> Table 76 gives <c>randomBytes</c>; owned, disposed after framing.</param>
public sealed record TpmRandomResponse(TpmRcConstants ResponseCode, Tpm2bDigest RandomBytes): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_GetCapability()</c>: a <c>moreData</c> flag followed by the
/// capability data (TPM 2.0 Library Part 3, clause 30.2).
/// </summary>
/// <remarks>
/// <see cref="CapabilityData"/> is disposable (some union arms own pooled memory); <see cref="TpmSimulator"/>
/// disposes it after framing, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="CapabilityData">The capability-data union arm to return.</param>
/// <param name="MoreData">Whether more properties are available beyond those returned.</param>
public sealed record TpmCapabilityResponse(TpmRcConstants ResponseCode, TpmsCapabilityData CapabilityData, TpmiYesNo MoreData): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_CreatePrimary()</c>: the object handle followed by the exported
/// public area and the creation by-products (TPM 2.0 Library Part 3, clause 24.1).
/// </summary>
/// <remarks>
/// Every payload slot owns pooled memory; <see cref="TpmSimulator"/> writes each through its own
/// <c>WriteTo</c> — the object handle, the public area, then <c>creationData</c>, <c>creationHash</c>,
/// <c>creationTicket</c> and <c>name</c> in the order clause 24.1's response table fixes — and then disposes
/// them all, as the terminal owner. The creation data, creation hash, creation ticket, and Name are computed
/// faithfully (TPM 2.0 Library Part 3, clause 24.1; Part 2, clause 15) in the effectful loop.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="ObjectHandle">The handle of the created object, framed in the response handle area. TPM 2.0 Library Part 3, clause 24.1.2, Table 192 types this slot <c>TPM_HANDLE</c> — "handle of type TPM_HT_TRANSIENT for created Primary Object" is the description, not an interface-type constraint the unmarshaling enforces.</param>
/// <param name="OutPublic">The exported public area; disposed after framing.</param>
/// <param name="CreationData">
/// The creation data the object was created with (<c>TPM2B_CREATION_DATA</c>, TPM 2.0 Library Part 2, clause
/// 15.2, Table 262) in an owned pooled carrier; disposed after framing.
/// </param>
/// <param name="CreationHash">
/// The Name-algorithm digest of <paramref name="CreationData"/> (<c>TPM2B_DIGEST</c>, Part 2, clause 10.3.2,
/// Table 90) in an owned pooled carrier; disposed after framing.
/// </param>
/// <param name="CreationTicket">
/// The creation ticket binding the creation data to the object (<c>TPMT_TK_CREATION</c>, Part 2, clause 10.6.3,
/// Table 110) in an owned pooled carrier; disposed after framing.
/// </param>
/// <param name="Name">
/// The created object's Name (<c>TPM2B_NAME</c>, Part 1, clause 13, Table 9) in an owned pooled carrier of its own —
/// separate from the copy the key state retains — disposed after framing.
/// </param>
public sealed record TpmCreatePrimaryResponse(
    TpmRcConstants ResponseCode,
    TpmHandle ObjectHandle,
    Tpm2bPublic OutPublic,
    Tpm2bCreationData CreationData,
    Tpm2bDigest CreationHash,
    TpmtTkCreation CreationTicket,
    Tpm2bName Name): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_Sign()</c>, <c>TPM2_SignDigest()</c>, or <c>TPM2_SignSequenceComplete()</c>:
/// a <c>TPMT_SIGNATURE</c> whose active member is the ECDSA or RSA signature (TPM 2.0 Library Part 3, clauses
/// 20.5, 20.7, and 20.6; Part 2, clauses 11.3.2 and 11.3.6). All three commands' response tables (Tables 106,
/// 127, and 125) give the same single <c>TPMT_SIGNATURE signature</c> parameter, so this intent is
/// command-agnostic and carries no command code of its own.
/// </summary>
/// <remarks>
/// <see cref="Signature"/> owns pooled memory for its member's buffers; <see cref="TpmSimulator"/> writes it
/// through its own <c>WriteTo</c> and then disposes it, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="Signature">The <c>TPMT_SIGNATURE</c>; disposed after framing.</param>
public sealed record TpmSignResponse(TpmRcConstants ResponseCode, TpmtSignature Signature): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to every sequence Start command — <c>TPM2_HashSequenceStart()</c>,
/// <c>TPM2_SignSequenceStart()</c>, and <c>TPM2_VerifySequenceStart()</c>: the transient handle of the newly
/// opened sequence context, framed in the response handle area with no parameters at all (TPM 2.0 Library
/// Part 3, clauses 17.4, 17.5 and 17.6, Tables 86, 88 and 90). Shared by all of them, exactly as
/// <see cref="TpmSignResponse"/> is shared by the sign-family completion commands.
/// </summary>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="SequenceHandle">The handle of the newly opened sequence, framed in the response handle area. Tables 86/88/90 type this slot <c>TPMI_DH_OBJECT</c> — "handle of a sequence object" is the description, not an interface-type constraint the unmarshaling enforces.</param>
public sealed record TpmSequenceStartResponse(TpmRcConstants ResponseCode, TpmHandle SequenceHandle): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_VerifySequenceComplete()</c>: a <c>TPMT_TK_VERIFIED</c> validation
/// ticket, always tagged <c>TPM_ST_MESSAGE_VERIFIED</c> (TPM 2.0 Library Part 3, clause 20.3, Table 119: "tag
/// will be TPM_ST_MESSAGE_VERIFIED") — the sequence-command counterpart of <see cref="TpmVerifySignatureResponse"/>
/// and <see cref="TpmVerifyDigestSignatureResponse"/>, sharing their single-parameter, no-attest, no-signature
/// shape.
/// </summary>
/// <remarks>
/// <see cref="Validation"/> is an owned carrier holding the whole ticket; <see cref="TpmSimulator"/> writes it
/// through its own <c>WriteTo</c> and then disposes it, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="Validation">The <c>TPMT_TK_VERIFIED</c> validation ticket (TPM 2.0 Library Part 2, clause 10.6.5, Table 113); owned, disposed after framing.</param>
public sealed record TpmVerifySequenceCompleteResponse(TpmRcConstants ResponseCode, TpmtTkVerified Validation): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_SequenceComplete()</c> and <c>TPM2_Hash()</c>: the digest and its
/// <c>TPMT_TK_HASHCHECK</c> ticket — Tables 94 and 70 (TPM 2.0 Library Part 3, clauses 17.8 and 15.4) are
/// identical in shape (<c>TPM2B_DIGEST</c> then the ticket), so one intent frames both, exactly as
/// <see cref="TpmSequenceStartResponse"/> serves every Start command.
/// </summary>
/// <remarks>
/// Both carriers are owned; <see cref="TpmSimulator"/> writes each through its own <c>WriteTo</c> and then
/// disposes them, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="Result">The digest (<c>result</c> / <c>outHash</c>, <c>TPM2B_DIGEST</c>); owned, disposed after framing.</param>
/// <param name="Validation">The hash-check ticket (<c>validation</c>, <c>TPMT_TK_HASHCHECK</c>, TPM 2.0 Library Part 2, clause 10.6.7, Table 115) — the NULL ticket when the hierarchy was <c>TPM_RH_NULL</c> or the octets were not safe to sign; owned, disposed after framing.</param>
public sealed record TpmDigestResponse(TpmRcConstants ResponseCode, Tpm2bDigest Result, TpmtTkHashcheck Validation): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_HMAC()</c> (TPM 2.0 Library Part 3, clause 15.5, Table 72): the single
/// <c>outHMAC</c> parameter, a <c>TPM2B_DIGEST</c> holding <c>HMAC_hashAlg(key, buffer)</c>. Unlike
/// <see cref="TpmDigestResponse"/> there is no ticket — an HMAC needs no hash-check, since it is not a digest
/// that could later be signed by a restricted key.
/// </summary>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="OutHmac">The computed HMAC (<c>outHMAC</c>, <c>TPM2B_DIGEST</c>); owned, disposed after framing.</param>
public sealed record TpmHmacResponse(TpmRcConstants ResponseCode, Tpm2bDigest OutHmac): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to a session-authorized <c>TPM2_HMAC()</c> (TPM 2.0 Library Part 3, clause 15.5,
/// Table 72; Part 1, clause 15.6.1): a <c>TPM_ST_SESSIONS</c>-tagged envelope carrying the already-framed
/// <c>outHMAC</c> parameter area — the exact octets rpHash covered — followed by the single authorizing
/// session's response entry (nonceTPM, the echoed attributes, the response HMAC or the empty hmac Part 4
/// <c>BuildSingleResponseAuth</c> assigns a <c>TPM2_PolicyPassword()</c> session).
/// </summary>
/// <remarks>
/// <see cref="ParameterArea"/> and the entry's carriers are pooled; <see cref="TpmSimulator"/> frames the
/// envelope and then disposes them, as the terminal owner. The entry's <c>RetainedNonceTpm</c> is not this
/// intent's to release: the completing transition transferred it onto the durable session record.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="ParameterArea">The framed <c>TPM2B_DIGEST</c> <c>outHMAC</c> parameter area; disposed after framing.</param>
/// <param name="Entry">The authorizing session's framed response entry; its framed nonce and HMAC are disposed after framing.</param>
public sealed record TpmHmacOverSessionResponse(
    TpmRcConstants ResponseCode,
    TpmParameterArea ParameterArea,
    TpmHmacFramedSession Entry): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to a session-authorized <c>TPM2_HMAC_Start()</c> (TPM 2.0 Library Part 3, clause
/// 17.2, Table 81; Part 1, clause 15.6.1): a <c>TPM_ST_SESSIONS</c>-tagged envelope whose handle area carries
/// the new <c>sequenceHandle</c>, whose parameter area is empty (Part 3, Table 81 returns no parameter), followed by
/// the single authorizing session's response entry over that empty area.
/// </summary>
/// <remarks>
/// The entry's framed nonce and HMAC are pooled; <see cref="TpmSimulator"/> frames the envelope and then
/// disposes them, as the terminal owner. The entry's <c>RetainedNonceTpm</c> is not this intent's to release:
/// the completing transition transferred it onto the durable session record.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="SequenceHandle">The handle of the newly opened HMAC sequence, written into the response handle area.</param>
/// <param name="Entry">The authorizing session's framed response entry; its framed nonce and HMAC are disposed after framing.</param>
public sealed record TpmHmacStartOverSessionResponse(
    TpmRcConstants ResponseCode,
    TpmiDhObject SequenceHandle,
    TpmHmacFramedSession Entry): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_Create()</c>: the wrapped private blob, the exported public area, and the
/// creation by-products (TPM 2.0 Library Part 3, clause 12.1). Unlike <c>TPM2_CreatePrimary()</c> the created
/// object is not loaded, so there is no response handle and no Name.
/// </summary>
/// <remarks>
/// Every payload slot owns pooled memory; <see cref="TpmSimulator"/> writes each through its own <c>WriteTo</c>
/// — <c>outPrivate</c>, the public area, then <c>creationData</c>, <c>creationHash</c> and
/// <c>creationTicket</c> in the order clause 12.1's response table fixes — and then disposes them all, as the
/// terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="PrivateBlob">The wrapped private blob (<c>outPrivate</c>) as a <c>TPM2B_PRIVATE</c> (TPM 2.0 Library Part 2, clause 12.3.7, Table 243), whose content is by definition the TPM's own opaque encoding; owned, disposed after framing.</param>
/// <param name="OutPublic">The exported public area; disposed after framing.</param>
/// <param name="CreationData">
/// The creation data the object was created with (<c>TPM2B_CREATION_DATA</c>, TPM 2.0 Library Part 2, clause
/// 15.2, Table 262) in an owned pooled carrier; disposed after framing.
/// </param>
/// <param name="CreationHash">
/// The Name-algorithm digest of <paramref name="CreationData"/> (<c>TPM2B_DIGEST</c>, Part 2, clause 10.3.2,
/// Table 90) in an owned pooled carrier; disposed after framing.
/// </param>
/// <param name="CreationTicket">
/// The creation ticket binding the creation data to the object (<c>TPMT_TK_CREATION</c>, Part 2, clause 10.6.3,
/// Table 110) in an owned pooled carrier; disposed after framing.
/// </param>
public sealed record TpmCreateResponse(
    TpmRcConstants ResponseCode,
    Tpm2bPrivate PrivateBlob,
    Tpm2bPublic OutPublic,
    Tpm2bCreationData CreationData,
    Tpm2bDigest CreationHash,
    TpmtTkCreation CreationTicket): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_Create()</c> over one or two sessions: a <c>TPM_ST_SESSIONS</c>-tagged
/// response carrying the (unencrypted — response encryption is out of scope for
/// <c>TPM2_Create()</c>) <c>outPrivate ‖ outPublic ‖ creationData ‖ creationHash ‖ creationTicket</c> parameter
/// area followed by the response session area, in command-session order — a <c>TPM_RS_PW</c> parent-auth
/// session's placeholder entry (an empty nonce, echoed attributes, an empty HMAC, since it carries no key) when
/// <see cref="HasPasswordPlaceholder"/> is set, then every real (HMAC-table) session's entry in
/// <see cref="Entries"/> (its rolled nonceTPM, echoed attributes, and its own response HMAC) — the request-decrypt
/// counterpart of <see cref="TpmUnsealOverSessionsResponse"/> (TPM 2.0 Library Part 3, clause 12.1; Part 1,
/// clauses 15.7 and 16.6.5).
/// </summary>
/// <remarks>
/// <see cref="ParameterArea"/> is a pooled carrier; <see cref="TpmSimulator"/> frames the session-tagged envelope
/// and then disposes it, as the terminal owner, along with each entry's own <c>Hmac</c> buffer.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="ParameterArea">The framed <c>outPrivate ‖ outPublic ‖ creationData ‖ creationHash ‖ creationTicket</c> response parameter area; disposed after framing.</param>
/// <param name="HasPasswordPlaceholder">Whether session index 0 is a <c>TPM_RS_PW</c> session needing the empty-nonce, empty-HMAC password placeholder entry.</param>
/// <param name="PasswordPlaceholderAttributes">The password session's command session-attributes octet, framed in its entry. Meaningful only when <see cref="HasPasswordPlaceholder"/> is set.</param>
/// <param name="Entries">Every real session's framed response entry, in command-session order (after the password placeholder, when present); each entry's <c>Hmac</c> buffer is disposed after framing.</param>
public sealed record TpmCreateOverSessionsResponse(
    TpmRcConstants ResponseCode,
    TpmParameterArea ParameterArea,
    bool HasPasswordPlaceholder,
    TpmaSession PasswordPlaceholderAttributes,
    ImmutableArray<TpmCreateFramedSessionEntry> Entries): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_Load()</c>: the transient handle of the loaded object followed by its Name
/// (TPM 2.0 Library Part 3, clause 12.2).
/// </summary>
/// <remarks>
/// <see cref="Name"/> is an owned <c>TPM2B_NAME</c> carrier; <see cref="TpmSimulator"/> serializes the object
/// handle and the Name into the framed response and then disposes it, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="ObjectHandle">The handle of the loaded object, framed in the response handle area. TPM 2.0 Library Part 3, clause 12.2.2, Table 21 types this slot <c>TPM_HANDLE</c> — "handle of type TPM_HT_TRANSIENT for the loaded object" is the description, not an interface-type constraint the unmarshaling enforces.</param>
/// <param name="Name">The object Name as a <c>TPM2B_NAME</c> (TPM 2.0 Library Part 2, clause 10.4.3, Table 105); owned, disposed after framing.</param>
public sealed record TpmLoadResponse(
    TpmRcConstants ResponseCode,
    TpmHandle ObjectHandle,
    Tpm2bName Name): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_ContextSave()</c>: the framed <c>TPMS_CONTEXT</c> — sequence, savedHandle,
/// hierarchy, and the encrypted, integrity-protected context blob — as the command's whole parameter area
/// (TPM 2.0 Library Part 3, clause 28.2.2, Table 225).
/// </summary>
/// <remarks>
/// <see cref="Context"/> is owned; <see cref="TpmSimulator"/> writes it through its own <c>WriteTo</c> and then
/// disposes it — which releases <see cref="Structures.TpmsContext.ContextBlob"/> — as the terminal owner,
/// mirroring <see cref="TpmCreatePrimaryResponse"/>'s owned-structure framing.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="Context">The framed context (<c>TPMS_CONTEXT</c>); owned, disposed after framing.</param>
public sealed record TpmContextSaveResponse(
    TpmRcConstants ResponseCode,
    TpmsContext Context): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_ContextLoad()</c>: the handle assigned to the reloaded resource, carried
/// in the response handle area alone — Table 227 defines no response parameter (TPM 2.0 Library Part 3, clause
/// 28.3.1: "loadedHandle ... the handle assigned to the resource after it has been successfully loaded").
/// </summary>
/// <remarks>
/// <see cref="LoadedHandle"/> is a value type; nothing here is owned or disposed, unlike
/// <see cref="TpmLoadResponse"/>'s owned Name — the same handle-first write, minus a trailing structure.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="LoadedHandle">The handle assigned to the reloaded resource — the saved handle itself for a session, or the freshly drawn transient handle for an object or sequence.</param>
public sealed record TpmContextLoadResponse(
    TpmRcConstants ResponseCode,
    TpmiDhContext LoadedHandle): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_Unseal()</c>: a <c>TPM2B_SENSITIVE_DATA</c> carrying the recovered sealed
/// data (TPM 2.0 Library Part 3, clause 12.7).
/// </summary>
/// <remarks>
/// <paramref name="OutData"/> is a borrowed reference to the carrier the loaded sealed object owns, so nothing
/// is disposed after framing — <see cref="TpmSimulator"/> takes the view at the framing primitive and copies the
/// octets into the framed <c>TPM2B_SENSITIVE_DATA</c>. The borrow keeps a retained trace snapshot of this
/// intent fail-loud: once <c>TPM2_FlushContext()</c> or teardown releases the sealed object, reading the
/// snapshot's carrier throws rather than exposing recycled pool memory.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="OutData">The recovered sealed data — a borrowed reference to the carrier the loaded sealed object owns.</param>
public sealed record TpmUnsealResponse(TpmRcConstants ResponseCode, Tpm2bSensitiveData OutData): TpmResponseIntent(ResponseCode);

/// <summary>
/// The framed outcome of <c>TPM2_Duplicate()</c> (TPM 2.0 Library Part 3, clause 13.1): the duplication blob
/// and the outer-wrapper seed protected to the new parent. The modeled no-inner-wrapper form frames an empty
/// <c>encryptionKeyOut</c>.
/// </summary>
/// <param name="ResponseCode">The response code.</param>
/// <param name="Duplicate">The duplicated sensitive area (<c>TPM2B_PRIVATE</c>) in an owned pooled carrier; released by the framing step once serialized.</param>
/// <param name="OutSymSeed">The protected outer-wrapper seed (<c>TPM2B_ENCRYPTED_SECRET</c>) in an owned pooled carrier — the dispose-immune empty sentinel for a <c>TPM_RH_NULL</c> new parent; released by the framing step once serialized.</param>
public sealed record TpmDuplicateResponse(TpmRcConstants ResponseCode, Tpm2bPrivate Duplicate, Tpm2bEncryptedSecret OutSymSeed): TpmResponseIntent(ResponseCode);

/// <summary>
/// The framed outcome of <c>TPM2_Import()</c> (TPM 2.0 Library Part 3, clause 13.3): the imported object's
/// sensitive area re-wrapped under the new parent.
/// </summary>
/// <param name="ResponseCode">The response code.</param>
/// <param name="OutPrivate">The re-wrapped sensitive area (<c>TPM2B_PRIVATE</c>) in an owned pooled carrier; released by the framing step once serialized.</param>
public sealed record TpmImportResponse(TpmRcConstants ResponseCode, Tpm2bPrivate OutPrivate): TpmResponseIntent(ResponseCode);

/// <summary>
/// The framed outcome of a password- or bare-policy-authorized <c>TPM2_ObjectChangeAuth()</c> (TPM 2.0 Library
/// Part 3, clause 12.8): the object's new authorization value, wrapped into a fresh private area — the
/// Unseal/Duplicate response shape, framed with no trailing response-session area, since neither a password
/// slot nor a policy slot with no digest binding earns one in this model (mirroring
/// <see cref="TpmDuplicateResponse"/>'s own DUP-role slot). An HMAC-authorized completion instead frames
/// through the shared over-sessions machinery (<see cref="TpmOverSessionsResponse"/>).
/// </summary>
/// <param name="ResponseCode">The response code.</param>
/// <param name="OutPrivate">The wrapped private area (<c>TPM2B_PRIVATE</c>) in an owned pooled carrier; released by the framing step once serialized.</param>
public sealed record TpmObjectChangeAuthResponse(TpmRcConstants ResponseCode, Tpm2bPrivate OutPrivate): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful plain-form response to <c>TPM2_RSA_Encrypt()</c>: a <c>TPM2B_PUBLIC_KEY_RSA</c> carrying the
/// encrypted output (TPM 2.0 Library Part 3, clause 14.2, Table 45) — the <c>TPM2_Unseal()</c>/
/// <c>TPM2_ObjectChangeAuth()</c> response shape, no trailing response-session area. The session form instead
/// frames through the shared over-sessions machinery (<see cref="TpmOverSessionsResponse"/>) and never reaches
/// this type.
/// </summary>
/// <param name="ResponseCode">The response code (success).</param>
/// <param name="OutData">The encrypted output (<c>TPM2B_PUBLIC_KEY_RSA</c>) in an owned pooled carrier; released by the framing step once serialized.</param>
public sealed record TpmRsaEncryptResponse(TpmRcConstants ResponseCode, Tpm2bPublicKeyRsa OutData): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful plain-form response to <c>TPM2_RSA_Decrypt()</c>: a <c>TPM2B_PUBLIC_KEY_RSA</c> carrying the
/// recovered plaintext (TPM 2.0 Library Part 3, clause 14.3, Table 47) — the <c>TPM2_Unseal()</c>/
/// <c>TPM2_ObjectChangeAuth()</c> response shape, no trailing response-session area. The session form instead
/// frames through the shared over-sessions machinery (<see cref="TpmOverSessionsResponse"/>) and never reaches
/// this type.
/// </summary>
/// <param name="ResponseCode">The response code (success).</param>
/// <param name="Message">
/// The recovered plaintext (<c>TPM2B_PUBLIC_KEY_RSA</c>) in an owned pooled carrier; released by the framing
/// step once serialized, zeroed first — the recovered plaintext is never left in a freed pooled buffer (the
/// clear-before-dispose discipline).
/// </param>
public sealed record TpmRsaDecryptResponse(TpmRcConstants ResponseCode, Tpm2bPublicKeyRsa Message): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_NV_Read()</c>: the data read from the NV Index as a
/// <c>TPM2B_MAX_NV_BUFFER</c> (TPM 2.0 Library Part 3, clause 31.13).
/// </summary>
/// <remarks>
/// <see cref="Data"/> carries a BORROW of the carrier the durable NV Index owns, plus the requested offset and
/// size — not a rental of this intent's. The Index goes on living after the command and remains that carrier's
/// single owner, so this is the one intent-carried carrier that must NOT join the blanket release
/// <see cref="TpmSimulator"/> performs after framing every other intent buffer, exactly as
/// <see cref="TpmPolicyGetDigestResponse.PolicyDigest"/> must not: releasing it here would leave the still-live
/// Index holding a returned buffer. Framing only copies the window's octets into the framed
/// <c>TPM2B_MAX_NV_BUFFER</c>.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="Data">The window of the Index's data area the read answers with, borrowed from the Index that owns it.</param>
public sealed record TpmNvReadDataResponse(TpmRcConstants ResponseCode, TpmNvDataWindow Data): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_NV_ReadPublic()</c>: the NV Index's public area followed by its computed
/// Name (TPM 2.0 Library Part 3, clause 31.6). <c>Auth Index: None</c>, so the response carries no session area
/// regardless of what accompanied the command.
/// </summary>
/// <remarks>
/// <see cref="NvPublic"/> and <see cref="NvName"/> are the terminal owners of, respectively, the built public
/// area (which owns pooled policy-digest memory) and the Name carrier; <see cref="TpmSimulator"/> frames
/// <c>nvPublic</c> as a <c>TPM2B_NV_PUBLIC</c> (a UINT16 size prefix around <see cref="NvPublic"/>'s marshaled
/// octets) and <c>nvName</c> through the carrier's own <c>WriteTo</c>, then disposes both.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="NvPublic">The Index's public area; disposed after framing.</param>
/// <param name="NvName">The Index's computed Name as a <c>TPM2B_NAME</c> (TPM 2.0 Library Part 2, clause 10.4.3, Table 105); owned, disposed after framing.</param>
public sealed record TpmNvReadPublicResponse(
    TpmRcConstants ResponseCode,
    TpmsNvPublic NvPublic,
    Tpm2bName NvName): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_ReadPublic()</c>: a loaded object's public area, Name, and Qualified Name
/// (TPM 2.0 Library Part 3, clause 12.4, Table 25). <c>Auth Index: None</c>, so the response carries no session
/// area regardless of what accompanied the command.
/// </summary>
/// <remarks>
/// Every carrier is BORROWED from the still-loaded object's own durable record — the object outlives the
/// response — so <see cref="TpmSimulator"/> frames each through its own <c>WriteTo</c> and never disposes any
/// of them, the same borrowing <see cref="TpmNvReadDataResponse"/> applies to an Index's data window.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="OutPublic">The object's public area (<c>TPM2B_PUBLIC</c>, TPM 2.0 Library Part 2, clause 12.2.5, Table 236); borrowed from the object's record, never disposed here.</param>
/// <param name="Name">The object's Name (<c>TPM2B_NAME</c>, TPM 2.0 Library Part 2, clause 10.4.3, Table 105); borrowed, never disposed here.</param>
/// <param name="QualifiedName">The object's Qualified Name (<c>TPM2B_NAME</c>; TPM 2.0 Library Part 1, clause 23.5); borrowed, never disposed here.</param>
public sealed record TpmReadPublicResponse(
    TpmRcConstants ResponseCode,
    Tpm2bPublic OutPublic,
    Tpm2bName Name,
    Tpm2bName QualifiedName): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to a session-authorized NV command (<c>TPM2_NV_Read()</c>, <c>TPM2_NV_Write()</c>,
/// <c>TPM2_NV_DefineSpace()</c>, <c>TPM2_NV_UndefineSpace()</c>, <c>TPM2_NV_Increment()</c>, or
/// <c>TPM2_NV_Extend()</c>) whose auth area carried an HMAC session
/// rather than a password: a <c>TPM_ST_SESSIONS</c>-tagged response carrying the command's own (possibly
/// empty) response parameter area followed by the response session area (nonceTPM, sessionAttributes, HMAC)
/// (TPM 2.0 Library Part 1, clause 15.6.1) — the NV-family counterpart of
/// <see cref="TpmPolicySecretOverSessionResponse"/>, generalized over <see cref="ParameterArea"/> since
/// <c>TPM2_NV_Write()</c>/<c>TPM2_NV_DefineSpace()</c>/<c>TPM2_NV_UndefineSpace()</c>/<c>TPM2_NV_Increment()</c>/
/// <c>TPM2_NV_Extend()</c> carry no response
/// parameter at all while <c>TPM2_NV_Read()</c> carries the read <c>TPM2B_MAX_NV_BUFFER</c> data. The
/// parameter-free hierarchy and provisioning commands (<c>TPM2_Clear()</c>, <c>TPM2_ClearControl()</c>,
/// <c>TPM2_HierarchyControl()</c>, <c>TPM2_SetPrimaryPolicy()</c>) frame through the same shape. The one NV
/// command that does not is <c>TPM2_NV_Certify()</c>, whose response owes one entry PER command session over a
/// non-empty parameter area (<see cref="TpmOverSessionsResponse"/>) — this single-entry shape cannot
/// express it.
/// </summary>
/// <remarks>
/// <see cref="ParameterArea"/> and <see cref="Hmac"/> are pooled carriers; <see cref="TpmSimulator"/> frames the
/// session-tagged envelope and then disposes all three, as the terminal owner — <see cref="NonceTpm"/> included:
/// it is the framing step's own carrier, rented alongside the one the durable session record keeps.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="ParameterArea">The framed response parameter bytes (empty for Write/DefineSpace/UndefineSpace/Increment/Extend); disposed after framing.</param>
/// <param name="NonceTpm">The rolled nonceTPM framed as the response session nonce (nonceNewer) — a <c>TPM2B_NONCE</c> (TPM 2.0 Library Part 2, clause 10.3.4, Table 92) in an owned pooled carrier, disposed after framing.</param>
/// <param name="SessionAttributes">The response session-attributes octet, framed and folded into <paramref name="Hmac"/>.</param>
/// <param name="Hmac">The response session HMAC as the <c>TPMS_AUTH_RESPONSE.hmac</c> <c>TPM2B_AUTH</c> (TPM 2.0 Library Part 2, clause 10.12.3, Table 157); owned, disposed after framing.</param>
public sealed record TpmNvSessionResponse(
    TpmRcConstants ResponseCode,
    TpmParameterArea ParameterArea,
    Tpm2bNonce NonceTpm,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to an authValue rotation — <c>TPM2_NV_ChangeAuth()</c> (TPM 2.0 Library Part 3,
/// clause 31.15, Table 270) or <c>TPM2_HierarchyChangeAuth()</c> (clause 24.8, Table 206): a
/// <c>TPM_ST_SESSIONS</c>-tagged response with an empty parameter area — neither returns any parameter —
/// followed by one response session entry per command session, in command-session order (Part 1, clause 16.6).
/// </summary>
/// <remarks>
/// Distinct from <see cref="TpmNvSessionResponse"/>, which frames a single entry: these are the commands whose
/// authorization area can carry two sessions, the one that authorizes the rotation and a separate
/// <c>decrypt</c> session protecting <c>newAuth</c> in flight. A <c>TPM_RS_PW</c> slot — which only
/// <c>TPM2_HierarchyChangeAuth()</c> admits, and only beside that companion — contributes the empty-nonce,
/// empty-HMAC placeholder entry it is owed. Each REAL entry's <c>Hmac</c> is a pooled buffer
/// <see cref="TpmSimulator"/> disposes after framing, as the terminal owner, while a placeholder owns none; each
/// entry's <c>NewNonceTpm</c> is likewise an owned carrier disposed after framing, distinct from the carrier the
/// rolling transition installed on the durable session.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="Entries">Every session's framed response entry, in command-session order.</param>
public sealed record TpmNvChangeAuthResponse(
    TpmRcConstants ResponseCode,
    ImmutableArray<TpmNvChangeAuthFramedSessionEntry> Entries): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_Certify()</c>: the signed attestation as a <c>TPM2B_ATTEST</c> followed by
/// the <c>TPMT_SIGNATURE</c> over its digest (TPM 2.0 Library Part 3, clause 18.2).
/// </summary>
/// <remarks>
/// <see cref="CertifyInfo"/> and <see cref="Signature"/> own pooled memory; <see cref="TpmSimulator"/> writes
/// each through its own <c>WriteTo</c> and then disposes both, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="CertifyInfo">The <c>TPM2B_ATTEST</c> over the marshaled <c>TPMS_ATTEST</c>; disposed after framing.</param>
/// <param name="Signature">The <c>TPMT_SIGNATURE</c> over the attestation digest; disposed after framing.</param>
public sealed record TpmCertifyResponse(
    TpmRcConstants ResponseCode,
    Tpm2bAttest CertifyInfo,
    TpmtSignature Signature): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_CertifyCreation()</c>: the signed attestation as a <c>TPM2B_ATTEST</c>
/// followed by the <c>TPMT_SIGNATURE</c> over its digest (TPM 2.0 Library Part 3, clause 18.3) — the same shape
/// as <see cref="TpmCertifyResponse"/>.
/// </summary>
/// <remarks>
/// <see cref="CertifyInfo"/> and <see cref="Signature"/> own pooled memory; <see cref="TpmSimulator"/> writes
/// each through its own <c>WriteTo</c> and then disposes both, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="CertifyInfo">The <c>TPM2B_ATTEST</c> over the marshaled <c>TPMS_ATTEST</c>; disposed after framing.</param>
/// <param name="Signature">The <c>TPMT_SIGNATURE</c> over the attestation digest; disposed after framing.</param>
public sealed record TpmCertifyCreationResponse(
    TpmRcConstants ResponseCode,
    Tpm2bAttest CertifyInfo,
    TpmtSignature Signature): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_GetTime()</c>: the signed attestation as a <c>TPM2B_ATTEST</c> followed by
/// the <c>TPMT_SIGNATURE</c> over its digest (TPM 2.0 Library Part 3, clause 18.7) — the same shape as
/// <see cref="TpmCertifyResponse"/>.
/// </summary>
/// <remarks>
/// <see cref="TimeInfo"/> and <see cref="Signature"/> own pooled memory; <see cref="TpmSimulator"/> writes each
/// through its own <c>WriteTo</c> and then disposes both, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="TimeInfo">The <c>TPM2B_ATTEST</c> over the marshaled <c>TPMS_ATTEST</c>; disposed after framing.</param>
/// <param name="Signature">The <c>TPMT_SIGNATURE</c> over the attestation digest; disposed after framing.</param>
public sealed record TpmGetTimeResponse(
    TpmRcConstants ResponseCode,
    Tpm2bAttest TimeInfo,
    TpmtSignature Signature): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_GetSessionAuditDigest()</c>: the signed attestation as a
/// <c>TPM2B_ATTEST</c> followed by the <c>TPMT_SIGNATURE</c> over its digest — the NULL Signature for the NULL
/// signer (TPM 2.0 Library Part 3, clause 18.5, Table 104) — the same shape as <see cref="TpmGetTimeResponse"/>.
/// </summary>
/// <remarks>
/// <see cref="AuditInfo"/> and <see cref="Signature"/> own pooled memory, except when <see cref="Signature"/> is
/// the dispose-immune <see cref="TpmtSignature.Null"/>; <see cref="TpmSimulator"/> writes each through its own
/// <c>WriteTo</c> and then disposes both, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="AuditInfo">The <c>TPM2B_ATTEST</c> over the marshaled <c>TPMS_ATTEST</c>; disposed after framing.</param>
/// <param name="Signature">The <c>TPMT_SIGNATURE</c> over the attestation digest, or <see cref="TpmtSignature.Null"/> for the NULL signer; disposed after framing.</param>
public sealed record TpmGetSessionAuditDigestResponse(
    TpmRcConstants ResponseCode,
    Tpm2bAttest AuditInfo,
    TpmtSignature Signature): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_ReadClock()</c>: the current <c>TPMS_TIME_INFO</c>, uncertified and
/// unsigned (TPM 2.0 Library Part 3, clause 29.1).
/// </summary>
/// <remarks>
/// <see cref="CurrentTime"/> is a value type read straight from state, so nothing is disposed after framing.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="CurrentTime">The current Time/Clock/resetCount/restartCount/Safe snapshot.</param>
public sealed record TpmReadClockResponse(TpmRcConstants ResponseCode, TpmsTimeInfo CurrentTime): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_NV_Certify()</c>: the signed attestation as a <c>TPM2B_ATTEST</c> followed
/// by the <c>TPMT_SIGNATURE</c> over its digest (TPM 2.0 Library Part 3, clause 31.16) — the same shape as
/// <see cref="TpmCertifyResponse"/>.
/// </summary>
/// <remarks>
/// <see cref="CertifyInfo"/> and <see cref="Signature"/> own pooled memory; <see cref="TpmSimulator"/> writes
/// each through its own <c>WriteTo</c> and then disposes both, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="CertifyInfo">The <c>TPM2B_ATTEST</c> over the marshaled <c>TPMS_ATTEST</c>; disposed after framing.</param>
/// <param name="Signature">The <c>TPMT_SIGNATURE</c> over the attestation digest; disposed after framing.</param>
public sealed record TpmNvCertifyResponse(
    TpmRcConstants ResponseCode,
    Tpm2bAttest CertifyInfo,
    TpmtSignature Signature): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to a command whose authorization area carried at least one real session and whose
/// slots are independent of one another — an attest command (<c>TPM2_Certify()</c>, <c>TPM2_CertifyCreation()</c>,
/// <c>TPM2_Quote()</c>, <c>TPM2_GetTime()</c>, <c>TPM2_NV_Certify()</c>: the framed <c>TPM2B_ATTEST ‖
/// TPMT_SIGNATURE</c>) or a signing-family command (<c>TPM2_Sign()</c>, <c>TPM2_SignDigest()</c>,
/// <c>TPM2_SignSequenceComplete()</c>: the framed <c>TPMT_SIGNATURE</c>; <c>TPM2_VerifySequenceComplete()</c>: the
/// framed <c>TPMT_TK_VERIFIED</c>; <c>TPM2_SequenceUpdate()</c>: no parameter at all): a
/// <c>TPM_ST_SESSIONS</c>-tagged response carrying the already-framed parameter area followed by one response
/// session entry per command session, in command-session order (TPM 2.0 Library Part 3, clause 18.2 Table 98,
/// clause 18.3 Table 100, clause 18.4 Table 102, clause 18.7 Table 108, clause 31.16.2 Table 272, clause 20.5
/// Table 123, clause 20.7 Table 127, clause 20.6 Table 125, clause 20.3 Table 119, clause 17.7 Table 92; Part 1,
/// clause 15.6.1).
/// </summary>
/// <remarks>
/// <para>
/// Every such command may authorize more than one handle, or ride a companion beside its one authorizing slot,
/// and each slot's session kind is independent of the others', so the response owes its parameter area AND an
/// entry per session with the <c>TPM_RS_PW</c> placeholder decided per entry rather than by a single leading
/// flag — the shape neither <see cref="TpmNvSessionResponse"/> (parameters, one entry) nor
/// <see cref="TpmNvChangeAuthResponse"/> (entries, no parameters) can express. <see cref="TpmCreateOverSessionsResponse"/>
/// is the closest sibling shape.
/// </para>
/// <para>
/// <see cref="ParameterArea"/> is a pooled carrier; <see cref="TpmSimulator"/> frames the session-tagged envelope
/// and then disposes it, as the terminal owner, along with each real entry's own <c>Hmac</c> buffer. A
/// placeholder entry owns nothing: a password session carries no key, so its entry is an empty nonce, the echoed
/// attributes, and an empty HMAC (Part 1, clause 16.6.4.1's password authorization has no session secret to key
/// one with).
/// </para>
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="ParameterArea">The framed response parameter area — the exact octets rpHash was computed over, empty for <c>TPM2_SequenceUpdate()</c>; disposed after framing.</param>
/// <param name="Entries">Every session's framed response entry, in command-session order; each real entry's <c>Hmac</c> buffer is disposed after framing.</param>
/// <param name="ResponseHandle">
/// The response handle area (TPM 2.0 Library Part 3, clause 4.3), written by <c>SerializeOverSessionsResponse</c>
/// immediately after the header and ahead of <c>parameterSize</c> when present — excluded from rpHash by
/// construction, since rpHash covers only <see cref="ParameterArea"/> (TPM 2.0 Library Part 1, clause 15.8:
/// "The contents of the handles area of the response are not included in the rpHash."). <see langword="null"/>
/// for every command whose <c>TPMA_CC.R_HANDLE</c> row is clear.
/// </param>
public sealed record TpmOverSessionsResponse(
    TpmRcConstants ResponseCode,
    TpmParameterArea ParameterArea,
    ImmutableArray<TpmFramedSessionEntry> Entries,
    TpmHandle? ResponseHandle = null): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_VerifySignature()</c>: a <c>TPMT_TK_VERIFIED</c> validation ticket (TPM 2.0
/// Library Part 3, clause 20.2) — unlike every other attest-producing command in this file, there is no
/// <c>TPM2B_ATTEST</c> and no <c>TPMT_SIGNATURE</c>.
/// </summary>
/// <remarks>
/// <see cref="Validation"/> is an owned carrier holding the whole ticket; <see cref="TpmSimulator"/> writes it
/// through its own <c>WriteTo</c> and then disposes it, as the terminal owner. Table 117 gives the response one
/// parameter, so the tag, hierarchy, and digest travel as that one structure.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="Validation">The <c>TPMT_TK_VERIFIED</c> validation ticket (TPM 2.0 Library Part 2, clause 10.6.5, Table 113); owned, disposed after framing.</param>
public sealed record TpmVerifySignatureResponse(
    TpmRcConstants ResponseCode,
    TpmtTkVerified Validation): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_VerifyDigestSignature()</c>: a <c>TPMT_TK_VERIFIED</c> validation ticket
/// tagged <c>TPM_ST_DIGEST_VERIFIED</c> (TPM 2.0 Library Part 3, clause 20.4; Part 2, clause 10.6.5, Table 112).
/// A distinct type from <see cref="TpmVerifySignatureResponse"/> even though both frame the identical
/// <c>TPMT_TK_VERIFIED</c> wire shape: this ticket's <see cref="TpmtTkVerified.Metadata"/> carries the verified
/// scheme's hash algorithm (Table 111's <c>digestVerified</c> arm), which <c>TPM2_VerifySignature()</c>'s
/// <c>TPM_ST_VERIFIED</c> ticket never does.
/// </summary>
/// <remarks>
/// <see cref="Validation"/> is an owned carrier holding the whole ticket; <see cref="TpmSimulator"/> writes it
/// through its own <c>WriteTo</c> and then disposes it, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="Validation">The <c>TPMT_TK_VERIFIED</c> validation ticket (TPM 2.0 Library Part 2, clause 10.6.5, Table 113); owned, disposed after framing.</param>
public sealed record TpmVerifyDigestSignatureResponse(
    TpmRcConstants ResponseCode,
    TpmtTkVerified Validation): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_Encapsulate()</c>: the DHKEM shared secret followed by its ciphertext
/// (TPM 2.0 Library Part 3, clause 14.10, Table 61).
/// </summary>
/// <remarks>
/// <see cref="SharedSecret"/> and <see cref="Ciphertext"/> own pooled memory; <see cref="TpmSimulator"/>
/// writes each through its own <c>WriteTo</c> — in Table 61's order, <c>sharedSecret</c> then
/// <c>ciphertext</c> — and then disposes both, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="SharedSecret">The DHKEM shared secret (<c>TPM2B_SHARED_SECRET</c>); disposed after framing.</param>
/// <param name="Ciphertext">The DHKEM ciphertext — the ephemeral SEC 1 point (<c>TPM2B_KEM_CIPHERTEXT</c>); disposed after framing.</param>
public sealed record TpmEncapsulateResponse(
    TpmRcConstants ResponseCode,
    Tpm2bSharedSecret SharedSecret,
    Tpm2bKemCiphertext Ciphertext): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_Decapsulate()</c>: the recovered DHKEM shared secret alone (TPM 2.0
/// Library Part 3, clause 14.11, Table 63).
/// </summary>
/// <remarks>
/// <see cref="SharedSecret"/> owns pooled memory; <see cref="TpmSimulator"/> writes it through its own
/// <c>WriteTo</c> and then disposes it, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="SharedSecret">The recovered DHKEM shared secret (<c>TPM2B_SHARED_SECRET</c>); disposed after framing.</param>
public sealed record TpmDecapsulateResponse(
    TpmRcConstants ResponseCode,
    Tpm2bSharedSecret SharedSecret): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_PCR_Read()</c>: the PCR update counter, the selection actually read, and
/// the selected register values (TPM 2.0 Library Part 3, clause 22.4).
/// </summary>
/// <remarks>
/// <see cref="PcrSelection"/> is the carrier the parser rented, which <c>TPM2_PCR_Read()</c>'s own request
/// transferred here unchanged; <see cref="TpmSimulator"/> writes it through its own <c>WriteTo</c> as
/// <c>pcrSelectionOut</c> and then disposes it, as the terminal owner. <see cref="PcrValues"/> are references
/// into durable bank state, so nothing is disposed for them — they are copied into the framed
/// <c>TPML_DIGEST</c>.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="PcrUpdateCounter">
/// The TPM-wide PCR-change count carried on <see cref="TpmSimulatorState.PcrUpdateCounter"/>, which a caller
/// compares across two reads to learn that some register moved.
/// </param>
/// <param name="PcrSelection">The parsed selection, re-marshaled as <c>pcrSelectionOut</c>; disposed after framing.</param>
/// <param name="PcrValues">The selected register values in ascending PCR-index order, framed as a <c>TPML_DIGEST</c>.</param>
public sealed record TpmPcrReadResponse(
    TpmRcConstants ResponseCode,
    uint PcrUpdateCounter,
    TpmlPcrSelection PcrSelection,
    ImmutableArray<ReadOnlyMemory<byte>> PcrValues): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_PCR_Event()</c> and <c>TPM2_EventSequenceComplete()</c>: the tagged
/// digests of the event, one per implemented hash algorithm — Tables 133 and 96 (TPM 2.0 Library Part 3,
/// clauses 22.3 and 17.9) are identical in shape (one <c>TPML_DIGEST_VALUES</c>), so one intent frames both,
/// exactly as <see cref="TpmDigestResponse"/> serves Tables 94 and 70.
/// </summary>
/// <remarks>
/// <see cref="Digests"/> is an owned carrier; <see cref="TpmSimulator"/> writes it through its own
/// <c>WriteTo</c> and then disposes it, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="Digests">The tagged digests (<c>digests</c> / <c>results</c>, <c>TPML_DIGEST_VALUES</c>, TPM 2.0 Library Part 2, clause 10.8.6, Table 127); owned, disposed after framing.</param>
public sealed record TpmDigestValuesResponse(TpmRcConstants ResponseCode, TpmlDigestValues Digests): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_Quote()</c>: the signed attestation as a <c>TPM2B_ATTEST</c> followed by
/// the <c>TPMT_SIGNATURE</c> over its digest (TPM 2.0 Library Part 3, clause 18.4).
/// </summary>
/// <remarks>
/// <see cref="Quoted"/> and <see cref="Signature"/> own pooled memory; <see cref="TpmSimulator"/> writes each
/// through its own <c>WriteTo</c> and then disposes both, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="Quoted">The <c>TPM2B_ATTEST</c> over the marshaled <c>TPMS_ATTEST</c>; disposed after framing.</param>
/// <param name="Signature">The <c>TPMT_SIGNATURE</c> over the attestation digest; disposed after framing.</param>
public sealed record TpmQuoteResponse(
    TpmRcConstants ResponseCode,
    Tpm2bAttest Quoted,
    TpmtSignature Signature): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_StartAuthSession()</c>: the started session's handle followed by the TPM's
/// initial nonce (TPM 2.0 Library Part 3, clause 11.1).
/// </summary>
/// <remarks>
/// <see cref="NonceTpm"/> is always the real, retained nonceTPM the effectful loop drew from the injected RNG,
/// for every session kind: a bound HMAC session's session-key <c>KDFa</c> consumed it (Part 1, clause 16.6.10),
/// and a policy or trial session's <c>TPM2_PolicySigned()</c> <c>aHash</c> later binds to it (Part 3, clause
/// 23.3) — so neither can be a placeholder. <see cref="NonceTpm"/> is the framing step's own owned carrier,
/// rented alongside the one the durable session record keeps, and released once framed.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="SessionHandle">The started session handle, framed in the response handle area.</param>
/// <param name="NonceTpm">The real nonceTPM to frame verbatim — a <c>TPM2B_NONCE</c> (TPM 2.0 Library Part 2, clause 10.3.4, Table 92) in an owned pooled carrier, disposed after framing.</param>
public sealed record TpmStartAuthSessionResponse(
    TpmRcConstants ResponseCode,
    TpmiShAuthSession SessionHandle,
    Tpm2bNonce NonceTpm): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_Unseal()</c> over one or two sessions: a <c>TPM_ST_SESSIONS</c>-tagged
/// response carrying the (possibly encrypted) <c>outData</c> (<c>TPM2B_SENSITIVE_DATA</c>) parameter followed by
/// the response session area, in command-session order — a satisfied plain policy session's placeholder entry (a
/// zero nonce of its hash width, echoed attributes, an empty HMAC, since it carries no key) when
/// <see cref="HasPolicyPlaceholder"/> is set, then every real (HMAC-table) session's entry in <see cref="Entries"/>
/// (its rolled nonceTPM, echoed attributes, and its own response HMAC) (TPM 2.0 Library Part 3, clause 12.7; Part
/// 1, clauses 15.7 and 18).
/// </summary>
/// <remarks>
/// <see cref="ParameterArea"/> is a pooled carrier; <see cref="TpmSimulator"/> frames the session-tagged envelope
/// and then disposes it, as the terminal owner, along with each entry's own <c>Hmac</c> buffer. The parameter area
/// holds the recovered secret, encrypted when a session carries the <c>encrypt</c> attribute, so it is zeroed
/// before disposal regardless.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="ParameterArea">The framed <c>TPM2B_SENSITIVE_DATA</c> (<c>outData</c>), its data portion encrypted when a session carries the <c>encrypt</c> attribute; disposed after framing.</param>
/// <param name="HasPolicyPlaceholder">Whether session index 0 needs the zero-nonce, empty-HMAC policy placeholder entry.</param>
/// <param name="PolicyNonceLength">The width in octets of the policy session's response nonce (a zero placeholder of its hash digest width). Meaningful only when <see cref="HasPolicyPlaceholder"/> is set.</param>
/// <param name="PolicyAttributes">The policy session's response session-attributes octet, framed in its entry. Meaningful only when <see cref="HasPolicyPlaceholder"/> is set.</param>
/// <param name="Entries">Every real session's framed response entry, in command-session order (after the policy placeholder, when present); each entry's <c>Hmac</c> buffer is disposed after framing.</param>
public sealed record TpmUnsealOverSessionsResponse(
    TpmRcConstants ResponseCode,
    TpmParameterArea ParameterArea,
    bool HasPolicyPlaceholder,
    int PolicyNonceLength,
    TpmaSession PolicyAttributes,
    ImmutableArray<TpmUnsealFramedSessionEntry> Entries): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_PolicyGetDigest()</c>: the session's current policyDigest as a
/// <c>TPM2B_DIGEST</c> (TPM 2.0 Library Part 3, clause 23.6).
/// </summary>
/// <remarks>
/// <see cref="PolicyDigest"/> is a BORROW of the durable session state's own carrier, not a rental of this
/// intent's — the session goes on accumulating after this command and remains the carrier's single owner. It is
/// therefore the one intent-carried carrier that must NOT join the blanket release
/// <see cref="TpmSimulator"/> performs after framing every other intent buffer: releasing it here would leave
/// the still-live session holding a returned buffer, and the next assertion against it would fail on a carrier
/// its owner never released. Framing only copies the octets into the framed <c>TPM2B_DIGEST</c>.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="PolicyDigest">The session's accumulated policyDigest (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90), borrowed from the session record that owns it.</param>
public sealed record TpmPolicyGetDigestResponse(
    TpmRcConstants ResponseCode,
    Tpm2bDigest PolicyDigest): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_PolicySecret()</c>: the timeout and policy authorization ticket (TPM 2.0
/// Library Part 3, clause 23.4).
/// </summary>
/// <remarks>
/// When <see cref="TicketDigest"/> is <see langword="null"/> (the immediate form, a trial session, or a
/// non-negative expiration — clause 23.2.5: "if expiration is non-negative, a NULL Ticket is returned"),
/// <see cref="TpmSimulator"/> frames an empty <c>TPM2B_TIMEOUT</c> and a well-formed NULL <c>TPMT_TK_AUTH</c>
/// (tag <c>TPM_ST_AUTH_SECRET</c>, hierarchy <c>TPM_RH_NULL</c>, empty digest — Part 2, clause 10.6.2's
/// NULL-ticket convention). Otherwise it frames the real 8-byte big-endian <c>TPM2B_TIMEOUT</c> (bit 63 =
/// expires-on-reset) and the real <c>TPMT_TK_AUTH</c>. Either way it then disposes <see cref="Timeout"/> and
/// <see cref="TicketDigest"/> as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="Timeout">The deadline as a <c>TPM2B_TIMEOUT</c> (TPM 2.0 Library Part 2, clause 10.3.10, Table 98), bit 63 carrying the expires-on-reset flag; owned, disposed after framing, and ignored (a NULL timeout is framed instead) when <see cref="TicketDigest"/> is <see langword="null"/>.</param>
/// <param name="Hierarchy">The hierarchy framed in the ticket's own <c>hierarchy</c> field; meaningless when <see cref="TicketDigest"/> is <see langword="null"/> (a NULL ticket always frames <c>TPM_RH_NULL</c> regardless).</param>
/// <param name="TicketDigest">The minted ticket's HMAC digest as the <c>TPM2B_DIGEST</c> <c>TPMT_TK_AUTH.digest</c> names (Part 2, clause 10.6.6, Table 114); owned, disposed after framing. <see langword="null"/> for a NULL ticket.</param>
public sealed record TpmPolicySecretResponse(
    TpmRcConstants ResponseCode,
    Tpm2bTimeout Timeout,
    TpmiRhHierarchy Hierarchy,
    Tpm2bDigest? TicketDigest): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_PolicySecret()</c> when <c>authHandle</c> was authorized by an HMAC or
/// POLICY session rather than a password: a <c>TPM_ST_SESSIONS</c>-tagged response carrying the framed
/// <c>TPM2B_TIMEOUT ‖ TPMT_TK_AUTH</c> parameter bytes followed by the response session area (nonceTPM,
/// sessionAttributes, HMAC) (TPM 2.0 Library Part 3, clause 23.4; Part 1, clause 15.6.1) — the
/// session-authorized counterpart of <see cref="TpmPolicySecretResponse"/>: one framed parameter area and one
/// response session entry (nonceTPM, sessionAttributes, HMAC), the same shape <see cref="TpmOverSessionsResponse"/>
/// generalizes to an arbitrary entry count.
/// </summary>
/// <remarks>
/// <see cref="ParameterArea"/> and <see cref="Hmac"/> are pooled carriers; <see cref="TpmSimulator"/> frames the
/// session-tagged envelope and then disposes all three, as the terminal owner — <see cref="NonceTpm"/> included:
/// it is the framing step's own carrier, rented alongside the one the durable session record keeps.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="ParameterArea">The framed <c>TPM2B_TIMEOUT ‖ TPMT_TK_AUTH</c> parameter bytes; disposed after framing.</param>
/// <param name="NonceTpm">The rolled nonceTPM framed as the response session nonce (nonceNewer) — a <c>TPM2B_NONCE</c> (TPM 2.0 Library Part 2, clause 10.3.4, Table 92) in an owned pooled carrier, disposed after framing.</param>
/// <param name="SessionAttributes">The response session-attributes octet, framed and folded into <paramref name="Hmac"/>.</param>
/// <param name="Hmac">The response session HMAC as the <c>TPMS_AUTH_RESPONSE.hmac</c> <c>TPM2B_AUTH</c> (TPM 2.0 Library Part 2, clause 10.12.3, Table 157); owned, disposed after framing.</param>
public sealed record TpmPolicySecretOverSessionResponse(
    TpmRcConstants ResponseCode,
    TpmParameterArea ParameterArea,
    Tpm2bNonce NonceTpm,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_PolicySigned()</c>: the timeout and policy authorization ticket (TPM 2.0
/// Library Part 3, clause 23.3).
/// </summary>
/// <remarks>
/// When <see cref="TicketDigest"/> is <see langword="null"/> (a trial session, or a non-negative
/// <c>expiration</c>), <see cref="TpmSimulator"/> frames an empty <c>TPM2B_TIMEOUT</c> and a well-formed NULL
/// <c>TPMT_TK_AUTH</c> (tag <c>TPM_ST_AUTH_SIGNED</c> — set even on a NULL ticket, Part 2, clause 10.6.2's
/// NULL-ticket convention — hierarchy <c>TPM_RH_NULL</c>, empty digest). Otherwise it frames the real 8-byte
/// big-endian <c>TPM2B_TIMEOUT</c> (bit 63 = expires-on-reset) and the real <c>TPMT_TK_AUTH</c>. Either way it
/// then disposes <see cref="Timeout"/> and <see cref="TicketDigest"/> as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="Timeout">The deadline as a <c>TPM2B_TIMEOUT</c> (TPM 2.0 Library Part 2, clause 10.3.10, Table 98), bit 63 carrying the expires-on-reset flag; owned, disposed after framing, and ignored (a NULL timeout is framed instead) when <see cref="TicketDigest"/> is <see langword="null"/>.</param>
/// <param name="Hierarchy">The hierarchy framed in the ticket's own <c>hierarchy</c> field; meaningless when <see cref="TicketDigest"/> is <see langword="null"/> (a NULL ticket always frames <c>TPM_RH_NULL</c> regardless).</param>
/// <param name="TicketDigest">The minted ticket's HMAC digest as the <c>TPM2B_DIGEST</c> <c>TPMT_TK_AUTH.digest</c> names (Part 2, clause 10.6.6, Table 114); owned, disposed after framing. <see langword="null"/> for a NULL ticket.</param>
public sealed record TpmPolicySignedResponse(
    TpmRcConstants ResponseCode,
    Tpm2bTimeout Timeout,
    TpmiRhHierarchy Hierarchy,
    Tpm2bDigest? TicketDigest): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_MakeCredential()</c>: the integrity-protected, encrypted credential blob
/// (<c>TPM2B_ID_OBJECT</c>) followed by the seed encrypted to the credential key's public area
/// (<c>TPM2B_ENCRYPTED_SECRET</c>) (TPM 2.0 Library Part 3, clause 12.6).
/// </summary>
/// <remarks>
/// <see cref="CredentialBlob"/> and <see cref="Secret"/> are owned carriers; <see cref="TpmSimulator"/> writes
/// each through its own <c>WriteTo</c> and then disposes both, as the terminal owner. Both outputs are public (they
/// protect the credential cryptographically), so the response is framed with the no-sessions tag.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="CredentialBlob">The <c>TPMS_ID_OBJECT</c> as a <c>TPM2B_ID_OBJECT</c> (TPM 2.0 Library Part 2, clause 12.4.3, Table 245); owned, disposed after framing.</param>
/// <param name="Secret">The marshaled seed transport as a <c>TPM2B_ENCRYPTED_SECRET</c> (TPM 2.0 Library Part 2, clause 11.4.3, Table 224); owned, disposed after framing.</param>
public sealed record TpmMakeCredentialResponse(
    TpmRcConstants ResponseCode,
    Tpm2bIdObject CredentialBlob,
    Tpm2bEncryptedSecret Secret): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_ActivateCredential()</c>: a single <c>TPM2B_DIGEST</c> <c>certInfo</c> — the
/// recovered credential secret (TPM 2.0 Library Part 3, clause 12.5). Recovering it proves the activate object and
/// the credential key co-reside in one TPM.
/// </summary>
/// <remarks>
/// <see cref="CertInfo"/> is an owned carrier holding the recovered secret; it is confidential, so
/// <see cref="TpmSimulator"/>, as the terminal owner, releases its pinned segment to the pool, which zeroes
/// every segment it takes back. The activate-object-authorizing and credential-key sessions are empty-auth
/// password sessions, so the response carries no session area and is framed with the no-sessions tag.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="CertInfo">The recovered credential secret as the <c>TPM2B_DIGEST</c> Table 27 gives <c>certInfo</c>; owned, disposed after framing.</param>
public sealed record TpmActivateCredentialResponse(
    TpmRcConstants ResponseCode,
    Tpm2bDigest CertInfo): TpmResponseIntent(ResponseCode);
