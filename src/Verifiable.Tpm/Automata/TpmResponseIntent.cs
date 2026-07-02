using System;
using System.Buffers;
using System.Collections.Immutable;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

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
/// passed, <c>TPM_RC_FAILURE</c> when it failed (TPM 2.0 Library Part 1, clause 10.4).
/// </param>
public sealed record TpmTestResultResponse(TpmRcConstants ResponseCode, TpmRcConstants TestResult): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_GetRandom()</c>: a <c>TPM2B_DIGEST</c> carrying the random
/// octets (TPM 2.0 Library Part 3, clause 16.1).
/// </summary>
/// <remarks>
/// The octets are held in a pooled buffer rented by the RNG action executor. <see cref="TpmSimulator"/>
/// copies them into the framed response and then disposes <see cref="RandomBytes"/>; the intent is the
/// terminal owner of that buffer and is consumed exactly once, immediately after the transition.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="RandomBytes">The pooled buffer holding the produced octets; disposed after framing.</param>
/// <param name="Length">The number of valid octets in <paramref name="RandomBytes"/>.</param>
public sealed record TpmRandomResponse(TpmRcConstants ResponseCode, IMemoryOwner<byte> RandomBytes, int Length): TpmResponseIntent(ResponseCode);

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
/// <see cref="OutPublic"/> owns pooled memory and <see cref="CreationByProducts"/> is a pooled buffer;
/// <see cref="TpmSimulator"/> serializes the object handle, the public area, and the by-products region into
/// the framed response and then disposes both, as the terminal owner. The creation data, creation hash,
/// creation ticket, and Name are computed faithfully (TPM 2.0 Library Part 3, clause 24.1; Part 2, clause 15)
/// in the effectful loop and carried here pre-framed.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="ObjectHandle">The transient handle of the created object, framed in the response handle area.</param>
/// <param name="OutPublic">The exported public area; disposed after framing.</param>
/// <param name="CreationByProducts">The pre-framed <c>creationData ‖ creationHash ‖ creationTicket ‖ name</c> wire bytes; disposed after framing.</param>
/// <param name="CreationByProductsLength">The number of valid octets in <paramref name="CreationByProducts"/>.</param>
public sealed record TpmCreatePrimaryResponse(
    TpmRcConstants ResponseCode,
    uint ObjectHandle,
    Tpm2bPublic OutPublic,
    IMemoryOwner<byte> CreationByProducts,
    int CreationByProductsLength): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_Sign()</c>: a <c>TPMT_SIGNATURE</c> whose active member is the ECDSA or
/// RSA signature (TPM 2.0 Library Part 3, clause 20.2; Part 2, clauses 11.3.2 and 11.3.4).
/// </summary>
/// <remarks>
/// <see cref="Signature"/> holds the signature octets in pooled memory — IEEE P1363 (<c>r ‖ s</c>) for ECDSA,
/// or the raw RSA signature for an RSA scheme. <see cref="TpmSimulator"/> frames it per
/// <see cref="SignatureScheme"/> — splitting ECDSA into <c>r</c> and <c>s</c>, or writing a single RSA
/// signature buffer — and then disposes it, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="Signature">The signature octets; disposed after framing.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>), selecting how the signature is framed.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, framed inside the signature.</param>
public sealed record TpmSignResponse(TpmRcConstants ResponseCode, Signature Signature, TpmAlgIdConstants SignatureScheme, TpmAlgIdConstants HashAlg): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_Create()</c>: the wrapped private blob, the exported public area, and the
/// creation by-products (TPM 2.0 Library Part 3, clause 12.1). Unlike <c>TPM2_CreatePrimary()</c> the created
/// object is not loaded, so there is no response handle and no Name.
/// </summary>
/// <remarks>
/// <see cref="PrivateBlob"/> and <see cref="CreationByProducts"/> are pooled buffers and <see cref="OutPublic"/>
/// owns pooled memory; <see cref="TpmSimulator"/> serializes <c>outPrivate</c>, the public area, and the
/// <c>creationData ‖ creationHash ‖ creationTicket</c> region into the framed response and then disposes all
/// three, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="PrivateBlob">The wrapped private blob (<c>outPrivate</c>); disposed after framing.</param>
/// <param name="PrivateBlobLength">The number of valid octets in <paramref name="PrivateBlob"/>.</param>
/// <param name="OutPublic">The exported public area; disposed after framing.</param>
/// <param name="CreationByProducts">The pre-framed <c>creationData ‖ creationHash ‖ creationTicket</c> wire bytes; disposed after framing.</param>
/// <param name="CreationByProductsLength">The number of valid octets in <paramref name="CreationByProducts"/>.</param>
public sealed record TpmCreateResponse(
    TpmRcConstants ResponseCode,
    IMemoryOwner<byte> PrivateBlob,
    int PrivateBlobLength,
    Tpm2bPublic OutPublic,
    IMemoryOwner<byte> CreationByProducts,
    int CreationByProductsLength): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_Load()</c>: the transient handle of the loaded object followed by its Name
/// (TPM 2.0 Library Part 3, clause 12.2).
/// </summary>
/// <remarks>
/// <see cref="Name"/> is a pooled buffer; <see cref="TpmSimulator"/> serializes the object handle and the Name
/// into the framed response and then disposes it, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="ObjectHandle">The transient handle of the loaded object, framed in the response handle area.</param>
/// <param name="Name">The pooled buffer holding the object Name; disposed after framing.</param>
/// <param name="NameLength">The number of valid octets in <paramref name="Name"/>.</param>
public sealed record TpmLoadResponse(
    TpmRcConstants ResponseCode,
    uint ObjectHandle,
    IMemoryOwner<byte> Name,
    int NameLength): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_Unseal()</c>: a <c>TPM2B_SENSITIVE_DATA</c> carrying the recovered sealed
/// data (TPM 2.0 Library Part 3, clause 12.7).
/// </summary>
/// <remarks>
/// The octets are durable model memory owned by the loaded sealed object, so nothing is disposed after framing —
/// <see cref="TpmSimulator"/> copies them into the framed <c>TPM2B_SENSITIVE_DATA</c>.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="OutData">The recovered sealed data.</param>
public sealed record TpmUnsealResponse(TpmRcConstants ResponseCode, ReadOnlyMemory<byte> OutData): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_NV_Read()</c>: the data read from the NV Index as a
/// <c>TPM2B_MAX_NV_BUFFER</c> (TPM 2.0 Library Part 3, clause 31.13).
/// </summary>
/// <remarks>
/// <see cref="Data"/> references the durable NV-Index data area, so nothing is disposed after framing —
/// <see cref="TpmSimulator"/> copies it into the framed <c>TPM2B_MAX_NV_BUFFER</c>.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="Data">The octets read from the Index at the requested offset and length.</param>
public sealed record TpmNvReadDataResponse(TpmRcConstants ResponseCode, ReadOnlyMemory<byte> Data): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_Certify()</c>: the signed attestation as a <c>TPM2B_ATTEST</c> followed by
/// the <c>TPMT_SIGNATURE</c> over its digest (TPM 2.0 Library Part 3, clause 18.2).
/// </summary>
/// <remarks>
/// <see cref="CertifyInfo"/> is a pooled buffer holding the marshaled <c>TPMS_ATTEST</c> and <see cref="Signature"/>
/// owns pooled memory; <see cref="TpmSimulator"/> frames the sized attest and the ECDSA <c>r</c>/<c>s</c> and then
/// disposes both, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="CertifyInfo">The pooled buffer holding the marshaled <c>TPMS_ATTEST</c>; disposed after framing.</param>
/// <param name="CertifyInfoLength">The number of valid octets in <paramref name="CertifyInfo"/>.</param>
/// <param name="Signature">The signature over the attestation digest; disposed after framing.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c>), the <c>TPMU_SIGNATURE</c> selector.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, framed inside the signature.</param>
public sealed record TpmCertifyResponse(
    TpmRcConstants ResponseCode,
    IMemoryOwner<byte> CertifyInfo,
    int CertifyInfoLength,
    Signature Signature,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants HashAlg): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_PCR_Read()</c>: the PCR update counter, the selection actually read, and
/// the selected register values (TPM 2.0 Library Part 3, clause 22.4).
/// </summary>
/// <remarks>
/// <see cref="SelectionBytes"/> is the caller's <c>TPML_PCR_SELECTION</c> echoed verbatim and the
/// <see cref="PcrValues"/> are references into durable bank state, so nothing is disposed after framing —
/// <see cref="TpmSimulator"/> copies them into the framed <c>pcrSelectionOut</c> and <c>TPML_DIGEST</c>.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="PcrUpdateCounter">The PCR update counter (zero this slice — no register has been extended).</param>
/// <param name="SelectionBytes">The <c>TPML_PCR_SELECTION</c> read, echoed as <c>pcrSelectionOut</c>.</param>
/// <param name="PcrValues">The selected register values in ascending PCR-index order, framed as a <c>TPML_DIGEST</c>.</param>
public sealed record TpmPcrReadResponse(
    TpmRcConstants ResponseCode,
    uint PcrUpdateCounter,
    ReadOnlyMemory<byte> SelectionBytes,
    ImmutableArray<ReadOnlyMemory<byte>> PcrValues): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_Quote()</c>: the signed attestation as a <c>TPM2B_ATTEST</c> followed by
/// the <c>TPMT_SIGNATURE</c> over its digest (TPM 2.0 Library Part 3, clause 18.4).
/// </summary>
/// <remarks>
/// <see cref="Quoted"/> is a pooled buffer holding the marshaled <c>TPMS_ATTEST</c> and <see cref="Signature"/>
/// owns pooled memory; <see cref="TpmSimulator"/> frames the sized attest and the ECDSA <c>r</c>/<c>s</c> and then
/// disposes both, as the terminal owner.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="Quoted">The pooled buffer holding the marshaled <c>TPMS_ATTEST</c>; disposed after framing.</param>
/// <param name="QuotedLength">The number of valid octets in <paramref name="Quoted"/>.</param>
/// <param name="Signature">The signature over the attestation digest; disposed after framing.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c>), the <c>TPMU_SIGNATURE</c> selector.</param>
/// <param name="HashAlg">The signing scheme's hash algorithm, framed inside the signature.</param>
public sealed record TpmQuoteResponse(
    TpmRcConstants ResponseCode,
    IMemoryOwner<byte> Quoted,
    int QuotedLength,
    Signature Signature,
    TpmAlgIdConstants SignatureScheme,
    TpmAlgIdConstants HashAlg): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_StartAuthSession()</c>: the started session's handle followed by the TPM's
/// initial nonce (TPM 2.0 Library Part 3, clause 11.1).
/// </summary>
/// <remarks>
/// <para>
/// A policy or trial session leaves <see cref="NonceTpm"/> empty: its nonceTPM value is immaterial to the
/// policyDigest the assertions drive, so <see cref="TpmSimulator"/> frames a deterministic zero nonce of
/// <see cref="NonceLength"/> octets, which those tests do not inspect.
/// </para>
/// <para>
/// A bound HMAC session instead supplies the real nonceTPM in <see cref="NonceTpm"/>: it is the value the
/// session-key <c>KDFa</c> consumed (Part 1, clause 17.6.10), so the host must receive it verbatim to derive the
/// same key. <see cref="NonceTpm"/> references the durable session state, so nothing is disposed after framing.
/// </para>
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="SessionHandle">The started session handle, framed in the response handle area.</param>
/// <param name="NonceLength">The width in octets of the nonceTPM to frame (the session hash digest width).</param>
/// <param name="NonceTpm">The nonceTPM octets to frame verbatim (a bound HMAC session), or empty to frame a zero nonce of <paramref name="NonceLength"/> octets (a policy or trial session).</param>
public sealed record TpmStartAuthSessionResponse(
    TpmRcConstants ResponseCode,
    uint SessionHandle,
    int NonceLength,
    ReadOnlyMemory<byte> NonceTpm = default): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to an encrypt-attributed <c>TPM2_GetRandom()</c> over a bound HMAC session: a
/// <c>TPM_ST_SESSIONS</c>-tagged response carrying the encrypted <c>TPM2B_DIGEST</c> parameter followed by the
/// response session area (nonceTPM, sessionAttributes, HMAC) (TPM 2.0 Library Part 3, clause 16.1; Part 1,
/// clauses 18.7 and 19).
/// </summary>
/// <remarks>
/// <see cref="ParameterArea"/> and <see cref="Hmac"/> are pooled buffers; <see cref="TpmSimulator"/> frames the
/// session-tagged envelope and then disposes both, as the terminal owner. The parameter area holds the recovered
/// value the encryption protects, so it is zeroed before disposal. <see cref="NonceTpm"/> references the durable
/// session's rolled nonce, so it is not disposed.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="ParameterArea">The framed <c>TPM2B_DIGEST</c> with its data portion encrypted; disposed after framing.</param>
/// <param name="ParameterLength">The number of valid octets in <paramref name="ParameterArea"/>.</param>
/// <param name="NonceTpm">The rolled nonceTPM framed as the response session nonce (nonceNewer).</param>
/// <param name="SessionAttributes">The response session attributes byte, framed and folded into <paramref name="Hmac"/>.</param>
/// <param name="Hmac">The response session HMAC; disposed after framing.</param>
/// <param name="HmacLength">The number of valid octets in <paramref name="Hmac"/>.</param>
public sealed record TpmEncryptedRandomResponse(
    TpmRcConstants ResponseCode,
    IMemoryOwner<byte> ParameterArea,
    int ParameterLength,
    ReadOnlyMemory<byte> NonceTpm,
    byte SessionAttributes,
    IMemoryOwner<byte> Hmac,
    int HmacLength): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to a policy-gated <c>TPM2_Unseal()</c> over two sessions: a <c>TPM_ST_SESSIONS</c>-tagged
/// response carrying the encrypted <c>outData</c> (<c>TPM2B_SENSITIVE_DATA</c>) parameter followed by the response
/// session area with BOTH sessions' entries in command order — the policy session's entry (a zero nonce of its hash
/// width, echoed attributes, and an empty HMAC, since a satisfied plain policy session carries no key) then the
/// encrypt session's entry (its rolled nonceTPM, echoed attributes, and the response HMAC) (TPM 2.0 Library Part 3,
/// clause 12.7; Part 1, clauses 18.7 and 19).
/// </summary>
/// <remarks>
/// <see cref="ParameterArea"/> and <see cref="Hmac"/> are pooled buffers; <see cref="TpmSimulator"/> frames the
/// session-tagged envelope and then disposes both, as the terminal owner. The parameter area holds the recovered
/// secret the encryption protects, so it is zeroed before disposal. <see cref="EncryptNonceTpm"/> references the
/// durable encrypt session's rolled nonce, so it is not disposed.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="ParameterArea">The framed <c>TPM2B_SENSITIVE_DATA</c> (<c>outData</c>) with its data portion encrypted; disposed after framing.</param>
/// <param name="ParameterLength">The number of valid octets in <paramref name="ParameterArea"/>.</param>
/// <param name="PolicyNonceLength">The width in octets of the policy session's response nonce (a zero placeholder of its hash digest width).</param>
/// <param name="PolicyAttributes">The policy session's response session-attributes byte, framed in its entry.</param>
/// <param name="EncryptNonceTpm">The encrypt session's rolled nonceTPM framed as its response nonce (nonceNewer).</param>
/// <param name="EncryptAttributes">The encrypt session's response session-attributes byte, framed and folded into <paramref name="Hmac"/>.</param>
/// <param name="Hmac">The encrypt session's response HMAC; disposed after framing.</param>
/// <param name="HmacLength">The number of valid octets in <paramref name="Hmac"/>.</param>
public sealed record TpmUnsealOverSessionsResponse(
    TpmRcConstants ResponseCode,
    IMemoryOwner<byte> ParameterArea,
    int ParameterLength,
    int PolicyNonceLength,
    byte PolicyAttributes,
    ReadOnlyMemory<byte> EncryptNonceTpm,
    byte EncryptAttributes,
    IMemoryOwner<byte> Hmac,
    int HmacLength): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_PolicyGetDigest()</c>: the session's current policyDigest as a
/// <c>TPM2B_DIGEST</c> (TPM 2.0 Library Part 3, clause 23.6).
/// </summary>
/// <remarks>
/// <see cref="PolicyDigest"/> references the durable session state, so nothing is disposed after framing —
/// <see cref="TpmSimulator"/> copies it into the framed <c>TPM2B_DIGEST</c>.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="PolicyDigest">The session's accumulated policyDigest.</param>
public sealed record TpmPolicyGetDigestResponse(
    TpmRcConstants ResponseCode,
    ReadOnlyMemory<byte> PolicyDigest): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_PolicySecret()</c> in its immediate form: an empty timeout followed by a
/// NULL policy authorization ticket (TPM 2.0 Library Part 3, clause 23.4).
/// </summary>
/// <remarks>
/// The immediate (expiration 0) form produces no usable ticket, so <see cref="TpmSimulator"/> frames an empty
/// <c>TPM2B_TIMEOUT</c> and a well-formed NULL <c>TPMT_TK_AUTH</c> (a placeholder the test does not inspect). The
/// intent owns no memory, so nothing is disposed after framing.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
public sealed record TpmPolicySecretResponse(TpmRcConstants ResponseCode): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_MakeCredential()</c>: the integrity-protected, encrypted credential blob
/// (<c>TPM2B_ID_OBJECT</c>) followed by the seed encrypted to the credential key's public area
/// (<c>TPM2B_ENCRYPTED_SECRET</c>) (TPM 2.0 Library Part 3, clause 12.6).
/// </summary>
/// <remarks>
/// <see cref="CredentialBlob"/> and <see cref="Secret"/> are pooled buffers; <see cref="TpmSimulator"/> frames
/// each as a sized <c>TPM2B</c> and then disposes both, as the terminal owner. Both outputs are public (they
/// protect the credential cryptographically), so the response is framed with the no-sessions tag.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="CredentialBlob">The pooled buffer holding the <c>TPMS_ID_OBJECT</c>; disposed after framing.</param>
/// <param name="CredentialBlobLength">The number of valid octets in <paramref name="CredentialBlob"/>.</param>
/// <param name="Secret">The pooled buffer holding the marshaled seed transport; disposed after framing.</param>
/// <param name="SecretLength">The number of valid octets in <paramref name="Secret"/>.</param>
public sealed record TpmMakeCredentialResponse(
    TpmRcConstants ResponseCode,
    IMemoryOwner<byte> CredentialBlob,
    int CredentialBlobLength,
    IMemoryOwner<byte> Secret,
    int SecretLength): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_ActivateCredential()</c>: a single <c>TPM2B_DIGEST</c> <c>certInfo</c> — the
/// recovered credential secret (TPM 2.0 Library Part 3, clause 12.5). Recovering it proves the activate object and
/// the credential key co-reside in one TPM.
/// </summary>
/// <remarks>
/// <see cref="CertInfo"/> is a pooled buffer holding the recovered secret; it is confidential, so
/// <see cref="TpmSimulator"/> zeroes it before disposing it, as the terminal owner. The activate-object-authorizing
/// and credential-key sessions are empty-auth password sessions, so the response carries no session area and is
/// framed with the no-sessions tag.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="CertInfo">The pooled buffer holding the recovered credential secret; zeroed and disposed after framing.</param>
/// <param name="CertInfoLength">The number of valid octets in <paramref name="CertInfo"/>.</param>
public sealed record TpmActivateCredentialResponse(
    TpmRcConstants ResponseCode,
    IMemoryOwner<byte> CertInfo,
    int CertInfoLength): TpmResponseIntent(ResponseCode);
