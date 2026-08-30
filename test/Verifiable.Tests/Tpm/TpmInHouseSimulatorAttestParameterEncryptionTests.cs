using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives session-based parameter encryption on the attest family — <c>TPM2_Certify()</c>,
/// <c>TPM2_CertifyCreation()</c>, <c>TPM2_Quote()</c>, <c>TPM2_GetTime()</c>, and <c>TPM2_NV_Certify()</c> —
/// against the in-house behavioural <see cref="TpmSimulator"/>, in both directions: the <c>decrypt</c> attribute
/// protecting <c>qualifyingData</c> on the way in and the <c>encrypt</c> attribute protecting the
/// <c>TPM2B_ATTEST</c> on the way out (TPM 2.0 Library Part 1, clause 18.1; the per-command tables are Part 3,
/// clauses 18.2, 18.3, 18.4, 18.7, and 31.16).
/// </summary>
/// <remarks>
/// <para>
/// Every round trip runs through the production path — <see cref="TpmCommandExecutor"/>, the real command inputs,
/// the real <see cref="TpmSession"/>, and the real response codecs — so what is proven is that the two sides
/// agree, not that one side is self-consistent. The observable that carries the proof is the attestation itself:
/// <c>extraData</c> echoes <c>qualifyingData</c> (Part 2, clause 10.11.12, Table 154), so a request keystream mismatch shows
/// up as an attestation signed over different octets, and a response keystream mismatch shows up as a
/// <c>TPM2B_ATTEST</c> that does not parse into the value the caller sent.
/// </para>
/// <para>
/// The tests that reach a rule the executor's own admissibility guard would pre-empt plant their session bytes on
/// the WIRE instead, through a rewriting device: Part 3, clause 5.5's session-area consistency checks run
/// strictly before clause 5.6's authorization, so a slot planted with an arbitrary <c>hmac</c> is still refused
/// for the area rule under test.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorAttestParameterEncryptionTests
{
    /// <summary>The hash algorithm every session in this file negotiates unless a test names another.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The PCR bank <c>TPM2_Quote()</c> attests over.</summary>
    private const TpmAlgIdConstants PcrBank = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The command header's fixed width: tag (UINT16), commandSize (UINT32), commandCode (UINT32).</summary>
    private const int HeaderSize = 10;

    /// <summary>The NV Index <c>TPM2_NV_Certify()</c> attests over here.</summary>
    private const uint NvIndexHandle = 0x0100_0021;

    /// <summary>Index attributes that authorize read and write with the Index's own authValue.</summary>
    private const TpmaNv IndexAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>The PCR indices <c>TPM2_Quote()</c> attests over.</summary>
    private static int[] PcrIndices { get; } = [0, 7];

    /// <summary>
    /// The <c>qualifyingData</c> every round trip supplies. Its whole job is to be recognisable: it is what the
    /// attestation's <c>extraData</c> must echo back, and what must NOT appear anywhere in the command bytes once
    /// a decrypt session protects it.
    /// </summary>
    private static byte[] Nonce { get; } = "Attest parameter confidentiality"u8.ToArray();

    /// <summary>The attestation key's own authorization password, non-empty so the cipher key's authValue term is observable.</summary>
    private const string SignerPassword = "signer-authValue";

    /// <summary>The octets <see cref="SignerPassword"/> becomes on the wire, which is what a session folds into its keys.</summary>
    private static byte[] SignerAuth { get; } = System.Text.Encoding.UTF8.GetBytes(SignerPassword);

    /// <summary>An authorization value that is not the signer's, for the wrong-cipher-key negative.</summary>
    private static byte[] WrongSignerAuth { get; } = [0x21, 0x22, 0x23, 0x24, 0x25, 0x26];

    /// <summary>The NV Index's own authorization value.</summary>
    private static byte[] IndexAuth { get; } = [0x0A, 0x0B, 0x0C, 0x0D];

    /// <summary>The octets written into the NV Index and certified back out of it.</summary>
    private static byte[] WrittenData { get; } = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// <c>TPM2_Quote()</c>'s <c>qualifyingData</c> survives XOR obfuscation intact: the attestation's
    /// <c>extraData</c> echoes exactly the octets the caller supplied, which it can only do if the simulator
    /// derived the same keystream over the same nonce order the host encrypted with (TPM 2.0 Library Part 1,
    /// clauses 19.1 and 19.2; the parameter is the first command parameter and a TPM2B, Part 3, clause 18.4,
    /// Table 101).
    /// </summary>
    [TestMethod]
    public async Task QuoteWithXorEncryptedQualifyingDataEchoesItIntoTheAttestation()
    {
        await RunQuoteAsync(TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT).ConfigureAwait(false);
    }

    /// <summary>
    /// The AES-CFB half of <see cref="QuoteWithXorEncryptedQualifyingDataEchoesItIntoTheAttestation"/>: CFB mode
    /// is the platform-specific alternative to the mandatory XOR obfuscation (TPM 2.0 Library Part 1, clause
    /// 19.3), keyed and IV'd from the same KDFa output.
    /// </summary>
    [TestMethod]
    public async Task QuoteWithAesCfbEncryptedQualifyingDataEchoesItIntoTheAttestation()
    {
        await RunQuoteAsync(TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_Quote()</c>'s <c>TPM2B_ATTEST</c> survives XOR obfuscation in the response direction: the caller
    /// recovers an attestation that parses and echoes its own nonce, which it can only do if the simulator
    /// encrypted with the response nonce order — nonceNewer the freshly rolled nonceTPM, nonceOlder the command
    /// caller nonce (TPM 2.0 Library Part 1, clause 18.2) — and did so BEFORE rpHash (clause 18.1), so the
    /// response HMAC covers the ciphertext.
    /// </summary>
    [TestMethod]
    public async Task QuoteWithXorEncryptedAttestationDecryptsToAParsableAttestation()
    {
        await RunQuoteAsync(TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT).ConfigureAwait(false);
    }

    /// <summary>The AES-CFB half of <see cref="QuoteWithXorEncryptedAttestationDecryptsToAParsableAttestation"/> (TPM 2.0 Library Part 1, clause 18.3).</summary>
    [TestMethod]
    public async Task QuoteWithAesCfbEncryptedAttestationDecryptsToAParsableAttestation()
    {
        await RunQuoteAsync(TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT).ConfigureAwait(false);
    }

    /// <summary>
    /// One session carries BOTH attributes on the same command: "The attributes can be SET in different sessions
    /// or in the same session" (TPM 2.0 Library Part 1, clause 18.1). Both directions are keyed from the same
    /// <c>sessionValue</c> and differ only in nonce order, so a single session doing both jobs is the tightest
    /// check that the two orders are not accidentally the same.
    /// </summary>
    [TestMethod]
    public async Task QuoteWithOneSessionSettingBothDecryptAndEncryptRoundTripsBothDirections()
    {
        await RunQuoteAsync(
            TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB),
            TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT | TpmaSession.ENCRYPT).ConfigureAwait(false);
    }

    /// <summary>
    /// A companion negotiating SHA-384 alongside a SHA-256 authorization area succeeds end to end: cpHash and
    /// rpHash are computed per session under that session's OWN hash algorithm (TPM 2.0 Library Part 1, clause
    /// 16.7 equation 15 and clause 15.8 equation 16), and the companion's keystream is derived under its own
    /// algorithm too (clauses 18.2 and 18.3).
    /// </summary>
    [TestMethod]
    public async Task QuoteWithASha384CompanionSucceedsEndToEnd()
    {
        await RunQuoteAsync(
            TpmtSymDef.Xor(TpmAlgIdConstants.TPM_ALG_SHA384),
            TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT | TpmaSession.ENCRYPT,
            companionAlg: TpmAlgIdConstants.TPM_ALG_SHA384).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_Certify()</c>'s <c>qualifyingData</c> round-trips over a decrypt companion (TPM 2.0 Library Part
    /// 3, clause 18.2, Table 97: the first command parameter and a TPM2B).
    /// </summary>
    [TestMethod]
    public async Task CertifyWithXorEncryptedQualifyingDataEchoesItIntoTheAttestation()
    {
        await RunCertifyAsync(TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT).ConfigureAwait(false);
    }

    /// <summary>The AES-CFB half of <see cref="CertifyWithXorEncryptedQualifyingDataEchoesItIntoTheAttestation"/> (TPM 2.0 Library Part 1, clause 18.3).</summary>
    [TestMethod]
    public async Task CertifyWithAesCfbEncryptedQualifyingDataEchoesItIntoTheAttestation()
    {
        await RunCertifyAsync(TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_Certify()</c>'s <c>certifyInfo</c> round-trips over an encrypt companion (TPM 2.0 Library Part 3,
    /// clause 18.2, Table 98: the first response parameter and a TPM2B).
    /// </summary>
    [TestMethod]
    public async Task CertifyWithXorEncryptedAttestationDecryptsToAParsableAttestation()
    {
        await RunCertifyAsync(TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT).ConfigureAwait(false);
    }

    /// <summary>The AES-CFB half of <see cref="CertifyWithXorEncryptedAttestationDecryptsToAParsableAttestation"/> (TPM 2.0 Library Part 1, clause 18.3).</summary>
    [TestMethod]
    public async Task CertifyWithAesCfbEncryptedAttestationDecryptsToAParsableAttestation()
    {
        await RunCertifyAsync(TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_CertifyCreation()</c>'s <c>qualifyingData</c> round-trips over a decrypt companion. Its
    /// <c>creationHash</c> and <c>creationTicket</c> sit BEHIND the first parameter and so are never protected
    /// (TPM 2.0 Library Part 1, clause 18.1: "only the first parameter ... can be encrypted"); the ticket still
    /// re-verifies, which proves those trailing parameters were parsed from the same octets the caller sent.
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationWithXorEncryptedQualifyingDataEchoesItIntoTheAttestation()
    {
        await RunCertifyCreationAsync(TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT).ConfigureAwait(false);
    }

    /// <summary>The AES-CFB half of <see cref="CertifyCreationWithXorEncryptedQualifyingDataEchoesItIntoTheAttestation"/> (TPM 2.0 Library Part 1, clause 18.3).</summary>
    [TestMethod]
    public async Task CertifyCreationWithAesCfbEncryptedQualifyingDataEchoesItIntoTheAttestation()
    {
        await RunCertifyCreationAsync(TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_CertifyCreation()</c>'s <c>certifyInfo</c> round-trips over an encrypt companion (TPM 2.0 Library
    /// Part 3, clause 18.3, Table 100).
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationWithXorEncryptedAttestationDecryptsToAParsableAttestation()
    {
        await RunCertifyCreationAsync(TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT).ConfigureAwait(false);
    }

    /// <summary>The AES-CFB half of <see cref="CertifyCreationWithXorEncryptedAttestationDecryptsToAParsableAttestation"/> (TPM 2.0 Library Part 1, clause 18.3).</summary>
    [TestMethod]
    public async Task CertifyCreationWithAesCfbEncryptedAttestationDecryptsToAParsableAttestation()
    {
        await RunCertifyCreationAsync(TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_GetTime()</c>'s <c>qualifyingData</c> round-trips over a decrypt companion (TPM 2.0 Library Part
    /// 3, clause 18.7, Table 107), with the companion at index 2 behind the two authorizing slots
    /// <c>@privacyAdminHandle</c> and <c>@signHandle</c>.
    /// </summary>
    [TestMethod]
    public async Task GetTimeWithXorEncryptedQualifyingDataEchoesItIntoTheAttestation()
    {
        await RunGetTimeAsync(TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT).ConfigureAwait(false);
    }

    /// <summary>The AES-CFB half of <see cref="GetTimeWithXorEncryptedQualifyingDataEchoesItIntoTheAttestation"/> (TPM 2.0 Library Part 1, clause 18.3).</summary>
    [TestMethod]
    public async Task GetTimeWithAesCfbEncryptedQualifyingDataEchoesItIntoTheAttestation()
    {
        await RunGetTimeAsync(TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_GetTime()</c>'s <c>timeInfo</c> round-trips over an encrypt companion (TPM 2.0 Library Part 3,
    /// clause 18.7, Table 108).
    /// </summary>
    [TestMethod]
    public async Task GetTimeWithXorEncryptedAttestationDecryptsToAParsableAttestation()
    {
        await RunGetTimeAsync(TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT).ConfigureAwait(false);
    }

    /// <summary>The AES-CFB half of <see cref="GetTimeWithXorEncryptedAttestationDecryptsToAParsableAttestation"/> (TPM 2.0 Library Part 1, clause 18.3).</summary>
    [TestMethod]
    public async Task GetTimeWithAesCfbEncryptedAttestationDecryptsToAParsableAttestation()
    {
        await RunGetTimeAsync(TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_NV_Certify()</c>'s <c>qualifyingData</c> round-trips over a decrypt companion sitting at index 2
    /// (TPM 2.0 Library Part 3, clause 31.16.2, Table 271): this is the command with two authorizing slots AND a
    /// third handle that carries no authorization, so it is the one that exercises a companion at the last
    /// position Table 9 allows.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyWithXorEncryptedQualifyingDataEchoesItIntoTheAttestation()
    {
        await RunNvCertifyAsync(TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT).ConfigureAwait(false);
    }

    /// <summary>The AES-CFB half of <see cref="NvCertifyWithXorEncryptedQualifyingDataEchoesItIntoTheAttestation"/> (TPM 2.0 Library Part 1, clause 18.3).</summary>
    [TestMethod]
    public async Task NvCertifyWithAesCfbEncryptedQualifyingDataEchoesItIntoTheAttestation()
    {
        await RunNvCertifyAsync(TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_NV_Certify()</c>'s <c>certifyInfo</c> round-trips over an encrypt companion at index 2 (TPM 2.0
    /// Library Part 3, clause 31.16.2, Table 272).
    /// </summary>
    [TestMethod]
    public async Task NvCertifyWithXorEncryptedAttestationDecryptsToAParsableAttestation()
    {
        await RunNvCertifyAsync(TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT).ConfigureAwait(false);
    }

    /// <summary>The AES-CFB half of <see cref="NvCertifyWithXorEncryptedAttestationDecryptsToAParsableAttestation"/> (TPM 2.0 Library Part 1, clause 18.3).</summary>
    [TestMethod]
    public async Task NvCertifyWithAesCfbEncryptedAttestationDecryptsToAParsableAttestation()
    {
        await RunNvCertifyAsync(TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT).ConfigureAwait(false);
    }

    /// <summary>
    /// A <c>TPM2_NV_Certify()</c> companion at index 2 carrying BOTH attributes protects the command parameter
    /// and the response parameter in one command — the last position Table 12 admits, doing both jobs (TPM 2.0
    /// Library Part 1, clauses 15.6.1 and 18.1).
    /// </summary>
    [TestMethod]
    public async Task NvCertifyWithACompanionAtIndexTwoRoundTripsBothDirections()
    {
        await RunNvCertifyAsync(
            TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB),
            TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT | TpmaSession.ENCRYPT).ConfigureAwait(false);
    }

    /// <summary>
    /// An EMPTY <c>qualifyingData</c> over a decrypt session succeeds: "The size of the parameter to be encrypted
    /// can be zero" (TPM 2.0 Library Part 3, clause 5.7). Nothing is transformed, but the parameter's framing and
    /// the whole decrypt step still run, so this is the boundary the size arithmetic has to survive.
    /// </summary>
    [TestMethod]
    public async Task QuoteWithEmptyQualifyingDataOverADecryptSessionSucceeds()
    {
        await RunQuoteAsync(
            TpmtSymDef.Xor(HmacSessionAlg),
            TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT,
            qualifyingData: ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
    }

    /// <summary>
    /// Two DIFFERENT sessions carry the two attributes on one command, and neither is the first session, so the
    /// first session's command HMAC folds BOTH their nonceTPMs — the decrypt session's, then the encrypt
    /// session's, each exactly once (TPM 2.0 Library Part 1, clause 16.6.3.4 and clause 16.6.5's equation 17:
    /// "If different sessions are used for decrypt and encrypt, both nonceTPMs are included"). Driven on
    /// <c>TPM2_Certify()</c>, whose two authorizing slots plus a companion fill the three blocks clause 15.6.1
    /// allows: the object slot at index 0 folds, the sign slot at index 1 decrypts, and the companion at index 2
    /// encrypts. A success is the only outcome consistent with the host and the simulator concatenating those two
    /// terms in the same order.
    /// </summary>
    [TestMethod]
    public async Task CertifyWithDecryptAndEncryptOnDifferentSessionsFoldsBothNoncesIntoTheFirstSession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, password: null).ConfigureAwait(false);
        (uint objectHandle, TpmSession objectSession) = await StartBoundSessionAsync(
            tpm, registry, pool, subject.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Null, HmacSessionAlg).ConfigureAwait(false);
        (uint signHandle, TpmSession signSession) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), HmacSessionAlg).ConfigureAwait(false);

        try
        {
            using(objectSession)
            using(signSession)
            using(companion)
            {
                signSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                using CertifyInput input = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

                TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                    tpm, input, [objectSession, signSession, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"A three-slot area whose decrypt and encrypt ride different non-first sessions must attest: '{result.ResponseCode}'.");

                using CertifyResponse certify = result.Value;
                AssertAttestationEchoes(certify.CertifyInfo, Nonce);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, companionHandle).ConfigureAwait(false);
            await FlushAsync(tpm, registry, pool, signHandle).ConfigureAwait(false);
            await FlushAsync(tpm, registry, pool, objectHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The <c>decrypt</c> attribute riding the AUTHORIZING sign session folds that session's authorized entity's
    /// authValue into the cipher key: "If a session is also being used for authorization, sessionValue ... is
    /// sessionKey ‖ authValue" (TPM 2.0 Library Part 1, clause 18.1). The signing key here carries a NON-EMPTY
    /// authValue, so the term is observable — with it dropped on either side the recovered <c>qualifyingData</c>
    /// would be garbage and <c>extraData</c> would not echo.
    /// </summary>
    [TestMethod]
    public async Task CertifyWithDecryptOnTheAuthorizingSignSessionFoldsTheSignerAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, SignerPassword).ConfigureAwait(false);

        //Unbound so no bind omission can hide the term: the sign session's key folds the signer's authValue into
        //BOTH its HMAC and its cipher, and the two sides must agree on both.
        (uint signHandle, TpmSession signSession) = await StartUnboundSessionAsync(
            tpm, registry, pool, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg).ConfigureAwait(false);

        try
        {
            using(signSession)
            {
                signSession.SetAuthValue(SignerAuth, pool);
                signSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT | TpmaSession.ENCRYPT;

                using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
                using CertifyInput input = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

                TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                    tpm, input, [objectAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"An authorizing session carrying decrypt and encrypt must attest: '{result.ResponseCode}'.");

                using CertifyResponse certify = result.Value;
                AssertAttestationEchoes(certify.CertifyInfo, Nonce);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, signHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The other half of the <c>sessionValue</c> rule: a companion authorizes no entity, so its
    /// <c>sessionValue</c> is its session key ALONE (TPM 2.0 Library Part 1, clause 18.1: "If the session is not
    /// being used for authorization, sessionValue is sessionKey"). The signing key still carries a non-empty
    /// authValue, and the round trip succeeds without it being folded anywhere — which is what separates this
    /// case from <see cref="CertifyWithDecryptOnTheAuthorizingSignSessionFoldsTheSignerAuthValue"/>.
    /// </summary>
    [TestMethod]
    public async Task CertifyWithDecryptOnASeparateCompanionUsesTheSessionKeyAlone()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, SignerPassword).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await StartBoundSessionAsync(
            tpm, registry, pool, subject.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg).ConfigureAwait(false);

        try
        {
            using(companion)
            {
                companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT | TpmaSession.ENCRYPT;

                using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession signAuth = TpmPasswordSession.Create(SignerAuth, pool);
                using CertifyInput input = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

                TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                    tpm, input, [objectAuth, signAuth, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"A companion carrying both attributes must attest with its session key alone: '{result.ResponseCode}'.");

                using CertifyResponse certify = result.Value;
                AssertAttestationEchoes(certify.CertifyInfo, Nonce);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, companionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A session BOUND to the very entity it authorizes still folds that entity's authValue into the CIPHER key,
    /// even though its authorization HMAC omits it: "The binding of the session is ignored" (TPM 2.0 Library
    /// Part 1, clause 18.1), against clause 16.6.10's equation 22, which drops the term from the HMAC key. The
    /// two keys therefore differ for one and the same session, and only a design that keeps them apart can make
    /// this command both authorize and decrypt correctly.
    /// </summary>
    [TestMethod]
    public async Task QuoteOverASessionBoundToTheSignerFoldsTheSignerAuthValueIntoTheCipherKey()
    {
        (bool isSuccess, byte[] extraData) = await QuoteOverBoundSignerSessionAsync(SignerAuth).ConfigureAwait(false);

        Assert.IsTrue(isSuccess, "A session bound to the signer it authorizes must attest.");
        Assert.IsTrue(
            extraData.AsSpan().SequenceEqual(Nonce),
            "extraData must echo the caller's qualifyingData, which it can only do if the cipher key folded the signer's authValue while the HMAC key omitted it.");
    }

    /// <summary>
    /// The honest malleability negative (TPM 2.0 Library Part 1, clause 18.1: the two schemes "are, by
    /// themselves, malleable ... mitigated by the HMAC authorization session verification"): a caller whose
    /// cipher key is wrong but whose cpHash covers exactly the ciphertext it transmitted passes every HMAC check,
    /// so the command SUCCEEDS and the attestation is signed over garbage <c>extraData</c>. The wrong key is
    /// reached honestly — the same bound session as
    /// <see cref="QuoteOverASessionBoundToTheSignerFoldsTheSignerAuthValueIntoTheCipherKey"/>, told to fold a
    /// value that is not the signer's — because the bind omission keeps the HMAC key correct while the cipher key
    /// diverges. The TPM has no way to detect this; that is the property being pinned, not a defect.
    /// </summary>
    [TestMethod]
    public async Task QuoteOverABoundSessionWithAWrongCipherAuthValueIsSignedOverGarbageQualifyingData()
    {
        (bool isSuccess, byte[] extraData) = await QuoteOverBoundSignerSessionAsync(WrongSignerAuth).ConfigureAwait(false);

        Assert.IsTrue(isSuccess, "A wrong decryption key is undetectable, so the command must still succeed.");
        Assert.HasCount(
            Nonce.Length, extraData,
            "XOR obfuscation and CFB preserve length, so the attested extraData is exactly as wide as the plaintext the caller meant to send.");
        Assert.IsFalse(
            extraData.AsSpan().SequenceEqual(Nonce),
            "The attestation is signed over what decryption produced, so a wrong cipher key must leave extraData different from the intended nonce.");
    }

    /// <summary>
    /// Removing the decrypt companion from the wire breaks the FIRST session's command HMAC: "To prevent removal
    /// of extra encrypting sessions, the nonceTPM of each of these sessions is included in the HMAC computation
    /// of the first authorization session of a command" (TPM 2.0 Library Part 1, clause 16.6.3.4). The identical
    /// command with the companion left in place succeeds, so the failure is the fold and nothing else.
    /// </summary>
    [TestMethod]
    public async Task StrippingTheDecryptCompanionFromTheWireBreaksTheSignSlotHmac()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        (uint signHandle, TpmSession signSession) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Null, HmacSessionAlg).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg).ConfigureAwait(false);

        try
        {
            using(signSession)
            using(companion)
            {
                companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using TpmDevice strippingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_Quote, command => WithoutLastSession(command, handleCount: 1));
                using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
                using QuoteInput input = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
                ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

                TpmResult<QuoteResponse> stripped = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                    strippingDevice, input, [signSession, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                if(stripped.IsSuccess)
                {
                    stripped.Value.Dispose();
                }

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), stripped.ResponseCode,
                    "The sign slot's HMAC covers the removed companion's nonceTPM, so the area without it must fail at slot 0.");

                using TpmlPcrSelection intactSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
                using QuoteInput intactInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, intactSelection, pool);
                TpmResult<QuoteResponse> intact = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                    tpm, intactInput, [signSession, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(intact.IsSuccess, $"The identical command with the companion left in place must succeed: '{intact.ResponseCode}'.");
                intact.Value.Dispose();
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, companionHandle).ConfigureAwait(false);
            await FlushAsync(tpm, registry, pool, signHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A SECOND session claiming <c>decrypt</c> is refused with <c>TPM_RC_ATTRIBUTES</c> encoded to the
    /// RE-CLAIMING slot: "the decrypt attribute can only be SET in one session per command" (TPM 2.0 Library Part
    /// 1, clause 18.1; Part 3, clause 5.5's step 4.1.2), blamed on the offending entry (Part 2, clause 6.6.2).
    /// The second claim is planted on the wire because the host executor refuses to frame such a command at all,
    /// and the area is otherwise entirely well formed, so the refusal can be about nothing else.
    /// </summary>
    [TestMethod]
    public async Task TwoDecryptClaimingSessionsOnCertifyAreRefusedAtTheSecondClaimer()
    {
        TpmRcConstants responseCode = await CertifyWithPlantedSecondClaimAsync(TpmaSession.DECRYPT).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 2), responseCode,
            "A second decrypt claimer is refused at its own index, never at the slot that claimed the attribute first.");
    }

    /// <summary>
    /// The <c>encrypt</c> half of <see cref="TwoDecryptClaimingSessionsOnCertifyAreRefusedAtTheSecondClaimer"/>:
    /// "The encrypt attribute can only be SET in one session that is used in a command" (TPM 2.0 Library Part 1,
    /// clause 18.1).
    /// </summary>
    [TestMethod]
    public async Task TwoEncryptClaimingSessionsOnCertifyAreRefusedAtTheSecondClaimer()
    {
        TpmRcConstants responseCode = await CertifyWithPlantedSecondClaimAsync(TpmaSession.ENCRYPT).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 2), responseCode,
            "A second encrypt claimer is refused at its own index, never at the slot that claimed the attribute first.");
    }

    /// <summary>
    /// A <c>qualifyingData</c> whose declared size overruns the parameter area is refused rather than decrypted:
    /// the first parameter's framing is what locates every parameter behind it, so a frame that cannot be walked
    /// is malformed (<c>TPM_RC_INSUFFICIENT</c>, TPM 2.0 Library Part 3, clause 5.2) before any session work
    /// happens. The decryption step keeps the same two size arms the reference's own decryption routine names
    /// (<c>TPM_RC_INSUFFICIENT</c> for a buffer shorter than the size field, <c>TPM_RC_SIZE</c> for a declared
    /// size overrunning the area) as the layer behind this one.
    /// </summary>
    [TestMethod]
    public async Task QualifyingDataSizeFieldOverrunningTheParameterAreaIsRefused()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg).ConfigureAwait(false);

        try
        {
            using(companion)
            {
                companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using TpmDevice corruptingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_Quote, OverstateFirstParameterSize);
                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
                using QuoteInput input = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
                ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

                TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                    corruptingDevice, input, [signAuth, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                if(result.IsSuccess)
                {
                    result.Value.Dispose();
                }

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_INSUFFICIENT, result.ResponseCode,
                    "A first-parameter size field wider than the parameter area leaves the frame unwalkable, which is TPM_RC_INSUFFICIENT.");
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, companionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>qualifyingData</c> protected by a decrypt session never appears on the wire in the clear: the
    /// parameter's plaintext octets are absent from the command bytes as a contiguous sequence, while the same
    /// command without the attribute carries them verbatim. The pair is what makes the assertion non-vacuous
    /// (TPM 2.0 Library Part 1, clause 18.1).
    /// </summary>
    [TestMethod]
    public async Task QuoteOverADecryptSessionKeepsTheQualifyingDataOffTheWire()
    {
        (byte[] protectedCommand, byte[] plainCommand) = await CaptureQuoteCommandsAsync(TpmaSession.DECRYPT).ConfigureAwait(false);

        Assert.IsTrue(
            ContainsSubsequence(plainCommand, Nonce),
            "Without the decrypt attribute the qualifyingData crosses in the clear, which is what makes the check below meaningful.");
        Assert.IsFalse(
            ContainsSubsequence(protectedCommand, Nonce),
            "A decrypt session protects the first command parameter, so its plaintext must not appear in the command bytes.");
    }

    /// <summary>
    /// A <c>TPM2B_ATTEST</c> protected by an encrypt session never appears on the wire in the clear: the
    /// attestation structure's <c>TPM_GENERATED_VALUE</c> magic — the fixed four octets every genuine attestation
    /// starts with (TPM 2.0 Library Part 2, clause 6.2, Table 7 for the constant; clause 10.11.12, Table 154 for
    /// the <c>magic</c> field it opens <c>TPMS_ATTEST</c> with) — is absent from the response bytes, while the same
    /// command without the attribute carries it. The magic is the right probe precisely because it is
    /// caller-independent: it is present in every unprotected attestation and in none that is encrypted.
    /// </summary>
    [TestMethod]
    public async Task QuoteOverAnEncryptSessionKeepsTheAttestationOffTheWire()
    {
        byte[] magic = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(magic, TpmConstants32.TPM_GENERATED_VALUE);

        (byte[] protectedResponse, byte[] plainResponse) = await CaptureQuoteResponsesAsync(TpmaSession.ENCRYPT).ConfigureAwait(false);

        Assert.IsTrue(
            ContainsSubsequence(plainResponse, magic),
            "Without the encrypt attribute the attestation crosses in the clear, so its magic is present — which is what makes the check below meaningful.");
        Assert.IsFalse(
            ContainsSubsequence(protectedResponse, magic),
            "An encrypt session protects the first response parameter, so the attestation's magic must not appear in the response bytes.");
    }

    /// <summary>
    /// Both a refused and a successful encrypted attest round trip return every rented carrier to the pool: the
    /// companion slot's parse-rented <c>nonceCaller</c> and <c>hmac</c>, and the pooled carrier the decryption
    /// step rents for the recovered <c>qualifyingData</c>, which exists only on this path.
    /// </summary>
    [TestMethod]
    public async Task EncryptedAttestRoundTripsReturnEveryRentedCarrierToThePool()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg).ConfigureAwait(false);

        long baseline;

        try
        {
            using(companion)
            {
                companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT | TpmaSession.ENCRYPT;
                baseline = trackingPool.OutstandingCount;

                //A refusal that happens after the request record was built and its carriers rented: the signing
                //key handle is unknown, so the arm rejects and releases through the record's own Dispose. Each
                //round trip lives in its own scope so nothing it rented is still held when the balance is read.
                {
                    using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                    using TpmlPcrSelection missingSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
                    using QuoteInput missingInput = QuoteInput.ForEcdsa(
                        TpmiDhObject.FromValue(ak.ObjectHandle.Value + 1), Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, missingSelection, pool);
                    ReadOnlyMemory<byte>[] missingNames = [ak.Name.Span.ToArray()];

                    TpmResult<QuoteResponse> refused = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                        tpm, missingInput, [signAuth, companion], missingNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    if(refused.IsSuccess)
                    {
                        refused.Value.Dispose();
                    }

                    Assert.AreEqual(
                        TpmRcConstants.TPM_RC_HANDLE, refused.ResponseCode,
                        "The balance below proves nothing unless the refused command really was refused.");
                }

                {
                    using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                    using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
                    using QuoteInput input = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
                    ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

                    TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                        tpm, input, [signAuth, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(result.IsSuccess, $"The successful round trip must attest: '{result.ResponseCode}'.");

                    using QuoteResponse quote = result.Value;
                    AssertAttestationEchoes(quote.Quoted, Nonce);
                }

                //Measured while the companion session is still alive, so the only rentals the delta can cover are
                //the ones the two commands made: the slot's parse-rented nonce and hmac carriers, and the pooled
                //carrier the decryption step rents for the recovered qualifyingData.
                Assert.AreEqual(
                    baseline, trackingPool.OutstandingCount,
                    "A refused and a successful encrypted attest round trip must both return every rented carrier to the pool.");
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, companionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_Quote()</c> area fills all three blocks an authorization area may hold — the authorizing sign
    /// session, then a companion that decrypts and a companion that encrypts — and both directions survive at
    /// once. An area carries "at least one but no more than three" blocks and Table 12 marks positions 2 and 3
    /// alike as an encryption, decryption, or audit session (TPM 2.0 Library Part 1, clause 15.6.1), and
    /// <c>TPM2_Quote()</c> authorizes a single handle, so both later positions are open to it. The sign slot's
    /// command HMAC folds BOTH companions' nonceTPMs, the decrypt session's first and the encrypt session's second
    /// (clause 16.6.3.4 and clause 16.6.5's equation 17), so a success is only possible if host and simulator lay
    /// those two terms end to end in the same order across a three-block area — and the attestation that comes
    /// back must still echo the caller's <c>qualifyingData</c> and parse as a quote.
    /// </summary>
    [TestMethod]
    public async Task QuoteWithTwoCompanionsOneDecryptingOneEncryptingRoundTripsBothDirections()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        (uint signHandle, TpmSession signSession) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Null, HmacSessionAlg).ConfigureAwait(false);
        (uint decryptHandle, TpmSession decryptCompanion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptCompanion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), HmacSessionAlg).ConfigureAwait(false);

        try
        {
            using(signSession)
            using(decryptCompanion)
            using(encryptCompanion)
            {
                decryptCompanion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                encryptCompanion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
                using QuoteInput input = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
                ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

                TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                    tpm, input, [signSession, decryptCompanion, encryptCompanion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"A sign session with two companions, one decrypting and one encrypting, must attest: '{result.ResponseCode}'.");

                using QuoteResponse quote = result.Value;
                AssertAttestationEchoes(quote.Quoted, Nonce);
                Assert.AreEqual(
                    TpmStConstants.TPM_ST_ATTEST_QUOTE, quote.Quoted.AttestationData.Type,
                    "The TPM2B_ATTEST recovered through the encrypt companion must parse as a quote, which a garbled keystream would not allow.");
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, encryptHandle).ConfigureAwait(false);
            await FlushAsync(tpm, registry, pool, decryptHandle).ConfigureAwait(false);
            await FlushAsync(tpm, registry, pool, signHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The once-per-command rule survives the third block: with two companions present, a <c>decrypt</c> claim
    /// planted onto the one at index 2 — the slot at index 1 having claimed it already — is refused with
    /// <c>TPM_RC_ATTRIBUTES</c> encoded to the RE-CLAIMING slot ("the decrypt attribute can only be SET in one
    /// session per command", TPM 2.0 Library Part 1, clause 18.1; blamed on the offending entry, Part 2, clause
    /// 6.6.2). The claim is planted on the wire because the host executor refuses to frame such a command at all,
    /// and the area is otherwise entirely well formed, so the refusal can be about nothing else.
    /// </summary>
    [TestMethod]
    public async Task QuoteWithTwoCompanionsBothClaimingDecryptIsRefusedAtTheSecondClaimer()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        (uint decryptHandle, TpmSession decryptCompanion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptCompanion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg).ConfigureAwait(false);

        try
        {
            using(decryptCompanion)
            using(encryptCompanion)
            {
                //The framed command is entirely legal — one decrypt companion and one encrypt companion — and only
                //the wire rewrite makes the slot at index 2 claim what the slot at index 1 already took.
                decryptCompanion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                encryptCompanion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                using TpmDevice plantingDevice = CreateRewritingDevice(
                    simulator, TpmCcConstants.TPM_CC_Quote,
                    command => SetSessionAttributeBit(command, handleCount: 1, sessionIndex: 2, TpmaSession.DECRYPT));
                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
                using QuoteInput input = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
                ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

                TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                    plantingDevice, input, [signAuth, decryptCompanion, encryptCompanion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                if(result.IsSuccess)
                {
                    result.Value.Dispose();
                }

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 2), result.ResponseCode,
                    "The third block is blamed for re-claiming what the second block took, never the other way round.");
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, encryptHandle).ConfigureAwait(false);
            await FlushAsync(tpm, registry, pool, decryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The three-block bound is the bound: an authorization area holds "at least one but no more than three"
    /// blocks (TPM 2.0 Library Part 1, clause 15.6.1), so a <c>TPM2_Quote()</c> area carrying a FOURTH one leaves
    /// octets that no slot accounts for against the declared <c>authorizationSize</c> — a bare
    /// <c>TPM_RC_AUTHSIZE</c> naming no slot, because the surplus belongs to the area rather than to any session
    /// in it. The fourth block is planted on the wire, the host executor having no way to express it.
    /// </summary>
    [TestMethod]
    public async Task QuoteAreaCarryingAFourthSessionIsRefusedWithAuthSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg).ConfigureAwait(false);

        try
        {
            using(companion)
            {
                byte[] Rewrite(byte[] command)
                {
                    byte[] withThird = WithAppendedSession(command, handleCount: 1, companionHandle, TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT);

                    return WithAppendedSession(withThird, handleCount: 1, companionHandle, TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT);
                }

                companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using TpmDevice rewritingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_Quote, Rewrite);
                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
                using QuoteInput input = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
                ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

                TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                    rewritingDevice, input, [signAuth, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                if(result.IsSuccess)
                {
                    result.Value.Dispose();
                }

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_AUTHSIZE, result.ResponseCode,
                    "A fourth session's octets are surplus against the declared authorizationSize, which is a bare TPM_RC_AUTHSIZE naming no slot.");
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, companionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The <c>TPM2_CertifyCreation()</c> half of
    /// <see cref="QuoteWithTwoCompanionsOneDecryptingOneEncryptingRoundTripsBothDirections"/>: only
    /// <c>@signHandle</c> authorizes this command (TPM 2.0 Library Part 3, clause 18.3, Table 99), so Table 9's
    /// positions 2 and 3 are both free and the area carries a decrypting companion and an encrypting one
    /// alongside the sign session. The re-verified creation ticket rides through unprotected behind the first
    /// parameter, so a success also pins that the parameters after <c>qualifyingData</c> were left alone.
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationWithTwoCompanionsRoundTripsBothDirections()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, password: null).ConfigureAwait(false);
        (uint signHandle, TpmSession signSession) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Null, HmacSessionAlg).ConfigureAwait(false);
        (uint decryptHandle, TpmSession decryptCompanion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptCompanion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), HmacSessionAlg).ConfigureAwait(false);

        try
        {
            using(signSession)
            using(decryptCompanion)
            using(encryptCompanion)
            {
                decryptCompanion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                encryptCompanion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                using CertifyCreationInput input = CertifyCreationInput.ForEcdsa(
                    ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), subject.Name.Span.ToArray()];

                TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                    tpm, input, [signSession, decryptCompanion, encryptCompanion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"A sign session with two companions, one decrypting and one encrypting, must attest: '{result.ResponseCode}'.");

                using CertifyCreationResponse certifyCreation = result.Value;
                AssertAttestationEchoes(certifyCreation.CertifyInfo, Nonce);
                Assert.AreEqual(
                    TpmStConstants.TPM_ST_ATTEST_CREATION, certifyCreation.CertifyInfo.AttestationData.Type,
                    "The TPM2B_ATTEST recovered through the encrypt companion must parse as a creation attestation.");
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, encryptHandle).ConfigureAwait(false);
            await FlushAsync(tpm, registry, pool, decryptHandle).ConfigureAwait(false);
            await FlushAsync(tpm, registry, pool, signHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Both a refused and a successful two-companion round trip return every rented carrier to the pool,
    /// including the ones only the THIRD block makes the parser rent — that slot's own <c>nonceCaller</c>
    /// (<c>TPM2B_NONCE</c>) and <c>hmac</c> (<c>TPM2B_AUTH</c>), each non-empty on the wire. The refusal happens
    /// after the request record was built, so its carriers are reached through the record's own
    /// <c>IDisposable.Dispose</c>, which is the only owner they ever had.
    /// </summary>
    [TestMethod]
    public async Task QuoteWithTwoCompanionsReturnsEverySecondCompanionCarrierToThePool()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        (uint decryptHandle, TpmSession decryptCompanion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptCompanion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), HmacSessionAlg).ConfigureAwait(false);

        long baseline;

        try
        {
            using(decryptCompanion)
            using(encryptCompanion)
            {
                decryptCompanion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                encryptCompanion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                baseline = trackingPool.OutstandingCount;

                //A refusal that happens after the request record was built and all three slots' carriers rented:
                //the signing key handle is unknown, so the arm rejects and releases through the record's own
                //Dispose. Each round trip lives in its own scope so nothing it rented is still held when the
                //balance is read.
                {
                    using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                    using TpmlPcrSelection missingSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
                    using QuoteInput missingInput = QuoteInput.ForEcdsa(
                        TpmiDhObject.FromValue(ak.ObjectHandle.Value + 1), Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, missingSelection, pool);
                    ReadOnlyMemory<byte>[] missingNames = [ak.Name.Span.ToArray()];

                    TpmResult<QuoteResponse> refused = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                        tpm, missingInput, [signAuth, decryptCompanion, encryptCompanion], missingNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    if(refused.IsSuccess)
                    {
                        refused.Value.Dispose();
                    }

                    Assert.AreEqual(
                        TpmRcConstants.TPM_RC_HANDLE, refused.ResponseCode,
                        "The balance below proves nothing unless the refused command really was refused.");
                }

                {
                    using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                    using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
                    using QuoteInput input = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
                    ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

                    TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                        tpm, input, [signAuth, decryptCompanion, encryptCompanion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(result.IsSuccess, $"The successful two-companion round trip must attest: '{result.ResponseCode}'.");

                    using QuoteResponse quote = result.Value;
                    AssertAttestationEchoes(quote.Quoted, Nonce);
                }

                //Measured while both companion sessions are still alive, so the only rentals the delta can cover
                //are the ones the two commands made — among them the third block's own nonce and hmac carriers.
                Assert.AreEqual(
                    baseline, trackingPool.OutstandingCount,
                    "A refused and a successful two-companion round trip must both return every rented carrier to the pool.");
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, encryptHandle).ConfigureAwait(false);
            await FlushAsync(tpm, registry, pool, decryptHandle).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Runs <c>TPM2_Quote()</c> over a <c>TPM_RS_PW</c> sign slot plus one companion carrying
    /// <paramref name="companionAttributes"/>, and asserts the attestation echoes what was sent.
    /// </summary>
    /// <param name="symmetric">The symmetric definition the companion negotiates.</param>
    /// <param name="companionAttributes">The attributes the companion carries.</param>
    /// <param name="companionAlg">The hash algorithm the companion negotiates.</param>
    /// <param name="qualifyingData">The qualifying data to send; <see cref="Nonce"/> when not given.</param>
    private async Task RunQuoteAsync(
        TpmtSymDef symmetric, TpmaSession companionAttributes, TpmAlgIdConstants companionAlg = HmacSessionAlg, ReadOnlyMemory<byte>? qualifyingData = null)
    {
        ReadOnlyMemory<byte> nonce = qualifyingData ?? Nonce;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, symmetric, companionAlg).ConfigureAwait(false);

        try
        {
            using(companion)
            {
                companion.SessionAttributes = companionAttributes;

                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
                using QuoteInput input = QuoteInput.ForEcdsa(ak.ObjectHandle, nonce.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
                ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

                TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                    tpm, input, [signAuth, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_Quote over a '{symmetric.Algorithm}' companion failed: '{result.ResponseCode}'.");

                using QuoteResponse quote = result.Value;
                AssertAttestationEchoes(quote.Quoted, nonce.Span);
                Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_QUOTE, quote.Quoted.AttestationData.Type);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, companionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>Runs <c>TPM2_Certify()</c> over two password slots plus one companion, and asserts the attestation echoes what was sent.</summary>
    /// <param name="symmetric">The symmetric definition the companion negotiates.</param>
    /// <param name="companionAttributes">The attributes the companion carries.</param>
    private async Task RunCertifyAsync(TpmtSymDef symmetric, TpmaSession companionAttributes)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, password: null).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, symmetric, HmacSessionAlg).ConfigureAwait(false);

        try
        {
            using(companion)
            {
                companion.SessionAttributes = companionAttributes;

                using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                using CertifyInput input = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

                TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                    tpm, input, [objectAuth, signAuth, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_Certify over a '{symmetric.Algorithm}' companion failed: '{result.ResponseCode}'.");

                using CertifyResponse certify = result.Value;
                AssertAttestationEchoes(certify.CertifyInfo, Nonce);
                Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_CERTIFY, certify.CertifyInfo.AttestationData.Type);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, companionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>Runs <c>TPM2_CertifyCreation()</c> over a password sign slot plus one companion, and asserts the attestation echoes what was sent.</summary>
    /// <param name="symmetric">The symmetric definition the companion negotiates.</param>
    /// <param name="companionAttributes">The attributes the companion carries.</param>
    private async Task RunCertifyCreationAsync(TpmtSymDef symmetric, TpmaSession companionAttributes)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, password: null).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, symmetric, HmacSessionAlg).ConfigureAwait(false);

        try
        {
            using(companion)
            {
                companion.SessionAttributes = companionAttributes;

                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                using CertifyCreationInput input = CertifyCreationInput.ForEcdsa(
                    ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), subject.Name.Span.ToArray()];

                TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                    tpm, input, [signAuth, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_CertifyCreation over a '{symmetric.Algorithm}' companion failed: '{result.ResponseCode}'.");

                using CertifyCreationResponse certifyCreation = result.Value;
                AssertAttestationEchoes(certifyCreation.CertifyInfo, Nonce);
                Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_CREATION, certifyCreation.CertifyInfo.AttestationData.Type);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, companionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>Runs <c>TPM2_GetTime()</c> over two password slots plus one companion, and asserts the attestation echoes what was sent.</summary>
    /// <param name="symmetric">The symmetric definition the companion negotiates.</param>
    /// <param name="companionAttributes">The attributes the companion carries.</param>
    private async Task RunGetTimeAsync(TpmtSymDef symmetric, TpmaSession companionAttributes)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, password: null).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, symmetric, HmacSessionAlg).ConfigureAwait(false);

        try
        {
            using(companion)
            {
                companion.SessionAttributes = companionAttributes;

                using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                using GetTimeInput input = GetTimeInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), ak.Name.Span.ToArray()];

                TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                    tpm, input, [privacyAdminAuth, signAuth, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_GetTime over a '{symmetric.Algorithm}' companion failed: '{result.ResponseCode}'.");

                using GetTimeResponse getTime = result.Value;
                AssertAttestationEchoes(getTime.TimeInfo, Nonce);
                Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_TIME, getTime.TimeInfo.AttestationData.Type);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, companionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>Runs <c>TPM2_NV_Certify()</c> over two password slots plus one companion at index 2, and asserts the attestation echoes what was sent.</summary>
    /// <param name="symmetric">The symmetric definition the companion negotiates.</param>
    /// <param name="companionAttributes">The attributes the companion carries.</param>
    private async Task RunNvCertifyAsync(TpmtSymDef symmetric, TpmaSession companionAttributes)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, password: null).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, symmetric, HmacSessionAlg).ConfigureAwait(false);

        try
        {
            using(companion)
            {
                companion.SessionAttributes = companionAttributes;

                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
                using NvCertifyInput input = NvCertifyInput.ForEcdsa(
                    ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

                byte[] indexName = await ComputeNvIndexNameAsync(pool).ConfigureAwait(false);
                ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), indexName, indexName];

                TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                    tpm, input, [signAuth, indexAuth, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Certify over a '{symmetric.Algorithm}' companion failed: '{result.ResponseCode}'.");

                using NvCertifyResponse nvCertify = result.Value;
                AssertAttestationEchoes(nvCertify.CertifyInfo, Nonce);
                Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_NV, nvCertify.CertifyInfo.AttestationData.Type);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, companionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Quotes over a single sign session that is BOUND to the signing key it authorizes and carries the
    /// <c>decrypt</c> attribute, folding <paramref name="cipherAuthValue"/> into the cipher key while the bind
    /// omission keeps the authorization HMAC key on the session key alone.
    /// </summary>
    /// <param name="cipherAuthValue">The authValue the host folds into the cipher key — the signer's own, or a wrong one.</param>
    /// <returns>Whether the command succeeded, and the attested <c>extraData</c> when it did.</returns>
    private async Task<(bool IsSuccess, byte[] ExtraData)> QuoteOverBoundSignerSessionAsync(byte[] cipherAuthValue)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, SignerPassword).ConfigureAwait(false);
        (uint sessionHandle, TpmSession signSession) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, SignerAuth, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg, isBoundToAuthorizedEntity: true).ConfigureAwait(false);

        try
        {
            using(signSession)
            {
                signSession.SetAuthValue(cipherAuthValue, pool);
                signSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
                using QuoteInput input = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
                ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

                TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                    tpm, input, [signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                if(!result.IsSuccess)
                {
                    return (false, []);
                }

                using QuoteResponse quote = result.Value;

                return (true, quote.Quoted.AttestationData.ExtraData.Span.ToArray());
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Certifies over a real object session at index 0 carrying <paramref name="attribute"/> and a real companion
    /// at index 2, with the SAME attribute planted onto the companion's octet on the wire, and returns what the
    /// simulator answered.
    /// </summary>
    /// <param name="attribute">The parameter-encryption attribute two slots end up claiming.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> CertifyWithPlantedSecondClaimAsync(TpmaSession attribute)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, password: null).ConfigureAwait(false);
        (uint objectHandle, TpmSession objectSession) = await StartBoundSessionAsync(
            tpm, registry, pool, subject.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg).ConfigureAwait(false);

        try
        {
            using(objectSession)
            using(companion)
            {
                //The command the executor frames is entirely legal — one decrypt session and one encrypt session,
                //in different slots — and only the wire rewrite below makes the companion claim what slot 0
                //already took.
                TpmaSession companionAttribute = attribute == TpmaSession.DECRYPT ? TpmaSession.ENCRYPT : TpmaSession.DECRYPT;
                objectSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | attribute;
                companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | companionAttribute;

                using TpmDevice plantingDevice = CreateRewritingDevice(
                    simulator, TpmCcConstants.TPM_CC_Certify,
                    command => SetSessionAttributeBit(command, handleCount: 2, sessionIndex: 2, attribute));
                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                using CertifyInput input = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

                TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                    plantingDevice, input, [objectSession, signAuth, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                if(result.IsSuccess)
                {
                    result.Value.Dispose();
                }

                return result.ResponseCode;
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, companionHandle).ConfigureAwait(false);
            await FlushAsync(tpm, registry, pool, objectHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Captures the <c>TPM2_Quote()</c> command bytes twice — once with a companion carrying
    /// <paramref name="attribute"/> and once with the same companion carrying nothing — so a confidentiality
    /// claim can be checked against its own control.
    /// </summary>
    /// <param name="attribute">The attribute the protected run's companion carries.</param>
    /// <returns>The protected command bytes and the unprotected ones.</returns>
    private async Task<(byte[] Protected, byte[] Plain)> CaptureQuoteCommandsAsync(TpmaSession attribute)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        byte[]? captured = null;
        using TpmDevice tpm = TpmDevice.Create(async (command, commandPool, cancellationToken) =>
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == TpmCcConstants.TPM_CC_Quote)
            {
                captured = bytes;
            }

            return await simulator.SubmitAsync(command, commandPool, cancellationToken).ConfigureAwait(false);
        });

        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg).ConfigureAwait(false);

        try
        {
            using(companion)
            {
                companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | attribute;
                await QuoteOnceAsync(tpm, registry, pool, ak, companion).ConfigureAwait(false);
                byte[] protectedCommand = captured!;
                captured = null;

                using TpmPasswordSession plainAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmlPcrSelection plainSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
                using QuoteInput plainInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, plainSelection, pool);

                TpmResult<QuoteResponse> plainResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                    tpm, plainInput, [plainAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(plainResult.IsSuccess, $"The unprotected control quote must succeed: '{plainResult.ResponseCode}'.");
                plainResult.Value.Dispose();

                return (protectedCommand, captured!);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, companionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Captures the <c>TPM2_Quote()</c> response bytes twice — once with a companion carrying
    /// <paramref name="attribute"/> and once with no companion at all — so a response-confidentiality claim can be
    /// checked against its own control.
    /// </summary>
    /// <param name="attribute">The attribute the protected run's companion carries.</param>
    /// <returns>The protected response bytes and the unprotected ones.</returns>
    private async Task<(byte[] Protected, byte[] Plain)> CaptureQuoteResponsesAsync(TpmaSession attribute)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        byte[]? captured = null;
        using TpmDevice tpm = TpmDevice.Create(async (command, commandPool, cancellationToken) =>
        {
            bool isQuote = ReadCommandCode(command.Span) == TpmCcConstants.TPM_CC_Quote;
            TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, commandPool, cancellationToken).ConfigureAwait(false);
            if(isQuote && result.IsSuccess)
            {
                captured = result.Value.AsReadOnlySpan().ToArray();
            }

            return result;
        });

        using CreatePrimaryResponse ak = await CreateSignerAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await StartBoundSessionAsync(
            tpm, registry, pool, ak.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg), HmacSessionAlg).ConfigureAwait(false);

        try
        {
            using(companion)
            {
                companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | attribute;
                await QuoteOnceAsync(tpm, registry, pool, ak, companion).ConfigureAwait(false);
                byte[] protectedResponse = captured!;
                captured = null;

                using TpmPasswordSession plainAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmlPcrSelection plainSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
                using QuoteInput plainInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, plainSelection, pool);

                TpmResult<QuoteResponse> plainResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                    tpm, plainInput, [plainAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(plainResult.IsSuccess, $"The unprotected control quote must succeed: '{plainResult.ResponseCode}'.");
                plainResult.Value.Dispose();

                return (protectedResponse, captured!);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, companionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>Issues one successful <c>TPM2_Quote()</c> over a password sign slot and the given companion.</summary>
    /// <param name="tpm">The device to submit through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="ak">The signing key.</param>
    /// <param name="companion">The companion session, with its attributes already set.</param>
    private async Task QuoteOnceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse ak, TpmSession companion)
    {
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
        using QuoteInput input = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
        ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

        TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, input, [signAuth, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The protected quote must succeed: '{result.ResponseCode}'.");
        result.Value.Dispose();
    }

    /// <summary>
    /// Asserts an attestation is a genuine one carrying the expected <c>extraData</c> (TPM 2.0 Library Part 2,
    /// clause 10.11.12, Table 154: <c>magic</c> is <c>TPM_GENERATED_VALUE</c> (clause 6.2, Table 7) and <c>extraData</c> is the caller's
    /// <c>qualifyingData</c>).
    /// </summary>
    /// <param name="attest">The attestation the response carried.</param>
    /// <param name="expectedExtraData">The qualifying data the caller sent.</param>
    private static void AssertAttestationEchoes(Tpm2bAttest attest, ReadOnlySpan<byte> expectedExtraData)
    {
        TpmsAttest attestationData = attest.AttestationData;
        Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attestationData.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
        Assert.IsTrue(
            attestationData.ExtraData.Span.SequenceEqual(expectedExtraData),
            "extraData must echo the caller's qualifyingData exactly, which pins both directions of the keystream.");
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + <c>TPM_RC_S</c> +
    /// <c>TPM_RC_n</c>, transcribed test-side because the production helper is private.
    /// </summary>
    /// <param name="baseRc">The unencoded response code.</param>
    /// <param name="sessionIndex">The zero-based session index the code is blamed on.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>The endorsement hierarchy's Name, which for a permanent handle is the 4-octet handle value (TPM 2.0 Library Part 1, clause 13, Table 9).</summary>
    /// <returns>The 4-octet Name.</returns>
    private static byte[] EndorsementHandleBytes()
    {
        byte[] bytes = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, (uint)TpmRh.TPM_RH_ENDORSEMENT);

        return bytes;
    }

    /// <summary>Reads a framed command's <c>commandCode</c> field (TPM 2.0 Library Part 1, clause 15.2.3's commandCode header field).</summary>
    /// <param name="command">The framed command.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(ReadOnlySpan<byte> command) =>
        (TpmCcConstants)BinaryPrimitives.ReadUInt32BigEndian(command[(sizeof(ushort) + sizeof(uint))..]);

    /// <summary>
    /// Wraps the simulator in a device that rewrites the wire bytes of exactly one command code on their way in,
    /// leaving every other command untouched.
    /// </summary>
    /// <param name="simulator">The simulator the rewritten command is submitted to.</param>
    /// <param name="commandCode">The command whose bytes are rewritten.</param>
    /// <param name="rewrite">The rewrite to apply.</param>
    /// <returns>The rewriting device; the caller owns it.</returns>
    private static TpmDevice CreateRewritingDevice(TpmSimulator simulator, TpmCcConstants commandCode, Func<byte[], byte[]> rewrite)
    {
        return TpmDevice.Create(async (command, commandPool, cancellationToken) =>
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == commandCode)
            {
                bytes = rewrite(bytes);
            }

            return await simulator.SubmitAsync(bytes, commandPool, cancellationToken).ConfigureAwait(false);
        });
    }

    /// <summary>
    /// Appends one more <c>TPMS_AUTH_COMMAND</c> block to a framed command's authorization area — an empty
    /// nonceCaller, the given attributes, and an empty hmac — fixing up both the area's declared size and the
    /// command's own.
    /// </summary>
    /// <param name="command">The framed command.</param>
    /// <param name="handleCount">The command's handle count, which locates the authorization area.</param>
    /// <param name="sessionHandle">The handle the appended slot names.</param>
    /// <param name="sessionAttributes">The attributes the appended slot presents.</param>
    /// <returns>The rewritten command.</returns>
    private static byte[] WithAppendedSession(ReadOnlySpan<byte> command, int handleCount, uint sessionHandle, TpmaSession sessionAttributes)
    {
        int areaSizeOffset = HeaderSize + (handleCount * sizeof(uint));
        uint areaSize = BinaryPrimitives.ReadUInt32BigEndian(command[areaSizeOffset..]);
        int areaEnd = areaSizeOffset + sizeof(uint) + (int)areaSize;
        int blockSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);

        byte[] rewritten = new byte[command.Length + blockSize];
        command[..areaEnd].CopyTo(rewritten);

        int offset = areaEnd;
        BinaryPrimitives.WriteUInt32BigEndian(rewritten.AsSpan(offset), sessionHandle);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(rewritten.AsSpan(offset), 0);
        offset += sizeof(ushort);
        rewritten[offset] = (byte)sessionAttributes;
        offset += sizeof(byte);
        BinaryPrimitives.WriteUInt16BigEndian(rewritten.AsSpan(offset), 0);
        offset += sizeof(ushort);

        command[areaEnd..].CopyTo(rewritten.AsSpan(offset));
        BinaryPrimitives.WriteUInt32BigEndian(rewritten.AsSpan(areaSizeOffset), areaSize + (uint)blockSize);
        BinaryPrimitives.WriteUInt32BigEndian(rewritten.AsSpan(sizeof(ushort)), (uint)rewritten.Length);

        return rewritten;
    }

    /// <summary>
    /// Sets one attribute bit in the <c>sessionAttributes</c> octet of a chosen <c>TPMS_AUTH_COMMAND</c> block,
    /// leaving every other octet of the frame alone.
    /// </summary>
    /// <param name="command">The framed command.</param>
    /// <param name="handleCount">The command's handle count, which locates the authorization area.</param>
    /// <param name="sessionIndex">The zero-based slot whose octet is rewritten.</param>
    /// <param name="sessionAttributes">The attribute bits to set.</param>
    /// <returns>The rewritten command.</returns>
    private static byte[] SetSessionAttributeBit(ReadOnlySpan<byte> command, int handleCount, int sessionIndex, TpmaSession sessionAttributes)
    {
        byte[] rewritten = command.ToArray();
        int cursor = HeaderSize + (handleCount * sizeof(uint)) + sizeof(uint);
        for(int slot = 0; slot < sessionIndex; slot++)
        {
            cursor += sizeof(uint);
            ushort skipNonce = BinaryPrimitives.ReadUInt16BigEndian(rewritten.AsSpan(cursor));
            cursor += sizeof(ushort) + skipNonce + sizeof(byte);
            ushort skipHmac = BinaryPrimitives.ReadUInt16BigEndian(rewritten.AsSpan(cursor));
            cursor += sizeof(ushort) + skipHmac;
        }

        cursor += sizeof(uint);
        ushort nonceSize = BinaryPrimitives.ReadUInt16BigEndian(rewritten.AsSpan(cursor));
        cursor += sizeof(ushort) + nonceSize;
        rewritten[cursor] |= (byte)sessionAttributes;

        return rewritten;
    }

    /// <summary>
    /// Removes the LAST <c>TPMS_AUTH_COMMAND</c> block from a framed command's authorization area, fixing up both
    /// the area's declared size and the command's own — the wire an attacker who strips an encrypting session
    /// would produce.
    /// </summary>
    /// <param name="command">The framed command.</param>
    /// <param name="handleCount">The command's handle count, which locates the authorization area.</param>
    /// <returns>The rewritten command.</returns>
    private static byte[] WithoutLastSession(ReadOnlySpan<byte> command, int handleCount)
    {
        int areaSizeOffset = HeaderSize + (handleCount * sizeof(uint));
        uint areaSize = BinaryPrimitives.ReadUInt32BigEndian(command[areaSizeOffset..]);
        int areaStart = areaSizeOffset + sizeof(uint);
        int areaEnd = areaStart + (int)areaSize;

        int lastBlockStart = areaStart;
        int cursor = areaStart;
        while(cursor < areaEnd)
        {
            lastBlockStart = cursor;
            cursor += sizeof(uint);
            ushort nonceSize = BinaryPrimitives.ReadUInt16BigEndian(command[cursor..]);
            cursor += sizeof(ushort) + nonceSize + sizeof(byte);
            ushort hmacSize = BinaryPrimitives.ReadUInt16BigEndian(command[cursor..]);
            cursor += sizeof(ushort) + hmacSize;
        }

        int removed = areaEnd - lastBlockStart;
        byte[] rewritten = new byte[command.Length - removed];
        command[..lastBlockStart].CopyTo(rewritten);
        command[areaEnd..].CopyTo(rewritten.AsSpan(lastBlockStart));
        BinaryPrimitives.WriteUInt32BigEndian(rewritten.AsSpan(areaSizeOffset), areaSize - (uint)removed);
        BinaryPrimitives.WriteUInt32BigEndian(rewritten.AsSpan(sizeof(ushort)), (uint)rewritten.Length);

        return rewritten;
    }

    /// <summary>
    /// Overstates the first command parameter's declared size so it can no longer fit inside the parameter area,
    /// leaving the parameters behind it unreachable.
    /// </summary>
    /// <param name="command">The framed command.</param>
    /// <returns>The rewritten command.</returns>
    private static byte[] OverstateFirstParameterSize(byte[] command)
    {
        int areaSizeOffset = HeaderSize + sizeof(uint);
        uint areaSize = BinaryPrimitives.ReadUInt32BigEndian(command.AsSpan(areaSizeOffset));
        int parametersStart = areaSizeOffset + sizeof(uint) + (int)areaSize;

        byte[] rewritten = [.. command];
        BinaryPrimitives.WriteUInt16BigEndian(rewritten.AsSpan(parametersStart), ushort.MaxValue);

        return rewritten;
    }

    /// <summary>Whether <paramref name="needle"/> occurs as a contiguous sequence inside <paramref name="haystack"/>.</summary>
    /// <param name="haystack">The bytes to search.</param>
    /// <param name="needle">The sequence to look for.</param>
    /// <returns><see langword="true"/> when the sequence occurs.</returns>
    private static bool ContainsSubsequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if(needle.IsEmpty || needle.Length > haystack.Length)
        {
            return false;
        }

        for(int start = 0; start + needle.Length <= haystack.Length; start++)
        {
            if(haystack.Slice(start, needle.Length).SequenceEqual(needle))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Starts a bound, unsalted HMAC session through the production path and wraps it as a <see cref="TpmSession"/>.</summary>
    /// <param name="tpm">The device to submit through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="bindHandle">The entity the session binds to.</param>
    /// <param name="bindAuthValue">That entity's authorization value, which the session key folds.</param>
    /// <param name="symmetric">The symmetric definition to negotiate.</param>
    /// <param name="sessionAlg">The session hash algorithm to negotiate.</param>
    /// <param name="isBoundToAuthorizedEntity">Whether the bind entity is the entity this session will authorize, which drops the authValue from the HMAC key alone.</param>
    /// <returns>The session handle and the wrapped session; the caller owns both.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartBoundSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint bindHandle, ReadOnlyMemory<byte> bindAuthValue,
        TpmtSymDef symmetric, TpmAlgIdConstants sessionAlg, bool isBoundToAuthorizedEntity = false)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(bindHandle, sessionAlg, symmetric);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(started.SessionHandle.Value), bindAuthValue, startInput.NonceCaller, started.NonceTPM, sessionAlg, pool,
            symmetric: symmetric, isBoundToAuthorizedEntity: isBoundToAuthorizedEntity, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Starts an unbound, unsalted HMAC session through the production path and wraps it as a <see cref="TpmSession"/>.</summary>
    /// <param name="tpm">The device to submit through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="symmetric">The symmetric definition to negotiate.</param>
    /// <param name="sessionAlg">The session hash algorithm to negotiate.</param>
    /// <returns>The session handle and the wrapped session; the caller owns both.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartUnboundSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtSymDef symmetric, TpmAlgIdConstants sessionAlg)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(sessionAlg, symmetric);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, sessionAlg, pool, symmetric)
        {
            SessionAttributes = TpmaSession.CONTINUE_SESSION
        };

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Creates a primary ECC P-256 signing key under the given hierarchy.</summary>
    /// <param name="tpm">The device to submit through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy the key is created under.</param>
    /// <param name="password">The key's own authorization value, or <see langword="null"/> for an empty one.</param>
    /// <returns>The CreatePrimary response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateSignerAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, string? password)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy,
            password,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Defines <see cref="NvIndexHandle"/> and writes <see cref="WrittenData"/> into it in full.</summary>
    /// <param name="tpm">The device to submit through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task DefineAndWriteNvIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth auth = Tpm2bAuth.Create(IndexAuth, pool);
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool);
        using var publicInfo = new TpmsNvPublic(NvIndexHandle, HmacSessionAlg, IndexAttributes, policyDigest, dataSize: (ushort)WrittenData.Length);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, defineInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");

        using TpmPasswordSession writeAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(WrittenData, pool);
        var writeInput = new NvWriteInput(NvIndexHandle, NvIndexHandle, writeInputBuffer, Offset: 0);

        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"NV_Write failed: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// Transcribes <see cref="NvIndexHandle"/>'s Name — <c>nameAlg ‖ H_nameAlg(TPMS_NV_PUBLIC)</c> (TPM 2.0
    /// Library Part 1, clause 13, Table 9) — independently of the simulator, for cpHash's handle-Name area.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The Index's Name.</returns>
    private async Task<byte[]> ComputeNvIndexNameAsync(BaseMemoryPool pool)
    {
        TpmaNv writtenAttributes = IndexAttributes | TpmaNv.TPMA_NV_WRITTEN;

        byte[] marshaled = new byte[sizeof(uint) + sizeof(ushort) + sizeof(uint) + sizeof(ushort) + sizeof(ushort)];
        int offset = 0;
        BinaryPrimitives.WriteUInt32BigEndian(marshaled.AsSpan(offset), NvIndexHandle);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset), (ushort)HmacSessionAlg);
        offset += sizeof(ushort);
        BinaryPrimitives.WriteUInt32BigEndian(marshaled.AsSpan(offset), (uint)writtenAttributes);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset), 0);
        offset += sizeof(ushort);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset), (ushort)WrittenData.Length);

        Tag tag = Tag.Create(HashAlgorithmName.SHA256)
            .With(Purpose.Digest)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(marshaled),
            outputByteLength: 32,
            tag: tag,
            pool: pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] name = new byte[sizeof(ushort) + digest.AsReadOnlySpan().Length];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)HmacSessionAlg);
        digest.AsReadOnlySpan().CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>Flushes a loaded session or object handle, ignoring the outcome.</summary>
    /// <param name="tpm">The device to submit through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    private static async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(handle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
    }

    /// <summary>Creates a response codec registry covering every command this file issues.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_Quote, TpmResponseCodec.Quote);
        _ = registry.Register(TpmCcConstants.TPM_CC_Certify, TpmResponseCodec.Certify);
        _ = registry.Register(TpmCcConstants.TPM_CC_CertifyCreation, TpmResponseCodec.CertifyCreation);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetTime, TpmResponseCodec.GetTime);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Certify, TpmResponseCodec.NvCertify);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);

        return registry;
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator; the caller owns it.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-attest-parameter-encryption", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed.");
        result.Value.Dispose();

        return simulator;
    }
}
