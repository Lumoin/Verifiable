using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the ONE authorization-slot table the three zero-handle commands share — <c>TPM2_StirRandom()</c>,
/// <c>TPM2_TestParms()</c> and <c>TPM2_GetRandom()</c>, none of which carries an <c>@</c>-decorated handle — over
/// the raw wire against the in-house behavioural <see cref="TpmSimulator"/>, entirely in-process with no external
/// assets. Every case is hand-framed, because <see cref="TpmCommandExecutor"/>'s own client-side guards refuse
/// most of these compositions before any octet reaches the transport, and the answers the table gives are what
/// this file proves: the slot's handle kind and loadedness first (Part 3, clause 5.5, step 4), then the
/// attribute consistency a session authorizing no entity must satisfy (step 4.4.2), and only where a command has
/// a parameter of the right direction does a <c>decrypt</c> or <c>encrypt</c> claim survive — the one cell where
/// <c>TPM2_GetRandom()</c>, whose response parameter IS encryptable, parts company with the other two.
/// TPM 2.0 Library Part 3, clauses 16.1, 16.2, 30.3, 5.5 and 5.7; Part 1, clauses 15.6.4, 16.4 and 18.1;
/// Part 2, clause 6.6.2.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorZeroHandleSessionTests
{
    /// <summary>The hash algorithm every session these tests compose negotiates.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The SHA-256 digest width, in octets — the cpHash width used here.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The octet count the framed <c>TPM2_GetRandom()</c> parameter area asks for.</summary>
    private const ushort RandomDrawLength = 16;

    /// <summary>A handle in the transient-object range, which the authorization slot admits no more than any other non-session type.</summary>
    private const uint TransientRangeHandle = 0x8000_0000;

    /// <summary>A handle in the NV Index range, whose KIND the slot settles before it ever asks whether anything is loaded there.</summary>
    private const uint NvIndexRangeHandle = 0x0100_0111;

    /// <summary>The value <see cref="ExpectedRc"/> reads as "the answer names no session".</summary>
    private const int NoBlamedSession = -1;

    /// <summary>The additional input the framed <c>TPM2_StirRandom()</c> parameter area carries.</summary>
    private static byte[] StirInData { get; } = [0xA1, 0xB2, 0xC3, 0xD4];

    /// <summary>
    /// The <c>TPMT_PUBLIC_PARMS</c> every framed <c>TPM2_TestParms()</c> carries: RSA-2048 with RSASSA over
    /// SHA-256 and no symmetric definition — a combination this simulator implements, so a refusal in this file
    /// is never the parameters' own doing.
    /// </summary>
    private static TpmtPublicParms RsaSigningParms { get; } = TpmtPublicParms.Create(
        TpmAlgIdConstants.TPM_ALG_RSA,
        TpmuPublicParms.Rsa(TpmsRsaParms.ForSigning(2048, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256))));

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "If present, a password authorization is always associated with a command handle that requires
    /// authorization as there is no session context associated with a password that would allow it to be used
    /// for encryption or command audit." — a zero-handle command has no such handle, and the three attributes a
    /// slot authorizing nothing could claim instead are exactly the three a password slot may never carry, so a
    /// <c>TPM_RS_PW</c> slot is refused with the session-index-encoded <c>TPM_RC_ATTRIBUTES</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.4 and 15.6.4, Table 15; Part 3, clause 5.5, step 4.4.2</see>.
    /// </summary>
    /// <param name="commandCode">The zero-handle command under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_StirRandom, DisplayName = "TPM2_StirRandom()")]
    [DataRow(TpmCcConstants.TPM_CC_TestParms, DisplayName = "TPM2_TestParms()")]
    [DataRow(TpmCcConstants.TPM_CC_GetRandom, DisplayName = "TPM2_GetRandom()")]
    public async Task ZeroHandleCommandOverAPasswordSlotReturnsSessionEncodedAttributes(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] parameters = ParameterAreaFor(commandCode, pool);
        byte[] authArea = BuildPasswordAuthArea();

        TpmRcConstants code = await SubmitZeroHandleAsync(simulator, pool, commandCode, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
            $"'{commandCode}' has no command handle for a TPM_RS_PW authorization to attach to, so the slot is refused with the session-index-encoded TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// "If a session is not being used for authorization, at least one of decrypt, encrypt, or audit must be SET.
    /// (TPM_RC_ATTRIBUTES)." — a loaded HMAC session at the lone slot of a zero-handle command authorizes
    /// nothing, so claiming none of the three is the refusal this rule names, blamed on the offending slot.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.4.2; Part 2, clause 6.6.2</see>.
    /// </summary>
    /// <param name="commandCode">The zero-handle command under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_StirRandom, DisplayName = "TPM2_StirRandom()")]
    [DataRow(TpmCcConstants.TPM_CC_TestParms, DisplayName = "TPM2_TestParms()")]
    [DataRow(TpmCcConstants.TPM_CC_GetRandom, DisplayName = "TPM2_GetRandom()")]
    public async Task ZeroHandleCommandOverAnAttributelessSessionReturnsSessionEncodedAttributes(TpmCcConstants commandCode)
    {
        await AssertSessionClaimAnswerAsync(
            commandCode, TpmaSession.CONTINUE_SESSION, TpmtSymDef.Xor(SessionAlg),
            TpmRcConstants.TPM_RC_ATTRIBUTES, blamedSessionIndex: 0,
            "a session authorizing nothing must claim at least one of decrypt, encrypt or audit").ConfigureAwait(false);
    }

    /// <summary>
    /// "This attribute indicates that the session is being used for audit. A digest is maintained in the session
    /// context and is updated each time the session is used with a command and audit is SET." — the claim is
    /// admitted on all three zero-handle commands, including <c>TPM2_TestParms()</c>, whose over-session form has
    /// no other claim it can carry to success, and the command succeeds, extending the session's audit digest to
    /// <c>H(0…0 ‖ cpHash ‖ rpHash)</c> on its first use (TPM 2.0 Library Part 1, clause 17.1, equation 30) with
    /// the response echoing <c>audit</c> SET, <c>auditExclusive</c> SET and <c>auditReset</c> CLEAR (Table 38) —
    /// proved by chaining cpHash/rpHash from the octets this test itself sent and read, then reading the
    /// session's digest back through <c>TPM2_GetSessionAuditDigest()</c> with the NULL signer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1; Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    /// <param name="commandCode">The zero-handle command under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_StirRandom, DisplayName = "TPM2_StirRandom()")]
    [DataRow(TpmCcConstants.TPM_CC_TestParms, DisplayName = "TPM2_TestParms()")]
    [DataRow(TpmCcConstants.TPM_CC_GetRandom, DisplayName = "TPM2_GetRandom()")]
    public async Task ZeroHandleCommandOverAnAuditClaimingSessionSucceeds(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateSessionRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        byte[] parameters = ParameterAreaFor(commandCode, pool);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(device, registry, pool, TpmtSymDef.Xor(SessionAlg), TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                byte[] authArea = await BuildSessionAuthAreaAsync(session, commandCode, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await SubmitZeroHandleForAuditAsync(simulator, pool, commandCode, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_SUCCESS, code,
                    $"'{commandCode}' over a session claiming audit alone succeeds (TPM 2.0 Library Part 1, clause 17.1).");

                byte auditedAttributes = ReadResponseSessionAttributes(response, outHandleCount: 0, sessionIndex: 0);
                Assert.AreEqual(
                    (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE), auditedAttributes,
                    $"'{commandCode}': the response echoes audit SET and auditExclusive SET (the session's first use as an audit session), with auditReset CLEAR (TPM 2.0 Library Part 2, clause 8.4, Table 38).");

                byte[] responseParameters = ReadResponseParameters(response, outHandleCount: 0);
                byte[] cpHash = await ComputeZeroHandleCpHashAsync(commandCode, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] rpHash = await ComputeRpHashAsync(commandCode, responseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] expectedDigest = await ExtendAuditDigestAsync(priorDigest: null, cpHash, rpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);

                using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(sessionHandle), ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                using GetSessionAuditDigestResponse? auditDigestResponse = digestResult.IsSuccess ? digestResult.Value : null;

                Assert.IsTrue(
                    digestResult.IsSuccess,
                    $"'{commandCode}': TPM2_GetSessionAuditDigest() over the freshly audited session must succeed: '{digestResult.ResponseCode}'.");
                Assert.IsTrue(
                    auditDigestResponse!.SessionAudit.ExclusiveSession.IsYes,
                    $"'{commandCode}': the session became the exclusive audit session on its first use (TPM 2.0 Library Part 1, clause 17.2).");
                Assert.IsTrue(
                    expectedDigest.AsSpan().SequenceEqual(auditDigestResponse.SessionAudit.SessionDigest.AsReadOnlySpan()),
                    $"'{commandCode}': the session's audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) chained from this exchange's own wire octets (TPM 2.0 Library Part 1, clause 17.1, equation 30).");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "This attribute may only be SET in a response that has a sized buffer as its first parameter." — the one
    /// cell where the three commands part company: <c>TPM2_GetRandom()</c>'s response carries
    /// <c>randomBytes</c>, a sized buffer, so an <c>encrypt</c> claim there is admitted and the command
    /// succeeds, while <c>TPM2_StirRandom()</c> and <c>TPM2_TestParms()</c> answer header-only responses with
    /// nothing to encrypt and refuse the claim with the session-index-encoded <c>TPM_RC_ATTRIBUTES</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 15.6.4, Table 15, and 18.1; Part 3, clauses 16.1, 16.2.2, Table 78, and 30.3.2, Table 241</see>.
    /// </summary>
    /// <param name="commandCode">The zero-handle command under test.</param>
    /// <param name="expectedBaseCode">The response code the command's own response shape earns.</param>
    /// <param name="blamedSessionIndex">The slot the answer names, or -1 when it names none.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_StirRandom, TpmRcConstants.TPM_RC_ATTRIBUTES, 0, DisplayName = "TPM2_StirRandom() answers header-only, so encrypt is refused")]
    [DataRow(TpmCcConstants.TPM_CC_TestParms, TpmRcConstants.TPM_RC_ATTRIBUTES, 0, DisplayName = "TPM2_TestParms() answers header-only, so encrypt is refused")]
    [DataRow(TpmCcConstants.TPM_CC_GetRandom, TpmRcConstants.TPM_RC_SUCCESS, NoBlamedSession, DisplayName = "TPM2_GetRandom()'s randomBytes is encryptable, so encrypt succeeds")]
    public async Task ZeroHandleCommandOverAnEncryptClaimingSessionAnswersItsOwnResponseParameterRule(
        TpmCcConstants commandCode, TpmRcConstants expectedBaseCode, int blamedSessionIndex)
    {
        await AssertSessionClaimAnswerAsync(
            commandCode, TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT, TpmtSymDef.Xor(SessionAlg),
            expectedBaseCode, blamedSessionIndex,
            "an encrypt claim is admitted exactly where the response's first parameter is a sized buffer").ConfigureAwait(false);
    }

    /// <summary>
    /// "If the symmetric algorithm is TPM_ALG_NULL and encryption or decryption is specified, the TPM returns
    /// TPM_RC_SYMMETRIC." — but only once the claim itself is admissible: <c>TPM2_StirRandom()</c>'s
    /// <c>inData</c> IS a sized first command parameter, so its slot reaches the symmetric rule and answers
    /// <c>TPM_RC_SYMMETRIC</c>, while <c>TPM2_TestParms()</c> (whose <c>TPMT_PUBLIC_PARMS</c> has no size field)
    /// and <c>TPM2_GetRandom()</c> (whose only parameter is a bare <c>UINT16</c>) are refused for the attribute
    /// itself, never for an algorithm they never negotiated.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 5.7; Part 2, clause 12.2.3.10, Table 234</see>.
    /// </summary>
    /// <param name="commandCode">The zero-handle command under test.</param>
    /// <param name="expectedBaseCode">The response code the command's own first-parameter shape earns.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_StirRandom, TpmRcConstants.TPM_RC_SYMMETRIC, DisplayName = "TPM2_StirRandom()'s inData is encryptable, so the symmetric rule decides")]
    [DataRow(TpmCcConstants.TPM_CC_TestParms, TpmRcConstants.TPM_RC_ATTRIBUTES, DisplayName = "TPM2_TestParms() has no sized first parameter, so the attribute decides")]
    [DataRow(TpmCcConstants.TPM_CC_GetRandom, TpmRcConstants.TPM_RC_ATTRIBUTES, DisplayName = "TPM2_GetRandom() has no sized first parameter, so the attribute decides")]
    public async Task ZeroHandleCommandOverADecryptClaimingNullSymmetricSessionAnswersItsOwnCommandParameterRule(
        TpmCcConstants commandCode, TpmRcConstants expectedBaseCode)
    {
        await AssertSessionClaimAnswerAsync(
            commandCode, TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT, TpmtSymDef.Null,
            expectedBaseCode, blamedSessionIndex: 0,
            "a decrypt claim is judged against the command's own first parameter before the session's symmetric algorithm").ConfigureAwait(false);
    }

    /// <summary>
    /// "If the session is not loaded, the TPM will return the warning TPM_RC_REFERENCE_S0 + N where N is the
    /// number of the session. The first session is session zero, N = 0." — a well-typed session handle whose
    /// session has been flushed names a plausible but dead context, told apart from a handle that was never a
    /// session handle at all.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.2; Part 2, clause 6.6.2</see>.
    /// </summary>
    /// <param name="commandCode">The zero-handle command under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_StirRandom, DisplayName = "TPM2_StirRandom()")]
    [DataRow(TpmCcConstants.TPM_CC_TestParms, DisplayName = "TPM2_TestParms()")]
    [DataRow(TpmCcConstants.TPM_CC_GetRandom, DisplayName = "TPM2_GetRandom()")]
    public async Task ZeroHandleCommandOverAnUnloadedSessionHandleReturnsReferenceMiss(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateSessionRegistry();

        byte[] parameters = ParameterAreaFor(commandCode, pool);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(device, registry, pool, TpmtSymDef.Xor(SessionAlg), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] authArea;
        using(session)
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
            authArea = await BuildSessionAuthAreaAsync(session, commandCode, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
        }

        await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);

        TpmRcConstants code = await SubmitZeroHandleAsync(simulator, pool, commandCode, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_REFERENCE_S0, code,
            $"'{commandCode}' over a session handle naming no loaded session must be blamed on the offending slot index.");
    }

    /// <summary>
    /// A LOADED policy session claiming <c>encrypt</c>, authorizing no entity, is admitted exactly like an
    /// HMAC companion — Table 12, footnote [2]: "a policy authorization session can also be used for encryption
    /// and decryption." <c>TPM2_StirRandom()</c> and <c>TPM2_TestParms()</c> answer header-only responses with
    /// nothing to encrypt, so the claim is refused by the area's own attribute rule, session-encoded
    /// <c>TPM_RC_ATTRIBUTES</c> at index 0 — the same refusal an HMAC companion claiming <c>encrypt</c> here
    /// would draw.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.6.1, Table 12, footnote [2]; clause 18.1</see>.
    /// </summary>
    /// <param name="commandCode">The zero-handle command under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_StirRandom, DisplayName = "TPM2_StirRandom()")]
    [DataRow(TpmCcConstants.TPM_CC_TestParms, DisplayName = "TPM2_TestParms()")]
    public async Task ZeroHandleCommandOverALoadedPolicySessionClaimingEncryptReturnsSessionEncodedAttributes(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateSessionRegistry();

        byte[] parameters = ParameterAreaFor(commandCode, pool);

        (uint policyHandle, TpmSession policySession) = await StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, TpmtSymDef.Xor(SessionAlg), TpmSeConstants.TPM_SE_POLICY).ConfigureAwait(false);
        try
        {
            byte[] authArea;
            using(policySession)
            {
                policySession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                authArea = await BuildSessionAuthAreaAsync(policySession, commandCode, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
            }

            TpmRcConstants code = await SubmitZeroHandleAsync(simulator, pool, commandCode, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
                $"'{commandCode}' over a loaded POLICY session claiming encrypt is admitted like an HMAC companion, then refused session-encoded ATTRIBUTES because its own response is header-only.");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A LOADED policy session claiming <c>encrypt</c>, admitted exactly like an HMAC companion (TPM 2.0
    /// Library Part 1, clause 15.6.1, Table 12, footnote [2]), succeeds over <c>TPM2_GetRandom()</c> — whose
    /// <c>randomBytes</c> IS a sized response parameter (Part 3, Table 76) — framed with <c>TPM_ST_SESSIONS</c>;
    /// applying the session's own KDFa-derived keystream (clause 18.2, equation 4) to the wire ciphertext, using
    /// the session's Empty Buffer key (unbound, unsalted — Part 3, clause 11.1.1) and the nonces this exchange
    /// actually carried, yields octets that differ from the wire ciphertext, proving the keystream is non-zero.
    /// <c>TPM2_GetRandom()</c> carries no independent oracle for its own draw, so this does not — and cannot —
    /// prove the recovered octets are the genuine plaintext, only that the response was genuinely transformed.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.6.1, Table 12, footnote [2]; clause 18.2</see>.
    /// </summary>
    [TestMethod]
    public async Task GetRandomOverALoadedPolicySessionClaimingEncryptSucceedsWithTheResponseGenuinelyTransformed()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateSessionRegistry();

        byte[] parameters = ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);

        (uint policyHandle, TpmSession policySession) = await StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, TpmtSymDef.Xor(SessionAlg), TpmSeConstants.TPM_SE_POLICY).ConfigureAwait(false);
        try
        {
            byte[] authArea;
            using(policySession)
            {
                policySession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                authArea = await BuildSessionAuthAreaAsync(policySession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
            }

            var authReader = new TpmReader(authArea);
            _ = authReader.ReadUInt32();
            byte[] nonceCallerSent = authReader.ReadBytes(authReader.ReadUInt16()).ToArray();

            (TpmRcConstants code, byte[] response) = await SubmitZeroHandleForAuditAsync(
                simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SUCCESS, code,
                $"TPM2_GetRandom() over a loaded POLICY session claiming encrypt must succeed: '{code}'.");

            byte[] nonceTpmReturned = ReadResponseNonceTpm(response, outHandleCount: 0, sessionIndex: 0);
            byte[] responseParameters = ReadResponseParameters(response, outHandleCount: 0);

            //randomBytes' own TPM2B size field is never itself encrypted (Part 1, clause 20.1); only the octets
            //after it are the ciphertext this session's keystream protects.
            byte[] cipherText = responseParameters[sizeof(ushort)..];
            Assert.AreEqual(RandomDrawLength, cipherText.Length, "The ciphertext's length must equal the requested draw, since encryption changes no length.");

            await TpmParameterEncryption.XorAsync(
                HashAlgorithmName.SHA256, ReadOnlyMemory<byte>.Empty, nonceTpmReturned, nonceCallerSent, cipherText, pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(
                cipherText.AsSpan().SequenceEqual(responseParameters.AsSpan(sizeof(ushort))),
                "Applying the session's own keystream must change the octets, proving the response was genuinely transformed rather than passed through unencrypted.");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A loaded policy companion's own nonceTPM stays UNCHANGED after a refused command — "If that code is not
    /// TPM_RC_SUCCESS, the post processing code will not update any session or audit data" — so a SECOND, honestly
    /// signed attempt over the SAME (never-rolled) nonce still verifies; once that attempt succeeds, the response
    /// carries a FRESHLY rolled nonceTPM, different from the one the session started with (TPM 2.0 Library Part 1,
    /// clause 16.6.5). The corrupted attempt is also uncharged: the policy session is unbound, so no
    /// dictionary-attack accounting applies to it (Part 1, clause 16.8.1) — <c>LockoutCounter</c> must not move.
    /// </summary>
    /// <remarks>
    /// The client-side <see cref="TpmSession"/> wrapper here never calls its own response-verification step (this
    /// test frames every attempt by hand), so its own <see cref="TpmSessionBase.NonceTpm"/> stays fixed at the
    /// value <c>TPM2_StartAuthSession()</c> returned across both attempts — the SAME value a genuinely unrolled
    /// simulator-side session would still expect on the second attempt's command HMAC.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.9; Part 1, clause 16.6.5</see>.
    /// </remarks>
    [TestMethod]
    public async Task GetRandomOverALoadedPolicySessionRollsNonceTpmOnSuccessAndLeavesItUnchangedOnFailure()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateSessionRegistry();

        byte[] parameters = ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);

        (uint policyHandle, TpmSession policySession) = await StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, TpmtSymDef.Xor(SessionAlg), TpmSeConstants.TPM_SE_POLICY).ConfigureAwait(false);
        try
        {
            using(policySession)
            {
                policySession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                byte[] startingNonceTpm = policySession.NonceTpm.ToArray();

                //A corrupted hmac over the session's own (still unrolled) nonceTPM: refused session-encoded
                //BAD_AUTH, and — per clause 5.9 — the session's nonceTPM must not move for it.
                byte[] corruptedAuthArea = await BuildSessionAuthAreaAsync(policySession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                corruptedAuthArea[^1] ^= 0xFF;

                TpmResult<TpmDictionaryAttackParameters> before = await device.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(before.IsSuccess, $"Reading the dictionary-attack parameters failed: '{before.ResponseCode}'.");

                TpmRcConstants failureCode = await SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetRandom, corruptedAuthArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), failureCode,
                    "A corrupted policy-companion hmac is refused session-encoded BAD_AUTH, the inner draw not taken.");

                TpmResult<TpmDictionaryAttackParameters> after = await device.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(after.IsSuccess, $"Reading the dictionary-attack parameters failed: '{after.ResponseCode}'.");
                Assert.AreEqual(
                    before.Value.LockoutCounter, after.Value.LockoutCounter,
                    "An unbound policy session's wrong HMAC is uncharged (Part 1, clause 16.8.1): failedTries must not move.");

                //A second, correctly signed attempt, still keyed on the SAME nonceTPM the session started with:
                //it verifies only because the failed attempt above left that nonceTPM untouched.
                byte[] honestAuthArea = await BuildSessionAuthAreaAsync(policySession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                (TpmRcConstants successCode, byte[] response) = await SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetRandom, honestAuthArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_SUCCESS, successCode,
                    $"A correctly signed second attempt over the session's never-rolled nonceTPM must succeed: '{successCode}'.");

                byte[] rolledNonceTpm = ReadResponseNonceTpm(response, outHandleCount: 0, sessionIndex: 0);
                Assert.IsFalse(
                    startingNonceTpm.AsSpan().SequenceEqual(rolledNonceTpm),
                    "A successful command must roll the policy companion's nonceTPM to a fresh value.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A LOADED policy session claiming <c>decrypt</c> with a NULL symmetric algorithm is admitted exactly like
    /// an HMAC companion would be (Table 12, footnote [2]), then refused by the symmetric
    /// rule itself: "If the symmetric algorithm is TPM_ALG_NULL and encryption or decryption is specified, the
    /// TPM returns TPM_RC_SYMMETRIC." <c>TPM2_StirRandom()</c>'s <c>inData</c> IS a sized first command
    /// parameter, so its slot reaches this rule rather than the attribute gate a command with no such parameter
    /// would answer instead.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// clause 18; Part 3, clause 5.7</see>.
    /// </summary>
    [TestMethod]
    public async Task StirRandomOverANullSymmetricPolicySessionClaimingDecryptReturnsSessionEncodedSymmetric()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateSessionRegistry();

        byte[] parameters = ParameterAreaFor(TpmCcConstants.TPM_CC_StirRandom, pool);

        (uint policyHandle, TpmSession policySession) = await StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, TpmtSymDef.Null, TpmSeConstants.TPM_SE_POLICY).ConfigureAwait(false);
        try
        {
            byte[] authArea;
            using(policySession)
            {
                policySession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                authArea = await BuildSessionAuthAreaAsync(policySession, TpmCcConstants.TPM_CC_StirRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
            }

            TpmRcConstants code = await SubmitZeroHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_StirRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_SYMMETRIC, sessionIndex: 0), code,
                "A NULL-symmetric policy companion claiming decrypt at a decrypt-admitting slot is refused session-encoded TPM_RC_SYMMETRIC, exactly as an HMAC companion would be.");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A LOADED policy session claiming <c>encrypt</c>, admitted exactly like an HMAC companion, answers a
    /// response entry whose <c>hmac</c> field genuinely verifies under <c>sessionKey</c> ALONE — "If the session
    /// is not being used for authorization, sessionValue is sessionKey" — recomputed here independently from the
    /// response's own rpHash (over the STILL-ENCRYPTED <c>randomBytes</c>), the freshly rolled nonceTPM and the
    /// echoed <c>sessionAttributes</c> octet, with no <c>authValue</c> term at all, since the companion authorizes
    /// no entity.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// clause 18; clause 16.6.5</see>.
    /// </summary>
    [TestMethod]
    public async Task GetRandomOverALoadedPolicySessionClaimingEncryptHasAResponseHmacThatVerifiesUnderTheSessionKeyAlone()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateSessionRegistry();

        byte[] parameters = ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);

        (uint policyHandle, TpmSession policySession) = await StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, TpmtSymDef.Xor(SessionAlg), TpmSeConstants.TPM_SE_POLICY).ConfigureAwait(false);
        try
        {
            byte[] authArea;
            using(policySession)
            {
                policySession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                authArea = await BuildSessionAuthAreaAsync(policySession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
            }

            var authReader = new TpmReader(authArea);
            _ = authReader.ReadUInt32();
            byte[] nonceCallerSent = authReader.ReadBytes(authReader.ReadUInt16()).ToArray();

            (TpmRcConstants code, byte[] response) = await SubmitZeroHandleForAuditAsync(
                simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, $"TPM2_GetRandom() over a loaded POLICY session claiming encrypt must succeed: '{code}'.");

            byte[] cipherResponseParameters = ReadResponseParameters(response, outHandleCount: 0);
            byte[] rpHash = await ComputeRpHashAsync(TpmCcConstants.TPM_CC_GetRandom, cipherResponseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
            byte[] nonceTpmReturned = ReadResponseNonceTpm(response, outHandleCount: 0, sessionIndex: 0);
            byte echoedAttributes = ReadResponseSessionAttributes(response, outHandleCount: 0, sessionIndex: 0);
            byte[] wireHmac = ReadResponseSessionHmac(response, outHandleCount: 0, sessionIndex: 0);

            Assert.AreEqual(
                (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT), echoedAttributes,
                "The response echoes exactly the sessionAttributes octet the request carried.");

            byte[] data = [.. rpHash, .. nonceTpmReturned, .. nonceCallerSent, echoedAttributes];
            using HmacValue expected = await CryptographicKeyEvents.ComputeHmacAsync(
                data, ReadOnlyMemory<byte>.Empty, outputByteLength: Sha256DigestSize,
                tag: Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Hmac).With(EncodingScheme.Raw).With(MaterialSemantics.Direct),
                pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(
                expected.AsReadOnlySpan().SequenceEqual(wireHmac),
                "The response hmac must equal HMAC_sessionAlg(sessionKey, rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes) with sessionKey alone (the Empty Buffer here) and no authValue term, since the companion authorizes no entity.");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If the session handle is not a handle for an HMAC session, a handle for a policy session, or, TPM_RS_PW
    /// then the TPM shall return TPM_RC_HANDLE." — a structural fact about the octets, settled before anything
    /// is looked up, so a transient-object handle and an NV Index handle are both refused on their KIND alone,
    /// session-index-encoded to the offending slot.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.1; Part 2, clauses 7.2 and 6.6.2</see>.
    /// </summary>
    /// <param name="commandCode">The zero-handle command under test.</param>
    /// <param name="slotHandle">The non-session value framed into the authorization slot's session handle field.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_StirRandom, TransientRangeHandle, DisplayName = "TPM2_StirRandom() over a transient-object handle")]
    [DataRow(TpmCcConstants.TPM_CC_StirRandom, NvIndexRangeHandle, DisplayName = "TPM2_StirRandom() over an NV Index handle")]
    [DataRow(TpmCcConstants.TPM_CC_TestParms, TransientRangeHandle, DisplayName = "TPM2_TestParms() over a transient-object handle")]
    [DataRow(TpmCcConstants.TPM_CC_TestParms, NvIndexRangeHandle, DisplayName = "TPM2_TestParms() over an NV Index handle")]
    [DataRow(TpmCcConstants.TPM_CC_GetRandom, TransientRangeHandle, DisplayName = "TPM2_GetRandom() over a transient-object handle")]
    [DataRow(TpmCcConstants.TPM_CC_GetRandom, NvIndexRangeHandle, DisplayName = "TPM2_GetRandom() over an NV Index handle")]
    public async Task ZeroHandleCommandOverANonSessionAuthorizationSlotHandleReturnsSessionEncodedHandle(TpmCcConstants commandCode, uint slotHandle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateSessionRegistry();

        TpmRcConstants code = await SubmitOverPatchedSlotAsync(simulator, device, registry, pool, commandCode, slotHandle).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 0), code,
            $"'{commandCode}' over a non-session handle at the authorization slot is refused on the handle's kind, ahead of any credential evaluation.");
    }

    /// <summary>
    /// "If the tag is TPM_ST_SESSIONS, the TPM will attempt to unmarshal an authorizationSize and return
    /// TPM_RC_AUTHSIZE if the value is not within an acceptable range." with "The minimum value is
    /// (sizeof(TPM_HANDLE) + sizeof(UINT16) + sizeof(TPMA_SESSION) + sizeof(UINT16))" — a sessions-tagged
    /// command declaring an EMPTY authorization area is beneath that nine-octet minimum and is refused at the
    /// frame, before the slot table above is ever consulted.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 3.1</see>.
    /// </summary>
    /// <param name="commandCode">The zero-handle command under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_StirRandom, DisplayName = "TPM2_StirRandom()")]
    [DataRow(TpmCcConstants.TPM_CC_TestParms, DisplayName = "TPM2_TestParms()")]
    [DataRow(TpmCcConstants.TPM_CC_GetRandom, DisplayName = "TPM2_GetRandom()")]
    public async Task ZeroHandleCommandWithAnEmptyAuthorizationAreaReturnsAuthsize(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] parameters = ParameterAreaFor(commandCode, pool);

        TpmRcConstants code = await SubmitZeroHandleAsync(simulator, pool, commandCode, ReadOnlyMemory<byte>.Empty, parameters, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTHSIZE, code,
            $"'{commandCode}' tagged TPM_ST_SESSIONS with an authorizationSize below the nine-octet minimum is TPM_RC_AUTHSIZE.");
    }

    /// <summary>
    /// Frames <paramref name="commandCode"/> over a live, owner-bound HMAC session negotiating
    /// <paramref name="symmetric"/> and claiming <paramref name="attributes"/>, and asserts the answer the
    /// command's own parameter shape earns.
    /// </summary>
    /// <param name="commandCode">The zero-handle command under test.</param>
    /// <param name="attributes">The <c>TPMA_SESSION</c> octet the slot carries.</param>
    /// <param name="symmetric">The symmetric definition the session negotiates.</param>
    /// <param name="expectedBaseCode">The expected response code before any session-index encoding.</param>
    /// <param name="blamedSessionIndex">The slot the answer names, or <see cref="NoBlamedSession"/> when it names none.</param>
    /// <param name="rule">The rule under proof, quoted into the assertion message.</param>
    private async Task AssertSessionClaimAnswerAsync(
        TpmCcConstants commandCode, TpmaSession attributes, TpmtSymDef symmetric,
        TpmRcConstants expectedBaseCode, int blamedSessionIndex, string rule)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateSessionRegistry();

        byte[] parameters = ParameterAreaFor(commandCode, pool);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(device, registry, pool, symmetric, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = attributes;
                byte[] authArea = await BuildSessionAuthAreaAsync(session, commandCode, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                TpmRcConstants code = await SubmitZeroHandleAsync(simulator, pool, commandCode, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    ExpectedRc(expectedBaseCode, blamedSessionIndex), code,
                    $"'{commandCode}' over a session claiming '{attributes}': {rule}.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Frames <paramref name="commandCode"/> over a genuine, well-formed HMAC authorization block whose slot
    /// handle field is then overwritten with <paramref name="slotHandle"/>, so the nonce, attributes and hmac
    /// stay exactly as a real session would carry them and only the handle under test differs.
    /// </summary>
    /// <param name="simulator">The simulator the framed octets are submitted to.</param>
    /// <param name="device">The TPM device the session's own lifecycle commands run through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="commandCode">The zero-handle command under test.</param>
    /// <param name="slotHandle">The wire-only substitute for the authorization slot's session handle field.</param>
    /// <returns>The response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> SubmitOverPatchedSlotAsync(
        TpmSimulator simulator, TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, TpmCcConstants commandCode, uint slotHandle)
    {
        byte[] parameters = ParameterAreaFor(commandCode, pool);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(device, registry, pool, TpmtSymDef.Xor(SessionAlg), TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                byte[] authArea = await BuildSessionAuthAreaAsync(session, commandCode, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                BinaryPrimitives.WriteUInt32BigEndian(authArea.AsSpan(0, sizeof(uint)), slotHandle);

                return await SubmitZeroHandleAsync(simulator, pool, commandCode, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Serializes the parameter area of one zero-handle command through its own production input type, so a
    /// refusal in this file is never a malformed body's doing.
    /// </summary>
    /// <param name="commandCode">The zero-handle command whose parameter area is wanted.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parameter area's octets.</returns>
    internal static byte[] ParameterAreaFor(TpmCcConstants commandCode, BaseMemoryPool pool)
    {
        using Tpm2bSensitiveData inData = Tpm2bSensitiveData.Create(StirInData, pool);

        ITpmCommandInput input = commandCode switch
        {
            TpmCcConstants.TPM_CC_StirRandom => new StirRandomInput(inData),
            TpmCcConstants.TPM_CC_TestParms => new TestParmsInput(RsaSigningParms),
            TpmCcConstants.TPM_CC_GetRandom => new GetRandomInput(RandomDrawLength),
            _ => throw new ArgumentOutOfRangeException(nameof(commandCode), commandCode, "Only the three zero-handle commands are framed here.")
        };

        int length = input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Memory<byte> parameters = owner.Memory[..length];
        var writer = new TpmWriter(parameters.Span);
        input.WriteParameters(ref writer);

        return parameters.Span.ToArray();
    }

    /// <summary>
    /// Builds one <c>TPMS_AUTH_COMMAND</c> block over <paramref name="session"/>, its command HMAC computed on
    /// the cpHash a zero-handle command owns: the command code folded with the parameter area and NO Name term,
    /// there being no handle whose Name could enter it (TPM 2.0 Library Part 1, clause 15.7, equation 15).
    /// </summary>
    /// <param name="session">The authorizing session, whose caller nonce this rolls.</param>
    /// <param name="commandCode">The command the HMAC commits to.</param>
    /// <param name="parameters">The parameter area the HMAC commits to.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The block's octets, without the authorizationSize field that precedes them.</returns>
    internal static async Task<byte[]> BuildSessionAuthAreaAsync(TpmSession session, TpmCcConstants commandCode, byte[] parameters, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        int cpHashInputLength = sizeof(uint) + parameters.Length;
        using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
        Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
        {
            var cpHashWriter = new TpmWriter(cpHashInput.Span);
            cpHashWriter.WriteUInt32((uint)commandCode);
            cpHashWriter.WriteBytes(parameters);
        }

        using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            cpHashInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        session.RollNonceCaller(pool);
        using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(
            cpHash.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);

        int blockSize = session.GetAuthCommandSize();
        using IMemoryOwner<byte> blockOwner = pool.Rent(blockSize);
        Memory<byte> block = blockOwner.Memory[..blockSize];
        var writer = new TpmWriter(block.Span);
        session.WriteAuthCommand(ref writer, hmac);

        return block.Span.ToArray();
    }

    /// <summary>
    /// Builds a one-slot authorization block naming <c>TPM_RS_PW</c> with an empty nonce and an empty password —
    /// the password form of <c>TPMS_AUTH_COMMAND</c> (TPM 2.0 Library Part 1, clause 16.6.4.1).
    /// </summary>
    /// <returns>The block's octets, without the authorizationSize field that precedes them.</returns>
    private static byte[] BuildPasswordAuthArea()
    {
        byte[] block = new byte[sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort)];
        BinaryPrimitives.WriteUInt32BigEndian(block.AsSpan(0, sizeof(uint)), (uint)TpmRh.TPM_RH_PW);
        BinaryPrimitives.WriteUInt16BigEndian(block.AsSpan(sizeof(uint), sizeof(ushort)), 0);
        block[sizeof(uint) + sizeof(ushort)] = (byte)TpmaSession.CONTINUE_SESSION;
        BinaryPrimitives.WriteUInt16BigEndian(block.AsSpan(sizeof(uint) + sizeof(ushort) + sizeof(byte), sizeof(ushort)), 0);

        return block;
    }

    /// <summary>
    /// Frames a <c>TPM_ST_SESSIONS</c> command with no handle area — <paramref name="authArea"/> preceded by its
    /// own size, then <paramref name="parameters"/> — and submits it straight to the simulator, bypassing
    /// <see cref="TpmCommandExecutor"/>, whose client-side guards would refuse most of these compositions before
    /// any octet reached the wire.
    /// </summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="commandCode">The command code written into the header.</param>
    /// <param name="authArea">The authorization block, or empty to declare an authorizationSize of zero.</param>
    /// <param name="parameters">The parameter area.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The response code, still carrying any session-index encoding.</returns>
    internal static async Task<TpmRcConstants> SubmitZeroHandleAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmCcConstants commandCode, ReadOnlyMemory<byte> authArea, ReadOnlyMemory<byte> parameters, CancellationToken cancellationToken)
    {
        int length = TpmHeader.HeaderSize + sizeof(uint) + authArea.Length + parameters.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Memory<byte> command = owner.Memory[..length];

        var writer = new TpmWriter(command.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)commandCode);
        header.WriteTo(ref writer);
        writer.WriteUInt32((uint)authArea.Length);
        writer.WriteBytes(authArea.Span);
        writer.WriteBytes(parameters.Span);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a refused command rather than fault.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>
    /// Frames a <c>TPM_ST_SESSIONS</c> command with no handle area — the same wire shape as
    /// <see cref="SubmitZeroHandleAsync"/> — and submits it straight to the simulator, but also returns the raw
    /// response octets alongside the code so an audit digest can be chained from them independently of the codec.
    /// </summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="commandCode">The command code written into the header.</param>
    /// <param name="authArea">The authorization block.</param>
    /// <param name="parameters">The parameter area.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The response code, still carrying any session-index encoding, and the full raw response.</returns>
    internal static async Task<(TpmRcConstants Code, byte[] Response)> SubmitZeroHandleForAuditAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmCcConstants commandCode, ReadOnlyMemory<byte> authArea, ReadOnlyMemory<byte> parameters, CancellationToken cancellationToken)
    {
        int length = TpmHeader.HeaderSize + sizeof(uint) + authArea.Length + parameters.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Memory<byte> command = owner.Memory[..length];

        var writer = new TpmWriter(command.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)commandCode);
        header.WriteTo(ref writer);
        writer.WriteUInt32((uint)authArea.Length);
        writer.WriteBytes(authArea.Span);
        writer.WriteBytes(parameters.Span);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a refused command rather than fault.");

        using TpmResponse response = result.Value;
        byte[] responseBytes = response.AsReadOnlySpan().ToArray();
        var reader = new TpmReader(response.AsReadOnlySpan());

        return ((TpmRcConstants)TpmHeader.Parse(ref reader).Code, responseBytes);
    }

    /// <summary>
    /// Reads the response parameter area out of a captured raw response's octets — the bytes rpHash (TPM 2.0
    /// Library Part 1, clause 15.8, equation 16) is computed over, as actually returned on the wire, independent
    /// of whatever the codec parsed them into.
    /// </summary>
    /// <param name="responseBytes">The raw response octets, tagged <c>TPM_ST_SESSIONS</c>.</param>
    /// <param name="outHandleCount">The number of output handles the response carries before its parameter area.</param>
    /// <returns>The response parameter octets.</returns>
    internal static byte[] ReadResponseParameters(byte[] responseBytes, int outHandleCount)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < outHandleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint parameterSize = reader.ReadUInt32();

        return reader.ReadBytes((int)parameterSize).ToArray();
    }

    /// <summary>
    /// Reads one entry's <c>sessionAttributes</c> octet out of a captured raw response's authorization area — the
    /// octet Table 38's <c>audit</c>/<c>auditExclusive</c>/<c>auditReset</c> echo lands in and the response HMAC
    /// is computed over, walked directly off the wire rather than through any parsed session state.
    /// </summary>
    /// <param name="responseBytes">The raw response octets.</param>
    /// <param name="outHandleCount">The number of output handles preceding the parameter area.</param>
    /// <param name="sessionIndex">The zero-based position, in request order, of the session entry to read.</param>
    /// <returns>The entry's raw <c>sessionAttributes</c> octet.</returns>
    internal static byte ReadResponseSessionAttributes(byte[] responseBytes, int outHandleCount, int sessionIndex)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < outHandleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint parameterSize = reader.ReadUInt32();
        _ = reader.ReadBytes((int)parameterSize);

        byte attributes = 0;
        for(int i = 0; i <= sessionIndex; i++)
        {
            ushort nonceLength = reader.ReadUInt16();
            _ = reader.ReadBytes(nonceLength);
            attributes = reader.ReadByte();
            ushort hmacLength = reader.ReadUInt16();
            _ = reader.ReadBytes(hmacLength);
        }

        return attributes;
    }

    /// <summary>
    /// Reads one entry's freshly rolled <c>nonceTPM</c> octets out of a captured raw response's authorization
    /// area — the value a decrypt or encrypt companion's own parameter-encryption keystream folds as its
    /// response-side context field (TPM 2.0 Library Part 1, clause 18.2), walked directly off the wire.
    /// </summary>
    /// <param name="responseBytes">The raw response octets.</param>
    /// <param name="outHandleCount">The number of output handles preceding the parameter area.</param>
    /// <param name="sessionIndex">The zero-based position, in request order, of the session entry to read.</param>
    /// <returns>The entry's raw <c>nonceTPM</c> octets.</returns>
    internal static byte[] ReadResponseNonceTpm(byte[] responseBytes, int outHandleCount, int sessionIndex)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < outHandleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint parameterSize = reader.ReadUInt32();
        _ = reader.ReadBytes((int)parameterSize);

        byte[] nonceTpm = [];
        for(int i = 0; i <= sessionIndex; i++)
        {
            ushort nonceLength = reader.ReadUInt16();
            nonceTpm = reader.ReadBytes(nonceLength).ToArray();
            _ = reader.ReadByte();
            ushort hmacLength = reader.ReadUInt16();
            _ = reader.ReadBytes(hmacLength);
        }

        return nonceTpm;
    }

    /// <summary>
    /// Reads one entry's raw <c>hmac</c> octets out of a captured raw response's authorization area — the value
    /// the response HMAC verification compares against, walked directly off the wire independent of any session
    /// object's own parsed state.
    /// </summary>
    /// <param name="responseBytes">The raw response octets.</param>
    /// <param name="outHandleCount">The number of output handles preceding the parameter area.</param>
    /// <param name="sessionIndex">The zero-based position, in request order, of the session entry to read.</param>
    /// <returns>The entry's raw <c>hmac</c> octets.</returns>
    internal static byte[] ReadResponseSessionHmac(byte[] responseBytes, int outHandleCount, int sessionIndex)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < outHandleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint parameterSize = reader.ReadUInt32();
        _ = reader.ReadBytes((int)parameterSize);

        byte[] hmac = [];
        for(int i = 0; i <= sessionIndex; i++)
        {
            ushort nonceLength = reader.ReadUInt16();
            _ = reader.ReadBytes(nonceLength);
            _ = reader.ReadByte();
            ushort hmacLength = reader.ReadUInt16();
            hmac = reader.ReadBytes(hmacLength).ToArray();
        }

        return hmac;
    }

    /// <summary>
    /// Computes <c>cpHash = H_sessionAlg(commandCode ‖ parameters)</c> (TPM 2.0 Library Part 1, clause 15.7,
    /// equation 15) for a zero-handle command, whose Name area is empty since no handle enters it, over octets
    /// this test assembled itself from the command it sent.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="parameters">The parameter area as sent.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The cpHash octets.</returns>
    internal static async Task<byte[]> ComputeZeroHandleCpHashAsync(TpmCcConstants commandCode, ReadOnlyMemory<byte> parameters, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        byte[] input = new byte[sizeof(uint) + parameters.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, (uint)commandCode);
        parameters.Span.CopyTo(input.AsSpan(sizeof(uint)));

        return await HashSha256Async(input, pool, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Computes <c>rpHash = H_sessionAlg(TPM_RC_SUCCESS ‖ commandCode ‖ parameters)</c> (TPM 2.0 Library Part 1,
    /// clause 15.8, equation 16) over the response parameter octets as actually read off the wire.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="responseParameters">The response parameter area as read.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The rpHash octets.</returns>
    internal static async Task<byte[]> ComputeRpHashAsync(TpmCcConstants commandCode, ReadOnlyMemory<byte> responseParameters, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        byte[] input = new byte[sizeof(uint) + sizeof(uint) + responseParameters.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, (uint)TpmRcConstants.TPM_RC_SUCCESS);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(sizeof(uint)), (uint)commandCode);
        responseParameters.Span.CopyTo(input.AsSpan(2 * sizeof(uint)));

        return await HashSha256Async(input, pool, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Extends an audit session digest by one round: <c>H(old ‖ cpHash ‖ rpHash)</c>, with the Zero Digest of the
    /// session's hash width standing in for <paramref name="priorDigest"/> on the session's first use as an audit
    /// session (TPM 2.0 Library Part 1, clause 17.1, equation 30).
    /// </summary>
    /// <param name="priorDigest">The digest before this extend, or <see langword="null"/> on first use.</param>
    /// <param name="cpHash">The audited command's cpHash.</param>
    /// <param name="rpHash">The audited command's rpHash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The extended digest.</returns>
    internal static async Task<byte[]> ExtendAuditDigestAsync(byte[]? priorDigest, byte[] cpHash, byte[] rpHash, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        byte[] old = priorDigest ?? new byte[Sha256DigestSize];
        byte[] input = new byte[old.Length + cpHash.Length + rpHash.Length];
        old.CopyTo(input, 0);
        cpHash.CopyTo(input, old.Length);
        rpHash.CopyTo(input, old.Length + cpHash.Length);

        return await HashSha256Async(input, pool, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Computes a raw SHA-256 digest over <paramref name="input"/> through the project's own digest primitive.</summary>
    /// <param name="input">The octets to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The digest octets.</returns>
    internal static async Task<byte[]> HashSha256Async(ReadOnlyMemory<byte> input, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Starts a bound, unsalted HMAC session against <c>TPM_RH_OWNER</c> — a permanent entity, so its
    /// factory-empty authValue needs no installation and the bind lends the session no dictionary-attack
    /// protection — negotiating <paramref name="symmetric"/> and thereby earning a non-empty session key for its
    /// command HMAC (TPM 2.0 Library Part 1, clause 16.6.10, equation 20).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="symmetric">The symmetric definition to negotiate.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The started session handle and its client-side wrapper.</returns>
    internal static async Task<(uint Handle, TpmSession Session)> StartOwnerBoundSessionAsync(
        TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtSymDef symmetric, CancellationToken cancellationToken)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession((uint)TpmRh.TPM_RH_OWNER, SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to TPM_RH_OWNER) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(startResponse.SessionHandle.Value), ReadOnlyMemory<byte>.Empty, startInput.NonceCaller,
            startResponse.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric: symmetric, cancellationToken: cancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (startResponse.SessionHandle.Value, session);
    }

    /// <summary>
    /// Starts an unbound, unsalted session negotiating <paramref name="symmetric"/> — a companion slot's own
    /// shape, since none of <c>TPM2_GetRandom()</c>, <c>TPM2_StirRandom()</c> or <c>TPM2_TestParms()</c> has a
    /// handle for any slot to authorize.
    /// </summary>
    /// <remarks>
    /// <paramref name="sessionType"/> selects the underlying TPM session's own type (HMAC by default, or POLICY
    /// for a policy companion proof); the returned <see cref="TpmSession"/> wrapper is otherwise identical either
    /// way, because its own wire math (the command/response HMAC and the parameter-encryption keystream) reads
    /// only the session's raw handle value and negotiated <see cref="Symmetric"/> definition, never the handle's
    /// type octet — an unbound, unsalted session's key is the shared Empty Buffer regardless of kind (TPM 2.0
    /// Library Part 3, clause 11.1.1: "For all session types, this command will cause initialization of the
    /// sessionKey"; Part 1, clause 18: "If the session is not being used for authorization, sessionValue is
    /// sessionKey"), so a POLICY companion's wire bytes are byte-identical in form to an HMAC companion's over
    /// the same nonces and symmetric definition.
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <param name="symmetric">The symmetric definition to negotiate — <see cref="TpmtSymDef.Null"/> when a caller never claims <c>decrypt</c> or <c>encrypt</c> over this session.</param>
    /// <param name="sessionType">The session type to start — <see cref="TpmSeConstants.TPM_SE_HMAC"/> for an HMAC companion, <see cref="TpmSeConstants.TPM_SE_POLICY"/> for a policy companion.</param>
    /// <returns>The started session handle and its client-side wrapper.</returns>
    internal static async Task<(uint Handle, TpmSession Session)> StartUnboundSessionAsync(
        TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, CancellationToken cancellationToken, TpmtSymDef? symmetric = null,
        TpmSeConstants sessionType = TpmSeConstants.TPM_SE_HMAC)
    {
        StartAuthSessionInput startInput = sessionType == TpmSeConstants.TPM_SE_HMAC
            ? StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric)
            : new StartAuthSessionInput
            {
                TpmKey = (uint)TpmRh.TPM_RH_NULL,
                Bind = (uint)TpmRh.TPM_RH_NULL,
                NonceCaller = RandomNumberGenerator.GetBytes(Sha256DigestSize),
                EncryptedSalt = ReadOnlyMemory<byte>.Empty,
                SessionType = sessionType,
                AuthHash = SessionAlg,
                Symmetric = symmetric ?? TpmtSymDef.Null
            };

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        var session = new TpmSession(new TpmHandle(startResponse.SessionHandle.Value), startResponse.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric)
        {
            SessionAttributes = TpmaSession.CONTINUE_SESSION
        };

        return (startResponse.SessionHandle.Value, session);
    }

    /// <summary>Flushes <paramref name="handle"/> if it names a started session, releasing the simulator-side context.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The session handle, or zero when no session was started.</param>
    internal static async Task FlushIfPresentAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            device, FlushContextInput.ForHandle(handle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
    }

    /// <summary>
    /// The response code a case expects: <paramref name="baseRc"/> as it stands when the answer names no slot,
    /// or session-index-encoded to <paramref name="blamedSessionIndex"/> when it does.
    /// </summary>
    /// <param name="baseRc">The base response code.</param>
    /// <param name="blamedSessionIndex">The blamed slot's zero-based index, or <see cref="NoBlamedSession"/>.</param>
    /// <returns>The expected response code.</returns>
    private static TpmRcConstants ExpectedRc(TpmRcConstants baseRc, int blamedSessionIndex) =>
        blamedSessionIndex == NoBlamedSession ? baseRc : SessionEncodedRc(baseRc, blamedSessionIndex);

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)) — a local mirror of the production session-index encoding, transcribed
    /// independently here since the production helper is private.
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    internal static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>
    /// Builds the digest <see cref="Tag"/> used to independently compute cpHash: SHA-256 digest, raw encoding,
    /// direct material — the same shape <c>TpmCommandExecutor</c>'s own cpHash computation uses.
    /// </summary>
    /// <returns>The digest tag.</returns>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    /// <summary>Creates the response codec registry for the session lifecycle commands these tests drive.</summary>
    /// <returns>The registry.</returns>
    internal static TpmResponseRegistry CreateSessionRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>
    /// Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational
    /// phase — the precondition all three commands carry. Shared with
    /// <see cref="Verifiable.Tests.Tpm.TpmInHouseSimulatorNoAuthSessionTests"/>, which extends this class's
    /// hand-framing fixture for the generic no-authorization mechanism's own tests.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The operational simulator.</returns>
    internal static async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        var simulator = new TpmSimulator("tpm-in-house-zero-handle-session", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(cancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitStartupAsync(simulator, pool, new StartupInput(TpmSuConstants.TPM_SU_CLEAR), cancellationToken).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }

    /// <summary>Frames <c>TPM2_Startup()</c> directly to the simulator, sessionless, and returns its response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The startup command input.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The response code.</returns>
    private static async Task<TpmRcConstants> SubmitStartupAsync(TpmSimulator simulator, BaseMemoryPool pool, StartupInput input, CancellationToken cancellationToken)
    {
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The transport itself must succeed.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }
}
