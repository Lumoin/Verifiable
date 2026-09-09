using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_StirRandom()</c> over a <c>decrypt</c>-attributed authorization session against the in-house
/// behavioural <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same
/// production command path the production code uses (<see cref="TpmCommandExecutor"/>, <see cref="TpmSession"/>
/// and the real command/response codecs), and over the raw wire where the executor's own client-side guard would
/// refuse the composition first. The proof that the PLAINTEXT reaches the RNG reseed state is twin equality: a
/// simulator stirred over an XOR or AES-CFB decrypt session draws exactly the octets a twin stirred with the same
/// plaintext in the sessionless form draws, while a twin stirred with a different plaintext draws different
/// octets. TPM 2.0 Library Part 3, clauses 16.2, 5.5, 5.6 and 5.7; Part 1, clauses 8.4.11.2, 15.7, 16.8.1 and 18.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorStirRandomOverSessionTests
{
    /// <summary>The hash algorithm every session these tests compose negotiates.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The SHA-256 digest width, in octets — the cpHash width and the session nonce width used here.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The octet count every twin comparison draws from the RNG after its stir.</summary>
    private const ushort DrawLength = 32;

    /// <summary>The declared data size of the Ordinary Index this file defines as a bind target.</summary>
    private const ushort OrdinaryDataSize = 16;

    /// <summary>The dictionary-attack-PROTECTED Ordinary Index used as a bind target and as the lockout driver.</summary>
    private const uint DaProtectedBindIndexHandle = 0x0100_0110;

    /// <summary>Dictionary-attack-protected Ordinary Index attributes: <c>TPMA_NV_NO_DA</c> is CLEAR.</summary>
    private const TpmaNv DaProtectedAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>The Index authorization value used throughout.</summary>
    private static byte[] CorrectIndexAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong authorization value, distinct from <see cref="CorrectIndexAuth"/>.</summary>
    private static byte[] WrongIndexAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>The octets written into the Index that drives the TPM into Lockout mode.</summary>
    private static byte[] PrimingWriteData { get; } = [0x2A];

    /// <summary>The additional input every stir under test folds into the RNG reseed state.</summary>
    private static byte[] StirPlaintext { get; } =
        [0x53, 0x74, 0x69, 0x72, 0x20, 0x69, 0x6E, 0x70, 0x75, 0x74, 0x20, 0x41, 0x00, 0xFF, 0x10, 0x20];

    /// <summary>A different additional input, one octet apart from <see cref="StirPlaintext"/>.</summary>
    private static byte[] AlternateStirPlaintext { get; } =
        [0x53, 0x74, 0x69, 0x72, 0x20, 0x69, 0x6E, 0x70, 0x75, 0x74, 0x20, 0x42, 0x00, 0xFF, 0x10, 0x20];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "This command is used to add additional entropy to the RNG state." over an XOR decrypt session: "the TPM
    /// will decrypt the parameter using the values associated with the session before parsing parameters", so
    /// what reaches the RNG is <c>inData</c>'s PLAINTEXT and not the octets that travelled the wire. Proven by
    /// twin equality — the stirred-over-session simulator's next draw equals a sessionless twin's stirred with
    /// the same plaintext — and made non-vacuous by a third twin stirred with a different plaintext, whose draw
    /// differs, so the equality is content-sensitive and ciphertext reaching the RNG could not produce it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 16.2.1 and 5.7; Part 1, clauses 8.4.11.2 and 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task XorEncryptedStirRandomOverADecryptSessionReachesTheRngAsPlaintext()
    {
        await AssertPlaintextReachesTheRngAsync(TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
    }

    /// <summary>
    /// The same rule over the AES-CFB channel, whose ciphertext is unrelated to the XOR channel's and to the
    /// plaintext alike: the stirred-over-session simulator's next draw still equals the sessionless twin's
    /// stirred with the same plaintext, and differs from the twin stirred with another plaintext.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 16.2.1 and 5.7; Part 1, clauses 18.1 and 18.3</see>.
    /// </summary>
    [TestMethod]
    public async Task AesCfbEncryptedStirRandomOverADecryptSessionReachesTheRngAsPlaintext()
    {
        await AssertPlaintextReachesTheRngAsync(TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)).ConfigureAwait(false);
    }

    /// <summary>
    /// Table 78 is the header alone, so the accepted session form answers <c>TPM_ST_SESSIONS</c> with
    /// <c>parameterSize</c> zero and exactly ONE response authorization entry — the lone companion slot's, whose
    /// response HMAC the production <see cref="TpmSession"/> verifies before this test ever sees a success.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 16.2.2, Table 78; Part 1, clauses 15.6.1 and 16.6</see>.
    /// </summary>
    [TestMethod]
    public async Task StirRandomOverADecryptSessionAnswersSuccessWithNoParametersAndOneResponseEntry()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[]? capturedResponse = null;
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken cancellationToken)
        {
            TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, commandPool, cancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                capturedResponse = result.Value.AsReadOnlySpan().ToArray();
            }

            return result;
        }

        using TpmDevice device = TpmDevice.Create(CaptureAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateStirRegistry();

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(device, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                TpmResult<StirRandomResponse> result = await StirOverSessionAsync(device, registry, pool, session, StirPlaintext).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_StirRandom() over a decrypt session failed: '{result.ResponseCode}'.");

                Assert.IsNotNull(capturedResponse, "The capturing transport must have observed the response octets.");

                var reader = new TpmReader(capturedResponse);
                TpmHeader header = TpmHeader.Parse(ref reader);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)header.Code, "The accepted session form answers TPM_RC_SUCCESS.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_SESSIONS, header.Tag, "A response carrying an authorization area is tagged TPM_ST_SESSIONS.");

                uint parameterSize = reader.ReadUInt32();
                Assert.AreEqual(0u, parameterSize, "Table 78 defines no response parameter, so parameterSize is zero.");

                var entries = new List<int>();
                while(reader.Remaining > 0)
                {
                    entries.Add(reader.Consumed);

                    ushort nonceSize = reader.ReadUInt16();
                    reader.Skip(nonceSize);
                    _ = reader.ReadByte();
                    ushort hmacSize = reader.ReadUInt16();
                    reader.Skip(hmacSize);
                }

                Assert.HasCount(1, entries, "The lone companion slot owes exactly one response authorization entry.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_StirRandom()</c> carries no <c>@</c>-decorated handle, so its lone session authorizes no entity
    /// and its command HMAC is keyed on the session key alone: a tampered HMAC is therefore the non-charging
    /// <c>TPM_RC_BAD_AUTH</c>, session-index-encoded to the offending slot, and <c>TPM_PT_LOCKOUT_COUNTER</c>
    /// does not move — "the authValue associated with a permanent entity, other than TPM_RH_LOCKOUT, does not
    /// receive DA protection", and here no entity was authorized at all.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 16.2.2 and 5.6; Part 1, clauses 16.6 and 16.8.1; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task StirRandomOverADecryptSessionWithATamperedHmacReturnsSessionEncodedBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateStirRegistry();

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(device, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                async ValueTask<TpmResult<TpmResponse>> TamperAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken cancellationToken)
                {
                    byte[] mutable = command.ToArray();
                    TamperLastHmacOctet(mutable);

                    return await simulator.SubmitAsync(mutable, commandPool, cancellationToken).ConfigureAwait(false);
                }

                using TpmDevice tamperingDevice = TpmDevice.Create(TamperAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

                TpmResult<StirRandomResponse> result = await StirOverSessionAsync(tamperingDevice, registry, pool, session, StirPlaintext).ConfigureAwait(false);

                Assert.IsFalse(result.IsSuccess, "A tampered command HMAC must be rejected.");
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
                    "TPM2_StirRandom() authorizes no entity, so a tampered HMAC is the session-index-encoded TPM_RC_BAD_AUTH.");

                uint counterAfter = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);
                Assert.AreEqual(counterBefore, counterAfter, "A refusal that authorizes no entity never charges failedTries.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "The inData parameter may not be larger than 128 octets." judged on the PLAINTEXT: the ciphertext a
    /// decrypt session carries is exactly as wide as its plaintext ("the encrypted data size and the plain-text
    /// data size is the same"), so a 129-octet body passes the frame's own structural reads and is refused only
    /// once the decrypt step has recovered it and the parameter core runs — a structural failure of
    /// <c>inData</c> itself, <c>TPM2_StirRandom()</c>'s sole parameter (Table 77, index 0), so it is
    /// parameter-encoded, passed through the decrypt continuation unchanged rather than blamed on the claiming
    /// slot (TPM 2.0 Library Part 2, clause 6.6.2, Table 15's closing sentence: a code is designated once). Hand-
    /// framed, because the host carrier refuses to hold 129 octets at all. The refusal fires AFTER the
    /// session's own request-decryption transform has already run the keystream over the raw parameter area in
    /// place, so this is the one refusal class where a partially-transformed buffer is in flight when the
    /// command is rejected: "When an error is encountered while unmarshaling a command parameter, an error
    /// response code is returned, and no command processing occurs." (clause 5.8.2) means no
    /// <c>TPM2_StirRandom()</c> effect ever declares, so the RNG stream a later draw sees is byte-identical to a
    /// twin that never issued the refused stir.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 16.2.1, 5.7 and 5.8.2; Part 2, clause 11.1.13, Table 169; clause 6.6.2, Table 15; Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task StirRandomOverADecryptSessionWithA129OctetPlaintextReturnsParameterEncodedSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateStirRegistry();

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(device, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                byte[] oversizedPlaintext = new byte[Tpm2bSensitiveData.MaxSize + 1];
                for(int i = 0; i < oversizedPlaintext.Length; i++)
                {
                    oversizedPlaintext[i] = (byte)(i + 1);
                }

                byte[] framed = await FrameStirRandomOverSessionAsync(session, oversizedPlaintext, pool).ConfigureAwait(false);
                TpmRcConstants code = await SubmitRawAsync(simulator, pool, framed).ConfigureAwait(false);

                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, parameterIndex: 0), code,
                    "A recovered inData wider than 128 octets is TPM_RC_SIZE designated to inData itself (Table 77, index 0), not to the slot that claimed decrypt.");

                byte[] refusedDraw = await DrawRandomAsync(device, registry, pool).ConfigureAwait(false);
                byte[] unstirredTwinDraw = await DrawFromAnUnstirredTwinAsync(TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);

                Assert.AreSequenceEqual(
                    unstirredTwinDraw, refusedDraw,
                    "A post-decrypt-step refusal must still leave the RNG stream exactly where an unstirred twin's stands, since no TPM2_StirRandom() effect ever declares on this path.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Builds a fresh operational simulator with an owner-bound session negotiating <paramref name="symmetric"/>
    /// — the same RNG-consuming command history <see cref="StirRandomOverADecryptSessionWithA129OctetPlaintextReturnsParameterEncodedSize"/>
    /// runs, minus the refused stir itself — and returns the octets its next <c>TPM2_GetRandom()</c> draws: the
    /// unstirred twin's same-ordinal draw.
    /// </summary>
    /// <param name="symmetric">The symmetric definition the twin's session negotiates, matching the refused arm's.</param>
    /// <returns>The octets drawn.</returns>
    private async Task<byte[]> DrawFromAnUnstirredTwinAsync(TpmtSymDef symmetric)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateStirRegistry();

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(device, registry, pool, symmetric).ConfigureAwait(false);
        try
        {
            using(session)
            {
                return await DrawRandomAsync(device, registry, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If the entity is authorized in a bind session, it receives DA protection if the bind entity receives DA
    /// protection" — a session bound to a dictionary-attack-protected NV Index carries that protection into the
    /// command it authorizes, so while the TPM is in Lockout mode the stir is refused with the format-zero
    /// <c>TPM_RC_LOCKOUT</c> before any HMAC is evaluated.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 16.2; Part 1, clauses 16.8.1 and 16.8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task StirRandomOverASessionBoundToADaProtectedIndexInLockoutModeReturnsLockout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateStirRegistry();

        await DriveIntoLockoutAsync(device, pool, registry).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> lockedOut = await device.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lockedOut.IsSuccess, $"Reading the dictionary-attack parameters failed: '{lockedOut.ResponseCode}'.");
        Assert.IsTrue(lockedOut.Value.IsLockedOut, "The arrangement must leave the TPM in Lockout mode, or the case proves nothing.");

        (uint sessionHandle, TpmSession session) = await StartBoundSessionAsync(
            device, registry, pool, DaProtectedBindIndexHandle, CorrectIndexAuth, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                TpmResult<StirRandomResponse> result = await StirOverSessionAsync(device, registry, pool, session, StirPlaintext).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode,
                    "A bind entity that receives DA protection lends it to the command, which Lockout mode refuses with the format-zero TPM_RC_LOCKOUT.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "For a response, the TPM uses the last nonceCaller and a newly generated nonceTPM in the HMAC." — and an
    /// error answer is the header alone, which carries no response authorization and therefore rolls nothing: a
    /// second stir on the same session succeeds after a success, proving both sides rolled together, and a third
    /// succeeds after a REFUSAL, proving the refusal rolled no <c>nonceTPM</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 16.2; Part 1, clause 16.6.3</see>.
    /// </summary>
    [TestMethod]
    public async Task StirRandomOverADecryptSessionRollsTheNonceOnSuccessAndNotOnARefusal()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateStirRegistry();

        async ValueTask<TpmResult<TpmResponse>> TamperAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken cancellationToken)
        {
            byte[] mutable = command.ToArray();
            TamperLastHmacOctet(mutable);

            return await simulator.SubmitAsync(mutable, commandPool, cancellationToken).ConfigureAwait(false);
        }

        using TpmDevice tamperingDevice = TpmDevice.Create(TamperAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(device, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                TpmResult<StirRandomResponse> first = await StirOverSessionAsync(device, registry, pool, session, StirPlaintext).ConfigureAwait(false);
                Assert.IsTrue(first.IsSuccess, $"The first stir over the session failed: '{first.ResponseCode}'.");

                TpmResult<StirRandomResponse> second = await StirOverSessionAsync(device, registry, pool, session, StirPlaintext).ConfigureAwait(false);
                Assert.IsTrue(
                    second.IsSuccess,
                    $"A second stir on the same session must succeed, which only a nonce rolled on BOTH sides of the first success allows: '{second.ResponseCode}'.");

                TpmResult<StirRandomResponse> refused = await StirOverSessionAsync(tamperingDevice, registry, pool, session, StirPlaintext).ConfigureAwait(false);
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), refused.ResponseCode,
                    "A tampered command HMAC is the session-encoded, non-charging TPM_RC_BAD_AUTH.");

                TpmResult<StirRandomResponse> afterRefusal = await StirOverSessionAsync(device, registry, pool, session, StirPlaintext).ConfigureAwait(false);
                Assert.IsTrue(
                    afterRefusal.IsSuccess,
                    $"A header-only refusal carries no response authorization and rolls no nonceTPM, so the next stir must still verify: '{afterRefusal.ResponseCode}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If the symmetric algorithm is TPM_ALG_NULL and encryption or decryption is specified, the TPM returns
    /// TPM_RC_SYMMETRIC." — the executor is the client-side half of that rule and refuses the composition with
    /// an <see cref="ArgumentException"/> before any octet reaches the wire, so a caller cannot emit a request
    /// whose response path it could not interpret.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 5.7</see>.
    /// </summary>
    [TestMethod]
    public async Task StirRandomOverADecryptSessionWithANullSymmetricIsRefusedByTheExecutor()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateStirRegistry();

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(device, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using Tpm2bSensitiveData inData = Tpm2bSensitiveData.Create(StirPlaintext, pool);
                var input = new StirRandomInput(inData);

                _ = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
                    await TpmCommandExecutor.ExecuteAsync<StirRandomResponse>(
                        device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The session form returns every carrier its parse rented — the raw parameter area carrying the ciphertext
    /// and the authorization slot's own nonce and hmac credentials — across a refusal at the command HMAC and a
    /// success whose decrypt step rents the recovered <c>inData</c> as well. A refusal returns to the baseline
    /// exactly; a success returns to the baseline plus the ONE carrier the reseeded RNG state itself occupies,
    /// which "is executed" leaves standing until the next stir replaces it, and a second success replaces rather
    /// than accumulates it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 16.2, 5.6 and 5.7; Part 1, clause 8.4.11.2</see>.
    /// </summary>
    [TestMethod]
    public async Task StirRandomOverADecryptSessionReturnsItsCarriersAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateStirRegistry();

        async ValueTask<TpmResult<TpmResponse>> TamperAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken cancellationToken)
        {
            byte[] mutable = command.ToArray();
            TamperLastHmacOctet(mutable);

            return await simulator.SubmitAsync(mutable, commandPool, cancellationToken).ConfigureAwait(false);
        }

        using TpmDevice tamperingDevice = TpmDevice.Create(TamperAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(device, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                long baseline = trackingPool.OutstandingCount;

                TpmResult<StirRandomResponse> refused = await StirOverSessionAsync(tamperingDevice, registry, pool, session, StirPlaintext).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, refused.BaseError, "The arrangement must refuse at the command HMAC.");
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A command refused at its command HMAC releases every carrier its parse rented.");

                TpmResult<StirRandomResponse> accepted = await StirOverSessionAsync(device, registry, pool, session, StirPlaintext).ConfigureAwait(false);
                Assert.IsTrue(accepted.IsSuccess, $"TPM2_StirRandom() over a decrypt session failed: '{accepted.ResponseCode}'.");
                Assert.AreEqual(
                    baseline + 1, trackingPool.OutstandingCount,
                    "The decrypt step, the stir effect and the response framing release every carrier but the one the reseeded RNG state itself occupies.");

                TpmResult<StirRandomResponse> secondAccepted = await StirOverSessionAsync(device, registry, pool, session, AlternateStirPlaintext).ConfigureAwait(false);
                Assert.IsTrue(secondAccepted.IsSuccess, $"A second TPM2_StirRandom() over the same session failed: '{secondAccepted.ResponseCode}'.");
                Assert.AreEqual(
                    baseline + 1, trackingPool.OutstandingCount,
                    "A later stir replaces the retained reseed state rather than accumulating a second carrier alongside it.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The twin comparison both round-trip cases share: a simulator stirred over a <paramref name="symmetric"/>
    /// decrypt session draws exactly what a sessionless twin stirred with the same plaintext draws, and not what
    /// a twin stirred with a different plaintext draws.
    /// </summary>
    /// <param name="symmetric">The symmetric definition the decrypt session negotiates.</param>
    private async Task AssertPlaintextReachesTheRngAsync(TpmtSymDef symmetric)
    {
        byte[] overSession = await StirOverSessionThenDrawAsync(symmetric, StirPlaintext).ConfigureAwait(false);
        byte[] sameInputTwin = await StirSessionlesslyThenDrawAsync(symmetric, StirPlaintext).ConfigureAwait(false);
        byte[] otherInputTwin = await StirSessionlesslyThenDrawAsync(symmetric, AlternateStirPlaintext).ConfigureAwait(false);

        Assert.IsTrue(
            overSession.AsSpan().SequenceEqual(sameInputTwin),
            $"A stir over a '{symmetric.Algorithm}' decrypt session must reseed with the same octets the sessionless form reseeds with, which only the decrypted PLAINTEXT reaching the RNG produces.");

        Assert.IsFalse(
            overSession.AsSpan().SequenceEqual(otherInputTwin),
            "A twin stirred with different additional input must draw differently, or the equality above would hold for any input and prove nothing.");
    }

    /// <summary>
    /// Runs the session arm of the twin comparison: an owner-bound session negotiating
    /// <paramref name="symmetric"/>, one <c>decrypt</c>-attributed <c>TPM2_StirRandom()</c> carrying
    /// <paramref name="plaintext"/>, then one sessionless draw.
    /// </summary>
    /// <param name="symmetric">The symmetric definition the decrypt session negotiates.</param>
    /// <param name="plaintext">The additional input, encrypted client-side by the executor.</param>
    /// <returns>The octets drawn after the stir.</returns>
    private async Task<byte[]> StirOverSessionThenDrawAsync(TpmtSymDef symmetric, byte[] plaintext)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateStirRegistry();

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(device, registry, pool, symmetric).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                TpmResult<StirRandomResponse> stirred = await StirOverSessionAsync(device, registry, pool, session, plaintext).ConfigureAwait(false);
                Assert.IsTrue(stirred.IsSuccess, $"TPM2_StirRandom() over a '{symmetric.Algorithm}' decrypt session failed: '{stirred.ResponseCode}'.");

                return await DrawRandomAsync(device, registry, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Runs the sessionless arm of the twin comparison over the identical command history: the same owner-bound
    /// session is started, so the session arm's own <c>TPM2_StartAuthSession()</c> draw has its counterpart here;
    /// <paramref name="plaintext"/> is stirred in the plain <c>TPM_ST_NO_SESSIONS</c> form; and one draw is
    /// discarded to stand for the response nonce the session arm's framing draws before its own final draw.
    /// </summary>
    /// <param name="symmetric">The symmetric definition the session negotiates, matching the session arm's.</param>
    /// <param name="plaintext">The additional input, sent in the clear.</param>
    /// <returns>The octets drawn after the stir.</returns>
    private async Task<byte[]> StirSessionlesslyThenDrawAsync(TpmtSymDef symmetric, byte[] plaintext)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateStirRegistry();

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(device, registry, pool, symmetric).ConfigureAwait(false);
        try
        {
            using(session)
            {
                using Tpm2bSensitiveData inData = Tpm2bSensitiveData.Create(plaintext, pool);
                var input = new StirRandomInput(inData);

                TpmResult<StirRandomResponse> stirred = await TpmCommandExecutor.ExecuteAsync<StirRandomResponse>(
                    device, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(stirred.IsSuccess, $"The sessionless TPM2_StirRandom() failed: '{stirred.ResponseCode}'.");

                _ = await DrawRandomAsync(device, registry, pool).ConfigureAwait(false);

                return await DrawRandomAsync(device, registry, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>Issues one <c>decrypt</c>-attributed <c>TPM2_StirRandom()</c> over <paramref name="session"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The authorizing session, which carries the decrypt attribute.</param>
    /// <param name="plaintext">The additional input the executor encrypts client-side.</param>
    /// <returns>The stir result.</returns>
    private async Task<TpmResult<StirRandomResponse>> StirOverSessionAsync(
        TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSession session, byte[] plaintext)
    {
        using Tpm2bSensitiveData inData = Tpm2bSensitiveData.Create(plaintext, pool);
        var input = new StirRandomInput(inData);

        return await TpmCommandExecutor.ExecuteAsync<StirRandomResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Draws <see cref="DrawLength"/> octets with a sessionless <c>TPM2_GetRandom()</c>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The drawn octets.</returns>
    private async Task<byte[]> DrawRandomAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        var input = new GetRandomInput(DrawLength);

        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_GetRandom() failed: '{result.ResponseCode}'.");

        using GetRandomResponse response = result.Value;

        return response.RandomBytes.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Hand-frames a <c>decrypt</c>-attributed <c>TPM2_StirRandom()</c> whose <c>inData</c> body is
    /// <paramref name="plaintext"/>, encrypted with the session's own keystream through the production
    /// <see cref="TpmSessionBase.EncryptFirstParameterAsync"/> and authorized by a genuine command HMAC over
    /// cpHash — the command code folded with the ciphertext parameter area and no Name term, this command
    /// having no handle (TPM 2.0 Library Part 1, clause 15.7, equation 15).
    /// </summary>
    /// <param name="session">The authorizing session, whose caller nonce this rolls.</param>
    /// <param name="plaintext">The additional input, of any width the caller wants to place on the wire.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The exact octets to submit.</returns>
    private async Task<byte[]> FrameStirRandomOverSessionAsync(TpmSession session, byte[] plaintext, BaseMemoryPool pool)
    {
        int parametersLength = sizeof(ushort) + plaintext.Length;
        using IMemoryOwner<byte> parametersOwner = pool.Rent(parametersLength);
        Memory<byte> parameters = parametersOwner.Memory[..parametersLength];
        BinaryPrimitives.WriteUInt16BigEndian(parameters.Span[..sizeof(ushort)], (ushort)plaintext.Length);
        plaintext.CopyTo(parameters.Span[sizeof(ushort)..]);

        session.RollNonceCaller(pool);
        await session.EncryptFirstParameterAsync(parameters[sizeof(ushort)..], pool, TestContext.CancellationToken).ConfigureAwait(false);

        int cpHashInputLength = sizeof(uint) + parametersLength;
        using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
        Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
        {
            var cpHashWriter = new TpmWriter(cpHashInput.Span);
            cpHashWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_StirRandom);
            cpHashWriter.WriteBytes(parameters.Span);
        }

        using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            cpHashInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(
            cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        int authAreaSize = sizeof(uint) + session.GetAuthCommandSize();
        int totalSize = TpmHeader.HeaderSize + authAreaSize + parametersLength;

        using IMemoryOwner<byte> commandOwner = pool.Rent(totalSize);
        Memory<byte> command = commandOwner.Memory[..totalSize];
        var writer = new TpmWriter(command.Span);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
        writer.WriteUInt32((uint)totalSize);
        writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_StirRandom);
        writer.WriteUInt32((uint)session.GetAuthCommandSize());
        session.WriteAuthCommand(ref writer, hmac);
        writer.WriteBytes(parameters.Span);

        return command.Span.ToArray();
    }

    /// <summary>
    /// Flips every bit of the LAST octet of an authorization slot's <c>hmac</c> field, navigating to it from the
    /// front of the frame so the offset follows the actual nonce and hmac widths rather than a guess about the
    /// trailing parameter area.
    /// </summary>
    /// <param name="command">The framed command, mutated in place.</param>
    private static void TamperLastHmacOctet(byte[] command)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        _ = reader.ReadUInt32();
        _ = reader.ReadUInt32();

        ushort nonceSize = reader.ReadUInt16();
        reader.Skip(nonceSize);
        _ = reader.ReadByte();

        ushort hmacSize = reader.ReadUInt16();
        Assert.IsGreaterThan(0, hmacSize, "The arrangement must carry a non-empty hmac for the tamper to change one.");

        int lastHmacOctet = reader.Consumed + hmacSize - 1;
        command[lastHmacOctet] ^= 0xFF;
    }

    /// <summary>Submits raw, hand-framed octets straight to the simulator and returns the unwrapped response code.</summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="command">The exact octets to submit.</param>
    /// <returns>The response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> SubmitRawAsync(TpmSimulator simulator, BaseMemoryPool pool, byte[] command)
    {
        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The transport itself must succeed even when the TPM refuses the command.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>
    /// Starts an HMAC session bound to <c>TPM_RH_OWNER</c> — a permanent entity, so its factory-empty authValue
    /// needs no installation and the bind lends the session no dictionary-attack protection — negotiating
    /// <paramref name="symmetric"/> for parameter encryption.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="symmetric">The symmetric definition to negotiate.</param>
    /// <returns>The started session handle and its client-side wrapper.</returns>
    private async Task<(uint Handle, TpmSession Session)> StartOwnerBoundSessionAsync(
        TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtSymDef symmetric)
    {
        return await StartBoundSessionAsync(device, registry, pool, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, symmetric).ConfigureAwait(false);
    }

    /// <summary>
    /// Starts a bound, unsalted HMAC session against <paramref name="bindHandle"/> through the production
    /// <c>TPM2_StartAuthSession()</c> path, deriving the client-side session key from
    /// <paramref name="bindAuthValue"/> (TPM 2.0 Library Part 1, clause 16.6.10, equation 20).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="bindHandle">The entity to bind to.</param>
    /// <param name="bindAuthValue">The bind entity's authValue fed into the session-key KDFa.</param>
    /// <param name="symmetric">The symmetric definition to negotiate.</param>
    /// <returns>The started session handle and its client-side wrapper.</returns>
    private async Task<(uint Handle, TpmSession Session)> StartBoundSessionAsync(
        TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, uint bindHandle, ReadOnlyMemory<byte> bindAuthValue, TpmtSymDef symmetric)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(bindHandle, SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to 0x{bindHandle:X8}) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(startResponse.SessionHandle.Value), bindAuthValue, startInput.NonceCaller,
            startResponse.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric: symmetric, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (startResponse.SessionHandle.Value, session);
    }

    /// <summary>
    /// Lowers <c>maxTries</c> to one and drives the TPM into Lockout mode with a single wrong-password write
    /// against the freshly defined dictionary-attack-protected Index the caller then binds a session to.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    private async Task DriveIntoLockoutAsync(TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry)
    {
        const uint LoweredMaxTries = 1;

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        await DefineIndexAsync(device, pool, registry, DaProtectedBindIndexHandle, DaProtectedAttributes).ConfigureAwait(false);

        TpmResult<NvWriteResponse> wrongResult = await WriteIndexAsync(
            device, pool, registry, DaProtectedBindIndexHandle, WrongIndexAuth, PrimingWriteData).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode,
            "The priming write must fail and count, taking the TPM into Lockout mode.");
    }

    /// <summary>
    /// Issues <c>TPM2_NV_DefineSpace()</c> for <paramref name="nvIndex"/> with <see cref="CorrectIndexAuth"/> as
    /// the Index authValue, authorized by the factory-empty owner authValue over a password session.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    private async Task DefineIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);

        using var auth = Tpm2bAuth.Create(CorrectIndexAuth, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, OrdinaryDataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace(0x{nvIndex:X8}) failed: '{result.ResponseCode}'.");
    }

    /// <summary>Issues an Index-arm <c>TPM2_NV_Write()</c> at offset zero over a password session.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to write, which also authorizes the write.</param>
    /// <param name="suppliedAuth">The authorization value supplied for the Index.</param>
    /// <param name="data">The octets to store.</param>
    /// <returns>The write result.</returns>
    private async Task<TpmResult<NvWriteResponse>> WriteIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ReadOnlyMemory<byte> data)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(data.Span, pool);
        var input = new NvWriteInput(nvIndex, nvIndex, buffer, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads <c>TPM_PT_LOCKOUT_COUNTER</c>, the live <c>failedTries</c> value, back over <c>TPM2_GetCapability()</c>.</summary>
    /// <param name="device">The device the capability is read through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The reported counter value.</returns>
    private async Task<uint> ReadLockoutCounterAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        TpmResult<GetCapabilityResponse> result = await TpmCommandExecutor.ExecuteAsync<GetCapabilityResponse>(
            device, GetCapabilityInput.ForTpmProperties(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER, count: 1), [], null, pool, registry,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"GetCapability(TPM_PT_LOCKOUT_COUNTER) failed: '{result.ResponseCode}'.");

        using GetCapabilityResponse properties = result.Value;
        var reported = properties.CapabilityData.TpmProperties;
        Assert.IsNotNull(reported);
        Assert.IsNotEmpty(reported);
        Assert.AreEqual(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER, reported[0].Property);

        return reported[0].Value;
    }

    /// <summary>Flushes <paramref name="handle"/> if it names a started session, releasing the simulator-side context.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The session handle, or zero when no session was started.</param>
    private static async Task FlushIfPresentAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            device, FlushContextInput.ForHandle(handle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)) — a local mirror of the production session-index encoding, transcribed
    /// independently here since the production helper is private.
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>
    /// Builds the digest <see cref="Tag"/> used to independently compute cpHash: SHA-256 digest, raw encoding,
    /// direct material — the same shape <c>TpmCommandExecutor</c>'s own cpHash computation uses.
    /// </summary>
    /// <returns>The digest tag.</returns>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    /// <summary>Creates the response codec registry covering every command these tests drive.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateStirRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_StirRandom, TpmResponseCodec.StirRandom)
            .Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom)
            .Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability)
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>
    /// Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational
    /// phase — the precondition <c>TPM2_StirRandom()</c> carries.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-stirrandom-session", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitStartupAsync(simulator, pool, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }

    /// <summary>Frames <c>TPM2_Startup()</c> directly to the simulator, sessionless, and returns its response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The startup command input.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitStartupAsync(TpmSimulator simulator, BaseMemoryPool pool, StartupInput input)
    {
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The transport itself must succeed.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }
}
