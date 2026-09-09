using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
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
/// Drives the one authorization-area shape of <c>TPM2_HierarchyChangeAuth()</c> that mixes credential kinds: a
/// <c>TPM_RS_PW</c> slot authorizing the hierarchy at index 0 beside a separate <c>decrypt</c> session at index
/// 1 protecting <c>newAuth</c> (TPM 2.0 Library Part 3, clause 24.8; Part 1, clauses 15.6.1 and 18.1), against
/// the in-house behavioural <see cref="TpmSimulator"/> through the production command path.
/// </summary>
/// <remarks>
/// <para>
/// The area is legal wire. Part 1, clause 15.6.1's Table 12 admits a password authorization at position 1 and a
/// decryption session at position 2, and clause 15.6.4, Table 15 forbids the AUTHORIZING slot nothing except the
/// attributes it could not key — which is precisely why the confidentiality of <c>newAuth</c> has to ride a
/// separate session here. What makes the shape load-bearing rather than decorative is that <c>newAuth</c>
/// arrives ENCRYPTED: a TPM that read the area as a lone password authorization would install the ciphertext as
/// the hierarchy's authorization value and lock the caller out of the hierarchy it just provisioned.
/// </para>
/// <para>
/// Each test therefore drives the whole ladder the two-block area owes — the companion is resolved and validated
/// (clause 5.5, step 4), its command HMAC is verified like every other session in the area (clause 5.6), the
/// password slot's own credential is compared (clause 5.6, check 10), <c>newAuth</c> is decrypted (clause 5.7),
/// and the response carries one entry per request session in request order ("If the responseCode is
/// TPM_RC_SUCCESS, the response has the same number of sessions in the same order as the request", clause
/// 16.6.1) — and reads the outcome from what the hierarchy's authorization value will subsequently authorize,
/// never from an internal marker.
/// </para>
/// <para>
/// The decrypt companion is SALTED against an RSA <c>tpmKey</c> rather than bound to the hierarchy, so its
/// session key is a secret the transcript does not carry even while the hierarchy's own authorization value is
/// still being established (Part 1, clause 16.6.12, equation 25).
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorHierarchyChangeAuthPasswordSlotTests
{
    /// <summary>The hash algorithm every session these tests start negotiates.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA endorsement-key template this simulator builds fixes nameAlg to SHA-256.</summary>
    private const TpmAlgIdConstants TpmKeyNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA public exponent the framework key generator uses (the wire template's "0" encodes this default, TPM 2.0 Library Part 2, Table 228).</summary>
    private const uint DefaultRsaExponent = 65537;

    /// <summary>The authorization value the owner hierarchy is provisioned with before each case runs.</summary>
    private static byte[] OwnerAuth { get; } = [0x61, 0x62, 0x63, 0x64, 0x65, 0x66];

    /// <summary>The replacement authorization value the rotation under test sends as <c>newAuth</c>.</summary>
    private static byte[] ReplacementAuth { get; } = [0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78];

    /// <summary>A value that is not the owner hierarchy's authorization value, for the wrong-password case.</summary>
    private static byte[] WrongAuth { get; } = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];

    /// <summary>The value a probe rotation installs when it is asked to prove that some other value authorizes.</summary>
    private static byte[] ProbeAuth { get; } = [0x51, 0x52, 0x53, 0x54];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A <c>[TPM_RS_PW, decrypt]</c> area rotates the hierarchy to the PLAINTEXT <c>newAuth</c>: the companion is
    /// verified and its keystream removed before the value is installed (TPM 2.0 Library Part 3, clause 5.6
    /// precedes clause 5.7, which precedes the command's own actions).
    /// </summary>
    /// <remarks>
    /// The proof is what the hierarchy subsequently accepts, read in the order that makes it conclusive: the OLD
    /// value must stop authorizing, and then the plaintext replacement must authorize. A simulator that took this
    /// area down the lone-password path would install the ciphertext, which fails the second leg — both values
    /// would be refused, and no marker inside the simulator is consulted to notice it.
    /// </remarks>
    [TestMethod]
    public async Task HierarchyChangeAuthOverAPasswordSlotWithADecryptCompanionRotatesToThePlaintext()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        //The salting key is created while the owner hierarchy still carries the Empty Buffer, so the empty
        //password session below is the correct authorization for it.
        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(device, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        try
        {
            await ProvisionOwnerAuthAsync(device, registry, pool).ConfigureAwait(false);

            (TpmSession companion, uint companionHandle, IMemoryOwner<byte> salt) = await StartSaltedDecryptCompanionAsync(
                device, registry, pool, tpmKey).ConfigureAwait(false);

            using(salt)
            using(companion)
            {
                try
                {
                    TpmRcConstants rotation = await RotateOverPasswordSlotAsync(
                        device, registry, pool, companion, OwnerAuth, ReplacementAuth).ConfigureAwait(false);
                    Assert.AreEqual(
                        TpmRcConstants.TPM_RC_SUCCESS, rotation,
                        "A password slot beside a decrypt companion is a legal authorization area (TPM 2.0 Library Part 1, clause 15.6.1, Table 12).");
                }
                finally
                {
                    await FlushIfPresentAsync(device, registry, pool, companionHandle).ConfigureAwait(false);
                }
            }

            TpmRcConstants stale = await RotateWithPasswordAsync(device, registry, pool, OwnerAuth, ProbeAuth).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), stale,
                "The replaced authorization value must stop authorizing the hierarchy once the rotation has committed.");

            TpmRcConstants withPlaintext = await RotateWithPasswordAsync(device, registry, pool, ReplacementAuth, ProbeAuth).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SUCCESS, withPlaintext,
                "The hierarchy must hold the PLAINTEXT newAuth: an area read as a lone password authorization would have installed the companion's ciphertext instead.");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>[TPM_RS_PW, decrypt]</c> area whose password slot presents the WRONG value is refused with
    /// <c>TPM_RC_BAD_AUTH</c> session-index-encoded to slot 0, leaving both the authorization value and the
    /// dictionary-attack counter untouched (TPM 2.0 Library Part 3, clause 5.6, check 10; Part 2, clause 6.6.2).
    /// </summary>
    /// <remarks>
    /// <c>TPM_RC_BAD_AUTH</c> rather than <c>TPM_RC_AUTH_FAIL</c> because the owner hierarchy is dictionary-attack
    /// exempt — only <c>lockoutAuth</c> among the permanent handles is protected (Part 1, clause 16.8.1) — so the
    /// failure counter must not move either, which the lockout-counter probe reads back rather than assumes. The
    /// encoding is what tells a caller WHICH slot it got wrong in an area holding two credentials.
    /// </remarks>
    [TestMethod]
    public async Task HierarchyChangeAuthOverAWrongPasswordSlotIsRefusedAtSlotZeroAndChargesNothing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(device, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        try
        {
            await ProvisionOwnerAuthAsync(device, registry, pool).ConfigureAwait(false);
            uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

            (TpmSession companion, uint companionHandle, IMemoryOwner<byte> salt) = await StartSaltedDecryptCompanionAsync(
                device, registry, pool, tpmKey).ConfigureAwait(false);

            using(salt)
            using(companion)
            {
                try
                {
                    TpmRcConstants refusal = await RotateOverPasswordSlotAsync(
                        device, registry, pool, companion, WrongAuth, ReplacementAuth).ConfigureAwait(false);

                    Assert.AreEqual(
                        TpmRcConstants.TPM_RC_BAD_AUTH, refusal.GetBaseError(),
                        "A dictionary-attack-exempt hierarchy answers a wrong password with TPM_RC_BAD_AUTH (TPM 2.0 Library Part 3, clause 5.6, check 10).");
                    Assert.AreEqual(
                        SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), refusal,
                        "The refusal names the slot that carried the wrong credential (TPM 2.0 Library Part 2, clause 6.6.2).");
                }
                finally
                {
                    await FlushIfPresentAsync(device, registry, pool, companionHandle).ConfigureAwait(false);
                }
            }

            uint counterAfter = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);
            Assert.AreEqual(counterBefore, counterAfter, "A dictionary-attack-exempt hierarchy's failed compare must move no counter (Part 1, clause 16.8.1).");

            TpmRcConstants stillValid = await RotateWithPasswordAsync(device, registry, pool, OwnerAuth, ProbeAuth).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SUCCESS, stillValid,
                "A refused rotation must alter no TPM state, so the hierarchy keeps the authorization value it had (Part 3, clause 5.6's closing rule).");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>[TPM_RS_PW, decrypt]</c> area whose COMPANION carries a corrupted command HMAC is refused at slot 1
    /// and applies no rotation, even though the password slot presented the correct value (TPM 2.0 Library Part
    /// 3, clause 5.6, check 9 — which applies to every session in the authorization area, not only to the one
    /// that authorizes a handle).
    /// </summary>
    /// <remarks>
    /// This is the leg that a fork made on slot 0's handle alone loses: with the companion never resolved, its
    /// HMAC is never verified, and an area whose second block was tampered with in flight is answered as a
    /// success. The corruption flips the final octet of the authorization area — the last octet of the
    /// companion's <c>hmac</c> field — so no length in the frame moves and the refusal can only come from the
    /// verification itself.
    /// </remarks>
    [TestMethod]
    public async Task HierarchyChangeAuthWithACorruptedCompanionHmacIsRefusedAtSlotOneAndAppliesNoRotation()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(device, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        try
        {
            await ProvisionOwnerAuthAsync(device, registry, pool).ConfigureAwait(false);

            (TpmSession companion, uint companionHandle, IMemoryOwner<byte> salt) = await StartSaltedDecryptCompanionAsync(
                device, registry, pool, tpmKey).ConfigureAwait(false);

            using(salt)
            using(companion)
            {
                try
                {
                    using TpmDevice tamperingDevice = CreateRewritingDevice(
                        simulator, TpmCcConstants.TPM_CC_HierarchyChangeAuth, WithCorruptedTrailingAuthOctet);

                    TpmRcConstants refusal = await RotateOverPasswordSlotAsync(
                        tamperingDevice, registry, pool, companion, OwnerAuth, ReplacementAuth).ConfigureAwait(false);

                    Assert.AreEqual(
                        TpmRcConstants.TPM_RC_BAD_AUTH, refusal.GetBaseError(),
                        "An unbound companion authorizes no dictionary-attack-protected entity, so its own HMAC mismatch is TPM_RC_BAD_AUTH (Part 3, clause 5.6, check 9).");
                    Assert.AreEqual(
                        SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), refusal,
                        "The refusal names the companion's own slot (TPM 2.0 Library Part 2, clause 6.6.2).");
                }
                finally
                {
                    await FlushIfPresentAsync(device, registry, pool, companionHandle).ConfigureAwait(false);
                }
            }

            TpmRcConstants stillValid = await RotateWithPasswordAsync(device, registry, pool, OwnerAuth, ProbeAuth).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SUCCESS, stillValid,
                "A command refused for any session's HMAC alters no TPM state, so no rotation may have landed (Part 3, clause 5.6's closing rule).");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Both refusals of a <c>[TPM_RS_PW, decrypt]</c> area return the <c>newAuth</c> carrier the parse rented to
    /// the pool: the wrong-password refusal, which fires inside the transition, and the corrupted-companion
    /// refusal, which fires after the request has been handed to the verification effect.
    /// </summary>
    /// <remarks>
    /// The two refusals release the carrier from different owners — one from the transition's own rejecting arm,
    /// the other from the point that terminates a command whose queued request no later arm will ever see — so
    /// measuring both is what makes the accounting a property of the shape rather than of one code path. The
    /// instrument is <see cref="MeteredHousePool"/>: a genuine <see cref="BaseMemoryPool"/> whose own rent and
    /// return telemetry is observed, so nothing here depends on a seam in production code.
    /// </remarks>
    [TestMethod]
    public async Task HierarchyChangeAuthPasswordSlotRefusalsReturnTheParseRentedNewAuthToThePool()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(device, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        try
        {
            await ProvisionOwnerAuthAsync(device, registry, pool).ConfigureAwait(false);

            //The session establishment moves durable rentals into both the simulator's session record and the
            //client session, so the baseline is taken only once both exist.
            (TpmSession companion, uint companionHandle, IMemoryOwner<byte> salt) = await StartSaltedDecryptCompanionAsync(
                device, registry, pool, tpmKey).ConfigureAwait(false);

            using(salt)
            using(companion)
            {
                try
                {
                    long wrongPasswordBaseline = trackingPool.OutstandingCount;

                    TpmRcConstants wrongPassword = await RotateOverPasswordSlotAsync(
                        device, registry, pool, companion, WrongAuth, ReplacementAuth).ConfigureAwait(false);
                    Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), wrongPassword, "The wrong-password refusal names slot 0, the [TPM_RS_PW] authorization slot (TPM 2.0 Library Part 2, clause 6.6.2).");

                    Assert.AreEqual(
                        wrongPasswordBaseline, trackingPool.OutstandingCount,
                        "The password-compare refusal must return the parse-rented newAuth carrier to the pool.");

                    using TpmDevice tamperingDevice = CreateRewritingDevice(
                        simulator, TpmCcConstants.TPM_CC_HierarchyChangeAuth, WithCorruptedTrailingAuthOctet);

                    long companionBaseline = trackingPool.OutstandingCount;

                    TpmRcConstants corruptedCompanion = await RotateOverPasswordSlotAsync(
                        tamperingDevice, registry, pool, companion, OwnerAuth, ReplacementAuth).ConfigureAwait(false);
                    Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), corruptedCompanion, "The corrupted-companion refusal names slot 1, the companion session's own slot (TPM 2.0 Library Part 2, clause 6.6.2).");

                    Assert.AreEqual(
                        companionBaseline, trackingPool.OutstandingCount,
                        "The companion-HMAC refusal must return the parse-rented newAuth carrier to the pool.");
                }
                finally
                {
                    await FlushIfPresentAsync(device, registry, pool, companionHandle).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The ACCEPTED leg of the mixed area balances too, which is the harder half: a refused command releases
    /// everything through one request-wide disposal, while an accepted one splits the release across the
    /// completing tail (both slots' <c>hmac</c> fields and the captured parameter area), the branch that owes a
    /// <c>TPM_RS_PW</c> slot a placeholder response entry (that slot's caller nonce, which keys no response HMAC),
    /// and the response framing (the decrypt companion's caller nonce, transferred into its entry and read one
    /// last time by the HMAC it keys). Every one of those is a distinct site, and a rotation whose count returns
    /// to where it started is the only evidence that no site was missed.
    /// </summary>
    /// <remarks>
    /// Two marks are taken because the session establishment itself leaves durable rentals on both sides — the
    /// simulator's session record and the client's own session object — which are settled only by the flush and
    /// the client-side disposal, not by the command. The first mark predates the companion, so the count returns
    /// to it only once the companion is gone from both sides; the second predates the rotation alone, so the
    /// count returns to it the moment the command completes. The instrument is <see cref="MeteredHousePool"/>,
    /// which is the house pool itself with its own rent and return telemetry observed.
    /// </remarks>
    [TestMethod]
    public async Task HierarchyChangeAuthOverAPasswordSlotWithADecryptCompanionBalancesEveryCarrier()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(device, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        try
        {
            await ProvisionOwnerAuthAsync(device, registry, pool).ConfigureAwait(false);

            long beforeCompanion = trackingPool.OutstandingCount;

            (TpmSession companion, uint companionHandle, IMemoryOwner<byte> salt) = await StartSaltedDecryptCompanionAsync(
                device, registry, pool, tpmKey).ConfigureAwait(false);

            using(salt)
            using(companion)
            {
                long beforeRotation = trackingPool.OutstandingCount;

                TpmRcConstants rotation = await RotateOverPasswordSlotAsync(
                    device, registry, pool, companion, OwnerAuth, ReplacementAuth).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_SUCCESS, rotation,
                    "A password slot beside a decrypt companion is a legal authorization area (TPM 2.0 Library Part 1, clause 15.6.1, Table 12).");

                Assert.AreEqual(
                    beforeRotation, trackingPool.OutstandingCount,
                    "The accepted rotation returns both slots' credentials, the captured parameter area and the superseded authorization value, and installs exactly one replacement in its place.");

                await FlushIfPresentAsync(device, registry, pool, companionHandle).ConfigureAwait(false);
            }

            Assert.AreEqual(
                beforeCompanion, trackingPool.OutstandingCount,
                "Once the companion is flushed and its client-side session disposed, the rotation has left nothing outstanding at all.");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Issues <c>TPM2_HierarchyChangeAuth()</c> for the owner hierarchy over an authorization area of exactly
    /// <c>[TPM_RS_PW, decrypt companion]</c> — the shape under test.
    /// </summary>
    /// <param name="device">The device the command is submitted through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="companion">The established decrypt companion, already carrying the <c>decrypt</c> attribute.</param>
    /// <param name="currentAuth">The value the password slot presents as the hierarchy's current authorization value.</param>
    /// <param name="newAuth">The replacement value, which the companion encrypts on its way out.</param>
    /// <returns>The command's response code.</returns>
    private async Task<TpmRcConstants> RotateOverPasswordSlotAsync(
        TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSession companion,
        ReadOnlyMemory<byte> currentAuth, ReadOnlyMemory<byte> newAuth)
    {
        using TpmPasswordSession passwordSlot = TpmPasswordSession.Create(currentAuth.Span, pool);
        using Tpm2bAuth replacement = Tpm2bAuth.Create(newAuth.Span, pool);
        using HierarchyChangeAuthInput input = new(TpmRh.TPM_RH_OWNER, replacement);

        TpmResult<HierarchyChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyChangeAuthResponse>(
            device, input, [passwordSlot, companion], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        return result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode;
    }

    /// <summary>
    /// Issues the plain single-<c>TPM_RS_PW</c> form of <c>TPM2_HierarchyChangeAuth()</c> for the owner
    /// hierarchy — the probe every case reads its outcome through, and the form whose behaviour the two-block
    /// fork must leave untouched.
    /// </summary>
    /// <param name="device">The device the command is submitted through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="currentAuth">The value presented as the hierarchy's current authorization value.</param>
    /// <param name="newAuth">The replacement value, sent in the clear.</param>
    /// <returns>The command's response code.</returns>
    private async Task<TpmRcConstants> RotateWithPasswordAsync(
        TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, ReadOnlyMemory<byte> currentAuth, ReadOnlyMemory<byte> newAuth)
    {
        using TpmPasswordSession passwordSlot = TpmPasswordSession.Create(currentAuth.Span, pool);
        using Tpm2bAuth replacement = Tpm2bAuth.Create(newAuth.Span, pool);
        using HierarchyChangeAuthInput input = new(TpmRh.TPM_RH_OWNER, replacement);

        TpmResult<HierarchyChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyChangeAuthResponse>(
            device, input, [passwordSlot], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        return result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode;
    }

    /// <summary>Moves the owner hierarchy from the factory-state Empty Buffer to <see cref="OwnerAuth"/>, so every case runs against a real credential.</summary>
    /// <param name="device">The device the command is submitted through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task ProvisionOwnerAuthAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        TpmRcConstants provisioned = await RotateWithPasswordAsync(device, registry, pool, ReadOnlyMemory<byte>.Empty, OwnerAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, provisioned, "Provisioning the owner hierarchy's authorization value must succeed.");
    }

    /// <summary>
    /// Starts an unbound, SALTED HMAC session negotiating XOR obfuscation and marks it as the area's
    /// <c>decrypt</c> companion (TPM 2.0 Library Part 1, clause 18.2).
    /// </summary>
    /// <remarks>
    /// Salting rather than binding is what keeps the companion's session key out of the transcript: a session
    /// bound to the hierarchy being rotated derives its key from the very authorization value in play, so a
    /// captured exchange plus a guess at that value would reproduce the keystream (clause 16.6.10, equation 20).
    /// The salt travels back to the caller so the host can derive the identical key (clause 16.6.12, equation 25).
    /// </remarks>
    /// <param name="device">The device the session is started through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tpmKey">The loaded RSA decrypt key the salt is encrypted to.</param>
    /// <returns>The established companion, its handle, and the salt carrier the caller owns.</returns>
    private async Task<(TpmSession Companion, uint CompanionHandle, IMemoryOwner<byte> Salt)> StartSaltedDecryptCompanionAsync(
        TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse tpmKey)
    {
        ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

        (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateSaltedHmacSession(
            tpmKey.ObjectHandle.Value, modulus, DefaultRsaExponent, TpmKeyNameAlg, SessionAlg, rsaBackend.EncryptOaep, TestEntropy.NewCounterStream(), pool,
            TestContext.CancellationToken, symmetric: TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);

        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (salted, unbound, XOR) failed: '{startResult.ResponseCode}'.");

            StartAuthSessionResponse started = startResult.Value;
            TpmSession companion = await TpmSession.CreateBoundAsync(
                new TpmHandle(started.SessionHandle.Value), ReadOnlyMemory<byte>.Empty, startInput.NonceCaller, started.NonceTPM,
                SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric: TpmtSymDef.Xor(SessionAlg), salt: salt.Memory[..saltLength],
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            //The companion authorizes no entity, so it must claim at least one of decrypt/encrypt/audit to be
            //admitted at all (TPM 2.0 Library Part 3, clause 5.5, step 4.4.2); decrypt is the one that gives
            //newAuth its confidentiality.
            companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            return (companion, started.SessionHandle.Value, salt);
        }
        catch
        {
            salt.Dispose();
            throw;
        }
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

    /// <summary>Creates the RSA endorsement-key-shaped decrypt key (RESTRICTED+DECRYPT, SHA-256 nameAlg) the salted companion encrypts its salt to.</summary>
    /// <param name="device">The device the command is submitted through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaDecryptKeyAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_OWNER, pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Flushes a handle, ignoring the outcome, so a case never leaks a TPM slot into the next one.</summary>
    /// <param name="device">The device the command is submitted through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    private static async Task FlushIfPresentAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            device, FlushContextInput.ForHandle(handle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
    }

    /// <summary>
    /// Flips the final octet of a framed command's authorization area — the last octet of the LAST session's
    /// <c>hmac</c> field — leaving every length in the frame exactly as it was.
    /// </summary>
    /// <remarks>
    /// The area's extent is read from the frame itself: <c>authorizationSize</c> sits after the header and this
    /// command's single handle, and the area follows it (TPM 2.0 Library Part 1, clause 15.5). Corrupting the
    /// LAST octet reaches the trailing <c>hmac</c> without needing to walk the slots.
    /// </remarks>
    /// <param name="command">The framed command to tamper with.</param>
    /// <returns>A new framed command whose last authorization octet differs.</returns>
    private static byte[] WithCorruptedTrailingAuthOctet(byte[] command)
    {
        const int HandleCount = 1;

        int authorizationSizeOffset = TpmHeader.HeaderSize + (HandleCount * sizeof(uint));
        uint authorizationSize = BinaryPrimitives.ReadUInt32BigEndian(command.AsSpan(authorizationSizeOffset, sizeof(uint)));
        int lastAuthOctet = authorizationSizeOffset + sizeof(uint) + (int)authorizationSize - 1;

        byte[] tampered = (byte[])command.Clone();
        tampered[lastAuthOctet] ^= 0xFF;

        return tampered;
    }

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
        }, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
    }

    /// <summary>Reads a framed command's <c>commandCode</c> field (TPM 2.0 Library Part 1, clause 15.2.3's commandCode header field).</summary>
    /// <param name="command">The framed command.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(ReadOnlySpan<byte> command)
    {
        var reader = new TpmReader(command);
        TpmHeader header = TpmHeader.Parse(ref reader);

        return (TpmCcConstants)header.Code;
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + <c>TPM_RC_S</c> +
    /// <c>TPM_RC_n</c>(0x100·(index+1)) — a local mirror of the production session-index encoding, transcribed
    /// independently here since the production helper is private.
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>Creates a response codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmResponseCodec.HierarchyChangeAuth)
            .Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>
    /// Creates a simulator with both the ECC and RSA signing backends wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator; the caller owns it.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-hierarchy-change-auth-password-slot",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupClearAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task IssueStartupClearAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
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
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }
}
