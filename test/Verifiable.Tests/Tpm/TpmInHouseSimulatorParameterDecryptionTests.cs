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
using Verifiable.Tpm.Extensions.DictionaryAttack;
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
/// Drives request-direction (decrypt-attribute) parameter decryption against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production
/// command path the production code uses (<see cref="TpmCommandExecutor"/>, the real <see cref="CreateInput"/>,
/// <see cref="TpmSession"/>, and the real response codecs): <c>TPM2_Create()</c> now accepts a parent-authorizing
/// HMAC session (or <c>TPM_RS_PW</c>) paired with a SEPARATE bound HMAC session carrying the <c>decrypt</c>
/// attribute that protects <c>inSensitive</c> (TPM 2.0 Library Part 1, clauses 19 and 21; Part 3, clauses 5.5,
/// 5.6, and 12.1) — where previously a decrypt-attributed session had no effect at all.
/// </summary>
/// <remarks>
/// <para>
/// Every negative test is proven non-vacuous: the SAME bytes, with the mechanism under test intact, succeed; only
/// the deliberately broken variant is rejected. The stripped-decrypt-session test is this suite's crown negative
/// (R-B5): it proves the nonceTPMdecrypt fold (clause 17.6.3.4) actually binds the decrypt session into the
/// parent-authorizing session's command HMAC, so silently removing the decrypt session from the wire is detected
/// as an authorization failure rather than merely disabling confidentiality.
/// </para>
/// <para>
/// Two tests hand-assemble their own wire bytes and submit them directly to the simulator, firewalled to the wire
/// with no back-channel into simulator internals: both use UNBOUND, UNSALTED HMAC sessions, whose session key is
/// <c>KDFa(authHash, Empty, "ATH", nonceTPM, nonceCaller, bits)</c> — computable from the public start nonces
/// alone (TPM 2.0 Library Part 1, clause 17.6.9). Independence here is at the composition level, not the
/// primitive level: the command's cpHash and HMAC (clause 16.7 and clause 17.6.5) are assembled by hand, field
/// by field, and computed through the project's own <c>Kdfa</c> and registered digest/HMAC seam — the same
/// primitives <c>KdfaTests</c> pins to known-answer vectors — then compared against what the SIMULATOR accepted.
/// This is the only way to reach the simulator's own size guard and to prove an independently-encrypted (rather
/// than production-encrypted) request decrypts correctly: the host executor's own admissibility guard
/// (<see cref="ArgumentException"/> for a malformed decrypt-session combination) would otherwise reject these
/// specific requests before they ever reached the wire.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorParameterDecryptionTests
{
    /// <summary>The session/name hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The digest width, in octets, of <see cref="SessionAlg"/>.</summary>
    private const int DigestSize = 32;

    /// <summary>The lowered <c>maxTries</c> the F3 lockout regression uses to reach Lockout mode quickly.</summary>
    private const uint LockoutTestMaxTries = 2;

    /// <summary>
    /// How many pooled carriers a started, unbound, unsalted session keeps outstanding for as long as it is
    /// loaded: its retained nonceTPM alone (TPM 2.0 Library Part 1, clause 17.6.5).
    /// </summary>
    private const int RetainedNonceTpmPerSession = 1;

    /// <summary>The fixed secret sealed by the round-trip tests.</summary>
    private static byte[] SecretBytes { get; } = "Confidentially sealed secret."u8.ToArray();

    /// <summary>The real authorization value carried, encrypted, inside <c>inSensitive</c>.</summary>
    private static byte[] IntendedUserAuth { get; } = [0x51, 0x52, 0x53, 0x54, 0x55];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task CreateOverSessionsWithXorEncryptedInSensitiveRoundTripsThroughUnseal()
    {
        await RunProductionEncryptedRoundTripAsync(TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
    }

    [TestMethod]
    public async Task CreateOverSessionsWithAesCfbEncryptedInSensitiveRoundTripsThroughUnseal()
    {
        await RunProductionEncryptedRoundTripAsync(TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a sealed object whose <c>inSensitive</c> (carrying <see cref="IntendedUserAuth"/>) is encrypted by
    /// the production <see cref="TpmSession"/> over a SEPARATE bound decrypt session, then unseals it over a
    /// second HMAC session using the recovered authorization value — proving the production request-decrypt path
    /// round-trips for both symmetric schemes.
    /// </summary>
    private async Task RunProductionEncryptedRoundTripAsync(TpmtSymDef symmetric)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint parentAuthSessionHandle = 0;
        uint decryptSessionHandle = 0;
        uint itemHandle = 0;
        uint unsealSessionHandle = 0;

        try
        {
            (parentAuthSessionHandle, TpmSession parentAuthSession, _, _) =
                await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Null).ConfigureAwait(false);
            using(parentAuthSession)
            {
                (decryptSessionHandle, TpmSession decryptSession, _, _) =
                    await StartHmacSessionAsync(tpm, registry, pool, parentHandle, symmetric).ConfigureAwait(false);
                using(decryptSession)
                {
                    parentAuthSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;
                    decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                    using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, IntendedUserAuth, pool);
                    using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
                    using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                    TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                        tpm, createInput, [parentAuthSession, decryptSession], [parent.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(createResult.IsSuccess, $"Create over sessions with a {symmetric.Algorithm} decrypt session failed: '{createResult.ResponseCode}'.");

                    using CreateResponse created = createResult.Value;
                    using LoadResponse loaded = await LoadSealedObjectAsync(tpm, registry, pool, parentHandle, created).ConfigureAwait(false);
                    itemHandle = loaded.ObjectHandle.Value;

                    (unsealSessionHandle, TpmSession unsealSession, _, _) =
                        await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Null).ConfigureAwait(false);
                    using(unsealSession)
                    {
                        //The recovered authValue only round-trips correctly if the simulator genuinely decrypted
                        //inSensitive with the SAME key/nonces the host encrypted it with.
                        unsealSession.SetAuthValue(IntendedUserAuth, pool);

                        UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
                        TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                            tpm, unsealInput, [unsealSession], [loaded.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                        Assert.IsTrue(unsealResult.IsSuccess, $"Unseal with the decrypted userAuth failed: '{unsealResult.ResponseCode}'.");
                        using UnsealResponse unsealed = unsealResult.Value;
                        Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes), "The recovered secret must equal the sealed one.");
                    }
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, unsealSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, decryptSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentAuthSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_Create()</c> over ONE session that both authorizes the parent and carries <c>decrypt</c> — no
    /// separate companion — round-trips the sealed secret through <c>TPM2_Unseal()</c>, under XOR obfuscation.
    /// </summary>
    [TestMethod]
    public async Task CreateOverADecryptAttributedParentSessionWithXorRoundTripsThroughUnseal()
    {
        await RunAuthorizingSlotDecryptRoundTripAsync(TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
    }

    /// <summary>
    /// The AES-CFB twin of
    /// <see cref="CreateOverADecryptAttributedParentSessionWithXorRoundTripsThroughUnseal"/>: the same single
    /// authorizing-and-decrypting slot, keyed through the block cipher instead of the obfuscation.
    /// </summary>
    [TestMethod]
    public async Task CreateOverADecryptAttributedParentSessionWithAesCfbRoundTripsThroughUnseal()
    {
        await RunAuthorizingSlotDecryptRoundTripAsync(TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a sealed object whose <c>inSensitive</c> is decrypted over the SAME session that authorizes the
    /// parent, then unseals it with the recovered authorization value.
    /// </summary>
    /// <remarks>
    /// <para>
    /// "A session with this attribute does not need to be associated with an entity identified in the handle
    /// area" (TPM 2.0 Library Part 1, clause 16.6.4, Table 12) states the permission the other way round: the
    /// attribute MAY ride a session that authorizes nothing, and equally may ride one that authorizes something.
    /// A single-session area of this shape is what clause 16.6.1 describes as "a single session can be used for
    /// authorization, encryption, decryption, and audit at the same time".
    /// </para>
    /// <para>
    /// The session here is unbound and unsalted and the parent carries a real authorization value, so its
    /// <c>sessionValue</c> is <c>sessionKey ‖ authValue</c> with an empty session key — the cipher key is
    /// entirely the parent's authValue (clause 19.1's own observation about the unbound and unsalted case). That
    /// makes the round trip a direct test of the entity term: a simulator keying the cipher on the session key
    /// alone would decrypt <c>inSensitive</c> to garbage, seal a garbage <c>userAuth</c>, and the unseal below
    /// would fail its authorization.
    /// </para>
    /// </remarks>
    /// <param name="symmetric">The symmetric definition the single session negotiates.</param>
    private async Task RunAuthorizingSlotDecryptRoundTripAsync(TpmtSymDef symmetric)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreatePasswordProtectedStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint parentAuthSessionHandle = 0;
        uint itemHandle = 0;
        uint unsealSessionHandle = 0;

        try
        {
            (parentAuthSessionHandle, TpmSession parentAuthSession) =
                await StartUnboundHmacSessionAsync(tpm, registry, pool, symmetric).ConfigureAwait(false);
            using(parentAuthSession)
            {
                parentAuthSession.SetAuthValue(ParentPasswordBytes, pool);
                parentAuthSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, IntendedUserAuth, pool);
                using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
                using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                    tpm, createInput, [parentAuthSession], [parent.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(
                    createResult.IsSuccess,
                    $"Create over one session that both authorizes the parent and carries a {symmetric.Algorithm} decrypt attribute failed: '{createResult.ResponseCode}'.");

                using CreateResponse created = createResult.Value;
                using LoadResponse loaded = await LoadUnderPasswordProtectedParentAsync(tpm, registry, pool, parentHandle, created).ConfigureAwait(false);
                itemHandle = loaded.ObjectHandle.Value;

                (unsealSessionHandle, TpmSession unsealSession) =
                    await StartUnboundHmacSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);
                using(unsealSession)
                {
                    //The recovered authValue only round-trips if the simulator keyed its decryption on the SAME
                    //sessionValue the host keyed its encryption on — session key AND the parent's live authValue.
                    unsealSession.SetAuthValue(IntendedUserAuth, pool);

                    UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
                    TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                        tpm, unsealInput, [unsealSession], [loaded.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsTrue(unsealResult.IsSuccess, $"Unseal with the decrypted userAuth failed: '{unsealResult.ResponseCode}'.");
                    using UnsealResponse unsealed = unsealResult.Value;
                    Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes), "The recovered secret must equal the sealed one.");
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, unsealSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentAuthSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_Unseal()</c> over ONE session that both authorizes the sealed item and carries <c>encrypt</c>
    /// returns <c>outData</c> the host decrypts back to the sealed secret, while the secret never appears in the
    /// response bytes on the wire — and the pool balance is unchanged across the whole exchange.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The attribute may ride an authorizing session (TPM 2.0 Library Part 1, clause 16.6.4, Table 12: "A session
    /// with this attribute does not need to be associated with an entity identified in the handle area"), and
    /// when it does, its cipher key folds the entity's own authValue — <c>sessionValue</c> is
    /// <c>sessionKey ‖ authValue</c> "if a session is also being used for authorization", with the binding of the
    /// session ignored (clause 19.1). The session here is unbound and unsalted, so the cipher key is entirely the
    /// item's <c>userAuth</c>.
    /// </para>
    /// <para>
    /// The round trip is what proves the transform happened at all: the host decrypts the first response
    /// parameter unconditionally when its session carries <c>encrypt</c>, so a simulator that returned the secret
    /// in the clear would have it decrypted into garbage rather than passed through. The wire assertion adds the
    /// confidentiality half — an observer on the transport sees no plaintext.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async Task UnsealOverAnEncryptAttributedAuthorizingSessionKeepsOutDataOffTheWire()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        byte[]? unsealResponseBytes = null;
        async ValueTask<TpmResult<TpmResponse>> CaptureUnsealResponseAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken cancellationToken)
        {
            TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, commandPool, cancellationToken).ConfigureAwait(false);
            if(result.IsSuccess && BinaryPrimitives.ReadUInt32BigEndian(command.Span[6..10]) == (uint)TpmCcConstants.TPM_CC_Unseal)
            {
                unsealResponseBytes = result.Value.AsReadOnlySpan().ToArray();
            }

            return result;
        }

        using TpmDevice tpm = TpmDevice.Create(CaptureUnsealResponseAsync);

        long baseline = trackingPool.OutstandingCount;
        uint parentHandle = 0;
        uint itemHandle = 0;
        uint unsealSessionHandle = 0;

        try
        {
            using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
            parentHandle = parent.ObjectHandle.Value;

            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, IntendedUserAuth, pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(createResult.IsSuccess, $"Create (seal) failed: '{createResult.ResponseCode}'.");

            using CreateResponse created = createResult.Value;
            using LoadResponse loaded = await LoadSealedObjectAsync(tpm, registry, pool, parentHandle, created).ConfigureAwait(false);
            itemHandle = loaded.ObjectHandle.Value;

            (unsealSessionHandle, TpmSession unsealSession) =
                await StartUnboundHmacSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
            using(unsealSession)
            {
                unsealSession.SetAuthValue(IntendedUserAuth, pool);
                unsealSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
                TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                    tpm, unsealInput, [unsealSession], [loaded.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(
                    unsealResult.IsSuccess,
                    $"Unseal over one session that both authorizes the item and carries encrypt failed: '{unsealResult.ResponseCode}'.");
                using UnsealResponse unsealed = unsealResult.Value;
                Assert.IsTrue(
                    unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes),
                    "The host must decrypt outData back to the sealed secret, which it can only do if the simulator encrypted it under the same sessionValue.");
            }

            Assert.IsNotNull(unsealResponseBytes, "The unseal response must have been captured, or the wire assertion below proves nothing.");
            Assert.IsFalse(
                ContainsSubsequence(unsealResponseBytes, SecretBytes),
                "An encrypt-attributed session protects the first response parameter, so the sealed secret must not appear in the response bytes.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, unsealSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Every carrier the encrypted unseal exchange rented must reach the pool again.");
    }

    /// <summary>
    /// Loads a sealed object under a parent whose authorization value is <see cref="ParentPassword"/>, through
    /// the production <c>TPM2_Load()</c> path.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The password-protected parent's handle.</param>
    /// <param name="created">The <c>TPM2_Create()</c> response carrying the private blob and public area.</param>
    /// <returns>The load response (the caller owns it).</returns>
    private async Task<LoadResponse> LoadUnderPasswordProtectedParentAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, CreateResponse created)
    {
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(created.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(created.OutPublic, pool);
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.Create(ParentPasswordBytes, pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object under a password-protected parent) failed: '{loadResult.ResponseCode}'.");

        return loadResult.Value;
    }

    /// <summary>Whether <paramref name="haystack"/> contains <paramref name="needle"/> as a contiguous run.</summary>
    /// <param name="haystack">The octets searched.</param>
    /// <param name="needle">The octets searched for.</param>
    /// <returns><see langword="true"/> when the run is present.</returns>
    private static bool ContainsSubsequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        return needle.Length != 0 && haystack.IndexOf(needle) >= 0;
    }

    /// <summary>The authorization value the password-protected storage parent carries.</summary>
    private const string ParentPassword = "parent-auth-slot-zero";

    /// <summary>The octets of <see cref="ParentPassword"/>, as a session folds them into its cipher key.</summary>
    private static byte[] ParentPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(ParentPassword);

    /// <summary>
    /// Creates the ECC storage parent carrying <see cref="ParentPassword"/> — the fixture the authorizing-slot
    /// decrypt tests need, since a parent with an empty authValue would make the entity term of the cipher key
    /// invisible.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreatePasswordProtectedStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, ParentPassword, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (password-protected storage parent) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Starts an UNBOUND, UNSALTED HMAC session negotiating <paramref name="symmetric"/>. Such a session's
    /// sessionKey is the Empty Buffer with no KDFa run at all (TPM 2.0 Library Part 1, clause 17.6.9), so
    /// whatever the caller hands it through <c>SetAuthValue</c> is the whole of its <c>sessionValue</c>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="symmetric">The symmetric definition to negotiate.</param>
    /// <returns>The started session's handle and the host-side session object (the caller owns it).</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartUnboundHmacSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtSymDef symmetric)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, symmetric);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound, unsalted) failed: '{startResult.ResponseCode}'.");

        //The response's own nonceTPM carrier transfers into the session, which releases it on its own Dispose —
        //the ownership transfer the sibling bound-session helper in this file already relies on.
        StartAuthSessionResponse startResponse = startResult.Value;
        var session = new TpmSession(new TpmHandle(startResponse.SessionHandle.Value), startResponse.NonceTPM, SessionAlg, pool, symmetric)
        {
            SessionAttributes = TpmaSession.CONTINUE_SESSION
        };

        return (startResponse.SessionHandle.Value, session);
    }

    /// <summary>
    /// F5 regression (adversarial review, MINOR host/sim divergence): two REAL sessions negotiating DIFFERENT
    /// hash algorithms — a SHA-256 parent-authorizing session (index 0) and a SHA-384 decrypt companion (index
    /// 1) — must succeed end to end over <c>TPM2_Create()</c>. Before the fix, the host computed ONE cpHash
    /// under the "first session with a real hash" rule and fed it to EVERY session's HMAC, and framed the
    /// response rpHash the same single-hash way; each session HMACs (and verifies) under its OWN algorithm
    /// (TPM 2.0 Library Part 1, clause 16.7, equation 15/16), so a genuine, spec-legal mixed-hash command
    /// diverged from what the (per-session-alg-correct) simulator computed and was falsely rejected. A SUCCESS
    /// result here means the host command-side cpHash, the host response-side rpHash
    /// (<c>TpmSession.VerifyAndUpdateAsync</c>), AND the simulator's own response-side rpHash
    /// (<c>SealDataOverSessionsAsync</c>) all now agree per-session-algorithm.
    /// </summary>
    [TestMethod]
    public async Task MixedHashTwoSessionCreateSucceedsEndToEnd()
    {
        const TpmAlgIdConstants DecryptSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA384;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint parentAuthSessionHandle = 0;
        uint decryptSessionHandle = 0;

        try
        {
            //Session 0: SHA-256, authorizes the parent. Session 1: SHA-384, the decrypt companion protecting
            //inSensitive — a genuinely mixed-hash two-session authorization area.
            (parentAuthSessionHandle, TpmSession parentAuthSession, _, _) =
                await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Null).ConfigureAwait(false);
            using(parentAuthSession)
            {
                (decryptSessionHandle, TpmSession decryptSession, _, _) = await StartHmacSessionAsync(
                    tpm, registry, pool, parentHandle, TpmtSymDef.Xor(DecryptSessionAlg), DecryptSessionAlg).ConfigureAwait(false);
                using(decryptSession)
                {
                    parentAuthSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;
                    decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                    using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, IntendedUserAuth, pool);
                    using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
                    using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                    TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                        tpm, createInput, [parentAuthSession, decryptSession], [parent.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsTrue(createResult.IsSuccess,
                        $"Create over two sessions negotiating DIFFERENT hash algorithms (SHA-256 auth + SHA-384 decrypt) must succeed end to end — a conformant TPM does not reject this shape: '{createResult.ResponseCode}'.");
                    createResult.Value.Dispose();
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, decryptSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentAuthSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task DecryptSessionThatSkipsEncryptionProducesGarbageUserAuthDetectedByLaterUnseal()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint parentAuthSessionHandle = 0;
        uint decryptSessionHandle = 0;
        uint itemHandle = 0;

        try
        {
            (parentAuthSessionHandle, TpmSession parentAuthSession, _, _) =
                await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Null).ConfigureAwait(false);
            using(parentAuthSession)
            {
                (decryptSessionHandle, TpmSession realDecryptSession, _, _) =
                    await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
                using(realDecryptSession)
                {
                    parentAuthSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;
                    realDecryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                    //A session that claims the decrypt attribute (so the simulator genuinely applies its own
                    //XOR transform) but whose EncryptFirstParameterAsync is a no-op — a caller bug that sends
                    //the plaintext while claiming it is protected. The command HMAC is still computed for real
                    //by the wrapped production session, over whatever bytes actually went out (cpHash covers the
                    //wire bytes as sent, not "what should have been sent"), so it verifies; only the simulator's
                    //own, genuine XOR then corrupts the plaintext it was never meant to touch.
                    using var noOpEncryptSession = new SkipEncryptionHmacSession(realDecryptSession);

                    using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, IntendedUserAuth, pool);
                    using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
                    using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                    TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                        tpm, createInput, [parentAuthSession, noOpEncryptSession], [parent.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    //The simulator XORs whatever bytes it actually received with its own genuine, freshly-derived
                    //mask; since the host sent PLAINTEXT (the no-op EncryptFirstParameterAsync), the result is
                    //effectively random content, not a deliberately crafted attack — it may fail to decode as a
                    //well-formed TPMS_SENSITIVE_CREATE outright (a plausible parameter-error rejection) or decode
                    //with a corrupted userAuth. Either outcome proves the same thing: if the simulator's decrypt
                    //were a silent passthrough (a bug this test exists to catch), the well-formed plaintext would
                    //have parsed AND round-tripped through Unseal with the INTENDED userAuth unchanged.
                    if(createResult.IsSuccess)
                    {
                        using CreateResponse created = createResult.Value;
                        using LoadResponse loaded = await LoadSealedObjectAsync(tpm, registry, pool, parentHandle, created).ConfigureAwait(false);
                        itemHandle = loaded.ObjectHandle.Value;

                        (uint verifySessionHandle, TpmSession verifySession, _, _) =
                            await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Null).ConfigureAwait(false);
                        try
                        {
                            using(verifySession)
                            {
                                verifySession.SetAuthValue(IntendedUserAuth, pool);

                                UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
                                TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                                    tpm, unsealInput, [verifySession], [loaded.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                                Assert.IsFalse(unsealResult.IsSuccess,
                                    "The stored userAuth must be garbage (plaintext XORed once by the simulator's genuine transform, never by the host), so the INTENDED authValue must no longer match it — proving the simulator's decrypt is real, not a silent passthrough.");
                            }
                        }
                        finally
                        {
                            await FlushIfPresentAsync(tpm, registry, verifySessionHandle).ConfigureAwait(false);
                        }
                    }
                    else
                    {
                        //A malformed-PARAMETER rejection (not, say, ATTRIBUTES/HANDLE, which would indicate an
                        //unrelated bug in the session-area or handle plumbing) — also proves the simulator's
                        //decrypt is real: a passthrough bug would have let the well-formed plaintext through
                        //unchanged, and well-formed plaintext never fails to decode this way.
                        bool isMalformedParameter = createResult.ResponseCode is
                            TpmRcConstants.TPM_RC_SIZE or TpmRcConstants.TPM_RC_INSUFFICIENT or TpmRcConstants.TPM_RC_VALUE or TpmRcConstants.TPM_RC_TYPE;
                        Assert.IsTrue(isMalformedParameter,
                            $"Create must fail with a malformed-parameter code when it rejects the genuinely-XORed garbage, got '{createResult.ResponseCode}'.");
                    }
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, decryptSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentAuthSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task TwoDecryptAttributedSessionsAreRejectedWithSessionEncodedAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint parentAuthSessionHandle = 0;
        uint decryptSessionHandle = 0;

        try
        {
            (parentAuthSessionHandle, TpmSession parentAuthSession, _, _) =
                await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
            using(parentAuthSession)
            {
                (decryptSessionHandle, TpmSession decryptSession, _, _) =
                    await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
                using(decryptSession)
                {
                    //Session 0 negotiated a real symmetric (so the tampered decrypt bit does not instead trip the
                    //TPM_RC_SYMMETRIC check) but is sent WITHOUT the decrypt attribute; a wire-tampering device
                    //flips it on after the host has built and HMAC'd the command, so the "second decrypt session"
                    //rule (Part 3, clause 5.5) is what the simulator's own attribute-consistency pass — which runs
                    //strictly before any HMAC is evaluated — actually rejects on.
                    parentAuthSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;
                    decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                    byte[]? captured = null;
                    async ValueTask<TpmResult<TpmResponse>> SetFirstSessionDecryptBitAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
                    {
                        byte[] mutable = command.ToArray();
                        captured = mutable;
                        SetSessionAttributesBit(mutable, sessionOrdinal: 0, (byte)TpmaSession.DECRYPT);

                        return await simulator.SubmitAsync(mutable, commandPool, ct).ConfigureAwait(false);
                    }

                    using TpmDevice tamperingDevice = TpmDevice.Create(SetFirstSessionDecryptBitAsync);

                    using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, IntendedUserAuth, pool);
                    using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
                    using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                    TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                        tamperingDevice, createInput, [parentAuthSession, decryptSession], [parent.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsFalse(result.IsSuccess, "A second session claiming decrypt must be rejected.");
                    Assert.AreEqual(
                        SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), result.ResponseCode,
                        "Only ONE session may set the decrypt attribute; the SECOND offending session (index 1) is blamed, not the first.");
                    Assert.IsNotNull(captured, "The tampering wrapper must have observed the outgoing command.");
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, decryptSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentAuthSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task DecryptOnUnsealIsRejectedBecauseItHasNoEncryptableCommandParameter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;

        try
        {
            using LoadResponse loaded = await SealAndLoadPlainAsync(tpm, registry, pool, parentHandle).ConfigureAwait(false);
            itemHandle = loaded.ObjectHandle.Value;

            (sessionHandle, TpmSession session, _, _) = await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION;
                session.SetAuthValue(IntendedUserAuth, pool);

                //Unseal has no command parameters at all, so a decrypt-attributed session over it must be
                //rejected outright (Part 3, clause 5.5) — set by wire tampering, since Unseal's own UnsealInput
                //never exposes a decrypt-eligible first parameter for the host to agree to in the first place.
                byte[]? captured = null;
                async ValueTask<TpmResult<TpmResponse>> SetDecryptBitAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
                {
                    byte[] mutable = command.ToArray();
                    captured = mutable;
                    SetSessionAttributesBit(mutable, sessionOrdinal: 0, (byte)TpmaSession.DECRYPT);

                    return await simulator.SubmitAsync(mutable, commandPool, ct).ConfigureAwait(false);
                }

                using TpmDevice tamperingDevice = TpmDevice.Create(SetDecryptBitAsync);

                UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
                TpmResult<UnsealResponse> result = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                    tamperingDevice, unsealInput, [session], [loaded.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(result.IsSuccess, "Decrypt on a command with no encryptable first parameter must be rejected.");
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), result.ResponseCode,
                    "TPM2_Unseal() has no encryptable command parameter, so decrypt SET is TPM_RC_ATTRIBUTES.");
                Assert.IsNotNull(captured, "The tampering wrapper must have observed the outgoing command.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task NullSymmetricDecryptSessionIsRejectedWithSessionEncodedSymmetric()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint parentAuthSessionHandle = 0;
        uint nullSymmetricSessionHandle = 0;

        try
        {
            (parentAuthSessionHandle, TpmSession parentAuthSession, _, _) =
                await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Null).ConfigureAwait(false);
            using(parentAuthSession)
            {
                //Negotiated with TPM_ALG_NULL at StartAuthSession time — the simulator's own recorded symmetric
                //for this session handle is permanently Null; only the per-command decrypt BIT is tampered on.
                (nullSymmetricSessionHandle, TpmSession nullSymmetricSession, _, _) =
                    await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Null).ConfigureAwait(false);
                using(nullSymmetricSession)
                {
                    parentAuthSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;
                    nullSymmetricSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;

                    byte[]? captured = null;
                    async ValueTask<TpmResult<TpmResponse>> SetSecondSessionDecryptBitAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
                    {
                        byte[] mutable = command.ToArray();
                        captured = mutable;
                        SetSessionAttributesBit(mutable, sessionOrdinal: 1, (byte)TpmaSession.DECRYPT);

                        return await simulator.SubmitAsync(mutable, commandPool, ct).ConfigureAwait(false);
                    }

                    using TpmDevice tamperingDevice = TpmDevice.Create(SetSecondSessionDecryptBitAsync);

                    using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, IntendedUserAuth, pool);
                    using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
                    using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                    TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                        tamperingDevice, createInput, [parentAuthSession, nullSymmetricSession], [parent.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsFalse(result.IsSuccess, "A decrypt session negotiated with TPM_ALG_NULL must be rejected.");
                    Assert.AreEqual(
                        SessionEncodedRc(TpmRcConstants.TPM_RC_SYMMETRIC, sessionIndex: 1), result.ResponseCode,
                        "decrypt SET on a session whose negotiated symmetric is TPM_ALG_NULL is TPM_RC_SYMMETRIC.");
                    Assert.IsNotNull(captured, "The tampering wrapper must have observed the outgoing command.");
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, nullSymmetricSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentAuthSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task StrippingTheDecryptSessionMakesTheParentAuthHmacMismatch()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint parentAuthSessionHandle = 0;
        uint decryptSessionHandle = 0;

        try
        {
            (parentAuthSessionHandle, TpmSession parentAuthSession, _, _) =
                await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Null).ConfigureAwait(false);
            using(parentAuthSession)
            {
                (decryptSessionHandle, TpmSession decryptSession, _, _) =
                    await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
                using(decryptSession)
                {
                    parentAuthSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;
                    decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                    byte[]? captured = null;
                    async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
                    {
                        captured = command.ToArray();
                        return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
                    }

                    using TpmDevice capturingDevice = TpmDevice.Create(CaptureAsync);

                    using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, IntendedUserAuth, pool);
                    using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
                    using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                    //The SAME bytes WITH the decrypt session present must succeed (non-vacuous baseline).
                    TpmResult<CreateResponse> genuineResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                        capturingDevice, createInput, [parentAuthSession, decryptSession], [parent.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(genuineResult.IsSuccess, $"The genuine two-session Create must succeed: '{genuineResult.ResponseCode}'.");
                    genuineResult.Value.Dispose();

                    Assert.IsNotNull(captured, "The capturing wrapper must have observed the outgoing command.");

                    byte[] stripped = RemoveSecondSession(captured!);

                    TpmResult<TpmResponse> strippedResult = await simulator.SubmitAsync(stripped, pool, TestContext.CancellationToken).ConfigureAwait(false);
                    using(TpmResponse strippedResponse = strippedResult.Value)
                    {
                        var reader = new TpmReader(strippedResponse.AsReadOnlySpan());
                        TpmHeader header = TpmHeader.Parse(ref reader);
                        var rc = (TpmRcConstants)header.Code;

                        //The storage parent is created with noDa SET (CreateStorageParentAsync), so it is
                        //DA-exempt: a mismatched HMAC against it is TPM_RC_BAD_AUTH, never counted TPM_RC_AUTH_FAIL.
                        Assert.AreEqual(
                            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), rc,
                            $"Removing the decrypt session must make session 0's command HMAC mismatch (the fold, clause 17.6.3.4, no longer applies), got '{rc}'.");
                    }
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, decryptSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentAuthSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task IndependentlyEncryptedInSensitiveDecryptsCorrectlyThroughTheHandCraftedWirePath()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        try
        {
            HandCraftedCreateResult result = await SendHandCraftedCreateAsync(
                simulator, pool, parentHandle, parent.Name.Span.ToArray(), corruptDeclaredInSensitiveSize: false, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, result.ResponseCode, "The independently-encrypted request must be accepted.");
            Assert.IsNotNull(result.OutPrivate);
            Assert.IsNotNull(result.OutPublic);

            using LoadResponse loaded = await LoadSealedObjectRawAsync(tpm, registry, pool, parentHandle, result.OutPrivate!, result.OutPublic!).ConfigureAwait(false);
            try
            {
                (uint verifySessionHandle, TpmSession verifySession, _, _) =
                    await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Null).ConfigureAwait(false);
                try
                {
                    using(verifySession)
                    {
                        verifySession.SetAuthValue(IntendedUserAuth, pool);

                        UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
                        TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                            tpm, unsealInput, [verifySession], [loaded.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                        Assert.IsTrue(unsealResult.IsSuccess, $"Unseal with the intended userAuth must succeed: '{unsealResult.ResponseCode}'.");
                        using UnsealResponse unsealed = unsealResult.Value;
                        Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes), "The recovered secret must equal the sealed one.");
                    }
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, registry, verifySessionHandle).ConfigureAwait(false);
                }
            }
            finally
            {
                await FlushIfPresentAsync(tpm, registry, loaded.ObjectHandle.Value).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task TruncatedFirstParameterSizeIsRejectedWithSessionEncodedSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        try
        {
            HandCraftedCreateResult result = await SendHandCraftedCreateAsync(
                simulator, pool, parentHandle, parent.Name.Span.ToArray(), corruptDeclaredInSensitiveSize: true, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_SIZE, sessionIndex: 1), result.ResponseCode,
                "A declared inSensitive size exceeding the remaining parameter bytes must be TPM_RC_SIZE, session-index-encoded to the decrypt session.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// F3 regression (adversarial review, MINOR wrong RC): a locked-out TPM must reject <c>TPM2_Create()</c>
    /// with <c>TPM_RC_LOCKOUT</c> when the parent is DA-protected, regardless of whether the parent-authorizing
    /// session is a bound HMAC session or a plain <c>TPM_RS_PW</c>. Before the fix,
    /// <c>OnCreateSealedObjectOverSessions</c> gated lockout only when the FIRST session was a real HMAC
    /// session (<c>if(firstIsHmac &amp;&amp; parentIsDaProtected &amp;&amp; state.IsInLockout)</c>), so a
    /// <c>TPM_RS_PW</c> parent-auth session paired with a decrypt-attributed HMAC companion — the two-session
    /// shape <c>TryParseCreate</c> routes to this same function — skipped the lockout refusal entirely and
    /// performed the Create while locked out (TPM 2.0 Library Part 3, clause 5.6, check 3: DA/Lockout is
    /// checked before any credential is evaluated, unconditionally).
    /// </summary>
    [TestMethod]
    public async Task LockedOutTpmRejectsCreateOverPasswordAuthorizedDaProtectedParent()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //A DA-protected storage parent (noDa: false) — the gate under test is keyed on this bit.
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: false);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary (DA-protected storage parent) failed: '{parentResult.ResponseCode}'.");

        using CreatePrimaryResponse parent = parentResult.Value;
        uint parentHandle = parent.ObjectHandle.Value;
        uint decryptSessionHandle = 0;
        uint bruteForceItemHandle = 0;

        try
        {
            //1. Lower maxTries so a handful of failures reaches Lockout mode quickly.
            TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
                ReadOnlyMemory<byte>.Empty, LockoutTestMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
                TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

            //2. Seal+load a THROWAWAY DA-protected object under the same parent and fail its Unseal password
            //LockoutTestMaxTries times. Any DA-protected auth surface feeds the ONE shared lockout counter (TPM
            //2.0 Library Part 1, clause 17.8) — this is independent of the Create exploit exercised in step 3.
            using Tpm2bSensitiveCreate bruteForceSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, IntendedUserAuth, pool);
            using Tpm2bPublic bruteForceTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: false);
            using CreateInput bruteForceCreateInput = new(parentHandle, bruteForceSensitive, bruteForceTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession bruteForceParentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<CreateResponse> bruteForceCreateResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, bruteForceCreateInput, [bruteForceParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(bruteForceCreateResult.IsSuccess, $"Create (throwaway DA-protected object) failed: '{bruteForceCreateResult.ResponseCode}'.");

            using CreateResponse bruteForceObject = bruteForceCreateResult.Value;
            LoadResponse bruteForceLoaded = await LoadSealedObjectAsync(tpm, registry, pool, parentHandle, bruteForceObject).ConfigureAwait(false);
            using(bruteForceLoaded)
            {
                bruteForceItemHandle = bruteForceLoaded.ObjectHandle.Value;

                byte[] wrongPassword = [0xFF, 0xEE, 0xDD, 0xCC];
                for(uint attempt = 1; attempt <= LockoutTestMaxTries; attempt++)
                {
                    using TpmPasswordSession wrongAuth = TpmPasswordSession.Create(wrongPassword, pool);
                    UnsealInput bruteForceUnsealInput = UnsealInput.ForItem(bruteForceLoaded.ObjectHandle);
                    TpmResult<UnsealResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                        tpm, bruteForceUnsealInput, [wrongAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsFalse(wrongResult.IsSuccess, $"Attempt {attempt} of {LockoutTestMaxTries} with a wrong password must fail.");
                }
            }

            //Confirm the TPM actually reached Lockout mode before exercising the exploit below.
            TpmResult<TpmDictionaryAttackParameters> lockoutState = await tpm.GetDictionaryAttackParametersAsync(
                pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(lockoutState.IsSuccess, $"GetDictionaryAttackParameters failed: '{lockoutState.ResponseCode}'.");
            Assert.IsTrue(lockoutState.Value.IsLockedOut, "The TPM must be in Lockout mode before the Create exploit runs.");

            //3. THE EXPLOIT: TPM2_Create() with [TPM_RS_PW parent-auth session, bound HMAC decrypt-attributed
            //companion] against the (now globally locked-out) DA-protected parent — the two-session shape that
            //routes to OnCreateSealedObjectOverSessions via TryParseCreate's "!isSingleSession" branch.
            (decryptSessionHandle, TpmSession decryptSession, _, _) =
                await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
            using(decryptSession)
            {
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using TpmPasswordSession exploitParentAuth = TpmPasswordSession.CreateEmpty(pool);
                using Tpm2bSensitiveCreate exploitSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, IntendedUserAuth, pool);
                using Tpm2bPublic exploitTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: false);
                using CreateInput exploitCreateInput = new(parentHandle, exploitSensitive, exploitTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                TpmResult<CreateResponse> exploitResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                    tpm, exploitCreateInput, [exploitParentAuth, decryptSession], [parent.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                if(exploitResult.IsSuccess)
                {
                    exploitResult.Value.Dispose();
                }

                Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, exploitResult.ResponseCode,
                    "A locked-out TPM must reject TPM2_Create() over a DA-protected parent authorized by " +
                    $"[TPM_RS_PW, decrypt HMAC] with TPM_RC_LOCKOUT, regardless of the parent session's kind (got '{exploitResult.ResponseCode}').");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, decryptSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, bruteForceItemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// The outcome of <see cref="SendHandCraftedCreateAsync"/>: the response code, on success the created
    /// object's private blob and public area, and the two session handles the helper started, so a caller that
    /// accounts for pool rentals can flush them and settle the sessions' durable carriers.
    /// </summary>
    /// <param name="ResponseCode">The command's response code.</param>
    /// <param name="OutPrivate">The created object's private blob, or <see langword="null"/> when the command was refused.</param>
    /// <param name="OutPublic">The created object's public area, or <see langword="null"/> when the command was refused.</param>
    /// <param name="AuthorizingSessionHandle">The parent-authorizing session the helper started.</param>
    /// <param name="DecryptSessionHandle">The decrypt companion the helper started.</param>
    private sealed record HandCraftedCreateResult(
        TpmRcConstants ResponseCode, byte[]? OutPrivate, Tpm2bPublic? OutPublic, uint AuthorizingSessionHandle, uint DecryptSessionHandle);

    /// <summary>
    /// Hand-assembles a <c>TPM2_Create()</c> over-sessions command with two UNBOUND, UNSALTED HMAC sessions (a
    /// parent-authorizing session and a SEPARATE decrypt session negotiating XOR), independently knows both
    /// session keys to be the Empty Buffer (neither session is bound nor salted, so no KDFa runs — Part 1
    /// clause 17.6.9), independently XOR-encrypts <c>inSensitive</c>'s data portion via
    /// <see cref="TpmParameterEncryption.XorAsync"/>, independently composes both command HMACs (equation 17
    /// (Part 1, clause 17.6.5) plus the nonceTPMdecrypt fold, clause 17.6.3.4) through the project's registered digest/HMAC seam, and submits
    /// the raw bytes directly to the simulator.
    /// </summary>
    /// <param name="corruptDeclaredInSensitiveSize">
    /// When set, <c>inSensitive</c>'s own outer size field (never itself encrypted, Part 1 clause 21.1) is
    /// overwritten to declare far more bytes than actually follow, after encryption — proving the simulator's own
    /// truncated-size guard independently of the host executor's identical, unavoidable pre-flight guard.
    /// </param>
    /// <param name="userAuthOverride">
    /// The octets to place in <c>TPMS_SENSITIVE_CREATE.userAuth</c> instead of <see cref="IntendedUserAuth"/>,
    /// written straight to the wire rather than through <see cref="Tpm2bAuth"/> so a proof can declare a width
    /// that carrier's own factory refuses; <see langword="null"/> for the intended value, which is written by the
    /// production wire type as every other case here is.
    /// </param>
    private static async Task<HandCraftedCreateResult> SendHandCraftedCreateAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint parentHandle, ReadOnlyMemory<byte> parentName,
        bool corruptDeclaredInSensitiveSize, CancellationToken cancellationToken, byte[]? userAuthOverride = null)
    {
        (uint firstHandle, Tpm2bAuth firstKey, byte[] firstNonceTpm) = await StartUnboundHmacSessionWithIndependentKeyAsync(
            simulator, pool, TpmtSymDef.Null, cancellationToken).ConfigureAwait(false);
        (uint decryptHandle, Tpm2bAuth decryptKey, byte[] decryptNonceTpm) = await StartUnboundHmacSessionWithIndependentKeyAsync(
            simulator, pool, TpmtSymDef.Xor(SessionAlg), cancellationToken).ConfigureAwait(false);

        try
        {
            byte[] firstNonceCaller = DrawNonceCaller(DigestSize, pool);
            byte[] decryptNonceCaller = DrawNonceCaller(DigestSize, pool);
            const byte firstAttributes = (byte)TpmaSession.CONTINUE_SESSION;
            const byte decryptAttributes = (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT);

            //inSensitive's data portion (everything after its own outer 2-octet size field): userAuth (TPM2B_AUTH)
            //then data (TPM2B_SENSITIVE_DATA), Part 2 clause 11.1.15 — built with production wire-structure types
            //(not hand-rolled), then XORed independently. A caller-supplied userAuth is the one exception: it is
            //written straight to the wire, which is the only way to present a width Tpm2bAuth itself refuses.
            using Tpm2bAuth userAuthField = userAuthOverride is null ? Tpm2bAuth.Create(IntendedUserAuth, pool) : Tpm2bAuth.Empty;
            using Tpm2bSensitiveData dataField = Tpm2bSensitiveData.Create(SecretBytes, pool);
            int userAuthFieldSize = userAuthOverride is null ? userAuthField.SerializedSize : sizeof(ushort) + userAuthOverride.Length;
            int sensitiveInnerSize = userAuthFieldSize + dataField.SerializedSize;
            using IMemoryOwner<byte> sensitiveInnerOwner = pool.Rent(sensitiveInnerSize);
            Memory<byte> sensitiveInner = sensitiveInnerOwner.Memory[..sensitiveInnerSize];
            {
                var innerWriter = new TpmWriter(sensitiveInner.Span);
                if(userAuthOverride is null)
                {
                    userAuthField.WriteTo(ref innerWriter);
                }
                else
                {
                    innerWriter.WriteTpm2b(userAuthOverride);
                }

                dataField.WriteTo(ref innerWriter);
            }

            //mask = KDFa(SHA256, decryptSessionKey, "XOR", nonceCaller, nonceTPM, sensitiveInnerSize·8) XORed in
            //place (Part 1, clause 19.2, equation 4) — through the project's own XOR obfuscation primitive, the
            //same one a genuine decrypt session drives; independence here is that THIS test derives the key and
            //the nonces by hand rather than through a production TpmSession.
            await TpmParameterEncryption.XorAsync(
                HashAlgorithmName.SHA256, decryptKey.AsReadOnlyMemory(), decryptNonceCaller, decryptNonceTpm, sensitiveInner, pool, cancellationToken).ConfigureAwait(false);

            using Tpm2bPublic inPublic = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
            int inPublicSize = inPublic.GetSerializedSize();

            ushort declaredInnerSize = corruptDeclaredInSensitiveSize ? ushort.MaxValue : (ushort)sensitiveInnerSize;

            //Parameters: inSensitive (declared size ‖ possibly-encrypted inner bytes) ‖ inPublic ‖ outsideInfo (empty) ‖ creationPCR (empty).
            int parametersSize = sizeof(ushort) + sensitiveInnerSize + inPublicSize + sizeof(ushort) + sizeof(uint);
            using IMemoryOwner<byte> parametersOwner = pool.Rent(parametersSize);
            Memory<byte> parameters = parametersOwner.Memory[..parametersSize];
            {
                var paramWriter = new TpmWriter(parameters.Span);
                paramWriter.WriteUInt16(declaredInnerSize);
                paramWriter.WriteBytes(sensitiveInner.Span);
                inPublic.WriteTo(ref paramWriter);
                paramWriter.WriteUInt16(0); //outsideInfo: empty TPM2B_DATA.
                paramWriter.WriteUInt32(0); //creationPCR: empty TPML_PCR_SELECTION (count = 0).
            }

            //cpHash = H_SHA256(commandCode ‖ parentName ‖ parameters) — Part 1, clause 16.7, equation 15.
            int cpHashInputLength = sizeof(uint) + parentName.Length + parametersSize;
            using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
            {
                var writer = new TpmWriter(cpHashInputOwner.Memory.Span[..cpHashInputLength]);
                writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_Create);
                writer.WriteBytes(parentName.Span);
                writer.WriteBytes(parameters.Span);
            }

            using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
                cpHashInputOwner.Memory[..cpHashInputLength], outputByteLength: DigestSize, tag: DigestTag(), pool: pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            //Session 0 authorizes the parent, so its command HMAC folds the decrypt session's nonceTPM (clause
            //17.6.3.4); the parent carries no retained authValue in this model, so the HMAC key is the session key
            //alone (equivalent to equation 19 (Part 1, clause 17.6.9)'s degenerate form).
            using HmacValue firstHmac = await ComputeIndependentCommandHmacAsync(
                firstKey.AsReadOnlyMemory(), cpHash.AsReadOnlyMemory(), firstNonceCaller, firstNonceTpm, decryptNonceTpm, firstAttributes, pool, cancellationToken).ConfigureAwait(false);
            using HmacValue decryptHmac = await ComputeIndependentCommandHmacAsync(
                decryptKey.AsReadOnlyMemory(), cpHash.AsReadOnlyMemory(), decryptNonceCaller, decryptNonceTpm, foldedNonces: ReadOnlyMemory<byte>.Empty, decryptAttributes, pool, cancellationToken).ConfigureAwait(false);

            int authBodySize =
                (sizeof(uint) + (sizeof(ushort) + firstNonceCaller.Length) + sizeof(byte) + (sizeof(ushort) + firstHmac.Length)) +
                (sizeof(uint) + (sizeof(ushort) + decryptNonceCaller.Length) + sizeof(byte) + (sizeof(ushort) + decryptHmac.Length));

            int totalSize = TpmConstants.HeaderSize + sizeof(uint) + sizeof(uint) + authBodySize + parametersSize;
            using IMemoryOwner<byte> commandOwner = pool.Rent(totalSize);
            Memory<byte> command = commandOwner.Memory[..totalSize];
            var commandWriter = new TpmWriter(command.Span);
            commandWriter.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
            commandWriter.WriteUInt32((uint)totalSize);
            commandWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_Create);
            commandWriter.WriteUInt32(parentHandle);
            commandWriter.WriteUInt32((uint)authBodySize);
            commandWriter.WriteUInt32(firstHandle);
            commandWriter.WriteTpm2b(firstNonceCaller);
            commandWriter.WriteByte(firstAttributes);
            commandWriter.WriteTpm2b(firstHmac.AsReadOnlySpan());
            commandWriter.WriteUInt32(decryptHandle);
            commandWriter.WriteTpm2b(decryptNonceCaller);
            commandWriter.WriteByte(decryptAttributes);
            commandWriter.WriteTpm2b(decryptHmac.AsReadOnlySpan());
            commandWriter.WriteBytes(parameters.Span);

            TpmResult<TpmResponse> transportResult = await simulator.SubmitAsync(command, pool, cancellationToken).ConfigureAwait(false);
            using TpmResponse response = transportResult.Value;
            var responseReader = new TpmReader(response.AsReadOnlySpan());
            ushort responseTag = responseReader.ReadUInt16();
            _ = responseReader.ReadUInt32();
            var responseCode = (TpmRcConstants)responseReader.ReadUInt32();

            if(responseCode != TpmRcConstants.TPM_RC_SUCCESS || responseTag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
            {
                return new HandCraftedCreateResult(responseCode, null, null, firstHandle, decryptHandle);
            }

            //Success: the response parameter area (outPrivate ‖ outPublic) sits right after the parameterSize field;
            //this test does not re-verify the response HMACs (already exercised by the parameter-encryption and
            //session-auth flow tests) — only that the CONTENT round-trips.
            uint responseParameterSize = responseReader.ReadUInt32();
            ReadOnlySpan<byte> responseParameters = responseReader.PeekBytes((int)responseParameterSize);
            var paramReader = new TpmReader(responseParameters);
            Tpm2bPrivate outPrivate = Tpm2bPrivate.Parse(ref paramReader, pool);
            Tpm2bPublic outPublic = Tpm2bPublic.Parse(ref paramReader, pool);
            byte[] outPrivateBytes;
            using(outPrivate)
            {
                outPrivateBytes = outPrivate.Span.ToArray();
            }

            return new HandCraftedCreateResult(TpmRcConstants.TPM_RC_SUCCESS, outPrivateBytes, outPublic, firstHandle, decryptHandle);
        }
        finally
        {
            firstKey.Dispose();
            decryptKey.Dispose();
        }
    }

    /// <summary>
    /// Starts an unbound, unsalted HMAC session through the production <c>TPM2_StartAuthSession()</c> path and
    /// returns its handle plus the session's INDEPENDENTLY known session key and initial nonceTPM. Because the
    /// session is neither bound nor salted, sessionKey is the Empty Buffer (TPM 2.0 Library Part 1, clause
    /// 17.6.9) — no KDFa is run at all — so the "independent" oracle here is simply the empty key, not a
    /// derivation. The caller disposes the returned <see cref="Tpm2bAuth"/>, which zeroes the key on release.
    /// </summary>
    private static async Task<(uint SessionHandle, Tpm2bAuth SessionKey, byte[] NonceTpm)> StartUnboundHmacSessionWithIndependentKeyAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmtSymDef symmetric, CancellationToken cancellationToken)
    {
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, symmetric);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse startResponse = startResult.Value;
        byte[] nonceTpm = startResponse.NonceTPM.AsReadOnlySpan().ToArray();

        return (startResponse.SessionHandle.Value, Tpm2bAuth.CreateEmpty(pool), nonceTpm);
    }

    /// <summary>
    /// Independent command-HMAC composition (TPM 2.0 Library Part 1, clause 17.6.5 equation 17, plus the
    /// nonceTPMdecrypt fold of clause 17.6.3.4): <c>HMAC(sessionKey, cpHash ‖ nonceCaller ‖ nonceTPM ‖
    /// foldedNonces ‖ sessionAttributes)</c>, assembled via <see cref="TpmWriter"/> into a pooled buffer and
    /// computed through <c>CryptographicKeyEvents.ComputeHmacAsync</c> — the parent carries no retained authValue
    /// in this model, so the key is the session key alone.
    /// </summary>
    private static async ValueTask<HmacValue> ComputeIndependentCommandHmacAsync(
        ReadOnlyMemory<byte> sessionKey, ReadOnlyMemory<byte> cpHash, ReadOnlyMemory<byte> nonceCaller, ReadOnlyMemory<byte> nonceTpm,
        ReadOnlyMemory<byte> foldedNonces, byte sessionAttributes, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        int inputLength = cpHash.Length + nonceCaller.Length + nonceTpm.Length + foldedNonces.Length + 1;
        using IMemoryOwner<byte> input = pool.Rent(inputLength);
        var writer = new TpmWriter(input.Memory.Span[..inputLength]);
        writer.WriteBytes(cpHash.Span);
        writer.WriteBytes(nonceCaller.Span);
        writer.WriteBytes(nonceTpm.Span);
        if(!foldedNonces.IsEmpty)
        {
            writer.WriteBytes(foldedNonces.Span);
        }
        writer.WriteByte(sessionAttributes);

        return await CryptographicKeyEvents.ComputeHmacAsync(
            input.Memory[..inputLength], sessionKey, outputByteLength: DigestSize, tag: HmacTag(), pool: pool, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Draws a nonceCaller of <paramref name="length"/> octets through the registered <see cref="GenerateNonceDelegate"/>
    /// (never a bare <see cref="RandomNumberGenerator"/> call) and materializes it as a plain octet array, the
    /// shape the hand-crafted wire assembly above holds every session field in.
    /// </summary>
    private static byte[] DrawNonceCaller(int length, BaseMemoryPool pool)
    {
        using Nonce nonce = CryptographicKeyEvents.GenerateNonce(length, Tag.Create(Purpose.Nonce), pool);
        return nonce.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Builds the digest <see cref="Tag"/> exactly as <c>TpmCommandExecutor.BuildDigestTag</c> does: SHA-256
    /// digest, raw encoding, direct material.
    /// </summary>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    /// <summary>
    /// Builds the HMAC <see cref="Tag"/> exactly as <c>TpmSession.ComputeSessionHmacAsync</c> does: SHA-256
    /// HMAC, raw encoding, direct material.
    /// </summary>
    private static Tag HmacTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Hmac).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);


    /// <summary>
    /// Sets a bit in the <paramref name="sessionOrdinal"/>-th (zero-based) session's <c>sessionAttributes</c>
    /// octet of a captured command, navigating the auth area with a <see cref="TpmReader"/> so it works
    /// regardless of nonce sizes. Mutates <paramref name="command"/> in place.
    /// </summary>
    private static void SetSessionAttributesBit(byte[] command, int sessionOrdinal, byte bit)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        _ = reader.ReadUInt32(); //parentHandle.
        _ = reader.ReadUInt32(); //authorizationSize.

        for(int i = 0; i < sessionOrdinal; i++)
        {
            _ = reader.ReadUInt32(); //sessionHandle.
            ushort skipNonceSize = reader.ReadUInt16();
            reader.Skip(skipNonceSize);
            _ = reader.ReadByte(); //sessionAttributes.
            ushort skipHmacSize = reader.ReadUInt16();
            reader.Skip(skipHmacSize);
        }

        _ = reader.ReadUInt32(); //this session's handle.
        ushort nonceSize = reader.ReadUInt16();
        reader.Skip(nonceSize);

        int attributesIndex = reader.Consumed;
        command[attributesIndex] |= bit;
    }

    /// <summary>
    /// Removes the second session's entire <c>TPMS_AUTH_COMMAND</c> entry from a captured two-session command,
    /// patching <c>authorizationSize</c> and <c>commandSize</c> to match — the wire-level "stripped decrypt
    /// session" this fold detects.
    /// </summary>
    private static byte[] RemoveSecondSession(byte[] command)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        _ = reader.ReadUInt32(); //parentHandle.
        uint authorizationSize = reader.ReadUInt32();
        int sessionsStart = reader.Consumed;

        //First session: skip over it (handle + nonce + attributes + hmac).
        _ = reader.ReadUInt32();
        ushort firstNonceSize = reader.ReadUInt16();
        reader.Skip(firstNonceSize);
        _ = reader.ReadByte();
        ushort firstHmacSize = reader.ReadUInt16();
        reader.Skip(firstHmacSize);

        int secondSessionStart = reader.Consumed;

        //Second session: measure its length, then drop it.
        _ = reader.ReadUInt32();
        ushort secondNonceSize = reader.ReadUInt16();
        reader.Skip(secondNonceSize);
        _ = reader.ReadByte();
        ushort secondHmacSize = reader.ReadUInt16();
        reader.Skip(secondHmacSize);

        int secondSessionEnd = reader.Consumed;
        int secondSessionLength = secondSessionEnd - secondSessionStart;

        byte[] stripped = new byte[command.Length - secondSessionLength];
        Array.Copy(command, 0, stripped, 0, secondSessionStart);
        Array.Copy(command, secondSessionEnd, stripped, secondSessionStart, command.Length - secondSessionEnd);

        //Patch authorizationSize (right after parentHandle, i.e. at TpmConstants.HeaderSize + 4) and commandSize
        //(at offset 2, the UINT32 right after the 2-octet tag).
        int authorizationSizeOffset = TpmConstants.HeaderSize + sizeof(uint);
        BinaryPrimitives.WriteUInt32BigEndian(stripped.AsSpan(authorizationSizeOffset), authorizationSize - (uint)secondSessionLength);
        BinaryPrimitives.WriteUInt32BigEndian(stripped.AsSpan(sizeof(ushort)), (uint)stripped.Length);

        _ = sessionsStart; //Only used to document the auth area's start; the patch offsets above are computed directly.

        return stripped;
    }


    /// <summary>
    /// Wraps a real, production <see cref="TpmSession"/> for every concern EXCEPT command-direction parameter
    /// encryption, which this type makes a deliberate no-op — simulating a caller that claims the <c>decrypt</c>
    /// attribute but sends the plaintext, so the simulator's OWN (genuine) decrypt corrupts it. Everything else
    /// (nonce rolling, the command HMAC, response verification) delegates to the wrapped session unchanged, so
    /// the command HMAC is still computed for real, over whatever bytes actually went out.
    /// </summary>
    private sealed class SkipEncryptionHmacSession: TpmSessionBase, IDisposable
    {
        /// <summary>The wrapped, production session every other concern delegates to.</summary>
        private readonly TpmSession inner;

        /// <summary>
        /// Wraps <paramref name="inner"/>, mirroring its session attributes and symmetric definition so the host
        /// executor's own admissibility checks see the same values a genuine session would report.
        /// </summary>
        /// <param name="inner">The production session to wrap; disposed together with this instance.</param>
        public SkipEncryptionHmacSession(TpmSession inner)
        {
            this.inner = inner;
            SessionAttributes = inner.SessionAttributes;
            Symmetric = inner.Symmetric;
        }

        /// <inheritdoc/>
        public override TpmHandle SessionHandle => inner.SessionHandle;

        /// <inheritdoc/>
        public override TpmAlgIdConstants HashAlgorithm => inner.HashAlgorithm;

        /// <inheritdoc/>
        public override ReadOnlyMemory<byte> NonceTpm => inner.NonceTpm;

        /// <inheritdoc/>
        public override void RollNonceCaller(BaseMemoryPool pool) => inner.RollNonceCaller(pool);

        /// <inheritdoc/>
        /// <remarks>Deliberately a no-op: the data is left exactly as received, unlike a genuine decrypt session.</remarks>
        public override ValueTask EncryptFirstParameterAsync(Memory<byte> firstParameterData, BaseMemoryPool pool, CancellationToken cancellationToken) =>
            ValueTask.CompletedTask;

        /// <inheritdoc/>
        public override int GetAuthCommandSize() => inner.GetAuthCommandSize();

        /// <inheritdoc/>
        public override ValueTask<Tpm2bAuth?> PrepareAuthHmacAsync(
            ReadOnlyMemory<byte> cpHash, BaseMemoryPool pool, CancellationToken cancellationToken, ReadOnlyMemory<byte> foldedSessionNonces = default) =>
            inner.PrepareAuthHmacAsync(cpHash, pool, cancellationToken, foldedSessionNonces);

        /// <inheritdoc/>
        public override void WriteAuthCommand(ref TpmWriter writer, Tpm2bAuth? precomputedHmac) => inner.WriteAuthCommand(ref writer, precomputedHmac);

        /// <inheritdoc/>
        public override ValueTask<bool> VerifyAndUpdateAsync(TpmsAuthResponse response, ReadOnlyMemory<byte> rpHash, BaseMemoryPool pool, CancellationToken cancellationToken) =>
            inner.VerifyAndUpdateAsync(response, rpHash, pool, cancellationToken);

        /// <summary>Disposes the wrapped session.</summary>
        public void Dispose() => inner.Dispose();
    }


    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)) — the test-side mirror of TpmLifecycleTransitions.SessionEncodedRc, transcribed
    /// independently since production helpers are private.
    /// </summary>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>
    /// Starts a bound, unsalted HMAC session against <paramref name="bindHandle"/> through the production
    /// <c>TPM2_StartAuthSession()</c> path and wraps it as a <see cref="TpmSession"/>. Negotiates
    /// <paramref name="sessionAlg"/> (defaulting to the file's usual <see cref="SessionAlg"/>) so a caller can
    /// build a mixed-hash multi-session command (F5: two sessions negotiating DIFFERENT hash algorithms).
    /// </summary>
    private async Task<(uint SessionHandle, TpmSession Session, byte[] InitialNonceCaller, byte[] InitialNonceTpm)> StartHmacSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint bindHandle, TpmtSymDef symmetric, TpmAlgIdConstants sessionAlg = SessionAlg)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(bindHandle, sessionAlg, symmetric);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        byte[] initialNonceCaller = startInput.NonceCaller.ToArray();
        byte[] initialNonceTpm = startResponse.NonceTPM.AsReadOnlySpan().ToArray();
        using Tpm2bAuth bindAuth = Tpm2bAuth.CreateEmpty(pool);

        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(startResponse.SessionHandle.Value), bindAuth.AsReadOnlyMemory(), startInput.NonceCaller,
            startResponse.NonceTPM, sessionAlg, pool, symmetric: symmetric, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (startResponse.SessionHandle.Value, session, initialNonceCaller, initialNonceTpm);
    }

    /// <summary>Loads a just-created sealed object back through the production <c>TPM2_Load()</c> path (password-authorized parent).</summary>
    /// <summary>
    /// An authValue "should not be larger than the digest size of the algorithm used to compute the Name of the
    /// object" (TPM 2.0 Library Part 1, clause 17.6.4.2, enforced by the reference's <c>TPM2_Create()</c> with
    /// <c>TPM_RC_SIZE</c>) — on the DECRYPTED path: a 33-octet <c>userAuth</c> against the SHA-256 nameAlg
    /// template, carried inside an XOR-encrypted <c>inSensitive</c>, is refused with <c>TPM_RC_SIZE</c> after
    /// decryption, exactly as the plain arm refuses it.
    /// </summary>
    [TestMethod]
    public async Task CreateOverSessionsWithAnOverWideDecryptedUserAuthIsRefusedWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint parentAuthSessionHandle = 0;
        uint decryptSessionHandle = 0;

        byte[] overWideUserAuth = new byte[33];
        overWideUserAuth.AsSpan().Fill(0x5A);

        try
        {
            (parentAuthSessionHandle, TpmSession parentAuthSession, _, _) =
                await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Null).ConfigureAwait(false);
            using(parentAuthSession)
            {
                (decryptSessionHandle, TpmSession decryptSession, _, _) =
                    await StartHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
                using(decryptSession)
                {
                    parentAuthSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;
                    decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                    using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, overWideUserAuth, pool);
                    using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
                    using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                    TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                        tpm, createInput, [parentAuthSession, decryptSession], [parent.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.AreEqual(
                        TpmRcConstants.TPM_RC_SIZE, createResult.ResponseCode,
                        "A decrypted userAuth wider than the nameAlg digest must be refused with TPM_RC_SIZE (Part 1, clause 17.6.4.2).");
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, decryptSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentAuthSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The <c>sizeof(TPMU_HA)</c> bound a <c>TPM2B_AUTH</c> carries (TPM 2.0 Library Part 2, clause 10.4.5, Table
    /// 95, page 135, over clause 10.4.2, Table 92, page 134) applies to the userAuth RECOVERED from an encrypted
    /// <c>inSensitive</c> exactly as it applies to a plaintext one, and this is the only authorization value on
    /// which it cannot be answered at the wire read: <c>inSensitive</c>'s OWN outer size field travels in the
    /// clear (Part 1, clause 19.1, so the parser can delimit the field), but the nested
    /// <c>TPMS_SENSITIVE_CREATE.userAuth</c> size field is inside the encrypted portion, and until the keystream
    /// is removed no parser can read it. So a declared width one octet past the bound is FIRST detectable after
    /// decryption, and is <c>TPM_RC_SIZE</c> there — bare, as every other refusal read out of the recovered
    /// structure is, since it is the recovered structure and not the frame that is malformed. The response code
    /// is the same one the plain form answers, so a caller cannot tell from the code alone whether its keystream
    /// or its input was wrong, which is the point: a wrong decryption key is undetectable (clause 19.1's
    /// malleability note), so recovered garbage must be refused as a structure rather than trusted.
    /// </summary>
    /// <remarks>
    /// The command is hand-assembled and independently encrypted through
    /// <see cref="TpmParameterEncryption.XorAsync"/> — the same seam
    /// <see cref="IndependentlyEncryptedInSensitiveDecryptsCorrectlyThroughTheHandCraftedWirePath"/> drives to
    /// prove the identical frame with an intended userAuth round-trips, which is what makes the refusal here
    /// attributable to the declared width. The declared width is written straight to the wire because
    /// <see cref="Tpm2bAuth.Create(ReadOnlySpan{byte}, BaseMemoryPool)"/> refuses the same bound by throwing, so
    /// no production factory can build the offending field. The accounting is read from real pool telemetry: the
    /// refusing arm is the terminal owner of everything the parse rented for the refused command, so once the two
    /// sessions the frame used are flushed nothing is left outstanding. The refusal sits AFTER the decrypt step,
    /// so this is the arm that answers for the two slots' supplied <c>hmac</c> carriers as well as for the
    /// parameter area and the two caller nonces — five rentals, all non-empty, all released by the one whole-
    /// request release the arm performs. The count is therefore read twice: immediately after the refusal, where
    /// the only carriers that may remain are the two sessions' retained nonceTPMs, and again after those two
    /// sessions are flushed.
    /// </remarks>
    [TestMethod]
    public async Task CreateOverADecryptSessionWithARecoveredUserAuthPastTheUnionBoundIsRefusedWithSize()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        byte[] pastBoundUserAuth = new byte[Tpm2bAuth.MaxSize + 1];
        pastBoundUserAuth.AsSpan().Fill(0x5A);

        try
        {
            long baseline = trackingPool.OutstandingCount;

            HandCraftedCreateResult result = await SendHandCraftedCreateAsync(
                simulator, pool, parentHandle, parent.Name.Span.ToArray(), corruptDeclaredInSensitiveSize: false,
                TestContext.CancellationToken, userAuthOverride: pastBoundUserAuth).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SIZE, result.ResponseCode,
                "A recovered userAuth declaring a size past sizeof(TPMU_HA) is not a well-formed TPM2B_AUTH whatever key produced it, so it is TPM_RC_SIZE.");

            Assert.AreEqual(
                baseline + RetainedNonceTpmPerSession * 2, trackingPool.OutstandingCount,
                "Every carrier the refused command's parse rented — the parameter area, both slots' caller nonces and both slots' supplied hmacs — is released at the refusing arm itself, so the only carriers still outstanding before any flush are the two sessions' retained nonceTPMs.");

            await FlushIfPresentAsync(tpm, registry, result.DecryptSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, result.AuthorizingSessionHandle).ConfigureAwait(false);

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The refusing arm releases every carrier the parse rented for the refused command, so flushing the two sessions returns the count to where it started.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_Load()</c> blob DECLARING an over-wide authorization value — a well-formed
    /// [length ‖ userAuth ‖ data] encoding whose 33-octet declared <c>userAuth</c> exceeds the SHA-256
    /// nameAlg's digest — must be refused with <c>TPM_RC_SIZE</c>: this model's private blob carries no
    /// integrity wrap yet, so the load-time bound (TPM 2.0 Library Part 1, clause 17.6.4.2) is what keeps a
    /// hand-crafted blob from installing a wider authValue than <c>TPM2_Create()</c>'s own gate admits.
    /// </summary>
    [TestMethod]
    public async Task LoadingABlobDeclaringAnOverWideUserAuthIsRefusedWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        try
        {
            using CreateResponse legitimate = await SealPlainAsync(tpm, registry, pool, parentHandle).ConfigureAwait(false);

            //[UINT16 = 33][33 filler octets][4 data octets]: structurally valid, over-wide declared userAuth.
            byte[] craftedBlob = new byte[sizeof(ushort) + 33 + 4];
            BinaryPrimitives.WriteUInt16BigEndian(craftedBlob, 33);
            craftedBlob.AsSpan(sizeof(ushort), 33).Fill(0x5A);

            TpmResult<LoadResponse> refused = await LoadSealedObjectRawExpectingAsync(
                tpm, registry, pool, parentHandle, craftedBlob, ClonePublic(legitimate.OutPublic, pool)).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SIZE, refused.ResponseCode,
                "A crafted blob declaring a userAuth wider than the nameAlg digest must be refused with TPM_RC_SIZE.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A structurally MALFORMED <c>TPM2_Load()</c> private blob — empty, shorter than its own length prefix, or
    /// declaring a <c>userAuth</c> length that overruns the blob — answers <c>TPM_RC_SIZE</c> on the wire
    /// instead of crashing the recovery arithmetic: the blob is attacker-controlled input, so a structure of
    /// the wrong size must be a response code, never an exception escaping the simulator.
    /// </summary>
    [TestMethod]
    public async Task MalformedPrivateBlobsAreRefusedWithSizeInsteadOfCrashing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        try
        {
            using CreateResponse legitimate = await SealPlainAsync(tpm, registry, pool, parentHandle).ConfigureAwait(false);

            //Empty; a single octet (shorter than the UINT16 length prefix); a declared length overrunning the blob.
            byte[][] malformedBlobs = [[], [0x00], [0xFF, 0xFF]];
            foreach(byte[] malformedBlob in malformedBlobs)
            {
                TpmResult<LoadResponse> refused = await LoadSealedObjectRawExpectingAsync(
                    tpm, registry, pool, parentHandle, malformedBlob, ClonePublic(legitimate.OutPublic, pool)).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_SIZE, refused.ResponseCode,
                    $"A malformed private blob of {malformedBlob.Length} octet(s) must be refused with TPM_RC_SIZE, never an exception.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>Seals a fixed secret under an empty-adjacent legitimate authValue via the password-only Create form and returns the response; the caller owns and must dispose it.</summary>
    private async Task<CreateResponse> SealPlainAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, IntendedUserAuth, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (seal) failed: '{createResult.ResponseCode}'.");

        return createResult.Value;
    }

    /// <summary>Loads a sealed object from raw private-blob bytes and a public area, returning the raw result without asserting — the negative-case counterpart of <see cref="LoadSealedObjectRawAsync"/>.</summary>
    private async Task<TpmResult<LoadResponse>> LoadSealedObjectRawExpectingAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, byte[] outPrivate, Tpm2bPublic outPublic)
    {
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(outPrivate, pool);
        using Tpm2bPublic inPublic = outPublic;
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    private async Task<LoadResponse> LoadSealedObjectAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, CreateResponse created) =>
        await LoadSealedObjectRawAsync(tpm, registry, pool, parentHandle, created.OutPrivate.Span.ToArray(), ClonePublic(created.OutPublic, pool)).ConfigureAwait(false);

    /// <summary>Loads a sealed object from raw private-blob bytes and a public area back through the production <c>TPM2_Load()</c> path.</summary>
    private async Task<LoadResponse> LoadSealedObjectRawAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, byte[] outPrivate, Tpm2bPublic outPublic)
    {
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(outPrivate, pool);
        using Tpm2bPublic inPublic = outPublic;
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");

        return loadResult.Value;
    }

    /// <summary>Seals a fixed secret under an empty authValue via the plain (untouched) password-only Create form, then loads it — used only to exercise Unseal's own rejection, independent of Package B's decrypt path.</summary>
    private async Task<LoadResponse> SealAndLoadPlainAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, IntendedUserAuth, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (seal) failed: '{createResult.ResponseCode}'.");

        using CreateResponse sealedObject = createResult.Value;

        return await LoadSealedObjectAsync(tpm, registry, pool, parentHandle, sealedObject).ConfigureAwait(false);
    }

    /// <summary>Reserializes a public area into a fresh <see cref="Tpm2bPublic"/> (a disk-persisted round trip).</summary>
    private static Tpm2bPublic ClonePublic(Tpm2bPublic source, BaseMemoryPool pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);

        var reader = new TpmReader(owner.Memory.Span[..size]);
        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>Flushes a transient object or session handle when one is present (non-zero), ignoring the result.</summary>
    private async Task FlushIfPresentAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        if(!registry.TryGet(TpmCcConstants.TPM_CC_FlushContext, out _))
        {
            _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        }

        var flush = FlushContextInput.ForHandle(handle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, BaseMemoryPool.Shared, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates the deterministic ECC storage parent under the owner hierarchy.</summary>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary storage parent failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a response codec registry covering the Create/Load/Unseal/StartAuthSession flows this file drives.</summary>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-param-decryption", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupClearAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire.
    /// </summary>
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
    }
}
