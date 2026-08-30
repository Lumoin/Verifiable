using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Foundation.Automata;
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

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Hardening coverage for <c>TPM2_SignSequenceStart()</c>, <c>TPM2_SequenceUpdate()</c>, and
/// <c>TPM2_SignSequenceComplete()</c> against the in-house behavioural <see cref="TpmSimulator"/>: the
/// key-identity binding by Name rather than handle, the completion-side attribute gates the simulator
/// generates only from a random primary (so they are proven by driving the shipped, public
/// <see cref="TpmLifecycleTransitions.Create"/> transition delegate directly over a state captured from the
/// simulator's own trace and a single flipped field), first-block forgery attempts split across the wire,
/// the absence of key authorization at Start, memory-pool balance across the whole command surface, and
/// malformed wire framings
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3: Commands, clauses 17.5, 17.7, 17.8, 20.6).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorSignSequenceHardeningTests
{
    /// <summary>The lowered <c>maxTries</c> used by the test that drives the TPM into Lockout mode quickly.</summary>
    private const uint LoweredMaxTries = 2;

    /// <summary>
    /// A transient handle value distinct from any handle the shared <c>NextObjectHandle</c> allocator would
    /// produce in these tests — stands in for a key reloaded at a different numeric handle in the flipped-state
    /// Name-binding drive.
    /// </summary>
    private const uint ReloadedSigningKeyHandleValue = 0x8000_FFFFu;

    /// <summary>
    /// <c>TPM_GENERATED_VALUE</c> (Table 7), big-endian: the four octets a restricted signing key's first
    /// presented sequence block must never begin with.
    /// </summary>
    private static byte[] TpmGeneratedValueBytes { get; } = [0xFF, 0x54, 0x43, 0x47];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The key identity a completing command must match is bound by Name, not by numeric handle: a key
    /// Name-equal to the one that started the sequence but loaded at a DIFFERENT handle still completes it.
    /// Because the simulator assigns primaries a random key pair, the positive half of this rule cannot be
    /// exercised by loading a genuine second copy of the same key over the wire; it is instead proven by
    /// capturing the state right after <c>TPM2_SignSequenceStart()</c> from the simulator's own trace
    /// subscription, installing the SAME (shared, not disposed) starting key's <see cref="TransientKeyState"/>
    /// under a second, different handle via a record <c>with</c> expression, and driving the public
    /// <see cref="TpmLifecycleTransitions.Create"/> transition delegate directly with a
    /// <see cref="TpmSignSequenceCompleteRequested"/> naming that new handle — exactly the input
    /// <c>TryParseSignSequenceComplete</c> would have produced from a real wire frame. No private member,
    /// reflection, or production-code test seam is touched
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6: "If keyHandle refers to a key that is not the same as
    /// the key that was used to start the signature context, the TPM shall return TPM_RC_SIGN_CONTEXT_KEY" — by
    /// exclusion, a key that IS the same reproduces the same Name and is admitted).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteAgainstAKeyNameEqualCopyAtADifferentHandleProducesTheSignAction()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        var capture = new LastStateObserver();
        using IDisposable subscription = simulator.Subscribe(capture);

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        TpmSimulatorState? maybeCapturedState = capture.LastState;
        Assert.IsNotNull(maybeCapturedState, "The simulator's own trace subscription must have observed at least one step by the time TPM2_SignSequenceStart() returns.");
        TpmSimulatorState capturedState = maybeCapturedState!;

        Assert.IsTrue(capturedState.TransientObjects.TryGetValue(primary.ObjectHandle, out TransientKeyState? maybeStartingKey), "The starting key must be present in the captured post-Start state.");
        TransientKeyState startingKey = maybeStartingKey!;

        TpmiDhObject reloadedHandle = TpmiDhObject.FromValue(ReloadedSigningKeyHandleValue);
        TransientKeyState nameEqualCopyAtANewHandle = startingKey with { Handle = reloadedHandle };
        TpmSimulatorState mutatedState = capturedState with
        {
            TransientObjects = capturedState.TransientObjects.SetItem(reloadedHandle, nameEqualCopyAtANewHandle)
        };

        //Both carriers are the shared, dispose-immune Empty sentinels: a successful transition disposes only the
        //two password carriers itself (never through this record's own Dispose), so this using's own Dispose on
        //scope exit is a harmless second call on carriers this drive never actually owned, kept here only to
        //satisfy this method's own local disposal obligation for the IDisposable it constructs.
        using var request = new TpmSignSequenceCompleteRequested(sequenceHandle, reloadedHandle, Tpm2bAuth.Empty, Tpm2bAuth.Empty, Tpm2bMaxBuffer.Empty);
        TransitionDelegate<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol> transition = TpmLifecycleTransitions.Create();
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? result = await transition(
            mutatedState, request, TpmSimulatorStackSymbol.Lifecycle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result, "OnSignSequenceComplete always yields a transition — either a rejection or a declared signing action — never a halt.");
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> nonNullResult = result!;
        Assert.IsInstanceOfType<TpmEccSignSequenceAction>(
            nonNullResult.NextState.NextAction,
            "A key Name-equal to the one that started the sequence, loaded at a DIFFERENT handle, must produce the signing action rather than a TPM_RC_SIGN_CONTEXT_KEY rejection.");
    }

    /// <summary>
    /// The other half of the Name-binding rule: a DIFFERENT key's state installed at the SAME numeric handle the
    /// sequence started under is refused with <c>TPM_RC_SIGN_CONTEXT_KEY</c>, proving the gate compares Names and
    /// not handles — an implementation comparing handles instead would incorrectly accept this request, since
    /// <c>keyHandle</c> equals the handle the sequence recorded
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteAgainstADifferentKeyLoadedAtTheStartingHandleReturnsSignContextKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        var capture = new LastStateObserver();
        using IDisposable subscription = simulator.Subscribe(capture);

        using CreatePrimaryResponse startingKeyPrimary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreatePrimaryResponse otherKeyPrimary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, startingKeyPrimary.ObjectHandle, []).ConfigureAwait(false);

        TpmSimulatorState? maybeCapturedState = capture.LastState;
        Assert.IsNotNull(maybeCapturedState, "The simulator's own trace subscription must have observed at least one step by the time TPM2_SignSequenceStart() returns.");
        TpmSimulatorState capturedState = maybeCapturedState!;

        Assert.IsTrue(capturedState.TransientObjects.TryGetValue(otherKeyPrimary.ObjectHandle, out TransientKeyState? maybeOtherKey), "The other key must be present in the captured post-Start state.");
        TransientKeyState otherKey = maybeOtherKey!;

        TransientKeyState otherKeyAtTheStartingHandle = otherKey with { Handle = startingKeyPrimary.ObjectHandle };
        TpmSimulatorState mutatedState = capturedState with
        {
            TransientObjects = capturedState.TransientObjects.SetItem(startingKeyPrimary.ObjectHandle, otherKeyAtTheStartingHandle)
        };

        using var request = new TpmSignSequenceCompleteRequested(sequenceHandle, startingKeyPrimary.ObjectHandle, Tpm2bAuth.Empty, Tpm2bAuth.Empty, Tpm2bMaxBuffer.Empty);
        TransitionDelegate<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol> transition = TpmLifecycleTransitions.Create();
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? result = await transition(
            mutatedState, request, TpmSimulatorStackSymbol.Lifecycle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result, "OnSignSequenceComplete always yields a transition — either a rejection or a declared signing action — never a halt.");
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> nonNullResult = result!;
        Assert.IsInstanceOfType<TpmHeaderOnlyResponse>(nonNullResult.NextState.ResponseIntent, "A rejection frames a header-only response.");
        var rejection = (TpmHeaderOnlyResponse)nonNullResult.NextState.ResponseIntent!;
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIGN_CONTEXT_KEY, rejection.ResponseCode,
            "A different key's state installed at the sequence's OWN starting handle must still be refused with TPM_RC_SIGN_CONTEXT_KEY: the gate compares Names, not handles.");
    }

    /// <summary>
    /// "The x509sign attribute of keyHandle must not be SET" is a normative refusal <c>TPM2_SignSequenceComplete()</c>
    /// carries independently of the errata fail-fast check <c>TPM2_SignSequenceStart()</c> performs; because a
    /// key's <c>x509sign</c> bit lives inside the <c>TPMT_PUBLIC</c> its Name is computed over, no wire sequence
    /// of commands can reach this gate (a key with x509sign SET is already refused at Start, and a DIFFERENT
    /// x509sign key at Complete trips the Name gate first). It is proven here by flipping only the retained
    /// <c>Attributes</c> field of the SAME starting key's captured state — leaving its already-computed Name
    /// unchanged, exactly as the request's own <c>keyHandle</c> still names it — and driving the public
    /// transition delegate directly
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteAgainstAKeyForcedX509SignReturnsAttributes()
    {
        var rejection = await DriveSignSequenceCompleteWithAFlippedStartingKeyAsync(
            startingKey => startingKey with { Attributes = startingKey.Attributes | TpmaObject.X509SIGN }).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, rejection.ResponseCode,
            "A key whose x509sign attribute is SET must be refused with TPM_RC_ATTRIBUTES at TPM2_SignSequenceComplete(), independently of the Start-side errata check.");
    }

    /// <summary>
    /// "If keyHandle does not refer to a signing key, the TPM shall return TPM_RC_KEY" is re-checked at Complete
    /// even though a key whose <c>sign</c> (SIGN_ENCRYPT) attribute is CLEAR is already refused at Start; because
    /// SIGN_ENCRYPT lives inside the Name-computed public area, this gate is likewise unreachable over the wire
    /// and is proven with the same flipped-state technique as the x509sign gate
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6; clause 20.5.1's definition of a signing key).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteAgainstAKeyForcedSignEncryptClearReturnsKey()
    {
        var rejection = await DriveSignSequenceCompleteWithAFlippedStartingKeyAsync(
            startingKey => startingKey with { Attributes = startingKey.Attributes & ~TpmaObject.SIGN_ENCRYPT }).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_KEY, rejection.ResponseCode,
            "A key whose sign (SIGN_ENCRYPT) attribute is CLEAR must be refused with TPM_RC_KEY at TPM2_SignSequenceComplete(), independently of the Start-side check.");
    }

    /// <summary>
    /// "If keyHandle refers to a key whose scheme is TPM_ALG_NULL, the TPM shall return TPM_RC_SCHEME" is
    /// re-checked at Complete even though a NULL-scheme key is already refused at Start; because the scheme lives
    /// inside the Name-computed public area, this gate is likewise unreachable over the wire and is proven with
    /// the same flipped-state technique
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteAgainstAKeyForcedNullSigningSchemeReturnsScheme()
    {
        var rejection = await DriveSignSequenceCompleteWithAFlippedStartingKeyAsync(
            startingKey => startingKey with { SigningScheme = null, SigningSchemeHashAlg = null }).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SCHEME, rejection.ResponseCode,
            "A key whose retained signing scheme is NULL must be refused with TPM_RC_SCHEME at TPM2_SignSequenceComplete(), independently of the Start-side check.");
    }

    /// <summary>
    /// The first-block safety verdict is settled from the FIRST buffer the sequence ever sees: an EMPTY first
    /// update settles it "not safe to sign" (fewer than <c>sizeof(TPM_GENERATED)</c> octets), and a SECOND update
    /// that opens with <c>TPM_GENERATED_VALUE</c> can never re-settle it — the restricted key is refused exactly
    /// as if the forged prefix had been presented first
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.7; clause 17.8's "fewer than sizeof(TPM_GENERATED)
    /// octets" note).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOnARestrictedKeyWithAnEmptyFirstUpdateFollowedByTpmGeneratedContentReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] forgedSecondBlock = [.. TpmGeneratedValueBytes, .. "forged attestation body"u8.ToArray()];

        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], forgedSecondBlock).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, [], [], []).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, completeResult.ResponseCode,
            "An empty first update settles the verdict unsafe; a TPM_GENERATED_VALUE-prefixed SECOND update must not re-open it — the restricted key must still be refused with TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// The same conservative, settle-once verdict defeats splitting <c>TPM_GENERATED_VALUE</c>'s four octets
    /// across two updates: a first block of only its first two octets is already fewer than
    /// <c>sizeof(TPM_GENERATED)</c>, so the verdict settles unsafe before the magic value is ever complete on the
    /// wire, and the innocuous-looking remainder in the second update cannot rescue it
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.8's "fewer than sizeof(TPM_GENERATED) octets" note).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOnARestrictedKeyWithTheTpmGeneratedValueSplitAcrossTwoUpdatesReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] firstTwoOctets = TpmGeneratedValueBytes[..2];
        byte[] remainder = [.. TpmGeneratedValueBytes[2..], .. "innocent-looking tail"u8.ToArray()];

        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], firstTwoOctets).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], remainder).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, [], [], []).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, completeResult.ResponseCode,
            "A first block of only TPM_GENERATED_VALUE's first two octets is already unsafe (fewer than sizeof(TPM_GENERATED)); the restricted key must be refused with TPM_RC_ATTRIBUTES regardless of what completes the value in a later update.");
    }

    /// <summary>
    /// The empty-first-block verdict is proven discriminating on its own: an empty first update followed only by
    /// entirely innocuous content — never containing <c>TPM_GENERATED_VALUE</c> anywhere — is STILL refused,
    /// because the verdict was already settled unsafe by the empty first block and the actual content of later
    /// updates is irrelevant to it
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.8's "fewer than sizeof(TPM_GENERATED) octets" note).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOnARestrictedKeyWithAnEmptyFirstUpdateFollowedByInnocentContentReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] innocentContent = "nothing but perfectly ordinary content"u8.ToArray();

        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], innocentContent).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, [], [], []).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, completeResult.ResponseCode,
            "An empty first update settles the verdict unsafe regardless of every later update's content; the restricted key must still be refused with TPM_RC_ATTRIBUTES even though no update ever carries TPM_GENERATED_VALUE.");
    }

    /// <summary>
    /// The first-block safety verdict is consulted only when the completing key is RESTRICTED: the same three
    /// forgery-shaped patterns proven refused on a restricted key above — an empty first update followed by
    /// TPM_GENERATED_VALUE, the value split across two updates, and an empty first update followed by innocent
    /// content — all succeed under an UNRESTRICTED key, since it never consults the verdict at all
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6's restricted-only rule).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOnAnUnrestrictedKeyWithTheSameFirstBlockPatternsSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        byte[] forgedSecondBlock = [.. TpmGeneratedValueBytes, .. "forged attestation body"u8.ToArray()];
        TpmiDhObject firstSequence = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, firstSequence, [], []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, firstSequence, [], forgedSecondBlock).ConfigureAwait(false);
        TpmResult<SignSequenceCompleteResponse> firstComplete = await SubmitCompleteAsync(
            tpm, registry, pool, firstSequence, primary.ObjectHandle, [], [], []).ConfigureAwait(false);
        Assert.IsTrue(firstComplete.IsSuccess, $"Empty-first-update then TPM_GENERATED_VALUE, under an unrestricted key, must succeed: '{firstComplete.ResponseCode}'.");
        firstComplete.Value.Dispose();

        byte[] firstTwoOctets = TpmGeneratedValueBytes[..2];
        byte[] remainder = [.. TpmGeneratedValueBytes[2..], .. "innocent-looking tail"u8.ToArray()];
        TpmiDhObject secondSequence = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, secondSequence, [], firstTwoOctets).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, secondSequence, [], remainder).ConfigureAwait(false);
        TpmResult<SignSequenceCompleteResponse> secondComplete = await SubmitCompleteAsync(
            tpm, registry, pool, secondSequence, primary.ObjectHandle, [], [], []).ConfigureAwait(false);
        Assert.IsTrue(secondComplete.IsSuccess, $"TPM_GENERATED_VALUE split across two updates, under an unrestricted key, must succeed: '{secondComplete.ResponseCode}'.");
        secondComplete.Value.Dispose();

        byte[] innocentContent = "nothing but perfectly ordinary content"u8.ToArray();
        TpmiDhObject thirdSequence = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, thirdSequence, [], []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, thirdSequence, [], innocentContent).ConfigureAwait(false);
        TpmResult<SignSequenceCompleteResponse> thirdComplete = await SubmitCompleteAsync(
            tpm, registry, pool, thirdSequence, primary.ObjectHandle, [], [], []).ConfigureAwait(false);
        Assert.IsTrue(thirdComplete.IsSuccess, $"Empty-first-update then innocent content, under an unrestricted key, must succeed: '{thirdComplete.ResponseCode}'.");
        thirdComplete.Value.Dispose();
    }

    /// <summary>
    /// "Authorization of the key referenced by keyHandle is not required at this time" is proven directly, on a
    /// DA-protected key with a NON-EMPTY password: a bare <c>TPM2_SignSequenceStart()</c> with no sessions at all
    /// succeeds and leaves the lockout counter untouched, and — because no lockout gate exists anywhere in the
    /// Start transition — a second Start against the SAME key STILL succeeds once repeated wrong key
    /// authorizations elsewhere have driven the TPM into general Lockout mode
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.5: "Authorization of the key referenced by keyHandle is
    /// not required at this time. It is checked later, when TPM2_SignSequenceComplete() is called.").
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartOnADaProtectedPasswordGuardedKeySucceedsWithNoSessionsAndRemainsUnaffectedByLockout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = await CreateDaProtectedEccSigningPrimaryAsync(tpm, registry, pool, "start-no-auth-key-password").ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> beforeStart = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<SignSequenceStartResponse> firstStart = await SubmitStartAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        Assert.IsTrue(firstStart.IsSuccess, $"TPM2_SignSequenceStart() with no sessions at all, against a DA-protected password-guarded key, must succeed: '{firstStart.ResponseCode}'.");

        TpmResult<TpmDictionaryAttackParameters> afterStart = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(beforeStart.Value.LockoutCounter, afterStart.Value.LockoutCounter, "TPM2_SignSequenceStart() must never move failedTries: it checks no authorization of keyHandle at all.");

        byte[] wrongKeyAuth = "wrong-start-no-auth-key-password"u8.ToArray();
        TpmiDhObject lockoutDriverSequence = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        for(uint attempt = 1; attempt <= LoweredMaxTries; attempt++)
        {
            TpmResult<SignSequenceCompleteResponse> wrongKeyResult = await SubmitCompleteAsync(
                tpm, registry, pool, lockoutDriverSequence, primary.ObjectHandle, [], wrongKeyAuth, []).ConfigureAwait(false);
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), wrongKeyResult.ResponseCode,
                $"Attempt {attempt} of {LoweredMaxTries} must count as an auth-failure at Complete, not yet Lockout mode. A failing SignSequenceComplete() leaves the sequence unmodified, so the same sequence is reused.");
        }

        TpmResult<TpmDictionaryAttackParameters> locked = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(locked.Value.IsLockedOut, "The DA-protected signing key must now be in Lockout mode.");

        TpmResult<SignSequenceStartResponse> secondStart = await SubmitStartAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        Assert.IsTrue(secondStart.IsSuccess, $"TPM2_SignSequenceStart() must still succeed against the same DA-protected key while the TPM is in general Lockout mode: '{secondStart.ResponseCode}'.");
    }

    /// <summary>
    /// A refused <c>TPM2_SignSequenceStart()</c> returns the parsed <c>auth</c> carrier to the pool: Start against
    /// a storage parent's <c>sign</c>-attribute-CLEAR key is refused with TPM_RC_KEY after a non-empty auth has
    /// already been rented at parse
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.5).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartRefusedOnANonSigningKeyReturnsTheParsedCarriersToPool()
    {
        using var housePool = new MeteredHousePool();
        BaseMemoryPool pool = housePool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        long baseline = housePool.OutstandingCount;

        byte[] sequenceAuth = "attempted-sequence-auth"u8.ToArray();
        TpmResult<SignSequenceStartResponse> startResult = await SubmitStartAsync(tpm, registry, pool, parent.ObjectHandle, sequenceAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, startResult.ResponseCode, "A storage parent's sign attribute is CLEAR; TPM2_SignSequenceStart() must refuse it with TPM_RC_KEY.");

        Assert.AreEqual(baseline, housePool.OutstandingCount, "A refused TPM2_SignSequenceStart() must return its parsed, non-empty auth carrier to the pool.");
    }

    /// <summary>
    /// A refused <c>TPM2_SequenceUpdate()</c> returns BOTH parsed carriers to the pool: a wrong sequence password
    /// leaves the pool balance exactly where it was before the update, proving the refusal disposes the parsed
    /// password AND the parsed (never-installed) buffer
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateWithAWrongSequencePasswordReturnsTheParsedCarriersToPool()
    {
        using var housePool = new MeteredHousePool();
        BaseMemoryPool pool = housePool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] sequenceAuth = "pool-update-auth"u8.ToArray();
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, sequenceAuth).ConfigureAwait(false);

        long baseline = housePool.OutstandingCount;

        byte[] wrongAuth = "wrong-pool-update-auth"u8.ToArray();
        byte[] attemptedBuffer = "attempted update payload"u8.ToArray();
        TpmResult<SequenceUpdateResponse> wrongResult = await SubmitUpdateAsync(tpm, registry, pool, sequenceHandle, wrongAuth, attemptedBuffer).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), wrongResult.ResponseCode,
            "A wrong sequence auth must be refused with session-index-0-encoded TPM_RC_BAD_AUTH.");

        Assert.AreEqual(baseline, housePool.OutstandingCount, "A refused TPM2_SequenceUpdate() must return both its parsed password carrier and its parsed, never-installed buffer carrier to the pool.");
    }

    /// <summary>
    /// A <c>TPM2_SignSequenceComplete()</c> refused with <c>TPM_RC_SIGN_CONTEXT_KEY</c> returns ALL THREE parsed
    /// carriers to the pool — the sequence password, the key password, and the trailing buffer — even though the
    /// refusal fires only after both passwords have already verified correctly
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteRefusedOnASignContextKeyMismatchReturnsAllThreeParsedCarriersToPool()
    {
        using var housePool = new MeteredHousePool();
        BaseMemoryPool pool = housePool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse startingKey = await CreateDaProtectedEccSigningPrimaryAsync(tpm, registry, pool, "pool-starting-key-pw").ConfigureAwait(false);
        using CreatePrimaryResponse otherKey = await CreateDaProtectedEccSigningPrimaryAsync(tpm, registry, pool, "pool-other-key-pw").ConfigureAwait(false);
        byte[] sequenceAuth = "pool-complete-sequence-auth"u8.ToArray();
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, startingKey.ObjectHandle, sequenceAuth).ConfigureAwait(false);

        long baseline = housePool.OutstandingCount;

        byte[] otherKeyAuth = "pool-other-key-pw"u8.ToArray();
        byte[] trailing = "trailing content"u8.ToArray();
        TpmResult<SignSequenceCompleteResponse> wrongKeyResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, otherKey.ObjectHandle, sequenceAuth, otherKeyAuth, trailing).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIGN_CONTEXT_KEY, wrongKeyResult.ResponseCode,
            "Completing with a genuinely different, correctly-authorized key must be refused with TPM_RC_SIGN_CONTEXT_KEY.");

        Assert.AreEqual(baseline, housePool.OutstandingCount, "A TPM2_SignSequenceComplete() refused with TPM_RC_SIGN_CONTEXT_KEY must return its sequence-password, key-password, and trailing-buffer rentals to the pool.");
    }

    /// <summary>
    /// A COMPLETED sequence returns every accumulated segment rental — plus the deep-copied starting key Name and
    /// the sequence's own auth carrier — to the pool: the balance after <c>TPM2_SignSequenceStart()</c>, three
    /// <c>TPM2_SequenceUpdate()</c> calls, and a successful <c>TPM2_SignSequenceComplete()</c> returns to exactly
    /// its post-<c>TPM2_CreatePrimary()</c> baseline, proving the <c>{F}</c> flush releases the whole
    /// accumulator
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 29.4.6: "When ... TPM2_SignSequenceComplete() ...
    /// completes successfully, the sequence context is flushed from the TPM").
    /// </summary>
    [TestMethod]
    public async Task CompletedSignSequenceReturnsEverySegmentRentalToPool()
    {
        using var housePool = new MeteredHousePool();
        BaseMemoryPool pool = housePool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        long baseline = housePool.OutstandingCount;

        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        Assert.IsGreaterThan(baseline, housePool.OutstandingCount, "The started sequence must hold live carrier rentals, or the balance assertion below is vacuous.");

        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], "chunk one "u8.ToArray()).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], "chunk two "u8.ToArray()).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], "chunk three"u8.ToArray()).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, [], [], "trailing"u8.ToArray()).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SignSequenceComplete() over the accumulated segments must succeed: '{completeResult.ResponseCode}'.");
        completeResult.Value.Dispose();

        Assert.AreEqual(baseline, housePool.OutstandingCount, "A completed sequence must return every accumulated segment rental, the deep-copied starting key Name, and the sequence auth to the pool once flushed.");
    }

    /// <summary>
    /// Disposing the simulator returns every OPEN sequence's accumulated rentals to the pool: two concurrently
    /// open sequences, each carrying at least one accumulated segment, leave the pool's outstanding-rental count
    /// at exactly zero once <see cref="TpmSimulator.Dispose"/> sweeps the sequence table
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 27.4).
    /// </summary>
    [TestMethod]
    public async Task DisposingTheSimulatorWithOpenSequencesReturnsEverySequenceRentalToPool()
    {
        using var housePool = new MeteredHousePool();
        BaseMemoryPool pool = housePool.Pool;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        try
        {
            using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
            TpmResponseRegistry registry = CreateRegistry();

            CreatePrimaryResponse primaryOneResponse = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
            TpmiDhObject primaryOneHandle = primaryOneResponse.ObjectHandle;
            primaryOneResponse.Dispose();

            CreatePrimaryResponse primaryTwoResponse = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
            TpmiDhObject primaryTwoHandle = primaryTwoResponse.ObjectHandle;
            primaryTwoResponse.Dispose();

            TpmiDhObject sequenceOne = await StartSequenceAsync(tpm, registry, pool, primaryOneHandle, []).ConfigureAwait(false);
            await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceOne, [], "sequence one segment"u8.ToArray()).ConfigureAwait(false);

            TpmiDhObject sequenceTwo = await StartSequenceAsync(tpm, registry, pool, primaryTwoHandle, []).ConfigureAwait(false);
            await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceTwo, [], "sequence two segment"u8.ToArray()).ConfigureAwait(false);

            Assert.IsGreaterThan(0L, housePool.OutstandingCount, "The scenario must leave live carrier rentals, or the balance assertion below is vacuous.");
        }
        finally
        {
            simulator.Dispose();
        }

        Assert.AreEqual(0L, housePool.OutstandingCount, "Disposing the simulator with two open sequences must return every accumulated segment (and both primaries' own retained key state) to the pool.");
    }

    /// <summary>
    /// <c>TPM2_FlushContext()</c> on an OPEN sequence returns every accumulated rental to the pool: the balance
    /// after starting a sequence, feeding it two updates, and flushing it returns to exactly its
    /// post-<c>TPM2_CreatePrimary()</c> baseline
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 28.4).
    /// </summary>
    [TestMethod]
    public async Task FlushContextOnAnOpenSequenceReturnsEverySegmentRentalToPool()
    {
        using var housePool = new MeteredHousePool();
        BaseMemoryPool pool = housePool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        long baseline = housePool.OutstandingCount;

        byte[] sequenceAuth = "flush-balance-auth"u8.ToArray();
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, sequenceAuth).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, sequenceAuth, "some segment content"u8.ToArray()).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, sequenceAuth, "more segment content"u8.ToArray()).ConfigureAwait(false);
        Assert.IsGreaterThan(baseline, housePool.OutstandingCount, "The open sequence must hold live carrier rentals, or the balance assertion below is vacuous.");

        FlushContextInput flushInput = FlushContextInput.ForHandle(sequenceHandle.Value);
        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"TPM2_FlushContext() on an open sequence must succeed: '{flushResult.ResponseCode}'.");

        Assert.AreEqual(baseline, housePool.OutstandingCount, "TPM2_FlushContext() on an open sequence must return the sequence auth and every accumulated segment rental to the pool.");
    }

    /// <summary>
    /// A wire-declared <c>auth</c> one octet over <see cref="Tpm2bAuth.MaxSize"/> (64), bypassing
    /// <see cref="SignSequenceStartInput"/>'s own host-side bound, is refused with <c>TPM_RC_SIZE</c> at parse,
    /// before the key handle is ever resolved
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.5, Table 87).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartWithAuthOverMaxSizeHandFramedReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        byte[] oversizedAuth = new byte[Tpm2bAuth.MaxSize + 1];
        TpmRcConstants code = await SubmitSignSequenceStartCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, primary.ObjectHandle.Value, oversizedAuth, []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "An auth one octet over Tpm2bAuth.MaxSize must be refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// A wire-declared <c>buffer</c> one octet over <see cref="Tpm2bMaxBuffer.MaxSize"/> (1024) at
    /// <c>TPM2_SignSequenceComplete()</c>, bypassing <see cref="SignSequenceCompleteInput"/>'s own host-side
    /// bound, is refused with <c>TPM_RC_SIZE</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6, Table 124).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteWithABufferOverMaxSizeHandFramedReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        byte[] tooLargeBuffer = new byte[Tpm2bMaxBuffer.MaxSize + 1];
        (uint SessionHandle, byte[] Hmac)[] sessions = [((uint)TpmRh.TPM_RH_PW, Array.Empty<byte>()), ((uint)TpmRh.TPM_RH_PW, Array.Empty<byte>())];
        TpmRcConstants code = await SubmitSignSequenceCompleteCommandAsync(
            simulator, pool, sequenceHandle.Value, primary.ObjectHandle.Value, sessions, tooLargeBuffer, authorizationSizeOverride: null).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "A buffer one octet over Tpm2bMaxBuffer.MaxSize must be refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// Either slot of <c>TPM2_SignSequenceComplete()</c>'s authorization area may hold a real session, resolved
    /// before any rule is applied: an HMAC-session handle naming no loaded session at the KEY slot (Auth Index
    /// 2, the second slot) is refused with <c>TPM_RC_REFERENCE_S1</c>, the reference warning that already carries
    /// the offending slot's index
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.5, step 4; Part 2: Structures, clause 6.6.3).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteWithAnUnloadedSessionHandleAtTheKeySlotReturnsReferenceS1()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        (uint SessionHandle, byte[] Hmac)[] sessions = [((uint)TpmRh.TPM_RH_PW, Array.Empty<byte>()), (0x0200_0000u, Array.Empty<byte>())];
        TpmRcConstants code = await SubmitSignSequenceCompleteCommandAsync(
            simulator, pool, sequenceHandle.Value, primary.ObjectHandle.Value, sessions, [], authorizationSizeOverride: null).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_REFERENCE_S1, code,
            "An HMAC-session handle naming no loaded session at the key slot (index 1) must be refused with TPM_RC_REFERENCE_S1.");
    }

    /// <summary>
    /// The sequence-slot mirror of <see cref="SignSequenceCompleteWithAnUnloadedSessionHandleAtTheKeySlotReturnsReferenceS1"/>:
    /// an HMAC-session handle naming no loaded session at the SEQUENCE slot (Auth Index 1, the first slot) is
    /// refused with <c>TPM_RC_REFERENCE_S0</c>, even though the key slot is a genuine password session — the
    /// slots resolve in wire order and the first miss answers
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.5, step 4; Part 2: Structures, clause 6.6.3).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteWithAnUnloadedSessionHandleAtTheSequenceSlotReturnsReferenceS0()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        (uint SessionHandle, byte[] Hmac)[] sessions = [(0x0200_0000u, Array.Empty<byte>()), ((uint)TpmRh.TPM_RH_PW, Array.Empty<byte>())];
        TpmRcConstants code = await SubmitSignSequenceCompleteCommandAsync(
            simulator, pool, sequenceHandle.Value, primary.ObjectHandle.Value, sessions, [], authorizationSizeOverride: null).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_REFERENCE_S0, code,
            "An HMAC-session handle naming no loaded session at the sequence slot (index 0) must be refused with TPM_RC_REFERENCE_S0, even though the key slot is a genuine password session.");
    }

    /// <summary>
    /// <c>TPM2_SignSequenceComplete()</c> decorates both of its handles with <c>@</c> (Table 124), so an area
    /// holding exactly one well-formed block — a lone minimal <c>TPM_RS_PW</c> block, the smallest area clause
    /// 5.5 admits — is refused with a bare <c>TPM_RC_AUTH_MISSING</c>: "An authorization session is present for
    /// each of the handles with the '@' decoration (TPM_RC_AUTH_MISSING)"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.5, step 5, and clause 20.6, Table 124).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteWithOneBlockForTwoAuthorizedHandlesReturnsAuthMissing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        (uint SessionHandle, byte[] Hmac)[] onlyOneSlot = [((uint)TpmRh.TPM_RH_PW, Array.Empty<byte>())];
        TpmRcConstants code = await SubmitSignSequenceCompleteCommandAsync(
            simulator, pool, sequenceHandle.Value, primary.ObjectHandle.Value, onlyOneSlot, [], authorizationSizeOverride: null).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_MISSING, code, "One block for two @-decorated handles must be refused with TPM_RC_AUTH_MISSING.");
    }

    /// <summary>
    /// A declared <c>authorizationSize</c> claiming two full session slots' worth of octets while only ONE slot
    /// is actually framed on the wire is refused with <c>TPM_RC_AUTHSIZE</c> before any session is parsed: the
    /// declared size does not fit within what the reader actually has remaining
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 15.6.1).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteWithAuthorizationSizeClaimingTwoSlotsButFramingOnlyOneReturnsAuthSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        const int PasswordSlotSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        (uint SessionHandle, byte[] Hmac)[] onlyOneSlot = [((uint)TpmRh.TPM_RH_PW, Array.Empty<byte>())];
        uint declaredForTwoSlots = 2 * PasswordSlotSize;

        TpmRcConstants code = await SubmitSignSequenceCompleteCommandAsync(
            simulator, pool, sequenceHandle.Value, primary.ObjectHandle.Value, onlyOneSlot, [], authorizationSizeOverride: declaredForTwoSlots).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTHSIZE, code, "A declared authorizationSize claiming two slots while only one is actually framed must be refused with TPM_RC_AUTHSIZE.");
    }

    /// <summary>
    /// One trailing octet after <c>TPM2_SequenceUpdate()</c>'s <c>buffer</c> parameter — the command's final
    /// parameter — is refused with <c>TPM_RC_SIZE</c>: no octet may follow the last parameter
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.2).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateWithOneTrailingOctetAfterTheBufferReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        byte[] buffer = "trailing octet probe"u8.ToArray();
        TpmRcConstants code = await SubmitSequenceUpdateCommandWithTrailingOctetAsync(simulator, pool, sequenceHandle.Value, buffer).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "One octet trailing the buffer parameter must be refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// Captures the starting key's state right after <c>TPM2_SignSequenceStart()</c>, applies
    /// <paramref name="flipAttributes"/> to it, installs the flipped copy at the SAME handle the sequence
    /// recorded (so the Name comparison at Complete still passes and the flipped gate is the only one that can
    /// fire), and drives the public <see cref="TpmLifecycleTransitions.Create"/> transition delegate directly
    /// with a completing request naming that handle.
    /// </summary>
    /// <param name="flipAttributes">Produces the flipped copy of the captured starting key's state.</param>
    /// <returns>The header-only rejection the transition produced.</returns>
    private async Task<TpmHeaderOnlyResponse> DriveSignSequenceCompleteWithAFlippedStartingKeyAsync(Func<TransientKeyState, TransientKeyState> flipAttributes)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        var capture = new LastStateObserver();
        using IDisposable subscription = simulator.Subscribe(capture);

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        TpmSimulatorState? maybeCapturedState = capture.LastState;
        Assert.IsNotNull(maybeCapturedState, "The simulator's own trace subscription must have observed at least one step by the time TPM2_SignSequenceStart() returns.");
        TpmSimulatorState capturedState = maybeCapturedState!;

        Assert.IsTrue(capturedState.TransientObjects.TryGetValue(primary.ObjectHandle, out TransientKeyState? maybeStartingKey), "The starting key must be present in the captured post-Start state.");
        TransientKeyState startingKey = maybeStartingKey!;

        TransientKeyState flippedKey = flipAttributes(startingKey);
        TpmSimulatorState mutatedState = capturedState with
        {
            TransientObjects = capturedState.TransientObjects.SetItem(primary.ObjectHandle, flippedKey)
        };

        using var request = new TpmSignSequenceCompleteRequested(sequenceHandle, primary.ObjectHandle, Tpm2bAuth.Empty, Tpm2bAuth.Empty, Tpm2bMaxBuffer.Empty);
        TransitionDelegate<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol> transition = TpmLifecycleTransitions.Create();
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? result = await transition(
            mutatedState, request, TpmSimulatorStackSymbol.Lifecycle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result, "OnSignSequenceComplete always yields a transition — either a rejection or a declared signing action — never a halt.");
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> nonNullResult = result!;
        Assert.IsInstanceOfType<TpmHeaderOnlyResponse>(nonNullResult.NextState.ResponseIntent, "A rejection frames a header-only response.");

        return (TpmHeaderOnlyResponse)nonNullResult.NextState.ResponseIntent!;
    }

    /// <summary>
    /// Submits <see cref="SignSequenceStartInput.Create"/> with no session (Auth Index None; no authorization of
    /// <c>keyHandle</c> is required at Start) and returns the raw result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The candidate signing key handle.</param>
    /// <param name="sequenceAuth">The sequence's own authValue.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<SignSequenceStartResponse>> SubmitStartAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        using SignSequenceStartInput input = SignSequenceStartInput.Create(keyHandle, sequenceAuth, pool);

        return await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Starts a sequence via <see cref="SubmitStartAsync"/>, asserting success, and returns its handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The signing key handle.</param>
    /// <param name="sequenceAuth">The sequence's own authValue.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartSequenceAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        TpmResult<SignSequenceStartResponse> result = await SubmitStartAsync(tpm, registry, pool, keyHandle, sequenceAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SignSequenceStart() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>
    /// Submits <see cref="SequenceUpdateInput.Create"/> over a single <c>TPM_RS_PW</c> session authorizing
    /// <c>@sequenceHandle</c> (Auth Index 1) and returns the raw result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence (or candidate) handle.</param>
    /// <param name="sequenceAuth">The caller-supplied sequence auth (empty for an empty-authValue sequence).</param>
    /// <param name="buffer">The update buffer.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<SequenceUpdateResponse>> SubmitUpdateAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, byte[] sequenceAuth, byte[] buffer)
    {
        using TpmPasswordSession sequenceSession = sequenceAuth.Length == 0 ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(sequenceAuth, pool);
        using SequenceUpdateInput input = SequenceUpdateInput.Create(sequenceHandle, buffer, pool);

        return await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
            tpm, input, [sequenceSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Updates a sequence via <see cref="SubmitUpdateAsync"/>, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence handle.</param>
    /// <param name="sequenceAuth">The sequence's own authValue.</param>
    /// <param name="buffer">The update buffer.</param>
    private async Task UpdateSequenceSuccessfullyAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, byte[] sequenceAuth, byte[] buffer)
    {
        TpmResult<SequenceUpdateResponse> result = await SubmitUpdateAsync(tpm, registry, pool, sequenceHandle, sequenceAuth, buffer).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SequenceUpdate() failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Submits <see cref="SignSequenceCompleteInput.Create"/> over two <c>TPM_RS_PW</c> sessions authorizing
    /// <c>@sequenceHandle</c> (Auth Index 1, session 0) then <c>@keyHandle</c> (Auth Index 2, session 1), and
    /// returns the raw result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence handle.</param>
    /// <param name="keyHandle">The candidate signing key handle.</param>
    /// <param name="sequenceAuth">The caller-supplied sequence auth (empty for an empty-authValue sequence).</param>
    /// <param name="keyAuth">The caller-supplied key auth (empty for an empty-authValue key).</param>
    /// <param name="buffer">The trailing Complete buffer.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<SignSequenceCompleteResponse>> SubmitCompleteAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, TpmiDhObject keyHandle,
        byte[] sequenceAuth, byte[] keyAuth, byte[] buffer)
    {
        using TpmPasswordSession sequenceSession = sequenceAuth.Length == 0 ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(sequenceAuth, pool);
        using TpmPasswordSession keySession = keyAuth.Length == 0 ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(keyAuth, pool);
        using SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(sequenceHandle, keyHandle, buffer, pool);

        return await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
            tpm, input, [sequenceSession, keySession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Composes a restricted ECC signing key template — <c>TPMA_OBJECT.restricted</c> SET alongside <c>sign</c>,
    /// with no password (empty authValue) — mirroring
    /// <c>TpmInHouseSimulatorSignSequenceTests.CreateRestrictedEccSigningKeyInput</c>'s direct-template style,
    /// since no production factory builds a restricted signing key.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the returned CreatePrimaryInput, whose Dispose releases them.")]
    private static CreatePrimaryInput CreateRestrictedEccSigningKeyInput(BaseMemoryPool pool)
    {
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);

        var attributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH |
            TpmaObject.SIGN_ENCRYPT |
            TpmaObject.RESTRICTED |
            TpmaObject.NO_DA;

        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            attributes,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));

        return new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
    }

    /// <summary>Creates a restricted ECC signing primary under the owner hierarchy and returns the response (the caller owns it).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateRestrictedEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreateRestrictedEccSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (restricted ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an unrestricted, empty-password ECC P-256 signing primary under the owner hierarchy and returns the response (the caller owns it).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a DA-protected, password-guarded ECC P-256 signing primary under the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="password">The key's own password.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateDaProtectedEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, string password)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: false);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (DA-protected ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an unrestricted, empty-password ECC storage parent under the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary storage parent failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceUpdate, TpmResponseCodec.SequenceUpdate);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceComplete, TpmResponseCodec.SignSequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)).
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers
    /// it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-sign-sequence-hardening",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
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

    /// <summary>
    /// Hand-frames a <c>TPM2_SignSequenceStart()</c> command with a caller-chosen tag, <c>auth</c>, and
    /// <c>context</c> body, bypassing <see cref="SignSequenceStartInput"/> (which always frames
    /// <c>TPM_ST_NO_SESSIONS</c>, bounds <c>auth</c> host-side, and frames an empty context) — letting a caller
    /// submit an oversized <c>auth</c> or a malformed tag directly against the simulator.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag to frame verbatim.</param>
    /// <param name="keyHandle">The <c>keyHandle</c> handle value.</param>
    /// <param name="sequenceAuth">The <c>auth</c> parameter's octets.</param>
    /// <param name="context">The <c>context</c> parameter's octets, written verbatim as a TPM2B.</param>
    /// <param name="length">The framed command's total length.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameSignSequenceStartCommand(
        BaseMemoryPool pool, ushort tag, uint keyHandle, ReadOnlySpan<byte> sequenceAuth, ReadOnlySpan<byte> context, out int length)
    {
        length =
            TpmHeader.HeaderSize
            + sizeof(uint)                          //Handle area: keyHandle.
            + (sizeof(ushort) + sequenceAuth.Length) //auth: TPM2B_AUTH.
            + (sizeof(ushort) + context.Length);     //context: TPM2B_SIGNATURE_CTX.

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader(tag, (uint)length, (uint)TpmCcConstants.TPM_CC_SignSequenceStart);
            header.WriteTo(ref writer);
            writer.WriteUInt32(keyHandle);
            writer.WriteTpm2b(sequenceAuth);
            writer.WriteTpm2b(context);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_SignSequenceStart()</c> built by <see cref="FrameSignSequenceStartCommand"/>
    /// straight to the simulator (bypassing <see cref="TpmCommandExecutor"/>) and yields the response code.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag to frame verbatim.</param>
    /// <param name="keyHandle">The <c>keyHandle</c> handle value.</param>
    /// <param name="sequenceAuth">The <c>auth</c> parameter's octets.</param>
    /// <param name="context">The <c>context</c> parameter's octets.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSignSequenceStartCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, ushort tag, uint keyHandle, byte[] sequenceAuth, byte[] context)
    {
        using IMemoryOwner<byte> commandOwner = FrameSignSequenceStartCommand(pool, tag, keyHandle, sequenceAuth, context, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_SequenceUpdate()</c> command over a single empty-password <c>TPM_RS_PW</c> slot,
    /// followed by one octet beyond the <c>buffer</c> parameter the wire layout does not admit — bypassing
    /// <see cref="SequenceUpdateInput"/>, which always frames the command with nothing trailing its buffer.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The <c>@sequenceHandle</c> handle value.</param>
    /// <param name="buffer">The <c>buffer</c> parameter's octets, written verbatim as a TPM2B.</param>
    /// <param name="length">The framed command's total length.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameSequenceUpdateCommandWithTrailingOctet(
        BaseMemoryPool pool, uint sequenceHandle, ReadOnlySpan<byte> buffer, out int length)
    {
        const int PasswordSlotSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);

        length =
            TpmHeader.HeaderSize
            + sizeof(uint)                     //Handle area: @sequenceHandle.
            + sizeof(uint) + PasswordSlotSize  //authorizationSize + one empty TPM_RS_PW slot.
            + sizeof(ushort) + buffer.Length   //buffer: TPM2B_MAX_BUFFER.
            + 1;                               //One trailing octet the wire layout does not admit.

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_SequenceUpdate);
            header.WriteTo(ref writer);
            writer.WriteUInt32(sequenceHandle);
            writer.WriteUInt32((uint)PasswordSlotSize);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteTpm2b(buffer);
            writer.WriteByte(0xAA);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_SequenceUpdate()</c> built by
    /// <see cref="FrameSequenceUpdateCommandWithTrailingOctet"/> straight to the simulator (bypassing
    /// <see cref="TpmCommandExecutor"/>) and yields the response code.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The <c>@sequenceHandle</c> handle value.</param>
    /// <param name="buffer">The <c>buffer</c> parameter's octets.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSequenceUpdateCommandWithTrailingOctetAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint sequenceHandle, byte[] buffer)
    {
        using IMemoryOwner<byte> commandOwner = FrameSequenceUpdateCommandWithTrailingOctet(pool, sequenceHandle, buffer, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_SignSequenceComplete()</c> command over an explicit list of session slots — each a
    /// (sessionHandle, hmac) pair written as a full <c>TPMS_AUTH_COMMAND</c> entry with an empty nonceCaller and
    /// the CONTINUE_SESSION attribute — followed by the <c>buffer</c> parameter (TPM2B_MAX_BUFFER), bypassing
    /// <see cref="SignSequenceCompleteInput"/> and <see cref="TpmCommandExecutor"/> so a caller can submit a
    /// malformed authorization area or an oversized buffer directly against the simulator.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The <c>@sequenceHandle</c> handle value.</param>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle value.</param>
    /// <param name="sessions">The session slots to frame, in wire order.</param>
    /// <param name="buffer">The <c>buffer</c> parameter's octets, written verbatim as a TPM2B.</param>
    /// <param name="authorizationSizeOverride">
    /// When supplied, the declared <c>authorizationSize</c> field value, in place of the actual octet count the
    /// framed <paramref name="sessions"/> occupy — lets a caller declare a session-area size the wire bytes do
    /// not match.
    /// </param>
    /// <param name="length">The framed command's total length.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameSignSequenceCompleteCommand(
        BaseMemoryPool pool, uint sequenceHandle, uint keyHandle, (uint SessionHandle, byte[] Hmac)[] sessions,
        ReadOnlySpan<byte> buffer, uint? authorizationSizeOverride, out int length)
    {
        int actualAuthorizationSize = 0;
        foreach((uint _, byte[] hmac) in sessions)
        {
            actualAuthorizationSize += sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort) + hmac.Length;
        }

        uint authorizationSize = authorizationSizeOverride ?? (uint)actualAuthorizationSize;

        length =
            TpmHeader.HeaderSize
            + (2 * sizeof(uint))                //Handle area: @sequenceHandle then @keyHandle.
            + sizeof(uint)                      //authorizationSize.
            + actualAuthorizationSize            //The framed session slots.
            + (sizeof(ushort) + buffer.Length); //buffer: TPM2B_MAX_BUFFER.

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_SignSequenceComplete);
            header.WriteTo(ref writer);
            writer.WriteUInt32(sequenceHandle);
            writer.WriteUInt32(keyHandle);
            writer.WriteUInt32(authorizationSize);
            foreach((uint sessionHandle, byte[] hmac) in sessions)
            {
                writer.WriteUInt32(sessionHandle);
                writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
                writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
                writer.WriteTpm2b(hmac);
            }

            writer.WriteTpm2b(buffer);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_SignSequenceComplete()</c> built by
    /// <see cref="FrameSignSequenceCompleteCommand"/> straight to the simulator (bypassing
    /// <see cref="TpmCommandExecutor"/>) and yields the response code.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The <c>@sequenceHandle</c> handle value.</param>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle value.</param>
    /// <param name="sessions">The session slots to frame, in wire order.</param>
    /// <param name="buffer">The <c>buffer</c> parameter's octets.</param>
    /// <param name="authorizationSizeOverride">The declared <c>authorizationSize</c> override, or <see langword="null"/> for the actual size.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSignSequenceCompleteCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint sequenceHandle, uint keyHandle,
        (uint SessionHandle, byte[] Hmac)[] sessions, byte[] buffer, uint? authorizationSizeOverride)
    {
        using IMemoryOwner<byte> commandOwner = FrameSignSequenceCompleteCommand(
            pool, sequenceHandle, keyHandle, sessions, buffer, authorizationSizeOverride, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// Captures the most recent post-transition <see cref="TpmSimulatorState"/> the simulator's own
    /// <see cref="IObservable{T}"/> trace emits — the exact same public channel a replay journal or metrics
    /// subscriber would use, not a test-only hook into production code.
    /// </summary>
    private sealed class LastStateObserver: IObserver<TraceEntry<TpmSimulatorState, TpmSimulatorInput>>
    {
        /// <summary>Gets the state after the most recently observed step, or <see langword="null"/> before the first one.</summary>
        public TpmSimulatorState? LastState { get; private set; }

        /// <inheritdoc/>
        public void OnNext(TraceEntry<TpmSimulatorState, TpmSimulatorInput> value) => LastState = value.StateAfter;

        /// <inheritdoc/>
        public void OnError(Exception error)
        {
        }

        /// <inheritdoc/>
        public void OnCompleted()
        {
        }
    }
}
