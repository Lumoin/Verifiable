using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_StirRandom()</c>'s sessionless form - the <c>TPM_ST_NO_SESSIONS</c> tag Table 77 names when
/// neither an audit nor a decrypt session is present - against the in-house behavioural
/// <see cref="TpmSimulator"/>, entirely in-process and with no external assets, through the same production
/// command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="StirRandomInput"/> and response codec) and, where a frame must be malformed on purpose, straight
/// over the raw wire.
/// </summary>
/// <remarks>
/// The observable effect of a stir is a RESEED: the command itself answers only a header, so every proof here
/// reads the reseed out through the RNG's own consumers by comparing a stirred simulator against an UNSTIRRED
/// TWIN. Two default-constructed simulators draw byte-identical <c>TPM2_GetRandom()</c> streams - the twin
/// invariance the whole file rests on and which its first test pins - so any divergence between a twin pair is
/// attributable to the stir alone. TPM 2.0 Library Part 3, clause 16.2; Part 1, clause 8.4.11.2; Part 2, clauses
/// 11.1.13 and 11.1.14.
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorStirRandomTests
{
    /// <summary>The width of a random draw the twin comparisons read the RNG stream out through.</summary>
    private const int DrawWidth = 32;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The control the reseed proofs rest on: this simulator's RNG is a deterministic per-instance stream that
    /// is not derived from the instance's own identifier, so two independently constructed, independently
    /// started simulators draw byte-identical <c>TPM2_GetRandom()</c> octets. Nothing but a reseed can separate
    /// a twin pair, which is what makes "differs from an unstirred twin" evidence of the reseed rather than of
    /// ordinary RNG advance.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 16.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TwoUnstirredSimulatorsDrawByteIdenticalRandomStreams()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator first = CreatePoweredOff("tpm-in-house-stir-control-first");
        using TpmSimulator second = CreatePoweredOff("tpm-in-house-stir-control-second");
        using TpmDevice firstDevice = TpmDevice.Create(first.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using TpmDevice secondDevice = TpmDevice.Create(second.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await BringOperationalAsync(first, pool).ConfigureAwait(false);
        await BringOperationalAsync(second, pool).ConfigureAwait(false);

        byte[] firstDraw = await DrawRandomAsync(firstDevice, registry, pool).ConfigureAwait(false);
        byte[] secondDraw = await DrawRandomAsync(secondDevice, registry, pool).ConfigureAwait(false);

        Assert.AreSequenceEqual(firstDraw, secondDraw);
    }

    /// <summary>
    /// "This command is used to add additional entropy to the RNG state." (clause 16.2.1) and Table 78 lists
    /// <c>tag</c>, <c>responseSize</c> and <c>responseCode</c> alone, so a well-formed sessionless stir answers
    /// <c>TPM_RC_SUCCESS</c> with the 10-octet header and nothing behind it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 16.2, Tables 77 and 78</see>.
    /// </summary>
    [TestMethod]
    public async Task StirRandomAnswersSuccessWithAHeaderOnlyResponse()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = CreatePoweredOff("tpm-in-house-stir-success");
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        using Tpm2bSensitiveData inData = Tpm2bSensitiveData.Create(Pattern(DrawWidth, 0x5A), pool);
        TpmResult<StirRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<StirRandomResponse>(
            device, new StirRandomInput(inData), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"A well-formed TPM2_StirRandom must answer TPM_RC_SUCCESS: '{result.ResponseCode}'.");
        Assert.AreSame(StirRandomResponse.Instance, result.Value, "Table 78's response is the header alone, so it resolves to the parameterless singleton.");
    }

    /// <summary>
    /// "The DRBG Protected Capability should be reseeded using entropy from the entropy Protected Capability
    /// when: ... TPM2_StirRandom() is executed" (Part 1, clause 8.4.11.2), so the octets a later
    /// <c>TPM2_GetRandom()</c> returns from a stirred TPM differ from those its unstirred twin returns at the
    /// same ordinal draw.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 8.4.11.2; Part 3, clause 16.2</see>.
    /// </summary>
    [TestMethod]
    public async Task AStirChangesTheNextRandomDrawFromAnUnstirredTwins()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] stirred = await DrawAfterStirsAsync(pool, "tpm-in-house-stir-effect", [Pattern(DrawWidth, 0x11)]).ConfigureAwait(false);
        byte[] unstirred = await DrawAfterStirsAsync(pool, "tpm-in-house-stir-effect-twin", []).ConfigureAwait(false);

        Assert.IsFalse(((ReadOnlySpan<byte>)stirred).SequenceEqual(unstirred),
            "Clause 16.2's additional entropy must reach the RNG state, so a stirred draw cannot equal its unstirred twin's.");
    }

    /// <summary>
    /// The additional input is the whole of what a stir contributes beyond the reseed itself, so two twins
    /// stirred with the SAME <c>inData</c> - "additional input, as defined in SP 800-90A." (Table 77) - remain
    /// byte-identical in every later draw, exactly as they were before either stirred.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 16.2, Table 77</see>.
    /// </summary>
    [TestMethod]
    public async Task TwinsStirredWithTheSameAdditionalInputDrawIdenticalRandomStreams()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] additionalInput = Pattern(DrawWidth, 0x2C);
        byte[] first = await DrawAfterStirsAsync(pool, "tpm-in-house-stir-agree-first", [additionalInput]).ConfigureAwait(false);
        byte[] second = await DrawAfterStirsAsync(pool, "tpm-in-house-stir-agree-second", [additionalInput]).ConfigureAwait(false);

        Assert.AreSequenceEqual(first, second);
    }

    /// <summary>
    /// The additional input a stir folds in augments the RNG Protected Capability's own draw rather than
    /// replacing it: "the TPM has no way of determining whether the value has any entropy or not. As a
    /// consequence, it is just deemed to be 'additional information.'" (Part 1, clause 8.4.11.2) - and Part 4's
    /// reference stirrer "starts with a buffer full of entropy" before folding the caller's octets in. Two TPMs
    /// with DIFFERENT injected entropy backends, stirred with the SAME <c>inData</c>, therefore draw DIFFERENT
    /// streams afterward - the backend still contributes - and the exact relation holds: since both share the
    /// same stir digest and the same block counter, their post-stir keystreams are identical, so XORing the
    /// 0xFF-backed draw with <c>0xFF</c> recovers exactly what the 0x00-backed twin drew. Before either stirs,
    /// each backend's own pattern passes through untouched, pinning that the later difference is the stir's
    /// doing and not merely two different backends.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 16.2.1; Part 1, clause 8.4.11.2</see>.
    /// </summary>
    [TestMethod]
    public async Task TheStirKeystreamAugmentsTheInjectedBackendDrawRatherThanReplacingIt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator zeroBacked = new("tpm-in-house-stir-xor-zero", rng: static destination => destination.Clear(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        using TpmSimulator ffBacked = new("tpm-in-house-stir-xor-ff", rng: static destination => destination.Fill(0xFF), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        using TpmDevice zeroDevice = TpmDevice.Create(zeroBacked.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using TpmDevice ffDevice = TpmDevice.Create(ffBacked.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await BringOperationalAsync(zeroBacked, pool).ConfigureAwait(false);
        await BringOperationalAsync(ffBacked, pool).ConfigureAwait(false);

        byte[] zeroControlDraw = await DrawRandomAsync(zeroDevice, registry, pool).ConfigureAwait(false);
        byte[] ffControlDraw = await DrawRandomAsync(ffDevice, registry, pool).ConfigureAwait(false);

        Assert.AreSequenceEqual(new byte[DrawWidth], zeroControlDraw,
            "Before any stir, the 0x00-filling backend's own octets must pass through FillEntropy untouched.");
        Assert.AreSequenceEqual(Constant(DrawWidth, 0xFF), ffControlDraw,
            "Before any stir, the 0xFF-filling backend's own octets must pass through FillEntropy untouched.");

        byte[] sharedInData = Pattern(DrawWidth, 0x5C);
        TpmRcConstants zeroStirCode = await StirAsync(zeroDevice, registry, pool, sharedInData).ConfigureAwait(false);
        TpmRcConstants ffStirCode = await StirAsync(ffDevice, registry, pool, sharedInData).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, zeroStirCode, "The 0x00-backed stir under test must itself have succeeded.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, ffStirCode, "The 0xFF-backed stir under test must itself have succeeded.");

        byte[] zeroDraw = await DrawRandomAsync(zeroDevice, registry, pool).ConfigureAwait(false);
        byte[] ffDraw = await DrawRandomAsync(ffDevice, registry, pool).ConfigureAwait(false);

        Assert.IsFalse(((ReadOnlySpan<byte>)zeroDraw).SequenceEqual(ffDraw),
            "Clause 8.4.11.2's additional information augments the entropy draw rather than replacing it, so two differently-backed TPMs stirred with the same inData must still draw differently.");

        byte[] recoveredFromFf = new byte[DrawWidth];
        for(int i = 0; i < DrawWidth; i++)
        {
            recoveredFromFf[i] = (byte)(ffDraw[i] ^ 0xFF);
        }

        Assert.AreSequenceEqual(zeroDraw, recoveredFromFf,
            "The same stir digest and the same block counter yield the identical keystream for both backends, so XORing the 0xFF backend's own octets out of its draw must recover exactly the 0x00 backend's draw.");
    }

    /// <summary>
    /// The reseed is triggered by the command's execution, not by the width of what it carries: Part 1, clause
    /// 8.4.11.2 lists "TPM2_StirRandom() is executed" as its own reseed trigger, and this model's fold is fully
    /// deterministic in the prior stir state alone - <c>stir' = SHA-256(stir)</c> when <c>inData</c> is empty, no
    /// entropy source drawn - so an EMPTY <c>inData</c> - a well-formed <c>TPM2B_SENSITIVE_DATA</c> of declared
    /// size zero - still separates the stirred TPM's stream from its unstirred twin's.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 8.4.11.2; Part 3, clause 16.2, Table 77</see>.
    /// </summary>
    [TestMethod]
    public async Task AStirWithAnEmptyAdditionalInputStillReseeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] stirred = await DrawAfterStirsAsync(pool, "tpm-in-house-stir-empty", [[]]).ConfigureAwait(false);
        byte[] unstirred = await DrawAfterStirsAsync(pool, "tpm-in-house-stir-empty-twin", []).ConfigureAwait(false);

        Assert.IsFalse(((ReadOnlySpan<byte>)stirred).SequenceEqual(unstirred),
            "An empty inData is still an executed TPM2_StirRandom, so the reseed must be observable.");
    }

    /// <summary>
    /// The reseed list of Part 1, clause 8.4.11.2 is triggered on EVERY execution - "TPM2_StirRandom() is
    /// executed" - and each execution folds its own "additional information" into the state the previous one
    /// left, so a SECOND stir carrying different <c>inData</c> moves the stream again rather than reproducing
    /// the once-stirred stream.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 8.4.11.2; Part 3, clause 16.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ASecondStirWithDifferentAdditionalInputChangesTheRandomStreamAgain()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] first = Pattern(DrawWidth, 0x11);
        byte[] second = Pattern(DrawWidth, 0x22);
        byte[] onceStirred = await DrawAfterStirsAsync(pool, "tpm-in-house-stir-twice-once", [first]).ConfigureAwait(false);
        byte[] twiceStirred = await DrawAfterStirsAsync(pool, "tpm-in-house-stir-twice-both", [first, second]).ConfigureAwait(false);

        Assert.IsFalse(((ReadOnlySpan<byte>)onceStirred).SequenceEqual(twiceStirred),
            "A second executed TPM2_StirRandom is a second reseed, so its stream must differ from the once-stirred stream.");
    }

    /// <summary>
    /// The reseed reaches the RNG Protected Capability itself, not one command's answer: "Any Protected
    /// Capability that requires an unpredictable number obtains it from a Random Number Generator (RNG)
    /// Protected Capability in the same TPM." (Part 1, clause 8.4.11.2), so the <c>nonceTPM</c> a later
    /// <c>TPM2_StartAuthSession()</c> returns - drawn from that same capability, never through
    /// <c>TPM2_GetRandom()</c> - differs from an unstirred twin's.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 8.4.11.2 and 16.6.9; Part 3, clause 16.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ASessionNonceTpmDrawnAfterAStirDiffersFromAnUnstirredTwins()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] stirred = await StartSessionNonceAfterStirAsync(pool, "tpm-in-house-stir-nonce", isStirred: true).ConfigureAwait(false);
        byte[] unstirred = await StartSessionNonceAfterStirAsync(pool, "tpm-in-house-stir-nonce-twin", isStirred: false).ConfigureAwait(false);

        Assert.IsFalse(((ReadOnlySpan<byte>)stirred).SequenceEqual(unstirred),
            "Every consumer of the RNG Protected Capability must observe the reseed, TPM2_StartAuthSession's nonceTPM included.");
    }

    /// <summary>
    /// "The inData parameter may not be larger than 128 octets." (clause 16.2.1), the bound Part 2's clause
    /// 11.1.13 fixes as "For interoperability, MAX_SYM_DATA should be 128." and Table 170 applies to
    /// <c>buffer[size]{:sizeof(TPMU_SENSITIVE_CREATE)}</c>: exactly 128 octets is the widest well-formed
    /// <c>inData</c> and is accepted.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 16.2; Part 2, clauses 11.1.13 and 11.1.14, Tables 169 and 170</see>.
    /// </summary>
    [TestMethod]
    public async Task AStirOfExactlyOneHundredTwentyEightOctetsSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = CreatePoweredOff("tpm-in-house-stir-max");
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        TpmRcConstants responseCode = await StirAsync(device, registry, pool, Pattern(Tpm2bSensitiveData.MaxSize, 0x7E)).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, responseCode,
            "Clause 16.2.1's bound is 128 octets inclusive, so exactly MAX_SYM_DATA octets must be accepted.");
    }

    /// <summary>
    /// One octet past clause 16.2.1's "The inData parameter may not be larger than 128 octets." is a declared
    /// size larger than the type allows, which Table 2 answers with <c>TPM_RC_SIZE</c> - "the value of a size
    /// parameter is larger or smaller than allowed" - parameter-encoded to <c>inData</c>, <c>TPM2_StirRandom()</c>'s
    /// sole parameter (Table 77, index 0). The frame is built by hand because a well-behaved host
    /// carrier cannot hold an over-bound <c>TPM2B_SENSITIVE_DATA</c> at all.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.8.2 and 16.2; Part 2, clause 11.1.14, Table 170; clause 6.6.2, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task AStirOfOneHundredTwentyNineOctetsReturnsParameterEncodedSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = CreatePoweredOff("tpm-in-house-stir-oversize");

        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        TpmRcConstants responseCode = await SubmitFramedAsync(simulator, pool, BuildStirBody(Pattern(Tpm2bSensitiveData.MaxSize + 1, 0x33))).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), responseCode,
            "Clause 16.2.1 bounds inData at 128 octets, so 129 is Table 2's TPM_RC_SIZE, parameter-encoded at index 0 (Table 77).");
    }

    /// <summary>
    /// "When an error is encountered while unmarshaling a command parameter, an error response code is returned,
    /// and no command processing occurs." (clause 5.8.2), so a refused stir performs no reseed at all: the
    /// stream a TPM draws after an over-bound stir is byte-identical to its unstirred twin's.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.8.2 and 16.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ARefusedStirLeavesTheRandomStreamIdenticalToAnUnstirredTwins()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator refused = CreatePoweredOff("tpm-in-house-stir-refused");
        using TpmSimulator twin = CreatePoweredOff("tpm-in-house-stir-refused-twin");
        using TpmDevice refusedDevice = TpmDevice.Create(refused.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using TpmDevice twinDevice = TpmDevice.Create(twin.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await BringOperationalAsync(refused, pool).ConfigureAwait(false);
        await BringOperationalAsync(twin, pool).ConfigureAwait(false);

        TpmRcConstants responseCode = await SubmitFramedAsync(refused, pool, BuildStirBody(Pattern(Tpm2bSensitiveData.MaxSize + 1, 0x44))).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), responseCode, "The over-bound stir under test must be refused before its stream is compared.");

        byte[] refusedDraw = await DrawRandomAsync(refusedDevice, registry, pool).ConfigureAwait(false);
        byte[] twinDraw = await DrawRandomAsync(twinDevice, registry, pool).ConfigureAwait(false);

        Assert.AreSequenceEqual(twinDraw, refusedDraw);
    }

    /// <summary>
    /// A declared <c>inData</c> size the frame cannot supply is Table 2's <c>TPM_RC_INSUFFICIENT</c> - "the
    /// input buffer did not contain enough octets to allow unmarshaling of the expected data type" - and not
    /// <c>TPM_RC_SIZE</c>, which belongs to a width the TYPE forbids rather than one the frame is too short for;
    /// parameter-encoded to <c>inData</c>, <c>TPM2_StirRandom()</c>'s sole parameter (Table 77, index 0).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.8.2 and 16.2; Table 2; Part 2, clause 6.6.2, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task AStirWhoseSizeFieldExceedsTheFrameReturnsParameterEncodedInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = CreatePoweredOff("tpm-in-house-stir-short");

        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        //A size field declaring 32 octets over a body that carries only four of them.
        var body = new List<byte>();
        AppendUInt16(body, 32);
        body.AddRange(Pattern(4, 0x55));

        TpmRcConstants responseCode = await SubmitFramedAsync(simulator, pool, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), responseCode,
            "A declared inData width past the frame is Table 2's TPM_RC_INSUFFICIENT, never TPM_RC_SIZE, parameter-encoded at index 0 (Table 77).");
    }

    /// <summary>
    /// Clause 5.2's header validation fixes <c>commandSize</c> as the exact octet count of the command, and
    /// Table 77's parameter area is the one <c>TPM2B_SENSITIVE_DATA</c>, so an octet trailing a fully consumed
    /// <c>inData</c> makes the size parameter smaller than the frame - Table 2's <c>TPM_RC_SIZE</c>, "the value
    /// of a size parameter is larger or smaller than allowed".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.2, 5.8.2 and 16.2, Tables 2 and 77</see>.
    /// </summary>
    [TestMethod]
    public async Task AStirWithATrailingOctetReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = CreatePoweredOff("tpm-in-house-stir-trailing");

        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        var body = new List<byte>(BuildStirBody(Pattern(4, 0x66))) { 0x00 };

        TpmRcConstants responseCode = await SubmitFramedAsync(simulator, pool, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, responseCode,
            "inData is the whole parameter area, so an octet behind it is TPM_RC_SIZE.");
    }

    /// <summary>
    /// "If the TPM has not been initialized (TPM2_Startup()), then the commandCode is TPM_CC_Startup
    /// (TPM_RC_INITIALIZE)." (clause 5.3, mode check 3), so a stir issued after power-on but before
    /// <c>TPM2_Startup()</c> is refused with <c>TPM_RC_INITIALIZE</c> and the TPM stays uninitialized.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.3 and 16.2</see>.
    /// </summary>
    [TestMethod]
    public async Task AStirBeforeStartupReturnsInitialize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = CreatePoweredOff("tpm-in-house-stir-preinit");
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        TpmRcConstants responseCode = await StirAsync(device, registry, pool, Pattern(DrawWidth, 0x77)).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INITIALIZE, responseCode,
            "Clause 5.3's third mode check admits only TPM_CC_Startup before TPM2_Startup().");
        Assert.AreEqual(TpmLifecyclePhase.Initializing, simulator.CurrentPhase);
    }

    /// <summary>
    /// "If the TPM is in Failure mode, then the commandCode is TPM_CC_GetTestResult or TPM_CC_GetCapability
    /// (TPM_RC_FAILURE)" (clause 5.3, mode check 1) - <c>TPM_CC_StirRandom</c> is neither, so a stir attempted
    /// after a failed self-test is refused with <c>TPM_RC_FAILURE</c>. "In Failure mode, the TPM has no
    /// cryptographic capability", which is exactly what a reseed of the RNG state would require.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.3 and 16.2</see>.
    /// </summary>
    [TestMethod]
    public async Task AStirInFailureModeReturnsFailure()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = new TpmSimulator("tpm-in-house-stir-failure",selfTest: TpmSelfTestBehavior.Fails, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);
        _ = await SubmitInputForCodeAsync(simulator, pool, new SelfTestInput(IsFullTest: false)).ConfigureAwait(false);
        Assert.AreEqual(TpmLifecyclePhase.FailureMode, simulator.CurrentPhase, "The injected self-test failure must have driven the TPM into Failure mode.");

        TpmRcConstants responseCode = await StirAsync(device, registry, pool, Pattern(DrawWidth, 0x88)).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, responseCode,
            "Clause 5.3's first mode check admits only TPM2_GetTestResult and TPM2_GetCapability in Failure mode.");
    }

    /// <summary>
    /// The additional input is sensitive material the TPM holds only as long as the reseed needs it. "When an
    /// error is encountered while unmarshaling a command parameter, an error response code is returned, and no
    /// command processing occurs." (clause 5.8.2), so a REFUSED stir returns every octet it read and leaves the
    /// pool exactly where it found it; an ACCEPTED one returns everything but the reseed state it installs,
    /// which the RNG Protected Capability holds for the life of the TPM (Part 1, clause 8.4.11.2) and which the
    /// TPM releases when it goes away.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.8.2 and 16.2; Part 1, clause 8.4.11.2</see>.
    /// </summary>
    [TestMethod]
    public async Task AStirReturnsItsCarriersAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        long baseline;
        long afterRefusal;
        long afterSuccess;

        using(TpmSimulator simulator = CreatePoweredOff("tpm-in-house-stir-pool"))
        {
            using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
            TpmResponseRegistry registry = CreateRegistry();

            await BringOperationalAsync(simulator, pool).ConfigureAwait(false);
            baseline = trackingPool.OutstandingCount;

            TpmRcConstants refusal = await SubmitFramedAsync(simulator, pool, BuildStirBody(Pattern(Tpm2bSensitiveData.MaxSize + 1, 0x99))).ConfigureAwait(false);
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), refusal, "The refusal half of the pair must actually be refused.");
            afterRefusal = trackingPool.OutstandingCount;

            TpmRcConstants success = await StirAsync(device, registry, pool, Pattern(DrawWidth, 0xAA)).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, success, "The success half of the pair must actually succeed.");
            afterSuccess = trackingPool.OutstandingCount;
        }

        Assert.AreEqual(baseline, afterRefusal, "A TPM2_StirRandom refused for an over-bound inData must return every carrier it rented.");
        Assert.AreEqual(baseline + 1L, afterSuccess, "An accepted TPM2_StirRandom retains exactly one carrier: the reseed state the RNG keeps for the life of the TPM.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Disposing the TPM must release the reseed state it was holding.");
    }

    /// <summary>Creates a powered-off simulator needing no asymmetric backend, since a stir needs none.</summary>
    /// <param name="identifier">The simulator's own identifier.</param>
    /// <returns>The powered-off simulator.</returns>
    private static TpmSimulator CreatePoweredOff(string identifier) => new(identifier, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StirRandom, TpmResponseCodec.StirRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>Builds a repeating octet pattern of the requested width, so a stir's additional input is fixed and reproducible.</summary>
    /// <param name="length">The number of octets.</param>
    /// <param name="seed">The first octet; each following octet increments it.</param>
    /// <returns>The pattern.</returns>
    private static byte[] Pattern(int length, byte seed)
    {
        byte[] octets = new byte[length];
        for(int i = 0; i < length; i++)
        {
            octets[i] = (byte)(seed + i);
        }

        return octets;
    }

    /// <summary>Builds an octet array holding the same value at every position, an injected backend's own signature.</summary>
    /// <param name="length">The number of octets.</param>
    /// <param name="value">The value every octet carries.</param>
    /// <returns>The constant-filled array.</returns>
    private static byte[] Constant(int length, byte value)
    {
        byte[] octets = new byte[length];
        Array.Fill(octets, value);

        return octets;
    }

    /// <summary>Appends a big-endian <c>UINT16</c> to a command body under construction.</summary>
    /// <param name="body">The body being built.</param>
    /// <param name="value">The value to append.</param>
    private static void AppendUInt16(List<byte> body, int value)
    {
        body.Add((byte)(value >> 8));
        body.Add((byte)(value & 0xFF));
    }

    /// <summary>
    /// Lays out <c>TPM2_StirRandom()</c>'s sessionless parameter area by hand - the <c>UINT16</c> size field of
    /// Table 170 followed by the octets themselves - so a width the host carriers refuse to hold can still be
    /// put on the wire.
    /// </summary>
    /// <param name="additionalInput">The octets the size field declares.</param>
    /// <returns>The parameter area.</returns>
    private static byte[] BuildStirBody(byte[] additionalInput)
    {
        var body = new List<byte>();
        AppendUInt16(body, additionalInput.Length);
        body.AddRange(additionalInput);

        return [.. body];
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> straight to the simulator, sessionless, to move it into
    /// <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        TpmRcConstants responseCode = await SubmitInputForCodeAsync(simulator, pool, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, responseCode, "TPM2_Startup(CLEAR) must succeed.");
    }

    /// <summary>Frames a typed command input sessionless and submits it straight to the simulator.</summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The command input to frame.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitInputForCodeAsync(TpmSimulator simulator, BaseMemoryPool pool, ITpmCommandInput input)
    {
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a framed command rather than fault.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>
    /// Frames a <c>TPM_ST_NO_SESSIONS</c> <c>TPM2_StirRandom()</c> header around <paramref name="body"/> and
    /// submits it straight to the simulator, bypassing the host carriers so a malformed parameter area reaches
    /// the wire intact.
    /// </summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="body">The parameter area, already laid out.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitFramedAsync(TpmSimulator simulator, BaseMemoryPool pool, byte[] body)
    {
        int length = TpmHeader.HeaderSize + body.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_StirRandom);
        header.WriteTo(ref writer);
        writer.WriteBytes(body);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a malformed command rather than fault.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>Issues one sessionless <c>TPM2_StirRandom()</c> through the production command path.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="additionalInput">The additional input to fold into the RNG state.</param>
    /// <returns>The response code, <c>TPM_RC_SUCCESS</c> when the command was accepted.</returns>
    private async Task<TpmRcConstants> StirAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, byte[] additionalInput)
    {
        using Tpm2bSensitiveData inData = Tpm2bSensitiveData.Create(additionalInput, pool);
        TpmResult<StirRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<StirRandomResponse>(
            device, new StirRandomInput(inData), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        return result.IsSuccess switch
        {
            true => TpmRcConstants.TPM_RC_SUCCESS,
            false => result.ResponseCode
        };
    }

    /// <summary>Draws <see cref="DrawWidth"/> octets through <c>TPM2_GetRandom()</c> and copies them out.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The drawn octets.</returns>
    private async Task<byte[]> DrawRandomAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, new GetRandomInput(DrawWidth), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_GetRandom failed: '{result.ResponseCode}'.");

        using GetRandomResponse response = result.Value;

        return response.RandomBytes.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Brings a fresh simulator operational, issues <paramref name="stirs"/> in order - none of them for the
    /// unstirred twin of a pair - and returns the octets the next <c>TPM2_GetRandom()</c> answers, which is how
    /// every reseed proof in this file reads the RNG state out.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="identifier">The simulator's own identifier.</param>
    /// <param name="stirs">The additional inputs to stir in, in order.</param>
    /// <returns>The octets drawn after the stirs.</returns>
    private async Task<byte[]> DrawAfterStirsAsync(BaseMemoryPool pool, string identifier, byte[][] stirs)
    {
        using TpmSimulator simulator = CreatePoweredOff(identifier);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        foreach(byte[] stir in stirs)
        {
            TpmRcConstants responseCode = await StirAsync(device, registry, pool, stir).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, responseCode, "Every stir a reseed proof relies on must itself have succeeded.");
        }

        return await DrawRandomAsync(device, registry, pool).ConfigureAwait(false);
    }

    /// <summary>
    /// Brings a fresh simulator operational, optionally stirs it once, then starts an unbound unsalted HMAC
    /// session and returns the <c>nonceTPM</c> the TPM drew for it - the RNG consumer that is not
    /// <c>TPM2_GetRandom()</c>. The session is flushed before the simulator is disposed.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="identifier">The simulator's own identifier.</param>
    /// <param name="isStirred">Whether to issue a stir ahead of the session.</param>
    /// <returns>The session's <c>nonceTPM</c> octets.</returns>
    private async Task<byte[]> StartSessionNonceAfterStirAsync(BaseMemoryPool pool, string identifier, bool isStirred)
    {
        using TpmSimulator simulator = CreatePoweredOff(identifier);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        if(isStirred)
        {
            TpmRcConstants responseCode = await StirAsync(device, registry, pool, Pattern(DrawWidth, 0xBB)).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, responseCode, "The stir preceding the session must itself have succeeded.");
        }

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants.TPM_ALG_SHA256, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"TPM2_StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        byte[] nonceTpm = started.NonceTPM.AsReadOnlySpan().ToArray();

        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            device, FlushContextInput.ForHandle(started.SessionHandle.Value), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        return nonceTpm;
    }
}
