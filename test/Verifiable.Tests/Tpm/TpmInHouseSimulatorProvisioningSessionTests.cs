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
using Verifiable.Tpm.Extensions.Hierarchy;
using Verifiable.Tpm.Extensions.Policy;
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
/// Drives the two provisioning-authorized clock commands — <c>TPM2_ClockRateAdjust()</c> and
/// <c>TPM2_ClockSet()</c>, whose handle areas are the same single <c>TPMI_RH_PROVISION</c> <c>@auth</c> with
/// USER role — over authorization SESSIONS and over the raw wire: the owner and the platform arm, the bind
/// omission a session bound to <c>TPM_RH_OWNER</c> earns, the dictionary-attack posture a permanent entity and
/// a dictionary-attack-protected bind entity each impose, the authorization slot's refusals, the parameter
/// refusals both commands answer AFTER the command HMAC has verified, the fail-closed
/// <c>decrypt</c>/<c>encrypt</c>/<c>audit</c> answers a command with no sized parameter owes, and the hierarchy
/// enable gate both arms ride — against the in-house behavioural <see cref="TpmSimulator"/>, entirely in-process
/// with no external assets, through the same production command path the production code uses
/// (<see cref="TpmCommandExecutor"/> and the real command/response codecs). TPM 2.0 Library Part 3, clauses
/// 29.2, 29.3, 5.4, 5.5, 5.6 and 5.7; Part 2, clauses 6.6.2, 6.7 and 9.21; Part 1, clauses 13, 15.7, 16.6,
/// 16.8.1, 18.1 and 33.3.6.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorProvisioningSessionTests
{
    /// <summary>The SHA-256 digest width, in octets — the cpHash width and the session nonce width used here.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The hash algorithm for every session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The declared data size of every Ordinary Index this file defines.</summary>
    private const ushort OrdinaryDataSize = 16;

    /// <summary>The dictionary-attack-PROTECTED Ordinary Index used as a bind target and as the lockout driver.</summary>
    private const uint BindIndexHandle = 0x0100_0140;

    /// <summary>A defined NV Index handle framed into the authorization slot, where a non-session handle is under proof.</summary>
    private const uint NonSessionSlotIndexHandle = 0x0100_0141;

    /// <summary>
    /// The per-command oscillator tick contribution used where a rate change must be OBSERVABLE: at the nominal
    /// divisor a command advances Clock and Time by exactly this many milliseconds, and one coarse step moves
    /// that advance by about one percent, which a thousand-millisecond quantum resolves and the default
    /// one-millisecond quantum does not.
    /// </summary>
    private const ulong RateProbeQuantumMs = 1_000UL;

    /// <summary>
    /// The number of coarse steps whose accumulated divisor change reaches exactly the ±15% bound — fifteen
    /// times <c>TpmClockRate.CoarseStep</c> is <c>TpmClockRate.MaxDeviation</c>, so the fifteenth step is
    /// admitted and the sixteenth is the first that would cross.
    /// </summary>
    private const int CoarseStepsToTheBound = 15;

    /// <summary>
    /// A Clock setting far above any value a test run reaches by per-command advance and far below the clause
    /// 29.2 ceiling, so every <c>newTime</c> framed with it is a genuine forward set.
    /// </summary>
    private const ulong ForwardClockTarget = 1_000_000_000UL;

    /// <summary>Dictionary-attack-protected Ordinary Index attributes carrying no lock attribute at all.</summary>
    private const TpmaNv DaProtectedAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>The Index authorization value used throughout.</summary>
    private static byte[] CorrectAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong authorization value, distinct from every correct one this file installs.</summary>
    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>The owner authorization value installed before an owner arm is proven, so the HMAC key is not the empty buffer.</summary>
    private static byte[] InstalledOwnerAuth { get; } = [0x51, 0x62, 0x73, 0x84, 0x95, 0xA6, 0xB7, 0xC8];

    /// <summary>The platform authorization value installed before a platform arm is proven.</summary>
    private static byte[] InstalledPlatformAuth { get; } = [0x19, 0x28, 0x37, 0x46, 0x55, 0x64, 0x73, 0x82];

    /// <summary>A single-octet payload for the priming write that drives the TPM into Lockout mode.</summary>
    private static byte[] PrimingWriteData { get; } = [0x2A];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The owner arm of <c>TPM2_ClockRateAdjust()</c> over an unbound, unsalted HMAC session: "This command
    /// adjusts the rate of advance of Clock and Time to provide a better approximation to real time." — with the
    /// divisor unadjusted every admitted command advances Clock by exactly the oscillator quantum, and after one
    /// <c>TPM_CLOCK_COARSE_FASTER</c> step the very next admitted command advances it by more. A non-empty
    /// <c>ownerAuth</c> is installed first so the command HMAC is genuinely secret-keyed, and the executor's own
    /// verification of the response authorization is what makes the returned success meaningful.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3.1; Part 2, clause 6.7, Table 19; Part 1, clause 15.7, equation 15</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockRateAdjustOverHmacSessionAtTheOwnerArmSpeedsTheNextAdvance()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(RateProbeQuantumMs).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        await InstallOwnerAuthAsync(device).ConfigureAwait(false);

        ulong nominalAdvance = await MeasureAdvancePerCommandAsync(device, registry, pool).ConfigureAwait(false);
        Assert.AreEqual(
            RateProbeQuantumMs, nominalAdvance,
            "With no adjustment applied a command must advance Clock by exactly its oscillator quantum, or the case measures nothing.");

        TpmRcConstants code = await ProvisioningOverHmacAsync(
            device, pool, registry, TpmCcConstants.TPM_CC_ClockRateAdjust, TpmRh.TPM_RH_OWNER, InstalledOwnerAuth,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, code,
            $"Clause 29.3.1's owner arm over an HMAC session must succeed and its response authorization must verify on the host: '{code}'.");

        ulong fasterAdvance = await MeasureAdvancePerCommandAsync(device, registry, pool).ConfigureAwait(false);
        Assert.IsGreaterThan(
            nominalAdvance, fasterAdvance,
            "Clause 29.3.1: a TPM_CLOCK_COARSE_FASTER step must make Clock and Time advance faster from the next command onward.");
    }

    /// <summary>
    /// The platform arm of the same sentence — Table 236's <c>@auth</c> is <c>TPMI_RH_PROVISION</c>, whose two
    /// admitted values are <c>TPM_RH_OWNER</c> and <c>TPM_RH_PLATFORM</c> — proven over a session against an
    /// installed <c>platformAuth</c>, and in the opposite direction: "A TPM_CLOCK_ADJUST value in Table 19 is
    /// used to change the rate at which the TPM internal oscillator is divided. A change to the divider will
    /// change the rate at which Clock and Time change."
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3.2, Table 236; Part 2, clauses 6.7 and 9.21, Table 67</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockRateAdjustOverHmacSessionAtThePlatformArmSlowsTheNextAdvance()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(RateProbeQuantumMs).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        ulong nominalAdvance = await MeasureAdvancePerCommandAsync(device, registry, pool).ConfigureAwait(false);
        Assert.AreEqual(RateProbeQuantumMs, nominalAdvance, "With no adjustment applied a command must advance Clock by exactly its oscillator quantum.");

        TpmRcConstants code = await ProvisioningOverHmacAsync(
            device, pool, registry, TpmCcConstants.TPM_CC_ClockRateAdjust, TpmRh.TPM_RH_PLATFORM, InstalledPlatformAuth,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, $"Clause 29.3's platform arm over an HMAC session must succeed: '{code}'.");

        ulong slowerAdvance = await MeasureAdvancePerCommandAsync(device, registry, pool).ConfigureAwait(false);
        Assert.IsLessThan(
            nominalAdvance, slowerAdvance,
            "Clause 6.7: a TPM_CLOCK_COARSE_SLOWER step raises the divisor, so Clock and Time advance more slowly from the next command onward.");
    }

    /// <summary>
    /// The owner arm of <c>TPM2_ClockSet()</c> over an unbound, unsalted HMAC session: "This command is used to
    /// advance the value of the TPM's Clock." and "If both of these checks succeed, Clock is set to newTime." —
    /// which <c>TPM2_ReadClock()</c> then confirms, with <c>Safe</c> YES because an explicitly caller-set Clock
    /// is by construction a value never previously reported.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 29.2.1 and 29.1; Part 1, clause 15.7, equation 15</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockSetOverHmacSessionAtTheOwnerArmSetsClockAndReadClockConfirms()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        await InstallOwnerAuthAsync(device).ConfigureAwait(false);

        TpmRcConstants code = await ProvisioningOverHmacAsync(
            device, pool, registry, TpmCcConstants.TPM_CC_ClockSet, TpmRh.TPM_RH_OWNER, InstalledOwnerAuth,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, code,
            $"Clause 29.2.1's owner arm over an HMAC session must succeed and its response authorization must verify on the host: '{code}'.");

        await AssertClockWasSetAsync(device, registry, pool, ForwardClockTarget).ConfigureAwait(false);
    }

    /// <summary>
    /// The platform arm of "This command requires Platform Authorization or Owner Authorization." over a session,
    /// against an installed <c>platformAuth</c>: Part 3's Table 234 names the same <c>TPMI_RH_PROVISION</c>
    /// <c>@auth</c> Table 236 does, so the platform hierarchy sets Clock exactly as the owner hierarchy does.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.2.2, Table 234; Part 2, clause 9.21, Table 67</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockSetOverHmacSessionAtThePlatformArmSetsClockAndReadClockConfirms()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        TpmRcConstants code = await ProvisioningOverHmacAsync(
            device, pool, registry, TpmCcConstants.TPM_CC_ClockSet, TpmRh.TPM_RH_PLATFORM, InstalledPlatformAuth,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, $"Clause 29.2.1's platform arm over an HMAC session must succeed: '{code}'.");

        await AssertClockWasSetAsync(device, registry, pool, ForwardClockTarget).ConfigureAwait(false);
    }

    /// <summary>
    /// "If the authorization is for the entity to which the session is bound, the HMAC key is the session's
    /// sessionKey" — a session BOUND to <c>TPM_RH_OWNER</c> authorizes either provisioning clock command with the
    /// authValue term omitted, and the TPM mirrors the omission on the response authorization, which the executor
    /// verifies with the session key alone. The installed non-empty <c>ownerAuth</c> is what makes the omission
    /// observable: a TPM that folded it anyway would key the command HMAC differently and refuse.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.10, equation 22; Part 3, clauses 29.2.1 and 29.3.1</see>.
    /// </summary>
    /// <param name="commandCode">The provisioning clock command under proof.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, DisplayName = "TPM2_ClockRateAdjust over a session bound to the owner hierarchy")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, DisplayName = "TPM2_ClockSet over a session bound to the owner hierarchy")]
    public async Task ProvisioningClockCommandOverASessionBoundToTheOwnerHierarchySucceedsWithTheAuthValueOmitted(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        await InstallOwnerAuthAsync(device).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartBoundHmacSessionAsync(
            device, registry, pool, (uint)TpmRh.TPM_RH_OWNER, InstalledOwnerAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                TpmRcConstants code = await ProvisioningOverSessionAsync(
                    device, pool, registry, session, commandCode, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
                    ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_SUCCESS, code,
                    $"The bind omission must authorize the owner arm and be mirrored on the response authorization: '{code}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If the authorization is not for the entity to which the session is bound, the HMAC key is the
    /// concatenation of the entity's authValue to the session's sessionKey" (clause 16.6.10, equation 21) — a
    /// session BOUND to <c>TPM_RH_OWNER</c> presented on the PLATFORM arm authorizes a DIFFERENT entity than the
    /// one it is bound to, so equation 21's folded form governs, not equation 22's omission: the client's HMAC
    /// key must still fold platformAuth, and sending the sessionKey-alone form the owner arm accepts is a
    /// mismatch, the session-encoded <c>TPM_RC_BAD_AUTH</c>, uncharged. The same session then authorizes the
    /// platform arm correctly once platformAuth is folded into the key, without a restart — proving the
    /// omission is keyed on the COMMAND's own authorized entity, never on the session's bind alone.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.10, equations 21 and 22; Part 3, clauses 29.2.1 and 29.3.1</see>.
    /// </summary>
    /// <param name="commandCode">The provisioning clock command under proof.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, DisplayName = "TPM2_ClockRateAdjust over an owner-bound session on the platform arm")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, DisplayName = "TPM2_ClockSet over an owner-bound session on the platform arm")]
    public async Task ProvisioningClockCommandOverASessionBoundToTheOwnerHierarchyOnThePlatformArmRejectsTheOmissionForm(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        await InstallOwnerAuthAsync(device).ConfigureAwait(false);
        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartBoundHmacSessionAsync(
            device, registry, pool, (uint)TpmRh.TPM_RH_OWNER, InstalledOwnerAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                TpmRcConstants omittedOverPlatform = await ProvisioningOverSessionAsync(
                    device, pool, registry, session, commandCode, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty,
                    ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), omittedOverPlatform,
                    "The owner bind's omission does not carry over to the platform arm, so the session-key-alone form is a command-HMAC mismatch, session-encoded TPM_RC_BAD_AUTH.");
                Assert.AreEqual(
                    counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
                    "Clause 16.8.1: a dictionary-attack-exempt permanent entity's authorization mismatch must never charge failedTries.");

                TpmRcConstants foldedOverPlatform = await ProvisioningOverSessionAsync(
                    device, pool, registry, session, commandCode, TpmRh.TPM_RH_PLATFORM, InstalledPlatformAuth,
                    ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_SUCCESS, foldedOverPlatform,
                    $"Folding platformAuth into the same session's HMAC key must authorize the platform arm it actually names: '{foldedOverPlatform}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "the authValue associated with a permanent entity, other than TPM_RH_LOCKOUT, does not receive DA
    /// protection" — a wrong command HMAC over an UNBOUND session is therefore the non-charging
    /// <c>TPM_RC_BAD_AUTH</c>, named on the offending session by Part 2, clause 6.6.2's session-index encoding,
    /// with <c>TPM_PT_LOCKOUT_COUNTER</c> unmoved.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 2, clause 6.6.2; Part 3, clauses 29.2 and 29.3</see>.
    /// </summary>
    /// <param name="commandCode">The provisioning clock command under proof.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, DisplayName = "TPM2_ClockRateAdjust with a wrong command HMAC")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, DisplayName = "TPM2_ClockSet with a wrong command HMAC")]
    public async Task ProvisioningClockCommandOverHmacSessionWithWrongOwnerAuthReturnsSessionEncodedBadAuthUncharged(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        await InstallOwnerAuthAsync(device).ConfigureAwait(false);

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmRcConstants code = await ProvisioningOverHmacAsync(
            device, pool, registry, commandCode, TpmRh.TPM_RH_OWNER, WrongAuth,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
            "A permanent entity other than TPM_RH_LOCKOUT is dictionary-attack exempt, so its command-HMAC mismatch is the session-encoded TPM_RC_BAD_AUTH.");
        Assert.AreEqual(
            counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "Clause 16.8.1: a dictionary-attack-exempt authValue must never charge failedTries.");
    }

    /// <summary>
    /// "If the entity is authorized in a bind session, it receives DA protection if the bind entity receives DA
    /// protection" — a session BOUND to a dictionary-attack-protected NV Index carries that protection into
    /// whatever it authorizes, including the otherwise-exempt owner arm, so a wrong command HMAC is the
    /// session-encoded, CHARGING <c>TPM_RC_AUTH_FAIL</c> rather than the exempt entity's <c>TPM_RC_BAD_AUTH</c>,
    /// and <c>TPM_PT_LOCKOUT_COUNTER</c> moves by exactly one.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3; Part 2, clause 6.6.2</see>.
    /// </summary>
    /// <param name="commandCode">The provisioning clock command under proof.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, DisplayName = "TPM2_ClockRateAdjust over a dictionary-attack-protected bind")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, DisplayName = "TPM2_ClockSet over a dictionary-attack-protected bind")]
    public async Task ProvisioningClockCommandOverASessionBoundToADaProtectedIndexWithAWrongHmacReturnsAuthFailAndChargesFailedTries(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        await DefineIndexAsync(device, pool, registry, BindIndexHandle, DaProtectedAttributes).ConfigureAwait(false);
        await InstallOwnerAuthAsync(device).ConfigureAwait(false);

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartBoundHmacSessionAsync(
            device, registry, pool, BindIndexHandle, CorrectAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                TpmRcConstants code = await ProvisioningOverSessionAsync(
                    device, pool, registry, session, commandCode, TpmRh.TPM_RH_OWNER, WrongAuth,
                    ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), code,
                    "A dictionary-attack-protected bind entity turns the exempt entity's TPM_RC_BAD_AUTH into the charging TPM_RC_AUTH_FAIL.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }

        Assert.AreEqual(
            counterBefore + 1u, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "A command that receives dictionary-attack protection through its bind entity charges failedTries exactly once on a mismatch.");
    }

    /// <summary>
    /// "While in Lockout mode, any use of a DA-protected authValue will return TPM_RC_LOCKOUT" reaching a
    /// provisioning clock command through its BIND entity: with the TPM already in Lockout mode a session bound
    /// to a dictionary-attack-protected NV Index is refused with the bare <c>TPM_RC_LOCKOUT</c> before any
    /// authValue is evaluated, while the very same command over a <c>TPM_RS_PW</c> slot naming the
    /// dictionary-attack-exempt owner hierarchy still succeeds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3; Part 3, clauses 29.2.1 and 29.3.1</see>.
    /// </summary>
    /// <param name="commandCode">The provisioning clock command under proof.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, DisplayName = "TPM2_ClockRateAdjust bound to a DA-protected Index in Lockout mode")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, DisplayName = "TPM2_ClockSet bound to a DA-protected Index in Lockout mode")]
    public async Task ProvisioningClockCommandOverASessionBoundToADaProtectedIndexInLockoutModeReturnsLockoutWhileThePasswordOwnerSlotWorks(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        await DriveIntoLockoutAsync(device, pool, registry).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> lockedOut = await device.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lockedOut.IsSuccess, $"Reading the dictionary-attack parameters failed: '{lockedOut.ResponseCode}'.");
        Assert.IsTrue(lockedOut.Value.IsLockedOut, "The arrangement must leave the TPM in Lockout mode, or the case proves nothing.");

        (uint sessionHandle, TpmSession session) = await StartBoundHmacSessionAsync(
            device, registry, pool, BindIndexHandle, CorrectAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                TpmRcConstants code = await ProvisioningOverSessionAsync(
                    device, pool, registry, session, commandCode, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
                    ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_LOCKOUT, code,
                    "A bind entity that receives dictionary-attack protection lends it to the command, which Lockout mode then refuses with the bare TPM_RC_LOCKOUT.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }

        TpmRcConstants passwordCode = await ProvisioningWithPasswordAsync(
            device, pool, registry, commandCode, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, passwordCode,
            $"Clause 16.8.1: the owner hierarchy's own authValue is dictionary-attack exempt, so Lockout mode does not gate a password slot naming it: '{passwordCode}'.");
    }

    /// <summary>
    /// Clause 5.5, step 4 fixes the RESOLUTION ORDER at the authorization slot: a handle's kind (HMAC session,
    /// policy session, or <c>TPM_RS_PW</c>) is settled before its loadedness. A loaded POLICY session clears that
    /// order and reaches a command whose <c>@auth</c> admits ownerPolicy/platformPolicy alongside
    /// ownerAuth/platformAuth — a kind of authorization this simulator does not implement — so it is answered
    /// with the bare <c>TPM_RC_AUTH_TYPE</c> this simulator uses for an unimplemented authorization kind, naming
    /// no slot.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4; clauses 29.2 and 29.3</see>.
    /// </summary>
    /// <param name="commandCode">The provisioning clock command under proof.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, DisplayName = "TPM2_ClockRateAdjust over a loaded policy session")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, DisplayName = "TPM2_ClockSet over a loaded policy session")]
    public async Task ProvisioningClockCommandOverALoadedPolicySessionReturnsAuthType(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        TpmResult<StartAuthSessionResponse> policyStartResult = await device.StartPolicySessionAsync(HmacSessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");

        using StartAuthSessionResponse policyStarted = policyStartResult.Value;
        uint policySessionHandle = policyStarted.SessionHandle.Value;
        try
        {
            using TpmPolicySession policySlot = TpmPolicySession.ForSession(policySessionHandle, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);

            TpmRcConstants code = await ProvisioningOverSlotAsync(
                device, pool, registry, policySlot, commandCode, TpmRh.TPM_RH_OWNER,
                ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_TYPE, code,
                "A genuine POLICY session at the sole authorization slot must be refused with the bare TPM_RC_AUTH_TYPE.");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policySessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A session handle in the <c>0x02000000</c> range that names no loaded session is blamed on the offending
    /// slot index: "TPM_RC_REFERENCE_S0 ... the 1st session handle references a session that is not loaded",
    /// distinct from the bare <c>TPM_RC_AUTH_TYPE</c> a LOADED policy session earns.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.6.2; Part 3, clause 5.6</see>.
    /// </summary>
    /// <param name="commandCode">The provisioning clock command under proof.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, DisplayName = "TPM2_ClockRateAdjust over an unloaded session handle")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, DisplayName = "TPM2_ClockSet over an unloaded session handle")]
    public async Task ProvisioningClockCommandOverAnUnloadedSessionHandleReturnsReferenceMiss(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using(session)
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);

            TpmRcConstants code = await ProvisioningOverSessionAsync(
                device, pool, registry, session, commandCode, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
                ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_REFERENCE_S0, code,
                "A session handle naming no loaded session must be blamed on the offending slot index.");
        }
    }

    /// <summary>
    /// The third row of the authorization slot's own resolution: "If the session handle is not a handle for an
    /// HMAC session, a handle for a policy session, or, TPM_RS_PW then the TPM shall return TPM_RC_HANDLE" — a
    /// defined NV Index handle framed into the slot is refused before any credential is evaluated,
    /// session-index-encoded to the offending slot.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.1; Part 2, clause 6.6.2</see>.
    /// </summary>
    /// <param name="commandCode">The provisioning clock command under proof.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, DisplayName = "TPM2_ClockRateAdjust with a non-session authorization slot handle")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, DisplayName = "TPM2_ClockSet with a non-session authorization slot handle")]
    public async Task ProvisioningClockCommandOverANonSessionAuthorizationSlotHandleReturnsSessionEncodedHandle(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        await DefineIndexAsync(device, pool, registry, NonSessionSlotIndexHandle, DaProtectedAttributes).ConfigureAwait(false);

        TpmRcConstants code = await ProvisioningOverHmacHandFramedAsync(
            device, pool, registry, commandCode, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, default,
            slotHandleOverride: NonSessionSlotIndexHandle).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 0), code,
            "A non-session handle at the authorization slot is refused with the session-index-encoded TPM_RC_HANDLE, ahead of any credential evaluation.");
    }

    /// <summary>
    /// "A TPM_CLOCK_ADJUST value in Table 19 is used to change the rate at which the TPM internal oscillator is
    /// divided" — Table 19 defines seven values and marks any other <c>#TPM_RC_VALUE</c>, and the clause-5 order
    /// puts parameter unmarshalling (clause 5.8) after authorization (clause 5.6), so an octet outside the seven
    /// is answered <c>TPM_RC_VALUE</c> parameter-encoded at rateAdjust, parameter 1, only once the command HMAC
    /// has verified. Such a refusal is a
    /// header-only error response, so it rolls no nonce and the SAME session then authorizes a well-formed step
    /// without a restart. The refused command is hand-framed straight to the wire, since the host
    /// <see cref="ClockRateAdjustInput"/> now refuses an undefined step client-side before framing (its own
    /// separate proof, <see cref="ClockRateAdjustInputFramingTests"/>) — this test's own subject is the TPM's
    /// wire-level ordering, which a client-side refusal would never reach.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19; Part 3, clauses 5.6, 5.8.2 and 29.3.1; Part 1, clause 16.6.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockRateAdjustOverHmacSessionWithAnUndefinedStepReturnsValueAndRollsNoNonce()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(RateProbeQuantumMs).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        await InstallOwnerAuthAsync(device).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, InstalledOwnerAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                //One past TPM_CLOCK_COARSE_FASTER, so the octet is a well-formed INT8 that names no Table 19 member.
                const TpmClockAdjustConstants OutsideTableNineteen = (TpmClockAdjustConstants)4;

                session.SetAuthValue(InstalledOwnerAuth.AsSpan(), pool);
                TpmRcConstants refused = await SubmitProvisioningHandFramedOverSessionAsync(
                    device, pool, session, TpmCcConstants.TPM_CC_ClockRateAdjust, TpmRh.TPM_RH_OWNER,
                    ForwardClockTarget, OutsideTableNineteen).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), refused,
                    "A rateAdjust octet outside Table 19's seven members is refused at rateAdjust, parameter 1 of TPM2_ClockRateAdjust()'s own command table, judged after the authorization.");

                TpmRcConstants accepted = await ProvisioningOverSessionAsync(
                    device, pool, registry, session, TpmCcConstants.TPM_CC_ClockRateAdjust, TpmRh.TPM_RH_OWNER, InstalledOwnerAuth,
                    ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_SUCCESS, accepted,
                    $"A header-only refusal carries no response authorization and rolls no nonceTPM, so the next command on the same session must still verify: '{accepted}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If the requested adjustment would make the rate advance faster or slower than the nominal accuracy of the
    /// input frequency, the TPM shall return TPM_RC_VALUE." — with "The nominal rate of advance for Clock and
    /// Time shall be accurate to within 15 percent" fixing the bound, fifteen coarse steps reach it exactly and
    /// the sixteenth is the first that would cross, answered <c>TPM_RC_VALUE</c> parameter-encoded at
    /// rateAdjust, parameter 1, after the command HMAC has verified and with the rate unchanged — proven by the
    /// same session then accepting a step back toward nominal without a restart.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3.1; Part 1, clauses 33.3.6 and 16.6.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockRateAdjustOverHmacSessionCrossingTheBoundReturnsValueAndLeavesTheRateUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(RateProbeQuantumMs).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(session)
            {
                for(int step = 0; step < CoarseStepsToTheBound; ++step)
                {
                    TpmRcConstants admitted = await ProvisioningOverSessionAsync(
                        device, pool, registry, session, TpmCcConstants.TPM_CC_ClockRateAdjust, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
                        ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);
                    Assert.AreEqual(
                        TpmRcConstants.TPM_RC_SUCCESS, admitted,
                        $"Step {step + 1} of the fifteen that reach the ±15% bound exactly must be admitted: '{admitted}'.");
                }

                ulong advanceAtTheBound = await MeasureAdvancePerCommandAsync(device, registry, pool).ConfigureAwait(false);

                TpmRcConstants refused = await ProvisioningOverSessionAsync(
                    device, pool, registry, session, TpmCcConstants.TPM_CC_ClockRateAdjust, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
                    ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), refused,
                    "Clause 29.3.1: an adjustment beyond the nominal accuracy of the input frequency is refused at rateAdjust, parameter 1 of TPM2_ClockRateAdjust()'s own command table.");

                ulong advanceAfterTheRefusal = await MeasureAdvancePerCommandAsync(device, registry, pool).ConfigureAwait(false);
                ulong advanceDrift = advanceAfterTheRefusal > advanceAtTheBound
                    ? advanceAfterTheRefusal - advanceAtTheBound
                    : advanceAtTheBound - advanceAfterTheRefusal;

                Assert.IsLessThanOrEqualTo(
                    1ul, advanceDrift,
                    "A refused adjustment must leave the divisor exactly as it stood, so the advance can move by no more than the single millisecond the carried tick residue shifts it.");
                Assert.IsLessThan(
                    RateProbeQuantumMs, advanceAfterTheRefusal,
                    "The fifteen admitted slower steps still govern the advance after the refusal, so it stays below the nominal quantum.");

                TpmRcConstants accepted = await ProvisioningOverSessionAsync(
                    device, pool, registry, session, TpmCcConstants.TPM_CC_ClockRateAdjust, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
                    ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_SUCCESS, accepted,
                    $"A post-HMAC refusal rolls no nonceTPM, so a step back toward nominal on the same session must still verify: '{accepted}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "The command will fail if newTime is less than the current value of Clock or if the new time is greater
    /// than FF FF 00 00 00 00 00 0016. ... If either of these checks fails, the TPM shall return TPM_RC_VALUE and
    /// make no change to Clock." — on the session form both gates are judged AFTER the command HMAC has verified,
    /// so each refusal is a header-only error response that rolls no nonce and the SAME session then sets Clock
    /// forward without a restart.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 29.2.1, 5.6 and 5.8.2; Part 1, clause 16.6.3</see>.
    /// </summary>
    /// <param name="isAboveTheCeiling">Whether the refused <c>newTime</c> is the above-ceiling one rather than the backward one.</param>
    [TestMethod]
    [DataRow(false, DisplayName = "newTime below the current Clock")]
    [DataRow(true, DisplayName = "newTime above the clause 29.2 ceiling")]
    public async Task ClockSetOverHmacSessionWithARefusedNewTimeReturnsValueAndRollsNoNonce(bool isAboveTheCeiling)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        TpmsTimeInfo before = await ReadClockAsync(device, registry, pool).ConfigureAwait(false);
        Assert.IsGreaterThan(0ul, before.ClockInfo.Clock, "Clock must already be non-zero for a backward set to be meaningful.");

        ulong refusedTime = isAboveTheCeiling ? TpmLifecycleTransitions.MaxClockValue + 1ul : before.ClockInfo.Clock - 1ul;

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(session)
            {
                TpmRcConstants refused = await ProvisioningOverSessionAsync(
                    device, pool, registry, session, TpmCcConstants.TPM_CC_ClockSet, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
                    refusedTime, TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), refused,
                    "Clause 29.2.1: a newTime failing either check is TPM_RC_VALUE, judged after the authorization.");

                TpmsTimeInfo afterRefusal = await ReadClockAsync(device, registry, pool).ConfigureAwait(false);
                Assert.IsGreaterThan(
                    before.ClockInfo.Clock, afterRefusal.ClockInfo.Clock,
                    "Clause 29.2.1: a refused set makes no change to Clock, which therefore only advanced by the intervening commands' own quanta.");

                TpmRcConstants accepted = await ProvisioningOverSessionAsync(
                    device, pool, registry, session, TpmCcConstants.TPM_CC_ClockSet, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
                    ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_SUCCESS, accepted,
                    $"A header-only refusal carries no response authorization and rolls no nonceTPM, so the next command on the same session must still verify: '{accepted}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }

        await AssertClockWasSetAsync(device, registry, pool, ForwardClockTarget).ConfigureAwait(false);
    }

    /// <summary>
    /// The accepting half of the raw command-HMAC proof: a hand-framed composition whose cpHash is computed
    /// independently — the command code folded with the authorizing handle's own four octets, "the Name of a
    /// permanent entity is the handle" (Part 1, clause 13, Table 9), and the plaintext parameter area (one INT8
    /// octet for <c>rateAdjust</c>, eight UINT64 octets for <c>newTime</c>) — succeeds, which makes that cpHash
    /// the thing the TPM's own command-HMAC verification must agree with.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.7, equation 15, and clause 13, Table 9; Part 3, clauses 29.2.2 and 29.3.2</see>.
    /// </summary>
    /// <param name="commandCode">The provisioning clock command under proof.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, DisplayName = "TPM2_ClockRateAdjust hand-framed with the correct cpHash")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, DisplayName = "TPM2_ClockSet hand-framed with the correct cpHash")]
    public async Task ProvisioningClockCommandOverHmacHandFramedWithTheCorrectCpHashSucceeds(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        TpmRcConstants code = await ProvisioningOverHmacHandFramedAsync(
            device, pool, registry, commandCode, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, default).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, $"A cpHash independently computed the production way must verify: '{code}'.");
    }

    /// <summary>
    /// The negative twin: the same composition, but cpHash's Name term is <c>TPM_RH_PLATFORM</c>'s four octets
    /// while the wire's handle area still carries <c>TPM_RH_OWNER</c> — a command HMAC keyed on the WRONG Name
    /// cannot verify against the octets the TPM actually received, so the answer is the session-encoded,
    /// non-charging <c>TPM_RC_BAD_AUTH</c> the exempt permanent entity earns.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.7, equation 15, and clause 13, Table 9; Part 2, clause 6.6.2</see>.
    /// </summary>
    /// <param name="commandCode">The provisioning clock command under proof.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, DisplayName = "TPM2_ClockRateAdjust hand-framed with the wrong Name term")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, DisplayName = "TPM2_ClockSet hand-framed with the wrong Name term")]
    public async Task ProvisioningClockCommandOverHmacHandFramedWithTheWrongNameReturnsSessionEncodedBadAuth(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmRcConstants code = await ProvisioningOverHmacHandFramedAsync(
            device, pool, registry, commandCode, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, default,
            cpHashHandleOverride: TpmRh.TPM_RH_PLATFORM).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
            "cpHash folding the wrong Name term cannot key a command HMAC that verifies against the octets actually on the wire.");
        Assert.AreEqual(
            counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "TPM_RH_OWNER's authValue is dictionary-attack exempt, so the mismatch never charges failedTries.");
    }

    /// <summary>
    /// "If session-based encryption is allowed, only the first parameter in the parameter area of a request or
    /// response can be encrypted. That parameter must have an explicit size field." — neither command's parameter
    /// has one (<c>rateAdjust</c> is a bare INT8, <c>newTime</c> a bare UINT64) and neither response carries a
    /// parameter at all, so a <c>decrypt</c>- or <c>encrypt</c>-attributed authorizing session fails closed with
    /// <c>TPM_RC_ATTRIBUTES</c> naming the offending slot — a "no sized parameter" refusal, which is why
    /// <c>audit</c> (Table 38's row names no such precondition) is proven separately, not folded into this same
    /// message. Proven hand-framed, because the executor's own client-side guard refuses the encryption
    /// compositions before any octet reaches the wire.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clauses 5.5, 5.7, 29.2 and 29.3</see>.
    /// </summary>
    /// <param name="commandCode">The provisioning clock command under proof.</param>
    /// <param name="attribute">The <c>TPMA_SESSION</c> bit under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, TpmaSession.DECRYPT, DisplayName = "TPM2_ClockRateAdjust with a decrypt claim")]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, TpmaSession.ENCRYPT, DisplayName = "TPM2_ClockRateAdjust with an encrypt claim")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, TpmaSession.DECRYPT, DisplayName = "TPM2_ClockSet with a decrypt claim")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, TpmaSession.ENCRYPT, DisplayName = "TPM2_ClockSet with an encrypt claim")]
    public async Task ProvisioningClockCommandOverSessionWithAnUnsupportedClaimReturnsSessionEncodedAttributes(TpmCcConstants commandCode, TpmaSession attribute)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        TpmRcConstants code = await ProvisioningOverHmacHandFramedAsync(
            device, pool, registry, commandCode, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, attribute).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
            "A command with no sized parameter and a header-only response must fail closed on the offending session with the session-index-encoded TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// <c>audit</c> carries no "sized parameter" precondition (TPM 2.0 Library Part 2, clause 8.4, Table 38), so
    /// the authorizing session claiming it is admitted and the provisioning clock command succeeds, unlike a
    /// <c>decrypt</c> or <c>encrypt</c> claim on these same header-only-response commands (Part 1, clause 17.1) —
    /// extending the session's audit digest to <c>H(0…0 ‖ cpHash ‖ rpHash)</c> on its first use (equation 30)
    /// with the response echoing <c>audit</c> SET, <c>auditExclusive</c> SET and <c>auditReset</c> CLEAR (Table
    /// 38) — proved by chaining cpHash/rpHash from the octets this test itself sent and read, then reading the
    /// session's digest back through <c>TPM2_GetSessionAuditDigest()</c> with the NULL signer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1; Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    /// <param name="commandCode">The provisioning clock command under proof.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, DisplayName = "TPM2_ClockRateAdjust with an audit claim")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, DisplayName = "TPM2_ClockSet with an audit claim")]
    public async Task ProvisioningClockCommandOverSessionWithAnAuditClaimSucceeds(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes |= TpmaSession.AUDIT;

                (TpmRcConstants code, byte[] response, byte[] cpHash) = await ProvisioningOverHmacHandFramedForAuditAsync(
                    device, pool, session, commandCode, TpmRh.TPM_RH_OWNER,
                    ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_SUCCESS, code,
                    "An audit-claiming session over an audited provisioning command succeeds (TPM 2.0 Library Part 1, clause 17.1).");

                byte auditedAttributes = ReadResponseSessionAttributes(response, outHandleCount: 0, sessionIndex: 0);
                Assert.AreEqual(
                    (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE), auditedAttributes,
                    "The response echoes audit SET and auditExclusive SET (the session's first use as an audit session), with auditReset CLEAR (TPM 2.0 Library Part 2, clause 8.4, Table 38).");

                byte[] responseParameters = ReadResponseParameters(response, outHandleCount: 0);
                byte[] rpHash = await ComputeRpHashAsync(commandCode, responseParameters, pool).ConfigureAwait(false);
                byte[] expectedDigest = await ExtendAuditDigestAsync(priorDigest: null, cpHash, rpHash, pool).ConfigureAwait(false);

                using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(sessionHandle), ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                using GetSessionAuditDigestResponse? auditDigestResponse = digestResult.IsSuccess ? digestResult.Value : null;

                Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() over the freshly audited session must succeed: '{digestResult.ResponseCode}'.");
                Assert.IsTrue(auditDigestResponse!.SessionAudit.ExclusiveSession.IsYes, "The session became the exclusive audit session on its first use (TPM 2.0 Library Part 1, clause 17.2).");
                Assert.IsTrue(
                    expectedDigest.AsSpan().SequenceEqual(auditDigestResponse.SessionAudit.SessionDigest.AsReadOnlySpan()),
                    "The session's audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) chained from the provisioning exchange's own wire octets (TPM 2.0 Library Part 1, clause 17.1, equation 30).");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The client-side half of clause 18.1's rule: the executor refuses to compose either provisioning clock
    /// command with a <c>decrypt</c>- or <c>encrypt</c>-attributed authorizing session at all, throwing before
    /// any octet reaches the wire — the reason the wire-side proof above must be hand-framed.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 5.7</see>.
    /// </summary>
    /// <param name="commandCode">The provisioning clock command under proof.</param>
    /// <param name="attribute">The <c>TPMA_SESSION</c> bit under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, TpmaSession.DECRYPT, DisplayName = "the executor refuses TPM2_ClockRateAdjust with a decrypt claim")]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, TpmaSession.ENCRYPT, DisplayName = "the executor refuses TPM2_ClockRateAdjust with an encrypt claim")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, TpmaSession.DECRYPT, DisplayName = "the executor refuses TPM2_ClockSet with a decrypt claim")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, TpmaSession.ENCRYPT, DisplayName = "the executor refuses TPM2_ClockSet with an encrypt claim")]
    public async Task ProvisioningClockCommandOverSessionWithAnEncryptionClaimIsRefusedByTheExecutor(TpmCcConstants commandCode, TpmaSession attribute)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes |= attribute;

                _ = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
                    await ProvisioningOverSessionAsync(
                        device, pool, registry, session, commandCode, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
                        ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false)).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPMI_RH_PROVISION</c> admits <c>TPM_RH_OWNER</c> and <c>TPM_RH_PLATFORM</c> and nothing else, with
    /// "#TPM_RC_VALUE" as the unmarshalling error for any other value — so <c>TPM_RH_ENDORSEMENT</c> at
    /// <c>@auth</c> is <c>TPM_RC_VALUE</c> handle-encoded at the invoked command's own auth handle, handle 1,
    /// on the session form too, answered at the head of the transition before the authorization slot is even
    /// resolved.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.21, Table 67; Part 3, clauses 29.2.2 and 29.3.2</see>.
    /// </summary>
    /// <param name="commandCode">The provisioning clock command under proof.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, DisplayName = "TPM2_ClockRateAdjust with a non-provision @auth over a session")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, DisplayName = "TPM2_ClockSet with a non-provision @auth over a session")]
    public async Task ProvisioningClockCommandOverHmacSessionWithANonProvisionHandleReturnsValue(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        TpmRcConstants code = await ProvisioningOverHmacAsync(
            device, pool, registry, commandCode, TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), code,
            "A handle outside TPMI_RH_PROVISION designates the invoked command's own auth handle, handle 1, at unmarshalling.");
    }

    /// <summary>
    /// "This command requires Platform Authorization or Owner Authorization." on the PASSWORD form once
    /// <c>platformAuth</c> is a real value: the authorization is compared against the hierarchy's live carrier
    /// rather than the factory one, so a rotated <c>platformAuth</c> is what sets Clock, and
    /// <c>TPM2_ReadClock()</c> confirms the new setting.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 29.2.1 and 24.8; Part 1, clause 16.6.4.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockSetUnderAnInstalledPlatformAuthOverAPasswordSlotSetsClock()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        TpmRcConstants code = await ProvisioningWithPasswordAsync(
            device, pool, registry, TpmCcConstants.TPM_CC_ClockSet, TpmRh.TPM_RH_PLATFORM, InstalledPlatformAuth,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, $"An installed platformAuth must authorize clause 29.2's set over a password slot: '{code}'.");

        await AssertClockWasSetAsync(device, registry, pool, ForwardClockTarget).ConfigureAwait(false);
    }

    /// <summary>
    /// The refusing half of the same installed <c>platformAuth</c>: "the authValue associated with a permanent
    /// entity, other than TPM_RH_LOCKOUT, does not receive DA protection", so a wrong value over the password
    /// slot is the non-charging <c>TPM_RC_BAD_AUTH</c> session-index-encoded to the offending slot, with
    /// <c>TPM_PT_LOCKOUT_COUNTER</c> unmoved and Clock unchanged — and the superseded factory-empty value is
    /// exactly such a wrong value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 3, clauses 29.2.1 and 24.8</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockSetUnderAWrongInstalledPlatformAuthReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);
        TpmsTimeInfo before = await ReadClockAsync(device, registry, pool).ConfigureAwait(false);

        TpmRcConstants code = await ProvisioningWithPasswordAsync(
            device, pool, registry, TpmCcConstants.TPM_CC_ClockSet, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), code,
            "Once platformAuth is rotated the superseded value must no longer authorize clause 29.2's set, and the refusal is the exempt entity's non-charging TPM_RC_BAD_AUTH.");
        Assert.AreEqual(
            counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "Clause 16.8.1: a dictionary-attack-exempt authValue must never charge failedTries.");

        TpmsTimeInfo after = await ReadClockAsync(device, registry, pool).ConfigureAwait(false);
        Assert.IsLessThan(
            ForwardClockTarget, after.ClockInfo.Clock,
            "A refused authorization applies none of clause 29.2's effect, so Clock only advanced by the intervening commands' own quanta.");
        Assert.IsGreaterThan(before.ClockInfo.Clock, after.ClockInfo.Clock, "The intervening commands still advance Clock by their own quanta.");
    }

    /// <summary>
    /// "If the handle references a primary seed for a hierarchy (TPM_RH_ENDORSEMENT, TPM_RH_OWNER, or
    /// TPM_RH_PLATFORM) then the enable for the hierarchy is SET (TPM_RC_HIERARCHY)" — with <c>shEnable</c>
    /// CLEARed under Platform Authorization the owner arm of either provisioning clock command answers
    /// <c>TPM_RC_HIERARCHY</c> handle-encoded at the invoked command's own auth handle, handle 1, on the
    /// password form AND on the session form, refused before any authorization is judged, while the platform
    /// arm still succeeds; SETting the enable again restores the owner arm, proving the refusal was the enable
    /// and not the command.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.4, check 5; clauses 24.2, 29.2.1 and 29.3.1</see>.
    /// </summary>
    /// <param name="commandCode">The provisioning clock command under proof.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, DisplayName = "TPM2_ClockRateAdjust under a disabled owner hierarchy")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, DisplayName = "TPM2_ClockSet under a disabled owner hierarchy")]
    public async Task ProvisioningClockCommandUnderADisabledOwnerHierarchyReturnsHierarchyWhileThePlatformArmWorks(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        await SetHierarchyEnableAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, TpmiYesNo.No).ConfigureAwait(false);

        TpmRcConstants passwordCode = await ProvisioningWithPasswordAsync(
            device, pool, registry, commandCode, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), passwordCode,
            "Clause 5.4's check 5 refuses a disabled hierarchy at the invoked command's own auth handle, handle 1, ahead of clause 5.6's authorization.");

        TpmRcConstants sessionCode = await ProvisioningOverHmacAsync(
            device, pool, registry, commandCode, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), sessionCode,
            "The enable gate precedes the command-HMAC verification a session adds, so the session form answers the same handle-encoded TPM_RC_HIERARCHY.");

        TpmRcConstants platformCode = await ProvisioningOverHmacAsync(
            device, pool, registry, commandCode, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, platformCode,
            $"The platform arm is gated by phEnable alone and must still succeed: '{platformCode}'.");

        await SetHierarchyEnableAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, TpmiYesNo.Yes).ConfigureAwait(false);

        TpmRcConstants restoredCode = await ProvisioningOverHmacAsync(
            device, pool, registry, commandCode, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
            ForwardClockTarget + 1_000_000ul, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, restoredCode,
            $"With shEnable SET again the same owner-authorized command must succeed, proving the refusal was the enable: '{restoredCode}'.");
    }

    /// <summary>
    /// The converse enable, on <c>TPM2_ClockSet()</c>: with <c>phEnable</c> CLEARed under Platform Authorization
    /// the platform arm answers <c>TPM_RC_HIERARCHY</c> handle-encoded at the invoked command's own auth
    /// handle, handle 1 — "then the enable for the hierarchy is SET (TPM_RC_HIERARCHY)" — while the owner arm,
    /// gated by <c>shEnable</c> alone, still sets Clock.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.4, check 5; clauses 24.2 and 29.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockSetUnderADisabledPlatformHierarchyReturnsHierarchyWhileTheOwnerArmSetsClock()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        await SetHierarchyEnableAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, TpmiYesNo.No).ConfigureAwait(false);

        TpmRcConstants platformCode = await ProvisioningOverHmacAsync(
            device, pool, registry, TpmCcConstants.TPM_CC_ClockSet, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), platformCode,
            "Clause 5.4's check 5 refuses a disabled platform hierarchy at authHandle, handle 1 of TPM2_ClockSet's own command table, ahead of any authorization.");

        TpmRcConstants ownerCode = await ProvisioningOverHmacAsync(
            device, pool, registry, TpmCcConstants.TPM_CC_ClockSet, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty,
            ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, ownerCode, $"The owner arm is gated by shEnable alone and must still succeed: '{ownerCode}'.");

        await AssertClockWasSetAsync(device, registry, pool, ForwardClockTarget).ConfigureAwait(false);
    }

    /// <summary>
    /// The HMAC-session form of both provisioning clock commands returns every carrier its parse rented — the raw
    /// parameter area and the authorization slot's own nonce and hmac credentials — across a refusal at the
    /// command HMAC, a success, AND a post-HMAC parameter refusal (an out-of-Table-19 octet for
    /// <c>TPM2_ClockRateAdjust()</c>, a backward <c>newTime</c> for <c>TPM2_ClockSet()</c>, both judged after the
    /// same verified session's HMAC): the metered pool returns to its baseline after each.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 29.2 and 29.3; Part 1, clause 15.7</see>.
    /// </summary>
    /// <param name="commandCode">The provisioning clock command under proof.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ClockRateAdjust, DisplayName = "TPM2_ClockRateAdjust returns its carriers")]
    [DataRow(TpmCcConstants.TPM_CC_ClockSet, DisplayName = "TPM2_ClockSet returns its carriers")]
    public async Task ProvisioningClockCommandOverHmacSessionReturnsItsCarriersAcrossARefusalAndASuccess(TpmCcConstants commandCode)
    {
        //One past TPM_CLOCK_COARSE_FASTER, so the octet is a well-formed INT8 that names no Table 19 member.
        const TpmClockAdjustConstants OutsideTableNineteen = (TpmClockAdjustConstants)4;

        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateProvisioningRegistry();

        await InstallOwnerAuthAsync(device).ConfigureAwait(false);

        (uint wrongSessionHandle, TpmSession wrongSession) = await StartUnboundSessionAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);
        (uint correctSessionHandle, TpmSession correctSession) = await StartUnboundSessionAsync(device, pool, registry, InstalledOwnerAuth).ConfigureAwait(false);
        try
        {
            using(wrongSession)
            using(correctSession)
            {
                long baseline = trackingPool.OutstandingCount;

                TpmRcConstants refused = await ProvisioningOverSessionAsync(
                    device, pool, registry, wrongSession, commandCode, TpmRh.TPM_RH_OWNER, WrongAuth,
                    ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), refused,
                    "A wrong command HMAC against a dictionary-attack-exempt permanent entity is the session-encoded TPM_RC_BAD_AUTH.");
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A command refused at its command HMAC releases every carrier its parse rented.");

                TpmRcConstants accepted = await ProvisioningOverSessionAsync(
                    device, pool, registry, correctSession, commandCode, TpmRh.TPM_RH_OWNER, InstalledOwnerAuth,
                    ForwardClockTarget, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, accepted, $"The provisioning clock command over an HMAC session failed: '{accepted}'.");
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The accepting continuation and the response framing between them release every carrier.");

                TpmRcConstants postHmacRefusal = commandCode switch
                {
                    TpmCcConstants.TPM_CC_ClockRateAdjust => await SubmitProvisioningHandFramedOverSessionAsync(
                        device, pool, correctSession, commandCode, TpmRh.TPM_RH_OWNER, ForwardClockTarget, OutsideTableNineteen).ConfigureAwait(false),
                    _ => await ProvisioningOverSessionAsync(
                        device, pool, registry, correctSession, commandCode, TpmRh.TPM_RH_OWNER, InstalledOwnerAuth,
                        newTime: 0UL, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false)
                };
                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), postHmacRefusal,
                    $"'{commandCode}''s own post-HMAC parameter gate — Table 19 membership or the newTime bound — designates the command's own parameter 1: '{postHmacRefusal}'.");
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refusal judged AFTER the command HMAC has verified must still release every carrier its parse rented.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, wrongSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(device, registry, pool, correctSessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Asserts that a successful <c>TPM2_ClockSet()</c> put Clock at <paramref name="expectedTarget"/>, allowing
    /// only for the per-command quanta the intervening readback commands themselves contribute, and that
    /// <c>Safe</c> is YES.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="expectedTarget">The <c>newTime</c> the successful set requested.</param>
    private async Task AssertClockWasSetAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, ulong expectedTarget)
    {
        TpmsTimeInfo after = await ReadClockAsync(device, registry, pool).ConfigureAwait(false);

        Assert.IsGreaterThanOrEqualTo(
            expectedTarget, after.ClockInfo.Clock,
            "Clause 29.2.1: a successful set puts Clock at newTime, which the readback then advances by its own quantum alone.");
        Assert.IsLessThan(
            expectedTarget + 1_000ul, after.ClockInfo.Clock,
            "Clock must sit at the requested value plus only the intervening commands' own quanta, not at some unrelated value.");
        Assert.IsTrue(after.ClockInfo.Safe.IsYes, "Clause 29.2.1: an explicitly caller-set Clock is a value never previously reported, so Safe is YES.");
    }

    /// <summary>
    /// Measures the milliseconds one admitted command advances Clock by, as the difference between two
    /// immediately consecutive <c>TPM2_ReadClock()</c> answers.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The per-command advance, in milliseconds.</returns>
    private async Task<ulong> MeasureAdvancePerCommandAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        TpmsTimeInfo first = await ReadClockAsync(device, registry, pool).ConfigureAwait(false);
        TpmsTimeInfo second = await ReadClockAsync(device, registry, pool).ConfigureAwait(false);

        return second.ClockInfo.Clock - first.ClockInfo.Clock;
    }

    /// <summary>Issues one <c>TPM2_ReadClock()</c> and returns the parsed current-time snapshot (Part 3, clause 29.1).</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The current <c>TPMS_TIME_INFO</c>.</returns>
    private async Task<TpmsTimeInfo> ReadClockAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        TpmResult<ReadClockResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadClockResponse>(
            device, new ReadClockInput(), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ReadClock failed: '{result.ResponseCode}'.");

        return result.Value.CurrentTime;
    }

    /// <summary>
    /// Issues whichever provisioning clock command <paramref name="commandCode"/> names over a freshly started
    /// UNBOUND, unsalted HMAC session whose authValue term is <paramref name="suppliedAuth"/>, flushing the
    /// session afterwards.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="commandCode">The provisioning clock command to issue.</param>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="newTime">The <c>newTime</c> a <c>TPM2_ClockSet()</c> requests.</param>
    /// <param name="rateAdjust">The <c>rateAdjust</c> a <c>TPM2_ClockRateAdjust()</c> requests.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> ProvisioningOverHmacAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmCcConstants commandCode, TpmRh authHandle,
        ReadOnlyMemory<byte> suppliedAuth, ulong newTime, TpmClockAdjustConstants rateAdjust)
    {
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, suppliedAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                return await ProvisioningOverSessionAsync(
                    device, pool, registry, session, commandCode, authHandle, suppliedAuth, newTime, rateAdjust).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Issues whichever provisioning clock command <paramref name="commandCode"/> names over a CALLER-OWNED HMAC
    /// session, folding <paramref name="suppliedAuth"/> as the entity authValue term (empty composes the
    /// bind-omission form on a session bound to the authorized hierarchy). The <c>handleNames</c> argument is
    /// <see langword="null"/> because the sole handle is permanent (Part 1, clause 13, Table 9).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="session">The authorizing session.</param>
    /// <param name="commandCode">The provisioning clock command to issue.</param>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="suppliedAuth">The authValue term to fold, or empty for the omission form.</param>
    /// <param name="newTime">The <c>newTime</c> a <c>TPM2_ClockSet()</c> requests.</param>
    /// <param name="rateAdjust">The <c>rateAdjust</c> a <c>TPM2_ClockRateAdjust()</c> requests.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> ProvisioningOverSessionAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmSession session, TpmCcConstants commandCode,
        TpmRh authHandle, ReadOnlyMemory<byte> suppliedAuth, ulong newTime, TpmClockAdjustConstants rateAdjust)
    {
        session.SetAuthValue(suppliedAuth.Span, pool);

        return await ProvisioningOverSlotAsync(device, pool, registry, session, commandCode, authHandle, newTime, rateAdjust).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues whichever provisioning clock command <paramref name="commandCode"/> names over an arbitrary
    /// authorization slot — an HMAC session, a policy session or a password slot alike — and returns the raw
    /// response code.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="slot">The authorization slot the command is framed with.</param>
    /// <param name="commandCode">The provisioning clock command to issue.</param>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="newTime">The <c>newTime</c> a <c>TPM2_ClockSet()</c> requests.</param>
    /// <param name="rateAdjust">The <c>rateAdjust</c> a <c>TPM2_ClockRateAdjust()</c> requests.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> ProvisioningOverSlotAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmSessionBase slot, TpmCcConstants commandCode,
        TpmRh authHandle, ulong newTime, TpmClockAdjustConstants rateAdjust) =>
        commandCode switch
        {
            TpmCcConstants.TPM_CC_ClockSet => ResponseCodeOf(await TpmCommandExecutor.ExecuteAsync<ClockSetResponse>(
                device, new ClockSetInput(authHandle, newTime), [slot], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)),
            _ => ResponseCodeOf(await TpmCommandExecutor.ExecuteAsync<ClockRateAdjustResponse>(
                device, new ClockRateAdjustInput(authHandle, rateAdjust), [slot], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false))
        };

    /// <summary>
    /// Reduces a command result to one comparable response code: <c>TPM_RC_SUCCESS</c> for a success, and the
    /// TPM's own answer otherwise, so a case can assert the whole of Table 2's answer space uniformly.
    /// </summary>
    /// <typeparam name="TResponse">The command's response type.</typeparam>
    /// <param name="result">The command result.</param>
    /// <returns>The response code the TPM answered.</returns>
    private static TpmRcConstants ResponseCodeOf<TResponse>(TpmResult<TResponse> result) =>
        result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode;

    /// <summary>
    /// Issues whichever provisioning clock command <paramref name="commandCode"/> names over a <c>TPM_RS_PW</c>
    /// password slot carrying <paramref name="suppliedAuth"/> (Part 1, clause 16.6.4.1).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="commandCode">The provisioning clock command to issue.</param>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="suppliedAuth">The password the slot carries.</param>
    /// <param name="newTime">The <c>newTime</c> a <c>TPM2_ClockSet()</c> requests.</param>
    /// <param name="rateAdjust">The <c>rateAdjust</c> a <c>TPM2_ClockRateAdjust()</c> requests.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> ProvisioningWithPasswordAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmCcConstants commandCode, TpmRh authHandle,
        ReadOnlyMemory<byte> suppliedAuth, ulong newTime, TpmClockAdjustConstants rateAdjust)
    {
        using TpmPasswordSession slot = TpmPasswordSession.Create(suppliedAuth.Span, pool);

        return await ProvisioningOverSlotAsync(device, pool, registry, slot, commandCode, authHandle, newTime, rateAdjust).ConfigureAwait(false);
    }

    /// <summary>
    /// The SIMULATOR-side proof for the session-attribute fail-closed gate, the authorization slot's own
    /// resolution, and the raw command-HMAC verification: hand-frames a raw provisioning clock command authorized
    /// by a single unbound, unsalted HMAC session whose <c>sessionAttributes</c> octet carries
    /// <paramref name="attribute"/>, and submits it directly to the transport — bypassing
    /// <see cref="TpmCommandExecutor"/>, whose own client-side guard would refuse an encryption attribute before
    /// any bytes reach the wire. The cpHash is the SAME production computation <see cref="TpmSession"/> performs
    /// for every executor-composed case in this file: equation (15) folds the command code,
    /// <paramref name="cpHashHandleOverride"/> (or <paramref name="authHandle"/> when omitted) as the permanent
    /// handle's own Name, and the plaintext parameter octets. <paramref name="slotHandleOverride"/>, when
    /// supplied, patches the wire's authorization slot handle field AFTER the genuine session has framed a
    /// well-formed block, so the nonce, session attributes and hmac stay exactly as a real session would carry
    /// them.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry (used only for the session's own lifecycle commands).</param>
    /// <param name="commandCode">The provisioning clock command to frame.</param>
    /// <param name="authHandle">The authorizing hierarchy, written into the wire's handle area.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="newTime">The <c>newTime</c> a <c>TPM2_ClockSet()</c> frames.</param>
    /// <param name="rateAdjust">The <c>rateAdjust</c> a <c>TPM2_ClockRateAdjust()</c> frames.</param>
    /// <param name="attribute">The <c>TPMA_SESSION</c> bit under test.</param>
    /// <param name="slotHandleOverride">A wire-only substitute for the authorization slot's session handle field, or <see langword="null"/> to leave the genuine session handle in place.</param>
    /// <param name="cpHashHandleOverride">A wire-only substitute for cpHash's Name term, or <see langword="null"/> to fold <paramref name="authHandle"/>.</param>
    /// <returns>The raw wire response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> ProvisioningOverHmacHandFramedAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmCcConstants commandCode, TpmRh authHandle,
        ReadOnlyMemory<byte> suppliedAuth, ulong newTime, TpmClockAdjustConstants rateAdjust, TpmaSession attribute,
        uint? slotHandleOverride = null, TpmRh? cpHashHandleOverride = null)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            session.SetAuthValue(suppliedAuth.Span, pool);
            session.SessionAttributes |= attribute;

            return await SubmitProvisioningHandFramedOverSessionAsync(
                device, pool, session, commandCode, authHandle, newTime, rateAdjust, slotHandleOverride, cpHashHandleOverride).ConfigureAwait(false);
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The hand-framing core <see cref="ProvisioningOverHmacHandFramedAsync"/> uses, factored out so a caller
    /// that already holds a LIVE, previously-verified session can hand-frame one more command over that SAME
    /// session — the shape a post-HMAC-refusal-then-retry proof needs, since the session's own nonce state must
    /// carry across both commands. Bypasses <see cref="TpmCommandExecutor"/> and the host command types' own
    /// client-side guards entirely, so a value the host type would refuse to frame still reaches the wire.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The already-started session to authorize the command with; not started or flushed here.</param>
    /// <param name="commandCode">The provisioning clock command to frame.</param>
    /// <param name="authHandle">The authorizing hierarchy, written into the wire's handle area.</param>
    /// <param name="newTime">The <c>newTime</c> a <c>TPM2_ClockSet()</c> frames.</param>
    /// <param name="rateAdjust">The <c>rateAdjust</c> a <c>TPM2_ClockRateAdjust()</c> frames.</param>
    /// <param name="slotHandleOverride">A wire-only substitute for the authorization slot's session handle field, or <see langword="null"/> to leave the genuine session handle in place.</param>
    /// <param name="cpHashHandleOverride">A wire-only substitute for cpHash's Name term, or <see langword="null"/> to fold <paramref name="authHandle"/>.</param>
    /// <returns>The raw wire response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> SubmitProvisioningHandFramedOverSessionAsync(
        TpmDevice device, BaseMemoryPool pool, TpmSession session, TpmCcConstants commandCode, TpmRh authHandle,
        ulong newTime, TpmClockAdjustConstants rateAdjust, uint? slotHandleOverride = null, TpmRh? cpHashHandleOverride = null)
    {
        //cpHash = H_SHA256(commandCode || Name(authHandle) || parameters) — TPM 2.0 Library Part 1, clause
        //15.7, equation 15, with the permanent handle's Name being the handle's own four octets (clause 13,
        //Table 9) and the parameters term the plaintext octets this command declares.
        int parameterSize = ParameterAreaSize(commandCode);
        int cpHashInputLength = sizeof(uint) + sizeof(uint) + parameterSize;
        using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
        Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
        {
            var cpHashWriter = new TpmWriter(cpHashInput.Span);
            cpHashWriter.WriteUInt32((uint)commandCode);
            cpHashWriter.WriteUInt32((uint)(cpHashHandleOverride ?? authHandle));
            WriteParameterArea(ref cpHashWriter, commandCode, newTime, rateAdjust);
        }

        using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            cpHashInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.RollNonceCaller(pool);
        using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(
            cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        const int handlesSize = sizeof(uint);
        int authAreaSize = sizeof(uint) + session.GetAuthCommandSize();
        int totalSize = TpmHeader.HeaderSize + handlesSize + authAreaSize + parameterSize;

        using IMemoryOwner<byte> commandOwner = pool.Rent(totalSize);
        Memory<byte> command = commandOwner.Memory[..totalSize];
        var writer = new TpmWriter(command.Span);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
        writer.WriteUInt32((uint)totalSize);
        writer.WriteUInt32((uint)commandCode);
        writer.WriteUInt32((uint)authHandle);
        writer.WriteUInt32((uint)session.GetAuthCommandSize());
        session.WriteAuthCommand(ref writer, hmac);
        WriteParameterArea(ref writer, commandCode, newTime, rateAdjust);

        if(slotHandleOverride is uint overrideHandle)
        {
            int slotHandleOffset = TpmHeader.HeaderSize + handlesSize + sizeof(uint);
            BinaryPrimitives.WriteUInt32BigEndian(command.Span.Slice(slotHandleOffset, sizeof(uint)), overrideHandle);
        }

        TpmResult<TpmResponse> transportResult = await device.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(transportResult.IsSuccess, "The transport itself must succeed even when the TPM refuses the command.");

        using TpmResponse response = transportResult.Value;
        var responseReader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref responseReader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// The audit twin of <see cref="SubmitProvisioningHandFramedOverSessionAsync"/>: hand-frames a raw
    /// provisioning clock command over an already-started, LIVE session, submits it directly to the transport,
    /// and returns the raw response octets and the independently computed cpHash alongside the response code —
    /// the session is neither started nor flushed here, so the caller keeps it loaded to read its audit digest
    /// back through <c>TPM2_GetSessionAuditDigest()</c>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The already-started session to authorize the command with, carrying <c>audit</c>.</param>
    /// <param name="commandCode">The provisioning clock command to frame.</param>
    /// <param name="authHandle">The authorizing hierarchy, written into the wire's handle area.</param>
    /// <param name="newTime">The <c>newTime</c> a <c>TPM2_ClockSet()</c> frames.</param>
    /// <param name="rateAdjust">The <c>rateAdjust</c> a <c>TPM2_ClockRateAdjust()</c> frames.</param>
    /// <returns>The response code, the raw response octets and cpHash.</returns>
    private async Task<(TpmRcConstants ResponseCode, byte[] Response, byte[] CpHash)> ProvisioningOverHmacHandFramedForAuditAsync(
        TpmDevice device, BaseMemoryPool pool, TpmSession session, TpmCcConstants commandCode, TpmRh authHandle, ulong newTime, TpmClockAdjustConstants rateAdjust)
    {
        int parameterSize = ParameterAreaSize(commandCode);
        int cpHashInputLength = sizeof(uint) + sizeof(uint) + parameterSize;
        using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
        Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
        {
            var cpHashWriter = new TpmWriter(cpHashInput.Span);
            cpHashWriter.WriteUInt32((uint)commandCode);
            cpHashWriter.WriteUInt32((uint)authHandle);
            WriteParameterArea(ref cpHashWriter, commandCode, newTime, rateAdjust);
        }

        using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            cpHashInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.RollNonceCaller(pool);
        using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(
            cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        const int handlesSize = sizeof(uint);
        int authAreaSize = sizeof(uint) + session.GetAuthCommandSize();
        int totalSize = TpmHeader.HeaderSize + handlesSize + authAreaSize + parameterSize;

        using IMemoryOwner<byte> commandOwner = pool.Rent(totalSize);
        Memory<byte> command = commandOwner.Memory[..totalSize];
        var writer = new TpmWriter(command.Span);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
        writer.WriteUInt32((uint)totalSize);
        writer.WriteUInt32((uint)commandCode);
        writer.WriteUInt32((uint)authHandle);
        writer.WriteUInt32((uint)session.GetAuthCommandSize());
        session.WriteAuthCommand(ref writer, hmac);
        WriteParameterArea(ref writer, commandCode, newTime, rateAdjust);

        TpmResult<TpmResponse> transportResult = await device.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(transportResult.IsSuccess, "The transport itself must succeed even when the TPM refuses the command.");

        using TpmResponse response = transportResult.Value;
        byte[] responseBytes = response.AsReadOnlySpan().ToArray();
        var responseReader = new TpmReader(responseBytes);

        return ((TpmRcConstants)TpmHeader.Parse(ref responseReader).Code, responseBytes, cpHash.AsReadOnlySpan().ToArray());
    }

    /// <summary>
    /// Reads the response parameter area out of a captured raw response's octets — the bytes rpHash (TPM 2.0
    /// Library Part 1, clause 15.8, equation 16) is computed over, as actually returned on the wire, independent
    /// of whatever the codec parsed them into.
    /// </summary>
    /// <param name="responseBytes">The raw response octets, tagged <c>TPM_ST_SESSIONS</c>.</param>
    /// <param name="outHandleCount">The number of output handles the response carries before its parameter area.</param>
    /// <returns>The response parameter octets.</returns>
    private static byte[] ReadResponseParameters(byte[] responseBytes, int outHandleCount)
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
    private static byte ReadResponseSessionAttributes(byte[] responseBytes, int outHandleCount, int sessionIndex)
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
    /// Computes <c>rpHash = H_sessionAlg(TPM_RC_SUCCESS ‖ commandCode ‖ parameters)</c> (TPM 2.0 Library Part 1,
    /// clause 15.8, equation 16) over the response parameter octets as actually read off the wire.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="responseParameters">The response parameter area as read.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The rpHash octets.</returns>
    private async Task<byte[]> ComputeRpHashAsync(TpmCcConstants commandCode, ReadOnlyMemory<byte> responseParameters, BaseMemoryPool pool)
    {
        byte[] input = new byte[sizeof(uint) + sizeof(uint) + responseParameters.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, (uint)TpmRcConstants.TPM_RC_SUCCESS);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(sizeof(uint)), (uint)commandCode);
        responseParameters.Span.CopyTo(input.AsSpan(2 * sizeof(uint)));

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
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
    /// <returns>The extended digest.</returns>
    private async Task<byte[]> ExtendAuditDigestAsync(byte[]? priorDigest, byte[] cpHash, byte[] rpHash, BaseMemoryPool pool)
    {
        byte[] old = priorDigest ?? new byte[Sha256DigestSize];
        byte[] input = new byte[old.Length + cpHash.Length + rpHash.Length];
        old.CopyTo(input, 0);
        cpHash.CopyTo(input, old.Length);
        rpHash.CopyTo(input, old.Length + cpHash.Length);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// The width of the parameter area each provisioning clock command declares: one INT8 octet for
    /// <c>rateAdjust</c> (Part 3, Table 236), eight UINT64 octets for <c>newTime</c> (Table 234).
    /// </summary>
    /// <param name="commandCode">The provisioning clock command.</param>
    /// <returns>The parameter area width, in octets.</returns>
    private static int ParameterAreaSize(TpmCcConstants commandCode) =>
        commandCode switch
        {
            TpmCcConstants.TPM_CC_ClockSet => sizeof(ulong),
            _ => sizeof(sbyte)
        };

    /// <summary>
    /// Writes the plaintext parameter area each provisioning clock command declares, in its own wire form: the
    /// signed <c>rateAdjust</c> octet (<c>TPM_CLOCK_COARSE_SLOWER</c> frames as <c>FD</c>) or the big-endian
    /// eight-octet <c>newTime</c>.
    /// </summary>
    /// <param name="writer">The writer positioned at the parameter area.</param>
    /// <param name="commandCode">The provisioning clock command.</param>
    /// <param name="newTime">The <c>newTime</c> a <c>TPM2_ClockSet()</c> frames.</param>
    /// <param name="rateAdjust">The <c>rateAdjust</c> a <c>TPM2_ClockRateAdjust()</c> frames.</param>
    private static void WriteParameterArea(ref TpmWriter writer, TpmCcConstants commandCode, ulong newTime, TpmClockAdjustConstants rateAdjust)
    {
        if(commandCode == TpmCcConstants.TPM_CC_ClockSet)
        {
            writer.WriteUInt64(newTime);
        }
        else
        {
            writer.WriteInt8((sbyte)rateAdjust);
        }
    }

    /// <summary>
    /// Builds the digest <see cref="Tag"/> used to independently compute cpHash for
    /// <see cref="ProvisioningOverHmacHandFramedAsync"/>: SHA-256 digest, raw encoding, direct material — the
    /// same shape <c>TpmCommandExecutor</c>'s own cpHash computation uses.
    /// </summary>
    /// <returns>The digest tag.</returns>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

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
    /// Starts an unbound, unsalted HMAC session (TPM 2.0 Library Part 1, clause 16.6.9) and composes the host
    /// session over it with <paramref name="authValue"/> as its authValue term.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authValue">The authValue the session proves.</param>
    /// <returns>The session handle (to flush) and the composed session (to dispose).</returns>
    private async Task<(uint Handle, TpmSession Session)> StartUnboundSessionAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, ReadOnlyMemory<byte> authValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        session.SetAuthValue(authValue.Span, pool);

        return (started.SessionHandle.Value, session);
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
    /// <returns>The started session handle and its client-side wrapper.</returns>
    private async Task<(uint Handle, TpmSession Session)> StartBoundHmacSessionAsync(
        TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, uint bindHandle, ReadOnlyMemory<byte> bindAuthValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(bindHandle, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to 0x{bindHandle:X8}) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(startResponse.SessionHandle.Value), bindAuthValue, startInput.NonceCaller,
            startResponse.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (startResponse.SessionHandle.Value, session);
    }

    /// <summary>
    /// Installs <see cref="InstalledOwnerAuth"/> as <c>ownerAuth</c> over the factory-empty value, so a
    /// subsequent command HMAC is keyed on a genuine secret rather than the empty buffer.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    private async Task InstallOwnerAuthAsync(TpmDevice device)
    {
        TpmResult<HierarchyChangeAuthResponse> result = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, InstalledOwnerAuth, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Installing ownerAuth failed: '{result.ResponseCode}'.");
    }

    /// <summary>Installs <see cref="InstalledPlatformAuth"/> as <c>platformAuth</c> over the factory-empty value.</summary>
    /// <param name="device">The TPM device.</param>
    private async Task InstallPlatformAuthAsync(TpmDevice device)
    {
        TpmResult<HierarchyChangeAuthResponse> result = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, InstalledPlatformAuth, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Installing platformAuth failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Writes <paramref name="state"/> into <paramref name="hierarchy"/>'s enable through a password-authorized
    /// <c>TPM2_HierarchyControl()</c> under Platform Authorization, asserting the write succeeded — Platform
    /// Authorization may CLEAR or SET any enable (TPM 2.0 Library Part 3, clause 24.2.1).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="hierarchy">The hierarchy whose enable is written.</param>
    /// <param name="state">The enable's new state.</param>
    private async Task SetHierarchyEnableAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh hierarchy, TpmiYesNo state)
    {
        using TpmPasswordSession session = TpmPasswordSession.CreateEmpty(pool);
        var input = new HierarchyControlInput(TpmRh.TPM_RH_PLATFORM, hierarchy, state);

        TpmResult<HierarchyControlResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyControlResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyControl() on '{hierarchy}' failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Lowers <c>maxTries</c> to one and drives the TPM into Lockout mode with a single wrong-password write
    /// against a freshly defined dictionary-attack-protected Index (<see cref="BindIndexHandle"/>), which the
    /// caller subsequently reuses as a bind target.
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

        await DefineIndexAsync(device, pool, registry, BindIndexHandle, DaProtectedAttributes).ConfigureAwait(false);

        TpmResult<NvWriteResponse> wrongResult = await WriteIndexAsync(device, pool, registry, BindIndexHandle, WrongAuth, PrimingWriteData).ConfigureAwait(false);

        //Arrangement machinery, not the normative case under proof: the password arm answers the
        //session-index-encoded TPM_RC_AUTH_FAIL for this rejection, and with maxTries lowered to one it
        //engages Lockout mode at once.
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode,
            "The priming write must fail and count, taking the TPM into Lockout mode.");
    }

    /// <summary>
    /// Issues <c>TPM2_NV_DefineSpace()</c> for <paramref name="nvIndex"/> with <see cref="CorrectAuth"/> as the
    /// Index authValue, authorized by the (empty) owner authValue over a password session.
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

        //The input takes ownership of the auth value and public area and disposes them; the redundant using
        //locals satisfy CA2000 and are safe because both types have idempotent disposal.
        using var auth = Tpm2bAuth.Create(CorrectAuth, pool);
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

    /// <summary>Creates a response codec registry for the commands these tests drive directly.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateProvisioningRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_ClockSet, TpmResponseCodec.ClockSet)
            .Register(TpmCcConstants.TPM_CC_ClockRateAdjust, TpmResponseCodec.ClockRateAdjust)
            .Register(TpmCcConstants.TPM_CC_ReadClock, TpmResponseCodec.ReadClock)
            .Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl)
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

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

    /// <summary>
    /// Creates a simulator whose per-command oscillator quantum is <paramref name="clockAdvanceQuantumMs"/>,
    /// powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase — the
    /// precondition both provisioning clock commands carry.
    /// </summary>
    /// <param name="clockAdvanceQuantumMs">The per-command oscillator tick contribution.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(ulong clockAdvanceQuantumMs = TpmSimulatorState.DefaultClockAdvanceQuantumMs)
    {
        var simulator = new TpmSimulator("tpm-in-house-provisioning-session", clockAdvanceQuantumMs: clockAdvanceQuantumMs, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitStartupAsync(simulator, BaseMemoryPool.Shared, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
