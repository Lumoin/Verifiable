using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Nv;
using Verifiable.Tpm.Extensions.Pin;
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
/// The six hierarchy-family commands under proof — <c>TPM2_Clear()</c>, <c>TPM2_ClearControl()</c>,
/// <c>TPM2_HierarchyControl()</c>, <c>TPM2_SetPrimaryPolicy()</c>, the session arms of <c>TPM2_NV_DefineSpace()</c>
/// and <c>TPM2_NV_UndefineSpace()</c> — named so a <see cref="DataRowAttribute"/> can drive one test method across
/// every one of them.
/// </summary>
internal enum HierarchySlotCommand
{
    /// <summary>Names <c>TPM2_Clear()</c> for <see cref="TpmInHouseSimulatorHierarchySlotTableTests"/>'s data-driven cases.</summary>
    Clear,

    /// <summary>Names <c>TPM2_ClearControl()</c> for <see cref="TpmInHouseSimulatorHierarchySlotTableTests"/>'s data-driven cases.</summary>
    ClearControl,

    /// <summary>Names <c>TPM2_HierarchyControl()</c> for <see cref="TpmInHouseSimulatorHierarchySlotTableTests"/>'s data-driven cases.</summary>
    HierarchyControl,

    /// <summary>Names <c>TPM2_SetPrimaryPolicy()</c> for <see cref="TpmInHouseSimulatorHierarchySlotTableTests"/>'s data-driven cases.</summary>
    SetPrimaryPolicy,

    /// <summary>Names <c>TPM2_NV_DefineSpace()</c>'s session arm for <see cref="TpmInHouseSimulatorHierarchySlotTableTests"/>'s data-driven cases.</summary>
    NvDefineSpace,

    /// <summary>Names <c>TPM2_NV_UndefineSpace()</c>'s session arm for <see cref="TpmInHouseSimulatorHierarchySlotTableTests"/>'s data-driven cases.</summary>
    NvUndefineSpace
}

/// <summary>
/// Names the other four hierarchy-family commands with a session-authorized form — the INVARIANCE side of the
/// proof <see cref="HierarchySlotCommand"/>'s six commands carry, so a <see cref="DataRowAttribute"/> can drive one
/// test method across every one of them.
/// </summary>
internal enum CompliantHierarchySlotCommand
{
    /// <summary>Names <c>TPM2_NV_GlobalWriteLock()</c> for <see cref="TpmInHouseSimulatorHierarchySlotTableTests"/>'s data-driven cases.</summary>
    NvGlobalWriteLock,

    /// <summary>Names <c>TPM2_ClockSet()</c> for <see cref="TpmInHouseSimulatorHierarchySlotTableTests"/>'s data-driven cases.</summary>
    ClockSet,

    /// <summary>Names <c>TPM2_ClockRateAdjust()</c> for <see cref="TpmInHouseSimulatorHierarchySlotTableTests"/>'s data-driven cases.</summary>
    ClockRateAdjust,

    /// <summary>Names <c>TPM2_HierarchyChangeAuth()</c> for <see cref="TpmInHouseSimulatorHierarchySlotTableTests"/>'s data-driven cases.</summary>
    HierarchyChangeAuth
}

/// <summary>
/// Proves that the hierarchy family judges its authorization slot by the one table the signing family applies —
/// an unloaded HMAC-session handle, a loaded POLICY session, and a non-session handle type answer alike whichever
/// of the ten commands names the slot — and that the NV and hierarchy commands mirror an Empty command
/// <c>hmac</c> into an Empty response <c>hmac</c> exactly as the signing family does, entirely in-process against
/// the in-house behavioural <see cref="TpmSimulator"/> through the same production command path the production
/// code uses.
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
/// clause 5.5, step 4; Part 1, clause 16.6.16</see>.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorHierarchySlotTableTests
{
    /// <summary>The hash algorithm for every session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The declared data size of every Ordinary Index this file defines.</summary>
    private const ushort OrdinaryDataSize = 16;

    /// <summary>The Index authorization value installed on the Index <c>TPM2_NV_UndefineSpace()</c>'s cases remove.</summary>
    private static byte[] IndexAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>The Ordinary Index attributes every defined Index in this file carries — no lock, no policy-delete, not platform-created.</summary>
    private const TpmaNv OrdinaryAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>Attributes of a self-authorizing, dictionary-attack-exempt <c>TPM_NT_EXTEND</c> Index.</summary>
    private const TpmaNv ExtendAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA
        | (TpmaNv)((uint)TpmNt.TPM_NT_EXTEND << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>
    /// <see cref="OrdinaryAttributes"/> plus <c>TPMA_NV_PLATFORMCREATE</c> — "SET (1): Index defined using
    /// Platform Authorization" (TPM 2.0 Library Part 2, Table 249) — for the Indexes this file's platform-arm
    /// happy-path cases define under <c>TPM_RH_PLATFORM</c>.
    /// </summary>
    private const TpmaNv PlatformOrdinaryAttributes = OrdinaryAttributes | TpmaNv.TPMA_NV_PLATFORMCREATE;

    /// <summary>The Index handle <c>TPM2_NV_DefineSpace()</c>'s slot-table cases attempt to define — never actually persisted, since every case is refused before the command's body runs.</summary>
    private const uint DefineSpaceIndexHandle = 0x0100_50A0;

    /// <summary>The Index handle pre-defined so <c>TPM2_NV_UndefineSpace()</c>'s slot-table cases have a real Index to name.</summary>
    private const uint UndefineSpaceIndexHandle = 0x0100_50B0;

    /// <summary>The SHA-256 digest width, in octets — every session hash and every Extend Index's declared data size in this file.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The Index <c>TPM2_NV_DefineSpace()</c>'s platform-arm happy-path case defines over a real session.</summary>
    private const uint DefineSpacePlatformHappyIndexHandle = 0x0100_02B0;

    /// <summary>The Index pre-defined so <c>TPM2_NV_UndefineSpace()</c>'s platform-arm happy-path case has a real Index to remove over a real session.</summary>
    private const uint UndefineSpacePlatformHappyIndexHandle = 0x0100_02B1;

    /// <summary>The Empty-authValue Index the response-hmac mirroring pin's <c>TPM2_NV_Write()</c> case writes to.</summary>
    private const uint NvWriteEmptyAuthIndexHandle = 0x0100_02B2;

    /// <summary>The Empty-authValue Index the response-hmac mirroring pin's <c>TPM2_NV_Read()</c> case reads from, pre-written over the same empty-hmac shape.</summary>
    private const uint NvReadEmptyAuthIndexHandle = 0x0100_02B3;

    /// <summary>The Empty-authValue <c>TPM_NT_EXTEND</c> Index the response-hmac mirroring pin's <c>TPM2_NV_Extend()</c> case extends.</summary>
    private const uint NvExtendEmptyAuthIndexHandle = 0x0100_02B4;

    /// <summary>The Index carrying a REAL, non-empty authValue that clause 16.6.16's negative case authorizes with an Empty hmac.</summary>
    private const uint NonEmptyAuthValueIndexHandle = 0x0100_02B5;

    /// <summary>The <c>TPM_NT_PIN_FAIL</c> Index the two-slot framer's <c>TPM2_NV_ChangeAuth()</c> happy-path pin rotates.</summary>
    private const uint NvChangeAuthHappyIndexHandle = 0x0100_02B8;

    /// <summary>The real, non-empty authorization value <see cref="NonEmptyAuthValueIndexHandle"/> carries.</summary>
    private static byte[] NonEmptyAuthValue { get; } = [0x5A, 0x5B, 0x5C, 0x5D];

    /// <summary>Sixteen octets written to an Ordinary Index by this file's response-hmac mirroring cases.</summary>
    private static byte[] NvBufferPayload { get; } =
        [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];

    /// <summary>Thirty-two octets extended into a <c>TPM_NT_EXTEND</c> Index by this file's response-hmac mirroring case.</summary>
    private static byte[] ExtendPayload { get; } = new byte[Sha256DigestSize];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Clause 5.5, step 4.2: "If the session is not loaded, the TPM will return the warning TPM_RC_REFERENCE_S0 +
    /// N where N is the number of the session. The first session is session zero, N = 0." An HMAC-session handle
    /// that names no loaded session answers the same bare <c>TPM_RC_REFERENCE_S0</c> whichever of the six
    /// commands names the slot — the cell every session-authorized command shares with the signing family.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.2</see>.
    /// </summary>
    /// <param name="command">The command under proof.</param>
    [TestMethod]
    [DataRow(HierarchySlotCommand.Clear)]
    [DataRow(HierarchySlotCommand.ClearControl)]
    [DataRow(HierarchySlotCommand.HierarchyControl)]
    [DataRow(HierarchySlotCommand.SetPrimaryPolicy)]
    [DataRow(HierarchySlotCommand.NvDefineSpace)]
    [DataRow(HierarchySlotCommand.NvUndefineSpace)]
    public async Task OverAnUnloadedHmacSessionHandleReturnsReferenceMiss(HierarchySlotCommand command)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint unloadedHandle = await StartAndFlushHmacSessionAsync(device, pool, registry).ConfigureAwait(false);

        ITpmCommandInput input = await BuildInputAsync(device, pool, registry, command).ConfigureAwait(false);
        try
        {
            TpmRcConstants code = await SubmitOverSlotAsync(device, pool, input, unloadedHandle).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_REFERENCE_S0, code,
                $"{command}: an HMAC-session handle naming no loaded session must be the bare TPM_RC_REFERENCE_S0.");
        }
        finally
        {
            (input as IDisposable)?.Dispose();
        }
    }

    /// <summary>
    /// Clause 5.5, step 4 fixes the RESOLUTION ORDER: a handle's kind (HMAC session, policy session, or
    /// <c>TPM_RS_PW</c>) is settled before its loadedness. A loaded POLICY session clears that classification and
    /// reaches the command's own authorization rule, which admits a policy alongside an HMAC/password only through
    /// a kind of authorization this simulator does not implement — so it is answered with the bare
    /// <c>TPM_RC_AUTH_TYPE</c> this simulator uses for an unimplemented authorization kind, naming no slot, on
    /// every one of the six commands, exactly as the signing family answers it. A loaded policy session and an
    /// unloaded HMAC handle are distinct cells, never both collapsed into the bare, non-session-encoded
    /// <c>TPM_RC_REFERENCE_S0</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4</see>.
    /// </summary>
    /// <param name="command">The command under proof.</param>
    [TestMethod]
    [DataRow(HierarchySlotCommand.Clear)]
    [DataRow(HierarchySlotCommand.ClearControl)]
    [DataRow(HierarchySlotCommand.HierarchyControl)]
    [DataRow(HierarchySlotCommand.SetPrimaryPolicy)]
    [DataRow(HierarchySlotCommand.NvDefineSpace)]
    [DataRow(HierarchySlotCommand.NvUndefineSpace)]
    public async Task OverALoadedPolicySessionReturnsAuthType(HierarchySlotCommand command)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint policyHandle = await StartPolicySessionAsync(device, registry, pool).ConfigureAwait(false);
        try
        {
            ITpmCommandInput input = await BuildInputAsync(device, pool, registry, command).ConfigureAwait(false);
            try
            {
                TpmRcConstants code = await SubmitOverSlotAsync(device, pool, input, policyHandle).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_AUTH_TYPE, code,
                    $"{command}: a genuine POLICY session at the sole authorization slot must be refused with the bare TPM_RC_AUTH_TYPE.");
            }
            finally
            {
                (input as IDisposable)?.Dispose();
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Clause 5.5, step 4.1: "If the session handle is not a handle for an HMAC session, a handle for a policy
    /// session, or, TPM_RS_PW then the TPM shall return TPM_RC_HANDLE" — session-index-encoded (TPM 2.0 Library
    /// Part 2, clause 6.6.2), since the refusal names the offending slot rather than reporting a handle whose
    /// top octet is not a session kind at all as merely "not loaded".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.1; Part 2, clause 6.6.2</see>.
    /// </summary>
    /// <param name="command">The command under proof.</param>
    [TestMethod]
    [DataRow(HierarchySlotCommand.Clear)]
    [DataRow(HierarchySlotCommand.ClearControl)]
    [DataRow(HierarchySlotCommand.HierarchyControl)]
    [DataRow(HierarchySlotCommand.SetPrimaryPolicy)]
    [DataRow(HierarchySlotCommand.NvDefineSpace)]
    [DataRow(HierarchySlotCommand.NvUndefineSpace)]
    public async Task OverANonSessionHandleTypeReturnsSessionEncodedHandle(HierarchySlotCommand command)
    {
        const uint NonSessionHandle = 0x8000_0000;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        ITpmCommandInput input = await BuildInputAsync(device, pool, registry, command).ConfigureAwait(false);
        try
        {
            TpmRcConstants code = await SubmitOverSlotAsync(device, pool, input, NonSessionHandle).ConfigureAwait(false);

            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 0), code,
                $"{command}: a handle whose top octet is not a session kind at all must be the session-encoded TPM_RC_HANDLE.");
        }
        finally
        {
            (input as IDisposable)?.Dispose();
        }
    }

    /// <summary>
    /// The NV family's response-hmac mirroring pin: Part 1, clause 16.6.16, "The TPM will use the same formulation in the response as
    /// was in the command. This is, if hmac was non-zero in the command, the TPM will compute authHMAC as shown
    /// in Equation 17 and use the result as hmac. If hmac was an Empty Buffer in the command, it will be an Empty
    /// Buffer in the response." An unbound, unsalted session (so the session key is Empty) authorizing
    /// <c>TPM_RH_OWNER</c>, whose <c>ownerAuth</c> is the factory-empty value, with the caller supplying an
    /// Empty <c>hmac</c>: the command HMAC verification's own empty-key rule accepts it, and the RESPONSE
    /// <c>hmac</c> field is the Empty Buffer too — width 0 on the wire — rather than a computed 32-octet HMAC,
    /// with the response nonceTPM still rolled to its full session-hash width.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockWithAnEmptyHmacOverAnUnboundSessionOnTheFactoryEmptyOwnerAuthIsAnsweredWithAnEmptyHmac()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartUnboundHmacSessionAsync(device, registry, pool).ConfigureAwait(false);
        try
        {
            (TpmRcConstants code, int nonceTpmSize, int responseHmacSize) = await SubmitSingleHandleCommandWithEmptyHmacAsync(
                simulator, pool, TpmCcConstants.TPM_CC_NV_GlobalWriteLock, (uint)TpmRh.TPM_RH_OWNER, sessionHandle).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "An Empty hmac over an entirely empty HMAC key must authorize the command.");
            Assert.AreEqual(SHA256.HashSizeInBytes, nonceTpmSize, "The response entry must carry a rolled nonceTPM of the session hash's width.");
            Assert.AreEqual(0, responseHmacSize, "An Empty command hmac is answered with an Empty response hmac — the same formulation in both directions (clause 16.6.16).");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The hierarchy family's response-hmac mirroring pin, on the multi-hop path <c>TPM2_Clear()</c> takes through the storage-proof
    /// seed draw before its response is framed: the same clause 16.6.16 arrangement — an unbound, unsalted
    /// session, the factory-empty <c>platformAuth</c>, an Empty supplied <c>hmac</c> — is answered with an Empty
    /// response <c>hmac</c> and a rolled nonceTPM, proving the emptiness test survives the hop through the seed
    /// draw rather than being lost when the command HMAC's carrier is released ahead of it.
    /// </summary>
    [TestMethod]
    public async Task ClearWithAnEmptyHmacOverAnUnboundSessionOnTheFactoryEmptyPlatformAuthIsAnsweredWithAnEmptyHmac()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartUnboundHmacSessionAsync(device, registry, pool).ConfigureAwait(false);
        try
        {
            (TpmRcConstants code, int nonceTpmSize, int responseHmacSize) = await SubmitSingleHandleCommandWithEmptyHmacAsync(
                simulator, pool, TpmCcConstants.TPM_CC_Clear, (uint)TpmRh.TPM_RH_PLATFORM, sessionHandle).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "An Empty hmac over an entirely empty HMAC key must authorize the command.");
            Assert.AreEqual(SHA256.HashSizeInBytes, nonceTpmSize, "The response entry must carry a rolled nonceTPM of the session hash's width.");
            Assert.AreEqual(0, responseHmacSize, "An Empty command hmac is answered with an Empty response hmac even across the storage-proof-seed hop (clause 16.6.16).");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Clause 5.5, step 4 is a single table: the four commands of <see cref="CompliantHierarchySlotCommand"/>
    /// answer a genuine POLICY session at the sole authorization slot the same
    /// bare <c>TPM_RC_AUTH_TYPE</c> this simulator uses for an authorization kind it does not implement, exactly
    /// as the other six commands in <see cref="HierarchySlotCommand"/> do.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4</see>.
    /// </summary>
    /// <param name="command">The already-compliant command under proof.</param>
    [TestMethod]
    [DataRow(CompliantHierarchySlotCommand.NvGlobalWriteLock)]
    [DataRow(CompliantHierarchySlotCommand.ClockSet)]
    [DataRow(CompliantHierarchySlotCommand.ClockRateAdjust)]
    [DataRow(CompliantHierarchySlotCommand.HierarchyChangeAuth)]
    public async Task PolicySessionCellIsInvariantAcrossTheCompliantHierarchyCommands(CompliantHierarchySlotCommand command)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint policyHandle = await StartPolicySessionAsync(device, registry, pool).ConfigureAwait(false);
        try
        {
            ITpmCommandInput input = BuildCompliantInput(command);
            try
            {
                TpmRcConstants code = await SubmitOverSlotAsync(device, pool, input, policyHandle).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_AUTH_TYPE, code,
                    $"{command}: a genuine POLICY session at the sole authorization slot must be refused with the bare TPM_RC_AUTH_TYPE.");
            }
            finally
            {
                (input as IDisposable)?.Dispose();
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Part 3 clause 5.4 item 2's persistent-object resolution is orthogonal to the slot table: every one of the
    /// six commands in <see cref="HierarchySlotCommand"/> authorizes a genuine HMAC session on the factory-empty
    /// <c>platformAuth</c>: "TPM2_Clear() ... requires
    /// Platform Authorization" (TPM 2.0 Library Part 3, clause 24.6.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 24.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ClearOverHmacSessionSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<ClearResponse> result = await ExecuteOverUnboundHmacSessionAsync<ClearResponse>(
            device, pool, registry, new ClearInput(TpmRh.TPM_RH_PLATFORM)).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"TPM2_Clear() over a real HMAC session succeeds on the factory-empty platformAuth: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// "TPM2_ClearControl() ... requires Platform Authorization or Lockout Authorization" (TPM 2.0 Library Part 3,
    /// clause 24.7.1) — the fixed slot resolution changes only cells (b) and (c); a genuine HMAC session on the
    /// factory-empty <c>platformAuth</c> still authorizes cell (a)'s complement.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 24.7.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ClearControlOverHmacSessionSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<ClearControlResponse> result = await ExecuteOverUnboundHmacSessionAsync<ClearControlResponse>(
            device, pool, registry, new ClearControlInput(TpmRh.TPM_RH_PLATFORM, TpmiYesNo.No)).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"TPM2_ClearControl() over a real HMAC session succeeds on the factory-empty platformAuth: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// "TPM2_HierarchyControl() ... requires Platform Authorization" (TPM 2.0 Library Part 3, clause 24.4.1) — a
    /// genuine HMAC session on the factory-empty <c>platformAuth</c> still authorizes the command once its slot
    /// resolves through the same table the signing family uses.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 24.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HierarchyControlOverHmacSessionSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<HierarchyControlResponse> result = await ExecuteOverUnboundHmacSessionAsync<HierarchyControlResponse>(
            device, pool, registry, new HierarchyControlInput(TpmRh.TPM_RH_PLATFORM, TpmRh.TPM_RH_OWNER, TpmiYesNo.No)).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyControl() over a real HMAC session succeeds on the factory-empty platformAuth: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// "TPM2_SetPrimaryPolicy() ... requires Platform Authorization, Owner Authorization, or Endorsement
    /// Authorization" (TPM 2.0 Library Part 3, clause 24.9.1) — a genuine HMAC session on the factory-empty
    /// <c>platformAuth</c> still authorizes the command once its slot resolves through the same table.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 24.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task SetPrimaryPolicyOverHmacSessionSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using var input = new SetPrimaryPolicyInput(TpmRh.TPM_RH_PLATFORM, Tpm2bDigest.Empty, TpmAlgIdConstants.TPM_ALG_NULL);
        TpmResult<SetPrimaryPolicyResponse> result = await ExecuteOverUnboundHmacSessionAsync<SetPrimaryPolicyResponse>(
            device, pool, registry, input).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"TPM2_SetPrimaryPolicy() over a real HMAC session succeeds on the factory-empty platformAuth: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Table 263... no — Table 208's <c>@authHandle</c> admits <c>TPM_RH_OWNER</c> or <c>TPM_RH_PLATFORM</c>: the
    /// platform arm over a genuine HMAC session on the factory-empty <c>platformAuth</c> still defines a fresh
    /// Index once <c>TPM2_NV_DefineSpace()</c>'s session arm resolves its slot through the shared table.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.3.1</see>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "auth and publicInfo transfer ownership into the returned NvDefineSpaceInput, which the local using on input disposes; both carriers dispose idempotently, matching the established TryDefineIndexAsync recipe this repository's other NV test classes already use.")]
    [TestMethod]
    public async Task NvDefineSpaceOverHmacSessionAtThePlatformArmSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using Tpm2bAuth auth = Tpm2bAuth.Create(IndexAuth, pool);
        using var publicInfo = new TpmsNvPublic(DefineSpacePlatformHappyIndexHandle, HmacSessionAlg, PlatformOrdinaryAttributes, Tpm2bDigest.Empty, OrdinaryDataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_PLATFORM, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> result = await ExecuteOverUnboundHmacSessionAsync<NvDefineSpaceResponse>(
            device, pool, registry, input).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace()'s platform arm over a real HMAC session succeeds on the factory-empty platformAuth: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// The platform-arm complement: "The Index will be removed whether the index was defined using Owner
    /// Authorization or Platform Authorization" (TPM 2.0 Library Part 3, clause 31.4.1's Note) — a genuine HMAC
    /// session on the factory-empty <c>platformAuth</c> still removes a platform-created Index once
    /// <c>TPM2_NV_UndefineSpace()</c>'s session arm resolves its slot through the shared table.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOverHmacSessionAtThePlatformArmSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, UndefineSpacePlatformHappyIndexHandle, PlatformOrdinaryAttributes, OrdinaryDataSize, IndexAuth).ConfigureAwait(false);

        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(UndefineSpacePlatformHappyIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(publicResult.IsSuccess, $"NvReadPublicAsync failed: '{publicResult.ResponseCode}'.");
        using NvReadPublicResponse indexPublic = publicResult.Value;
        byte[] indexName = indexPublic.NvName.Span.ToArray();

        TpmResult<NvUndefineSpaceResponse> result = await ExecuteOverUnboundHmacSessionAsync<NvUndefineSpaceResponse>(
            device, pool, registry, new NvUndefineSpaceInput(TpmRh.TPM_RH_PLATFORM, UndefineSpacePlatformHappyIndexHandle),
            [ReadOnlyMemory<byte>.Empty, indexName]).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_UndefineSpace()'s platform arm over a real HMAC session succeeds on the factory-empty platformAuth: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// The response-hmac mirroring pin extends past the Clear/NV_GlobalWriteLock cases to <c>TPM2_NV_Write()</c>: "If hmac was
    /// an Empty Buffer in the command, it will be an Empty Buffer in the response" — the owner arm (the only
    /// write arm this simulator models over an HMAC session) over
    /// the factory-empty <c>ownerAuth</c>, on an unbound session whose key is also Empty, accepts an Empty
    /// command hmac and answers with an Empty response hmac.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.16</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteWithAnEmptyHmacOverAnUnboundSessionOnTheFactoryEmptyOwnerAuthIsAnsweredWithAnEmptyHmac()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, NvWriteEmptyAuthIndexHandle, OrdinaryAttributes, OrdinaryDataSize, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        uint sessionHandle = await StartUnboundHmacSessionAsync(device, registry, pool).ConfigureAwait(false);
        try
        {
            using Tpm2bMaxNvBuffer data = Tpm2bMaxNvBuffer.Create(NvBufferPayload, pool);
            var input = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, NvWriteEmptyAuthIndexHandle, data, Offset: 0);

            (TpmRcConstants code, byte[] response) = await SubmitOverSlotWithEmptyHmacAsync(
                device, pool, input, sessionHandle, TpmaSession.CONTINUE_SESSION).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "An Empty hmac over an entirely empty HMAC key must authorize TPM2_NV_Write()'s owner arm on the factory-empty ownerAuth.");

            (int nonceTpmSize, int responseHmacSize) = ReadResponseSessionEntryWidths(response, outHandleCount: 0);
            Assert.AreEqual(Sha256DigestSize, nonceTpmSize, "The response entry must carry a rolled nonceTPM of the session hash's width.");
            Assert.AreEqual(0, responseHmacSize, "An Empty command hmac is answered with an Empty response hmac (clause 16.6.16), across the NV family's shared framer.");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The response-hmac mirroring pin on <c>TPM2_NV_Read()</c>: the same Empty-hmac-over-Empty-key shape answers an Empty response hmac even
    /// though the response also carries the read <c>data</c> parameter — clause 16.6.16's rule reads the SUPPLIED
    /// hmac, not the parameter area's shape.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.16</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadWithAnEmptyHmacOverAnUnboundSessionOnAnIndexWithAnEmptyAuthValueIsAnsweredWithAnEmptyHmac()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, NvReadEmptyAuthIndexHandle, OrdinaryAttributes, OrdinaryDataSize, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        uint writeSessionHandle = await StartUnboundHmacSessionAsync(device, registry, pool).ConfigureAwait(false);
        try
        {
            using Tpm2bMaxNvBuffer data = Tpm2bMaxNvBuffer.Create(NvBufferPayload, pool);
            var writeInput = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, NvReadEmptyAuthIndexHandle, data, Offset: 0);

            (TpmRcConstants writeCode, _) = await SubmitOverSlotWithEmptyHmacAsync(
                device, pool, writeInput, writeSessionHandle, TpmaSession.CONTINUE_SESSION).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, writeCode, "The setup write, over the owner arm (the only write arm this simulator models over an HMAC session), must succeed so the Index carries TPMA_NV_WRITTEN before the read is proven.");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, writeSessionHandle).ConfigureAwait(false);
        }

        uint readSessionHandle = await StartUnboundHmacSessionAsync(device, registry, pool).ConfigureAwait(false);
        try
        {
            var readInput = new NvReadInput(NvReadEmptyAuthIndexHandle, NvReadEmptyAuthIndexHandle, (ushort)NvBufferPayload.Length, Offset: 0);

            (TpmRcConstants code, byte[] response) = await SubmitOverSlotWithEmptyHmacAsync(
                device, pool, readInput, readSessionHandle, TpmaSession.CONTINUE_SESSION).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "An Empty hmac over an entirely empty HMAC key must authorize TPM2_NV_Read() on an Index with an Empty authValue.");

            (int nonceTpmSize, int responseHmacSize) = ReadResponseSessionEntryWidths(response, outHandleCount: 0);
            Assert.AreEqual(Sha256DigestSize, nonceTpmSize, "The response entry must carry a rolled nonceTPM of the session hash's width.");
            Assert.AreEqual(0, responseHmacSize, "An Empty command hmac is answered with an Empty response hmac (clause 16.6.16), even when the response carries the read data parameter.");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, readSessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The response-hmac mirroring pin on the two-hop path: <c>TPM2_NV_Extend()</c> frames its response only after
    /// a second hop (the extend itself runs between the command hmac's verification and the response's framing),
    /// and an Empty hmac over an Empty key still answers an Empty response hmac exactly as the single-hop commands
    /// do — the emptiness test survives the hop rather than being lost when the command hmac's own carrier is
    /// released ahead of it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.16</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendWithAnEmptyHmacOverAnUnboundSessionOnAnIndexWithAnEmptyAuthValueIsAnsweredWithAnEmptyHmac()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, NvExtendEmptyAuthIndexHandle, ExtendAttributes, (ushort)Sha256DigestSize, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        uint sessionHandle = await StartUnboundHmacSessionAsync(device, registry, pool).ConfigureAwait(false);
        try
        {
            using Tpm2bMaxNvBuffer data = Tpm2bMaxNvBuffer.Create(ExtendPayload, pool);
            var input = new NvExtendInput(NvExtendEmptyAuthIndexHandle, NvExtendEmptyAuthIndexHandle, data);

            (TpmRcConstants code, byte[] response) = await SubmitOverSlotWithEmptyHmacAsync(
                device, pool, input, sessionHandle, TpmaSession.CONTINUE_SESSION).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "An Empty hmac over an entirely empty HMAC key must authorize TPM2_NV_Extend() on an Index with an Empty authValue.");

            (int nonceTpmSize, int responseHmacSize) = ReadResponseSessionEntryWidths(response, outHandleCount: 0);
            Assert.AreEqual(Sha256DigestSize, nonceTpmSize, "The response entry must carry a rolled nonceTPM of the session hash's width.");
            Assert.AreEqual(0, responseHmacSize, "An Empty command hmac is answered with an Empty response hmac (clause 16.6.16), surviving the two-hop path's own carrier release.");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The response-hmac mirroring pin on the hierarchy family's other compliant command: an Empty hmac over an unbound session on the
    /// factory-empty <c>platformAuth</c> answers an Empty response hmac, exactly as the
    /// <c>TPM2_Clear()</c> case does on the multi-hop path — <c>TPM2_ClockSet()</c> takes the single-hop path.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.16</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockSetWithAnEmptyHmacOverAnUnboundSessionOnTheFactoryEmptyPlatformAuthIsAnsweredWithAnEmptyHmac()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartUnboundHmacSessionAsync(device, registry, pool).ConfigureAwait(false);
        try
        {
            var input = new ClockSetInput(TpmRh.TPM_RH_PLATFORM, NewTime: 1_000);

            (TpmRcConstants code, byte[] response) = await SubmitOverSlotWithEmptyHmacAsync(
                device, pool, input, sessionHandle, TpmaSession.CONTINUE_SESSION).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "An Empty hmac over an entirely empty HMAC key must authorize TPM2_ClockSet() on the factory-empty platformAuth.");

            (int nonceTpmSize, int responseHmacSize) = ReadResponseSessionEntryWidths(response, outHandleCount: 0);
            Assert.AreEqual(Sha256DigestSize, nonceTpmSize, "The response entry must carry a rolled nonceTPM of the session hash's width.");
            Assert.AreEqual(0, responseHmacSize, "An Empty command hmac is answered with an Empty response hmac (clause 16.6.16).");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Clause 16.6.16's other direction: "if hmac was non-zero in the command, the TPM will compute authHMAC as
    /// shown in Equation 17 and use the result as hmac" — a genuinely computed, non-Empty command hmac over an
    /// entirely empty key (RFC 2104's well-defined empty-key HMAC) still verifies normally, and the response hmac
    /// is answered in kind: a real, non-Empty digest, not collapsed to Empty merely because the key was empty.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.16</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockSetWithAGenuineHmacOverAnEntirelyEmptyKeyIsAnsweredWithAComputedResponseHmac()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        const ulong NewTime = 1_000;
        var input = new ClockSetInput(TpmRh.TPM_RH_PLATFORM, NewTime);

        (TpmRcConstants code, byte[] response, _) = await SubmitOverGenuineHmacSessionHandFramedAsync(
            device, pool, registry, input, TpmRh.TPM_RH_PLATFORM, UInt64Bytes(NewTime), extraAttributes: default, flushSessionAfterSubmit: true).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "A genuinely computed authHMAC over an entirely empty key must still verify normally.");

        (int nonceTpmSize, int responseHmacSize) = ReadResponseSessionEntryWidths(response, outHandleCount: 0);
        Assert.AreEqual(Sha256DigestSize, nonceTpmSize, "The response entry must carry a rolled nonceTPM of the session hash's width.");
        Assert.AreEqual(Sha256DigestSize, responseHmacSize, "Clause 16.6.16 mirrors the command's own formulation: a non-Empty supplied hmac is answered with a genuinely computed, non-Empty response hmac.");
    }

    /// <summary>
    /// The command-side rule the response mirroring never relaxes: the Empty-hmac allowance requires the HMAC
    /// key — session key AND authValue together — to be entirely empty; an Index carrying a REAL authValue falls
    /// through to the ordinary compare, which an Empty supplied hmac can never satisfy, so the command is refused
    /// rather than silently authorized.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.16</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadWithAnEmptyHmacOverAnIndexWithARealAuthValueIsRefused()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, NonEmptyAuthValueIndexHandle, OrdinaryAttributes | TpmaNv.TPMA_NV_NO_DA, OrdinaryDataSize, NonEmptyAuthValue).ConfigureAwait(false);

        using TpmPasswordSession writeSession = TpmPasswordSession.Create(NonEmptyAuthValue, pool);
        using Tpm2bMaxNvBuffer setupData = Tpm2bMaxNvBuffer.Create(NvBufferPayload, pool);
        var setupWriteInput = new NvWriteInput(NonEmptyAuthValueIndexHandle, NonEmptyAuthValueIndexHandle, setupData, Offset: 0);
        TpmResult<NvWriteResponse> setupResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, setupWriteInput, [writeSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(setupResult.IsSuccess, $"The setup write over a password session (the Index's own real authValue) must succeed so the Index carries TPMA_NV_WRITTEN before the read is proven: '{setupResult.ResponseCode}'.");

        uint sessionHandle = await StartUnboundHmacSessionAsync(device, registry, pool).ConfigureAwait(false);
        try
        {
            var input = new NvReadInput(NonEmptyAuthValueIndexHandle, NonEmptyAuthValueIndexHandle, (ushort)NvBufferPayload.Length, Offset: 0);

            (TpmRcConstants code, _) = await SubmitOverSlotWithEmptyHmacAsync(
                device, pool, input, sessionHandle, TpmaSession.CONTINUE_SESSION).ConfigureAwait(false);

            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
                "An Empty supplied hmac over a session whose key is empty but whose authorized Index carries a real authValue cannot satisfy the ordinary compare, so a dictionary-attack-exempt Index answers the session-encoded, uncharged TPM_RC_BAD_AUTH.");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "the audit digest is extended" (TPM 2.0 Library Part 1, clause 17.1, equation 30) is unconditional on
    /// whether the command hmac itself was Empty: an audit-claiming session with an Empty hmac over an entirely
    /// empty key still authorizes the command, the response hmac stays Empty (clause 16.6.16), AND the session's
    /// audit digest still extends to <c>H(0…0 ‖ cpHash ‖ rpHash)</c> — read back through
    /// <c>TPM2_GetSessionAuditDigest()</c> with the NULL signer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockSetOverAnAuditClaimingSessionWithAnEmptyHmacOverAnEmptyKeyStillExtendsTheAuditDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        uint sessionHandle = await StartUnboundHmacSessionAsync(device, registry, pool).ConfigureAwait(false);
        try
        {
            const ulong NewTime = 2_000;
            var input = new ClockSetInput(TpmRh.TPM_RH_PLATFORM, NewTime);

            (TpmRcConstants code, byte[] response) = await SubmitOverSlotWithEmptyHmacAsync(
                device, pool, input, sessionHandle, TpmaSession.AUDIT | TpmaSession.CONTINUE_SESSION).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "An audit-claiming session with an Empty hmac over an entirely empty key must still authorize the command.");

            (int nonceTpmSize, int responseHmacSize) = ReadResponseSessionEntryWidths(response, outHandleCount: 0);
            Assert.AreEqual(0, responseHmacSize, "The response hmac stays Empty (clause 16.6.16) even while the session simultaneously extends its audit digest.");
            Assert.AreEqual(Sha256DigestSize, nonceTpmSize, "The response entry must carry a rolled nonceTPM of the session hash's width.");

            byte[] cpHash = await ComputeCpHashAsync(TpmCcConstants.TPM_CC_ClockSet, HandleNameBytes(TpmRh.TPM_RH_PLATFORM), UInt64Bytes(NewTime), pool).ConfigureAwait(false);
            byte[] responseParameters = ReadResponseParameters(response, outHandleCount: 0);
            byte[] rpHash = await ComputeRpHashAsync(TpmCcConstants.TPM_CC_ClockSet, responseParameters, pool).ConfigureAwait(false);
            byte[] expectedDigest = await ExtendAuditDigestAsync(priorDigest: null, cpHash, rpHash, pool).ConfigureAwait(false);

            using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(sessionHandle), ReadOnlySpan<byte>.Empty, pool);
            using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            using GetSessionAuditDigestResponse? auditDigestResponse = digestResult.IsSuccess ? digestResult.Value : null;

            Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() over the freshly audited session must succeed: '{digestResult.ResponseCode}'.");
            Assert.IsTrue(
                expectedDigest.AsSpan().SequenceEqual(auditDigestResponse!.SessionAudit.SessionDigest.AsReadOnlySpan()),
                "The session's audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) chained from this ClockSet exchange's own wire octets, even though the response hmac itself stayed Empty.");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_NV_ChangeAuth()</c> carries two authorization slots: "If successful, the authorization secret
    /// (authValue) of the NV Index associated with nvIndex is changed" (TPM 2.0 Library Part 3, clause 31.15.1) —
    /// the ADMIN-role policy slot and the platform password slot each receive their response entry, and the
    /// rotation succeeds end to end through the production <c>ChangePinAsync</c> verb.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.15.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvChangeAuthOverTheTwoSlotFramerRotatesTheIndexAuthValue()
    {
        const uint PinLimit = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<NvWriteResponse> defineResult = await device.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, NvChangeAuthHappyIndexHandle, IndexAuth, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");

        TpmResult<NvChangeAuthResponse> rotationResult = await device.ChangePinAsync(
            NvChangeAuthHappyIndexHandle, IndexAuth, NonEmptyAuthValue, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            rotationResult.IsSuccess,
            $"TPM2_NV_ChangeAuth() over the renamed two-slot framer must still rotate the Index authValue end to end: '{rotationResult.ResponseCode}'.");
    }

    /// <summary>
    /// <c>TPM2_HierarchyChangeAuth()</c> over its two slots: "the authorization secret (authValue) associated with
    /// hierarchy authHandle is changed" (TPM 2.0 Library Part 3, clause 24.8.1) — a single real HMAC session at
    /// slot 0, no decrypt companion at slot 1, rotates a hierarchy's authValue.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 24.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HierarchyChangeAuthOverTheTwoSlotFramerRotatesTheHierarchyAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using var input = new HierarchyChangeAuthInput(TpmRh.TPM_RH_ENDORSEMENT, Tpm2bAuth.Empty);
        TpmResult<HierarchyChangeAuthResponse> result = await ExecuteOverUnboundHmacSessionAsync<HierarchyChangeAuthResponse>(
            device, pool, registry, input).ConfigureAwait(false);

        Assert.IsTrue(
            result.IsSuccess,
            $"TPM2_HierarchyChangeAuth() over the renamed two-slot framer, authorized by a single real HMAC session, must still rotate the hierarchy authValue: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// The metered-pool complement of the three-cell table and the empty-hmac success path: every carrier a
    /// parse rents — the always-empty raw parameter area and the authorization slot's own nonce and hmac
    /// credentials — is released whichever of the three refusal cells is hit, and the accepting continuation and
    /// response framing between them release theirs too.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4; Part 1, clause 16.6.16</see>.
    /// </summary>
    [TestMethod]
    public async Task HierarchySlotTableReturnsItsCarriersAcrossEveryRefusalCellAndAnEmptyHmacSuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        uint unloadedHandle = await StartAndFlushHmacSessionAsync(device, pool, registry).ConfigureAwait(false);
        ITpmCommandInput unloadedInput = await BuildInputAsync(device, pool, registry, HierarchySlotCommand.Clear).ConfigureAwait(false);
        try
        {
            TpmRcConstants code = await SubmitOverSlotAsync(device, pool, unloadedInput, unloadedHandle).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_S0, code, "The unloaded-HMAC-handle cell must still answer TPM_RC_REFERENCE_S0.");
        }
        finally
        {
            (unloadedInput as IDisposable)?.Dispose();
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The unloaded-handle refusal cell releases every carrier its parse rented.");

        uint policyHandle = await StartPolicySessionAsync(device, registry, pool).ConfigureAwait(false);
        try
        {
            ITpmCommandInput policyInput = await BuildInputAsync(device, pool, registry, HierarchySlotCommand.Clear).ConfigureAwait(false);
            try
            {
                TpmRcConstants code = await SubmitOverSlotAsync(device, pool, policyInput, policyHandle).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_TYPE, code, "The loaded-policy-session cell must still answer the bare TPM_RC_AUTH_TYPE.");
            }
            finally
            {
                (policyInput as IDisposable)?.Dispose();
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The loaded-policy-session refusal cell releases every carrier its parse rented.");

        const uint NonSessionHandle = 0x8000_0000;
        ITpmCommandInput nonSessionInput = await BuildInputAsync(device, pool, registry, HierarchySlotCommand.Clear).ConfigureAwait(false);
        try
        {
            TpmRcConstants code = await SubmitOverSlotAsync(device, pool, nonSessionInput, NonSessionHandle).ConfigureAwait(false);
            Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 0), code, "The non-session-handle-type cell must still answer the session-encoded TPM_RC_HANDLE.");
        }
        finally
        {
            (nonSessionInput as IDisposable)?.Dispose();
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The non-session-handle-type refusal cell releases every carrier its parse rented.");

        uint successHandle = await StartUnboundHmacSessionAsync(device, registry, pool).ConfigureAwait(false);
        try
        {
            var successInput = new NvGlobalWriteLockInput(TpmRh.TPM_RH_OWNER);
            (TpmRcConstants code, _) = await SubmitOverSlotWithEmptyHmacAsync(device, pool, successInput, successHandle, TpmaSession.CONTINUE_SESSION).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "The empty-hmac success case must still succeed under the pool meter.");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, successHandle).ConfigureAwait(false);
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The empty-hmac success path releases every carrier the completing continuation and the response framing between them rented.");
    }

    /// <summary>Builds the <see cref="ITpmCommandInput"/> for one of the four already-compliant commands' invariance case.</summary>
    /// <param name="command">The command to build an input for.</param>
    /// <returns>The command input; disposed by the caller when it implements <see cref="IDisposable"/>.</returns>
    private static ITpmCommandInput BuildCompliantInput(CompliantHierarchySlotCommand command) =>
        command switch
        {
            CompliantHierarchySlotCommand.NvGlobalWriteLock => new NvGlobalWriteLockInput(TpmRh.TPM_RH_OWNER),
            CompliantHierarchySlotCommand.ClockSet => new ClockSetInput(TpmRh.TPM_RH_PLATFORM, NewTime: 0),
            CompliantHierarchySlotCommand.ClockRateAdjust => new ClockRateAdjustInput(TpmRh.TPM_RH_PLATFORM, TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE),
            CompliantHierarchySlotCommand.HierarchyChangeAuth => new HierarchyChangeAuthInput(TpmRh.TPM_RH_PLATFORM, Tpm2bAuth.Empty),
            _ => throw new NotSupportedException($"No input builder is defined for '{command}'.")
        };

    /// <summary>Starts a fresh unbound, unsalted HMAC session and executes <paramref name="input"/> over it through the production executor, flushing the session afterward.</summary>
    /// <typeparam name="TResponse">The command's response wire type.</typeparam>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="input">The command input.</param>
    /// <returns>The command's result.</returns>
    private async Task<TpmResult<TResponse>> ExecuteOverUnboundHmacSessionAsync<TResponse>(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, ITpmCommandInput input,
        IReadOnlyList<ReadOnlyMemory<byte>>? handleNames = null)
        where TResponse : ITpmWireType
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;
        try
        {
            using var session = new TpmSession(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);

            return await TpmCommandExecutor.ExecuteAsync<TResponse>(
                device, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>Defines an NV Index under <paramref name="authHandle"/> carrying <paramref name="authValue"/> and asserts the definition succeeded.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The hierarchy authorizing the definition.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's <c>TPMA_NV</c> attributes.</param>
    /// <param name="dataSize">The declared data area size.</param>
    /// <param name="authValue">The Index authorization value to define with.</param>
    private async Task DefineIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh authHandle, uint nvIndex, TpmaNv attributes, ushort dataSize, ReadOnlyMemory<byte> authValue)
    {
        using TpmPasswordSession hierarchySession = TpmPasswordSession.CreateEmpty(pool);
        using var auth = Tpm2bAuth.Create(authValue.Span, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, HmacSessionAlg, attributes, Tpm2bDigest.Empty, dataSize);
        using var input = new NvDefineSpaceInput(authHandle, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [hierarchySession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace(0x{nvIndex:X8}) under '{authHandle}' failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Frames <paramref name="input"/> exactly as <see cref="SubmitOverSlotAsync"/> does — one authorization slot
    /// naming <paramref name="slotSessionHandle"/> and an Empty <c>nonceCaller</c> — but with a caller-chosen
    /// <paramref name="attributes"/> octet and an Empty <c>hmac</c>, returning the raw response octets so the
    /// caller can read whatever the response carries: its session entry's widths, or its parameter area and
    /// session attributes (the audit chain).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The command's handle and parameter area.</param>
    /// <param name="slotSessionHandle">The wire value written into the sole authorization slot.</param>
    /// <param name="attributes">The wire's <c>sessionAttributes</c> octet.</param>
    /// <returns>The raw response code and the raw response octets.</returns>
    private async Task<(TpmRcConstants Code, byte[] ResponseBytes)> SubmitOverSlotWithEmptyHmacAsync(
        TpmDevice device, BaseMemoryPool pool, ITpmCommandInput input, uint slotSessionHandle, TpmaSession attributes)
    {
        const int AuthEntrySize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        int totalSize = TpmHeader.HeaderSize + input.GetSerializedSize() + sizeof(uint) + AuthEntrySize;

        using IMemoryOwner<byte> owner = pool.Rent(totalSize);
        Memory<byte> command = owner.Memory[..totalSize];
        var writer = new TpmWriter(command.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)totalSize, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        writer.WriteUInt32(AuthEntrySize);
        writer.WriteUInt32(slotSessionHandle);
        writer.WriteUInt16(0);
        writer.WriteByte((byte)attributes);
        writer.WriteUInt16(0);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await device.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The transport itself must succeed even when the TPM refuses the command.");

        using TpmResponse response = result.Value;
        byte[] responseBytes = response.AsReadOnlySpan().ToArray();
        var reader = new TpmReader(responseBytes);
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return ((TpmRcConstants)responseHeader.Code, responseBytes);
    }

    /// <summary>
    /// Starts a fresh unbound, unsalted HMAC session, computes a genuine command hmac over
    /// <paramref name="cpHashNameHandle"/>'s Name and <paramref name="cpHashParameterBytes"/>, and submits
    /// <paramref name="input"/> hand-framed with that real authorization — the negative twin of
    /// <see cref="SubmitOverSlotWithEmptyHmacAsync"/>, proving clause 16.6.16's OTHER direction.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="input">The command's handle and parameter area — this file's one genuine-hmac hand-framer only ever drives <c>TPM2_ClockSet()</c>, so the parameter is concretely typed rather than through <see cref="ITpmCommandInput"/>.</param>
    /// <param name="cpHashNameHandle">The permanent handle whose own four octets fold into cpHash's Name term.</param>
    /// <param name="cpHashParameterBytes">The command's parameter octets, as cpHash's own parameters term.</param>
    /// <param name="extraAttributes">Extra <c>sessionAttributes</c> bits beyond <c>continueSession</c>, which is always set.</param>
    /// <param name="flushSessionAfterSubmit">Whether the session is flushed once the response has been read.</param>
    /// <returns>The raw response code, the raw response octets, and the session handle.</returns>
    private async Task<(TpmRcConstants Code, byte[] ResponseBytes, uint SessionHandle)> SubmitOverGenuineHmacSessionHandFramedAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, ClockSetInput input,
        TpmRh cpHashNameHandle, ReadOnlyMemory<byte> cpHashParameterBytes, TpmaSession extraAttributes, bool flushSessionAfterSubmit)
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
            session.SessionAttributes |= (TpmaSession.CONTINUE_SESSION | extraAttributes);

            byte[] cpHash = await ComputeCpHashAsync(input.CommandCode, HandleNameBytes(cpHashNameHandle), cpHashParameterBytes, pool).ConfigureAwait(false);

            session.RollNonceCaller(pool);
            using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(cpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);

            int authAreaSize = session.GetAuthCommandSize();
            int totalSize = TpmHeader.HeaderSize + input.GetSerializedSize() + sizeof(uint) + authAreaSize;

            using IMemoryOwner<byte> commandOwner = pool.Rent(totalSize);
            Memory<byte> command = commandOwner.Memory[..totalSize];
            var writer = new TpmWriter(command.Span);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)totalSize, (uint)input.CommandCode);
            header.WriteTo(ref writer);
            input.WriteHandles(ref writer);
            writer.WriteUInt32((uint)authAreaSize);
            session.WriteAuthCommand(ref writer, hmac);
            input.WriteParameters(ref writer);

            TpmResult<TpmResponse> transportResult = await device.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(transportResult.IsSuccess, "The transport itself must succeed even when the TPM refuses the command.");

            using TpmResponse response = transportResult.Value;
            byte[] responseBytes = response.AsReadOnlySpan().ToArray();
            var responseReader = new TpmReader(responseBytes);
            TpmHeader responseHeader = TpmHeader.Parse(ref responseReader);

            return ((TpmRcConstants)responseHeader.Code, responseBytes, sessionHandle);
        }
        finally
        {
            if(flushSessionAfterSubmit)
            {
                await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
            }
        }
    }

    /// <summary>Reads a captured raw response's sole session entry widths — <c>nonceTPM</c> and <c>hmac</c> — for a response with no output handles and no output parameters this file cares to inspect.</summary>
    /// <param name="responseBytes">The raw response octets.</param>
    /// <param name="outHandleCount">The number of output handles preceding the parameter area.</param>
    /// <returns>The entry's <c>nonceTPM</c> and <c>hmac</c> wire widths.</returns>
    private static (int NonceTpmSize, int ResponseHmacSize) ReadResponseSessionEntryWidths(byte[] responseBytes, int outHandleCount)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < outHandleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint parameterSize = reader.ReadUInt32();
        _ = reader.ReadBytes((int)parameterSize);
        ushort nonceTpmSize = reader.ReadUInt16();
        _ = reader.ReadBytes(nonceTpmSize);
        _ = reader.ReadByte();
        ushort responseHmacSize = reader.ReadUInt16();

        return (nonceTpmSize, responseHmacSize);
    }

    /// <summary>Reads the response parameter area out of a captured raw response's octets — the bytes rpHash is computed over, as actually returned on the wire.</summary>
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

    /// <summary>Computes <c>cpHash = H(commandCode ‖ nameBytes ‖ parameterBytes)</c> (TPM 2.0 Library Part 1, clause 15.7, equation 15) through the project's own digest primitive.</summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="nameBytes">The concatenated Name terms of every authorized handle, in handle order.</param>
    /// <param name="parameterBytes">The command's own parameter octets.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The cpHash octets.</returns>
    private async Task<byte[]> ComputeCpHashAsync(TpmCcConstants commandCode, ReadOnlyMemory<byte> nameBytes, ReadOnlyMemory<byte> parameterBytes, BaseMemoryPool pool)
    {
        byte[] input = new byte[sizeof(uint) + nameBytes.Length + parameterBytes.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, (uint)commandCode);
        nameBytes.Span.CopyTo(input.AsSpan(sizeof(uint)));
        parameterBytes.Span.CopyTo(input.AsSpan(sizeof(uint) + nameBytes.Length));

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>Computes <c>rpHash = H(TPM_RC_SUCCESS ‖ commandCode ‖ parameters)</c> (TPM 2.0 Library Part 1, clause 15.8, equation 16) over the response parameter octets as actually read off the wire.</summary>
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

    /// <summary>Extends an audit session digest by one round: <c>H(old ‖ cpHash ‖ rpHash)</c>, with the Zero Digest standing in for <paramref name="priorDigest"/> on first use (TPM 2.0 Library Part 1, clause 17.1, equation 30).</summary>
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

    /// <summary>Writes a permanent handle's own four octets — its Name, per TPM 2.0 Library Part 1, clause 13, Table 9.</summary>
    /// <param name="handle">The permanent handle.</param>
    /// <returns>The handle's big-endian four octets.</returns>
    private static byte[] HandleNameBytes(TpmRh handle)
    {
        byte[] bytes = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, (uint)handle);

        return bytes;
    }

    /// <summary>Writes a <c>UINT64</c> parameter's big-endian octets, matching <see cref="TpmWriter.WriteUInt64(ulong)"/>'s own wire form.</summary>
    /// <param name="value">The value to write.</param>
    /// <returns>The value's big-endian eight octets.</returns>
    private static byte[] UInt64Bytes(ulong value)
    {
        byte[] bytes = new byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);

        return bytes;
    }

    /// <summary>Builds the digest <see cref="Tag"/> used to independently compute cpHash/rpHash/the audit chain: SHA-256, raw encoding, direct material — the same shape the production hmac/digest computation uses.</summary>
    /// <returns>The digest tag.</returns>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    /// <summary>Creates a response codec registry for every command these tests drive.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_Clear, TpmResponseCodec.Clear)
            .Register(TpmCcConstants.TPM_CC_ClearControl, TpmResponseCodec.ClearControl)
            .Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl)
            .Register(TpmCcConstants.TPM_CC_SetPrimaryPolicy, TpmResponseCodec.SetPrimaryPolicy)
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_GlobalWriteLock, TpmResponseCodec.NvGlobalWriteLock)
            .Register(TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmResponseCodec.HierarchyChangeAuth)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>
    /// Builds the <see cref="ITpmCommandInput"/> the named command's slot-table cases share, valid enough to
    /// parse and reach authorization but never actually completing (every case in this file is refused at the
    /// authorization slot, before the command's own body runs). <c>TPM2_NV_UndefineSpace()</c> resolves its
    /// Index's existence BEFORE the authorization slot (clause 5.4 precedes clause 5.5), so its case defines
    /// <see cref="UndefineSpaceIndexHandle"/> for real over a password session first.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="command">The command to build an input for.</param>
    /// <returns>The command input; disposed by the caller when it implements <see cref="IDisposable"/>.</returns>
    private async Task<ITpmCommandInput> BuildInputAsync(TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, HierarchySlotCommand command) =>
        command switch
        {
            HierarchySlotCommand.Clear => new ClearInput(TpmRh.TPM_RH_PLATFORM),
            HierarchySlotCommand.ClearControl => new ClearControlInput(TpmRh.TPM_RH_PLATFORM, TpmiYesNo.No),
            HierarchySlotCommand.HierarchyControl => new HierarchyControlInput(TpmRh.TPM_RH_PLATFORM, TpmRh.TPM_RH_OWNER, TpmiYesNo.No),
            HierarchySlotCommand.SetPrimaryPolicy => new SetPrimaryPolicyInput(TpmRh.TPM_RH_PLATFORM, Tpm2bDigest.Empty, HmacSessionAlg),
            HierarchySlotCommand.NvDefineSpace => BuildNvDefineSpaceInput(pool),
            HierarchySlotCommand.NvUndefineSpace => await BuildNvUndefineSpaceInputAsync(device, pool, registry).ConfigureAwait(false),
            _ => throw new NotSupportedException($"No input builder is defined for '{command}'.")
        };

    /// <summary>Builds the <c>TPM2_NV_DefineSpace()</c> input <see cref="BuildInputAsync"/> shares for its slot-table case.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The input; the returned <see cref="NvDefineSpaceInput"/> owns the auth and publicInfo carriers and disposes them.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The auth and publicInfo carriers transfer to the returned NvDefineSpaceInput, which disposes them; the caller disposes the returned input itself.")]
    private static NvDefineSpaceInput BuildNvDefineSpaceInput(BaseMemoryPool pool)
    {
        Tpm2bAuth auth = Tpm2bAuth.Create(IndexAuth, pool);
        var publicInfo = new TpmsNvPublic(DefineSpaceIndexHandle, HmacSessionAlg, OrdinaryAttributes, Tpm2bDigest.Empty, OrdinaryDataSize);

        return new NvDefineSpaceInput(TpmRh.TPM_RH_PLATFORM, auth, publicInfo);
    }

    /// <summary>Defines <see cref="UndefineSpaceIndexHandle"/> for real, then builds the <c>TPM2_NV_UndefineSpace()</c> input <see cref="BuildInputAsync"/> shares for its slot-table case.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <returns>The input.</returns>
    private async Task<ITpmCommandInput> BuildNvUndefineSpaceInputAsync(TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry)
    {
        await DefineOrdinaryIndexAsync(device, pool, registry, UndefineSpaceIndexHandle).ConfigureAwait(false);

        return new NvUndefineSpaceInput(TpmRh.TPM_RH_PLATFORM, UndefineSpaceIndexHandle);
    }

    /// <summary>Defines an Ordinary Index under Owner Authorization over a password session, for a case that needs a real Index to name.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    private async Task DefineOrdinaryIndexAsync(TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth auth = Tpm2bAuth.Create(IndexAuth, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, HmacSessionAlg, OrdinaryAttributes, Tpm2bDigest.Empty, OrdinaryDataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace(0x{nvIndex:X8}) failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Frames <paramref name="input"/> by hand with ONE authorization slot naming <paramref name="slotSessionHandle"/>,
    /// an Empty <c>nonceCaller</c> and an Empty <c>hmac</c> — sufficient to reach the authorization slot's
    /// resolution, which every case in this file refuses before either field is ever read — and returns the raw
    /// response code.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The command's handle and parameter area.</param>
    /// <param name="slotSessionHandle">The wire value written into the sole authorization slot.</param>
    /// <returns>The raw response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> SubmitOverSlotAsync(TpmDevice device, BaseMemoryPool pool, ITpmCommandInput input, uint slotSessionHandle)
    {
        const int AuthEntrySize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        int totalSize = TpmHeader.HeaderSize + input.GetSerializedSize() + sizeof(uint) + AuthEntrySize;

        using IMemoryOwner<byte> owner = pool.Rent(totalSize);
        Memory<byte> command = owner.Memory[..totalSize];
        var writer = new TpmWriter(command.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)totalSize, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        writer.WriteUInt32(AuthEntrySize);
        writer.WriteUInt32(slotSessionHandle);
        writer.WriteUInt16(0);
        writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
        writer.WriteUInt16(0);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await device.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The transport itself must succeed even when the TPM refuses the command.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>
    /// Frames a raw, single-handle, zero-response-parameter command (<c>TPM2_NV_GlobalWriteLock()</c> or
    /// <c>TPM2_Clear()</c>, the two shapes the response-hmac mirroring cases use) authorized by ONE real session whose <c>nonceCaller</c>
    /// and <c>hmac</c> are both the Empty Buffer, submits it, and reads the response's code and — on success —
    /// its single session entry's nonceTPM and hmac widths (TPM 2.0 Library Part 1, clause 15.6.1; Part 2, clause
    /// 10.12.3, Table 157).
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="commandCode">The command to frame — must take exactly one handle and own no response parameters.</param>
    /// <param name="authHandle">The single handle, written into the handle area.</param>
    /// <param name="sessionHandle">The authorizing HMAC session.</param>
    /// <returns>The response code and, on success, the entry's nonceTPM and hmac sizes (zero otherwise).</returns>
    private async Task<(TpmRcConstants Code, int NonceTpmSize, int ResponseHmacSize)> SubmitSingleHandleCommandWithEmptyHmacAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmCcConstants commandCode, uint authHandle, uint sessionHandle)
    {
        const int AuthEntrySize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        int commandSize = TpmHeader.HeaderSize + sizeof(uint) + sizeof(uint) + AuthEntrySize;

        using IMemoryOwner<byte> owner = pool.Rent(commandSize);
        Memory<byte> command = owner.Memory[..commandSize];
        var writer = new TpmWriter(command.Span);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
        writer.WriteUInt32((uint)commandSize);
        writer.WriteUInt32((uint)commandCode);
        writer.WriteUInt32(authHandle);
        writer.WriteUInt32(AuthEntrySize);
        writer.WriteUInt32(sessionHandle);
        writer.WriteUInt16(0);
        writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
        writer.WriteUInt16(0);

        TpmResult<TpmResponse> submitted = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitted.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitted.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader header = TpmHeader.Parse(ref reader);
        var code = (TpmRcConstants)header.Code;
        if(code != TpmRcConstants.TPM_RC_SUCCESS)
        {
            return (code, 0, 0);
        }

        _ = reader.ReadUInt32();
        ushort nonceTpmSize = reader.ReadUInt16();
        _ = reader.ReadBytes(nonceTpmSize);
        _ = reader.ReadByte();
        ushort responseHmacSize = reader.ReadUInt16();

        return (code, nonceTpmSize, responseHmacSize);
    }

    /// <summary>Starts an unbound, unsalted HMAC session, then flushes it, returning its now-unloaded handle.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <returns>A session-shaped handle that names no loaded session.</returns>
    private async Task<uint> StartAndFlushHmacSessionAsync(TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry)
    {
        uint sessionHandle = await StartUnboundHmacSessionAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext failed: '{flushResult.ResponseCode}'.");

        return sessionHandle;
    }

    /// <summary>Starts an unbound, unsalted HMAC session (TPM 2.0 Library Part 1, clause 16.6.9) and returns its handle.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The started session's handle.</returns>
    private async Task<uint> StartUnboundHmacSessionAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse started = startResult.Value;

        return started.SessionHandle.Value;
    }

    /// <summary>Starts a policy session (TPM 2.0 Library Part 3, clause 23.3) and returns its loaded handle.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The started policy session's handle.</returns>
    private async Task<uint> StartPolicySessionAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        TpmResult<StartAuthSessionResponse> policyStartResult = await device.StartPolicySessionAsync(HmacSessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");

        using StartAuthSessionResponse policyStarted = policyStartResult.Value;

        return policyStarted.SessionHandle.Value;
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
    /// Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational
    /// phase every command in this file requires.
    /// </summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator("tpm-in-house-hierarchy-slot-table", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitStartupAsync(simulator, BaseMemoryPool.Shared, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
