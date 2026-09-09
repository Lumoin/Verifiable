using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Hierarchy;
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
/// Drives <c>TPM2_NV_UndefineSpaceSpecial()</c> - the removal of a platform-created NV Index carrying
/// <c>TPMA_NV_POLICY_DELETE</c> - against the in-house behavioural <see cref="TpmSimulator"/>, entirely
/// in-process with no external assets, through the same production command path production code uses
/// (<see cref="TpmCommandExecutor"/> and the real command/response codecs). The focus is the command's ADMIN
/// slot (<c>@nvIndex</c>, which admits a policy session and nothing else) and the effect a satisfied policy
/// buys: the Index leaves the TPM, its handle frees, and a written Counter's value retires into the phantom
/// high-water mark.
/// </summary>
/// <remarks>
/// <para>
/// <b>Two authorizations, two roles.</b> The command carries two handles, each decorated: <c>@nvIndex</c> at
/// Auth Index 1 with Auth Role ADMIN, and <c>@platform</c> at Auth Index 2 with Auth Role USER. ADMIN role on
/// an NV Index has no authValue path - "If the entity being authorized is an NV Index, then the associated
/// authorization session is a policy session" - so slot 0 is a policy session whose <c>commandCode</c> names
/// this command, while slot 1 is an ordinary password or HMAC authorization of the platform hierarchy.
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
/// clauses 31.5 and 5.6; Part 1, clause 34.2.3</see>.
/// </para>
/// <para>
/// <b>The response key.</b> The deletion is committed before the response is framed, so there is no Index
/// authValue left to key the policy slot's response HMAC on: "Since the index is deleted, the Empty Buffer is
/// used as the authValue when generating the response HMAC". That holds even when the policy asserted
/// <c>TPM2_PolicyAuthValue()</c> and the COMMAND HMAC therefore folded the Index authValue - the two directions
/// are keyed differently, which is what the response-keying test transcribes off the wire.
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
/// clause 31.5.1; Part 1, clause 16.6.10</see>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorNvUndefineSpaceSpecialTests
{
    /// <summary>The session, policy and Name hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The SHA-256 digest width in octets.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The declared data size of every Ordinary Index this file defines.</summary>
    private const ushort OrdinaryDataSize = 16;

    /// <summary>The declared data size of a Counter Index: the whole 8-octet counter word (TPM 2.0 Library Part 2, clause 13.4).</summary>
    private const ushort CounterDataSize = 8;

    /// <summary>The declared data size of a <c>TPM_NT_PIN_FAIL</c> Index: the whole 8-octet <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c>.</summary>
    private const ushort PinCounterParametersSize = 8;

    /// <summary>The platform-created, policy-delete Index every deletion case here targets.</summary>
    private const uint PolicyDeleteIndexHandle = 0x0100_00F0;

    /// <summary>A second platform-created, policy-delete Index, defined with a DIFFERENT policy so a satisfied session can be offered to the wrong Index.</summary>
    private const uint SecondPolicyDeleteIndexHandle = 0x0100_00F1;

    /// <summary>The platform-created, policy-delete Counter Index whose retired value the high-water mark must carry.</summary>
    private const uint CounterIndexHandle = 0x0100_00F2;

    /// <summary>The platform-created, policy-delete Index defined with an Empty Policy - the permanently undeletable Index.</summary>
    private const uint EmptyPolicyIndexHandle = 0x0100_00F3;

    /// <summary>An owner-created ordinary Index carrying a satisfiable deletion policy, for the attribute gate.</summary>
    private const uint OwnerCreatedIndexHandle = 0x0100_00F4;

    /// <summary>A platform-created Index WITHOUT <c>TPMA_NV_POLICY_DELETE</c>, carrying a satisfiable deletion policy, for the attribute gate.</summary>
    private const uint PlatformOnlyIndexHandle = 0x0100_00F5;

    /// <summary>A handle in the NV Index range that is never defined.</summary>
    private const uint UndefinedIndexHandle = 0x0100_00F6;

    /// <summary>The platform-created, policy-delete <c>TPM_NT_PIN_FAIL</c> Index the throttle cases target.</summary>
    private const uint PinIndexHandle = 0x0100_00F7;

    /// <summary>The owner-created Index the shEnable-CLEARed accessibility case targets.</summary>
    private const uint ShEnableClearedIndexHandle = 0x0100_00F8;

    /// <summary>The Index authorization value every Index this file defines carries.</summary>
    private static byte[] IndexAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong authorization value, distinct from every value these tests install.</summary>
    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>The authorization value a redefined Index carries in place of <see cref="IndexAuth"/>, for the bind-recomputation case.</summary>
    private static byte[] SecondIndexAuth { get; } = [0x71, 0x72, 0x73, 0x74];

    /// <summary>The sixteen octets an Ordinary Index is populated with.</summary>
    private static byte[] IndexData { get; } =
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

    /// <summary>
    /// The attribute set of a platform-created, policy-delete Ordinary Index: readable and writable with the
    /// Index authValue, dictionary-attack exempt, and carrying both attributes this command requires
    /// (TPM 2.0 Library Part 2, clause 13.4, Table 249, bits 10 and 30).
    /// </summary>
    private const TpmaNv PolicyDeleteAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA
        | TpmaNv.TPMA_NV_PLATFORMCREATE | TpmaNv.TPMA_NV_POLICY_DELETE;

    /// <summary>The same platform-created set with <c>TPMA_NV_POLICY_DELETE</c> deliberately CLEAR.</summary>
    private const TpmaNv PlatformOnlyAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA | TpmaNv.TPMA_NV_PLATFORMCREATE;

    /// <summary>An owner-created ordinary set: neither attribute this command requires is present.</summary>
    private const TpmaNv OwnerCreatedAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>A platform-created, policy-delete Counter Index (<c>TPM_NT_COUNTER</c>), incrementable with the Index authValue.</summary>
    private const TpmaNv PolicyDeleteCounterAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA
        | TpmaNv.TPMA_NV_PLATFORMCREATE | TpmaNv.TPMA_NV_POLICY_DELETE
        | (TpmaNv)((uint)TpmNt.TPM_NT_COUNTER << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>
    /// A platform-created, policy-delete <c>TPM_NT_PIN_FAIL</c> Index as DEFINED: its spec-mandated
    /// <c>TPMA_NV_NO_DA</c> (TPM 2.0 Library Part 3, clause 31.3.1), Index-authValue reads, and the
    /// owner-hierarchy write arm the counter window is provisioned through.
    /// </summary>
    private const TpmaNv PolicyDeletePinFailAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_OWNERREAD | TpmaNv.TPMA_NV_NO_DA
        | TpmaNv.TPMA_NV_PLATFORMCREATE | TpmaNv.TPMA_NV_POLICY_DELETE
        | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_FAIL << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "This command allows removal of a platform-created NV Index that has TPMA_NV_POLICY_DELETE SET. This
    /// command requires that the policy of the NV Index be satisfied before the NV Index may be deleted.
    /// Because administrative role is required, the policy must contain a command that sets the policy command
    /// code to TPM_CC_NV_UndefineSpaceSpecial" - a policy session asserting exactly that one assertion, paired
    /// with a <c>TPM_RS_PW</c> platform slot carrying the factory-empty platformAuth, deletes the Index, and
    /// the Index is then gone from <c>TPM2_NV_ReadPublic()</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialUnderACommandCodeOnlyPolicyDeletesThePolicyDeleteIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceSpecialResponse> result = await UndefineSpaceSpecialAsync(
            device, pool, registry, PolicyDeleteIndexHandle, indexName,
            assertedAuthValue: null, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"A policy asserting PolicyCommandCode(TPM_CC_NV_UndefineSpaceSpecial) satisfies clause 31.5.1's ADMIN requirement on its own: '{result.ResponseCode}'.");

        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(PolicyDeleteIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), publicResult.ResponseCode,
            "Clause 31.5.1 removes the Index, so the handle no longer references a defined Index.");
    }

    /// <summary>
    /// The deletion is total rather than nominal: with the Index removed, "If nvIndex is not defined, the TPM
    /// shall return TPM_RC_HANDLE" is the answer <c>TPM2_NV_Write()</c> and <c>TPM2_NV_UndefineSpace()</c> both
    /// give, and the freed handle accepts a fresh definition.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.5.1 and 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialLeavesTheHandleUndefinedAndRedefinable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceSpecialResponse> result = await UndefineSpaceSpecialAsync(
            device, pool, registry, PolicyDeleteIndexHandle, indexName,
            assertedAuthValue: null, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_UndefineSpaceSpecial() failed: '{result.ResponseCode}'.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, IndexAuth, IndexData).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), writeResult.ResponseCode, "A deleted Index cannot be written: its handle references no Index at all.");

        TpmResult<NvUndefineSpaceResponse> undefineResult = await UndefineSpaceAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), undefineResult.ResponseCode,
            "Clause 31.4.1's own first sentence answers for the deleted Index: an undefined nvIndex is TPM_RC_HANDLE, H2 (EntityGetLoadStatus's wrap, nvIndex is handle 2).");

        TpmResult<NvDefineSpaceResponse> redefineResult = await TryDefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        Assert.IsTrue(redefineResult.IsSuccess, $"The deletion frees the handle, so the same handle must accept a fresh definition: '{redefineResult.ResponseCode}'.");
    }

    /// <summary>
    /// "Since the index is deleted, the Empty Buffer is used as the authValue when generating the response
    /// HMAC" - under a policy that asserted <c>TPM2_PolicyAuthValue()</c> the COMMAND HMAC folds the Index's own
    /// authValue (Part 1, clause 16.6.10, equation 21), yet the framed response authorization is keyed on the
    /// Empty Buffer alone. Both halves are transcribed independently from the captured exchange: the framed
    /// HMAC must equal the Empty-keyed candidate and must differ from the authValue-keyed one, which is exactly
    /// the response a TPM that had carried the authValue over into the response key would have produced.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.5.1; Part 1, clauses 16.6.5 and 16.6.10</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialUnderAPolicyAuthValuePolicyKeysTheResponseOnTheEmptyBuffer()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeAuthValueThenCommandCodePolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        TpmResult<StartAuthSessionResponse> startResult = await device.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartPolicySessionAsync failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;
        var exchange = new List<(byte[] Command, byte[] Response)>();

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);

            TpmResult<PolicyAuthValueResponse> authValueResult = await device.PolicyAuthValueAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValueAsync failed: '{authValueResult.ResponseCode}'.");

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await device.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCodeAsync failed: '{commandCodeResult.ResponseCode}'.");

            session.SetAuthValue(IndexAuth, pool);

            //The Index's authValue keys the command HMAC and nothing else: clause 31.5.1 moves the caller's own
            //response key to the Empty Buffer the moment the TPM answers, which is what this transport does.
            async ValueTask<TpmResult<TpmResponse>> RekeyAfterTheDeletionAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
            {
                byte[] commandBytes = command.ToArray();
                TpmResult<TpmResponse> answered = await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
                if(ReadCommandCode(commandBytes) == TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial && answered.IsSuccess)
                {
                    exchange.Add((commandBytes, answered.Value.AsReadOnlySpan().ToArray()));
                    session.SetAuthValue(ReadOnlySpan<byte>.Empty, pool);
                }

                return answered;
            }

            using TpmDevice rekeyingDevice = TpmDevice.Create(RekeyAfterTheDeletionAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
            using TpmPasswordSession platformSession = TpmPasswordSession.CreateEmpty(pool);
            var input = new NvUndefineSpaceSpecialInput(PolicyDeleteIndexHandle);

            TpmResult<NvUndefineSpaceSpecialResponse> result = await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceSpecialResponse>(
                rekeyingDevice, input, [session, platformSession], [indexName, ReadOnlyMemory<byte>.Empty], pool, registry,
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A PolicyAuthValue-carrying policy authorizes the deletion just as well: '{result.ResponseCode}'.");
        }
        finally
        {
            _ = await device.FlushContextAsync(sessionHandle, CancellationToken.None).ConfigureAwait(false);
        }

        Assert.HasCount(1, exchange, "The transport must have observed exactly one TPM2_NV_UndefineSpaceSpecial exchange.");

        (byte[] command, byte[] response) = exchange[0];
        byte[] nonceCaller = ReadCommandSessionEntries(command, handleCount: 2)[0].NonceCaller;
        (int hmacStart, int hmacLength, byte[] nonceTpm, byte sessionAttributes) = ReadFirstResponseSessionEntry(response);
        byte[] hmacData = BuildResponseHmacData(response, nonceTpm, nonceCaller, sessionAttributes);

        byte[] emptyKeyedHmac = await ComputeSessionHmacAsync(ReadOnlyMemory<byte>.Empty, hmacData, pool).ConfigureAwait(false);
        byte[] authValueKeyedHmac = await ComputeSessionHmacAsync(IndexAuth, hmacData, pool).ConfigureAwait(false);

        Assert.IsFalse(
            emptyKeyedHmac.AsSpan().SequenceEqual(authValueKeyedHmac),
            "The two candidate keys must produce different HMACs, or this test would prove nothing.");
        Assert.IsTrue(
            response.AsSpan(hmacStart, hmacLength).SequenceEqual(emptyKeyedHmac),
            "Clause 31.5.1 keys the response HMAC on the Empty Buffer because the Index whose authValue would otherwise key it no longer exists.");

        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(PolicyDeleteIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), publicResult.ResponseCode, "The deletion the response was framed for must genuinely have happened.");
    }

    /// <summary>
    /// A written Counter Index retires into the TPM's phantom high-water mark on every deletion route, so a
    /// Counter deleted by this command can never be rolled back by redefining its handle: the redefinition's
    /// first increment must land ABOVE every value the deleted Counter ever reported.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.5.1; Part 1, clause 34.2.6.3</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialRetiresAWrittenCounterIntoTheHighWaterMark()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, CounterIndexHandle, PolicyDeleteCounterAttributes, deletionPolicy, CounterDataSize).ConfigureAwait(false);

        for(int increment = 0; increment < 3; increment++)
        {
            TpmResult<NvIncrementResponse> incrementResult = await IncrementAsync(device, pool, registry, CounterIndexHandle, IndexAuth).ConfigureAwait(false);
            Assert.IsTrue(incrementResult.IsSuccess, $"TPM2_NV_Increment() failed: '{incrementResult.ResponseCode}'.");
        }

        ulong retiredValue = await ReadCounterValueAsync(device, pool, registry, CounterIndexHandle, IndexAuth).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, CounterIndexHandle).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceSpecialResponse> result = await UndefineSpaceSpecialAsync(
            device, pool, registry, CounterIndexHandle, indexName,
            assertedAuthValue: null, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_UndefineSpaceSpecial() failed: '{result.ResponseCode}'.");

        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, CounterIndexHandle, PolicyDeleteCounterAttributes, deletionPolicy, CounterDataSize).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> seedResult = await IncrementAsync(device, pool, registry, CounterIndexHandle, IndexAuth).ConfigureAwait(false);
        Assert.IsTrue(seedResult.IsSuccess, $"The redefined Counter's first increment failed: '{seedResult.ResponseCode}'.");

        ulong seededValue = await ReadCounterValueAsync(device, pool, registry, CounterIndexHandle, IndexAuth).ConfigureAwait(false);
        Assert.IsGreaterThan(
            retiredValue, seededValue,
            $"A deleted Counter's value retires into the high-water mark, so the redefinition seeds above it: retired '{retiredValue}', seeded '{seededValue}'.");
    }

    /// <summary>
    /// "If the entity being authorized is an NV Index, then the associated authorization session is a policy
    /// session" - a plaintext <c>TPM_RS_PW</c> session at the ADMIN slot is the wrong KIND of authorization
    /// rather than a wrong value, so it is the bare <c>TPM_RC_AUTH_TYPE</c> and no session-index modifier. The
    /// password carries the Index's genuine authValue here, so nothing but the authorization type can be what
    /// is refused.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6; Part 1, clause 34.2.3</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithAPasswordSessionOnTheIndexIsRefusedWithAuthType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);

        using TpmPasswordSession indexSession = TpmPasswordSession.Create(IndexAuth, pool);
        using TpmPasswordSession platformSession = TpmPasswordSession.CreateEmpty(pool);
        var input = new NvUndefineSpaceSpecialInput(PolicyDeleteIndexHandle);

        TpmResult<NvUndefineSpaceSpecialResponse> result = await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceSpecialResponse>(
            device, input, [indexSession, platformSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode, "ADMIN role over an NV Index has no authValue path, so a password session is refused on its kind.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(PolicyDeleteAttributes, attributes, "A refused command deletes nothing and changes nothing.");
    }

    /// <summary>
    /// The same requirement against everything short of a policy session: a genuine HMAC session keyed on the
    /// Index's own authValue is refused with the bare <c>TPM_RC_AUTH_TYPE</c> too, because the ADMIN-role rule
    /// names the session KIND rather than the strength of the channel.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6; Part 1, clause 16.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithAnHmacSessionOnTheIndexIsRefusedWithAuthType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(device, pool, registry, IndexAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                using TpmPasswordSession platformSession = TpmPasswordSession.CreateEmpty(pool);
                var input = new NvUndefineSpaceSpecialInput(PolicyDeleteIndexHandle);

                TpmResult<NvUndefineSpaceSpecialResponse> result = await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceSpecialResponse>(
                    device, input, [session, platformSession], [indexName, ReadOnlyMemory<byte>.Empty], pool, registry,
                    TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode,
                    "An HMAC session never asserts ADMIN role over an NV Index, however well keyed it is.");
            }
        }
        finally
        {
            _ = await device.FlushContextAsync(sessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A session handle that references nothing loaded is a different refusal from a session of the wrong kind:
    /// the handle at the first authorization slot cannot be resolved at all, so the warning names the slot -
    /// <c>TPM_RC_REFERENCE_S0</c> - rather than judging a session's type.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.6 and 31.5</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithAnUnloadedSessionOnTheIndexIsRefusedWithReferenceS0()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        TpmResult<StartAuthSessionResponse> startResult = await device.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartPolicySessionAsync failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);

        TpmResult<FlushContextResponse> flushResult = await device.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"FlushContextAsync failed: '{flushResult.ResponseCode}'.");

        using TpmPasswordSession platformSession = TpmPasswordSession.CreateEmpty(pool);
        var input = new NvUndefineSpaceSpecialInput(PolicyDeleteIndexHandle);

        TpmResult<NvUndefineSpaceSpecialResponse> result = await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceSpecialResponse>(
            device, input, [session, platformSession], [indexName, ReadOnlyMemory<byte>.Empty], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_REFERENCE_S0, result.ResponseCode,
            "A handle at the first authorization slot that references no loaded session is TPM_RC_REFERENCE_S0.");
    }

    /// <summary>
    /// A trial session accumulates a policyDigest for prediction and authorizes nothing, so offering one at the
    /// ADMIN slot is a policy failure rather than a type failure: it IS a policy session, it simply cannot
    /// satisfy anything.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 11.1.1 and 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialOverATrialSessionIsRefusedWithPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        TpmResult<StartAuthSessionResponse> startResult = await device.StartTrialPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartTrialPolicySessionAsync failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await device.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCodeAsync failed: '{commandCodeResult.ResponseCode}'.");

            using TpmPasswordSession platformSession = TpmPasswordSession.CreateEmpty(pool);
            var input = new NvUndefineSpaceSpecialInput(PolicyDeleteIndexHandle);

            TpmResult<NvUndefineSpaceSpecialResponse> result = await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceSpecialResponse>(
                device, input, [session, platformSession], [indexName, ReadOnlyMemory<byte>.Empty], pool, registry,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), result.ResponseCode,
                "A trial session computes a policyDigest but authorizes nothing, so its offer is a policy failure.");
        }
        finally
        {
            _ = await device.FlushContextAsync(sessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The permanently undeletable Index, proved at both deletion commands. An Empty Policy is a legal
    /// <c>authPolicy</c> for a policy-delete Index, and the pair of refusals is what makes such an Index
    /// permanent: <c>TPM2_NV_UndefineSpace()</c> answers "If nvIndex references an Index that has its
    /// TPMA_NV_POLICY_DELETE attribute SET, the TPM shall return TPM_RC_ATTRIBUTES", while this command has no
    /// policy path to offer at all, since an Index whose authPolicy has zero size cannot have one satisfied -
    /// <c>TPM_RC_AUTH_UNAVAILABLE</c>, decided before any digest is compared.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.4.1 and 5.6; Part 1, clause 34.2.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialOnAnIndexWithAnEmptyAuthPolicyIsRefusedWithAuthUnavailable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, EmptyPolicyIndexHandle, PolicyDeleteAttributes, ReadOnlyMemory<byte>.Empty, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, EmptyPolicyIndexHandle).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> undefineResult = await UndefineSpaceAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, EmptyPolicyIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), undefineResult.ResponseCode,
            "Clause 31.4.1 refuses a TPMA_NV_POLICY_DELETE Index outright, whichever hierarchy authorized the deletion — nvIndex, handle 2 of Table 247.");

        TpmResult<NvUndefineSpaceSpecialResponse> result = await UndefineSpaceSpecialAsync(
            device, pool, registry, EmptyPolicyIndexHandle, indexName,
            assertedAuthValue: null, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, result.ResponseCode,
            "An Index whose authPolicy has zero size has no policy path, so the ADMIN slot is unavailable before any digest compare.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, EmptyPolicyIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(PolicyDeleteAttributes, attributes, "Neither refusal touches the Index, which is exactly why an Empty-Policy Index is permanent.");
    }

    /// <summary>
    /// A genuinely satisfied policy session still authorizes nothing but the Index whose <c>authPolicy</c> it
    /// matches: offered against an Index defined with a DIFFERENT digest, the accumulated policyDigest fails the
    /// compare and the refusal is <c>TPM_RC_POLICY_FAIL</c>, ahead of every command-code question.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6; Part 1, clause 16.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialUnderASatisfiedPolicyForAnotherIndexIsRefusedWithPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] commandCodeOnlyPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        byte[] authValuePolicy = ComputeAuthValueThenCommandCodePolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, commandCodeOnlyPolicy, OrdinaryDataSize).ConfigureAwait(false);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, SecondPolicyDeleteIndexHandle, PolicyDeleteAttributes, authValuePolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        //The session satisfies the SECOND Index's authPolicy exactly, and is offered against the first.
        TpmResult<NvUndefineSpaceSpecialResponse> result = await UndefineSpaceSpecialAsync(
            device, pool, registry, PolicyDeleteIndexHandle, indexName,
            IndexAuth, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), result.ResponseCode,
            "A policyDigest that matches another Index's authPolicy satisfies nothing here: the compare is against THIS Index.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(PolicyDeleteAttributes, attributes, "A refused deletion leaves the Index defined.");
    }

    /// <summary>
    /// "Because administrative role is required, the policy must contain a command that sets the policy command
    /// code to TPM_CC_NV_UndefineSpaceSpecial" - a session whose accumulated digest matches the Index's
    /// <c>authPolicy</c> but which never asserted <c>TPM2_PolicyCommandCode()</c> at all fails the second half
    /// of that conjunction, which is unsatisfiable rather than merely unmatched: <c>TPM_RC_POLICY_FAIL</c>. The
    /// Index is defined with exactly the <c>PolicyAuthValue</c>-only digest the session reaches, so the digest
    /// half genuinely passes.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.5.1 and 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialUnderAPolicyThatNeverBoundACommandCodeIsRefusedWithPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] authValueOnlyPolicy = ComputeAuthValueOnlyPolicy();
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, authValueOnlyPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceSpecialResponse> result = await UndefineSpaceSpecialAsync(
            device, pool, registry, PolicyDeleteIndexHandle, indexName,
            IndexAuth, restrictedCommand: null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), result.ResponseCode,
            "A policy that binds no command code can never assert ADMIN role, whatever its digest matches.");
    }

    /// <summary>
    /// A session that DID assert <c>TPM2_PolicyCommandCode()</c>, satisfies the Index's <c>authPolicy</c>
    /// exactly, but bound a DIFFERENT command (<c>TPM_CC_NV_ChangeAuth</c>, the other ADMIN-role NV command) is
    /// refused with <c>TPM_RC_POLICY_CC</c> - a distinct answer from the unbound case, because the caller's
    /// defect is different: the policy is the right shape but scoped to another command.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6, check 6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialUnderAPolicyScopedToAnotherCommandIsRefusedWithPolicyCc()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] rotationScopedPolicy = ComputeAuthValueThenCommandCodePolicy(TpmCcConstants.TPM_CC_NV_ChangeAuth);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, rotationScopedPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceSpecialResponse> result = await UndefineSpaceSpecialAsync(
            device, pool, registry, PolicyDeleteIndexHandle, indexName,
            IndexAuth, TpmCcConstants.TPM_CC_NV_ChangeAuth, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_CC, 0), result.ResponseCode,
            "A bound-but-wrong command code is TPM_RC_POLICY_CC, distinct from the unbound case's TPM_RC_POLICY_FAIL.");
    }

    /// <summary>
    /// "If nvIndex references an Index that has its TPMA_NV_PLATFORMCREATE or TPMA_NV_POLICY_DELETE attribute
    /// CLEAR, the TPM shall return TPM_RC_ATTRIBUTES" - and that gate lives in the command's action, after the
    /// authorizations. An owner-created ordinary Index carrying a satisfiable deletion policy therefore answers
    /// <c>TPM_RC_ATTRIBUTES</c> only once the policy has satisfied; a session that fails the same policy against
    /// the same Index answers the policy failure instead, which is the order pin.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialOnAnOwnerCreatedIndexIsRefusedWithAttributesOnlyOnceThePolicySatisfies()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, OwnerCreatedIndexHandle, OwnerCreatedAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, OwnerCreatedIndexHandle).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceSpecialResponse> unsatisfiedResult = await UndefineSpaceSpecialAsync(
            device, pool, registry, OwnerCreatedIndexHandle, indexName,
            assertedAuthValue: null, restrictedCommand: null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), unsatisfiedResult.ResponseCode,
            "The attribute gate sits in the action, behind the authorizations, so an unsatisfied policy answers first.");

        TpmResult<NvUndefineSpaceSpecialResponse> satisfiedResult = await UndefineSpaceSpecialAsync(
            device, pool, registry, OwnerCreatedIndexHandle, indexName,
            assertedAuthValue: null, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), satisfiedResult.ResponseCode,
            "An Index with TPMA_NV_PLATFORMCREATE and TPMA_NV_POLICY_DELETE CLEAR is refused by clause 31.5.1's attribute sentence — nvIndex, handle 1 of Table 249.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, OwnerCreatedIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(OwnerCreatedAttributes, attributes, "The Index this command may not delete survives untouched.");
    }

    /// <summary>
    /// The shEnable half of the accessibility probe this command shares with the two Undefine commands: "If
    /// shEnable is CLEAR, indexes created using Owner Authorization are not accessible even for deletion by the
    /// platform" (clause 31.4.1's Note, folded into clause 31.5.1's own Index probe) - with shEnable CLEARed, an
    /// owner-created Index carrying a satisfiable deletion policy is <c>TPM_RC_HANDLE</c> ahead of any
    /// authorization, and once shEnable is SET again the same call reaches the post-authorization
    /// <c>TPM_RC_ATTRIBUTES</c> clause 31.5.1's attribute sentence answers for an Index without
    /// <c>TPMA_NV_PLATFORMCREATE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.4.1 and 31.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialOnAnOwnerCreatedIndexWithShEnableClearReturnsHandleThenAttributesOnceReEnabled()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ShEnableClearedIndexHandle, OwnerCreatedAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, ShEnableClearedIndexHandle).ConfigureAwait(false);

        await SetHierarchyEnableAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, TpmiYesNo.No).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceSpecialResponse> hiddenResult = await UndefineSpaceSpecialAsync(
            device, pool, registry, ShEnableClearedIndexHandle, indexName,
            assertedAuthValue: null, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), hiddenResult.ResponseCode,
            "Clause 31.4.1's Note folds into this command's Index probe: while shEnable is CLEAR an owner-created Index is not accessible even for deletion by the platform.");

        await SetHierarchyEnableAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, TpmiYesNo.Yes).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceSpecialResponse> restoredResult = await UndefineSpaceSpecialAsync(
            device, pool, registry, ShEnableClearedIndexHandle, indexName,
            assertedAuthValue: null, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), restoredResult.ResponseCode,
            "With shEnable SET again the probe passes and authorization satisfies, reaching the post-authorization attribute gate an Index without TPMA_NV_PLATFORMCREATE always fails.");
    }

    /// <summary>
    /// The other half of the same attribute sentence: a platform-created Index whose
    /// <c>TPMA_NV_POLICY_DELETE</c> is CLEAR is refused with <c>TPM_RC_ATTRIBUTES</c> even under a satisfied
    /// deletion policy - such an Index is removed with <c>TPM2_NV_UndefineSpace()</c>, which the same test
    /// confirms still works on it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.5.1 and 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialOnAPlatformCreatedIndexWithoutPolicyDeleteIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PlatformOnlyIndexHandle, PlatformOnlyAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PlatformOnlyIndexHandle).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceSpecialResponse> result = await UndefineSpaceSpecialAsync(
            device, pool, registry, PlatformOnlyIndexHandle, indexName,
            assertedAuthValue: null, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), result.ResponseCode,
            "Both attributes are required, so a platform-created Index without TPMA_NV_POLICY_DELETE is refused here.");

        TpmResult<NvUndefineSpaceResponse> undefineResult = await UndefineSpaceAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PlatformOnlyIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(
            undefineResult.IsSuccess,
            $"An Index this command refuses is the one TPM2_NV_UndefineSpace() removes under Platform Authorization: '{undefineResult.ResponseCode}'.");
    }

    /// <summary>
    /// "If nvIndex is not defined, the TPM shall return TPM_RC_HANDLE" - the Index probe runs at the head of the
    /// command, so an undefined handle is refused before any session is judged.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialOnAnUndefinedIndexIsRefusedWithHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        byte[] absentName = ComputeIndependentNvName(UndefinedIndexHandle, SessionAlg, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize);

        TpmResult<NvUndefineSpaceSpecialResponse> result = await UndefineSpaceSpecialAsync(
            device, pool, registry, UndefinedIndexHandle, absentName,
            assertedAuthValue: null, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode, "A handle that references no defined Index is TPM_RC_HANDLE.");
    }

    /// <summary>
    /// "If the handle references a primary seed for a hierarchy (TPM_RH_ENDORSEMENT, TPM_RH_OWNER, or
    /// TPM_RH_PLATFORM) then the enable for the hierarchy is SET (TPM_RC_HIERARCHY)" - with <c>phEnable</c>
    /// CLEARed, the platform handle this command always carries cannot authorize anything, so the refusal is
    /// <c>TPM_RC_HIERARCHY</c> and it precedes the Index probe.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.4 and 24.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithPhEnableClearIsRefusedWithHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        await DisableHierarchyAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceSpecialResponse> result = await UndefineSpaceSpecialAsync(
            device, pool, registry, PolicyDeleteIndexHandle, indexName,
            assertedAuthValue: null, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 1), result.ResponseCode,
            "platformAuth cannot authorize anything while phEnable is CLEAR, this command included.");
    }

    /// <summary>
    /// "As long as phEnableNV is CLEAR, the TPM will return an error in response to any command that attempts to
    /// operate upon an NV index that has TPMA_NV_PLATFORMCREATE SET" - the Index rather than the hierarchy is
    /// what becomes unreachable, so the refusal is the Index probe's <c>TPM_RC_HANDLE</c> and not
    /// <c>TPM_RC_HIERARCHY</c>: the platform hierarchy itself is still enabled.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 24.2.1 and 31.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithPhEnableNvClearIsRefusedWithHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        await DisableHierarchyAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM_NV).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceSpecialResponse> result = await UndefineSpaceSpecialAsync(
            device, pool, registry, PolicyDeleteIndexHandle, indexName,
            assertedAuthValue: null, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "A platform-created Index is not accessible while phEnableNV is CLEAR, so its handle answers as an undefined one would.");
    }

    /// <summary>
    /// A deletion attempted under a <c>TPM2_PolicyAuthValue()</c>-carrying policy IS an attempt at the Index's
    /// own authorization value, so a wrong value is a failed authorization: on a <c>TPM_NT_PIN_FAIL</c> Index it
    /// advances <c>pinCount</c> by exactly one, and the mandatory <c>TPMA_NV_NO_DA</c> keeps the answer a
    /// session-encoded <c>TPM_RC_BAD_AUTH</c> rather than <c>TPM_RC_AUTH_FAIL</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.6.5 and 34.2.6.6; Part 3, clause 31.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithAWrongIndexAuthValueUnderPolicyAuthValueChargesThePinCount()
    {
        const uint PinLimit = 3;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeAuthValueThenCommandCodePolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefinePinIndexAsync(device, pool, registry, PinIndexHandle, deletionPolicy, pinCount: 0, PinLimit).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PinIndexHandle).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceSpecialResponse> result = await UndefineSpaceSpecialAsync(
            device, pool, registry, PinIndexHandle, indexName,
            WrongAuth, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A deletion presenting the wrong Index authorization value must not be accepted.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError, "A PIN Fail Index is spec-mandated TPMA_NV_NO_DA, so a mismatch is TPM_RC_BAD_AUTH.");
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, result.ResponseCode,
            "The mismatch is rejected by the ADMIN slot's own session, so the raw wire code carries the session-index modifier.");

        TpmResult<TpmPinCounterParameters> counters = await device.ReadPinCountersAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(counters.IsSuccess, $"ReadPinCountersAsync failed: '{counters.ResponseCode}'.");
        Assert.AreEqual(1u, counters.Value.PinCount, "A single wrong-value deletion attempt must advance pinCount by exactly one.");
    }

    /// <summary>
    /// The converse of the charge above: under a COMMAND-CODE-ONLY policy (no <c>TPM2_PolicyAuthValue()</c>), the
    /// ADMIN slot never folds the Index authValue into the command HMAC, so a mismatched HMAC on that slot is not
    /// an authorization attempt against the PIN Index at all - it is a malformed proof of the policy the caller
    /// already asserted. The refusal is the session-encoded <c>TPM_RC_BAD_AUTH</c> the ADMIN slot's own HMAC
    /// compare always answers, and both <c>pinCount</c> and <c>TPM_PT_LOCKOUT_COUNTER</c> stand still, proving the
    /// PIN throttle is neutral to command-code-only deletions, the <c>IsAuthValueNeeded</c> fork of equations 21 and 22.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.10, equations 21 and 22; Part 3, clause 31.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithAWrongHmacUnderACommandCodeOnlyPolicyChargesNeitherPinCountNorLockout()
    {
        const uint PinLimit = 3;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefinePinIndexAsync(device, pool, registry, PinIndexHandle, deletionPolicy, pinCount: 0, PinLimit).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PinIndexHandle).ConfigureAwait(false);

        uint lockoutCounterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        //A different, well-formed Name term folds into cpHash's Name1 in place of the Index's own, so the client
        //computes a command HMAC the TPM's own recomputation over the CORRECT Name cannot match - a malformed
        //proof rather than a wrong secret, since IsAuthValueNeeded is CLEAR and no authValue term is folded by
        //either side.
        byte[] wrongIndexName = (byte[])indexName.Clone();
        wrongIndexName[^1] ^= 0xFF;

        TpmResult<NvUndefineSpaceSpecialResponse> result = await UndefineSpaceSpecialAsync(
            device, pool, registry, PinIndexHandle, wrongIndexName,
            assertedAuthValue: null, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A command HMAC computed over the wrong Name term must not verify.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError, "A malformed command HMAC on the ADMIN slot is TPM_RC_BAD_AUTH.");
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, result.ResponseCode,
            "The mismatch is caught at the ADMIN slot's own verification, so the raw wire code carries the session-index modifier.");

        TpmResult<TpmPinCounterParameters> counters = await device.ReadPinCountersAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(counters.IsSuccess, $"ReadPinCountersAsync failed: '{counters.ResponseCode}'.");
        Assert.AreEqual(0u, counters.Value.PinCount, "A command-code-only policy never folds the Index authValue, so pinCount is untouched by the failed HMAC.");

        Assert.AreEqual(
            lockoutCounterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "TPMA_NV_NO_DA and the command-HMAC-level refusal both keep TPM_PT_LOCKOUT_COUNTER untouched.");
    }

    /// <summary>
    /// Once <c>pinCount</c> has reached <c>pinLimit</c> the Index's authValue is unavailable, so a deletion
    /// under a <c>TPM2_PolicyAuthValue()</c>-carrying policy is refused with a bare
    /// <c>TPM_RC_AUTH_UNAVAILABLE</c> before any HMAC work runs - the code carries no session-index modifier at
    /// all - even for the CORRECT value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.6; Part 3, clause 31.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialOnAPinIndexAtItsLimitIsRefusedWithAuthUnavailableBeforeTheHmac()
    {
        const uint PinLimit = 2;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeAuthValueThenCommandCodePolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefinePinIndexAsync(device, pool, registry, PinIndexHandle, deletionPolicy, PinLimit, PinLimit).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PinIndexHandle).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceSpecialResponse> result = await UndefineSpaceSpecialAsync(
            device, pool, registry, PinIndexHandle, indexName,
            IndexAuth, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, result.ResponseCode,
            "The at-limit gate precedes the session-HMAC verification queue entirely, so no session-index modifier is applied.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, PinIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_POLICY_DELETE, attributes & TpmaNv.TPMA_NV_POLICY_DELETE,
            "The refused deletion leaves the Index exactly where it was.");
    }

    /// <summary>
    /// "TPM2_Clear() will remove any NV Index that used Owner Authorization to define the Index" - and only
    /// those, so a platform-created policy-delete Index survives the clear with its policy intact and is still
    /// removable by the one command that may remove it. An owner-created Index defined alongside it is gone,
    /// which is what makes the survival meaningful rather than a clear that did nothing.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.3; Part 3, clauses 24.6.1 and 31.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TpmClearLeavesThePolicyDeleteIndexForThisCommandToDelete()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, OwnerCreatedIndexHandle, OwnerCreatedAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        TpmResult<ClearResponse> clearResult = await device.ClearAsync(ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(clearResult.IsSuccess, $"TPM2_Clear() failed: '{clearResult.ResponseCode}'.");

        TpmResult<NvReadPublicResponse> ownerPublicResult = await device.NvReadPublicAsync(OwnerCreatedIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), ownerPublicResult.ResponseCode, "TPM2_Clear() removes every Index defined under Owner Authorization.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(PolicyDeleteAttributes, attributes, "A platform-created Index survives TPM2_Clear() with its attribute word intact.");

        TpmResult<NvUndefineSpaceSpecialResponse> result = await UndefineSpaceSpecialAsync(
            device, pool, registry, PolicyDeleteIndexHandle, indexName,
            assertedAuthValue: null, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The surviving Index is still deletable by its own rules after the clear: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// A session's bind entity is a value captured when the session was started, not a live reference:
    /// <see cref="SessionBoundEntity"/> folds the Name WITH the bind entity's authValue at
    /// <c>TPM2_StartAuthSession()</c>, so the recorded value is sensitive to that authValue changing. Deleting
    /// the bound Index and redefining the SAME handle with the SAME nameAlg/attributes/authPolicy/dataSize but a
    /// DIFFERENT Index authValue reproduces the "squatting" case Part 1, clause 16.6.10 defends against: the
    /// recomputed Name is identical, but the recomputed bind value is not, so the session no longer matches and
    /// the omission stops firing - the caller must fold the NEW authValue to authorize the redefined Index, and
    /// the OLD one no longer works.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.10</see>.
    /// </summary>
    [TestMethod]
    public async Task ASessionBoundToTheDeletedIndexNoLongerOmitsTheAuthValueAfterARedefinitionWithADifferentValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        (uint boundHandle, TpmSession boundSession) = await StartBoundHmacSessionAsync(
            device, pool, registry, PolicyDeleteIndexHandle, IndexAuth).ConfigureAwait(false);
        try
        {
            using(boundSession)
            {
                TpmResult<NvUndefineSpaceSpecialResponse> deletion = await UndefineSpaceSpecialAsync(
                    device, pool, registry, PolicyDeleteIndexHandle, indexName,
                    assertedAuthValue: null, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
                Assert.IsTrue(deletion.IsSuccess, $"TPM2_NV_UndefineSpaceSpecial() failed: '{deletion.ResponseCode}'.");

                await DefineIndexAsync(
                    device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize,
                    SecondIndexAuth).ConfigureAwait(false);
                byte[] redefinedIndexName = await ReadNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
                Assert.AreSequenceEqual(
                    indexName, redefinedIndexName,
                    "TPMS_NV_PUBLIC carries no authValue field, so an identical public area redefinition reproduces the identical Name - the 'squatting' precondition.");

                //The redefined Index is seeded over TPM_RS_PW with its NEW authValue first: a read of an unwritten
                //Index answers TPM_RC_NV_UNINITIALIZED ahead of any authValue check (Part 3, clause 31.1), so
                //only a written Index lets the Index-authValue read arm reach the compare the bind decides. The
                //probe is TPM2_NV_Read()'s Index arm because that is the Index-authValue arm this simulator
                //authorizes over an HMAC session; TPM2_NV_Write()'s Index arm is password-only.
                using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(IndexData, pool);
                using TpmPasswordSession seedingSession = TpmPasswordSession.Create(SecondIndexAuth, pool);
                var seedInput = new NvWriteInput(PolicyDeleteIndexHandle, PolicyDeleteIndexHandle, buffer, Offset: 0);
                TpmResult<NvWriteResponse> seed = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
                    device, seedInput, [seedingSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(seed.IsSuccess, $"The redefined Index must be written under its new authValue before a read can reach the authValue compare: '{seed.ResponseCode}'.");

                //The first write SETS TPMA_NV_WRITTEN and so moves the Name (Part 1, clause 13): cpHash folds the
                //Name as each read finds it, which is the written one from here on.
                byte[] writtenIndexName = await ReadNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

                var readInput = new NvReadInput(PolicyDeleteIndexHandle, PolicyDeleteIndexHandle, (ushort)IndexData.Length, Offset: 0);

                boundSession.SetAuthValue(IndexAuth, pool);
                TpmResult<NvReadResponse> staleRead = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                    device, readInput, [boundSession], [writtenIndexName, writtenIndexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_BAD_AUTH, staleRead.BaseError,
                    $"The bind no longer matches, so the OLD authValue the session was bound with no longer authorizes the redefined Index (TPMA_NV_NO_DA keeps the mismatch uncharged): '{staleRead.ResponseCode}'.");

                boundSession.SetAuthValue(SecondIndexAuth, pool);
                TpmResult<NvReadResponse> freshRead = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                    device, readInput, [boundSession], [writtenIndexName, writtenIndexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(
                    freshRead.IsSuccess,
                    $"With the bind omission no longer firing, the session folds whatever authValue it is given - the redefined Index's NEW authValue authorizes: '{freshRead.ResponseCode}'.");
            }
        }
        finally
        {
            _ = await device.FlushContextAsync(boundHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The command returns every carrier its parse rented on both of the paths its ladder takes, and the
    /// accepting one returns more than that: undefining is the Index's ownership-end boundary, so the carriers
    /// the definition took out are released with it and the pool falls back to where it stood before the Index
    /// existed. A refusal in the policy ladder leaves that definition untouched, so it returns to the
    /// with-the-Index-defined level instead.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.5 and 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialReturnsItsCarriersAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvUndefineSpaceSpecialRegistry();

        long undefinedBaseline = trackingPool.OutstandingCount;

        byte[] deletionPolicy = ComputeCommandCodeOnlyPolicy(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        long definedBaseline = trackingPool.OutstandingCount;
        Assert.IsGreaterThan(undefinedBaseline, definedBaseline, "A defined Index holds carriers of its own, which is what the accepting transition must give back.");

        TpmResult<NvUndefineSpaceSpecialResponse> refusal = await UndefineSpaceSpecialAsync(
            device, pool, registry, PolicyDeleteIndexHandle, indexName,
            assertedAuthValue: null, restrictedCommand: null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), refusal.ResponseCode,
            "Part 4's CheckPolicyAuthSession answers TPM_RC_POLICY_FAIL when the policy session's own digest was never satisfied.");
        Assert.AreEqual(
            definedBaseline, trackingPool.OutstandingCount,
            "A refusal in the policy ladder releases the request's own carriers through its Dispose and leaves the Index's alone.");

        TpmResult<NvUndefineSpaceSpecialResponse> accepted = await UndefineSpaceSpecialAsync(
            device, pool, registry, PolicyDeleteIndexHandle, indexName,
            assertedAuthValue: null, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(accepted.IsSuccess, $"TPM2_NV_UndefineSpaceSpecial() failed: '{accepted.ResponseCode}'.");
        Assert.AreEqual(
            undefinedBaseline, trackingPool.OutstandingCount,
            "The accepting transition is the terminal owner of the request's carriers AND of the deleted Index's own.");
    }

    /// <summary>
    /// Composes <c>TPM2_NV_UndefineSpaceSpecial()</c> over a policy session built to order at the ADMIN slot and
    /// a <c>TPM_RS_PW</c> platform slot, so a test can present a policy whose SHAPE is wrong rather than a value
    /// that is wrong. The handle area supplies the Index's Name and leaves the platform handle's own Name to be
    /// derived from its four octets (TPM 2.0 Library Part 1, clause 13, Table 9).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to attempt the deletion against.</param>
    /// <param name="indexName">The Index's Name, folded into cpHash.</param>
    /// <param name="assertedAuthValue">The authorization value to prove with <c>TPM2_PolicyAuthValue()</c>, or <see langword="null"/> to assert no authValue at all.</param>
    /// <param name="restrictedCommand">The command code to bind with <c>TPM2_PolicyCommandCode()</c>, or <see langword="null"/> to bind none.</param>
    /// <param name="platformAuth">The authorization value supplied for the platform slot.</param>
    /// <returns>The deletion's raw result.</returns>
    private async Task<TpmResult<NvUndefineSpaceSpecialResponse>> UndefineSpaceSpecialAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        uint nvIndex,
        ReadOnlyMemory<byte> indexName,
        ReadOnlyMemory<byte>? assertedAuthValue,
        TpmCcConstants? restrictedCommand,
        ReadOnlyMemory<byte> platformAuth)
    {
        TpmResult<StartAuthSessionResponse> startResult = await device.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartPolicySessionAsync failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);

            if(assertedAuthValue is ReadOnlyMemory<byte> authValue)
            {
                TpmResult<PolicyAuthValueResponse> authValueResult = await device.PolicyAuthValueAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValueAsync failed: '{authValueResult.ResponseCode}'.");

                session.SetAuthValue(authValue.Span, pool);
            }

            if(restrictedCommand is TpmCcConstants boundCommand)
            {
                TpmResult<PolicyCommandCodeResponse> commandCodeResult = await device.PolicyCommandCodeAsync(
                    sessionHandle, boundCommand, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCodeAsync failed: '{commandCodeResult.ResponseCode}'.");
            }

            using TpmPasswordSession platformSession = TpmPasswordSession.Create(platformAuth.Span, pool);
            var input = new NvUndefineSpaceSpecialInput(nvIndex);

            return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceSpecialResponse>(
                device, input, [session, platformSession], [indexName, ReadOnlyMemory<byte>.Empty], pool, registry,
                TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await device.FlushContextAsync(sessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>Defines an NV Index under <paramref name="authHandle"/> and asserts the definition succeeded.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The provisioning hierarchy that authorizes the definition.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <param name="authPolicy">The access policy digest to define with.</param>
    /// <param name="dataSize">The declared data area size.</param>
    private async Task DefineIndexAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        TpmRh authHandle,
        uint nvIndex,
        TpmaNv attributes,
        ReadOnlyMemory<byte> authPolicy,
        ushort dataSize) =>
        await DefineIndexAsync(device, pool, registry, authHandle, nvIndex, attributes, authPolicy, dataSize, IndexAuth).ConfigureAwait(false);

    /// <summary>Defines an NV Index under <paramref name="authHandle"/> carrying <paramref name="authValue"/> and asserts the definition succeeded.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The provisioning hierarchy that authorizes the definition.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <param name="authPolicy">The access policy digest to define with.</param>
    /// <param name="dataSize">The declared data area size.</param>
    /// <param name="authValue">The Index authorization value to define with.</param>
    private async Task DefineIndexAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        TpmRh authHandle,
        uint nvIndex,
        TpmaNv attributes,
        ReadOnlyMemory<byte> authPolicy,
        ushort dataSize,
        ReadOnlyMemory<byte> authValue)
    {
        TpmResult<NvDefineSpaceResponse> result = await TryDefineIndexAsync(
            device, pool, registry, authHandle, nvIndex, attributes, authPolicy, dataSize, authValue).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace() under '{authHandle}' failed: '{result.ResponseCode}'.");
    }

    /// <summary>Defines an NV Index under <paramref name="authHandle"/> and reports the raw result.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The provisioning hierarchy that authorizes the definition.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <param name="authPolicy">The access policy digest to define with.</param>
    /// <param name="dataSize">The declared data area size.</param>
    /// <returns>The definition's raw result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> TryDefineIndexAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        TpmRh authHandle,
        uint nvIndex,
        TpmaNv attributes,
        ReadOnlyMemory<byte> authPolicy,
        ushort dataSize) =>
        await TryDefineIndexAsync(device, pool, registry, authHandle, nvIndex, attributes, authPolicy, dataSize, IndexAuth).ConfigureAwait(false);

    /// <summary>Defines an NV Index under <paramref name="authHandle"/> carrying <paramref name="authValue"/> and reports the raw result.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The provisioning hierarchy that authorizes the definition.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <param name="authPolicy">The access policy digest to define with.</param>
    /// <param name="dataSize">The declared data area size.</param>
    /// <param name="authValue">The Index authorization value to define with.</param>
    /// <returns>The definition's raw result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> TryDefineIndexAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        TpmRh authHandle,
        uint nvIndex,
        TpmaNv attributes,
        ReadOnlyMemory<byte> authPolicy,
        ushort dataSize,
        ReadOnlyMemory<byte> authValue)
    {
        using TpmPasswordSession hierarchySession = TpmPasswordSession.CreateEmpty(pool);

        //The input takes ownership of the auth value and public area and disposes them; the redundant using
        //locals satisfy CA2000 and are safe because both types have idempotent disposal.
        using var auth = Tpm2bAuth.Create(authValue.Span, pool);
        using var policyDigest = Tpm2bDigest.Create(authPolicy.Span, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, SessionAlg, attributes, policyDigest, dataSize);
        using var input = new NvDefineSpaceInput(authHandle, auth, publicInfo);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [hierarchySession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Defines a platform-created, policy-delete <c>TPM_NT_PIN_FAIL</c> Index and provisions its counter window
    /// through the owner-authorized write arm - the only write path a PIN Index has, since its own authValue
    /// authorizes reads alone (TPM 2.0 Library Part 1, clause 34.2.6.1).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="authPolicy">The access policy digest to define with.</param>
    /// <param name="pinCount">The attempt count to provision.</param>
    /// <param name="pinLimit">The attempt threshold to provision.</param>
    private async Task DefinePinIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> authPolicy, uint pinCount, uint pinLimit)
    {
        await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, nvIndex, PolicyDeletePinFailAttributes, authPolicy, PinCounterParametersSize).ConfigureAwait(false);

        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using IMemoryOwner<byte> blobOwner = pool.Rent(PinCounterParametersSize);
        Memory<byte> blob = blobOwner.Memory[..PinCounterParametersSize];
        BinaryPrimitives.WriteUInt32BigEndian(blob.Span, pinCount);
        BinaryPrimitives.WriteUInt32BigEndian(blob.Span[sizeof(uint)..], pinLimit);

        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(blob.Span, pool);
        var input = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, nvIndex, buffer, Offset: 0);

        TpmResult<NvWriteResponse> result = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The owner-authorized counter write failed: '{result.ResponseCode}'.");
    }

    /// <summary>Issues an Index-authValue <c>TPM2_NV_Write()</c> against <paramref name="nvIndex"/> at offset zero.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to write.</param>
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

    /// <summary>Issues a password-authorized <c>TPM2_NV_UndefineSpace()</c> under <paramref name="authHandle"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The provisioning hierarchy that authorizes the removal.</param>
    /// <param name="nvIndex">The Index to remove.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <returns>The removal result.</returns>
    private async Task<TpmResult<NvUndefineSpaceResponse>> UndefineSpaceAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var input = new NvUndefineSpaceInput(authHandle, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues an Index-authValue <c>TPM2_NV_Increment()</c> against <paramref name="nvIndex"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Counter Index to increment.</param>
    /// <param name="suppliedAuth">The authorization value supplied for the Index.</param>
    /// <returns>The increment result.</returns>
    private async Task<TpmResult<NvIncrementResponse>> IncrementAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var input = new NvIncrementInput(nvIndex, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads a Counter Index's whole 8-octet value back over the Index-authValue <c>TPM2_NV_Read()</c> arm.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Counter Index to read.</param>
    /// <param name="suppliedAuth">The authorization value supplied for the Index.</param>
    /// <returns>The counter's current value.</returns>
    private async Task<ulong> ReadCounterValueAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var input = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: CounterDataSize, Offset: 0);

        TpmResult<NvReadResponse> result = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Read() failed: '{result.ResponseCode}'.");

        using NvReadResponse read = result.Value;

        return BinaryPrimitives.ReadUInt64BigEndian(read.Data);
    }

    /// <summary>
    /// Starts an UNBOUND, unsalted HMAC session and keys it on <paramref name="authValue"/> - the shape the
    /// ADMIN slot must refuse on its kind rather than on its value.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authValue">The authorization value the session would prove.</param>
    /// <returns>The session handle (to flush) and the composed session (to dispose).</returns>
    private async Task<(uint Handle, TpmSession Session)> StartUnboundHmacSessionAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, ReadOnlyMemory<byte> authValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (HMAC) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);
        session.SetAuthValue(authValue.Span, pool);

        return (started.SessionHandle.Value, session);
    }

    /// <summary>
    /// Starts a bound, unsalted HMAC session against <paramref name="bindHandle"/>, deriving the client-side
    /// session key from <paramref name="bindAuthValue"/> (TPM 2.0 Library Part 1, clause 16.6.10, equation 20).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="bindHandle">The entity to bind to.</param>
    /// <param name="bindAuthValue">The bind entity's authValue fed into the session-key derivation.</param>
    /// <returns>The started session handle and its client-side wrapper.</returns>
    private async Task<(uint Handle, TpmSession Session)> StartBoundHmacSessionAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint bindHandle, ReadOnlyMemory<byte> bindAuthValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(bindHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to 0x{bindHandle:X8}) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(started.SessionHandle.Value), bindAuthValue, startInput.NonceCaller, started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Reads <c>TPM_PT_LOCKOUT_COUNTER</c>, the live <c>failedTries</c> value, back over <c>TPM2_GetCapability()</c>.</summary>
    /// <param name="device">The TPM device.</param>
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

    /// <summary>
    /// CLEARs <paramref name="hierarchy"/>'s enable through a password-authorized <c>TPM2_HierarchyControl()</c>
    /// under Platform Authorization, asserting the write succeeded - Platform Authorization may CLEAR any enable
    /// including its own (TPM 2.0 Library Part 3, clause 24.2.1).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="hierarchy">The hierarchy whose enable is CLEARed.</param>
    private async Task DisableHierarchyAsync(TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh hierarchy)
    {
        using TpmPasswordSession session = TpmPasswordSession.CreateEmpty(pool);
        var input = new HierarchyControlInput(TpmRh.TPM_RH_PLATFORM, hierarchy, TpmiYesNo.No);

        TpmResult<HierarchyControlResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyControlResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyControl() disabling '{hierarchy}' failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Writes <paramref name="hierarchy"/>'s enable to <paramref name="state"/> through a password-authorized
    /// <c>TPM2_HierarchyControl()</c> under Platform Authorization, asserting the write succeeded - Platform
    /// Authorization may write any enable in either direction, including re-SETting one it CLEARed
    /// (TPM 2.0 Library Part 3, clause 24.2.1).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="hierarchy">The hierarchy or NV enable being written.</param>
    /// <param name="state">The enable value to write.</param>
    private async Task SetHierarchyEnableAsync(TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh hierarchy, TpmiYesNo state)
    {
        using TpmPasswordSession session = TpmPasswordSession.CreateEmpty(pool);
        var input = new HierarchyControlInput(TpmRh.TPM_RH_PLATFORM, hierarchy, state);

        TpmResult<HierarchyControlResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyControlResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyControl() on '{hierarchy}' failed: '{result.ResponseCode}'.");
    }

    /// <summary>Reads an Index's <c>TPMA_NV</c> attribute word back through <c>TPM2_NV_ReadPublic()</c>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Index whose public area is wanted.</param>
    /// <returns>The Index's attribute word.</returns>
    private async Task<TpmaNv> ReadIndexAttributesAsync(TpmDevice device, uint nvIndex)
    {
        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(publicResult.IsSuccess, $"NvReadPublicAsync failed: '{publicResult.ResponseCode}'.");

        using NvReadPublicResponse indexPublic = publicResult.Value;

        return indexPublic.NvPublic.Attributes;
    }

    /// <summary>Reads an Index's Name back over <c>TPM2_NV_ReadPublic()</c>, for the cpHash handle area a session-authorized command needs.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Index whose Name is wanted.</param>
    /// <returns>The Index's Name.</returns>
    private async Task<byte[]> ReadNameAsync(TpmDevice device, uint nvIndex)
    {
        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(publicResult.IsSuccess, $"NvReadPublicAsync failed: '{publicResult.ResponseCode}'.");

        using NvReadPublicResponse indexPublic = publicResult.Value;

        return indexPublic.NvName.Span.ToArray();
    }

    /// <summary>
    /// Transcribes the minimal deletion policy from its single extend formula:
    /// <c>policyDigest = H(zeroes ‖ TPM_CC_PolicyCommandCode ‖ commandCode)</c> folded over the all-zero
    /// starting digest a fresh policy session carries (TPM 2.0 Library Part 3, clause 23.11; Part 1, clause
    /// 16.7), written out with <see cref="BinaryPrimitives"/> and the framework digest rather than through the
    /// policy-digest helper the implementation under test folds its own copy with.
    /// </summary>
    /// <param name="boundCommand">The command code the policy binds.</param>
    /// <returns>The transcribed policy digest.</returns>
    private static byte[] ComputeCommandCodeOnlyPolicy(TpmCcConstants boundCommand) =>
        ExtendForCommandCode(new byte[Sha256DigestSize], boundCommand);

    /// <summary>
    /// Transcribes the deletion policy that also proves the Index's own authorization value, from the two
    /// extend formulas in order: <c>H(zeroes ‖ TPM_CC_PolicyAuthValue)</c> (TPM 2.0 Library Part 3, clause
    /// 23.17) then <c>H(policyDigest ‖ TPM_CC_PolicyCommandCode ‖ commandCode)</c> (clause 23.11).
    /// </summary>
    /// <param name="boundCommand">The command code the policy binds.</param>
    /// <returns>The transcribed policy digest.</returns>
    private static byte[] ComputeAuthValueThenCommandCodePolicy(TpmCcConstants boundCommand) =>
        ExtendForCommandCode(ComputeAuthValueOnlyPolicy(), boundCommand);

    /// <summary>
    /// Transcribes the policy that asserts <c>TPM2_PolicyAuthValue()</c> and nothing else:
    /// <c>H(zeroes ‖ TPM_CC_PolicyAuthValue)</c> (TPM 2.0 Library Part 3, clause 23.17).
    /// </summary>
    /// <returns>The transcribed policy digest.</returns>
    private static byte[] ComputeAuthValueOnlyPolicy()
    {
        byte[] input = new byte[Sha256DigestSize + sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(Sha256DigestSize), (uint)TpmCcConstants.TPM_CC_PolicyAuthValue);

        return SHA256.HashData(input);
    }

    /// <summary>
    /// Extends a policy digest for <c>TPM2_PolicyCommandCode()</c>:
    /// <c>policyDigest = H(policyDigest ‖ TPM_CC_PolicyCommandCode ‖ commandCode)</c>
    /// (TPM 2.0 Library Part 3, clause 23.11).
    /// </summary>
    /// <param name="current">The digest to extend.</param>
    /// <param name="boundCommand">The command code the policy binds.</param>
    /// <returns>The extended digest.</returns>
    private static byte[] ExtendForCommandCode(ReadOnlySpan<byte> current, TpmCcConstants boundCommand)
    {
        byte[] input = new byte[current.Length + sizeof(uint) + sizeof(uint)];
        current.CopyTo(input);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(current.Length), (uint)TpmCcConstants.TPM_CC_PolicyCommandCode);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(current.Length + sizeof(uint)), (uint)boundCommand);

        return SHA256.HashData(input);
    }

    /// <summary>
    /// Independently transcribes an NV Index's Name: <c>nameAlg ‖ H_nameAlg(nvIndex ‖ nameAlg ‖ attributes ‖
    /// authPolicy ‖ dataSize)</c>, the whole marshaled <c>TPMS_NV_PUBLIC</c> hashed per TPM 2.0 Library Part 1,
    /// clause 13, Table 9 - the only way to name an Index that does not exist to be read back.
    /// </summary>
    /// <param name="nvIndex">The Index handle.</param>
    /// <param name="nameAlg">The Name hash algorithm.</param>
    /// <param name="attributes">The Index attributes to hash.</param>
    /// <param name="authPolicy">The access policy digest to hash.</param>
    /// <param name="dataSize">The declared data area size to hash.</param>
    /// <returns>The transcribed Name.</returns>
    private static byte[] ComputeIndependentNvName(
        uint nvIndex, TpmAlgIdConstants nameAlg, TpmaNv attributes, ReadOnlyMemory<byte> authPolicy, ushort dataSize)
    {
        int marshaledLength = sizeof(uint) + sizeof(ushort) + sizeof(uint) + sizeof(ushort) + authPolicy.Length + sizeof(ushort);
        byte[] marshaled = new byte[marshaledLength];
        int offset = 0;

        BinaryPrimitives.WriteUInt32BigEndian(marshaled.AsSpan(offset, sizeof(uint)), nvIndex);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset, sizeof(ushort)), (ushort)nameAlg);
        offset += sizeof(ushort);
        BinaryPrimitives.WriteUInt32BigEndian(marshaled.AsSpan(offset, sizeof(uint)), (uint)attributes);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset, sizeof(ushort)), (ushort)authPolicy.Length);
        offset += sizeof(ushort);
        authPolicy.Span.CopyTo(marshaled.AsSpan(offset));
        offset += authPolicy.Length;
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset, sizeof(ushort)), dataSize);

        byte[] name = new byte[sizeof(ushort) + Sha256DigestSize];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)nameAlg);
        SHA256.HashData(marshaled).CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>
    /// Assembles the data a response authorization HMAC is computed over:
    /// <c>rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes</c>, where
    /// <c>rpHash = H(responseCode ‖ commandCode ‖ parameters)</c> and this command has no response parameters at
    /// all (TPM 2.0 Library Part 1, clauses 15.8 and 16.6.5).
    /// </summary>
    /// <param name="responseBytes">The captured response bytes, whose header supplies the response code.</param>
    /// <param name="responseNonceTpm">The session entry's rolled nonceTPM.</param>
    /// <param name="commandNonceCaller">The caller nonce the command's own session entry carried.</param>
    /// <param name="sessionAttributes">The session entry's echoed attributes octet.</param>
    /// <returns>The assembled HMAC input.</returns>
    private static byte[] BuildResponseHmacData(
        byte[] responseBytes, byte[] responseNonceTpm, byte[] commandNonceCaller, byte sessionAttributes)
    {
        var reader = new TpmReader(responseBytes);
        TpmHeader header = TpmHeader.Parse(ref reader);

        byte[] rpHashInput = new byte[sizeof(uint) + sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(rpHashInput, header.Code);
        BinaryPrimitives.WriteUInt32BigEndian(rpHashInput.AsSpan(sizeof(uint)), (uint)TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);

        byte[] rpHash = SHA256.HashData(rpHashInput);

        byte[] data = new byte[rpHash.Length + responseNonceTpm.Length + commandNonceCaller.Length + sizeof(byte)];
        int offset = 0;
        rpHash.CopyTo(data.AsSpan(offset));
        offset += rpHash.Length;
        responseNonceTpm.CopyTo(data.AsSpan(offset));
        offset += responseNonceTpm.Length;
        commandNonceCaller.CopyTo(data.AsSpan(offset));
        offset += commandNonceCaller.Length;
        data[offset] = sessionAttributes;

        return data;
    }

    /// <summary>
    /// Computes a session authorization HMAC: <c>HMAC_sessionAlg(sessionKey ‖ authValue, data)</c> (TPM 2.0
    /// Library Part 1, clause 16.6.5, equation 17). An unbound, unsalted session's key is the Empty Buffer, so
    /// the caller's <paramref name="sessionValue"/> is the authValue term alone - or nothing at all, which is
    /// what this command's response is keyed with.
    /// </summary>
    /// <param name="sessionValue">The concatenated HMAC key.</param>
    /// <param name="data">The HMAC input.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The computed HMAC.</returns>
    private async Task<byte[]> ComputeSessionHmacAsync(ReadOnlyMemory<byte> sessionValue, ReadOnlyMemory<byte> data, BaseMemoryPool pool)
    {
        using HmacValue hmac = await CryptographicKeyEvents.ComputeHmacAsync(
            data, sessionValue, Sha256DigestSize, CryptoTags.HmacSha256Value, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return hmac.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Walks a built command's authorization area and yields each session entry's handle, caller nonce,
    /// attributes octet, and the position of its <c>hmac</c> field's data octets: handle area,
    /// <c>authorizationSize</c>, then one <c>sessionHandle ‖ nonceCaller ‖ sessionAttributes ‖ hmac</c> entry per
    /// session until the declared size is consumed (TPM 2.0 Library Part 1, clause 17.5).
    /// </summary>
    /// <param name="command">The captured command bytes.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <returns>The parsed session entries, in authorization-area order.</returns>
    private static List<(uint Handle, byte[] NonceCaller, byte Attributes, int HmacStart, int HmacLength)> ReadCommandSessionEntries(byte[] command, int handleCount)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < handleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint authorizationSize = reader.ReadUInt32();
        int authStart = reader.Consumed;

        var entries = new List<(uint Handle, byte[] NonceCaller, byte Attributes, int HmacStart, int HmacLength)>(2);
        while(reader.Consumed - authStart < (int)authorizationSize)
        {
            uint handle = reader.ReadUInt32();
            ushort nonceSize = reader.ReadUInt16();
            byte[] nonceCaller = reader.PeekBytes(nonceSize).ToArray();
            reader.Skip(nonceSize);
            byte attributes = reader.ReadByte();
            ushort hmacSize = reader.ReadUInt16();
            int hmacStart = reader.Consumed;
            reader.Skip(hmacSize);

            entries.Add((handle, nonceCaller, attributes, hmacStart, hmacSize));
        }

        return entries;
    }

    /// <summary>
    /// Reads the FIRST session entry out of a framed response's authorization area and reports where its HMAC
    /// field's data octets sit: header, <c>parameterSize</c> (zero for a command with no response parameters),
    /// then <c>nonceTPM ‖ sessionAttributes ‖ hmac</c>.
    /// </summary>
    /// <param name="response">The captured response bytes.</param>
    /// <returns>The HMAC data's offset and length, the entry's rolled nonceTPM, and its echoed attributes octet.</returns>
    private static (int HmacStart, int HmacLength, byte[] NonceTpm, byte SessionAttributes) ReadFirstResponseSessionEntry(byte[] response)
    {
        var reader = new TpmReader(response);
        _ = TpmHeader.Parse(ref reader);
        _ = reader.ReadUInt32();

        ushort nonceSize = reader.ReadUInt16();
        byte[] nonceTpm = reader.PeekBytes(nonceSize).ToArray();
        reader.Skip(nonceSize);
        byte sessionAttributes = reader.ReadByte();
        ushort hmacSize = reader.ReadUInt16();

        return (reader.Consumed, hmacSize, nonceTpm, sessionAttributes);
    }

    /// <summary>Reads a captured TPM command's header <c>code</c> field, leaving every other field unexamined.</summary>
    /// <param name="command">The captured command bytes.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(byte[] command)
    {
        var reader = new TpmReader(command);
        TpmHeader header = TpmHeader.Parse(ref reader);

        return (TpmCcConstants)header.Code;
    }

    /// <summary>Creates a response codec registry for the commands these tests drive directly.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateNvUndefineSpaceSpecialRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, TpmResponseCodec.NvUndefineSpaceSpecial)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead)
            .Register(TpmCcConstants.TPM_CC_NV_Increment, TpmResponseCodec.NvIncrement)
            .Register(TpmCcConstants.TPM_CC_NV_GlobalWriteLock, TpmResponseCodec.NvGlobalWriteLock)
            .Register(TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmResponseCodec.HierarchyChangeAuth)
            .Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>
    /// Frames <c>TPM2_Startup()</c> - a sessionless command (<c>TPM_ST_NO_SESSIONS</c>) - directly to the
    /// simulator and returns its response code.
    /// </summary>
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
    /// phase, which is the precondition <c>TPM2_NV_UndefineSpaceSpecial()</c> carries.
    /// </summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator("tpm-in-house-nv-undefine-space-special", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitStartupAsync(simulator, BaseMemoryPool.Shared, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
