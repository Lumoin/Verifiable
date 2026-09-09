using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Hierarchy;
using Verifiable.Tpm.Extensions.Nv;
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
/// Drives <c>TPM2_NV_UndefineSpace()</c>'s Platform Authorization arm and the deletion rules clause 31.4.1
/// states — which hierarchy may remove which Index, the <c>TPMA_NV_POLICY_DELETE</c> refusal that sends an
/// Index to <c>TPM2_NV_UndefineSpaceSpecial()</c> instead, the order the two body gates hold relative to each
/// other and to the authorization that precedes them, the reach <c>shEnable</c> and <c>phEnableNV</c> give the
/// two Index populations, and the effects a deletion carries (a PIN throttle released, a Counter's value
/// retired into the phantom high-water mark) — on both the password and the HMAC-session form, against the
/// in-house behavioural <see cref="TpmSimulator"/>, entirely in-process with no external assets, through the
/// same production command path the production code uses (<see cref="TpmCommandExecutor"/> and the real
/// command/response codecs). TPM 2.0 Library Part 3, clauses 31.4, 24.2.1 and 5.4; Part 2, clauses 9.21 and
/// 13.4; Part 1, clauses 15.7, 16.6.10, 16.8.1 and 34.2.6.3.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorNvUndefineSpacePlatformTests
{
    /// <summary>The declared data size of every Ordinary Index this file defines.</summary>
    private const ushort OrdinaryDataSize = 16;

    /// <summary>The declared data size of a Counter and of a PIN Index (TPM 2.0 Library Part 2, clause 13.2).</summary>
    private const ushort EightOctetDataSize = 8;

    /// <summary>An Ordinary Index defined under Owner Authorization, so its <c>TPMA_NV_PLATFORMCREATE</c> is CLEAR.</summary>
    private const uint OwnerCreatedIndexHandle = 0x0100_00E0;

    /// <summary>An Ordinary Index defined under Platform Authorization, so its <c>TPMA_NV_PLATFORMCREATE</c> is SET.</summary>
    private const uint PlatformCreatedIndexHandle = 0x0100_00E1;

    /// <summary>A platform-created Index additionally electing <c>TPMA_NV_POLICY_DELETE</c>.</summary>
    private const uint PolicyDeleteIndexHandle = 0x0100_00E2;

    /// <summary>A PIN Fail Index, defined under Owner Authorization, whose throttle the platform arm releases.</summary>
    private const uint PinFailIndexHandle = 0x0100_00E3;

    /// <summary>A Counter Index, defined under Owner Authorization, whose value the deletion retires.</summary>
    private const uint CounterIndexHandle = 0x0100_00E4;

    /// <summary>A second owner-created Ordinary Index, used where two Indexes must coexist.</summary>
    private const uint SecondOwnerCreatedIndexHandle = 0x0100_00E5;

    /// <summary>An Index handle left undefined, for the password-form handle-area-order pin.</summary>
    private const uint UndefinedIndexForPasswordOrderPinHandle = 0x0100_00E6;

    /// <summary>An Index handle left undefined, for the session-form handle-area-order pin.</summary>
    private const uint UndefinedIndexForSessionOrderPinHandle = 0x0100_00E7;

    /// <summary>An NV Index handle offered as an inadmissible <c>@authHandle</c> value.</summary>
    private const uint NvIndexRangeHandle = 0x0100_00EF;

    /// <summary>A handle in the transient-object range, which <c>TPMI_RH_PROVISION</c> admits no more than an Index handle does.</summary>
    private const uint TransientRangeHandle = 0x8000_0000;

    /// <summary>The hash algorithm for every HMAC session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// Ordinary Index attributes for an owner-created Index: readable and writable with the Index authValue,
    /// writable with owner authorization, opted out of the global dictionary-attack mechanism so the deletion
    /// cases stay disjoint from it.
    /// </summary>
    private const TpmaNv OwnerCreatedAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>The same Ordinary Index electing <c>TPMA_NV_PLATFORMCREATE</c>, which only a platform-authorized definition may carry.</summary>
    private const TpmaNv PlatformCreatedAttributes = OwnerCreatedAttributes | TpmaNv.TPMA_NV_PLATFORMCREATE;

    /// <summary>
    /// The platform-created Ordinary Index additionally electing <c>TPMA_NV_POLICY_DELETE</c>, which only
    /// Platform Authorization may install (TPM 2.0 Library Part 3, clause 31.3.1).
    /// </summary>
    private const TpmaNv PolicyDeleteAttributes = PlatformCreatedAttributes | TpmaNv.TPMA_NV_POLICY_DELETE;

    /// <summary>
    /// PIN Fail attributes with the spec-mandated <c>TPMA_NV_NO_DA</c> SET (TPM 2.0 Library Part 2, clause 13.4)
    /// and <c>TPMA_NV_AUTHWRITE</c> CLEAR (Part 1, clause 34.2.6.1), defined under Owner Authorization.
    /// </summary>
    private const TpmaNv PinFailAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA
        | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_FAIL << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>Counter attributes authorizing increment and read with the Index authValue, defined under Owner Authorization.</summary>
    private const TpmaNv CounterAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA
        | (TpmaNv)((uint)TpmNt.TPM_NT_COUNTER << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The Index authorization value (and, for a PIN Index, the correct PIN) used throughout.</summary>
    private static byte[] IndexAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong authorization value, distinct from every value these tests install.</summary>
    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>The platformAuth value installed over the factory-empty one where an installed value is under test.</summary>
    private static byte[] InstalledPlatformAuth { get; } = [0x5E, 0x4D, 0x3C, 0x2B, 0x1A];

    /// <summary>
    /// The four octets of <c>TPM_RH_PLATFORM</c>, supplied as cpHash's Name1 term where a test proves that term
    /// rather than leaving the host to derive it (TPM 2.0 Library Part 1, clause 13, Table 9).
    /// </summary>
    private static byte[] PlatformHandleName { get; } = [0x40, 0x00, 0x00, 0x0C];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "An Index with TPMA_NV_PLATFORMCREATE CLEAR may be deleted with Platform Authorization as long as
    /// shEnable is SET" - the platform arm on a factory-state TPM, whose platformAuth is the Empty Buffer,
    /// removes an Index the owner defined, and the removal is real: the handle answers <c>TPM_RC_HANDLE</c>
    /// afterwards.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.4.1; Part 2, clause 9.21, Table 67</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceUnderTheFactoryEmptyPlatformAuthDeletesAnOwnerCreatedIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, OwnerCreatedIndexHandle, OwnerCreatedAttributes, OrdinaryDataSize).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> result = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, OwnerCreatedIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"Clause 31.4.1's Note admits Platform Authorization against an owner-created Index while shEnable is SET: '{result.ResponseCode}'.");

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), await ProbeIndexAsync(device, OwnerCreatedIndexHandle).ConfigureAwait(false),
            "Clause 31.4.1 removes the Index from the TPM, so its handle is no longer defined.");
    }

    /// <summary>
    /// The same platform arm once platformAuth is a real value: "This command removes an Index from the TPM",
    /// and the authorization the removal requires is compared against the hierarchy's live carrier rather than
    /// the factory one, so a rotated platformAuth is what authorizes it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.4.1 and 24.8; Part 1, clause 16.6.4.3</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceUnderAnInstalledPlatformAuthDeletesAnOwnerCreatedIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, OwnerCreatedIndexHandle, OwnerCreatedAttributes, OrdinaryDataSize).ConfigureAwait(false);
        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> refusedWithTheFactoryValue = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, OwnerCreatedIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), refusedWithTheFactoryValue.ResponseCode,
            "Once platformAuth is rotated the superseded value must no longer authorize clause 31.4's removal.");

        TpmResult<NvUndefineSpaceResponse> result = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, OwnerCreatedIndexHandle, InstalledPlatformAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The installed platformAuth must authorize the removal: '{result.ResponseCode}'.");

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), await ProbeIndexAsync(device, OwnerCreatedIndexHandle).ConfigureAwait(false),
            "Clause 31.4.1 removes the Index from the TPM, so its handle is no longer defined.");
    }

    /// <summary>
    /// "SET (1): This Index may be undefined with Platform Authorization but not with Owner Authorization" -
    /// the platform arm against the Index population the bit names as its own: a definition the platform
    /// authorized, carrying <c>TPMA_NV_PLATFORMCREATE</c>, is removed by Platform Authorization.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 13.4, Table 249, bit 30; Part 3, clause 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceUnderPlatformAuthDeletesAPlatformCreatedIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PlatformCreatedIndexHandle, PlatformCreatedAttributes, OrdinaryDataSize).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> result = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PlatformCreatedIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"Table 249's bit 30 names Platform Authorization as this Index's deletion authority: '{result.ResponseCode}'.");

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), await ProbeIndexAsync(device, PlatformCreatedIndexHandle).ConfigureAwait(false),
            "Clause 31.4.1 removes the Index from the TPM, so its handle is no longer defined.");
    }

    /// <summary>
    /// The converse half of the same bit - "CLEAR (0): This Index may be undefined using Owner Authorization
    /// but not with Platform Authorization" - proving the widened <c>@authHandle</c> did not displace the owner
    /// arm: an owner-created Index still deletes under Owner Authorization.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 13.4, Table 249, bit 30; Part 3, clause 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceUnderOwnerAuthDeletesAnOwnerCreatedIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, OwnerCreatedIndexHandle, OwnerCreatedAttributes, OrdinaryDataSize).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> result = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, OwnerCreatedIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"An Index with TPMA_NV_PLATFORMCREATE CLEAR must still delete under Owner Authorization: '{result.ResponseCode}'.");

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), await ProbeIndexAsync(device, OwnerCreatedIndexHandle).ConfigureAwait(false),
            "Clause 31.4.1 removes the Index from the TPM, so its handle is no longer defined.");
    }

    /// <summary>
    /// The platform arm over an unbound, unsalted HMAC session. "This command removes an Index from the TPM",
    /// and the command HMAC that authorizes the removal verifies against a cpHash whose Name1 is the four
    /// octets <c>40 00 00 0C</c> - "If the Name is a handle, the Name is only the handle value" (Part 1, clause
    /// 13, Table 9), supplied here by hand rather than derived, so the term itself is under proof - and whose Name2 is the Index's own
    /// computed Name, with an empty parameters term because Part 3's Table 247 defines no command parameters. An
    /// installed platformAuth is what makes the HMAC key genuinely secret-keyed, and the executor's own
    /// verification of the response authorization is what makes the returned success meaningful.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.4.1; Part 1, clause 15.7, equation 15, and clause 13, Table 9</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOverHmacSessionUnderPlatformAuthDeletesAnOwnerCreatedIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, OwnerCreatedIndexHandle, OwnerCreatedAttributes, OrdinaryDataSize).ConfigureAwait(false);
        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        byte[] indexName = await ReadIndexNameAsync(device, OwnerCreatedIndexHandle).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> result = await UndefineIndexOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, OwnerCreatedIndexHandle, InstalledPlatformAuth,
            [PlatformHandleName, indexName]).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The session form's cpHash folds Name1 = 40 00 00 0C and Name2 = the Index Name, and its response authorization must verify: '{result.ResponseCode}'.");

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), await ProbeIndexAsync(device, OwnerCreatedIndexHandle).ConfigureAwait(false),
            "Clause 31.4.1 removes the Index from the TPM, so its handle is no longer defined.");
    }

    /// <summary>
    /// "If the authorization is for the entity to which the session is bound, the HMAC key is the session's
    /// sessionKey" - a session BOUND to <c>TPM_RH_PLATFORM</c> authorizes the platform arm with the authValue
    /// term omitted, and the TPM mirrors the omission on the response authorization, which the executor
    /// verifies with the session key alone. The installed non-empty platformAuth is what makes the omission
    /// observable: a TPM that folded it anyway would key the command HMAC differently and refuse.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.10, equation 22; Part 3, clause 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOverASessionBoundToThePlatformHierarchyDeletesWithTheAuthValueOmitted()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, OwnerCreatedIndexHandle, OwnerCreatedAttributes, OrdinaryDataSize).ConfigureAwait(false);
        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        byte[] indexName = await ReadIndexNameAsync(device, OwnerCreatedIndexHandle).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartBoundHmacSessionAsync(
            device, registry, pool, (uint)TpmRh.TPM_RH_PLATFORM, InstalledPlatformAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                TpmResult<NvUndefineSpaceResponse> result = await UndefineIndexOverSessionAsync(
                    device, pool, registry, session, TpmRh.TPM_RH_PLATFORM, OwnerCreatedIndexHandle, ReadOnlyMemory<byte>.Empty,
                    [PlatformHandleName, indexName]).ConfigureAwait(false);
                Assert.IsTrue(
                    result.IsSuccess,
                    $"The bind omission must authorize the platform arm and be mirrored on the response authorization: '{result.ResponseCode}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), await ProbeIndexAsync(device, OwnerCreatedIndexHandle).ConfigureAwait(false),
            "A bind-authorized command applies clause 31.4.1's effect exactly as an explicitly authorized one does.");
    }

    /// <summary>
    /// "If nvIndex references an Index that has its TPMA_NV_PLATFORMCREATE attribute SET, the TPM shall return
    /// TPM_RC_NV_AUTHORIZATION unless Platform Authorization is provided" - the password form: a
    /// correctly-authorized owner request against a platform-created Index is refused on the authority the
    /// Index records, not on the authValue it proved, and the Index survives the refusal.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOfAPlatformCreatedIndexUnderOwnerAuthReturnsNvAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PlatformCreatedIndexHandle, PlatformCreatedAttributes, OrdinaryDataSize).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> result = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, PlatformCreatedIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode,
            "Clause 31.4.1 answers TPM_RC_NV_AUTHORIZATION for a PLATFORMCREATE Index unless Platform Authorization is provided.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, await ProbeIndexAsync(device, PlatformCreatedIndexHandle).ConfigureAwait(false),
            "A refused removal leaves the Index defined.");
    }

    /// <summary>
    /// The same sentence over an HMAC session: "If nvIndex references an Index that has its
    /// TPMA_NV_PLATFORMCREATE attribute SET, the TPM shall return TPM_RC_NV_AUTHORIZATION unless Platform
    /// Authorization is provided". The gate runs after the command HMAC has verified, so the answer is the
    /// unencoded format-zero body-gate code rather than a session-encoded authorization failure.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOverHmacSessionOfAPlatformCreatedIndexUnderOwnerAuthReturnsNvAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PlatformCreatedIndexHandle, PlatformCreatedAttributes, OrdinaryDataSize).ConfigureAwait(false);

        byte[] indexName = await ReadIndexNameAsync(device, PlatformCreatedIndexHandle).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> result = await UndefineIndexOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, PlatformCreatedIndexHandle, ReadOnlyMemory<byte>.Empty,
            [ReadOnlyMemory<byte>.Empty, indexName]).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode,
            "Clause 31.4.1's PLATFORMCREATE gate answers identically on the session form, unencoded rather than session-encoded.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, await ProbeIndexAsync(device, PlatformCreatedIndexHandle).ConfigureAwait(false),
            "A refused removal leaves the Index defined.");
    }

    /// <summary>
    /// "If nvIndex references an Index that has its TPMA_NV_POLICY_DELETE attribute SET, the TPM shall return
    /// TPM_RC_ATTRIBUTES" - the owner arm, password form. Such an Index is removable only through
    /// <c>TPM2_NV_UndefineSpaceSpecial()</c>'s ADMIN-role policy, so this command refuses it whatever
    /// authorization it carries.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.4.1; Part 2, clause 13.4, Table 249, bit 10</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOfAPolicyDeleteIndexUnderOwnerAuthReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PolicyDeleteIndexHandle, PolicyDeleteAttributes, OrdinaryDataSize).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> result = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, PolicyDeleteIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode,
            "Clause 31.4.1 answers TPM_RC_ATTRIBUTES for a TPMA_NV_POLICY_DELETE Index under Owner Authorization.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, await ProbeIndexAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false),
            "A refused removal leaves the Index defined.");
    }

    /// <summary>
    /// The same sentence under the authority that defined the Index: "If nvIndex references an Index that has
    /// its TPMA_NV_POLICY_DELETE attribute SET, the TPM shall return TPM_RC_ATTRIBUTES". Platform Authorization
    /// buys no exemption here - the attribute closes this command to every hierarchy, which is what makes an
    /// Empty-Policy Index of this kind permanently undeletable.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.4.1; Part 1, clause 34.2.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOfAPolicyDeleteIndexUnderPlatformAuthReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PolicyDeleteIndexHandle, PolicyDeleteAttributes, OrdinaryDataSize).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> result = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode,
            "Clause 31.4.1's TPMA_NV_POLICY_DELETE refusal is hierarchy-independent: Platform Authorization is refused just the same.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, await ProbeIndexAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false),
            "A refused removal leaves the Index defined.");
    }

    /// <summary>
    /// "If nvIndex references an Index that has its TPMA_NV_POLICY_DELETE attribute SET, the TPM shall return
    /// TPM_RC_ATTRIBUTES" - the owner arm over an HMAC session, where the gate is reached only once the command
    /// HMAC has verified, so the answer names nvIndex, handle 2 of Table 247, exactly as the password form does.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOverHmacSessionOfAPolicyDeleteIndexUnderOwnerAuthReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PolicyDeleteIndexHandle, PolicyDeleteAttributes, OrdinaryDataSize).ConfigureAwait(false);

        byte[] indexName = await ReadIndexNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> result = await UndefineIndexOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, PolicyDeleteIndexHandle, ReadOnlyMemory<byte>.Empty,
            [ReadOnlyMemory<byte>.Empty, indexName]).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode,
            "Clause 31.4.1's TPMA_NV_POLICY_DELETE refusal answers identically on the session form.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, await ProbeIndexAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false),
            "A refused removal leaves the Index defined.");
    }

    /// <summary>
    /// The fourth corner of the same sentence: the platform arm over an HMAC session against a
    /// <c>TPMA_NV_POLICY_DELETE</c> Index is "TPM_RC_ATTRIBUTES", proving the refusal is a property of the
    /// Index rather than of the authorization mechanism or of the hierarchy that supplied it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOverHmacSessionOfAPolicyDeleteIndexUnderPlatformAuthReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PolicyDeleteIndexHandle, PolicyDeleteAttributes, OrdinaryDataSize).ConfigureAwait(false);
        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        byte[] indexName = await ReadIndexNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> result = await UndefineIndexOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, InstalledPlatformAuth,
            [PlatformHandleName, indexName]).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode,
            "Clause 31.4.1's TPMA_NV_POLICY_DELETE refusal binds the platform arm's session form too.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, await ProbeIndexAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false),
            "A refused removal leaves the Index defined.");
    }

    /// <summary>
    /// The order pin between the authorization and the body: a WRONG platformAuth against a
    /// <c>TPMA_NV_POLICY_DELETE</c> Index answers the authorization failure, not clause 31.4.1's
    /// "TPM_RC_ATTRIBUTES". "The authValue associated with a permanent entity, other than TPM_RH_LOCKOUT, does
    /// not receive DA protection", so that failure is the non-charging <c>TPM_RC_BAD_AUTH</c>, and the correct
    /// platformAuth against the same Index then reaches the attribute gate - which is what proves the two
    /// answers are ordered rather than merely different.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.4.1 and 5.5; Part 1, clause 16.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOfAPolicyDeleteIndexWithAWrongPlatformAuthReturnsBadAuthAheadOfTheAttributeGate()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PolicyDeleteIndexHandle, PolicyDeleteAttributes, OrdinaryDataSize).ConfigureAwait(false);
        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> misAuthorized = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), misAuthorized.ResponseCode,
            "The authorization is judged before clause 31.4.1's body gates, so a wrong platformAuth answers the authorization failure and never TPM_RC_ATTRIBUTES.");
        Assert.AreEqual(
            counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "Clause 16.8.1: a dictionary-attack-exempt permanent entity must never charge failedTries.");

        TpmResult<NvUndefineSpaceResponse> correctlyAuthorized = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PolicyDeleteIndexHandle, InstalledPlatformAuth).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), correctlyAuthorized.ResponseCode,
            "Only a request that clears the authorization reaches clause 31.4.1's TPMA_NV_POLICY_DELETE refusal.");
    }

    /// <summary>
    /// The handle-area-before-authorization order (Part 3, clause 5.4: "A TPM is required to perform the handle
    /// area validation before the authorization checks"): a WRONG platformAuth against an UNDEFINED Index
    /// answers the Index probe's <c>TPM_RC_HANDLE</c>, never the authValue compare's <c>TPM_RC_BAD_AUTH</c> - the
    /// Index's presence is a handle-area outcome and resolves before the authorization checks the authorizing
    /// hierarchy still needs, on the password form.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.4; clause 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOfAnUndefinedIndexWithAWrongPlatformAuthReturnsHandleAheadOfTheAuthValueCompare()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> result = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, UndefinedIndexForPasswordOrderPinHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), result.ResponseCode,
            "The Index probe is a handle-area outcome (clause 5.4) and resolves ahead of the authValue compare, so an undefined Index answers TPM_RC_HANDLE even under a wrong platformAuth.");
    }

    /// <summary>
    /// The session form's own copy of the same order: a WRONG platformAuth over an HMAC session against an
    /// UNDEFINED Index answers <c>TPM_RC_HANDLE</c> from the Index probe, naming nvIndex (handle 2 of Table 247),
    /// before the session or its command HMAC are ever consulted - the handle area resolves first regardless of
    /// authorization mechanism.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.4; clause 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOverAnHmacSessionOfAnUndefinedIndexWithAWrongPlatformAuthReturnsHandleAheadOfTheAuthValueCompare()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> result = await UndefineIndexOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, UndefinedIndexForSessionOrderPinHandle, WrongAuth,
            [PlatformHandleName, PlatformHandleName]).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), result.ResponseCode,
            "The Index probe precedes session resolution and the command-HMAC compare alike, so the session form designates nvIndex, handle 2 of Table 247, exactly as the password form does.");
    }

    /// <summary>
    /// The order pin between clause 31.4.1's two body gates. The clause states them as "If nvIndex references
    /// an Index that has its TPMA_NV_PLATFORMCREATE attribute SET, the TPM shall return
    /// TPM_RC_NV_AUTHORIZATION unless Platform Authorization is provided. If nvIndex references an Index that
    /// has its TPMA_NV_POLICY_DELETE attribute SET, the TPM shall return TPM_RC_ATTRIBUTES", and an Index
    /// carrying BOTH attributes distinguishes them: under Owner Authorization the answer is the attribute code,
    /// while the sibling Index carrying <c>TPMA_NV_PLATFORMCREATE</c> alone answers
    /// <c>TPM_RC_NV_AUTHORIZATION</c> under the very same authorization.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOfAPolicyDeleteIndexUnderOwnerAuthAnswersAttributesAheadOfNvAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PolicyDeleteIndexHandle, PolicyDeleteAttributes, OrdinaryDataSize).ConfigureAwait(false);
        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PlatformCreatedIndexHandle, PlatformCreatedAttributes, OrdinaryDataSize).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> platformCreateOnly = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, PlatformCreatedIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_AUTHORIZATION, platformCreateOnly.ResponseCode,
            "An Index carrying TPMA_NV_PLATFORMCREATE alone answers the authorization-attribute code under Owner Authorization.");

        TpmResult<NvUndefineSpaceResponse> bothAttributes = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, PolicyDeleteIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), bothAttributes.ResponseCode,
            "An Index carrying both attributes answers TPM_RC_ATTRIBUTES: the TPMA_NV_POLICY_DELETE gate is decided ahead of the TPMA_NV_PLATFORMCREATE one.");
    }

    /// <summary>
    /// "If shEnable is CLEAR, indexes created using Owner Authorization are not accessible even for deletion by
    /// the platform" - with <c>shEnable</c> CLEARed under Platform Authorization the owner-created Index is
    /// <c>TPM_RC_HANDLE</c> to the platform arm, exactly as an undefined handle would be, and SETting the
    /// enable again restores the reach: the very same request then removes it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.4.1; clause 24.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceUnderPlatformAuthWhileShEnableIsClearReturnsHandleAndDeletesOnceReEnabled()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, OwnerCreatedIndexHandle, OwnerCreatedAttributes, OrdinaryDataSize).ConfigureAwait(false);
        await SetHierarchyEnableAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, TpmiYesNo.No).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> hiddenResult = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, OwnerCreatedIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), hiddenResult.ResponseCode,
            "Clause 31.4.1's Note: while shEnable is CLEAR an owner-created Index is not accessible even for deletion by the platform.");

        await SetHierarchyEnableAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, TpmiYesNo.Yes).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> restoredResult = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, OwnerCreatedIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(
            restoredResult.IsSuccess,
            $"With shEnable SET again the same platform-authorized removal must succeed, proving the refusal was the enable and not the Index: '{restoredResult.ResponseCode}'.");
    }

    /// <summary>
    /// "As long as phEnableNV is CLEAR, the TPM will return an error in response to any command that attempts
    /// to operate upon an NV index that has TPMA_NV_PLATFORMCREATE SET" - the platform-created Index is
    /// <c>TPM_RC_HANDLE</c> at this command while that enable is CLEAR, and the enable reaches the Index rather
    /// than the authorizing hierarchy: an owner-created Index still deletes under the very same Platform
    /// Authorization.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 24.2.1; clause 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceWhilePhEnableNvIsClearReturnsHandleForAPlatformCreatedIndexWhileAnOwnerCreatedOneDeletes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PlatformCreatedIndexHandle, PlatformCreatedAttributes, OrdinaryDataSize).ConfigureAwait(false);
        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, OwnerCreatedIndexHandle, OwnerCreatedAttributes, OrdinaryDataSize).ConfigureAwait(false);
        await SetHierarchyEnableAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM_NV, TpmiYesNo.No).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> hiddenResult = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PlatformCreatedIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), hiddenResult.ResponseCode,
            "Clause 24.2.1: while phEnableNV is CLEAR an Index with TPMA_NV_PLATFORMCREATE SET is not accessible to any command.");

        TpmResult<NvUndefineSpaceResponse> reachableResult = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, OwnerCreatedIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(
            reachableResult.IsSuccess,
            $"phEnableNV gates the Index population, not the authorizing hierarchy, so an owner-created Index still deletes under Platform Authorization: '{reachableResult.ResponseCode}'.");
    }

    /// <summary>
    /// "An Index with TPMA_NV_PLATFORMCREATE CLEAR may be deleted with Platform Authorization as long as
    /// shEnable is SET" applied to an exhausted PIN Fail Index: the platform is trusted to remove any Index
    /// whichever hierarchy defined it, so it is the escape hatch from a PIN throttle at its limit that Owner
    /// Authorization alone need not provide, and the redefinition that follows starts a fresh throttle.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.4.1; Part 1, clause 34.2.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceUnderPlatformAuthDeletesAnExhaustedPinFailIndexAndTheRedefinitionStartsAFreshThrottle()
    {
        const uint PinLimit = 1;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, PinFailIndexHandle, PinFailAttributes, EightOctetDataSize).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinFailIndexHandle, pinCount: 0, PinLimit).ConfigureAwait(false);

        TpmResult<NvReadResponse> exhaustingFailure = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, WrongAuth).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), exhaustingFailure.ResponseCode, "One wrong PIN against pinLimit == 1 must exhaust the throttle.");

        TpmResult<NvReadResponse> blockedResult = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, IndexAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, blockedResult.ResponseCode, "The correct PIN must be refused once the throttle is exhausted.");

        TpmResult<NvUndefineSpaceResponse> platformRemoval = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PinFailIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(
            platformRemoval.IsSuccess,
            $"Clause 31.4.1's Note admits Platform Authorization against an owner-created Index: '{platformRemoval.ResponseCode}'.");

        TpmResult<NvDefineSpaceResponse> redefineResult = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, PinFailIndexHandle, PinFailAttributes, EightOctetDataSize).ConfigureAwait(false);
        Assert.IsTrue(redefineResult.IsSuccess, $"The freed handle must accept a fresh definition: '{redefineResult.ResponseCode}'.");

        await WritePinCounterParametersAsync(device, pool, registry, PinFailIndexHandle, pinCount: 0, PinLimit).ConfigureAwait(false);

        TpmResult<NvReadResponse> freshThrottleResult = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, IndexAuth).ConfigureAwait(false);
        Assert.IsTrue(freshThrottleResult.IsSuccess, $"The redefined Index must accept the correct PIN on a fresh throttle: '{freshThrottleResult.ResponseCode}'.");

        using NvReadResponse counters = freshThrottleResult.Value;
        Assert.AreEqual(
            0u, ReadPinCount(counters.Data),
            "A successful PIN Fail authorization below the limit resets pinCount, so the fresh throttle reads back at zero.");
    }

    /// <summary>
    /// The other side of that escape hatch, as a regression on the unauthenticated-undefine exploit: "The
    /// authValue associated with a permanent entity, other than TPM_RH_LOCKOUT, does not receive DA protection",
    /// so a WRONG platformAuth is the non-charging <c>TPM_RC_BAD_AUTH</c> - and, crucially, the exhausted PIN
    /// Fail Index survives it with its throttle intact, so the refused removal composed with a redefinition is
    /// no throttle-reset primitive.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 3, clause 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOfAnExhaustedPinFailIndexWithAWrongPlatformAuthIsRefusedUnchargedAndLeavesTheThrottleExhausted()
    {
        const uint PinLimit = 1;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, PinFailIndexHandle, PinFailAttributes, EightOctetDataSize).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinFailIndexHandle, pinCount: 0, PinLimit).ConfigureAwait(false);
        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        TpmResult<NvReadResponse> exhaustingFailure = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, WrongAuth).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), exhaustingFailure.ResponseCode, "One wrong PIN against pinLimit == 1 must exhaust the throttle.");

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> exploitAttempt = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PinFailIndexHandle, WrongAuth).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), exploitAttempt.ResponseCode,
            "An unauthenticated removal must be refused, not silently succeed.");
        Assert.AreEqual(
            counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "Clause 16.8.1: a dictionary-attack-exempt permanent entity must never charge failedTries, even on a refusal.");

        TpmResult<NvDefineSpaceResponse> redefineAttempt = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, PinFailIndexHandle, PinFailAttributes, EightOctetDataSize).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_DEFINED, redefineAttempt.ResponseCode,
            "The Index must still be defined - the removal never ran - so a redefinition collides rather than starting a fresh throttle.");

        TpmResult<NvReadResponse> stillBlockedResult = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, IndexAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, stillBlockedResult.ResponseCode,
            "The exhausted Index must remain in place and still blocked - the refused removal achieved nothing.");
    }

    /// <summary>
    /// The effect the platform route carries alongside the removal: on the first increment of an unwritten
    /// Counter Index "the TPM will initialize the 8-octet counter value such that the first increment will set
    /// a value that is greater than any value that a counter Index with the same Name has had over the lifetime
    /// of the TPM". A platform-authorized removal of a written Counter must therefore retire its value into the
    /// phantom high-water mark, so a redefinition at the same handle seeds above every value the deleted
    /// counter reported rather than restarting at one.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.3; Part 3, clause 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceUnderPlatformAuthOfAWrittenCounterRetiresThePhantomHighWaterMark()
    {
        const int IncrementsBeforeRemoval = 4;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, CounterIndexHandle, CounterAttributes, EightOctetDataSize).ConfigureAwait(false);

        for(int increment = 0; increment < IncrementsBeforeRemoval; increment++)
        {
            TpmResult<NvIncrementResponse> seedingResult = await IncrementAsync(device, pool, registry, CounterIndexHandle, IndexAuth).ConfigureAwait(false);
            Assert.IsTrue(seedingResult.IsSuccess, $"Seeding increment {increment + 1} must succeed: '{seedingResult.ResponseCode}'.");
        }

        TpmResult<NvUndefineSpaceResponse> platformRemoval = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, CounterIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(platformRemoval.IsSuccess, $"The platform-authorized removal must succeed: '{platformRemoval.ResponseCode}'.");

        TpmResult<NvDefineSpaceResponse> redefineResult = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, CounterIndexHandle, CounterAttributes, EightOctetDataSize).ConfigureAwait(false);
        Assert.IsTrue(redefineResult.IsSuccess, $"The freed handle must accept a fresh definition: '{redefineResult.ResponseCode}'.");

        TpmResult<NvIncrementResponse> firstIncrementAfterRemoval = await IncrementAsync(device, pool, registry, CounterIndexHandle, IndexAuth).ConfigureAwait(false);
        Assert.IsTrue(firstIncrementAfterRemoval.IsSuccess, $"The first increment after the redefinition must succeed: '{firstIncrementAfterRemoval.ResponseCode}'.");

        TpmResult<NvReadResponse> readResult = await ReadIndexAsync(device, pool, registry, CounterIndexHandle, IndexAuth).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"The read-back must succeed: '{readResult.ResponseCode}'.");

        using NvReadResponse counterValue = readResult.Value;
        Assert.IsGreaterThan(
            (ulong)IncrementsBeforeRemoval, BinaryPrimitives.ReadUInt64BigEndian(counterValue.Data),
            "Clause 34.2.6.3: the redefined counter's first increment must exceed every value the removed counter with the same Name reported.");
    }

    /// <summary>
    /// Table 67 admits exactly two values on <c>@authHandle</c>, "TPM_RH_OWNER handle for Owner Authorization"
    /// and "TPM_RH_PLATFORM handle for Platform Authorization", and names "#TPM_RC_VALUE response code returned
    /// when the unmarshaling of this type fails" for anything else - so widening the arm to admit
    /// <c>TPM_RH_PLATFORM</c> leaves every other handle refused with the interface type's own answer, naming
    /// authHandle (handle 1 of Table 247), ahead of the enable, the authorization and the Index probe alike.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.21, Table 67; Part 3, clause 31.4.2, Table 247</see>.
    /// </summary>
    /// <param name="inadmissibleAuthHandle">The handle offered on <c>@authHandle</c>, outside <c>TPMI_RH_PROVISION</c>'s admitted set.</param>
    [TestMethod]
    [DataRow((uint)TpmRh.TPM_RH_ENDORSEMENT, DisplayName = "TPM_RH_ENDORSEMENT")]
    [DataRow((uint)TpmRh.TPM_RH_LOCKOUT, DisplayName = "TPM_RH_LOCKOUT")]
    [DataRow((uint)TpmRh.TPM_RH_NULL, DisplayName = "TPM_RH_NULL")]
    [DataRow((uint)TpmRh.TPM_RH_PLATFORM_NV, DisplayName = "TPM_RH_PLATFORM_NV")]
    [DataRow(NvIndexRangeHandle, DisplayName = "an NV Index handle")]
    [DataRow(TransientRangeHandle, DisplayName = "a transient object handle")]
    public async Task NvUndefineSpaceWithANonProvisionAuthHandleReturnsValue(uint inadmissibleAuthHandle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, OwnerCreatedIndexHandle, OwnerCreatedAttributes, OrdinaryDataSize).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> result = await UndefineIndexAsync(
            device, pool, registry, (TpmRh)inadmissibleAuthHandle, OwnerCreatedIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode,
            "Part 2 Table 67 answers TPM_RC_VALUE when TPMI_RH_PROVISION fails to unmarshal, designating authHandle, handle 1 of Table 247, session-independent.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, await ProbeIndexAsync(device, OwnerCreatedIndexHandle).ConfigureAwait(false),
            "A refused removal leaves the Index defined.");
    }

    /// <summary>
    /// "This command removes an Index from the TPM" - and it returns every carrier the round trip rented while
    /// doing so. The metered pool returns to its post-definition balance after a refusal at the value compare,
    /// and to its pre-definition balance after the accepting transition, which is the Index's own retained
    /// authValue carrier being released at the ownership-end boundary the deletion is.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceReturnsItsCarriersAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        long baseline = trackingPool.OutstandingCount;

        await DefineIndexAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, SecondOwnerCreatedIndexHandle, OwnerCreatedAttributes, OrdinaryDataSize).ConfigureAwait(false);

        long withIndexDefined = trackingPool.OutstandingCount;

        TpmResult<NvUndefineSpaceResponse> refused = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, SecondOwnerCreatedIndexHandle, WrongAuth).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), refused.ResponseCode,
            "Platform authorization is DA-exempt (clause 16.8.1), so a wrong platformAuth against a defined, accessible Index is the plain TPM_RC_BAD_AUTH.");
        Assert.AreEqual(
            withIndexDefined, trackingPool.OutstandingCount,
            "A refusal at the value compare releases the supplied credential through the request's own Dispose and leaves the Index's carriers alone.");

        TpmResult<NvUndefineSpaceResponse> accepted = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, SecondOwnerCreatedIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(accepted.IsSuccess, $"TPM2_NV_UndefineSpace() failed: '{accepted.ResponseCode}'.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The accepting transition is the Index's ownership-end boundary and releases its retained authValue carrier along with the supplied credential.");
    }

    /// <summary>Creates a response codec registry for the commands these tests drive.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateNvRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_NV_Increment, TpmResponseCodec.NvIncrement)
            .Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl)
            .Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>
    /// Issues <c>TPM2_NV_DefineSpace()</c> for <paramref name="nvIndex"/> with <see cref="IndexAuth"/> as the
    /// Index authValue and an empty <c>authPolicy</c>, authorized by <paramref name="authHandle"/> over a
    /// password session - the provisioning arm whose hierarchy determines whether
    /// <c>TPMA_NV_PLATFORMCREATE</c> must be SET or CLEAR (TPM 2.0 Library Part 3, clause 31.3.1).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The provisioning hierarchy that authorizes the definition.</param>
    /// <param name="authSupplied">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <param name="dataSize">The declared data size.</param>
    /// <returns>The define-space result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh authHandle, ReadOnlyMemory<byte> authSupplied, uint nvIndex,
        TpmaNv attributes, ushort dataSize)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(authSupplied.Span, pool);

        //The input takes ownership of the auth value and public area and disposes them; the redundant using
        //locals satisfy CA2000 and are safe because both types have idempotent disposal.
        using var auth = Tpm2bAuth.Create(IndexAuth, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, dataSize);
        using var input = new NvDefineSpaceInput(authHandle, auth, publicInfo);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues a password-authorized <c>TPM2_NV_UndefineSpace()</c> against <paramref name="nvIndex"/> under
    /// <paramref name="authHandle"/> (TPM 2.0 Library Part 3, clause 31.4).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The provisioning-hierarchy handle to authorize with, admissible or not.</param>
    /// <param name="nvIndex">The Index to undefine.</param>
    /// <param name="authSupplied">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <returns>The undefine-space result.</returns>
    private async Task<TpmResult<NvUndefineSpaceResponse>> UndefineIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh authHandle, uint nvIndex, ReadOnlyMemory<byte> authSupplied)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(authSupplied.Span, pool);
        var input = new NvUndefineSpaceInput(authHandle, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues <c>TPM2_NV_UndefineSpace()</c> over a freshly started UNBOUND, unsalted HMAC session whose
    /// authValue term is <paramref name="suppliedAuth"/>, flushing the session afterwards.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="nvIndex">The Index to undefine.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="handleNames">The Name terms cpHash folds, in handle order.</param>
    /// <returns>The undefine-space result.</returns>
    private async Task<TpmResult<NvUndefineSpaceResponse>> UndefineIndexOverHmacAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth,
        ReadOnlyMemory<byte>[] handleNames)
    {
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, suppliedAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                return await UndefineIndexOverSessionAsync(device, pool, registry, session, authHandle, nvIndex, suppliedAuth, handleNames).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Issues <c>TPM2_NV_UndefineSpace()</c> over a CALLER-OWNED session, folding
    /// <paramref name="suppliedAuth"/> as the entity authValue term (empty composes the bind-omission form on a
    /// session bound to the authorized hierarchy).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="session">The authorizing session.</param>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="nvIndex">The Index to undefine.</param>
    /// <param name="suppliedAuth">The authValue term to fold, or empty for the omission form.</param>
    /// <param name="handleNames">The Name terms cpHash folds, in handle order.</param>
    /// <returns>The undefine-space result.</returns>
    private async Task<TpmResult<NvUndefineSpaceResponse>> UndefineIndexOverSessionAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmSession session, TpmRh authHandle, uint nvIndex,
        ReadOnlyMemory<byte> suppliedAuth, ReadOnlyMemory<byte>[] handleNames)
    {
        session.SetAuthValue(suppliedAuth.Span, pool);
        var input = new NvUndefineSpaceInput(authHandle, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            device, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

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

    /// <summary>Installs <see cref="InstalledPlatformAuth"/> as <c>platformAuth</c> over the factory-empty value.</summary>
    /// <param name="device">The TPM device.</param>
    private async Task InstallPlatformAuthAsync(TpmDevice device)
    {
        TpmResult<HierarchyChangeAuthResponse> result = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, InstalledPlatformAuth, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Installing platformAuth failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Writes <paramref name="state"/> into <paramref name="hierarchy"/>'s enable through a
    /// password-authorized <c>TPM2_HierarchyControl()</c> under Platform Authorization, asserting the write
    /// succeeded - Platform Authorization may CLEAR or SET any enable (TPM 2.0 Library Part 3, clause 24.2.1).
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
    /// Issues an Index-authValue <c>TPM2_NV_Read()</c> over that Index's full declared window, which is how a
    /// PIN Index's counters and a Counter Index's value are observed and how a removed Index's absence is felt
    /// from the authorization side.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to read.</param>
    /// <param name="suppliedAuth">The authValue supplied for the Index.</param>
    /// <returns>The read result; on success, the caller owns and must dispose <see cref="TpmResult{T}.Value"/>.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var readInput = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: EightOctetDataSize, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues an OWNER-authorized <c>TPM2_NV_Write()</c> storing <paramref name="pinCount"/> and
    /// <paramref name="pinLimit"/> as the 8-octet <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> blob (TPM 2.0 Library
    /// Part 2, clause 13.3), asserting the provisioning write succeeded. A PIN Index forbids
    /// <c>TPMA_NV_AUTHWRITE</c> (Part 1, clause 34.2.6.1), so the owner-authorized arm is its sole provisioning
    /// path.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to write.</param>
    /// <param name="pinCount">The pinCount value to store.</param>
    /// <param name="pinLimit">The pinLimit value to store.</param>
    private async Task WritePinCounterParametersAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, uint pinCount, uint pinLimit)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using IMemoryOwner<byte> owner = pool.Rent(EightOctetDataSize);
        Memory<byte> blob = owner.Memory[..EightOctetDataSize];
        BinaryPrimitives.WriteUInt32BigEndian(blob.Span, pinCount);
        BinaryPrimitives.WriteUInt32BigEndian(blob.Span[sizeof(uint)..], pinLimit);

        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(blob.Span, pool);
        var writeInput = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, nvIndex, writeInputBuffer, Offset: 0);

        TpmResult<NvWriteResponse> result = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, writeInput, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"Provisioning the PIN counters failed: '{result.ResponseCode}'.");
    }

    /// <summary>Issues an Index-authValue <c>TPM2_NV_Increment()</c> against a Counter Index.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Counter Index to increment, which also authorizes the increment.</param>
    /// <param name="suppliedAuth">The authValue supplied for the Index.</param>
    /// <returns>The increment result.</returns>
    private async Task<TpmResult<NvIncrementResponse>> IncrementAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var incrementInput = new NvIncrementInput(nvIndex, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
            device, incrementInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads the pinCount field (the first four octets) from a PIN Index read's returned data.</summary>
    /// <param name="data">The octets <see cref="NvReadResponse.Data"/> returned.</param>
    /// <returns>The pinCount value.</returns>
    private static uint ReadPinCount(ReadOnlySpan<byte> data) => BinaryPrimitives.ReadUInt32BigEndian(data);

    /// <summary>
    /// Reads an Index's Name back from the TPM through <c>TPM2_NV_ReadPublic()</c> - the authoritative source
    /// of a session-authorized command's cpHash Name2 term (TPM 2.0 Library Part 1, clause 13).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Index whose Name is wanted.</param>
    /// <returns>The Index's Name.</returns>
    private async Task<byte[]> ReadIndexNameAsync(TpmDevice device, uint nvIndex)
    {
        TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(nameResult.IsSuccess, $"NvReadPublicAsync(0x{nvIndex:X8}) failed: '{nameResult.ResponseCode}'.");

        using NvReadPublicResponse namePublic = nameResult.Value;

        return namePublic.NvName.Span.ToArray();
    }

    /// <summary>
    /// Probes whether <paramref name="nvIndex"/> is still defined through <c>TPM2_NV_ReadPublic()</c>, the
    /// unauthorized public-area read (TPM 2.0 Library Part 3, clause 31.6), and reports the outcome as a
    /// response code so a removal's effect is observable without an authorization of its own.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Index handle to probe.</param>
    /// <returns><c>TPM_RC_SUCCESS</c> while the Index is defined, otherwise the refusal the probe answered.</returns>
    private async Task<TpmRcConstants> ProbeIndexAsync(TpmDevice device, uint nvIndex)
    {
        TpmResult<NvReadPublicResponse> result = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        if(!result.IsSuccess)
        {
            return result.ResponseCode;
        }

        using NvReadPublicResponse indexPublic = result.Value;

        return TpmRcConstants.TPM_RC_SUCCESS;
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
    /// phase, which is the precondition <c>TPM2_NV_UndefineSpace()</c> carries.
    /// </summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator("tpm-in-house-nv-undefine-space-platform", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitStartupAsync(simulator, BaseMemoryPool.Shared, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
