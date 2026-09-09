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
/// Drives the platform provisioning arm of <c>TPM2_NV_DefineSpace()</c> - the authority
/// <c>TPMA_NV_PLATFORMCREATE</c> records and the consistency rule that binds the two, the
/// <c>TPMA_NV_POLICY_DELETE</c> attribute only Platform Authorization may install, the two enables the platform
/// arm answers to, the dictionary-attack exemption a permanent entity carries, and the two consequences the bit
/// confers downstream (an Index that survives <c>TPM2_Clear()</c> and an Index the owner may still globally
/// write-lock) - against the in-house behavioural <see cref="TpmSimulator"/>, entirely in-process with no
/// external assets, through the same production command path the production code uses
/// (<see cref="TpmCommandExecutor"/> and the real command/response codecs). TPM 2.0 Library Part 3, clauses
/// 31.1, 31.3.1, 24.6.1 and 31.12.1; Part 2, clauses 9.21 and 13.4; Part 1, clauses 15.7, 16.8.1, 18.1, 34.2.2
/// and 34.2.3.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorNvPlatformProvisioningTests
{
    /// <summary>The declared data size of every Ordinary Index this file defines.</summary>
    private const ushort OrdinaryDataSize = 16;

    /// <summary>The SHA-256 digest width, in octets - the Name digest width and the policy digest width used here.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The hash algorithm every Index and every session in this file elects.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The platform-created Index the definition arms install.</summary>
    private const uint PlatformIndexHandle = 0x0100_00D0;

    /// <summary>The owner-created Index used wherever the owner arm is the control.</summary>
    private const uint OwnerIndexHandle = 0x0100_00D5;

    /// <summary>The platform-created Index carrying <c>TPMA_NV_POLICY_DELETE</c> over a real deletion policy.</summary>
    private const uint PolicyDeleteIndexHandle = 0x0100_00D6;

    /// <summary>The platform-created <c>TPMA_NV_POLICY_DELETE</c> Index defined over an Empty Policy.</summary>
    private const uint EmptyPolicyDeleteIndexHandle = 0x0100_00D7;

    /// <summary>The Index handle the attribute-consistency cases define under both authorities in turn.</summary>
    private const uint ConsistencyIndexHandle = 0x0100_00D8;

    /// <summary>The Index handle the session-authorized definition arms install.</summary>
    private const uint SessionIndexHandle = 0x0100_00D9;

    /// <summary>The Index handle the decrypt-authorized definition arm installs.</summary>
    private const uint DecryptIndexHandle = 0x0100_00DA;

    /// <summary>The platform-created Index electing <c>TPMA_NV_GLOBALLOCK</c>.</summary>
    private const uint GlobalLockIndexHandle = 0x0100_00DB;

    /// <summary>A second defined Index, offered as an inadmissible <c>@authHandle</c> value.</summary>
    private const uint SecondaryIndexHandle = 0x0100_00DC;

    /// <summary>The Index handle the pool-balance case defines.</summary>
    private const uint MeteredIndexHandle = 0x0100_00DD;

    /// <summary>The Index handle the session-form phEnable-CLEAR case defines against.</summary>
    private const uint SessionPhEnableIndexHandle = 0x0100_00DE;

    /// <summary>The Index handle the session-form phEnableNV-CLEAR case defines against.</summary>
    private const uint SessionPhEnableNvIndexHandle = 0x0100_00DF;

    /// <summary>The Index handle the session-form pool-balance case defines.</summary>
    private const uint MeteredSessionIndexHandle = 0x0100_00E0;

    /// <summary>A handle in the transient-object range, which <c>TPMI_RH_PROVISION</c> admits no more than an Index handle does.</summary>
    private const uint TransientRangeHandle = 0x8000_0000;

    /// <summary>
    /// The platform hierarchy's own handle, whose Name is those four octets (TPM 2.0 Library Part 1, clause 13,
    /// Table 9) - the <c>Name1</c> term equation 15 folds into this command's cpHash.
    /// </summary>
    private static byte[] PlatformHandleName { get; } = [0x40, 0x00, 0x00, 0x0C];

    /// <summary>A four-octet Name term that is NOT the platform handle's, for the cpHash mismatch twin.</summary>
    private static byte[] ForeignHandleName { get; } = [0x40, 0x00, 0x00, 0x0B];

    /// <summary>
    /// Ordinary Index attributes an owner-authorized definition may carry: readable and writable with the Index
    /// authValue, writable with owner authorization, opted out of dictionary-attack protection so a refusal
    /// elsewhere in a case never moves <c>failedTries</c>.
    /// </summary>
    private const TpmaNv OwnerCreateAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>The same Ordinary Index, claiming <c>TPMA_NV_PLATFORMCREATE</c> - what a platform-authorized definition must carry.</summary>
    private const TpmaNv PlatformCreateAttributes = OwnerCreateAttributes | TpmaNv.TPMA_NV_PLATFORMCREATE;

    /// <summary>The platform-created Index that additionally elects <c>TPMA_NV_POLICY_DELETE</c>.</summary>
    private const TpmaNv PolicyDeleteAttributes = PlatformCreateAttributes | TpmaNv.TPMA_NV_POLICY_DELETE;

    /// <summary>The platform-created Index that additionally elects <c>TPMA_NV_GLOBALLOCK</c>.</summary>
    private const TpmaNv GlobalLockPlatformCreateAttributes = PlatformCreateAttributes | TpmaNv.TPMA_NV_GLOBALLOCK;

    /// <summary>The Index authorization value used throughout.</summary>
    private static byte[] IndexAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong authorization value, distinct from every value these tests install.</summary>
    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>The platformAuth value installed over the factory-empty one where an installed value is under test.</summary>
    private static byte[] InstalledPlatformAuth { get; } = [0x5E, 0x4D, 0x3C, 0x2B, 0x1A];

    /// <summary>The sixteen octets an Ordinary Index is populated with.</summary>
    private static byte[] IndexData { get; } =
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

    /// <summary>
    /// A single-octet payload for a write attempt a lock must refuse; its content is immaterial since the write
    /// never reaches the Index's stored data.
    /// </summary>
    private static byte[] RefusedWriteAttempt { get; } = [0x00];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "If platformAuth/platformPolicy is used for authorization, then TPMA_NV_PLATFORMCREATE shall be SET in
    /// publicInfo" and "The TPM will validate that this attribute is SET when the Index is defined using
    /// Platform Authorization" - a platform-authorized definition on a factory-state TPM, whose platformAuth is
    /// the Empty Buffer, installs the Index, its public area reports the attribute back, and the Name the TPM
    /// reports equals the independently transcribed digest over a <c>TPMS_NV_PUBLIC</c> carrying that bit, so
    /// the attribute is inside the Index's identity rather than beside it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.3.1; Part 2, clause 13.4, Table 249; Part 1, clause 13</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceUnderTheFactoryEmptyPlatformAuthInstallsAPlatformCreatedIndexWhoseNameFoldsTheAttribute()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PlatformIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The platform arm under the factory-empty platformAuth must define the Index: '{result.ResponseCode}'.");

        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(PlatformIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(publicResult.IsSuccess, $"The defined Index's public area must read back: '{publicResult.ResponseCode}'.");

        using NvReadPublicResponse indexPublic = publicResult.Value;
        Assert.AreEqual(
            TpmaNv.TPMA_NV_PLATFORMCREATE, indexPublic.NvPublic.Attributes & TpmaNv.TPMA_NV_PLATFORMCREATE,
            "Clause 31.3.1 requires TPMA_NV_PLATFORMCREATE SET on a platform-authorized definition, and the public area is where that record is observable.");

        byte[] expectedName = await ComputeIndependentNvNameAsync(
            pool, PlatformIndexHandle, SessionAlg, PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty, OrdinaryDataSize).ConfigureAwait(false);
        Assert.IsTrue(
            indexPublic.NvName.Span.SequenceEqual(expectedName),
            "The attribute word is inside TPMS_NV_PUBLIC, so the Name must equal the spec recipe transcribed over a public area carrying TPMA_NV_PLATFORMCREATE.");
    }

    /// <summary>
    /// The same platform arm once platformAuth is a real value: <c>TPM2_HierarchyChangeAuth()</c> replaces the
    /// factory-empty secret, and the definition ladder compares against the live carrier - platform
    /// authorization survives every other hierarchy's state, so its own installed secret must define an Index
    /// exactly as the empty one did.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.3.1 and 24.8; Part 1, clause 16.6.4.3</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceUnderAnInstalledPlatformAuthInstallsThePlatformCreatedIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        await InstallHierarchyAuthAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, InstalledPlatformAuth).ConfigureAwait(false);

        TpmResult<NvDefineSpaceResponse> staleResult = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PlatformIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), staleResult.ResponseCode,
            "The superseded factory-empty value is no longer platformAuth, so it authorizes nothing.");

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, InstalledPlatformAuth, PlatformIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The installed platformAuth must define the platform-created Index: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, PlatformIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_PLATFORMCREATE, attributes & TpmaNv.TPMA_NV_PLATFORMCREATE,
            "An installed platformAuth defines exactly the Index the factory-empty one defines.");
    }

    /// <summary>
    /// The consistency rule in both directions: "If platformAuth/platformPolicy is used for authorization, then
    /// TPMA_NV_PLATFORMCREATE shall be SET in publicInfo. If ownerAuth/ownerPolicy is used for authorization,
    /// TPMA_NV_PLATFORMCREATE shall be CLEAR in publicInfo. If TPMA_NV_PLATFORMCREATE is not set correctly for
    /// the authorization, the TPM shall return TPM_RC_ATTRIBUTES." The bit records which authority may
    /// subsequently delete the Index, so a definition that mis-states it is refused rather than silently
    /// corrected, and the refused handle stays undefined.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.3.1; Part 2, clause 13.4, Table 249</see>.
    /// </summary>
    /// <param name="authHandle">The provisioning hierarchy authorizing the definition.</param>
    /// <param name="isPlatformCreateRequested">Whether the definition claims <c>TPMA_NV_PLATFORMCREATE</c>.</param>
    /// <param name="isExpectedToInstall">Whether the claim matches the authorization and the Index therefore installs.</param>
    [TestMethod]
    [DataRow((uint)TpmRh.TPM_RH_OWNER, true, false, DisplayName = "owner authorization claiming TPMA_NV_PLATFORMCREATE is TPM_RC_ATTRIBUTES")]
    [DataRow((uint)TpmRh.TPM_RH_OWNER, false, true, DisplayName = "owner authorization with TPMA_NV_PLATFORMCREATE CLEAR installs")]
    [DataRow((uint)TpmRh.TPM_RH_PLATFORM, true, true, DisplayName = "platform authorization claiming TPMA_NV_PLATFORMCREATE installs")]
    [DataRow((uint)TpmRh.TPM_RH_PLATFORM, false, false, DisplayName = "platform authorization with TPMA_NV_PLATFORMCREATE CLEAR is TPM_RC_ATTRIBUTES")]
    public async Task NvDefineSpacePlatformCreateMustMatchTheAuthorizingAuthority(uint authHandle, bool isPlatformCreateRequested, bool isExpectedToInstall)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        TpmaNv attributes = isPlatformCreateRequested ? PlatformCreateAttributes : OwnerCreateAttributes;

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, (TpmRh)authHandle, ReadOnlyMemory<byte>.Empty, ConsistencyIndexHandle,
            attributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        if(isExpectedToInstall)
        {
            Assert.IsTrue(result.IsSuccess, $"The claim matches the authorization, so the definition must install: '{result.ResponseCode}'.");

            TpmaNv installed = await ReadIndexAttributesAsync(device, ConsistencyIndexHandle).ConfigureAwait(false);
            Assert.AreEqual(
                attributes & TpmaNv.TPMA_NV_PLATFORMCREATE, installed & TpmaNv.TPMA_NV_PLATFORMCREATE,
                "The installed Index records exactly the authority that defined it.");

            return;
        }

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), result.ResponseCode,
            "TPMA_NV_PLATFORMCREATE not set correctly for the authorization is TPM_RC_ATTRIBUTES in either direction.");

        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(ConsistencyIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), publicResult.ResponseCode,
            "A refused definition installs nothing, so the handle is still undefined.");
    }

    /// <summary>
    /// The same consistency rule on the session form: the authorization mechanism is not what the rule is
    /// written in terms of - "If TPMA_NV_PLATFORMCREATE is not set correctly for the authorization, the TPM
    /// shall return TPM_RC_ATTRIBUTES" binds the authorizing AUTHORITY, so a command HMAC that verifies still
    /// leaves the definition refused on the same two cells.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.3.1 and 5.6; Part 2, clause 13.4, Table 249</see>.
    /// </summary>
    /// <param name="authHandle">The provisioning hierarchy authorizing the definition over an HMAC session.</param>
    /// <param name="isPlatformCreateRequested">Whether the definition claims <c>TPMA_NV_PLATFORMCREATE</c>.</param>
    [TestMethod]
    [DataRow((uint)TpmRh.TPM_RH_OWNER, true, DisplayName = "owner authorization claiming TPMA_NV_PLATFORMCREATE over a session is TPM_RC_ATTRIBUTES")]
    [DataRow((uint)TpmRh.TPM_RH_PLATFORM, false, DisplayName = "platform authorization with TPMA_NV_PLATFORMCREATE CLEAR over a session is TPM_RC_ATTRIBUTES")]
    public async Task NvDefineSpaceOverAnHmacSessionPlatformCreateMustMatchTheAuthorizingAuthority(uint authHandle, bool isPlatformCreateRequested)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        TpmaNv attributes = isPlatformCreateRequested ? PlatformCreateAttributes : OwnerCreateAttributes;

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexOverHmacAsync(
            device, pool, registry, (TpmRh)authHandle, ReadOnlyMemory<byte>.Empty, ConsistencyIndexHandle,
            attributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), result.ResponseCode,
            "The command-body rule is stated over the authorizing authority, so an HMAC session reaches exactly the same refusal the password form does.");

        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(ConsistencyIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), publicResult.ResponseCode,
            "A refused definition installs nothing over a session either.");
    }

    /// <summary>
    /// "If TPMA_NV_POLICY_DELETE is SET, then the authorization shall be with Platform Authorization or the TPM
    /// shall return TPM_RC_ATTRIBUTES" - the owner may never install the ADMIN-only deletion path, which is what
    /// keeps "Requiring platform authorization protects against the current TPM owner creating such an Index"
    /// true. The refusal is reached even though the definition's own <c>TPMA_NV_PLATFORMCREATE</c> claim is
    /// consistent with the authorization it carries.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.3.1; Part 1, clause 34.2.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceWithPolicyDeleteUnderOwnerAuthorizationReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        byte[] deletionPolicy = await ComputeDeletionAuthPolicyAsync(pool).ConfigureAwait(false);

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, PolicyDeleteIndexHandle,
            OwnerCreateAttributes | TpmaNv.TPMA_NV_POLICY_DELETE, deletionPolicy).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode,
            "Clause 31.3.1 confines TPMA_NV_POLICY_DELETE to Platform Authorization, so an owner-authorized definition claiming it is TPM_RC_ATTRIBUTES.");

        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(PolicyDeleteIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), publicResult.ResponseCode,
            "The owner cannot leave an undeletable Index behind, so nothing was installed.");
    }

    /// <summary>
    /// The arm the same sentence permits: "If the Index to be created has its TPMA_NV_POLICY_DELETE attribute
    /// SET, then platform authorization is required for allocation" - a platform-authorized definition carrying
    /// <c>TPMA_NV_PLATFORMCREATE</c> alongside <c>TPMA_NV_POLICY_DELETE</c> installs, and both bits read back
    /// out of the public area.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.3.1; Part 1, clause 34.2.2; Part 2, clause 13.4, Table 249</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceWithPolicyDeleteUnderPlatformAuthorizationInstalls()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        byte[] deletionPolicy = await ComputeDeletionAuthPolicyAsync(pool).ConfigureAwait(false);

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PolicyDeleteIndexHandle,
            PolicyDeleteAttributes, deletionPolicy).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"Platform Authorization is exactly what allocating a TPMA_NV_POLICY_DELETE Index requires: '{result.ResponseCode}'.");

        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(PolicyDeleteIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(publicResult.IsSuccess, $"The installed Index's public area must read back: '{publicResult.ResponseCode}'.");

        using NvReadPublicResponse indexPublic = publicResult.Value;
        Assert.AreEqual(
            PolicyDeleteAttributes, indexPublic.NvPublic.Attributes,
            "The public area records both the authority that defined the Index and the deletion path it elected.");
        Assert.IsTrue(
            indexPublic.NvPublic.AuthPolicy.AsReadOnlySpan().SequenceEqual(deletionPolicy),
            "The deletion policy is retained verbatim - it is the only authorization that can ever remove this Index.");
    }

    /// <summary>
    /// "It permits creation of an Index that can never be deleted. One example is an Empty Policy, which can
    /// never be satisfied" - the Empty-Policy <c>TPMA_NV_POLICY_DELETE</c> definition is LEGAL rather than
    /// refused at definition, because the specification means such Indexes to be creatable; the consequence is
    /// deferred to the deletion commands, which is where the Index turns out to be permanently undeletable.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.2; Part 3, clause 31.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceWithPolicyDeleteAndAnEmptyAuthPolicyUnderPlatformAuthorizationInstalls()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, EmptyPolicyDeleteIndexHandle,
            PolicyDeleteAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(
            result.IsSuccess,
            $"An Empty Policy is the specification's own example of a legal, permanently undeletable Index: '{result.ResponseCode}'.");

        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(EmptyPolicyDeleteIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(publicResult.IsSuccess, $"The installed Index's public area must read back: '{publicResult.ResponseCode}'.");

        using NvReadPublicResponse indexPublic = publicResult.Value;
        Assert.IsTrue(
            indexPublic.NvPublic.AuthPolicy.AsReadOnlySpan().IsEmpty,
            "The Index was defined over an Empty Policy, and nothing at definition substitutes a satisfiable one for it.");
        Assert.AreEqual(
            TpmaNv.TPMA_NV_POLICY_DELETE, indexPublic.NvPublic.Attributes & TpmaNv.TPMA_NV_POLICY_DELETE,
            "The elected deletion path is recorded even though no authorization can ever satisfy it.");
    }

    /// <summary>
    /// "Platform Authorization may not be used if phEnable or phEnableNV is CLEAR" - with <c>phEnable</c>
    /// CLEARed by <c>TPM2_HierarchyControl()</c> under Platform Authorization, the platform definition arm is
    /// <c>TPM_RC_HIERARCHY</c> at the availability gate, while the owner arm, whose enable is untouched, still
    /// defines.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.1, 5.4 and 24.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceUnderPlatformAuthorizationWithPhEnableClearReturnsHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        await DisableHierarchyAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM).ConfigureAwait(false);

        TpmResult<NvDefineSpaceResponse> platformResult = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PlatformIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), platformResult.ResponseCode,
            "platformAuth cannot authorize anything while phEnable is CLEAR, a definition included.");

        TpmResult<NvDefineSpaceResponse> ownerResult = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, OwnerIndexHandle,
            OwnerCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(ownerResult.IsSuccess, $"The storage enable is untouched, so the owner arm must still define: '{ownerResult.ResponseCode}'.");
    }

    /// <summary>
    /// The second enable the same sentence names: "Platform Authorization may not be used if phEnable or
    /// phEnableNV is CLEAR" - with <c>phEnableNV</c> alone CLEARed (<c>phEnable</c> still SET, so platformAuth
    /// itself remains usable), the platform definition arm is <c>TPM_RC_HIERARCHY</c> while the owner arm, whose
    /// Indexes are gated by <c>shEnable</c> instead, still defines.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.1 and 24.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceUnderPlatformAuthorizationWithPhEnableNvClearReturnsHierarchyWhileTheOwnerArmDefines()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        await DisableHierarchyAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM_NV).ConfigureAwait(false);

        TpmResult<NvDefineSpaceResponse> platformResult = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PlatformIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), platformResult.ResponseCode,
            "phEnableNV gates the platform's NV reach on its own, so the platform definition arm is refused while platformAuth itself is still usable.");

        TpmResult<NvDefineSpaceResponse> ownerResult = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, OwnerIndexHandle,
            OwnerCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(
            ownerResult.IsSuccess,
            $"An owner-created Index is gated by shEnable, which this command left SET: '{ownerResult.ResponseCode}'.");
    }

    /// <summary>
    /// The session form's own entry-time enable gate: "Platform Authorization may not be used if phEnable or
    /// phEnableNV is CLEAR" - with <c>phEnable</c> CLEARed, platformAuth is unusable for anything (Part 1, clause
    /// 10.2), so <see cref="BeginHierarchyAuthorization"/> answers <c>TPM_RC_HIERARCHY</c> before the command
    /// HMAC is even checked, proving the gate the password form applies at the identical point in its own ladder
    /// also protects the session form.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.1, 5.4 and 24.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOverAnHmacSessionWithPhEnableClearReturnsHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        await DisableHierarchyAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM).ConfigureAwait(false);

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, SessionPhEnableIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), result.ResponseCode,
            "phEnable CLEAR leaves platformAuth unusable for authorization, so the session form's entry-time enable gate answers TPM_RC_HIERARCHY.");
    }

    /// <summary>
    /// The session form's phEnableNV gate runs after the command HMAC verifies: a CORRECT platformAuth over an
    /// HMAC session still verifies the HMAC, then reaches <c>TPM_RC_HIERARCHY</c> at that gate - the position
    /// that keeps both forms answering the same code for {phEnableNV CLEAR, correct credential}.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.1 and 24.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOverAnHmacSessionWithPhEnableNvClearReturnsHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        await DisableHierarchyAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM_NV).ConfigureAwait(false);

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, SessionPhEnableNvIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), result.ResponseCode,
            "phEnableNV gates the platform's NV reach on the session form too, even with a correct platformAuth whose command HMAC verifies.");
    }

    /// <summary>
    /// The non-provision-handle refusal proved on the session form: <c>TPM_RH_ENDORSEMENT</c> and a defined NV
    /// Index handle are both outside <c>TPMI_RH_PROVISION</c>'s admitted set, so the session form answers
    /// <c>TPM_RC_VALUE</c> handle-encoded at authHandle, handle 1 of Table 245, before any session is even
    /// resolved - the same designation the password form gives for the identical handles.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.21, Table 67</see>.
    /// </summary>
    /// <param name="authHandle">The inadmissible <c>@authHandle</c> value.</param>
    [TestMethod]
    [DataRow((uint)TpmRh.TPM_RH_ENDORSEMENT, DisplayName = "TPM_RH_ENDORSEMENT is not TPMI_RH_PROVISION")]
    [DataRow(SecondaryIndexHandle, DisplayName = "a defined NV Index handle is not TPMI_RH_PROVISION")]
    public async Task NvDefineSpaceOverAnHmacSessionWithANonProvisionAuthHandleReturnsValue(uint authHandle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        TpmResult<NvDefineSpaceResponse> secondaryDefinition = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, SecondaryIndexHandle,
            OwnerCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(secondaryDefinition.IsSuccess, $"The fixture Index must be defined: '{secondaryDefinition.ResponseCode}'.");

        //The executor derives a permanent handle's cpHash Name from its own four octets but requires the Name of
        //an NV Index handle from the caller (TPM 2.0 Library Part 1, clause 15.7, equation 15), so the Index row
        //offers the fixture Index's transcribed Name; the TPM never reads it, since the handle is refused at the
        //transition head before any cpHash is judged.
        byte[] secondaryName = await ComputeIndependentNvNameAsync(
            pool, SecondaryIndexHandle, SessionAlg, OwnerCreateAttributes, ReadOnlyMemory<byte>.Empty, OrdinaryDataSize).ConfigureAwait(false);
        ReadOnlyMemory<byte>? cpHashHandleName = authHandle == SecondaryIndexHandle ? secondaryName : null;

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexOverHmacAsync(
            device, pool, registry, (TpmRh)authHandle, ReadOnlyMemory<byte>.Empty, ConsistencyIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty, cpHashHandleName).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode,
            "Part 2 Table 67's #TPM_RC_VALUE fires for a non-provision @authHandle on the session form too, designating authHandle, handle 1, ahead of session resolution.");
    }

    /// <summary>
    /// "The authValue associated with a permanent entity, other than TPM_RH_LOCKOUT, does not receive DA
    /// protection" - a wrong platformAuth on the definition arm is the plain <c>TPM_RC_BAD_AUTH</c> of a
    /// dictionary-attack-exempt entity, <c>failedTries</c> is untouched (read back over
    /// <c>TPM_PT_LOCKOUT_COUNTER</c>), and the refused command installs nothing.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 3, clause 31.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceWithWrongPlatformAuthReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        await InstallHierarchyAuthAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, InstalledPlatformAuth).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, WrongAuth, PlatformIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), result.ResponseCode,
            "The platform hierarchy is DA-exempt, so a wrong value is TPM_RC_BAD_AUTH rather than TPM_RC_AUTH_FAIL.");
        Assert.AreEqual(
            counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "Platform authorization is categorically exempt from dictionary-attack protection, so the refusal charges no failedTries.");

        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(PlatformIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), publicResult.ResponseCode, "A refused definition installs no Index.");
    }

    /// <summary>
    /// The same dictionary-attack exemption over an HMAC session: a command HMAC keyed on a wrong platformAuth
    /// fails to verify and is answered with the non-charging <c>TPM_RC_BAD_AUTH</c>, named on the offending
    /// session by the session-index encoding, with <c>failedTries</c> untouched - which is what keeps platform
    /// authorization usable as the recovery path over a session as well as over a password.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 2, clause 6.6.2; Part 3, clauses 31.3.1 and 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOverAnHmacSessionWithWrongPlatformAuthReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        await InstallHierarchyAuthAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, InstalledPlatformAuth).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, WrongAuth, SessionIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
            "A wrong platformAuth over a session is the session-encoded, non-charging TPM_RC_BAD_AUTH.");
        Assert.AreEqual(
            counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "A DA-exempt permanent entity charges no failedTries on the session form either.");

        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(SessionIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), publicResult.ResponseCode, "A refused definition installs no Index.");
    }

    /// <summary>
    /// <c>@authHandle</c> is a <c>TPMI_RH_PROVISION</c>, whose only values are <c>TPM_RH_OWNER</c> and
    /// <c>TPM_RH_PLATFORM</c>: "#TPM_RC_VALUE response code returned when the unmarshaling of this type fails" -
    /// the endorsement and lockout hierarchies, the NULL hierarchy, a defined NV Index handle and a
    /// transient-range handle are each refused with TPM_RC_VALUE handle-encoded at authHandle, handle 1 of
    /// Table 245, ahead of any enable check and any authorization, so admitting the platform hierarchy widened
    /// the interface type by exactly one value and no more.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.21, Table 67; Part 3, clause 31.3</see>.
    /// </summary>
    /// <param name="authHandle">The inadmissible handle offered as <c>@authHandle</c>.</param>
    [TestMethod]
    [DataRow((uint)TpmRh.TPM_RH_ENDORSEMENT, DisplayName = "TPM_RH_ENDORSEMENT is not a provisioning selector")]
    [DataRow((uint)TpmRh.TPM_RH_LOCKOUT, DisplayName = "TPM_RH_LOCKOUT is not a provisioning selector")]
    [DataRow((uint)TpmRh.TPM_RH_NULL, DisplayName = "TPM_RH_NULL is not a provisioning selector")]
    [DataRow(SecondaryIndexHandle, DisplayName = "a defined NV Index handle is not a provisioning selector")]
    [DataRow(TransientRangeHandle, DisplayName = "a transient-range handle is not a provisioning selector")]
    public async Task NvDefineSpaceWithANonProvisionAuthHandleReturnsValue(uint authHandle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        TpmResult<NvDefineSpaceResponse> secondary = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, SecondaryIndexHandle,
            OwnerCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(secondary.IsSuccess, $"The Index offered as an inadmissible selector must genuinely exist: '{secondary.ResponseCode}'.");

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, (TpmRh)authHandle, ReadOnlyMemory<byte>.Empty, PlatformIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode,
            "TPMI_RH_PROVISION admits TPM_RH_OWNER and TPM_RH_PLATFORM alone.");

        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(PlatformIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), publicResult.ResponseCode,
            "A handle the interface type refuses runs no part of the command's effect.");
    }

    /// <summary>
    /// "cpHash = HsessionAlg(commandCode {Name1 {Name2 {Name3}}} {parameters})" (equation 15) and a permanent
    /// handle's Name is its own four octets - so the platform definition arm's single Name term is
    /// <c>40 00 00 0C</c>. Both halves are proved on the wire: a caller folding a DIFFERENT four-octet Name
    /// produces a command HMAC the TPM refuses, and a caller folding those exact four octets is authorized and
    /// the Index installs.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 15.7 and 13, Table 9; Part 3, clause 31.3</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceUnderPlatformAuthorizationOverAnHmacSessionFoldsThePlatformHandleAsTheCpHashNameTerm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        await InstallHierarchyAuthAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, InstalledPlatformAuth).ConfigureAwait(false);

        TpmResult<NvDefineSpaceResponse> foreignNameResult = await DefineIndexOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, InstalledPlatformAuth, SessionIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty, ForeignHandleName).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), foreignNameResult.ResponseCode,
            "The Name term is load-bearing inside cpHash, so folding any other four octets breaks the command HMAC.");

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, InstalledPlatformAuth, SessionIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty, PlatformHandleName).ConfigureAwait(false);
        Assert.IsTrue(
            result.IsSuccess,
            $"Folding the platform handle's own four octets is what the TPM folds, so the command HMAC verifies: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, SessionIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_PLATFORMCREATE, attributes & TpmaNv.TPMA_NV_PLATFORMCREATE,
            "The session-authorized platform arm installs the same platform-created Index the password arm does.");
    }

    /// <summary>
    /// "If a session is also being used for authorization, sessionValue ... is sessionKey ‖ authValue" - the
    /// <c>auth</c> command parameter is the first sized parameter of this command, so a decrypt-attributed
    /// authorizing session encrypts it, and under the platform arm the entity whose authValue folds into
    /// sessionValue is the PLATFORM. The recovered plaintext becomes the Index authValue, which is provable only
    /// from outside: writing the new Index with that value succeeds, so the TPM keyed the decryption on
    /// platformAuth exactly as the caller keyed the encryption.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 18.1, 18.2 and 18.3; Part 3, clauses 31.3 and 5.7</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceUnderPlatformAuthorizationOverADecryptSessionKeysTheAuthParameterOnPlatformAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        await InstallHierarchyAuthAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, InstalledPlatformAuth).ConfigureAwait(false);

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexOverDecryptSessionAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, InstalledPlatformAuth, DecryptIndexHandle, PlatformCreateAttributes).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The platform arm's decrypt-auth path must define the Index: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, DecryptIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_PLATFORMCREATE, attributes & TpmaNv.TPMA_NV_PLATFORMCREATE,
            "The decrypt path changes how the authValue crosses the bus, never which authority defined the Index.");

        TpmResult<NvWriteResponse> write = await WriteIndexAsync(
            device, pool, registry, DecryptIndexHandle, DecryptIndexHandle, IndexAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(
            write.IsSuccess,
            $"The Index authValue the TPM recovered must be the plaintext the caller encrypted, or nothing could authorize with it: '{write.ResponseCode}'.");
    }

    /// <summary>
    /// The clear operation will "delete any NV Index with TPMA_NV_PLATFORMCREATE == CLEAR", and "TPM2_Clear()
    /// will remove any NV Index that used Owner Authorization to define the Index" - so the owner-created Index
    /// is gone afterwards (its handle answering <c>TPM_RC_HANDLE</c>) while the platform-created one is still
    /// there: its handle resolves, its public area reads back, and its data survives with it. This is what makes
    /// "the platform is permitted to create Indices that can never be deleted, because such Indices might be
    /// essential for proper platform operation" true across an ownership change.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 24.6.1 and 31.3.1; Part 1, clause 34.2.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ClearDeletesTheOwnerCreatedIndexAndLeavesThePlatformCreatedOne()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        TpmResult<NvDefineSpaceResponse> ownerDefine = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, OwnerIndexHandle,
            OwnerCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(ownerDefine.IsSuccess, $"The owner-created Index must exist before the clear: '{ownerDefine.ResponseCode}'.");

        TpmResult<NvDefineSpaceResponse> platformDefine = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, PlatformIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(platformDefine.IsSuccess, $"The platform-created Index must exist before the clear: '{platformDefine.ResponseCode}'.");

        TpmResult<NvWriteResponse> seed = await WriteIndexAsync(
            device, pool, registry, PlatformIndexHandle, PlatformIndexHandle, IndexAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(seed.IsSuccess, $"The platform-created Index must carry data before the clear: '{seed.ResponseCode}'.");

        TpmResult<ClearResponse> clearResult = await device.ClearAsync(ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(clearResult.IsSuccess, $"TPM2_Clear() failed: '{clearResult.ResponseCode}'.");

        TpmResult<NvReadPublicResponse> ownerAfter = await device.NvReadPublicAsync(OwnerIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), ownerAfter.ResponseCode,
            "An Index that used Owner Authorization to be defined is removed by the clear, so its handle no longer resolves.");

        TpmResult<NvReadPublicResponse> platformAfter = await device.NvReadPublicAsync(PlatformIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            platformAfter.IsSuccess,
            $"An Index with TPMA_NV_PLATFORMCREATE SET is outside the clear's deletion rule, so its handle still resolves: '{platformAfter.ResponseCode}'.");

        using(NvReadPublicResponse survivor = platformAfter.Value)
        {
            Assert.AreEqual(
                PlatformCreateAttributes | TpmaNv.TPMA_NV_WRITTEN, survivor.NvPublic.Attributes,
                "The surviving Index is the same Index, not a re-created shell: every attribute it was defined with is still there, and the TPM-maintained TPMA_NV_WRITTEN its seeding write SET is still there too.");
        }

        TpmResult<NvReadResponse> readBack = await ReadIndexAsync(device, pool, registry, PlatformIndexHandle, IndexAuth).ConfigureAwait(false);
        Assert.IsTrue(readBack.IsSuccess, $"The surviving Index's data must still be readable: '{readBack.ResponseCode}'.");

        using(NvReadResponse data = readBack.Value)
        {
            Assert.IsTrue(
                data.Data.SequenceEqual(IndexData),
                "The clear leaves a platform-created Index's data area untouched along with its metadata.");
        }
    }

    /// <summary>
    /// "Index locking is independent of TPMA_NV_PLATFORMCREATE and the type of authorization. For example, an
    /// index with TPMA_NV_PLATFORMCREATE SET will be locked if the command uses Owner Authorization" - an
    /// owner-authorized <c>TPM2_NV_GlobalWriteLock()</c> reaches a platform-created Index electing
    /// <c>TPMA_NV_GLOBALLOCK</c>, and the lock is real rather than nominal: the Index then refuses
    /// <c>TPM2_NV_Write()</c> with <c>TPM_RC_NV_LOCKED</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.12.1 and 31.7.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockUnderOwnerAuthorizationLocksAPlatformCreatedIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        TpmResult<NvDefineSpaceResponse> define = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, GlobalLockIndexHandle,
            GlobalLockPlatformCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(define.IsSuccess, $"The platform-created TPMA_NV_GLOBALLOCK Index must exist: '{define.ResponseCode}'.");

        TpmResult<NvWriteResponse> beforeWrite = await WriteIndexAsync(
            device, pool, registry, GlobalLockIndexHandle, GlobalLockIndexHandle, IndexAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(beforeWrite.IsSuccess, $"The platform-created Index must be writable before the global lock: '{beforeWrite.ResponseCode}'.");

        TpmResult<NvGlobalWriteLockResponse> lockResult = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"The owner arm must authorize the global write lock: '{lockResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "The lock reaches an Index with TPMA_NV_PLATFORMCREATE SET even though the command carried Owner Authorization.");

        TpmResult<NvWriteResponse> afterWrite = await WriteIndexAsync(
            device, pool, registry, GlobalLockIndexHandle, GlobalLockIndexHandle, IndexAuth, RefusedWriteAttempt).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_LOCKED, afterWrite.ResponseCode,
            "An owner-authorized global lock write-locks the platform-created Index for real, so its next write is TPM_RC_NV_LOCKED.");
    }

    /// <summary>
    /// The platform definition arm returns every carrier its parse rented on both paths its ladder takes: the
    /// attribute-consistency refusal in the command body, which never installs an Index, and the accepting
    /// transition, which transfers the Index authValue into durable state - the metered pool returns to its
    /// baseline after each.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.3 and 31.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceReturnsItsCarriersAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        long baseline = trackingPool.OutstandingCount;

        TpmResult<NvDefineSpaceResponse> refusal = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, MeteredIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), refusal.ResponseCode,
            "Clause 31.3.1 requires TPMA_NV_PLATFORMCREATE CLEAR for an owner-authorized definition; claiming it is TPM_RC_ATTRIBUTES.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A refusal in the command body releases the parsed authValue and public area through the request's own Dispose.");

        TpmResult<NvDefineSpaceResponse> accepted = await DefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, MeteredIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(accepted.IsSuccess, $"TPM2_NV_DefineSpace() failed: '{accepted.ResponseCode}'.");

        TpmResult<NvUndefineSpaceResponse> deleted = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, MeteredIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(deleted.IsSuccess, $"TPM2_NV_UndefineSpace() failed: '{deleted.ResponseCode}'.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The accepting transition hands the Index authValue to durable state, and the deletion that ends that ownership releases it.");
    }

    /// <summary>
    /// The session form returns every carrier its parse rented on the same two paths the password form does: the
    /// attribute-consistency refusal <c>ContinueNvDefineSpaceOverSession</c> answers after the command HMAC has
    /// already verified, and the accepting transition that follows it - the metered pool returns to baseline
    /// after each, proving the session-form gates dispose exactly as their password-form counterparts do.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.3 and 31.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOverAnHmacSessionReturnsItsCarriersAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePlatformProvisioningRegistry();

        long baseline = trackingPool.OutstandingCount;

        TpmResult<NvDefineSpaceResponse> refusal = await DefineIndexOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, MeteredSessionIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), refusal.ResponseCode,
            "Clause 31.3.1 requires TPMA_NV_PLATFORMCREATE CLEAR for an owner-authorized definition over a session too.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A refusal in ContinueNvDefineSpaceOverSession's body releases the request's carriers through its own Dispose.");

        TpmResult<NvDefineSpaceResponse> accepted = await DefineIndexOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, MeteredSessionIndexHandle,
            PlatformCreateAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(accepted.IsSuccess, $"TPM2_NV_DefineSpace() over a session failed: '{accepted.ResponseCode}'.");

        TpmResult<NvUndefineSpaceResponse> deleted = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, MeteredSessionIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(deleted.IsSuccess, $"TPM2_NV_UndefineSpace() failed: '{deleted.ResponseCode}'.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The accepting transition hands the Index authValue to durable state, and the deletion that ends that ownership releases it.");
    }

    /// <summary>Creates a response codec registry for the commands these tests drive.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreatePlatformProvisioningRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_NV_GlobalWriteLock, TpmResponseCodec.NvGlobalWriteLock)
            .Register(TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmResponseCodec.HierarchyChangeAuth)
            .Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl)
            .Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>
    /// Issues a password-authorized <c>TPM2_NV_DefineSpace()</c> under <paramref name="authHandle"/> with
    /// <see cref="IndexAuth"/> as the Index authValue, returning the result unasserted so a case can pin either
    /// an installation or a refusal. The command's sole handle is a permanent one, so the executor is given no
    /// supplied Names.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorizing hierarchy, admissible or not.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <param name="authPolicy">The access policy digest to define with; empty defines an Empty Policy.</param>
    /// <returns>The definition result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh authHandle, ReadOnlyMemory<byte> suppliedAuth,
        uint nvIndex, TpmaNv attributes, ReadOnlyMemory<byte> authPolicy)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);

        //The input takes ownership of the auth value and public area and disposes them; the redundant using
        //locals satisfy CA2000 and are safe because every one of these types has idempotent disposal.
        using Tpm2bDigest policyDigest = authPolicy.IsEmpty ? Tpm2bDigest.Empty : Tpm2bDigest.Create(authPolicy.Span, pool);
        using var auth = Tpm2bAuth.Create(IndexAuth, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, SessionAlg, attributes, policyDigest, OrdinaryDataSize);
        using var input = new NvDefineSpaceInput(authHandle, auth, publicInfo);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues <c>TPM2_NV_DefineSpace()</c> over a freshly started UNBOUND, unsalted HMAC session whose authValue
    /// term is <paramref name="suppliedAuth"/>, flushing the session afterwards. When
    /// <paramref name="cpHashHandleName"/> is <see langword="null"/> the host derives the cpHash Name term from
    /// the permanent handle's own four octets; supplying it folds those octets instead, which is how a wrong
    /// Name term is offered without hand-framing the command.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <param name="authPolicy">The access policy digest to define with; empty defines an Empty Policy.</param>
    /// <param name="cpHashHandleName">The Name term to fold into cpHash, or <see langword="null"/> to let the host derive it.</param>
    /// <returns>The definition result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineIndexOverHmacAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh authHandle, ReadOnlyMemory<byte> suppliedAuth,
        uint nvIndex, TpmaNv attributes, ReadOnlyMemory<byte> authPolicy, ReadOnlyMemory<byte>? cpHashHandleName = null)
    {
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, suppliedAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                using Tpm2bDigest policyDigest = authPolicy.IsEmpty ? Tpm2bDigest.Empty : Tpm2bDigest.Create(authPolicy.Span, pool);
                using var auth = Tpm2bAuth.Create(IndexAuth, pool);
                using var publicInfo = new TpmsNvPublic(nvIndex, SessionAlg, attributes, policyDigest, OrdinaryDataSize);
                using var input = new NvDefineSpaceInput(authHandle, auth, publicInfo);

                ReadOnlyMemory<byte>[]? handleNames = cpHashHandleName is ReadOnlyMemory<byte> name ? [name] : null;

                return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
                    device, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Issues <c>TPM2_NV_DefineSpace()</c> over a single unbound, unsalted HMAC session that carries the
    /// <c>decrypt</c> attribute as well as the authorization - the shape TPM 2.0 Library Part 1, clause 18.1
    /// describes, where one session both proves the authorization and protects the first command parameter, and
    /// the encryption key folds the authorized entity's own authValue after the session key.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="suppliedAuth">The authorization value proven by the session and folded into the encryption key.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <returns>The definition result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineIndexOverDecryptSessionAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh authHandle, ReadOnlyMemory<byte> suppliedAuth,
        uint nvIndex, TpmaNv attributes)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool, TpmtSymDef.Xor(SessionAlg));
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool, TpmtSymDef.Xor(SessionAlg));
            session.SetAuthValue(suppliedAuth.Span, pool);
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            using var auth = Tpm2bAuth.Create(IndexAuth, pool);
            using var publicInfo = new TpmsNvPublic(nvIndex, SessionAlg, attributes, Tpm2bDigest.Empty, OrdinaryDataSize);
            using var input = new NvDefineSpaceInput(authHandle, auth, publicInfo);

            return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
                device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>Issues a password-authorized <c>TPM2_NV_UndefineSpace()</c> under <paramref name="authHandle"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <param name="nvIndex">The Index to delete.</param>
    /// <returns>The deletion result.</returns>
    private async Task<TpmResult<NvUndefineSpaceResponse>> UndefineIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh authHandle, ReadOnlyMemory<byte> suppliedAuth, uint nvIndex)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var input = new NvUndefineSpaceInput(authHandle, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues a password-authorized <c>TPM2_NV_GlobalWriteLock()</c> under <paramref name="authHandle"/>. The
    /// command carries one permanent handle and no parameters, so the executor is given no supplied Names.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <returns>The global-write-lock result.</returns>
    private async Task<TpmResult<NvGlobalWriteLockResponse>> GlobalWriteLockAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh authHandle, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var input = new NvGlobalWriteLockInput(authHandle);

        return await TpmCommandExecutor.ExecuteAsync<NvGlobalWriteLockResponse>(
            device, input, [session], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues a password-authorized <c>TPM2_NV_Write()</c> against <paramref name="nvIndex"/> at offset zero.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorization handle.</param>
    /// <param name="nvIndex">The Index to write.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <param name="data">The octets to store.</param>
    /// <returns>The write result.</returns>
    private async Task<TpmResult<NvWriteResponse>> WriteIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex,
        ReadOnlyMemory<byte> suppliedAuth, ReadOnlyMemory<byte> data)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(data.Span, pool);
        var input = new NvWriteInput(authHandle, nvIndex, buffer, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues a password-authorized <c>TPM2_NV_Read()</c> of the whole data area of <paramref name="nvIndex"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to read, authorizing with its own authValue.</param>
    /// <param name="suppliedAuth">The Index authorization value.</param>
    /// <returns>The read result.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var input = new NvReadInput(nvIndex, nvIndex, OrdinaryDataSize, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
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
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);
        session.SetAuthValue(authValue.Span, pool);

        return (started.SessionHandle.Value, session);
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
    /// Replaces <paramref name="hierarchy"/>'s authorization value through a password-authorized
    /// <c>TPM2_HierarchyChangeAuth()</c>, asserting the rotation succeeded - the way an installed platformAuth
    /// is put in place before the definition arms are exercised against it.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="hierarchy">The hierarchy whose authorization value is replaced.</param>
    /// <param name="currentAuth">The hierarchy's current authorization value.</param>
    /// <param name="newAuth">The replacement authorization value.</param>
    private async Task InstallHierarchyAuthAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh hierarchy, ReadOnlyMemory<byte> currentAuth,
        ReadOnlyMemory<byte> newAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(currentAuth.Span, pool);

        //The input takes ownership of the replacement carrier and disposes it; the redundant using local
        //satisfies CA2000 and is safe because the carrier's disposal is idempotent.
        using var replacement = Tpm2bAuth.Create(newAuth.Span, pool);
        using var input = new HierarchyChangeAuthInput(hierarchy, replacement);

        TpmResult<HierarchyChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyChangeAuthResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyChangeAuth() on '{hierarchy}' failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// CLEARs <paramref name="hierarchy"/>'s enable through a password-authorized <c>TPM2_HierarchyControl()</c>
    /// under Platform Authorization, asserting the write succeeded - Platform Authorization may CLEAR any enable
    /// including its own and the platform NV enable (TPM 2.0 Library Part 3, clause 24.2.1).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="hierarchy">The hierarchy or NV enable that is CLEARed.</param>
    private async Task DisableHierarchyAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh hierarchy)
    {
        using TpmPasswordSession session = TpmPasswordSession.CreateEmpty(pool);
        var input = new HierarchyControlInput(TpmRh.TPM_RH_PLATFORM, hierarchy, TpmiYesNo.No);

        TpmResult<HierarchyControlResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyControlResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyControl() disabling '{hierarchy}' failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Reads an Index's <c>TPMA_NV</c> attribute word back through <c>TPM2_NV_ReadPublic()</c>, which is how the
    /// attributes a definition installed - and the TPM-maintained lock bits - are observable from outside (TPM
    /// 2.0 Library Part 3, clause 31.6).
    /// </summary>
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
    /// Independently transcribes an NV Index's Name: <c>nameAlg ‖ H_nameAlg(nvIndex ‖ nameAlg ‖ attributes ‖
    /// authPolicy ‖ dataSize)</c>, the whole marshaled <c>TPMS_NV_PUBLIC</c> (TPM 2.0 Library Part 2, clause
    /// 13.6, Table 251) hashed per Part 1, clause 13, Table 9. Uses <see cref="BinaryPrimitives"/> and the
    /// project's registered digest seam directly, never <c>TpmsNvPublic.WriteTo</c> or the production Name
    /// helper.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle.</param>
    /// <param name="nameAlg">The Name hash algorithm.</param>
    /// <param name="attributes">The Index attributes to hash.</param>
    /// <param name="authPolicy">The access policy digest to hash.</param>
    /// <param name="dataSize">The declared data area size to hash.</param>
    /// <returns>The transcribed Name (nameAlg prefix followed by the digest).</returns>
    private async Task<byte[]> ComputeIndependentNvNameAsync(
        BaseMemoryPool pool, uint nvIndex, TpmAlgIdConstants nameAlg, TpmaNv attributes, ReadOnlyMemory<byte> authPolicy, ushort dataSize)
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

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            marshaled, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] name = new byte[sizeof(ushort) + Sha256DigestSize];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)nameAlg);
        digest.AsReadOnlySpan().CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>
    /// Transcribes the deletion policy a <c>TPMA_NV_POLICY_DELETE</c> Index is expected to carry:
    /// <c>policyDigest = H(0^32 ‖ TPM_CC_PolicyCommandCode ‖ TPM_CC_NV_UndefineSpaceSpecial)</c>, the extend
    /// formula of <c>TPM2_PolicyCommandCode()</c> applied once to a zero starting digest - the minimal policy
    /// that "the policy must contain a command that sets the policy command code to
    /// TPM_CC_NV_UndefineSpaceSpecial" names. Written out with <see cref="BinaryPrimitives"/> and the project's
    /// registered digest seam, never through the production policy builder.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The transcribed policy digest.</returns>
    private async Task<byte[]> ComputeDeletionAuthPolicyAsync(BaseMemoryPool pool)
    {
        byte[] commandCodeInput = new byte[Sha256DigestSize + sizeof(uint) + sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(commandCodeInput.AsSpan(Sha256DigestSize), (uint)TpmCcConstants.TPM_CC_PolicyCommandCode);
        BinaryPrimitives.WriteUInt32BigEndian(commandCodeInput.AsSpan(Sha256DigestSize + sizeof(uint)), (uint)TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            commandCodeInput, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)) - a local mirror of the production session-index encoding, transcribed
    /// independently here since the production helper is private.
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

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
    /// phase, which is the precondition <c>TPM2_NV_DefineSpace()</c> carries.
    /// </summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator("tpm-in-house-nv-platform-provisioning", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitStartupAsync(simulator, BaseMemoryPool.Shared, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
