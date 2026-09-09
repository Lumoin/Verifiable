using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
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

namespace Verifiable.Tests.Tpm;

/// <summary>
/// <c>TPM2_EvictControl()</c> over objects <c>TPM2_LoadExternal()</c> loaded, against the in-house behavioural
/// <see cref="TpmSimulator"/>: a public-only object under a real hierarchy persists and keeps working through
/// its persistent handle until <c>TPM2_Clear()</c> sweeps it, while a Temporary Object — one associated with
/// <c>TPM_RH_NULL</c>, public-only or full, and a Primary created there — may not be made persistent
/// (TPM 2.0 Library Part 3, clauses 28.5 and 24.6; Part 1, clause 26.4).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorExternalObjectEvictionTests
{
    /// <summary>The Name algorithm used throughout.</summary>
    private const TpmAlgIdConstants NameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The width of a P-256 coordinate or scalar.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The persistent handle the persisted external object takes.</summary>
    private const uint PersistentHandle = 0x8100_0170;

    /// <summary>The message the signatures are over.</summary>
    private static byte[] MessageBytes { get; } = "Persist me from outside the TPM."u8.ToArray();

    /// <summary>The attribute word of an external signing key: caller-supplied, USER-role by password, dictionary-attack exempt.</summary>
    private const TpmaObject ExternalSigningAttributes = TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT | TpmaObject.NO_DA;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A public-only ECC key associated with the owner hierarchy is not a Temporary Object, so
    /// <c>TPM2_EvictControl()</c> persists it: <c>TPM2_VerifySignature()</c> through the persistent handle
    /// succeeds with a real ticket, <c>TPM2_ReadPublic()</c> through it answers the object's Name and a Qualified
    /// Name equal to it, and <c>TPM2_Clear()</c> — which flushes "resident objects (persistent and volatile) in
    /// the Storage and Endorsement hierarchies" — evicts it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 28.5.1 and 24.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task PublicOnlyExternalObjectUnderOwnerPersistsWorksAndIsClearedAway()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(PublicOnlyExternalObjectUnderOwnerPersistsWorksAndIsClearedAway), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        byte[] expectedName = TranscribeEccName(pool, key);
        TpmiDhObject transient = await LoadEccAsync(tpm, registry, pool, key, TpmiRhHierarchy.Owner, scalar: null).ConfigureAwait(false);
        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, transient.Value, PersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"A public-only object under a real hierarchy must persist (Part 3, clause 28.5.1), but failed: '{persistResult.ResponseCode}'.");

        var persistent = TpmiDhObject.FromValue(PersistentHandle);
        byte[] digest = SHA256.HashData(MessageBytes);
        using VerifySignatureInput verifyInput = VerifySignatureInput.ForEcdsa(persistent, digest, key.Key.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation), NameAlg, pool);
        TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifySignature() through the persistent handle must succeed, but failed: '{verifyResult.ResponseCode}'.");
        using(VerifySignatureResponse verified = verifyResult.Value)
        {
            Assert.IsFalse(verified.Validation.IsNull, "The persisted object keeps its owner-hierarchy association and earns a real ticket.");
        }

        TpmResult<ReadPublicResponse> readResult = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(tpm, ReadPublicInput.ForHandle(persistent), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"TPM2_ReadPublic() through the persistent handle must succeed, but failed: '{readResult.ResponseCode}'.");
        using(ReadPublicResponse readPublic = readResult.Value)
        {
            Assert.IsTrue(readPublic.Name.Span.SequenceEqual(expectedName), "The persisted object keeps its Name.");
            Assert.IsTrue(readPublic.QualifiedName.Span.SequenceEqual(expectedName), "The Qualified Name for an external object is its Name (Part 3, clause 12.3.1), persisting included.");
        }

        using TpmPasswordSession platformAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ClearResponse> clearResult = await TpmCommandExecutor.ExecuteAsync<ClearResponse>(tpm, new ClearInput(TpmRh.TPM_RH_PLATFORM), [platformAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(clearResult.IsSuccess, $"TPM2_Clear() failed: '{clearResult.ResponseCode}'.");

        TpmResult<ReadPublicResponse> afterClear = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(tpm, ReadPublicInput.ForHandle(persistent), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), afterClear.ResponseCode, "TPM2_Clear() evicts the persisted owner-hierarchy object (Part 3, clause 24.6.1).");
    }

    /// <summary>
    /// A persistent object is disabled, not evicted, when its hierarchy is disabled: "the TPM will disable use
    /// of any persistent entity associated with the disabled hierarchy and will flush any transient objects
    /// associated with the disabled hierarchy". <c>TPM2_VerifySignature()</c> and <c>TPM2_ReadPublic()</c>
    /// through the persistent handle are refused with <c>TPM_RC_HANDLE</c> while <c>TPM_RH_OWNER</c> is
    /// disabled, and both succeed again — <c>TPM2_VerifySignature()</c> with a real, non-NULL ticket — once
    /// <c>TPM2_HierarchyControl()</c> re-enables it, the object having stayed in place the whole time.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 24.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task PersistedExternalObjectIsUnusableWhileItsHierarchyIsDisabled()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(PersistedExternalObjectIsUnusableWhileItsHierarchyIsDisabled), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        TpmiDhObject transient = await LoadEccAsync(tpm, registry, pool, key, TpmiRhHierarchy.Owner, scalar: null).ConfigureAwait(false);
        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, transient.Value, PersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"A public-only object under a real hierarchy must persist (Part 3, clause 28.5.1), but failed: '{persistResult.ResponseCode}'.");
        var persistent = TpmiDhObject.FromValue(PersistentHandle);
        byte[] digest = SHA256.HashData(MessageBytes);

        await SetOwnerHierarchyEnabledAsync(tpm, registry, pool, TpmiYesNo.No).ConfigureAwait(false);

        using(VerifySignatureInput disabledVerifyInput = VerifySignatureInput.ForEcdsa(persistent, digest, key.Key.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation), NameAlg, pool))
        {
            TpmResult<VerifySignatureResponse> disabledVerify = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(tpm, disabledVerifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), disabledVerify.ResponseCode, "The disabled hierarchy's persistent object is not evicted, but its use is disabled (Part 3, clause 24.2.1).");
        }

        TpmResult<ReadPublicResponse> disabledRead = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(tpm, ReadPublicInput.ForHandle(persistent), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), disabledRead.ResponseCode, "TPM2_ReadPublic() through the disabled hierarchy's persistent object also answers TPM_RC_HANDLE.");

        await SetOwnerHierarchyEnabledAsync(tpm, registry, pool, TpmiYesNo.Yes).ConfigureAwait(false);

        TpmResult<ReadPublicResponse> reenabledRead = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(tpm, ReadPublicInput.ForHandle(persistent), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(reenabledRead.IsSuccess, $"TPM2_ReadPublic() must find the persistent object again once its hierarchy is re-enabled, but failed: '{reenabledRead.ResponseCode}'.");
        reenabledRead.Value.Dispose();

        using VerifySignatureInput reenabledVerifyInput = VerifySignatureInput.ForEcdsa(persistent, digest, key.Key.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation), NameAlg, pool);
        TpmResult<VerifySignatureResponse> reenabledVerify = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(tpm, reenabledVerifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(reenabledVerify.IsSuccess, $"TPM2_VerifySignature() must succeed again once the hierarchy is re-enabled, but failed: '{reenabledVerify.ResponseCode}'.");
        using(VerifySignatureResponse reenabledVerified = reenabledVerify.Value)
        {
            Assert.IsFalse(reenabledVerified.Validation.IsNull, "The re-enabled persistent object keeps its owner-hierarchy association and earns a real ticket.");
        }
    }

    /// <summary>
    /// An object associated with <c>TPM_RH_NULL</c> is a Temporary Object and may not be made persistent — a full
    /// external object, a public-only one under <c>TPM_RH_NULL</c>, and a Primary created in the NULL hierarchy
    /// alike are refused with <c>TPM_RC_ATTRIBUTES</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.5.1</see>.
    /// </summary>
    /// <param name="kind">The Temporary Object under test.</param>
    [TestMethod]
    [DataRow(TemporaryObjectKind.FullExternal)]
    [DataRow(TemporaryObjectKind.PublicOnlyExternal)]
    [DataRow(TemporaryObjectKind.NullPrimary)]
    public async Task TemporaryObjectMayNotBePersisted(TemporaryObjectKind kind)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(TemporaryObjectMayNotBePersisted)}-{kind}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        uint handle;
        CreatePrimaryResponse? primary = null;
        try
        {
            switch(kind)
            {
                case TemporaryObjectKind.FullExternal:
                {
                    handle = (await LoadEccAsync(tpm, registry, pool, key, TpmiRhHierarchy.Null, scalar: key.D).ConfigureAwait(false)).Value;
                    break;
                }
                case TemporaryObjectKind.PublicOnlyExternal:
                {
                    handle = (await LoadEccAsync(tpm, registry, pool, key, TpmiRhHierarchy.Null, scalar: null).ConfigureAwait(false)).Value;
                    break;
                }
                default:
                {
                    primary = await CreateNullPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
                    handle = primary.ObjectHandle.Value;
                    break;
                }
            }

            TpmResult<EvictControlResponse> result = await TpmEvictControlHarness.EvictControlAsync(
                tpm, registry, pool, handle, PersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode, $"{kind} is a Temporary Object and may not be made persistent (Part 3, clause 28.5.1).");
        }
        finally
        {
            primary?.Dispose();
        }
    }

    /// <summary>
    /// Pool hygiene: the refused persist of a Temporary Object and the persist-then-evict of an owner-hierarchy
    /// external object leave the pool with exactly the carriers outstanding before them — the persistent copy's
    /// deep-copied carriers are released on eviction.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.5</see>.
    /// </summary>
    [TestMethod]
    public async Task EvictControlOfExternalObjectsLeavesThePoolBalanced()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(EvictControlOfExternalObjectsLeavesThePoolBalanced), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        TpmiDhObject nullObject = await LoadEccAsync(tpm, registry, pool, key, TpmiRhHierarchy.Null, scalar: null).ConfigureAwait(false);
        TpmiDhObject ownerObject = await LoadEccAsync(tpm, registry, pool, key, TpmiRhHierarchy.Owner, scalar: null).ConfigureAwait(false);
        long baseline = trackingPool.OutstandingCount;

        TpmResult<EvictControlResponse> refused = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, nullObject.Value, PersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), refused.ResponseCode, "The Temporary Object's persist is refused.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refused persist returns every carrier it rented.");

        TpmResult<EvictControlResponse> persisted = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, ownerObject.Value, PersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persisted.IsSuccess, $"The owner-hierarchy object must persist, but failed: '{persisted.ResponseCode}'.");

        TpmResult<EvictControlResponse> evicted = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, PersistentHandle, PersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(evicted.IsSuccess, $"Evicting the persistent object must succeed, but failed: '{evicted.ResponseCode}'.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The persistent copy's deep-copied carriers are released on eviction.");
    }

    /// <summary>The Temporary Objects <see cref="TemporaryObjectMayNotBePersisted"/> drives.</summary>
    internal enum TemporaryObjectKind
    {
        /// <summary>An external object loaded with its sensitive area under <c>TPM_RH_NULL</c>.</summary>
        FullExternal,

        /// <summary>An external object loaded from its public area under <c>TPM_RH_NULL</c>.</summary>
        PublicOnlyExternal,

        /// <summary>A Primary Object created in the NULL hierarchy.</summary>
        NullPrimary,
    }

    /// <summary>A P-256 key pair minted by the framework, its coordinates and scalar padded to the field width.</summary>
    private sealed class EccKeyMaterial: IDisposable
    {
        /// <summary>Gets the framework key, the off-TPM signing oracle.</summary>
        public ECDsa Key { get; }

        /// <summary>Gets the public point's X coordinate, 32 octets.</summary>
        public byte[] X { get; }

        /// <summary>Gets the public point's Y coordinate, 32 octets.</summary>
        public byte[] Y { get; }

        /// <summary>Gets the private scalar, 32 octets.</summary>
        public byte[] D { get; }

        /// <summary>Initializes the material from the framework key.</summary>
        /// <param name="key">The framework key; owned.</param>
        private EccKeyMaterial(ECDsa key)
        {
            Key = key;
            ECParameters parameters = key.ExportParameters(includePrivateParameters: true);
            X = PadLeft(parameters.Q.X!, P256ComponentSize);
            Y = PadLeft(parameters.Q.Y!, P256ComponentSize);
            D = PadLeft(parameters.D!, P256ComponentSize);
        }

        /// <summary>Mints a fresh P-256 key pair.</summary>
        /// <returns>The material; the caller disposes it.</returns>
        public static EccKeyMaterial Generate() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

        /// <summary>Releases the framework key and clears the scalar.</summary>
        public void Dispose()
        {
            Array.Clear(D);
            Key.Dispose();
        }
    }

    /// <summary>Left-pads an unsigned big-endian integer to a fixed width.</summary>
    /// <param name="value">The integer's octets.</param>
    /// <param name="width">The target width.</param>
    /// <returns>The padded octets.</returns>
    private static byte[] PadLeft(byte[] value, int width)
    {
        byte[] padded = new byte[width];
        value.CopyTo(padded, width - value.Length);

        return padded;
    }

    /// <summary>Creates an operational simulator with the elliptic-curve backend.</summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool) =>
        HmacKeyHarness.CreateOperationalAsync($"tpm-in-house-external-eviction-{name}", pool, TestContext.CancellationToken);

    /// <summary>Builds the codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_LoadExternal, TpmResponseCodec.LoadExternal)
            .Register(TpmCcConstants.TPM_CC_VerifySignature, TpmResponseCodec.VerifySignature)
            .Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl)
            .Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl)
            .Register(TpmCcConstants.TPM_CC_Clear, TpmResponseCodec.Clear);

    /// <summary>Builds an ECC P-256 ECDSA-SHA-256 signing public area carrying the key's point.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <returns>The public area; the caller owns it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the point transfers to the returned public area, which its owner disposes.")]
    private static Tpm2bPublic BuildEccPublic(BaseMemoryPool pool, EccKeyMaterial key) =>
        Tpm2bPublic.CreateEccSigningKey(NameAlg, ExternalSigningAttributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(NameAlg), TpmsEccPoint.Create(key.X, key.Y, pool), pool);

    /// <summary>Transcribes the Name the TPM must compute for the key's public area: <c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c> (TPM 2.0 Library Part 1, clause 13, Table 9).</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <returns>The Name octets.</returns>
    private static byte[] TranscribeEccName(BaseMemoryPool pool, EccKeyMaterial key)
    {
        using Tpm2bPublic publicArea = BuildEccPublic(pool, key);
        byte[] marshaled = new byte[publicArea.GetSerializedSize()];
        var writer = new TpmWriter(marshaled);
        publicArea.WriteTo(ref writer);
        byte[] digest = SHA256.HashData(marshaled.AsSpan(sizeof(ushort)));
        byte[] name = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)NameAlg);
        digest.CopyTo(name, sizeof(ushort));

        return name;
    }

    /// <summary>Issues <c>TPM2_LoadExternal()</c> for the key under <paramref name="hierarchy"/> — public-only when <paramref name="scalar"/> is <see langword="null"/> — asserting success, and returns the handle.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <param name="hierarchy">The hierarchy the object joins.</param>
    /// <param name="scalar">The private scalar, or <see langword="null"/> for a public-only load.</param>
    /// <returns>The loaded handle.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public and sensitive areas transfers to the load input, disposed here once the command has been issued.")]
    private async Task<TpmiDhObject> LoadEccAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, EccKeyMaterial key, TpmiRhHierarchy hierarchy, byte[]? scalar)
    {
        TpmtSensitive? inPrivate = scalar is null
            ? null
            : new TpmtSensitive(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Empty, TpmuSensitiveComposite.FromEcc(Tpm2bEccParameter.Create(scalar, pool)));
        using var input = new LoadExternalInput(inPrivate, BuildEccPublic(pool, key), hierarchy);
        TpmResult<LoadExternalResponse> result = await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_LoadExternal() under 0x{hierarchy.Value:X8} failed: '{result.ResponseCode}'.");
        using LoadExternalResponse loaded = result.Value;

        return loaded.ObjectHandle;
    }

    /// <summary>Creates an empty-auth ECC P-256 signing primary in the NULL hierarchy.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateNullPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(TpmRh.TPM_RH_NULL, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(NameAlg), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (NULL hierarchy) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Writes the owner hierarchy's enable through <c>TPM2_HierarchyControl()</c> under platform authorization and asserts success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="state">The enable state to write.</param>
    private async Task SetOwnerHierarchyEnabledAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiYesNo state)
    {
        using TpmPasswordSession platformAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<HierarchyControlResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyControlResponse>(
            tpm, new HierarchyControlInput(TpmRh.TPM_RH_PLATFORM, TpmRh.TPM_RH_OWNER, state), [platformAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyControl(OWNER, {state}) failed: '{result.ResponseCode}'.");
    }
}
