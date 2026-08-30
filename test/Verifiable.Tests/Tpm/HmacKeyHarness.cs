using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Shared plumbing for the KEYEDHASH HMAC-key simulator acceptance tests (<c>TPM2_HMAC()</c>,
/// <c>TPM2_HMAC_Start()</c>, the HMAC arm of <c>TPM2_SequenceComplete()</c>): an operational in-house
/// <see cref="TpmSimulator"/>, a deterministic ECC storage parent, and a create-then-load of an HMAC signing key
/// under it — all in-process against the production wire path (<see cref="TpmCommandExecutor"/>, the real device
/// verbs, and the real codecs), so each command's own class carries only its normative assertions. Every verb
/// that authorizes an object or a sequence takes the password to present, so a class can prove the
/// authorization ladder as well as the positive path.
/// </summary>
internal static class HmacKeyHarness
{
    /// <summary>The nameAlg used for the storage parent and the HMAC keys throughout these tests.</summary>
    public const TpmAlgIdConstants NameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// Creates an ECC-capable simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the
    /// operational phase.
    /// </summary>
    /// <param name="name">A per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <param name="seed">The hierarchy-proof seed the simulator's tickets derive from, so a test can recompute a minted ticket off-TPM; empty for the identifier-derived default.</param>
    /// <returns>The operational simulator.</returns>
    public static async Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool, CancellationToken cancellationToken, ReadOnlyMemory<byte> seed = default)
    {
        var simulator = new TpmSimulator(name, signingBackend: BouncyCastleTpmEccSigningBackend.Create(), seed: seed);
        await simulator.PowerOnAsync(cancellationToken).ConfigureAwait(false);

        var startup = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + startup.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)startup.CommandCode);
        header.WriteTo(ref writer);
        startup.WriteHandles(ref writer);
        startup.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }

    /// <summary>Builds the response codec registry covering every executor-driven command these tests issue.</summary>
    /// <returns>The registry.</returns>
    public static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_HMAC, TpmResponseCodec.Hmac);
        _ = registry.Register(TpmCcConstants.TPM_CC_HMAC_Start, TpmResponseCodec.HmacStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceUpdate, TpmResponseCodec.SequenceUpdate);
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceComplete, TpmResponseCodec.SequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_EventSequenceComplete, TpmResponseCodec.EventSequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceComplete, TpmResponseCodec.SignSequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_ReadPublic, TpmResponseCodec.ReadPublic);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyCommandCode, TpmResponseCodec.PolicyCommandCode);
        _ = registry.Register(TpmCcConstants.TPM_CC_Duplicate, TpmResponseCodec.Duplicate);
        _ = registry.Register(TpmCcConstants.TPM_CC_Import, TpmResponseCodec.Import);

        return registry;
    }

    /// <summary>Creates the deterministic ECC storage parent under the requested hierarchy (the owner hierarchy by default), with an empty hierarchy authorization; the caller owns and flushes the response.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <param name="hierarchy">The hierarchy the primary is created under.</param>
    /// <returns>The CreatePrimary response for the storage parent.</returns>
    public static async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CancellationToken cancellationToken, TpmRh hierarchy = TpmRh.TPM_RH_OWNER)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            hierarchy, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [hierarchyAuth], null, pool, registry, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent under '{hierarchy}' failed: '{parentResult.ResponseCode}'.");

        return parentResult.Value;
    }

    /// <summary>
    /// Issues <c>TPM2_Create()</c> for an HMAC key template and returns the raw result, so a caller can assert
    /// either a successful creation or a specific refusal without the harness deciding.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <param name="keyBytes">The HMAC key value (empty when the TPM is to generate it).</param>
    /// <param name="hashAlg">The HMAC scheme hash algorithm.</param>
    /// <param name="isRestricted">Whether the template sets the restricted attribute.</param>
    /// <param name="isSensitiveDataOrigin">Whether the template sets sensitiveDataOrigin (the TPM generates the key).</param>
    /// <param name="userAuth">The key's authorization value (empty for the KAT keys).</param>
    /// <param name="isNoDa">Whether the template sets <c>noDA</c>, exempting the key from dictionary-attack protection.</param>
    /// <param name="isUserWithAuth">Whether the template sets <c>userWithAuth</c>, admitting a password or HMAC session for the USER role.</param>
    /// <param name="isDuplicable">Whether the template clears <c>fixedTPM</c> and <c>fixedParent</c>, so the key may be duplicated.</param>
    /// <param name="authPolicy">The key's authorization policy digest (empty for an authValue-only key).</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The raw create result; the caller disposes the value on success.</returns>
    public static async Task<TpmResult<CreateResponse>> CreateHmacKeyAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, ReadOnlyMemory<byte> keyBytes, TpmAlgIdConstants hashAlg,
        bool isRestricted = false, bool isSensitiveDataOrigin = false, ReadOnlyMemory<byte> userAuth = default,
        bool isNoDa = true, bool isUserWithAuth = true, bool isDuplicable = false, ReadOnlyMemory<byte> authPolicy = default,
        CancellationToken cancellationToken = default)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForHmacKey(keyBytes.Span, userAuth.Span, pool);
        using Tpm2bPublic template = Tpm2bPublic.CreateHmacKeyTemplate(
            NameAlg, hashAlg, pool, authPolicy: authPolicy.Span, noDa: isNoDa, userWithAuth: isUserWithAuth, isDuplicable: isDuplicable,
            isRestricted: isRestricted, isSensitiveDataOrigin: isSensitiveDataOrigin);

        return await CreateAsync(tpm, registry, pool, parentHandle, inSensitive, template, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues <c>TPM2_Create()</c> for an arbitrary KEYEDHASH template — any attribute word and scheme, the
    /// form the refusal ladder needs — with a caller-supplied sensitive value, and returns the raw result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <param name="attributes">The exact <c>TPMA_OBJECT</c> word.</param>
    /// <param name="scheme">The keyed-hash scheme.</param>
    /// <param name="sensitiveData">The sensitive value (empty when the TPM is to generate it, or for an empty seal).</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The raw create result; the caller disposes the value on success.</returns>
    public static async Task<TpmResult<CreateResponse>> CreateKeyedHashObjectAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, TpmaObject attributes, TpmsKeyedHashParms scheme,
        ReadOnlyMemory<byte> sensitiveData, CancellationToken cancellationToken)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForHmacKey(sensitiveData.Span, ReadOnlySpan<byte>.Empty, pool);
        using Tpm2bPublic template = Tpm2bPublic.CreateKeyedHashTemplate(NameAlg, attributes, scheme, authPolicy: default, pool);

        return await CreateAsync(tpm, registry, pool, parentHandle, inSensitive, template, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues a password-authorized <c>TPM2_Create()</c> under the empty-auth storage parent.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <param name="inSensitive">
    /// The sensitive creation parameters — borrowed; the caller owns and disposes them. The create input is given
    /// a reserialized copy, released with it.
    /// </param>
    /// <param name="template">
    /// The public template — borrowed; the caller owns and disposes it. The create input is given a reserialized
    /// copy, released with it.
    /// </param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The raw create result; the caller disposes the value on success.</returns>
    public static async Task<TpmResult<CreateResponse>> CreateAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, Tpm2bSensitiveCreate inSensitive, Tpm2bPublic template, CancellationToken cancellationToken)
    {
        using Tpm2bSensitiveCreate inSensitiveCopy = CloneSensitiveCreate(inSensitive, pool);
        using Tpm2bPublic templateCopy = ClonePublic(template, pool);
        using CreateInput createInput = new(parentHandle, inSensitiveCopy, templateCopy, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues a password-authorized <c>TPM2_Create()</c> under the empty-auth storage parent whose
    /// <c>inSensitive</c> is marshaled by hand from <paramref name="userAuth"/> and <paramref name="data"/> —
    /// the form a data width the typed sensitive carrier refuses to build needs — and returns the raw result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <param name="userAuth">The authorization value marshaled into <c>inSensitive</c>.</param>
    /// <param name="data">The sensitive data marshaled into <c>inSensitive</c>, unbounded.</param>
    /// <param name="template">The public template — borrowed; the caller owns and disposes it.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The raw create result; the caller disposes the value on success.</returns>
    public static async Task<TpmResult<CreateResponse>> CreateWithRawSensitiveAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, ReadOnlyMemory<byte> userAuth, ReadOnlyMemory<byte> data, Tpm2bPublic template,
        CancellationToken cancellationToken)
    {
        var createInput = new RawSensitiveCreateInput(parentHandle, userAuth, data, template);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The marshaled width of a <c>TPM2B_SENSITIVE_CREATE</c> carrying an authorization value and sensitive data
    /// of the given lengths: the size prefix, then <c>TPM2B_AUTH ‖ TPM2B_SENSITIVE_DATA</c> (TPM 2.0 Library
    /// Part 2, clauses 11.1.15 and 11.1.16, Tables 171 and 172).
    /// </summary>
    /// <param name="userAuthLength">The authorization value length.</param>
    /// <param name="dataLength">The sensitive data length.</param>
    /// <returns>The serialized size.</returns>
    public static int SensitiveCreateSerializedSize(int userAuthLength, int dataLength) =>
        sizeof(ushort) + (sizeof(ushort) + userAuthLength) + (sizeof(ushort) + dataLength);

    /// <summary>
    /// Marshals a <c>TPM2B_SENSITIVE_CREATE</c> straight into <paramref name="writer"/> — <c>TPM2B_AUTH(userAuth)
    /// ‖ TPM2B_SENSITIVE_DATA(data)</c> inside the size-prefixed envelope (TPM 2.0 Library Part 2, clauses
    /// 11.1.15 and 11.1.16, Tables 171 and 172) — without the typed carrier's width bound, so an over-wide data
    /// field can be framed on purpose, and without an intermediate buffer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    /// <param name="userAuth">The authorization value.</param>
    /// <param name="data">The sensitive data.</param>
    public static void WriteSensitiveCreate(ref TpmWriter writer, ReadOnlySpan<byte> userAuth, ReadOnlySpan<byte> data)
    {
        writer.WriteUInt16((ushort)(SensitiveCreateSerializedSize(userAuth.Length, data.Length) - sizeof(ushort)));
        writer.WriteTpm2b(userAuth);
        writer.WriteTpm2b(data);
    }

    /// <summary>Issues a password-authorized <c>TPM2_Load()</c> of a created object under the empty-auth storage parent and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <param name="outPrivate">
    /// The wrapped private blob to load, typically a prior <c>TPM2_Create()</c> or <c>TPM2_Import()</c>
    /// response's <c>OutPrivate</c> — borrowed; the caller owns and disposes it. The load input is given its own
    /// pooled copy, released with it.
    /// </param>
    /// <param name="inPublic">
    /// The public area to load — borrowed; the caller owns and disposes it. The load input is given a
    /// reserialized copy, released with it (the round trip a disk-persisted public blob makes).
    /// </param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The raw load result; the caller disposes the value on success.</returns>
    public static async Task<TpmResult<LoadResponse>> LoadAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, Tpm2bPrivate outPrivate, Tpm2bPublic inPublic, CancellationToken cancellationToken)
    {
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(outPrivate.Span, pool);
        using Tpm2bPublic inPublicCopy = ClonePublic(inPublic, pool);
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublicCopy);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// A created-and-loaded HMAC key's transient handle and an independent pooled clone of its Name, plus — when
    /// <see cref="CreateAndLoadHmacKeyWithPublicAsync"/> produced it — an independent pooled clone of its public
    /// area, both outliving the Create/Load responses that produced them. The caller disposes this to release the
    /// Name and, when present, the public area.
    /// </summary>
    internal sealed class LoadedHmacKey: IDisposable
    {
        /// <summary>Whether the Name and public-area clones this instance owns have already been released.</summary>
        private bool isDisposed;

        /// <summary>Gets the loaded transient object handle.</summary>
        public uint Handle { get; }

        /// <summary>Gets an independent pooled clone of the loaded key's Name.</summary>
        public Tpm2bName Name { get; }

        /// <summary>Gets an independent pooled clone of the loaded key's public area, or <see langword="null"/> when the caller did not request one.</summary>
        public Tpm2bPublic? PublicArea { get; }

        /// <summary>Initializes a loaded HMAC key result, adopting ownership of <paramref name="name"/> and <paramref name="publicArea"/>.</summary>
        /// <param name="handle">The loaded transient object handle.</param>
        /// <param name="name">An independent pooled clone of the Name; owned by this instance.</param>
        /// <param name="publicArea">An independent pooled clone of the public area, owned by this instance, or <see langword="null"/>.</param>
        public LoadedHmacKey(uint handle, Tpm2bName name, Tpm2bPublic? publicArea = null)
        {
            Handle = handle;
            Name = name;
            PublicArea = publicArea;
        }

        /// <summary>Releases the Name clone and, when present, the public area clone this instance owns.</summary>
        public void Dispose()
        {
            if(!isDisposed)
            {
                Name.Dispose();
                PublicArea?.Dispose();
                isDisposed = true;
            }
        }
    }

    /// <summary>
    /// Creates an HMAC key from <paramref name="keyBytes"/> and loads it under <paramref name="parentHandle"/>,
    /// asserting both succeed, and returns the loaded key.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <param name="keyBytes">The HMAC key value (empty when the TPM is to generate it).</param>
    /// <param name="hashAlg">The HMAC scheme hash algorithm.</param>
    /// <param name="userAuth">The key's authorization value.</param>
    /// <param name="isNoDa">Whether the template sets <c>noDA</c>.</param>
    /// <param name="isUserWithAuth">Whether the template sets <c>userWithAuth</c>.</param>
    /// <param name="isDuplicable">Whether the template clears <c>fixedTPM</c> and <c>fixedParent</c>.</param>
    /// <param name="authPolicy">The key's authorization policy digest.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The loaded HMAC key; the caller disposes it.</returns>
    public static Task<LoadedHmacKey> CreateAndLoadHmacKeyAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, ReadOnlyMemory<byte> keyBytes, TpmAlgIdConstants hashAlg,
        ReadOnlyMemory<byte> userAuth = default, bool isNoDa = true, bool isUserWithAuth = true, bool isDuplicable = false, ReadOnlyMemory<byte> authPolicy = default,
        CancellationToken cancellationToken = default) =>
        CreateAndLoadHmacKeyCoreAsync(
            tpm, registry, pool, parentHandle, keyBytes, hashAlg, includePublic: false, userAuth, isNoDa, isUserWithAuth, isDuplicable, authPolicy, cancellationToken);

    /// <summary>
    /// Creates an HMAC key and loads it exactly as <see cref="CreateAndLoadHmacKeyAsync"/> does, additionally
    /// cloning the created public area into the returned <see cref="LoadedHmacKey.PublicArea"/> — the form a
    /// later <c>TPM2_Import()</c> at a different parent presents as <c>objectPublic</c>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <param name="keyBytes">The HMAC key value (empty when the TPM is to generate it).</param>
    /// <param name="hashAlg">The HMAC scheme hash algorithm.</param>
    /// <param name="userAuth">The key's authorization value.</param>
    /// <param name="isNoDa">Whether the template sets <c>noDA</c>.</param>
    /// <param name="isUserWithAuth">Whether the template sets <c>userWithAuth</c>.</param>
    /// <param name="isDuplicable">Whether the template clears <c>fixedTPM</c> and <c>fixedParent</c>.</param>
    /// <param name="authPolicy">The key's authorization policy digest.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The loaded HMAC key, its <see cref="LoadedHmacKey.PublicArea"/> populated; the caller disposes it.</returns>
    public static Task<LoadedHmacKey> CreateAndLoadHmacKeyWithPublicAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, ReadOnlyMemory<byte> keyBytes, TpmAlgIdConstants hashAlg,
        ReadOnlyMemory<byte> userAuth = default, bool isNoDa = true, bool isUserWithAuth = true, bool isDuplicable = false, ReadOnlyMemory<byte> authPolicy = default,
        CancellationToken cancellationToken = default) =>
        CreateAndLoadHmacKeyCoreAsync(
            tpm, registry, pool, parentHandle, keyBytes, hashAlg, includePublic: true, userAuth, isNoDa, isUserWithAuth, isDuplicable, authPolicy, cancellationToken);

    /// <summary>The shared Create-then-Load implementation behind <see cref="CreateAndLoadHmacKeyAsync"/> and <see cref="CreateAndLoadHmacKeyWithPublicAsync"/>.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <param name="keyBytes">The HMAC key value (empty when the TPM is to generate it).</param>
    /// <param name="hashAlg">The HMAC scheme hash algorithm.</param>
    /// <param name="includePublic">Whether the returned key clones the created public area.</param>
    /// <param name="userAuth">The key's authorization value.</param>
    /// <param name="isNoDa">Whether the template sets <c>noDA</c>.</param>
    /// <param name="isUserWithAuth">Whether the template sets <c>userWithAuth</c>.</param>
    /// <param name="isDuplicable">Whether the template clears <c>fixedTPM</c> and <c>fixedParent</c>.</param>
    /// <param name="authPolicy">The key's authorization policy digest.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The loaded HMAC key; the caller disposes it.</returns>
    private static async Task<LoadedHmacKey> CreateAndLoadHmacKeyCoreAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, ReadOnlyMemory<byte> keyBytes, TpmAlgIdConstants hashAlg,
        bool includePublic, ReadOnlyMemory<byte> userAuth, bool isNoDa, bool isUserWithAuth, bool isDuplicable, ReadOnlyMemory<byte> authPolicy,
        CancellationToken cancellationToken)
    {
        TpmResult<CreateResponse> createResult = await CreateHmacKeyAsync(
            tpm, registry, pool, parentHandle, keyBytes, hashAlg, isRestricted: false, isSensitiveDataOrigin: keyBytes.IsEmpty, userAuth,
            isNoDa, isUserWithAuth, isDuplicable, authPolicy, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (HMAC key) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        Tpm2bPublic? publicArea = includePublic ? ClonePublic(created.OutPublic, pool) : null;
        try
        {
            TpmResult<LoadResponse> loadResult = await LoadAsync(
                tpm, registry, pool, parentHandle, created.OutPrivate, created.OutPublic, cancellationToken).ConfigureAwait(false);
            Assert.IsTrue(loadResult.IsSuccess, $"Load (HMAC key) failed: '{loadResult.ResponseCode}'.");
            using LoadResponse loaded = loadResult.Value;

            return new LoadedHmacKey(loaded.ObjectHandle.Value, Tpm2bName.Create(loaded.Name.Span, pool), publicArea);
        }
        catch
        {
            publicArea?.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Reserializes sensitive creation parameters into a fresh carrier through a pinned scratch rental, so a
    /// consuming command input can own the copy while the caller keeps its own. The scratch held the secret
    /// plaintext, so every exit clears it before the rental returns to the pool.
    /// </summary>
    /// <param name="source">The sensitive creation parameters to clone.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>An independent copy of the sensitive creation parameters.</returns>
    public static Tpm2bSensitiveCreate CloneSensitiveCreate(Tpm2bSensitiveCreate source, BaseMemoryPool pool)
    {
        int size = source.SerializedSize;
        using IMemoryOwner<byte> owner = pool.Rent(size, AllocationKind.Pinned);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..size]);
            source.WriteTo(ref writer);
            var reader = new TpmReader(owner.Memory.Span[..size]);

            return Tpm2bSensitiveCreate.Parse(ref reader, pool);
        }
        finally
        {
            owner.Memory.Span[..size].Clear();
        }
    }

    /// <summary>Reserializes a public area into a fresh carrier, the round trip a disk-persisted public blob makes.</summary>
    /// <param name="source">The public area to clone.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>An independent copy of the public area.</returns>
    public static Tpm2bPublic ClonePublic(Tpm2bPublic source, BaseMemoryPool pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);
        var reader = new TpmReader(owner.Memory.Span[..size]);

        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>Runs one <c>TPM2_HMAC()</c> over an empty-auth key and returns the raw result for the caller to assert.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The loaded HMAC key handle.</param>
    /// <param name="data">The data to authenticate.</param>
    /// <param name="hashAlg">The requested hash algorithm (may be <c>TPM_ALG_NULL</c> to use the key's default).</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The raw HMAC result; the caller disposes the value on success.</returns>
    public static Task<TpmResult<HmacResponse>> HmacAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint keyHandle, ReadOnlyMemory<byte> data, TpmAlgIdConstants hashAlg, CancellationToken cancellationToken) =>
        HmacAsync(tpm, registry, pool, keyHandle, data, hashAlg, ReadOnlyMemory<byte>.Empty, cancellationToken);

    /// <summary>Runs one <c>TPM2_HMAC()</c> presenting <paramref name="keyPassword"/> for the key and returns the raw result for the caller to assert.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The loaded HMAC key handle.</param>
    /// <param name="data">The data to authenticate.</param>
    /// <param name="hashAlg">The requested hash algorithm (may be <c>TPM_ALG_NULL</c> to use the key's default).</param>
    /// <param name="keyPassword">The password presented in the key's <c>TPM_RS_PW</c> session.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The raw HMAC result; the caller disposes the value on success.</returns>
    public static async Task<TpmResult<HmacResponse>> HmacAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint keyHandle, ReadOnlyMemory<byte> data, TpmAlgIdConstants hashAlg,
        ReadOnlyMemory<byte> keyPassword, CancellationToken cancellationToken)
    {
        using HmacInput input = HmacInput.Create(TpmiDhObject.FromValue(keyHandle), data.Span, TpmiAlgHash.FromValue(hashAlg), pool);
        using TpmPasswordSession keyAuth = PasswordSession(keyPassword, pool);

        return await TpmCommandExecutor.ExecuteAsync<HmacResponse>(
            tpm, input, [keyAuth], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues <c>TPM2_HMAC_Start()</c> and returns the raw result for the caller to assert.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The loaded HMAC key handle.</param>
    /// <param name="hashAlg">The requested hash algorithm (may be <c>TPM_ALG_NULL</c>).</param>
    /// <param name="keyPassword">The password presented in the key's <c>TPM_RS_PW</c> session.</param>
    /// <param name="sequenceAuth">The authorization value assigned to the new sequence (Table 80's <c>auth</c>).</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The raw result.</returns>
    public static async Task<TpmResult<HmacStartResponse>> HmacStartAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint keyHandle, TpmAlgIdConstants hashAlg,
        ReadOnlyMemory<byte> keyPassword, ReadOnlyMemory<byte> sequenceAuth, CancellationToken cancellationToken)
    {
        using HmacStartInput input = HmacStartInput.Create(TpmiDhObject.FromValue(keyHandle), sequenceAuth.Span, TpmiAlgHash.FromValue(hashAlg), pool);
        using TpmPasswordSession keyAuth = PasswordSession(keyPassword, pool);

        return await TpmCommandExecutor.ExecuteAsync<HmacStartResponse>(
            tpm, input, [keyAuth], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Runs one <c>TPM2_HMAC()</c> authorized by a real session — an HMAC session or a policy session — over
    /// the key whose Name is <paramref name="keyName"/>, and returns the raw result for the caller to assert.
    /// The command HMAC (and the response HMAC an <see cref="TpmSession"/> verifies) travels over the real wire.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The authorizing session; the caller owns and disposes it.</param>
    /// <param name="keyHandle">The loaded HMAC key handle.</param>
    /// <param name="keyName">The key's Name, cpHash's single handle-Name term.</param>
    /// <param name="data">The data to authenticate.</param>
    /// <param name="hashAlg">The requested hash algorithm (may be <c>TPM_ALG_NULL</c> to use the key's default).</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The raw HMAC result; the caller disposes the value on success.</returns>
    public static async Task<TpmResult<HmacResponse>> HmacOverSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSessionBase session, uint keyHandle, ReadOnlyMemory<byte> keyName,
        ReadOnlyMemory<byte> data, TpmAlgIdConstants hashAlg, CancellationToken cancellationToken)
    {
        using HmacInput input = HmacInput.Create(TpmiDhObject.FromValue(keyHandle), data.Span, TpmiAlgHash.FromValue(hashAlg), pool);

        return await TpmCommandExecutor.ExecuteAsync<HmacResponse>(
            tpm, input, [session], [keyName], pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Runs one <c>TPM2_HMAC_Start()</c> authorized by a real session over the key whose Name is
    /// <paramref name="keyName"/>, and returns the raw result for the caller to assert.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The authorizing session; the caller owns and disposes it.</param>
    /// <param name="keyHandle">The loaded HMAC key handle.</param>
    /// <param name="keyName">The key's Name, cpHash's single handle-Name term.</param>
    /// <param name="hashAlg">The requested hash algorithm (may be <c>TPM_ALG_NULL</c>).</param>
    /// <param name="sequenceAuth">The authorization value assigned to the new sequence (Table 80's <c>auth</c>).</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The raw result.</returns>
    public static async Task<TpmResult<HmacStartResponse>> HmacStartOverSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSessionBase session, uint keyHandle, ReadOnlyMemory<byte> keyName,
        TpmAlgIdConstants hashAlg, ReadOnlyMemory<byte> sequenceAuth, CancellationToken cancellationToken)
    {
        using HmacStartInput input = HmacStartInput.Create(TpmiDhObject.FromValue(keyHandle), sequenceAuth.Span, TpmiAlgHash.FromValue(hashAlg), pool);

        return await TpmCommandExecutor.ExecuteAsync<HmacStartResponse>(
            tpm, input, [session], [keyName], pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues <c>TPM2_SequenceUpdate()</c> presenting <paramref name="sequencePassword"/> and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The open sequence handle.</param>
    /// <param name="buffer">The block to append.</param>
    /// <param name="sequencePassword">The password presented in the sequence's <c>TPM_RS_PW</c> session.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The raw result.</returns>
    public static async Task<TpmResult<SequenceUpdateResponse>> SequenceUpdateAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, ReadOnlyMemory<byte> buffer,
        ReadOnlyMemory<byte> sequencePassword, CancellationToken cancellationToken)
    {
        using TpmPasswordSession sequenceAuth = PasswordSession(sequencePassword, pool);
        using SequenceUpdateInput input = SequenceUpdateInput.Create(sequenceHandle, buffer.Span, pool);

        return await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
            tpm, input, [sequenceAuth], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues <c>TPM2_SequenceComplete()</c> presenting <paramref name="sequencePassword"/> and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence to complete.</param>
    /// <param name="buffer">The trailing block.</param>
    /// <param name="sequencePassword">The password presented in the sequence's <c>TPM_RS_PW</c> session.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The raw result; the caller owns a successful value.</returns>
    public static async Task<TpmResult<SequenceCompleteResponse>> SequenceCompleteAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, ReadOnlyMemory<byte> buffer,
        ReadOnlyMemory<byte> sequencePassword, CancellationToken cancellationToken)
    {
        using TpmPasswordSession sequenceAuth = PasswordSession(sequencePassword, pool);
        using SequenceCompleteInput input = SequenceCompleteInput.Create(sequenceHandle, buffer.Span, TpmiRhHierarchy.Owner, pool);

        return await TpmCommandExecutor.ExecuteAsync<SequenceCompleteResponse>(
            tpm, input, [sequenceAuth], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues <c>TPM2_FlushContext()</c> for a handle and returns the raw result for the caller to assert.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The raw result.</returns>
    public static async Task<TpmResult<FlushContextResponse>> FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle, CancellationToken cancellationToken)
    {
        FlushContextInput input = FlushContextInput.ForHandle(handle);

        return await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Flushes a transient object or session handle when one is present (non-zero), ignoring the result — for teardown only.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush, or 0 when none was acquired.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A task that completes once the flush is issued.</returns>
    public static async Task FlushIfPresentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle, CancellationToken cancellationToken)
    {
        if(handle == 0)
        {
            return;
        }

        _ = await FlushAsync(tpm, registry, pool, handle, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The <c>TPM2_PolicyCommandCode(TPM_CC_Duplicate)</c> policy digest over a fresh session (TPM 2.0 Library
    /// Part 3, clause 23.11), the minimal DUP-role policy a duplicable key binds to.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The SHA-256 policy digest; the caller disposes it.</returns>
    public static Tpm2bDigest DuplicationPolicyDigest(BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> currentOwner = pool.Rent(32);
        Span<byte> current = currentOwner.Memory.Span[..32];
        current.Clear();

        using IMemoryOwner<byte> destinationOwner = pool.Rent(32);
        Span<byte> destination = destinationOwner.Memory.Span[..32];
        _ = TpmPolicyDigest.ExtendForCommandCode(current, TpmCcConstants.TPM_CC_Duplicate, NameAlg, destination);

        return Tpm2bDigest.Create(destination, pool);
    }

    /// <summary>
    /// Runs the DUP-role export of a duplicable KEYEDHASH object to <paramref name="newParentHandle"/> under a
    /// fresh policy session that has latched <c>TPM_CC_Duplicate</c>, asserting success, and returns the response
    /// (TPM 2.0 Library Part 3, clause 13.1).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="objectHandle">The loaded duplicable object.</param>
    /// <param name="objectName">The object's Name.</param>
    /// <param name="newParentHandle">The new parent handle, or <c>TPM_RH_NULL</c> for the bare form.</param>
    /// <param name="newParentName">The new parent's Name (a permanent handle's own four octets for <c>TPM_RH_NULL</c>).</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>
    /// The duplication response; the caller disposes it. Its <c>Duplicate</c> (<see cref="Tpm2bPrivate"/>) is the
    /// migration blob and its <c>OutSymSeed</c> (<see cref="Tpm2bEncryptedSecret"/>) is the transported seed.
    /// </returns>
    public static async Task<DuplicateResponse> DuplicateAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint objectHandle, ReadOnlyMemory<byte> objectName, uint newParentHandle, ReadOnlyMemory<byte> newParentName,
        CancellationToken cancellationToken)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(NameAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");
        uint sessionHandle;
        using(StartAuthSessionResponse started = startResult.Value)
        {
            sessionHandle = started.SessionHandle.Value;
        }

        try
        {
            PolicyCommandCodeInput commandCodeInput = PolicyCommandCodeInput.Create(sessionHandle, TpmCcConstants.TPM_CC_Duplicate);
            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await TpmCommandExecutor.ExecuteAsync<PolicyCommandCodeResponse>(
                tpm, commandCodeInput, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            DuplicateInput input = new(objectHandle, newParentHandle);
            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, NameAlg, pool);
            TpmResult<DuplicateResponse> result = await TpmCommandExecutor.ExecuteAsync<DuplicateResponse>(
                tpm, input, [policySession], [objectName, newParentName], pool, registry, cancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Duplicate failed: '{result.ResponseCode}'.");

            return result.Value;
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Issues a password-authorized <c>TPM2_Import()</c> under the empty-auth parent and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The importing storage parent.</param>
    /// <param name="objectPublic">The duplicated object's public area — borrowed; the caller owns and disposes it.</param>
    /// <param name="duplicate">The duplication blob — borrowed; the caller owns and disposes it.</param>
    /// <param name="inSymSeed">The transported seed — borrowed; the caller owns and disposes it. <see cref="Tpm2bEncryptedSecret.Empty"/> for the bare form.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The raw import result; the caller disposes the value on success.</returns>
    public static async Task<TpmResult<ImportResponse>> ImportAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, Tpm2bPublic objectPublic, Tpm2bPrivate duplicate, Tpm2bEncryptedSecret inSymSeed,
        CancellationToken cancellationToken)
    {
        int publicSize = objectPublic.GetSerializedSize();
        using IMemoryOwner<byte> publicOwner = pool.Rent(publicSize);
        Span<byte> marshaledPublic = publicOwner.Memory.Span[..publicSize];
        var publicWriter = new TpmWriter(marshaledPublic);
        objectPublic.WriteTo(ref publicWriter);

        using ImportInput importInput = ImportInput.Create(parentHandle, marshaledPublic, duplicate.Span, inSymSeed.Span, pool);
        using TpmPasswordSession importParentAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<ImportResponse>(
            tpm, importInput, [importParentAuth], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Starts an unsalted HMAC session bound to <paramref name="bindHandle"/> (an empty-auth entity) that
    /// negotiates no symmetric algorithm, and builds the host-side <see cref="TpmSession"/> that authorizes
    /// commands over it, with <c>continueSession</c> SET — the parameter-encryption-free form of
    /// <see cref="StartBoundHmacSessionAsync(TpmDevice, TpmResponseRegistry, BaseMemoryPool, uint, ReadOnlyMemory{byte}, TpmtSymDef, bool, CancellationToken)"/>.
    /// The caller disposes the session and flushes the handle.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="bindHandle">The entity the session is bound to.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The session handle and the host session.</returns>
    public static Task<(uint SessionHandle, TpmSession Session)> StartBoundHmacSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint bindHandle, CancellationToken cancellationToken) =>
        StartBoundHmacSessionAsync(tpm, registry, pool, bindHandle, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Null, isBoundToAuthorizedEntity: false, cancellationToken);

    /// <summary>
    /// Starts an unsalted HMAC session bound to <paramref name="bindHandle"/>, whose authorization value is
    /// <paramref name="bindAuth"/>, negotiating <paramref name="symmetric"/> for session-based parameter
    /// encryption (TPM 2.0 Library Part 1, clause 18.1), and builds the host-side <see cref="TpmSession"/> that
    /// authorizes commands over it, with <c>continueSession</c> SET. The started response's <c>nonceTPM</c>
    /// passes into the session, which owns it from then on. The caller disposes the session and flushes the
    /// handle.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="bindHandle">The entity the session is bound to.</param>
    /// <param name="bindAuth">The bind entity's authorization value, folded into the session key (Part 1, clause 16.6.12, equation 25); empty for an empty-auth entity.</param>
    /// <param name="symmetric">The symmetric definition the session negotiates; <see cref="TpmtSymDef.Null"/> for none.</param>
    /// <param name="isBoundToAuthorizedEntity">Whether the session will authorize the very entity it is bound to, so the host's command HMAC key omits that entity's authorization value (Part 1, clause 16.6.10, equation 22) while its cipher key keeps it (clause 18.1).</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The session handle and the host session.</returns>
    public static async Task<(uint SessionHandle, TpmSession Session)> StartBoundHmacSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint bindHandle, ReadOnlyMemory<byte> bindAuth, TpmtSymDef symmetric,
        bool isBoundToAuthorizedEntity, CancellationToken cancellationToken)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(bindHandle, NameAlg, symmetric);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound HMAC) failed: '{startResult.ResponseCode}'.");

        //The response owns nothing but nonceTPM, and TpmSession.CreateBoundAsync takes that over (disposing it
        //itself if the key derivation fails), so the response is deliberately not disposed here.
        StartAuthSessionResponse started = startResult.Value;

        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(started.SessionHandle.Value), bindAuth, startInput.NonceCaller,
            started.NonceTPM, NameAlg, pool, symmetric: symmetric, isBoundToAuthorizedEntity: isBoundToAuthorizedEntity, cancellationToken: cancellationToken).ConfigureAwait(false);
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (started.SessionHandle.Value, session);
    }

    /// <summary>
    /// Applies the session-index response-code modifier a TPM adds when a failure is attributed to a specific
    /// authorization session: <c>rc = baseRc + TPM_RC_S + 0x100 * (sessionIndex + 1)</c> (TPM 2.0 Library Part 2,
    /// clause 6.6.2).
    /// </summary>
    /// <param name="baseRc">The unmodified format-1 response code.</param>
    /// <param name="sessionIndex">The zero-based index of the session the failure names.</param>
    /// <returns>The session-index-encoded response code.</returns>
    public static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>Builds a <c>TPM_RS_PW</c> session carrying <paramref name="password"/>, the empty session for an empty value.</summary>
    /// <param name="password">The password to present.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The password session.</returns>
    public static TpmPasswordSession PasswordSession(ReadOnlyMemory<byte> password, BaseMemoryPool pool) =>
        password.IsEmpty ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(password.Span, pool);

    /// <summary>
    /// A <c>TPM2_Create()</c> input that marshals <c>inSensitive</c> by hand from an authorization value and
    /// sensitive data, so a frame the typed sensitive carrier refuses to build (an over-wide data field) can
    /// still ride the production executor under any authorization session. It owns nothing: the value and data
    /// memory are the caller's and the template is borrowed.
    /// </summary>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <param name="userAuth">The authorization value marshaled into <c>inSensitive</c>.</param>
    /// <param name="data">The sensitive data marshaled into <c>inSensitive</c>, unbounded.</param>
    /// <param name="template">The public template — borrowed; the caller owns and disposes it.</param>
    internal sealed class RawSensitiveCreateInput(uint parentHandle, ReadOnlyMemory<byte> userAuth, ReadOnlyMemory<byte> data, Tpm2bPublic template): ITpmCommandInput
    {
        /// <summary>The <c>TPM2_Create()</c> command code.</summary>
        public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_Create;

        /// <summary>
        /// Whether the first parameter may be encrypted: <c>inSensitive</c> is encryptable in principle, but this
        /// raw form never asks for parameter encryption, so it declares none.
        /// </summary>
        public bool FirstCommandParameterIsEncryptable => false;

        /// <summary>The handle area plus <c>inSensitive ‖ inPublic ‖ outsideInfo ‖ creationPCR</c>.</summary>
        /// <returns>The serialized size.</returns>
        public int GetSerializedSize() =>
            sizeof(uint) + SensitiveCreateSerializedSize(userAuth.Length, data.Length) + template.GetSerializedSize() + sizeof(ushort) + sizeof(uint);

        /// <summary>Writes <c>@parentHandle</c>.</summary>
        /// <param name="writer">The writer.</param>
        public void WriteHandles(ref TpmWriter writer) => writer.WriteUInt32(parentHandle);

        /// <summary>Marshals <c>inSensitive</c>, then writes <c>inPublic</c>, an empty <c>outsideInfo</c>, and an empty <c>creationPCR</c>.</summary>
        /// <param name="writer">The writer.</param>
        public void WriteParameters(ref TpmWriter writer)
        {
            WriteSensitiveCreate(ref writer, userAuth.Span, data.Span);
            template.WriteTo(ref writer);
            writer.WriteUInt16(0);
            writer.WriteUInt32(0);
        }
    }
}
