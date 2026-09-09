using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tests.TestInfrastructure;
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
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the plain (<c>TPM_ST_NO_SESSIONS</c>) form of <c>TPM2_ContextSave()</c> against the in-house
/// behavioural <see cref="TpmSimulator"/> through the production command path (<see cref="TpmCommandExecutor"/>
/// with <see cref="ContextSaveInput"/> and <see cref="TpmResponseCodec.ContextSave"/>): "This command saves a
/// session context, object context, or sequence object context outside the TPM. No authorization sessions of
/// any type are allowed with this command and tag is required to be TPM_ST_NO_SESSIONS".
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.2.1</see>.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorContextSaveTests
{
    /// <summary>The Name algorithm used throughout.</summary>
    private const TpmAlgIdConstants NameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA modulus width in bits every key in this class uses.</summary>
    private const ushort RsaKeyBits = 2048;

    /// <summary>SHA-256's digest width in octets, used to build the HMAC key recipe's fixed seed.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>
    /// A handle from this class's assigned NV-index block (<c>0x0100_0200..0x0100_020F</c>): never defined as a
    /// live index, used only as a raw handle value outside Table 57's admitted ranges.
    /// </summary>
    private const uint NvIndexHandle = 0x0100_0200u;

    /// <summary>A persistent handle, likewise used only as a raw value outside Table 57's admitted ranges.</summary>
    private const uint PersistentHandle = 0x8100_0001u;

    /// <summary>
    /// How many <see cref="Tpm2bMaxBuffer.MaxSize"/>-octet <c>TPM2_SequenceUpdate()</c> blocks
    /// <see cref="GrowSequenceOverContextCapacityAsync"/> feeds a sequence: enough that the retained segments
    /// alone, once the context blob's own 42-octet framing (a 34-octet integrity field, an 8-octet fingerprint)
    /// is added, exceed <see cref="Tpm2bContextData.MaxSize"/>.
    /// </summary>
    private const int SequenceUpdatesToExceedContextCapacity = 70;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// An ordinary transient key (a Table 58 <c>0x80000000</c> stamp, an object whose own <c>stClear</c> is not
    /// SET) is saved twice in a row - once as an RSA key, once as an ECC key - and each save advances "the
    /// counter (objectContextID)" (TPM 2.0 Library Part 1, clause 27.2.2) by exactly one, independent of which
    /// object it stamped; the framed blob carries at least the 42-octet integrity-and-fingerprint framing plus
    /// one octet of serialized resource.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.12, Table 58</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextSaveOrdinaryTransientObjectsGetSequentialObjectCounterValues()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextSaveOrdinaryTransientObjectsGetSequentialObjectCounterValues), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse rsaKey = await CreateRsaSigningKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreatePrimaryResponse eccKey = await CreateEccSigningKeyAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<ContextSaveResponse> rsaSaved = await SaveAsync(tpm, registry, pool, rsaKey.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(rsaSaved.IsSuccess, $"Saving the RSA key must succeed: '{rsaSaved.ResponseCode}'.");
        using ContextSaveResponse rsaContext = rsaSaved.Value;
        Assert.AreEqual(TpmiDhSaved.OrdinaryTransientObject, rsaContext.Context.SavedHandle.Value, "An ordinary object (stClear CLEAR) is stamped 0x80000000.");
        Assert.AreEqual(TpmiRhHierarchy.Owner, rsaContext.Context.Hierarchy, "The saved hierarchy is the key's own - TPM_RH_OWNER here.");
        Assert.AreEqual(1ul, rsaContext.Context.Sequence, "The object counter's first stamp is 1.");
        Assert.IsGreaterThan(42, rsaContext.Context.ContextBlob.Length, "The blob carries the 34-octet integrity field, the 8-octet fingerprint, and at least one octet of serialized resource.");

        TpmResult<ContextSaveResponse> eccSaved = await SaveAsync(tpm, registry, pool, eccKey.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(eccSaved.IsSuccess, $"Saving the ECC key must succeed: '{eccSaved.ResponseCode}'.");
        using ContextSaveResponse eccContext = eccSaved.Value;
        Assert.AreEqual(TpmiDhSaved.OrdinaryTransientObject, eccContext.Context.SavedHandle.Value, "The ECC key is likewise an ordinary object.");
        Assert.AreEqual(2ul, eccContext.Context.Sequence, "The object counter advances to 2 for the second save, regardless of which object it saved.");
    }

    /// <summary>
    /// "When an object's context is saved, a copy of the object context is integrity protected, encrypted, and
    /// returned to the caller. The original context remains in the TPM and the TPM retains its handle.": after a
    /// successful save, <c>TPM2_ReadPublic()</c> at the same handle still succeeds and answers the identical Name.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.4</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextSaveLeavesTheObjectLoadedAndReadPublicAnswersTheSameName()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextSaveLeavesTheObjectLoadedAndReadPublicAnswersTheSameName), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaSigningKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] nameBeforeSave = key.Name.Span.ToArray();

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, key.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"The save must succeed: '{saved.ResponseCode}'.");
        saved.Value.Dispose();

        TpmResult<ReadPublicResponse> readAfterSave = await ReadPublicAsync(tpm, registry, pool, key.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(readAfterSave.IsSuccess, $"TPM2_ReadPublic() at the same handle must still succeed after the save: '{readAfterSave.ResponseCode}'.");
        using ReadPublicResponse readResponse = readAfterSave.Value;
        Assert.IsTrue(readResponse.Name.Span.SequenceEqual(nameBeforeSave), "The object's Name is unchanged - the original stays loaded at its original handle.");
    }

    /// <summary>
    /// Table 58's <c>0x80000002</c> arm - "a transient object with the stClear attribute SET" - is stamped only
    /// when the resolved object's own <c>TPMA_OBJECT.stClear</c> bit is SET; a key built with that bit carries
    /// the stamp home rather than the ordinary <c>0x80000000</c> value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.12, Table 58</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextSaveStClearObjectIsStampedWithTheStClearSavedHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextSaveStClearObjectIsStampedWithTheStClearSavedHandle), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<CreatePrimaryResponse> created = await TryCreateStClearRsaKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.IsTrue(created.IsSuccess, $"TPM2_CreatePrimary() must admit a template with TPMA_OBJECT.stClear SET: '{created.ResponseCode}'.");
        using CreatePrimaryResponse key = created.Value;

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, key.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"Saving the stClear object must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse context = saved.Value;
        Assert.AreEqual(TpmiDhSaved.StClearTransientObject, context.Context.SavedHandle.Value, "An object whose own stClear attribute is SET is stamped 0x80000002.");
    }

    /// <summary>
    /// A loaded sealed (KEYEDHASH) object resolves through <c>LoadedKeyedHashObjects</c> exactly like a key
    /// through <c>TransientObjects</c>: it is stamped the same ordinary <c>0x80000000</c> value, and its
    /// hierarchy follows its own - here its storage parent's owner hierarchy.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.12, Table 58</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextSaveLoadedSealedObjectIsStampedOrdinaryWithItsOwnHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextSaveLoadedSealedObjectIsStampedOrdinaryWithItsOwnHierarchy), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreateResponse sealedBlob = await CreateSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle).ConfigureAwait(false);
        (TpmiDhObject sealedHandle, byte[] _) = await LoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle, sealedBlob).ConfigureAwait(false);

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, sealedHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"Saving the loaded sealed object must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse context = saved.Value;
        Assert.AreEqual(TpmiDhSaved.OrdinaryTransientObject, context.Context.SavedHandle.Value, "A loaded KEYEDHASH (sealed) object is an ordinary object exactly like a key.");
        Assert.AreEqual(TpmiRhHierarchy.Owner, context.Context.Hierarchy, "The sealed object's hierarchy follows its storage parent's own (TPM_RH_OWNER here).");
    }

    /// <summary>
    /// A loaded HMAC (KEYEDHASH) key, unlike the sealed-object recipe above, was placed in the NULL hierarchy by
    /// <c>TPM2_LoadExternal()</c>: it is stamped the same ordinary <c>0x80000000</c> value, but the saved
    /// hierarchy carries NULL rather than an owner-derived value - Table 58's arm depends only on the object's
    /// own <c>stClear</c> bit, never on which hierarchy it lives in.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.12, Table 58</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextSaveLoadedHmacKeyIsStampedOrdinaryWithTheNullHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextSaveLoadedHmacKeyIsStampedOrdinaryWithTheNullHierarchy), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using LoadExternalResponse hmacKey = await LoadHmacKeyAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, hmacKey.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"Saving the loaded HMAC key must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse context = saved.Value;
        Assert.AreEqual(TpmiDhSaved.OrdinaryTransientObject, context.Context.SavedHandle.Value, "The loaded HMAC (KEYEDHASH) key is an ordinary object.");
        Assert.AreEqual(TpmiRhHierarchy.Null, context.Context.Hierarchy, "TPM2_LoadExternal() placed the key in the NULL hierarchy; the saved context carries that same hierarchy.");
    }

    /// <summary>
    /// Table 58's <c>0x80000001</c> arm names "a sequence object": an open hash sequence context is saved with
    /// that stamp, and - "Sequence objects and sessions are in the NULL hierarchy" - the NULL hierarchy.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.2.4</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextSaveOpenHashSequenceIsStampedSequenceObjectWithTheNullHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextSaveOpenHashSequenceIsStampedSequenceObjectWithTheNullHierarchy), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, sequenceHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"Saving an open hash sequence must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse context = saved.Value;
        Assert.AreEqual(TpmiDhSaved.SequenceObject, context.Context.SavedHandle.Value, "An open sequence context is stamped 0x80000001.");
        Assert.AreEqual(TpmiRhHierarchy.Null, context.Context.Hierarchy, "Sequence objects are in the NULL hierarchy.");
    }

    /// <summary>
    /// "The context associated with a session is unique. That is, the data describing the session's state may be
    /// either on the TPM or saved off the TPM, but not both.": a started HMAC or policy session is saved under
    /// its OWN handle (Table 58 needs no fixed stand-in for a session), carries the NULL hierarchy and the
    /// session counter's first stamp, and is thereafter gone from RAM - a second save of the same handle is
    /// refused, yet the vacated slot still admits a fresh <c>TPM2_StartAuthSession()</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.5</see>.
    /// </summary>
    /// <param name="kind">Which session kind is started and saved.</param>
    [TestMethod]
    [DataRow(SessionKind.Hmac)]
    [DataRow(SessionKind.Policy)]
    public async Task ContextSaveOfAStartedSessionYieldsItsOwnHandleAndRemovesItFromRam(SessionKind kind)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(ContextSaveOfAStartedSessionYieldsItsOwnHandleAndRemovesItFromRam)}-{kind}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartSessionAsync(tpm, registry, pool, kind).ConfigureAwait(false);

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"Saving the {kind} session must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse context = saved.Value;
        Assert.AreEqual(sessionHandle, context.Context.SavedHandle.Value, "A session's own handle stands in as its savedHandle.");
        Assert.AreEqual(TpmiRhHierarchy.Null, context.Context.Hierarchy, "Session contexts belong to the NULL hierarchy.");
        Assert.AreEqual(1ul, context.Context.Sequence, "The session counter's first stamp is 1.");

        TpmResult<ContextSaveResponse> replaySave = await SaveAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, replaySave.ResponseCode, "Once saved, the session is gone from RAM: saveHandle (the sole handle, index 0) references a session no longer present, TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.4).");

        _ = await StartSessionAsync(tpm, registry, pool, kind).ConfigureAwait(false);
    }

    /// <summary>
    /// "One counter is used for transient and sequence object contexts. A second counter is used for session
    /// contexts.": an object save and a session save each answer sequence 1 independently - neither counter
    /// observes the other's activity.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.2.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextSaveObjectAndSessionCountersAdvanceIndependently()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextSaveObjectAndSessionCountersAdvanceIndependently), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaSigningKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmResult<ContextSaveResponse> objectSaved = await SaveAsync(tpm, registry, pool, key.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(objectSaved.IsSuccess, $"The object save must succeed: '{objectSaved.ResponseCode}'.");
        using ContextSaveResponse objectContext = objectSaved.Value;

        uint sessionHandle = await StartSessionAsync(tpm, registry, pool, SessionKind.Hmac).ConfigureAwait(false);
        TpmResult<ContextSaveResponse> sessionSaved = await SaveAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        Assert.IsTrue(sessionSaved.IsSuccess, $"The session save must succeed: '{sessionSaved.ResponseCode}'.");
        using ContextSaveResponse sessionContext = sessionSaved.Value;

        Assert.AreEqual(1ul, objectContext.Context.Sequence, "The object counter's first stamp is 1, independent of any session activity.");
        Assert.AreEqual(1ul, sessionContext.Context.Sequence, "The session counter's first stamp is likewise 1 - a separate counter from the object's.");
    }

    /// <summary>
    /// Table 57's <c>TPMI_DH_CONTEXT</c> admits only the HMAC session range, the policy session range, and the
    /// transient-object range - "The Table 57 type defines the handle values that may be used in
    /// TPM2_ContextSave() or TPM2_Flush()." - so a permanent handle, an NV Index, a persistent handle, or
    /// <c>TPM_RH_NULL</c> is <c>TPM_RC_VALUE</c>, handle-encoded to the same index at parse, before any table is resolved.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.11, Table 57</see>.
    /// </summary>
    /// <param name="handle">The out-of-range raw handle value under test.</param>
    [TestMethod]
    [DataRow((uint)TpmRh.TPM_RH_OWNER)]
    [DataRow(NvIndexHandle)]
    [DataRow(PersistentHandle)]
    [DataRow((uint)TpmRh.TPM_RH_NULL)]
    public async Task ContextSaveHandleOutsideTable57IsRefusedWithValue(uint handle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(ContextSaveHandleOutsideTable57IsRefusedWithValue)}-{handle:X8}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, handle).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, handleIndex: 0), saved.ResponseCode,
            $"Table 224: saveHandle is TPM2_ContextSave()'s sole handle (index 0); 0x{handle:X8} is outside Table 57's three admitted ranges.");
        DisposeIfSuccess(saved);
    }

    /// <summary>
    /// A handle inside Table 57's transient range that names no loaded resource of any kind is
    /// <c>TPM_RC_REFERENCE_H0</c> - <c>saveHandle</c> is <c>TPM2_ContextSave()</c>'s sole handle (index 0), and
    /// <c>TPMI_DH_CONTEXT</c> never admits the persistent range, so every reachable miss here is an unloaded
    /// transient object.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.4, step 2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextSaveUnloadedTransientHandleAnswersReferenceH0()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextSaveUnloadedTransientHandleAnswersReferenceH0), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, TpmHandleRanges.TRANSIENT_FIRST + 0xFF).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, saved.ResponseCode, "saveHandle is TPM2_ContextSave()'s sole handle (index 0); an in-range transient value naming nothing loaded is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1).");
        DisposeIfSuccess(saved);
    }

    /// <summary>
    /// A handle inside Table 57's HMAC-session or policy-session range that names no loaded session is likewise
    /// <c>TPM_RC_REFERENCE_H0</c> - <c>saveHandle</c>'s sole (index 0) position, over a session range instead of
    /// the transient-object range, the session-in-the-handle-area branch of the same clause.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.4, step 2.4</see>.
    /// </summary>
    /// <param name="handle">The unloaded in-range session handle under test.</param>
    [TestMethod]
    [DataRow(TpmHandleRanges.HMAC_SESSION_FIRST + 0xFF)]
    [DataRow(TpmHandleRanges.POLICY_SESSION_FIRST + 0xFF)]
    public async Task ContextSaveUnloadedSessionHandleAnswersReferenceH0(uint handle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(ContextSaveUnloadedSessionHandleAnswersReferenceH0)}-{handle:X8}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, handle).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, saved.ResponseCode, "saveHandle is TPM2_ContextSave()'s sole handle (index 0); an in-range session value naming no loaded session is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.4).");
        DisposeIfSuccess(saved);
    }

    /// <summary>
    /// "No authorization sessions of any type are allowed with this command and tag is required to be
    /// TPM_ST_NO_SESSIONS": a <c>TPM_ST_SESSIONS</c>-tagged arrival is refused with bare <c>TPM_RC_BAD_TAG</c>
    /// before the handle is even read.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextSaveWithSessionsTagIsRefusedWithBadTag()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextSaveWithSessionsTagIsRefusedWithBadTag), pool).ConfigureAwait(false);

        byte[] body = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(body, TpmHandleRanges.TRANSIENT_FIRST);

        TpmRcConstants responseCode = await SubmitContextSaveFramedAsync(simulator, pool, (ushort)TpmStConstants.TPM_ST_SESSIONS, body).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_TAG, responseCode, "tag is required to be TPM_ST_NO_SESSIONS - a TPM_ST_SESSIONS arrival is refused before the handle is even read.");
    }

    /// <summary>
    /// Table 224 carries one handle-area handle and no parameters at all: an octet trailing an otherwise
    /// well-formed frame is <c>TPM_RC_SIZE</c> (clause 5.2's general wire-shape rule).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.2, Table 224</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextSaveWithATrailingOctetIsRefusedWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextSaveWithATrailingOctetIsRefusedWithSize), pool).ConfigureAwait(false);

        byte[] body = new byte[sizeof(uint) + 1];
        BinaryPrimitives.WriteUInt32BigEndian(body, TpmHandleRanges.TRANSIENT_FIRST);
        body[^1] = 0xA5;

        TpmRcConstants responseCode = await SubmitContextSaveFramedAsync(simulator, pool, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, body).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, responseCode, "TPM2_ContextSave() carries no parameters beyond saveHandle; a trailing octet after it is TPM_RC_SIZE.");
    }

    /// <summary>
    /// A serialized resource wider than <see cref="Tpm2bContextData.MaxSize"/> can carry is refused with
    /// <c>TPM_RC_MEMORY</c> - "need space for internal operations", Table 3's general description of the code -
    /// judged before any crypto runs: a hash sequence fed enough <c>TPM2_SequenceUpdate()</c> blocks to retain
    /// more octets than a UINT16-sized blob can frame trips this refusal at the next save.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 6.2, Table 3</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextSaveOverSizeSequenceIsRefusedWithMemory()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextSaveOverSizeSequenceIsRefusedWithMemory), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool).ConfigureAwait(false);
        await GrowSequenceOverContextCapacityAsync(tpm, registry, pool, sequenceHandle).ConfigureAwait(false);

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, sequenceHandle.Value).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_MEMORY, saved.ResponseCode, "A serialization wider than the TPM2B_CONTEXT_DATA ceiling is TPM_RC_MEMORY.");
        DisposeIfSuccess(saved);
    }

    /// <summary>
    /// "TPM_RC_INITIALIZE": a command submitted before <c>TPM2_Startup()</c> is refused before any of this
    /// command's own rules run.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 12.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextSavePreStartupIsRefusedWithInitialize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = new TpmSimulator(
            $"tpm-in-house-context-save-{nameof(ContextSavePreStartupIsRefusedWithInitialize)}", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, TpmHandleRanges.TRANSIENT_FIRST).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_INITIALIZE, saved.ResponseCode, "Before TPM2_Startup() every command is TPM_RC_INITIALIZE.");
        DisposeIfSuccess(saved);
    }

    /// <summary>
    /// "TPM_RC_FAILURE": once a failed self-test has entered Failure Mode, every command but the few Failure
    /// Mode admits is refused before its own rules run.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 12.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextSaveFailureModeIsRefusedWithFailure()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = new TpmSimulator(
            $"tpm-in-house-context-save-{nameof(ContextSaveFailureModeIsRefusedWithFailure)}",selfTest: TpmSelfTestBehavior.Fails, rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        TpmRcConstants selfTestCode = await SubmitSelfTestAsync(simulator, pool).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, selfTestCode, "A failing self-test enters Failure Mode.");

        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, TpmHandleRanges.TRANSIENT_FIRST).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, saved.ResponseCode, "In Failure Mode TPM2_ContextSave() is TPM_RC_FAILURE.");
        DisposeIfSuccess(saved);
    }

    /// <summary>
    /// Pool hygiene across every refusal category and a success: a parse refusal (a handle outside Table 57), a
    /// transition refusal (an unloaded handle), and a success each leave the pool with exactly the carriers
    /// outstanding before them.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextSavePoolBalanceAcrossValueHandleAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextSavePoolBalanceAcrossValueHandleAndASuccess), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaSigningKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        long baseline = trackingPool.OutstandingCount;

        TpmResult<ContextSaveResponse> parseRefusal = await SaveAsync(tpm, registry, pool, (uint)TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, handleIndex: 0), parseRefusal.ResponseCode,
            "Table 224: saveHandle is TPM2_ContextSave()'s sole handle (index 0); a permanent handle is outside Table 57's admitted ranges.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A parse refusal returns every carrier it rented.");

        TpmResult<ContextSaveResponse> transitionRefusal = await SaveAsync(tpm, registry, pool, TpmHandleRanges.TRANSIENT_FIRST + 0xFF).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, transitionRefusal.ResponseCode, "An in-range transient saveHandle (index 0) naming nothing loaded is TPM_RC_REFERENCE_H0 at the transition (TPM 2.0 Library Part 3, clause 5.4, step 2.1).");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A transition refusal returns every carrier it rented.");

        TpmResult<ContextSaveResponse> success = await SaveAsync(tpm, registry, pool, key.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(success.IsSuccess, $"The final save must succeed: '{success.ResponseCode}'.");
        success.Value.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A success releases every carrier once its response is disposed.");
    }

    /// <summary>
    /// Pool hygiene across a session save: the baseline is taken BEFORE the session starts, so the count proves
    /// that saving the session releases the live session record's carriers along with the framed response - back
    /// to the pre-session baseline, not merely to some intermediate level.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.5</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextSavePoolBalanceAcrossASessionSaveReleasesItsLiveCarriers()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextSavePoolBalanceAcrossASessionSaveReleasesItsLiveCarriers), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        uint sessionHandle = await StartSessionAsync(tpm, registry, pool, SessionKind.Hmac).ConfigureAwait(false);

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"The session save must succeed: '{saved.ResponseCode}'.");
        saved.Value.Dispose();

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A session save releases the live session record's carriers along with the framed response.");
    }

    /// <summary>The session kinds <see cref="ContextSaveOfAStartedSessionYieldsItsOwnHandleAndRemovesItFromRam"/> drives.</summary>
    internal enum SessionKind
    {
        /// <summary>An unbound, unsalted HMAC session.</summary>
        Hmac,

        /// <summary>An unbound, unsalted policy session.</summary>
        Policy
    }

    /// <summary>Disposes <paramref name="result"/>'s success value, when there is one - the response object a negative test never otherwise reads still owes its pooled carrier back on the rare implementation defect that lets it succeed.</summary>
    /// <typeparam name="T">The response type.</typeparam>
    /// <param name="result">The result to release.</param>
    private static void DisposeIfSuccess<T>(TpmResult<T> result)
        where T: IDisposable
    {
        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }
    }

    /// <summary>Issues <c>TPM2_ContextSave()</c> through the production executor - no session admitted, per clause 28.2.1's total preclusion.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The raw handle value to save.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<ContextSaveResponse>> SaveAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        ContextSaveInput input = ContextSaveInput.ForHandle(handle);

        return await TpmCommandExecutor.ExecuteAsync<ContextSaveResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues a sessionless <c>TPM2_ReadPublic()</c> for <paramref name="objectHandle"/> through the production executor.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="objectHandle">The handle to read.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<ReadPublicResponse>> ReadPublicAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint objectHandle)
    {
        ReadPublicInput input = ReadPublicInput.ForHandle(TpmiDhObject.FromValue(objectHandle));

        return await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates an unrestricted RSA signing key through <c>TPM2_CreatePrimary()</c> under the owner hierarchy.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaSigningKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(TpmRh.TPM_RH_OWNER, password: null, RsaKeyBits, TpmtRsaScheme.Rsassa(NameAlg), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an ECC P-256 ECDSA signing primary under the owner hierarchy.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(NameAlg), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Attempts to create an RSA signing primary whose template carries <see cref="TpmaObject.ST_CLEAR"/> SET -
    /// no such recipe exists anywhere in this suite, so the template is built by hand from the same attribute set
    /// <see cref="CreateRsaSigningKeyAsync"/> uses, with that one extra bit added.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<CreatePrimaryResponse>> TryCreateStClearRsaKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        var objectAttributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH |
            TpmaObject.SIGN_ENCRYPT |
            TpmaObject.NO_DA |
            TpmaObject.ST_CLEAR;

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic inPublic = Tpm2bPublic.CreateRsaSigningTemplate(NameAlg, objectAttributes, RsaKeyBits, TpmtRsaScheme.Rsassa(NameAlg));
        using CreatePrimaryInput input = new(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates an empty-password ECC storage parent under the owner hierarchy, asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller owns it.</returns>
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

    /// <summary>Seals a small datum under <paramref name="parentHandle"/> via <c>TPM2_Create()</c> - returned, not loaded - asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent.</param>
    /// <returns>The response; the caller owns it.</returns>
    private async Task<CreateResponse> CreateSealedObjectAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject parentHandle)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData("context-save sealed datum"u8.ToArray(), pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(NameAlg, pool, noDa: true);
        using CreateInput createInput = new(parentHandle.Value, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"Create (seal) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Loads <paramref name="sealedObject"/> under <paramref name="parentHandle"/> via <c>TPM2_Load()</c>, asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent.</param>
    /// <param name="sealedObject">The Create response carrying the blob to load.</param>
    /// <returns>The loaded object's handle and its Name as <c>TPM2_Load()</c> returned it.</returns>
    private async Task<(TpmiDhObject Handle, byte[] Name)> LoadSealedObjectAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject parentHandle, CreateResponse sealedObject)
    {
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
        using LoadInput loadInput = new(parentHandle.Value, inPrivate, inPublic);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<LoadResponse> result = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_Load() failed: '{result.ResponseCode}'.");
        using LoadResponse loaded = result.Value;

        return (loaded.ObjectHandle, loaded.Name.Span.ToArray());
    }

    /// <summary>Persist-then-reload a public area through wire bytes only, yielding an independently-owned copy rather than aliasing <paramref name="source"/>'s own storage.</summary>
    /// <param name="source">The public area to clone.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The cloned public area; the caller owns and disposes it.</returns>
    private static Tpm2bPublic ClonePublic(Tpm2bPublic source, BaseMemoryPool pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);

        var reader = new TpmReader(owner.Memory.Span[..size]);

        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>Loads a fixed HMAC (KEYEDHASH) key with its sensitive area under <c>TPM_RH_NULL</c>.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller owns it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public and sensitive areas transfers to the load input, disposed here once the command has been issued.")]
    private async Task<LoadExternalResponse> LoadHmacKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        byte[] seed = new byte[Sha256DigestSize];
        Array.Fill(seed, (byte)0xC0);
        byte[] hmacKey = [0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B];
        byte[] message = new byte[seed.Length + hmacKey.Length];
        seed.CopyTo(message, 0);
        hmacKey.CopyTo(message, seed.Length);
        byte[] unique = SHA256.HashData(message);

        TpmaObject attributes = TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT | TpmaObject.NO_DA;
        Tpm2bPublic inPublic = Tpm2bPublic.CreateKeyedHashTemplate(NameAlg, attributes, TpmsKeyedHashParms.Hmac(NameAlg), default, pool, unique);
        TpmtSensitive inPrivate = TpmtSensitive.ForKeyedHash(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Create(seed, pool), Tpm2bSensitiveData.Create(hmacKey, pool));
        using var input = new LoadExternalInput(inPrivate, inPublic, TpmiRhHierarchy.Null);

        TpmResult<LoadExternalResponse> result = await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_LoadExternal() (HMAC) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Opens a SHA-256 hash sequence context with an empty authValue.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The sequence handle.</returns>
    private async Task<TpmiDhObject> StartHashSequenceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using HashSequenceStartInput input = HashSequenceStartInput.Create([], TpmiAlgHash.FromValue(NameAlg), pool);
        TpmResult<HashSequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HashSequenceStart() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>Appends one <see cref="Tpm2bMaxBuffer.MaxSize"/>-octet block to an open hash sequence via <c>TPM2_SequenceUpdate()</c> under an empty password, asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The open sequence's handle.</param>
    /// <param name="buffer">The block to append.</param>
    private async Task UpdateSequenceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, byte[] buffer)
    {
        using TpmPasswordSession sequenceSession = TpmPasswordSession.CreateEmpty(pool);
        using SequenceUpdateInput input = SequenceUpdateInput.Create(sequenceHandle, buffer, pool);

        TpmResult<SequenceUpdateResponse> result = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
            tpm, input, [sequenceSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SequenceUpdate() failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Feeds <see cref="SequenceUpdatesToExceedContextCapacity"/> full-width blocks into an open sequence so its
    /// retained segments alone, once the context blob's own framing is added, exceed <see cref="Tpm2bContextData.MaxSize"/>.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The open sequence's handle.</param>
    private async Task GrowSequenceOverContextCapacityAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle)
    {
        byte[] block = new byte[Tpm2bMaxBuffer.MaxSize];
        Array.Fill(block, (byte)0xA5);

        for(int updateIndex = 0; updateIndex < SequenceUpdatesToExceedContextCapacity; updateIndex++)
        {
            await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, block).ConfigureAwait(false);
        }
    }

    /// <summary>Starts an unbound, unsalted session of the given kind through the production <c>TPM2_StartAuthSession()</c> path, asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="kind">Which session kind to start.</param>
    /// <returns>The started session's own handle.</returns>
    private async Task<uint> StartSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, SessionKind kind)
    {
        StartAuthSessionInput input = kind switch
        {
            SessionKind.Hmac => StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(NameAlg, TestEntropy.NewCounterStream(), pool),
            SessionKind.Policy => StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(NameAlg, TestEntropy.NewCounterStream(), pool),
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };
        TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"StartAuthSession ({kind}) failed: '{result.ResponseCode}'.");
        using StartAuthSessionResponse started = result.Value;

        return started.SessionHandle.Value;
    }

    /// <summary>Creates an operational simulator with both asymmetric backends wired.</summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            $"tpm-in-house-context-save-{name}", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an unauthorized command on the wire.</summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)TpmHeader.Parse(ref reader).Code, "TPM2_Startup(CLEAR) must succeed.");
    }

    /// <summary>Issues <c>TPM2_SelfTest(NO)</c> directly against the simulator and returns its response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSelfTestAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new SelfTestInput(IsFullTest: false);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer TPM2_SelfTest() rather than fault.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>Hand-frames a <c>TPM_CC_ContextSave</c> command with a caller-chosen tag and body, submits it straight to the simulator, and returns the response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag.</param>
    /// <param name="body">The handle and parameter area, already laid out.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitContextSaveFramedAsync(TpmSimulator simulator, BaseMemoryPool pool, ushort tag, byte[] body)
    {
        int length = TpmHeader.HeaderSize + body.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader(tag, (uint)length, (uint)TpmCcConstants.TPM_CC_ContextSave);
        header.WriteTo(ref writer);
        writer.WriteBytes(body);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        if(result.IsSuccess)
        {
            using TpmResponse response = result.Value;
            var reader = new TpmReader(response.AsReadOnlySpan());

            return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
        }

        return result.ResponseCode;
    }

    /// <summary>Builds the codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_ContextSave, TpmResponseCodec.ContextSave);
        _ = registry.Register(TpmCcConstants.TPM_CC_ContextLoad, TpmResponseCodec.ContextLoad);
        _ = registry.Register(TpmCcConstants.TPM_CC_ReadPublic, TpmResponseCodec.ReadPublic);
        _ = registry.Register(TpmCcConstants.TPM_CC_LoadExternal, TpmResponseCodec.LoadExternal);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceUpdate, TpmResponseCodec.SequenceUpdate);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);

        return registry;
    }
}
