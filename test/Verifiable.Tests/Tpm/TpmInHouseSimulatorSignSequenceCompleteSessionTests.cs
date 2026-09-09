using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the session-authorized form of <c>TPM2_SignSequenceComplete()</c> against the in-house behavioural
/// <see cref="TpmSimulator"/>, in-process through the production command path
/// (<see cref="TpmCommandExecutor"/> with the real <see cref="SignSequenceCompleteInput"/> and the real response
/// codecs).
/// </summary>
/// <remarks>
/// <para>
/// Table 124 gives the command two authorized handles in handle order — <c>@sequenceHandle</c> (Auth Index 1,
/// Auth Role USER) then <c>@keyHandle</c> (Auth Index 2, Auth Role USER) — so its authorization area carries two
/// authorizing blocks, each independently a <c>TPM_RS_PW</c> password or a loaded HMAC session, and at most one
/// further companion block that authorizes nothing and rides the area to carry <c>decrypt</c>
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3: Commands, clause 20.6; Part 1: Architecture, clause 15.6.1 and Table 12).
/// </para>
/// <para>
/// A sequence object's Name is the Empty Buffer, so the handle-Name area cpHash is computed over is
/// <c>EmptyBuffer ‖ Name(keyHandle)</c> and the executor derives the first term from the input's own declaration
/// rather than from any caller-supplied Name (Part 3, clause 17.7.1; Part 1, clause 29.4.6). A sequence is also
/// exempt from dictionary-attack protection, while the signing key beside it is not, which is what makes the two
/// authorizing slots answer a wrong credential with different codes and different counter effects.
/// </para>
/// <para>
/// Every real session here verifies the response authorization end to end inside
/// <see cref="TpmCommandExecutor.ExecuteAsync"/> (<c>TpmSession.VerifyAndUpdateAsync</c>), so a success is also a
/// proof that the framed response entry was genuine and that the session adopted a rolled <c>nonceTPM</c>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorSignSequenceCompleteSessionTests
{
    /// <summary>The hash algorithm every HMAC session these tests start negotiates.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The password bound to every signing key these tests create that carries one.</summary>
    private const string KeyPasswordText = "sign-sequence-complete-key-auth";

    /// <summary>A password that matches no fixture's key authorization value.</summary>
    private const string WrongKeyPasswordText = "sign-sequence-complete-wrong-key-auth";

    /// <summary>The RFC 4231 test case 3 key: twenty octets of <c>0xaa</c>.</summary>
    private static byte[] Rfc4231Case3Key { get; } = Convert.FromHexString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    /// <summary>The RFC 4231 test case 3 data: fifty octets of <c>0xdd</c>.</summary>
    private static byte[] Rfc4231Case3Data { get; } = Convert.FromHexString("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");

    /// <summary>The published RFC 4231 test case 3 HMAC-SHA-256 value.</summary>
    private static byte[] Rfc4231Case3Sha256 { get; } = Convert.FromHexString("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    /// <summary>The authorization value every sequence these tests start is created with.</summary>
    private static byte[] SequenceAuth { get; } = "sign-sequence-complete-sequence-auth"u8.ToArray();

    /// <summary>An authorization value that matches no sequence these tests start.</summary>
    private static byte[] WrongSequenceAuth { get; } = "sign-sequence-complete-wrong-sequence-auth"u8.ToArray();

    /// <summary>The key's authorization value as octets, the form a session folds it in.</summary>
    private static byte[] KeyAuth { get; } = System.Text.Encoding.UTF8.GetBytes(KeyPasswordText);

    /// <summary>The wrong key authorization value as octets.</summary>
    private static byte[] WrongKeyAuth { get; } = System.Text.Encoding.UTF8.GetBytes(WrongKeyPasswordText);

    /// <summary>
    /// <c>TPM_GENERATED_VALUE</c> (Part 2, Table 7), big-endian: the four octets a restricted signing key's first
    /// presented message block must never begin with.
    /// </summary>
    private static byte[] TpmGeneratedValueBytes { get; } = [0xFF, 0x54, 0x43, 0x47];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Both authorizing slots as REAL HMAC sessions over a KEYEDHASH HMAC key — the sequence session folding the
    /// sequence's own authorization value, the key session folding the key's — sign the whole message presented in
    /// the one <c>buffer</c> parameter, and the signature is the published RFC 4231 case 3 HMAC-SHA-256 value.
    /// Both slots adopt a rolled <c>nonceTPM</c> from their own response entry, which they do only after that
    /// entry's own HMAC verified (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clause 20.6, Table 124; Part 1: Architecture, clauses
    /// 16.6.3.1 and 16.6.5). The signing oracle is the published vector in
    /// <see href="https://www.rfc-editor.org/rfc/rfc4231">RFC 4231</see>, clause 4.4 (test case 3).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOverTwoHmacSessionsInOneBufferMatchesRfc4231Case3()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteOverTwoHmacSessionsInOneBufferMatchesRfc4231Case3), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyAuth,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject keyHandle = TpmiDhObject.FromValue(key.Handle);
        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, keyHandle, SequenceAuth).ConfigureAwait(false);

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(SequenceAuth, pool);
            keySession.SetAuthValue(KeyAuth, pool);

            byte[] sequenceNonceBefore = sequenceSession.NonceTpm.ToArray();
            byte[] keyNonceBefore = keySession.NonceTpm.ToArray();

            TpmResult<SignSequenceCompleteResponse> result = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, keyHandle, key.Name.AsReadOnlyMemory(), Rfc4231Case3Data, [sequenceSession, keySession]).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_SignSequenceComplete() over two real HMAC sessions must succeed: '{result.ResponseCode}'.");

            using SignSequenceCompleteResponse completed = result.Value;
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_HMAC, completed.SignatureAlgorithm, "The framed TPMT_SIGNATURE must select the HMAC member.");
            Assert.IsTrue(
                completed.Signature.HmacSignature!.AsReadOnlyMemory().Span.SequenceEqual(Rfc4231Case3Sha256),
                "The session-authorized completion must produce the published RFC 4231 case 3 HMAC-SHA-256 value.");

            Assert.IsFalse(
                sequenceSession.NonceTpm.Span.SequenceEqual(sequenceNonceBefore),
                "The sequence slot must adopt a genuinely rolled nonceTPM from its own verified response entry.");
            Assert.IsFalse(
                keySession.NonceTpm.Span.SequenceEqual(keyNonceBefore),
                "The key slot must likewise adopt a genuinely rolled nonceTPM from its own verified response entry.");
        }
        finally
        {
            sequenceSession.Dispose();
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The same RFC 4231 case 3 message delivered across two <c>TPM2_SequenceUpdate()</c> calls over the SAME
    /// sequence session plus the trailing <c>buffer</c> at the completion reproduces the identical published
    /// value: "buffer: data to be added to the signature" is appended to what the updates already accumulated
    /// before the whole message is hashed and signed, and the sequence's authorization is the same folded value
    /// at every step (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 3: Commands, clauses 17.7 and 20.6, Table 124). The oracle is again
    /// <see href="https://www.rfc-editor.org/rfc/rfc4231">RFC 4231</see>, clause 4.4 (test case 3).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOverTwoHmacSessionsSplitAcrossUpdatesMatchesRfc4231Case3()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteOverTwoHmacSessionsSplitAcrossUpdatesMatchesRfc4231Case3), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyAuth,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject keyHandle = TpmiDhObject.FromValue(key.Handle);
        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, keyHandle, SequenceAuth).ConfigureAwait(false);

        byte[] firstChunk = Rfc4231Case3Data[..20];
        byte[] secondChunk = Rfc4231Case3Data[20..40];
        byte[] trailing = Rfc4231Case3Data[40..];

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(SequenceAuth, pool);
            keySession.SetAuthValue(KeyAuth, pool);

            await UpdateOverSessionAsync(tpm, registry, pool, sequenceHandle, firstChunk, sequenceSession).ConfigureAwait(false);
            await UpdateOverSessionAsync(tpm, registry, pool, sequenceHandle, secondChunk, sequenceSession).ConfigureAwait(false);

            TpmResult<SignSequenceCompleteResponse> result = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, keyHandle, key.Name.AsReadOnlyMemory(), trailing, [sequenceSession, keySession]).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_SignSequenceComplete() after two session-authorized updates must succeed: '{result.ResponseCode}'.");

            using SignSequenceCompleteResponse completed = result.Value;
            Assert.IsTrue(
                completed.Signature.HmacSignature!.AsReadOnlyMemory().Span.SequenceEqual(Rfc4231Case3Sha256),
                "A message split across updates and a trailing buffer must produce the same published RFC 4231 case 3 value as the one-buffer completion.");
        }
        finally
        {
            sequenceSession.Dispose();
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The asymmetric arm of the same shape: both slots as real HMAC sessions over an ECC signing key sign the
    /// SHA-256 digest of the whole accumulated message, and the signature verifies off-TPM against a public key
    /// reconstructed solely from the exported public point — an oracle that shares no code path with the signer
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6, Table 124; clause 20.1, Table 115's ECDSA row).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOverTwoHmacSessionsWithAnEccKeyVerifiesOffTpm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteOverTwoHmacSessionsWithAnEccKeyVerifiesOffTpm), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, KeyPasswordText, isNoDa: true).ConfigureAwait(false);

        byte[] chunk = "Verifiable session-authorized sequence signing "u8.ToArray();
        byte[] trailing = "acceptance message."u8.ToArray();
        byte[] wholeMessage = [.. chunk, .. trailing];

        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);
        await UpdateOverPasswordAsync(tpm, registry, pool, sequenceHandle, chunk, SequenceAuth).ConfigureAwait(false);

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(SequenceAuth, pool);
            keySession.SetAuthValue(KeyAuth, pool);

            TpmResult<SignSequenceCompleteResponse> result = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, key.ObjectHandle, key.Name.AsReadOnlyMemory(), trailing, [sequenceSession, keySession]).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_SignSequenceComplete() (ECDSA, two real HMAC sessions) must succeed: '{result.ResponseCode}'.");

            using SignSequenceCompleteResponse completed = result.Value;
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, completed.SignatureAlgorithm, "The framed TPMT_SIGNATURE must select the ECDSA member.");

            byte[] digest = SHA256.HashData(wholeMessage);
            Assert.IsTrue(
                VerifyEcdsaSignatureOffTpm(key.OutPublic.PublicArea.Unique.Ecc!, digest, completed.Signature),
                "The session-authorized ECDSA signature must verify against the SHA-256 digest of the whole accumulated message.");
        }
        finally
        {
            sequenceSession.Dispose();
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The authorizing blocks are independent: a real HMAC session at <c>@sequenceHandle</c> beside a plain
    /// <c>TPM_RS_PW</c> block at <c>@keyHandle</c> is an admissible area and signs, the password slot owing only
    /// its inline value comparison and a placeholder response entry while the session slot owes a command HMAC and
    /// a verified response entry (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 1: Architecture, clause 15.6.1, Table 12; clause 16.6.4).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOverASequenceSessionAndAKeyPasswordSlotSigns()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteOverASequenceSessionAndAKeyPasswordSlotSigns), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, KeyPasswordText, isNoDa: true).ConfigureAwait(false);
        byte[] message = "sequence session beside a key password slot."u8.ToArray();

        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(SequenceAuth, pool);
            byte[] sequenceNonceBefore = sequenceSession.NonceTpm.ToArray();

            using TpmPasswordSession keyPassword = HmacKeyHarness.PasswordSession(KeyAuth, pool);
            TpmResult<SignSequenceCompleteResponse> result = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, key.ObjectHandle, key.Name.AsReadOnlyMemory(), message, [sequenceSession, keyPassword]).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A sequence HMAC session beside a key TPM_RS_PW slot must sign: '{result.ResponseCode}'.");

            using SignSequenceCompleteResponse completed = result.Value;
            byte[] digest = SHA256.HashData(message);
            Assert.IsTrue(
                VerifyEcdsaSignatureOffTpm(key.OutPublic.PublicArea.Unique.Ecc!, digest, completed.Signature),
                "The mixed-area completion must sign the SHA-256 digest of the whole message.");
            Assert.IsFalse(
                sequenceSession.NonceTpm.Span.SequenceEqual(sequenceNonceBefore),
                "The one real slot must adopt a rolled nonceTPM from its own response entry, which the password slot's placeholder entry cannot supply.");
        }
        finally
        {
            sequenceSession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The mirror of the mixed area: a <c>TPM_RS_PW</c> block at <c>@sequenceHandle</c> beside a real HMAC session
    /// at <c>@keyHandle</c> is equally admissible and signs, proving neither slot's kind is fixed by its position
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 15.6.1, Table 12; Part 3: Commands, clause 20.6,
    /// Table 124).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOverASequencePasswordSlotAndAKeySessionSigns()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteOverASequencePasswordSlotAndAKeySessionSigns), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, KeyPasswordText, isNoDa: true).ConfigureAwait(false);
        byte[] message = "key session beside a sequence password slot."u8.ToArray();

        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);

        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            keySession.SetAuthValue(KeyAuth, pool);
            byte[] keyNonceBefore = keySession.NonceTpm.ToArray();

            using TpmPasswordSession sequencePassword = HmacKeyHarness.PasswordSession(SequenceAuth, pool);
            TpmResult<SignSequenceCompleteResponse> result = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, key.ObjectHandle, key.Name.AsReadOnlyMemory(), message, [sequencePassword, keySession]).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A sequence TPM_RS_PW slot beside a key HMAC session must sign: '{result.ResponseCode}'.");

            using SignSequenceCompleteResponse completed = result.Value;
            byte[] digest = SHA256.HashData(message);
            Assert.IsTrue(
                VerifyEcdsaSignatureOffTpm(key.OutPublic.PublicArea.Unique.Ecc!, digest, completed.Signature),
                "The reversed mixed-area completion must sign the SHA-256 digest of the whole message.");
            Assert.IsFalse(
                keySession.NonceTpm.Span.SequenceEqual(keyNonceBefore),
                "The key slot's real session must adopt a rolled nonceTPM from the second response entry, so the placeholder for the password slot ahead of it was framed at the right position.");
        }
        finally
        {
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A third block that authorizes nothing and carries only <c>decrypt</c> rides the area beside the two
    /// password blocks and protects <c>buffer</c> — a <c>TPM2B_MAX_BUFFER</c>, the first parameter and a sized
    /// one, which is exactly what may be encrypted — and the recovered plaintext still produces the published RFC
    /// 4231 case 3 value, so the companion's keystream was applied and removed correctly
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clauses 15.6.1 and 18.1; Part 3: Commands, clause 20.6,
    /// Table 124). The recovered plaintext is checked against
    /// <see href="https://www.rfc-editor.org/rfc/rfc4231">RFC 4231</see>, clause 4.4 (test case 3).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOverTwoPasswordSlotsAndADecryptingCompanionSigns()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteOverTwoPasswordSlotsAndADecryptingCompanionSigns), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyAuth,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject keyHandle = TpmiDhObject.FromValue(key.Handle);
        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, keyHandle, SequenceAuth).ConfigureAwait(false);

        (uint companionHandle, TpmSession companion) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(SessionAlg),
            isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            using TpmPasswordSession sequencePassword = HmacKeyHarness.PasswordSession(SequenceAuth, pool);
            using TpmPasswordSession keyPassword = HmacKeyHarness.PasswordSession(KeyAuth, pool);

            TpmResult<SignSequenceCompleteResponse> result = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, keyHandle, key.Name.AsReadOnlyMemory(), Rfc4231Case3Data,
                [sequencePassword, keyPassword, companion]).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A decrypting companion beside two password slots must complete the sequence: '{result.ResponseCode}'.");

            using SignSequenceCompleteResponse completed = result.Value;
            Assert.IsTrue(
                completed.Signature.HmacSignature!.AsReadOnlyMemory().Span.SequenceEqual(Rfc4231Case3Sha256),
                "The buffer recovered from the companion's keystream must be the RFC 4231 case 3 message, so the completion reproduces its published HMAC.");
        }
        finally
        {
            companion.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, companionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "the Name associated with sequenceHandle will be the Empty Buffer": the executor derives that present,
    /// zero-length term from the input's own declaration that handle 0 names a sequence, and a caller-supplied
    /// Name for it is refused with <see cref="ArgumentException"/> rather than silently ignored — folding octets
    /// the TPM never folds would only surface later as an unexplained HMAC mismatch
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.7.1; Part 1: Architecture, clause 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteWithASuppliedNameForTheSequenceHandleThrows()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteWithASuppliedNameForTheSequenceHandleThrows), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, KeyPasswordText, isNoDa: true).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(SequenceAuth, pool);
            keySession.SetAuthValue(KeyAuth, pool);

            //The plausible caller mistake: folding the sequence HANDLE's own four octets, the term a permanent or
            //session handle would contribute, in place of the Empty Buffer a sequence object contributes.
            byte[] suppliedSequenceName = new byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(suppliedSequenceName, sequenceHandle.Value);
            ReadOnlyMemory<byte>[] handleNames = [suppliedSequenceName, key.Name.AsReadOnlyMemory()];
            byte[] message = "message"u8.ToArray();
            using SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(sequenceHandle, key.ObjectHandle, message, pool);

            await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
                await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
                    tpm, input, [sequenceSession, keySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }
        finally
        {
            sequenceSession.Dispose();
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "A sequence is exempt from dictionary attack protection and authorization failures will not cause the TPM
    /// to enter lockout": a wrong authorization value folded into the SEQUENCE slot's HMAC session is refused with
    /// session-index-0-encoded <c>TPM_RC_BAD_AUTH</c> and moves no counter, even though the signing key beside it
    /// IS dictionary-attack protected — so the exemption belongs to the sequence entity, not to the command
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 29.4.6; Part 2: Structures, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOverSessionsWithAWrongSequenceHmacIsRefusedAtSlotZeroAndChargesNothing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteOverSessionsWithAWrongSequenceHmacIsRefusedAtSlotZeroAndChargesNothing), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, KeyPasswordText, isNoDa: false).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(WrongSequenceAuth, pool);
            keySession.SetAuthValue(KeyAuth, pool);

            TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

            TpmResult<SignSequenceCompleteResponse> result = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, key.ObjectHandle, key.Name.AsReadOnlyMemory(), "message"u8.ToArray(), [sequenceSession, keySession]).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
                "A wrong sequence authorization over an unbound HMAC session must be refused with session-index-0-encoded TPM_RC_BAD_AUTH, never the charged TPM_RC_AUTH_FAIL.");

            TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                before.Value.LockoutCounter, after.Value.LockoutCounter,
                "A sequence's authorization failure must never move failedTries, even when the key it completes under is dictionary-attack protected.");
        }
        finally
        {
            sequenceSession.Dispose();
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The key slot keeps its entity's dictionary-attack standing: a wrong authorization value folded into the KEY
    /// slot's HMAC session against a DA-protected signing key is refused with session-index-1-encoded
    /// <c>TPM_RC_AUTH_FAIL</c> and charges <c>failedTries</c> exactly once, the sequence slot beside it having
    /// authorized correctly (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 1: Architecture, clause 16.8.3; Part 2: Structures, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOverSessionsWithAWrongKeyHmacOnADaProtectedKeyIsRefusedAtSlotOneAndCharges()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteOverSessionsWithAWrongKeyHmacOnADaProtectedKeyIsRefusedAtSlotOneAndCharges), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, KeyPasswordText, isNoDa: false).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(SequenceAuth, pool);
            keySession.SetAuthValue(WrongKeyAuth, pool);

            TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

            TpmResult<SignSequenceCompleteResponse> result = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, key.ObjectHandle, key.Name.AsReadOnlyMemory(), "message"u8.ToArray(), [sequenceSession, keySession]).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), result.ResponseCode,
                "A wrong key authorization at Auth Index 2 must be refused with session-index-1-encoded TPM_RC_AUTH_FAIL when the key is dictionary-attack protected.");

            TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                before.Value.LockoutCounter + 1, after.Value.LockoutCounter,
                "A wrong key authorization against a dictionary-attack-protected signing key must charge failedTries exactly once.");
        }
        finally
        {
            sequenceSession.Dispose();
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The authorization area is judged strictly in wire order: a wrong HMAC at the SEQUENCE slot (index 0) is
    /// the whole answer — refused with session-index-0-encoded <c>TPM_RC_BAD_AUTH</c>, uncharged (a sequence is
    /// exempt from dictionary-attack protection) — and the WRONG password presented at the KEY slot (index 1)
    /// against a DA-protected key is never compared, so <c>failedTries</c> does not move
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.6 — the checks are made per authorization, in the order the
    /// sessions appear; Part 1: Architecture, clause 29.4.6; Part 2: Structures, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteWithAWrongSequenceHmacAheadOfAWrongKeyPasswordIsRefusedAtSlotZeroUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteWithAWrongSequenceHmacAheadOfAWrongKeyPasswordIsRefusedAtSlotZeroUncharged), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, KeyPasswordText, isNoDa: false).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(WrongSequenceAuth, pool);
            using TpmPasswordSession wrongKeyPassword = HmacKeyHarness.PasswordSession(WrongKeyAuth, pool);

            TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

            TpmResult<SignSequenceCompleteResponse> result = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, key.ObjectHandle, key.Name.AsReadOnlyMemory(), "message"u8.ToArray(), [sequenceSession, wrongKeyPassword]).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
                "The sequence slot's HMAC mismatch at index 0 must be the answer, uncharged, before the key slot's password is ever compared.");

            TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                before.Value.LockoutCounter, after.Value.LockoutCounter,
                "A wrong key password behind an unverified sequence slot must never charge failedTries.");
        }
        finally
        {
            sequenceSession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The same wrong key authorization against a <c>noDA</c> signing key is refused with the UNCHARGED
    /// session-index-1-encoded <c>TPM_RC_BAD_AUTH</c> instead: the code and the counter effect both follow the
    /// authorized entity's own dictionary-attack standing, not the slot's position
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 16.8.1; Part 3: Commands, clause 5.6).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOverSessionsWithAWrongKeyHmacOnANoDaKeyIsRefusedAtSlotOneUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteOverSessionsWithAWrongKeyHmacOnANoDaKeyIsRefusedAtSlotOneUncharged), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, KeyPasswordText, isNoDa: true).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(SequenceAuth, pool);
            keySession.SetAuthValue(WrongKeyAuth, pool);

            TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

            TpmResult<SignSequenceCompleteResponse> result = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, key.ObjectHandle, key.Name.AsReadOnlyMemory(), "message"u8.ToArray(), [sequenceSession, keySession]).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), result.ResponseCode,
                "A wrong key authorization against a noDA signing key must be refused with the uncharged session-index-1-encoded TPM_RC_BAD_AUTH.");

            TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                before.Value.LockoutCounter, after.Value.LockoutCounter,
                "TPM_RC_BAD_AUTH is the uncharged refusal, so a noDA key's failed authorization must move no counter.");
        }
        finally
        {
            sequenceSession.Dispose();
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If keyHandle refers to a key that is not the same as the key that was used to start the signature context,
    /// the TPM shall return TPM_RC_SIGN_CONTEXT_KEY": the refusal is the command's own rule, so it is BARE — never
    /// session-encoded — and its response is header-only, which leaves both sessions' <c>nonceTPM</c> unrolled and
    /// the sequence's accumulated state unmodified. A corrected retry over the very SAME sessions signs exactly the
    /// original message, the failed attempt's own trailing buffer nowhere in it
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 6.2 and 20.6; Part 1: Architecture, clause 15.8).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOverSessionsWithADifferentSigningKeyReturnsHandleEncodedSignContextKeyAndRollsNoNonce()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteOverSessionsWithADifferentSigningKeyReturnsHandleEncodedSignContextKeyAndRollsNoNonce), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse startingKey = await CreateEccSigningPrimaryAsync(tpm, registry, pool, KeyPasswordText, isNoDa: true).ConfigureAwait(false);
        using CreatePrimaryResponse otherKey = await CreateEccSigningPrimaryAsync(tpm, registry, pool, KeyPasswordText, isNoDa: true).ConfigureAwait(false);

        byte[] originalMessage = "the original, unmodified sequence message."u8.ToArray();
        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, startingKey.ObjectHandle, SequenceAuth).ConfigureAwait(false);
        await UpdateOverPasswordAsync(tpm, registry, pool, sequenceHandle, originalMessage, SequenceAuth).ConfigureAwait(false);

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(SequenceAuth, pool);
            keySession.SetAuthValue(KeyAuth, pool);

            byte[] sequenceNonceBefore = sequenceSession.NonceTpm.ToArray();
            byte[] keyNonceBefore = keySession.NonceTpm.ToArray();

            TpmResult<SignSequenceCompleteResponse> refused = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, otherKey.ObjectHandle, otherKey.Name.AsReadOnlyMemory(), "tail"u8.ToArray(), [sequenceSession, keySession]).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_SIGN_CONTEXT_KEY, 1), refused.ResponseCode,
                "Completing over sessions with a key different from the one that started the sequence designates keyHandle, handle 2 of Table 124, exactly as the password form does.");

            Assert.IsTrue(
                sequenceSession.NonceTpm.Span.SequenceEqual(sequenceNonceBefore),
                "An error response is header-only and carries no session area, so the sequence slot's nonceTPM must not have rolled.");
            Assert.IsTrue(
                keySession.NonceTpm.Span.SequenceEqual(keyNonceBefore),
                "The key slot's nonceTPM must likewise not have rolled across the refusal.");

            TpmResult<SignSequenceCompleteResponse> retried = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, startingKey.ObjectHandle, startingKey.Name.AsReadOnlyMemory(), [], [sequenceSession, keySession]).ConfigureAwait(false);
            Assert.IsTrue(retried.IsSuccess, $"A corrected retry over the very same sessions must succeed, which it can only do if neither nonce rolled: '{retried.ResponseCode}'.");

            using SignSequenceCompleteResponse completed = retried.Value;
            byte[] digest = SHA256.HashData(originalMessage);
            Assert.IsTrue(
                VerifyEcdsaSignatureOffTpm(startingKey.OutPublic.PublicArea.Unique.Ecc!, digest, completed.Signature),
                "The retried completion must sign exactly the ORIGINAL accumulated message: the refused attempt's own trailing buffer was never installed.");
        }
        finally
        {
            sequenceSession.Dispose();
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "When ... TPM2_SignSequenceComplete() ... completes successfully, the sequence context is flushed from the
    /// TPM": over sessions the flush rides the same transition that installs the framed response, so
    /// <c>sequenceHandle</c> — the sole handle, index 0 — is a TRANSIENT-range value resolving to nothing loaded
    /// on the second completion, refused <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0 Library Part 3, clause 5.4, step
    /// 2.1) while BOTH sessions remain live and complete a freshly started sequence
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 1: Architecture, clause 29.4.6; Part 3: Commands, clause 20.6,
    /// Table 124's <c>{F}</c>).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOverSessionsFlushesTheSequenceOnSuccessWhileBothSessionsStayUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteOverSessionsFlushesTheSequenceOnSuccessWhileBothSessionsStayUsable), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, KeyPasswordText, isNoDa: true).ConfigureAwait(false);
        TpmiDhObject firstSequence = await StartSignSequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(SequenceAuth, pool);
            keySession.SetAuthValue(KeyAuth, pool);

            TpmResult<SignSequenceCompleteResponse> first = await CompleteOverSessionsAsync(
                tpm, registry, pool, firstSequence, key.ObjectHandle, key.Name.AsReadOnlyMemory(), "message"u8.ToArray(), [sequenceSession, keySession]).ConfigureAwait(false);
            Assert.IsTrue(first.IsSuccess, $"The first session-authorized completion must succeed: '{first.ResponseCode}'.");
            first.Value.Dispose();

            TpmResult<SignSequenceCompleteResponse> second = await CompleteOverSessionsAsync(
                tpm, registry, pool, firstSequence, key.ObjectHandle, key.Name.AsReadOnlyMemory(), "message"u8.ToArray(), [sequenceSession, keySession]).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_REFERENCE_H0, second.ResponseCode,
                "sequenceHandle is TPM2_SignSequenceComplete()'s sole handle (index 0); a second completion on an already-flushed sequence is a TRANSIENT-range value resolving to nothing loaded, TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1), proving the flush rode the successful response.");

            TpmiDhObject secondSequence = await StartSignSequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);
            TpmResult<SignSequenceCompleteResponse> third = await CompleteOverSessionsAsync(
                tpm, registry, pool, secondSequence, key.ObjectHandle, key.Name.AsReadOnlyMemory(), "message"u8.ToArray(), [sequenceSession, keySession]).ConfigureAwait(false);
            Assert.IsTrue(
                third.IsSuccess,
                $"Only the SEQUENCE is flushed by a successful completion: both sessions must still authorize a freshly started sequence: '{third.ResponseCode}'.");
            third.Value.Dispose();
        }
        finally
        {
            sequenceSession.Dispose();
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If this attribute is CLEAR, then USER role authorizations can only be provided by satisfying the object's
    /// authPolicy in a policy session": a signing key whose <c>TPMA_OBJECT.userWithAuth</c> is CLEAR refuses the
    /// key slot's real HMAC session with a BARE <c>TPM_RC_POLICY_FAIL</c> even though that session folds the
    /// CORRECT authorization value — it is the session's SHAPE, not its credential, that is inadmissible — and the
    /// refusal moves no counter, because the gate runs before any command HMAC is queued for verification
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 22.2.4; Part 3: Commands, clause 5.6, check 7.1).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOverSessionsOnAUserWithAuthClearKeyReturnsSessionEncodedPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteOverSessionsOnAUserWithAuthClearKeyReturnsSessionEncodedPolicyFail), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateUserWithAuthClearEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(SequenceAuth, pool);
            keySession.SetAuthValue(KeyAuth, pool);

            TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

            TpmResult<SignSequenceCompleteResponse> result = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, key.ObjectHandle, key.Name.AsReadOnlyMemory(), "message"u8.ToArray(), [sequenceSession, keySession]).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 1), result.ResponseCode,
                "A userWithAuth-CLEAR key must refuse the key slot's HMAC session at keyHandle, session 2 of Table 124: it is the session's SHAPE, not its credential, that is inadmissible for the USER role.");

            TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                before.Value.LockoutCounter, after.Value.LockoutCounter,
                "TPM_RC_POLICY_FAIL is not an authorization failure, so the gate must move no counter even against a dictionary-attack-protected key.");
        }
        finally
        {
            sequenceSession.Dispose();
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A sequence started by <c>TPM2_VerifySequenceStart()</c> is a VERIFICATION context, and a sequence handle of
    /// the wrong kind presented to a Complete command is refused with <c>TPM_RC_MODE</c> ("If sequenceHandle
    /// references an Event Sequence, then the TPM shall return TPM_RC_MODE"; "If sequenceHandle references a hash
    /// or HMAC sequence, the TPM shall return TPM_RC_MODE"). It is a command rule, so it answers BARE over
    /// sessions exactly as it does over passwords, and only after both slots have proved their authorizations
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 17.8, 17.9 and 20.6; clause 5.8's rules-after-authorization
    /// order).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOverSessionsOnAVerificationSequenceReturnsHandleEncodedMode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteOverSessionsOnAVerificationSequenceReturnsHandleEncodedMode), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, KeyPasswordText, isNoDa: true).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(SequenceAuth, pool);
            keySession.SetAuthValue(KeyAuth, pool);

            TpmResult<SignSequenceCompleteResponse> result = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, key.ObjectHandle, key.Name.AsReadOnlyMemory(), "message"u8.ToArray(), [sequenceSession, keySession]).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_MODE, 0), result.ResponseCode,
                "TPM2_SignSequenceComplete() over a verification sequence designates sequenceHandle, handle 1 of Table 124, the same command rule the password form answers.");
        }
        finally
        {
            sequenceSession.Dispose();
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "the handle associated with a specific HMAC or policy session can occur only once in the Authorization
    /// Area": naming the SAME live HMAC session in both of Table 124's authorizing blocks is refused with
    /// <c>TPM_RC_HANDLE</c>
    /// session-encoded to the SECOND occurrence — the offending re-claim, not the first, legitimate one
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 15.6.3; Part 2: Structures, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteWithTheSameHmacSessionHandleInBothSlotsIsRefusedWithHandleAtSlotOne()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteWithTheSameHmacSessionHandleInBothSlotsIsRefusedWithHandleAtSlotOne), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, KeyPasswordText, isNoDa: true).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(SequenceAuth, pool);

            //Composing the SAME live session into both slots produces the exact wire shape clause 15.6.3 forbids:
            //two TPMS_AUTH_COMMAND entries naming one real sessionHandle.
            TpmResult<SignSequenceCompleteResponse> result = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, key.ObjectHandle, key.Name.AsReadOnlyMemory(), "message"u8.ToArray(), [session, session]).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, result.BaseError, "The once-only handle rule answers a handle error.");
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 1), result.ResponseCode,
                "The refusal names the SECOND occurrence, so the wire code carries session index 1's modifier.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If the restricted attribute of keyHandle is SET, then message must not begin with TPM_GENERATED_VALUE":
    /// the rule is judged over the recovered message and answers the BARE <c>TPM_RC_ATTRIBUTES</c> over sessions,
    /// with the sequence retained — clause 20.6 names no code for it, and this is the same "this key's attributes
    /// forbid this use" refusal the family answers elsewhere
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6; clause 17.7's first-block rule).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOverSessionsOnARestrictedKeyWithATpmGeneratedFirstBlockReturnsHandleEncodedAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteOverSessionsOnARestrictedKeyWithATpmGeneratedFirstBlockReturnsHandleEncodedAttributes), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);

        byte[] message = [.. TpmGeneratedValueBytes, .. "trailing content"u8.ToArray()];

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(SequenceAuth, pool);
            keySession.SetAuthValue(KeyAuth, pool);

            TpmResult<SignSequenceCompleteResponse> result = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, key.ObjectHandle, key.Name.AsReadOnlyMemory(), message, [sequenceSession, keySession]).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode,
                "A restricted signing key completing a message whose first presented block begins with TPM_GENERATED_VALUE designates keyHandle, handle 2 of Table 124.");
        }
        finally
        {
            sequenceSession.Dispose();
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A refused session-authorized area and a successful one each return every carrier they rented — the session
    /// key, the supplied command HMACs, the raw parameter area, and every intermediate digest buffer — proven with
    /// real pool telemetry over the real wire rather than an internal hook. Both areas fold NON-EMPTY
    /// authorization values into both slots, so the carriers under accounting are genuine rentals rather than the
    /// degenerate empty-buffer case, and a mid-scenario liveness assertion proves the live sessions genuinely held
    /// rentals before either balance assertion
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6, Table 124).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOverSessionsKeepsPoolBalanceExactAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteOverSessionsKeepsPoolBalanceExactAcrossARefusalAndASuccess), trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, trackingPool.Pool, KeyPasswordText, isNoDa: true).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        //Each phase opens its own sequence and leaves none behind: the refused phase flushes its retained sequence
        //explicitly, the successful phase's completion flushes its own, so both balance assertions are read
        //against the same state the baseline was taken in.
        TpmiDhObject refusedSequence = await StartSignSequenceAsync(tpm, registry, trackingPool.Pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);

        (uint refusedSequenceSessionHandle, TpmSession refusedSequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        (uint refusedKeySessionHandle, TpmSession refusedKeySession) = await StartUnboundHmacSessionAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        try
        {
            refusedSequenceSession.SetAuthValue(SequenceAuth, trackingPool.Pool);
            refusedKeySession.SetAuthValue(WrongKeyAuth, trackingPool.Pool);

            Assert.IsGreaterThan(
                baseline, trackingPool.OutstandingCount,
                "Two live HMAC sessions carrying non-empty authorization values must hold rented carriers, or the balance assertion below is vacuous.");

            TpmResult<SignSequenceCompleteResponse> refused = await CompleteOverSessionsAsync(
                tpm, registry, trackingPool.Pool, refusedSequence, key.ObjectHandle, key.Name.AsReadOnlyMemory(), "message"u8.ToArray(),
                [refusedSequenceSession, refusedKeySession]).ConfigureAwait(false);
            Assert.IsTrue(refused.IsTpmError, "The wrong key authorization must be refused.");
        }
        finally
        {
            refusedSequenceSession.Dispose();
            refusedKeySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, trackingPool.Pool, refusedSequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, trackingPool.Pool, refusedKeySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, trackingPool.Pool, refusedSequence.Value, TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A refused session-authorized area must return every rented carrier to the pool.");

        TpmiDhObject successSequence = await StartSignSequenceAsync(tpm, registry, trackingPool.Pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);

        (uint successSequenceSessionHandle, TpmSession successSequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        (uint successKeySessionHandle, TpmSession successKeySession) = await StartUnboundHmacSessionAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        try
        {
            successSequenceSession.SetAuthValue(SequenceAuth, trackingPool.Pool);
            successKeySession.SetAuthValue(KeyAuth, trackingPool.Pool);

            Assert.IsGreaterThan(
                baseline, trackingPool.OutstandingCount,
                "The successful run's live sessions must likewise hold rented carriers, or its balance assertion is vacuous.");

            TpmResult<SignSequenceCompleteResponse> succeeded = await CompleteOverSessionsAsync(
                tpm, registry, trackingPool.Pool, successSequence, key.ObjectHandle, key.Name.AsReadOnlyMemory(), "message"u8.ToArray(),
                [successSequenceSession, successKeySession]).ConfigureAwait(false);
            Assert.IsTrue(succeeded.IsSuccess, $"The correct authorization must complete the sequence: '{succeeded.ResponseCode}'.");
            succeeded.Value.Dispose();
        }
        finally
        {
            successSequenceSession.Dispose();
            successKeySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, trackingPool.Pool, successSequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, trackingPool.Pool, successKeySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A successful session-authorized area must likewise return every rented carrier to the pool.");
    }

    /// <summary>
    /// Creates an ECC-capable simulator and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational
    /// phase.
    /// </summary>
    /// <param name="name">A per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator; the caller disposes it.</returns>
    private Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool) =>
        HmacKeyHarness.CreateOperationalAsync(name, pool, TestContext.CancellationToken);

    /// <summary>Creates a response codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySequenceStart, TpmResponseCodec.VerifySequenceStart);

        return registry;
    }

    /// <summary>
    /// Starts a signing sequence under <paramref name="keyHandle"/> with <paramref name="sequenceAuth"/> as its
    /// own authorization value, asserting success. <c>keyHandle</c> carries no <c>@</c> at Start (Part 3,
    /// clause 17.5, Table 87), so the command is framed with no session at all.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The signing key the sequence is started under.</param>
    /// <param name="sequenceAuth">The sequence's own authorization value.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartSignSequenceAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        using SignSequenceStartInput input = SignSequenceStartInput.Create(keyHandle, sequenceAuth, pool);
        TpmResult<SignSequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SignSequenceStart() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>
    /// Starts a VERIFICATION sequence under <paramref name="keyHandle"/>, asserting success — the context whose
    /// kind makes a signing completion inadmissible (Part 3, clause 17.6, Table 89).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The key the verification sequence is started under.</param>
    /// <param name="sequenceAuth">The sequence's own authorization value.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartVerifySequenceAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        using VerifySequenceStartInput input = VerifySequenceStartInput.Create(keyHandle, sequenceAuth, pool);
        TpmResult<VerifySequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<VerifySequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_VerifySequenceStart() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>
    /// Starts an unbound, unsalted HMAC session that negotiates no symmetric algorithm and builds the host-side
    /// <see cref="TpmSession"/> that authorizes commands over it, with <c>continueSession</c> SET. The caller
    /// disposes the session and flushes the handle.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle and the host session.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartUnboundHmacSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"StartAuthSession (unbound HMAC) failed: '{result.ResponseCode}'.");

        //The response owns nothing but nonceTPM, and the session takes that over, so the response is deliberately
        //not disposed here.
        StartAuthSessionResponse started = result.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);

        return (started.SessionHandle.Value, session);
    }

    /// <summary>
    /// Submits <c>TPM2_SignSequenceComplete()</c> over <paramref name="sessions"/> in slot order, supplying the
    /// Empty Buffer for the sequence handle's cpHash Name term and <paramref name="keyName"/> for the key's, and
    /// returns the raw result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence to complete.</param>
    /// <param name="keyHandle">The candidate signing key.</param>
    /// <param name="keyName">The signing key's Name, cpHash's second handle-area term.</param>
    /// <param name="buffer">The trailing block appended before signing.</param>
    /// <param name="sessions">The authorization area in slot order: the sequence's block, the key's block, and any companion.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<SignSequenceCompleteResponse>> CompleteOverSessionsAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, TpmiDhObject keyHandle,
        ReadOnlyMemory<byte> keyName, byte[] buffer, TpmSessionBase[] sessions)
    {
        using SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(sequenceHandle, keyHandle, buffer, pool);
        ReadOnlyMemory<byte>[] handleNames = [ReadOnlyMemory<byte>.Empty, keyName];

        return await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
            tpm, input, sessions, handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Appends <paramref name="buffer"/> to an open sequence over <paramref name="session"/> — the sequence's own
    /// authorizing block, whose cpHash Name term is the Empty Buffer the executor derives — asserting success.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence handle.</param>
    /// <param name="buffer">The block to append.</param>
    /// <param name="session">The session authorizing the sequence.</param>
    private async Task UpdateOverSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, byte[] buffer, TpmSession session)
    {
        using SequenceUpdateInput input = SequenceUpdateInput.Create(sequenceHandle, buffer, pool);
        TpmResult<SequenceUpdateResponse> result = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
            tpm, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SequenceUpdate() over an HMAC session failed: '{result.ResponseCode}'.");
    }

    /// <summary>Appends <paramref name="buffer"/> to an open sequence over its <c>TPM_RS_PW</c> block, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence handle.</param>
    /// <param name="buffer">The block to append.</param>
    /// <param name="sequenceAuth">The sequence's own authorization value.</param>
    private async Task UpdateOverPasswordAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, byte[] buffer, byte[] sequenceAuth)
    {
        using TpmPasswordSession sequencePassword = HmacKeyHarness.PasswordSession(sequenceAuth, pool);
        using SequenceUpdateInput input = SequenceUpdateInput.Create(sequenceHandle, buffer, pool);
        TpmResult<SequenceUpdateResponse> result = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
            tpm, input, [sequencePassword], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SequenceUpdate() over a password block failed: '{result.ResponseCode}'.");
    }

    /// <summary>Creates an unrestricted ECC P-256 ECDSA/SHA-256 signing primary under the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="password">The key's own authorization value.</param>
    /// <param name="isNoDa">Whether the template sets <c>noDA</c>, exempting the key from dictionary-attack protection.</param>
    /// <returns>The CreatePrimary response; the caller owns and disposes it.</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, string password, bool isNoDa)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: isNoDa);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256 signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Composes a CreatePrimary input for a dictionary-attack-protected ECC signing key whose
    /// <c>TPMA_OBJECT.userWithAuth</c> bit is CLEAR; no production factory omits that bit, so the public template
    /// is built directly.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the returned CreatePrimaryInput, whose Dispose releases them.")]
    private static CreatePrimaryInput CreateUserWithAuthClearEccSigningKeyInput(BaseMemoryPool pool)
    {
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.WithPassword(KeyPasswordText, pool);

        var attributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.SIGN_ENCRYPT;

        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            attributes,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));

        return new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
    }

    /// <summary>Creates the userWithAuth-CLEAR ECC signing primary under the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response; the caller owns and disposes it.</returns>
    private async Task<CreatePrimaryResponse> CreateUserWithAuthClearEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreateUserWithAuthClearEccSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (userWithAuth-CLEAR ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Composes a RESTRICTED ECC signing key template — <c>TPMA_OBJECT.restricted</c> SET alongside <c>sign</c>,
    /// carrying <see cref="KeyPasswordText"/> so its slot folds a genuine authorization value; no production
    /// factory builds a restricted signing key.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the returned CreatePrimaryInput, whose Dispose releases them.")]
    private static CreatePrimaryInput CreateRestrictedEccSigningKeyInput(BaseMemoryPool pool)
    {
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.WithPassword(KeyPasswordText, pool);

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

    /// <summary>Creates the restricted ECC signing primary under the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response; the caller owns and disposes it.</returns>
    private async Task<CreatePrimaryResponse> CreateRestrictedEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreateRestrictedEccSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (restricted ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Verifies a P-256 ECDSA signature off-TPM against a public key reconstructed solely from the simulator's
    /// exported public point, sharing no code path with the signer.
    /// </summary>
    /// <param name="point">The exported public point.</param>
    /// <param name="digest">The digest that must have been signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns><see langword="true"/> when the signature verifies.</returns>
    private static bool VerifyEcdsaSignatureOffTpm(TpmsEccPoint point, byte[] digest, TpmuSignature signature)
    {
        var ecParameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = ToFixed(point.X.AsReadOnlySpan(), P256ComponentSize),
                Y = ToFixed(point.Y.AsReadOnlySpan(), P256ComponentSize)
            }
        };

        byte[] p1363Signature = new byte[2 * P256ComponentSize];
        ToFixed(signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        using ECDsa ecdsa = ECDsa.Create(ecParameters);

        return ecdsa.VerifyHash(digest, p1363Signature);
    }

    /// <summary>
    /// Left-pads a big-endian integer to a fixed width, as the IEEE P1363 and ECPoint encodings require; the
    /// simulator returns TPM2B integers that may omit leading zero octets.
    /// </summary>
    /// <param name="value">The big-endian value.</param>
    /// <param name="length">The fixed width to pad to.</param>
    /// <returns>A new array of exactly <paramref name="length"/> octets.</returns>
    private static byte[] ToFixed(ReadOnlySpan<byte> value, int length)
    {
        byte[] result = new byte[length];
        if(value.Length <= length)
        {
            value.CopyTo(result.AsSpan(length - value.Length));
        }
        else
        {
            value[^length..].CopyTo(result);
        }

        return result;
    }

    /// <summary>
    /// No <c>TPM2_SignSequenceComplete()</c> response parameter has a size field — Table 125's response is a bare
    /// <c>TPMT_SIGNATURE</c> — so an <c>encrypt</c> claim is refused with <c>TPM_RC_ATTRIBUTES</c> encoded to the
    /// claiming slot, here the KEY slot at index 1, the one command of the family where the claim can ride a
    /// second authorizing block
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6, Table 125; Part 1: Architecture, clause 18.1 — "only
    /// the first parameter in the parameter area of a request or response can be encrypted. That parameter must
    /// have an explicit size field"; Part 2: Structures, clause 6.6.2). The claim is planted on the WIRE because
    /// the area's structural checks (Part 3, clause 5.5) precede clause 5.6's authorization.
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteWithAnEncryptClaimAtTheKeySlotIsRefusedWithAttributesAtSlotOne()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignSequenceCompleteWithAnEncryptClaimAtTheKeySlotIsRefusedWithAttributesAtSlotOne), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, KeyPasswordText, isNoDa: true).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(SequenceAuth, pool);
            keySession.SetAuthValue(KeyAuth, pool);

            static byte[] Rewrite(byte[] command)
            {
                SetSessionAttributeBit(command, handleCount: 2, sessionIndex: 1, TpmaSession.ENCRYPT);

                return command;
            }

            using TpmDevice rewritingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_SignSequenceComplete, Rewrite);

            TpmResult<SignSequenceCompleteResponse> result = await CompleteOverSessionsAsync(
                rewritingDevice, registry, pool, sequenceHandle, key.ObjectHandle, key.Name.AsReadOnlyMemory(), "message"u8.ToArray(), [sequenceSession, keySession]).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_ATTRIBUTES, result.BaseError,
                "No TPM2_SignSequenceComplete() response parameter has a size field, so an encrypt claim must be refused with TPM_RC_ATTRIBUTES.");
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), result.ResponseCode,
                "The refusal names the claiming slot (index 1), so the wire code carries its session-index modifier.");
        }
        finally
        {
            sequenceSession.Dispose();
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>The command header's fixed width: tag (UINT16), commandSize (UINT32), commandCode (UINT32).</summary>
    private const int CommandHeaderSize = 10;

    /// <summary>Reads a framed command's command code (TPM 2.0 Library Part 1, clause 15.2.3's commandCode header field).</summary>
    /// <param name="command">The framed command.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(ReadOnlySpan<byte> command) =>
        (TpmCcConstants)BinaryPrimitives.ReadUInt32BigEndian(command[(sizeof(ushort) + sizeof(uint))..]);

    /// <summary>
    /// Builds a device that rewrites every framed command carrying <paramref name="commandCode"/> through
    /// <paramref name="rewrite"/> before it reaches the simulator, so a wire-level shape the host executor
    /// would never frame can be planted on exactly one command.
    /// </summary>
    /// <param name="simulator">The simulator the rewritten commands reach.</param>
    /// <param name="commandCode">The command code the rewrite applies to.</param>
    /// <param name="rewrite">The rewrite.</param>
    /// <returns>The rewriting device.</returns>
    private static TpmDevice CreateRewritingDevice(TpmSimulator simulator, TpmCcConstants commandCode, Func<byte[], byte[]> rewrite)
    {
        return TpmDevice.Create(async (command, commandPool, cancellationToken) =>
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == commandCode)
            {
                bytes = rewrite(bytes);
            }

            return await simulator.SubmitAsync(bytes, commandPool, cancellationToken).ConfigureAwait(false);
        }, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
    }

    /// <summary>
    /// ORs <paramref name="sessionAttributes"/> into the attributes octet of the slot at <paramref name="sessionIndex"/>
    /// of a framed command's authorization area, walking the earlier slots by their own sized fields.
    /// </summary>
    /// <param name="command">The framed command, rewritten in place.</param>
    /// <param name="handleCount">The command's handle count, which fixes where the area begins.</param>
    /// <param name="sessionIndex">The zero-based slot to rewrite.</param>
    /// <param name="sessionAttributes">The bits to set.</param>
    private static void SetSessionAttributeBit(byte[] command, int handleCount, int sessionIndex, TpmaSession sessionAttributes)
    {
        int offset = CommandHeaderSize + (handleCount * sizeof(uint)) + sizeof(uint);
        for(int slot = 0; slot < sessionIndex; slot++)
        {
            offset += sizeof(uint);
            offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(command.AsSpan(offset, sizeof(ushort)));
            offset += sizeof(byte);
            offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(command.AsSpan(offset, sizeof(ushort)));
        }

        offset += sizeof(uint);
        offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(command.AsSpan(offset, sizeof(ushort)));
        command[offset] |= (byte)sessionAttributes;
    }

    /// <summary>
    /// The RSA arm of the same shape: both slots as real HMAC sessions over an RSASSA signing key sign the SHA-256
    /// digest of the whole accumulated message, and the signature verifies off-TPM against a public key
    /// reconstructed solely from the exported modulus — the RSA signing action framing its response over sessions
    /// exactly as the ECC and HMAC arms do
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6, Table 124; clause 20.1, Table 115's RSASSA row).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOverTwoHmacSessionsWithAnRsaKeyVerifiesOffTpm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateRsaCapableOperationalAsync(nameof(SignSequenceCompleteOverTwoHmacSessionsWithAnRsaKeyVerifiesOffTpm), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, KeyPasswordText, keyBits: 2048, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> created = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(created.IsSuccess, $"CreatePrimary (RSA-2048 RSASSA signing key) failed: '{created.ResponseCode}'.");
        using CreatePrimaryResponse key = created.Value;

        byte[] chunk = "Verifiable session-authorized RSA sequence signing "u8.ToArray();
        byte[] trailing = "acceptance message."u8.ToArray();
        byte[] wholeMessage = [.. chunk, .. trailing];

        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);
        await UpdateOverPasswordAsync(tpm, registry, pool, sequenceHandle, chunk, SequenceAuth).ConfigureAwait(false);

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(SequenceAuth, pool);
            keySession.SetAuthValue(KeyAuth, pool);

            TpmResult<SignSequenceCompleteResponse> result = await CompleteOverSessionsAsync(
                tpm, registry, pool, sequenceHandle, key.ObjectHandle, key.Name.AsReadOnlyMemory(), trailing, [sequenceSession, keySession]).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_SignSequenceComplete() (RSASSA, two real HMAC sessions) must succeed: '{result.ResponseCode}'.");

            using SignSequenceCompleteResponse completed = result.Value;
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSASSA, completed.SignatureAlgorithm, "The framed TPMT_SIGNATURE must select the RSASSA member.");

            using var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = key.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
                Exponent = [0x01, 0x00, 0x01]
            });
            Assert.IsTrue(
                rsa.VerifyData(wholeMessage, completed.Signature.RsaSignature.Buffer.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                "The session-authorized RSASSA signature must verify against the whole accumulated message under the exported modulus.");
        }
        finally
        {
            sequenceSession.Dispose();
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Creates an operational simulator carrying an RSA signing backend beside the ECC one — the RSA arm of
    /// <c>TPM2_SignSequenceComplete()</c> needs it, and the shared harness builds an ECC-only simulator — powered
    /// on and started with <c>TPM2_Startup(TPM_SU_CLEAR)</c> exactly as the harness does.
    /// </summary>
    /// <param name="name">A per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator; the caller disposes it.</returns>
    private async Task<TpmSimulator> CreateRsaCapableOperationalAsync(string name, BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            name, signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var startup = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + startup.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)startup.CommandCode);
        header.WriteTo(ref writer);
        startup.WriteHandles(ref writer);
        startup.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
