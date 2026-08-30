using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Acceptance tests for the SESSION-authorized form of <c>TPM2_SignDigest()</c> against the in-house behavioural
/// <see cref="TpmSimulator"/>: <c>@keyHandle</c> (Auth Index 1, Auth Role USER) authorized by a real HMAC session
/// — unbound, bound to the signing key itself, or a <c>TPM_RS_PW</c> password slot beside a companion carrying
/// <c>decrypt</c> — with <c>context</c>, the sized first command parameter, protected by session-based parameter
/// encryption (TPM 2.0 Library Part 3, clause 20.7, Tables 126/127; Part 1, clauses 15.6.1, 16.6 and 18.1).
/// </summary>
/// <remarks>
/// <para>
/// Every real session here verifies the simulator's response authorization end to end through
/// <see cref="TpmSession.VerifyAndUpdateAsync"/> inside <see cref="TpmCommandExecutor"/>, so a wrong response
/// HMAC surfaces as a failed exchange rather than as a silently accepted signature, and a session's
/// <c>nonceTPM</c> only changes once its own response entry has authenticated.
/// </para>
/// <para>
/// The command's own rules run AFTER the authorization and after the first parameter is recovered (Part 3,
/// clauses 5.6, 5.7 and 5.8 in that order), so <c>TPM_RC_TICKET</c>, <c>TPM_RC_SCHEME</c> and the command's
/// <c>TPM_RC_SIZE</c> answer BARE on the session form exactly as they do on the password form, while a failure
/// attributed to a slot — an inadmissible attribute, a mismatched command HMAC, an over-bound recovered
/// parameter — is session-index-encoded to that slot (Part 2, clause 6.6.2). The refusals the host executor
/// pre-empts client-side are planted on the WIRE through a rewriting device, since Part 3, clause 5.5's
/// session-area checks run before clause 5.6's authorization and that ordering is what such a test names.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorSignDigestSessionTests
{
    /// <summary>The hash algorithm every session in this class negotiates.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The number of octets in a NIST P-256 coordinate, an ECDSA r/s component, and a SHA-256 digest.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus size in bits the RSA cases create their signing key with.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The command header's fixed width: tag (UINT16), commandSize (UINT32), commandCode (UINT32).</summary>
    private const int CommandHeaderSize = 10;

    /// <summary>The NULL <c>TPMT_TK_HASHCHECK</c>'s serialized width: tag (UINT16), hierarchy (UINT32), an empty digest (UINT16).</summary>
    private const int NullValidationTicketSize = sizeof(ushort) + sizeof(uint) + sizeof(ushort);

    /// <summary>The message whose SHA-256 digest every case signs.</summary>
    private static byte[] MessageBytes { get; } = "Verifiable in-house TPM SignDigest over sessions."u8.ToArray();

    /// <summary>The password the signing key is created with in the cases that give it one.</summary>
    private const string SigningKeyPassword = "sign-digest-session-key-auth";

    /// <summary>
    /// <see cref="SigningKeyPassword"/>'s UTF-8 octets, matching the password-to-authValue convention
    /// <see cref="Tpm2bAuth.CreateFromPassword"/> applies on the creation side.
    /// </summary>
    private static byte[] SigningKeyAuth { get; } = System.Text.Encoding.UTF8.GetBytes(SigningKeyPassword);

    /// <summary>A value that is not <see cref="SigningKeyAuth"/>, presented where a mismatch is the subject.</summary>
    private static byte[] WrongSigningKeyAuth { get; } = "sign-digest-session-key-wrong"u8.ToArray();

    /// <summary>A fixed seed standing in for the hierarchy's persistent proof secret, making a minted ticket reproducible off-TPM.</summary>
    private static byte[] TicketSeed { get; } = Convert.FromHexString("102030405060708090A0B0C0D0E0F00102030405060708090A0B0C0D0E0F00");

    /// <summary>
    /// A short, in-bounds but NON-EMPTY <c>context</c>, which Table 220's <c>empty[0]</c> arm forbids for every
    /// scheme this simulator resolves.
    /// </summary>
    private static byte[] NonEmptyContext { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>
    /// A <c>context</c> one octet wider than <c>sizeof(TPMU_SIGNATURE_CTX)</c>, the bound
    /// <see cref="Tpm2bSignatureCtx.MaxSize"/> names (TPM 2.0 Library Part 2, Tables 220/221).
    /// </summary>
    private static byte[] OverBoundContext { get; } = new byte[Tpm2bSignatureCtx.MaxSize + 1];

    /// <summary>The HMAC key octets the KEYEDHASH case loads, so its object is a real signing-shaped KEYEDHASH key.</summary>
    private static byte[] KeyedHashKeyBytes { get; } = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

    /// <summary>Gets or sets the per-test context, whose cancellation token every exchange observes.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// <c>@keyHandle</c> carries Auth Index 1 and Auth Role USER, which a real HMAC session may discharge as well
    /// as a password: an ECC signing key authorized by an UNBOUND, unsalted HMAC session folding the key's own
    /// authorization value signs the caller's digest under the key's retained ECDSA/SHA-256 scheme, and the
    /// signature verifies off-TPM against the exported public point
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7, Table 126; Part 1: Architecture, clause 16.6.5,
    /// equation 17).
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverAnUnboundHmacSessionOverAnEccKeyVerifiesOffTpm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignDigestOverAnUnboundHmacSessionOverAnEccKeyVerifiesOffTpm), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(SigningKeyAuth, pool);

            using SignDigestInput input = SignDigestInput.Create(key.ObjectHandle, digest, pool);
            TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                tpm, input, [session], [key.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_SignDigest() over an unbound HMAC session must sign: '{result.ResponseCode}'.");

            using SignDigestResponse signature = result.Value;
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, signature.SignatureAlgorithm, "The key's retained ECDSA scheme must drive the signature.");
            Assert.IsTrue(
                VerifyEcdsaSignatureOffTpm(key.OutPublic.PublicArea.Unique.Ecc!, digest, signature.Signature),
                "A session-authorized ECDSA signature must verify against the simulator's exported public key.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The RSA arm of <see cref="SignDigestOverAnUnboundHmacSessionOverAnEccKeyVerifiesOffTpm"/>: an RSA signing
    /// key created with an explicit RSASSA/SHA-256 template scheme, authorized by an unbound HMAC session folding
    /// its authorization value, signs under that retained scheme — <c>TPM2_SignDigest()</c> carries no
    /// <c>inScheme</c> for a caller to substitute one — and the signature verifies off-TPM against the exported
    /// modulus (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7.1).
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverAnUnboundHmacSessionOverAnRsaKeyVerifiesOffTpm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignDigestOverAnUnboundHmacSessionOverAnRsaKeyVerifiesOffTpm), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(SigningKeyAuth, pool);

            using SignDigestInput input = SignDigestInput.Create(key.ObjectHandle, digest, pool);
            TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                tpm, input, [session], [key.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_SignDigest() over an unbound HMAC session must sign with an RSA key: '{result.ResponseCode}'.");

            using SignDigestResponse signature = result.Value;
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSASSA, signature.SignatureAlgorithm, "The key's retained RSASSA scheme must drive the signature.");
            Assert.IsTrue(
                VerifyRsaSsaSignatureOffTpm(key.OutPublic.PublicArea.Unique.GetRsaModulus(), digest, signature.Signature),
                "A session-authorized RSASSA signature must verify against the simulator's exported modulus.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "Signing using a restricted key is permitted, but it requires a valid TPMT_TK_HASHCHECK indicating that
    /// digest is known by the TPM to be the hash of some message"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7.1): a RESTRICTED ECC signing key authorized over an
    /// HMAC session and given a genuine ticket — Equation (7), <c>HMAC_contextAlg(proof, TPM_ST_HASHCHECK ‖
    /// digest)</c> (Part 2: Structures, clause 10.6.7), reproduced here from the injected proof seed — signs, and
    /// the ticket-validating effect frames its response over the session's own entry so the exchange's response
    /// authorization verifies.
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverASessionWithASeedReproducedTicketOnARestrictedEccKeySigns()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateSeededOperationalAsync(nameof(SignDigestOverASessionWithASeedReproducedTicketOnARestrictedEccKeySigns), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] ticketDigest = await ComputeHashcheckTicketDigestAsync(TicketSeed, (uint)TpmRh.TPM_RH_OWNER, digest, pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            using TpmtTkHashcheck validation = TpmtTkHashcheck.Create(TpmiRhHierarchy.Owner, ticketDigest, pool);
            using SignDigestInput input = SignDigestInput.CreateForRestrictedKey(key.ObjectHandle, digest, validation, pool);
            TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                tpm, input, [session], [key.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A restricted ECC key with a valid ticket must sign over a session: '{result.ResponseCode}'.");

            using SignDigestResponse signature = result.Value;
            Assert.IsTrue(
                VerifyEcdsaSignatureOffTpm(key.OutPublic.PublicArea.Unique.Ecc!, digest, signature.Signature),
                "The signature the ticket-validating effect framed over the session must verify against the exported public key.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The RSA arm of <see cref="SignDigestOverASessionWithASeedReproducedTicketOnARestrictedEccKeySigns"/>: a
    /// restricted RSA signing key authorized over an HMAC session and given a genuine, seed-reproduced
    /// <c>TPMT_TK_HASHCHECK</c> signs, and the RSASSA signature verifies off-TPM against the exported modulus
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7; Part 2: Structures, clause 10.6.7).
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverASessionWithASeedReproducedTicketOnARestrictedRsaKeySigns()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateSeededOperationalAsync(nameof(SignDigestOverASessionWithASeedReproducedTicketOnARestrictedRsaKeySigns), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRestrictedRsaSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] ticketDigest = await ComputeHashcheckTicketDigestAsync(TicketSeed, (uint)TpmRh.TPM_RH_OWNER, digest, pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            using TpmtTkHashcheck validation = TpmtTkHashcheck.Create(TpmiRhHierarchy.Owner, ticketDigest, pool);
            using SignDigestInput input = SignDigestInput.CreateForRestrictedKey(key.ObjectHandle, digest, validation, pool);
            TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                tpm, input, [session], [key.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A restricted RSA key with a valid ticket must sign over a session: '{result.ResponseCode}'.");

            using SignDigestResponse signature = result.Value;
            Assert.IsTrue(
                VerifyRsaSsaSignatureOffTpm(key.OutPublic.PublicArea.Unique.GetRsaModulus(), digest, signature.Signature),
                "The RSA signature the ticket-validating effect framed over the session must verify against the exported modulus.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A ticket the caller tampered with is a COMMAND-rule refusal, not a slot's: it answers a BARE
    /// <c>TPM_RC_TICKET</c> with no session-index modifier, and because an error response is header-only and
    /// rolls no <c>nonceTPM</c> (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clause 6.2; Part 1: Architecture, clause 15.8), the very
    /// same session then signs successfully once the genuine ticket is supplied — which a rolled nonce would make
    /// impossible.
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverASessionWithATamperedTicketIsBareTicketAndLeavesTheSessionUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateSeededOperationalAsync(nameof(SignDigestOverASessionWithATamperedTicketIsBareTicketAndLeavesTheSessionUsable), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] genuineTicketDigest = await ComputeHashcheckTicketDigestAsync(TicketSeed, (uint)TpmRh.TPM_RH_OWNER, digest, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tamperedTicketDigest = (byte[])genuineTicketDigest.Clone();
        tamperedTicketDigest[^1] ^= 0x01;

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            byte[] nonceTpmBeforeRefusal = session.NonceTpm.ToArray();

            using(TpmtTkHashcheck tampered = TpmtTkHashcheck.Create(TpmiRhHierarchy.Owner, tamperedTicketDigest, pool))
            using(SignDigestInput refusedInput = SignDigestInput.CreateForRestrictedKey(key.ObjectHandle, digest, tampered, pool))
            {
                TpmResult<SignDigestResponse> refused = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                    tpm, refusedInput, [session], [key.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(refused.IsTpmError, "A single-bit-tampered ticket must be refused.");
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_TICKET, refused.ResponseCode,
                    "The ticket check is one of the command's own rules, decided after the authorization, so it answers bare rather than session-index-encoded.");
            }

            Assert.IsTrue(
                session.NonceTpm.Span.SequenceEqual(nonceTpmBeforeRefusal),
                "An error response carries no session area, so the session's nonceTPM must not roll on a refusal.");

            using TpmtTkHashcheck genuine = TpmtTkHashcheck.Create(TpmiRhHierarchy.Owner, genuineTicketDigest, pool);
            using SignDigestInput retryInput = SignDigestInput.CreateForRestrictedKey(key.ObjectHandle, digest, genuine, pool);
            TpmResult<SignDigestResponse> retry = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                tpm, retryInput, [session], [key.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(retry.IsSuccess, $"The SAME session must still authorize a corrected retry after a command-rule refusal: '{retry.ResponseCode}'.");
            retry.Value.Dispose();
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If keyHandle is not a restricted signing key, then this may be a NULL Ticket with tag =
    /// TPM_ST_HASHCHECK" (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clause 20.7, Table 126) — so a RESTRICTED key given the
    /// NULL ticket has no valid <c>TPMT_TK_HASHCHECK</c> and is refused <c>TPM_RC_TICKET</c>, bare, over a session
    /// exactly as over a password: the rule is one of the command's own, run after the authorization has proved
    /// the authValue (Part 3, clauses 5.6 and 5.8).
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverASessionAgainstARestrictedKeyWithANullTicketIsBareTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignDigestOverASessionAgainstARestrictedKeyWithANullTicketIsBareTicket), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            using SignDigestInput input = SignDigestInput.Create(key.ObjectHandle, digest, pool);
            TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                tpm, input, [session], [key.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_TICKET, result.ResponseCode,
                "A restricted key given a NULL validation ticket must be refused with a bare TPM_RC_TICKET on the session form too.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "Only the first parameter in the parameter area of a request ... can be encrypted. That parameter must
    /// have an explicit size field" (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 1: Architecture, clause 18.1): <c>context</c> is Table 126's first
    /// parameter and a <c>TPM2B_SIGNATURE_CTX</c>, so a session claiming <c>decrypt</c> with XOR obfuscation is
    /// admitted and the command signs — the conformant plaintext for every scheme this simulator resolves being
    /// the empty one (Part 2: Structures, clause 11.3.8, Tables 220/221), which is what the protected field
    /// carries.
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverAnXorDecryptSessionSignsTheProtectedEmptyContext() =>
        await RunDecryptProtectedSignDigestAsync(
            nameof(SignDigestOverAnXorDecryptSessionSignsTheProtectedEmptyContext), TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);

    /// <summary>
    /// The AES-128-CFB counterpart of <see cref="SignDigestOverAnXorDecryptSessionSignsTheProtectedEmptyContext"/>
    /// — the platform-specific CFB mode keyed and IV'd from the session's KDFa
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 18.3) — over the same first parameter of Table 126.
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverAnAesCfbDecryptSessionSignsTheProtectedEmptyContext() =>
        await RunDecryptProtectedSignDigestAsync(
            nameof(SignDigestOverAnAesCfbDecryptSessionSignsTheProtectedEmptyContext), TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)).ConfigureAwait(false);

    /// <summary>
    /// Table 220's <c>empty[0]</c> arm — "all other signature schemes do not support additional context" — is the
    /// only conformant <c>context</c> for the schemes this simulator resolves
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.7, Table 220): a NON-EMPTY but in-bounds context
    /// recovered on the session form is refused with a BARE <c>TPM_RC_SIZE</c>, because the emptiness rule is one
    /// of the command's own rules and not a slot's (Part 3: Commands, clause 5.8).
    /// </summary>
    [TestMethod]
    public async Task SignDigestWithANonEmptyContextOverASessionIsBareSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignDigestWithANonEmptyContextOverASessionIsBareSize), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(SigningKeyAuth, pool);

            var input = new SignDigestWithContextInput(key.ObjectHandle.Value, NonEmptyContext, digest);
            TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                tpm, input, [session], [key.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SIZE, result.ResponseCode,
                "A non-empty context is refused by the command's own rule, so it answers a bare TPM_RC_SIZE with no session-index modifier.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The bound on a decrypt-protected parameter belongs to the recovered PLAINTEXT, and a failure of that step
    /// is blamed on the slot that claimed the attribute
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 18.1; Part 2: Structures, clause 6.6.2): a
    /// <c>context</c> one octet wider than <c>sizeof(TPMU_SIGNATURE_CTX)</c> crossing a <c>decrypt</c> session is
    /// refused with <c>TPM_RC_SIZE</c> session-index-encoded to that slot, unlike the emptiness rule's bare
    /// answer.
    /// </summary>
    [TestMethod]
    public async Task SignDigestWithAnOverBoundContextOverADecryptSessionIsSizeAtTheDecryptSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignDigestWithAnOverBoundContextOverADecryptSessionIsSizeAtTheDecryptSlot), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(SigningKeyAuth, pool);
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            var input = new SignDigestWithContextInput(key.ObjectHandle.Value, OverBoundContext, digest);
            TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                tpm, input, [session], [key.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SIZE, result.BaseError,
                "A recovered context wider than sizeof(TPMU_SIGNATURE_CTX) is a size fault.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_SIZE, sessionIndex: 0), result.ResponseCode,
                "The decryption step's failure names the slot that claimed decrypt, so the wire code carries its session-index modifier.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "The scheme of keyHandle must be a signing scheme that supports signing a digest (e.g., TPM_ALG_ECDSA, but
    /// not TPM_ALG_HMAC)" (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clause 20.7.1): a loaded KEYEDHASH HMAC key named as
    /// <c>@keyHandle</c> is refused <c>TPM_RC_SCHEME</c> at handle resolution — before the authorization ladder
    /// runs at all — so the session form answers exactly what the password form answers, bare.
    /// </summary>
    [TestMethod]
    public async Task SignDigestAgainstAKeyedHashKeyOverASessionIsBareScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignDigestAgainstAKeyedHashKeyOverASessionIsBareScheme), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey keyedHashKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, KeyedHashKeyBytes, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            using SignDigestInput input = SignDigestInput.Create(TpmiDhObject.FromValue(keyedHashKey.Handle), digest, pool);
            TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                tpm, input, [session], [keyedHashKey.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SCHEME, result.ResponseCode,
                "A KEYEDHASH object has no digest-signing scheme, and the refusal is decided at resolution, so it is bare.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A real HMAC session genuinely verifies <c>@keyHandle</c>'s own authorization value: a WRONG value folded
    /// into the session key fails the command HMAC with <c>TPM_RC_AUTH_FAIL</c> session-index-encoded to the key
    /// slot and charges <c>failedTries</c> exactly once against a DA-PROTECTED key
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 16.8.7; Part 2: Structures, clause 6.6.2; Part 3:
    /// Commands, clause 5.6).
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverASessionWithAWrongAuthValueOnADaProtectedKeyIsAuthFailAndCharges()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignDigestOverASessionWithAWrongAuthValueOnADaProtectedKeyIsAuthFailAndCharges), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: false).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess, $"GetDictionaryAttackParameters failed: '{before.ResponseCode}'.");

        TpmRcConstants responseCode = await SignDigestWithPresentedAuthValueAsync(tpm, registry, pool, key, WrongSigningKeyAuth).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), responseCode,
            "A wrong authValue over a real session against a DA-protected key must answer TPM_RC_AUTH_FAIL at the key slot.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter + 1, after.Value.LockoutCounter,
            "The mismatch against a DA-protected signing key must charge the lockout counter exactly once.");
    }

    /// <summary>
    /// The <c>noDA</c> contrast to
    /// <see cref="SignDigestOverASessionWithAWrongAuthValueOnADaProtectedKeyIsAuthFailAndCharges"/>: the same
    /// mismatch against a dictionary-attack-EXEMPT key answers the uncharged <c>TPM_RC_BAD_AUTH</c>, still
    /// session-index-encoded to the key slot
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 16.8.1; Part 2: Structures, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverASessionWithAWrongAuthValueOnANoDaKeyIsBadAuthAndUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignDigestOverASessionWithAWrongAuthValueOnANoDaKeyIsBadAuthAndUncharged), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess, $"GetDictionaryAttackParameters failed: '{before.ResponseCode}'.");

        TpmRcConstants responseCode = await SignDigestWithPresentedAuthValueAsync(tpm, registry, pool, key, WrongSigningKeyAuth).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), responseCode,
            "A wrong authValue against a noDA key must answer the uncharged TPM_RC_BAD_AUTH at the key slot.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "A noDA key's mismatch must move no dictionary-attack counter.");
    }

    /// <summary>
    /// A session's <c>nonceTPM</c> changes on every use, command and response alike, and a session adopts the new
    /// value only once the response entry carrying it has authenticated
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clauses 16.6.3 and 16.6.5): two consecutive
    /// <c>TPM2_SignDigest()</c> commands over one continued session each sign, and each rolls the nonce — a
    /// nonce that failed to roll would fail the second exchange's own verification.
    /// </summary>
    [TestMethod]
    public async Task TwoSignDigestsOverOneSessionEachSignAndRollTheNonceTpm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(TwoSignDigestsOverOneSessionEachSignAndRollTheNonceTpm), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(SigningKeyAuth, pool);

            for(int exchange = 0; exchange < 2; exchange++)
            {
                byte[] nonceTpmBefore = session.NonceTpm.ToArray();

                using SignDigestInput input = SignDigestInput.Create(key.ObjectHandle, digest, pool);
                TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                    tpm, input, [session], [key.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"Exchange {exchange} over the continued session must sign: '{result.ResponseCode}'.");
                result.Value.Dispose();

                Assert.IsFalse(
                    session.NonceTpm.Span.SequenceEqual(nonceTpmBefore),
                    $"Exchange {exchange} must adopt a genuinely rolled nonceTPM from its own authenticated response entry.");
            }
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Binding already incorporates the bind entity's authorization value into the session key, so a session that
    /// authorizes the very key it is bound to omits that value from the per-command HMAC key
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 16.6.10, equations 20 and 22):
    /// <c>TPM2_SignDigest()</c> signs over such a session with NO per-command authorization value presented, and
    /// the signature verifies off-TPM.
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverASessionBoundToTheSigningKeyItselfSignsWithoutAPerCommandAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignDigestOverASessionBoundToTheSigningKeyItselfSignsWithoutAPerCommandAuthValue), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: false).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(key.ObjectHandle.Value, SessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to the signing key) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;
        try
        {
            using TpmSession session = await TpmSession.CreateBoundAsync(
                new TpmHandle(sessionHandle), SigningKeyAuth, startInput.NonceCaller, started.NonceTPM, SessionAlg, pool,
                isBoundToAuthorizedEntity: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

            using SignDigestInput input = SignDigestInput.Create(key.ObjectHandle, digest, pool);
            TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                tpm, input, [session], [key.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A session bound to the signing key itself must sign with the authValue folded into the bind alone: '{result.ResponseCode}'.");

            using SignDigestResponse signature = result.Value;
            Assert.IsTrue(
                VerifyEcdsaSignatureOffTpm(key.OutPublic.PublicArea.Unique.Ecc!, digest, signature.Signature),
                "The signature produced over a bound session must verify against the exported public key.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_SignDigest()</c>'s response carries a <c>TPMT_SIGNATURE</c> and so has no sized first parameter
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7, Table 127), and only a sized first response parameter
    /// can be encrypted (Part 1: Architecture, clause 18.1): a session claiming <c>encrypt</c> is refused
    /// <c>TPM_RC_ATTRIBUTES</c> session-index-encoded to its slot. The host executor refuses the same claim
    /// client-side, so the bit is planted on the wire, where Part 3, clause 5.5's area checks answer it ahead of
    /// clause 5.6's command HMAC — which the planted octet also breaks.
    /// </summary>
    [TestMethod]
    public async Task SignDigestWithAPlantedEncryptAttributeIsAttributesAtItsSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignDigestWithAPlantedEncryptAttributeIsAttributesAtItsSlot), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(SigningKeyAuth, pool);

            using TpmDevice plantingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_SignDigest, command => WithSlotZeroAttribute(command, TpmaSession.ENCRYPT));
            using SignDigestInput input = SignDigestInput.Create(key.ObjectHandle, digest, pool);
            TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                plantingDevice, input, [session], [key.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A planted encrypt claim on a response with no sized first parameter must be refused.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), result.ResponseCode,
                "The area check answers TPM_RC_ATTRIBUTES at the claiming slot, ahead of the command HMAC the planted octet also breaks.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An authorization area may mix a <c>TPM_RS_PW</c> password at the authorizing position with a companion
    /// carried only for <c>decrypt</c> behind it
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 15.6.1, Table 12): the password slot is compared inline,
    /// the companion presents a real command HMAC of its own keyed on its session key ALONE — "if the session is
    /// not being used for authorization, sessionValue is sessionKey" (clause 18.1) — and it protects
    /// <c>context</c>, so the command signs and the signature verifies off-TPM.
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverAPasswordKeySlotWithADecryptCompanionSigns()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignDigestOverAPasswordKeySlotWithADecryptCompanionSigns), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint companionHandle, TpmSession companion) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        try
        {
            companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            using TpmPasswordSession keyAuth = HmacKeyHarness.PasswordSession(SigningKeyAuth, pool);
            using SignDigestInput input = SignDigestInput.Create(key.ObjectHandle, digest, pool);
            TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                tpm, input, [keyAuth, companion], [key.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A password key slot beside a decrypt companion must sign: '{result.ResponseCode}'.");

            using SignDigestResponse signature = result.Value;
            Assert.IsTrue(
                VerifyEcdsaSignatureOffTpm(key.OutPublic.PublicArea.Unique.Ecc!, digest, signature.Signature),
                "The signature produced over a mixed password-and-companion area must verify against the exported public key.");
        }
        finally
        {
            companion.Dispose();
            await FlushIfPresentAsync(tpm, registry, pool, companionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A successful session-authorized <c>TPM2_SignDigest()</c> leaves no pooled carrier outstanding: every
    /// buffer the parse rented for the authorization area and the parameter area, and every buffer the framing
    /// rented for the response entry, is released along the accepting path
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7 — the balance is the accounting proof that the accepted
    /// path owns what it rents).
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverASessionReturnsEveryCarrierToTheMeteredPoolOnSuccess()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants responseCode = await RunSignDigestForPoolBalanceAsync(
            nameof(SignDigestOverASessionReturnsEveryCarrierToTheMeteredPoolOnSuccess), trackingPool.Pool, SigningKeyAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, responseCode, "The balance below proves nothing unless the command really did sign.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A successful session-authorized TPM2_SignDigest() must leave no pooled carrier outstanding.");
    }

    /// <summary>
    /// The refusing counterpart of
    /// <see cref="SignDigestOverASessionReturnsEveryCarrierToTheMeteredPoolOnSuccess"/>: a wrong authorization
    /// value refuses the exchange at the key slot's command HMAC, transferring nothing into an action, and the
    /// refusing arm still returns every parse-rented carrier to the pool
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.6).
    /// </summary>
    [TestMethod]
    public async Task SignDigestRefusedOverASessionReturnsEveryCarrierToTheMeteredPool()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants responseCode = await RunSignDigestForPoolBalanceAsync(
            nameof(SignDigestRefusedOverASessionReturnsEveryCarrierToTheMeteredPool), trackingPool.Pool, WrongSigningKeyAuth).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), responseCode,
            "The balance below proves nothing unless the command really was refused at the key slot.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refused session-authorized TPM2_SignDigest() must leave no pooled carrier outstanding.");
    }

    /// <summary>
    /// Runs one <c>TPM2_SignDigest()</c> over an owner-bound HMAC session negotiating
    /// <paramref name="symmetric"/> and claiming <c>decrypt</c>, and asserts the command signed and the
    /// signature verifies off-TPM.
    /// </summary>
    /// <param name="simulatorName">The calling test's name, identifying the simulator instance.</param>
    /// <param name="symmetric">The symmetric definition the session negotiates for parameter encryption.</param>
    private async Task RunDecryptProtectedSignDigestAsync(string simulatorName, TpmtSymDef symmetric)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(simulatorName, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, symmetric).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(SigningKeyAuth, pool);
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            using SignDigestInput input = SignDigestInput.Create(key.ObjectHandle, digest, pool);
            TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                tpm, input, [session], [key.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_SignDigest() over a '{symmetric.Algorithm}' decrypt session must sign: '{result.ResponseCode}'.");

            using SignDigestResponse signature = result.Value;
            Assert.IsTrue(
                VerifyEcdsaSignatureOffTpm(key.OutPublic.PublicArea.Unique.Ecc!, digest, signature.Signature),
                "A decrypt-protected TPM2_SignDigest() must still produce a signature that verifies against the exported public key.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Issues one <c>TPM2_SignDigest()</c> over a fresh unbound HMAC session folding
    /// <paramref name="presentedAuthValue"/> and yields what the simulator answered, so an authorization-value
    /// case asserts only the code and the counter.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The signing key to authorize.</param>
    /// <param name="presentedAuthValue">The authorization value the session folds.</param>
    /// <returns>The response code the exchange answered.</returns>
    private async Task<TpmRcConstants> SignDigestWithPresentedAuthValueAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse key, byte[] presentedAuthValue)
    {
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(presentedAuthValue, pool);

            using SignDigestInput input = SignDigestInput.Create(key.ObjectHandle, digest, pool);
            TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                tpm, input, [session], [key.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            if(result.IsSuccess)
            {
                result.Value.Dispose();

                return TpmRcConstants.TPM_RC_SUCCESS;
            }

            return result.ResponseCode;
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Runs a complete session-authorized <c>TPM2_SignDigest()</c> flow — simulator, signing key, session,
    /// exchange, flush and teardown — entirely against <paramref name="pool"/>, so a metered pool measured around
    /// the call sees every rent and every return the whole flow made.
    /// </summary>
    /// <param name="simulatorName">The calling test's name, identifying the simulator instance.</param>
    /// <param name="pool">The metered memory pool every step rents from.</param>
    /// <param name="presentedAuthValue">The authorization value the session folds, deciding success or refusal.</param>
    /// <returns>The response code the exchange answered.</returns>
    private async Task<TpmRcConstants> RunSignDigestForPoolBalanceAsync(string simulatorName, BaseMemoryPool pool, byte[] presentedAuthValue)
    {
        using TpmSimulator simulator = await CreateOperationalAsync(simulatorName, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);
        TpmRcConstants responseCode = await SignDigestWithPresentedAuthValueAsync(tpm, registry, pool, key, presentedAuthValue).ConfigureAwait(false);

        return responseCode;
    }

    /// <summary>
    /// Starts an unbound, unsalted HMAC session negotiating <paramref name="symmetric"/> and builds the host-side
    /// <see cref="TpmSession"/> that authorizes commands over it, with <c>continueSession</c> SET. The caller
    /// disposes the session and flushes the handle.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="symmetric">The symmetric definition the session negotiates.</param>
    /// <returns>The session handle and the host session.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartUnboundSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtSymDef symmetric)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, symmetric);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound HMAC) failed: '{startResult.ResponseCode}'.");

        //The response owns nothing but nonceTPM, which the constructed session takes over, so the response is
        //deliberately not disposed here.
        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, pool, symmetric)
        {
            SessionAttributes = TpmaSession.CONTINUE_SESSION
        };

        return (started.SessionHandle.Value, session);
    }

    /// <summary>
    /// Starts an HMAC session bound to the empty-authorization owner hierarchy negotiating
    /// <paramref name="symmetric"/>, so its session key is non-empty and can key a parameter-encryption
    /// keystream, and builds the host-side <see cref="TpmSession"/> with <c>continueSession</c> SET. The caller
    /// disposes the session and flushes the handle.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="symmetric">The symmetric definition the session negotiates.</param>
    /// <returns>The session handle and the host session.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartOwnerBoundSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtSymDef symmetric)
    {
        return await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, symmetric,
            isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Flushes <paramref name="handle"/> when it names something, ignoring the outcome of a handle already gone.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    private static async Task FlushIfPresentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(handle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates an ECC P-256 signing primary under the owner hierarchy with an ECDSA/SHA-256 template scheme and
    /// the supplied authorization value; the caller owns the response.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="password">The password the key retains as its authorization value.</param>
    /// <param name="isNoDa">Whether the template sets <c>noDA</c>, exempting the key from dictionary-attack protection.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, string password, bool isNoDa)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: isNoDa);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256 signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates an RSA 2048 signing primary under the owner hierarchy with an explicit RSASSA/SHA-256 template
    /// scheme and the supplied authorization value; the caller owns the response.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="password">The password the key retains as its authorization value.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, string password)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password, Rsa2048KeyBits,
            TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA 2048 RSASSA signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Composes a RESTRICTED ECC signing key template — <c>restricted</c> SET alongside <c>sign</c>, with an
    /// empty authorization value — since no production factory builds a restricted signing key.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the returned CreatePrimaryInput, whose Dispose releases them.")]
    private static CreatePrimaryInput CreateRestrictedEccSigningKeyInput(BaseMemoryPool pool)
    {
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);

        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            RestrictedSigningAttributes,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));

        return new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
    }

    /// <summary>
    /// Composes a RESTRICTED RSA signing key template — the RSA counterpart of
    /// <see cref="CreateRestrictedEccSigningKeyInput"/>, carrying an explicit RSASSA/SHA-256 template scheme.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the returned CreatePrimaryInput, whose Dispose releases them.")]
    private static CreatePrimaryInput CreateRestrictedRsaSigningKeyInput(BaseMemoryPool pool)
    {
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);

        Tpm2bPublic inPublic = Tpm2bPublic.CreateRsaSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            RestrictedSigningAttributes,
            Rsa2048KeyBits,
            TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256));

        return new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
    }

    /// <summary>The object attributes both restricted signing templates carry: an empty-auth, USER-role, noDA restricted signer.</summary>
    private static TpmaObject RestrictedSigningAttributes =>
        TpmaObject.FIXED_TPM |
        TpmaObject.FIXED_PARENT |
        TpmaObject.SENSITIVE_DATA_ORIGIN |
        TpmaObject.USER_WITH_AUTH |
        TpmaObject.SIGN_ENCRYPT |
        TpmaObject.RESTRICTED |
        TpmaObject.NO_DA;

    /// <summary>Creates the restricted ECC signing primary under the owner hierarchy; the caller owns the response.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateRestrictedEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreateRestrictedEccSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (restricted ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates the restricted RSA signing primary under the owner hierarchy; the caller owns the response.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateRestrictedRsaSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreateRestrictedRsaSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (restricted RSA signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers it
    /// on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="name">A per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool) =>
        CreateOperationalCoreAsync(name, pool, ReadOnlyMemory<byte>.Empty);

    /// <summary>
    /// Creates a simulator whose hierarchy proof derives from <see cref="TicketSeed"/>, making a minted
    /// <c>TPMT_TK_HASHCHECK</c> reproducible off-TPM, and brings it into the operational phase.
    /// </summary>
    /// <param name="name">A per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private Task<TpmSimulator> CreateSeededOperationalAsync(string name, BaseMemoryPool pool) =>
        CreateOperationalCoreAsync(name, pool, TicketSeed);

    /// <summary>The shared simulator construction and startup behind the seeded and unseeded factories.</summary>
    /// <param name="name">A per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="seed">The hierarchy proof seed to inject, empty for the identifier-derived default.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalCoreAsync(string name, BaseMemoryPool pool, ReadOnlyMemory<byte> seed)
    {
        var simulator = new TpmSimulator(
            name,
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(),
            seed: seed);
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
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must reach the simulator.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }

    /// <summary>Builds the response codec registry covering every executor-driven command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignDigest, TpmResponseCodec.SignDigest);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// The format-one session-index encoding: <c>rc = baseRc + TPM_RC_S + 0x100 · (sessionIndex + 1)</c> (TPM 2.0
    /// Library Part 2, clause 6.6.2).
    /// </summary>
    /// <param name="baseRc">The unmodified format-one response code.</param>
    /// <param name="sessionIndex">The zero-based index of the session the failure names.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        HmacKeyHarness.SessionEncodedRc(baseRc, sessionIndex);

    /// <summary>Reads a framed command's <c>commandCode</c> field (TPM 2.0 Library Part 1, clause 15.2.3's commandCode header field).</summary>
    /// <param name="command">The framed command.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(ReadOnlySpan<byte> command) =>
        (TpmCcConstants)BinaryPrimitives.ReadUInt32BigEndian(command[(sizeof(ushort) + sizeof(uint))..]);

    /// <summary>
    /// Wraps the simulator in a device that rewrites the wire bytes of exactly one command code on their way in,
    /// leaving every other command untouched.
    /// </summary>
    /// <param name="simulator">The simulator the rewritten command is submitted to.</param>
    /// <param name="commandCode">The command whose bytes are rewritten.</param>
    /// <param name="rewrite">The rewrite to apply.</param>
    /// <returns>The rewriting device; the caller owns it.</returns>
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
        });
    }

    /// <summary>
    /// Sets attribute bits in the <c>sessionAttributes</c> octet of the first <c>TPMS_AUTH_COMMAND</c> block of a
    /// one-handle command, leaving every other octet of the frame alone.
    /// </summary>
    /// <param name="command">The framed command.</param>
    /// <param name="attribute">The attribute bits to set.</param>
    /// <returns>The rewritten command.</returns>
    private static byte[] WithSlotZeroAttribute(byte[] command, TpmaSession attribute)
    {
        byte[] rewritten = (byte[])command.Clone();

        //Header, the one handle, authorizationSize, the slot's session handle, then the slot's nonceCaller.
        int cursor = CommandHeaderSize + sizeof(uint) + sizeof(uint) + sizeof(uint);
        ushort nonceSize = BinaryPrimitives.ReadUInt16BigEndian(rewritten.AsSpan(cursor));
        cursor += sizeof(ushort) + nonceSize;
        rewritten[cursor] |= (byte)attribute;

        return rewritten;
    }

    /// <summary>
    /// Verifies a P-256 ECDSA signature off-TPM against a public key reconstructed solely from the simulator's
    /// exported public point, sharing no code path with the signer.
    /// </summary>
    /// <param name="point">The exported public point.</param>
    /// <param name="digest">The digest that was signed.</param>
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
    /// Verifies an RSASSA (PKCS#1 v1.5) signature off-TPM against a key reconstructed solely from the simulator's
    /// exported modulus, sharing no code path with the signer.
    /// </summary>
    /// <param name="modulus">The exported modulus.</param>
    /// <param name="digest">The digest that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns><see langword="true"/> when the signature verifies.</returns>
    private static bool VerifyRsaSsaSignatureOffTpm(ReadOnlySpan<byte> modulus, byte[] digest, TpmuSignature signature)
    {
        var rsaParameters = new RSAParameters
        {
            Modulus = modulus.ToArray(),
            Exponent = [0x01, 0x00, 0x01]
        };

        using RSA rsa = RSA.Create(rsaParameters);

        return rsa.VerifyHash(digest, signature.RsaSignature.Buffer.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    /// <summary>
    /// Left-pads a big-endian integer to a fixed width, as the IEEE P1363 and <c>ECPoint</c> encodings require:
    /// the simulator returns TPM2B integers that may omit leading zero octets.
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

    /// <summary>Computes a SHA-256 digest through the registered digest seam rather than a direct framework hash.</summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A token observed across the computation.</param>
    /// <returns>The 32-octet digest.</returns>
    private static async Task<byte[]> ComputeSha256Async(ReadOnlyMemory<byte> message, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        Tag tag = Tag.Create(HashAlgorithmName.SHA256)
            .With(Purpose.Digest)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(message),
            outputByteLength: P256ComponentSize,
            tag: tag,
            pool: pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>Computes an HMAC-SHA-256 through the registered HMAC seam.</summary>
    /// <param name="message">The message to authenticate.</param>
    /// <param name="key">The HMAC key.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A token observed across the computation.</param>
    /// <returns>The 32-octet HMAC.</returns>
    private static async Task<byte[]> ComputeHmacSha256Async(ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> key, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using HmacValue hmac = await CryptographicKeyEvents.ComputeHmacAsync(
            message, key, P256ComponentSize, CryptoTags.HmacSha256Value, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return hmac.AsReadOnlySpan().ToArray();
    }

    /// <summary>Builds the hierarchy proof-derivation input: the injected seed followed by the hierarchy handle.</summary>
    /// <param name="seed">The injected seed.</param>
    /// <param name="hierarchy">The hierarchy handle.</param>
    /// <returns>The proof-derivation input octets.</returns>
    private static byte[] BuildProofInput(byte[] seed, uint hierarchy)
    {
        byte[] input = new byte[seed.Length + sizeof(uint)];
        var writer = new TpmWriter(input);
        writer.WriteBytes(seed);
        writer.WriteUInt32(hierarchy);

        return input;
    }

    /// <summary>Builds the hash-check ticket HMAC message of Equation (7): <c>TPM_ST_HASHCHECK</c> (UINT16) followed by the digest.</summary>
    /// <param name="digest">The digest the ticket asserts the TPM produced.</param>
    /// <returns>The message octets.</returns>
    private static byte[] BuildHashcheckTicketMessage(ReadOnlySpan<byte> digest)
    {
        byte[] message = new byte[sizeof(ushort) + digest.Length];
        var writer = new TpmWriter(message);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_HASHCHECK);
        writer.WriteBytes(digest);

        return message;
    }

    /// <summary>
    /// Reproduces a hash-check ticket digest from the injected proof seed: <c>proof = H(seed ‖ hierarchy)</c>,
    /// <c>digest = HMAC(proof, TPM_ST_HASHCHECK ‖ digest)</c> — Equation (7), TPM 2.0 Library Part 2, clause
    /// 10.6.7.
    /// </summary>
    /// <param name="seed">The injected hierarchy proof seed.</param>
    /// <param name="hierarchy">The hierarchy the ticket is claimed under.</param>
    /// <param name="digest">The digest the ticket asserts the TPM produced.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A token observed across the computations.</param>
    /// <returns>The 32-octet ticket digest.</returns>
    private static async Task<byte[]> ComputeHashcheckTicketDigestAsync(
        byte[] seed, uint hierarchy, byte[] digest, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        byte[] proof = await ComputeSha256Async(BuildProofInput(seed, hierarchy), pool, cancellationToken).ConfigureAwait(false);
        byte[] message = BuildHashcheckTicketMessage(digest);

        return await ComputeHmacSha256Async(message, proof, pool, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// A <c>TPM2_SignDigest()</c> input that marshals <c>context</c> verbatim from caller-supplied octets, so a
    /// frame <see cref="SignDigestInput"/> refuses to build — a non-empty or over-bound
    /// <c>TPM2B_SIGNATURE_CTX</c> — can still ride the production executor over any authorization area. It owns
    /// nothing: the context and digest memory are the caller's, and the <c>validation</c> ticket is the NULL one
    /// Table 126's note admits for an unrestricted key.
    /// </summary>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle value.</param>
    /// <param name="context">The <c>context</c> octets, marshaled verbatim as a TPM2B.</param>
    /// <param name="digest">The <c>digest</c> octets.</param>
    private sealed class SignDigestWithContextInput(uint keyHandle, ReadOnlyMemory<byte> context, ReadOnlyMemory<byte> digest): ITpmCommandInput
    {
        /// <summary>The <c>TPM2_SignDigest()</c> command code.</summary>
        public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_SignDigest;

        /// <summary>
        /// <c>context</c> is Table 126's first parameter and carries an explicit size field, so a session may
        /// claim <c>decrypt</c> over it (TPM 2.0 Library Part 1, clause 18.1).
        /// </summary>
        public bool FirstCommandParameterIsEncryptable => true;

        /// <summary>The handle area plus <c>context ‖ digest ‖ validation</c>.</summary>
        /// <returns>The serialized size.</returns>
        public int GetSerializedSize() =>
            sizeof(uint) + sizeof(ushort) + context.Length + sizeof(ushort) + digest.Length + NullValidationTicketSize;

        /// <summary>Writes <c>@keyHandle</c>.</summary>
        /// <param name="writer">The writer.</param>
        public void WriteHandles(ref TpmWriter writer) => writer.WriteUInt32(keyHandle);

        /// <summary>Marshals <c>context</c> and <c>digest</c> as TPM2B fields, then the NULL <c>validation</c> ticket.</summary>
        /// <param name="writer">The writer.</param>
        public void WriteParameters(ref TpmWriter writer)
        {
            writer.WriteTpm2b(context.Span);
            writer.WriteTpm2b(digest.Span);
            writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_HASHCHECK);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_NULL);
            writer.WriteUInt16(0);
        }
    }
}
