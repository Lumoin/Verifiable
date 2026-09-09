using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Pins the two distinct keys one <see cref="TpmSession"/> derives from the same material — the authorization
/// HMAC key of TPM 2.0 Library Part 1, clause 16.6.10 (equations 21 and 22) and the parameter-encryption
/// <c>sessionValue</c> of clause 18.1 — and the attest family's declaration that its first command parameter and
/// its first response parameter are the sized buffers those clauses may protect.
/// </summary>
/// <remarks>
/// <para>
/// The oracle is independent in the same sense as <see cref="TpmParameterEncryptionExecutorTests"/>'s: the
/// expected session key is derived here by driving <see cref="Kdfa"/> by hand, the expected authorization HMAC
/// by driving <see cref="CryptographicKeyEvents.ComputeHmacAsync"/> by hand over a data buffer assembled here,
/// and the expected ciphertext by driving <see cref="TpmParameterEncryption.XorAsync"/> by hand with the command
/// direction's nonce order — while the session under test reaches the same values through its own code paths.
/// The caller nonce each comparison needs is read back off the serialized <c>TPMS_AUTH_COMMAND</c> the session
/// itself writes, so nothing here depends on a seam in production code.
/// </para>
/// <para>
/// Each authValue-bearing case is driven with a NON-EMPTY authorization value, because the two keys coincide
/// whenever the value is empty and a comparison over an empty value would prove nothing about which key folds
/// it.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmSessionBoundEncryptionKeyTests
{
    /// <summary>The session hash algorithm every case here negotiates.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The SHA-256 digest width in octets: the session key length, the nonce width, and the HMAC width.</summary>
    private const int DigestLength = 32;

    /// <summary>The TPM command header width in octets: tag (2) + commandSize (4) + commandCode (4).</summary>
    private const int HeaderSize = 10;

    /// <summary>The authorized entity's authorization value. It carries no trailing zero octet, so
    /// <see cref="TpmSession.SetAuthValue"/>'s clause 16.6.4.3 trimming leaves it byte-identical and the oracle
    /// can fold the literal.</summary>
    private static ReadOnlySpan<byte> EntityAuthValue => "attest-signer-authorization-value"u8;

    /// <summary>The bind entity's authorization value, the KDFa key of the bound session key (clause 16.6.10,
    /// equation 20). It is deliberately unlike <see cref="EntityAuthValue"/>.</summary>
    private static ReadOnlySpan<byte> BindAuthValue => "bind-entity-authorization-value"u8;

    /// <summary>The qualifying data <see cref="QuoteInput"/> carries as its first command parameter.</summary>
    private static ReadOnlySpan<byte> QualifyingData => "TPM2_Quote qualifying data for the confidential path"u8;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A session whose <c>bind</c> entity is the entity it authorizes keys its command HMAC on <c>sessionKey</c>
    /// alone — TPM 2.0 Library Part 1, clause 16.6.10 equation 22, against equation 21's
    /// <c>sessionKey || authValue</c> — while its parameter encryption keys on <c>sessionKey || authValue</c>
    /// all the same, because clause 18.1 says of the cipher's <c>sessionValue</c> that "The binding of the
    /// session is ignored". Both halves are recomputed by hand, and each is also shown to differ from the key
    /// the other half uses, so neither assertion can pass on a session that derives one key for both purposes.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The canned nonceTPM ownership transfers to the bound TpmSession, disposed by the using statement.")]
    public async Task BoundToTheAuthorizedEntityKeysTheHmacOnSessionKeyAndTheCipherOnSessionKeyWithAuthValue()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;

        using Tpm2bNonce startNonceCaller = MakeNonce(0x5A, pool);
        using Tpm2bNonce startNonceTpm = MakeNonce(0xC3, pool);
        using Tpm2bAuth bindAuth = Tpm2bAuth.Create(BindAuthValue, pool);
        using Tpm2bAuth entityAuth = Tpm2bAuth.Create(EntityAuthValue, pool);
        using Tpm2bAuth sessionKey = await DeriveBoundSessionKeyOracleAsync(
            bindAuth.AsReadOnlyMemory(), startNonceTpm.AsReadOnlyMemory(), startNonceCaller.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using TpmSession session = await TpmSession.CreateBoundAsync(
                new TpmHandle(0x02000000u),
                bindAuth.AsReadOnlyMemory(),
                startNonceCaller.AsReadOnlyMemory(),
                Tpm2bNonce.Create(startNonceTpm.AsReadOnlySpan(), pool),
                SessionAlg, TestEntropy.NewCounterStream(),
                pool,
                symmetric: TpmtSymDef.Xor(SessionAlg),
                isBoundToAuthorizedEntity: true,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
            session.SetAuthValue(EntityAuthValue, pool);

            using Tpm2bAuth cpHash = MakeCpHash(0x31, pool);
            using Tpm2bAuth commandHmac = await PrepareAuthHmacAsync(session, cpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);

            int authCommandSize = session.GetAuthCommandSize();
            using IMemoryOwner<byte> authCommandOwner = pool.Rent(authCommandSize);
            Memory<byte> authCommand = authCommandOwner.Memory[..authCommandSize];
            WriteAuthCommandArea(session, commandHmac, authCommand);
            ReadOnlyMemory<byte> nonceCaller = ReadAuthCommandNonceCaller(authCommand);
            ReadOnlyMemory<byte> nonceTpm = session.NonceTpm;

            using IMemoryOwner<byte> cipherKeyOwner = pool.Rent(sessionKey.AsReadOnlyMemory().Length + entityAuth.AsReadOnlyMemory().Length);
            ReadOnlyMemory<byte> cipherKey = Concatenate(sessionKey.AsReadOnlyMemory(), entityAuth.AsReadOnlyMemory(), cipherKeyOwner);

            using IMemoryOwner<byte> hmacOnSessionKeyOwner = pool.Rent(DigestLength);
            Memory<byte> hmacOnSessionKey = hmacOnSessionKeyOwner.Memory[..DigestLength];
            await ComputeExpectedAuthHmacAsync(
                sessionKey.AsReadOnlyMemory(), cpHash.AsReadOnlyMemory(), nonceCaller, nonceTpm,
                (byte)session.SessionAttributes, hmacOnSessionKey, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using IMemoryOwner<byte> hmacOnCipherKeyOwner = pool.Rent(DigestLength);
            Memory<byte> hmacOnCipherKey = hmacOnCipherKeyOwner.Memory[..DigestLength];
            await ComputeExpectedAuthHmacAsync(
                cipherKey, cpHash.AsReadOnlyMemory(), nonceCaller, nonceTpm,
                (byte)session.SessionAttributes, hmacOnCipherKey, pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(
                commandHmac.AsReadOnlySpan().SequenceEqual(hmacOnSessionKey.Span),
                "A session bound to the entity it authorizes keys its command HMAC on sessionKey alone (TPM 2.0 Library Part 1, clause 16.6.10, equation 22).");
            Assert.IsFalse(
                commandHmac.AsReadOnlySpan().SequenceEqual(hmacOnCipherKey.Span),
                "The bound session's command HMAC must not be the equation 21 form, or the omission the TPM performs is not being performed here.");

            using IMemoryOwner<byte> underTestOwner = pool.Rent(QualifyingData.Length);
            Memory<byte> underTest = underTestOwner.Memory[..QualifyingData.Length];
            QualifyingData.CopyTo(underTest.Span);
            await session.EncryptFirstParameterAsync(underTest, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using IMemoryOwner<byte> onCipherKeyOwner = pool.Rent(QualifyingData.Length);
            Memory<byte> onCipherKey = onCipherKeyOwner.Memory[..QualifyingData.Length];
            QualifyingData.CopyTo(onCipherKey.Span);
            await ObfuscateOracleAsync(cipherKey, nonceCaller, nonceTpm, onCipherKey, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using IMemoryOwner<byte> onSessionKeyOwner = pool.Rent(QualifyingData.Length);
            Memory<byte> onSessionKey = onSessionKeyOwner.Memory[..QualifyingData.Length];
            QualifyingData.CopyTo(onSessionKey.Span);
            await ObfuscateOracleAsync(sessionKey.AsReadOnlyMemory(), nonceCaller, nonceTpm, onSessionKey, pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(
                underTest.Span.SequenceEqual(onCipherKey.Span),
                "Parameter encryption keys on sessionKey || authValue even for a session bound to the entity it authorizes (TPM 2.0 Library Part 1, clause 18.1: \"The binding of the session is ignored\").");
            Assert.IsFalse(
                underTest.Span.SequenceEqual(onSessionKey.Span),
                "The cipher must not reuse the HMAC's bind-omitted key, or the entity's authValue is not protecting the parameter at all.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The session and every oracle buffer must return their pooled carriers.");
    }

    /// <summary>
    /// The same bound session that has NOT declared its bind entity to be the entity it authorizes keys BOTH
    /// its command HMAC and its parameter encryption on <c>sessionKey || authValue</c>: TPM 2.0 Library Part 1,
    /// clause 16.6.10 omits the authValue from the HMAC key only when the authorization is for the bound entity,
    /// and binding to some other entity (the entropy-raising use the clause's own note describes) leaves
    /// equation 21 in force.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The canned nonceTPM ownership transfers to the bound TpmSession, disposed by the using statement.")]
    public async Task BoundWithoutTheAuthorizedEntityDeclarationKeysBothTheHmacAndTheCipherOnSessionKeyWithAuthValue()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;

        using Tpm2bNonce startNonceCaller = MakeNonce(0x5A, pool);
        using Tpm2bNonce startNonceTpm = MakeNonce(0xC3, pool);
        using Tpm2bAuth bindAuth = Tpm2bAuth.Create(BindAuthValue, pool);
        using Tpm2bAuth entityAuth = Tpm2bAuth.Create(EntityAuthValue, pool);
        using Tpm2bAuth sessionKey = await DeriveBoundSessionKeyOracleAsync(
            bindAuth.AsReadOnlyMemory(), startNonceTpm.AsReadOnlyMemory(), startNonceCaller.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(0x02000000u),
            bindAuth.AsReadOnlyMemory(),
            startNonceCaller.AsReadOnlyMemory(),
            Tpm2bNonce.Create(startNonceTpm.AsReadOnlySpan(), pool),
            SessionAlg, TestEntropy.NewCounterStream(),
            pool,
            symmetric: TpmtSymDef.Xor(SessionAlg),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
        session.SetAuthValue(EntityAuthValue, pool);

        using IMemoryOwner<byte> foldedKeyOwner = pool.Rent(sessionKey.AsReadOnlyMemory().Length + entityAuth.AsReadOnlyMemory().Length);
        ReadOnlyMemory<byte> foldedKey = Concatenate(sessionKey.AsReadOnlyMemory(), entityAuth.AsReadOnlyMemory(), foldedKeyOwner);

        await AssertBothKeysAsync(session, foldedKey, pool, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// An unbound, unsalted session has an Empty Buffer for its session key (TPM 2.0 Library Part 1, clause
    /// 16.6.9), so both keys reduce to the entity's authValue alone: the command HMAC by equation 21 with an
    /// empty first term, and the parameter encryption by clause 18.1's <c>sessionKey || authValue</c> with the
    /// same. Clause 18.1's own caution applies to this shape — the cipher's entropy is then entirely the
    /// authValue's.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The canned nonceTPM ownership transfers to the TpmSession, disposed by the using statement.")]
    public async Task UnboundSessionKeysBothTheHmacAndTheCipherOnTheAuthValue()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;

        using Tpm2bNonce startNonceTpm = MakeNonce(0xC3, pool);
        using Tpm2bAuth entityAuth = Tpm2bAuth.Create(EntityAuthValue, pool);

        using var session = new TpmSession(
            new TpmHandle(0x02000000u),
            Tpm2bNonce.Create(startNonceTpm.AsReadOnlySpan(), pool),
            SessionAlg, TestEntropy.NewCounterStream(),
            pool,
            TpmtSymDef.Xor(SessionAlg));

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
        session.SetAuthValue(EntityAuthValue, pool);

        await AssertBothKeysAsync(session, entityAuth.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// All five attest commands carry <c>qualifyingData</c> (<c>TPM2B_DATA</c>) as the first entry of their
    /// parameter area — TPM 2.0 Library Part 3, Tables 89, 91, 93, 99 and 254 — which is exactly the shape Part 1
    /// clause 18.1 and clause 15.4 make eligible for the <c>decrypt</c> attribute, so each input declares it.
    /// </summary>
    [TestMethod]
    public void AttestCommandInputsDeclareTheirFirstCommandParameterEncryptable()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;

        TpmiDhObject signHandle = TpmiDhObject.FromValue(0x80000000u);
        TpmiDhObject objectHandle = TpmiDhObject.FromValue(0x80000001u);

        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(TpmAlgIdConstants.TPM_ALG_SHA256, [0, 7], pool);
        using QuoteInput quote = QuoteInput.ForEcdsa(signHandle, QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
        using CertifyInput certify = CertifyInput.ForEcdsa(objectHandle, signHandle, QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        using CertifyCreationInput certifyCreation = CertifyCreationInput.ForEcdsa(
            signHandle, objectHandle, QualifyingData, QualifyingData, TpmtTkCreation.Null, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        using GetTimeInput getTime = GetTimeInput.ForEcdsa(signHandle, QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        using NvCertifyInput nvCertify = NvCertifyInput.ForEcdsa(
            signHandle, (uint)TpmRh.TPM_RH_OWNER, 0x01000000u, QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, size: 8, offset: 0, pool);

        Assert.IsTrue(quote.FirstCommandParameterIsEncryptable, "TPM2_Quote's first parameter is qualifyingData (TPM 2.0 Library Part 3, Table 101).");
        Assert.IsTrue(certify.FirstCommandParameterIsEncryptable, "TPM2_Certify's first parameter is qualifyingData (TPM 2.0 Library Part 3, Table 97).");
        Assert.IsTrue(certifyCreation.FirstCommandParameterIsEncryptable, "TPM2_CertifyCreation's first parameter is qualifyingData (TPM 2.0 Library Part 3, Table 99).");
        Assert.IsTrue(getTime.FirstCommandParameterIsEncryptable, "TPM2_GetTime's first parameter is qualifyingData (TPM 2.0 Library Part 3, Table 107).");
        Assert.IsTrue(nvCertify.FirstCommandParameterIsEncryptable, "TPM2_NV_Certify's first parameter is qualifyingData (TPM 2.0 Library Part 3, Table 271).");
    }

    /// <summary>
    /// All five attest commands return a <c>TPM2B_ATTEST</c> as the first entry of their response parameter area
    /// — TPM 2.0 Library Part 3, Tables 98, 100, 102, 108 and 272 — which is the shape Part 1 clause 18.1 and
    /// clause 15.4 make eligible for the <c>encrypt</c> attribute, so each codec declares it.
    /// </summary>
    [TestMethod]
    public void AttestResponseCodecsDeclareTheirFirstResponseParameterEncryptable()
    {
        Assert.IsTrue(TpmResponseCodec.Quote.ResponseFirstParameterIsEncryptable, "TPM2_Quote returns quoted (TPM2B_ATTEST) first (TPM 2.0 Library Part 3, Table 102).");
        Assert.IsTrue(TpmResponseCodec.Certify.ResponseFirstParameterIsEncryptable, "TPM2_Certify returns certifyInfo (TPM2B_ATTEST) first (TPM 2.0 Library Part 3, Table 98).");
        Assert.IsTrue(TpmResponseCodec.CertifyCreation.ResponseFirstParameterIsEncryptable, "TPM2_CertifyCreation returns certifyInfo (TPM2B_ATTEST) first (TPM 2.0 Library Part 3, Table 100).");
        Assert.IsTrue(TpmResponseCodec.GetTime.ResponseFirstParameterIsEncryptable, "TPM2_GetTime returns timeInfo (TPM2B_ATTEST) first (TPM 2.0 Library Part 3, Table 108).");
        Assert.IsTrue(TpmResponseCodec.NvCertify.ResponseFirstParameterIsEncryptable, "TPM2_NV_Certify returns certifyInfo (TPM2B_ATTEST) first (TPM 2.0 Library Part 3, Table 272).");
    }

    /// <summary>
    /// A decrypt-attributed session on <c>TPM2_Quote()</c> reaches the device instead of being refused by the
    /// executor's admissibility gate, and what reaches it is ciphertext: the qualifying data on the wire is not
    /// the plaintext the caller supplied, and it recovers to that plaintext under
    /// <c>sessionKey || authValue</c> with the command direction's nonce order — nonceNewer = nonceCaller,
    /// nonceOlder = nonceTPM (TPM 2.0 Library Part 1, clause 18.2). Only the data portion is transformed; the
    /// TPM2B size field is untouched (clause 18.1), which is what lets the recovered length match.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The canned nonceTPM ownership transfers to the bound TpmSession, disposed by the using statement; the captured command buffer is disposed in the finally.")]
    public async Task DecryptAttributedSessionOnQuoteEncryptsTheQualifyingDataOnTheWire()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_Quote, TpmResponseCodec.Quote);

        using Tpm2bNonce startNonceCaller = MakeNonce(0x5A, pool);
        using Tpm2bNonce startNonceTpm = MakeNonce(0xC3, pool);
        using Tpm2bAuth bindAuth = Tpm2bAuth.Create(BindAuthValue, pool);
        using Tpm2bAuth entityAuth = Tpm2bAuth.Create(EntityAuthValue, pool);
        using Tpm2bAuth sessionKey = await DeriveBoundSessionKeyOracleAsync(
            bindAuth.AsReadOnlyMemory(), startNonceTpm.AsReadOnlyMemory(), startNonceCaller.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        //capturedOwner is declared null and assigned once inside the Handler local function below; a using
        //declaration cannot target a variable assigned after its declaration (CS1656).
        IMemoryOwner<byte>? capturedOwner = null;
        int capturedLength = 0;

        ValueTask<TpmResult<TpmResponse>> Handler(ReadOnlyMemory<byte> command, BaseMemoryPool handlerPool, CancellationToken cancellationToken)
        {
            capturedOwner = handlerPool.Rent(command.Length);
            command.CopyTo(capturedOwner.Memory);
            capturedLength = command.Length;

            return ValueTask.FromResult(ErrorResponse(TpmRcConstants.TPM_RC_FAILURE, handlerPool));
        }

        try
        {
            using var device = TpmDevice.Create(Handler, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

            using TpmSession session = await TpmSession.CreateBoundAsync(
                new TpmHandle(0x02000000u),
                bindAuth.AsReadOnlyMemory(),
                startNonceCaller.AsReadOnlyMemory(),
                Tpm2bNonce.Create(startNonceTpm.AsReadOnlySpan(), pool),
                SessionAlg, TestEntropy.NewCounterStream(),
                pool,
                symmetric: TpmtSymDef.Xor(SessionAlg),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
            session.SetAuthValue(EntityAuthValue, pool);

            using IMemoryOwner<byte> signerNameOwner = pool.Rent(DigestLength + sizeof(ushort));
            Memory<byte> signerName = signerNameOwner.Memory[..(DigestLength + sizeof(ushort))];
            FillPattern(signerName.Span, 0x21);
            ReadOnlyMemory<byte>[] handleNames = [signerName];

            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(TpmAlgIdConstants.TPM_ALG_SHA256, [0, 7], pool);
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(
                TpmiDhObject.FromValue(0x80000000u), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

            TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                device, quoteInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_FAILURE, result.ResponseCode,
                "A decrypt-attributed session on TPM2_Quote must reach the device and surface its answer, not be refused by the executor's admissibility gate.");

            Assert.IsNotNull(capturedOwner, "The device must have been invoked.");
            ReadOnlyMemory<byte> command = capturedOwner.Memory[..capturedLength];
            ReadOnlyMemory<byte> nonceCaller = ReadCommandNonceCaller(command, handleAreaSize: sizeof(uint));
            ReadOnlyMemory<byte> wireQualifyingData = ReadCommandFirstParameter(command, handleAreaSize: sizeof(uint));

            int plaintextOctets = QualifyingData.Length;
            int wireOctets = wireQualifyingData.Length;
            Assert.AreEqual(
                plaintextOctets, wireOctets,
                "Neither XOR obfuscation nor CFB pads, so the encrypted parameter has the plaintext's length (TPM 2.0 Library Part 1, clause 18.1).");
            Assert.IsFalse(
                wireQualifyingData.Span.SequenceEqual(QualifyingData),
                "The qualifying data must not appear on the wire in the clear when a session carries the decrypt attribute.");

            using IMemoryOwner<byte> cipherKeyOwner = pool.Rent(sessionKey.AsReadOnlyMemory().Length + entityAuth.AsReadOnlyMemory().Length);
            ReadOnlyMemory<byte> cipherKey = Concatenate(sessionKey.AsReadOnlyMemory(), entityAuth.AsReadOnlyMemory(), cipherKeyOwner);

            using IMemoryOwner<byte> recoveredOwner = pool.Rent(wireQualifyingData.Length);
            Memory<byte> recovered = recoveredOwner.Memory[..wireQualifyingData.Length];
            wireQualifyingData.CopyTo(recovered);
            await ObfuscateOracleAsync(
                cipherKey, nonceCaller, session.NonceTpm, recovered, pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(
                recovered.Span.SequenceEqual(QualifyingData),
                "The wire bytes must recover to the caller's qualifying data under sessionKey || authValue with nonceNewer = nonceCaller and nonceOlder = nonceTPM (TPM 2.0 Library Part 1, clause 18.2).");
        }
        finally
        {
            capturedOwner?.Dispose();
        }
    }

    /// <summary>
    /// Asserts that <paramref name="session"/> derives BOTH its command HMAC and its parameter-encryption key
    /// from <paramref name="expectedKey"/>, and that neither reduces to the session key alone.
    /// </summary>
    /// <param name="session">The session under test, already carrying its attributes and authorization value.</param>
    /// <param name="expectedKey">The <c>sessionValue</c> the oracle expects both keys to be.</param>
    /// <param name="pool">The memory pool for the oracle buffers.</param>
    /// <param name="cancellationToken">A token observed across the oracle's HMAC and KDF calls.</param>
    private static async ValueTask AssertBothKeysAsync(
        TpmSession session,
        ReadOnlyMemory<byte> expectedKey,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        using Tpm2bAuth cpHash = MakeCpHash(0x31, pool);
        using Tpm2bAuth commandHmac = await PrepareAuthHmacAsync(session, cpHash, pool, cancellationToken).ConfigureAwait(false);

        int authCommandSize = session.GetAuthCommandSize();
        using IMemoryOwner<byte> authCommandOwner = pool.Rent(authCommandSize);
        Memory<byte> authCommand = authCommandOwner.Memory[..authCommandSize];
        WriteAuthCommandArea(session, commandHmac, authCommand);
        ReadOnlyMemory<byte> nonceCaller = ReadAuthCommandNonceCaller(authCommand);
        ReadOnlyMemory<byte> nonceTpm = session.NonceTpm;

        using IMemoryOwner<byte> expectedHmacOwner = pool.Rent(DigestLength);
        Memory<byte> expectedHmac = expectedHmacOwner.Memory[..DigestLength];
        await ComputeExpectedAuthHmacAsync(
            expectedKey, cpHash.AsReadOnlyMemory(), nonceCaller, nonceTpm,
            (byte)session.SessionAttributes, expectedHmac, pool, cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            commandHmac.AsReadOnlySpan().SequenceEqual(expectedHmac.Span),
            "The command HMAC must be keyed on sessionKey || authValue (TPM 2.0 Library Part 1, clause 16.6.10, equation 21).");

        using IMemoryOwner<byte> underTestOwner = pool.Rent(QualifyingData.Length);
        Memory<byte> underTest = underTestOwner.Memory[..QualifyingData.Length];
        QualifyingData.CopyTo(underTest.Span);
        await session.EncryptFirstParameterAsync(underTest, pool, cancellationToken).ConfigureAwait(false);

        using IMemoryOwner<byte> expectedCipherOwner = pool.Rent(QualifyingData.Length);
        Memory<byte> expectedCipher = expectedCipherOwner.Memory[..QualifyingData.Length];
        QualifyingData.CopyTo(expectedCipher.Span);
        await ObfuscateOracleAsync(expectedKey, nonceCaller, nonceTpm, expectedCipher, pool, cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            underTest.Span.SequenceEqual(expectedCipher.Span),
            "Parameter encryption must be keyed on sessionKey || authValue (TPM 2.0 Library Part 1, clause 18.1).");
    }

    /// <summary>
    /// Runs <see cref="TpmSession.PrepareAuthHmacAsync"/> and unwraps its nullable result, which only a password
    /// session ever leaves null.
    /// </summary>
    /// <param name="session">The session computing the HMAC.</param>
    /// <param name="cpHash">The command-parameter hash the HMAC covers.</param>
    /// <param name="pool">The memory pool for the HMAC buffers.</param>
    /// <param name="cancellationToken">A token observed across the HMAC.</param>
    /// <returns>The computed command HMAC; the caller disposes it.</returns>
    private static async ValueTask<Tpm2bAuth> PrepareAuthHmacAsync(
        TpmSession session,
        Tpm2bAuth cpHash,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        Tpm2bAuth? prepared = await session.PrepareAuthHmacAsync(cpHash.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        Assert.IsNotNull(prepared, "An HMAC session always precomputes a command HMAC.");

        return prepared;
    }

    /// <summary>
    /// Serializes the session's <c>TPMS_AUTH_COMMAND</c> into <paramref name="destination"/>, which is how the
    /// caller nonce the session generated internally becomes observable to the oracle.
    /// </summary>
    /// <param name="session">The session writing its authorization entry.</param>
    /// <param name="commandHmac">The precomputed command HMAC the entry carries.</param>
    /// <param name="destination">A buffer of exactly <see cref="TpmSession.GetAuthCommandSize"/> octets.</param>
    private static void WriteAuthCommandArea(TpmSession session, Tpm2bAuth commandHmac, Memory<byte> destination)
    {
        var writer = new TpmWriter(destination.Span);
        session.WriteAuthCommand(ref writer, commandHmac);
    }

    /// <summary>
    /// Reads <c>nonceCaller</c> out of a serialized <c>TPMS_AUTH_COMMAND</c> (TPM 2.0 Library Part 1, Table 22:
    /// sessionHandle, nonceCaller, sessionAttributes, hmac).
    /// </summary>
    /// <param name="authCommand">The serialized authorization entry.</param>
    /// <returns>The caller nonce, aliasing <paramref name="authCommand"/>.</returns>
    private static ReadOnlyMemory<byte> ReadAuthCommandNonceCaller(ReadOnlyMemory<byte> authCommand)
    {
        var reader = new TpmReader(authCommand.Span);
        _ = reader.ReadUInt32();
        TpmBlob nonce = reader.ReadTpm2bBlob();

        return authCommand.Slice(nonce.Offset, nonce.Length);
    }

    /// <summary>
    /// Reads the single session's <c>nonceCaller</c> out of a serialized command.
    /// </summary>
    /// <param name="command">The whole command frame.</param>
    /// <param name="handleAreaSize">The command's handle-area width in octets.</param>
    /// <returns>The caller nonce, aliasing <paramref name="command"/>.</returns>
    private static ReadOnlyMemory<byte> ReadCommandNonceCaller(ReadOnlyMemory<byte> command, int handleAreaSize)
    {
        var reader = new TpmReader(command.Span);
        reader.Skip(HeaderSize + handleAreaSize);
        _ = reader.ReadUInt32();
        _ = reader.ReadUInt32();
        TpmBlob nonce = reader.ReadTpm2bBlob();

        return command.Slice(nonce.Offset, nonce.Length);
    }

    /// <summary>
    /// Reads the data portion of the first command parameter out of a serialized command, skipping the whole
    /// authorization area (TPM 2.0 Library Part 1, clause 15.6: authorizationSize precedes it).
    /// </summary>
    /// <param name="command">The whole command frame.</param>
    /// <param name="handleAreaSize">The command's handle-area width in octets.</param>
    /// <returns>The first parameter's data, aliasing <paramref name="command"/>.</returns>
    private static ReadOnlyMemory<byte> ReadCommandFirstParameter(ReadOnlyMemory<byte> command, int handleAreaSize)
    {
        var reader = new TpmReader(command.Span);
        reader.Skip(HeaderSize + handleAreaSize);
        uint authorizationSize = reader.ReadUInt32();
        reader.Skip((int)authorizationSize);
        TpmBlob firstParameter = reader.ReadTpm2bBlob();

        return command.Slice(firstParameter.Offset, firstParameter.Length);
    }

    /// <summary>
    /// Derives the bound session key by hand: <c>KDFa(SHA-256, bindAuthValue, "ATH", nonceTPM, nonceCaller,
    /// 256)</c> (TPM 2.0 Library Part 1, clause 16.6.10, equation 20).
    /// </summary>
    /// <param name="bindAuth">The bind entity's authorization value.</param>
    /// <param name="startNonceTpm">The TPM nonce from the StartAuthSession response.</param>
    /// <param name="startNonceCaller">The caller nonce sent in the StartAuthSession command.</param>
    /// <param name="pool">The memory pool for the derivation buffers.</param>
    /// <param name="cancellationToken">A token observed across the derivation.</param>
    /// <returns>The session key; the caller disposes it, which zeroes the key on release.</returns>
    private static async ValueTask<Tpm2bAuth> DeriveBoundSessionKeyOracleAsync(
        ReadOnlyMemory<byte> bindAuth,
        ReadOnlyMemory<byte> startNonceTpm,
        ReadOnlyMemory<byte> startNonceCaller,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> derived = await Kdfa.DeriveAsync(
            HashAlgorithmName.SHA256, bindAuth, "ATH", startNonceTpm, startNonceCaller, DigestLength * 8, pool, cancellationToken).ConfigureAwait(false);

        try
        {
            return Tpm2bAuth.Create(derived.Memory.Span[..DigestLength], pool);
        }
        finally
        {
            derived.Memory.Span[..DigestLength].Clear();
        }
    }

    /// <summary>
    /// Computes the command authorization HMAC by hand: <c>HMAC_sessionAlg(key, cpHash || nonceCaller ||
    /// nonceTPM || sessionAttributes)</c> (TPM 2.0 Library Part 1, clause 16.6.5, equation 17 with the command
    /// direction's nonce order).
    /// </summary>
    /// <param name="key">The <c>sessionValue</c> keying the HMAC.</param>
    /// <param name="cpHash">The command-parameter hash.</param>
    /// <param name="nonceCaller">nonceNewer for a command.</param>
    /// <param name="nonceTpm">nonceOlder for a command.</param>
    /// <param name="sessionAttributes">The TPMA_SESSION octet the entry carries.</param>
    /// <param name="destination">A buffer of exactly <see cref="DigestLength"/> octets.</param>
    /// <param name="pool">The memory pool for the data buffer.</param>
    /// <param name="cancellationToken">A token observed across the HMAC.</param>
    private static async ValueTask ComputeExpectedAuthHmacAsync(
        ReadOnlyMemory<byte> key,
        ReadOnlyMemory<byte> cpHash,
        ReadOnlyMemory<byte> nonceCaller,
        ReadOnlyMemory<byte> nonceTpm,
        byte sessionAttributes,
        Memory<byte> destination,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        int dataLength = cpHash.Length + nonceCaller.Length + nonceTpm.Length + sizeof(byte);
        using IMemoryOwner<byte> dataOwner = pool.Rent(dataLength);
        {
            var writer = new TpmWriter(dataOwner.Memory.Span[..dataLength]);
            writer.WriteBytes(cpHash.Span);
            writer.WriteBytes(nonceCaller.Span);
            writer.WriteBytes(nonceTpm.Span);
            writer.WriteByte(sessionAttributes);
        }

        using HmacValue hmac = await CryptographicKeyEvents.ComputeHmacAsync(
            dataOwner.Memory[..dataLength], key, outputByteLength: DigestLength, tag: HmacTag(), pool: pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        hmac.AsReadOnlySpan().CopyTo(destination.Span);
    }

    /// <summary>
    /// Applies XOR obfuscation by hand over a copy of <paramref name="source"/> (TPM 2.0 Library Part 1, clause
    /// 19.2). The transform is self-inverse, so one routine serves both directions; the direction lives entirely
    /// in which nonce the caller passes as <paramref name="nonceNewer"/>.
    /// </summary>
    /// <param name="key">The <c>sessionValue</c> keying the mask.</param>
    /// <param name="nonceNewer">The KDFa <c>contextU</c>.</param>
    /// <param name="nonceOlder">The KDFa <c>contextV</c>.</param>
    /// <param name="data">The data to transform in place.</param>
    /// <param name="pool">The memory pool for the mask.</param>
    /// <param name="cancellationToken">A token observed across the KDF.</param>
    private static async ValueTask ObfuscateOracleAsync(
        ReadOnlyMemory<byte> key,
        ReadOnlyMemory<byte> nonceNewer,
        ReadOnlyMemory<byte> nonceOlder,
        Memory<byte> data,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        await TpmParameterEncryption.XorAsync(
            HashAlgorithmName.SHA256, key, nonceNewer, nonceOlder, data, pool, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Concatenates two terms into <paramref name="owner"/>'s buffer, which is how <c>sessionKey || authValue</c>
    /// is assembled for the oracle.
    /// </summary>
    /// <param name="first">The leading term.</param>
    /// <param name="second">The trailing term.</param>
    /// <param name="owner">A carrier of at least the combined length.</param>
    /// <returns>The concatenation, aliasing <paramref name="owner"/>.</returns>
    private static ReadOnlyMemory<byte> Concatenate(ReadOnlyMemory<byte> first, ReadOnlyMemory<byte> second, IMemoryOwner<byte> owner)
    {
        int length = first.Length + second.Length;
        Memory<byte> buffer = owner.Memory[..length];
        first.CopyTo(buffer);
        second.CopyTo(buffer[first.Length..]);

        return buffer;
    }

    /// <summary>
    /// Builds a deterministic session nonce of the session hash's digest width.
    /// </summary>
    /// <param name="seed">The pattern seed distinguishing this nonce from the others.</param>
    /// <param name="pool">The memory pool for the nonce.</param>
    /// <returns>The nonce; the caller disposes it.</returns>
    private static Tpm2bNonce MakeNonce(byte seed, BaseMemoryPool pool)
    {
        Span<byte> nonce = stackalloc byte[DigestLength];
        FillPattern(nonce, seed);

        return Tpm2bNonce.Create(nonce, pool);
    }

    /// <summary>
    /// Builds a deterministic stand-in for a cpHash of the session hash's digest width. Its value is never
    /// interpreted: it is the pHash term both the session and the oracle hash over.
    /// </summary>
    /// <param name="seed">The pattern seed.</param>
    /// <param name="pool">The memory pool for the buffer.</param>
    /// <returns>The cpHash stand-in; the caller disposes it.</returns>
    private static Tpm2bAuth MakeCpHash(byte seed, BaseMemoryPool pool)
    {
        Span<byte> cpHash = stackalloc byte[DigestLength];
        FillPattern(cpHash, seed);

        return Tpm2bAuth.Create(cpHash, pool);
    }

    /// <summary>
    /// Fills <paramref name="destination"/> with a deterministic, seed-distinguished pattern.
    /// </summary>
    /// <param name="destination">The buffer to fill.</param>
    /// <param name="seed">The pattern seed.</param>
    private static void FillPattern(Span<byte> destination, byte seed)
    {
        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)(seed ^ i);
        }
    }

    /// <summary>
    /// Builds the HMAC <see cref="Tag"/> exactly as <c>TpmSession</c> does: SHA-256 HMAC, raw encoding, direct
    /// material.
    /// </summary>
    /// <returns>The tag.</returns>
    private static Tag HmacTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Hmac).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    /// <summary>
    /// Frames a header-only error response, the shortest well-formed answer a device can give.
    /// </summary>
    /// <param name="responseCode">The response code the frame carries.</param>
    /// <param name="pool">The memory pool for the frame.</param>
    /// <returns>The framed response, owned by the returned result and disposed by the executor under test.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The frame owner ownership transfers to the returned TpmResponse, disposed by the executor under test.")]
    private static TpmResult<TpmResponse> ErrorResponse(TpmRcConstants responseCode, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> frame = pool.Rent(HeaderSize);
        var writer = new TpmWriter(frame.Memory.Span[..HeaderSize]);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_NO_SESSIONS);
        writer.WriteUInt32((uint)HeaderSize);
        writer.WriteUInt32((uint)responseCode);

        return TpmResult<TpmResponse>.Success(new TpmResponse(frame, HeaderSize));
    }
}
