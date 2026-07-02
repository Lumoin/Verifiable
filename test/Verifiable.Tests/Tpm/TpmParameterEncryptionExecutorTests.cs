using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Deterministic, non-hardware end-to-end coverage of session-based parameter encryption through
/// <see cref="TpmCommandExecutor.ExecuteAsync"/>, driving a scripted <see cref="TpmDevice.Create"/> handler.
/// </summary>
/// <remarks>
/// <para>
/// The scripted handler is an independent oracle that derives the bound session key with the project's
/// <see cref="Kdfa"/>, computes the XOR/CFB parameter encryption with
/// <see cref="TpmParameterEncryption"/>, and computes the rpHash and response HMAC via
/// <see cref="CryptographicKeyEvents"/>, then produces a wire-faithful encrypted response. It routes through
/// the same registered crypto abstraction the library uses everywhere; what makes it an independent oracle is
/// that it drives that crypto by hand on the device side (its own nonce ordering, key assembly, and wire
/// framing) while the executor + <see cref="TpmSession"/> (the system under test) drive it through their own
/// code paths. A divergence in nonce ordering, the parameter-encryption key, the wire placement of the
/// encrypted data, or the verify-before-decrypt ordering fails the comparison.
/// </para>
/// <para>
/// Sessions here are bound with an empty authValue, so sessionValue reduces unambiguously to the session key
/// (Part 1 §19.1) regardless of the authValue-inclusion rule, and the oracle and the implementation must agree.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmParameterEncryptionExecutorTests
{
    private const int HeaderSize = 10;

    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The canned nonceTPM ownership transfers to the bound TpmSession, disposed by the using statement.")]
    public async Task EncryptedResponseFirstParameterDecryptsToKnownPlaintext()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;
        using Tpm2bAuth bindAuth = Tpm2bAuth.Create("det-bound-key"u8, pool);
        using Tpm2bNonce startNonceCaller = MakeNonce(32, 0x5A, pool);
        using Tpm2bNonce startNonceTpm = MakeNonce(32, 0xC3, pool);
        using Tpm2bAuth sessionKey = await DeriveBoundSessionKeyOracleAsync(
            bindAuth.AsReadOnlyMemory(), startNonceTpm.AsReadOnlyMemory(), startNonceCaller.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        //The known plaintext the scripted TPM "returns" as randomBytes, before encryption.
        const int PlaintextLength = 32;
        using IMemoryOwner<byte> plaintext = pool.Rent(PlaintextLength);
        FillPattern(plaintext.Memory.Span[..PlaintextLength], 0x11);
        using Tpm2bNonce nonceTpmNew = MakeNonce(32, 0x7E, pool);
        const byte ResponseAttributes = (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT);

        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> handlerPool,
            CancellationToken cancellationToken)
        {
            ReadOnlyMemory<byte> nonceCaller = ExtractCommandNonceCaller(command);

            return BuildEncryptedGetRandomResponseAsync(
                sessionKey.AsReadOnlyMemory(), nonceCaller, nonceTpmNew.AsReadOnlyMemory(), plaintext.Memory[..PlaintextLength], ResponseAttributes, handlerPool, cancellationToken);
        }

        using var device = TpmDevice.Create(Handler);

        using TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(0x02000000u),
            bindAuth.AsReadOnlyMemory(),
            startNonceCaller.AsReadOnlyMemory(),
            Tpm2bNonce.Create(startNonceTpm.AsReadOnlySpan(), pool),
            SessionAlg,
            pool,
            symmetric: TpmtSymDef.Xor(SessionAlg),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

        var input = new GetRandomInput((ushort)PlaintextLength);
        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Encrypted GetRandom must verify and decrypt: '{result.ResponseCode}'.");

        using GetRandomResponse response = result.Value;
        Assert.IsTrue(response.RandomBytes.AsReadOnlySpan().SequenceEqual(plaintext.Memory.Span[..PlaintextLength]),
            "The decrypted first response parameter must equal the plaintext the scripted TPM encrypted.");
    }

    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The canned nonceTPM ownership transfers to the bound TpmSession, disposed by the using statement.")]
    public async Task ResponseDecryptionFailsClosedWhenSessionKeyDiverges()
    {
        //A wrong session key must surface as an HMAC failure (TPM_RC_AUTH_FAIL), never as silently mis-decrypted
        //plaintext: the response HMAC and the XOR mask key off the same session key.
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;
        using Tpm2bAuth bindAuth = Tpm2bAuth.Create("det-bound-key"u8, pool);
        using Tpm2bNonce startNonceCaller = MakeNonce(32, 0x5A, pool);
        using Tpm2bNonce startNonceTpm = MakeNonce(32, 0xC3, pool);

        Span<byte> wrongKeyMaterial = stackalloc byte[32];
        FillPattern(wrongKeyMaterial, 0x99);
        using Tpm2bAuth wrongKey = Tpm2bAuth.Create(wrongKeyMaterial, pool);

        const int PlaintextLength = 16;
        using IMemoryOwner<byte> plaintext = pool.Rent(PlaintextLength);
        FillPattern(plaintext.Memory.Span[..PlaintextLength], 0x22);
        using Tpm2bNonce nonceTpmNew = MakeNonce(32, 0x7E, pool);
        const byte ResponseAttributes = (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT);

        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> handlerPool,
            CancellationToken cancellationToken)
        {
            ReadOnlyMemory<byte> nonceCaller = ExtractCommandNonceCaller(command);

            return BuildEncryptedGetRandomResponseAsync(
                wrongKey.AsReadOnlyMemory(), nonceCaller, nonceTpmNew.AsReadOnlyMemory(), plaintext.Memory[..PlaintextLength], ResponseAttributes, handlerPool, cancellationToken);
        }

        using var device = TpmDevice.Create(Handler);

        using TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(0x02000000u),
            bindAuth.AsReadOnlyMemory(),
            startNonceCaller.AsReadOnlyMemory(),
            Tpm2bNonce.Create(startNonceTpm.AsReadOnlySpan(), pool),
            SessionAlg,
            pool,
            symmetric: TpmtSymDef.Xor(SessionAlg),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

        var input = new GetRandomInput((ushort)PlaintextLength);
        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTpmError);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, result.ResponseCode,
            "A diverged session key must fail the response HMAC before any decrypted bytes are interpreted.");
    }

    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The TpmResponse ownership transfers to the returned TpmResult and is disposed by the executor under test.")]
    public async Task FirstCommandParameterIsEncryptedOnTheWire()
    {
        //The executor must encrypt the data portion of the first command parameter (decrypt attribute) before
        //sending. A scripted device captures the command and returns an error so execution stops after the send;
        //the test recovers the encrypted data with the independent oracle and asserts it matches the plaintext.
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;
        using Tpm2bAuth bindAuth = Tpm2bAuth.Create("det-bound-key"u8, pool);
        using Tpm2bNonce startNonceCaller = MakeNonce(32, 0x5A, pool);
        using Tpm2bNonce startNonceTpm = MakeNonce(32, 0xC3, pool);
        using Tpm2bAuth sessionKey = await DeriveBoundSessionKeyOracleAsync(
            bindAuth.AsReadOnlyMemory(), startNonceTpm.AsReadOnlyMemory(), startNonceCaller.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        const int PlaintextLength = 24;
        using IMemoryOwner<byte> plaintext = pool.Rent(PlaintextLength);
        FillPattern(plaintext.Memory.Span[..PlaintextLength], 0x44);

        IMemoryOwner<byte>? observed = null;
        int observedLength = 0;

        try
        {
            ValueTask<TpmResult<TpmResponse>> Handler(
                ReadOnlyMemory<byte> command,
                MemoryPool<byte> handlerPool,
                CancellationToken cancellationToken)
            {
                //The borrowed command memory is not valid after the handler returns, so take a pooled copy.
                IMemoryOwner<byte> copy = handlerPool.Rent(command.Length);
                command.Span.CopyTo(copy.Memory.Span);
                observed = copy;
                observedLength = command.Length;

                return ValueTask.FromResult(ErrorResponse(TpmRcConstants.TPM_RC_VALUE, handlerPool));
            }

            using var device = TpmDevice.Create(Handler);

            using TpmSession session = await TpmSession.CreateBoundAsync(
                new TpmHandle(0x02000000u),
                bindAuth.AsReadOnlyMemory(),
                startNonceCaller.AsReadOnlyMemory(),
                Tpm2bNonce.Create(startNonceTpm.AsReadOnlySpan(), pool),
                SessionAlg,
                pool,
                symmetric: TpmtSymDef.Xor(SessionAlg),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            using var input = new EncryptableProbeInput(plaintext.Memory.Span[..PlaintextLength], pool);
            TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsTpmError, "The scripted error must surface so execution stops after the command is captured.");
            Assert.IsNotNull(observed);

            ReadOnlyMemory<byte> observedCommand = observed.Memory[..observedLength];
            ReadOnlyMemory<byte> nonceCaller = ExtractCommandNonceCaller(observedCommand);
            ReadOnlyMemory<byte> encryptedFirstParam = ExtractCommandFirstParameterData(observedCommand);

            Assert.AreEqual(PlaintextLength, encryptedFirstParam.Length, "Parameter encryption must not change the data length.");
            Assert.IsFalse(encryptedFirstParam.Span.SequenceEqual(plaintext.Memory.Span[..PlaintextLength]), "The first command parameter must be encrypted on the wire.");

            //Command direction (Part 1 §19.2): nonceNewer = nonceCaller, nonceOlder = nonceTPM (the session's
            //current nonceTPM, which for the first command is the StartAuthSession nonceTPM). XOR is self-inverse,
            //so the same call recovers the plaintext in place.
            using IMemoryOwner<byte> recovered = pool.Rent(PlaintextLength);
            encryptedFirstParam.Span.CopyTo(recovered.Memory.Span);
            await TpmParameterEncryption.XorAsync(
                HashAlgorithmName.SHA256, sessionKey.AsReadOnlyMemory(), nonceCaller, startNonceTpm.AsReadOnlyMemory(), recovered.Memory[..PlaintextLength], pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(recovered.Memory.Span[..PlaintextLength].SequenceEqual(plaintext.Memory.Span[..PlaintextLength]),
                "Decrypting the captured first parameter with the independent oracle must recover the plaintext.");
        }
        finally
        {
            observed?.Dispose();
        }
    }

    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The canned nonceTPM ownership transfers to the bound TpmSession, disposed by the using statement.")]
    public async Task EncryptedResponseCfbDecryptsToKnownPlaintext()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;
        const int KeyBits = 128;
        using Tpm2bAuth bindAuth = Tpm2bAuth.Create("det-bound-key"u8, pool);
        using Tpm2bNonce startNonceCaller = MakeNonce(32, 0x5A, pool);
        using Tpm2bNonce startNonceTpm = MakeNonce(32, 0xC3, pool);
        using Tpm2bAuth sessionKey = await DeriveBoundSessionKeyOracleAsync(
            bindAuth.AsReadOnlyMemory(), startNonceTpm.AsReadOnlyMemory(), startNonceCaller.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        //Block-multiple plaintext so the independent oracle CFB needs no partial-block handling.
        const int PlaintextLength = 32;
        using IMemoryOwner<byte> plaintext = pool.Rent(PlaintextLength);
        FillPattern(plaintext.Memory.Span[..PlaintextLength], 0x11);
        using Tpm2bNonce nonceTpmNew = MakeNonce(32, 0x7E, pool);
        const byte ResponseAttributes = (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT);

        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> handlerPool,
            CancellationToken cancellationToken)
        {
            ReadOnlyMemory<byte> nonceCaller = ExtractCommandNonceCaller(command);

            return BuildCfbEncryptedGetRandomResponseAsync(
                sessionKey.AsReadOnlyMemory(), nonceCaller, nonceTpmNew.AsReadOnlyMemory(), plaintext.Memory[..PlaintextLength], ResponseAttributes, KeyBits, handlerPool, cancellationToken);
        }

        using var device = TpmDevice.Create(Handler);

        using TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(0x02000000u),
            bindAuth.AsReadOnlyMemory(),
            startNonceCaller.AsReadOnlyMemory(),
            Tpm2bNonce.Create(startNonceTpm.AsReadOnlySpan(), pool),
            SessionAlg,
            pool,
            symmetric: TpmtSymDef.Aes(KeyBits, TpmAlgIdConstants.TPM_ALG_CFB),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

        var input = new GetRandomInput((ushort)PlaintextLength);
        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Encrypted (CFB) GetRandom must verify and decrypt: '{result.ResponseCode}'.");

        using GetRandomResponse response = result.Value;
        Assert.IsTrue(response.RandomBytes.AsReadOnlySpan().SequenceEqual(plaintext.Memory.Span[..PlaintextLength]),
            "The AES-CFB-decrypted first response parameter must equal the plaintext the scripted TPM encrypted.");
    }

    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The TpmResponse ownership transfers to the returned TpmResult and is disposed by the executor under test.")]
    public async Task FirstCommandParameterIsCfbEncryptedOnTheWire()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;
        const int KeyBits = 128;
        using Tpm2bAuth bindAuth = Tpm2bAuth.Create("det-bound-key"u8, pool);
        using Tpm2bNonce startNonceCaller = MakeNonce(32, 0x5A, pool);
        using Tpm2bNonce startNonceTpm = MakeNonce(32, 0xC3, pool);
        using Tpm2bAuth sessionKey = await DeriveBoundSessionKeyOracleAsync(
            bindAuth.AsReadOnlyMemory(), startNonceTpm.AsReadOnlyMemory(), startNonceCaller.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        const int PlaintextLength = 32; //Block-multiple.
        using IMemoryOwner<byte> plaintext = pool.Rent(PlaintextLength);
        FillPattern(plaintext.Memory.Span[..PlaintextLength], 0x44);

        IMemoryOwner<byte>? observed = null;
        int observedLength = 0;

        try
        {
            ValueTask<TpmResult<TpmResponse>> Handler(
                ReadOnlyMemory<byte> command,
                MemoryPool<byte> handlerPool,
                CancellationToken cancellationToken)
            {
                //The borrowed command memory is not valid after the handler returns, so take a pooled copy.
                IMemoryOwner<byte> copy = handlerPool.Rent(command.Length);
                command.Span.CopyTo(copy.Memory.Span);
                observed = copy;
                observedLength = command.Length;

                return ValueTask.FromResult(ErrorResponse(TpmRcConstants.TPM_RC_VALUE, handlerPool));
            }

            using var device = TpmDevice.Create(Handler);

            using TpmSession session = await TpmSession.CreateBoundAsync(
                new TpmHandle(0x02000000u),
                bindAuth.AsReadOnlyMemory(),
                startNonceCaller.AsReadOnlyMemory(),
                Tpm2bNonce.Create(startNonceTpm.AsReadOnlySpan(), pool),
                SessionAlg,
                pool,
                symmetric: TpmtSymDef.Aes(KeyBits, TpmAlgIdConstants.TPM_ALG_CFB),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            using var input = new EncryptableProbeInput(plaintext.Memory.Span[..PlaintextLength], pool);
            TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsTpmError);
            Assert.IsNotNull(observed);

            ReadOnlyMemory<byte> observedCommand = observed.Memory[..observedLength];
            ReadOnlyMemory<byte> nonceCaller = ExtractCommandNonceCaller(observedCommand);
            ReadOnlyMemory<byte> encryptedFirstParam = ExtractCommandFirstParameterData(observedCommand);

            Assert.AreEqual(PlaintextLength, encryptedFirstParam.Length, "Parameter encryption must not change the data length.");
            Assert.IsFalse(encryptedFirstParam.Span.SequenceEqual(plaintext.Memory.Span[..PlaintextLength]), "The first command parameter must be encrypted on the wire.");

            //Command direction (Part 1 §19.2): nonceNewer = nonceCaller, nonceOlder = nonceTPM (the session's
            //current nonceTPM, which for the first command is the StartAuthSession nonceTPM).
            using IMemoryOwner<byte> recovered = pool.Rent(PlaintextLength);
            encryptedFirstParam.Span.CopyTo(recovered.Memory.Span);
            await TpmParameterEncryption.CfbAsync(
                HashAlgorithmName.SHA256, KeyBits, sessionKey.AsReadOnlyMemory(), nonceCaller, startNonceTpm.AsReadOnlyMemory(), recovered.Memory[..PlaintextLength], encrypting: false, pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(recovered.Memory.Span[..PlaintextLength].SequenceEqual(plaintext.Memory.Span[..PlaintextLength]),
                "AES-CFB decrypting the captured first parameter with the independent oracle must recover the plaintext.");
        }
        finally
        {
            observed?.Dispose();
        }
    }

    [TestMethod]
    public async Task DecryptAttributeOnNonEncryptableCommandThrows()
    {
        await AssertExecuteThrowsAsync(
            TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT,
            TpmtSymDef.Xor(TpmAlgIdConstants.TPM_ALG_SHA256),
            useEncryptableInput: false).ConfigureAwait(false);
    }

    [TestMethod]
    public async Task DecryptAttributeWithNullSymmetricThrows()
    {
        //The session carries the decrypt attribute but negotiated no symmetric algorithm (TPM_ALG_NULL); even
        //on an encryptable command this is inadmissible (the TPM would return TPM_RC_SYMMETRIC).
        await AssertExecuteThrowsAsync(
            TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT,
            symmetric: null,
            useEncryptableInput: true).ConfigureAwait(false);
    }

    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The canned nonceTPM ownership transfers to the TpmSession, disposed by the using statement.")]
    public async Task EncryptAttributeOnNonEncryptableResponseThrows()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        ValueTask<TpmResult<TpmResponse>> Handler(ReadOnlyMemory<byte> command, MemoryPool<byte> handlerPool, CancellationToken cancellationToken)
        {
            Assert.Fail("The device must not be invoked when the encrypt attribute is inadmissible.");

            return ValueTask.FromResult(TpmResult<TpmResponse>.TransportError(0u));
        }

        using var device = TpmDevice.Create(Handler);

        using Tpm2bNonce startNonceTpm = MakeNonce(32, 0xC3, pool);
        Tpm2bNonce nonceTpm = Tpm2bNonce.Create(startNonceTpm.AsReadOnlySpan(), pool);
        using var session = new TpmSession(
            new TpmHandle(0x02000000u), nonceTpm, TpmAlgIdConstants.TPM_ALG_SHA256, pool, TpmtSymDef.Xor(TpmAlgIdConstants.TPM_ALG_SHA256));
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

        //FlushContext has no response parameters, so the encrypt attribute cannot apply.
        var input = FlushContextInput.ForHandle(0x80000000u);

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The canned nonceTPM ownership transfers to each TpmSession, disposed by the using statements.")]
    public async Task DuplicateDecryptAttributeThrows()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        ValueTask<TpmResult<TpmResponse>> Handler(ReadOnlyMemory<byte> command, MemoryPool<byte> handlerPool, CancellationToken cancellationToken)
        {
            Assert.Fail("The device must not be invoked when two sessions both set the decrypt attribute.");

            return ValueTask.FromResult(TpmResult<TpmResponse>.TransportError(0u));
        }

        using var device = TpmDevice.Create(Handler);

        using Tpm2bNonce startNonceTpm = MakeNonce(32, 0xC3, pool);
        TpmtSymDef xor = TpmtSymDef.Xor(TpmAlgIdConstants.TPM_ALG_SHA256);
        using var first = new TpmSession(
            new TpmHandle(0x02000000u), Tpm2bNonce.Create(startNonceTpm.AsReadOnlySpan(), pool), TpmAlgIdConstants.TPM_ALG_SHA256, pool, xor);
        using var second = new TpmSession(
            new TpmHandle(0x02000001u), Tpm2bNonce.Create(startNonceTpm.AsReadOnlySpan(), pool), TpmAlgIdConstants.TPM_ALG_SHA256, pool, xor);
        first.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
        second.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

        Span<byte> probe = stackalloc byte[8];
        FillPattern(probe, 0x55);
        using var input = new EncryptableProbeInput(probe, pool);

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, input, [first, second], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The canned nonceTPM ownership transfers to the TpmSession, disposed by the using statement.")]
    private async Task AssertExecuteThrowsAsync(TpmaSession attributes, TpmtSymDef? symmetric, bool useEncryptableInput)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        ValueTask<TpmResult<TpmResponse>> Handler(ReadOnlyMemory<byte> command, MemoryPool<byte> handlerPool, CancellationToken cancellationToken)
        {
            Assert.Fail("The device must not be invoked when parameter encryption is inadmissible.");

            return ValueTask.FromResult(TpmResult<TpmResponse>.TransportError(0u));
        }

        using var device = TpmDevice.Create(Handler);

        using Tpm2bNonce startNonceTpm = MakeNonce(32, 0xC3, pool);
        Tpm2bNonce nonceTpm = Tpm2bNonce.Create(startNonceTpm.AsReadOnlySpan(), pool);
        using var session = new TpmSession(
            new TpmHandle(0x02000000u), nonceTpm, TpmAlgIdConstants.TPM_ALG_SHA256, pool, symmetric);
        session.SessionAttributes = attributes;

        if(useEncryptableInput)
        {
            Span<byte> probe = stackalloc byte[8];
            FillPattern(probe, 0x66);
            using var encryptable = new EncryptableProbeInput(probe, pool);
            await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
                await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    device, encryptable, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }
        else
        {
            var plain = new GetRandomInput(8);
            await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
                await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    device, plain, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }
    }

    /// <summary>The SHA-256 session key length in octets.</summary>
    private const int SessionKeyLength = 32;

    /// <summary>
    /// Derives the bound session key with the project's KDFa: <c>KDFa(SHA-256, bindAuth, "ATH", nonceTPM,
    /// nonceCaller, 256)</c> (Part 1 §17.6.10), returning it in the same <see cref="Tpm2bAuth"/> semantic carrier
    /// the production session uses (<see cref="TpmSession.CreateBoundAsync"/> derives the identical key into the
    /// identical type). What makes this an independent oracle is that the KDF is driven by hand here, with the
    /// device-side nonce ordering. The caller disposes the returned value, which zeroes the key on release.
    /// </summary>
    private static async ValueTask<Tpm2bAuth> DeriveBoundSessionKeyOracleAsync(
        ReadOnlyMemory<byte> bindAuth,
        ReadOnlyMemory<byte> startNonceTpm,
        ReadOnlyMemory<byte> startNonceCaller,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> derived = await Kdfa.DeriveAsync(
            HashAlgorithmName.SHA256, bindAuth, "ATH", startNonceTpm, startNonceCaller, SessionKeyLength * 8, pool, cancellationToken).ConfigureAwait(false);

        try
        {
            return Tpm2bAuth.Create(derived.Memory.Span[..SessionKeyLength], pool);
        }
        finally
        {
            derived.Memory.Span[..SessionKeyLength].Clear();
        }
    }

    private static async ValueTask<TpmResult<TpmResponse>> BuildEncryptedGetRandomResponseAsync(
        ReadOnlyMemory<byte> sessionKey,
        ReadOnlyMemory<byte> nonceCaller,
        ReadOnlyMemory<byte> nonceTpmNew,
        ReadOnlyMemory<byte> plaintext,
        byte attributes,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        //Encrypt the first response parameter with XOR: response direction nonceNewer = nonceTPM, nonceOlder =
        //nonceCaller. XOR is self-inverse, so the same call encrypts the plaintext in place.
        using IMemoryOwner<byte> encrypted = pool.Rent(plaintext.Length);
        plaintext.Span.CopyTo(encrypted.Memory.Span);
        await TpmParameterEncryption.XorAsync(
            HashAlgorithmName.SHA256, sessionKey, nonceTpmNew, nonceCaller, encrypted.Memory[..plaintext.Length], pool, cancellationToken).ConfigureAwait(false);

        return await FrameEncryptedSessionResponseAsync(
            sessionKey, nonceCaller, nonceTpmNew, encrypted.Memory[..plaintext.Length], attributes, pool, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<TpmResponse>> BuildCfbEncryptedGetRandomResponseAsync(
        ReadOnlyMemory<byte> sessionKey,
        ReadOnlyMemory<byte> nonceCaller,
        ReadOnlyMemory<byte> nonceTpmNew,
        ReadOnlyMemory<byte> plaintext,
        byte attributes,
        int keyBits,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        //Encrypt the first response parameter with AES-CFB: response direction nonceNewer = nonceTPM, nonceOlder = nonceCaller.
        using IMemoryOwner<byte> encrypted = pool.Rent(plaintext.Length);
        plaintext.Span.CopyTo(encrypted.Memory.Span);
        await TpmParameterEncryption.CfbAsync(
            HashAlgorithmName.SHA256, keyBits, sessionKey, nonceTpmNew, nonceCaller, encrypted.Memory[..plaintext.Length], encrypting: true, pool, cancellationToken).ConfigureAwait(false);

        return await FrameEncryptedSessionResponseAsync(
            sessionKey, nonceCaller, nonceTpmNew, encrypted.Memory[..plaintext.Length], attributes, pool, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Frames a TPM_ST_SESSIONS GetRandom response carrying an already-encrypted first parameter, computing the
    /// rpHash (over the encrypted bytes) and the response HMAC exactly as the TPM would, via the project crypto.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The frame owner ownership transfers to the returned TpmResponse, disposed by the executor under test.")]
    private static async ValueTask<TpmResult<TpmResponse>> FrameEncryptedSessionResponseAsync(
        ReadOnlyMemory<byte> sessionKey,
        ReadOnlyMemory<byte> nonceCaller,
        ReadOnlyMemory<byte> nonceTpmNew,
        ReadOnlyMemory<byte> encrypted,
        byte attributes,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        int encryptedLength = encrypted.Length;

        //randomBytes parameter area: TPM2B size (the unencrypted size field) + encrypted data.
        int paramAreaLength = sizeof(ushort) + encryptedLength;

        //rpHash = H(responseCode || commandCode || encrypted parameter area).
        //The rpHash input is responseCode(BE32 0) || commandCode(BE32) || (uint16 encrypted.Length || encrypted).
        int rpHashInputLength = sizeof(uint) + sizeof(uint) + paramAreaLength;
        using IMemoryOwner<byte> rpHashInput = pool.Rent(rpHashInputLength);
        {
            var writer = new TpmWriter(rpHashInput.Memory.Span[..rpHashInputLength]);
            writer.WriteUInt32(0u);
            writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_GetRandom);
            writer.WriteUInt16((ushort)encryptedLength);
            writer.WriteBytes(encrypted.Span);
        }

        using DigestValue rpHashValue = await CryptographicKeyEvents.ComputeDigestAsync(
            rpHashInput.Memory[..rpHashInputLength], outputByteLength: SessionKeyLength, tag: DigestTag(), pool: pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        //Response HMAC = HMAC(sessionKey, rpHash || nonceTPM(new) || nonceCaller || sessionAttributes).
        int hmacInputLength = rpHashValue.AsReadOnlySpan().Length + nonceTpmNew.Length + nonceCaller.Length + 1;
        using IMemoryOwner<byte> hmacInput = pool.Rent(hmacInputLength);
        {
            var writer = new TpmWriter(hmacInput.Memory.Span[..hmacInputLength]);
            writer.WriteBytes(rpHashValue.AsReadOnlySpan());
            writer.WriteBytes(nonceTpmNew.Span);
            writer.WriteBytes(nonceCaller.Span);
            writer.WriteByte(attributes);
        }

        using HmacValue hmacValue = await CryptographicKeyEvents.ComputeHmacAsync(
            hmacInput.Memory[..hmacInputLength], sessionKey, outputByteLength: SessionKeyLength, tag: HmacTag(), pool: pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        //authArea = TPM2B(nonceTPM new) || sessionAttributes || TPM2B(hmac).
        int authAreaLength = (sizeof(ushort) + nonceTpmNew.Length) + 1 + (sizeof(ushort) + hmacValue.AsReadOnlySpan().Length);
        int bodySize = sizeof(uint) + paramAreaLength + authAreaLength; //parameterSize field + params + auth.
        int total = HeaderSize + bodySize;

        IMemoryOwner<byte> frame = pool.Rent(total);
        var frameWriter = new TpmWriter(frame.Memory.Span[..total]);
        frameWriter.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
        frameWriter.WriteUInt32((uint)total);
        frameWriter.WriteUInt32((uint)TpmRcConstants.TPM_RC_SUCCESS);
        frameWriter.WriteUInt32((uint)paramAreaLength);
        frameWriter.WriteUInt16((ushort)encryptedLength);
        frameWriter.WriteBytes(encrypted.Span);
        frameWriter.WriteTpm2b(nonceTpmNew.Span);
        frameWriter.WriteByte(attributes);
        frameWriter.WriteTpm2b(hmacValue.AsReadOnlySpan());

        return SuccessFrame(frame, total);
    }

    /// <summary>
    /// Builds the digest <see cref="Tag"/> exactly as <c>TpmCommandExecutor.BuildDigestTag</c> does: SHA-256
    /// digest, raw encoding, direct material.
    /// </summary>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    /// <summary>
    /// Builds the HMAC <see cref="Tag"/> exactly as <c>TpmSession.ComputeSessionHmacAsync</c> does: SHA-256
    /// HMAC, raw encoding, direct material.
    /// </summary>
    private static Tag HmacTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Hmac).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The frame owner ownership transfers to the returned TpmResponse, disposed by the executor under test.")]
    private static TpmResult<TpmResponse> ErrorResponse(TpmRcConstants responseCode, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> frame = pool.Rent(HeaderSize);
        var writer = new TpmWriter(frame.Memory.Span[..HeaderSize]);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_NO_SESSIONS);
        writer.WriteUInt32((uint)HeaderSize);
        writer.WriteUInt32((uint)responseCode);

        return SuccessFrame(frame, HeaderSize);
    }

    private static ReadOnlyMemory<byte> ExtractCommandNonceCaller(ReadOnlyMemory<byte> command)
    {
        //Command layout for one session: header(10) + handles + authSize(4) + [sessionHandle(4) + nonceCaller(TPM2B) + ...].
        //GetRandom and the probe command both have zero handles.
        var reader = new TpmReader(command.Span);
        _ = reader.ReadUInt16();   //tag.
        _ = reader.ReadUInt32();   //commandSize.
        _ = reader.ReadUInt32();   //commandCode.
        _ = reader.ReadUInt32();   //authorizationSize.
        _ = reader.ReadUInt32();   //sessionHandle.

        TpmBlob nonce = reader.ReadTpm2bBlob();

        return command.Slice(nonce.Offset, nonce.Length);
    }

    private static ReadOnlyMemory<byte> ExtractCommandFirstParameterData(ReadOnlyMemory<byte> command)
    {
        //Parameters begin after header(10) + authSize field(4) + the authorization area. Zero handles.
        var reader = new TpmReader(command.Span);
        reader.Skip(HeaderSize);
        uint authSize = reader.ReadUInt32();

        reader.Skip((int)authSize);
        TpmBlob firstParam = reader.ReadTpm2bBlob();

        return command.Slice(firstParam.Offset, firstParam.Length);
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The TpmResponse is owned by the returned TpmResult and disposed by the executor under test.")]
    private static TpmResult<TpmResponse> SuccessFrame(IMemoryOwner<byte> frame, int length)
    {
        return TpmResult<TpmResponse>.Success(new TpmResponse(frame, length));
    }

    private static Tpm2bNonce MakeNonce(int length, byte seed, MemoryPool<byte> pool)
    {
        Span<byte> b = stackalloc byte[length];
        FillPattern(b, seed);

        return Tpm2bNonce.Create(b, pool);
    }

    private static void FillPattern(Span<byte> destination, byte seed)
    {
        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)(seed ^ i);
        }
    }

    /// <summary>
    /// A test-only command whose first parameter is an encryptable sized buffer, used to drive the command
    /// parameter-encryption path. It reports <see cref="TpmCcConstants.TPM_CC_GetRandom"/> (zero handles) so the
    /// executor's command-attribute lookup resolves, and writes a single TPM2B holding the supplied data.
    /// </summary>
    private sealed class EncryptableProbeInput: ITpmCommandInput, IDisposable
    {
        private readonly Tpm2bData payload;

        public EncryptableProbeInput(ReadOnlySpan<byte> data, MemoryPool<byte> pool)
        {
            payload = Tpm2bData.Create(data, pool);
        }

        public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_GetRandom;

        public bool FirstCommandParameterIsEncryptable => true;

        public int GetSerializedSize() => payload.SerializedSize;

        public void WriteHandles(ref TpmWriter writer)
        {
        }

        public void WriteParameters(ref TpmWriter writer)
        {
            payload.WriteTo(ref writer);
        }

        public void Dispose()
        {
            payload.Dispose();
        }
    }
}
