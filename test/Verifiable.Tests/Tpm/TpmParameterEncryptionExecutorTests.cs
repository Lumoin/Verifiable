using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
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
/// The scripted handler is an independent oracle: it derives the bound session key with
/// <see cref="SP800108HmacCounterKdf"/>, computes the XOR mask, rpHash, and response HMAC with
/// <see cref="System.Security.Cryptography"/> primitives, and produces a wire-faithful encrypted response.
/// The executor + <see cref="TpmSession"/> (the system under test) route through the project's own KDFa, HMAC,
/// and XOR. A divergence in nonce ordering, the parameter-encryption key, the wire placement of the encrypted
/// data, or the verify-before-decrypt ordering fails the comparison.
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
    private const int AuthSizeFieldSize = sizeof(uint);

    public TestContext TestContext { get; set; } = null!;

    private static byte[] BindAuth { get; } = Encoding.UTF8.GetBytes("det-bound-key");

    private static byte[] StartNonceCaller { get; } = BuildPattern(32, 0x5A);

    private static byte[] StartNonceTpm { get; } = BuildPattern(32, 0xC3);

    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The canned nonceTPM ownership transfers to the bound TpmSession, disposed by the using statement.")]
    public async Task EncryptedResponseFirstParameterDecryptsToKnownPlaintext()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;
        byte[] sessionKey = DeriveBoundSessionKeyOracle(SessionAlg);

        //The known plaintext the scripted TPM "returns" as randomBytes, before encryption.
        byte[] plaintext = BuildPattern(32, 0x11);
        byte[] nonceTpmNew = BuildPattern(32, 0x7E);
        const byte ResponseAttributes = (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT);

        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> handlerPool,
            CancellationToken cancellationToken)
        {
            byte[] nonceCaller = ExtractCommandNonceCaller(command.Span);
            byte[] frame = BuildEncryptedGetRandomResponse(sessionKey, nonceCaller, nonceTpmNew, plaintext, ResponseAttributes);

            return ValueTask.FromResult(SuccessFrame(frame, handlerPool));
        }

        using var device = TpmDevice.Create(Handler);

        using TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(0x02000000u),
            BindAuth,
            StartNonceCaller,
            Tpm2bNonce.Create(StartNonceTpm, pool),
            SessionAlg,
            pool,
            symmetric: TpmtSymDef.Xor(SessionAlg),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

        var input = new GetRandomInput((ushort)plaintext.Length);
        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Encrypted GetRandom must verify and decrypt: '{result.ResponseCode}'.");

        using GetRandomResponse response = result.Value;
        Assert.IsTrue(response.RandomBytes.AsReadOnlySpan().SequenceEqual(plaintext),
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
        byte[] wrongKey = BuildPattern(32, 0x99);
        byte[] plaintext = BuildPattern(16, 0x22);
        byte[] nonceTpmNew = BuildPattern(32, 0x7E);
        const byte ResponseAttributes = (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT);

        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> handlerPool,
            CancellationToken cancellationToken)
        {
            byte[] nonceCaller = ExtractCommandNonceCaller(command.Span);
            byte[] frame = BuildEncryptedGetRandomResponse(wrongKey, nonceCaller, nonceTpmNew, plaintext, ResponseAttributes);

            return ValueTask.FromResult(SuccessFrame(frame, handlerPool));
        }

        using var device = TpmDevice.Create(Handler);

        using TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(0x02000000u),
            BindAuth,
            StartNonceCaller,
            Tpm2bNonce.Create(StartNonceTpm, pool),
            SessionAlg,
            pool,
            symmetric: TpmtSymDef.Xor(SessionAlg),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

        var input = new GetRandomInput((ushort)plaintext.Length);
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
        byte[] sessionKey = DeriveBoundSessionKeyOracle(SessionAlg);
        byte[] plaintext = BuildPattern(24, 0x44);

        byte[]? observedCommand = null;
        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> handlerPool,
            CancellationToken cancellationToken)
        {
            observedCommand = command.ToArray();
            byte[] frame = BuildErrorFrame(TpmRcConstants.TPM_RC_VALUE);

            return ValueTask.FromResult(SuccessFrame(frame, handlerPool));
        }

        using var device = TpmDevice.Create(Handler);

        using TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(0x02000000u),
            BindAuth,
            StartNonceCaller,
            Tpm2bNonce.Create(StartNonceTpm, pool),
            SessionAlg,
            pool,
            symmetric: TpmtSymDef.Xor(SessionAlg),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

        using var input = new EncryptableProbeInput(plaintext, pool);
        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTpmError, "The scripted error must surface so execution stops after the command is captured.");
        Assert.IsNotNull(observedCommand);

        byte[] nonceCaller = ExtractCommandNonceCaller(observedCommand);
        byte[] encryptedFirstParam = ExtractCommandFirstParameterData(observedCommand);

        Assert.HasCount(plaintext.Length, encryptedFirstParam, "Parameter encryption must not change the data length.");
        Assert.IsFalse(encryptedFirstParam.AsSpan().SequenceEqual(plaintext), "The first command parameter must be encrypted on the wire.");

        //Command direction (Part 1 §19.2): nonceNewer = nonceCaller, nonceOlder = nonceTPM (the session's
        //current nonceTPM, which for the first command is the StartAuthSession nonceTPM).
        byte[] mask = SP800108HmacCounterKdf.DeriveBytes(
            sessionKey, HashAlgorithmName.SHA256, Encoding.ASCII.GetBytes("XOR"), Concat(nonceCaller, StartNonceTpm), plaintext.Length);
        byte[] recovered = Xor(encryptedFirstParam, mask);

        Assert.IsTrue(recovered.AsSpan().SequenceEqual(plaintext),
            "Decrypting the captured first parameter with the independent oracle must recover the plaintext.");
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
        byte[] sessionKey = DeriveBoundSessionKeyOracle(SessionAlg);

        //Block-multiple plaintext so the independent oracle CFB needs no partial-block handling.
        byte[] plaintext = BuildPattern(32, 0x11);
        byte[] nonceTpmNew = BuildPattern(32, 0x7E);
        const byte ResponseAttributes = (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT);

        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> handlerPool,
            CancellationToken cancellationToken)
        {
            byte[] nonceCaller = ExtractCommandNonceCaller(command.Span);
            byte[] frame = BuildCfbEncryptedGetRandomResponse(sessionKey, nonceCaller, nonceTpmNew, plaintext, ResponseAttributes, KeyBits);

            return ValueTask.FromResult(SuccessFrame(frame, handlerPool));
        }

        using var device = TpmDevice.Create(Handler);

        using TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(0x02000000u),
            BindAuth,
            StartNonceCaller,
            Tpm2bNonce.Create(StartNonceTpm, pool),
            SessionAlg,
            pool,
            symmetric: TpmtSymDef.Aes(KeyBits, TpmAlgIdConstants.TPM_ALG_CFB),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

        var input = new GetRandomInput((ushort)plaintext.Length);
        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Encrypted (CFB) GetRandom must verify and decrypt: '{result.ResponseCode}'.");

        using GetRandomResponse response = result.Value;
        Assert.IsTrue(response.RandomBytes.AsReadOnlySpan().SequenceEqual(plaintext),
            "The AES-CFB-decrypted first response parameter must equal the plaintext the scripted TPM encrypted.");
    }

    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The canned nonceTPM ownership transfers to the bound TpmSession, disposed by the using statement.")]
    public async Task FirstCommandParameterIsCfbEncryptedOnTheWire()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;
        const int KeyBits = 128;
        byte[] sessionKey = DeriveBoundSessionKeyOracle(SessionAlg);
        byte[] plaintext = BuildPattern(32, 0x44); //Block-multiple.

        byte[]? observedCommand = null;
        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> handlerPool,
            CancellationToken cancellationToken)
        {
            observedCommand = command.ToArray();
            byte[] frame = BuildErrorFrame(TpmRcConstants.TPM_RC_VALUE);

            return ValueTask.FromResult(SuccessFrame(frame, handlerPool));
        }

        using var device = TpmDevice.Create(Handler);

        using TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(0x02000000u),
            BindAuth,
            StartNonceCaller,
            Tpm2bNonce.Create(StartNonceTpm, pool),
            SessionAlg,
            pool,
            symmetric: TpmtSymDef.Aes(KeyBits, TpmAlgIdConstants.TPM_ALG_CFB),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

        using var input = new EncryptableProbeInput(plaintext, pool);
        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTpmError);
        Assert.IsNotNull(observedCommand);

        byte[] nonceCaller = ExtractCommandNonceCaller(observedCommand);
        byte[] encryptedFirstParam = ExtractCommandFirstParameterData(observedCommand);

        Assert.HasCount(plaintext.Length, encryptedFirstParam, "Parameter encryption must not change the data length.");
        Assert.IsFalse(encryptedFirstParam.AsSpan().SequenceEqual(plaintext), "The first command parameter must be encrypted on the wire.");

        //Command direction (Part 1 §19.2): nonceNewer = nonceCaller, nonceOlder = nonceTPM (the session's
        //current nonceTPM, which for the first command is the StartAuthSession nonceTPM).
        (byte[] key, byte[] iv) = DeriveCfbKeyIv(sessionKey, nonceCaller, StartNonceTpm, KeyBits);
        byte[] recovered = CfbReference(key, iv, encryptedFirstParam, encrypting: false);

        Assert.IsTrue(recovered.AsSpan().SequenceEqual(plaintext),
            "AES-CFB decrypting the captured first parameter with the independent oracle must recover the plaintext.");
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

        Tpm2bNonce nonceTpm = Tpm2bNonce.Create(StartNonceTpm, pool);
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

        TpmtSymDef xor = TpmtSymDef.Xor(TpmAlgIdConstants.TPM_ALG_SHA256);
        using var first = new TpmSession(
            new TpmHandle(0x02000000u), Tpm2bNonce.Create(StartNonceTpm, pool), TpmAlgIdConstants.TPM_ALG_SHA256, pool, xor);
        using var second = new TpmSession(
            new TpmHandle(0x02000001u), Tpm2bNonce.Create(StartNonceTpm, pool), TpmAlgIdConstants.TPM_ALG_SHA256, pool, xor);
        first.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
        second.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

        using var input = new EncryptableProbeInput(BuildPattern(8, 0x55), pool);

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

        Tpm2bNonce nonceTpm = Tpm2bNonce.Create(StartNonceTpm, pool);
        using var session = new TpmSession(
            new TpmHandle(0x02000000u), nonceTpm, TpmAlgIdConstants.TPM_ALG_SHA256, pool, symmetric);
        session.SessionAttributes = attributes;

        if(useEncryptableInput)
        {
            using var encryptable = new EncryptableProbeInput(BuildPattern(8, 0x66), pool);
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

    private static byte[] DeriveBoundSessionKeyOracle(TpmAlgIdConstants sessionAlg)
    {
        //sessionKey = KDFa(sessionAlg, bindAuth, "ATH", nonceTPM, nonceCaller, bits) (Part 1 §17.6.10), computed
        //with the independent SP800-108 oracle. CreateBoundAsync derives the same key via the project's KDFa.
        HashAlgorithmName hash = sessionAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_SHA256 => HashAlgorithmName.SHA256,
            TpmAlgIdConstants.TPM_ALG_SHA384 => HashAlgorithmName.SHA384,
            TpmAlgIdConstants.TPM_ALG_SHA512 => HashAlgorithmName.SHA512,
            TpmAlgIdConstants.TPM_ALG_SHA1 => HashAlgorithmName.SHA1,
            _ => throw new ArgumentOutOfRangeException(nameof(sessionAlg))
        };
        int digestSize = hash == HashAlgorithmName.SHA1 ? 20 : hash == HashAlgorithmName.SHA384 ? 48 : hash == HashAlgorithmName.SHA512 ? 64 : 32;

        return SP800108HmacCounterKdf.DeriveBytes(
            BindAuth, hash, Encoding.ASCII.GetBytes("ATH"), Concat(StartNonceTpm, StartNonceCaller), digestSize);
    }

    private static byte[] BuildEncryptedGetRandomResponse(byte[] sessionKey, byte[] nonceCaller, byte[] nonceTpmNew, byte[] plaintext, byte attributes)
    {
        //Encrypt the first response parameter with XOR: response direction nonceNewer = nonceTPM, nonceOlder = nonceCaller.
        byte[] mask = SP800108HmacCounterKdf.DeriveBytes(
            sessionKey, HashAlgorithmName.SHA256, Encoding.ASCII.GetBytes("XOR"), Concat(nonceTpmNew, nonceCaller), plaintext.Length);
        byte[] encrypted = Xor(plaintext, mask);

        return FrameEncryptedSessionResponse(sessionKey, nonceCaller, nonceTpmNew, encrypted, attributes);
    }

    private static byte[] BuildCfbEncryptedGetRandomResponse(byte[] sessionKey, byte[] nonceCaller, byte[] nonceTpmNew, byte[] plaintext, byte attributes, int keyBits)
    {
        //Encrypt the first response parameter with AES-CFB: response direction nonceNewer = nonceTPM, nonceOlder = nonceCaller.
        (byte[] key, byte[] iv) = DeriveCfbKeyIv(sessionKey, nonceTpmNew, nonceCaller, keyBits);
        byte[] encrypted = CfbReference(key, iv, plaintext, encrypting: true);

        return FrameEncryptedSessionResponse(sessionKey, nonceCaller, nonceTpmNew, encrypted, attributes);
    }

    /// <summary>
    /// Frames a TPM_ST_SESSIONS GetRandom response carrying an already-encrypted first parameter, computing the
    /// rpHash (over the encrypted bytes) and the response HMAC exactly as the TPM would.
    /// </summary>
    private static byte[] FrameEncryptedSessionResponse(byte[] sessionKey, byte[] nonceCaller, byte[] nonceTpmNew, byte[] encrypted, byte attributes)
    {
        //randomBytes parameter area: TPM2B size (the unencrypted size field) + encrypted data.
        byte[] paramArea = new byte[sizeof(ushort) + encrypted.Length];
        BinaryPrimitives.WriteUInt16BigEndian(paramArea, (ushort)encrypted.Length);
        encrypted.CopyTo(paramArea, sizeof(ushort));

        //rpHash = H(responseCode || commandCode || encrypted parameter area).
        byte[] rpHash = SHA256.HashData(Concat(Be32(0u), Be32((uint)TpmCcConstants.TPM_CC_GetRandom), paramArea));

        //Response HMAC = HMAC(sessionKey, rpHash || nonceTPM(new) || nonceCaller || sessionAttributes).
        byte[] hmac = HMACSHA256.HashData(sessionKey, Concat(rpHash, nonceTpmNew, nonceCaller, [attributes]));

        byte[] authArea = Concat(
            Tpm2b(nonceTpmNew),
            [attributes],
            Tpm2b(hmac));

        int bodySize = sizeof(uint) + paramArea.Length + authArea.Length; //parameterSize field + params + auth.
        int total = HeaderSize + bodySize;
        byte[] frame = new byte[total];
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(0), (ushort)TpmStConstants.TPM_ST_SESSIONS);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(2), (uint)total);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(6), (uint)TpmRcConstants.TPM_RC_SUCCESS);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(HeaderSize), (uint)paramArea.Length);
        paramArea.CopyTo(frame, HeaderSize + sizeof(uint));
        authArea.CopyTo(frame, HeaderSize + sizeof(uint) + paramArea.Length);

        return frame;
    }

    /// <summary>
    /// Derives the AES-CFB key and IV the TPM would use: KDFa(SHA-256, sessionValue, "CFB", nonceNewer,
    /// nonceOlder, keyBits + 128) via the independent SP800-108 oracle; key = MSB octets, IV = next 16 octets.
    /// </summary>
    private static (byte[] Key, byte[] Iv) DeriveCfbKeyIv(byte[] sessionValue, byte[] nonceNewer, byte[] nonceOlder, int keyBits)
    {
        int keySize = (keyBits + 7) / 8;
        byte[] material = SP800108HmacCounterKdf.DeriveBytes(
            sessionValue, HashAlgorithmName.SHA256, Encoding.ASCII.GetBytes("CFB"), Concat(nonceNewer, nonceOlder), keySize + 16);

        return (material[..keySize], material[keySize..(keySize + 16)]);
    }

    /// <summary>
    /// A test-local, independently-written AES full-block CFB-128 transform (block-multiple data only), used as
    /// the oracle cipher for the executor mini-responder. Independent of the production <c>AesCfb</c>; the
    /// production primitive is anchored separately against the NIST SP800-38A vector.
    /// </summary>
    private static byte[] CfbReference(byte[] key, byte[] iv, byte[] data, bool encrypting)
    {
        const int BlockSize = 16;
        using Aes aes = Aes.Create();
        aes.Key = key;

        byte[] output = new byte[data.Length];
        byte[] feedback = (byte[])iv.Clone();
        byte[] keystream = new byte[BlockSize];

        for(int offset = 0; offset < data.Length; offset += BlockSize)
        {
            _ = aes.EncryptEcb(feedback, keystream, PaddingMode.None);
            for(int i = 0; i < BlockSize; i++)
            {
                output[offset + i] = (byte)(data[offset + i] ^ keystream[i]);
            }

            //Full-block feedback: encryption feeds back produced ciphertext, decryption the consumed ciphertext.
            Array.Copy(encrypting ? output : data, offset, feedback, 0, BlockSize);
        }

        return output;
    }

    private static byte[] BuildErrorFrame(TpmRcConstants responseCode)
    {
        byte[] frame = new byte[HeaderSize];
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(0), (ushort)TpmStConstants.TPM_ST_NO_SESSIONS);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(2), (uint)HeaderSize);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(6), (uint)responseCode);

        return frame;
    }

    private static byte[] ExtractCommandNonceCaller(ReadOnlySpan<byte> command)
    {
        //Command layout for one session: header(10) + handles + authSize(4) + [sessionHandle(4) + nonceCaller(TPM2B) + ...].
        //GetRandom and the probe command both have zero handles.
        var reader = new TpmReader(command);
        _ = reader.ReadUInt16();   //tag.
        _ = reader.ReadUInt32();   //commandSize.
        _ = reader.ReadUInt32();   //commandCode.
        _ = reader.ReadUInt32();   //authorizationSize.
        _ = reader.ReadUInt32();   //sessionHandle.

        return reader.ReadTpm2b().ToArray();
    }

    private static byte[] ExtractCommandFirstParameterData(ReadOnlySpan<byte> command)
    {
        //Parameters begin after header(10) + authSize field(4) + the authorization area. Zero handles.
        uint authSize = BinaryPrimitives.ReadUInt32BigEndian(command.Slice(HeaderSize, AuthSizeFieldSize));
        int parametersStart = HeaderSize + AuthSizeFieldSize + (int)authSize;

        ReadOnlySpan<byte> parameters = command[parametersStart..];
        ushort firstSize = BinaryPrimitives.ReadUInt16BigEndian(parameters);

        return parameters.Slice(sizeof(ushort), firstSize).ToArray();
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The TpmResponse is owned by the returned TpmResult and disposed by the executor under test.")]
    private static TpmResult<TpmResponse> SuccessFrame(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return TpmResult<TpmResponse>.Success(new TpmResponse(owner, bytes.Length));
    }

    private static byte[] Tpm2b(byte[] data)
    {
        byte[] result = new byte[sizeof(ushort) + data.Length];
        BinaryPrimitives.WriteUInt16BigEndian(result, (ushort)data.Length);
        data.CopyTo(result, sizeof(ushort));

        return result;
    }

    private static byte[] Be32(uint value)
    {
        byte[] result = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(result, value);

        return result;
    }

    private static byte[] Xor(byte[] data, byte[] mask)
    {
        byte[] result = new byte[data.Length];
        for(int i = 0; i < data.Length; i++)
        {
            result[i] = (byte)(data[i] ^ mask[i]);
        }

        return result;
    }

    private static byte[] BuildPattern(int length, byte seed)
    {
        byte[] result = new byte[length];
        for(int i = 0; i < length; i++)
        {
            result[i] = (byte)(seed ^ i);
        }

        return result;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int length = 0;
        foreach(byte[] part in parts)
        {
            length += part.Length;
        }

        byte[] result = new byte[length];
        int offset = 0;
        foreach(byte[] part in parts)
        {
            part.CopyTo(result, offset);
            offset += part.Length;
        }

        return result;
    }

    /// <summary>
    /// A test-only command whose first parameter is an encryptable sized buffer, used to drive the command
    /// parameter-encryption path. It reports <see cref="TpmCcConstants.TPM_CC_GetRandom"/> (zero handles) so the
    /// executor's command-attribute lookup resolves, and writes a single TPM2B holding the supplied data.
    /// </summary>
    private sealed class EncryptableProbeInput: ITpmCommandInput, IDisposable
    {
        private readonly Tpm2bData payload;

        public EncryptableProbeInput(byte[] data, MemoryPool<byte> pool)
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
