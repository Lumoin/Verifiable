using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Host-only structural tests for <see cref="TpmSession"/> and the bound-session establishment factory.
/// </summary>
/// <remarks>
/// <para>
/// These tests deliberately assert only observable structure (input fields, session handle/algorithm,
/// serialized auth-command size, argument guards, disposal). The derived session key and the per-command
/// nonceCaller are secret session state with no public accessor — exposing them for a host-side known-answer
/// test would be a production test seam. The cryptographic correctness of the bound key derivation is gated
/// instead by the SP800-108 oracle over KDFa (see <c>KdfaTests</c>) plus the hardware bound-session HMAC in
/// <c>HwTpmSessionTests</c>, whose verification only succeeds when the host and the TPM derive an identical
/// session key.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmSessionTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA1, 20)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA256, 32)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA384, 48)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA512, 64)]
    public void CreateBoundUnsaltedHmacSessionBuildsExpectedInput(TpmAlgIdConstants authHash, int digestSize)
    {
        const uint BindHandle = 0x80000001u;
        StartAuthSessionInput input = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(BindHandle, authHash);

        Assert.AreEqual(BindHandle, input.Bind, "Bind handle must be the supplied entity handle.");
        Assert.AreEqual((uint)TpmRh.TPM_RH_NULL, input.TpmKey, "An unsalted session must carry no salt key (TPM_RH_NULL).");
        Assert.AreEqual(TpmSeConstants.TPM_SE_HMAC, input.SessionType, "Session type must be HMAC.");
        Assert.AreEqual(authHash, input.AuthHash, "AuthHash must be the requested algorithm.");
        Assert.IsTrue(input.EncryptedSalt.IsEmpty, "An unsalted session must carry an empty encryptedSalt.");
        Assert.HasCount(digestSize, input.NonceCaller, "nonceCaller must be a full-digest-size caller nonce (>= 16 octets per Part 3 §11.1).");
        Assert.AreEqual(TpmCcConstants.TPM_CC_StartAuthSession, input.CommandCode);
    }

    [TestMethod]
    public void CreateBoundUnsaltedHmacSessionGeneratesFreshNonceEachCall()
    {
        const uint BindHandle = 0x80000001u;
        StartAuthSessionInput first = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(BindHandle, TpmAlgIdConstants.TPM_ALG_SHA256);
        StartAuthSessionInput second = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(BindHandle, TpmAlgIdConstants.TPM_ALG_SHA256);

        Assert.IsFalse(
            first.NonceCaller.Span.SequenceEqual(second.NonceCaller.Span),
            "Each establishment must generate an independent caller nonce.");
    }

    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA1, 20)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA256, 32)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA384, 48)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA512, 64)]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the nonce transfers to the bound session on success and CreateBoundAsync disposes it on a derivation failure; the session is disposed by the using statement.")]
    public async Task CreateBoundAsyncProducesUsableSession(TpmAlgIdConstants sessionAlg, int digestSize)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var sessionHandle = new TpmHandle(0x02000000u);

        byte[] bindAuth = [0x01, 0x02, 0x03, 0x04];
        byte[] startNonceCaller = new byte[digestSize];
        startNonceCaller.AsSpan().Fill(0x5A);
        Tpm2bNonce nonceTpm = Tpm2bNonce.CreateRandom(digestSize, pool);

        using TpmSession session = await TpmSession.CreateBoundAsync(
            sessionHandle, bindAuth, startNonceCaller, nonceTpm, sessionAlg, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(sessionHandle.Value, session.SessionHandle.Value, "The session must keep its StartAuthSession handle.");
        Assert.AreEqual(sessionAlg, session.HashAlgorithm, "The session must report its hash algorithm.");

        //TPMS_AUTH_COMMAND: sessionHandle(4) + nonceCaller(2 + digest) + sessionAttributes(1) + hmac(2 + digest).
        int expectedAuthSize = sizeof(uint) + (sizeof(ushort) + digestSize) + sizeof(byte) + (sizeof(ushort) + digestSize);
        Assert.AreEqual(expectedAuthSize, session.GetAuthCommandSize(), "Bound HMAC session auth-command size must account for a full-digest nonce and HMAC.");
    }

    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the nonce transfers to the bound session on success and CreateBoundAsync disposes it on a derivation failure; the session is disposed by the using statement.")]
    public async Task CreateBoundAsyncAcceptsEmptyBindAuth()
    {
        //Binding to an empty-auth entity still derives a non-empty session key (KDFa over an empty key), so
        //the bound path is exercised without an authValue. The factory must not reject the empty bind auth.
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var sessionHandle = new TpmHandle(0x02000000u);
        Tpm2bNonce nonceTpm = Tpm2bNonce.CreateRandom(32, pool);

        using TpmSession session = await TpmSession.CreateBoundAsync(
            sessionHandle, ReadOnlyMemory<byte>.Empty, new byte[32], nonceTpm, TpmAlgIdConstants.TPM_ALG_SHA256, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(sessionHandle.Value, session.SessionHandle.Value);
    }

    [TestMethod]
    public async Task CreateBoundAsyncRejectsNullNonceTpm()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        await Assert.ThrowsExactlyAsync<ArgumentNullException>(async () =>
            await TpmSession.CreateBoundAsync(
                new TpmHandle(0x02000000u), new byte[] { 0x01 }, new byte[32], null!, TpmAlgIdConstants.TPM_ALG_SHA256, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    [TestMethod]
    public async Task CreateBoundAsyncRejectsNullPool()
    {
        Tpm2bNonce nonceTpm = Tpm2bNonce.CreateRandom(32, BaseMemoryPool.Shared);
        try
        {
            await Assert.ThrowsExactlyAsync<ArgumentNullException>(async () =>
                await TpmSession.CreateBoundAsync(
                    new TpmHandle(0x02000000u), new byte[] { 0x01 }, new byte[32], nonceTpm, TpmAlgIdConstants.TPM_ALG_SHA256, null!, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }
        finally
        {
            nonceTpm.Dispose();
        }
    }
}
