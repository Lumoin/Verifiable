using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography.EventLogs;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.EventLogs;

/// <summary>
/// Non-hardware coverage for the generic <see cref="CryptoProof"/> log path: a software-signed proof flows
/// through the production <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/> and verifies through the
/// same <c>CryptoFunctionRegistry</c> seam every other trust domain uses, and a proof made over different bytes
/// fails closed. The TPM is one producer of these carriers (see the TPM simulator quote tests); this path is
/// TPM-agnostic.
/// </summary>
[TestClass]
internal sealed class CryptoProofLogReplayTests
{
    /// <summary>
    /// Gets or sets the per-test context (supplies the cancellation token).
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task SoftwareSignedCryptoProofEntryReplaysSuccessfully()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;

        byte[] canonical = "Domain-agnostic attestation statement."u8.ToArray();
        byte[] digest = SHA256.HashData(canonical);

        var sign = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(CryptoAlgorithm.P256, Purpose.Signing);
        (Signature signature, CryptoEvent? _) = await sign(
            privateKey.AsReadOnlyMemory(), canonical, pool, context: null, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using var disposableSignature = signature;

        var proof = new CryptoProof(signature, publicKey, CryptoAlgorithm.P256);
        LogEntry<ReadOnlyMemory<byte>, CryptoProof> entry = new()
        {
            Index = 0,
            PreviousDigest = null,
            Digest = digest,
            CanonicalBytes = canonical,
            Operation = canonical,
            Proofs = [proof]
        };

        LogReplayResult<int, ReadOnlyMemory<byte>, CryptoProof> result =
            await CryptoProofLogReplayHarness.ReplayGenesisAsync(entry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"A valid crypto proof must replay successfully; error: '{result.Error}'.");
        Assert.IsInstanceOfType<ActiveLogState<int>>(result.State);
    }

    [TestMethod]
    public async Task ProofOverDifferentBytesFailsClosed()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;

        byte[] signedBytes = "the bytes that were actually signed"u8.ToArray();
        byte[] tamperedBytes = "the bytes that were NOT the signed ones"u8.ToArray();

        var sign = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(CryptoAlgorithm.P256, Purpose.Signing);
        (Signature signature, CryptoEvent? _) = await sign(
            privateKey.AsReadOnlyMemory(), signedBytes, pool, context: null, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using var disposableSignature = signature;

        //The entry is internally consistent (digest matches its canonical bytes), but the signature was produced
        //over different bytes — so proof validation must fail-closed and the genesis state must not be applied.
        var proof = new CryptoProof(signature, publicKey, CryptoAlgorithm.P256);
        LogEntry<ReadOnlyMemory<byte>, CryptoProof> entry = new()
        {
            Index = 0,
            PreviousDigest = null,
            Digest = SHA256.HashData(tamperedBytes),
            CanonicalBytes = tamperedBytes,
            Operation = tamperedBytes,
            Proofs = [proof]
        };

        LogReplayResult<int, ReadOnlyMemory<byte>, CryptoProof> result =
            await CryptoProofLogReplayHarness.ReplayGenesisAsync(entry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A proof produced over different bytes must not verify.");
        Assert.IsInstanceOfType<EmptyLogState<int>>(result.State, "Genesis state must not be applied when proof validation fails.");
        Assert.IsTrue(
            result.Error is not null && result.Error.Contains("does not verify", StringComparison.Ordinal),
            $"The error must report the failed proof; got '{result.Error}'.");
    }
}
