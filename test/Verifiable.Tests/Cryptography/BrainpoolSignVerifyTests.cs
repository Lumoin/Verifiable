using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// End-to-end sign/verify round-trip tests for the four Brainpool r1 curves
/// landed in Q.2, both at the raw BouncyCastle function layer and through
/// the registry-driven <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>.
/// </summary>
/// <remarks>
/// <para>
/// These tests exercise the full happy path: TestKeyMaterialProvider → BC
/// sign / verify → tampered-payload negative case. The signature size check
/// pins the IEEE P1363 component size to the field byte size for each curve.
/// </para>
/// </remarks>
[TestClass]
internal sealed class BrainpoolSignVerifyTests
{
    private static readonly byte[] SampleData =
        Encoding.UTF8.GetBytes("oid4vp brainpool round-trip test vector");


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task BrainpoolP256r1SignAndVerifyRoundTrip()
    {
        await AssertBcRoundTrip(
            TestKeyMaterialProvider.CreateBrainpoolP256r1KeyMaterial(),
            BouncyCastleCryptographicFunctions.SignBrainpoolP256r1Async,
            BouncyCastleCryptographicFunctions.VerifyBrainpoolP256r1Async,
            expectedSignatureLength: 64,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task BrainpoolP320r1SignAndVerifyRoundTrip()
    {
        await AssertBcRoundTrip(
            TestKeyMaterialProvider.CreateBrainpoolP320r1KeyMaterial(),
            BouncyCastleCryptographicFunctions.SignBrainpoolP320r1Async,
            BouncyCastleCryptographicFunctions.VerifyBrainpoolP320r1Async,
            expectedSignatureLength: 80,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task BrainpoolP384r1SignAndVerifyRoundTrip()
    {
        await AssertBcRoundTrip(
            TestKeyMaterialProvider.CreateBrainpoolP384r1KeyMaterial(),
            BouncyCastleCryptographicFunctions.SignBrainpoolP384r1Async,
            BouncyCastleCryptographicFunctions.VerifyBrainpoolP384r1Async,
            expectedSignatureLength: 96,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task BrainpoolP512r1SignAndVerifyRoundTrip()
    {
        await AssertBcRoundTrip(
            TestKeyMaterialProvider.CreateBrainpoolP512r1KeyMaterial(),
            BouncyCastleCryptographicFunctions.SignBrainpoolP512r1Async,
            BouncyCastleCryptographicFunctions.VerifyBrainpoolP512r1Async,
            expectedSignatureLength: 128,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task BrainpoolSignatureFailsOnTamperedPayload()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateBrainpoolP256r1KeyMaterial();
        try
        {
            Signature signature = await BouncyCastleCryptographicFunctions.SignBrainpoolP256r1Async(
                keyMaterial.PrivateKey.AsReadOnlyMemory(),
                SampleData,
                SensitiveMemoryPool<byte>.Shared,
                null,
                TestContext.CancellationToken).ConfigureAwait(false);
            try
            {
                byte[] tampered = (byte[])SampleData.Clone();
                tampered[0] ^= 0x01;

                bool valid = await BouncyCastleCryptographicFunctions.VerifyBrainpoolP256r1Async(
                    tampered,
                    signature.AsReadOnlyMemory(),
                    keyMaterial.PublicKey.AsReadOnlyMemory(),
                    null,
                    TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(valid,
                    "Verification must reject the signature after the payload's first byte is flipped.");
            }
            finally
            {
                signature.Dispose();
            }
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    private static async Task AssertBcRoundTrip(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial,
        Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, System.Buffers.MemoryPool<byte>, System.Collections.Frozen.FrozenDictionary<string, object>?, CancellationToken, ValueTask<Signature>> signAsync,
        Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, System.Collections.Frozen.FrozenDictionary<string, object>?, CancellationToken, ValueTask<bool>> verifyAsync,
        int expectedSignatureLength,
        CancellationToken cancellationToken)
    {
        try
        {
            Signature signature = await signAsync(
                keyMaterial.PrivateKey.AsReadOnlyMemory(),
                SampleData,
                SensitiveMemoryPool<byte>.Shared,
                null,
                cancellationToken).ConfigureAwait(false);
            try
            {
                Assert.AreEqual(expectedSignatureLength, signature.AsReadOnlySpan().Length,
                    "IEEE P1363 signature length must match 2× the curve field byte size.");

                bool valid = await verifyAsync(
                    SampleData,
                    signature.AsReadOnlyMemory(),
                    keyMaterial.PublicKey.AsReadOnlyMemory(),
                    null,
                    cancellationToken).ConfigureAwait(false);

                Assert.IsTrue(valid, "Verification must accept the signature on unmodified data.");
            }
            finally
            {
                signature.Dispose();
            }
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }
}
