using System.Collections.Frozen;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.test;

public static class FakeTpmClient
{
    public static ValueTask<bool> VerifyAsync(string keyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        //Fake verification - just check if handle is valid.
        return ValueTask.FromResult(keyHandle == "Tpm-key-handle-123");
    }
}


[TestClass]
public class FakeTpmHandleTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task FakeTpmHandleTest()
    {
        //Create TPM verification delegate that matches the VerificationDelegate signature.
        VerificationDelegate tpmVerificationDelegate =
            async (dataToVerify, signature, verificationContext, context) =>
            {
                //Decode handle from verificationContext bytes.
                string handle = Encoding.UTF8.GetString(verificationContext.Span);

                //Call fake TPM verification logic.
                return await FakeTpmClient.VerifyAsync(handle, dataToVerify.Span, signature.Span);
            };

        //Create TPM tag.
        var tpmTag = new Tag(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Ed25519,
            [typeof(Purpose)] = Purpose.Verification
        });

        //Encode handle as bytes for storage.
        string tpmHandle = "Tpm-key-handle-123";
        var handleBytes = SensitiveMemoryPool<byte>.Shared.Rent(Encoding.UTF8.GetByteCount(tpmHandle));
        Encoding.UTF8.GetBytes(tpmHandle, handleBytes.Memory.Span);
        var handleMemory = new PublicKeyMemory(handleBytes, tpmTag);

        //Create TPM public key.
        var tpmPublicKey = new PublicKey(handleMemory, "Tpm-key-id", tpmVerificationDelegate);

        //Test data and fake signature.
        var testData = Encoding.UTF8.GetBytes("Hello TPM!");
        var fakeSignature = new Signature(SensitiveMemoryPool<byte>.Shared.Rent(64), Tag.Empty);

        //Verify using TPM key - should work transparently.
        bool verified = await tpmPublicKey.VerifyAsync(testData, fakeSignature);
        bool verifiedWithExtension = await handleMemory.VerifyAsync(testData, fakeSignature, tpmVerificationDelegate);

        Assert.IsTrue(verified, "TPM verification should succeed.");
        Assert.IsTrue(verifiedWithExtension, "TPM verification with extension should succeed.");
    }
}