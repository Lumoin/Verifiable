using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.test
{
    /*
    public class TmpOperation: KeyOperationLocation
    {
        public string Handle { get; init; } = string.Empty;
    }*/


    public static class FakeTpmClient
    {
        public static ValueTask<bool> VerifyAsync(string keyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            //Fake verification - just check if handle is valid
            return ValueTask.FromResult(keyHandle == "tpm-key-handle-123");
        }
    }


    [TestClass]
    public class FakeTpmHandleTests
    {
        [TestMethod]
        public async ValueTask FakeTpmHandleTest()
        {
            //Create TPM verification function that matches the delegate signature
            VerificationFunction<byte, byte, Signature, ValueTask<bool>> tpmVerificationFunction =
                async (verificationContext, dataToVerify, signature) =>
                {
                    //Decode handle from verificationContext bytes
                    string handle = Encoding.UTF8.GetString(verificationContext.Span);

                    //Call fake TPM verification logic
                    return await FakeTpmClient.VerifyAsync(handle, dataToVerify.Span, signature.AsReadOnlySpan());
                };

            //Create TPM tag
            var tpmTag = new Tag(new Dictionary<Type, object>
            {
                [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Ed25519,
                [typeof(Purpose)] = Purpose.Verification,
                //[typeof(KeyOperationLocation)] = new TpmOperation { Handle = "tpm-key-handle-123" }
            });

            //Encode handle as bytes for storage
            string tpmHandle = "tpm-key-handle-123";
            var handleBytes = SensitiveMemoryPool<byte>.Shared.Rent(Encoding.UTF8.GetByteCount(tpmHandle));
            Encoding.UTF8.GetBytes(tpmHandle, handleBytes.Memory.Span);
            var handleMemory = new PublicKeyMemory(handleBytes, tpmTag);

            //Create TPM public key
            var tpmPublicKey = new PublicKey(handleMemory, "tpm-key-id", tpmVerificationFunction);

            //Test data and fake signature
            var testData = Encoding.UTF8.GetBytes("Hello TPM!");
            var fakeSignature = new Signature(SensitiveMemoryPool<byte>.Shared.Rent(64), Tag.Empty);

            //Verify using TPM key - should work transparently
            bool verified = await tpmPublicKey.VerifyAsync(testData, fakeSignature);
            bool verifiedWithExtension = await handleMemory.VerifyAsync(testData, fakeSignature, tpmVerificationFunction);

            Assert.IsTrue(verified, "TPM verification should succeed");
            Assert.IsTrue(verifiedWithExtension, "TPM verification with extension should succeed");
        }
    }
}
