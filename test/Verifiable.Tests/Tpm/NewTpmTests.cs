using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;

namespace Verifiable.Tests.Tpm
{
    [TestClass]
    public sealed class NewTpmTests
    {        
        [SupportedOSPlatform(Platforms.Windows)]
        [RunOnlyOnPlatformTestMethod(Platforms.Windows)]
        public void TpmWindowsSupportsWindows()
        {            
            Assert.IsTrue(TpmWindows.IsSupported);
        }

        
        [SupportedOSPlatform(Platforms.Linux)]
        [RunOnlyOnPlatformTestMethod(Platforms.Linux)]        
        public void TpmLinuxSupportsLinux()
        {
            Assert.IsTrue(TpmLinux.IsSupported);
        }

        
        [SkipOnCiTestMethod]
        public void TpmVirtualSupportsAllPlatforms()
        {
            Assert.IsTrue(TpmVirtual.IsSupported);
        }

        
        [SkipOnCiTestMethod]
        public void GetVersionSucceeds()
        {
            var version = Verifiable.Tpm.Tpm.GetTpmFirmwareVersion();
            Assert.IsTrue(version != null);
        }


        [TestMethod]
        [Ignore("Sketch. Does not work.")]
        public void SelfTestSucceeds()
        {
            bool isSelfTestSuccess = Verifiable.Tpm.Tpm.SelfTest(fullTest: true);
            Assert.IsTrue(isSelfTestSuccess);
        }

        
        [SkipOnCiTestMethod]
        public void IsFipsSucceeds()
        {
            var isFips = Verifiable.Tpm.Tpm.IsFips();
            Assert.IsTrue(isFips);
        }


        [TestMethod]
        [Ignore("Sketch. Does not call a working version.")]
        public void GetSupportedAlgorithms()
        {
            var supportedAlgorithms = Verifiable.Tpm.Tpm.GetSupportedAlgorithms();

            Assert.IsNotNull(supportedAlgorithms, "The collection is null.");
            Assert.IsTrue(supportedAlgorithms.Count > 0, "The collection is empty.");
        }

        
        [SkipOnCiTestMethod]
        public void CalculateShortSha256()
        {
            const string TestStringToBeHashed = "Hello, SHA-256 world!";
            ReadOnlySpan<byte> controlValue = Encoding.UTF8.GetBytes(TestStringToBeHashed);
            byte[] controlValueHash = SHA256.HashData(controlValue);

            byte[]? tpmSha256 = Verifiable.Tpm.Tpm.CalculateSha256(TestStringToBeHashed);

            CollectionAssert.AreEqual(controlValueHash, tpmSha256);
        }


        [TestMethod]
        [Ignore("Sketch. Does not work.")]
        public void CalculateLongSha256()
        {
            //TODO: The array to be hashed is of constant value while developing
            //on purpose.
            byte[] longByteArray = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 4, 5};
                                    
            byte[] longControlValueHash = SHA256.HashData(longByteArray);
            byte[]? longTpmSha256 = Verifiable.Tpm.Tpm.CalculateLongSha256(longByteArray);

            Assert.AreEqual(longControlValueHash, longTpmSha256);
        }
    }
}
