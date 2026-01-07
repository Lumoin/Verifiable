using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;

namespace Verifiable.Tests.Tpm
{
    /// <summary>
    /// Tests for TPM functionality across different platforms.
    /// </summary>
    [TestClass]
    public sealed class NewTpmTests
    {
        private const string TestStringToBeHashed = "Hello, SHA-256 world!";


        [SupportedOSPlatform(Platforms.Windows)]
        [RunOnlyOnPlatformTestMethod(platforms: [Platforms.Windows])]
        public void TpmWindowsSupportsWindows()
        {
            Assert.IsTrue(TpmWindows.IsSupported);
        }


        [SupportedOSPlatform(Platforms.Linux)]
        [RunOnlyOnPlatformTestMethod(platforms: [Platforms.Linux])]
        public void TpmLinuxSupportsLinux()
        {
            Assert.IsTrue(TpmLinux.IsSupported);
        }


        [RunOnlyOnPlatformSkipOnCiTestMethod(platforms: [Platforms.Windows, Platforms.Linux])]
        public void TpmVirtualSupportsWindowsAndLinux()
        {
            Assert.IsTrue(TpmVirtual.IsSupported);
        }


        [RunOnlyOnPlatformSkipOnCiTestMethod(platforms: [Platforms.Windows, Platforms.Linux])]
        public void GetVersionSucceeds()
        {
            var version = Verifiable.Tpm.Tpm.GetTpmFirmwareVersion();
            Assert.IsNotNull(version);
        }


        [TestMethod]
        [Ignore("Sketch. Does not work.")]
        public void SelfTestSucceeds()
        {
            bool isSelfTestSuccess = Verifiable.Tpm.Tpm.SelfTest(fullTest: true);
            Assert.IsTrue(isSelfTestSuccess);
        }


        [RunOnlyOnPlatformSkipOnCiTestMethod(platforms: [Platforms.Windows, Platforms.Linux])]
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
            Assert.IsNotEmpty(supportedAlgorithms, "The collection is empty.");
        }


        [RunOnlyOnPlatformSkipOnCiTestMethod(platforms: [Platforms.Windows, Platforms.Linux])]
        public void CalculateShortSha256()
        {
            ReadOnlySpan<byte> controlValue = Encoding.UTF8.GetBytes(TestStringToBeHashed);
            byte[] controlValueHash = SHA256.HashData(controlValue);

            byte[]? tpmSha256 = Verifiable.Tpm.Tpm.CalculateSha256(TestStringToBeHashed);

            CollectionAssert.AreEqual(controlValueHash, tpmSha256);
        }


        [TestMethod]
        [Ignore("Sketch. Does not work.")]
        public void CalculateLongSha256()
        {
            //The array to be hashed is of constant value while developing on purpose.
            byte[] longByteArray = [0, 1, 2, 3, 4, 5, 6, 7, 4, 5];

            byte[] longControlValueHash = SHA256.HashData(longByteArray);
            byte[]? longTpmSha256 = Verifiable.Tpm.Tpm.CalculateLongSha256(longByteArray);

            CollectionAssert.AreEqual(longControlValueHash, longTpmSha256);
        }
    }
}