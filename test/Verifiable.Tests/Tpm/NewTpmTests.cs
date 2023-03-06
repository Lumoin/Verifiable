using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Xunit;

namespace Verifiable.Tests.Tpm
{
    public class NewTpmTests
    {                
        [SupportedOSPlatform(Platforms.Windows)]
        [RunOnlyOnPlatformFact(Platforms.Windows)]
        public void TpmWindowsSupportsWindows()
        {            
            Assert.True(TpmWindows.IsSupported);
        }


        [SupportedOSPlatform(Platforms.Linux)]
        [RunOnlyOnPlatformFact(Platforms.Linux)]
        public void TpmLinuxSupportsLinux()
        {            
            Assert.True(TpmLinux.IsSupported);
        }

        [SkipTpmTestOnCiFact]
        public void TpmVirtualSupportsAllPlatforms()
        {
            Assert.True(TpmVirtual.IsSupported);
        }


        [SkipTpmTestOnCiFact]
        public void GetVersionSucceeds()
        {
            var version = Verifiable.Tpm.Tpm.GetTpmFirmwareVersion();
            Assert.True(version != null);
        }


        [Fact(Skip = "Sketch. Does not work.")]
        public void SelfTestSucceeds()
        {
            bool isSelfTestSuccess = Verifiable.Tpm.Tpm.SelfTest(fullTest: true);
            Assert.True(isSelfTestSuccess);
        }

        [SkipTpmTestOnCiFact]
        public void IsFipsSucceeds()
        {
            var isFips = Verifiable.Tpm.Tpm.IsFips();
            Assert.True(isFips);
        }


        [Fact(Skip = "Sketch. Does not call a working version.")]
        public void GetSupportedAlgorithms()
        {
            var supportedAlgorithms = Verifiable.Tpm.Tpm.GetSupportedAlgorithms();

            Assert.NotEmpty(supportedAlgorithms);
        }


        [SkipTpmTestOnCiFact]
        public void CalculateShortSha256()
        {
            const string TestStringToBeHashed = "Hello, SHA-256 world!";
            ReadOnlySpan<byte> controlValue = Encoding.UTF8.GetBytes(TestStringToBeHashed);
            byte[] controlValueHash = SHA256.HashData(controlValue);

            byte[]? tpmSha256 = Verifiable.Tpm.Tpm.CalculateSha256(TestStringToBeHashed);

            Assert.Equal(controlValueHash, tpmSha256);
        }


        [Fact(Skip = "Sketch. Does not work.")]
        public void CalculateLongSha256()
        {
            //TODO: The array to be hashed is of constant value while developing
            //on purpose.
            byte[] longByteArray = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 4, 5};
                                    
            byte[] longControlValueHash = SHA256.HashData(longByteArray);
            byte[]? longTpmSha256 = Verifiable.Tpm.Tpm.CalculateLongSha256(longByteArray);

            Assert.Equal(longControlValueHash, longTpmSha256);
        }
    }
}
