using System;
using System.Runtime.InteropServices;
using Verifiable.Tpm;
using Xunit;


namespace Verifiable.Tests
{
    /// <summary>
    /// Quick test container TPM check for tests...
    /// </summary>
    public class TpmTests: IDisposable
    {
        private TpmWrapper TpmWrapper { get; }

        public TpmTests()
        {
            string? usePlatformTpmString = Environment.GetEnvironmentVariable("USE_PLATFORM_TPM");
            string? dotNetPlatformString = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");

            bool usePlatformTpm = string.IsNullOrWhiteSpace(usePlatformTpmString) && bool.TryParse(usePlatformTpmString, out usePlatformTpm);
            bool isCiEnvironment = dotNetPlatformString?.Equals("ci", StringComparison.InvariantCultureIgnoreCase) == true;

            //It is not possible to test TPM functionality at all unless on supported platforms.
            Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux),
                $"Trust Platform Module (TPM) 2.0 is supported only on {OSPlatform.Windows} and {OSPlatform.Linux}.");

            //CI TPM tests skipped until an emulator or a platform can be used.
            Skip.If(isCiEnvironment);

            //Local builds are currently possible only on simulator and Windows.
            //CI builds are done using TPM, but currently it works only on Linux.
            //TODO: Add simulator for local Linux builds too. Running on physical TPM may cause unexpected
            //systemwide problems. Only test platform TPMs on CI as the environments can be thrown away.
            Skip.If(
                /* This first condition checks if this is a CI environment. Skip if parameters are not set correctly. */
                (!usePlatformTpm && isCiEnvironment && !RuntimeInformation.IsOSPlatform(OSPlatform.Linux))

                /* And this one if this this is a local Windows environment with simulator. */
                || (!isCiEnvironment && !usePlatformTpm && !RuntimeInformation.IsOSPlatform(OSPlatform.Windows)),
                $"Trust Platform Module (TPM) 2.0 on continuous environment is supported only on {OSPlatform.Linux}.");

            //TODO: Linux simulator for local runs should be added and something like runSettings that makes it
            //easy enough to choose where to run (messing with hardware TPM can cause trouble, so can't be
            //used by default).
            if(!usePlatformTpm && !isCiEnvironment && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                TpmWrapper = new TpmSimulatorWrapper();
            }
            else
            {
                //The CI pipeline installs TPM libraries on Linux...
                TpmWrapper = new TpmWrapper();
            }
        }


        /// <summary>
        /// Checks that calling supported TPM platforms does not throw.
        /// </summary>
        [SkippableFact]
        public void TpmIsPlatformSupported()
        {
            _ = TpmExtensions.IsTpmPlatformSupported();
        }

                
        [SkippableFact]
        public void TpmGetPropertiesSucceeds()
        {
            var tpmInfo = TpmWrapper.Tpm.GetAllTpmInfo();

            //A sampling of properties are checked here against known values.
            Assert.True(!string.IsNullOrWhiteSpace(tpmInfo.Properties.VendorString));
            Assert.True(!string.IsNullOrWhiteSpace(tpmInfo.Properties.ManufacturerName));
            Assert.True(tpmInfo.Properties.IsFips1402);
            Assert.True(tpmInfo.PrcBanks.Count > 0);
        }


        [SkippableFact]
        public void TpmGetPcrBanksSucceeds()
        {
            var pcrBanks = TpmWrapper.Tpm.GetPcrBanks();

            Assert.True(pcrBanks.Count > 0, "There should be one or more banks after querying the TPM.");
            foreach(var pcrBank in pcrBanks)
            {
                Assert.True(TpmValidator.IsValidBank(pcrBank), "One or more of the buffer lengths in the PCR bank length did not match the bank algorithm.");
            }
        }


        /// <inheritdoc />
        public void Dispose()
        {
            TpmWrapper?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
