using System;
using Tpm2Lib;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Xunit;


namespace Verifiable.Tests.Tpm
{
    /// <summary>
    /// Quick test container TPM check for tests...
    /// </summary>
    public class TpmTests: IDisposable
    {
        private TpmWrapper TpmWrapper { get; }


        public TpmTests()
        {          
            //The CI pipeline installs TPM libraries on Linux...
            TpmWrapper = new TpmWrapper();
        }


        /// <summary>
        /// Checks that calling supported TPM platforms does not throw.
        /// </summary>
        [SkipTpmTestOnCiFact]
        public void TpmIsPlatformSupported()
        {
            _ = TpmExtensions.IsTpmPlatformSupported();
        }


        [SkipTpmTestOnCiFact]
        public void TpmGetPropertiesSucceeds()
        {
            var tpmInfo = TpmWrapper.Tpm.GetAllTpmInfo();

            //A sampling of properties are checked here against known values.
            Assert.True(!string.IsNullOrWhiteSpace(tpmInfo.Properties.VendorString));
            Assert.True(!string.IsNullOrWhiteSpace(tpmInfo.Properties.ManufacturerName));
            Assert.True(tpmInfo.Properties.IsFips1402);
            Assert.True(tpmInfo.PrcBanks.Count > 0);
        }


        [SkipTpmTestOnCiFact]
        public void TpmGetPcrBanksSucceeds()
        {
            var pcrBanks = TpmWrapper.Tpm.GetPcrBanks();

            Assert.True(pcrBanks.Count > 0, "There should be one or more banks after querying the TPM.");
            foreach(var pcrBank in pcrBanks)
            {
                Assert.True(TpmValidator.IsValidBank(pcrBank), "One or more of the buffer lengths in the PCR bank length did not match the bank algorithm.");
            }
        }

        [SkipTpmTestOnCiFact]
        public void HashCheck()
        {

            TkHashcheck validation;
            byte[] hashData = TpmWrapper.Tpm.Hash(new byte[] { 1, 2, 3 },   // Data to hash
                                       TpmAlgId.Sha256,          // Hash algorithm
                                       TpmRh.Owner,              // Hierarchy for ticket (not used here)
                                       out validation);          // Ticket (not used in this example)
            Console.WriteLine("Hashed data (Hash): " + BitConverter.ToString(hashData));

        }


        /// <inheritdoc />
        public void Dispose()
        {
            TpmWrapper?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
