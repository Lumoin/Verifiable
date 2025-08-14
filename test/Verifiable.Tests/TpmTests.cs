using Tpm2Lib;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;


namespace Verifiable.Tests.Tpm
{
    /// <summary>
    /// Quick test container TPM check for tests...
    /// </summary>
    [TestClass]
    public sealed class TpmTests: IDisposable
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
        [SkipOnCiTestMethod]
        public void TpmIsPlatformSupported()
        {
            _ = TpmExtensions.IsTpmPlatformSupported();
        }


        [SkipOnCiTestMethod]
        public void TpmGetPropertiesSucceeds()
        {
            var tpmInfo = TpmWrapper.Tpm.GetAllTpmInfo();

            //A sampling of properties are checked here against known values.
            Assert.IsFalse(string.IsNullOrWhiteSpace(tpmInfo.Properties.VendorString));
            Assert.IsFalse(string.IsNullOrWhiteSpace(tpmInfo.Properties.ManufacturerName));
            Assert.IsTrue(tpmInfo.Properties.IsFips1402);
            Assert.IsGreaterThan(0, tpmInfo.PrcBanks.Count);
        }


        [SkipOnCiTestMethod]
        public void TpmGetPcrBanksSucceeds()
        {
            var pcrBanks = TpmWrapper.Tpm.GetPcrBanks();

            Assert.IsGreaterThan(0, pcrBanks.Count, "There should be one or more banks after querying the TPM.");
            foreach(var pcrBank in pcrBanks)
            {
                Assert.IsTrue(TpmValidator.IsValidBank(pcrBank), "One or more of the buffer lengths in the PCR bank length did not match the bank algorithm.");
            }
        }

        [SkipOnCiTestMethod]
        public void HashCheck()
        {
            byte[] hashData = TpmWrapper.Tpm.Hash([1, 2, 3],   // Data to hash
                                       TpmAlgId.Sha256,          // Hash algorithm
                                       TpmRh.Owner,              // Hierarchy for ticket (not used here)
                                       out TkHashcheck validation);          // Ticket (not used in this example)
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
