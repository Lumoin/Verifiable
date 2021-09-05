namespace Verifiable.Tpm
{
    public record TpmData(string Algorithm, int BankLength)
    {
        public string Algorithm { get; init; } = Algorithm;

        public int BankLength { get; init; } = BankLength;
    }


    public static class TpmConstants
    {
        public static TpmData Sha { get; } = new TpmData("Sha", 20);

        public static TpmData Sha256 { get; } = new TpmData("Sha256", 32);

        public static TpmData Sha384 { get; } = new TpmData("Sha384", 48);

        public static TpmData Sma3256 { get; } = new TpmData("Sm3256", 32);

        public static IReadOnlyCollection<TpmData> TpmDatas { get; } = new List<TpmData>(new[] { Sha, Sha256, Sha384, Sma3256 }).AsReadOnly();
    }
    

    /// <summary>
    /// Functions to check TPM values are valid.
    /// </summary>
    public static class TpmValidator
    {
        /// <summary>
        /// Checks if given <see cref="PcrBank"/> buffer lengths match the <see cref="PcrBank.Algorithm"/>.
        /// </summary>
        /// <param name="bank">The PCR bank to check.</param>
        /// <returns><see langword="True"/> if the check succeeds. <see langword="False"/> otherwise.</returns>
        public static bool IsValidBank(PcrBank bank)
        {
            static bool IsValidBank(PcrBank bank, int bankLength)
            {
                return bank.BankData.All(bankData => bankData.Data.Length == bankLength);
            }

            if(bank.Algorithm.Equals(TpmConstants.Sha.Algorithm, StringComparison.OrdinalIgnoreCase))
            {
                return IsValidBank(bank, TpmConstants.Sha.BankLength);
            }
            else if(bank.Algorithm.Equals(TpmConstants.Sha256.Algorithm, StringComparison.OrdinalIgnoreCase))
            {
                return IsValidBank(bank, TpmConstants.Sha256.BankLength);
            }
            else if(bank.Algorithm.Equals(TpmConstants.Sha384.Algorithm, StringComparison.OrdinalIgnoreCase))
            {
                return IsValidBank(bank, TpmConstants.Sha384.BankLength);
            }
            else if(bank.Algorithm.Equals(TpmConstants.Sma3256.Algorithm, StringComparison.OrdinalIgnoreCase))
            {
                return IsValidBank(bank, TpmConstants.Sma3256.BankLength);
            }

            return false;
        }
    }
}
