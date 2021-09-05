using System.Diagnostics;

namespace Verifiable.Tpm
{
    /// <summary>
    /// The Platform Configuration Register (PCR) bank of values on a given algorithm.
    /// </summary>
    /// <param name="Algorithm">The Trusted Platform Module (TPM) supported algorithm.</param>
    /// <param name="BankData">The PCR bank data.</param>
    /// <remarks>See more at <see href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">Trusted Platform Module Library Part 2: Structures [pdf]</see>.</remarks>
    [DebuggerDisplay("Algorithm = {Algorithm,nq}")]
    public record PcrBank(string Algorithm, IReadOnlyCollection<PcrData> BankData)
    {
        /// <summary>
        /// This is the same as <see cref="SupportedAlgorithm"/>, refactor...
        /// </summary>
        public string Algorithm { get; init; } = Guard.NotNull(Algorithm, nameof(Algorithm));

        /// <summary>
        /// The PCR bank data.
        /// </summary>
        public IReadOnlyCollection<PcrData> BankData { get; init; } = Guard.NotNull(BankData, nameof(BankData));
    }
}
