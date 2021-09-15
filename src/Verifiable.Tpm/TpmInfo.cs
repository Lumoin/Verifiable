using System.Collections.Generic;

namespace Verifiable.Tpm
{
    /// <summary>
    /// All TPM information that can be extracted.
    /// </summary>
    /// <param name="Properties">The TPM properties.</param>
    /// <param name="PrcBanks">TPM PCR buffer contents.</param>
    public record TpmInfo(TpmProperties Properties, IReadOnlyCollection<PcrBank> PrcBanks)
    {
        /// <summary>
        /// The TPM properties.
        /// </summary>
        public TpmProperties Properties { get; init; } = Guard.NotNull(Properties, nameof(Properties));

        /// <summary>
        /// The PCR banks data.
        /// </summary>
        public IReadOnlyCollection<PcrBank> PcrBanks { get; init; } = Guard.NotNull(PrcBanks, nameof(PrcBanks));
    }
}
