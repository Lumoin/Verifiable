using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.Tpm
{
    /// <summary>
    /// The Platform Configuration Register (PCR) value in a given index.
    /// </summary>
    /// <param name="Index">The PCR index.</param>
    /// <param name="Data">The PCR buffer value.</param>
    /// <remarks>See more at <see href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">Trusted Platform Module Library Part 2: Structures [pdf]</see>.</remarks>    
    [DebuggerDisplay("PcrData(Index = {Index}, Data = {System.BitConverter.ToString(Data.AsSpan().ToArray()),nq})")]
    public record PcrData(uint Index, ImmutableArray<byte> Data)
    {
        /// <summary>
        /// The PCR index.
        /// </summary>
        public uint Index { get; init; } = Index;

        /// <summary>
        /// The PCR buffer value.
        /// </summary>
        public ImmutableArray<byte> Data { get; init; } = Guard.NotNull(Data, nameof(Data));
    }
}
