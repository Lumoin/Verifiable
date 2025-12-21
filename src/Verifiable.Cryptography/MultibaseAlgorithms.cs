namespace Verifiable.Cryptography
{
    /// <summary>
    /// Multibase algorithm identifiers. See more at <see href="https://datatracker.ietf.org/doc/html/draft-multiformats-multibase">
    /// The Multibase Data Format draft-multiformats-multibase-05</see>.
    /// </summary>
    public static class MultibaseAlgorithms
    {
        /// <summary>
        /// Identity. 8-bit binary (encoder and decoder keeps data unmodified).
        /// </summary>
        /// <remarks>Status: active.</remarks>
        public static readonly char Identity = (char)0x00;

        /// <summary>
        /// Base 2.
        /// </summary>
        /// <example>01010101.</example>
        /// <remarks>Status: active.</remarks>
        public static readonly char Binary = '0';

        /// <summary>
        /// Base58 Bitcoin.
        /// </summary>
        /// <remarks>Status: active.</remarks>
        public static readonly char Base58Btc = 'z';

        /// <summary>
        /// Base64. No padding.
        /// </summary>
        /// <remarks>Status: active.</remarks>
        public static readonly char Base64 = 'm';
    }
}
