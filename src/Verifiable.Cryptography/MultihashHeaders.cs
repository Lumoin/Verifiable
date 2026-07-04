namespace Verifiable.Cryptography
{
    /// <summary>
    /// https://www.w3.org/TR/cid-1.0/#multihash
    /// </summary>
    public static class MultihashHeaders
    {
        /// <summary>
        /// This is a special value that is used to indicate that no multihash header is present.
        /// </summary>
        public static ReadOnlySpan<byte> None => [];

        /// <summary>
        /// BLAKE3 (256-bit output), multihash code <c>0x1e</c>. The did:webplus default hash function,
        /// and a common digest across the KERI/ACDC suite.
        /// </summary>
        public static ReadOnlySpan<byte> Blake3 => [0x1e];

        /// <summary>
        /// .
        /// </summary>
        /// <remarks>.</remarks>
        public static ReadOnlySpan<byte> Sha2Bits256 => [0x12];

        /// <summary>
        /// .
        /// </summary>
        /// <remarks>.</remarks>
        public static ReadOnlySpan<byte> Sha2384 => [0x20];

        /// <summary>
        /// .
        /// </summary>
        /// <remarks>.</remarks>
        public static ReadOnlySpan<byte> Sha3256 => [0x16];

        /// <summary>
        /// .
        /// </summary>
        /// <remarks>.</remarks>
        public static ReadOnlySpan<byte> Sha3384 => [0x15];
    }
}
