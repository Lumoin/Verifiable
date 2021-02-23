namespace DotDecentralized.Core.Cryptography
{
    /// <summary>
    /// A collection of well known OIDs. See more at <a href="http://www.oid-info.com/">OID Repository</a>
    /// </summary>
    public static class WellKnownOids
    {
        /// <summary>
        /// See more at <a href="http://www.oid-info.com/cgi-bin/display?oid=1.3.6.1.4.1.11591.15.1&action=display">Ed25519 curve</a>.
        /// </summary>
        public const string Ed25519 = "1.3.6.1.4.1.11591.15.1";

        /// <summary>
        /// See more at <a href="http://www.oid-info.com/cgi-bin/display?oid=1.3.101.112&action=display">Edwards-curve Digital Signature Algorithm (EdDSA) Ed25519</a>.
        /// </summary>
        public const string EdDSA25519 = "1.3.101.112";
    }
}
