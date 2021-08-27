using System.Diagnostics;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// https://www.w3.org/TR/did-core/#dfn-publickeyjwk, https://tools.ietf.org/html/rfc7517
    /// </summary>
    /// <remarks>Note that must not contain private key information, such as 'd' field,
    /// by DID Core specification.</remarks>
    [DebuggerDisplay("PublicKeyJwk(Crv = {Crv}, Kid = {Kid}, Kty = {Kty}, X = {X}, Y = {Y}, E = {E}, N = {N})")]
    public class PublicKeyJwk: KeyFormat
    {
        public string? Crv { get; set; }

        public string? Kid { get; set; }

        public string? Kty { get; set; }

        public string? X { get; set; }

        public string? Y { get; set; }

        //'E' and 'N' are for the RSA keys as per RFC 7517.
        public string? E { get; set; }

        public string? N { get; set; }
    }
}
