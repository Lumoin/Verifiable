using System.Security.Cryptography;
using System.Text;


namespace Verifiable.Jwt
{
    /// <summary>
    /// Xyz.
    /// </summary>
    public static class JoseUtilities
    {                
        //The rules are from https://datatracker.ietf.org/doc/html/rfc7638#section-3.1.
        
        private static string ECTThumbprintTemplate => $@"{{{{""{JwkProperties.Crv}"":""{{0}}"",""{JwkProperties.Kty}"":""{{1}}"",""{JwkProperties.X}"":""{{2}}"",""{JwkProperties.Y}"":""{{3}}""}}}}";

        //https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.3
        private static string EcdhTemplate => $@"{{{{""{JwkProperties.Crv}"":""{{0}}"",""{JwkProperties.Kty}"":""{{1}}"",""{JwkProperties.X}"":""{{2}}""}}}}";

        private static string EdDsaTemplate => $@"{{{{""{JwkProperties.Crv}"":""{{0}}"",""{JwkProperties.Kty}"":""{{1}}"",""{JwkProperties.X}"":""{{2}}""}}}}";

        private static string RsaThumbprintTemplate => $@"{{{{""{JwkProperties.E}"":""{{0}}"",""{JwkProperties.Kty}"":""{{1}}"",""{JwkProperties.N}"":""{{2}}""}}}}";

        private static string OctThumbprintTemplate => $@"{{{{""{JwkProperties.K}"":""{{0}}"",""{JwkProperties.Kty}"":"" {{1}}""}}}}";
        

        public static byte[] ComputeECThumbprint(string crv, string kty, string x, string y)
        {
            var canonicalJwk = string.Format(ECTThumbprintTemplate, crv, kty, x, y);
            return GenerateSha256Hash(Encoding.UTF8.GetBytes(canonicalJwk));
        }


        public static byte[] ComputeEcdhThumbprint(string crv, string kty, string x)
        {
            //TODO: The parameters can be checked here too.
            var canonicalJwk = string.Format(EcdhTemplate, crv, kty, x);
            return GenerateSha256Hash(Encoding.UTF8.GetBytes(canonicalJwk));
        }


        public static byte[] ComputeEdDsaThumbprint(string crv, string kty, string x)
        {
            var canonicalJwk = string.Format(EdDsaTemplate, crv, kty, x);
            return GenerateSha256Hash(Encoding.UTF8.GetBytes(canonicalJwk));
        }


        public static byte[] ComputeRsaThumbprint(string e, string kty, string n)
        {
            var canonicalJwk = string.Format(RsaThumbprintTemplate, e, kty, n);
            return GenerateSha256Hash(Encoding.UTF8.GetBytes(canonicalJwk));
        }


        public static byte[] ComputeOctThumbprint(string k, string kty)
        {
            var canonicalJwk = string.Format(OctThumbprintTemplate, k, kty);
            return GenerateSha256Hash(Encoding.UTF8.GetBytes(canonicalJwk));
        }
        
                
        private static byte[] GenerateSha256Hash(ReadOnlySpan<byte> input)
        {            
            return SHA256.HashData(input);
        }
    }
}
