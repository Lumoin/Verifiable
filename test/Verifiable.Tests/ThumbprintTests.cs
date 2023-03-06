using Verifiable.Jwt;
using Xunit;

namespace Verifiable.Core
{
    /// <summary>
    /// Tests for JoseUtilities.*Thumbprint calculations.
    /// </summary>
    public class ThumbprintTests
    {
        [Fact(Skip = "Work in progress.")]
        public void ECNistP256()
        {
            var crv = "P-256";
            var kty = "EC";
            var x = "x";
            var y = "y";            
            var thumbPrintBytes = JoseUtilities.ComputeECThumbprint(crv, kty, x, y);
            var thumbprint = Base64Url.Encode(thumbPrintBytes);
            var expected = "expected";
            Assert.Equal(expected, thumbprint);
        }
    }
}
