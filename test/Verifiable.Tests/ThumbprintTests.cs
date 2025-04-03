using Verifiable.Jwt;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Core
{
    /// <summary>
    /// Tests for JoseUtilities.*Thumbprint calculations.
    /// </summary>
    [TestClass]
    public sealed class ThumbprintTests
    {
        [TestMethod]
        [Ignore("Work in progress.")]
        public void ECNistP256()
        {
            var crv = "P-256";
            var kty = "EC";
            var x = "x";
            var y = "y";            
            var thumbPrintBytes = JoseUtilities.ComputeECThumbprint(crv, kty, x, y);
            var thumbprint = Base64Url.Encode(thumbPrintBytes);
            var expected = "expected";
            Assert.AreEqual(expected, thumbprint);
        }
    }
}
