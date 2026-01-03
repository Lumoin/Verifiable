using Verifiable.Core.Cryptography;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography
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
            using var thumbPrintBytes = JoseUtilities.ComputeECThumbprint(crv, kty, x, y);
            var thumbprint = TestSetup.Base64UrlEncoder(thumbPrintBytes.Memory.Span);
            var expected = "expected";
            Assert.AreEqual(expected, thumbprint);
        }
    }
}