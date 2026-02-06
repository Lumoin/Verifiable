using Verifiable.Core.Assessment;
using Verifiable.JCose;
using Verifiable.Jose;

namespace Verifiable.Tests.Jwt
{
    [TestClass]
    internal sealed class JwtKeyHeaderValidatorTests
    {
        //TODO: Put these to JsonWebKey2020?
        private static readonly List<(Func<string, bool> IsAlg, Func<string, bool> IsCrv)> ValidAlgCrvPairs = new()
        {
            (WellKnownJwaValues.IsEs256, WellKnownCurveValues.IsP256),
            (WellKnownJwaValues.IsEs384, WellKnownCurveValues.IsP384),
            (WellKnownJwaValues.IsEs256k1, WellKnownCurveValues.IsSecp256k1)
        };

        
        [TestMethod]
        public void ValidKeyHeaderWithAlgRequired()
        {
            var testHeaders1 = new Dictionary<string, object>
            {
                { JwkProperties.Kty,  WellKnownKeyTypeValues.Ec},
                { JwkProperties.Alg, WellKnownJwaValues.Es256 },
                { JwkProperties.Crv, WellKnownCurveValues.P256 },
                { JwkProperties.X, "abc" },
                { JwkProperties.Y, "abc" }
            };

            var result = JwtKeyTypeHeaderValidationUtilities.ValidateEc(testHeaders1, ValidAlgCrvPairs, isEcAlgRequired: true);
            Assert.IsNotNull(result);
            Assert.IsTrue(result.All(c => c.Outcome == ClaimOutcome.Success));
        }


        [TestMethod]
        public void ValidKeyHeaderWithAlgNotRequired()
        {
            var testHeaders1 = new Dictionary<string, object>
            {
                { JwkProperties.Kty,  WellKnownKeyTypeValues.Ec},
                { JwkProperties.Alg, WellKnownJwaValues.Es256 },
                { JwkProperties.Crv, WellKnownCurveValues.P256 },
                { JwkProperties.X, "abc" },
                { JwkProperties.Y, "abc" }
            };

            var result = JwtKeyTypeHeaderValidationUtilities.ValidateEc(testHeaders1, ValidAlgCrvPairs, isEcAlgRequired: false);
            Assert.IsNotNull(result);
            Assert.IsTrue(result.All(c => c.Outcome == ClaimOutcome.Success));
        }


        [TestMethod]
        public void ValidKeyHeaderWithYMissing()
        {
            var testHeaders1 = new Dictionary<string, object>
            {
                { JwkProperties.Kty,  WellKnownKeyTypeValues.Ec},
                { JwkProperties.Alg, WellKnownJwaValues.Es256 },
                { JwkProperties.Crv, WellKnownCurveValues.P256 },
                { JwkProperties.X, "abc" }
            };

            var result = JwtKeyTypeHeaderValidationUtilities.ValidateEc(testHeaders1, ValidAlgCrvPairs, isEcAlgRequired: false);
            Assert.IsNotNull(result);
            Assert.IsFalse(result.All(c => c.Outcome == ClaimOutcome.Success));
        }


        [TestMethod]
        public void ValidKeyHeaderWithXMissing()
        {
            var testHeaders1 = new Dictionary<string, object>
            {
                { JwkProperties.Kty,  WellKnownKeyTypeValues.Ec},
                { JwkProperties.Alg, WellKnownJwaValues.Es256 },
                { JwkProperties.Crv, WellKnownCurveValues.P256 },
                { JwkProperties.Y, "abc" }
            };

            var result = JwtKeyTypeHeaderValidationUtilities.ValidateEc(testHeaders1, ValidAlgCrvPairs, isEcAlgRequired: false);
            Assert.IsNotNull(result);
            Assert.IsFalse(result.All(c => c.Outcome == ClaimOutcome.Success));
        }


        [TestMethod]
        public void ValidKeyHeaderWithAlgPresentNotMatchingCrv()
        {
            var testHeaders1 = new Dictionary<string, object>
            {
                { JwkProperties.Kty,  WellKnownKeyTypeValues.Ec},
                { JwkProperties.Alg, WellKnownJwaValues.Es256 },
                { JwkProperties.Crv, WellKnownCurveValues.P384 },
                { JwkProperties.Y, "abc" }
            };

            var result = JwtKeyTypeHeaderValidationUtilities.ValidateEc(testHeaders1, ValidAlgCrvPairs, isEcAlgRequired: false);
            Assert.IsNotNull(result);
            Assert.IsFalse(result.All(c => c.Outcome == ClaimOutcome.Success));
        }


        [TestMethod]
        public void ValidKeyHeaderWithInvalidCurve()
        {
            var testHeaders1 = new Dictionary<string, object>
            {
                { JwkProperties.Kty,  WellKnownKeyTypeValues.Ec},
                { JwkProperties.Alg, WellKnownJwaValues.Es512 },
                { JwkProperties.Crv, WellKnownCurveValues.P521 },
                { JwkProperties.Y, "abc" }
            };

            var result = JwtKeyTypeHeaderValidationUtilities.ValidateEc(testHeaders1, ValidAlgCrvPairs, isEcAlgRequired: false);
            Assert.IsNotNull(result);
            Assert.IsFalse(result.All(c => c.Outcome == ClaimOutcome.Success));
        }
    }
}
