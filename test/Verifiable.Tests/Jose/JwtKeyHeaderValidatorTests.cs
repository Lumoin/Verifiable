using Verifiable.Core.Assessment;
using Verifiable.Core.Validation;
using Verifiable.JCose;

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
            (WellKnownJwaValues.IsEs256K, WellKnownCurveValues.IsSecp256k1)
        };

        
        [TestMethod]
        public void ValidKeyHeaderWithAlgRequired()
        {
            var testHeaders1 = new Dictionary<string, object>
            {
                { WellKnownJwkMemberNames.Kty,  WellKnownKeyTypeValues.Ec},
                { WellKnownJwkMemberNames.Alg, WellKnownJwaValues.Es256 },
                { WellKnownJwkMemberNames.Crv, WellKnownCurveValues.P256 },
                { WellKnownJwkMemberNames.X, "abc" },
                { WellKnownJwkMemberNames.Y, "abc" }
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
                { WellKnownJwkMemberNames.Kty,  WellKnownKeyTypeValues.Ec},
                { WellKnownJwkMemberNames.Alg, WellKnownJwaValues.Es256 },
                { WellKnownJwkMemberNames.Crv, WellKnownCurveValues.P256 },
                { WellKnownJwkMemberNames.X, "abc" },
                { WellKnownJwkMemberNames.Y, "abc" }
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
                { WellKnownJwkMemberNames.Kty,  WellKnownKeyTypeValues.Ec},
                { WellKnownJwkMemberNames.Alg, WellKnownJwaValues.Es256 },
                { WellKnownJwkMemberNames.Crv, WellKnownCurveValues.P256 },
                { WellKnownJwkMemberNames.X, "abc" }
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
                { WellKnownJwkMemberNames.Kty,  WellKnownKeyTypeValues.Ec},
                { WellKnownJwkMemberNames.Alg, WellKnownJwaValues.Es256 },
                { WellKnownJwkMemberNames.Crv, WellKnownCurveValues.P256 },
                { WellKnownJwkMemberNames.Y, "abc" }
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
                { WellKnownJwkMemberNames.Kty,  WellKnownKeyTypeValues.Ec},
                { WellKnownJwkMemberNames.Alg, WellKnownJwaValues.Es256 },
                { WellKnownJwkMemberNames.Crv, WellKnownCurveValues.P384 },
                { WellKnownJwkMemberNames.Y, "abc" }
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
                { WellKnownJwkMemberNames.Kty,  WellKnownKeyTypeValues.Ec},
                { WellKnownJwkMemberNames.Alg, WellKnownJwaValues.Es512 },
                { WellKnownJwkMemberNames.Crv, WellKnownCurveValues.P521 },
                { WellKnownJwkMemberNames.Y, "abc" }
            };

            var result = JwtKeyTypeHeaderValidationUtilities.ValidateEc(testHeaders1, ValidAlgCrvPairs, isEcAlgRequired: false);
            Assert.IsNotNull(result);
            Assert.IsFalse(result.All(c => c.Outcome == ClaimOutcome.Success));
        }
    }
}
