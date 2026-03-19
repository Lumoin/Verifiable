using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jose
{
    /// <summary>
    /// Tests that canonicalization of JWK properies algorithms works correctly.
    /// </summary>
    [TestClass]
    internal sealed class WellKnownJwkValuesTests
    {
        /// <summary>
        /// All of the well-known JWE algorithms should be recognized.
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<object[]> GetJwkProperties()
        {
            yield return new object[] { WellKnownJwkValues.Acr, new Func<string, bool>(WellKnownJwkValues.IsAcr) };
            yield return new object[] { WellKnownJwkValues.Amr, new Func<string, bool>(WellKnownJwkValues.IsAmr) };
            yield return new object[] { WellKnownJwkValues.Aud, new Func<string, bool>(WellKnownJwkValues.IsAud) };
            yield return new object[] { WellKnownJwkValues.Azp, new Func<string, bool>(WellKnownJwkValues.IsAzp) };
            yield return new object[] { WellKnownJwkValues.Crv, new Func<string, bool>(WellKnownJwkValues.IsCrv) };
            yield return new object[] { WellKnownJwkValues.D, new Func<string, bool>(WellKnownJwkValues.IsD) };
            yield return new object[] { WellKnownJwkValues.Dp, new Func<string, bool>(WellKnownJwkValues.IsDp) };
            yield return new object[] { WellKnownJwkValues.Dq, new Func<string, bool>(WellKnownJwkValues.IsDq) };
            yield return new object[] { WellKnownJwkValues.E, new Func<string, bool>(WellKnownJwkValues.IsE) };
            yield return new object[] { WellKnownJwkValues.Exp, new Func<string, bool>(WellKnownJwkValues.IsExp) };
            yield return new object[] { WellKnownJwkValues.Iat, new Func<string, bool>(WellKnownJwkValues.IsIat) };
            yield return new object[] { WellKnownJwkValues.Iss, new Func<string, bool>(WellKnownJwkValues.IsIss) };
            yield return new object[] { WellKnownJwkValues.Jti, new Func<string, bool>(WellKnownJwkValues.IsJti) };
            yield return new object[] { WellKnownJwkValues.K, new Func<string, bool>(WellKnownJwkValues.IsK) };
            yield return new object[] { WellKnownJwkValues.Kty, new Func<string, bool>(WellKnownJwkValues.IsKty) };
            yield return new object[] { WellKnownJwkValues.Use, new Func<string, bool>(WellKnownJwkValues.IsUse) };
            yield return new object[] { WellKnownJwkValues.KeyOps, new Func<string, bool>(WellKnownJwkValues.IsKeyOps) };
            yield return new object[] { WellKnownJwkValues.Alg, new Func<string, bool>(WellKnownJwkValues.IsAlg) };
            yield return new object[] { WellKnownJwkValues.Kid, new Func<string, bool>(WellKnownJwkValues.IsKid) };
            yield return new object[] { WellKnownJwkValues.X5u, new Func<string, bool>(WellKnownJwkValues.IsX5u) };
            yield return new object[] { WellKnownJwkValues.X5c, new Func<string, bool>(WellKnownJwkValues.IsX5c) };
            yield return new object[] { WellKnownJwkValues.X5t, new Func<string, bool>(WellKnownJwkValues.IsX5t) };
            yield return new object[] { WellKnownJwkValues.X5tHashS256, new Func<string, bool>(WellKnownJwkValues.IsX5tHashS256) };
            yield return new object[] { WellKnownJwkValues.Typ, new Func<string, bool>(WellKnownJwkValues.IsTyp) };
            yield return new object[] { WellKnownJwkValues.Cty, new Func<string, bool>(WellKnownJwkValues.IsCty) };
            yield return new object[] { WellKnownJwkValues.N, new Func<string, bool>(WellKnownJwkValues.IsN) };
            yield return new object[] { WellKnownJwkValues.Nbf, new Func<string, bool>(WellKnownJwkValues.IsNbf) };
            yield return new object[] { WellKnownJwkValues.P, new Func<string, bool>(WellKnownJwkValues.IsP) };
            yield return new object[] { WellKnownJwkValues.Q, new Func<string, bool>(WellKnownJwkValues.IsQ) };
            yield return new object[] { WellKnownJwkValues.Qi, new Func<string, bool>(WellKnownJwkValues.IsQi) };
            yield return new object[] { WellKnownJwkValues.Roles, new Func<string, bool>(WellKnownJwkValues.IsRoles) };
            yield return new object[] { WellKnownJwkValues.Sub, new Func<string, bool>(WellKnownJwkValues.IsSub) };
            yield return new object[] { WellKnownJwkValues.Tenant, new Func<string, bool>(WellKnownJwkValues.IsTenant) };
            yield return new object[] { WellKnownJwkValues.X, new Func<string, bool>(WellKnownJwkValues.IsX) };
            yield return new object[] { WellKnownJwkValues.Y, new Func<string, bool>(WellKnownJwkValues.IsY) };
        }


        /// <summary>
        /// Tests that all well-known JWK properies algorithm values are recognized correctly.
        /// </summary>
        /// <param name="correctAlgorithm">The correct to be used in test.</param>
        /// <param name="isCorrectAlgorithm">The function that checks if the algorithm is recognized.</param>
        [TestMethod]
        [DynamicData(nameof(GetJwkProperties))]
        public void JwaAlgorithmComparesCorrectly(string correctAlgorithm, Func<string, bool> isCorrectAlgorithm)
        {
            //A newly created instance should not reference the canonicalized version.
            //This means a different version even with the same case will not reference
            //the same object. This is a a premise check for the implementation of the
            //JwkProperties.GetCanonicalizedValue that relies on this optimization
            //to avoid comparing the actual strings if the references are the same.
            string instanceAlgorithm = new(correctAlgorithm);
            Assert.IsFalse(object.ReferenceEquals(correctAlgorithm, instanceAlgorithm), "Instance created from canonical should not reference equal to it.");

            //The correct algorithm should be correctly identified even if it's not the canonicalized version.
            //This is a premise check for the WellKnownJweAlgorithms.GetCanonicalizedValue, now the
            //comparison is done with the actual strings.
            Assert.IsTrue(isCorrectAlgorithm(instanceAlgorithm), "Is<SomeAlgorithm> should compare correctly to canonicalized version even if instance.");

            //The canonicalized version should be the same as the original.
            string canonicalizedVersion = WellKnownJwkValues.GetCanonicalizedValue(instanceAlgorithm);
            Assert.IsTrue(object.ReferenceEquals(correctAlgorithm, canonicalizedVersion), "Canonicalized version should be the same as original.");

            //A case with a toggled letter should not be the same since it's both a different string
            //and a different reference.
            string incorrectAlgorithm = instanceAlgorithm.ToggleCaseForLetterAt(0);
            Assert.IsFalse(isCorrectAlgorithm(incorrectAlgorithm), "Comparison should fail when casing is changed.");
        }
    }
}
