using System;
using System.Collections.Generic;
using Verifiable.Jwt;
using Verifiable.Tests.TestInfrastructure;
using Xunit;

namespace Verifiable.Tests.Jwt
{
    /// <summary>
    /// Tests that canonicalization of JWK properies algorithms works correctly.
    /// </summary>
    public class JwkPropertiesTests
    {
        /// <summary>
        /// All of the well-known JWE algorithms should be recognized.
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<object[]> GetJwkProperties()
        {
            yield return new object[] { JwkProperties.Acr, new Func<string, bool>(JwkProperties.IsAcr) };
            yield return new object[] { JwkProperties.Amr, new Func<string, bool>(JwkProperties.IsAmr) };
            yield return new object[] { JwkProperties.Aud, new Func<string, bool>(JwkProperties.IsAud) };
            yield return new object[] { JwkProperties.Azp, new Func<string, bool>(JwkProperties.IsAzp) };
            yield return new object[] { JwkProperties.Crv, new Func<string, bool>(JwkProperties.IsCrv) };
            yield return new object[] { JwkProperties.D, new Func<string, bool>(JwkProperties.IsD) };
            yield return new object[] { JwkProperties.Dp, new Func<string, bool>(JwkProperties.IsDp) };
            yield return new object[] { JwkProperties.Dq, new Func<string, bool>(JwkProperties.IsDq) };
            yield return new object[] { JwkProperties.E, new Func<string, bool>(JwkProperties.IsE) };
            yield return new object[] { JwkProperties.Exp, new Func<string, bool>(JwkProperties.IsExp) };
            yield return new object[] { JwkProperties.Iat, new Func<string, bool>(JwkProperties.IsIat) };
            yield return new object[] { JwkProperties.Iss, new Func<string, bool>(JwkProperties.IsIss) };
            yield return new object[] { JwkProperties.Jti, new Func<string, bool>(JwkProperties.IsJti) };
            yield return new object[] { JwkProperties.K, new Func<string, bool>(JwkProperties.IsK) };
            yield return new object[] { JwkProperties.Kty, new Func<string, bool>(JwkProperties.IsKty) };
            yield return new object[] { JwkProperties.Use, new Func<string, bool>(JwkProperties.IsUse) };
            yield return new object[] { JwkProperties.KeyOps, new Func<string, bool>(JwkProperties.IsKeyOps) };
            yield return new object[] { JwkProperties.Alg, new Func<string, bool>(JwkProperties.IsAlg) };
            yield return new object[] { JwkProperties.Kid, new Func<string, bool>(JwkProperties.IsKid) };
            yield return new object[] { JwkProperties.X5u, new Func<string, bool>(JwkProperties.IsX5u) };
            yield return new object[] { JwkProperties.X5c, new Func<string, bool>(JwkProperties.IsX5c) };
            yield return new object[] { JwkProperties.X5t, new Func<string, bool>(JwkProperties.IsX5t) };
            yield return new object[] { JwkProperties.X5tHashS256, new Func<string, bool>(JwkProperties.IsX5tHashS256) };
            yield return new object[] { JwkProperties.Typ, new Func<string, bool>(JwkProperties.IsTyp) };
            yield return new object[] { JwkProperties.Cty, new Func<string, bool>(JwkProperties.IsCty) };
            yield return new object[] { JwkProperties.N, new Func<string, bool>(JwkProperties.IsN) };
            yield return new object[] { JwkProperties.Nbf, new Func<string, bool>(JwkProperties.IsNbf) };
            yield return new object[] { JwkProperties.P, new Func<string, bool>(JwkProperties.IsP) };
            yield return new object[] { JwkProperties.Q, new Func<string, bool>(JwkProperties.IsQ) };
            yield return new object[] { JwkProperties.Qi, new Func<string, bool>(JwkProperties.IsQi) };
            yield return new object[] { JwkProperties.Roles, new Func<string, bool>(JwkProperties.IsRoles) };
            yield return new object[] { JwkProperties.Sub, new Func<string, bool>(JwkProperties.IsSub) };
            yield return new object[] { JwkProperties.Tenant, new Func<string, bool>(JwkProperties.IsTenant) };
            yield return new object[] { JwkProperties.X, new Func<string, bool>(JwkProperties.IsX) };
            yield return new object[] { JwkProperties.Y, new Func<string, bool>(JwkProperties.IsY) };
        }


        [Theory]
        [MemberData(nameof(GetJwkProperties))]
        public void JwaAlgorithmComparesCorrectly(string correctAlgorithm, Func<string, bool> isCorrectAlgorithm)
        {
            //A newly created instance should not reference the canonicalized version.
            //This means a different version even with the same case will not reference
            //the same object. This is a a premise check for the implementation of the
            //JwkProperties.GetCanonicalizedValue that relies on this optimization
            //to avoid comparing the actual strings if the references are the same.
            string instanceAlgorithm = new(correctAlgorithm);
            Assert.False(object.ReferenceEquals(correctAlgorithm, instanceAlgorithm), "Instance created from canonical should not reference equal to it.");

            //The correct algorithm should be correctly identified even if it's not the canonicalized version.
            //This is a premise check for the WellKnownJweAlgorithms.GetCanonicalizedValue, now the
            //comparison is done with the actual strings.
            Assert.True(isCorrectAlgorithm(instanceAlgorithm), "Is<SomeAlgorithm> should compare correctly to canonicalized version even if instance.");

            //The canonicalized version should be the same as the original.
            string canonicalizedVersion = JwkProperties.GetCanonicalizedValue(instanceAlgorithm);
            Assert.True(object.ReferenceEquals(correctAlgorithm, canonicalizedVersion), "Canonicalized version should be the same as original.");

            //A case with a toggled letter should not be the same since it's both a different string
            //and a different reference.
            string incorrectAlgorithm = instanceAlgorithm.ToggleCaseForLetterAt(0);
            Assert.False(isCorrectAlgorithm(incorrectAlgorithm), "Comparison should fail when casing is changed.");
        }
    }
}
