using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jose
{
    /// <summary>
    /// Tests canonicalization across the four JCose well-known classes:
    /// <see cref="WellKnownJwkMemberNames"/>, <see cref="WellKnownJoseHeaderNames"/>,
    /// <see cref="WellKnownJwtClaimNames"/>, and <see cref="WellKnownJwkValues"/>.
    /// Each class's <c>GetCanonicalizedValue</c> interns its own constants;
    /// these tests confirm the round-trip — a fresh string instance with the
    /// same content gets recognized by <c>Is&lt;X&gt;</c> and gets canonicalized
    /// back to the original reference.
    /// </summary>
    [TestClass]
    internal sealed class WellKnownJwkValuesTests
    {
        public static IEnumerable<object[]> GetJwkMemberNames()
        {
            yield return new object[] { WellKnownJwkMemberNames.Alg, new Func<string, bool>(WellKnownJwkMemberNames.IsAlg), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.Crv, new Func<string, bool>(WellKnownJwkMemberNames.IsCrv), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.D, new Func<string, bool>(WellKnownJwkMemberNames.IsD), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.Dp, new Func<string, bool>(WellKnownJwkMemberNames.IsDp), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.Dq, new Func<string, bool>(WellKnownJwkMemberNames.IsDq), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.E, new Func<string, bool>(WellKnownJwkMemberNames.IsE), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.K, new Func<string, bool>(WellKnownJwkMemberNames.IsK), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.KeyOps, new Func<string, bool>(WellKnownJwkMemberNames.IsKeyOps), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.Keys, new Func<string, bool>(WellKnownJwkMemberNames.IsKeys), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.Kid, new Func<string, bool>(WellKnownJwkMemberNames.IsKid), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.Kty, new Func<string, bool>(WellKnownJwkMemberNames.IsKty), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.N, new Func<string, bool>(WellKnownJwkMemberNames.IsN), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.P, new Func<string, bool>(WellKnownJwkMemberNames.IsP), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.Q, new Func<string, bool>(WellKnownJwkMemberNames.IsQ), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.Qi, new Func<string, bool>(WellKnownJwkMemberNames.IsQi), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.Use, new Func<string, bool>(WellKnownJwkMemberNames.IsUse), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.X, new Func<string, bool>(WellKnownJwkMemberNames.IsX), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.X5c, new Func<string, bool>(WellKnownJwkMemberNames.IsX5c), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.X5t, new Func<string, bool>(WellKnownJwkMemberNames.IsX5t), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.X5tHashS256, new Func<string, bool>(WellKnownJwkMemberNames.IsX5tHashS256), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.X5u, new Func<string, bool>(WellKnownJwkMemberNames.IsX5u), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwkMemberNames.Y, new Func<string, bool>(WellKnownJwkMemberNames.IsY), new Func<string, string>(WellKnownJwkMemberNames.GetCanonicalizedValue) };
        }


        public static IEnumerable<object[]> GetJoseHeaderNames()
        {
            yield return new object[] { WellKnownJoseHeaderNames.Cty, new Func<string, bool>(WellKnownJoseHeaderNames.IsCty), new Func<string, string>(WellKnownJoseHeaderNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJoseHeaderNames.Enc, new Func<string, bool>(WellKnownJoseHeaderNames.IsEnc), new Func<string, string>(WellKnownJoseHeaderNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJoseHeaderNames.Epk, new Func<string, bool>(WellKnownJoseHeaderNames.IsEpk), new Func<string, string>(WellKnownJoseHeaderNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJoseHeaderNames.Jwk, new Func<string, bool>(WellKnownJoseHeaderNames.IsJwk), new Func<string, string>(WellKnownJoseHeaderNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJoseHeaderNames.Jwt, new Func<string, bool>(WellKnownJoseHeaderNames.IsJwt), new Func<string, string>(WellKnownJoseHeaderNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJoseHeaderNames.Typ, new Func<string, bool>(WellKnownJoseHeaderNames.IsTyp), new Func<string, string>(WellKnownJoseHeaderNames.GetCanonicalizedValue) };
        }


        public static IEnumerable<object[]> GetJwtClaimNames()
        {
            yield return new object[] { WellKnownJwtClaimNames.Acr, new Func<string, bool>(WellKnownJwtClaimNames.IsAcr), new Func<string, string>(WellKnownJwtClaimNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwtClaimNames.Amr, new Func<string, bool>(WellKnownJwtClaimNames.IsAmr), new Func<string, string>(WellKnownJwtClaimNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwtClaimNames.Aud, new Func<string, bool>(WellKnownJwtClaimNames.IsAud), new Func<string, string>(WellKnownJwtClaimNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwtClaimNames.Azp, new Func<string, bool>(WellKnownJwtClaimNames.IsAzp), new Func<string, string>(WellKnownJwtClaimNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwtClaimNames.Exp, new Func<string, bool>(WellKnownJwtClaimNames.IsExp), new Func<string, string>(WellKnownJwtClaimNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwtClaimNames.Iat, new Func<string, bool>(WellKnownJwtClaimNames.IsIat), new Func<string, string>(WellKnownJwtClaimNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwtClaimNames.Iss, new Func<string, bool>(WellKnownJwtClaimNames.IsIss), new Func<string, string>(WellKnownJwtClaimNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwtClaimNames.Jti, new Func<string, bool>(WellKnownJwtClaimNames.IsJti), new Func<string, string>(WellKnownJwtClaimNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwtClaimNames.Nbf, new Func<string, bool>(WellKnownJwtClaimNames.IsNbf), new Func<string, string>(WellKnownJwtClaimNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwtClaimNames.Roles, new Func<string, bool>(WellKnownJwtClaimNames.IsRoles), new Func<string, string>(WellKnownJwtClaimNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwtClaimNames.Sub, new Func<string, bool>(WellKnownJwtClaimNames.IsSub), new Func<string, string>(WellKnownJwtClaimNames.GetCanonicalizedValue) };
            yield return new object[] { WellKnownJwtClaimNames.Tenant, new Func<string, bool>(WellKnownJwtClaimNames.IsTenant), new Func<string, string>(WellKnownJwtClaimNames.GetCanonicalizedValue) };
        }


        [TestMethod]
        [DynamicData(nameof(GetJwkMemberNames))]
        public void JwkMemberNameCanonicalizationRoundtrips(
            string canonical, Func<string, bool> isMatch, Func<string, string> canonicalize) =>
            AssertCanonicalizationRoundtrips(canonical, isMatch, canonicalize);


        [TestMethod]
        [DynamicData(nameof(GetJoseHeaderNames))]
        public void JoseHeaderNameCanonicalizationRoundtrips(
            string canonical, Func<string, bool> isMatch, Func<string, string> canonicalize) =>
            AssertCanonicalizationRoundtrips(canonical, isMatch, canonicalize);


        [TestMethod]
        [DynamicData(nameof(GetJwtClaimNames))]
        public void JwtClaimNameCanonicalizationRoundtrips(
            string canonical, Func<string, bool> isMatch, Func<string, string> canonicalize) =>
            AssertCanonicalizationRoundtrips(canonical, isMatch, canonicalize);


        private static void AssertCanonicalizationRoundtrips(
            string canonical, Func<string, bool> isMatch, Func<string, string> canonicalize)
        {
            //A newly created instance should not reference the canonicalized
            //constant. The Is/GetCanonicalizedValue contract has to recognize
            //value-equal but reference-different strings; this is the premise.
            string instance = new(canonical);
            Assert.IsFalse(object.ReferenceEquals(canonical, instance),
                "Instance created from canonical should not reference equal to it.");

            Assert.IsTrue(isMatch(instance),
                "Is<X> should compare correctly to canonicalized version even if instance.");

            string canonicalized = canonicalize(instance);
            Assert.IsTrue(object.ReferenceEquals(canonical, canonicalized),
                "Canonicalized version should be the same reference as original.");

            //A case with a toggled letter should not match. Single-letter
            //identifiers (D, E, K, N, P, Q, X, Y) get ToUpper from their
            //original lowercase to a different case — still not equal under
            //the Ordinal comparison.
            string mutated = instance.ToggleCaseForLetterAt(0);
            Assert.IsFalse(isMatch(mutated),
                "Comparison should fail when casing is changed.");
        }
    }
}
