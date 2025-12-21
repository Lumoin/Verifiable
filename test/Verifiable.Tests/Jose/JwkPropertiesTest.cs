using Verifiable.Jose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jwt
{
    /// <summary>
    /// Tests that canonicalization of JWA algorithms works correctly.
    /// </summary>
    [TestClass]
    public sealed class WellKnownJwaValuesTests
    {
        /// <summary>
        /// All of the well-known JWE algorithms should be recognized.
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<object[]> GetJwaAlgorithms()
        {
            yield return new object[] { WellKnownJwaValues.None, new Func<string, bool>(WellKnownJwaValues.IsNone) };
            yield return new object[] { WellKnownJwaValues.Hs256, new Func<string, bool>(WellKnownJwaValues.IsHs256) };
            yield return new object[] {WellKnownJwaValues.Hs384, new Func<string, bool>(WellKnownJwaValues.IsHs384) };
            yield return new object[] {WellKnownJwaValues.Hs512, new Func<string, bool>(WellKnownJwaValues.IsHs512) };
            yield return new object[] {WellKnownJwaValues.Es256, new Func<string, bool>(WellKnownJwaValues.IsEs256) };
            yield return new object[] {WellKnownJwaValues.Es384, new Func<string, bool>(WellKnownJwaValues.IsEs384) };
            yield return new object[] {WellKnownJwaValues.Es512, new Func<string, bool>(WellKnownJwaValues.IsEs512) };
            yield return new object[] {WellKnownJwaValues.Es256k1, new Func<string, bool>(WellKnownJwaValues.IsEs256k1) };
            yield return new object[] {WellKnownJwaValues.Ps256, new Func<string, bool>(WellKnownJwaValues.IsPs256) };
            yield return new object[] {WellKnownJwaValues.Ps384, new Func<string, bool>(WellKnownJwaValues.IsPs384) };
            yield return new object[] {WellKnownJwaValues.Ps512, new Func<string, bool>(WellKnownJwaValues.IsPs512) };
            yield return new object[] {WellKnownJwaValues.Rs256, new Func<string, bool>(WellKnownJwaValues.IsRs256) };
            yield return new object[] {WellKnownJwaValues.Rs384, new Func<string, bool>(WellKnownJwaValues.IsRs384) };
            yield return new object[] {WellKnownJwaValues.Rs512, new Func<string, bool>(WellKnownJwaValues.IsRs512) };
            yield return new object[] {WellKnownJwaValues.EdDsa, new Func<string, bool>(WellKnownJwaValues.IsEdDsa) };
        }


        /// <summary>
        /// Tests that all well-known JWA algorithms are recognized.
        /// </summary>
        /// <param name="algorithm">The algorithm to test.</param>
        /// <param name="algorithmCheck">The function that checks if the algorithm is recognized.</param>
        [TestMethod]
        [DynamicData(nameof(GetJwaAlgorithms))]
        public void JwaAlgorithmComparesCorrectly(string correctAlgorithm, Func<string, bool> isCorrectAlgorithm)
        {
            //A newly created instance should not reference the canonicalized version.
            //This means a different version even with the same case will not reference
            //the same object. This is a a premise check for the implementation of the
            //WellKnownJwaValues.GetCanonicalizedValue that relies on this optimization
            //to avoid comparing the actual strings if the references are the same.
            string instanceAlgorithm = new(correctAlgorithm);
            Assert.IsFalse(object.ReferenceEquals(correctAlgorithm, instanceAlgorithm), "Instance created from canonical should not reference equal to it.");

            //The correct algorithm should be correctly identified even if it's not the canonicalized version.
            //This is a premise check for the WellKnownJweAlgorithms.GetCanonicalizedValue, now the
            //comparison is done with the actual strings.
            Assert.IsTrue(isCorrectAlgorithm(instanceAlgorithm), "Is<SomeAlgorithm> should compare correctly to canonicalized version even if instance.");

            //The canonicalized version should be the same as the original.
            string canonicalizedVersion = WellKnownJwaValues.GetCanonicalizedValue(instanceAlgorithm);
            Assert.IsTrue(object.ReferenceEquals(correctAlgorithm, canonicalizedVersion), "Canonicalized version should be the same as original.");

            //A case with a toggled letter should not be the same since it's both a different string
            //and a different reference.
            string incorrectAlgorithm = instanceAlgorithm.ToggleCaseForLetterAt(0);
            Assert.IsFalse(isCorrectAlgorithm(incorrectAlgorithm), "Comparison should fail when casing is changed.");
        }
    }
}
