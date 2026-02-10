using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jwt
{
    /// <summary>
    /// Tests that canonicalization of kty values works correctly.
    /// </summary>
    [TestClass]
    internal sealed class WellKnownCurveValuesTests
    {
        /// <summary>
        /// All of the well-known curve values and their comparison functions..
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<object[]> GetCurveValues()
        {
            yield return new object[] { WellKnownCurveValues.Ed25519, new Func<string, bool>(WellKnownCurveValues.IsEd25519) };
            yield return new object[] { WellKnownCurveValues.Ed448, new Func<string, bool>(WellKnownCurveValues.IsEd448) };
            yield return new object[] { WellKnownCurveValues.P256, new Func<string, bool>(WellKnownCurveValues.IsP256) };
            yield return new object[] { WellKnownCurveValues.P384, new Func<string, bool>(WellKnownCurveValues.IsP384) };
            yield return new object[] { WellKnownCurveValues.P521, new Func<string, bool>(WellKnownCurveValues.IsP521) };            
            yield return new object[] { WellKnownCurveValues.Secp256k1, new Func<string, bool>(WellKnownCurveValues.IsSecp256k1) };
            yield return new object[] { WellKnownCurveValues.X25519, new Func<string, bool>(WellKnownCurveValues.IsX25519) };
            yield return new object[] { WellKnownCurveValues.X448, new Func<string, bool>(WellKnownCurveValues.IsX448) };            
        }


        /// <summary>
        /// Tests that all well-known JWT curve values are recognized correctly.
        /// </summary>
        /// <param name="curve">The curve to test.</param>
        /// <param name="isCorrectCurve">The function that checks if the algorithm is recognized.</param>
        [TestMethod]
        [DynamicData(nameof(GetCurveValues))]
        public void CurveValuesComparesCorrectly(string curve, Func<string, bool> isCorrectCurve)
        {
            //A newly created instance should not reference the canonicalized version.
            //This means a different version even with the same case will not reference
            //the same object. This is a a premise check for the implementation of the
            //WellKnownCurveValues.GetCanonicalizedValue that relies on this optimization
            //to avoid comparing the actual strings if the references are the same.
            string instanceAlgorithm = new(curve);
            Assert.IsFalse(object.ReferenceEquals(curve, instanceAlgorithm), "Instance created from canonical should not reference equal to it.");

            //The correct algorithm should be correctly identified even if it's not the canonicalized version.
            //This is a premise check for the WellKnownCurveValues.GetCanonicalizedValue, now the
            //comparison is done with the actual strings.
            Assert.IsTrue(isCorrectCurve(instanceAlgorithm), "Is<SomeAlgorithm> should compare correctly to canonicalized version even if instance.");

            //The canonicalized version should be the same as the original.
            string canonicalizedVersion = WellKnownCurveValues.GetCanonicalizedValue(instanceAlgorithm);
            Assert.IsTrue(object.ReferenceEquals(curve, canonicalizedVersion), "Canonicalized version should be the same as original.");

            //A case with a toggled letter should not be the same since it's both a different string
            //and a different reference.
            string incorrectAlgorithm = instanceAlgorithm.ToggleCaseForLetterAt(0);
            Assert.IsFalse(isCorrectCurve(incorrectAlgorithm), "Comparison should fail when casing is changed.");
        }
    }
}
