using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jwt
{
    /// <summary>
    /// Tests that canonicalization of JWE algorithms works correctly.
    /// </summary>
    [TestClass]
    internal class WellKnownJweAlgorithmsTests
    {
        /// <summary>
        /// All of the well-known JWE algorithms should be recognized.
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<object[]> GetJweAlgorithms()
        {
            yield return new object[] { WellKnownJweAlgorithms.Rsa15, new Func<string, bool>(WellKnownJweAlgorithms.IsRsa15) };
            yield return new object[] { WellKnownJweAlgorithms.RsaOaep, new Func<string, bool>(WellKnownJweAlgorithms.IsRsaOaep) };
            yield return new object[] { WellKnownJweAlgorithms.RsaOaep256, new Func<string, bool>(WellKnownJweAlgorithms.IsRsaOaep256) };
            yield return new object[] { WellKnownJweAlgorithms.A128Kw, new Func<string, bool>(WellKnownJweAlgorithms.IsA128Kw) };
            yield return new object[] { WellKnownJweAlgorithms.A192Kw, new Func<string, bool>(WellKnownJweAlgorithms.IsA192Kw) };
            yield return new object[] { WellKnownJweAlgorithms.A256Kw, new Func<string, bool>(WellKnownJweAlgorithms.IsA256Kw) };
            yield return new object[] { WellKnownJweAlgorithms.Dir, new Func<string, bool>(WellKnownJweAlgorithms.IsDir) };
            yield return new object[] { WellKnownJweAlgorithms.EcdhEs, new Func<string, bool>(WellKnownJweAlgorithms.IsEcdhEs) };
            yield return new object[] { WellKnownJweAlgorithms.EcdhEsA128Kw, new Func<string, bool>(WellKnownJweAlgorithms.IsEcdhEsA128Kw) };
            yield return new object[] { WellKnownJweAlgorithms.EcdhEsA192Kw, new Func<string, bool>(WellKnownJweAlgorithms.IsEcdhEsA192Kw) };
            yield return new object[] { WellKnownJweAlgorithms.EcdhEsA256Kw, new Func<string, bool>(WellKnownJweAlgorithms.IsEcdhEsA256Kw) };
            yield return new object[] { WellKnownJweAlgorithms.Ecdh1Pu, new Func<string, bool>(WellKnownJweAlgorithms.IsEcdh1Pu) };
            yield return new object[] { WellKnownJweAlgorithms.Ecdh1PuA128Kw, new Func<string, bool>(WellKnownJweAlgorithms.IsEcdh1PuA128Kw) };
            yield return new object[] { WellKnownJweAlgorithms.Ecdh1PuA192Kw, new Func<string, bool>(WellKnownJweAlgorithms.IsEcdh1PuA192Kw) };
            yield return new object[] { WellKnownJweAlgorithms.Ecdh1PuA256Kw, new Func<string, bool>(WellKnownJweAlgorithms.IsEcdh1PuA256Kw) };
            yield return new object[] { WellKnownJweAlgorithms.A128GcmKw, new Func<string, bool>(WellKnownJweAlgorithms.IsA128GcmKw) };
            yield return new object[] { WellKnownJweAlgorithms.A192GcmKw, new Func<string, bool>(WellKnownJweAlgorithms.IsA192GcmKw) };
            yield return new object[] { WellKnownJweAlgorithms.A256GcmKw, new Func<string, bool>(WellKnownJweAlgorithms.IsA256GcmKw) };
            yield return new object[] { WellKnownJweAlgorithms.Pbes2Hs256A128Kw, new Func<string, bool>(WellKnownJweAlgorithms.IsPbes2Hs256A128Kw) };
            yield return new object[] { WellKnownJweAlgorithms.Pbes2Hs384A192Kw, new Func<string, bool>(WellKnownJweAlgorithms.IsPbes2Hs384A192Kw) };
            yield return new object[] { WellKnownJweAlgorithms.Pbes2Hs512A256Kw, new Func<string, bool>(WellKnownJweAlgorithms.IsPbes2Hs512A256Kw) };
        }


        /// <summary>
        /// Tests that all well-known JWE algorithm values are recognized correctly.
        /// </summary>
        /// <param name="correctAlgorithm">The correct to be used in test.</param>
        /// <param name="isCorrectAlgorithm">The function that checks if the algorithm is recognized.</param>
        [TestMethod]
        [DynamicData(nameof(GetJweAlgorithms))]
        public void JweAlgorithmComparesCorrectly(string correctAlgorithm, Func<string, bool> isCorrectAlgorithm)
        {
            //A newly created instance should not reference the canonicalized version.
            //This means a different version even with the same case will not reference
            //the same object. This is a a premise check for the implementation of the
            //WellKnownJweAlgorithms.GetCanonicalizedValue that relies on this optimization
            //to avoid comparing the actual strings if the references are the same.
            string instanceAlgorithm = new(correctAlgorithm);
            Assert.IsFalse(object.ReferenceEquals(correctAlgorithm, instanceAlgorithm), "Instance created from canonical should not reference equal to it.");

            //The correct algorithm should be correctly identified even if it's not the canonicalized version.
            //This is a premise check for the WellKnownJweAlgorithms.GetCanonicalizedValue, now the
            //comparison is done with the actual strings.
            Assert.IsTrue(isCorrectAlgorithm(instanceAlgorithm), "Is<SomeAlgorithm> should compare correctly to canonicalized version even if instance.");

            //The canonicalized version should be the same as the original.
            string canonicalizedVersion = WellKnownJweAlgorithms.GetCanonicalizedValue(instanceAlgorithm);
            Assert.IsTrue(object.ReferenceEquals(correctAlgorithm, canonicalizedVersion), "Canonicalized version should be the same as original.");

            //A case with a toggled letter should not be the same since it's both a different string
            //and a different reference.
            string incorrectAlgorithm = instanceAlgorithm.ToggleCaseForLetterAt(0);
            Assert.IsFalse(isCorrectAlgorithm(incorrectAlgorithm), "Comparison should fail when casing is changed.");
        }   
    }
}
