using Verifiable.Jwt;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jwt
{
    /// <summary>
    /// Tests that canonicalization of JWE encryption algorithms works correctly.
    /// </summary>
    [TestClass]
    public sealed class WellKnownJweEncryptionAlgorithmsTests
    {
        /// <summary>
        /// All of the well-known JWE encryption algorithms should be recognized.
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<object[]> GetEncryptionAlgorithms()
        {
            yield return new object[] { WellKnownJweEncryptionAlgorithms.A128CbcHs256, new Func<string, bool>(WellKnownJweEncryptionAlgorithms.IsA128CbcHs256) };
            yield return new object[] { WellKnownJweEncryptionAlgorithms.A192CbcHs384, new Func<string, bool>(WellKnownJweEncryptionAlgorithms.IsA192CbcHs384) };
            yield return new object[] { WellKnownJweEncryptionAlgorithms.A256CbcHs512, new Func<string, bool>(WellKnownJweEncryptionAlgorithms.IsA256CbcHs512) };
            yield return new object[] { WellKnownJweEncryptionAlgorithms.A128Gcm, new Func<string, bool>(WellKnownJweEncryptionAlgorithms.IsA128Gcm) };
            yield return new object[] { WellKnownJweEncryptionAlgorithms.A192Gcm, new Func<string, bool>(WellKnownJweEncryptionAlgorithms.IsA192Gcm) };
            yield return new object[] { WellKnownJweEncryptionAlgorithms.A256Gcm, new Func<string, bool>(WellKnownJweEncryptionAlgorithms.IsA256Gcm) };
            yield return new object[] { WellKnownJweEncryptionAlgorithms.XC20P, new Func<string, bool>(WellKnownJweEncryptionAlgorithms.IsXC20P) };
        }


        /// <summary>
        /// Tests that all well-known JWE encryption algorithm values are recognized correctly.
        /// </summary>
        /// <param name="correctAlgorithm">The correct to be used in test.</param>
        /// <param name="isCorrectAlgorithm">The function that checks if the algorithm is recognized.</param>
        [TestMethod]
        [DynamicData(nameof(GetEncryptionAlgorithms), DynamicDataSourceType.Method)]
        public void EncryptionAlgorithmComparesCorrectly(string correctAlgorithm, Func<string, bool> isCorrectAlgorithm)
        {
            //A newly created instance should not reference the canonicalized version.
            //This means a different version even with the same case will not reference
            //the same object. This is a a premise check for the implementation of the
            //WellKnownJweEncryptionAlgorithms.GetCanonicalizedValue that relies on this optimization
            //to avoid comparing the actual strings if the references are the same.
            string instanceAlgorithm = new(correctAlgorithm);
            Assert.IsFalse(object.ReferenceEquals(correctAlgorithm, instanceAlgorithm), "Instance created from canonical should not reference equal to it.");

            //The correct algorithm should be correctly identified even if it's not the canonicalized version.
            //This is a premise check for the WellKnownJweAlgorithms.GetCanonicalizedValue, now the
            //comparison is done with the actual strings.
            Assert.IsTrue(isCorrectAlgorithm(instanceAlgorithm), "Is<SomeAlgorithm> should compare correctly to canonicalized version even if instance.");

            //The canonicalized version should be the same as the original.
            string canonicalizedVersion = WellKnownJweEncryptionAlgorithms.GetCanonicalizedValue(instanceAlgorithm);
            Assert.IsTrue(object.ReferenceEquals(correctAlgorithm, canonicalizedVersion), "Canonicalized version should be the same as original.");

            //A case with a toggled letter should not be the same since it's both a different string
            //and a different reference.
            string incorrectAlgorithm = instanceAlgorithm.ToggleCaseForLetterAt(0);
            Assert.IsFalse(isCorrectAlgorithm(incorrectAlgorithm), "Comparison should fail when casing is changed.");
        }       
    }
}
