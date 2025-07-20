using Verifiable.Core.Cryptography.Context;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests for <see cref="CryptoAlgorithm" /> <see cref="System.IEquatable{T}" /> implementation.
    /// </summary>
    [TestClass]
    public sealed class CryptoAlgorithmEquatableTests
    {
        /// <summary>
        /// A first instance for testing comparisons.
        /// </summary>
        private static CryptoAlgorithm CryptoAlgorithm1 { get; } = CryptoAlgorithm.P256;

        /// <summary>
        /// A second instance for testing comparisons.
        /// </summary>
        private static CryptoAlgorithm CryptoAlgorithm2 { get; } = CryptoAlgorithm.Rsa4096;


        [TestMethod]
        public void InstancesWithDifferentCodesAreNotEqual()
        {
            Assert.IsFalse(CryptoAlgorithm1.Equals(CryptoAlgorithm2));
            Assert.IsFalse(CryptoAlgorithm1 == CryptoAlgorithm2);
            Assert.IsTrue(CryptoAlgorithm1 != CryptoAlgorithm2);
        }


        [TestMethod]
        public void InstancesWithSameCodesAreEqual()
        {
            var cryptoAlgorithm1 = CryptoAlgorithm.P256;
            Assert.IsTrue(CryptoAlgorithm1.Equals(cryptoAlgorithm1));
            Assert.IsTrue(CryptoAlgorithm1 == cryptoAlgorithm1);
            Assert.IsFalse(CryptoAlgorithm1 != cryptoAlgorithm1);
        }


        [TestMethod]
        public void ComparisonWithTypeAndObjectSucceeds()
        {
            object cryptoAlgorithmAsObject = CryptoAlgorithm1;
            Assert.IsTrue(CryptoAlgorithm1.Equals(cryptoAlgorithmAsObject));
        }


        [TestMethod]
        public void CryptoAlgorithmAndObjectEqualityComparisonSucceeds()
        {
            object cryptoAlgorithmAsObject = CryptoAlgorithm1;
            bool result1 = CryptoAlgorithm1 == cryptoAlgorithmAsObject;
            Assert.IsTrue(result1);

            bool result2 = cryptoAlgorithmAsObject == CryptoAlgorithm1;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void CryptoAlgorithmAndObjectInequalityComparisonSucceeds()
        {
            object cryptoAlgorithmAsObject = CryptoAlgorithm1;
            bool result1 = CryptoAlgorithm1 != cryptoAlgorithmAsObject;
            Assert.IsFalse(result1);

            bool result2 = cryptoAlgorithmAsObject != CryptoAlgorithm1;
            Assert.IsFalse(result2);
        }


        [TestMethod]
        public void CryptoAlgorithmAndObjectEqualityComparisonWithDifferentValuesSucceeds()
        {
            object cryptoAlgorithmAsObject = CryptoAlgorithm2;
            bool result1 = CryptoAlgorithm1 == cryptoAlgorithmAsObject;
            Assert.IsFalse(result1);

            bool result2 = CryptoAlgorithm1 != cryptoAlgorithmAsObject;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void EqualsWithDifferentTypesReturnsFalse()
        {
            object differentType = new();
            Assert.IsFalse(CryptoAlgorithm1.Equals(differentType));
        }


        [TestMethod]
        public void EqualsWithNullObjectReturnsFalse()
        {
            object? nullObject = null;
            Assert.IsFalse(CryptoAlgorithm1.Equals(nullObject));
        }
    }
}
