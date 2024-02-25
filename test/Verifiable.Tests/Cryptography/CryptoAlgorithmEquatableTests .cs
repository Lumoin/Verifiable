using Verifiable.Core.Cryptography.Context;
using Xunit;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests for <see cref="CryptoAlgorithm" /> <see cref="System.IEquatable{T}" /> implementation.
    /// </summary>
    public class CryptoAlgorithmEquatableTests
    {
        /// <summary>
        /// A first instance for testing comparisons.
        /// </summary>
        private static CryptoAlgorithm CryptoAlgorithm1 { get; } = CryptoAlgorithm.P256;

        /// <summary>
        /// A second instance for testing comparisons.
        /// </summary>
        private static CryptoAlgorithm CryptoAlgorithm2 { get; } = CryptoAlgorithm.Rsa4096;
                

        [Fact]
        public void InstancesWithDifferentCodesAreNotEqual()
        {
            Assert.False(CryptoAlgorithm1.Equals(CryptoAlgorithm2));
            Assert.False(CryptoAlgorithm1 == CryptoAlgorithm2);
            Assert.True(CryptoAlgorithm1 != CryptoAlgorithm2);
        }


        [Fact]
        public void InstancesWithSameCodesAreEqual()
        {
            var cryptoAlgorithm1 = CryptoAlgorithm.P256;
            Assert.True(CryptoAlgorithm1.Equals(cryptoAlgorithm1));
            Assert.True(CryptoAlgorithm1 == cryptoAlgorithm1);
            Assert.False(CryptoAlgorithm1 != cryptoAlgorithm1);
        }


        [Fact]
        public void ComparisonWithTypeAndObjectSucceeds()
        {
            object cryptoAlgorithmAsObject = CryptoAlgorithm1;
            Assert.True(CryptoAlgorithm1.Equals(cryptoAlgorithmAsObject));
        }


        [Fact]
        public void CryptoAlgorithmAndObjectEqualityComparisonSucceeds()
        {
            object cryptoAlgorithmAsObject = CryptoAlgorithm1;
            bool result1 = CryptoAlgorithm1 == cryptoAlgorithmAsObject;
            Assert.True(result1);

            bool result2 = cryptoAlgorithmAsObject == CryptoAlgorithm1;
            Assert.True(result2);
        }


        [Fact]
        public void CryptoAlgorithmAndObjectInequalityComparisonSucceeds()
        {
            object cryptoAlgorithmAsObject = CryptoAlgorithm1;
            bool result1 = CryptoAlgorithm1 != cryptoAlgorithmAsObject;
            Assert.False(result1);

            bool result2 = cryptoAlgorithmAsObject != CryptoAlgorithm1;
            Assert.False(result2);
        }

                
        [Fact]
        public void CryptoAlgorithmAndObjectEqualityComparisonWithDifferentValuesSucceeds()
        {
            object cryptoAlgorithmAsObject = CryptoAlgorithm2;
            bool result1 = CryptoAlgorithm1 == cryptoAlgorithmAsObject;
            Assert.False(result1);

            bool result2 = CryptoAlgorithm1 != cryptoAlgorithmAsObject;
            Assert.True(result2);
        }


        [Fact]
        public void EqualsWithDifferentTypesReturnsFalse()
        {
            object differentType = new();
            Assert.False(CryptoAlgorithm1.Equals(differentType));
        }


        [Fact]
        public void EqualsWithNullObjectReturnsFalse()
        {
            object? nullObject = null;
            Assert.False(CryptoAlgorithm1.Equals(nullObject));
        }
    }
}
