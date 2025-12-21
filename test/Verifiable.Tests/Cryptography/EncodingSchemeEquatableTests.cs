using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests for <see cref="EncodingScheme" /> <see cref="System.IEquatable{T}" /> implementation.
    /// </summary>
    [TestClass]
    public sealed class EncodingSchemeEquatableTests
    {
        /// <summary>
        /// A first instance for testing comparisons.
        /// </summary>
        private static EncodingScheme EncodingScheme1 { get; } = EncodingScheme.Pkcs8;

        /// <summary>
        /// A second instance for testing comparisons.
        /// </summary>
        private static EncodingScheme EncodingScheme2 { get; } = EncodingScheme.Raw;

        

        [TestMethod]
        public void InstancesWithDifferentCodesAreNotEqual()
        {
            Assert.IsFalse(EncodingScheme1.Equals(EncodingScheme2));
            Assert.IsFalse(EncodingScheme1 == EncodingScheme2);
            Assert.IsTrue(EncodingScheme1 != EncodingScheme2);
        }


        [TestMethod]
        public void InstancesWithSameCodesAreEqual()
        {
            var encodingScheme1 = EncodingScheme.Pkcs8;
            Assert.IsTrue(EncodingScheme1.Equals(encodingScheme1));
            Assert.IsTrue(EncodingScheme1 == encodingScheme1);
            Assert.IsFalse(EncodingScheme1 != encodingScheme1);
        }


        [TestMethod]
        public void ComparisonWithTypeAndObjectSucceeds()
        {
            object encodingSchemeAsObject = EncodingScheme1;
            Assert.IsTrue(EncodingScheme1.Equals(encodingSchemeAsObject));
        }


        [TestMethod]
        public void PurposeAndObjectEqualityComparisonSucceeds()
        {
            object encodingSchemeAsObject = EncodingScheme1;
            bool result1 = EncodingScheme1 == encodingSchemeAsObject;
            Assert.IsTrue(result1);

            bool result2 = encodingSchemeAsObject == EncodingScheme1;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void PurposeAndObjectInequalityComparisonSucceeds()
        {
            object encodingSchemeAsObject = EncodingScheme1;
            bool result1 = EncodingScheme1 != encodingSchemeAsObject;
            Assert.IsFalse(result1);

            bool result2 = encodingSchemeAsObject != EncodingScheme1;
            Assert.IsFalse(result2);
        }

                
        [TestMethod]
        public void PurposeAndObjectEqualityComparisonWithDifferentValuesSucceeds()
        {
            object encodingSchemeAsObject = EncodingScheme2;
            bool result1 = EncodingScheme1 == encodingSchemeAsObject;
            Assert.IsFalse(result1);

            bool result2 = EncodingScheme1 != encodingSchemeAsObject;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void EqualsWithDifferentTypesReturnsFalse()
        {
            object differentType = new();
            Assert.IsFalse(EncodingScheme1.Equals(differentType));
        }


        [TestMethod]
        public void EqualsWithNullObjectReturnsFalse()
        {
            object? nullObject = null;
            Assert.IsFalse(EncodingScheme1.Equals(nullObject));
        }
    }
}
