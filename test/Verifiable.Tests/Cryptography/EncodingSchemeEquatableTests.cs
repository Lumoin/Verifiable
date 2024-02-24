using Verifiable.Core.Cryptography.Context;
using Xunit;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests for <see cref="EncodingScheme" /> <see cref="System.IEquatable{T}" /> implementation.
    /// </summary>
    public class EncodingSchemeEquatableTests
    {
        /// <summary>
        /// A first instance for testing comparisons.
        /// </summary>
        private static EncodingScheme EncodingScheme1 { get; } = EncodingScheme.Pkcs8;

        /// <summary>
        /// A second instance for testing comparisons.
        /// </summary>
        private static EncodingScheme EncodingScheme2 { get; } = EncodingScheme.Raw;

        

        [Fact]
        public void InstancesWithDifferentCodesAreNotEqual()
        {
            Assert.False(EncodingScheme1.Equals(EncodingScheme2));
            Assert.False(EncodingScheme1 == EncodingScheme2);
            Assert.True(EncodingScheme1 != EncodingScheme2);
        }


        [Fact]
        public void InstancesWithSameCodesAreEqual()
        {
            var encodingScheme1 = EncodingScheme.Pkcs8;
            Assert.True(EncodingScheme1.Equals(encodingScheme1));
            Assert.True(EncodingScheme1 == encodingScheme1);
            Assert.False(EncodingScheme1 != encodingScheme1);
        }


        [Fact]
        public void ComparisonWithTypeAndObjectSucceeds()
        {
            object encodingSchemeAsObject = EncodingScheme1;
            Assert.True(EncodingScheme1.Equals(encodingSchemeAsObject));
        }


        [Fact]
        public void PurposeAndObjectEqualityComparisonSucceeds()
        {
            object encodingSchemeAsObject = EncodingScheme1;
            bool result1 = EncodingScheme1 == encodingSchemeAsObject;
            Assert.True(result1);

            bool result2 = encodingSchemeAsObject == EncodingScheme1;
            Assert.True(result2);
        }


        [Fact]
        public void PurposeAndObjectInequalityComparisonSucceeds()
        {
            object encodingSchemeAsObject = EncodingScheme1;
            bool result1 = EncodingScheme1 != encodingSchemeAsObject;
            Assert.False(result1);

            bool result2 = encodingSchemeAsObject != EncodingScheme1;
            Assert.False(result2);
        }

                
        [Fact]
        public void PurposeAndObjectEqualityComparisonWithDifferentValuesSucceeds()
        {
            object encodingSchemeAsObject = EncodingScheme2;
            bool result1 = EncodingScheme1 == encodingSchemeAsObject;
            Assert.False(result1);

            bool result2 = EncodingScheme1 != encodingSchemeAsObject;
            Assert.True(result2);
        }


        [Fact]
        public void EqualsWithDifferentTypesReturnsFalse()
        {
            object differentType = new();
            Assert.False(EncodingScheme1.Equals(differentType));
        }


        [Fact]
        public void EqualsWithNullObjectReturnsFalse()
        {
            object? nullObject = null;
            Assert.False(EncodingScheme1.Equals(nullObject));
        }
    }
}
