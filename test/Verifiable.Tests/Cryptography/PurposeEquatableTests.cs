using Verifiable.Core.Cryptography.Context;
using Xunit;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests for <see cref="Purpose" /> <see cref="System.IEquatable{T}" /> implementation.
    /// </summary>
    public class PurposeEquatableTests
    {
        /// <summary>
        /// A first instance for testing comparisons.
        /// </summary>
        private static Purpose Purpose1 { get; } = Purpose.Public;

        /// <summary>
        /// A second instance for testing comparisons.
        /// </summary>
        private static Purpose Purpose2 { get; } = Purpose.Private;

        
        [Fact]
        public void InstancesWithDifferentCodesAreNotEqual()
        {
            Assert.False(Purpose1.Equals(Purpose2));
            Assert.False(Purpose1 == Purpose2);
            Assert.True(Purpose1 != Purpose2);
        }


        [Fact]
        public void InstancesWithSameCodesAreEqual()
        {
            var purposeDuplicatePublic = Purpose1;
            Assert.True(Purpose1.Equals(purposeDuplicatePublic));
            Assert.True(Purpose1 == purposeDuplicatePublic);
            Assert.False(Purpose1 != purposeDuplicatePublic);
        }


        [Fact]
        public void ComparisonWithTypeAndObjectSucceeds()
        {
            object purposeAsObject = Purpose1;
            Assert.True(Purpose1.Equals(purposeAsObject));
        }


        [Fact]
        public void PurposeAndObjectEqualityComparisonSucceeds()
        {
            object purposeAsObject = Purpose1;
            bool result1 = Purpose1 == purposeAsObject;
            Assert.True(result1);

            bool result2 = purposeAsObject == Purpose1;
            Assert.True(result2);
        }


        [Fact]
        public void PurposeAndObjectInequalityComparisonSucceeds()
        {
            object purposeAsObject = Purpose1;
            bool result1 = Purpose1 != purposeAsObject;
            Assert.False(result1);

            bool result2 = purposeAsObject != Purpose1;
            Assert.False(result2);
        }

                
        [Fact]
        public void PurposeAndObjectEqualityComparisonWithDifferentValuesSucceeds()
        {
            object purposeAsObject = Purpose2;
            bool result1 = Purpose1 == purposeAsObject;
            Assert.False(result1);

            bool result2 = Purpose1 != purposeAsObject;
            Assert.True(result2);
        }


        [Fact]
        public void EqualsWithDifferentTypesReturnsFalse()
        {
            object differentType = new();
            Assert.False(Purpose1.Equals(differentType));
        }


        [Fact]
        public void EqualsWithNullObjectReturnsFalse()
        {
            object? nullObject = null;
            Assert.False(Purpose1.Equals(nullObject));
        }
    }
}
