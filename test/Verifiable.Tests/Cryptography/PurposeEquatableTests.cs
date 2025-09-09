using Verifiable.Core.Cryptography.Context;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests for <see cref="Purpose" /> <see cref="System.IEquatable{T}" /> implementation.
    /// </summary>
    [TestClass]
    public sealed class PurposeEquatableTests
    {
        /// <summary>
        /// A first instance for testing comparisons.
        /// </summary>
        private static Purpose Purpose1 { get; } = Purpose.Verification;

        /// <summary>
        /// A second instance for testing comparisons.
        /// </summary>
        private static Purpose Purpose2 { get; } = Purpose.Signing;

        
        [TestMethod]
        public void InstancesWithDifferentCodesAreNotEqual()
        {
            Assert.IsFalse(Purpose1.Equals(Purpose2));
            Assert.IsFalse(Purpose1 == Purpose2);
            Assert.IsTrue(Purpose1 != Purpose2);
        }


        [TestMethod]
        public void InstancesWithSameCodesAreEqual()
        {
            var purposeDuplicatePublic = Purpose1;
            Assert.IsTrue(Purpose1.Equals(purposeDuplicatePublic));
            Assert.IsTrue(Purpose1 == purposeDuplicatePublic);
            Assert.IsFalse(Purpose1 != purposeDuplicatePublic);
        }


        [TestMethod]
        public void ComparisonWithTypeAndObjectSucceeds()
        {
            object purposeAsObject = Purpose1;
            Assert.IsTrue(Purpose1.Equals(purposeAsObject));
        }


        [TestMethod]
        public void PurposeAndObjectEqualityComparisonSucceeds()
        {
            object purposeAsObject = Purpose1;
            bool result1 = Purpose1 == purposeAsObject;
            Assert.IsTrue(result1);

            bool result2 = purposeAsObject == Purpose1;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void PurposeAndObjectInequalityComparisonSucceeds()
        {
            object purposeAsObject = Purpose1;
            bool result1 = Purpose1 != purposeAsObject;
            Assert.IsFalse(result1);

            bool result2 = purposeAsObject != Purpose1;
            Assert.IsFalse(result2);
        }

                
        [TestMethod]
        public void PurposeAndObjectEqualityComparisonWithDifferentValuesSucceeds()
        {
            object purposeAsObject = Purpose2;
            bool result1 = Purpose1 == purposeAsObject;
            Assert.IsFalse(result1);

            bool result2 = Purpose1 != purposeAsObject;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void EqualsWithDifferentTypesReturnsFalse()
        {
            object differentType = new();
            Assert.IsFalse(Purpose1.Equals(differentType));
        }


        [TestMethod]
        public void EqualsWithNullObjectReturnsFalse()
        {
            object? nullObject = null;
            Assert.IsFalse(Purpose1.Equals(nullObject));
        }
    }
}
