using Verifiable.Core.Model.Did;


namespace Verifiable.Tests.Did
{

    /// <summary>
    /// Tests for <see cref="PublicKeyMultibase" /> <see cref="System.IEquatable{T}" /> implementation.
    /// </summary>
    [TestClass]
    public sealed class PublicKeyMultibaseEquatableTests
    {
        /// <summary>
        /// A first instance for testing comparisons.
        /// </summary>
        private static PublicKeyMultibase Multibase1 { get; } = new PublicKeyMultibase("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");

        /// <summary>
        /// A second instance with different key for testing comparisons.
        /// </summary>
        private static PublicKeyMultibase Multibase2 { get; } = new PublicKeyMultibase("z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");

        /// <summary>
        /// A third instance with the same key as the first for testing equality.
        /// </summary>
        private static PublicKeyMultibase Multibase3 { get; } = new PublicKeyMultibase("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");


        [TestMethod]
        public void InstancesWithDifferentKeysAreNotEqual()
        {
            Assert.IsFalse(Multibase1.Equals(Multibase2));
            Assert.IsFalse(Multibase1 == Multibase2);
            Assert.IsTrue(Multibase1 != Multibase2);
        }


        [TestMethod]
        public void InstancesWithSameKeysAreEqual()
        {
            Assert.IsTrue(Multibase1.Equals(Multibase3));
            Assert.IsTrue(Multibase1 == Multibase3);
            Assert.IsFalse(Multibase1 != Multibase3);
        }


        [TestMethod]
        public void SameInstanceIsEqualToItself()
        {
            Assert.IsTrue(Multibase1.Equals(Multibase1));
            Assert.IsTrue(Multibase1 == Multibase1);
            Assert.IsFalse(Multibase1 != Multibase1);
        }


        [TestMethod]
        public void ComparisonWithTypeAndObjectSucceeds()
        {
            object multibaseAsObject = Multibase1;
            Assert.IsTrue(Multibase1.Equals(multibaseAsObject));
        }


        [TestMethod]
        public void MultibaseAndObjectEqualityComparisonSucceeds()
        {
            object multibaseAsObject = Multibase1;
            bool result1 = Multibase1 == multibaseAsObject;
            Assert.IsTrue(result1);

            bool result2 = multibaseAsObject == Multibase1;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void MultibaseAndObjectInequalityComparisonSucceeds()
        {
            object multibaseAsObject = Multibase1;
            bool result1 = Multibase1 != multibaseAsObject;
            Assert.IsFalse(result1);

            bool result2 = multibaseAsObject != Multibase1;
            Assert.IsFalse(result2);
        }


        [TestMethod]
        public void MultibaseAndObjectEqualityComparisonWithDifferentValuesSucceeds()
        {
            object multibaseAsObject = Multibase2;
            bool result1 = Multibase1 == multibaseAsObject;
            Assert.IsFalse(result1);

            bool result2 = Multibase1 != multibaseAsObject;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void EqualsWithDifferentTypesReturnsFalse()
        {
            object differentType = new();
            Assert.IsFalse(Multibase1.Equals(differentType));
        }


        [TestMethod]
        public void EqualsWithNullObjectReturnsFalse()
        {
            object? nullObject = null;
            Assert.IsFalse(Multibase1.Equals(nullObject));
        }


        [TestMethod]
        public void EqualsWithNullKeyFormatReturnsFalse()
        {
            KeyFormat? nullKeyFormat = null;
            Assert.IsFalse(Multibase1.Equals(nullKeyFormat));
        }


        [TestMethod]
        public void NullKeyFormatsAreEqual()
        {
            PublicKeyMultibase? multibase1 = null;
            PublicKeyMultibase? multibase2 = null;
            Assert.IsTrue(multibase1 == multibase2);
            Assert.IsFalse(multibase1 != multibase2);
        }


        [TestMethod]
        public void NullAndNonNullKeyFormatsAreNotEqual()
        {
            PublicKeyMultibase? nullMultibase = null;
            Assert.IsFalse(nullMultibase == Multibase1);
            Assert.IsFalse(Multibase1 == nullMultibase);
            Assert.IsTrue(nullMultibase != Multibase1);
            Assert.IsTrue(Multibase1 != nullMultibase);
        }


        [TestMethod]
        public void HashCodeIsConsistentForEqualInstances()
        {
            Assert.AreEqual(Multibase1.GetHashCode(), Multibase3.GetHashCode());
        }


        [TestMethod]
        public void HashCodeIsDifferentForDifferentInstances()
        {
            //Note: This test may occasionally fail due to hash collisions, but should generally pass.
            Assert.AreNotEqual(Multibase1.GetHashCode(), Multibase2.GetHashCode());
        }


        [TestMethod]
        public void HashCodeIsConsistentAcrossMultipleCalls()
        {
            int hash1 = Multibase1.GetHashCode();
            int hash2 = Multibase1.GetHashCode();
            Assert.AreEqual(hash1, hash2);
        }


        [TestMethod]
        public void MultibaseWithJwkTypeIsNotEqual()
        {
            var jwk = new PublicKeyJwk { Header = new Dictionary<string, object> { ["kty"] = "EC" } };

            Assert.IsFalse(Multibase1.Equals(jwk));
            Assert.IsFalse(Multibase1 == jwk);
            Assert.IsTrue(Multibase1 != jwk);
        }


        [TestMethod]
        public void ConstructorThrowsOnNullKey()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => new PublicKeyMultibase(null!));
        }
    }
}