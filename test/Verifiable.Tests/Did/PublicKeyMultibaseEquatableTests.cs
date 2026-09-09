using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Did;
using Verifiable.Tests.TestInfrastructure;


namespace Verifiable.Tests.Did
{

    /// <summary>
    /// Tests for <see cref="PublicKeyMultibase" /> <see cref="System.IEquatable{T}" /> implementation.
    /// </summary>
    [TestClass]
    internal sealed class PublicKeyMultibaseEquatableTests
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
        [SuppressMessage("Maintainability", "CA1508:Avoid dead conditional code", Justification = "Intentional null/null case to verify custom equality operator semantics; analyzer cannot reason about operator overloads.")]
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


        /// <summary>
        /// The <see cref="object.Equals(object?)"/>/<see cref="object.GetHashCode"/> contract requires
        /// that <see cref="PublicKeyMultibase.GetHashCode"/> be computed with the same comparison
        /// basis as <see cref="PublicKeyMultibase.Equals(KeyFormat?)"/> (ordinal, exact content). A
        /// soft hyphen (U+00AD, a Unicode default-ignorable code point) inserted into the key
        /// produces a byte-different string that a culture-aware comparison could still treat as
        /// equal; both halves of the contract — <c>Equals</c> returning <see langword="false"/> and
        /// <c>GetHashCode</c> differing — must hold for the type to behave correctly in hash
        /// containers.
        /// </summary>
        [TestMethod]
        public void KeyWithIgnorableCodePointIsNotEqualToOriginalAndHashesDiffer()
        {
            var tampered = new PublicKeyMultibase(Multibase1.Key.InsertIgnorableCodePointAt(1));

            Assert.IsFalse(Multibase1.Equals(tampered));
            Assert.IsFalse(Multibase1 == tampered);
            Assert.AreNotEqual(Multibase1.GetHashCode(), tampered.GetHashCode());
        }
    }
}
