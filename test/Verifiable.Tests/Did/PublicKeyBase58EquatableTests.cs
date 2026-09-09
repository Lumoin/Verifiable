using Verifiable.Core.Model.Did;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Did
{
    /// <summary>
    /// Tests for <see cref="PublicKeyBase58" /> <see cref="System.IEquatable{T}" /> implementation.
    /// </summary>
    [TestClass]
    [Obsolete("Test JSON material still contains these types.")]
    internal sealed class PublicKeyBase58EquatableTests
    {
        /// <summary>
        /// A first instance for testing comparisons.
        /// </summary>
        private static PublicKeyBase58 Base58Key1 { get; } = new PublicKeyBase58("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV");

        /// <summary>
        /// A second instance with different key for testing comparisons.
        /// </summary>
        private static PublicKeyBase58 Base58Key2 { get; } = new PublicKeyBase58("4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM");

        /// <summary>
        /// A third instance with the same key as the first for testing equality.
        /// </summary>
        private static PublicKeyBase58 Base58Key3 { get; } = new PublicKeyBase58("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV");


        /// <summary>
        /// The Base58-BTC alphabet is case-significant (upper- and lower-case letters are distinct
        /// symbols), so two keys differing anywhere in content, including only by case, are
        /// different key material; <see cref="PublicKeyBase58.Equals(KeyFormat?)"/> compares the
        /// full content and must treat them as unequal.
        /// </summary>
        [TestMethod]
        public void InstancesWithDifferentKeysAreNotEqual()
        {
            Assert.IsFalse(Base58Key1.Equals(Base58Key2));
            Assert.IsFalse(Base58Key1 == Base58Key2);
            Assert.IsTrue(Base58Key1 != Base58Key2);
        }


        /// <summary>
        /// Two <see cref="PublicKeyBase58"/> instances built from the exact same content are equal:
        /// <see cref="PublicKeyBase58.Equals(KeyFormat?)"/> compares the key string, not instance
        /// identity.
        /// </summary>
        [TestMethod]
        public void InstancesWithSameKeysAreEqual()
        {
            Assert.IsTrue(Base58Key1.Equals(Base58Key3));
            Assert.IsTrue(Base58Key1 == Base58Key3);
            Assert.IsFalse(Base58Key1 != Base58Key3);
        }


        /// <summary>
        /// The <see cref="object.Equals(object?)"/>/<see cref="object.GetHashCode"/> contract requires
        /// that instances <see cref="PublicKeyBase58.Equals(KeyFormat?)"/> considers equal report the
        /// same <see cref="PublicKeyBase58.GetHashCode"/> value, so the type behaves correctly as a
        /// hash-container key.
        /// </summary>
        [TestMethod]
        public void HashCodeIsConsistentForEqualInstances()
        {
            Assert.AreEqual(Base58Key1.GetHashCode(), Base58Key3.GetHashCode());
        }


        /// <summary>
        /// The key material is required; the constructor rejects a <see langword="null"/> key rather
        /// than accepting an instance with undefined content.
        /// </summary>
        [TestMethod]
        public void ConstructorThrowsOnNullKey()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => new PublicKeyBase58(null!));
        }


        /// <summary>
        /// The <see cref="object.Equals(object?)"/>/<see cref="object.GetHashCode"/> contract requires
        /// that <see cref="PublicKeyBase58.GetHashCode"/> be computed with the same comparison basis
        /// as <see cref="PublicKeyBase58.Equals(KeyFormat?)"/> (ordinal, exact content). A soft hyphen
        /// (U+00AD, a Unicode default-ignorable code point) inserted into the key produces a
        /// byte-different string that a culture-aware comparison could still treat as equal; both
        /// halves of the contract — <c>Equals</c> returning <see langword="false"/> and
        /// <c>GetHashCode</c> differing — must hold for the type to behave correctly in hash
        /// containers.
        /// </summary>
        [TestMethod]
        public void KeyWithIgnorableCodePointIsNotEqualToOriginalAndHashesDiffer()
        {
            var tampered = new PublicKeyBase58(Base58Key1.Key.InsertIgnorableCodePointAt(1));

            Assert.IsFalse(Base58Key1.Equals(tampered));
            Assert.IsFalse(Base58Key1 == tampered);
            Assert.AreNotEqual(Base58Key1.GetHashCode(), tampered.GetHashCode());
        }
    }
}
