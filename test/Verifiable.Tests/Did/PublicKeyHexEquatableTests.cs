using Verifiable.Core.Did;

namespace Verifiable.Tests.Did
{
    /// <summary>
    /// Tests for <see cref="PublicKeyHex" /> <see cref="System.IEquatable{T}" /> implementation.
    /// </summary>
    [TestClass]
    [Obsolete("Test JSON material still contains these types.")]
    public sealed class PublicKeyHexEquatableTests
    {
        /// <summary>
        /// A first instance for testing comparisons.
        /// </summary>
        private static PublicKeyHex Hex1 { get; } = new PublicKeyHex("d75a980182b10ab7d54bfed3c964071a0ee172f3daa62325af021a68f707511a");

        /// <summary>
        /// A second instance with different key for testing comparisons.
        /// </summary>
        private static PublicKeyHex Hex2 { get; } = new PublicKeyHex("0258a8b9a7e3c5c24a8b9d6e5f4c3b2a1908f7e6d5c4b3a2918e7d6c5b4a39281");

        /// <summary>
        /// A third instance with the same key as the first for testing equality.
        /// </summary>
        private static PublicKeyHex Hex3 { get; } = new PublicKeyHex("d75a980182b10ab7d54bfed3c964071a0ee172f3daa62325af021a68f707511a");

        /// <summary>
        /// A fourth instance with the same key as the first but in different case for testing case insensitive equality.
        /// </summary>
        private static PublicKeyHex Hex4 { get; } = new PublicKeyHex("D75A980182B10AB7D54BFED3C964071A0EE172F3DAA62325AF021A68F707511A");


        [TestMethod]
        public void InstancesWithDifferentKeysAreNotEqual()
        {
            Assert.IsFalse(Hex1.Equals(Hex2));
            Assert.IsFalse(Hex1 == Hex2);
            Assert.IsTrue(Hex1 != Hex2);
        }


        [TestMethod]
        public void InstancesWithSameKeysAreEqual()
        {
            Assert.IsTrue(Hex1.Equals(Hex3));
            Assert.IsTrue(Hex1 == Hex3);
            Assert.IsFalse(Hex1 != Hex3);
        }


        [TestMethod]
        public void InstancesWithSameKeysInDifferentCaseAreEqual()
        {
            Assert.IsTrue(Hex1.Equals(Hex4));
            Assert.IsTrue(Hex1 == Hex4);
            Assert.IsFalse(Hex1 != Hex4);
        }


        [TestMethod]
        public void SameInstanceIsEqualToItself()
        {
            Assert.IsTrue(Hex1.Equals(Hex1));
            Assert.IsTrue(Hex1 == Hex1);
            Assert.IsFalse(Hex1 != Hex1);
        }


        [TestMethod]
        public void ComparisonWithTypeAndObjectSucceeds()
        {
            object hexAsObject = Hex1;
            Assert.IsTrue(Hex1.Equals(hexAsObject));
        }


        [TestMethod]
        public void HexAndObjectEqualityComparisonSucceeds()
        {
            object hexAsObject = Hex1;
            bool result1 = Hex1 == hexAsObject;
            Assert.IsTrue(result1);

            bool result2 = hexAsObject == Hex1;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void HexAndObjectInequalityComparisonSucceeds()
        {
            object hexAsObject = Hex1;
            bool result1 = Hex1 != hexAsObject;
            Assert.IsFalse(result1);

            bool result2 = hexAsObject != Hex1;
            Assert.IsFalse(result2);
        }


        [TestMethod]
        public void HexAndObjectEqualityComparisonWithDifferentValuesSucceeds()
        {
            object hexAsObject = Hex2;
            bool result1 = Hex1 == hexAsObject;
            Assert.IsFalse(result1);

            bool result2 = Hex1 != hexAsObject;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void EqualsWithDifferentTypesReturnsFalse()
        {
            object differentType = new();
            Assert.IsFalse(Hex1.Equals(differentType));
        }


        [TestMethod]
        public void EqualsWithNullObjectReturnsFalse()
        {
            object? nullObject = null;
            Assert.IsFalse(Hex1.Equals(nullObject));
        }


        [TestMethod]
        public void EqualsWithNullKeyFormatReturnsFalse()
        {
            KeyFormat? nullKeyFormat = null;
            Assert.IsFalse(Hex1.Equals(nullKeyFormat));
        }


        [TestMethod]
        public void NullKeyFormatsAreEqual()
        {
            PublicKeyHex? hex1 = null;
            PublicKeyHex? hex2 = null;
            Assert.IsTrue(hex1 == hex2);
            Assert.IsFalse(hex1 != hex2);
        }


        [TestMethod]
        public void NullAndNonNullKeyFormatsAreNotEqual()
        {
            PublicKeyHex? nullHex = null;
            Assert.IsFalse(nullHex == Hex1);
            Assert.IsFalse(Hex1 == nullHex);
            Assert.IsTrue(nullHex != Hex1);
            Assert.IsTrue(Hex1 != nullHex);
        }


        [TestMethod]
        public void HashCodeIsConsistentForEqualInstances()
        {
            Assert.AreEqual(Hex1.GetHashCode(), Hex3.GetHashCode());
        }


        [TestMethod]
        public void HashCodeIsConsistentForCaseInsensitiveEqualInstances()
        {
            Assert.AreEqual(Hex1.GetHashCode(), Hex4.GetHashCode());
        }


        [TestMethod]
        public void HashCodeIsDifferentForDifferentInstances()
        {
            //Note: This test may occasionally fail due to hash collisions, but should generally pass.
            Assert.AreNotEqual(Hex1.GetHashCode(), Hex2.GetHashCode());
        }


        [TestMethod]
        public void HashCodeIsConsistentAcrossMultipleCalls()
        {
            int hash1 = Hex1.GetHashCode();
            int hash2 = Hex1.GetHashCode();
            Assert.AreEqual(hash1, hash2);
        }


        [TestMethod]
        public void HexWithJwkTypeIsNotEqual()
        {
            var jwk = new PublicKeyJwk { Header = new Dictionary<string, object> { ["kty"] = "EC" } };

            Assert.IsFalse(Hex1.Equals(jwk));
            Assert.IsFalse(Hex1 == jwk);
            Assert.IsTrue(Hex1 != jwk);
        }


        [TestMethod]
        public void HexWithMultibaseTypeIsNotEqual()
        {
            var multibase = new PublicKeyMultibase("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");

            Assert.IsFalse(Hex1.Equals(multibase));
            Assert.IsFalse(Hex1 == multibase);
            Assert.IsTrue(Hex1 != multibase);
        }


        [TestMethod]
        public void HexWithPemTypeIsNotEqual()
        {
            var pem = new PublicKeyPem(@"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4f7jGC8Y4A8L2Y9XZGx8QY4Y8A8L
2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QQ==
-----END PUBLIC KEY-----");

            Assert.IsFalse(Hex1.Equals(pem));
            Assert.IsFalse(Hex1 == pem);
            Assert.IsTrue(Hex1 != pem);
        }


        [TestMethod]
        public void ConstructorThrowsOnNullKey()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => new PublicKeyHex(null!));
        }


        [TestMethod]
        public void EmptyStringKeyIsAllowed()
        {
            var emptyHex = new PublicKeyHex("");
            Assert.AreEqual("", emptyHex.Key);
        }


        [TestMethod]
        public void WhitespaceKeyIsAllowed()
        {
            var whitespaceHex = new PublicKeyHex("   ");
            Assert.AreEqual("   ", whitespaceHex.Key);
        }


        [TestMethod]
        public void Ed25519HexKeyEqualityWorksCorrectly()
        {
            var hex1 = new PublicKeyHex("d75a980182b10ab7d54bfed3c964071a0ee172f3daa62325af021a68f707511a");
            var hex2 = new PublicKeyHex("d75a980182b10ab7d54bfed3c964071a0ee172f3daa62325af021a68f707511a");

            Assert.IsTrue(hex1.Equals(hex2));
            Assert.IsTrue(hex1 == hex2);
            Assert.IsFalse(hex1 != hex2);
        }


        [TestMethod]
        public void Secp256k1HexKeyEqualityWorksCorrectly()
        {
            var hex1 = new PublicKeyHex("0258a8b9a7e3c5c24a8b9d6e5f4c3b2a1908f7e6d5c4b3a2918e7d6c5b4a39281");
            var hex2 = new PublicKeyHex("0258a8b9a7e3c5c24a8b9d6e5f4c3b2a1908f7e6d5c4b3a2918e7d6c5b4a39281");

            Assert.IsTrue(hex1.Equals(hex2));
            Assert.IsTrue(hex1 == hex2);
            Assert.IsFalse(hex1 != hex2);
        }


        [TestMethod]
        public void P256HexKeyEqualityWorksCorrectly()
        {
            var hex1 = new PublicKeyHex("04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa8e58fc86d3ce5ccf6a7a48e1");
            var hex2 = new PublicKeyHex("04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa8e58fc86d3ce5ccf6a7a48e1");

            Assert.IsTrue(hex1.Equals(hex2));
            Assert.IsTrue(hex1 == hex2);
            Assert.IsFalse(hex1 != hex2);
        }


        [TestMethod]
        public void MixedCaseHexKeysAreEqual()
        {
            var lowerCaseHex = new PublicKeyHex("abcdef123456");
            var upperCaseHex = new PublicKeyHex("ABCDEF123456");
            var mixedCaseHex = new PublicKeyHex("AbCdEf123456");

            Assert.IsTrue(lowerCaseHex.Equals(upperCaseHex));
            Assert.IsTrue(lowerCaseHex.Equals(mixedCaseHex));
            Assert.IsTrue(upperCaseHex.Equals(mixedCaseHex));

            Assert.IsTrue(lowerCaseHex == upperCaseHex);
            Assert.IsTrue(lowerCaseHex == mixedCaseHex);
            Assert.IsTrue(upperCaseHex == mixedCaseHex);
        }


        [TestMethod]
        public void HashCodesAreSameForMixedCaseKeys()
        {
            var lowerCaseHex = new PublicKeyHex("abcdef123456");
            var upperCaseHex = new PublicKeyHex("ABCDEF123456");

            Assert.AreEqual(lowerCaseHex.GetHashCode(), upperCaseHex.GetHashCode());
        }
    }
}