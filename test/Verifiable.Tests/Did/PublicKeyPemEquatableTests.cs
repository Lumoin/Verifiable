using Verifiable.Core.Model.Did;

namespace Verifiable.Tests.Did
{
    /// <summary>
    /// Tests for <see cref="PublicKeyPem" /> <see cref="System.IEquatable{T}" /> implementation.
    /// </summary>
    [TestClass]
    [Obsolete("Test JSON material still contains these types.")]
    public sealed class PublicKeyPemEquatableTests
    {
        /// <summary>
        /// A first instance for testing comparisons.
        /// </summary>
        private static PublicKeyPem Pem1 { get; } = new PublicKeyPem(@"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4f7jGC8Y4A8L2Y9XZGx8QY4Y8A8L
2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QQ==
-----END PUBLIC KEY-----");

        /// <summary>
        /// A second instance with different key for testing comparisons.
        /// </summary>
        private static PublicKeyPem Pem2 { get; } = new PublicKeyPem(@"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4f7jGC8Y4A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8
QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8
QIDAQAB
-----END RSA PUBLIC KEY-----");

        /// <summary>
        /// A third instance with the same key as the first for testing equality.
        /// </summary>
        private static PublicKeyPem Pem3 { get; } = new PublicKeyPem(@"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4f7jGC8Y4A8L2Y9XZGx8QY4Y8A8L
2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QQ==
-----END PUBLIC KEY-----");

        /// <summary>
        /// A fourth instance with same content but different formatting for testing strict equality.
        /// </summary>
        private static PublicKeyPem Pem4 { get; } = new PublicKeyPem(@"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4f7jGC8Y4A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QQ==
-----END PUBLIC KEY-----");


        [TestMethod]
        public void InstancesWithDifferentKeysAreNotEqual()
        {
            Assert.IsFalse(Pem1.Equals(Pem2));
            Assert.IsFalse(Pem1 == Pem2);
            Assert.IsTrue(Pem1 != Pem2);
        }


        [TestMethod]
        public void InstancesWithSameKeysAreEqual()
        {
            Assert.IsTrue(Pem1.Equals(Pem3));
            Assert.IsTrue(Pem1 == Pem3);
            Assert.IsFalse(Pem1 != Pem3);
        }


        [TestMethod]
        public void InstancesWithDifferentFormattingAreNotEqual()
        {
            //PEM comparison is case and whitespace sensitive.
            Assert.IsFalse(Pem1.Equals(Pem4));
            Assert.IsFalse(Pem1 == Pem4);
            Assert.IsTrue(Pem1 != Pem4);
        }


        [TestMethod]
        public void SameInstanceIsEqualToItself()
        {
            Assert.IsTrue(Pem1.Equals(Pem1));
            Assert.IsTrue(Pem1 == Pem1);
            Assert.IsFalse(Pem1 != Pem1);
        }


        [TestMethod]
        public void ComparisonWithTypeAndObjectSucceeds()
        {
            object pemAsObject = Pem1;
            Assert.IsTrue(Pem1.Equals(pemAsObject));
        }


        [TestMethod]
        public void PemAndObjectEqualityComparisonSucceeds()
        {
            object pemAsObject = Pem1;
            bool result1 = Pem1 == pemAsObject;
            Assert.IsTrue(result1);

            bool result2 = pemAsObject == Pem1;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void PemAndObjectInequalityComparisonSucceeds()
        {
            object pemAsObject = Pem1;
            bool result1 = Pem1 != pemAsObject;
            Assert.IsFalse(result1);

            bool result2 = pemAsObject != Pem1;
            Assert.IsFalse(result2);
        }


        [TestMethod]
        public void PemAndObjectEqualityComparisonWithDifferentValuesSucceeds()
        {
            object pemAsObject = Pem2;
            bool result1 = Pem1 == pemAsObject;
            Assert.IsFalse(result1);

            bool result2 = Pem1 != pemAsObject;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void EqualsWithDifferentTypesReturnsFalse()
        {
            object differentType = new();
            Assert.IsFalse(Pem1.Equals(differentType));
        }


        [TestMethod]
        public void EqualsWithNullObjectReturnsFalse()
        {
            object? nullObject = null;
            Assert.IsFalse(Pem1.Equals(nullObject));
        }


        [TestMethod]
        public void EqualsWithNullKeyFormatReturnsFalse()
        {
            KeyFormat? nullKeyFormat = null;
            Assert.IsFalse(Pem1.Equals(nullKeyFormat));
        }


        [TestMethod]
        public void NullKeyFormatsAreEqual()
        {
            PublicKeyPem? pem1 = null;
            PublicKeyPem? pem2 = null;
            Assert.IsTrue(pem1 == pem2);
            Assert.IsFalse(pem1 != pem2);
        }


        [TestMethod]
        public void NullAndNonNullKeyFormatsAreNotEqual()
        {
            PublicKeyPem? nullPem = null;
            Assert.IsFalse(nullPem == Pem1);
            Assert.IsFalse(Pem1 == nullPem);
            Assert.IsTrue(nullPem != Pem1);
            Assert.IsTrue(Pem1 != nullPem);
        }


        [TestMethod]
        public void HashCodeIsConsistentForEqualInstances()
        {
            Assert.AreEqual(Pem1.GetHashCode(), Pem3.GetHashCode());
        }


        [TestMethod]
        public void HashCodeIsDifferentForDifferentInstances()
        {
            //Note: This test may occasionally fail due to hash collisions, but should generally pass.
            Assert.AreNotEqual(Pem1.GetHashCode(), Pem2.GetHashCode());
        }


        [TestMethod]
        public void HashCodeIsConsistentAcrossMultipleCalls()
        {
            int hash1 = Pem1.GetHashCode();
            int hash2 = Pem1.GetHashCode();
            Assert.AreEqual(hash1, hash2);
        }


        [TestMethod]
        public void PemWithJwkTypeIsNotEqual()
        {
            var jwk = new PublicKeyJwk { Header = new Dictionary<string, object> { ["kty"] = "EC" } };

            Assert.IsFalse(Pem1.Equals(jwk));
            Assert.IsFalse(Pem1 == jwk);
            Assert.IsTrue(Pem1 != jwk);
        }


        [TestMethod]
        public void PemWithMultibaseTypeIsNotEqual()
        {
            var multibase = new PublicKeyMultibase("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");

            Assert.IsFalse(Pem1.Equals(multibase));
            Assert.IsFalse(Pem1 == multibase);
            Assert.IsTrue(Pem1 != multibase);
        }


        [TestMethod]
        public void PemWithHexTypeIsNotEqual()
        {
            var hex = new PublicKeyHex("d75a980182b10ab7d54bfed3c964071a0ee172f3daa62325af021a68f707511a");

            Assert.IsFalse(Pem1.Equals(hex));
            Assert.IsFalse(Pem1 == hex);
            Assert.IsTrue(Pem1 != hex);
        }


        [TestMethod]
        public void ConstructorThrowsOnNullKey()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => new PublicKeyPem(null!));
        }


        [TestMethod]
        public void EmptyStringKeyIsAllowed()
        {
            var emptyPem = new PublicKeyPem("");
            Assert.AreEqual("", emptyPem.Key);
        }


        [TestMethod]
        public void WhitespaceKeyIsAllowed()
        {
            var whitespacePem = new PublicKeyPem("   ");
            Assert.AreEqual("   ", whitespacePem.Key);
        }


        [TestMethod]
        public void RsaPublicKeyPemEqualityWorksCorrectly()
        {
            var pem1 = new PublicKeyPem(@"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4f7jGC8Y4A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8
QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8
QIDAQAB
-----END RSA PUBLIC KEY-----");

            var pem2 = new PublicKeyPem(@"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4f7jGC8Y4A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8
QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8
QIDAQAB
-----END RSA PUBLIC KEY-----");

            Assert.IsTrue(pem1.Equals(pem2));
            Assert.IsTrue(pem1 == pem2);
            Assert.IsFalse(pem1 != pem2);
        }


        [TestMethod]
        public void EcPublicKeyPemEqualityWorksCorrectly()
        {
            var pem1 = new PublicKeyPem(@"-----BEGIN EC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4f7jGC8Y4A8L2Y9XZGx8QY4Y8A8L
2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QQ==
-----END EC PUBLIC KEY-----");

            var pem2 = new PublicKeyPem(@"-----BEGIN EC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4f7jGC8Y4A8L2Y9XZGx8QY4Y8A8L
2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QQ==
-----END EC PUBLIC KEY-----");

            Assert.IsTrue(pem1.Equals(pem2));
            Assert.IsTrue(pem1 == pem2);
            Assert.IsFalse(pem1 != pem2);
        }


        [TestMethod]
        public void PemComparisonIsCaseSensitive()
        {
            var lowerCasePem = new PublicKeyPem(@"-----begin public key-----
test content
-----end public key-----");

            var upperCasePem = new PublicKeyPem(@"-----BEGIN PUBLIC KEY-----
test content
-----END PUBLIC KEY-----");

            Assert.IsFalse(lowerCasePem.Equals(upperCasePem));
            Assert.IsFalse(lowerCasePem == upperCasePem);
            Assert.IsTrue(lowerCasePem != upperCasePem);
        }


        [TestMethod]
        public void PemComparisonIsWhitespaceSensitive()
        {
            var pemWithSpaces = new PublicKeyPem(@"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4f7jGC8Y4A8L2Y9XZGx8QY4Y8A8L
2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QQ==
-----END PUBLIC KEY-----");

            var pemWithoutSpaces = new PublicKeyPem(@"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4f7jGC8Y4A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QQ==
-----END PUBLIC KEY-----");

            Assert.IsFalse(pemWithSpaces.Equals(pemWithoutSpaces));
            Assert.IsFalse(pemWithSpaces == pemWithoutSpaces);
            Assert.IsTrue(pemWithSpaces != pemWithoutSpaces);
        }


        [TestMethod]
        public void PemWithDifferentLineEndingsAreNotEqual()
        {
            var pemWithCrlf = new PublicKeyPem("-----BEGIN PUBLIC KEY-----\r\ntest\r\n-----END PUBLIC KEY-----");
            var pemWithLf = new PublicKeyPem("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----");

            Assert.IsFalse(pemWithCrlf.Equals(pemWithLf));
            Assert.IsFalse(pemWithCrlf == pemWithLf);
            Assert.IsTrue(pemWithCrlf != pemWithLf);
        }


        [TestMethod]
        public void SingleLinePemEqualityWorksCorrectly()
        {
            var pem1 = new PublicKeyPem("-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE-----END PUBLIC KEY-----");
            var pem2 = new PublicKeyPem("-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE-----END PUBLIC KEY-----");

            Assert.IsTrue(pem1.Equals(pem2));
            Assert.IsTrue(pem1 == pem2);
            Assert.IsFalse(pem1 != pem2);
        }
    }
}