using Verifiable.Core.Did;

namespace Verifiable.Tests.Did
{
    /// <summary>
    /// Tests for <see cref="VerificationMethod" /> <see cref="System.IEquatable{T}" /> implementation.
    /// </summary>
    [TestClass]
    public sealed class VerificationMethodEquatableTests
    {
        /// <summary>
        /// A first instance for testing comparisons.
        /// </summary>
        private static VerificationMethod Method1 { get; } = new VerificationMethod
        {
            Id = "did:test:123#key-1",
            Type = "JsonWebKey2020",
            Controller = "did:test:123",
            KeyFormat = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    ["kty"] = "EC",
                    ["crv"] = "P-256",
                    ["x"] = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                    ["y"] = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
                }
            }
        };


        /// <summary>
        /// A second instance with different properties for testing comparisons.
        /// </summary>
        private static VerificationMethod Method2 { get; } = new VerificationMethod
        {
            Id = "did:test:456#key-2",
            Type = "Multikey",
            Controller = "did:test:456",
            KeyFormat = new PublicKeyMultibase("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
        };


        /// <summary>
        /// A third instance with the same properties as the first for testing equality.
        /// </summary>
        private static VerificationMethod Method3 { get; } = new VerificationMethod
        {
            Id = "did:test:123#key-1",
            Type = "JsonWebKey2020",
            Controller = "did:test:123",
            KeyFormat = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    ["kty"] = "EC",
                    ["crv"] = "P-256",
                    ["x"] = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                    ["y"] = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
                }
            }
        };


        [TestMethod]
        public void InstancesWithDifferentPropertiesAreNotEqual()
        {
            Assert.IsFalse(Method1.Equals(Method2));
            Assert.IsFalse(Method1 == Method2);
            Assert.IsTrue(Method1 != Method2);
        }


        [TestMethod]
        public void InstancesWithSamePropertiesAreEqual()
        {
            Assert.IsTrue(Method1.Equals(Method3));
            Assert.IsTrue(Method1 == Method3);
            Assert.IsFalse(Method1 != Method3);
        }


        [TestMethod]
        public void SameInstanceIsEqualToItself()
        {
            Assert.IsTrue(Method1.Equals(Method1));
            Assert.IsTrue(Method1 == Method1);
            Assert.IsFalse(Method1 != Method1);
        }


        [TestMethod]
        public void ComparisonWithTypeAndObjectSucceeds()
        {
            object methodAsObject = Method1;
            Assert.IsTrue(Method1.Equals(methodAsObject));
        }


        [TestMethod]
        public void MethodAndObjectEqualityComparisonSucceeds()
        {
            object methodAsObject = Method1;
            bool result1 = Method1 == methodAsObject;
            Assert.IsTrue(result1);

            bool result2 = methodAsObject == Method1;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void MethodAndObjectInequalityComparisonSucceeds()
        {
            object methodAsObject = Method1;
            bool result1 = Method1 != methodAsObject;
            Assert.IsFalse(result1);

            bool result2 = methodAsObject != Method1;
            Assert.IsFalse(result2);
        }


        [TestMethod]
        public void MethodAndObjectEqualityComparisonWithDifferentValuesSucceeds()
        {
            object methodAsObject = Method2;
            bool result1 = Method1 == methodAsObject;
            Assert.IsFalse(result1);

            bool result2 = Method1 != methodAsObject;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void EqualsWithDifferentTypesReturnsFalse()
        {
            object differentType = new();
            Assert.IsFalse(Method1.Equals(differentType));
        }


        [TestMethod]
        public void EqualsWithNullObjectReturnsFalse()
        {
            object? nullObject = null;
            Assert.IsFalse(Method1.Equals(nullObject));
        }


        [TestMethod]
        public void EqualsWithNullVerificationMethodReturnsFalse()
        {
            VerificationMethod? nullMethod = null;
            Assert.IsFalse(Method1.Equals(nullMethod));
        }


        [TestMethod]
        public void NullVerificationMethodsAreEqual()
        {
            VerificationMethod? method1 = null;
            VerificationMethod? method2 = null;
            Assert.IsTrue(method1 == method2);
            Assert.IsFalse(method1 != method2);
        }


        [TestMethod]
        public void NullAndNonNullVerificationMethodsAreNotEqual()
        {
            VerificationMethod? nullMethod = null;
            Assert.IsFalse(nullMethod == Method1);
            Assert.IsFalse(Method1 == nullMethod);
            Assert.IsTrue(nullMethod != Method1);
            Assert.IsTrue(Method1 != nullMethod);
        }


        [TestMethod]
        public void MethodsWithDifferentIdsAreNotEqual()
        {
            var method1 = new VerificationMethod
            {
                Id = "did:test:123#key-1",
                Type = "JsonWebKey2020",
                Controller = "did:test:123"
            };

            var method2 = new VerificationMethod
            {
                Id = "did:test:123#key-2",
                Type = "JsonWebKey2020",
                Controller = "did:test:123"
            };

            Assert.IsFalse(method1.Equals(method2));
            Assert.IsFalse(method1 == method2);
            Assert.IsTrue(method1 != method2);
        }


        [TestMethod]
        public void MethodsWithDifferentControllersAreNotEqual()
        {
            var method1 = new VerificationMethod
            {
                Id = "did:test:123#key-1",
                Type = "JsonWebKey2020",
                Controller = "did:test:123"
            };

            var method2 = new VerificationMethod
            {
                Id = "did:test:123#key-1",
                Type = "JsonWebKey2020",
                Controller = "did:test:456"
            };

            Assert.IsFalse(method1.Equals(method2));
            Assert.IsFalse(method1 == method2);
            Assert.IsTrue(method1 != method2);
        }


        [TestMethod]
        public void MethodsWithDifferentTypesAreNotEqual()
        {
            var method1 = new VerificationMethod
            {
                Id = "did:test:123#key-1",
                Type = "JsonWebKey2020",
                Controller = "did:test:123"
            };

            var method2 = new VerificationMethod
            {
                Id = "did:test:123#key-1",
                Type = "Multikey",
                Controller = "did:test:123"
            };

            Assert.IsFalse(method1.Equals(method2));
            Assert.IsFalse(method1 == method2);
            Assert.IsTrue(method1 != method2);
        }


        [TestMethod]
        public void MethodsWithDifferentKeyFormatsAreNotEqual()
        {
            var jwkFormat = new PublicKeyJwk
            {
                Header = new Dictionary<string, object> { ["kty"] = "EC" }
            };

            var multibaseFormat = new PublicKeyMultibase("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");

            var method1 = new VerificationMethod
            {
                Id = "did:test:123#key-1",
                Type = "JsonWebKey2020",
                Controller = "did:test:123",
                KeyFormat = jwkFormat
            };

            var method2 = new VerificationMethod
            {
                Id = "did:test:123#key-1",
                Type = "JsonWebKey2020",
                Controller = "did:test:123",
                KeyFormat = multibaseFormat
            };

            Assert.IsFalse(method1.Equals(method2));
            Assert.IsFalse(method1 == method2);
            Assert.IsTrue(method1 != method2);
        }


        [TestMethod]
        public void MethodsWithNullPropertiesCanBeEqual()
        {
            var method1 = new VerificationMethod
            {
                Id = null,
                Type = null,
                Controller = null,
                KeyFormat = null
            };

            var method2 = new VerificationMethod
            {
                Id = null,
                Type = null,
                Controller = null,
                KeyFormat = null
            };

            Assert.IsTrue(method1.Equals(method2));
            Assert.IsTrue(method1 == method2);
            Assert.IsFalse(method1 != method2);
        }


        [TestMethod]
        public void HashCodeIsConsistentForEqualInstances()
        {
            Assert.AreEqual(Method1.GetHashCode(), Method3.GetHashCode());
        }


        [TestMethod]
        public void HashCodeIsDifferentForDifferentInstances()
        {
            //Note: This test may occasionally fail due to hash collisions, but should generally pass.
            Assert.AreNotEqual(Method1.GetHashCode(), Method2.GetHashCode());
        }


        [TestMethod]
        public void HashCodeIsConsistentAcrossMultipleCalls()
        {
            int hash1 = Method1.GetHashCode();
            int hash2 = Method1.GetHashCode();
            Assert.AreEqual(hash1, hash2);
        }
    }
}