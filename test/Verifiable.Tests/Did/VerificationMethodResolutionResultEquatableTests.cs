using Verifiable.Core.Model.Did;

namespace Verifiable.Tests.Did
{
    /// <summary>
    /// Tests for <see cref="VerificationMethodResolutionResult" /> <see cref="System.IEquatable{T}" /> implementation.
    /// </summary>
    [TestClass]
    public sealed class VerificationMethodResolutionResultEquatableTests
    {
        /// <summary>
        /// A first instance for testing comparisons.
        /// </summary>
        private static VerificationMethodResolutionResult Result1 { get; } = VerificationMethodResolutionResult.Resolved(
            new VerificationMethod
            {
                Id = "test-key-1",
                Type = "JsonWebKey2020",
                Controller = "did:test:123",
                KeyFormat = new PublicKeyJwk
                {
                    Header = new Dictionary<string, object>
                    {
                        ["kty"] = "EC",
                        ["crv"] = "P-256"
                    }
                }
            },
            isLocal: true);


        /// <summary>
        /// A second instance for testing comparisons.
        /// </summary>
        private static VerificationMethodResolutionResult Result2 { get; } = VerificationMethodResolutionResult.Unresolved("did:test:456#key-2");


        /// <summary>
        /// A third instance identical to the first for testing equality.
        /// </summary>
        private static VerificationMethodResolutionResult Result3 { get; } = VerificationMethodResolutionResult.Resolved(
            new VerificationMethod
            {
                Id = "test-key-1",
                Type = "JsonWebKey2020",
                Controller = "did:test:123",
                KeyFormat = new PublicKeyJwk
                {
                    Header = new Dictionary<string, object>
                    {
                        ["kty"] = "EC",
                        ["crv"] = "P-256"
                    }
                }
            },
            isLocal: true);


        [TestMethod]
        public void InstancesWithDifferentDataAreNotEqual()
        {
            Assert.IsFalse(Result1.Equals(Result2));
            Assert.IsFalse(Result1 == Result2);
            Assert.IsTrue(Result1 != Result2);
        }


        [TestMethod]
        public void InstancesWithSameDataAreEqual()
        {
            //Note: This tests reference equality since Result1 and Result3 contain the same verification method reference.
            Assert.IsTrue(Result1.Equals(Result3));
            Assert.IsTrue(Result1 == Result3);
            Assert.IsFalse(Result1 != Result3);
        }


        [TestMethod]
        public void SameInstanceIsEqualToItself()
        {
            Assert.IsTrue(Result1.Equals(Result1));
            Assert.IsTrue(Result1 == Result1);
            Assert.IsFalse(Result1 != Result1);
        }


        [TestMethod]
        public void ComparisonWithTypeAndObjectSucceeds()
        {
            object resultAsObject = Result1;
            Assert.IsTrue(Result1.Equals(resultAsObject));
        }


        [TestMethod]
        public void ResultAndObjectEqualityComparisonSucceeds()
        {
            object resultAsObject = Result1;
            bool result1 = Result1 == resultAsObject;
            Assert.IsTrue(result1);

            bool result2 = resultAsObject == Result1;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void ResultAndObjectInequalityComparisonSucceeds()
        {
            object resultAsObject = Result1;
            bool result1 = Result1 != resultAsObject;
            Assert.IsFalse(result1);

            bool result2 = resultAsObject != Result1;
            Assert.IsFalse(result2);
        }


        [TestMethod]
        public void ResultAndObjectEqualityComparisonWithDifferentValuesSucceeds()
        {
            object resultAsObject = Result2;
            bool result1 = Result1 == resultAsObject;
            Assert.IsFalse(result1);

            bool result2 = Result1 != resultAsObject;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void EqualsWithDifferentTypesReturnsFalse()
        {
            object differentType = new();
            Assert.IsFalse(Result1.Equals(differentType));
        }


        [TestMethod]
        public void EqualsWithNullObjectReturnsFalse()
        {
            object? nullObject = null;
            Assert.IsFalse(Result1.Equals(nullObject));
        }


        [TestMethod]
        public void ResolvedResultsWithDifferentLocalFlagsAreNotEqual()
        {
            var localResult = VerificationMethodResolutionResult.Resolved(
                new VerificationMethod { Id = "same-key" },
                isLocal: true);

            var externalResult = VerificationMethodResolutionResult.Resolved(
                new VerificationMethod { Id = "same-key" },
                isLocal: false);

            Assert.IsFalse(localResult.Equals(externalResult));
            Assert.IsFalse(localResult == externalResult);
            Assert.IsTrue(localResult != externalResult);
        }


        [TestMethod]
        public void UnresolvedResultsWithSameReferenceAreEqual()
        {
            var unresolved1 = VerificationMethodResolutionResult.Unresolved("did:test:reference");
            var unresolved2 = VerificationMethodResolutionResult.Unresolved("did:test:reference");

            Assert.IsTrue(unresolved1.Equals(unresolved2));
            Assert.IsTrue(unresolved1 == unresolved2);
            Assert.IsFalse(unresolved1 != unresolved2);
        }


        [TestMethod]
        public void UnresolvedResultsWithDifferentReferencesAreNotEqual()
        {
            var unresolved1 = VerificationMethodResolutionResult.Unresolved("did:test:reference1");
            var unresolved2 = VerificationMethodResolutionResult.Unresolved("did:test:reference2");

            Assert.IsFalse(unresolved1.Equals(unresolved2));
            Assert.IsFalse(unresolved1 == unresolved2);
            Assert.IsTrue(unresolved1 != unresolved2);
        }


        [TestMethod]
        public void ResolvedAndUnresolvedResultsAreNotEqual()
        {
            var resolved = VerificationMethodResolutionResult.Resolved(new VerificationMethod { Id = "test" });
            var unresolved = VerificationMethodResolutionResult.Unresolved("test");

            Assert.IsFalse(resolved.Equals(unresolved));
            Assert.IsFalse(resolved == unresolved);
            Assert.IsTrue(resolved != unresolved);
        }


        [TestMethod]
        public void HashCodeIsConsistentForEqualInstances()
        {
            var result1 = VerificationMethodResolutionResult.Resolved(
                new VerificationMethod { Id = "test-key" },
                isLocal: true);

            var result2 = VerificationMethodResolutionResult.Resolved(
                new VerificationMethod { Id = "test-key" },
                isLocal: true);

            //Note: Hash codes should be equal for equal objects.
            Assert.AreEqual(result1.GetHashCode(), result2.GetHashCode());
        }


        [TestMethod]
        public void HashCodeIsDifferentForDifferentInstances()
        {
            //Note: This test may occasionally fail due to hash collisions, but should generally pass.
            Assert.AreNotEqual(Result1.GetHashCode(), Result2.GetHashCode());
        }
    }
}