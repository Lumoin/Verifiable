using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Did;


namespace Verifiable.Tests
{
    /// <summary>
    /// Tests for <see cref="DidUrl"/> <see cref="System.IEquatable{T}"/> implementation.
    /// </summary>
    [TestClass]
    internal sealed class DidUrlEquatableTests
    {
        /// <summary>
        /// A first absolute DID URL instance for testing comparisons.
        /// </summary>
        private static DidUrl AbsoluteDidUrl1 { get; } = DidUrl.Parse("did:example:123#key-1");

        /// <summary>
        /// A second absolute DID URL instance for testing comparisons.
        /// </summary>
        private static DidUrl AbsoluteDidUrl2 { get; } = DidUrl.Parse("did:example:456#key-2");

        /// <summary>
        /// A fragment-only DID URL instance for testing comparisons.
        /// </summary>
        private static DidUrl FragmentDidUrl1 { get; } = DidUrl.Parse("#key-1");

        /// <summary>
        /// A second fragment-only DID URL instance for testing comparisons.
        /// </summary>
        private static DidUrl FragmentDidUrl2 { get; } = DidUrl.Parse("#key-2");


        [TestMethod]
        public void InstancesWithDifferentValuesAreNotEqual()
        {
            Assert.IsFalse(AbsoluteDidUrl1.Equals(AbsoluteDidUrl2));
            Assert.IsFalse(AbsoluteDidUrl1 == AbsoluteDidUrl2);
            Assert.IsTrue(AbsoluteDidUrl1 != AbsoluteDidUrl2);
        }


        [TestMethod]
        public void InstancesWithSameValuesAreEqual()
        {
            var didUrl1 = DidUrl.Parse("did:example:123#key-1");
            Assert.IsTrue(AbsoluteDidUrl1.Equals(didUrl1));
            Assert.IsTrue(AbsoluteDidUrl1 == didUrl1);
            Assert.IsFalse(AbsoluteDidUrl1 != didUrl1);
        }


        [TestMethod]
        public void AbsoluteAndFragmentUrlsAreNotEqual()
        {
            Assert.IsFalse(AbsoluteDidUrl1.Equals(FragmentDidUrl1));
            Assert.IsFalse(AbsoluteDidUrl1 == FragmentDidUrl1);
            Assert.IsTrue(AbsoluteDidUrl1 != FragmentDidUrl1);
        }


        [TestMethod]
        public void FragmentInstancesWithDifferentValuesAreNotEqual()
        {
            Assert.IsFalse(FragmentDidUrl1.Equals(FragmentDidUrl2));
            Assert.IsFalse(FragmentDidUrl1 == FragmentDidUrl2);
            Assert.IsTrue(FragmentDidUrl1 != FragmentDidUrl2);
        }


        [TestMethod]
        public void FragmentInstancesWithSameValuesAreEqual()
        {
            var fragmentUrl1 = DidUrl.Parse("#key-1");
            Assert.IsTrue(FragmentDidUrl1.Equals(fragmentUrl1));
            Assert.IsTrue(FragmentDidUrl1 == fragmentUrl1);
            Assert.IsFalse(FragmentDidUrl1 != fragmentUrl1);
        }


        [TestMethod]
        public void ComparisonWithTypeAndObjectSucceeds()
        {
            object didUrlAsObject = AbsoluteDidUrl1;
            Assert.IsTrue(AbsoluteDidUrl1.Equals(didUrlAsObject));
        }


        [TestMethod]
        public void DidUrlAndObjectEqualityComparisonSucceeds()
        {
            object didUrlAsObject = AbsoluteDidUrl1;
            bool result1 = AbsoluteDidUrl1.Equals(didUrlAsObject);
            Assert.IsTrue(result1);

            bool result2 = ((DidUrl)didUrlAsObject).Equals(AbsoluteDidUrl1);
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void DidUrlAndObjectInequalityComparisonSucceeds()
        {
            object didUrlAsObject = AbsoluteDidUrl1;
            bool result1 = !AbsoluteDidUrl1.Equals(didUrlAsObject);
            Assert.IsFalse(result1);

            bool result2 = !((DidUrl)didUrlAsObject).Equals(AbsoluteDidUrl1);
            Assert.IsFalse(result2);
        }


        [TestMethod]
        public void DidUrlAndObjectEqualityComparisonWithDifferentValuesSucceeds()
        {
            object didUrlAsObject = AbsoluteDidUrl2;
            bool result1 = !AbsoluteDidUrl1.Equals(didUrlAsObject);
            Assert.IsTrue(result1);

            bool result2 = !((DidUrl)didUrlAsObject).Equals(AbsoluteDidUrl1);
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void EqualsWithDifferentTypesReturnsFalse()
        {
            object differentType = new();
            Assert.IsFalse(AbsoluteDidUrl1.Equals(differentType));
        }


        [TestMethod]
        public void EqualsWithNullObjectReturnsFalse()
        {
            object? nullObject = null;
            Assert.IsFalse(AbsoluteDidUrl1.Equals(nullObject));
        }


        [TestMethod]
        public void EqualsWithNullDidUrlReturnsFalse()
        {
            DidUrl? nullDidUrl = null;
            Assert.IsFalse(AbsoluteDidUrl1.Equals(nullDidUrl));
        }


        [TestMethod]
        [SuppressMessage("Maintainability", "CA1508:Avoid dead conditional code", Justification = "Intentional null/null case to verify custom equality operator semantics; analyzer cannot reason about operator overloads.")]
        public void NullDidUrlEqualityOperatorWorks()
        {
            DidUrl? nullDidUrl1 = null;
            DidUrl? nullDidUrl2 = null;

            Assert.IsTrue(nullDidUrl1 == nullDidUrl2);
            Assert.IsFalse(nullDidUrl1 != nullDidUrl2);
            Assert.IsFalse(nullDidUrl1 == AbsoluteDidUrl1);
            Assert.IsTrue(nullDidUrl1 != AbsoluteDidUrl1);
        }


        [TestMethod]
        public void GetHashCodeIsConsistentForEqualInstances()
        {
            var didUrl1 = DidUrl.Parse("did:example:123#key-1");
            var didUrl2 = DidUrl.Parse("did:example:123#key-1");

            Assert.AreEqual(didUrl1.GetHashCode(), didUrl2.GetHashCode());
        }


        [TestMethod]
        public void GetHashCodeIsDifferentForDifferentInstances()
        {
            int hash1 = AbsoluteDidUrl1.GetHashCode();
            int hash2 = AbsoluteDidUrl2.GetHashCode();

            Assert.AreNotEqual(hash1, hash2);
        }
    }
}