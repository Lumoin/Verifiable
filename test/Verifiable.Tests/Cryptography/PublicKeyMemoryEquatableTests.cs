using System.Buffers;
using Verifiable.Core;
using Verifiable.Core.Cryptography;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests for <see cref="PublicKeyMemory" /> <see cref="System.IEquatable{T}" /> implementation.
    /// </summary>
    [TestClass]
    public sealed class PublicKeyMemoryEquatableTests
    {
        /// <summary>
        /// First instance of a buffer for memory in multiple comparisons.
        /// </summary>
        private static IMemoryOwner<byte> Buffer1 => SensitiveMemoryPool<byte>.Shared.Rent(1);

        /// <summary>
        /// A second instance of a buffer for memory in multiple comparisons.
        /// </summary>
        private static IMemoryOwner<byte> Buffer2 => SensitiveMemoryPool<byte>.Shared.Rent(2);

        /// <summary>
        /// A first instance of public key memory used in multiple tests.
        /// </summary>        
        private static PublicKeyMemory PublicKeyMemory1 => new(Buffer1, Tag.Empty);

        /// <summary>
        /// A second instance of public key memory used in multiple tests.
        /// </summary>        
        private static PublicKeyMemory PublicKeyMemory2 => new(Buffer2, Tag.Empty);

        /// <summary>
        /// A third instance of public key memory used in multiple tests.
        /// </summary>        
        private static PublicKeyMemory PublicKeyMemory3 => new(Buffer1, Tag.Empty);


        [TestMethod]
        public void InstancesFromDifferentSizedBuffersAreNotEqual()
        {
            Assert.IsFalse(PublicKeyMemory1.Equals(PublicKeyMemory2));
            Assert.IsFalse(PublicKeyMemory1 == PublicKeyMemory2);
            Assert.IsTrue(PublicKeyMemory1 != PublicKeyMemory2);
        }


        [TestMethod]
        public void InstancesFromSameMemoryAreEqual()
        {
            var publicKeyMemory1 = new PublicKeyMemory(Buffer1, Tag.Empty);
            var publicKeyMemory2 = new PublicKeyMemory(Buffer1, Tag.Empty);

            Assert.IsTrue(publicKeyMemory1.Equals(publicKeyMemory2));
            Assert.IsTrue(publicKeyMemory1 == publicKeyMemory2);
            Assert.IsFalse(publicKeyMemory1 != publicKeyMemory2);
        }


        [TestMethod]
        public void SameLengthInstancesWithDifferentDataAreNotEqual()
        {
            var buffer1 = SensitiveMemoryPool<byte>.Shared.Rent(1);
            var buffer2 = SensitiveMemoryPool<byte>.Shared.Rent(1);
            buffer2.Memory.Span[0] = 0x01;

            var publicKeyMemory1 = new PublicKeyMemory(buffer1, Tag.Empty);
            var publicKeyMemory2 = new PublicKeyMemory(buffer2, Tag.Empty);

            Assert.IsFalse(publicKeyMemory1.Equals(publicKeyMemory2));
            Assert.IsTrue(publicKeyMemory1 != publicKeyMemory2);
            Assert.IsFalse(publicKeyMemory1 == publicKeyMemory2);

            publicKeyMemory1.Dispose();
            publicKeyMemory2.Dispose();
        }


        [TestMethod]
        public void ComparisonWithTypeAndObjectSucceeds()
        {
            Assert.IsTrue((object)PublicKeyMemory1 == PublicKeyMemory3);
            Assert.IsTrue(PublicKeyMemory1 == (object)PublicKeyMemory3);
            Assert.IsFalse((object)PublicKeyMemory1 != PublicKeyMemory3);
            Assert.IsFalse(PublicKeyMemory1 != (object)PublicKeyMemory3);
        }


        [TestMethod]
        public void EqualsWithTypeAndObjectSucceeds()
        {
            Assert.IsTrue(((object)PublicKeyMemory1).Equals(PublicKeyMemory3));
            Assert.IsTrue(PublicKeyMemory1.Equals((object)PublicKeyMemory3));
        }


        [TestMethod]
        public void ComparisonWithObjectAndObjectFails()
        {
            //The reasons for this is that == operator is searched
            //at compile time. Compiler does not find the overloads
            //and so the test fails. This is included here for the sake
            //of completeness. See EqualsWithObjectAndObjectSucceeds.            
            Assert.IsFalse((object)PublicKeyMemory1 == (object)PublicKeyMemory3);
        }


        [TestMethod]
        public void EqualsWithObjectAndObjectSucceeds()
        {
            //As opposed to ComparisonWithObjectAndObjectFails,
            //.Equals is a runtime construct and it does find
            //the overloads and so this comparison succeeds.
            Assert.IsTrue(((object)PublicKeyMemory1).Equals(PublicKeyMemory3));
        }
    }
}
