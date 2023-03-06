using System.Buffers;
using Verifiable.Core.Cryptography;
using Xunit;

namespace Verifiable.Core
{
    /// <summary>
    /// Tests for <see cref="PublicKeyMemory" /> <see cref="System.IEquatable{T}" /> implementation.
    /// </summary>
    public class PublicKeyMemoryEquatableTests
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
        private static PublicKeyMemory PublicKeyMemory1 => new PublicKeyMemory(Buffer1, Tag.Empty);

        /// <summary>
        /// A second instance of public key memory used in multiple tests.
        /// </summary>        
        private static PublicKeyMemory PublicKeyMemory2 => new PublicKeyMemory(Buffer2, Tag.Empty);

        /// <summary>
        /// A third instance of public key memory used in multiple tests.
        /// </summary>        
        private static PublicKeyMemory PublicKeyMemory3 => new PublicKeyMemory(Buffer1, Tag.Empty);


        [Fact]
        public void InstancesFromDifferentSizedBuffersAreNotEqual()
        {            
            Assert.False(PublicKeyMemory1.Equals(PublicKeyMemory2));
            Assert.False(PublicKeyMemory1 == PublicKeyMemory2);
            Assert.True(PublicKeyMemory1 != PublicKeyMemory2);
        }        


        [Fact]
        public void InstancesFromSameMemoryAreEqual()
        {            
            var publicKeyMemory1 = new PublicKeyMemory(Buffer1, Tag.Empty);
            var publicKeyMemory2 = new PublicKeyMemory(Buffer1, Tag.Empty);
            
            Assert.True(publicKeyMemory1.Equals(publicKeyMemory2));
            Assert.True(publicKeyMemory1 == publicKeyMemory2);
            Assert.False(publicKeyMemory1 != publicKeyMemory2);
        }


        [Fact]
        public void SameLengthInstancesWithDifferentDataAreNotEqual()
        {
            var buffer1 = SensitiveMemoryPool<byte>.Shared.Rent(1);
            var buffer2 = SensitiveMemoryPool<byte>.Shared.Rent(1);
            buffer2.Memory.Span[0] = 0x01;

            var publicKeyMemory1 = new PublicKeyMemory(buffer1, Tag.Empty);
            var publicKeyMemory2 = new PublicKeyMemory(buffer2, Tag.Empty);

            Assert.False(publicKeyMemory1.Equals(publicKeyMemory2));
            Assert.True(publicKeyMemory1 != publicKeyMemory2);
            Assert.False(publicKeyMemory1 == publicKeyMemory2);

            publicKeyMemory1.Dispose();
            publicKeyMemory2.Dispose();
        }


        [Fact]
        public void ComparisonWithTypeAndObjectSucceeds()
        {            
            Assert.True((object)PublicKeyMemory1 == PublicKeyMemory3);
            Assert.True(PublicKeyMemory1 == (object)PublicKeyMemory3);
            Assert.False((object)PublicKeyMemory1 != PublicKeyMemory3);
            Assert.False(PublicKeyMemory1 != (object)PublicKeyMemory3);
        }

        
        [Fact]
        public void EqualsWithTypeAndObjectSucceeds()
        {
            Assert.True(((object)PublicKeyMemory1).Equals(PublicKeyMemory3));
            Assert.True(PublicKeyMemory1.Equals((object)PublicKeyMemory3));
        }


        [Fact]
        public void ComparisonWithObjectAndObjectFails()
        {
            //The reasons for this is that == operator is searched
            //at compile time. Compiler does not find the overloads
            //and so the test fails. This is included here for the sake
            //of completeness. See EqualsWithObjectAndObjectSucceeds.            
            Assert.False((object)PublicKeyMemory1 == (object)PublicKeyMemory3);
        }


        [Fact]
        public void EqualsWithObjectAndObjectSucceeds()
        {
            //As opposed to ComparisonWithObjectAndObjectFails,
            //.Equals is a runtime construct and it does find
            //the overloads and so this comparison succeeds.
            Assert.True(((object)PublicKeyMemory1).Equals(PublicKeyMemory3));
        }
    }
}
