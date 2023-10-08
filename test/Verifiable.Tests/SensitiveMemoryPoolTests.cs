using System;
using Xunit;

namespace Verifiable.Core
{
    /// <summary>
    /// The the <see cref="SensitiveMemoryPool{T}"/> that is included with Verifiable library.
    /// </summary>
    public class SensitiveMemoryPoolTests
    {
        [Fact]
        public void ZeroLengthRentSucceeds()
        {
            var buffer = SensitiveMemoryPool<byte>.Shared.Rent(0);
            Assert.Equal(0, buffer.Memory.Length);
        }


        [Fact]
        public void SharedInstanceRentsAreExactlyRequestedLength()
        {
            //This is not an exhaustive search nor proof-by-construction, but nevertheless
            //tests these different length arrays.
            for(int bufferLengthRequest = 1; bufferLengthRequest < 10; bufferLengthRequest++)
            {
                var buffer = SensitiveMemoryPool<byte>.Shared.Rent(bufferLengthRequest);
                Assert.Equal(bufferLengthRequest, buffer.Memory.Length);
            }
        }


        [Fact]
        public void NegativeLengthRentFailsWithTheCorrectMessage()
        {
            const string ParameterName = "exactBufferSize";
            var exception1 = Assert.Throws<ArgumentOutOfRangeException>(() => SensitiveMemoryPool<byte>.Shared.Rent(-1));

            Assert.Equal(ParameterName, exception1.ParamName);
        }
    }
}
