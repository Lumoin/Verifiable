using Verifiable.Core;

namespace Verifiable.Tests.Core
{
    /// <summary>
    /// The the <see cref="SensitiveMemoryPool{T}"/> that is included with Verifiable library.
    /// </summary>
    [TestClass]
    public sealed class SensitiveMemoryPoolTests
    {
        [TestMethod]
        public void ZeroLengthRentSucceeds()
        {
            var buffer = SensitiveMemoryPool<byte>.Shared.Rent(0);
            Assert.AreEqual(0, buffer.Memory.Length);
        }


        [TestMethod]
        public void SharedInstanceRentsAreExactlyRequestedLength()
        {
            //This is not an exhaustive search nor proof-by-construction, but nevertheless
            //tests these different length arrays.
            for(int bufferLengthRequest = 1; bufferLengthRequest < 10; bufferLengthRequest++)
            {
                var buffer = SensitiveMemoryPool<byte>.Shared.Rent(bufferLengthRequest);
                Assert.AreEqual(bufferLengthRequest, buffer.Memory.Length);
            }
        }


        [TestMethod]
        public void NegativeLengthRentFailsWithTheCorrectMessage()
        {
            const string ParameterName = "exactBufferSize";
            var exception1 = Assert.ThrowsException<ArgumentOutOfRangeException>(() => SensitiveMemoryPool<byte>.Shared.Rent(-1));

            Assert.AreEqual(ParameterName, exception1.ParamName);
        }
    }
}
