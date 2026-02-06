using Verifiable.Tpm;

namespace Verifiable.Tests.Tpm
{
    /// <summary>
    /// TPM testing utilities for assertions.
    /// </summary>
    internal static class AssertUtilities
    {
        /// <summary>
        /// Asserts the TPM call was a success.
        /// </summary>
        /// <typeparam name="T">The call type.</typeparam>
        /// <param name="result">The result.</param>
        /// <param name="operation">The operation description.</param>
        public static void AssertSuccess<T>(TpmResult<T> result, string operation) where T : class
        {
            if(result.IsSuccess)
            {
                return;
            }

            if(result.IsTpmError)
            {
                Assert.Fail($"{operation} failed with TPM error: {result.ResponseCode}");
            }
            else if(result.IsTransportError)
            {
                Assert.Fail($"{operation} failed with transport error: {result.TransportErrorCode}");
            }
            else
            {
                Assert.Fail($"{operation} failed with unknown error.");
            }
        }
    }
}
