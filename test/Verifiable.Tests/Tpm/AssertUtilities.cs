using Verifiable.Tpm;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Assertion helpers for TPM command results.
/// </summary>
internal static class AssertUtilities
{
    /// <summary>
    /// Fails the test if the result is not a success, including the error code in the failure message.
    /// </summary>
    /// <typeparam name="T">The result value type.</typeparam>
    /// <param name="result">The TPM command result to assert.</param>
    /// <param name="operation">A description of the operation, used in the failure message.</param>
    public static void AssertSuccess<T>(TpmResult<T> result, string operation)
    {
        if(result.IsSuccess)
        {
            return;
        }

        if(result.IsTpmError)
        {
            Assert.Fail($"{operation} failed with TPM error: {result.ResponseCode} (0x{(uint)result.ResponseCode:X8}).");
        }
        else if(result.IsTransportError)
        {
            Assert.Fail($"{operation} failed with transport error: 0x{result.TransportErrorCode:X8}.");
        }
        else
        {
            Assert.Fail($"{operation} failed with unknown error.");
        }
    }
}