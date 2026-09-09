using System;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response parameters for TPM2_GetTestResult.
/// </summary>
/// <remarks>
/// <para>
/// This type represents the complete response parameter area for the
/// TPM2_GetTestResult command.
/// </para>
/// <para>
/// <b>Response parameters (Part 3, clause 10.4, Table 13):</b>
/// </para>
/// <list type="bullet">
///   <item><description>outData (TPM2B_MAX_BUFFER) - test result data; manufacturer-specific (Part 3, clause 10.4.1: "This command returns manufacturer-specific information regarding the results of a self-test and an indication of the test status."), empty on a simulator that runs no real self-test diagnostics.</description></item>
///   <item><description>testResult (TPM_RC) - the value that a subsequent TPM2_SelfTest() would return.</description></item>
/// </list>
/// <para>
/// The wire tag admits <c>TPM_ST_SESSIONS</c> "if an audit or encrypt session is present" (Table 12), so
/// <see cref="OutData"/> is the first response parameter an <c>encrypt</c> companion session may protect.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class GetTestResultResponse: ITpmWireType, IDisposable
{
    /// <summary>
    /// Whether <see cref="Dispose"/> has already released the owned <see cref="OutData"/> rental.
    /// </summary>
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the test result data (manufacturer-specific; empty on this simulator).
    /// </summary>
    public Tpm2bMaxBuffer OutData { get; }

    /// <summary>
    /// Gets the value a subsequent TPM2_SelfTest() would return.
    /// </summary>
    public TpmRcConstants TestResult { get; }

    /// <summary>
    /// Initializes the response around the parsed, owned <paramref name="outData"/> rental and the trailing
    /// <paramref name="testResult"/> code.
    /// </summary>
    /// <param name="outData">The owned, pooled test result data.</param>
    /// <param name="testResult">The value a subsequent TPM2_SelfTest() would return.</param>
    private GetTestResultResponse(Tpm2bMaxBuffer outData, TpmRcConstants testResult)
    {
        OutData = outData;
        TestResult = testResult;
    }

    /// <summary>
    /// Parses the response parameters from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for allocations.</param>
    /// <returns>The parsed response.</returns>
    public static GetTestResultResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        Tpm2bMaxBuffer outData = Tpm2bMaxBuffer.Parse(ref reader, pool);
        try
        {
            var testResult = (TpmRcConstants)reader.ReadUInt32();

            return new GetTestResultResponse(outData, testResult);
        }
        catch
        {
            //outData's only owner is this frame until the constructed response adopts it, so a testResult
            //field the frame does not carry must release its pooled rental rather than orphan it.
            outData.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Releases resources owned by this response.
    /// </summary>
    public void Dispose()
    {
        if(!Disposed)
        {
            OutData.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger's one-line rendering: the octet count and the result code, never the octets.</summary>
    private string DebuggerDisplay => $"GetTestResultResponse({OutData.Length} bytes, {TestResult})";
}
