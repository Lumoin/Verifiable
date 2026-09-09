using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Wire-format tests for <see cref="GetTestResultResponse"/> (TPM2_GetTestResult, TPM 2.0 Library Part 3,
/// clause 10.4.2, Table 13): asserts the response's two-field parameter order — <c>outData</c>
/// (TPM2B_MAX_BUFFER) then <c>testResult</c> (TPM_RC) — against hand-computed big-endian octets, mirroring
/// <see cref="EncapsulateResponseFramingTests"/>'s wire-format style.
/// </summary>
[TestClass]
internal sealed class GetTestResultResponseFramingTests
{
    /// <summary>
    /// A hand-framed Table 13 response with an EMPTY <c>outData</c> — the shape this simulator's own
    /// <c>TPM2_GetTestResult()</c> always emits, since it runs no real self-test diagnostics — parses to the
    /// expected fields byte-exactly.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 10.4.2, Table 13</see>.
    /// </summary>
    [TestMethod]
    public void GetTestResultResponseParsesEmptyOutDataAndTestResultByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] wire =
        [
            0x00, 0x00,             //outData: TPM2B_MAX_BUFFER, size 0.
            0x00, 0x00, 0x00, 0x00, //testResult: TPM_RC_SUCCESS.
        ];

        var reader = new TpmReader(wire);
        using GetTestResultResponse response = GetTestResultResponse.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining, "The response's TPM2B and TPM_RC must account for every octet in the wire frame.");
        Assert.AreEqual(0, response.OutData.Length, "An empty outData parses to a zero-length buffer.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, response.TestResult, "testResult follows outData and reads TPM_RC_SUCCESS from the zero UINT32 (Part 3, clause 10.4.2, Table 13).");
    }

    /// <summary>
    /// A hand-framed Table 13 response with a NON-EMPTY <c>outData</c> and a non-zero <c>testResult</c> — the
    /// general shape a real TPM's manufacturer-specific diagnostic buffer would carry, even though this
    /// simulator never emits one — parses to the expected fields byte-exactly, proving the host codec handles
    /// the general case rather than only the simulator's own always-empty answer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 10.4.2, Table 13</see>.
    /// </summary>
    [TestMethod]
    public void GetTestResultResponseParsesNonEmptyOutDataAndTestResultByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] outDataBytes = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] wire =
        [
            0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, //outData: TPM2B_MAX_BUFFER, size 4.
            0x00, 0x00, 0x01, 0x01,             //testResult: an arbitrary non-zero UINT32, to prove the field is read as-is.
        ];

        var reader = new TpmReader(wire);
        using GetTestResultResponse response = GetTestResultResponse.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining, "The response's TPM2B and TPM_RC must account for every octet in the wire frame.");
        Assert.AreSequenceEqual(outDataBytes, response.OutData.Span.ToArray());
        Assert.AreEqual((TpmRcConstants)0x00000101u, response.TestResult, "testResult is read as the raw wire UINT32, whatever value it carries.");
    }

    /// <summary>
    /// <see cref="GetTestResultResponse.Dispose"/> releases the pooled <c>outData</c> carrier it rented at
    /// parse time — the outstanding rental count returns to its pre-parse baseline.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 10.4.2, Table 13</see>.
    /// </summary>
    [TestMethod]
    public void GetTestResultResponseDisposeReleasesItsPooledOutDataCarrier()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        byte[] wire =
        [
            0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF,
            0x00, 0x00, 0x00, 0x00,
        ];

        long baseline = trackingPool.OutstandingCount;

        var reader = new TpmReader(wire);
        GetTestResultResponse response = GetTestResultResponse.Parse(ref reader, pool);
        response.Dispose();

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Dispose must return every carrier Parse rented.");
    }

    /// <summary>
    /// A wire frame declaring an <c>outData</c> width wider than the octets actually present refuses rather than
    /// reading past the buffer: <c>Tpm2bMaxBuffer.Parse</c> underruns the reader, which is a size fault, not an
    /// escape from the fail-closed contract every TPM2B parse in this codebase shares
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 10.4.2, Table 13</see>).
    /// </summary>
    [TestMethod]
    public void GetTestResultResponseWithATruncatedOutDataIsRefused()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] wire =
        [
            0x00, 0x04, 0xDE, 0xAD, //outData: TPM2B_MAX_BUFFER declares size 4 but only 2 octets of content follow.
        ];

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => ParseAndDispose(wire, pool),
            "A declared outData width wider than the octets present must refuse rather than read past the buffer.");
    }

    /// <summary>
    /// A wire frame whose <c>outData</c> is fully present but whose trailing <c>testResult</c> field is truncated
    /// refuses rather than reading past the buffer, and the <c>outData</c> carrier <see cref="GetTestResultResponse.Parse"/>
    /// already rented is not orphaned by the refusal — its own <c>catch</c> releases it before rethrowing.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 10.4.2, Table 13</see>.
    /// </summary>
    [TestMethod]
    public void GetTestResultResponseWithATruncatedTestResultReleasesTheRentedOutDataCarrier()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        byte[] wire =
        [
            0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, //outData: TPM2B_MAX_BUFFER, size 4, fully present.
            0x00, 0x00,                         //testResult: TPM_RC (UINT32) truncated to 2 octets.
        ];

        long baseline = trackingPool.OutstandingCount;

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => ParseAndDispose(wire, pool),
            "A response truncated after outData, before testResult's four octets are all present, must refuse rather than read past the buffer.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The outData carrier Parse already rented must not be orphaned when the trailing testResult field cannot be read.");
    }

    /// <summary>
    /// Parses <paramref name="wire"/> through <see cref="GetTestResultResponse.Parse"/> and immediately disposes
    /// the result — the single-statement body <see cref="Assert.ThrowsExactly{T}(Action, string)"/> requires,
    /// since a <see cref="TpmReader"/> is a ref struct a lambda cannot capture.
    /// </summary>
    /// <param name="wire">The wire octets to parse.</param>
    /// <param name="pool">The memory pool.</param>
    private static void ParseAndDispose(byte[] wire, BaseMemoryPool pool)
    {
        var reader = new TpmReader(wire);
        GetTestResultResponse.Parse(ref reader, pool).Dispose();
    }
}
