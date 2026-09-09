using System;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Wire-format tests for <see cref="SignSequenceStartInput"/> (TPM2_SignSequenceStart, Table 87),
/// <see cref="SequenceUpdateInput"/> (TPM2_SequenceUpdate, Table 91), and <see cref="SignSequenceCompleteInput"/>
/// (TPM2_SignSequenceComplete, Table 124), asserting the handle and parameter areas each frames against
/// hand-computed big-endian octets, mirroring <see cref="SignDigestInputFramingTests"/>'s wire-format style for
/// <see cref="ITpmCommandInput"/> types.
/// </summary>
[TestClass]
internal sealed class SequenceInputFramingTests
{
    /// <summary>
    /// <see cref="SignSequenceStartInput.Create"/> frames the key handle, a <c>TPM2B_AUTH</c> carrying the
    /// caller-supplied <c>sequenceAuth</c>, and an empty <c>TPM2B_SIGNATURE_CTX</c> — the shape every scheme this
    /// simulator executes resolves to
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.5, Table 87). The command's first parameter (<c>auth</c>)
    /// is a <c>TPM2B</c>, so <see cref="ITpmCommandInput.FirstCommandParameterIsEncryptable"/> is <see langword="true"/>.
    /// </summary>
    [TestMethod]
    public void SignSequenceStartInputCreateFramesTheHandleAndParametersByteExactlyPerTable87()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x80000001u);
        byte[] sequenceAuth = [0x11, 0x22, 0x33, 0x44];

        using SignSequenceStartInput input = SignSequenceStartInput.Create(keyHandle, sequenceAuth, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_SignSequenceStart, input.CommandCode);
        Assert.AreEqual(0x000001AAu, (uint)input.CommandCode, "TPM_CC_SignSequenceStart must equal Table 12's raw value 0x000001AA (TPM 2.0 Library Part 2: Structures, clause 6.5.2) — an enum member compared only to itself would still pass with a wrong wire value.");
        Assert.IsTrue(input.FirstCommandParameterIsEncryptable, "auth is the first TPM2B parameter, so it must be marked encryptable.");

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x01];
        byte[] expectedParameters =
        [
            0x00, 0x04, 0x11, 0x22, 0x33, 0x44, //auth: TPM2B_AUTH, size 4.
            0x00, 0x00 //context: TPM2B_SIGNATURE_CTX, empty.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="SignSequenceStartInput.CreateFromPassword"/> frames the UTF-8 octets of the caller-supplied
    /// password as the <c>auth</c> <c>TPM2B_AUTH</c>, matching the password-to-authValue convention
    /// <see cref="Tpm2bAuth.CreateFromPassword"/> applies on the wire
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.5, Table 87).
    /// </summary>
    [TestMethod]
    public void SignSequenceStartInputCreateFromPasswordFramesTheUtf8PasswordBytesByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x80000002u);
        const string SequencePassword = "seq-pw";
        byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(SequencePassword);

        using SignSequenceStartInput input = SignSequenceStartInput.CreateFromPassword(keyHandle, SequencePassword, pool);

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x02];
        byte[] expectedParameters = new byte[2 + passwordBytes.Length + 2];
        expectedParameters[0] = 0x00;
        expectedParameters[1] = (byte)passwordBytes.Length;
        passwordBytes.CopyTo(expectedParameters, 2);
        expectedParameters[^2] = 0x00;
        expectedParameters[^1] = 0x00;

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="SequenceUpdateInput.Create"/> frames the sequence handle and a <c>TPM2B_MAX_BUFFER</c> carrying
    /// the caller-supplied octets
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.7, Table 91). <c>buffer</c> is the command's only, and
    /// therefore first, parameter, so <see cref="ITpmCommandInput.FirstCommandParameterIsEncryptable"/> is
    /// <see langword="true"/>.
    /// </summary>
    [TestMethod]
    public void SequenceUpdateInputCreateFramesTheHandleAndParametersByteExactlyPerTable91()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject sequenceHandle = TpmiDhObject.FromValue(0x80000010u);
        byte[] buffer = [0xAA, 0xBB, 0xCC];

        using SequenceUpdateInput input = SequenceUpdateInput.Create(sequenceHandle, buffer, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_SequenceUpdate, input.CommandCode);
        Assert.AreEqual(0x0000015Cu, (uint)input.CommandCode, "TPM_CC_SequenceUpdate must equal Table 12's raw value 0x0000015C (TPM 2.0 Library Part 2: Structures, clause 6.5.2) — an enum member compared only to itself would still pass with a wrong wire value.");
        Assert.IsTrue(input.FirstCommandParameterIsEncryptable, "buffer is the only, and therefore first, TPM2B parameter, so it must be marked encryptable.");

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x10];
        byte[] expectedParameters = [0x00, 0x03, 0xAA, 0xBB, 0xCC];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// An empty <c>buffer</c> frames as the empty <c>TPM2B_MAX_BUFFER</c> — "may be any size up to the limits of
    /// the TPM," including zero
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.7, Table 91).
    /// </summary>
    [TestMethod]
    public void SequenceUpdateInputCreateWithAnEmptyBufferFramesTheEmptyTpm2bByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject sequenceHandle = TpmiDhObject.FromValue(0x80000011u);

        using SequenceUpdateInput input = SequenceUpdateInput.Create(sequenceHandle, ReadOnlySpan<byte>.Empty, pool);

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x11];
        byte[] expectedParameters = [0x00, 0x00];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// A <c>buffer</c> one octet over <see cref="Tpm2bMaxBuffer.MaxSize"/> is refused by
    /// <see cref="SequenceUpdateInput.Create"/> with an <see cref="ArgumentException"/> before any pool rental
    /// occurs — the bound is checked against the caller-supplied span itself, so the tracking pool's outstanding
    /// count never moves
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.8, Table 96's <c>MAX_2B_BUFFER_SIZE</c> floor, this
    /// library's fixed bound).
    /// </summary>
    [TestMethod]
    public void SequenceUpdateInputCreateOverMaxSizeThrowsArgumentExceptionAndRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        TpmiDhObject sequenceHandle = TpmiDhObject.FromValue(0x80000012u);
        byte[] tooLarge = new byte[Tpm2bMaxBuffer.MaxSize + 1];

        _ = Assert.ThrowsExactly<ArgumentException>(() => SequenceUpdateInput.Create(sequenceHandle, tooLarge, trackingPool.Pool));

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A buffer over MaxSize must be refused before any rental, so the pool stays balanced.");
    }

    /// <summary>
    /// A <c>buffer</c> one octet over <see cref="Tpm2bMaxBuffer.MaxSize"/> is refused by
    /// <see cref="SignSequenceCompleteInput.Create"/> with an <see cref="ArgumentException"/> before any pool
    /// rental occurs, mirroring <see cref="SequenceUpdateInputCreateOverMaxSizeThrowsArgumentExceptionAndRentsNothing"/>
    /// for Table 124's identical <c>TPM2B_MAX_BUFFER buffer</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6, Table 124).
    /// </summary>
    [TestMethod]
    public void SignSequenceCompleteInputCreateOverMaxSizeThrowsArgumentExceptionAndRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        TpmiDhObject sequenceHandle = TpmiDhObject.FromValue(0x80000022u);
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x80000005u);
        byte[] tooLarge = new byte[Tpm2bMaxBuffer.MaxSize + 1];

        _ = Assert.ThrowsExactly<ArgumentException>(() => SignSequenceCompleteInput.Create(sequenceHandle, keyHandle, tooLarge, trackingPool.Pool));

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A buffer over MaxSize must be refused before any rental, so the pool stays balanced.");
    }

    /// <summary>
    /// Pins the raw numeric values behind <see cref="TpmCcConstants.TPM_CC_VerifySequenceStart"/>,
    /// <see cref="TpmCcConstants.TPM_CC_VerifySequenceComplete"/>,
    /// <see cref="TpmRcConstants.TPM_RC_ONE_SHOT_SIGNATURE"/>, and
    /// <see cref="TpmRcConstants.TPM_RC_SIGN_CONTEXT_KEY"/> against the published tables — an enum member
    /// compared only to itself would still pass with a wrong wire value
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 6.5.2, Table 12; clause 6.6.3, Table 18).
    /// </summary>
    [TestMethod]
    public void SequenceVerifyCommandCodesAndResponseCodesMatchTheirPublishedTableValues()
    {
        //Read through an array so the comparison is against the runtime value, never a compile-time fold of the
        //enum member against itself.
        TpmCcConstants[] commandCodes = [TpmCcConstants.TPM_CC_VerifySequenceStart, TpmCcConstants.TPM_CC_VerifySequenceComplete];
        TpmRcConstants[] responseCodes = [TpmRcConstants.TPM_RC_ONE_SHOT_SIGNATURE, TpmRcConstants.TPM_RC_SIGN_CONTEXT_KEY];

        Assert.AreEqual(0x000001A9u, (uint)commandCodes[0], "TPM_CC_VerifySequenceStart must equal Table 12's raw value 0x000001A9.");
        Assert.AreEqual(0x000001A3u, (uint)commandCodes[1], "TPM_CC_VerifySequenceComplete must equal Table 12's raw value 0x000001A3.");
        Assert.AreEqual(0x000000ACu, (uint)responseCodes[0], "TPM_RC_ONE_SHOT_SIGNATURE must equal Table 17's raw value RC_FMT1 + 0x02C = 0x0AC.");
        Assert.AreEqual(0x000000ADu, (uint)responseCodes[1], "TPM_RC_SIGN_CONTEXT_KEY must equal Table 17's raw value RC_FMT1 + 0x02D = 0x0AD.");
    }

    /// <summary>
    /// <see cref="SignSequenceCompleteInput.Create"/> frames <c>sequenceHandle</c> then <c>keyHandle</c>, in that
    /// order, in the handle area, followed by a <c>TPM2B_MAX_BUFFER buffer</c> as the sole parameter
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6, Table 124). <c>buffer</c> is the first, and only,
    /// parameter, so <see cref="ITpmCommandInput.FirstCommandParameterIsEncryptable"/> is <see langword="true"/>.
    /// </summary>
    [TestMethod]
    public void SignSequenceCompleteInputCreateFramesBothHandlesInOrderAndParametersByteExactlyPerTable124()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject sequenceHandle = TpmiDhObject.FromValue(0x80000020u);
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x80000003u);
        byte[] buffer = [0x01, 0x02, 0x03, 0x04, 0x05];

        using SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(sequenceHandle, keyHandle, buffer, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_SignSequenceComplete, input.CommandCode);
        Assert.AreEqual(0x000001A4u, (uint)input.CommandCode, "TPM_CC_SignSequenceComplete must equal Table 12's raw value 0x000001A4 (TPM 2.0 Library Part 2: Structures, clause 6.5.2) — an enum member compared only to itself would still pass with a wrong wire value.");
        Assert.IsTrue(input.FirstCommandParameterIsEncryptable, "buffer is the only, and therefore first, TPM2B parameter, so it must be marked encryptable.");

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x20, 0x80, 0x00, 0x00, 0x03];
        byte[] expectedParameters = [0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// An empty trailing <c>buffer</c> is conformant on <see cref="SignSequenceCompleteInput"/> — the accumulated
    /// sequence content alone may already be the complete message, needing nothing appended at completion
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6, Table 124).
    /// </summary>
    [TestMethod]
    public void SignSequenceCompleteInputCreateWithAnEmptyBufferFramesTheEmptyTpm2bByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject sequenceHandle = TpmiDhObject.FromValue(0x80000021u);
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x80000004u);

        using SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(sequenceHandle, keyHandle, ReadOnlySpan<byte>.Empty, pool);

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x21, 0x80, 0x00, 0x00, 0x04];
        byte[] expectedParameters = [0x00, 0x00];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// Frames <paramref name="input"/>'s handle and parameter areas into freshly-sized buffers and asserts each
    /// reproduces the hand-computed octets exactly, and that <see cref="ITpmCommandInput.GetSerializedSize"/>
    /// accounts for precisely the two areas combined, mirroring <c>SignDigestInputFramingTests.AssertFraming</c>.
    /// </summary>
    /// <param name="input">The command input under test.</param>
    /// <param name="expectedHandles">The hand-computed handle area.</param>
    /// <param name="expectedParameters">The hand-computed parameter area.</param>
    private static void AssertFraming(ITpmCommandInput input, byte[] expectedHandles, byte[] expectedParameters)
    {
        Assert.AreEqual(expectedHandles.Length + expectedParameters.Length, input.GetSerializedSize(),
            "GetSerializedSize must account for exactly the handle area plus the parameter area.");

        byte[] handles = new byte[expectedHandles.Length];
        var handleWriter = new TpmWriter(handles);
        input.WriteHandles(ref handleWriter);
        Assert.AreEqual(handles.Length, handleWriter.Written, "WriteHandles must fill exactly the handle area.");
        Assert.AreSequenceEqual(expectedHandles, handles);

        byte[] parameters = new byte[expectedParameters.Length];
        var paramWriter = new TpmWriter(parameters);
        input.WriteParameters(ref paramWriter);
        Assert.AreEqual(parameters.Length, paramWriter.Written, "WriteParameters must fill exactly the parameter area.");
        Assert.AreSequenceEqual(expectedParameters, parameters);
    }
}
