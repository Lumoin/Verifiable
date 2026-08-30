using System;
using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
namespace Verifiable.Tests.Tpm;

/// <summary>
/// Wire-format tests for <see cref="VerifySequenceStartInput"/> (TPM2_VerifySequenceStart, Table 89),
/// <see cref="VerifySequenceCompleteInput"/> (TPM2_VerifySequenceComplete, Table 118), and
/// <see cref="Tpm2bSignatureHint"/> (TPM2B_SIGNATURE_HINT, Table 222), asserting the handle and parameter areas
/// each frames against hand-computed big-endian octets, mirroring <see cref="SequenceInputFramingTests"/>'s
/// wire-format style for the signing-sequence counterparts and <see cref="SignDigestInputFramingTests"/>'s
/// <c>TPMT_SIGNATURE</c> framing for <c>VerifyDigestSignatureInput</c>.
/// </summary>
[TestClass]
internal sealed class VerifySequenceInputFramingTests
{
    /// <summary>
    /// <see cref="VerifySequenceStartInput.Create"/> frames the key handle, a <c>TPM2B_AUTH</c> carrying the
    /// caller-supplied <c>sequenceAuth</c>, an empty <c>TPM2B_SIGNATURE_HINT</c>, and an empty
    /// <c>TPM2B_SIGNATURE_CTX</c> — the shape every scheme this simulator executes resolves to
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.6, Table 89). The command's first parameter (<c>auth</c>)
    /// is a <c>TPM2B</c>, so <see cref="ITpmCommandInput.FirstCommandParameterIsEncryptable"/> is <see langword="true"/>.
    /// </summary>
    [TestMethod]
    public void VerifySequenceStartInputCreateFramesTheHandleAndParametersByteExactlyPerTable89()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x80000001u);
        byte[] sequenceAuth = [0x11, 0x22, 0x33, 0x44];

        using VerifySequenceStartInput input = VerifySequenceStartInput.Create(keyHandle, sequenceAuth, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_VerifySequenceStart, input.CommandCode);
        Assert.AreEqual(0x000001A9u, (uint)input.CommandCode, "TPM_CC_VerifySequenceStart must equal Table 12's raw value 0x000001A9 (TPM 2.0 Library Part 2: Structures, clause 6.5.2) — an enum member compared only to itself would still pass with a wrong wire value.");
        Assert.IsTrue(input.FirstCommandParameterIsEncryptable, "auth is the first TPM2B parameter, so it must be marked encryptable.");

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x01];
        byte[] expectedParameters =
        [
            0x00, 0x04, 0x11, 0x22, 0x33, 0x44, //auth: TPM2B_AUTH, size 4.
            0x00, 0x00, //hint: TPM2B_SIGNATURE_HINT, empty.
            0x00, 0x00 //context: TPM2B_SIGNATURE_CTX, empty.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="VerifySequenceStartInput.CreateFromPassword"/> frames the UTF-8 octets of the caller-supplied
    /// password as the <c>auth</c> <c>TPM2B_AUTH</c>, matching the password-to-authValue convention
    /// <see cref="Tpm2bAuth.CreateFromPassword"/> applies on the wire
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.6, Table 89).
    /// </summary>
    [TestMethod]
    public void VerifySequenceStartInputCreateFromPasswordFramesTheUtf8PasswordBytesByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x80000002u);
        const string SequencePassword = "verify-seq-pw";
        byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(SequencePassword);

        using VerifySequenceStartInput input = VerifySequenceStartInput.CreateFromPassword(keyHandle, SequencePassword, pool);

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x02];
        byte[] expectedParameters = new byte[2 + passwordBytes.Length + 2 + 2];
        expectedParameters[0] = 0x00;
        expectedParameters[1] = (byte)passwordBytes.Length;
        passwordBytes.CopyTo(expectedParameters, 2);
        //Trailing hint (2 zero octets) then context (2 zero octets), both empty.
        expectedParameters[^4] = 0x00;
        expectedParameters[^3] = 0x00;
        expectedParameters[^2] = 0x00;
        expectedParameters[^1] = 0x00;

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="Tpm2bSignatureHint.MaxSize"/> is pinned to the raw value 57: RFC 8032 §5.2's Ed448 encoded R is
    /// 57 octets, the widest hint any v185 verification algorithm carries (§5.1's Ed25519 R is 32) — comparing
    /// the constant only to itself would still pass with a narrower bound and silently lose the Curve448 case
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.9, Table 222; RFC 8032, §5.2).
    /// </summary>
    /// <summary>
    /// The host framer refuses an HMAC member whose digest is not the hash's width before anything reaches the
    /// wire: <c>TPMU_SIGNATURE</c>'s HMAC member is a <c>TPMT_HA</c> whose digest is unsized, so any other width
    /// would desynchronize every parameter after it — <see cref="VerifySequenceCompleteInput"/> throws
    /// <see cref="InvalidOperationException"/> from <c>WriteParameters</c>, the posture its ECDSA arm takes for an
    /// odd-length pair (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 2: Structures, clause 10.2.2, Table 89).
    /// </summary>
    [TestMethod]
    public void VerifySequenceCompleteInputRefusesAnHmacMemberWhoseWidthIsNotTheHashes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.Create(
            TpmiDhObject.FromValue(0x80000002), TpmiDhObject.FromValue(0x80000001), new byte[33], TpmAlgIdConstants.TPM_ALG_HMAC, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        using IMemoryOwner<byte> scratch = pool.Rent(input.GetSerializedSize());

        _ = Assert.ThrowsExactly<InvalidOperationException>(() => Frame(input, scratch.Memory.Span));

        static void Frame(VerifySequenceCompleteInput input, Span<byte> destination)
        {
            var writer = new TpmWriter(destination);
            input.WriteParameters(ref writer);
        }
    }

    [TestMethod]
    public void Tpm2bSignatureHintMaxSizeIsFiftySevenOctets()
    {
        //Read through an array so the comparison is against the runtime value, never a compile-time fold of the
        //constant against itself.
        int[] bounds = [Tpm2bSignatureHint.MaxSize];

        Assert.AreEqual(57, bounds[0], "MaxSize must equal RFC 8032 §5.2's Ed448 encoded R width (57 octets) — Table 222 names no numeric MAX_SIGNATURE_HINT_SIZE, so the widest EdDSA hint any verification algorithm defines is the bound.");
    }

    /// <summary>
    /// A non-empty <c>hint</c>, bypassing <see cref="VerifySequenceStartInput"/>'s own fixed
    /// <see cref="Tpm2bSignatureHint.Empty"/>, is admitted by the wire type itself — clause 17.6's zero-length
    /// rule is a command-layer refusal, not a bound this type enforces. A hint exactly at MaxSize rents from the
    /// pool and returns it once disposed
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.9, Table 222).
    /// </summary>
    [TestMethod]
    public void Tpm2bSignatureHintAtMaxSizeIsAccepted()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        byte[] atBound = new byte[Tpm2bSignatureHint.MaxSize];
        atBound.AsSpan().Fill(0x5A);

        Tpm2bSignatureHint hint = Tpm2bSignatureHint.Create(atBound, trackingPool.Pool);
        Assert.IsGreaterThan(baseline, trackingPool.OutstandingCount, "A hint exactly at MaxSize must actually rent, or the balance assertion below is vacuous.");

        Assert.AreEqual(Tpm2bSignatureHint.MaxSize, hint.Size, "A hint exactly at MaxSize (57, EdDSA's encoded R over Curve448) must be accepted.");
        Assert.IsFalse(hint.IsEmpty);
        Assert.IsTrue(atBound.AsSpan().SequenceEqual(hint.Hint));

        hint.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Disposing the at-bound hint must return its rental to the pool.");
    }

    /// <summary>
    /// <see cref="Tpm2bSignatureHint.Create"/> refuses a hint one octet over <see cref="Tpm2bSignatureHint.MaxSize"/>
    /// with an <see cref="ArgumentException"/> BEFORE renting anything — the pool's outstanding count never moves
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.9).
    /// </summary>
    [TestMethod]
    public void Tpm2bSignatureHintCreateOverMaxSizeThrowsArgumentException()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        byte[] pastBound = new byte[Tpm2bSignatureHint.MaxSize + 1];

        _ = Assert.ThrowsExactly<ArgumentException>(() => Tpm2bSignatureHint.Create(pastBound, trackingPool.Pool));

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The MaxSize bound is checked before any rental, so an over-max Create() never rents at all.");
    }

    /// <summary>
    /// <see cref="Tpm2bSignatureHint.Parse"/> refuses a declared size one octet over
    /// <see cref="Tpm2bSignatureHint.MaxSize"/> with an <see cref="InvalidOperationException"/> (<c>TPM_RC_SIZE</c>
    /// semantics) BEFORE renting anything — the pool's outstanding count never moves
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.9).
    /// </summary>
    [TestMethod]
    public void Tpm2bSignatureHintParseOverMaxSizeThrowsBeforeAnyRental()
    {
        byte[] wire = [0x00, 0x3A]; //Size = 58, one over MaxSize (57).
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a plain
        //try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = Tpm2bSignatureHint.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The MaxSize bound is checked before any rental, so an over-max declared size never rents at all.");
    }

    /// <summary>
    /// <see cref="Tpm2bSignatureHint.Parse"/> refuses a declared size (within <see cref="Tpm2bSignatureHint.MaxSize"/>)
    /// that exceeds the octets actually remaining in the reader with an <see cref="ArgumentOutOfRangeException"/>,
    /// and rents nothing
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.9).
    /// </summary>
    [TestMethod]
    public void Tpm2bSignatureHintParseTruncatedDeclarationThrowsArgumentOutOfRangeAndRentsNothing()
    {
        //Declares 10 octets (within MaxSize) but only 2 follow the size prefix.
        byte[] wire = [0x00, 0x0A, 0x01, 0x02];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = Tpm2bSignatureHint.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected ArgumentOutOfRangeException.");
        }
        catch(ArgumentOutOfRangeException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The remaining-octet check runs before the rental it would otherwise size, so a truncated frame never orphans a rental.");
    }

    /// <summary>
    /// <see cref="Tpm2bSignatureHint.Empty"/> frames as two zero octets — the empty <c>TPM2B_SIGNATURE_HINT</c>
    /// every scheme this simulator executes carries — and disposing the shared sentinel leaves it usable for
    /// every other consumer: <see cref="Tpm2bSignatureHint.Hint"/> and <see cref="Tpm2bSignatureHint.WriteTo"/>
    /// are the two members that actually consult <c>Disposed</c>, so the proof reads and re-frames through them
    /// rather than through <see cref="Tpm2bSignatureHint.IsEmpty"/> (a readonly length check no disposal could
    /// ever break)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.9).
    /// </summary>
    [TestMethod]
    public void Tpm2bSignatureHintEmptyFramesAsTwoZeroOctets()
    {
        Tpm2bSignatureHint hint = Tpm2bSignatureHint.Empty;

        Assert.IsTrue(hint.IsEmpty);
        Assert.AreEqual(0, hint.Size);
        Assert.AreEqual(2, hint.SerializedSize);

        byte[] framed = new byte[2];
        var writer = new TpmWriter(framed);
        hint.WriteTo(ref writer);

        Assert.AreSequenceEqual((byte[])[0x00, 0x00], framed);

        //The shared Empty sentinel owns no pooled storage: Dispose is a harmless no-op for every consumer.
        hint.Dispose();

        Assert.IsTrue(Tpm2bSignatureHint.Empty.Hint.IsEmpty, "Hint must remain readable after Dispose() on the shared sentinel — it is the member that would throw ObjectDisposedException were the sentinel exemption removed.");

        byte[] reframed = new byte[2];
        var reframeWriter = new TpmWriter(reframed);
        Tpm2bSignatureHint.Empty.WriteTo(ref reframeWriter);
        Assert.AreSequenceEqual((byte[])[0x00, 0x00], reframed, "WriteTo must remain callable after Dispose() on the shared sentinel — every other consumer's own empty hint reaches the same singleton.");
    }

    /// <summary>
    /// <see cref="VerifySequenceCompleteInput.ForEcdsa"/> frames <c>sequenceHandle</c> then <c>keyHandle</c>, in
    /// that order, followed by a <c>TPMT_SIGNATURE</c> whose ECDSA arm carries <c>signatureR</c> then
    /// <c>signatureS</c> as separate <c>TPM2B_ECC_PARAMETER</c> fields — exactly as
    /// <c>VerifyDigestSignatureInput.ForEcdsa</c> frames its own <c>TPMT_SIGNATURE</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3, Table 118; Part 2: Structures, clause 11.3.2, Table
    /// 214). The command's only parameter, <c>signature</c>, carries no leading TPM2B size field, so
    /// <see cref="ITpmCommandInput.FirstCommandParameterIsEncryptable"/> is <see langword="false"/>.
    /// </summary>
    [TestMethod]
    public void VerifySequenceCompleteInputForEcdsaFramesByteExactlyPerTable118()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject sequenceHandle = TpmiDhObject.FromValue(0x80000020u);
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x80000003u);
        byte[] signature = [0xAA, 0xBB, 0xCC, 0xDD]; //r = AA BB, s = CC DD.

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, keyHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_VerifySequenceComplete, input.CommandCode);
        Assert.AreEqual(0x000001A3u, (uint)input.CommandCode, "TPM_CC_VerifySequenceComplete must equal Table 12's raw value 0x000001A3 (TPM 2.0 Library Part 2: Structures, clause 6.5.2) — an enum member compared only to itself would still pass with a wrong wire value.");
        Assert.IsFalse(input.FirstCommandParameterIsEncryptable, "signature (TPMT_SIGNATURE) carries no leading TPM2B size field, so it is not eligible for parameter encryption.");

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x20, 0x80, 0x00, 0x00, 0x03];
        byte[] expectedParameters =
        [
            0x00, 0x18, //signature.sigAlg = TPM_ALG_ECDSA.
            0x00, 0x0B, //signature.signature.hash = TPM_ALG_SHA256.
            0x00, 0x02, 0xAA, 0xBB, //signature.signature.signatureR.
            0x00, 0x02, 0xCC, 0xDD //signature.signature.signatureS.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="VerifySequenceCompleteInput.ForRsaSsa"/> frames the two handles then a <c>TPMT_SIGNATURE</c>
    /// whose RSA arm carries the whole signature as one <c>TPM2B_PUBLIC_KEY_RSA</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3, Table 118; Part 2: Structures, clause 11.3.1, Table
    /// 212).
    /// </summary>
    [TestMethod]
    public void VerifySequenceCompleteInputForRsaSsaFramesByteExactlyPerTable118()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject sequenceHandle = TpmiDhObject.FromValue(0x80000021u);
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x81000004u);
        byte[] signature = [0xDE, 0xAD, 0xBE, 0xEF];

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForRsaSsa(
            sequenceHandle, keyHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_VerifySequenceComplete, input.CommandCode);
        Assert.IsFalse(input.FirstCommandParameterIsEncryptable, "signature (TPMT_SIGNATURE) carries no leading TPM2B size field, so it is not eligible for parameter encryption.");

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x21, 0x81, 0x00, 0x00, 0x04];
        byte[] expectedParameters =
        [
            0x00, 0x14, //signature.sigAlg = TPM_ALG_RSASSA.
            0x00, 0x0B, //signature.signature.hash = TPM_ALG_SHA256.
            0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF //signature.signature.sig.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="VerifySequenceCompleteInput.ForRsaPss"/> selects <c>TPM_ALG_RSAPSS</c> rather than
    /// <c>TPM_ALG_RSASSA</c> in the framed <c>sigAlg</c> selector, otherwise identical to
    /// <see cref="VerifySequenceCompleteInputForRsaSsaFramesByteExactlyPerTable118"/>'s RSA shape
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3, Table 118).
    /// </summary>
    [TestMethod]
    public void VerifySequenceCompleteInputForRsaPssFramesTheRsapssSigAlgSelectorByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject sequenceHandle = TpmiDhObject.FromValue(0x80000022u);
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x81000005u);
        byte[] signature = [0x01, 0x02, 0x03];

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForRsaPss(
            sequenceHandle, keyHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x22, 0x81, 0x00, 0x00, 0x05];
        byte[] expectedParameters =
        [
            0x00, 0x16, //signature.sigAlg = TPM_ALG_RSAPSS.
            0x00, 0x0B, //signature.signature.hash = TPM_ALG_SHA256.
            0x00, 0x03, 0x01, 0x02, 0x03 //signature.signature.sig.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// Frames <paramref name="input"/>'s handle and parameter areas into freshly-sized buffers and asserts each
    /// reproduces the hand-computed octets exactly, and that <see cref="ITpmCommandInput.GetSerializedSize"/>
    /// accounts for precisely the two areas combined, mirroring <c>SequenceInputFramingTests.AssertFraming</c>.
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
