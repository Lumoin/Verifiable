using System;
using System.Buffers;
using System.Collections.Generic;
using Lumoin.Veritas.Cbor;
using Verifiable.Cbor;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Pins the COSE_Key map-key order <see cref="CredentialPublicKeyCborWriter"/> puts on the wire, and the
/// structural property that makes that order safe under the substrate's CTAP2 comparator: every COSE_Key
/// label this writer can emit encodes in a single initial byte, the one case where CTAP2's
/// major-type-first rule and RFC 8949's bytewise rule cannot disagree.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#ctap2-canonical-cbor-encoding-form">CTAP2.1
/// §6 "canonical CBOR encoding form"</see> orders map keys by (1) major type, lowest first, (2) length,
/// shortest first, (3) bytewise value, lowest first. <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC
/// 8949 §4.2.1</see> drops the first criterion and orders purely by length then bytewise. The two rules
/// therefore diverge only for keys whose encodings differ in major type AND whose lengths contradict that
/// major-type ordering.
/// </para>
/// <para>
/// A COSE_Key label encoded in one byte carries its major type in that same byte's high three bits
/// (<see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see>), so for a set of
/// one-byte keys "lowest bytewise" already means "lowest major type, then lowest argument" — the two rules
/// coincide term for term. The guard tests below hold every label
/// <see cref="CredentialPublicKeyCborWriter"/> can emit inside −24…23, the range RFC 8949 §3 encodes in a
/// single initial byte, which is the standing justification (S4 ruling S4-9) for running this writer over a
/// substrate whose CTAP2 comparator omits the major-type-first step.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CredentialPublicKeyCtap2OrderTests
{
    /// <summary>The length in octets of a P-256 affine coordinate, per SEC 1 for the P-256 field.</summary>
    private const int P256CoordinateLength = 32;

    /// <summary>The length in octets of the RSA-2048 modulus this test's synthetic RSA key carries.</summary>
    private const int Rsa2048ModulusLength = 256;

    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// An EC2 P-256 COSE_Key written through <see cref="CredentialPublicKeyCborWriter"/> puts its five
    /// labels on the wire as the byte run <c>01 03 20 21 22</c> — <c>kty</c> 1, <c>alg</c> 3, <c>crv</c> −1,
    /// <c>x</c> −2, <c>y</c> −3. Derived from
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see>: 1 and 3 are major
    /// type 0 with the argument in the initial byte (<c>0x01</c>, <c>0x03</c>); −1, −2 and −3 are major
    /// type 1 (<c>0x20</c> base) encoding −1−n, so n = 0, 1, 2 give <c>0x20</c>, <c>0x21</c>, <c>0x22</c>.
    /// That run is ascending under <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949
    /// §4.2.1</see>, which is what the CTAP2 canonical writer sorts to.
    /// </summary>
    [TestMethod]
    public void Ec2KeyLabelsAppearOnTheWireAsTheHandDerivedByteRun()
    {
        using MeteredHousePool pool = new();
        using IMemoryOwner<byte> xOwner = pool.Pool.Rent(P256CoordinateLength);
        using IMemoryOwner<byte> yOwner = pool.Pool.Rent(P256CoordinateLength);
        FillAscending(xOwner.Memory.Span[..P256CoordinateLength], 1);
        FillAscending(yOwner.Memory.Span[..P256CoordinateLength], 33);

        CoseKey coseKey = new(
            kty: CoseKeyTypes.Ec2,
            alg: WellKnownCoseAlgorithms.Es256,
            curve: CoseKeyCurves.P256,
            x: xOwner.Memory[..P256CoordinateLength],
            y: yOwner.Memory[..P256CoordinateLength]);

        TaggedMemory<byte> written = CredentialPublicKeyCborWriter.Write(coseKey);
        CoseKeyLabelRun run = ReadCoseKeyLabels(written.Memory, CborOptions.Lax);

        byte[] expectedLabelBytes = [0x01, 0x03, 0x20, 0x21, 0x22];

        Assert.IsTrue(
            run.EncodedLabels.AsSpan().SequenceEqual(expectedLabelBytes),
            $"Expected the wire label run 01 03 20 21 22; got {Convert.ToHexString(run.EncodedLabels)}.");
    }


    /// <summary>
    /// The same EC2 P-256 COSE_Key opens with the hand-derived initial bytes <c>A5 01</c>: a definite-length
    /// five-entry map is major type 5 with the count in the initial byte's additional information
    /// (<c>0xA0 | 5 = 0xA5</c>) per <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949
    /// §3</see>, immediately followed by the lowest label, <c>kty</c> = 1, as <c>0x01</c>.
    /// </summary>
    [TestMethod]
    public void Ec2KeyWireOpensWithTheHandDerivedMapHeaderAndKtyLabel()
    {
        using MeteredHousePool pool = new();
        using IMemoryOwner<byte> xOwner = pool.Pool.Rent(P256CoordinateLength);
        using IMemoryOwner<byte> yOwner = pool.Pool.Rent(P256CoordinateLength);
        FillAscending(xOwner.Memory.Span[..P256CoordinateLength], 1);
        FillAscending(yOwner.Memory.Span[..P256CoordinateLength], 33);

        CoseKey coseKey = new(
            kty: CoseKeyTypes.Ec2,
            alg: WellKnownCoseAlgorithms.Es256,
            curve: CoseKeyCurves.P256,
            x: xOwner.Memory[..P256CoordinateLength],
            y: yOwner.Memory[..P256CoordinateLength]);

        TaggedMemory<byte> written = CredentialPublicKeyCborWriter.Write(coseKey);

        byte[] expectedPrefix = [0xA5, 0x01];

        Assert.IsTrue(
            written.Span[..2].SequenceEqual(expectedPrefix),
            $"Expected the wire to open A5 01; got {Convert.ToHexString(written.Span[..2].ToArray())}.");
    }


    /// <summary>
    /// The EC2 P-256 COSE_Key this writer produces reads back under
    /// <see cref="CborConformanceMode.Ctap2Canonical"/> without a conformance refusal — the deterministic
    /// reader accepts the emitted key order, the minimal header widths and the definite lengths that
    /// <see href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#ctap2-canonical-cbor-encoding-form">CTAP2.1
    /// §6</see> requires of a <c>credentialPublicKey</c>.
    /// </summary>
    [TestMethod]
    public void Ec2KeyReadsBackUnderCtap2CanonicalWithoutARefusal()
    {
        using MeteredHousePool pool = new();
        using IMemoryOwner<byte> xOwner = pool.Pool.Rent(P256CoordinateLength);
        using IMemoryOwner<byte> yOwner = pool.Pool.Rent(P256CoordinateLength);
        FillAscending(xOwner.Memory.Span[..P256CoordinateLength], 1);
        FillAscending(yOwner.Memory.Span[..P256CoordinateLength], 33);

        CoseKey coseKey = new(
            kty: CoseKeyTypes.Ec2,
            alg: WellKnownCoseAlgorithms.Es256,
            curve: CoseKeyCurves.P256,
            x: xOwner.Memory[..P256CoordinateLength],
            y: yOwner.Memory[..P256CoordinateLength]);

        TaggedMemory<byte> written = CredentialPublicKeyCborWriter.Write(coseKey);
        CoseKeyLabelRun run = ReadCoseKeyLabels(written.Memory, CborOptions.Ctap2Canonical);

        int[] expectedLabels =
        [
            CoseKeyParameters.Kty,
            CoseKeyParameters.Alg,
            CoseKeyParameters.Crv,
            CoseKeyParameters.X,
            CoseKeyParameters.Y
        ];

        Assert.IsTrue(
            run.Labels.AsSpan().SequenceEqual(expectedLabels),
            "A CTAP2-canonical read must accept the writer's own COSE_Key and surface the same five labels.");
    }


    /// <summary>
    /// The EC2 label run the writer emits is strictly ascending under CTAP2's own three-criterion rule —
    /// major type first, then length, then bytewise — not merely under the length-then-bytewise rule of
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>. The two rules
    /// agree on this map, so a spec-correct CTAP2 verifier
    /// accepts the order a length-first comparator produced.
    /// <see href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#ctap2-canonical-cbor-encoding-form">CTAP2.1
    /// §6</see>.
    /// </summary>
    [TestMethod]
    public void Ec2LabelRunIsAscendingUnderTheCtap2MajorTypeFirstRule()
    {
        using MeteredHousePool pool = new();
        using IMemoryOwner<byte> xOwner = pool.Pool.Rent(P256CoordinateLength);
        using IMemoryOwner<byte> yOwner = pool.Pool.Rent(P256CoordinateLength);
        FillAscending(xOwner.Memory.Span[..P256CoordinateLength], 1);
        FillAscending(yOwner.Memory.Span[..P256CoordinateLength], 33);

        CoseKey coseKey = new(
            kty: CoseKeyTypes.Ec2,
            alg: WellKnownCoseAlgorithms.Es256,
            curve: CoseKeyCurves.P256,
            x: xOwner.Memory[..P256CoordinateLength],
            y: yOwner.Memory[..P256CoordinateLength]);

        TaggedMemory<byte> written = CredentialPublicKeyCborWriter.Write(coseKey);
        CoseKeyLabelRun run = ReadCoseKeyLabels(written.Memory, CborOptions.Lax);

        for(int i = 1; i < run.EncodedLabels.Length; i++)
        {
            ReadOnlySpan<byte> previous = run.EncodedLabels.AsSpan(i - 1, 1);
            ReadOnlySpan<byte> current = run.EncodedLabels.AsSpan(i, 1);

            int comparison = CompareCtap2Canonical(previous, current);

            Assert.IsLessThan(
                0,
                comparison,
                $"Label {run.Labels[i - 1]} must sort strictly before label {run.Labels[i]} under the CTAP2 rule.");
        }
    }


    /// <summary>
    /// An RSA COSE_Key written through <see cref="CredentialPublicKeyCborWriter"/> puts its four labels on
    /// the wire as <c>01 03 20 21</c> — <c>kty</c> 1, <c>alg</c> 3, <c>n</c> −1, <c>e</c> −2, the RSA label
    /// overloading of <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>,
    /// encoded by the same RFC 8949 §3 initial-byte derivation as the EC2 run. The RS256 algorithm value
    /// −257 needs three bytes, which does not participate in key ordering: only the labels do.
    /// </summary>
    [TestMethod]
    public void RsaKeyLabelsAppearOnTheWireAsTheHandDerivedByteRun()
    {
        using MeteredHousePool pool = new();
        using IMemoryOwner<byte> modulusOwner = pool.Pool.Rent(Rsa2048ModulusLength);
        FillAscending(modulusOwner.Memory.Span[..Rsa2048ModulusLength], 1);

        using IMemoryOwner<byte> exponentOwner = pool.Pool.Rent(3);
        Span<byte> exponent = exponentOwner.Memory.Span[..3];
        exponent[0] = 0x01;
        exponent[1] = 0x00;
        exponent[2] = 0x01;

        CoseKey coseKey = new(
            kty: CoseKeyTypes.Rsa,
            alg: WellKnownCoseAlgorithms.Rs256,
            n: modulusOwner.Memory[..Rsa2048ModulusLength],
            e: exponentOwner.Memory[..3]);

        TaggedMemory<byte> written = CredentialPublicKeyCborWriter.Write(coseKey);
        CoseKeyLabelRun run = ReadCoseKeyLabels(written.Memory, CborOptions.Lax);

        byte[] expectedLabelBytes = [0x01, 0x03, 0x20, 0x21];

        Assert.IsTrue(
            run.EncodedLabels.AsSpan().SequenceEqual(expectedLabelBytes),
            $"Expected the wire label run 01 03 20 21; got {Convert.ToHexString(run.EncodedLabels)}.");
    }


    /// <summary>
    /// The RSA COSE_Key this writer produces reads back under
    /// <see cref="CborConformanceMode.Ctap2Canonical"/> without a conformance refusal, the RSA counterpart
    /// of the EC2 read-back — the same
    /// <see href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#ctap2-canonical-cbor-encoding-form">CTAP2.1
    /// §6</see> gate over the <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>
    /// label set.
    /// </summary>
    [TestMethod]
    public void RsaKeyReadsBackUnderCtap2CanonicalWithoutARefusal()
    {
        using MeteredHousePool pool = new();
        using IMemoryOwner<byte> modulusOwner = pool.Pool.Rent(Rsa2048ModulusLength);
        FillAscending(modulusOwner.Memory.Span[..Rsa2048ModulusLength], 1);

        using IMemoryOwner<byte> exponentOwner = pool.Pool.Rent(3);
        Span<byte> exponent = exponentOwner.Memory.Span[..3];
        exponent[0] = 0x01;
        exponent[1] = 0x00;
        exponent[2] = 0x01;

        CoseKey coseKey = new(
            kty: CoseKeyTypes.Rsa,
            alg: WellKnownCoseAlgorithms.Rs256,
            n: modulusOwner.Memory[..Rsa2048ModulusLength],
            e: exponentOwner.Memory[..3]);

        TaggedMemory<byte> written = CredentialPublicKeyCborWriter.Write(coseKey);
        CoseKeyLabelRun run = ReadCoseKeyLabels(written.Memory, CborOptions.Ctap2Canonical);

        int[] expectedLabels =
        [
            CoseKeyParameters.Kty,
            CoseKeyParameters.Alg,
            CoseKeyParameters.RsaN,
            CoseKeyParameters.RsaE
        ];

        Assert.IsTrue(
            run.Labels.AsSpan().SequenceEqual(expectedLabels),
            "A CTAP2-canonical read must accept the writer's own RSA COSE_Key and surface the same four labels.");
    }


    /// <summary>
    /// Guard: <see cref="CoseKeyParameters.Kty"/> = 1 lies in −24…23 and encodes as the single initial byte
    /// <c>0x01</c> — major type 0 with the argument carried in the initial byte's additional information,
    /// per <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see>. A one-byte key
    /// is the case where CTAP2.1 §6's major-type-first rule and RFC 8949 §4.2.1's bytewise rule coincide.
    /// </summary>
    [TestMethod]
    public void KtyLabelEncodesAsASingleInitialByte()
    {
        using MeteredHousePool pool = new();
        AssertLabelEncodesAsSingleInitialByte(CoseKeyParameters.Kty, 0x01, pool);
    }


    /// <summary>
    /// Guard: <see cref="CoseKeyParameters.Alg"/> = 3 lies in −24…23 and encodes as the single initial byte
    /// <c>0x03</c>, by the same <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949
    /// §3</see> major-type-0 derivation, so CTAP2.1 §6 and RFC 8949 §4.2.1 agree on it.
    /// </summary>
    [TestMethod]
    public void AlgLabelEncodesAsASingleInitialByte()
    {
        using MeteredHousePool pool = new();
        AssertLabelEncodesAsSingleInitialByte(CoseKeyParameters.Alg, 0x03, pool);
    }


    /// <summary>
    /// Guard: <see cref="CoseKeyParameters.Crv"/> = −1 lies in −24…23 and encodes as the single initial byte
    /// <c>0x20</c> — major type 1 encodes −1−n, so n = 0 gives the initial byte <c>0x20</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see>. CTAP2.1 §6 and RFC
    /// 8949 §4.2.1 agree on it.
    /// </summary>
    [TestMethod]
    public void CrvLabelEncodesAsASingleInitialByte()
    {
        using MeteredHousePool pool = new();
        AssertLabelEncodesAsSingleInitialByte(CoseKeyParameters.Crv, 0x20, pool);
    }


    /// <summary>
    /// Guard: <see cref="CoseKeyParameters.X"/> = −2 lies in −24…23 and encodes as the single initial byte
    /// <c>0x21</c> — major type 1 with n = 1, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see>. CTAP2.1 §6 and RFC
    /// 8949 §4.2.1 agree on it.
    /// </summary>
    [TestMethod]
    public void XLabelEncodesAsASingleInitialByte()
    {
        using MeteredHousePool pool = new();
        AssertLabelEncodesAsSingleInitialByte(CoseKeyParameters.X, 0x21, pool);
    }


    /// <summary>
    /// Guard: <see cref="CoseKeyParameters.Y"/> = −3 lies in −24…23 and encodes as the single initial byte
    /// <c>0x22</c> — major type 1 with n = 2, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see>. CTAP2.1 §6 and RFC
    /// 8949 §4.2.1 agree on it.
    /// </summary>
    [TestMethod]
    public void YLabelEncodesAsASingleInitialByte()
    {
        using MeteredHousePool pool = new();
        AssertLabelEncodesAsSingleInitialByte(CoseKeyParameters.Y, 0x22, pool);
    }


    /// <summary>
    /// Guard: <see cref="CoseKeyParameters.RsaN"/> = −1, the RSA modulus label of
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>, lies in −24…23 and
    /// encodes as the single initial byte <c>0x20</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see>. CTAP2.1 §6 and RFC
    /// 8949 §4.2.1 agree on it.
    /// </summary>
    [TestMethod]
    public void RsaNLabelEncodesAsASingleInitialByte()
    {
        using MeteredHousePool pool = new();
        AssertLabelEncodesAsSingleInitialByte(CoseKeyParameters.RsaN, 0x20, pool);
    }


    /// <summary>
    /// Guard: <see cref="CoseKeyParameters.RsaE"/> = −2, the RSA public-exponent label of
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>, lies in −24…23 and
    /// encodes as the single initial byte <c>0x21</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see>. CTAP2.1 §6 and RFC
    /// 8949 §4.2.1 agree on it.
    /// </summary>
    [TestMethod]
    public void RsaELabelEncodesAsASingleInitialByte()
    {
        using MeteredHousePool pool = new();
        AssertLabelEncodesAsSingleInitialByte(CoseKeyParameters.RsaE, 0x21, pool);
    }


    /// <summary>
    /// The labels of one COSE_Key map as they appear on the wire — the decoded integer labels and the
    /// concatenation of their exact encoded byte runs, in wire order.
    /// </summary>
    /// <param name="Labels">The decoded integer labels, in wire order.</param>
    /// <param name="EncodedLabels">The encoded label bytes concatenated in wire order.</param>
    private readonly record struct CoseKeyLabelRun(int[] Labels, byte[] EncodedLabels);


    /// <summary>
    /// Walks a COSE_Key map with a reader built over <paramref name="options"/>, capturing each label both
    /// as its decoded integer and as the exact encoded bytes it occupies on the wire. Labels are read with
    /// the typed integer read, which is the path a deterministic conformance mode's key rules bind to, so a
    /// canonical-mode walk here refuses a non-conforming key order rather than silently accepting it.
    /// </summary>
    /// <param name="encoded">The encoded COSE_Key map.</param>
    /// <param name="options">The serializer options, and therefore the conformance mode, to read under.</param>
    /// <returns>The labels and their encoded byte runs, in wire order.</returns>
    private static CoseKeyLabelRun ReadCoseKeyLabels(ReadOnlyMemory<byte> encoded, CborSerializerOptions options)
    {
        CborReader reader = new(encoded, options);
        int? entryCount = reader.ReadStartMap();
        List<int> labels = new(entryCount ?? 0);
        List<byte> encodedLabels = [];

        while(reader.PeekState() != CborReaderState.EndMap)
        {
            long labelStart = reader.BytesConsumed;
            labels.Add(reader.ReadInt32());
            long labelEnd = reader.BytesConsumed;
            encodedLabels.AddRange(encoded.Span[(int)labelStart..(int)labelEnd]);

            _ = ReadCoseKeyValue(reader);
        }

        reader.ReadEndMap();

        return new CoseKeyLabelRun([.. labels], [.. encodedLabels]);
    }


    /// <summary>
    /// Reads one COSE_Key parameter value through a typed read, so the reader's conformance mode binds to
    /// the value's wire form too. The three shapes
    /// <see cref="CredentialPublicKeyCborWriter"/> emits are integers (<c>kty</c>, <c>alg</c>, <c>crv</c>),
    /// byte strings (<c>x</c>, <c>y</c>, <c>n</c>, <c>e</c>) and the boolean compressed-<c>y</c> sign.
    /// </summary>
    /// <param name="reader">The reader positioned on a value.</param>
    /// <returns>A scalar summary of the value; the walk uses it only to force the read.</returns>
    private static long ReadCoseKeyValue(CborReader reader)
    {
        return reader.PeekState() switch
        {
            CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger => reader.ReadInt64(),
            CborReaderState.ByteString => reader.ReadByteStringMemory().Length,
            CborReaderState.Boolean => reader.ReadBoolean() ? 1 : 0,
            CborReaderState state => throw new InvalidOperationException(
                $"A COSE_Key value in reader state {state} is outside the shapes CredentialPublicKeyCborWriter emits.")
        };
    }


    /// <summary>
    /// Compares two encoded map keys by CTAP2.1 §6's canonical rule: lower major type first, then shorter
    /// encoding, then lower bytewise value. Written out here rather than taken from the codec so the
    /// assertion is anchored on the specification's own three criteria.
    /// </summary>
    /// <param name="left">The first encoded key.</param>
    /// <param name="right">The second encoded key.</param>
    /// <returns>A negative value when <paramref name="left"/> sorts earlier, zero when equal, positive otherwise.</returns>
    private static int CompareCtap2Canonical(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        int leftMajorType = left[0] >> 5;
        int rightMajorType = right[0] >> 5;

        return (leftMajorType != rightMajorType, left.Length != right.Length) switch
        {
            (true, _) => leftMajorType.CompareTo(rightMajorType),
            (false, true) => left.Length.CompareTo(right.Length),
            _ => left.SequenceCompareTo(right)
        };
    }


    /// <summary>
    /// Asserts that <paramref name="label"/> lies in the −24…23 range RFC 8949 §3 encodes in a single
    /// initial byte, and that encoding it produces exactly that one hand-derived byte.
    /// </summary>
    /// <param name="label">The COSE_Key label constant under guard.</param>
    /// <param name="expectedInitialByte">The hand-derived initial byte the label must encode to.</param>
    /// <param name="pool">The house pool the encoding buffer is rented from.</param>
    private static void AssertLabelEncodesAsSingleInitialByte(int label, byte expectedInitialByte, MeteredHousePool pool)
    {
        Assert.IsTrue(
            label is >= -24 and <= 23,
            $"COSE_Key label {label} must lie in −24…23 to encode in a single initial byte.");

        using SlabBufferWriter buffer = new(pool.Pool);
        CborWriter writer = new(buffer, CborOptions.Ctap2Canonical);
        writer.WriteInt32(label);

        using IMemoryOwner<byte> owner = buffer.Detach();
        int encodedLength = owner.Memory.Length;

        Assert.AreEqual(1, encodedLength, $"COSE_Key label {label} must encode in exactly one byte.");
        Assert.AreEqual(expectedInitialByte, owner.Memory.Span[0], $"COSE_Key label {label} must encode as the hand-derived initial byte.");
    }


    /// <summary>Fills <paramref name="destination"/> with consecutive octets starting at <paramref name="first"/>.</summary>
    /// <param name="destination">The span to fill.</param>
    /// <param name="first">The value of the first octet.</param>
    private static void FillAscending(Span<byte> destination, int first)
    {
        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)(first + i);
        }
    }
}
