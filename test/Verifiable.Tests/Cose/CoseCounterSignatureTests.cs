using System.Buffers;
using System.Collections.Frozen;
using Lumoin.Veritas.Cbor;
using System.Linq;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Cose;

/// <summary>
/// Tests for RFC 9338 version 2 countersignature operations: the
/// <see cref="CounterSignatureV2"/>/<see cref="CounterSignature0V2"/> model, the
/// Countersign_structure builder (the target-dependent <c>other_fields</c>/context-text
/// derivation), the CBOR codec (including the tag-19 read-tolerant/write-never posture),
/// countersign/verify over both ETSI-relevant target shapes, the fail-closed rejection of
/// the deprecated RFC 8152 V1 countersignature labels, and metered custody.
/// </summary>
[TestClass]
internal sealed class CoseCounterSignatureTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task CountersignFullOverCoseSign1TargetAndVerifySucceeds()
    {
        using CoseSign1Message target = await BuildSignedCoseSign1TargetAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var countersignTarget = new CoseSign1CountersignTarget(
            target.ProtectedHeader.AsReadOnlyMemory(), target.Payload, target.Signature.AsReadOnlyMemory());

        var counterSigner = TestKeyMaterialProvider.CreateP521KeyMaterial();
        using var counterSignerPublicKey = counterSigner.PublicKey;
        using var counterSignerPrivateKey = counterSigner.PrivateKey;

        using CounterSignatureV2 counterSignature = await CoseCounterSign.CountersignFullAsync(
            countersignTarget,
            BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es512),
            counterSignerUnprotectedHeader: null,
            ReadOnlyMemory<byte>.Empty,
            CoseSerialization.BuildCountersignStructure,
            counterSignerPrivateKey,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        bool isValid = await CoseCounterSign.VerifyAsync(
            counterSignature, countersignTarget, ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
            counterSignerPublicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "A full countersignature over a COSE_Sign1 target must verify against its own key.");
    }


    [TestMethod]
    public async Task CountersignFullOverCoseSignatureTargetAndVerifySucceeds()
    {
        using CoseSignatureComponent target = await BuildSignedCoseSignatureTargetAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var countersignTarget = new CoseSignatureCountersignTarget(target.ProtectedHeader.AsReadOnlyMemory(), target.Signature.AsReadOnlyMemory());

        var counterSigner = TestKeyMaterialProvider.CreateP384KeyMaterial();
        using var counterSignerPublicKey = counterSigner.PublicKey;
        using var counterSignerPrivateKey = counterSigner.PrivateKey;

        using CounterSignatureV2 counterSignature = await CoseCounterSign.CountersignFullAsync(
            countersignTarget,
            BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es384),
            counterSignerUnprotectedHeader: null,
            ReadOnlyMemory<byte>.Empty,
            CoseSerialization.BuildCountersignStructure,
            counterSignerPrivateKey,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        bool isValid = await CoseCounterSign.VerifyAsync(
            counterSignature, countersignTarget, ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
            counterSignerPublicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "A full countersignature over a COSE_Signature target must verify against its own key.");
    }


    [TestMethod]
    public async Task CountersignAbbreviatedOverCoseSign1TargetAndVerifySucceeds()
    {
        using CoseSign1Message target = await BuildSignedCoseSign1TargetAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var countersignTarget = new CoseSign1CountersignTarget(
            target.ProtectedHeader.AsReadOnlyMemory(), target.Payload, target.Signature.AsReadOnlyMemory());

        var counterSigner = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var counterSignerPublicKey = counterSigner.PublicKey;
        using var counterSignerPrivateKey = counterSigner.PrivateKey;

        using CounterSignature0V2 counterSignature = await CoseCounterSign.CountersignAbbreviatedAsync(
            countersignTarget, ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
            counterSignerPrivateKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        bool isValid = await CoseCounterSign.VerifyAsync(
            counterSignature, countersignTarget, ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
            counterSignerPublicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "An abbreviated countersignature over a COSE_Sign1 target must verify against its own key.");
    }


    [TestMethod]
    public async Task CountersignAbbreviatedOverCoseSignatureTargetAndVerifySucceeds()
    {
        using CoseSignatureComponent target = await BuildSignedCoseSignatureTargetAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var countersignTarget = new CoseSignatureCountersignTarget(target.ProtectedHeader.AsReadOnlyMemory(), target.Signature.AsReadOnlyMemory());

        var counterSigner = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var counterSignerPublicKey = counterSigner.PublicKey;
        using var counterSignerPrivateKey = counterSigner.PrivateKey;

        using CounterSignature0V2 counterSignature = await CoseCounterSign.CountersignAbbreviatedAsync(
            countersignTarget, ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
            counterSignerPrivateKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        bool isValid = await CoseCounterSign.VerifyAsync(
            counterSignature, countersignTarget, ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
            counterSignerPublicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "An abbreviated countersignature over a COSE_Signature target must verify against its own key.");
    }


    [TestMethod]
    public async Task VerifyFullCountersignatureWithWrongKeyFails()
    {
        using CoseSign1Message target = await BuildSignedCoseSign1TargetAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var countersignTarget = new CoseSign1CountersignTarget(
            target.ProtectedHeader.AsReadOnlyMemory(), target.Payload, target.Signature.AsReadOnlyMemory());

        var counterSigner = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var counterSignerPrivateKey = counterSigner.PrivateKey;
        counterSigner.PublicKey.Dispose();

        var wrongKeyPair = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var wrongPublicKey = wrongKeyPair.PublicKey;
        wrongKeyPair.PrivateKey.Dispose();

        using CounterSignatureV2 counterSignature = await CoseCounterSign.CountersignFullAsync(
            countersignTarget, BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256), null, ReadOnlyMemory<byte>.Empty,
            CoseSerialization.BuildCountersignStructure, counterSignerPrivateKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        bool isValid = await CoseCounterSign.VerifyAsync(
            counterSignature, countersignTarget, ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
            wrongPublicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isValid, "Verification against the wrong key must fail.");
    }


    /// <summary>
    /// Proves <see cref="CoseCounterSign.CountersignFullAsync(CountersignTarget, EncodedCoseProtectedHeader, IReadOnlyDictionary{int, object}?, ReadOnlyMemory{byte}, BuildCountersignStructureDelegate, PrivateKeyMemory, SigningDelegate, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>
    /// produces a signature verifiable against an independently hand-assembled Countersign_structure,
    /// without calling <see cref="CoseSerialization.BuildCountersignStructure"/> for the oracle.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.1.6-04.
    /// </remarks>
    [TestMethod]
    public async Task CountersignFullAsyncProducesSignatureVerifiableAgainstIndependentlyBuiltCountersignStructure()
    {
        byte[] targetProtected = Convert.FromHexString("A201260300");
        byte[] targetPayload = "This is the content."u8.ToArray();
        byte[] targetSignature = Convert.FromHexString(
            "BB587D6B15F47BFD54D2CBFCECEF75451E92B08A514BD439FA3AA65C6AC92DF0D7328C4A47529B32ADD3DD1B4E940071C021E9A8F2641F1D8E3B053DDD65AE52");
        var countersignTarget = new CoseSign1CountersignTarget(targetProtected, targetPayload, targetSignature);

        EncodedCoseProtectedHeader counterSignerProtectedHeader = BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256);
        byte[] counterSignerProtectedHeaderBytes = counterSignerProtectedHeader.AsReadOnlySpan().ToArray();

        var counterSigner = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var counterSignerPublicKey = counterSigner.PublicKey;
        using var counterSignerPrivateKey = counterSigner.PrivateKey;

        using CounterSignatureV2 counterSignature = await CoseCounterSign.CountersignFullAsync(
            countersignTarget, counterSignerProtectedHeader, null, ReadOnlyMemory<byte>.Empty,
            CoseSerialization.BuildCountersignStructure, counterSignerPrivateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Independent oracle: hand-assemble the Countersign_structure per RFC 9338 §3.3 -- other_fields
        //present (COSE_Sign1 target) so context is "CounterSignatureV2".
        var oracleWriterBuffer = new ArrayBufferWriter<byte>();
        var oracleWriter = new CborWriter(oracleWriterBuffer, CborOptions.RfcCanonical);
        oracleWriter.WriteStartArray(6);
        oracleWriter.WriteTextString("CounterSignatureV2");
        oracleWriter.WriteByteString(targetProtected);
        oracleWriter.WriteByteString(counterSignerProtectedHeaderBytes);
        oracleWriter.WriteByteString([]);
        oracleWriter.WriteByteString(targetPayload);
        oracleWriter.WriteStartArray(1);
        oracleWriter.WriteByteString(targetSignature);
        oracleWriter.WriteEndArray();
        oracleWriter.WriteEndArray();
        byte[] oracleToBeSigned = oracleWriterBuffer.WrittenSpan.ToArray();

        (bool isValid, _) = await MicrosoftCryptographicFunctions.VerifyP256Async(oracleToBeSigned, counterSignature.Component.Signature.AsReadOnlyMemory(), counterSignerPublicKey.AsReadOnlyMemory(), cancellationToken: TestContext.CancellationToken, timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch)).ConfigureAwait(false);

        Assert.IsTrue(isValid, "The countersignature must verify against an independently assembled Countersign_structure.");
    }


    /// <summary>
    /// RFC 9338 Appendix A.2.1 (countersignature over a COSE_Sign1 target) as a byte-exact
    /// structural KAT for <see cref="CoseSerialization.BuildCountersignStructure"/>: the
    /// countersigned target's own bytes are the vector's own values, and the expected
    /// Countersign_structure is hand-assembled independently.
    /// Beyond the structural match, the appendix's OWN countersignature value is verified
    /// cryptographically against Bilbo's P-521 public key (RFC 9052 Appendix C.7.1) over OUR
    /// <c>BuildCountersignStructure</c> output -- the true cross-implementation oracle for the
    /// builder's two-axis (target-shape / abbreviation) context resolution, not merely a
    /// self-referential byte comparison.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.1.6-04, CB-5.3.5.3-09.
    /// </remarks>
    [TestMethod]
    public async Task BuildCountersignStructureMatchesRfc9338AppendixA21ExampleForCoseSign1Target()
    {
        byte[] targetProtected = Convert.FromHexString("A201260300");
        byte[] targetPayload = "This is the content."u8.ToArray();
        byte[] targetSignature = Convert.FromHexString(
            "BB587D6B15F47BFD54D2CBFCECEF75451E92B08A514BD439FA3AA65C6AC92DF0D7328C4A47529B32ADD3DD1B4E940071C021E9A8F2641F1D8E3B053DDD65AE52");
        byte[] counterSignerProtected = Convert.FromHexString("A1013823");
        byte[] counterSignatureValue = Convert.FromHexString(
            "01B1291B0E60A79C459A4A9184A0D393E034B34AF069A1CCA34F5A913AFFFF698002295FA9F8FCBFB6FDFF59132FC0C406E98754A98F1FBFE81C03095F481856BC470170227206FA5BEE3C0431C56A66824E7AAF692985952E31271434B2BA2E47A335C658B5E995AEB5D63CF2D0CED367D3E4CC8FFFD53B70D115BAA9E86961FBD1A5CF");

        var target = new CoseSign1CountersignTarget(targetProtected, targetPayload, targetSignature);
        CountersignStructureInput input = CountersignStructureInput.ForTarget(target, isAbbreviated: false, counterSignerProtected, ReadOnlyMemory<byte>.Empty);

        byte[] actual = CoseSerialization.BuildCountersignStructure(input);

        var oracleWriterBuffer = new ArrayBufferWriter<byte>();
        var oracleWriter = new CborWriter(oracleWriterBuffer, CborOptions.RfcCanonical);
        oracleWriter.WriteStartArray(6);
        oracleWriter.WriteTextString("CounterSignatureV2");
        oracleWriter.WriteByteString(targetProtected);
        oracleWriter.WriteByteString(counterSignerProtected);
        oracleWriter.WriteByteString([]);
        oracleWriter.WriteByteString(targetPayload);
        oracleWriter.WriteStartArray(1);
        oracleWriter.WriteByteString(targetSignature);
        oracleWriter.WriteEndArray();
        oracleWriter.WriteEndArray();
        byte[] oracle = oracleWriterBuffer.WrittenSpan.ToArray();

        Assert.IsTrue(oracle.AsSpan().SequenceEqual(actual), "Must match the RFC 9338 Appendix A.2.1 target shape byte-for-byte.");

        byte[] bilboP521PublicKey = BuildBilboP521UncompressedPublicKeyBytes();
        (bool isValid, _) = await MicrosoftCryptographicFunctions.VerifyP521Async(actual, counterSignatureValue, bilboP521PublicKey, cancellationToken: TestContext.CancellationToken, timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch)).ConfigureAwait(false);

        Assert.IsTrue(isValid,
            "RFC 9338 Appendix A.2.1's own countersignature value must verify against Bilbo's P-521 public key " +
            "(RFC 9052 Appendix C.7.1) over BuildCountersignStructure's output -- the cross-implementation oracle.");
    }


    /// <summary>
    /// A COSE_Signature target has exactly two bstr fields (protected, signature); since it has none,
    /// <c>other_fields</c> is omitted and the target's own signature value
    /// becomes Countersign_structure's <c>payload</c> slot -- so the context text drops the
    /// "V2" suffix even though the countersignature IS a version 2 one.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.3.5.3-03, CB-5.3.5.3-09.
    /// </remarks>
    [TestMethod]
    public void BuildCountersignStructureOmitsOtherFieldsAndUsesPlainContextForCoseSignatureTarget()
    {
        byte[] targetProtected = "target-protected"u8.ToArray();
        byte[] targetSignature = "target-signature-value"u8.ToArray();
        byte[] counterSignerProtected = "signer-protected"u8.ToArray();

        var target = new CoseSignatureCountersignTarget(targetProtected, targetSignature);
        CountersignStructureInput input = CountersignStructureInput.ForTarget(target, isAbbreviated: false, counterSignerProtected, ReadOnlyMemory<byte>.Empty);

        byte[] actual = CoseSerialization.BuildCountersignStructure(input);

        var oracleWriterBuffer = new ArrayBufferWriter<byte>();
        var oracleWriter = new CborWriter(oracleWriterBuffer, CborOptions.RfcCanonical);
        oracleWriter.WriteStartArray(5);
        oracleWriter.WriteTextString("CounterSignature");
        oracleWriter.WriteByteString(targetProtected);
        oracleWriter.WriteByteString(counterSignerProtected);
        oracleWriter.WriteByteString([]);
        oracleWriter.WriteByteString(targetSignature);
        oracleWriter.WriteEndArray();
        byte[] oracle = oracleWriterBuffer.WrittenSpan.ToArray();

        Assert.IsTrue(oracle.AsSpan().SequenceEqual(actual), "other_fields must be omitted and the context text must be the plain (non-V2) form for a COSE_Signature target.");
    }


    /// <summary>
    /// The same COSE_Signature target, abbreviated form: context drops to "CounterSignature0"
    /// (no "V2" suffix, other_fields still omitted) and sign_protected is entirely absent.
    /// </summary>
    [TestMethod]
    public void BuildCountersignStructureUsesAbbreviatedPlainContextForCoseSignatureTarget()
    {
        byte[] targetProtected = "target-protected"u8.ToArray();
        byte[] targetSignature = "target-signature-value"u8.ToArray();

        var target = new CoseSignatureCountersignTarget(targetProtected, targetSignature);
        CountersignStructureInput input = CountersignStructureInput.ForTarget(target, isAbbreviated: true, signProtected: null, ReadOnlyMemory<byte>.Empty);

        byte[] actual = CoseSerialization.BuildCountersignStructure(input);

        var oracleWriterBuffer = new ArrayBufferWriter<byte>();
        var oracleWriter = new CborWriter(oracleWriterBuffer, CborOptions.RfcCanonical);
        oracleWriter.WriteStartArray(4);
        oracleWriter.WriteTextString("CounterSignature0");
        oracleWriter.WriteByteString(targetProtected);
        oracleWriter.WriteByteString([]);
        oracleWriter.WriteByteString(targetSignature);
        oracleWriter.WriteEndArray();
        byte[] oracle = oracleWriterBuffer.WrittenSpan.ToArray();

        Assert.IsTrue(oracle.AsSpan().SequenceEqual(actual), "Abbreviated countersignature over a COSE_Signature target must use the plain 'CounterSignature0' context with no sign_protected field.");
    }


    /// <summary>
    /// An abbreviated countersignature over a COSE_Sign1 target: other_fields is present
    /// (one element, the target's own signature), so the context gains the "V2" suffix even
    /// though sign_protected itself is entirely absent (RFC 9338 §3.3's two independent axes).
    /// </summary>
    [TestMethod]
    public void BuildCountersignStructureUsesAbbreviatedV2ContextForCoseSign1Target()
    {
        byte[] targetProtected = "target-protected"u8.ToArray();
        byte[] targetPayload = "target-payload"u8.ToArray();
        byte[] targetSignature = "target-signature-value"u8.ToArray();

        var target = new CoseSign1CountersignTarget(targetProtected, targetPayload, targetSignature);
        CountersignStructureInput input = CountersignStructureInput.ForTarget(target, isAbbreviated: true, signProtected: null, ReadOnlyMemory<byte>.Empty);

        byte[] actual = CoseSerialization.BuildCountersignStructure(input);

        var oracleWriterBuffer = new ArrayBufferWriter<byte>();
        var oracleWriter = new CborWriter(oracleWriterBuffer, CborOptions.RfcCanonical);
        oracleWriter.WriteStartArray(5);
        oracleWriter.WriteTextString("CounterSignature0V2");
        oracleWriter.WriteByteString(targetProtected);
        oracleWriter.WriteByteString([]);
        oracleWriter.WriteByteString(targetPayload);
        oracleWriter.WriteStartArray(1);
        oracleWriter.WriteByteString(targetSignature);
        oracleWriter.WriteEndArray();
        oracleWriter.WriteEndArray();
        byte[] oracle = oracleWriterBuffer.WrittenSpan.ToArray();

        Assert.IsTrue(oracle.AsSpan().SequenceEqual(actual), "Abbreviated countersignature over a COSE_Sign1 target must use 'CounterSignature0V2' (other_fields present).");
    }


    [TestMethod]
    public void BuildCountersignStructureThrowsWhenFullFormOmitsSignProtected()
    {
        var target = new CoseSignatureCountersignTarget("protected"u8.ToArray(), "signature"u8.ToArray());
        CountersignStructureInput input = new(IsAbbreviated: false, target.ProtectedHeader, SignProtected: null, ReadOnlyMemory<byte>.Empty, target.Signature, null);

        Assert.ThrowsExactly<ArgumentException>(() => CoseSerialization.BuildCountersignStructure(input));
    }


    [TestMethod]
    public void BuildCountersignStructureThrowsWhenAbbreviatedFormSuppliesSignProtected()
    {
        var target = new CoseSignatureCountersignTarget("protected"u8.ToArray(), "signature"u8.ToArray());
        CountersignStructureInput input = new(IsAbbreviated: true, target.ProtectedHeader, SignProtected: ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, target.Signature, null);

        Assert.ThrowsExactly<ArgumentException>(() => CoseSerialization.BuildCountersignStructure(input));
    }


    /// <summary>
    /// RFC 9338 Appendix A.1.1's countersignature entry (label 11's own value, independent of
    /// which target carries it) as a byte-exact parse and round-trip KAT.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.1.6-02.
    /// </remarks>
    [TestMethod]
    public void ReadCounterSignatureV2ParsesRfc9338AppendixA11ExampleAndRoundTrips()
    {
        byte[] oracle = BuildRfc9338AppendixA11CounterSignatureValueBytes();

        using CounterSignatureV2 counterSignature = CoseSerialization.ReadCounterSignatureV2(oracle, BaseMemoryPool.Shared);

        IReadOnlyDictionary<int, object> protectedHeader = CoseSerialization.ParseProtectedHeader(counterSignature.Component.ProtectedHeader.AsReadOnlySpan());
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, protectedHeader[CoseHeaderParameters.Alg]);
        Assert.IsNotNull(counterSignature.Component.UnprotectedHeader);
        Assert.IsTrue(((byte[])counterSignature.Component.UnprotectedHeader![CoseHeaderParameters.Kid]).AsSpan().SequenceEqual("11"u8));
        Assert.HasCount(64, counterSignature.Component.Signature.AsReadOnlySpan().ToArray());

        using EncodedCoseCounterSignature reEncoded = CoseSerialization.WriteCounterSignatureV2(counterSignature, BaseMemoryPool.Shared);
        Assert.IsTrue(oracle.AsSpan().SequenceEqual(reEncoded.AsReadOnlySpan()), "Re-serializing must reproduce the RFC 9338 Appendix A.1.1 example byte-for-byte.");
    }


    /// <summary>
    /// The read-accept arm: a tag-19-tagged
    /// standalone countersignature is accepted on read.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-6.3-30.
    /// </remarks>
    [TestMethod]
    public void ReadCounterSignatureV2AcceptsTag19Prefix()
    {
        byte[] untagged = BuildRfc9338AppendixA11CounterSignatureValueBytes();

        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteTag(new CborTag((ulong)CoseTags.CounterSignature));
        writer.WriteEncodedValue(untagged);
        byte[] tagged = writerBuffer.WrittenSpan.ToArray();

        using CounterSignatureV2 fromTagged = CoseSerialization.ReadCounterSignatureV2(tagged, BaseMemoryPool.Shared);
        using CounterSignatureV2 fromUntagged = CoseSerialization.ReadCounterSignatureV2(untagged, BaseMemoryPool.Shared);

        Assert.AreEqual(fromUntagged, fromTagged, "The tag-19-tagged and untagged forms of the same value must decode identically.");
    }


    /// <summary>
    /// The emit-absence arm: <see cref="CoseSerialization.WriteCounterSignatureV2"/> never
    /// emits the CBOR tag 19 wrapper.
    /// </summary>
    [TestMethod]
    public void WriteCounterSignatureV2NeverEmitsTag19()
    {
        using CounterSignatureV2 counterSignature = CoseSerialization.ReadCounterSignatureV2(
            BuildRfc9338AppendixA11CounterSignatureValueBytes(), BaseMemoryPool.Shared);

        using EncodedCoseCounterSignature written = CoseSerialization.WriteCounterSignatureV2(counterSignature, BaseMemoryPool.Shared);

        var reader = new CborReader(written.AsReadOnlyMemory(), CborOptions.Lax);
        Assert.AreNotEqual(CborReaderState.Tag, reader.PeekState(), "The writer must never emit a leading CBOR tag.");
        Assert.AreEqual(CborReaderState.StartArray, reader.PeekState(), "The untagged form starts directly with the COSE_Signature-shaped array.");
    }


    /// <summary>
    /// The abbreviated COSE_Countersignature0 form (RFC 9338 §4.2, header label 12) round-trips
    /// byte-exact: reading the bstr-wrapped value recovers the raw signature bytes verbatim, and
    /// re-encoding reproduces the identical bstr wire bytes.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.1.6-02.
    /// </remarks>
    [TestMethod]
    public void ReadWriteCounterSignature0V2RoundTripsByteExact()
    {
        byte[] oracle = Convert.FromHexString(
            "00929663c8789bb28177ae28467e66377da12302d7f9594d2999afa5dfa531294f8896f2b6cdf1740014f4c7f1a358e3a6cf57f4ed6fb02fcf8f7aa989f5dfd07f0700a3a7d8f3c604ba70fa9411bd10c2591b483e1d2c31de003183e434d8fba18f17a4c7e3dfa003ac1cf3d30d44d2533c4989d3ac38c38b71481cc3430c9d65e7ddff");

        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteByteString(oracle);
        byte[] valueBytes = writerBuffer.WrittenSpan.ToArray();

        using CounterSignature0V2 counterSignature = CoseSerialization.ReadCounterSignature0V2(valueBytes, BaseMemoryPool.Shared);
        Assert.IsTrue(oracle.AsSpan().SequenceEqual(counterSignature.Value.AsReadOnlySpan()));

        using EncodedCoseCounterSignature reEncoded = CoseSerialization.WriteCounterSignature0V2(counterSignature, BaseMemoryPool.Shared);
        Assert.IsTrue(valueBytes.AsSpan().SequenceEqual(reEncoded.AsReadOnlySpan()), "Re-serializing must reproduce the exact bstr wire bytes.");
    }


    /// <summary>
    /// RFC 9338 §1's migration text -- "verification of 'CounterSignature'
    /// must be supported by new implementations to remain compatible with senders that adhere to [RFC8152]" --
    /// is satisfied by NEVER dispatching labels 7/9 to the version-2-only <see cref="CoseSerialization.ParseCounterSignatureHeaderValue"/>.
    /// They instead ride the SAME generic, non-label-discriminating unprotected-header-map codec
    /// <see cref="CoseSerialization.ReadCounterSignatureV2"/>/<see cref="CoseSerialization.WriteCounterSignatureV2"/>
    /// already use for every OTHER label on a full countersignature's OWN <c>COSE_Signature</c>-shaped
    /// unprotected header (RFC 9338 §3.1: full countersignatures carry their own protected/unprotected
    /// attributes): understood as present, round-tripped byte-exact, never cryptographically processed --
    /// <see cref="ParseCounterSignatureHeaderValueRejectsV1CounterSignatureLabel"/>/
    /// <see cref="ParseCounterSignatureHeaderValueRejectsV1CounterSignature0Label"/> below prove the
    /// SEPARATE, never-reached rejection path for a caller that mistakenly tried to dispatch label 7/9 there.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.1.6-03.
    /// </remarks>
    [TestMethod]
    public void ReadWriteCounterSignatureV2CarriesTheDeprecatedV1LabelsOnItsOwnUnprotectedHeaderOpaquelyAndByteExact()
    {
        byte[] protectedHeaderBytes = [0xA1, 0x01, 0x26]; //{1: -7} -- alg ES256, an arbitrary well-formed protected header.
        byte[] signatureBytes = [0x01, 0x02, 0x03, 0x04];
        byte[] label7Value = [0xAA, 0xBB, 0xCC]; //An opaque V1 "CounterSignature" (label 7) value -- content is irrelevant; only carriage matters.
        byte[] label9Value = [0xDD, 0xEE]; //An opaque V1 "CounterSignature0" (label 9) value.

        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(3);
        writer.WriteByteString(protectedHeaderBytes);
        writer.WriteStartMap(2);
        writer.WriteInt32(CoseHeaderParameters.CounterSignature); //7, canonical key order below 9.
        writer.WriteByteString(label7Value);
        writer.WriteInt32(CoseHeaderParameters.CounterSignature0); //9.
        writer.WriteByteString(label9Value);
        writer.WriteEndMap();
        writer.WriteByteString(signatureBytes);
        writer.WriteEndArray();
        byte[] oracle = writerBuffer.WrittenSpan.ToArray();

        using CounterSignatureV2 counterSignature = CoseSerialization.ReadCounterSignatureV2(oracle, BaseMemoryPool.Shared);

        Assert.IsNotNull(counterSignature.Component.UnprotectedHeader, "Labels 7/9 must be UNDERSTOOD as present -- decoded into the unprotected header map, never rejected.");
        Assert.IsTrue(label7Value.AsSpan().SequenceEqual((byte[])counterSignature.Component.UnprotectedHeader![CoseHeaderParameters.CounterSignature]));
        Assert.IsTrue(label9Value.AsSpan().SequenceEqual((byte[])counterSignature.Component.UnprotectedHeader![CoseHeaderParameters.CounterSignature0]));

        using EncodedCoseCounterSignature reEncoded = CoseSerialization.WriteCounterSignatureV2(counterSignature, BaseMemoryPool.Shared);
        Assert.IsTrue(oracle.AsSpan().SequenceEqual(reEncoded.AsReadOnlySpan()),
            "Round-tripped byte-exact: labels 7/9 ride the SAME generic unprotected-header-map codec as any other label, never rejected or reinterpreted.");
    }


    /// <summary>The deprecated RFC 8152 V1 full countersignature label (7) is rejected fail-closed.</summary>
    [TestMethod]
    public void ParseCounterSignatureHeaderValueRejectsV1CounterSignatureLabel()
    {
        byte[] valueBytes = BuildRfc9338AppendixA11CounterSignatureValueBytes();

        using CoseCounterSignatureParseResult result = CoseSerialization.ParseCounterSignatureHeaderValue(
            CoseHeaderParameters.CounterSignature, valueBytes, BaseMemoryPool.Shared);

        Assert.IsFalse(result.IsSuccess, "Label 7 (RFC 8152 V1 CounterSignature) must be rejected fail-closed, never accepted as a version 2 countersignature.");
        Assert.IsNull(result.CounterSignature);
    }


    /// <summary>The deprecated RFC 8152 V1 abbreviated countersignature label (9) is rejected fail-closed.</summary>
    [TestMethod]
    public void ParseCounterSignatureHeaderValueRejectsV1CounterSignature0Label()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteByteString([1, 2, 3, 4]);
        byte[] valueBytes = writerBuffer.WrittenSpan.ToArray();

        using CoseCounterSignatureParseResult result = CoseSerialization.ParseCounterSignatureHeaderValue(
            CoseHeaderParameters.CounterSignature0, valueBytes, BaseMemoryPool.Shared);

        Assert.IsFalse(result.IsSuccess, "Label 9 (RFC 8152 V1 CounterSignature0) must be rejected fail-closed, never accepted as a version 2 countersignature.");
        Assert.IsNull(result.CounterSignature);
    }


    /// <summary>
    /// The read-accept arm on the label-discriminating parse path: a header value under label 11
    /// (CounterSignatureVersion2) that carries a leading CBOR tag 19 still parses to a
    /// <see cref="CounterSignatureV2"/>.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.1.6-03.
    /// </remarks>
    [TestMethod]
    public void ParseCounterSignatureHeaderValueAcceptsLabel11WithTag19()
    {
        byte[] untagged = BuildRfc9338AppendixA11CounterSignatureValueBytes();
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteTag(new CborTag((ulong)CoseTags.CounterSignature));
        writer.WriteEncodedValue(untagged);
        byte[] tagged = writerBuffer.WrittenSpan.ToArray();

        using CoseCounterSignatureParseResult result = CoseSerialization.ParseCounterSignatureHeaderValue(
            CoseHeaderParameters.CounterSignatureVersion2, tagged, BaseMemoryPool.Shared);

        Assert.IsTrue(result.IsSuccess, "Label 11 with a leading tag 19 must be accepted (read-accept).");
        Assert.IsInstanceOfType<CounterSignatureV2>(result.CounterSignature);
    }


    [TestMethod]
    public void ParseCounterSignatureHeaderValueAcceptsLabel12()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteByteString([9, 9, 9]);
        byte[] valueBytes = writerBuffer.WrittenSpan.ToArray();

        using CoseCounterSignatureParseResult result = CoseSerialization.ParseCounterSignatureHeaderValue(
            CoseHeaderParameters.Countersignature0Version2, valueBytes, BaseMemoryPool.Shared);

        Assert.IsTrue(result.IsSuccess);
        Assert.IsInstanceOfType<CounterSignature0V2>(result.CounterSignature);
    }


    [TestMethod]
    public void ParseCounterSignatureHeaderValueFailsClosedOnMalformedBytesNeverThrows()
    {
        byte[] malformed = [0xFF, 0xFF, 0xFF];

        using CoseCounterSignatureParseResult result = CoseSerialization.ParseCounterSignatureHeaderValue(
            CoseHeaderParameters.CounterSignatureVersion2, malformed, BaseMemoryPool.Shared);

        Assert.IsFalse(result.IsSuccess, "Malformed bytes must fail closed to an unsuccessful result, not throw.");
    }


    /// <summary>
    /// The unknown-label switch arm inside <see cref="CoseSerialization.ParseCounterSignatureHeaderValue"/>
    /// guards a caller bug, not wire data -- every label the delegate's own contract admits (7, 9, 11, 12) is
    /// already enumerated, so ANY other value (including <see cref="CoseHeaderParameters.Alg"/>, 1, used here,
    /// and an arbitrary out-of-range value in the sibling test below) must surface as
    /// <see cref="System.Diagnostics.UnreachableException"/>, escaping the fail-closed <c>catch</c> clause below
    /// it -- proving the guard is NOT one of the types that clause matches (it would otherwise have been
    /// laundered into an ordinary <see cref="CoseCounterSignatureParseResult.Failure"/>, exactly like an
    /// ordinary malformed-input case).
    /// </summary>
    [TestMethod]
    public void ParseCounterSignatureHeaderValueThrowsUnreachableExceptionForALabelItsOwnContractRulesOut()
    {
        byte[] valueBytes = BuildRfc9338AppendixA11CounterSignatureValueBytes();

        Assert.ThrowsExactly<System.Diagnostics.UnreachableException>(() =>
            CoseSerialization.ParseCounterSignatureHeaderValue(CoseHeaderParameters.Alg, valueBytes, BaseMemoryPool.Shared));
    }


    /// <summary>The sibling of the test above, using an arbitrary value with no COSE header-parameter meaning at all.</summary>
    [TestMethod]
    public void ParseCounterSignatureHeaderValueThrowsUnreachableExceptionForAnArbitraryOutOfRangeLabel()
    {
        byte[] valueBytes = BuildRfc9338AppendixA11CounterSignatureValueBytes();

        Assert.ThrowsExactly<System.Diagnostics.UnreachableException>(() =>
            CoseSerialization.ParseCounterSignatureHeaderValue(999, valueBytes, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// RFC 9338 §4 / RFC 9052 §9: <see cref="CoseSerialization.ReadCounterSignatureV2"/> reads
    /// under <see cref="CborConformanceMode.RfcCanonical"/>, which rejects an indefinite-length-chunked bstr
    /// outright rather than the <see cref="CborConformanceMode.Lax"/> behavior of silently concatenating its
    /// chunks.
    /// </summary>
    [TestMethod]
    public void ReadCounterSignatureV2RejectsIndefiniteLengthChunkedProtectedHeaderByteString()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.Lax);
        writer.WriteStartArray(3);
        writer.WriteStartIndefiniteByteString();
        writer.WriteByteString([0xA1, 0x01]);
        writer.WriteByteString([0x26]);
        writer.WriteEndIndefiniteByteString();
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString([1, 2, 3, 4]);
        writer.WriteEndArray();
        byte[] oracle = writerBuffer.WrittenSpan.ToArray();

        Assert.ThrowsExactly<InvalidOperationException>(() => CoseSerialization.ReadCounterSignatureV2(oracle, BaseMemoryPool.Shared));

        using CoseCounterSignatureParseResult result = CoseSerialization.ParseCounterSignatureHeaderValue(
            CoseHeaderParameters.CounterSignatureVersion2, oracle, BaseMemoryPool.Shared);
        Assert.IsFalse(result.IsSuccess, "The fail-closed dispatch boundary must convert this into an unsuccessful result, not let it throw.");
    }


    /// <summary>The <see cref="CoseSerialization.ReadCounterSignature0V2"/> sibling of the test above.</summary>
    [TestMethod]
    public void ReadCounterSignature0V2RejectsIndefiniteLengthChunkedByteString()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.Lax);
        writer.WriteStartIndefiniteByteString();
        writer.WriteByteString([1, 2]);
        writer.WriteByteString([3, 4]);
        writer.WriteEndIndefiniteByteString();
        byte[] oracle = writerBuffer.WrittenSpan.ToArray();

        Assert.ThrowsExactly<InvalidOperationException>(() => CoseSerialization.ReadCounterSignature0V2(oracle, BaseMemoryPool.Shared));

        using CoseCounterSignatureParseResult result = CoseSerialization.ParseCounterSignatureHeaderValue(
            CoseHeaderParameters.Countersignature0Version2, oracle, BaseMemoryPool.Shared);
        Assert.IsFalse(result.IsSuccess, "The fail-closed dispatch boundary must convert this into an unsuccessful result, not let it throw.");
    }


    /// <summary>
    /// Label 11's own value type is <c>COSE_Countersignature /
    /// [+ COSE_Countersignature]</c> (RFC 9338 §2 Table 1) -- legal input carrying TWO full countersignatures
    /// together in the array-arm shape must decode, not fail closed, into a <see cref="CounterSignatureV2Sequence"/>
    /// holding both, each independently equal to the single-value decode of its own bytes.
    /// </summary>
    [TestMethod]
    public void ParseCounterSignatureHeaderValueDecodesTheOneOrMoreArrayArmForLabel11()
    {
        byte[] firstElement = BuildRfc9338AppendixA11CounterSignatureValueBytes();
        byte[] secondElement = BuildCounterSignatureV2ElementBytes(
            protectedHeaderHex: "a10138 22".Replace(" ", string.Empty, StringComparison.Ordinal), //{1: -35} -- alg ES384.
            kid: "second"u8.ToArray(),
            signature: Enumerable.Repeat((byte)0x5A, 96).ToArray());

        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(2);
        writer.WriteEncodedValue(firstElement);
        writer.WriteEncodedValue(secondElement);
        writer.WriteEndArray();
        byte[] oracle = writerBuffer.WrittenSpan.ToArray();

        using CoseCounterSignatureParseResult result = CoseSerialization.ParseCounterSignatureHeaderValue(
            CoseHeaderParameters.CounterSignatureVersion2, oracle, BaseMemoryPool.Shared);

        Assert.IsTrue(result.IsSuccess, "A legal [+ COSE_Countersignature] array with two elements must not fail closed.");

        if(result.CounterSignature is not CounterSignatureV2Sequence sequence)
        {
            Assert.Fail("Two elements must decode into a CounterSignatureV2Sequence, not the single-value shape.");
            return;
        }

        Assert.HasCount(2, sequence.Countersignatures);

        using CounterSignatureV2 expectedFirst = CoseSerialization.ReadCounterSignatureV2(firstElement, BaseMemoryPool.Shared);
        using CounterSignatureV2 expectedSecond = CoseSerialization.ReadCounterSignatureV2(secondElement, BaseMemoryPool.Shared);
        Assert.AreEqual(expectedFirst, sequence.Countersignatures[0]);
        Assert.AreEqual(expectedSecond, sequence.Countersignatures[1]);
    }


    /// <summary>An empty <c>[+ COSE_Countersignature]</c> array violates its own CDDL's one-or-more and must fail closed.</summary>
    [TestMethod]
    public void ParseCounterSignatureHeaderValueRejectsAnEmptyArrayArmForLabel11()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        byte[] oracle = writerBuffer.WrittenSpan.ToArray();

        using CoseCounterSignatureParseResult result = CoseSerialization.ParseCounterSignatureHeaderValue(
            CoseHeaderParameters.CounterSignatureVersion2, oracle, BaseMemoryPool.Shared);

        Assert.IsFalse(result.IsSuccess, "[+ COSE_Countersignature] requires at least one element (RFC 9338 §2 Table 1); zero must fail closed.");
    }


    [TestMethod]
    public async Task CountersignAndVerifyBothTargetShapesIsMeteredPoolBalanced()
    {
        using var metered = new MeteredHousePool();

        using CoseSign1Message sign1Target = await BuildSignedCoseSign1TargetAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var coseSign1CountersignTarget = new CoseSign1CountersignTarget(
            sign1Target.ProtectedHeader.AsReadOnlyMemory(), sign1Target.Payload, sign1Target.Signature.AsReadOnlyMemory());

        using CoseSignatureComponent signatureTargetComponent = await BuildSignedCoseSignatureTargetAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var coseSignatureCountersignTarget = new CoseSignatureCountersignTarget(
            signatureTargetComponent.ProtectedHeader.AsReadOnlyMemory(), signatureTargetComponent.Signature.AsReadOnlyMemory());

        var counterSigner = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var counterSignerPublicKey = counterSigner.PublicKey;
        using var counterSignerPrivateKey = counterSigner.PrivateKey;

        using(CounterSignatureV2 full = await CoseCounterSign.CountersignFullAsync(
            coseSign1CountersignTarget,
            EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 }), metered.Pool),
            null, ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure, counterSignerPrivateKey, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false))
        {
            bool isValid = await CoseCounterSign.VerifyAsync(
                full, coseSign1CountersignTarget, ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
                counterSignerPublicKey, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isValid);

            using EncodedCoseCounterSignature encoded = CoseSerialization.WriteCounterSignatureV2(full, metered.Pool);
            using CounterSignatureV2 parsed = CoseSerialization.ReadCounterSignatureV2(encoded.AsReadOnlyMemory(), metered.Pool);
            Assert.AreEqual(full, parsed);
        }

        using(CounterSignature0V2 abbreviated = await CoseCounterSign.CountersignAbbreviatedAsync(
            coseSignatureCountersignTarget, ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
            counterSignerPrivateKey, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false))
        {
            bool isValid = await CoseCounterSign.VerifyAsync(
                abbreviated, coseSignatureCountersignTarget, ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
                counterSignerPublicKey, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isValid);
        }

        Assert.IsGreaterThan(0, metered.RentedCount, "metered.Pool must have been exercised, or the balance assertion below is vacuous.");
        Assert.AreEqual(0, metered.OutstandingCount, "Countersigning, verifying, encoding, parsing, and disposing must not leak a single pooled carrier.");
    }


    /// <summary>
    /// Metered custody on the countersign failure path: an unregistered algorithm/purpose combination
    /// must not leak the caller-supplied protected header carrier -- ownership never transferred because the
    /// registry resolution throws in the OTHER (convenience) overload, before ever calling the fully
    /// parameterized <see cref="CoseCounterSign.CountersignFullAsync(CountersignTarget, EncodedCoseProtectedHeader, IReadOnlyDictionary{int, object}?, ReadOnlyMemory{byte}, BuildCountersignStructureDelegate, PrivateKeyMemory, SigningDelegate, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>
    /// overload whose own try/catch owns disposal once it IS reached --
    /// <see cref="CountersignFullAsyncDisposesCallerSuppliedProtectedHeaderWhenSigningDelegateThrowsMeteredPoolBalanced"/>
    /// and its cancellation sibling below prove that overload's own dispose-on-throw contract.
    /// </summary>
    [TestMethod]
    public async Task CountersignFullAsyncFailurePathDoesNotLeakCallerOwnedCarrierMeteredPoolBalanced()
    {
        using var metered = new MeteredHousePool();

        var target = new CoseSignatureCountersignTarget("target-protected"u8.ToArray(), "target-signature"u8.ToArray());

        var x25519 = TestKeyMaterialProvider.CreateX25519KeyMaterial();
        using var x25519PrivateKey = x25519.PrivateKey;
        x25519.PublicKey.Dispose();

        EncodedCoseProtectedHeader counterSignerProtectedHeader = EncodedCoseProtectedHeader.FromBytes(
            CoseSerialization.SerializeProtectedHeader(new Dictionary<int, object>()), metered.Pool);

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await CoseCounterSign.CountersignFullAsync(
                target, counterSignerProtectedHeader, null, ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
                x25519PrivateKey, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        //Ownership of counterSignerProtectedHeader never transferred (the registry resolution throws before
        //the fully parameterized overload -- and therefore its own try/catch -- is ever reached), so it stays
        //caller-owned here.
        counterSignerProtectedHeader.Dispose();

        Assert.IsGreaterThan(0, metered.RentedCount, "metered.Pool must have been exercised, or the balance assertion below is vacuous.");
        Assert.AreEqual(0, metered.OutstandingCount, "The caller-owned protected header carrier must not leak when signing-delegate resolution fails.");
    }


    /// <summary>
    /// Metered custody on <see cref="CoseCounterSign.CountersignFullAsync(CountersignTarget, EncodedCoseProtectedHeader, IReadOnlyDictionary{int, object}?, ReadOnlyMemory{byte}, BuildCountersignStructureDelegate, PrivateKeyMemory, SigningDelegate, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>'s
    /// own dispose-on-throw contract: once past its own null checks, this overload
    /// consumes <c>counterSignerProtectedHeader</c> regardless of outcome -- a signing-delegate throw must not
    /// orphan the caller-supplied carrier pre-transfer. Unlike the registry-resolution-failure precedent above,
    /// the test here does NOT dispose <c>counterSignerProtectedHeader</c> itself.
    /// </summary>
    [TestMethod]
    public async Task CountersignFullAsyncDisposesCallerSuppliedProtectedHeaderWhenSigningDelegateThrowsMeteredPoolBalanced()
    {
        using var metered = new MeteredHousePool();

        var target = new CoseSignatureCountersignTarget("target-protected"u8.ToArray(), "target-signature"u8.ToArray());

        var counterSigner = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var counterSignerPrivateKey = counterSigner.PrivateKey;
        counterSigner.PublicKey.Dispose();

        EncodedCoseProtectedHeader counterSignerProtectedHeader = EncodedCoseProtectedHeader.FromBytes(
            CoseSerialization.SerializeProtectedHeader(new Dictionary<int, object>()), metered.Pool);

        static ValueTask<(Signature Signature, CryptoEvent? Event)> ThrowingSigningDelegate(
            ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool,
            FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Simulated signing-delegate failure (test-only).");

        await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
            await CoseCounterSign.CountersignFullAsync(
                target, counterSignerProtectedHeader, null, ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
                counterSignerPrivateKey, ThrowingSigningDelegate, metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.IsGreaterThan(0, metered.RentedCount, "metered.Pool must have been exercised, or the balance assertion below is vacuous.");
        Assert.AreEqual(0, metered.OutstandingCount, "The caller-supplied protected header must not leak when the signing delegate itself throws.");
    }


    /// <summary>
    /// The cancellation sibling of <see cref="CountersignFullAsyncDisposesCallerSuppliedProtectedHeaderWhenSigningDelegateThrowsMeteredPoolBalanced"/>:
    /// an already-cancelled token trips <c>cancellationToken.ThrowIfCancellationRequested()</c> before the
    /// signing delegate is ever invoked, and must still not orphan <c>counterSignerProtectedHeader</c>.
    /// </summary>
    [TestMethod]
    public async Task CountersignFullAsyncDisposesCallerSuppliedProtectedHeaderWhenCancelledMeteredPoolBalanced()
    {
        using var metered = new MeteredHousePool();

        var target = new CoseSignatureCountersignTarget("target-protected"u8.ToArray(), "target-signature"u8.ToArray());

        var counterSigner = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var counterSignerPrivateKey = counterSigner.PrivateKey;
        counterSigner.PublicKey.Dispose();

        EncodedCoseProtectedHeader counterSignerProtectedHeader = EncodedCoseProtectedHeader.FromBytes(
            CoseSerialization.SerializeProtectedHeader(new Dictionary<int, object>()), metered.Pool);

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync().ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
            await CoseCounterSign.CountersignFullAsync(
                target, counterSignerProtectedHeader, null, ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
                counterSignerPrivateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async, metered.Pool, cancellationToken: cts.Token).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.IsGreaterThan(0, metered.RentedCount, "metered.Pool must have been exercised, or the balance assertion below is vacuous.");
        Assert.AreEqual(0, metered.OutstandingCount, "The caller-supplied protected header must not leak when the call is cancelled before signing.");
    }


    private static async Task<CoseSign1Message> BuildSignedCoseSign1TargetAsync(CancellationToken cancellationToken)
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var privateKey = keyPair.PrivateKey;
        keyPair.PublicKey.Dispose();

        //Fully qualified: the enclosing namespace's own last segment ("Cose") shadows the
        //unqualified Verifiable.JCose.Cose class name in simple-name lookup.
        return await Verifiable.JCose.Cose.SignAsync(
            BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256),
            null,
            "This is the content."u8.ToArray(),
            CoseSerialization.BuildSigStructure,
            privateKey,
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);
    }


    private static async Task<CoseSignatureComponent> BuildSignedCoseSignatureTargetAsync(CancellationToken cancellationToken)
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var privateKey = keyPair.PrivateKey;
        keyPair.PublicKey.Dispose();

        return await CoseSign.SignOneAsync(
            BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256),
            BuildAlgProtectedHeader(WellKnownCoseAlgorithms.Es256),
            null,
            "This is the content."u8.ToArray(),
            CoseSerialization.BuildCoseSignatureSigStructure,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    private static EncodedCoseProtectedHeader BuildAlgProtectedHeader(int algorithm) =>
        EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(new Dictionary<int, object> { [CoseHeaderParameters.Alg] = algorithm }), BaseMemoryPool.Shared);


    /// <summary>
    /// Bilbo Baggins's P-521 public key from RFC 9052 Appendix C.7.1 (the same key whose private
    /// half produced RFC 9338 Appendix A.2.1's countersignature value), as a SEC1 uncompressed
    /// point (<c>0x04 || X || Y</c>) -- the encoding <see cref="MicrosoftCryptographicFunctionsAdapter.VerifyP521Async"/>
    /// accepts directly as <c>publicKeyMaterial</c>.
    /// </summary>
    private static byte[] BuildBilboP521UncompressedPublicKeyBytes()
    {
        byte[] x = Convert.FromHexString(
            "0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad");
        byte[] y = Convert.FromHexString(
            "01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475");

        byte[] point = new byte[1 + x.Length + y.Length];
        point[0] = 0x04;
        x.CopyTo(point, 1);
        y.CopyTo(point, 1 + x.Length);

        return point;
    }


    /// <summary>
    /// Hand-assembles RFC 9338 Appendix A.1.1's countersignature entry (label 11's own value)
    /// verbatim, independent of <see cref="CoseSerialization.WriteCounterSignatureV2"/>.
    /// </summary>
    private static byte[] BuildRfc9338AppendixA11CounterSignatureValueBytes()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(3);
        writer.WriteByteString(Convert.FromHexString("a10126"));
        writer.WriteStartMap(1);
        writer.WriteInt32(CoseHeaderParameters.Kid);
        writer.WriteByteString("11"u8);
        writer.WriteEndMap();
        writer.WriteByteString(Convert.FromHexString(
            "5ac05e289d5d0e1b0a7f048a5d2b643813ded50bc9e49220f4f7278f85f19d4a77d655c9d3b51e805a74b099e1e085aacd97fc29d72f887e8802bb6650cceb2c"));
        writer.WriteEndArray();

        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Hand-assembles one <c>COSE_Countersignature</c> element (protected, unprotected {kid}, signature) --
    /// the shape RFC 9338 §2 Table 1's <c>[+ COSE_Countersignature]</c> array arm repeats one-or-more times.
    /// </summary>
    /// <param name="protectedHeaderHex">The already-serialized protected-header map's own bytes, as hex.</param>
    /// <param name="kid">The unprotected header's <c>kid</c> value.</param>
    /// <param name="signature">The signature value bytes.</param>
    private static byte[] BuildCounterSignatureV2ElementBytes(string protectedHeaderHex, byte[] kid, byte[] signature)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(3);
        writer.WriteByteString(Convert.FromHexString(protectedHeaderHex));
        writer.WriteStartMap(1);
        writer.WriteInt32(CoseHeaderParameters.Kid);
        writer.WriteByteString(kid);
        writer.WriteEndMap();
        writer.WriteByteString(signature);
        writer.WriteEndArray();

        return writerBuffer.WrittenSpan.ToArray();
    }
}
