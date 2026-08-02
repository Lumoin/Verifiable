using System;
using System.Formats.Cbor;
using Verifiable.Cbor;
using Verifiable.Foundation;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Byte-exact regression vectors for the four CB-AdES message-imprint-INPUT builders
/// (<see cref="CBAdESMessageImprints"/>), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clauses 5.2.6 (<c>adoTst</c>), 5.3.5.3 (<c>arcTst</c>), Annex A.1.2.1.2
/// (<c>sigRTst</c>), and Annex A.1.2.2.2 (<c>rfsTst</c>). This is the S2 exit criterion.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Firewalled, independent oracle.</strong> Every expected byte sequence in this file is assembled
/// directly with a fresh <see cref="CborWriter"/> in canonical mode, following the spec's own numbered
/// steps, with fixed literal fixture bytes standing in for protected headers/payload/signature/external
/// data and independently-assembled encoded <c>uHeaders</c> fixtures — never by calling
/// <see cref="CBAdESMessageImprints"/> or mirroring its internals. The verifier (this suite) reconstructs
/// each expected value from first principles; the builder under test is exercised only through its public
/// surface, against wire-shaped inputs.
/// </para>
/// <para>
/// <strong>D1 / step-12 reading.</strong> Every <c>arcTst</c> expected byte sequence below is the fully
/// assembled twelve-step array's OWN canonical CBOR encoding, with no additional outer <c>bstr</c> header —
/// matching this wave's recorded reading of the spec's closing sentence (see
/// <see cref="CBAdESMessageImprints"/>'s own remarks for D1 and the step-12 reading).
/// </para>
/// </remarks>
[TestClass]
internal sealed class CBAdESMessageImprintTests
{
    /// <summary>
    /// <c>sigTst</c> (clause 5.3.3, CB-5.3.3-02): the trivial builder returns exactly the input
    /// signature-value bytes, unwrapped and unconcatenated, byte-exact against a literal fixture -- no CBOR
    /// encoding of any kind, in contrast with the <c>arcTst</c>/<c>sigRTst</c>/<c>rfsTst</c> builders.
    /// </summary>
    [TestMethod]
    public void SigTstMessageImprintReturnsRawSignatureValueBytesUnwrapped()
    {
        byte[] signatureValue = [0x30, 0x81, 0x88, 0x02, 0x01, 0x00];

        using PooledMemory result = CBAdESMessageImprints.BuildSignatureTimestampMessageImprintInput(signatureValue, BaseMemoryPool.Shared);

        Assert.IsTrue(signatureValue.AsSpan().SequenceEqual(result.AsReadOnlySpan()), "sigTst's message-imprint input must be exactly the raw signature-value bytes, unwrapped.");
    }


    /// <summary>
    /// <c>sigTst</c> (clause 5.3.3): the trivial builder places no guard on an empty signature-value input --
    /// exercising that edge, since CB-5.3.3-02's literal reading applies unconditionally, with no minimum
    /// length the method itself enforces.
    /// </summary>
    [TestMethod]
    public void SigTstMessageImprintReturnsEmptyBytesForEmptySignatureValue()
    {
        using PooledMemory result = CBAdESMessageImprints.BuildSignatureTimestampMessageImprintInput(ReadOnlyMemory<byte>.Empty, BaseMemoryPool.Shared);

        Assert.AreEqual(0, result.Length, "An empty signature-value input must produce an empty message-imprint input, not throw.");
    }


    /// <summary>
    /// <c>arcTst</c> generation (clause 5.3.5.3), <c>COSE_Sign1</c>, attached payload: body protected header
    /// present, externally supplied data absent (step 5 zero-length sentinel), no <c>uHeaders</c> at all
    /// (steps 10/11 absent sentinel).
    /// </summary>
    [TestMethod]
    public void ArcTstGenerationCoseSign1AttachedPayloadMatchesIndependentOracle()
    {
        byte[] bodyProtectedHeader = [0x01, 0x02];
        byte[] payload = [0xAA, 0xBB, 0xCC];
        byte[] signatureValue = [0x10, 0x20, 0x30, 0x40];

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(6);
        writer.WriteTextString("Signature1"); //step 2: COSE_Sign1 context text.
        writer.WriteByteString(bodyProtectedHeader); //step 3.
        writer.WriteByteString(ReadOnlySpan<byte>.Empty); //step 5: no externally supplied data.
        writer.WriteByteString(payload); //steps 6/7: payload field present, wrapped in a bstr.
        writer.WriteByteString(signatureValue); //step 9.
        writer.WriteByteString(ReadOnlySpan<byte>.Empty); //steps 10/11: body layer has no uHeaders at all.
        writer.WriteEndArray();
        byte[] expected = writer.Encode();

        CBAdESArchiveTimestampImprintContext context = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader,
            signerProtectedHeader: null,
            externallySuppliedData: [],
            payloadSource: new CBAdESAttachedPayloadImprintSource(payload),
            signatureValue,
            uHeadersEncodedArray: null);

        bool built = CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput(context, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsTrue(built);
        using(result)
        {
            Assert.IsTrue(expected.AsSpan().SequenceEqual(result!.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");
        }
    }


    /// <summary>
    /// <c>arcTst</c> generation (clause 5.3.5.3), <c>COSE_Sign1</c>, detached payload (payload field absent,
    /// no <c>sigD</c>): the body protected header is itself absent (step 3 zero-length sentinel), and
    /// externally supplied data IS present (step 5), demonstrating the "present" branch this file's other
    /// scenarios pair with the "absent" branch.
    /// </summary>
    [TestMethod]
    public void ArcTstGenerationCoseSign1DetachedPayloadMatchesIndependentOracle()
    {
        byte[] externallySuppliedData = [0xEE];
        byte[] detachedPayload = [0x0A, 0x0B];
        byte[] signatureValue = [0x99];

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(6);
        writer.WriteTextString("Signature1");
        writer.WriteByteString(ReadOnlySpan<byte>.Empty); //step 3: body layer has no protected header.
        writer.WriteByteString(externallySuppliedData); //step 5: present.
        writer.WriteByteString(detachedPayload); //steps 6/7: payload field absent -- retrieved detached bytes, wrapped in a bstr.
        writer.WriteByteString(signatureValue);
        writer.WriteByteString(ReadOnlySpan<byte>.Empty);
        writer.WriteEndArray();
        byte[] expected = writer.Encode();

        CBAdESArchiveTimestampImprintContext context = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader: [],
            signerProtectedHeader: null,
            externallySuppliedData,
            payloadSource: new CBAdESDetachedPayloadImprintSource(detachedPayload),
            signatureValue,
            uHeadersEncodedArray: null);

        bool built = CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput(context, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsTrue(built);
        using(result)
        {
            Assert.IsTrue(expected.AsSpan().SequenceEqual(result!.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");
        }
    }


    /// <summary>
    /// <c>arcTst</c> generation (clause 5.3.5.3), <c>COSE_Sign</c>, signer-layer protected header PRESENT
    /// (step 4 executes and contributes the header's own bytes).
    /// </summary>
    [TestMethod]
    public void ArcTstGenerationCoseSignWithSignerProtectedHeaderPresentMatchesIndependentOracle()
    {
        byte[] bodyProtectedHeader = [0x0A];
        byte[] signerProtectedHeader = [0x0B, 0x0C];
        byte[] externallySuppliedData = [0xEE];
        byte[] payload = [0xF0];
        byte[] signatureValue = [0x77];

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(7);
        writer.WriteTextString("Signature"); //step 2: COSE_Sign context text.
        writer.WriteByteString(bodyProtectedHeader); //step 3.
        writer.WriteByteString(signerProtectedHeader); //step 4: COSE_Sign, signer layer present.
        writer.WriteByteString(externallySuppliedData); //step 5.
        writer.WriteByteString(payload); //steps 6/7.
        writer.WriteByteString(signatureValue); //step 9.
        writer.WriteByteString(ReadOnlySpan<byte>.Empty); //steps 10/11: no uHeaders at all.
        writer.WriteEndArray();
        byte[] expected = writer.Encode();

        CBAdESArchiveTimestampImprintContext context = BuildArcTstContext(
            CBAdESCoseSignStructureContext.Instance,
            bodyProtectedHeader,
            signerProtectedHeader,
            externallySuppliedData,
            payloadSource: new CBAdESAttachedPayloadImprintSource(payload),
            signatureValue,
            uHeadersEncodedArray: null);

        bool built = CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput(context, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsTrue(built);
        using(result)
        {
            Assert.IsTrue(expected.AsSpan().SequenceEqual(result!.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");
        }
    }


    /// <summary>
    /// <c>arcTst</c> generation (clause 5.3.5.3), <c>COSE_Sign</c>, signer-layer protected header ABSENT:
    /// step 4 still executes (a signer layer always exists under <c>COSE_Sign</c>) but contributes the
    /// zero-length <c>bstr</c> sentinel for "the signer layer's protected header map is itself absent" — one
    /// item either way, never skipped entirely (contrast with <c>COSE_Sign1</c>, where step 4 does not exist).
    /// </summary>
    [TestMethod]
    public void ArcTstGenerationCoseSignWithSignerProtectedHeaderAbsentUsesZeroLengthSentinel()
    {
        byte[] bodyProtectedHeader = [0x01];
        byte[] payload = [0x02];
        byte[] signatureValue = [0x03];

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(7);
        writer.WriteTextString("Signature");
        writer.WriteByteString(bodyProtectedHeader);
        writer.WriteByteString(ReadOnlySpan<byte>.Empty); //step 4: signer layer present but its protected header map is absent.
        writer.WriteByteString(ReadOnlySpan<byte>.Empty); //step 5.
        writer.WriteByteString(payload);
        writer.WriteByteString(signatureValue);
        writer.WriteByteString(ReadOnlySpan<byte>.Empty);
        writer.WriteEndArray();
        byte[] expected = writer.Encode();

        CBAdESArchiveTimestampImprintContext context = BuildArcTstContext(
            CBAdESCoseSignStructureContext.Instance,
            bodyProtectedHeader,
            signerProtectedHeader: Array.Empty<byte>(), //non-null, empty -- the "present but empty" sentinel.
            externallySuppliedData: [],
            payloadSource: new CBAdESAttachedPayloadImprintSource(payload),
            signatureValue,
            uHeadersEncodedArray: null);

        bool built = CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput(context, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsTrue(built);
        using(result)
        {
            Assert.IsTrue(expected.AsSpan().SequenceEqual(result!.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");
        }
    }


    /// <summary>
    /// The builder rejects a <see cref="CBAdESArchiveTimestampImprintContext.SignerProtectedHeader"/>
    /// nullness inconsistent with the structure: non-null under <c>COSE_Sign1</c> (which has no signer
    /// layer), and null under <c>COSE_Sign</c> (which always has one).
    /// </summary>
    [TestMethod]
    public void ArcTstGenerationThrowsWhenSignerProtectedHeaderNullnessMismatchesStructure()
    {
        CBAdESArchiveTimestampImprintContext coseSign1WithSignerHeader = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader: [],
            signerProtectedHeader: [0x01],
            externallySuppliedData: [],
            payloadSource: new CBAdESAttachedPayloadImprintSource(new byte[] { 0x02 }),
            signatureValue: [0x03],
            uHeadersEncodedArray: null);

        Assert.ThrowsExactly<ArgumentException>(() =>
            CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput(coseSign1WithSignerHeader, BaseMemoryPool.Shared, out _));

        CBAdESArchiveTimestampImprintContext coseSignWithoutSignerHeader = BuildArcTstContext(
            CBAdESCoseSignStructureContext.Instance,
            bodyProtectedHeader: [],
            signerProtectedHeader: null,
            externallySuppliedData: [],
            payloadSource: new CBAdESAttachedPayloadImprintSource(new byte[] { 0x02 }),
            signatureValue: [0x03],
            uHeadersEncodedArray: null);

        Assert.ThrowsExactly<ArgumentException>(() =>
            CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput(coseSignWithoutSignerHeader, BaseMemoryPool.Shared, out _));
    }


    /// <summary>
    /// <c>arcTst</c> generation (clause 5.3.5.3), <c>sigD</c>-present branch: two processed <c>pars</c>
    /// byte segments are concatenated, THEN the concatenation is wrapped in one <c>bstr</c> (step 7) —
    /// contrast with <c>adoTst</c>'s own <c>sigD</c> arm, which does not wrap at all.
    /// </summary>
    [TestMethod]
    public void ArcTstGenerationSigDBranchConcatenatesThenEncapsulatesProcessedPars()
    {
        byte[] segment1 = [0x01, 0x02];
        byte[] segment2 = [0x03];
        byte[] signatureValue = [0x55];

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(6);
        writer.WriteTextString("Signature1");
        writer.WriteByteString(ReadOnlySpan<byte>.Empty);
        writer.WriteByteString(ReadOnlySpan<byte>.Empty);
        writer.WriteByteString([0x01, 0x02, 0x03]); //step 7: concatenate segment1 then segment2, THEN wrap in one bstr.
        writer.WriteByteString(signatureValue);
        writer.WriteByteString(ReadOnlySpan<byte>.Empty);
        writer.WriteEndArray();
        byte[] expected = writer.Encode();

        CBAdESArchiveTimestampImprintContext context = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader: [],
            signerProtectedHeader: null,
            externallySuppliedData: [],
            payloadSource: new CBAdESSigDProcessedPayloadImprintSource([segment1, segment2]),
            signatureValue,
            uHeadersEncodedArray: null);

        bool built = CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput(context, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsTrue(built);
        using(result)
        {
            Assert.IsTrue(expected.AsSpan().SequenceEqual(result!.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");
        }
    }


    /// <summary>
    /// <c>arcTst</c> generation (clause 5.3.5.3), steps 10/11: a present, multi-element <c>uHeaders</c> array
    /// is appended in its exact wire order — each array item copied verbatim (the original <c>bstr</c> item,
    /// unmodified), never unwrapped or reordered.
    /// </summary>
    [TestMethod]
    public void ArcTstGenerationAppendsMultiElementUHeadersInWireOrder()
    {
        byte[] bodyProtectedHeader = [0x01];
        byte[] externallySuppliedData = [0x02];
        byte[] payload = [0x03];
        byte[] signatureValue = [0x04];
        byte[] item0 = [0xA0];
        byte[] item1 = [0xB0, 0xB1];
        byte[] item2 = [0xC0, 0xC1, 0xC2];
        byte[] uHeadersEncodedArray = BuildExpectedArrayOfByteStrings(item0, item1, item2);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(8);
        writer.WriteTextString("Signature1");
        writer.WriteByteString(bodyProtectedHeader);
        writer.WriteByteString(externallySuppliedData);
        writer.WriteByteString(payload);
        writer.WriteByteString(signatureValue);
        writer.WriteByteString(item0); //steps 10/11: uHeaders elements, in wire order.
        writer.WriteByteString(item1);
        writer.WriteByteString(item2);
        writer.WriteEndArray();
        byte[] expected = writer.Encode();

        CBAdESArchiveTimestampImprintContext context = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader,
            signerProtectedHeader: null,
            externallySuppliedData,
            payloadSource: new CBAdESAttachedPayloadImprintSource(payload),
            signatureValue,
            uHeadersEncodedArray);

        bool built = CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput(context, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsTrue(built);
        using(result)
        {
            Assert.IsTrue(expected.AsSpan().SequenceEqual(result!.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");
        }
    }


    /// <summary><c>arcTst</c> generation fails closed when <c>UHeadersEncodedArray</c> is present but the bytes are not themselves a CBOR array.</summary>
    [TestMethod]
    public void ArcTstGenerationFailsClosedWhenUHeadersIsNotAnArray()
    {
        CBAdESArchiveTimestampImprintContext context = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader: [],
            signerProtectedHeader: null,
            externallySuppliedData: [],
            payloadSource: new CBAdESAttachedPayloadImprintSource(new byte[] { 0x01 }),
            signatureValue: [0x02],
            uHeadersEncodedArray: BuildUHeadersBytesThatAreNotAnArray());

        bool built = CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput(context, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsFalse(built, "Non-array uHeaders bytes must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// <c>arcTst</c> generation fails closed when a <c>uHeaders</c> array element is not itself a CBOR byte
    /// string -- pins the take-path fail-closed check (CB-5.3.1-04): generation takes every element, so this
    /// exercises the take path exclusively.
    /// </summary>
    [TestMethod]
    public void ArcTstGenerationFailsClosedWhenUHeadersElementIsNotByteString()
    {
        CBAdESArchiveTimestampImprintContext context = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader: [],
            signerProtectedHeader: null,
            externallySuppliedData: [],
            payloadSource: new CBAdESAttachedPayloadImprintSource(new byte[] { 0x01 }),
            signatureValue: [0x02],
            uHeadersEncodedArray: BuildUHeadersArrayWithNonByteStringElement());

        bool built = CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput(context, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsFalse(built, "A non-bstr uHeaders array element must fail closed on the take path (CB-5.3.1-04).");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary><c>arcTst</c> generation fails closed on a zero-element <c>uHeaders</c> array (CB-5.3.1-07).</summary>
    [TestMethod]
    public void ArcTstGenerationFailsClosedOnZeroElementUHeadersArray()
    {
        CBAdESArchiveTimestampImprintContext context = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader: [],
            signerProtectedHeader: null,
            externallySuppliedData: [],
            payloadSource: new CBAdESAttachedPayloadImprintSource(new byte[] { 0x01 }),
            signatureValue: [0x02],
            uHeadersEncodedArray: BuildZeroElementUHeadersArray());

        bool built = CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput(context, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsFalse(built, "A zero-element uHeaders array violates CB-5.3.1-07's non-empty-array requirement and must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary><c>arcTst</c> generation fails closed on truncated <c>uHeaders</c> bytes (a well-formed one-element array with its final byte removed).</summary>
    [TestMethod]
    public void ArcTstGenerationFailsClosedOnTruncatedUHeadersBytes()
    {
        byte[] wellFormed = BuildExpectedArrayOfByteStrings([0xA0]);
        byte[] truncated = wellFormed[..^1];

        CBAdESArchiveTimestampImprintContext context = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader: [],
            signerProtectedHeader: null,
            externallySuppliedData: [],
            payloadSource: new CBAdESAttachedPayloadImprintSource(new byte[] { 0x01 }),
            signatureValue: [0x02],
            uHeadersEncodedArray: truncated);

        bool built = CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput(context, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsFalse(built, "Truncated uHeaders bytes must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// <c>arcTst</c> validation variant (clause 5.3.5.3, steps 10/11 replaced): with a four-element
    /// <c>uHeaders</c> array and the <c>arcTst</c> under validation at index 2, only elements 0 and 1
    /// contribute (the prefix rule) — and the validation output differs from the generation output (which
    /// takes all four) EXACTLY by the excluded suffix (items 2 and 3), both against this file's independent
    /// oracle and directly between the two shipped outputs.
    /// </summary>
    [TestMethod]
    public void ArcTstValidationAppendsOnlyElementsPrecedingTargetIndexAndDiffersFromGenerationByExcludedSuffix()
    {
        byte[] bodyProtectedHeader = [0x01];
        byte[] externallySuppliedData = [0x02];
        byte[] payload = [0x03];
        byte[] signatureValue = [0x04];
        byte[] item0 = [0xA0];
        byte[] item1 = [0xB0, 0xB1];
        byte[] item2 = [0xC0, 0xC1, 0xC2];
        byte[] item3 = [0xD0, 0xD1, 0xD2, 0xD3];
        byte[] uHeadersEncodedArray = BuildExpectedArrayOfByteStrings(item0, item1, item2, item3);

        var generationWriter = new CborWriter(CborConformanceMode.Canonical);
        generationWriter.WriteStartArray(9);
        generationWriter.WriteTextString("Signature1");
        generationWriter.WriteByteString(bodyProtectedHeader);
        generationWriter.WriteByteString(externallySuppliedData);
        generationWriter.WriteByteString(payload);
        generationWriter.WriteByteString(signatureValue);
        generationWriter.WriteByteString(item0);
        generationWriter.WriteByteString(item1);
        generationWriter.WriteByteString(item2);
        generationWriter.WriteByteString(item3);
        generationWriter.WriteEndArray();
        byte[] expectedGeneration = generationWriter.Encode();

        var validationWriter = new CborWriter(CborConformanceMode.Canonical);
        validationWriter.WriteStartArray(7);
        validationWriter.WriteTextString("Signature1");
        validationWriter.WriteByteString(bodyProtectedHeader);
        validationWriter.WriteByteString(externallySuppliedData);
        validationWriter.WriteByteString(payload);
        validationWriter.WriteByteString(signatureValue);
        validationWriter.WriteByteString(item0);
        validationWriter.WriteByteString(item1); //stops here: item2/item3 precede neither the target (index 2 is item2 itself).
        validationWriter.WriteEndArray();
        byte[] expectedValidation = validationWriter.Encode();

        CBAdESArchiveTimestampImprintContext context = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader,
            signerProtectedHeader: null,
            externallySuppliedData,
            payloadSource: new CBAdESAttachedPayloadImprintSource(payload),
            signatureValue,
            uHeadersEncodedArray);

        bool generatedOk = CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput(context, BaseMemoryPool.Shared, out PooledMemory? generationResult);
        bool validatedOk = CBAdESMessageImprints.TryBuildArchiveTimestampValidationMessageImprintInput(context, arcTstElementIndex: 2, BaseMemoryPool.Shared, out PooledMemory? validationResult);

        Assert.IsTrue(generatedOk);
        Assert.IsTrue(validatedOk);
        using(generationResult)
        using(validationResult)
        {
            Assert.IsTrue(expectedGeneration.AsSpan().SequenceEqual(generationResult!.AsReadOnlySpan()), "Generation must reproduce the independent oracle's bytes exactly.");
            Assert.IsTrue(expectedValidation.AsSpan().SequenceEqual(validationResult!.AsReadOnlySpan()), "Validation must reproduce the independent oracle's bytes exactly.");

            ReadOnlySpan<byte> generationBytes = generationResult!.AsReadOnlySpan();
            ReadOnlySpan<byte> validationBytes = validationResult!.AsReadOnlySpan();

            Assert.AreEqual((byte)(validationBytes[0] + 2), generationBytes[0], "The array-length header must differ by exactly the two excluded elements.");
            Assert.IsTrue(
                validationBytes[1..].SequenceEqual(generationBytes.Slice(1, validationBytes.Length - 1)),
                "Every element up to the excluded suffix must be byte-identical between generation and validation.");

            byte[] expectedSuffix = [.. EncodeCanonicalByteString(item2), .. EncodeCanonicalByteString(item3)];
            Assert.IsTrue(
                generationBytes[validationBytes.Length..].SequenceEqual(expectedSuffix),
                "Generation's output must differ from validation's exactly by the excluded arcTst-and-later uHeaders elements.");
        }
    }


    /// <summary><c>arcTst</c> validation fails closed when <c>UHeadersEncodedArray</c> is present but the bytes are not themselves a CBOR array.</summary>
    [TestMethod]
    public void ArcTstValidationFailsClosedWhenUHeadersIsNotAnArray()
    {
        CBAdESArchiveTimestampImprintContext context = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader: [],
            signerProtectedHeader: null,
            externallySuppliedData: [],
            payloadSource: new CBAdESAttachedPayloadImprintSource(new byte[] { 0x01 }),
            signatureValue: [0x02],
            uHeadersEncodedArray: BuildUHeadersBytesThatAreNotAnArray());

        bool built = CBAdESMessageImprints.TryBuildArchiveTimestampValidationMessageImprintInput(context, arcTstElementIndex: 0, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsFalse(built, "Non-array uHeaders bytes must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// <c>arcTst</c> validation fails closed when a non-bstr <c>uHeaders</c> element sits strictly in the
    /// SKIPPED range (position at or after <c>arcTstElementIndex</c>) -- pins the skip-path fail-closed check
    /// added alongside the take-path one (CB-5.3.1-04): a malformed element that will never be copied into
    /// the output must still be rejected, not silently walked past.
    /// </summary>
    [TestMethod]
    public void ArcTstValidationFailsClosedWhenNonByteStringElementIsInTheSkippedRange()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(2);
        writer.WriteByteString([0xA0]); //Element 0: taken (arcTstElementIndex 1 -> itemsToTake 1), a valid bstr.
        writer.WriteInt32(99); //Element 1: SKIPPED (i=1 >= itemsToTake=1), not a bstr -- the skip-path check.
        writer.WriteEndArray();
        byte[] uHeadersWithNonBstrInSkipRange = writer.Encode();

        CBAdESArchiveTimestampImprintContext context = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader: [],
            signerProtectedHeader: null,
            externallySuppliedData: [],
            payloadSource: new CBAdESAttachedPayloadImprintSource(new byte[] { 0x01 }),
            signatureValue: [0x02],
            uHeadersEncodedArray: uHeadersWithNonBstrInSkipRange);

        bool built = CBAdESMessageImprints.TryBuildArchiveTimestampValidationMessageImprintInput(context, arcTstElementIndex: 1, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsFalse(built, "A non-bstr uHeaders array element in the skipped range must fail closed too, not only in the taken range (CB-5.3.1-04).");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary><c>arcTst</c> validation fails closed on a zero-element <c>uHeaders</c> array (CB-5.3.1-07).</summary>
    [TestMethod]
    public void ArcTstValidationFailsClosedOnZeroElementUHeadersArray()
    {
        CBAdESArchiveTimestampImprintContext context = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader: [],
            signerProtectedHeader: null,
            externallySuppliedData: [],
            payloadSource: new CBAdESAttachedPayloadImprintSource(new byte[] { 0x01 }),
            signatureValue: [0x02],
            uHeadersEncodedArray: BuildZeroElementUHeadersArray());

        bool built = CBAdESMessageImprints.TryBuildArchiveTimestampValidationMessageImprintInput(context, arcTstElementIndex: 0, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsFalse(built, "A zero-element uHeaders array violates CB-5.3.1-07's non-empty-array requirement and must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary><c>arcTst</c> validation fails closed on truncated <c>uHeaders</c> bytes (a well-formed one-element array with its final byte removed).</summary>
    [TestMethod]
    public void ArcTstValidationFailsClosedOnTruncatedUHeadersBytes()
    {
        byte[] wellFormed = BuildExpectedArrayOfByteStrings([0xA0]);
        byte[] truncated = wellFormed[..^1];

        CBAdESArchiveTimestampImprintContext context = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader: [],
            signerProtectedHeader: null,
            externallySuppliedData: [],
            payloadSource: new CBAdESAttachedPayloadImprintSource(new byte[] { 0x01 }),
            signatureValue: [0x02],
            uHeadersEncodedArray: truncated);

        bool built = CBAdESMessageImprints.TryBuildArchiveTimestampValidationMessageImprintInput(context, arcTstElementIndex: 0, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsFalse(built, "Truncated uHeaders bytes must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// The absent-vs-empty-prefix asymmetry (recorded ruling, see
    /// <see cref="CBAdESArchiveTimestampImprintContext.UHeadersEncodedArray"/>'s remarks): with a non-empty,
    /// two-element <c>uHeaders</c> array PRESENT, validating at <c>arcTstElementIndex: 0</c> yields an EMPTY
    /// prefix -- ZERO items contributed, not the "not present" placeholder -- differing from the SAME-context
    /// call with <c>uHeaders</c> entirely ABSENT (<see langword="null"/>), which contributes exactly ONE
    /// zero-length <c>bstr</c> sentinel. The two outputs differ EXACTLY by the array's element-count header
    /// and that one trailing sentinel item.
    /// </summary>
    [TestMethod]
    public void ArcTstValidationAtIndexZeroWithPresentUHeadersDiffersFromAbsentUHeadersBySentinelItem()
    {
        byte[] bodyProtectedHeader = [0x01];
        byte[] externallySuppliedData = [0x02];
        byte[] payload = [0x03];
        byte[] signatureValue = [0x04];
        byte[] item0 = [0xA0];
        byte[] item1 = [0xB0, 0xB1];
        byte[] uHeadersEncodedArray = BuildExpectedArrayOfByteStrings(item0, item1);

        var presentPrefixWriter = new CborWriter(CborConformanceMode.Canonical);
        presentPrefixWriter.WriteStartArray(5); //Steps 10/11 contribute ZERO items -- the empty prefix.
        presentPrefixWriter.WriteTextString("Signature1");
        presentPrefixWriter.WriteByteString(bodyProtectedHeader);
        presentPrefixWriter.WriteByteString(externallySuppliedData);
        presentPrefixWriter.WriteByteString(payload);
        presentPrefixWriter.WriteByteString(signatureValue);
        presentPrefixWriter.WriteEndArray();
        byte[] expectedPresentEmptyPrefix = presentPrefixWriter.Encode();

        var absentWriter = new CborWriter(CborConformanceMode.Canonical);
        absentWriter.WriteStartArray(6); //Steps 10/11 contribute the ONE "not present" zero-length bstr sentinel.
        absentWriter.WriteTextString("Signature1");
        absentWriter.WriteByteString(bodyProtectedHeader);
        absentWriter.WriteByteString(externallySuppliedData);
        absentWriter.WriteByteString(payload);
        absentWriter.WriteByteString(signatureValue);
        absentWriter.WriteByteString(ReadOnlySpan<byte>.Empty);
        absentWriter.WriteEndArray();
        byte[] expectedAbsentSentinel = absentWriter.Encode();

        CBAdESArchiveTimestampImprintContext presentContext = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader,
            signerProtectedHeader: null,
            externallySuppliedData,
            payloadSource: new CBAdESAttachedPayloadImprintSource(payload),
            signatureValue,
            uHeadersEncodedArray);

        CBAdESArchiveTimestampImprintContext absentContext = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader,
            signerProtectedHeader: null,
            externallySuppliedData,
            payloadSource: new CBAdESAttachedPayloadImprintSource(payload),
            signatureValue,
            uHeadersEncodedArray: null);

        bool presentPrefixBuilt = CBAdESMessageImprints.TryBuildArchiveTimestampValidationMessageImprintInput(
            presentContext, arcTstElementIndex: 0, BaseMemoryPool.Shared, out PooledMemory? presentPrefixResult);
        bool absentBuilt = CBAdESMessageImprints.TryBuildArchiveTimestampValidationMessageImprintInput(
            absentContext, arcTstElementIndex: 0, BaseMemoryPool.Shared, out PooledMemory? absentResult);

        Assert.IsTrue(presentPrefixBuilt);
        Assert.IsTrue(absentBuilt);
        using(presentPrefixResult)
        using(absentResult)
        {
            Assert.IsTrue(
                expectedPresentEmptyPrefix.AsSpan().SequenceEqual(presentPrefixResult!.AsReadOnlySpan()),
                "The present-but-empty-prefix output must reproduce the independent oracle's bytes exactly.");
            Assert.IsTrue(
                expectedAbsentSentinel.AsSpan().SequenceEqual(absentResult!.AsReadOnlySpan()),
                "The absent-uHeaders output must reproduce the independent oracle's bytes exactly.");

            ReadOnlySpan<byte> presentBytes = presentPrefixResult!.AsReadOnlySpan();
            ReadOnlySpan<byte> absentBytes = absentResult!.AsReadOnlySpan();

            Assert.AreNotEqual(presentBytes.Length, absentBytes.Length, "The two readings must not accidentally converge to the same length.");
            Assert.AreEqual((byte)(presentBytes[0] + 1), absentBytes[0], "The array-length header must differ by exactly the one sentinel item.");
            Assert.IsTrue(presentBytes[1..].SequenceEqual(absentBytes[1..^1]), "Every element up to the sentinel must be byte-identical between the two readings.");
            Assert.AreEqual((byte)0x40, absentBytes[^1], "The sole difference must be the single zero-length bstr sentinel item appended at the end.");
        }
    }


    /// <summary>
    /// Validation-mode absent-<c>uHeaders</c> sentinel (matrix rows CB-5.3.5.3-14/-15): with
    /// <see cref="CBAdESArchiveTimestampImprintContext.UHeadersEncodedArray"/> null, the validation-time
    /// variant contributes the SAME single zero-length <c>bstr</c> "not present" sentinel as the
    /// generation-time variant, byte-exact against an independent oracle, regardless of the
    /// <c>arcTstElementIndex</c> value supplied -- there is no array to slice when the parameter itself is
    /// absent.
    /// </summary>
    [TestMethod]
    public void ArcTstValidationUsesZeroLengthSentinelWhenUHeadersAbsentRegardlessOfElementIndex()
    {
        byte[] bodyProtectedHeader = [0x0A];
        byte[] externallySuppliedData = [0x0B];
        byte[] payload = [0x0C];
        byte[] signatureValue = [0x0D];

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(6);
        writer.WriteTextString("Signature1");
        writer.WriteByteString(bodyProtectedHeader);
        writer.WriteByteString(externallySuppliedData);
        writer.WriteByteString(payload);
        writer.WriteByteString(signatureValue);
        writer.WriteByteString(ReadOnlySpan<byte>.Empty); //steps 10/11: uHeaders header parameter absent entirely.
        writer.WriteEndArray();
        byte[] expected = writer.Encode();

        CBAdESArchiveTimestampImprintContext context = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader,
            signerProtectedHeader: null,
            externallySuppliedData,
            payloadSource: new CBAdESAttachedPayloadImprintSource(payload),
            signatureValue,
            uHeadersEncodedArray: null);

        bool built = CBAdESMessageImprints.TryBuildArchiveTimestampValidationMessageImprintInput(
            context, arcTstElementIndex: 5, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsTrue(built);
        using(result)
        {
            Assert.IsTrue(expected.AsSpan().SequenceEqual(result!.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");
        }
    }


    /// <summary>
    /// <c>adoTst</c> (clause 5.2.6), attached-payload arm (CB-5.2.6-05): the CBOR byte string of the
    /// <c>payload</c> field.
    /// </summary>
    [TestMethod]
    public void AdoTstAttachedPayloadIsWrappedByteString()
    {
        byte[] payload = [0x01, 0x02, 0x03];
        byte[] expected = EncodeCanonicalByteString(payload);

        using PooledMemory result = CBAdESMessageImprints.BuildPayloadTimestampMessageImprintInput(new CBAdESAttachedPayloadImprintSource(payload), BaseMemoryPool.Shared);

        Assert.IsTrue(expected.AsSpan().SequenceEqual(result.AsReadOnlySpan()), "The attached-payload arm must be exactly bstr(payload).");
    }


    /// <summary>
    /// <c>adoTst</c> (clause 5.2.6), detached-and-unreferenced-payload arm (CB-5.2.6-05): the retrieved
    /// detached COSE Payload bytes, encapsulated in a CBOR byte string.
    /// </summary>
    [TestMethod]
    public void AdoTstDetachedPayloadIsWrappedByteString()
    {
        byte[] payload = [0x0A, 0x0B];
        byte[] expected = EncodeCanonicalByteString(payload);

        using PooledMemory result = CBAdESMessageImprints.BuildPayloadTimestampMessageImprintInput(new CBAdESDetachedPayloadImprintSource(payload), BaseMemoryPool.Shared);

        Assert.IsTrue(expected.AsSpan().SequenceEqual(result.AsReadOnlySpan()), "The detached-payload arm must be exactly bstr(payload).");
    }


    /// <summary>
    /// <c>adoTst</c> (clause 5.2.6), <c>sigD</c>-processed arm (CB-5.2.6-06, recorded reading): the
    /// concatenation of the processed <c>pars</c> segments, with NO CBOR byte-string wrapping at all —
    /// contrast with <see cref="ArcTstGenerationSigDBranchConcatenatesThenEncapsulatesProcessedPars"/>,
    /// whose own <c>sigD</c> arm wraps the identical concatenation in a <c>bstr</c>.
    /// </summary>
    [TestMethod]
    public void AdoTstSigDProcessedPayloadIsRawConcatenationWithNoByteStringWrapping()
    {
        byte[] segment1 = [0x01, 0x02];
        byte[] segment2 = [0x03];
        byte[] expected = [.. segment1, .. segment2];

        using PooledMemory result = CBAdESMessageImprints.BuildPayloadTimestampMessageImprintInput(
            new CBAdESSigDProcessedPayloadImprintSource([segment1, segment2]), BaseMemoryPool.Shared);

        Assert.IsTrue(expected.AsSpan().SequenceEqual(result.AsReadOnlySpan()), "The sigD-processed arm must be the raw concatenation, unwrapped.");
        Assert.AreNotEqual(EncodeCanonicalByteString(expected).Length, result.Length, "The sigD-processed arm must NOT be CBOR byte-string-wrapped, unlike the attached/detached arms.");
    }


    /// <summary>
    /// <c>sigRTst</c> (Annex A.1.2.1.2): the COSE signature value first, then only the <c>sigTst</c>/<c>refs</c>
    /// elements from a mixed <c>uHeaders</c> array (the <c>valData</c>/<c>arcTst</c>-labelled elements are
    /// filtered out), in their original wire order.
    /// </summary>
    [TestMethod]
    public void SigRTstMessageImprintFiltersToSigTstAndRefsElementsInWireOrderAfterSignatureValue()
    {
        byte[] signatureValue = [0x11, 0x22, 0x33];
        (byte[] uHeadersEncodedArray, byte[] sigTstElement, byte[] refsElement) = BuildMixedFilterFixture();
        byte[] expected = BuildExpectedArrayOfByteStrings(signatureValue, sigTstElement, refsElement);

        bool built = CBAdESMessageImprints.TryBuildSignatureAndReferencesTimestampMessageImprintInput(
            signatureValue, uHeadersEncodedArray, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsTrue(built);
        using(result)
        {
            Assert.IsTrue(expected.AsSpan().SequenceEqual(result!.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");
        }
    }


    /// <summary><c>sigRTst</c> (Annex A.1.2.1.2): no <c>uHeaders</c> at all collapses to the zero-length <c>bstr</c> sentinel after the signature value.</summary>
    [TestMethod]
    public void SigRTstMessageImprintUsesZeroLengthSentinelWhenUHeadersAbsent()
    {
        byte[] signatureValue = [0x44, 0x55];
        byte[] expected = BuildExpectedArrayOfByteStrings(signatureValue, Array.Empty<byte>());

        bool built = CBAdESMessageImprints.TryBuildSignatureAndReferencesTimestampMessageImprintInput(
            signatureValue, null, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsTrue(built);
        using(result)
        {
            Assert.IsTrue(expected.AsSpan().SequenceEqual(result!.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");
        }
    }


    /// <summary>
    /// <c>sigRTst</c> (Annex A.1.2.1.2): a present <c>uHeaders</c> array whose elements are ALL neither
    /// <c>sigTst</c> nor <c>refs</c> collapses to the SAME zero-length <c>bstr</c> sentinel as an entirely
    /// absent <c>uHeaders</c> — the two conditions read identically by this builder.
    /// </summary>
    [TestMethod]
    public void SigRTstMessageImprintCollapsesToZeroLengthSentinelWhenUHeadersPresentButNoElementsMatch()
    {
        byte[] signatureValue = [0x01];
        byte[] valDataElement = EncodeFilterFixtureElement(2, "valdata-marker");
        byte[] arcTstElement = EncodeFilterFixtureElement(3, "arctst-marker");
        byte[] uHeadersEncodedArray = BuildExpectedArrayOfByteStrings(valDataElement, arcTstElement);
        byte[] expected = BuildExpectedArrayOfByteStrings(signatureValue, Array.Empty<byte>());

        bool built = CBAdESMessageImprints.TryBuildSignatureAndReferencesTimestampMessageImprintInput(
            signatureValue, uHeadersEncodedArray, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsTrue(built);
        using(result)
        {
            Assert.IsTrue(expected.AsSpan().SequenceEqual(result!.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");
        }
    }


    /// <summary>
    /// <c>rfsTst</c> (Annex A.1.2.2.2) over the SAME mixed <c>uHeaders</c> fixture as
    /// <see cref="SigRTstMessageImprintFiltersToSigTstAndRefsElementsInWireOrderAfterSignatureValue"/>:
    /// identical filtered <c>sigTst</c>/<c>refs</c> elements, but the leading signature-value element is
    /// never added — the two outputs differ EXACTLY by that one leading element.
    /// </summary>
    [TestMethod]
    public void RfsTstMessageImprintMatchesSigRTstMinusTheLeadingSignatureElement()
    {
        byte[] signatureValue = [0x66, 0x77, 0x88];
        (byte[] uHeadersEncodedArray, byte[] sigTstElement, byte[] refsElement) = BuildMixedFilterFixture();

        bool sigRTstOk = CBAdESMessageImprints.TryBuildSignatureAndReferencesTimestampMessageImprintInput(
            signatureValue, uHeadersEncodedArray, BaseMemoryPool.Shared, out PooledMemory? sigRTstResult);
        bool rfsTstOk = CBAdESMessageImprints.TryBuildReferencesOnlyTimestampMessageImprintInput(
            uHeadersEncodedArray, BaseMemoryPool.Shared, out PooledMemory? rfsTstResult);

        Assert.IsTrue(sigRTstOk);
        Assert.IsTrue(rfsTstOk);
        using(sigRTstResult)
        using(rfsTstResult)
        {
            byte[] expectedSigRTst = BuildExpectedArrayOfByteStrings(signatureValue, sigTstElement, refsElement);
            byte[] expectedRfsTst = BuildExpectedArrayOfByteStrings(sigTstElement, refsElement);
            Assert.IsTrue(expectedSigRTst.AsSpan().SequenceEqual(sigRTstResult!.AsReadOnlySpan()), "sigRTst must reproduce the independent oracle's bytes exactly.");
            Assert.IsTrue(expectedRfsTst.AsSpan().SequenceEqual(rfsTstResult!.AsReadOnlySpan()), "rfsTst must reproduce the independent oracle's bytes exactly.");

            ReadOnlySpan<byte> sigRTstBytes = sigRTstResult!.AsReadOnlySpan();
            ReadOnlySpan<byte> rfsTstBytes = rfsTstResult!.AsReadOnlySpan();
            byte[] signatureValueTlv = EncodeCanonicalByteString(signatureValue);

            Assert.AreEqual((byte)(rfsTstBytes[0] + 1), sigRTstBytes[0], "The array-length header must differ by exactly the one leading signature element.");
            Assert.IsTrue(sigRTstBytes.Slice(1, signatureValueTlv.Length).SequenceEqual(signatureValueTlv), "The extra leading element must be exactly bstr(signatureValue).");
            Assert.IsTrue(sigRTstBytes[(1 + signatureValueTlv.Length)..].SequenceEqual(rfsTstBytes[1..]), "sigRTst and rfsTst must differ exactly by the leading signature element.");
        }
    }


    /// <summary><c>rfsTst</c> (Annex A.1.2.2.2): no <c>uHeaders</c> at all collapses to a single zero-length <c>bstr</c> sentinel.</summary>
    [TestMethod]
    public void RfsTstMessageImprintUsesZeroLengthSentinelWhenUHeadersAbsent()
    {
        byte[] expected = BuildExpectedArrayOfByteStrings(Array.Empty<byte>());

        bool built = CBAdESMessageImprints.TryBuildReferencesOnlyTimestampMessageImprintInput(null, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsTrue(built);
        using(result)
        {
            Assert.IsTrue(expected.AsSpan().SequenceEqual(result!.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");
        }
    }


    /// <summary><c>sigRTst</c> fails closed when <c>uHeadersEncodedArray</c> is present but the bytes are not themselves a CBOR array.</summary>
    [TestMethod]
    public void SigRTstMessageImprintFailsClosedWhenUHeadersIsNotAnArray()
    {
        bool built = CBAdESMessageImprints.TryBuildSignatureAndReferencesTimestampMessageImprintInput(
            new byte[] { 0x01 }, BuildUHeadersBytesThatAreNotAnArray(), BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsFalse(built, "Non-array uHeaders bytes must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary><c>sigRTst</c> fails closed when a <c>uHeaders</c> array element is not itself a CBOR byte string.</summary>
    [TestMethod]
    public void SigRTstMessageImprintFailsClosedWhenUHeadersElementIsNotByteString()
    {
        bool built = CBAdESMessageImprints.TryBuildSignatureAndReferencesTimestampMessageImprintInput(
            new byte[] { 0x01 }, BuildUHeadersArrayWithNonByteStringElement(), BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsFalse(built, "A non-bstr uHeaders array element must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary><c>sigRTst</c> fails closed on a zero-element <c>uHeaders</c> array (CB-5.3.1-07).</summary>
    [TestMethod]
    public void SigRTstMessageImprintFailsClosedOnZeroElementUHeadersArray()
    {
        bool built = CBAdESMessageImprints.TryBuildSignatureAndReferencesTimestampMessageImprintInput(
            new byte[] { 0x01 }, BuildZeroElementUHeadersArray(), BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsFalse(built, "A zero-element uHeaders array violates CB-5.3.1-07's non-empty-array requirement and must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary><c>sigRTst</c> fails closed on truncated <c>uHeaders</c> bytes (a well-formed one-element array with its final byte removed).</summary>
    [TestMethod]
    public void SigRTstMessageImprintFailsClosedOnTruncatedUHeadersBytes()
    {
        byte[] wellFormed = BuildExpectedArrayOfByteStrings([0xA0]);
        byte[] truncated = wellFormed[..^1];

        bool built = CBAdESMessageImprints.TryBuildSignatureAndReferencesTimestampMessageImprintInput(
            new byte[] { 0x01 }, truncated, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsFalse(built, "Truncated uHeaders bytes must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary><c>rfsTst</c> fails closed when <c>uHeadersEncodedArray</c> is present but the bytes are not themselves a CBOR array.</summary>
    [TestMethod]
    public void RfsTstMessageImprintFailsClosedWhenUHeadersIsNotAnArray()
    {
        bool built = CBAdESMessageImprints.TryBuildReferencesOnlyTimestampMessageImprintInput(
            BuildUHeadersBytesThatAreNotAnArray(), BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsFalse(built, "Non-array uHeaders bytes must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary><c>rfsTst</c> fails closed when a <c>uHeaders</c> array element is not itself a CBOR byte string.</summary>
    [TestMethod]
    public void RfsTstMessageImprintFailsClosedWhenUHeadersElementIsNotByteString()
    {
        bool built = CBAdESMessageImprints.TryBuildReferencesOnlyTimestampMessageImprintInput(
            BuildUHeadersArrayWithNonByteStringElement(), BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsFalse(built, "A non-bstr uHeaders array element must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary><c>rfsTst</c> fails closed on a zero-element <c>uHeaders</c> array (CB-5.3.1-07).</summary>
    [TestMethod]
    public void RfsTstMessageImprintFailsClosedOnZeroElementUHeadersArray()
    {
        bool built = CBAdESMessageImprints.TryBuildReferencesOnlyTimestampMessageImprintInput(
            BuildZeroElementUHeadersArray(), BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsFalse(built, "A zero-element uHeaders array violates CB-5.3.1-07's non-empty-array requirement and must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary><c>rfsTst</c> fails closed on truncated <c>uHeaders</c> bytes (a well-formed one-element array with its final byte removed).</summary>
    [TestMethod]
    public void RfsTstMessageImprintFailsClosedOnTruncatedUHeadersBytes()
    {
        byte[] wellFormed = BuildExpectedArrayOfByteStrings([0xA0]);
        byte[] truncated = wellFormed[..^1];

        bool built = CBAdESMessageImprints.TryBuildReferencesOnlyTimestampMessageImprintInput(
            truncated, BaseMemoryPool.Shared, out PooledMemory? result);

        Assert.IsFalse(built, "Truncated uHeaders bytes must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// Cross-check: for one shared fixture (the same signature value and encoded <c>uHeaders</c> array),
    /// <c>sigRTst</c>'s message-imprint input must differ from <c>arcTst</c>'s generation-time
    /// message-imprint input — two different algorithms over overlapping inputs must not accidentally
    /// converge to identical bytes.
    /// </summary>
    [TestMethod]
    public void SigRTstMessageImprintDiffersFromArcTstMessageImprintForSharedFixture()
    {
        byte[] signatureValue = [0x99, 0x88];
        byte[] sigTstElement = EncodeFilterFixtureElement(1, "shared-fixture");
        byte[] uHeadersEncodedArray = BuildExpectedArrayOfByteStrings(sigTstElement);

        CBAdESArchiveTimestampImprintContext arcTstContext = BuildArcTstContext(
            CBAdESCoseSign1StructureContext.Instance,
            bodyProtectedHeader: [],
            signerProtectedHeader: null,
            externallySuppliedData: [],
            payloadSource: new CBAdESAttachedPayloadImprintSource(new byte[] { 0xAB }),
            signatureValue,
            uHeadersEncodedArray);

        bool arcTstOk = CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput(arcTstContext, BaseMemoryPool.Shared, out PooledMemory? arcTstResult);
        bool sigRTstOk = CBAdESMessageImprints.TryBuildSignatureAndReferencesTimestampMessageImprintInput(
            signatureValue, uHeadersEncodedArray, BaseMemoryPool.Shared, out PooledMemory? sigRTstResult);

        Assert.IsTrue(arcTstOk);
        Assert.IsTrue(sigRTstOk);
        using(arcTstResult)
        using(sigRTstResult)
        {
            Assert.IsFalse(
                arcTstResult!.AsReadOnlySpan().SequenceEqual(sigRTstResult!.AsReadOnlySpan()),
                "Different message-imprint algorithms over the same underlying signature value and uHeaders must not accidentally converge to identical bytes.");
        }
    }


    /// <summary>
    /// Builds one <c>CBAdESArchiveTimestampImprintContext</c> from plain byte-array fixtures, mapping
    /// <see langword="null"/> to the "does not exist for this structure" (<c>COSE_Sign1</c>) or "not
    /// present" sentinel and a non-null (possibly empty) array to the "present" sentinel, matching
    /// <see cref="CBAdESArchiveTimestampImprintContext.SignerProtectedHeader"/> and
    /// <see cref="CBAdESArchiveTimestampImprintContext.UHeadersEncodedArray"/>'s own documented conventions.
    /// </summary>
    /// <param name="structureContext">The signature-structure context (step 2).</param>
    /// <param name="bodyProtectedHeader">The body layer's protected-header bytes (step 3).</param>
    /// <param name="signerProtectedHeader">
    /// The signer layer's protected-header bytes (step 4): <see langword="null"/> for "step 4 does not
    /// exist" (<c>COSE_Sign1</c>); a non-null (possibly empty) array for "step 4 executes" (<c>COSE_Sign</c>).
    /// </param>
    /// <param name="externallySuppliedData">The externally supplied application data (step 5).</param>
    /// <param name="payloadSource">The payload contribution source (steps 6/7).</param>
    /// <param name="signatureValue">The COSE signature value's raw content bytes (step 9).</param>
    /// <param name="uHeadersEncodedArray">
    /// The encoded <c>uHeaders</c> array bytes (steps 10/11), or <see langword="null"/> when that layer has
    /// no <c>uHeaders</c> header parameter at all.
    /// </param>
    /// <returns>The built context. <see cref="CBAdESArchiveTimestampImprintContext.CountersignatureOtherFields"/> is always <see langword="null"/> (step 8 is out of this stage's scope).</returns>
    private static CBAdESArchiveTimestampImprintContext BuildArcTstContext(
        CBAdESSignatureStructureContext structureContext,
        byte[] bodyProtectedHeader,
        byte[]? signerProtectedHeader,
        byte[] externallySuppliedData,
        CBAdESPayloadImprintSource payloadSource,
        byte[] signatureValue,
        byte[]? uHeadersEncodedArray)
    {
        return new CBAdESArchiveTimestampImprintContext
        {
            StructureContext = structureContext,
            BodyProtectedHeader = bodyProtectedHeader,
            SignerProtectedHeader = signerProtectedHeader is null ? null : (ReadOnlyMemory<byte>?)signerProtectedHeader,
            ExternallySuppliedData = externallySuppliedData,
            PayloadSource = payloadSource,
            CountersignatureOtherFields = null,
            SignatureValue = signatureValue,
            UHeadersEncodedArray = uHeadersEncodedArray is null ? null : (ReadOnlyMemory<byte>?)uHeadersEncodedArray
        };
    }


    /// <summary>
    /// Builds a four-element encoded <c>uHeaders</c> array (<c>valData</c>, <c>sigTst</c>, <c>arcTst</c>,
    /// <c>refs</c>, in that wire order) for the <c>sigRTst</c>/<c>rfsTst</c> filter tests, where only the
    /// <c>sigTst</c> and <c>refs</c> elements are expected to survive the filter.
    /// </summary>
    /// <returns>The encoded array, the expected surviving <c>sigTst</c> element, and the expected surviving <c>refs</c> element.</returns>
    private static (byte[] UHeadersEncodedArray, byte[] SigTstElement, byte[] RefsElement) BuildMixedFilterFixture()
    {
        byte[] valDataElement = EncodeFilterFixtureElement(2, "valdata-marker");
        byte[] sigTstElement = EncodeFilterFixtureElement(1, "sigtst-marker");
        byte[] arcTstElement = EncodeFilterFixtureElement(3, "arctst-marker");
        byte[] refsElement = EncodeFilterFixtureElement(4, "refs-marker");

        byte[] uHeadersEncodedArray = BuildExpectedArrayOfByteStrings(valDataElement, sigTstElement, arcTstElement, refsElement);

        return (uHeadersEncodedArray, sigTstElement, refsElement);
    }


    /// <summary>
    /// Encodes a one-entry <c>UHeaderInstance</c>-shaped map, <c>{ label =&gt; tstr(marker) }</c>, for the
    /// <c>sigRTst</c>/<c>rfsTst</c> filter tests: the filter inspects only the map's single key, so the
    /// value is an arbitrary, opaque marker string.
    /// </summary>
    /// <param name="label">The Table 8 label.</param>
    /// <param name="marker">An opaque marker string identifying this fixture element in assertion failures.</param>
    /// <returns>The encoded one-entry map bytes.</returns>
    private static byte[] EncodeFilterFixtureElement(int label, string marker)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(label);
        writer.WriteTextString(marker);
        writer.WriteEndMap();
        return writer.Encode();
    }


    /// <summary>
    /// Encodes a canonical CBOR array of byte strings, <c>[+bstr]</c> — the shared shape behind both an
    /// encoded <c>uHeaders</c> fixture array and a <c>sigRTst</c>/<c>rfsTst</c> expected message-imprint
    /// input (both are, at the wire level, exactly an array of <c>bstr</c> items).
    /// </summary>
    /// <param name="items">The byte-string items, in order.</param>
    /// <returns>The encoded array bytes.</returns>
    private static byte[] BuildExpectedArrayOfByteStrings(params byte[][] items)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(items.Length);
        foreach(byte[] item in items)
        {
            writer.WriteByteString(item);
        }

        writer.WriteEndArray();
        return writer.Encode();
    }


    /// <summary>Encodes <paramref name="content"/> as a single canonical CBOR byte string, <c>bstr(content)</c>.</summary>
    /// <param name="content">The content bytes.</param>
    /// <returns>The encoded <c>bstr</c> TLV bytes.</returns>
    private static byte[] EncodeCanonicalByteString(byte[] content)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteByteString(content);
        return writer.Encode();
    }


    /// <summary>
    /// Encodes a bare CBOR integer with no enclosing array -- a malformed <c>uHeaders</c> byte source that is
    /// not itself a CBOR array at all, exercising every builder's "not present as an array" fail-closed path.
    /// </summary>
    /// <returns>The encoded bytes.</returns>
    private static byte[] BuildUHeadersBytesThatAreNotAnArray()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteInt32(42);
        return writer.Encode();
    }


    /// <summary>
    /// Encodes a one-element <c>uHeaders</c> array whose sole element is a CBOR integer rather than a byte
    /// string -- CB-5.3.1-04's "every element shall be a CBOR byte string" violated at position 0.
    /// </summary>
    /// <returns>The encoded bytes.</returns>
    private static byte[] BuildUHeadersArrayWithNonByteStringElement()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(1);
        writer.WriteInt32(1); //Not a bstr -- CB-5.3.1-04 requires every element encapsulated in a CBOR byte string.
        writer.WriteEndArray();
        return writer.Encode();
    }


    /// <summary>
    /// Encodes a zero-element <c>uHeaders</c> array -- CB-5.3.1-07's "the uHeaders header parameter shall be
    /// a non-empty array" violated.
    /// </summary>
    /// <returns>The encoded bytes.</returns>
    private static byte[] BuildZeroElementUHeadersArray()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        return writer.Encode();
    }
}
