using Lumoin.Veritas.Cbor;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Cbor;

/// <summary>
/// CBOR serialization for COSE structures.
/// </summary>
/// <remarks>
/// <para>
/// This class provides the CBOR implementations for COSE serialization delegates
/// defined in <see cref="Verifiable.JCose"/>. It bridges the gap between the
/// format-agnostic <see cref="Cose"/> class and the actual CBOR encoding.
/// </para>
/// <para>
/// All methods use deterministic CBOR encoding per RFC 8949 §4.2.
/// </para>
/// </remarks>
public static class CoseSerialization
{
    /// <summary>
    /// Gets a delegate that builds the COSE Sig_structure for signing/verification.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The Sig_structure per RFC 9052 §4.4:
    /// </para>
    /// <code>
    /// Sig_structure = [
    ///     context : "Signature1",
    ///     body_protected : bstr,
    ///     external_aad : bstr,
    ///     payload : bstr
    /// ]
    /// </code>
    /// </remarks>
    public static BuildSigStructureDelegate BuildSigStructure { get; } = static (protectedHeader, payload, externalAad) =>
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(4);
        writer.WriteTextString("Signature1");
        writer.WriteByteString(protectedHeader);
        writer.WriteByteString(externalAad);
        writer.WriteByteString(payload);
        writer.WriteEndArray();

        return buffer.WrittenSpan.ToArray();
    };


    /// <summary>
    /// Gets a delegate that serializes a COSE_Sign1 message to CBOR bytes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The output includes CBOR tag(18) for COSE_Sign1.
    /// </para>
    /// <para>
    /// The protected bucket arrives already serialized, so its labels are read with the reading side's own label
    /// read before anything is written, and a message the reading side would refuse is not written.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-9">RFC 9052 Section 9</see>: "Applications MUST NOT
    /// generate messages with the same label used twice as a key in a single map."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052 Section 1.5</see>: "Applications can
    /// either fail processing or process messages by ignoring incorrect labels; however, they MUST NOT create
    /// messages with incorrect labels."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "Applications SHOULD
    /// verify that the same label does not occur in both the protected and unprotected header parameters."
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// The message's protected bucket carries one label twice, or a label that is neither an integer nor a text
    /// string, or a label its unprotected bucket also carries.
    /// </exception>
    public static SerializeCoseSign1Delegate SerializeCoseSign1 { get; } = static (message, pool) =>
    {
        RefuseToWriteMalformedBuckets(message.ProtectedHeader.AsReadOnlyMemory(), message.UnprotectedHeader, nameof(message));

        using var buffer = new SlabBufferWriter(pool);
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteTag(new CborTag(CoseTags.Sign1));
        writer.WriteStartArray(4);

        //Protected header (already serialized).
        writer.WriteByteString(message.ProtectedHeader.AsReadOnlySpan());

        //Unprotected header.
        if(message.UnprotectedHeader is not null && message.UnprotectedHeader.Count > 0)
        {
            writer.WriteStartMap(message.UnprotectedHeader.Count);
            foreach(var kvp in message.UnprotectedHeader)
            {
                writer.WriteInt32(kvp.Key);
                CborValueConverter.WriteValue(writer, kvp.Value);
            }
            writer.WriteEndMap();
        }
        else
        {
            writer.WriteStartMap(0);
            writer.WriteEndMap();
        }

        //Payload.
        writer.WriteByteString(message.Payload.Span);

        //Signature.
        writer.WriteByteString(message.Signature.AsReadOnlySpan());

        writer.WriteEndArray();

        //Route the encoded bytes through the pool so the wire form carries
        //CBOM provenance and OTel observes the allocation.
        using IMemoryOwner<byte> encoded = buffer.Detach();
        IMemoryOwner<byte> owner = pool.Rent(encoded.Memory.Length);
        encoded.Memory.Span.CopyTo(owner.Memory.Span);

        return new EncodedCoseSign1(owner, CryptoTags.CoseEncodedSign1);
    };


    /// <summary>
    /// Gets a delegate that parses COSE_Sign1 bytes into a message.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both buckets are judged as RFC 9052 defines their labels. A label is any CBOR integer, read whole, or a text
    /// string, and two labels are the same when their decoded values are equal, so one label written in two widths
    /// is one label (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052 Section 1.5</see>:
    /// "label = int / tstr"). The protected bucket's labels are read for that judgment alone, whatever the
    /// unprotected bucket holds, each judged as it is read, and its bytes are handed on raw. A protected bucket whose
    /// labels cannot be read past some point (one that is no well-formed map of labels) is handed on raw after every
    /// label read before that point has been judged: this parser does not refuse such a bucket, and a reader of the
    /// bucket's content (<see cref="ParseProtectedHeader"/> among them) refuses it in its own failure shape, while a
    /// verification that never reads the content verifies the signature over the bytes as they are. A protected
    /// bucket carrying bytes after its map, and a message carrying bytes after its array, are refused. A well-formed
    /// label the header dictionary does not carry, a text string or an integer outside the 32-bit signed range, is
    /// judged and passed over with its value, and nothing inside that value is read.
    /// </para>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "Labels in each of the
    /// maps MUST be unique. When processing messages, if a label appears multiple times, the message MUST be rejected
    /// as malformed. Applications SHOULD verify that the same label does not occur in both the protected and
    /// unprotected header parameters." A message holding one label in both buckets is refused, so the precedence
    /// sentence that follows the clause has nothing left to decide.
    /// </para>
    /// </remarks>
    /// <exception cref="CborContentException">
    /// A bucket carries one label twice, the unprotected bucket carries a map key that is neither an integer nor a
    /// text string, or the two buckets share a label; or the bytes are otherwise not a well-formed COSE_Sign1.
    /// </exception>
    /// <exception cref="InvalidOperationException">The bytes are not tagged as a COSE_Sign1 or do not hold its four elements.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of protectedHeaderCarrier and signatureCarrier transfers to the returned CoseSign1Message; the caller disposes the message.")]
    public static ParseCoseSign1Delegate ParseCoseSign1 { get; } = static (coseSign1Bytes, pool) =>
    {
        var reader = new CborReader(coseSign1Bytes, CborOptions.Lax);

        //Read and validate tag.
        CborTag tag = reader.ReadTag();
        if((int)tag.Value != CoseTags.Sign1)
        {
            throw new InvalidOperationException($"Expected COSE_Sign1 tag (18), got {(int)tag.Value}.");
        }

        //Read array.
        int? arrayLength = reader.ReadStartArray();
        if(arrayLength != 4)
        {
            throw new InvalidOperationException($"COSE_Sign1 must have 4 elements, got {arrayLength}.");
        }

        //Protected header — copy CborReader's heap byte[] into a pool-rented buffer wrapped in the
        //semantic carrier via EncodedCoseProtectedHeader.FromBytes, which routes a genuinely
        //zero-length header (RFC 9052 §3's empty_or_serialized_map, bstr .size 0 arm) through the
        //shared EmptyMemoryOwner singleton rather than a bare pool.Rent(0), which throws.
        byte[] protectedHeaderBytes = reader.ReadByteString();
        EncodedCoseProtectedHeader? protectedHeaderCarrier = EncodedCoseProtectedHeader.FromBytes(protectedHeaderBytes, pool);
        Signature? signatureCarrier = null;

        //Every carrier rented here moves into the returned message; on every failing exit the finally block
        //returns whichever is still held to the pool.
        try
        {
            //Unprotected header: a repeated label, or a label also in the protected bucket, is a malformed
            //message (RFC 9052 Section 3).
            Dictionary<int, object>? unprotectedHeader = null;
            HashSet<(Int128 Number, string? Text)> unprotectedLabels = [];
            int? mapLength = reader.ReadStartMap();
            if(mapLength > 0)
            {
                unprotectedHeader = [];
                for(int i = 0; i < mapLength; i++)
                {
                    ReadHeaderEntry(reader, unprotectedLabels, unprotectedHeader);
                }
            }

            reader.ReadEndMap();
            RefuseRepeatedOrSharedLabel(protectedHeaderBytes, unprotectedLabels, isUnreadableBucketRefused: false);

            //Payload (borrowed; the message's lifetime brackets the caller's
            //use of this returned reference).
            byte[] payload = reader.ReadByteString();

            //Signature: routed through the pool into a Signature carrier.
            byte[] signature = reader.ReadByteString();
            IMemoryOwner<byte> signatureOwner = pool.Rent(signature.Length);
            signature.CopyTo(signatureOwner.Memory.Span);
            signatureCarrier = new(signatureOwner, CryptoTags.AlgorithmAgnosticSignature);

            reader.ReadEndArray();
            if(reader.BytesRemaining != 0)
            {
                throw new CborContentException("Trailing bytes after the COSE_Sign1 structure.");
            }

            CoseSign1Message message = new(protectedHeaderCarrier, unprotectedHeader, payload, signatureCarrier);
            protectedHeaderCarrier = null;
            signatureCarrier = null;

            return message;
        }
        finally
        {
            protectedHeaderCarrier?.Dispose();
            signatureCarrier?.Dispose();
        }
    };


    /// <summary>
    /// Gets a delegate that parses a COSE_Sign1 whose payload slot may be the nil sentinel — the
    /// detached form ISO/IEC 18013-5 §9.1.3.4 uses for mdoc device signatures. The standard
    /// <see cref="ParseCoseSign1"/> rejects nil payloads (correct for SD-CWT, wrong for mdoc device
    /// auth), so this shares the <see cref="ParseCoseSign1Delegate"/> shape and the mdoc device
    /// verifier wires it as the parse seam. Routes protected-header + signature bytes through the
    /// pool; the returned message owns its carriers and the caller disposes it.
    /// </summary>
    /// <remarks>
    /// The two buckets are judged as <see cref="ParseCoseSign1"/> judges them: a label is any CBOR integer, read
    /// whole, or a text string; the protected bucket's labels are read for the judgment alone, each as it is read,
    /// whatever the unprotected bucket holds; a well-formed label the header dictionary does not carry is passed over
    /// with its value, and nothing inside that value is read. Unlike <see cref="ParseCoseSign1"/>, this parser refuses
    /// a protected bucket whose labels cannot be read, since the mdoc device verification it serves verifies the
    /// signature over the protected bytes without reading them again. A protected bucket carrying bytes after its map,
    /// and a message carrying bytes after its array, are refused.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "Labels in each of the
    /// maps MUST be unique. When processing messages, if a label appears multiple times, the message MUST be rejected
    /// as malformed. Applications SHOULD verify that the same label does not occur in both the protected and
    /// unprotected header parameters."
    /// </remarks>
    /// <exception cref="CborContentException">
    /// A bucket carries one label twice, the unprotected bucket carries a map key that is neither an integer nor a
    /// text string, or the two buckets share a label; or the bytes are otherwise not a well-formed COSE_Sign1.
    /// </exception>
    /// <exception cref="InvalidOperationException">The bytes are not tagged as a COSE_Sign1 or do not hold its four elements.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of protectedHeaderCarrier and signatureCarrier transfers to the returned CoseSign1Message; the caller disposes the message.")]
    public static ParseCoseSign1Delegate ParseCoseSign1AllowingNilPayload { get; } = static (coseSign1Bytes, pool) =>
    {
        var reader = new CborReader(coseSign1Bytes, CborOptions.Lax);

        CborTag tag = reader.ReadTag();
        if((int)tag.Value != CoseTags.Sign1)
        {
            throw new InvalidOperationException($"Expected COSE_Sign1 tag ({CoseTags.Sign1}), got {(int)tag.Value}.");
        }

        int? arrayLength = reader.ReadStartArray();
        if(arrayLength != 4)
        {
            throw new InvalidOperationException($"COSE_Sign1 must have 4 elements, got {arrayLength}.");
        }

        //EncodedCoseProtectedHeader.FromBytes routes a genuinely zero-length header (RFC 9052 §3's
        //empty_or_serialized_map, bstr .size 0 arm) through the shared EmptyMemoryOwner singleton
        //rather than a bare pool.Rent(0), which throws.
        byte[] protectedHeader = reader.ReadByteString();
        EncodedCoseProtectedHeader? protectedHeaderCarrier = EncodedCoseProtectedHeader.FromBytes(protectedHeader, pool);
        Signature? signatureCarrier = null;

        //Every carrier rented here moves into the returned message; on every failing exit the finally block
        //returns whichever is still held to the pool.
        try
        {
            //Unprotected header: read raw encoded value bytes; the verification math never touches it. A
            //repeated label, or a label also in the protected bucket, is a malformed message (RFC 9052 Section 3).
            Dictionary<int, object>? unprotectedHeader = null;
            HashSet<(Int128 Number, string? Text)> unprotectedLabels = [];
            if(reader.PeekState() == CborReaderState.StartMap)
            {
                int? mapEntries = reader.ReadStartMap();
                if(mapEntries is null || mapEntries.Value > 0)
                {
                    unprotectedHeader = [];
                    while(reader.PeekState() != CborReaderState.EndMap)
                    {
                        (Int128 Number, string? Text) label = ReadLabel(reader);
                        RefuseRepeatedLabel(unprotectedLabels, label);
                        if(IsDictionaryLabel(label, out int dictionaryLabel))
                        {
                            unprotectedHeader[dictionaryLabel] = reader.ReadEncodedValue().ToArray();
                        }
                        else
                        {
                            reader.SkipValue();
                        }
                    }
                }

                reader.ReadEndMap();
            }

            RefuseRepeatedOrSharedLabel(protectedHeader, unprotectedLabels, isUnreadableBucketRefused: true);

            //Payload: nil for the detached form, byte string for the attached form.
            ReadOnlyMemory<byte> payload = ReadOnlyMemory<byte>.Empty;
            if(reader.PeekState() == CborReaderState.Null)
            {
                reader.ReadNull();
            }
            else
            {
                payload = reader.ReadByteString();
            }

            byte[] signature = reader.ReadByteString();
            IMemoryOwner<byte> signatureOwner = pool.Rent(signature.Length);
            signature.CopyTo(signatureOwner.Memory.Span);
            signatureCarrier = new(signatureOwner, CryptoTags.AlgorithmAgnosticSignature);

            reader.ReadEndArray();
            if(reader.BytesRemaining != 0)
            {
                throw new CborContentException("Trailing bytes after the COSE_Sign1 structure.");
            }

            CoseSign1Message message = new(protectedHeaderCarrier, unprotectedHeader, payload, signatureCarrier);
            protectedHeaderCarrier = null;
            signatureCarrier = null;

            return message;
        }
        finally
        {
            protectedHeaderCarrier?.Dispose();
            signatureCarrier?.Dispose();
        }
    };


    /// <summary>
    /// Gets a delegate that builds the COSE Sig_structure for the "Signature" context — a
    /// per-signer <c>COSE_Signature</c> entry within a <c>COSE_Sign</c> message.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The Sig_structure per RFC 9052 §4.4:
    /// </para>
    /// <code>
    /// Sig_structure = [
    ///     context : "Signature",
    ///     body_protected : bstr,
    ///     sign_protected : bstr,
    ///     external_aad : bstr,
    ///     payload : bstr
    /// ]
    /// </code>
    /// </remarks>
    public static BuildCoseSignatureSigStructureDelegate BuildCoseSignatureSigStructure { get; } = static (bodyProtectedHeader, signProtectedHeader, payload, externalAad) =>
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(5);
        writer.WriteTextString("Signature");
        writer.WriteByteString(bodyProtectedHeader);
        writer.WriteByteString(signProtectedHeader);
        writer.WriteByteString(externalAad);
        writer.WriteByteString(payload);
        writer.WriteEndArray();

        return buffer.WrittenSpan.ToArray();
    };


    /// <summary>
    /// Gets a delegate that serializes a COSE_Sign message to CBOR bytes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The output includes CBOR tag(98) for COSE_Sign, mirroring
    /// <see cref="SerializeCoseSign1"/>'s tagged-only emission convention (RFC 9052 §4.1
    /// admits an untagged form too; this substrate always emits tagged — read tolerance for
    /// the untagged form lives on the parse side, <see cref="ParseCoseSign"/>).
    /// </para>
    /// <para>
    /// <strong>Payload: detached-aware via <see cref="CoseSignMessage.IsDetachedPayload"/>.</strong>
    /// RFC 9052 §4.1's <c>payload : bstr / nil</c> is written as the CBOR <c>nil</c> sentinel when the
    /// <c>message</c> reports a detached payload, and as a <c>bstr</c> (verbatim, including a
    /// genuinely zero-length attached payload) otherwise — the same producer-side distinction
    /// <c>CBAdESSignatureSerialization.SerializeCBAdESSign1</c> makes explicit via its own <c>payloadIsDetached</c>
    /// parameter for <c>COSE_Sign1</c>; this generic, non-CBAdES-specific <c>COSE_Sign</c> substrate has no
    /// sibling wrapper carrying that parameter, so it infers the same fact from the message itself.
    /// </para>
    /// <para>
    /// Every protected bucket, the body's and each signer's, arrives already serialized, so its labels are read with
    /// the reading side's own label read before anything is written, and a layer the reading side would refuse is not
    /// written. <see href="https://www.rfc-editor.org/rfc/rfc9052#section-9">RFC 9052 Section 9</see>: "Applications
    /// MUST NOT generate messages with the same label used twice as a key in a single map."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052 Section 1.5</see>: "Applications can
    /// either fail processing or process messages by ignoring incorrect labels; however, they MUST NOT create
    /// messages with incorrect labels."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "Applications SHOULD
    /// verify that the same label does not occur in both the protected and unprotected header parameters."
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// A protected bucket of the body or of a signer carries one label twice, or a label that is neither an integer
    /// nor a text string, or a label the same layer's unprotected bucket also carries.
    /// </exception>
    public static SerializeCoseSignDelegate SerializeCoseSign { get; } = static (message, pool) =>
    {
        RefuseToWriteMalformedBuckets(message.ProtectedHeader.AsReadOnlyMemory(), message.UnprotectedHeader, nameof(message));
        foreach(CoseSignatureComponent signerLayer in message.Signatures)
        {
            RefuseToWriteMalformedBuckets(signerLayer.ProtectedHeader.AsReadOnlyMemory(), signerLayer.UnprotectedHeader, nameof(message));
        }

        using var buffer = new SlabBufferWriter(pool);
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteTag(new CborTag(CoseTags.Sign));
        writer.WriteStartArray(4);

        //Body-layer protected header (already serialized).
        writer.WriteByteString(message.ProtectedHeader.AsReadOnlySpan());

        //Body-layer unprotected header.
        WriteUnprotectedHeaderMap(writer, message.UnprotectedHeader);

        //Payload: bstr / nil (RFC 9052 §4.1).
        if(message.IsDetachedPayload)
        {
            writer.WriteNull();
        }
        else
        {
            writer.WriteByteString(message.Payload.Span);
        }

        //Signatures: [+ COSE_Signature].
        writer.WriteStartArray(message.Signatures.Count);
        foreach(CoseSignatureComponent signer in message.Signatures)
        {
            writer.WriteStartArray(3);
            writer.WriteByteString(signer.ProtectedHeader.AsReadOnlySpan());
            WriteUnprotectedHeaderMap(writer, signer.UnprotectedHeader);
            writer.WriteByteString(signer.Signature.AsReadOnlySpan());
            writer.WriteEndArray();
        }
        writer.WriteEndArray();

        writer.WriteEndArray();

        //Route the encoded bytes through the pool so the wire form carries CBOM provenance
        //and OTel observes the allocation.
        using IMemoryOwner<byte> encoded = buffer.Detach();
        IMemoryOwner<byte> owner = pool.Rent(encoded.Memory.Length);
        encoded.Memory.Span.CopyTo(owner.Memory.Span);

        return new EncodedCoseSign(owner, CryptoTags.CoseEncodedSign);


        //Writes a COSE unprotected-header map to writer (empty when header is null or empty) — the
        //shape every layer of COSE_Sign (body and every signer) shares, per RFC 9052 §3's Headers
        //CDDL group.
        static void WriteUnprotectedHeaderMap(CborWriter writer, IReadOnlyDictionary<int, object>? header)
        {
            if(header is not null && header.Count > 0)
            {
                writer.WriteStartMap(header.Count);
                foreach(var kvp in header)
                {
                    writer.WriteInt32(kvp.Key);
                    CborValueConverter.WriteValue(writer, kvp.Value);
                }
                writer.WriteEndMap();
            }
            else
            {
                writer.WriteStartMap(0);
                writer.WriteEndMap();
            }
        }
    };


    /// <summary>
    /// Gets a delegate that performs the fail-closed parse of COSE_Sign bytes into a
    /// message. See <see cref="ParseCoseSignDelegate"/>'s remarks for the tagged/untagged
    /// acceptance and fail-closed conventions.
    /// </summary>
    /// <remarks>
    /// Every layer, the body and each signer, is judged as <see cref="ParseCoseSign1"/> judges its one layer: a label
    /// is any CBOR integer, read whole, or a text string; each protected bucket's labels are read for the judgment
    /// alone, whatever its layer's unprotected bucket holds, and a protected bucket whose labels cannot be read is
    /// handed on raw; a well-formed label the header dictionary does not carry is passed over. A layer that carries
    /// one label twice in a bucket, an unprotected map key that is neither an integer nor a
    /// text string, or one label in both of its buckets answers <see cref="CoseSignParseResult.Failure"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "Labels in each of the
    /// maps MUST be unique. When processing messages, if a label appears multiple times, the message MUST be rejected
    /// as malformed. Applications SHOULD verify that the same label does not occur in both the protected and
    /// unprotected header parameters."
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of bodyProtectedHeaderCarrier and every component transfers to the returned CoseSignMessage on success; the catch block disposes them on any failure path.")]
    public static ParseCoseSignDelegate ParseCoseSign { get; } = static (coseSignBytes, pool) =>
    {
        ArgumentNullException.ThrowIfNull(pool);

        EncodedCoseProtectedHeader? bodyProtectedHeaderCarrier = null;
        EncodedCoseProtectedHeader? signerProtectedHeaderCarrier = null;
        Signature? signatureCarrier = null;
        List<CoseSignatureComponent>? components = [];

        try
        {
            var reader = new CborReader(coseSignBytes, CborOptions.Lax);

            //RFC 9052 §4.1: "The signature structure can be encoded as either tagged or
            //untagged, depending on the context" -- a tag, when present, must be the
            //COSE_Sign_Tagged value 98; its absence is not itself a failure (mirrors the
            //CB-AdES ParseCBAdESSign1 CB-4.3 precedent established for COSE_Sign1).
            if(reader.PeekState() == CborReaderState.Tag)
            {
                CborTag tag = reader.ReadTag();
                if((int)tag.Value != CoseTags.Sign)
                {
                    throw new CborContentException($"Expected COSE_Sign tag ({CoseTags.Sign}), got {(int)tag.Value}.");
                }
            }

            reader.ReadStartArrayExpectLength(4);

            //RFC 9338 §4 / RFC 9052 §9: every bstr in a deterministically encoded COSE structure is
            //definite-length; CborReader.ReadByteStringMemory (distinct from ReadByteString, which
            //this Lax-mode reader would otherwise let silently assemble an indefinite-length chunked
            //bstr's chunks rather than reject it) hand-enforces that, the same strictness this method
            //already hand-enforces for arrays and maps.
            ReadOnlyMemory<byte> bodyProtectedHeaderBytes = reader.ReadByteStringMemory();
            bodyProtectedHeaderCarrier = EncodedCoseProtectedHeader.FromBytes(bodyProtectedHeaderBytes.Span, pool);

            Dictionary<int, object>? bodyUnprotectedHeader = ReadUnprotectedHeaderMap(reader, bodyProtectedHeaderBytes);

            ReadOnlyMemory<byte> payload;
            if(reader.PeekState() == CborReaderState.Null)
            {
                reader.ReadNull();
                payload = ReadOnlyMemory<byte>.Empty;
            }
            else
            {
                payload = reader.ReadByteStringMemory();
            }

            int? signatureCount = reader.ReadStartArray();
            if(signatureCount is null)
            {
                throw new CborContentException("The signatures array shall be definite-length (RFC 9052 §9).");
            }

            if(signatureCount.Value == 0)
            {
                throw new CborContentException(
                    "COSE_Sign requires at least one COSE_Signature entry (RFC 9052 §4.1, [+ COSE_Signature]).");
            }

            for(int i = 0; i < signatureCount.Value; i++)
            {
                reader.ReadStartArrayExpectLength(3);

                ReadOnlyMemory<byte> signerProtectedHeaderBytes = reader.ReadByteStringMemory();
                signerProtectedHeaderCarrier = EncodedCoseProtectedHeader.FromBytes(signerProtectedHeaderBytes.Span, pool);

                Dictionary<int, object>? signerUnprotectedHeader = ReadUnprotectedHeaderMap(reader, signerProtectedHeaderBytes);

                ReadOnlyMemory<byte> signatureBytes = reader.ReadByteStringMemory();
                IMemoryOwner<byte> signatureOwner = pool.Rent(signatureBytes.Length);
                signatureBytes.CopyTo(signatureOwner.Memory);
                signatureCarrier = new Signature(signatureOwner, CryptoTags.AlgorithmAgnosticSignature);

                reader.ReadEndArray();

                //Ownership of both per-signer carriers transfers into the component; null the
                //standalone locals so the catch block's cleanup (defense-in-depth from here on,
                //matching the ParseCBAdESSign1 convention) never double-disposes them through
                //two reference paths.
                components.Add(new CoseSignatureComponent(signerProtectedHeaderCarrier, signerUnprotectedHeader, signatureCarrier));
                signerProtectedHeaderCarrier = null;
                signatureCarrier = null;
            }

            reader.ReadEndArray();
            reader.ReadEndArray();

            if(reader.BytesRemaining != 0)
            {
                throw new CborContentException("Trailing bytes after the COSE_Sign structure.");
            }

            CoseSignMessage message = new(bodyProtectedHeaderCarrier, bodyUnprotectedHeader, payload, components);
            bodyProtectedHeaderCarrier = null;
            components = null;

            return CoseSignParseResult.Success(message);
        }
        catch(Exception ex) when(IsMalformedInputException(ex))
        {
            bodyProtectedHeaderCarrier?.Dispose();
            signerProtectedHeaderCarrier?.Dispose();
            signatureCarrier?.Dispose();
            if(components is not null)
            {
                foreach(CoseSignatureComponent component in components)
                {
                    component.Dispose();
                }
            }

            return CoseSignParseResult.Failure();
        }


        //Reads a COSE unprotected-header map from reader, returning null when empty — the shape every
        //layer of COSE_Sign (body and every signer) shares, per RFC 9052 §3's Headers CDDL group.
        //Fails closed on an indefinite-length map (RFC 9052 Section 9 requires definite lengths), on a label
        //repeated in either bucket, on a label also in the same layer's protected bucket, protectedHeaderBytes,
        //and on a protected bucket whose labels cannot be read (RFC 9052 Section 3).
        static Dictionary<int, object>? ReadUnprotectedHeaderMap(CborReader reader, ReadOnlyMemory<byte> protectedHeaderBytes)
        {
            int? mapLength = reader.ReadStartMap();
            if(mapLength is null)
            {
                throw new CborContentException("An unprotected headers map shall be definite-length (RFC 9052 §9).");
            }

            Dictionary<int, object>? header = null;
            HashSet<(Int128 Number, string? Text)> seenLabels = [];
            if(mapLength.Value > 0)
            {
                header = [];
                for(int i = 0; i < mapLength.Value; i++)
                {
                    ReadHeaderEntry(reader, seenLabels, header);
                }
            }

            reader.ReadEndMap();
            RefuseRepeatedOrSharedLabel(protectedHeaderBytes, seenLabels, isUnreadableBucketRefused: true);

            return header;
        }
    };


    /// <summary>
    /// Determines whether <paramref name="exception"/> belongs to the family of exceptions this leaf's CBOR readers
    /// raise for malformed input: the CBOR reader's own <see cref="CborException"/> family, the
    /// <see cref="InvalidOperationException"/> of a read in the wrong reader state, the <see cref="ArgumentException"/>
    /// family of a decoded value outside a constructor's domain, the <see cref="IndexOutOfRangeException"/> of a
    /// truncated structure, the <see cref="OverflowException"/> of an integer outside the width it is read into, and
    /// the <see cref="FormatException"/> a reader answers a refused shape with. The catches and normalizers around
    /// the COSE readers (the COSE_Sign1, COSE_Sign and countersignature parsers, the COSE verification and the
    /// <c>x5chain</c> extractor), the SD-CWT readers (the claim readers, the status claim among them, the Key Binding
    /// Token readers and the embedded SD-CWT parse) and the mdoc DeviceResponse and IACA trust readers name the
    /// family through this one predicate, so no member of it escapes one of those sites that another refuses;
    /// <see cref="ParseCoseSign"/>'s fail-closed catch converts it to <see cref="CoseSignParseResult.Failure"/>,
    /// mirroring <c>CBAdESSignatureSerialization</c>'s own <c>IsFailClosedParseException</c> predicate.
    /// </summary>
    /// <remarks>
    /// <see cref="OperationCanceledException"/> derives from none of these types, so a caller's cancellation is never
    /// read as malformed input. <see cref="ObjectDisposedException"/>, an <see cref="InvalidOperationException"/>, is
    /// left out: a carrier or a pool used after its disposal is a lifetime fault of the caller's, never content of
    /// the data item read.
    /// </remarks>
    /// <param name="exception">The exception to classify.</param>
    /// <returns><see langword="true"/> when the exception represents malformed input.</returns>
    internal static bool IsMalformedInputException(Exception exception) =>
        exception is (CborException or InvalidOperationException or ArgumentException
            or IndexOutOfRangeException or OverflowException or FormatException) and not ObjectDisposedException;


    /// <summary>
    /// Gets a delegate that builds the RFC 9338 §3.3 Countersign_structure ToBeSigned bytes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The Countersign_structure per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9338#section-3.3">RFC 9338 §3.3</see>:
    /// </para>
    /// <code>
    /// Countersign_structure = [
    ///   context : "CounterSignature" / "CounterSignature0" /
    ///             "CounterSignatureV2" / "CounterSignature0V2",
    ///   body_protected : empty_or_serialized_map,
    ///   ? sign_protected : empty_or_serialized_map,
    ///   external_aad : bstr,
    ///   payload : bstr,
    ///   ? other_fields : [+ bstr ]
    /// ]
    /// </code>
    /// <para>
    /// The context text is resolved from BOTH axes RFC 9338 §3.3 names, never just the
    /// countersignature form: <c>sign_protected</c>'s presence follows
    /// <see cref="CountersignStructureInput.IsAbbreviated"/> (full vs abbreviated
    /// countersignature); the "V2" suffix follows
    /// <see cref="CountersignStructureInput.OtherFieldsSignature"/>'s presence (which derives
    /// from the countersigned TARGET's own shape, not the
    /// countersignature's) — the two are independent, so a full countersignature over a
    /// COSE_Signature target (no <c>other_fields</c>) uses the PLAIN "CounterSignature"
    /// context text even though the structure itself is the RFC 9338 (version 2) one.
    /// </para>
    /// <para>
    /// Fails closed (<see cref="ArgumentException"/>) when <see cref="CountersignStructureInput.SignProtected"/>'s
    /// presence disagrees with <see cref="CountersignStructureInput.IsAbbreviated"/> — RFC
    /// 9338 §3.3 ties the two together ("This field is omitted for the Countersignature0V2
    /// attribute"), so an inconsistent input is a caller error, not wire data to tolerate.
    /// </para>
    /// </remarks>
    public static BuildCountersignStructureDelegate BuildCountersignStructure { get; } = static input =>
    {
        if(input.IsAbbreviated && input.SignProtected.HasValue)
        {
            throw new ArgumentException(
                "A Countersignature0V2 (abbreviated) has no protected attributes of its own; sign_protected must be omitted (RFC 9338 §3.3).",
                nameof(input));
        }

        if(!input.IsAbbreviated && !input.SignProtected.HasValue)
        {
            throw new ArgumentException(
                "A CounterSignatureV2 (full) carries sign_protected, even if zero-length, per RFC 9338 §3.3.",
                nameof(input));
        }

        string context = (input.IsAbbreviated, HasOtherFields: input.OtherFieldsSignature.HasValue) switch
        {
            (false, false) => "CounterSignature",
            (true, false) => "CounterSignature0",
            (false, true) => "CounterSignatureV2",
            (true, true) => "CounterSignature0V2"
        };

        int elementCount = 4 + (input.SignProtected.HasValue ? 1 : 0) + (input.OtherFieldsSignature.HasValue ? 1 : 0);

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(elementCount);
        writer.WriteTextString(context);
        writer.WriteByteString(input.BodyProtected.Span);
        if(input.SignProtected.HasValue)
        {
            writer.WriteByteString(input.SignProtected.Value.Span);
        }
        writer.WriteByteString(input.ExternalAad.Span);
        writer.WriteByteString(input.Payload.Span);
        if(input.OtherFieldsSignature.HasValue)
        {
            //other_fields is embedded as the CBOR array value it already is, never bstr-wrapped.
            writer.WriteStartArray(1);
            writer.WriteByteString(input.OtherFieldsSignature.Value.Span);
            writer.WriteEndArray();
        }
        writer.WriteEndArray();

        return buffer.WrittenSpan.ToArray();
    };


    /// <summary>
    /// Gets a delegate that reads a full version 2 countersignature (COSE header label 11)
    /// from CBOR bytes — the single-value arm of RFC 9338 §2 Table 1's <c>COSE_Countersignature
    /// / [+ COSE_Countersignature]</c> value type union. The array arm is decoded separately by
    /// <see cref="ParseCounterSignatureHeaderValue"/>'s own shape-aware dispatch, which calls
    /// this delegate once per array element rather than widening its own return type.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 9338 §3.1: "The full countersignature structure can be encoded as either tagged or
    /// untagged, depending on the context. A tagged COSE_Countersignature structure is
    /// identified by the CBOR tag 19." TS 119 152-1 is silent on tag 19, so this substrate is
    /// read-tolerant of it (accepted here when
    /// present) but never emits it — see <see cref="WriteCounterSignatureV2"/>.
    /// </para>
    /// <para>
    /// Reads under <see cref="CborConformanceMode.RfcCanonical"/>, not <see cref="CborConformanceMode.Lax"/>:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9338#section-4">RFC 9338 §4</see>'s determinism MUST
    /// (narrowing RFC 8949 §4.2 via RFC 9052 §9) means an indefinite-length map or byte string here is
    /// malformed input, not a lenient-but-legal alternate encoding — the same definite-length strictness
    /// <see cref="ParseCoseSign"/> enforces under its own (necessarily Lax, for reasons that method's own
    /// remarks give) reader via <see cref="CborReader.ReadByteStringMemory"/> in place of the
    /// general <see cref="CborReader.ReadByteString"/>.
    /// </para>
    /// <para>
    /// Throws on malformed input; the fail-closed boundary is
    /// <see cref="ParseCounterSignatureHeaderValue"/>.
    /// </para>
    /// </remarks>
    public static ReadCounterSignatureV2Delegate ReadCounterSignatureV2 { get; } = static (valueBytes, pool) =>
    {
        ArgumentNullException.ThrowIfNull(pool);

        var reader = new CborReader(valueBytes, CborOptions.RfcCanonical);

        //Tag 19 (COSE_Countersignature_Tagged) is read-tolerated, never required -- it wraps a single
        //COSE_Countersignature only (RFC 9338 §3.1); the [+ COSE_Countersignature] array arm this delegate
        //never itself decodes (see the class remarks) is never tagged this way either.
        if(reader.PeekState() == CborReaderState.Tag)
        {
            CborTag tag = reader.ReadTag();
            if((int)tag.Value != CoseTags.CounterSignature)
            {
                throw new CborContentException($"Expected COSE_Countersignature tag ({CoseTags.CounterSignature}), got {(int)tag.Value}.");
            }
        }

        CounterSignatureV2 result = ReadCounterSignatureV2Element(reader, pool);

        if(reader.BytesRemaining != 0)
        {
            throw new CborContentException("Trailing bytes after the COSE_Countersignature structure.");
        }

        return result;
    };


    /// <summary>
    /// Reads one untagged <c>COSE_Countersignature</c> element (RFC 9338 §3.1: <c>COSE_Countersignature =
    /// COSE_Signature</c>) from <paramref name="reader"/>'s current position — the shared core both
    /// <see cref="ReadCounterSignatureV2"/>'s single-value arm and <see cref="ParseCounterSignatureHeaderValue"/>'s
    /// <c>[+ COSE_Countersignature]</c> array-arm decode loop read each element with.
    /// </summary>
    /// <param name="reader">The CBOR reader positioned at the element's own 3-array.</param>
    /// <param name="pool">Memory pool the decoded carriers rent their buffers from.</param>
    /// <returns>The decoded full countersignature.</returns>
    /// <remarks>
    /// Ownership moves in two hand-off stages, each tracked through its own nullable local: the
    /// protected-header and signature carriers move into a <see cref="CoseSignatureComponent"/> local,
    /// which is then cleared; that component then moves into the returned <see cref="CounterSignatureV2"/>,
    /// which is then cleared in turn. The <c>finally</c> block disposes whichever of the three locals
    /// still holds a value — exactly one hand-off is incomplete on any failing path, so disposal happens
    /// exactly once; on the success path all three are already null, so it disposes nothing (mirrors the
    /// <see cref="Verifiable.Cryptography.Pki.TimestampTokenInfo.ReadFromTokenAsync(Verifiable.Cryptography.Pki.PkiCertificateMemory, BaseMemoryPool, CancellationToken)"/>
    /// precedent for this same staged-local shape).
    /// </remarks>
    private static CounterSignatureV2 ReadCounterSignatureV2Element(CborReader reader, BaseMemoryPool pool)
    {
        EncodedCoseProtectedHeader? protectedHeaderCarrier = null;
        Signature? signatureCarrier = null;
        CoseSignatureComponent? component = null;

        try
        {
            reader.ReadStartArrayExpectLength(3);

            byte[] protectedHeaderBytes = reader.ReadByteString();
            protectedHeaderCarrier = EncodedCoseProtectedHeader.FromBytes(protectedHeaderBytes, pool);

            Dictionary<int, object>? unprotectedHeader = ReadCounterSignatureUnprotectedHeaderMap(reader, protectedHeaderBytes);

            byte[] signatureBytes = reader.ReadByteString();
            IMemoryOwner<byte> signatureOwner = pool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(signatureOwner.Memory.Span);
            signatureCarrier = new Signature(signatureOwner, CryptoTags.AlgorithmAgnosticSignature);

            reader.ReadEndArray();

            //Ownership of both standalone carriers transfers into the component; null them so the
            //finally block's cleanup never double-disposes them through two reference paths. The
            //component itself is staged the same way before it transfers into the returned
            //CounterSignatureV2, so at every point in the finally block exactly one of component,
            //protectedHeaderCarrier or signatureCarrier is non-null for whatever ownership stage
            //failed.
            component = new CoseSignatureComponent(protectedHeaderCarrier, unprotectedHeader, signatureCarrier);
            protectedHeaderCarrier = null;
            signatureCarrier = null;

            CounterSignatureV2 result = new(component);
            component = null;

            return result;
        }
        finally
        {
            component?.Dispose();
            protectedHeaderCarrier?.Dispose();
            signatureCarrier?.Dispose();
        }


        //Reads a COSE unprotected-header map from mapReader for a countersignature's own
        //COSE_Signature shape, returning null when empty — the same Headers CDDL group every COSE
        //layer shares (RFC 9052 Section 3). A label repeated in either bucket, one label in both, or a
        //protected bucket whose labels cannot be read is a malformed countersignature (RFC 9052 Section 3).
        static Dictionary<int, object>? ReadCounterSignatureUnprotectedHeaderMap(CborReader mapReader, ReadOnlyMemory<byte> protectedHeaderBytes)
        {
            int? mapLength = mapReader.ReadStartMap();
            if(mapLength is null)
            {
                throw new CborContentException("An unprotected headers map shall be definite-length (RFC 9052 §9).");
            }

            Dictionary<int, object>? header = null;
            HashSet<(Int128 Number, string? Text)> seenLabels = [];
            if(mapLength.Value > 0)
            {
                header = [];
                for(int i = 0; i < mapLength.Value; i++)
                {
                    ReadHeaderEntry(mapReader, seenLabels, header);
                }
            }

            mapReader.ReadEndMap();
            RefuseRepeatedOrSharedLabel(protectedHeaderBytes, seenLabels, isUnreadableBucketRefused: true);

            return header;
        }
    }


    /// <summary>
    /// Reads label 11's <c>[+ COSE_Countersignature]</c> array arm (RFC 9338 §2 Table 1) — one or more
    /// full countersignatures carried together, none individually tagged (tag 19 wraps only the
    /// single-value arm, per <see cref="ReadCounterSignatureV2"/>'s own remarks). Disposes every
    /// already-decoded element on a mid-loop failure so a malformed later element never leaks the
    /// carriers of the elements decoded before it.
    /// </summary>
    /// <param name="valueBytes">The CBOR-encoded label-11 header-parameter value bytes.</param>
    /// <param name="pool">Memory pool the decoded carriers rent their buffers from.</param>
    /// <returns>The decoded sequence, holding at least one element.</returns>
    private static CounterSignatureV2Sequence ReadCounterSignatureV2Sequence(ReadOnlyMemory<byte> valueBytes, BaseMemoryPool pool)
    {
        var reader = new CborReader(valueBytes, CborOptions.RfcCanonical);
        int? count = reader.ReadStartArray();
        if(count is null || count.Value == 0)
        {
            throw new CborContentException(
                "COSE header label 11's [+ COSE_Countersignature] array arm requires at least one element (RFC 9338 §2 Table 1).");
        }

        List<CounterSignatureV2> elements = new(count.Value);

        try
        {
            for(int i = 0; i < count.Value; i++)
            {
                elements.Add(ReadCounterSignatureV2Element(reader, pool));
            }

            reader.ReadEndArray();

            if(reader.BytesRemaining != 0)
            {
                throw new CborContentException("Trailing bytes after the [+ COSE_Countersignature] array.");
            }

            //Nothing between this call and the return below can throw, so elements needs no
            //catch-side double-dispose guard.
            return new CounterSignatureV2Sequence(elements);
        }
        catch
        {
            foreach(CounterSignatureV2 element in elements)
            {
                element.Dispose();
            }

            throw;
        }
    }


    /// <summary>
    /// Dispatches label 11's value to whichever arm of RFC 9338 §2 Table 1's <c>COSE_Countersignature /
    /// [+ COSE_Countersignature]</c> union it structurally is — a single element's own array starts with
    /// a byte string (the <c>protected</c> field); the <c>[+ COSE_Countersignature]</c> array arm's outer
    /// array instead starts with a NESTED array (its first element's own <c>[protected, unprotected,
    /// signature]</c> triple) — so the two shapes are unambiguous by peeking one level deep, regardless of
    /// how many elements the array arm carries.
    /// </summary>
    /// <param name="valueBytes">The CBOR-encoded label-11 header-parameter value bytes.</param>
    /// <param name="pool">Memory pool the decoded carriers rent their buffers from.</param>
    /// <returns>The decoded single countersignature, or a sequence of two or more.</returns>
    private static CoseCounterSignature ReadCounterSignatureV2SingleOrSequence(ReadOnlyMemory<byte> valueBytes, BaseMemoryPool pool)
    {
        var probe = new CborReader(valueBytes, CborOptions.RfcCanonical);
        if(probe.PeekState() != CborReaderState.Tag)
        {
            _ = probe.ReadStartArray();
            if(probe.PeekState() == CborReaderState.StartArray)
            {
                return ReadCounterSignatureV2Sequence(valueBytes, pool);
            }
        }

        return ReadCounterSignatureV2(valueBytes, pool);
    }


    /// <summary>
    /// Gets a delegate that writes a full version 2 countersignature (COSE header label 11)
    /// to CBOR bytes, untagged.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Never emits CBOR tag 19 — the tagged form is reserved for read tolerance only.
    /// See <see cref="ReadCounterSignatureV2"/>.
    /// </para>
    /// <para>
    /// The protected bucket arrives already serialized, so its labels are read with the reading side's own label read
    /// before anything is written, and a countersignature the reading side would refuse is not written.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-9">RFC 9052 Section 9</see>: "Applications MUST NOT
    /// generate messages with the same label used twice as a key in a single map."
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// The countersignature's protected bucket carries one label twice, a label that is neither an integer nor a text
    /// string, or a label its unprotected bucket also carries, or it is no well-formed map of labels.
    /// </exception>
    public static WriteCounterSignatureV2Delegate WriteCounterSignatureV2 { get; } = static (counterSignature, pool) =>
    {
        ArgumentNullException.ThrowIfNull(counterSignature);
        ArgumentNullException.ThrowIfNull(pool);
        RefuseToWriteMalformedBuckets(
            counterSignature.Component.ProtectedHeader.AsReadOnlyMemory(), counterSignature.Component.UnprotectedHeader, nameof(counterSignature));

        using var buffer = new SlabBufferWriter(pool);
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(3);
        writer.WriteByteString(counterSignature.Component.ProtectedHeader.AsReadOnlySpan());
        WriteCounterSignatureUnprotectedHeaderMap(writer, counterSignature.Component.UnprotectedHeader);
        writer.WriteByteString(counterSignature.Component.Signature.AsReadOnlySpan());
        writer.WriteEndArray();

        //Route the encoded bytes through the pool so the wire form carries CBOM provenance
        //and OTel observes the allocation, mirroring SerializeCoseSign.
        using IMemoryOwner<byte> encoded = buffer.Detach();
        IMemoryOwner<byte> owner = pool.Rent(encoded.Memory.Length);
        encoded.Memory.Span.CopyTo(owner.Memory.Span);

        return new EncodedCoseCounterSignature(owner, CryptoTags.CoseEncodedCounterSignature);


        //Writes a COSE unprotected-header map to writer for a countersignature's own COSE_Signature
        //shape (empty when header is null or empty).
        static void WriteCounterSignatureUnprotectedHeaderMap(CborWriter writer, IReadOnlyDictionary<int, object>? header)
        {
            if(header is not null && header.Count > 0)
            {
                writer.WriteStartMap(header.Count);
                foreach(var kvp in header)
                {
                    writer.WriteInt32(kvp.Key);
                    CborValueConverter.WriteValue(writer, kvp.Value);
                }
                writer.WriteEndMap();
            }
            else
            {
                writer.WriteStartMap(0);
                writer.WriteEndMap();
            }
        }
    };


    /// <summary>
    /// Gets a delegate that reads an abbreviated version 2 countersignature (COSE header
    /// label 12) from CBOR bytes — a bare <c>bstr</c> per RFC 9338 §3.2.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Reads under <see cref="CborConformanceMode.RfcCanonical"/>, not <see cref="CborConformanceMode.Lax"/>:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9338#section-4">RFC 9338 §4</see>'s determinism MUST
    /// (narrowing RFC 8949 §4.2 via RFC 9052 §9) rules out an indefinite-length-chunked bstr here, which
    /// <see cref="CborConformanceMode.Lax"/> would otherwise silently accept by concatenating its chunks.
    /// </para>
    /// <para>
    /// Throws on malformed input; the fail-closed boundary is
    /// <see cref="ParseCounterSignatureHeaderValue"/>.
    /// </para>
    /// </remarks>
    public static ReadCounterSignature0V2Delegate ReadCounterSignature0V2 { get; } = static (valueBytes, pool) =>
    {
        ArgumentNullException.ThrowIfNull(pool);

        var reader = new CborReader(valueBytes, CborOptions.RfcCanonical);
        byte[] signatureBytes = reader.ReadByteString();

        if(reader.BytesRemaining != 0)
        {
            throw new CborContentException("Trailing bytes after the COSE_Countersignature0 value.");
        }

        IMemoryOwner<byte> signatureOwner = pool.Rent(signatureBytes.Length);
        signatureBytes.CopyTo(signatureOwner.Memory.Span);

        return new CounterSignature0V2(new Signature(signatureOwner, CryptoTags.AlgorithmAgnosticSignature));
    };


    /// <summary>
    /// Gets a delegate that writes an abbreviated version 2 countersignature (COSE header
    /// label 12) to CBOR bytes — a bare <c>bstr</c> per RFC 9338 §3.2.
    /// </summary>
    public static WriteCounterSignature0V2Delegate WriteCounterSignature0V2 { get; } = static (counterSignature, pool) =>
    {
        ArgumentNullException.ThrowIfNull(counterSignature);
        ArgumentNullException.ThrowIfNull(pool);

        using var buffer = new SlabBufferWriter(pool);
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteByteString(counterSignature.Value.AsReadOnlySpan());

        using IMemoryOwner<byte> encoded = buffer.Detach();
        IMemoryOwner<byte> owner = pool.Rent(encoded.Memory.Length);
        encoded.Memory.Span.CopyTo(owner.Memory.Span);

        return new EncodedCoseCounterSignature(owner, CryptoTags.CoseEncodedCounterSignature);
    };


    /// <summary>
    /// Gets a delegate that fail-closed dispatches a COSE header-parameter value to its
    /// version 2 countersignature form, by label.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="CoseHeaderParameters.CounterSignature"/> (7) and
    /// <see cref="CoseHeaderParameters.CounterSignature0"/> (9) — the deprecated RFC 8152
    /// version 1 countersignature labels — are rejected fail-closed, citing
    /// <see href="https://www.rfc-editor.org/rfc/rfc9338#section-1">RFC 9338 §1</see>'s
    /// migration text ("uses of 'CounterSignature' will migrate to 'CounterSignatureV2', and
    /// uses of 'CounterSignature0' will migrate to 'CounterSignature0V2'") and TS 119 152-1's
    /// own CDDL, which carries labels 11/12 only.
    /// </para>
    /// <para>
    /// Label 11 decodes through <see cref="ReadCounterSignatureV2SingleOrSequence"/>, which is
    /// shape-aware over RFC 9338 §2 Table 1's <c>COSE_Countersignature / [+ COSE_Countersignature]</c>
    /// value type union and tag-19-tolerant on the single-value arm (see <see cref="ReadCounterSignatureV2"/>'s
    /// own remarks); label 12 decodes through <see cref="ReadCounterSignature0V2"/> (no array arm — Table 1
    /// types label 12's value as <c>COSE_Countersignature0</c> alone).
    /// </para>
    /// <para>
    /// The final switch arm guards a programming error, not wire data — every label this delegate is ever
    /// invoked with (7, 9, 11, or 12) is already enumerated above; a fifth value means a caller violated
    /// <see cref="ParseCounterSignatureHeaderValueDelegate"/>'s own contract. It therefore throws
    /// <see cref="UnreachableException"/> rather than one of the types <see cref="IsMalformedInputException"/>
    /// matches (which include <see cref="ArgumentException"/>, so <see cref="ArgumentOutOfRangeException"/>
    /// would have been laundered into an ordinary <see cref="CoseCounterSignatureParseResult.Failure"/> by the
    /// catch clause below) — a caller bug must surface, not be mistaken for malformed wire content.
    /// </para>
    /// </remarks>
    public static ParseCounterSignatureHeaderValueDelegate ParseCounterSignatureHeaderValue { get; } = static (label, valueBytes, pool) =>
    {
        ArgumentNullException.ThrowIfNull(pool);

        try
        {
            return label switch
            {
                CoseHeaderParameters.CounterSignature or CoseHeaderParameters.CounterSignature0 =>
                    throw new CborContentException(
                        $"COSE header label {label} is the deprecated RFC 8152 version 1 countersignature form (RFC 9338 §1 migration); " +
                        $"this substrate models version 2 countersignatures only (labels {CoseHeaderParameters.CounterSignatureVersion2}/{CoseHeaderParameters.Countersignature0Version2})."),
                CoseHeaderParameters.CounterSignatureVersion2 =>
                    CoseCounterSignatureParseResult.Success(ReadCounterSignatureV2SingleOrSequence(valueBytes, pool)),
                CoseHeaderParameters.Countersignature0Version2 =>
                    CoseCounterSignatureParseResult.Success(ReadCounterSignature0V2(valueBytes, pool)),
                _ => throw new UnreachableException($"COSE header-parameter label {label} is not one of the four labels (7, 9, 11, 12) ParseCounterSignatureHeaderValueDelegate's own contract admits.")
            };
        }
        catch(Exception ex) when(IsMalformedInputException(ex))
        {
            return CoseCounterSignatureParseResult.Failure();
        }
    };


    /// <summary>
    /// Gets a delegate that serializes a protected header map to CBOR bytes.
    /// </summary>
    public static SerializeProtectedHeaderDelegate SerializeProtectedHeader { get; } = static header =>
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(header.Count);

        foreach(var kvp in header.OrderBy(x => x.Key))
        {
            writer.WriteInt32(kvp.Key);
            CborValueConverter.WriteValue(writer, kvp.Value);
        }

        writer.WriteEndMap();

        return buffer.WrittenSpan.ToArray();
    };


    /// <summary>
    /// Gets a delegate that parses protected header bytes into a dictionary.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A label is any CBOR integer, read whole, or a text string, and a label that appears twice in the map, judged on
    /// its decoded value so that one label written in two widths is one label, makes the message malformed
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "When processing
    /// messages, if a label appears multiple times, the message MUST be rejected as malformed.").
    /// </para>
    /// <para>
    /// The dictionary carries the integer labels within the 32-bit signed range. A well-formed label it does not carry,
    /// a text string or an integer outside that range, is judged for a repeat and passed over with its value; it is
    /// never read as another label (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052
    /// Section 1.5</see>: "label = int / tstr").
    /// </para>
    /// <para>
    /// Bytes after the map are refused: <see href="https://www.rfc-editor.org/rfc/rfc8949#section-1.2">RFC 8949
    /// Section 1.2</see> defines a well-formed data item as one that "does not include following extraneous data".
    /// </para>
    /// </remarks>
    /// <exception cref="CborContentException">
    /// The map carries one label twice, or a map key that is neither an integer nor a text string, or bytes after the
    /// map, or the bytes are otherwise not a well-formed map.
    /// </exception>
    public static ParseProtectedHeaderDelegate ParseProtectedHeader { get; } = static headerBytes =>
    {
        var reader = new CborReader(headerBytes.ToArray(), CborOptions.Lax);
        var result = new Dictionary<int, object>();
        HashSet<(Int128 Number, string? Text)> seenLabels = [];

        int? mapLength = reader.ReadStartMap();
        for(int i = 0; i < mapLength; i++)
        {
            ReadHeaderEntry(reader, seenLabels, result);
        }

        reader.ReadEndMap();
        if(reader.BytesRemaining != 0)
        {
            throw new CborContentException("The protected header carries bytes after its map (RFC 9052 Section 3).");
        }

        return result;
    };


    /// <summary>
    /// Reads one COSE header-map label as RFC 9052 Section 1.5 defines it: any CBOR integer, negative or unsigned,
    /// read whole and never cast down, or a text string. Two labels are the same when their decoded values are
    /// equal: integers by value whatever their encoded width, text strings by their characters; an integer and a
    /// text string are never the same. This is the one label read of the header maps this file reads and writes.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052 Section 1.5</see>: "label = int / tstr"
    /// and "In a CBOR map defined by this specification, the presence a label that is neither a text string nor an
    /// integer is an error. Applications can either fail processing or process messages by ignoring incorrect labels;
    /// however, they MUST NOT create messages with incorrect labels." This reader fails processing.
    /// </remarks>
    /// <param name="reader">The reader, positioned at a header-map label.</param>
    /// <returns>The decoded label: its integer value, or its text when it is a text string.</returns>
    /// <exception cref="CborContentException">The map key is neither an integer nor a text string.</exception>
    private static (Int128 Number, string? Text) ReadLabel(CborReader reader)
    {
        return reader.PeekState() switch
        {
            CborReaderState.UnsignedInteger => ((Int128)reader.ReadUInt64(), null),
            CborReaderState.NegativeInteger => (-1 - (Int128)reader.ReadCborNegativeIntegerRepresentation(), null),
            CborReaderState.TextString => (Int128.Zero, reader.ReadTextString()),
            CborReaderState otherState => throw new CborContentException(
                $"A COSE header label is an integer or a text string; the map carries a {otherState} map key (RFC 9052 Section 1.5).")
        };
    }


    /// <summary>
    /// Tells whether a decoded label is one the header dictionary carries: an integer within the 32-bit signed range
    /// of the dictionary's own label type.
    /// </summary>
    /// <param name="label">The decoded label.</param>
    /// <param name="dictionaryLabel">The label as the dictionary carries it, when it does.</param>
    /// <returns><see langword="true"/> when the dictionary carries the label.</returns>
    private static bool IsDictionaryLabel((Int128 Number, string? Text) label, out int dictionaryLabel)
    {
        bool isCarried = label.Text is null && label.Number >= int.MinValue && label.Number <= int.MaxValue;
        dictionaryLabel = isCarried ? (int)label.Number : 0;

        return isCarried;
    }


    /// <summary>
    /// Reads one entry of a COSE header map whose values the header dictionary decodes: its label is read and judged
    /// for a repeat, and a label the dictionary carries is stored with its decoded value (a null value is not stored),
    /// while any other well-formed label is passed over with its value. Every header map of this file whose values
    /// are decoded reads its entries here.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "Labels in each of the
    /// maps MUST be unique. When processing messages, if a label appears multiple times, the message MUST be rejected
    /// as malformed."
    /// </remarks>
    /// <param name="reader">The reader, positioned at an entry's label.</param>
    /// <param name="seenLabels">The labels already read from the same map.</param>
    /// <param name="header">The dictionary the entry is stored into.</param>
    /// <exception cref="CborContentException">The label repeats one the map already held, or is neither an integer nor a text string.</exception>
    private static void ReadHeaderEntry(CborReader reader, HashSet<(Int128 Number, string? Text)> seenLabels, Dictionary<int, object> header)
    {
        (Int128 Number, string? Text) label = ReadLabel(reader);
        RefuseRepeatedLabel(seenLabels, label);
        if(!IsDictionaryLabel(label, out int dictionaryLabel))
        {
            reader.SkipValue();

            return;
        }

        object? value = CborValueConverter.ReadValue(reader);
        if(value is not null)
        {
            header[dictionaryLabel] = value;
        }
    }


    /// <summary>
    /// Records <paramref name="label"/> as read from one COSE header map and refuses the message as
    /// malformed when the same map already held that label. The label is the decoded value, so one
    /// label written in two widths is one label.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "Labels in
    /// each of the maps MUST be unique. When processing messages, if a label appears multiple times, the
    /// message MUST be rejected as malformed." <see href="https://www.rfc-editor.org/rfc/rfc9052#section-9">RFC 9052
    /// Section 9</see>: "Applications MUST NOT parse and process messages with the same label used twice as
    /// a key in a single map."
    /// </remarks>
    /// <param name="seenLabels">The labels already read from the same map.</param>
    /// <param name="label">The decoded label just read.</param>
    /// <exception cref="CborContentException">The map already held <paramref name="label"/>.</exception>
    private static void RefuseRepeatedLabel(HashSet<(Int128 Number, string? Text)> seenLabels, (Int128 Number, string? Text) label)
    {
        if(!seenLabels.Add(label))
        {
            throw new CborContentException(
                $"COSE header label {DescribeLabel(label)} appears more than once in one map; the message is malformed (RFC 9052 Section 3).");
        }
    }


    /// <summary>
    /// Judges a layer's protected bucket: its labels are read in wire order and each is judged as it is read, so a
    /// label it carries twice refuses the message at its second occurrence, whatever the unprotected bucket holds and
    /// whatever follows in the bucket, and a label it shares with the unprotected bucket refuses the message too. A
    /// bucket carrying bytes after its map refuses the message. The protected bucket's labels are read for this
    /// judgment only; its bytes are handed on raw.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "Labels in each of the
    /// maps MUST be unique. When processing messages, if a label appears multiple times, the message MUST be rejected
    /// as malformed. Applications SHOULD verify that the same label does not occur in both the protected and
    /// unprotected header parameters." Since a message holding one label in both buckets is refused, the precedence
    /// sentence that follows the clause has nothing left to decide. The same section's
    /// "empty_or_serialized_map = bstr .cbor header_map / bstr .size 0" makes the bucket one serialized map, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-1.2">RFC 8949 Section 1.2</see> defines a
    /// well-formed data item as one that "does not include following extraneous data".
    /// </para>
    /// <para>
    /// The labels of the bucket's map are judged; the value under each label is passed over whole and nothing inside
    /// it is read here. A bucket whose labels cannot be read past the point read, one that is no well-formed map of
    /// labels, is refused with <paramref name="isUnreadableBucketRefused"/> set and handed on raw with it clear, after
    /// every label read before that point has been judged. The writing side and every parser but
    /// <see cref="ParseCoseSign1"/> set the flag.
    /// </para>
    /// </remarks>
    /// <param name="protectedHeaderBytes">The serialized protected bucket; empty when the bucket is empty.</param>
    /// <param name="unprotectedLabels">The labels read from the same layer's unprotected bucket.</param>
    /// <param name="isUnreadableBucketRefused">Whether a protected bucket whose labels cannot be read is refused here.</param>
    /// <exception cref="CborContentException">
    /// The protected bucket repeats a label, holds a label the unprotected bucket also holds, or carries bytes after its
    /// map; or, with <paramref name="isUnreadableBucketRefused"/> set, its labels cannot be read.
    /// </exception>
    private static void RefuseRepeatedOrSharedLabel(
        ReadOnlyMemory<byte> protectedHeaderBytes, HashSet<(Int128 Number, string? Text)> unprotectedLabels, bool isUnreadableBucketRefused)
    {
        if(protectedHeaderBytes.IsEmpty)
        {
            return;
        }

        var reader = new CborReader(protectedHeaderBytes, CborOptions.Lax);
        HashSet<(Int128 Number, string? Text)> protectedLabels = [];
        bool isFirstEntry = true;
        while(true)
        {
            (Int128 Number, string? Text)? label;
            try
            {
                label = ReadProtectedLabel(reader, isFirstEntry);
            }
            catch(Exception exception) when(IsMalformedInputException(exception))
            {
                if(!isUnreadableBucketRefused)
                {
                    return;
                }

                throw new CborContentException(
                    "The protected bucket is not a well-formed map of labels; the message is malformed (RFC 9052 Section 3).", exception);
            }

            if(label is not { } readLabel)
            {
                break;
            }

            isFirstEntry = false;
            RefuseRepeatedLabel(protectedLabels, readLabel);
            if(unprotectedLabels.Contains(readLabel))
            {
                throw new CborContentException(
                    $"COSE header label {DescribeLabel(readLabel)} is in both the protected and the unprotected bucket; the message is malformed (RFC 9052 Section 3).");
            }
        }

        if(reader.BytesRemaining != 0)
        {
            throw new CborContentException(
                "The protected bucket carries bytes after its map; the message is malformed (RFC 9052 Section 3).");
        }
    }


    /// <summary>
    /// Reads the next label of a serialized protected bucket through <see cref="ReadLabel"/>: before the first label the
    /// map's start is read, and before every later label the value of the label read before it is passed over.
    /// </summary>
    /// <param name="reader">The reader over the serialized protected bucket.</param>
    /// <param name="isFirstEntry">Whether no label of the bucket has been read yet.</param>
    /// <returns>The decoded label, or <see langword="null"/> when the map has ended.</returns>
    /// <exception cref="CborContentException">The bucket is not a well-formed map of labels.</exception>
    private static (Int128 Number, string? Text)? ReadProtectedLabel(CborReader reader, bool isFirstEntry)
    {
        if(isFirstEntry)
        {
            _ = reader.ReadStartMap();
        }
        else
        {
            reader.SkipValue();
        }

        if(reader.PeekState() == CborReaderState.EndMap)
        {
            reader.ReadEndMap();

            return null;
        }

        return ReadLabel(reader);
    }


    /// <summary>
    /// Refuses, as the caller's own argument, a layer whose protected bucket the reading side would refuse: a label
    /// carried twice, a map key that is neither an integer nor a text string, a label the layer's unprotected bucket
    /// also carries, or a bucket that is no well-formed map of labels. The judgment is the reading side's own,
    /// <see cref="RefuseRepeatedOrSharedLabel"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-9">RFC 9052 Section 9</see>: "Applications MUST NOT
    /// generate messages with the same label used twice as a key in a single map."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052 Section 1.5</see>: "Applications can
    /// either fail processing or process messages by ignoring incorrect labels; however, they MUST NOT create
    /// messages with incorrect labels."
    /// </remarks>
    /// <param name="protectedHeaderBytes">The layer's serialized protected bucket.</param>
    /// <param name="unprotectedHeader">The layer's unprotected bucket, or <see langword="null"/> when it is empty.</param>
    /// <param name="parameterName">The name of the serializer's parameter that carries the layer.</param>
    /// <exception cref="ArgumentException">The reading side would refuse the layer's buckets.</exception>
    private static void RefuseToWriteMalformedBuckets(
        ReadOnlyMemory<byte> protectedHeaderBytes, IReadOnlyDictionary<int, object>? unprotectedHeader, string parameterName)
    {
        HashSet<(Int128 Number, string? Text)> unprotectedLabels = [];
        if(unprotectedHeader is not null)
        {
            foreach(int unprotectedLabel in unprotectedHeader.Keys)
            {
                _ = unprotectedLabels.Add((unprotectedLabel, null));
            }
        }

        try
        {
            RefuseRepeatedOrSharedLabel(protectedHeaderBytes, unprotectedLabels, isUnreadableBucketRefused: true);
        }
        catch(Exception exception) when(IsMalformedInputException(exception))
        {
            throw new ArgumentException(
                "The protected bucket repeats a label, carries a label that is neither an integer nor a text string, or shares a label with the unprotected bucket; such a message is not written (RFC 9052 Sections 1.5, 3 and 9).",
                parameterName,
                exception);
        }
    }


    /// <summary>Answers the text a refusal names a decoded label by: its text, or its integer value.</summary>
    /// <param name="label">The decoded label.</param>
    /// <returns>The label's text or its integer value.</returns>
    private static string DescribeLabel((Int128 Number, string? Text) label)
    {
        return label.Text ?? label.Number.ToString(CultureInfo.InvariantCulture);
    }
}
