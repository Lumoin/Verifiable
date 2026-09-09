using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Veritas.Cbor;
using System.Linq;
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
    /// </remarks>
    public static SerializeCoseSign1Delegate SerializeCoseSign1 { get; } = static (message, pool) =>
    {
        using var buffer = new SlabBufferWriter(pool);
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteTag(new CborTag((ulong)CoseTags.Sign1));
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
        EncodedCoseProtectedHeader protectedHeaderCarrier = EncodedCoseProtectedHeader.FromBytes(protectedHeaderBytes, pool);

        //Unprotected header.
        Dictionary<int, object>? unprotectedHeader = null;
        int? mapLength = reader.ReadStartMap();
        if(mapLength > 0)
        {
            unprotectedHeader = new Dictionary<int, object>();
            for(int i = 0; i < mapLength; i++)
            {
                int key = reader.ReadInt32();
                object? value = CborValueConverter.ReadValue(reader);
                if(value is not null)
                {
                    unprotectedHeader[key] = value;
                }
            }
        }
        reader.ReadEndMap();

        //Payload (borrowed; the message's lifetime brackets the caller's
        //use of this returned reference).
        byte[] payload = reader.ReadByteString();

        //Signature — route through pool into a Signature carrier. The
        //signature carries a tag the verifier inspects; reuse the signing
        //tag conventions where possible. Here we use a generic
        //"signature value" Tag composition.
        byte[] signature = reader.ReadByteString();
        IMemoryOwner<byte> signatureOwner = pool.Rent(signature.Length);
        signature.CopyTo(signatureOwner.Memory.Span);
        Signature signatureCarrier = new(signatureOwner, CryptoTags.AlgorithmAgnosticSignature);

        reader.ReadEndArray();

        return new CoseSign1Message(
            protectedHeaderCarrier,
            unprotectedHeader,
            payload,
            signatureCarrier);
    };


    /// <summary>
    /// Gets a delegate that parses a COSE_Sign1 whose payload slot may be the nil sentinel — the
    /// detached form ISO/IEC 18013-5 §9.1.3.4 uses for mdoc device signatures. The standard
    /// <see cref="ParseCoseSign1"/> rejects nil payloads (correct for SD-CWT, wrong for mdoc device
    /// auth), so this shares the <see cref="ParseCoseSign1Delegate"/> shape and the mdoc device
    /// verifier wires it as the parse seam. Routes protected-header + signature bytes through the
    /// pool; the returned message owns its carriers and the caller disposes it.
    /// </summary>
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
        EncodedCoseProtectedHeader protectedHeaderCarrier = EncodedCoseProtectedHeader.FromBytes(protectedHeader, pool);

        //Unprotected header — read raw encoded value bytes; the verification math never touches it.
        Dictionary<int, object>? unprotectedHeader = null;
        if(reader.PeekState() == CborReaderState.StartMap)
        {
            int? mapEntries = reader.ReadStartMap();
            if(mapEntries is null || mapEntries.Value > 0)
            {
                unprotectedHeader = [];
                while(reader.PeekState() != CborReaderState.EndMap)
                {
                    int label = (int)reader.ReadInt64();
                    byte[] valueBytes = reader.ReadEncodedValue().ToArray();
                    unprotectedHeader[label] = valueBytes;
                }
            }
            reader.ReadEndMap();
        }

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
        Signature signatureCarrier = new(signatureOwner, CryptoTags.AlgorithmAgnosticSignature);

        reader.ReadEndArray();

        return new CoseSign1Message(
            protectedHeaderCarrier,
            unprotectedHeader,
            payload,
            signatureCarrier);
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
    /// RFC 9052 §4.1's <c>payload : bstr / nil</c> is written as the CBOR <c>nil</c> sentinel when
    /// <paramref name="message"/> reports a detached payload, and as a <c>bstr</c> (verbatim, including a
    /// genuinely zero-length attached payload) otherwise — the same producer-side distinction
    /// <c>CBAdESSignatureSerialization.SerializeCBAdESSign1</c> makes explicit via its own <c>payloadIsDetached</c>
    /// parameter for <c>COSE_Sign1</c>; this generic, non-CBAdES-specific <c>COSE_Sign</c> substrate has no
    /// sibling wrapper carrying that parameter, so it infers the same fact from the message itself.
    /// </para>
    /// </remarks>
    public static SerializeCoseSignDelegate SerializeCoseSign { get; } = static (message, pool) =>
    {
        using var buffer = new SlabBufferWriter(pool);
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteTag(new CborTag((ulong)CoseTags.Sign));
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


        /// <summary>
        /// Writes a COSE unprotected-header map (empty when <paramref name="header"/> is
        /// <see langword="null"/> or empty) — the shape every layer of COSE_Sign (body and
        /// every signer) shares, per RFC 9052 §3's <c>Headers</c> CDDL group.
        /// </summary>
        /// <param name="writer">The CBOR writer positioned to write the map.</param>
        /// <param name="header">The unprotected header map, or <see langword="null"/>.</param>
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

            Dictionary<int, object>? bodyUnprotectedHeader = ReadUnprotectedHeaderMap(reader);

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

                Dictionary<int, object>? signerUnprotectedHeader = ReadUnprotectedHeaderMap(reader);

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
        catch(Exception ex) when(IsFailClosedCoseSignParseException(ex))
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


        /// <summary>
        /// Reads a COSE unprotected-header map — the shape every layer of COSE_Sign (body
        /// and every signer) shares, per RFC 9052 §3's <c>Headers</c> CDDL group. Fails
        /// closed on an indefinite-length map (RFC 9052 §9 requires definite lengths).
        /// </summary>
        /// <param name="reader">The CBOR reader positioned at the map.</param>
        /// <returns>The decoded map, or <see langword="null"/> when empty.</returns>
        static Dictionary<int, object>? ReadUnprotectedHeaderMap(CborReader reader)
        {
            int? mapLength = reader.ReadStartMap();
            if(mapLength is null)
            {
                throw new CborContentException("An unprotected headers map shall be definite-length (RFC 9052 §9).");
            }

            Dictionary<int, object>? header = null;
            if(mapLength.Value > 0)
            {
                header = new Dictionary<int, object>();
                for(int i = 0; i < mapLength.Value; i++)
                {
                    int key = reader.ReadInt32();
                    object? value = CborValueConverter.ReadValue(reader);
                    if(value is not null)
                    {
                        header[key] = value;
                    }
                }
            }
            reader.ReadEndMap();

            return header;
        }
    };


    /// <summary>
    /// Determines whether <paramref name="exception"/> is one of the exception types
    /// <see cref="ParseCoseSign"/>'s malformed-input paths raise internally — the set the
    /// fail-closed catch clause converts to <see cref="CoseSignParseResult.Failure"/>
    /// rather than letting escape, mirroring <c>CBAdESSignatureSerialization</c>'s own
    /// <c>IsFailClosedParseException</c> predicate.
    /// </summary>
    /// <param name="exception">The exception to classify.</param>
    /// <returns><see langword="true"/> when the exception represents malformed input.</returns>
    private static bool IsFailClosedCoseSignParseException(Exception exception) =>
        exception is CborException or InvalidOperationException or ArgumentException
            or IndexOutOfRangeException or OverflowException or FormatException;


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

            Dictionary<int, object>? unprotectedHeader = ReadCounterSignatureUnprotectedHeaderMap(reader);

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


        /// <summary>
        /// Reads a COSE unprotected-header map for a countersignature's own COSE_Signature
        /// shape — the same <c>Headers</c> CDDL group every COSE layer shares (RFC 9052 §3).
        /// </summary>
        /// <param name="mapReader">The CBOR reader positioned at the map.</param>
        /// <returns>The decoded map, or <see langword="null"/> when empty.</returns>
        static Dictionary<int, object>? ReadCounterSignatureUnprotectedHeaderMap(CborReader mapReader)
        {
            int? mapLength = mapReader.ReadStartMap();
            if(mapLength is null)
            {
                throw new CborContentException("An unprotected headers map shall be definite-length (RFC 9052 §9).");
            }

            Dictionary<int, object>? header = null;
            if(mapLength.Value > 0)
            {
                header = new Dictionary<int, object>();
                for(int i = 0; i < mapLength.Value; i++)
                {
                    int key = mapReader.ReadInt32();
                    object? value = CborValueConverter.ReadValue(mapReader);
                    if(value is not null)
                    {
                        header[key] = value;
                    }
                }
            }
            mapReader.ReadEndMap();

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
            probe.ReadStartArray();
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
    /// Never emits CBOR tag 19 — the tagged form is reserved for read tolerance only.
    /// See <see cref="ReadCounterSignatureV2"/>.
    /// </remarks>
    public static WriteCounterSignatureV2Delegate WriteCounterSignatureV2 { get; } = static (counterSignature, pool) =>
    {
        ArgumentNullException.ThrowIfNull(counterSignature);
        ArgumentNullException.ThrowIfNull(pool);

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


        /// <summary>
        /// Writes a COSE unprotected-header map for a countersignature's own COSE_Signature
        /// shape (empty when <paramref name="header"/> is <see langword="null"/> or empty).
        /// </summary>
        /// <param name="writer">The CBOR writer positioned to write the map.</param>
        /// <param name="header">The unprotected header map, or <see langword="null"/>.</param>
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
    /// <see cref="UnreachableException"/> rather than one of the types <see cref="IsFailClosedCoseSignParseException"/>
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
        catch(Exception ex) when(IsFailClosedCoseSignParseException(ex))
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
    public static ParseProtectedHeaderDelegate ParseProtectedHeader { get; } = static headerBytes =>
    {
        var reader = new CborReader(headerBytes.ToArray(), CborOptions.Lax);
        var result = new Dictionary<int, object>();

        int? mapLength = reader.ReadStartMap();
        for(int i = 0; i < mapLength; i++)
        {
            int key = reader.ReadInt32();
            object? value = CborValueConverter.ReadValue(reader);
            if(value is not null)
            {
                result[key] = value;
            }
        }
        reader.ReadEndMap();

        return result;
    };
}
