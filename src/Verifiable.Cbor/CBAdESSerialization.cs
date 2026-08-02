using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;

namespace Verifiable.Cbor;

/// <summary>
/// CBOR encode/parse bindings for the CB-AdES stage-1 vocabulary — the seven new signed header parameters
/// (clause 5.2), the clause 5.4 shared syntax types (<c>oId</c>, <c>pkiOb</c>, <c>tstContainer</c>/
/// <c>TstToken</c>), and <c>adoTst</c> (clause 5.2.6, a straight <c>tstContainer</c> alias) — per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>. The typed models this class encodes/parses live in
/// <see cref="Verifiable.JCose"/> (<c>CBAdES*</c>); the CDDL derivation for each is documented on the
/// model type itself.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors <see cref="CoseSerialization"/>'s shape: static methods, <see cref="CborConformanceMode.Canonical"/>
/// throughout — both to write deterministic (RFC 8949 §4.2) CBOR and, on the parse side, to get the
/// framework's own definite-length/minimal-encoding validation for free, satisfying wavecb-contract.md
/// R-5's strict-conformance requirement with less hand-written validation. Every <c>TryParse*</c> method
/// additionally checks ascending (canonical) map-key order via
/// <see cref="CborReaderExtensions.ReadAscendingMapKey"/>, which <see cref="CborReader"/>'s conformance-mode
/// validation does not itself enforce on read.
/// </para>
/// <para>
/// <strong>Encode carrier.</strong> Every <c>Encode*</c> method returns a <see cref="PooledMemory"/> — the
/// general-purpose, pool-rented, tagged byte-buffer carrier (<c>Verifiable.Foundation</c>) — rather than a
/// naked <c>byte[]</c>, so the encoded bytes carry CBOM/OTel provenance like every other encoded wire form
/// in this library (<see cref="CoseSerialization.SerializeCoseSign1"/>'s own "route the encoded bytes
/// through the pool" comment). None of the stage-1 CB-AdES component values are RFC 8949 §3.4.5.1 Tag-24
/// "encoded CBOR data item" wrappers on the wire — clause 4.7's "encapsulation in CBOR byte strings"
/// resolves, for every type in this stage, to a plain <c>bstr</c> field holding raw (frequently DER) bytes,
/// never a CBOR-in-<c>bstr</c> wrapper — so <see cref="EncodedCborItem"/> (a Tag-24-specific carrier) does
/// not fit these shapes; <see cref="PooledMemory"/> is the reusable, tag-agnostic carrier this codebase
/// already has for "a pooled, tagged, disposable byte buffer with no domain shape of its own."
/// </para>
/// <para>
/// <strong>Parse fail-closed convention.</strong> Every <c>TryParse*</c> method returns <see langword="false"/>
/// for malformed, non-conformant, or truncated input; it never throws for untrusted bytes (contract R-5,
/// the <see cref="CoseVerification"/> exemplar). The catch-filter is centralized as
/// <see cref="IsFailClosedParseException"/>. A <c>TryParse*</c> method that owns a <see cref="DigestValue"/>
/// mid-parse (<c>x5ts</c>, <c>sigPId</c>, <c>sigD</c>) disposes every already-constructed digest before
/// returning <see langword="false"/>, so a malformed tail never leaks a pool rental.
/// </para>
/// <para>
/// <strong>Depth/size bounds.</strong> Every reader below is an iterative loop over a definite-length CBOR
/// array/map (no recursive descent of this class's own authorship); the one place this stage reads a
/// genuinely open-ended CBOR value (<c>srCms.commQuals</c>, <c>sigPQual.otherQuals</c>'s <c>value: any</c>)
/// delegates to the existing <see cref="CborValueConverter.ReadValue(CborReader)"/>, matching the same
/// convention <see cref="CoseSerialization"/> already uses for open-ended COSE header content. List
/// pre-allocation from an untrusted declared length is capped (<c>Math.Min(count, 64)</c>) so a hostile
/// declared count cannot force a large up-front allocation before any bytes are actually read.
/// </para>
/// <para>
/// <strong>Provisional wire mapping (D3, contract R-6):</strong> <c>srAts</c>'s <c>NotCertifiedItem</c> CDDL
/// is internally inconsistent with its own prose (see the D3 remarks on
/// <see cref="CBAdESSignerAttributeNotCertifiedItem"/>) — no byte-exact codec can be derived from clause
/// 5.2.5 alone. This class's wire mapping is a provisional, clearly-scoped reading:
/// <c>NotCertifiedItem = [ mediaType: tstr, qVals: [+any] ]</c> — a 2-element array whose second element is
/// itself an array of the opaque "qualifying values" the prose describes, with the CDDL's <c>*label =&gt;
/// any</c> catch-all's per-item labels NOT preserved (the model carries no per-value label field — see
/// <see cref="CBAdESSignerAttributeOpaqueQualifyingValue"/>). Revisit once ETSI clarifies.
/// </para>
/// <para>
/// <strong><c>sigD</c> wire projection.</strong> <see cref="CBAdESDetachedObjects"/>'s single ordered
/// <c>DetachedObjects</c> list projects onto the wire's positionally-coupled <c>pars</c>/<c>hashV</c>/
/// <c>ctys</c> parallel arrays (clause 5.2.8.1): <c>hashM</c>/<c>hashV</c> are written together only when
/// every entry carries a digest (CB-5.2.8-21 requires <c>hashV</c>, when present, to cover every <c>pars</c>
/// position) and <c>hashM</c> is derived from the entries' shared digest-algorithm tag; a mix of
/// digest-bearing and non-digest-bearing entries fails encoding (<see cref="ArgumentException"/> — trusted
/// caller-input construction, not untrusted-wire parsing). <c>ctys</c> is written, with an explicit CBOR
/// null (<c>#7.22</c>) for the CB-5.2.8-25 "implied" case, only when at least one entry carries a content
/// type. On parse, a length mismatch between <c>pars</c> and a present <c>hashV</c>/<c>ctys</c> fails
/// closed (CB-5.2.8-21/24).
/// </para>
/// </remarks>
public static class CBAdESSerialization
{
    /// <summary>
    /// Gets the <see cref="Tag"/> every <c>Encode*</c> method in this class stamps its returned
    /// <see cref="PooledMemory"/> carrier with — a CB-AdES component's encoded CBOR bytes, mirroring
    /// <see cref="CryptoTags.CoseEncodedProtectedHeader"/>'s composition for the same reason (structural,
    /// non-secret, CBOR-encoded wire data).
    /// </summary>
    private static Tag ComponentTag { get; } = Tag.Create(Purpose.Data).With(EncodingScheme.Cose);


    /// <summary>
    /// Determines whether <paramref name="exception"/> represents malformed or non-conformant untrusted
    /// CBOR input that every <c>TryParse*</c> method in this class catches to fail closed, per contract
    /// R-5 (strict conformance; parsing never throws for malformed input).
    /// </summary>
    /// <param name="exception">The exception to classify.</param>
    /// <returns><see langword="true"/> when the exception should be swallowed and reported as a parse failure.</returns>
    private static bool IsFailClosedParseException(Exception exception) =>
        exception is CborContentException or InvalidOperationException or ArgumentException
            or IndexOutOfRangeException or OverflowException or FormatException;


    /// <summary>
    /// Wraps raw digest bytes read from untrusted CBOR input into a pool-rented <see cref="DigestValue"/>,
    /// tagged by the best-known mapping of <paramref name="coseHashAlgorithm"/> to a
    /// <see cref="HashAlgorithmName"/> (falling back to a generic digest tag for an algorithm identifier
    /// this library carries no named tag for).
    /// </summary>
    /// <param name="digestBytes">The raw digest bytes.</param>
    /// <param name="coseHashAlgorithm">
    /// The digest-algorithm identifier read from the CDDL's <c>int / tstr</c> union (clause 5.1.7/5.2.7.1/
    /// 5.2.8.1) — see <see cref="CBAdESDigestAlgorithmIdentifier"/>.
    /// </param>
    /// <param name="pool">The memory pool the digest's buffer is rented from.</param>
    /// <returns>The owned <see cref="DigestValue"/>.</returns>
    private static DigestValue CreateDigestValue(byte[] digestBytes, CBAdESDigestAlgorithmIdentifier coseHashAlgorithm, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(digestBytes.Length);
        digestBytes.CopyTo(owner.Memory.Span);

        return new DigestValue(owner, ResolveDigestTag(coseHashAlgorithm));
    }


    /// <summary>
    /// Maps a digest-algorithm identifier to this library's <see cref="Tag"/> for that algorithm, falling
    /// back to a generic digest tag for an identifier this library has no named tag for — either because it
    /// is the CDDL's <c>tstr</c> arm, or because it is an <see langword="int"/> identifier this library does
    /// not carry a named <see cref="HashAlgorithmName"/> mapping for (the CDDL's digest-algorithm registry is
    /// open-ended — RFC 9053 or any amending/superseding specification — so an unrecognized-but-well-formed
    /// identifier is not itself malformed input).
    /// </summary>
    /// <param name="coseHashAlgorithm">The digest-algorithm identifier.</param>
    /// <returns>The resolved <see cref="Tag"/>.</returns>
    private static Tag ResolveDigestTag(CBAdESDigestAlgorithmIdentifier coseHashAlgorithm) => coseHashAlgorithm switch
    {
        CBAdESDigestAlgorithmIntegerIdentifier { Value: WellKnownCoseAlgorithms.Sha256 } => CryptoTags.Sha256Digest,
        CBAdESDigestAlgorithmIntegerIdentifier { Value: WellKnownCoseAlgorithms.Sha384 } => CryptoTags.Sha384Digest,
        CBAdESDigestAlgorithmIntegerIdentifier { Value: WellKnownCoseAlgorithms.Sha512 } => CryptoTags.Sha512Digest,
        CBAdESDigestAlgorithmIntegerIdentifier or CBAdESDigestAlgorithmTextIdentifier => Tag.Create(Purpose.Digest).With(EncodingScheme.Raw),
        _ => throw new NotSupportedException($"Unknown digest-algorithm identifier arm '{coseHashAlgorithm.GetType()}'.")
    };


    /// <summary>
    /// Writes a digest-algorithm identifier (<see cref="CBAdESDigestAlgorithmIdentifier"/>) to
    /// <paramref name="writer"/> per the CDDL's <c>int / tstr</c> union: the STORED identifier is written
    /// exactly as constructed — the <see langword="int"/> arm as a CBOR integer, the <see langword="string"/>
    /// arm as a CBOR text string — so any registered IANA COSE Algorithms identifier round-trips byte-exactly
    /// regardless of which arm a producer chose.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="identifier">The value to write.</param>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="identifier"/> is an unknown arm.</exception>
    private static void WriteDigestAlgorithmIdentifier(CborWriter writer, CBAdESDigestAlgorithmIdentifier identifier)
    {
        _ = identifier switch
        {
            CBAdESDigestAlgorithmIntegerIdentifier integerIdentifier => WriteInteger(writer, integerIdentifier),
            CBAdESDigestAlgorithmTextIdentifier textIdentifier => WriteText(writer, textIdentifier),
            _ => throw new NotSupportedException($"Unknown digest-algorithm identifier arm '{identifier.GetType()}'.")
        };

        static bool WriteInteger(CborWriter writer, CBAdESDigestAlgorithmIntegerIdentifier integerIdentifier)
        {
            writer.WriteInt32(integerIdentifier.Value);
            return true;
        }

        static bool WriteText(CborWriter writer, CBAdESDigestAlgorithmTextIdentifier textIdentifier)
        {
            writer.WriteTextString(textIdentifier.Value);
            return true;
        }
    }


    /// <summary>
    /// Reads a digest-algorithm identifier (<see cref="CBAdESDigestAlgorithmIdentifier"/>) from
    /// <paramref name="reader"/> per the CDDL's <c>int / tstr</c> union, accepting either arm — the CDDL does
    /// not narrow this to <see langword="int"/> at any of its three sites (clause 5.1.7/5.2.7.1/5.2.8.1).
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed identifier, holding whichever arm was on the wire.</returns>
    private static CBAdESDigestAlgorithmIdentifier ReadDigestAlgorithmIdentifier(CborReader reader) =>
        reader.PeekState() == CborReaderState.TextString
            ? new CBAdESDigestAlgorithmTextIdentifier(reader.ReadTextString())
            : new CBAdESDigestAlgorithmIntegerIdentifier(reader.ReadInt32());


    /// <summary>
    /// Encodes an <c>oId</c> shared-syntax value (<see cref="CBAdESObjectIdentifier"/>) to canonical CBOR.
    /// </summary>
    /// <param name="objectIdentifier">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>oId</c> map.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.4.1, Table 11</see>.
    /// </remarks>
    public static PooledMemory EncodeObjectIdentifier(CBAdESObjectIdentifier objectIdentifier, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(objectIdentifier);
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        WriteObjectIdentifier(writer, objectIdentifier);

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into an <c>oId</c> shared-syntax value (<see cref="CBAdESObjectIdentifier"/>).
    /// Fails closed: malformed or non-conformant input returns <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>oId</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.4.1, Table 11</see>.
    /// </remarks>
    public static bool TryParseObjectIdentifier(ReadOnlyMemory<byte> encoded, out CBAdESObjectIdentifier? result)
    {
        try
        {
            var reader = new CborReader(encoded, CborConformanceMode.Canonical);
            result = ReadObjectIdentifier(reader);
            if(reader.BytesRemaining != 0)
            {
                result = null;
                return false;
            }

            return true;
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            result = null;
            return false;
        }
    }


    /// <summary>
    /// Writes an <c>oId</c> map (clause 5.4.1, Table 11) to <paramref name="writer"/>. Shared by every
    /// component that embeds an <c>oId</c> (<c>srCms.commId</c>, <c>sigPId.id</c>,
    /// <c>SigPQual.spDSpec</c>).
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="objectIdentifier">The value to write.</param>
    private static void WriteObjectIdentifier(CborWriter writer, CBAdESObjectIdentifier objectIdentifier)
    {
        int memberCount = 1
            + (objectIdentifier.Desc is not null ? 1 : 0)
            + (objectIdentifier.DocRefs is not null ? 1 : 0);

        writer.WriteStartMap(memberCount);

        writer.WriteInt32(CBAdESObjectIdentifier.IdKey);
        writer.WriteUri(objectIdentifier.Id);

        if(objectIdentifier.Desc is not null)
        {
            writer.WriteInt32(CBAdESObjectIdentifier.DescKey);
            writer.WriteTextString(objectIdentifier.Desc);
        }

        if(objectIdentifier.DocRefs is not null)
        {
            writer.WriteInt32(CBAdESObjectIdentifier.DocRefsKey);
            writer.WriteStartArray(objectIdentifier.DocRefs.Count);
            foreach(Uri docRef in objectIdentifier.DocRefs)
            {
                writer.WriteUri(docRef);
            }

            writer.WriteEndArray();
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Reads an <c>oId</c> map (clause 5.4.1, Table 11) from <paramref name="reader"/>. Shared by every
    /// component that embeds an <c>oId</c>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the map is malformed or the required <c>id</c> member is absent.
    /// </exception>
    private static CBAdESObjectIdentifier ReadObjectIdentifier(CborReader reader)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 3);

        Uri? id = null;
        string? desc = null;
        List<Uri>? docRefs = null;
        int previousKey = 0;

        for(int i = 0; i < count; i++)
        {
            int key = reader.ReadAscendingMapKey(ref previousKey);

            _ = key switch
            {
                CBAdESObjectIdentifier.IdKey => AssignId(reader, ref id),
                CBAdESObjectIdentifier.DescKey => AssignDesc(reader, ref desc),
                CBAdESObjectIdentifier.DocRefsKey => AssignDocRefs(reader, ref docRefs),
                _ => throw new CborContentException($"Unknown oId map key {key}.")
            };
        }

        reader.ReadEndMap();

        if(id is null)
        {
            CborThrowHelper.ThrowMissingRequiredMapKey(CBAdESObjectIdentifier.IdKey);
        }

        return new CBAdESObjectIdentifier(id!, desc, docRefs);

        static bool AssignId(CborReader reader, ref Uri? id)
        {
            id = reader.ReadUri();
            return true;
        }

        static bool AssignDesc(CborReader reader, ref string? desc)
        {
            desc = reader.ReadTextString();
            return true;
        }

        static bool AssignDocRefs(CborReader reader, ref List<Uri>? docRefs)
        {
            int entryCount = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var refs = new List<Uri>(Math.Min(entryCount, 64));
            for(int i = 0; i < entryCount; i++)
            {
                refs.Add(reader.ReadUri());
            }

            reader.ReadEndArray();
            docRefs = refs;
            return true;
        }
    }


    /// <summary>
    /// Encodes a <c>pkiOb</c> shared-syntax value (<see cref="CBAdESPkiObject"/>) to canonical CBOR.
    /// </summary>
    /// <param name="pkiObject">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>pkiOb</c> map.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.4.2, Table 12</see>.
    /// </remarks>
    public static PooledMemory EncodePkiObject(CBAdESPkiObject pkiObject, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pkiObject);
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        WritePkiObject(writer, pkiObject);

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into a <c>pkiOb</c> shared-syntax value (<see cref="CBAdESPkiObject"/>).
    /// Fails closed: malformed or non-conformant input returns <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>pkiOb</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.4.2, Table 12</see>.
    /// </remarks>
    public static bool TryParsePkiObject(ReadOnlyMemory<byte> encoded, out CBAdESPkiObject? result)
    {
        try
        {
            var reader = new CborReader(encoded, CborConformanceMode.Canonical);
            result = ReadPkiObject(reader);
            if(reader.BytesRemaining != 0)
            {
                result = null;
                return false;
            }

            return true;
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            result = null;
            return false;
        }
    }


    /// <summary>
    /// Writes a <c>pkiOb</c> map (clause 5.4.2, Table 12) to <paramref name="writer"/>. Shared by every
    /// component that embeds a <c>pkiOb</c> (<c>srAts.certified</c>'s <c>x509AttrCert</c>/<c>otherAttrCert</c>).
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="pkiObject">The value to write.</param>
    private static void WritePkiObject(CborWriter writer, CBAdESPkiObject pkiObject)
    {
        int memberCount = 1
            + (pkiObject.Encoding is not null ? 1 : 0)
            + (pkiObject.SpecRef is not null ? 1 : 0);

        writer.WriteStartMap(memberCount);

        writer.WriteInt32(CBAdESPkiObject.ValKey);
        writer.WriteByteString(pkiObject.Val.Span);

        if(pkiObject.Encoding is not null)
        {
            writer.WriteInt32(CBAdESPkiObject.EncodingKey);
            writer.WriteUri(pkiObject.Encoding);
        }

        if(pkiObject.SpecRef is not null)
        {
            writer.WriteInt32(CBAdESPkiObject.SpecRefKey);
            writer.WriteUri(pkiObject.SpecRef);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Reads a <c>pkiOb</c> map (clause 5.4.2, Table 12) from <paramref name="reader"/>. Shared by every
    /// component that embeds a <c>pkiOb</c>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the map is malformed or the required <c>val</c> member is absent.
    /// </exception>
    private static CBAdESPkiObject ReadPkiObject(CborReader reader)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 3);

        byte[]? val = null;
        Uri? encoding = null;
        Uri? specRef = null;
        int previousKey = 0;

        for(int i = 0; i < count; i++)
        {
            int key = reader.ReadAscendingMapKey(ref previousKey);

            _ = key switch
            {
                CBAdESPkiObject.ValKey => AssignVal(reader, ref val),
                CBAdESPkiObject.EncodingKey => AssignEncoding(reader, ref encoding),
                CBAdESPkiObject.SpecRefKey => AssignSpecRef(reader, ref specRef),
                _ => throw new CborContentException($"Unknown pkiOb map key {key}.")
            };
        }

        reader.ReadEndMap();

        if(val is null)
        {
            CborThrowHelper.ThrowMissingRequiredMapKey(CBAdESPkiObject.ValKey);
        }

        return new CBAdESPkiObject { Val = val!, Encoding = encoding, SpecRef = specRef };

        static bool AssignVal(CborReader reader, ref byte[]? val)
        {
            val = reader.ReadByteString();
            return true;
        }

        static bool AssignEncoding(CborReader reader, ref Uri? encoding)
        {
            encoding = reader.ReadUri();
            return true;
        }

        static bool AssignSpecRef(CborReader reader, ref Uri? specRef)
        {
            specRef = reader.ReadUri();
            return true;
        }
    }


    /// <summary>
    /// Encodes a <c>tstContainer</c> shared-syntax value (<see cref="CBAdESTimestampContainer"/>) to
    /// canonical CBOR.
    /// </summary>
    /// <param name="container">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>tstContainer</c> map.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.4.3.3, Table 13</see>. Also the codec for <c>adoTst</c> (clause
    /// 5.2.6), a straight <c>tstContainer</c> alias — see <see cref="EncodePayloadTimestamp"/>.
    /// </remarks>
    public static PooledMemory EncodeTimestampContainer(CBAdESTimestampContainer container, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(container);
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        WriteTimestampContainer(writer, container);

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into a <c>tstContainer</c> shared-syntax value
    /// (<see cref="CBAdESTimestampContainer"/>). Fails closed: malformed or non-conformant input returns
    /// <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>tstContainer</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.4.3.3, Table 13</see>.
    /// </remarks>
    public static bool TryParseTimestampContainer(ReadOnlyMemory<byte> encoded, out CBAdESTimestampContainer? result)
    {
        try
        {
            var reader = new CborReader(encoded, CborConformanceMode.Canonical);
            result = ReadTimestampContainer(reader);
            if(reader.BytesRemaining != 0)
            {
                result.Dispose();
                result = null;
                return false;
            }

            return true;
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            result = null;
            return false;
        }
    }


    /// <summary>
    /// Writes a <c>tstContainer</c> map (clause 5.4.3.3, Table 13) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="container">The value to write.</param>
    private static void WriteTimestampContainer(CborWriter writer, CBAdESTimestampContainer container)
    {
        writer.WriteStartMap(1);
        writer.WriteInt32(CBAdESTimestampContainer.TstTokensKey);
        writer.WriteStartArray(container.TstTokens.Count);
        foreach(CBAdESTimestampToken token in container.TstTokens)
        {
            WriteToken(writer, token);
        }

        writer.WriteEndArray();
        writer.WriteEndMap();

        static void WriteToken(CborWriter writer, CBAdESTimestampToken token)
        {
            int memberCount = 1
                + (token.Type is not null ? 1 : 0)
                + (token.Encoding is not null ? 1 : 0)
                + (token.SpecRef is not null ? 1 : 0);

            writer.WriteStartMap(memberCount);

            writer.WriteInt32(CBAdESTimestampToken.ValKey);
            writer.WriteByteString(token.Val.Span);

            if(token.Type is not null)
            {
                writer.WriteInt32(CBAdESTimestampToken.TypeKey);
                writer.WriteTextString(token.Type);
            }

            if(token.Encoding is not null)
            {
                writer.WriteInt32(CBAdESTimestampToken.EncodingKey);
                writer.WriteUri(token.Encoding);
            }

            if(token.SpecRef is not null)
            {
                writer.WriteInt32(CBAdESTimestampToken.SpecRefKey);
                writer.WriteUri(token.SpecRef);
            }

            writer.WriteEndMap();
        }
    }


    /// <summary>
    /// Reads a <c>tstContainer</c> map (clause 5.4.3.3, Table 13) from <paramref name="reader"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">Thrown when the map or its token array is malformed.</exception>
    private static CBAdESTimestampContainer ReadTimestampContainer(CborReader reader)
    {
        _ = reader.ReadStartMapExpectLength(1);

        int key = reader.ReadInt32();
        if(key != CBAdESTimestampContainer.TstTokensKey)
        {
            throw new CborContentException($"Expected tstContainer map key {CBAdESTimestampContainer.TstTokensKey}, got {key}.");
        }

        int tokenCount = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
        var tokens = new List<CBAdESTimestampToken>(Math.Min(tokenCount, 64));
        for(int i = 0; i < tokenCount; i++)
        {
            tokens.Add(ReadToken(reader));
        }

        reader.ReadEndArray();
        reader.ReadEndMap();

        return new CBAdESTimestampContainer { TstTokens = tokens };

        static CBAdESTimestampToken ReadToken(CborReader reader)
        {
            int count = reader.ReadStartMapExpectLengthRange(1, 4);

            byte[]? val = null;
            string? type = null;
            Uri? encoding = null;
            Uri? specRef = null;
            int previousKey = 0;

            for(int i = 0; i < count; i++)
            {
                int key = reader.ReadAscendingMapKey(ref previousKey);

                _ = key switch
                {
                    CBAdESTimestampToken.ValKey => AssignVal(reader, ref val),
                    CBAdESTimestampToken.TypeKey => AssignType(reader, ref type),
                    CBAdESTimestampToken.EncodingKey => AssignEncoding(reader, ref encoding),
                    CBAdESTimestampToken.SpecRefKey => AssignSpecRef(reader, ref specRef),
                    _ => throw new CborContentException($"Unknown TstToken map key {key}.")
                };
            }

            reader.ReadEndMap();

            if(val is null)
            {
                CborThrowHelper.ThrowMissingRequiredMapKey(CBAdESTimestampToken.ValKey);
            }

            return new CBAdESTimestampToken { Val = val!, Type = type, Encoding = encoding, SpecRef = specRef };

            static bool AssignVal(CborReader reader, ref byte[]? val)
            {
                val = reader.ReadByteString();
                return true;
            }

            static bool AssignType(CborReader reader, ref string? type)
            {
                type = reader.ReadTextString();
                return true;
            }

            static bool AssignEncoding(CborReader reader, ref Uri? encoding)
            {
                encoding = reader.ReadUri();
                return true;
            }

            static bool AssignSpecRef(CborReader reader, ref Uri? specRef)
            {
                specRef = reader.ReadUri();
                return true;
            }
        }
    }


    /// <summary>
    /// Encodes the <c>x5ts</c> signed header parameter (<see cref="CBAdESCertificateThumbprints"/>,
    /// label <see cref="CBAdESHeaderParameters.X5ts"/>) to canonical CBOR.
    /// </summary>
    /// <param name="thumbprints">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>x5ts</c> array.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.2</see>.
    /// </remarks>
    public static PooledMemory EncodeCertificateThumbprints(CBAdESCertificateThumbprints thumbprints, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(thumbprints);
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(thumbprints.Thumbprints.Count);
        foreach(CBAdESCertificateThumbprint thumbprint in thumbprints.Thumbprints)
        {
            writer.WriteStartArray(2);
            WriteDigestAlgorithmIdentifier(writer, thumbprint.HashAlgorithm);
            writer.WriteByteString(thumbprint.Digest.AsReadOnlySpan());
            writer.WriteEndArray();
        }

        writer.WriteEndArray();

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>x5ts</c> signed header parameter
    /// (<see cref="CBAdESCertificateThumbprints"/>). Fails closed: malformed or non-conformant input
    /// returns <see langword="false"/>, never throws; every digest already constructed before a later
    /// failure is disposed before returning.
    /// </summary>
    /// <param name="encoded">The encoded <c>x5ts</c> array bytes.</param>
    /// <param name="pool">The memory pool each entry's digest buffer is rented from.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.2</see>.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of each digest transfers immediately into the owning CBAdESCertificateThumbprint, appended to thumbprints; the catch block and the trailing-bytes check both dispose every accumulated entry before returning false, and the caller disposes the returned CBAdESCertificateThumbprints on success.")]
    public static bool TryParseCertificateThumbprints(
        ReadOnlyMemory<byte> encoded,
        BaseMemoryPool pool,
        out CBAdESCertificateThumbprints? result)
    {
        ArgumentNullException.ThrowIfNull(pool);

        List<CBAdESCertificateThumbprint>? thumbprints = null;
        try
        {
            var reader = new CborReader(encoded, CborConformanceMode.Canonical);
            int count = reader.ReadStartArrayExpectLengthRange(CBAdESCertificateThumbprints.MinimumThumbprintCount, int.MaxValue);

            thumbprints = new List<CBAdESCertificateThumbprint>(Math.Min(count, 64));
            for(int i = 0; i < count; i++)
            {
                reader.ReadStartArrayExpectLength(2);
                CBAdESDigestAlgorithmIdentifier hashAlgorithm = ReadDigestAlgorithmIdentifier(reader);
                byte[] digestBytes = reader.ReadByteString();
                reader.ReadEndArray();

                DigestValue digest = CreateDigestValue(digestBytes, hashAlgorithm, pool);
                thumbprints.Add(new CBAdESCertificateThumbprint(hashAlgorithm, digest));
            }

            reader.ReadEndArray();

            if(reader.BytesRemaining != 0)
            {
                DisposeAll(thumbprints);
                result = null;
                return false;
            }

            result = new CBAdESCertificateThumbprints(thumbprints);
            return true;
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            DisposeAll(thumbprints);
            result = null;
            return false;
        }

        static void DisposeAll(List<CBAdESCertificateThumbprint>? items)
        {
            if(items is null)
            {
                return;
            }

            foreach(CBAdESCertificateThumbprint item in items)
            {
                item.Dispose();
            }
        }
    }


    /// <summary>
    /// Encodes the <c>srCms</c> signed header parameter (<see cref="CBAdESSignerCommitments"/>, label
    /// <see cref="CBAdESHeaderParameters.SrCms"/>) to canonical CBOR.
    /// </summary>
    /// <param name="commitments">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>srCms</c> array.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.3</see>.
    /// </remarks>
    public static PooledMemory EncodeSignerCommitments(CBAdESSignerCommitments commitments, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(commitments);
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(commitments.Commitments.Count);
        foreach(CBAdESCommitment commitment in commitments.Commitments)
        {
            WriteCommitment(writer, commitment);
        }

        writer.WriteEndArray();

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>srCms</c> signed header parameter
    /// (<see cref="CBAdESSignerCommitments"/>). Fails closed: malformed or non-conformant input returns
    /// <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>srCms</c> array bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.3</see>.
    /// </remarks>
    public static bool TryParseSignerCommitments(ReadOnlyMemory<byte> encoded, out CBAdESSignerCommitments? result)
    {
        try
        {
            var reader = new CborReader(encoded, CborConformanceMode.Canonical);
            int count = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var commitments = new List<CBAdESCommitment>(Math.Min(count, 64));
            for(int i = 0; i < count; i++)
            {
                commitments.Add(ReadCommitment(reader));
            }

            reader.ReadEndArray();

            if(reader.BytesRemaining != 0)
            {
                result = null;
                return false;
            }

            result = new CBAdESSignerCommitments { Commitments = commitments };
            return true;
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            result = null;
            return false;
        }
    }


    /// <summary>
    /// Writes an <c>SrCm</c> map (clause 5.2.3) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="commitment">The value to write.</param>
    private static void WriteCommitment(CborWriter writer, CBAdESCommitment commitment)
    {
        int memberCount = 1 + (commitment.CommitmentQualifiers is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(CBAdESCommitment.CommIdKey);
        WriteObjectIdentifier(writer, commitment.CommitmentId);

        if(commitment.CommitmentQualifiers is not null)
        {
            writer.WriteInt32(CBAdESCommitment.CommQualsKey);
            writer.WriteStartArray(commitment.CommitmentQualifiers.Count);
            foreach(object qualifier in commitment.CommitmentQualifiers)
            {
                CborValueConverter.WriteValue(writer, qualifier);
            }

            writer.WriteEndArray();
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Reads an <c>SrCm</c> map (clause 5.2.3) from <paramref name="reader"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the map is malformed or the required <c>commId</c> member is absent.
    /// </exception>
    private static CBAdESCommitment ReadCommitment(CborReader reader)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 2);

        CBAdESObjectIdentifier? commitmentId = null;
        List<object>? qualifiers = null;
        int previousKey = 0;

        for(int i = 0; i < count; i++)
        {
            int key = reader.ReadAscendingMapKey(ref previousKey);

            _ = key switch
            {
                CBAdESCommitment.CommIdKey => AssignCommitmentId(reader, ref commitmentId),
                CBAdESCommitment.CommQualsKey => AssignQualifiers(reader, ref qualifiers),
                _ => throw new CborContentException($"Unknown SrCm map key {key}.")
            };
        }

        reader.ReadEndMap();

        if(commitmentId is null)
        {
            CborThrowHelper.ThrowMissingRequiredMapKey(CBAdESCommitment.CommIdKey);
        }

        return new CBAdESCommitment(commitmentId!, qualifiers);

        static bool AssignCommitmentId(CborReader reader, ref CBAdESObjectIdentifier? commitmentId)
        {
            commitmentId = ReadObjectIdentifier(reader);
            return true;
        }

        static bool AssignQualifiers(CborReader reader, ref List<object>? qualifiers)
        {
            int count = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var values = new List<object>(Math.Min(count, 64));
            for(int i = 0; i < count; i++)
            {
                values.Add(CborValueConverter.ReadValue(reader)!);
            }

            reader.ReadEndArray();
            qualifiers = values;
            return true;
        }
    }


    /// <summary>
    /// Encodes the <c>sigPl</c> signed header parameter (<see cref="CBAdESSignatureProductionPlace"/>,
    /// label <see cref="CBAdESHeaderParameters.SigPl"/>) to canonical CBOR.
    /// </summary>
    /// <param name="place">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>sigPl</c> map.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when every member of <paramref name="place"/> is <see langword="null"/> (CB-5.2.4-04: <c>sigPl</c>
    /// shall have at least one of its members).
    /// </exception>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.4</see>.
    /// </remarks>
    public static PooledMemory EncodeSignatureProductionPlace(CBAdESSignatureProductionPlace place, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(place);
        ArgumentNullException.ThrowIfNull(pool);

        int memberCount = (place.AddressCountry is not null ? 1 : 0)
            + (place.AddressLocality is not null ? 1 : 0)
            + (place.AddressRegion is not null ? 1 : 0)
            + (place.PostOfficeBoxNumber is not null ? 1 : 0)
            + (place.PostalCode is not null ? 1 : 0)
            + (place.StreetAddress is not null ? 1 : 0);

        if(memberCount == 0)
        {
            throw new ArgumentException(
                "sigPl shall have at least one of its members (ETSI TS 119 152-1 V1.1.1, clause 5.2.4, CB-5.2.4-04).",
                nameof(place));
        }

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(memberCount);

        if(place.AddressCountry is not null)
        {
            writer.WriteInt32(CBAdESSignatureProductionPlace.AddressCountryKey);
            writer.WriteTextString(place.AddressCountry);
        }

        if(place.AddressLocality is not null)
        {
            writer.WriteInt32(CBAdESSignatureProductionPlace.AddressLocalityKey);
            writer.WriteTextString(place.AddressLocality);
        }

        if(place.AddressRegion is not null)
        {
            writer.WriteInt32(CBAdESSignatureProductionPlace.AddressRegionKey);
            writer.WriteTextString(place.AddressRegion);
        }

        if(place.PostOfficeBoxNumber is not null)
        {
            writer.WriteInt32(CBAdESSignatureProductionPlace.PostOfficeBoxNumberKey);
            writer.WriteTextString(place.PostOfficeBoxNumber);
        }

        if(place.PostalCode is not null)
        {
            writer.WriteInt32(CBAdESSignatureProductionPlace.PostalCodeKey);
            writer.WriteTextString(place.PostalCode);
        }

        if(place.StreetAddress is not null)
        {
            writer.WriteInt32(CBAdESSignatureProductionPlace.StreetAddressKey);
            writer.WriteTextString(place.StreetAddress);
        }

        writer.WriteEndMap();

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>sigPl</c> signed header parameter
    /// (<see cref="CBAdESSignatureProductionPlace"/>). Fails closed: malformed, non-conformant, or empty
    /// (CB-5.2.4-04) input returns <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>sigPl</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.4</see>.
    /// </remarks>
    public static bool TryParseSignatureProductionPlace(ReadOnlyMemory<byte> encoded, out CBAdESSignatureProductionPlace? result)
    {
        try
        {
            var reader = new CborReader(encoded, CborConformanceMode.Canonical);
            result = ReadSignatureProductionPlace(reader);
            if(reader.BytesRemaining != 0)
            {
                result = null;
                return false;
            }

            return true;
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            result = null;
            return false;
        }
    }


    /// <summary>
    /// Reads a <c>sigPl</c> map (clause 5.2.4) from <paramref name="reader"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">Thrown when the map is malformed.</exception>
    private static CBAdESSignatureProductionPlace ReadSignatureProductionPlace(CborReader reader)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 6);

        string? addressCountry = null;
        string? addressLocality = null;
        string? addressRegion = null;
        string? postOfficeBoxNumber = null;
        string? postalCode = null;
        string? streetAddress = null;
        int previousKey = 0;

        for(int i = 0; i < count; i++)
        {
            int key = reader.ReadAscendingMapKey(ref previousKey);

            _ = key switch
            {
                CBAdESSignatureProductionPlace.AddressCountryKey => Assign(reader, ref addressCountry),
                CBAdESSignatureProductionPlace.AddressLocalityKey => Assign(reader, ref addressLocality),
                CBAdESSignatureProductionPlace.AddressRegionKey => Assign(reader, ref addressRegion),
                CBAdESSignatureProductionPlace.PostOfficeBoxNumberKey => Assign(reader, ref postOfficeBoxNumber),
                CBAdESSignatureProductionPlace.PostalCodeKey => Assign(reader, ref postalCode),
                CBAdESSignatureProductionPlace.StreetAddressKey => Assign(reader, ref streetAddress),
                _ => throw new CborContentException($"Unknown sigPl map key {key}.")
            };
        }

        reader.ReadEndMap();

        return new CBAdESSignatureProductionPlace
        {
            AddressCountry = addressCountry,
            AddressLocality = addressLocality,
            AddressRegion = addressRegion,
            PostOfficeBoxNumber = postOfficeBoxNumber,
            PostalCode = postalCode,
            StreetAddress = streetAddress
        };

        static bool Assign(CborReader reader, ref string? field)
        {
            field = reader.ReadTextString();
            return true;
        }
    }


    /// <summary>
    /// Encodes the <c>srAts</c> signed header parameter (<see cref="CBAdESSignerAttributes"/>, label
    /// <see cref="CBAdESHeaderParameters.SrAts"/>) to canonical CBOR.
    /// </summary>
    /// <param name="attributes">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>srAts</c> map.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when every member of <paramref name="attributes"/> is <see langword="null"/> (CB-5.2.5-14:
    /// empty <c>srAts</c> shall not be generated).
    /// </exception>
    /// <remarks>
    /// <para>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.5</see>. See the class remarks for the D3 provisional
    /// <c>NotCertifiedItem</c> wire mapping.
    /// </para>
    /// </remarks>
    public static PooledMemory EncodeSignerAttributes(CBAdESSignerAttributes attributes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(attributes);
        ArgumentNullException.ThrowIfNull(pool);

        int memberCount = (attributes.Certified is not null ? 1 : 0)
            + (attributes.SignedAssertions is not null ? 1 : 0)
            + (attributes.Claimed is not null ? 1 : 0);

        if(memberCount == 0)
        {
            throw new ArgumentException(
                "Empty srAts header parameters shall not be generated (ETSI TS 119 152-1 V1.1.1, clause 5.2.5, CB-5.2.5-14).",
                nameof(attributes));
        }

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(memberCount);

        if(attributes.Certified is not null)
        {
            writer.WriteInt32(CBAdESSignerAttributes.CertifiedKey);
            writer.WriteStartArray(attributes.Certified.Count);
            foreach(CBAdESSignerAttributeCertifiedAttribute certified in attributes.Certified)
            {
                WriteCertifiedAttribute(writer, certified);
            }

            writer.WriteEndArray();
        }

        if(attributes.SignedAssertions is not null)
        {
            writer.WriteInt32(CBAdESSignerAttributes.SignedAssertionsKey);
            writer.WriteStartArray(attributes.SignedAssertions.Count);
            foreach(CBAdESSignerAttributeNotCertifiedItem item in attributes.SignedAssertions)
            {
                WriteNotCertifiedItem(writer, item);
            }

            writer.WriteEndArray();
        }

        if(attributes.Claimed is not null)
        {
            writer.WriteInt32(CBAdESSignerAttributes.ClaimedKey);
            writer.WriteStartArray(attributes.Claimed.Count);
            foreach(CBAdESSignerAttributeNotCertifiedItem item in attributes.Claimed)
            {
                WriteNotCertifiedItem(writer, item);
            }

            writer.WriteEndArray();
        }

        writer.WriteEndMap();

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>srAts</c> signed header parameter
    /// (<see cref="CBAdESSignerAttributes"/>). Fails closed: malformed or non-conformant input returns
    /// <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>srAts</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.5</see>. See the class remarks for the D3 provisional
    /// <c>NotCertifiedItem</c> wire mapping.
    /// </remarks>
    public static bool TryParseSignerAttributes(ReadOnlyMemory<byte> encoded, out CBAdESSignerAttributes? result)
    {
        try
        {
            var reader = new CborReader(encoded, CborConformanceMode.Canonical);
            result = ReadSignerAttributes(reader);
            if(reader.BytesRemaining != 0)
            {
                result = null;
                return false;
            }

            return true;
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            result = null;
            return false;
        }
    }


    /// <summary>
    /// Reads an <c>srAts</c> map (clause 5.2.5) from <paramref name="reader"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">Thrown when the map is malformed.</exception>
    private static CBAdESSignerAttributes ReadSignerAttributes(CborReader reader)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 3);

        List<CBAdESSignerAttributeCertifiedAttribute>? certified = null;
        List<CBAdESSignerAttributeNotCertifiedItem>? signedAssertions = null;
        List<CBAdESSignerAttributeNotCertifiedItem>? claimed = null;
        int previousKey = 0;

        for(int i = 0; i < count; i++)
        {
            int key = reader.ReadAscendingMapKey(ref previousKey);

            _ = key switch
            {
                CBAdESSignerAttributes.CertifiedKey => AssignCertified(reader, ref certified),
                CBAdESSignerAttributes.SignedAssertionsKey => AssignSignedAssertions(reader, ref signedAssertions),
                CBAdESSignerAttributes.ClaimedKey => AssignClaimed(reader, ref claimed),
                _ => throw new CborContentException($"Unknown srAts map key {key}.")
            };
        }

        reader.ReadEndMap();

        return new CBAdESSignerAttributes(certified, signedAssertions, claimed);

        static bool AssignCertified(CborReader reader, ref List<CBAdESSignerAttributeCertifiedAttribute>? certified)
        {
            int entryCount = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var entries = new List<CBAdESSignerAttributeCertifiedAttribute>(Math.Min(entryCount, 64));
            for(int i = 0; i < entryCount; i++)
            {
                entries.Add(ReadCertifiedAttribute(reader));
            }

            reader.ReadEndArray();
            certified = entries;
            return true;
        }

        static bool AssignSignedAssertions(CborReader reader, ref List<CBAdESSignerAttributeNotCertifiedItem>? signedAssertions)
        {
            signedAssertions = ReadAttrArrays(reader);
            return true;
        }

        static bool AssignClaimed(CborReader reader, ref List<CBAdESSignerAttributeNotCertifiedItem>? claimed)
        {
            claimed = ReadAttrArrays(reader);
            return true;
        }

        static List<CBAdESSignerAttributeNotCertifiedItem> ReadAttrArrays(CborReader reader)
        {
            int entryCount = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var entries = new List<CBAdESSignerAttributeNotCertifiedItem>(Math.Min(entryCount, 64));
            for(int i = 0; i < entryCount; i++)
            {
                entries.Add(ReadNotCertifiedItem(reader));
            }

            reader.ReadEndArray();
            return entries;
        }
    }


    /// <summary>
    /// Writes a <c>CertifiedAttr</c> one-entry map (clause 5.2.5, <c>CertifiedAttrChoice</c>) to
    /// <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="attribute">The value to write.</param>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="attribute"/> is an unknown arm.</exception>
    private static void WriteCertifiedAttribute(CborWriter writer, CBAdESSignerAttributeCertifiedAttribute attribute)
    {
        (int key, CBAdESPkiObject certificate) = attribute switch
        {
            CBAdESSignerAttributeX509AttributeCertificate x509 =>
                (CBAdESSignerAttributeCertifiedAttribute.X509AttrCertKey, x509.Certificate),
            CBAdESSignerAttributeOtherAttributeCertificate other =>
                (CBAdESSignerAttributeCertifiedAttribute.OtherAttrCertKey, other.Certificate),
            _ => throw new NotSupportedException($"Unknown CertifiedAttrChoice arm '{attribute.GetType()}'.")
        };

        writer.WriteStartMap(1);
        writer.WriteInt32(key);
        WritePkiObject(writer, certificate);
        writer.WriteEndMap();
    }


    /// <summary>
    /// Reads a <c>CertifiedAttr</c> one-entry map (clause 5.2.5, <c>CertifiedAttrChoice</c>) from
    /// <paramref name="reader"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">Thrown when the map key is not a known choice arm.</exception>
    private static CBAdESSignerAttributeCertifiedAttribute ReadCertifiedAttribute(CborReader reader)
    {
        _ = reader.ReadStartMapExpectLength(1);
        int key = reader.ReadInt32();
        CBAdESPkiObject certificate = ReadPkiObject(reader);
        reader.ReadEndMap();

        return key switch
        {
            CBAdESSignerAttributeCertifiedAttribute.X509AttrCertKey => new CBAdESSignerAttributeX509AttributeCertificate(certificate),
            CBAdESSignerAttributeCertifiedAttribute.OtherAttrCertKey => new CBAdESSignerAttributeOtherAttributeCertificate(certificate),
            _ => throw new CborContentException($"Unknown CertifiedAttrChoice map key {key}.")
        };
    }


    /// <summary>
    /// Writes a <c>NotCertifiedItem</c> per this class's D3 provisional wire mapping (see the class
    /// remarks): a 2-element array <c>[mediaType: tstr, qVals: [+any]]</c>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="item">The value to write.</param>
    private static void WriteNotCertifiedItem(CborWriter writer, CBAdESSignerAttributeNotCertifiedItem item)
    {
        writer.WriteStartArray(2);
        writer.WriteTextString(item.MediaType);
        writer.WriteStartArray(item.QualifyingValues.Count);
        foreach(CBAdESSignerAttributeOpaqueQualifyingValue value in item.QualifyingValues)
        {
            writer.WriteEncodedValue(value.EncodedValue.Span);
        }

        writer.WriteEndArray();
        writer.WriteEndArray();
    }


    /// <summary>
    /// Reads a <c>NotCertifiedItem</c> per this class's D3 provisional wire mapping (see the class
    /// remarks). Each opaque qualifying value is a zero-copy slice of <paramref name="reader"/>'s backing
    /// buffer, borrowed for as long as the ultimate <c>TryParse*</c> caller's <c>encoded</c> input stays
    /// alive.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">Thrown when the array is malformed.</exception>
    private static CBAdESSignerAttributeNotCertifiedItem ReadNotCertifiedItem(CborReader reader)
    {
        reader.ReadStartArrayExpectLength(2);
        string mediaType = reader.ReadTextString();

        int valueCount = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
        var values = new List<CBAdESSignerAttributeOpaqueQualifyingValue>(Math.Min(valueCount, 64));
        for(int i = 0; i < valueCount; i++)
        {
            ReadOnlyMemory<byte> encodedValue = reader.ReadEncodedValue();
            values.Add(new CBAdESSignerAttributeOpaqueQualifyingValue(
                CBAdESSignerAttributeOpaqueQualifyingValueKind.Unspecified, encodedValue));
        }

        reader.ReadEndArray();
        reader.ReadEndArray();

        return new CBAdESSignerAttributeNotCertifiedItem { MediaType = mediaType, QualifyingValues = values };
    }


    /// <summary>
    /// Encodes the <c>adoTst</c> signed header parameter (<see cref="CBAdESPayloadTimestamp"/>, label
    /// <see cref="CBAdESHeaderParameters.AdoTst"/>) to canonical CBOR. A straight <c>tstContainer</c> alias
    /// (clause 5.2.6): delegates to <see cref="EncodeTimestampContainer"/>.
    /// </summary>
    /// <param name="timestamp">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>adoTst</c> map.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.6</see>.
    /// </remarks>
    public static PooledMemory EncodePayloadTimestamp(CBAdESPayloadTimestamp timestamp, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(timestamp);
        ArgumentNullException.ThrowIfNull(pool);

        return EncodeTimestampContainer(timestamp.TimestampContainer, pool);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>adoTst</c> signed header parameter
    /// (<see cref="CBAdESPayloadTimestamp"/>). A straight <c>tstContainer</c> alias (clause 5.2.6):
    /// delegates to <see cref="TryParseTimestampContainer"/>. Fails closed: malformed or non-conformant
    /// input returns <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>adoTst</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.6</see>.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of container transfers immediately into the returned CBAdESPayloadTimestamp on success; on failure this method returns before any container is ever constructed.")]
    public static bool TryParsePayloadTimestamp(ReadOnlyMemory<byte> encoded, out CBAdESPayloadTimestamp? result)
    {
        if(!TryParseTimestampContainer(encoded, out CBAdESTimestampContainer? container) || container is null)
        {
            result = null;
            return false;
        }

        result = new CBAdESPayloadTimestamp(container);
        return true;
    }


    /// <summary>
    /// Encodes the <c>sigPId</c> signed header parameter (<see cref="CBAdESSignaturePolicyIdentifier"/>,
    /// label <see cref="CBAdESHeaderParameters.SigPId"/>) to canonical CBOR.
    /// </summary>
    /// <param name="identifier">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>sigPId</c> map.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.7.1</see>.
    /// </remarks>
    public static PooledMemory EncodeSignaturePolicyIdentifier(CBAdESSignaturePolicyIdentifier identifier, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(identifier);
        ArgumentNullException.ThrowIfNull(pool);

        int memberCount = 2
            + (identifier.DigestIsPerSpecification ? 1 : 0)
            + (identifier.Qualifiers is not null ? 1 : 0);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(CBAdESSignaturePolicyIdentifier.IdKey);
        WriteObjectIdentifier(writer, identifier.Id);

        writer.WriteInt32(CBAdESSignaturePolicyIdentifier.DigAlgValKey);
        writer.WriteStartArray(2);
        WriteDigestAlgorithmIdentifier(writer, identifier.HashAlgorithm);
        writer.WriteByteString(identifier.Digest.AsReadOnlySpan());
        writer.WriteEndArray();

        //CB-5.2.7-11: absence of digPSp is equivalent to false, so the default is omitted from the wire.
        if(identifier.DigestIsPerSpecification)
        {
            writer.WriteInt32(CBAdESSignaturePolicyIdentifier.DigPSpKey);
            writer.WriteBoolean(true);
        }

        if(identifier.Qualifiers is not null)
        {
            writer.WriteInt32(CBAdESSignaturePolicyIdentifier.SigPQualsKey);
            writer.WriteStartArray(identifier.Qualifiers.Count);
            foreach(CBAdESSignaturePolicyQualifier qualifier in identifier.Qualifiers)
            {
                WriteSignaturePolicyQualifier(writer, qualifier);
            }

            writer.WriteEndArray();
        }

        writer.WriteEndMap();

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Writes one <c>SigPQual</c> one-entry map (clause 5.2.7.2) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="qualifier">The value to write.</param>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="qualifier"/> is an unknown arm.</exception>
    /// <remarks>
    /// <strong>D11 (contract R-6, RULED):</strong> each <c>SigPQual</c> is written as a one-entry map keyed
    /// per Table 6 (clause 5.2.7.2) — <c>spURI</c>/<c>spUserNotice</c>/<c>spDSpec</c> use their fixed
    /// integer key (1/2/3 respectively); <c>otherQuals</c> uses the qualifier's own
    /// <see cref="CBAdESSignaturePolicyOtherQualifier.Label"/> as the map's single key, never a literal key
    /// <c>4</c>. See the D11 remarks on <see cref="CBAdESSignaturePolicyQualifier"/> for the ruling.
    /// </remarks>
    private static void WriteSignaturePolicyQualifier(CborWriter writer, CBAdESSignaturePolicyQualifier qualifier)
    {
        _ = qualifier switch
        {
            CBAdESSignaturePolicyUri spUri => WriteSpUri(writer, spUri),
            CBAdESSignaturePolicyUserNotice userNotice => WriteUserNotice(writer, userNotice),
            CBAdESSignaturePolicyDocumentSpecification docSpec => WriteSpDSpec(writer, docSpec),
            CBAdESSignaturePolicyOtherQualifier other => WriteOtherQualifier(writer, other),
            _ => throw new NotSupportedException($"Unknown SigPQual arm '{qualifier.GetType()}'.")
        };

        static bool WriteSpUri(CborWriter writer, CBAdESSignaturePolicyUri spUri)
        {
            writer.WriteStartMap(1);
            writer.WriteInt32(CBAdESSignaturePolicyQualifier.SpUriKey);
            writer.WriteUri(spUri.Location);
            writer.WriteEndMap();
            return true;
        }

        static bool WriteUserNotice(CborWriter writer, CBAdESSignaturePolicyUserNotice userNotice)
        {
            writer.WriteStartMap(1);
            writer.WriteInt32(CBAdESSignaturePolicyQualifier.SpUserNoticeKey);

            int memberCount = (userNotice.NoticeReference is not null ? 1 : 0) + (userNotice.ExplicitText is not null ? 1 : 0);
            writer.WriteStartMap(memberCount);

            if(userNotice.NoticeReference is not null)
            {
                writer.WriteInt32(CBAdESSignaturePolicyUserNotice.NoticeRefKey);
                WriteNoticeRef(writer, userNotice.NoticeReference);
            }

            if(userNotice.ExplicitText is not null)
            {
                writer.WriteInt32(CBAdESSignaturePolicyUserNotice.ExplTextKey);
                writer.WriteTextString(userNotice.ExplicitText);
            }

            writer.WriteEndMap();
            writer.WriteEndMap();
            return true;
        }

        static void WriteNoticeRef(CborWriter writer, CBAdESSignaturePolicyNoticeReference noticeRef)
        {
            writer.WriteStartMap(2);
            writer.WriteInt32(CBAdESSignaturePolicyNoticeReference.OrgKey);
            writer.WriteTextString(noticeRef.Organization);
            writer.WriteInt32(CBAdESSignaturePolicyNoticeReference.NoticeNumbersKey);
            writer.WriteUInt32Array(noticeRef.NoticeNumbers);
            writer.WriteEndMap();
        }

        static bool WriteSpDSpec(CborWriter writer, CBAdESSignaturePolicyDocumentSpecification docSpec)
        {
            writer.WriteStartMap(1);
            writer.WriteInt32(CBAdESSignaturePolicyQualifier.SpDSpecKey);
            WriteObjectIdentifier(writer, docSpec.Specification);
            writer.WriteEndMap();
            return true;
        }

        static bool WriteOtherQualifier(CborWriter writer, CBAdESSignaturePolicyOtherQualifier other)
        {
            writer.WriteStartMap(1);

            _ = other.Label switch
            {
                CBAdESSignaturePolicyQualifierIntegerLabel intLabel => WriteIntLabel(writer, intLabel),
                CBAdESSignaturePolicyQualifierTextLabel textLabel => WriteTextLabel(writer, textLabel),
                _ => throw new NotSupportedException($"Unknown label arm '{other.Label.GetType()}'.")
            };

            CborValueConverter.WriteValue(writer, other.Value);
            writer.WriteEndMap();
            return true;

            static bool WriteIntLabel(CborWriter writer, CBAdESSignaturePolicyQualifierIntegerLabel intLabel)
            {
                writer.WriteInt32(intLabel.Value);
                return true;
            }

            static bool WriteTextLabel(CborWriter writer, CBAdESSignaturePolicyQualifierTextLabel textLabel)
            {
                writer.WriteTextString(textLabel.Value);
                return true;
            }
        }
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>sigPId</c> signed header parameter
    /// (<see cref="CBAdESSignaturePolicyIdentifier"/>). Fails closed: malformed or non-conformant input
    /// returns <see langword="false"/>, never throws; a digest already constructed before a later failure
    /// is disposed before returning.
    /// </summary>
    /// <param name="encoded">The encoded <c>sigPId</c> map bytes.</param>
    /// <param name="pool">The memory pool the digest's buffer is rented from.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.7.1</see>. CB-5.2.7-12 (<c>digPSp</c> true requires an
    /// <c>spDSpec</c> qualifier) is enforced by <see cref="CBAdESSignaturePolicyIdentifier"/>'s own
    /// constructor, whose <see cref="ArgumentException"/> this method's catch already handles.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of digest transfers immediately into the returned CBAdESSignaturePolicyIdentifier on success; the trailing-bytes check and the catch block both dispose it explicitly on every failure path.")]
    public static bool TryParseSignaturePolicyIdentifier(
        ReadOnlyMemory<byte> encoded,
        BaseMemoryPool pool,
        out CBAdESSignaturePolicyIdentifier? result)
    {
        ArgumentNullException.ThrowIfNull(pool);

        DigestValue? digest = null;
        try
        {
            var reader = new CborReader(encoded, CborConformanceMode.Canonical);
            int count = reader.ReadStartMapExpectLengthRange(2, 4);

            CBAdESObjectIdentifier? id = null;
            CBAdESDigestAlgorithmIdentifier? hashAlgorithm = null;
            bool digestIsPerSpecification = false;
            List<CBAdESSignaturePolicyQualifier>? qualifiers = null;
            int previousKey = 0;

            for(int i = 0; i < count; i++)
            {
                int key = reader.ReadAscendingMapKey(ref previousKey);

                _ = key switch
                {
                    CBAdESSignaturePolicyIdentifier.IdKey => AssignId(reader, ref id),
                    CBAdESSignaturePolicyIdentifier.DigAlgValKey => AssignDigAlgVal(reader, pool, ref hashAlgorithm, ref digest),
                    CBAdESSignaturePolicyIdentifier.DigPSpKey => AssignDigPSp(reader, ref digestIsPerSpecification),
                    CBAdESSignaturePolicyIdentifier.SigPQualsKey => AssignQualifiers(reader, ref qualifiers),
                    _ => throw new CborContentException($"Unknown sigPId map key {key}.")
                };
            }

            reader.ReadEndMap();

            if(id is null || hashAlgorithm is null || digest is null)
            {
                throw new CborContentException("sigPId requires the 'id' (map key 1) and 'digAlgVal' (map key 2) members.");
            }

            if(reader.BytesRemaining != 0)
            {
                digest.Dispose();
                result = null;
                return false;
            }

            result = new CBAdESSignaturePolicyIdentifier(id, hashAlgorithm, digest, digestIsPerSpecification, qualifiers);
            return true;
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            digest?.Dispose();
            result = null;
            return false;
        }

        static bool AssignId(CborReader reader, ref CBAdESObjectIdentifier? id)
        {
            id = ReadObjectIdentifier(reader);
            return true;
        }

        static bool AssignDigAlgVal(CborReader reader, BaseMemoryPool pool, ref CBAdESDigestAlgorithmIdentifier? hashAlgorithm, ref DigestValue? digest)
        {
            reader.ReadStartArrayExpectLength(2);
            hashAlgorithm = ReadDigestAlgorithmIdentifier(reader);
            byte[] digestBytes = reader.ReadByteString();
            reader.ReadEndArray();

            digest = CreateDigestValue(digestBytes, hashAlgorithm, pool);
            return true;
        }

        static bool AssignDigPSp(CborReader reader, ref bool digestIsPerSpecification)
        {
            digestIsPerSpecification = reader.ReadBoolean();
            return true;
        }

        static bool AssignQualifiers(CborReader reader, ref List<CBAdESSignaturePolicyQualifier>? qualifiers)
        {
            int qualifierCount = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var qs = new List<CBAdESSignaturePolicyQualifier>(Math.Min(qualifierCount, 64));
            for(int i = 0; i < qualifierCount; i++)
            {
                qs.Add(ReadSignaturePolicyQualifier(reader));
            }

            reader.ReadEndArray();
            qualifiers = qs;
            return true;
        }
    }


    /// <summary>
    /// Reads one <c>SigPQual</c> one-entry map (clause 5.2.7.2) from <paramref name="reader"/>. The
    /// choice's key may be an integer (the three named arms 1/2/3, or an integer <c>otherQuals</c> label)
    /// or a text string (always an <c>otherQuals</c> label — the named arms never use a text key).
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">Thrown when the map is malformed.</exception>
    /// <remarks>
    /// <strong>D11 (contract R-6, RULED):</strong> a one-entry map's single key is read directly as the
    /// choice discriminator — <c>1</c>/<c>2</c>/<c>3</c> select <c>spURI</c>/<c>spUserNotice</c>/<c>spDSpec</c>
    /// (Table 6, clause 5.2.7.2); any other key (integer or text) is an <c>otherQuals</c> catch-all entry
    /// keyed by its own label, never a literal key <c>4</c>. See the D11 remarks on
    /// <see cref="CBAdESSignaturePolicyQualifier"/> for the ruling.
    /// </remarks>
    private static CBAdESSignaturePolicyQualifier ReadSignaturePolicyQualifier(CborReader reader)
    {
        _ = reader.ReadStartMapExpectLength(1);

        CBAdESSignaturePolicyQualifier result;
        if(reader.PeekState() == CborReaderState.TextString)
        {
            string textLabel = reader.ReadTextString();
            object value = CborValueConverter.ReadValue(reader)!;
            result = new CBAdESSignaturePolicyOtherQualifier(new CBAdESSignaturePolicyQualifierTextLabel(textLabel), value);
        }
        else
        {
            int key = reader.ReadInt32();
            result = key switch
            {
                CBAdESSignaturePolicyQualifier.SpUriKey => new CBAdESSignaturePolicyUri(reader.ReadUri()),
                CBAdESSignaturePolicyQualifier.SpUserNoticeKey => ReadUserNotice(reader),
                CBAdESSignaturePolicyQualifier.SpDSpecKey => new CBAdESSignaturePolicyDocumentSpecification(ReadObjectIdentifier(reader)),
                _ => new CBAdESSignaturePolicyOtherQualifier(
                    new CBAdESSignaturePolicyQualifierIntegerLabel(key), CborValueConverter.ReadValue(reader)!)
            };
        }

        reader.ReadEndMap();
        return result;

        static CBAdESSignaturePolicyUserNotice ReadUserNotice(CborReader reader)
        {
            int count = reader.ReadStartMapExpectLengthRange(1, 2);

            CBAdESSignaturePolicyNoticeReference? noticeReference = null;
            string? explicitText = null;
            int previousKey = 0;

            for(int i = 0; i < count; i++)
            {
                int key = reader.ReadAscendingMapKey(ref previousKey);

                _ = key switch
                {
                    CBAdESSignaturePolicyUserNotice.NoticeRefKey => AssignNoticeRef(reader, ref noticeReference),
                    CBAdESSignaturePolicyUserNotice.ExplTextKey => AssignExplicitText(reader, ref explicitText),
                    _ => throw new CborContentException($"Unknown SpUserNotice map key {key}.")
                };
            }

            reader.ReadEndMap();

            return new CBAdESSignaturePolicyUserNotice { NoticeReference = noticeReference, ExplicitText = explicitText };

            static bool AssignNoticeRef(CborReader reader, ref CBAdESSignaturePolicyNoticeReference? noticeReference)
            {
                noticeReference = ReadNoticeRef(reader);
                return true;
            }

            static bool AssignExplicitText(CborReader reader, ref string? explicitText)
            {
                explicitText = reader.ReadTextString();
                return true;
            }

            static CBAdESSignaturePolicyNoticeReference ReadNoticeRef(CborReader reader)
            {
                _ = reader.ReadStartMapExpectLength(2);

                int orgKey = reader.ReadInt32();
                if(orgKey != CBAdESSignaturePolicyNoticeReference.OrgKey)
                {
                    throw new CborContentException($"Expected NoticeRef map key {CBAdESSignaturePolicyNoticeReference.OrgKey}, got {orgKey}.");
                }

                string organization = reader.ReadTextString();

                int numbersKey = reader.ReadInt32();
                if(numbersKey != CBAdESSignaturePolicyNoticeReference.NoticeNumbersKey)
                {
                    throw new CborContentException(
                        $"Expected NoticeRef map key {CBAdESSignaturePolicyNoticeReference.NoticeNumbersKey}, got {numbersKey}.");
                }

                List<uint> noticeNumbers = reader.ReadUInt32Array();

                reader.ReadEndMap();

                return new CBAdESSignaturePolicyNoticeReference { Organization = organization, NoticeNumbers = noticeNumbers };
            }
        }
    }


    /// <summary>
    /// Encodes the <c>sigD</c> signed header parameter (<see cref="CBAdESDetachedObjects"/>, label
    /// <see cref="CBAdESHeaderParameters.SigD"/>) to canonical CBOR. See the class remarks for the wire
    /// projection of the model's single entry list onto the wire's <c>pars</c>/<c>hashV</c>/<c>ctys</c>
    /// parallel arrays.
    /// </summary>
    /// <param name="detachedObjects">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>sigD</c> map.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when some but not all entries carry a digest (CB-5.2.8-21).
    /// </exception>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.8.1</see>.
    /// </remarks>
    public static PooledMemory EncodeDetachedObjects(CBAdESDetachedObjects detachedObjects, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(detachedObjects);
        ArgumentNullException.ThrowIfNull(pool);

        bool anyDigest = false;
        bool allDigest = true;
        bool anyContentType = false;
        foreach(CBAdESDetachedObjectEntry entry in detachedObjects.DetachedObjects)
        {
            if(entry.Digest is not null)
            {
                anyDigest = true;
            }
            else
            {
                allDigest = false;
            }

            if(entry.ContentType is not null)
            {
                anyContentType = true;
            }
        }

        if(anyDigest && !allDigest)
        {
            throw new ArgumentException(
                "sigD's hashV, when present, shall carry a digest for every pars element (ETSI TS 119 152-1 V1.1.1, " +
                "clause 5.2.8.1, CB-5.2.8-21); some entries are missing a digest.",
                nameof(detachedObjects));
        }

        int memberCount = 2 + (anyDigest ? 2 : 0) + (anyContentType ? 1 : 0);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(CBAdESDetachedObjects.MechanismIdentifierKey);
        writer.WriteTag(CborTag.Uri);
        writer.WriteTextString(detachedObjects.MechanismIdentifier);

        writer.WriteInt32(CBAdESDetachedObjects.ReferencesKey);
        writer.WriteStartArray(detachedObjects.DetachedObjects.Count);
        foreach(CBAdESDetachedObjectEntry entry in detachedObjects.DetachedObjects)
        {
            writer.WriteTextString(entry.Reference);
        }

        writer.WriteEndArray();

        if(anyDigest)
        {
            writer.WriteInt32(CBAdESDetachedObjects.DigestAlgorithmKey);
            WriteDigestAlgorithmIdentifier(writer, detachedObjects.HashAlgorithm!);

            writer.WriteInt32(CBAdESDetachedObjects.DigestValuesKey);
            writer.WriteStartArray(detachedObjects.DetachedObjects.Count);
            foreach(CBAdESDetachedObjectEntry entry in detachedObjects.DetachedObjects)
            {
                writer.WriteByteString(entry.Digest!.AsReadOnlySpan());
            }

            writer.WriteEndArray();
        }

        if(anyContentType)
        {
            writer.WriteInt32(CBAdESDetachedObjects.ContentTypesKey);
            writer.WriteStartArray(detachedObjects.DetachedObjects.Count);
            foreach(CBAdESDetachedObjectEntry entry in detachedObjects.DetachedObjects)
            {
                if(entry.ContentType is null)
                {
                    writer.WriteNull();
                }
                else
                {
                    writer.WriteTextString(entry.ContentType);
                }
            }

            writer.WriteEndArray();
        }

        writer.WriteEndMap();

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>sigD</c> signed header parameter
    /// (<see cref="CBAdESDetachedObjects"/>). Fails closed: malformed, non-conformant, or length-mismatched
    /// (CB-5.2.8-21/24) input returns <see langword="false"/>, never throws; every digest already
    /// constructed before a later failure is disposed before returning.
    /// </summary>
    /// <param name="encoded">The encoded <c>sigD</c> map bytes.</param>
    /// <param name="pool">The memory pool each entry's digest buffer is rented from.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.8.1</see>.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of each digest transfers immediately into the owning CBAdESDetachedObjectEntry, appended to entries; the trailing-bytes check and the catch block both dispose every accumulated entry before returning false, and the caller disposes the returned CBAdESDetachedObjects on success.")]
    public static bool TryParseDetachedObjects(
        ReadOnlyMemory<byte> encoded,
        BaseMemoryPool pool,
        out CBAdESDetachedObjects? result)
    {
        ArgumentNullException.ThrowIfNull(pool);

        List<CBAdESDetachedObjectEntry>? entries = null;
        try
        {
            var reader = new CborReader(encoded, CborConformanceMode.Canonical);
            int count = reader.ReadStartMapExpectLengthRange(2, 5);

            string? mechanismIdentifier = null;
            List<string>? references = null;
            CBAdESDigestAlgorithmIdentifier? hashAlgorithm = null;
            List<byte[]>? digestValues = null;
            List<string?>? contentTypes = null;
            int previousKey = 0;

            for(int i = 0; i < count; i++)
            {
                int key = reader.ReadAscendingMapKey(ref previousKey);

                _ = key switch
                {
                    CBAdESDetachedObjects.MechanismIdentifierKey => AssignMechanismIdentifier(reader, ref mechanismIdentifier),
                    CBAdESDetachedObjects.ReferencesKey => AssignReferences(reader, ref references),
                    CBAdESDetachedObjects.DigestAlgorithmKey => AssignDigestAlgorithm(reader, ref hashAlgorithm),
                    CBAdESDetachedObjects.DigestValuesKey => AssignDigestValues(reader, ref digestValues),
                    CBAdESDetachedObjects.ContentTypesKey => AssignContentTypes(reader, ref contentTypes),
                    _ => throw new CborContentException($"Unknown sigD map key {key}.")
                };
            }

            reader.ReadEndMap();

            if(mechanismIdentifier is null || references is null || references.Count == 0)
            {
                throw new CborContentException("sigD requires the 'mId' (map key 1) and a non-empty 'pars' (map key 2) member.");
            }

            if((hashAlgorithm is null) != (digestValues is null))
            {
                throw new CborContentException(
                    "sigD's 'hashM' and 'hashV' members shall be present together, or absent together (CB-5.2.8-20/22).");
            }

            if(digestValues is not null && digestValues.Count != references.Count)
            {
                throw new CborContentException("sigD's 'hashV' shall have exactly as many elements as 'pars' (CB-5.2.8-21).");
            }

            if(contentTypes is not null && contentTypes.Count != references.Count)
            {
                throw new CborContentException("sigD's 'ctys' shall have exactly as many elements as 'pars' (CB-5.2.8-24).");
            }

            entries = new List<CBAdESDetachedObjectEntry>(references.Count);
            for(int i = 0; i < references.Count; i++)
            {
                DigestValue? digest = null;
                if(digestValues is not null)
                {
                    digest = CreateDigestValue(digestValues[i], hashAlgorithm!, pool);
                }

                string? contentType = contentTypes is not null ? contentTypes[i] : null;
                try
                {
                    entries.Add(new CBAdESDetachedObjectEntry(references[i], digest, contentType));
                }
                catch
                {
                    //The entry's constructor validates 'reference' before taking ownership of 'digest'; on a
                    //throw here 'digest' was never appended to 'entries', so it would otherwise escape the
                    //DisposeAll sweep below (safety-1).
                    digest?.Dispose();
                    throw;
                }
            }

            if(reader.BytesRemaining != 0)
            {
                DisposeAll(entries);
                result = null;
                return false;
            }

            result = new CBAdESDetachedObjects(mechanismIdentifier, entries, hashAlgorithm);
            return true;
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            DisposeAll(entries);
            result = null;
            return false;
        }

        static void DisposeAll(List<CBAdESDetachedObjectEntry>? items)
        {
            if(items is null)
            {
                return;
            }

            foreach(CBAdESDetachedObjectEntry item in items)
            {
                item.Dispose();
            }
        }

        static bool AssignMechanismIdentifier(CborReader reader, ref string? mechanismIdentifier)
        {
            CborTag tag = reader.ReadTag();
            if(tag != CborTag.Uri)
            {
                throw new CborContentException($"Expected CBOR tag {(ulong)CborTag.Uri} (URI) for sigD's mId, but got tag {(ulong)tag}.");
            }

            mechanismIdentifier = reader.ReadTextString();
            return true;
        }

        static bool AssignReferences(CborReader reader, ref List<string>? references)
        {
            int count = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var refs = new List<string>(Math.Min(count, 64));
            for(int i = 0; i < count; i++)
            {
                refs.Add(reader.ReadTextString());
            }

            reader.ReadEndArray();
            references = refs;
            return true;
        }

        static bool AssignDigestAlgorithm(CborReader reader, ref CBAdESDigestAlgorithmIdentifier? hashAlgorithm)
        {
            hashAlgorithm = ReadDigestAlgorithmIdentifier(reader);
            return true;
        }

        static bool AssignDigestValues(CborReader reader, ref List<byte[]>? digestValues)
        {
            int count = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var values = new List<byte[]>(Math.Min(count, 64));
            for(int i = 0; i < count; i++)
            {
                values.Add(reader.ReadByteString());
            }

            reader.ReadEndArray();
            digestValues = values;
            return true;
        }

        static bool AssignContentTypes(CborReader reader, ref List<string?>? contentTypes)
        {
            int count = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var types = new List<string?>(Math.Min(count, 64));
            for(int i = 0; i < count; i++)
            {
                types.Add(reader.PeekState() == CborReaderState.Null ? ReadNull(reader) : reader.ReadTextString());
            }

            reader.ReadEndArray();
            contentTypes = types;
            return true;

            static string? ReadNull(CborReader reader)
            {
                reader.ReadNull();
                return null;
            }
        }
    }
}
