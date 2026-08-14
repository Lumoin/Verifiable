using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Globalization;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;

namespace Verifiable.Cbor;

/// <summary>
/// CBOR encode/parse bindings for the CB-AdES vocabulary — the seven new signed header
/// parameters (clause 5.2), the clause 5.4 shared syntax types (<c>oId</c>, <c>pkiOb</c>, <c>tstContainer</c>/
/// <c>TstToken</c>), <c>adoTst</c> (clause 5.2.6, a straight <c>tstContainer</c> alias), the clause 5.3
/// unsigned components (<c>uHeaders</c>, <c>sigPSt</c>, <c>sigTst</c>, <c>valData</c>, <c>arcTst</c>), and
/// Annex A's <c>refs</c>/<c>sigRTst</c>/<c>rfsTst</c> — per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>. The typed models this class encodes/parses live in
/// <see cref="Verifiable.Cryptography.Pki"/> (<c>CBAdES*</c>); the CDDL
/// derivation for each is documented on the model type itself.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors <see cref="CoseSerialization"/>'s shape: static methods, <see cref="CborConformanceMode.Canonical"/>
/// throughout — both to write deterministic (RFC 8949 §4.2) CBOR and, on the parse side, to get the
/// framework's own definite-length/minimal-encoding validation for free, satisfying this library's
/// own strict-conformance posture with less hand-written validation. Every <c>TryParse*</c> method
/// additionally checks ascending (canonical) map-key order via
/// <see cref="CborReaderExtensions.ReadAscendingMapKey"/>, which <see cref="CborReader"/>'s conformance-mode
/// validation does not itself enforce on read.
/// </para>
/// <para>
/// <strong>Encode carrier.</strong> Every <c>Encode*</c> method returns a <see cref="PooledMemory"/> — the
/// general-purpose, pool-rented, tagged byte-buffer carrier (<c>Verifiable.Foundation</c>) — rather than a
/// naked <c>byte[]</c>, so the encoded bytes carry CBOM/OTel provenance like every other encoded wire form
/// in this library (<see cref="CoseSerialization.SerializeCoseSign1"/>'s own "route the encoded bytes
/// through the pool" comment). None of the CB-AdES component values are RFC 8949 §3.4.5.1 Tag-24
/// "encoded CBOR data item" wrappers on the wire — clause 4.7's "encapsulation in CBOR byte strings"
/// resolves, for every type this class encodes, to a plain <c>bstr</c> field holding raw (frequently DER) bytes,
/// never a CBOR-in-<c>bstr</c> wrapper — so <see cref="EncodedCborItem"/> (a Tag-24-specific carrier) does
/// not fit these shapes; <see cref="PooledMemory"/> is the reusable, tag-agnostic carrier this codebase
/// already has for "a pooled, tagged, disposable byte buffer with no domain shape of its own."
/// </para>
/// <para>
/// <strong>Parse fail-closed convention.</strong> Every <c>TryParse*</c> method returns <see langword="false"/>
/// for malformed, non-conformant, or truncated input; it never throws for untrusted bytes, mirroring
/// the <see cref="CoseVerification"/> exemplar. The catch-filter is centralized as
/// <see cref="IsFailClosedParseException"/>. A <c>TryParse*</c> method that owns a <see cref="DigestValue"/>
/// mid-parse (<c>x5ts</c>, <c>sigPId</c>, <c>sigD</c>) disposes every already-constructed digest before
/// returning <see langword="false"/>, so a malformed tail never leaks a pool rental.
/// </para>
/// <para>
/// <strong>Depth/size bounds.</strong> Every reader below is an iterative loop over a definite-length CBOR
/// array/map (no recursive descent of this class's own authorship); the one place this class reads a
/// genuinely open-ended CBOR value (<c>srCms.commQuals</c>, <c>sigPQual.otherQuals</c>'s <c>value: any</c>)
/// delegates to the existing <see cref="CborValueConverter.ReadValue(CborReader)"/>, matching the same
/// convention <see cref="CoseSerialization"/> already uses for open-ended COSE header content. List
/// pre-allocation from an untrusted declared length is capped (<c>Math.Min(count, 64)</c>) so a hostile
/// declared count cannot force a large up-front allocation before any bytes are actually read.
/// </para>
/// <para>
/// <strong>Provisional wire mapping:</strong> <c>srAts</c>'s <c>NotCertifiedItem</c> CDDL
/// is internally inconsistent with its own prose (see the remarks on
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
    /// CBOR input that every <c>TryParse*</c> method in this class catches to fail closed, per this library's
    /// strict conformance rule (parsing never throws for malformed input).
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
    /// 5.2.8.1) — see <see cref="AdESDigestAlgorithmIdentifier"/>.
    /// </param>
    /// <param name="pool">The memory pool the digest's buffer is rented from.</param>
    /// <returns>The owned <see cref="DigestValue"/>.</returns>
    private static DigestValue CreateDigestValue(byte[] digestBytes, AdESDigestAlgorithmIdentifier coseHashAlgorithm, BaseMemoryPool pool)
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
    private static Tag ResolveDigestTag(AdESDigestAlgorithmIdentifier coseHashAlgorithm) => coseHashAlgorithm switch
    {
        AdESDigestAlgorithmIntegerIdentifier { Value: WellKnownCoseAlgorithms.Sha256 } => CryptoTags.Sha256Digest,
        AdESDigestAlgorithmIntegerIdentifier { Value: WellKnownCoseAlgorithms.Sha384 } => CryptoTags.Sha384Digest,
        AdESDigestAlgorithmIntegerIdentifier { Value: WellKnownCoseAlgorithms.Sha512 } => CryptoTags.Sha512Digest,
        AdESDigestAlgorithmIntegerIdentifier or AdESDigestAlgorithmTextIdentifier => Tag.Create(Purpose.Digest).With(EncodingScheme.Raw),
        _ => throw new NotSupportedException($"Unknown digest-algorithm identifier arm '{coseHashAlgorithm.GetType()}'.")
    };


    /// <summary>
    /// Writes a digest-algorithm identifier (<see cref="AdESDigestAlgorithmIdentifier"/>) to
    /// <paramref name="writer"/> per the CDDL's <c>int / tstr</c> union: the STORED identifier is written
    /// exactly as constructed — the <see langword="int"/> arm as a CBOR integer, the <see langword="string"/>
    /// arm as a CBOR text string — so any registered IANA COSE Algorithms identifier round-trips byte-exactly
    /// regardless of which arm a producer chose.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="identifier">The value to write.</param>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="identifier"/> is an unknown arm.</exception>
    private static void WriteDigestAlgorithmIdentifier(CborWriter writer, AdESDigestAlgorithmIdentifier identifier)
    {
        _ = identifier switch
        {
            AdESDigestAlgorithmIntegerIdentifier integerIdentifier => WriteInteger(writer, integerIdentifier),
            AdESDigestAlgorithmTextIdentifier textIdentifier => WriteText(writer, textIdentifier),
            _ => throw new NotSupportedException($"Unknown digest-algorithm identifier arm '{identifier.GetType()}'.")
        };

        static bool WriteInteger(CborWriter writer, AdESDigestAlgorithmIntegerIdentifier integerIdentifier)
        {
            writer.WriteInt32(integerIdentifier.Value);
            return true;
        }

        static bool WriteText(CborWriter writer, AdESDigestAlgorithmTextIdentifier textIdentifier)
        {
            writer.WriteTextString(textIdentifier.Value);
            return true;
        }
    }


    /// <summary>
    /// Reads a digest-algorithm identifier (<see cref="AdESDigestAlgorithmIdentifier"/>) from
    /// <paramref name="reader"/> per the CDDL's <c>int / tstr</c> union, accepting either arm — the CDDL does
    /// not narrow this to <see langword="int"/> at any of its three sites (clause 5.1.7/5.2.7.1/5.2.8.1).
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed identifier, holding whichever arm was on the wire.</returns>
    private static AdESDigestAlgorithmIdentifier ReadDigestAlgorithmIdentifier(CborReader reader) =>
        reader.PeekState() == CborReaderState.TextString
            ? new AdESDigestAlgorithmTextIdentifier(reader.ReadTextString())
            : new AdESDigestAlgorithmIntegerIdentifier(reader.ReadInt32());


    /// <summary>
    /// Writes the shared "digest algorithm + digest value" two-element CBOR array shape this document reuses
    /// under several wire names — <c>COSE_CertHash</c> (<c>x5ts</c>, clause 5.1.7; the <c>x5t</c> member of
    /// Annex A.1.1's <c>CertId</c>) and <c>DigAlgVal</c> (<c>sigPId.digAlgVal</c>, clause 5.2.7.1;
    /// <c>CRLRef.digAlgVal</c>/<c>OCSPRef.digAlgVal</c>, Annex A.1.1) — to <paramref name="writer"/>. Reused
    /// verbatim at every call site rather than duplicated.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="hashAlgorithm">The digest-algorithm identifier (the pair's <c>hashAlg</c> element).</param>
    /// <param name="digest">The digest bytes (the pair's <c>hashValue</c> element).</param>
    /// <remarks>
    /// Widened from <see langword="private"/> to <see langword="internal"/> so
    /// <see cref="CBAdESSignatureSerialization"/> can reuse it for the clause 5.1.7 <c>x5t</c> IETF header,
    /// which shares this exact <c>COSE_CertHash</c> shape but has no dedicated public codec of its own
    /// (only the plural <c>x5ts</c> collection does) — reuse over reinvention.
    /// </remarks>
    internal static void WriteHashAlgorithmDigestPair(CborWriter writer, AdESDigestAlgorithmIdentifier hashAlgorithm, DigestValue digest)
    {
        writer.WriteStartArray(2);
        WriteDigestAlgorithmIdentifier(writer, hashAlgorithm);
        writer.WriteByteString(digest.AsReadOnlySpan());
        writer.WriteEndArray();
    }


    /// <summary>
    /// Reads the shared "digest algorithm + digest value" two-element CBOR array shape (see
    /// <see cref="WriteHashAlgorithmDigestPair"/>) from <paramref name="reader"/>, wrapping the digest bytes in
    /// a pool-rented <see cref="DigestValue"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <param name="pool">The memory pool the digest's buffer is rented from.</param>
    /// <param name="hashAlgorithm">Receives the parsed digest-algorithm identifier.</param>
    /// <param name="digest">Receives the parsed, pool-owned digest.</param>
    /// <remarks>
    /// Widened from <see langword="private"/> to <see langword="internal"/> — see
    /// <see cref="WriteHashAlgorithmDigestPair"/>'s remarks; <see cref="CBAdESSignatureSerialization"/> reuses
    /// this directly against its own live protected-header reader for the <c>x5t</c> IETF header.
    /// </remarks>
    internal static void ReadHashAlgorithmDigestPair(
        CborReader reader,
        BaseMemoryPool pool,
        out AdESDigestAlgorithmIdentifier hashAlgorithm,
        out DigestValue digest)
    {
        reader.ReadStartArrayExpectLength(2);
        hashAlgorithm = ReadDigestAlgorithmIdentifier(reader);
        byte[] digestBytes = reader.ReadByteString();
        reader.ReadEndArray();

        digest = CreateDigestValue(digestBytes, hashAlgorithm, pool);
    }


    /// <summary>
    /// Writes a CBOR tag-0 (<c>#6.0(tstr)</c>, RFC 8949 §3.4.1) "tdate" — an RFC 3339 date-time text string —
    /// to <paramref name="writer"/>. Shared by every component that carries a CDDL <c>#6.0(tstr)</c>
    /// member (<c>CRLId.issueTime</c>, <c>OCSPId.producedAt</c>, both Annex A.1.1).
    /// </summary>
    /// <remarks>
    /// Always writes the canonical whole-second, forced-<c>Z</c> form — legal per the CDDL (any RFC 3339
    /// <c>#6.0(tstr)</c> form is), but not the only legal wire shape a <c>tdate</c> may carry: a sub-second or
    /// non-<c>Z</c>-offset form is equally conformant and <see cref="ReadTDate"/> parses it faithfully. This
    /// writer is therefore canonical-on-CREATE only — every element this class builds fresh (signature
    /// creation, or a genuinely NEW unsigned-header element an augmentation verb appends) goes through here,
    /// but an AUGMENTATION verb never re-encodes a RETAINED element through this writer: doing so would
    /// silently collapse a foreign signature's own sub-second/non-<c>Z</c>-offset <c>producedAt</c> to this
    /// writer's normalized form, changing that element's wire bytes and breaking a prior <c>sigRTst</c>/
    /// <c>rfsTst</c> token's message-imprint coverage over it (clause 5.3.1 NOTE 1's imprint-unambiguity
    /// rationale — a defect this writer must never reintroduce). Retained elements instead
    /// survive byte-exact through the raw-splice seam
    /// (<see cref="CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader"/>'s own remarks); preserve-
    /// on-AUGMENT.
    /// </remarks>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="value">The date-time value to write.</param>
    private static void WriteTDate(CborWriter writer, DateTimeOffset value)
    {
        writer.WriteTag(CborTag.DateTimeString);
        writer.WriteTextString(value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture));
    }


    /// <summary>
    /// Reads a CBOR tag-0 (<c>#6.0(tstr)</c>, RFC 8949 §3.4.1) "tdate" from <paramref name="reader"/>. See
    /// <see cref="WriteTDate"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed date-time value.</returns>
    /// <exception cref="CborContentException">Thrown when the current item is not tagged 0.</exception>
    private static DateTimeOffset ReadTDate(CborReader reader)
    {
        CborTag tag = reader.ReadTag();
        if(tag != CborTag.DateTimeString)
        {
            throw new CborContentException($"Expected CBOR tag {(ulong)CborTag.DateTimeString} (tdate, RFC 8949 section 3.4.1), but got tag {(ulong)tag}.");
        }

        string rfc3339 = reader.ReadTextString();
        return DateTimeOffset.Parse(rfc3339, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
    }


    /// <summary>
    /// Writes <paramref name="value"/> as a CBOR tag 32 (<c>#6.32(tstr)</c>, RFC 8949 §3.4.4.4) text string,
    /// verbatim — the exact character sequence supplied, with no <see cref="Uri"/> normalization. Every
    /// identifier-valued member this codec writes through here is carried as <see langword="string"/>, not
    /// <see cref="Uri"/> (<see cref="System.Uri"/> normalizes on
    /// construction, so two spellings differing only by escaping or case would collapse to the same instance).
    /// Shared by every CB-AdES member typed <see langword="string"/> that the CDDL carries as <c>#6.32(tstr)</c>
    /// (<c>oId.id</c>, <c>pkiOb.encoding</c>/<c>specRef</c>, <c>TstToken.encoding</c>/<c>specRef</c>,
    /// <c>SigPQual.spURI</c>).
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="value">The identifier text to write.</param>
    private static void WriteUriText(CborWriter writer, string value)
    {
        writer.WriteTag(CborTag.Uri);
        writer.WriteTextString(value);
    }


    /// <summary>
    /// Reads a CBOR tag 32 (<c>#6.32(tstr)</c>, RFC 8949 §3.4.4.4) text string verbatim, with no
    /// <see cref="Uri"/> parsing/normalization applied. See <see cref="WriteUriText"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The exact character sequence read.</returns>
    /// <exception cref="CborContentException">Thrown when the current item is not tagged 32.</exception>
    private static string ReadUriText(CborReader reader)
    {
        CborTag tag = reader.ReadTag();
        if(tag != CborTag.Uri)
        {
            throw new CborContentException($"Expected CBOR tag {(ulong)CborTag.Uri} (URI), but got tag {(ulong)tag}.");
        }

        return reader.ReadTextString();
    }


    /// <summary>
    /// Encodes an <c>oId</c> shared-syntax value (<see cref="AdESObjectIdentifier"/>) to canonical CBOR.
    /// </summary>
    /// <param name="objectIdentifier">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>oId</c> map.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.4.1, Table 11</see>.
    /// </remarks>
    public static PooledMemory EncodeObjectIdentifier(AdESObjectIdentifier objectIdentifier, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(objectIdentifier);
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        WriteObjectIdentifier(writer, objectIdentifier);

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into an <c>oId</c> shared-syntax value (<see cref="AdESObjectIdentifier"/>).
    /// Fails closed: malformed or non-conformant input returns <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>oId</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.4.1, Table 11</see>.
    /// </remarks>
    public static bool TryParseObjectIdentifier(ReadOnlyMemory<byte> encoded, out AdESObjectIdentifier? result)
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
    private static void WriteObjectIdentifier(CborWriter writer, AdESObjectIdentifier objectIdentifier)
    {
        int memberCount = 1
            + (objectIdentifier.Desc is not null ? 1 : 0)
            + (objectIdentifier.DocRefs is not null ? 1 : 0);

        writer.WriteStartMap(memberCount);

        writer.WriteInt32(CBAdESWireKeys.ObjectIdentifierId);
        WriteUriText(writer, objectIdentifier.Id);

        if(objectIdentifier.Desc is not null)
        {
            writer.WriteInt32(CBAdESWireKeys.ObjectIdentifierDesc);
            writer.WriteTextString(objectIdentifier.Desc);
        }

        if(objectIdentifier.DocRefs is not null)
        {
            writer.WriteInt32(CBAdESWireKeys.ObjectIdentifierDocRefs);
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
    private static AdESObjectIdentifier ReadObjectIdentifier(CborReader reader)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 3);

        string? id = null;
        string? desc = null;
        List<Uri>? docRefs = null;
        int previousKey = 0;

        for(int i = 0; i < count; i++)
        {
            int key = reader.ReadAscendingMapKey(ref previousKey);

            _ = key switch
            {
                CBAdESWireKeys.ObjectIdentifierId => AssignId(reader, ref id),
                CBAdESWireKeys.ObjectIdentifierDesc => AssignDesc(reader, ref desc),
                CBAdESWireKeys.ObjectIdentifierDocRefs => AssignDocRefs(reader, ref docRefs),
                _ => throw new CborContentException($"Unknown oId map key {key}.")
            };
        }

        reader.ReadEndMap();

        if(id is null)
        {
            CborThrowHelper.ThrowMissingRequiredMapKey(CBAdESWireKeys.ObjectIdentifierId);
        }

        return new AdESObjectIdentifier(id!, desc, docRefs);

        static bool AssignId(CborReader reader, ref string? id)
        {
            id = ReadUriText(reader);
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
    /// Encodes a <c>pkiOb</c> shared-syntax value (<see cref="AdESPkiObject"/>) to canonical CBOR.
    /// </summary>
    /// <param name="pkiObject">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>pkiOb</c> map.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.4.2, Table 12</see>.
    /// </remarks>
    public static PooledMemory EncodePkiObject(AdESPkiObject pkiObject, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pkiObject);
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        WritePkiObject(writer, pkiObject);

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into a <c>pkiOb</c> shared-syntax value (<see cref="AdESPkiObject"/>).
    /// Fails closed: malformed or non-conformant input returns <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>pkiOb</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.4.2, Table 12</see>.
    /// </remarks>
    public static bool TryParsePkiObject(ReadOnlyMemory<byte> encoded, out AdESPkiObject? result)
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
    private static void WritePkiObject(CborWriter writer, AdESPkiObject pkiObject)
    {
        int memberCount = 1
            + (pkiObject.Encoding is not null ? 1 : 0)
            + (pkiObject.SpecRef is not null ? 1 : 0);

        writer.WriteStartMap(memberCount);

        writer.WriteInt32(CBAdESWireKeys.PkiObjectVal);
        writer.WriteByteString(pkiObject.Val.Span);

        if(pkiObject.Encoding is not null)
        {
            writer.WriteInt32(CBAdESWireKeys.PkiObjectEncoding);
            WriteUriText(writer, pkiObject.Encoding);
        }

        if(pkiObject.SpecRef is not null)
        {
            writer.WriteInt32(CBAdESWireKeys.PkiObjectSpecRef);
            WriteUriText(writer, pkiObject.SpecRef);
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
    private static AdESPkiObject ReadPkiObject(CborReader reader)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 3);

        byte[]? val = null;
        string? encoding = null;
        string? specRef = null;
        int previousKey = 0;

        for(int i = 0; i < count; i++)
        {
            int key = reader.ReadAscendingMapKey(ref previousKey);

            _ = key switch
            {
                CBAdESWireKeys.PkiObjectVal => AssignVal(reader, ref val),
                CBAdESWireKeys.PkiObjectEncoding => AssignEncoding(reader, ref encoding),
                CBAdESWireKeys.PkiObjectSpecRef => AssignSpecRef(reader, ref specRef),
                _ => throw new CborContentException($"Unknown pkiOb map key {key}.")
            };
        }

        reader.ReadEndMap();

        if(val is null)
        {
            CborThrowHelper.ThrowMissingRequiredMapKey(CBAdESWireKeys.PkiObjectVal);
        }

        return new AdESPkiObject { Val = val!, Encoding = encoding, SpecRef = specRef };

        static bool AssignVal(CborReader reader, ref byte[]? val)
        {
            val = reader.ReadByteString();
            return true;
        }

        static bool AssignEncoding(CborReader reader, ref string? encoding)
        {
            encoding = ReadUriText(reader);
            return true;
        }

        static bool AssignSpecRef(CborReader reader, ref string? specRef)
        {
            specRef = ReadUriText(reader);
            return true;
        }
    }


    /// <summary>
    /// Encodes a <c>tstContainer</c> shared-syntax value (<see cref="AdESTimestampContainer"/>) to
    /// canonical CBOR.
    /// </summary>
    /// <param name="container">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>tstContainer</c> map.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="container"/> carries a non-<see langword="null"/>
    /// <see cref="AdESTimestampContainer.CanonAlg"/> — the CB-AdES <c>tstContainer</c> CDDL has no
    /// <c>canonAlg</c> member (ETSI TS 119 152-1 V1.1.1, clause 5.4.3.3); <c>canonAlg</c> is JAdES-only.
    /// </exception>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.4.3.3, Table 13</see>. Also the codec for <c>adoTst</c> (clause
    /// 5.2.6), a straight <c>tstContainer</c> alias — see <see cref="EncodePayloadTimestamp"/>.
    /// </remarks>
    public static PooledMemory EncodeTimestampContainer(AdESTimestampContainer container, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(container);
        ArgumentNullException.ThrowIfNull(pool);

        if(container.CanonAlg is not null)
        {
            throw new ArgumentException(
                "tstContainer has no 'canonAlg' member on the CB-AdES wire (ETSI TS 119 152-1 V1.1.1, clause " +
                "5.4.3.3, Table 13); 'canonAlg' is JAdES-only.",
                nameof(container));
        }

        var writer = new CborWriter(CborConformanceMode.Canonical);
        WriteTimestampContainer(writer, container);

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into a <c>tstContainer</c> shared-syntax value
    /// (<see cref="AdESTimestampContainer"/>). Fails closed: malformed or non-conformant input returns
    /// <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>tstContainer</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.4.3.3, Table 13</see>.
    /// </remarks>
    public static bool TryParseTimestampContainer(ReadOnlyMemory<byte> encoded, out AdESTimestampContainer? result)
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
    private static void WriteTimestampContainer(CborWriter writer, AdESTimestampContainer container)
    {
        writer.WriteStartMap(1);
        writer.WriteInt32(CBAdESWireKeys.TimestampContainerTstTokens);
        writer.WriteStartArray(container.TstTokens.Count);
        foreach(AdESTimestampToken token in container.TstTokens)
        {
            WriteToken(writer, token);
        }

        writer.WriteEndArray();
        writer.WriteEndMap();

        static void WriteToken(CborWriter writer, AdESTimestampToken token)
        {
            int memberCount = 1
                + (token.Type is not null ? 1 : 0)
                + (token.Encoding is not null ? 1 : 0)
                + (token.SpecRef is not null ? 1 : 0);

            writer.WriteStartMap(memberCount);

            writer.WriteInt32(CBAdESWireKeys.TimestampTokenVal);
            writer.WriteByteString(token.Val.Span);

            if(token.Type is not null)
            {
                writer.WriteInt32(CBAdESWireKeys.TimestampTokenType);
                writer.WriteTextString(token.Type);
            }

            if(token.Encoding is not null)
            {
                writer.WriteInt32(CBAdESWireKeys.TimestampTokenEncoding);
                WriteUriText(writer, token.Encoding);
            }

            if(token.SpecRef is not null)
            {
                writer.WriteInt32(CBAdESWireKeys.TimestampTokenSpecRef);
                WriteUriText(writer, token.SpecRef);
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
    private static AdESTimestampContainer ReadTimestampContainer(CborReader reader)
    {
        _ = reader.ReadStartMapExpectLength(1);

        int key = reader.ReadInt32();
        if(key != CBAdESWireKeys.TimestampContainerTstTokens)
        {
            throw new CborContentException($"Expected tstContainer map key {CBAdESWireKeys.TimestampContainerTstTokens}, got {key}.");
        }

        int tokenCount = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
        var tokens = new List<AdESTimestampToken>(Math.Min(tokenCount, 64));
        for(int i = 0; i < tokenCount; i++)
        {
            tokens.Add(ReadToken(reader));
        }

        reader.ReadEndArray();
        reader.ReadEndMap();

        return new AdESTimestampContainer(tokens);

        static AdESTimestampToken ReadToken(CborReader reader)
        {
            int count = reader.ReadStartMapExpectLengthRange(1, 4);

            byte[]? val = null;
            string? type = null;
            string? encoding = null;
            string? specRef = null;
            int previousKey = 0;

            for(int i = 0; i < count; i++)
            {
                int key = reader.ReadAscendingMapKey(ref previousKey);

                _ = key switch
                {
                    CBAdESWireKeys.TimestampTokenVal => AssignVal(reader, ref val),
                    CBAdESWireKeys.TimestampTokenType => AssignType(reader, ref type),
                    CBAdESWireKeys.TimestampTokenEncoding => AssignEncoding(reader, ref encoding),
                    CBAdESWireKeys.TimestampTokenSpecRef => AssignSpecRef(reader, ref specRef),
                    _ => throw new CborContentException($"Unknown TstToken map key {key}.")
                };
            }

            reader.ReadEndMap();

            if(val is null)
            {
                CborThrowHelper.ThrowMissingRequiredMapKey(CBAdESWireKeys.TimestampTokenVal);
            }

            return new AdESTimestampToken { Val = val!, Type = type, Encoding = encoding, SpecRef = specRef };

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

            static bool AssignEncoding(CborReader reader, ref string? encoding)
            {
                encoding = ReadUriText(reader);
                return true;
            }

            static bool AssignSpecRef(CborReader reader, ref string? specRef)
            {
                specRef = ReadUriText(reader);
                return true;
            }
        }
    }


    /// <summary>
    /// Encodes the <c>x5ts</c> signed header parameter (<see cref="AdESCertificateThumbprints"/>,
    /// label <see cref="CBAdESHeaderParameters.X5ts"/>) to canonical CBOR.
    /// </summary>
    /// <param name="thumbprints">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>x5ts</c> array.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.2</see>.
    /// </remarks>
    public static PooledMemory EncodeCertificateThumbprints(AdESCertificateThumbprints thumbprints, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(thumbprints);
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(thumbprints.Thumbprints.Count);
        foreach(AdESCertificateThumbprint thumbprint in thumbprints.Thumbprints)
        {
            WriteHashAlgorithmDigestPair(writer, thumbprint.HashAlgorithm, thumbprint.Digest);
        }

        writer.WriteEndArray();

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>x5ts</c> signed header parameter
    /// (<see cref="AdESCertificateThumbprints"/>). Fails closed: malformed or non-conformant input
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
        Justification = "Ownership of each digest transfers immediately into the owning AdESCertificateThumbprint, appended to thumbprints; the catch block and the trailing-bytes check both dispose every accumulated entry before returning false, and the caller disposes the returned AdESCertificateThumbprints on success.")]
    public static bool TryParseCertificateThumbprints(
        ReadOnlyMemory<byte> encoded,
        BaseMemoryPool pool,
        out AdESCertificateThumbprints? result)
    {
        ArgumentNullException.ThrowIfNull(pool);

        List<AdESCertificateThumbprint>? thumbprints = null;
        try
        {
            var reader = new CborReader(encoded, CborConformanceMode.Canonical);
            int count = reader.ReadStartArrayExpectLengthRange(AdESCertificateThumbprints.MinimumThumbprintCount, int.MaxValue);

            thumbprints = new List<AdESCertificateThumbprint>(Math.Min(count, 64));
            for(int i = 0; i < count; i++)
            {
                ReadHashAlgorithmDigestPair(reader, pool, out AdESDigestAlgorithmIdentifier hashAlgorithm, out DigestValue digest);
                thumbprints.Add(new AdESCertificateThumbprint(hashAlgorithm, digest));
            }

            reader.ReadEndArray();

            if(reader.BytesRemaining != 0)
            {
                DisposeAll(thumbprints);
                result = null;
                return false;
            }

            result = new AdESCertificateThumbprints(thumbprints);
            return true;
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            DisposeAll(thumbprints);
            result = null;
            return false;
        }

        static void DisposeAll(List<AdESCertificateThumbprint>? items)
        {
            if(items is null)
            {
                return;
            }

            foreach(AdESCertificateThumbprint item in items)
            {
                item.Dispose();
            }
        }
    }


    /// <summary>
    /// Encodes the <c>srCms</c> signed header parameter (<see cref="AdESSignerCommitments"/>, label
    /// <see cref="CBAdESHeaderParameters.SrCms"/>) to canonical CBOR.
    /// </summary>
    /// <param name="commitments">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>srCms</c> array.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.3</see>.
    /// </remarks>
    public static PooledMemory EncodeSignerCommitments(AdESSignerCommitments commitments, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(commitments);
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(commitments.Commitments.Count);
        foreach(AdESCommitment commitment in commitments.Commitments)
        {
            WriteCommitment(writer, commitment);
        }

        writer.WriteEndArray();

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>srCms</c> signed header parameter
    /// (<see cref="AdESSignerCommitments"/>). Fails closed: malformed or non-conformant input returns
    /// <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>srCms</c> array bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.3</see>.
    /// </remarks>
    public static bool TryParseSignerCommitments(ReadOnlyMemory<byte> encoded, out AdESSignerCommitments? result)
    {
        try
        {
            var reader = new CborReader(encoded, CborConformanceMode.Canonical);
            int count = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var commitments = new List<AdESCommitment>(Math.Min(count, 64));
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

            result = new AdESSignerCommitments(commitments);
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
    private static void WriteCommitment(CborWriter writer, AdESCommitment commitment)
    {
        int memberCount = 1 + (commitment.CommitmentQualifiers is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(CBAdESWireKeys.CommitmentCommId);
        WriteObjectIdentifier(writer, commitment.CommitmentId);

        if(commitment.CommitmentQualifiers is not null)
        {
            writer.WriteInt32(CBAdESWireKeys.CommitmentCommQuals);
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
    private static AdESCommitment ReadCommitment(CborReader reader)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 2);

        AdESObjectIdentifier? commitmentId = null;
        List<object>? qualifiers = null;
        int previousKey = 0;

        for(int i = 0; i < count; i++)
        {
            int key = reader.ReadAscendingMapKey(ref previousKey);

            _ = key switch
            {
                CBAdESWireKeys.CommitmentCommId => AssignCommitmentId(reader, ref commitmentId),
                CBAdESWireKeys.CommitmentCommQuals => AssignQualifiers(reader, ref qualifiers),
                _ => throw new CborContentException($"Unknown SrCm map key {key}.")
            };
        }

        reader.ReadEndMap();

        if(commitmentId is null)
        {
            CborThrowHelper.ThrowMissingRequiredMapKey(CBAdESWireKeys.CommitmentCommId);
        }

        return new AdESCommitment(commitmentId!, qualifiers);

        static bool AssignCommitmentId(CborReader reader, ref AdESObjectIdentifier? commitmentId)
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
    /// Encodes the <c>sigPl</c> signed header parameter (<see cref="AdESSignatureProductionPlace"/>,
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
    public static PooledMemory EncodeSignatureProductionPlace(AdESSignatureProductionPlace place, BaseMemoryPool pool)
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
            writer.WriteInt32(CBAdESWireKeys.SignatureProductionPlaceAddressCountry);
            writer.WriteTextString(place.AddressCountry);
        }

        if(place.AddressLocality is not null)
        {
            writer.WriteInt32(CBAdESWireKeys.SignatureProductionPlaceAddressLocality);
            writer.WriteTextString(place.AddressLocality);
        }

        if(place.AddressRegion is not null)
        {
            writer.WriteInt32(CBAdESWireKeys.SignatureProductionPlaceAddressRegion);
            writer.WriteTextString(place.AddressRegion);
        }

        if(place.PostOfficeBoxNumber is not null)
        {
            writer.WriteInt32(CBAdESWireKeys.SignatureProductionPlacePostOfficeBoxNumber);
            writer.WriteTextString(place.PostOfficeBoxNumber);
        }

        if(place.PostalCode is not null)
        {
            writer.WriteInt32(CBAdESWireKeys.SignatureProductionPlacePostalCode);
            writer.WriteTextString(place.PostalCode);
        }

        if(place.StreetAddress is not null)
        {
            writer.WriteInt32(CBAdESWireKeys.SignatureProductionPlaceStreetAddress);
            writer.WriteTextString(place.StreetAddress);
        }

        writer.WriteEndMap();

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>sigPl</c> signed header parameter
    /// (<see cref="AdESSignatureProductionPlace"/>). Fails closed: malformed, non-conformant, or empty
    /// (CB-5.2.4-04) input returns <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>sigPl</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.4</see>.
    /// </remarks>
    public static bool TryParseSignatureProductionPlace(ReadOnlyMemory<byte> encoded, out AdESSignatureProductionPlace? result)
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
    private static AdESSignatureProductionPlace ReadSignatureProductionPlace(CborReader reader)
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
                CBAdESWireKeys.SignatureProductionPlaceAddressCountry => Assign(reader, ref addressCountry),
                CBAdESWireKeys.SignatureProductionPlaceAddressLocality => Assign(reader, ref addressLocality),
                CBAdESWireKeys.SignatureProductionPlaceAddressRegion => Assign(reader, ref addressRegion),
                CBAdESWireKeys.SignatureProductionPlacePostOfficeBoxNumber => Assign(reader, ref postOfficeBoxNumber),
                CBAdESWireKeys.SignatureProductionPlacePostalCode => Assign(reader, ref postalCode),
                CBAdESWireKeys.SignatureProductionPlaceStreetAddress => Assign(reader, ref streetAddress),
                _ => throw new CborContentException($"Unknown sigPl map key {key}.")
            };
        }

        reader.ReadEndMap();

        return new AdESSignatureProductionPlace
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
    /// Encodes the <c>srAts</c> signed header parameter (<see cref="AdESSignerAttributes"/>, label
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
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.5</see>. See the class remarks for the provisional
    /// <c>NotCertifiedItem</c> wire mapping. <paramref name="attributes"/>'s <c>SignedAssertions</c>/
    /// <c>Claimed</c> elements must each be a <see cref="CBAdESSignerAttributeNotCertifiedItem"/> — the only
    /// item shape this method's caller (a CB-AdES builder) ever supplies.
    /// </para>
    /// </remarks>
    public static PooledMemory EncodeSignerAttributes(AdESSignerAttributes attributes, BaseMemoryPool pool)
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
            writer.WriteInt32(CBAdESWireKeys.SignerAttributesCertified);
            writer.WriteStartArray(attributes.Certified.Count);
            foreach(AdESCertifiedAttribute certified in attributes.Certified)
            {
                WriteCertifiedAttribute(writer, certified);
            }

            writer.WriteEndArray();
        }

        if(attributes.SignedAssertions is not null)
        {
            writer.WriteInt32(CBAdESWireKeys.SignerAttributesSignedAssertions);
            writer.WriteStartArray(attributes.SignedAssertions.Count);
            foreach(CBAdESSignerAttributeNotCertifiedItem item in attributes.SignedAssertions)
            {
                WriteNotCertifiedItem(writer, item);
            }

            writer.WriteEndArray();
        }

        if(attributes.Claimed is not null)
        {
            writer.WriteInt32(CBAdESWireKeys.SignerAttributesClaimed);
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
    /// (<see cref="AdESSignerAttributes"/>). Fails closed: malformed or non-conformant input returns
    /// <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>srAts</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.5</see>. See the class remarks for the provisional
    /// <c>NotCertifiedItem</c> wire mapping.
    /// </remarks>
    public static bool TryParseSignerAttributes(ReadOnlyMemory<byte> encoded, out AdESSignerAttributes? result)
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
    private static AdESSignerAttributes ReadSignerAttributes(CborReader reader)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 3);

        List<AdESCertifiedAttribute>? certified = null;
        List<CBAdESSignerAttributeNotCertifiedItem>? signedAssertions = null;
        List<CBAdESSignerAttributeNotCertifiedItem>? claimed = null;
        int previousKey = 0;

        for(int i = 0; i < count; i++)
        {
            int key = reader.ReadAscendingMapKey(ref previousKey);

            _ = key switch
            {
                CBAdESWireKeys.SignerAttributesCertified => AssignCertified(reader, ref certified),
                CBAdESWireKeys.SignerAttributesSignedAssertions => AssignSignedAssertions(reader, ref signedAssertions),
                CBAdESWireKeys.SignerAttributesClaimed => AssignClaimed(reader, ref claimed),
                _ => throw new CborContentException($"Unknown srAts map key {key}.")
            };
        }

        reader.ReadEndMap();

        return new AdESSignerAttributes(certified, signedAssertions, claimed);

        static bool AssignCertified(CborReader reader, ref List<AdESCertifiedAttribute>? certified)
        {
            int entryCount = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var entries = new List<AdESCertifiedAttribute>(Math.Min(entryCount, 64));
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
    private static void WriteCertifiedAttribute(CborWriter writer, AdESCertifiedAttribute attribute)
    {
        (int key, AdESPkiObject certificate) = attribute switch
        {
            AdESX509AttributeCertificate x509 =>
                (CBAdESWireKeys.CertifiedAttributeX509AttrCert, x509.Certificate),
            AdESOtherAttributeCertificate other =>
                (CBAdESWireKeys.CertifiedAttributeOtherAttrCert, other.Certificate),
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
    private static AdESCertifiedAttribute ReadCertifiedAttribute(CborReader reader)
    {
        _ = reader.ReadStartMapExpectLength(1);
        int key = reader.ReadInt32();
        AdESPkiObject certificate = ReadPkiObject(reader);
        reader.ReadEndMap();

        return key switch
        {
            CBAdESWireKeys.CertifiedAttributeX509AttrCert => new AdESX509AttributeCertificate(certificate),
            CBAdESWireKeys.CertifiedAttributeOtherAttrCert => new AdESOtherAttributeCertificate(certificate),
            _ => throw new CborContentException($"Unknown CertifiedAttrChoice map key {key}.")
        };
    }


    /// <summary>
    /// Writes a <c>NotCertifiedItem</c> per this class's provisional wire mapping (see the class
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
    /// Reads a <c>NotCertifiedItem</c> per this class's provisional wire mapping (see the class
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
        if(!TryParseTimestampContainer(encoded, out AdESTimestampContainer? container) || container is null)
        {
            result = null;
            return false;
        }

        result = new CBAdESPayloadTimestamp(container);
        return true;
    }


    /// <summary>
    /// Encodes the <c>sigPId</c> signed header parameter (<see cref="AdESSignaturePolicyIdentifier"/>,
    /// label <see cref="CBAdESHeaderParameters.SigPId"/>) to canonical CBOR.
    /// </summary>
    /// <param name="identifier">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>sigPId</c> map.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <see cref="AdESSignaturePolicyIdentifier.HashAlgorithm"/> or
    /// <see cref="AdESSignaturePolicyIdentifier.Digest"/> is <see langword="null"/> — the CB-AdES <c>sigPId</c>
    /// CDDL's <c>digAlgVal</c> member (Table 5, key 2) carries no <c>?</c> presence marker, so it is mandatory,
    /// and its <c>DigAlgVal</c> shape couples <c>hashAlg</c>/<c>hashValue</c> as one unit (ETSI TS 119 152-1
    /// V1.1.1, clause 5.2.7.1).
    /// </exception>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.7.1</see>.
    /// </remarks>
    public static PooledMemory EncodeSignaturePolicyIdentifier(AdESSignaturePolicyIdentifier identifier, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(identifier);
        ArgumentNullException.ThrowIfNull(pool);

        AdESDigestAlgorithmIdentifier? hashAlgorithm = identifier.HashAlgorithm;
        DigestValue? digest = identifier.Digest;
        if(hashAlgorithm is null || digest is null)
        {
            throw new ArgumentException(
                "sigPId's 'digAlgVal' member is mandatory on the CB-AdES wire (ETSI TS 119 152-1 V1.1.1, clause " +
                "5.2.7.1, Table 5 key 2 carries no '?' presence marker); both 'hashAlg' and 'hashValue' shall " +
                "be present.",
                nameof(identifier));
        }

        int memberCount = 2
            + (identifier.DigestIsPerSpecification ? 1 : 0)
            + (identifier.Qualifiers is not null ? 1 : 0);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(CBAdESWireKeys.SignaturePolicyIdentifierId);
        WriteObjectIdentifier(writer, identifier.Id);

        writer.WriteInt32(CBAdESWireKeys.SignaturePolicyIdentifierDigAlgVal);
        WriteHashAlgorithmDigestPair(writer, hashAlgorithm, digest);

        //CB-5.2.7-11: absence of digPSp is equivalent to false, so the default is omitted from the wire.
        if(identifier.DigestIsPerSpecification)
        {
            writer.WriteInt32(CBAdESWireKeys.SignaturePolicyIdentifierDigPSp);
            writer.WriteBoolean(true);
        }

        if(identifier.Qualifiers is not null)
        {
            writer.WriteInt32(CBAdESWireKeys.SignaturePolicyIdentifierSigPQuals);
            writer.WriteStartArray(identifier.Qualifiers.Count);
            foreach(AdESSignaturePolicyQualifier qualifier in identifier.Qualifiers)
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
    /// Each <c>SigPQual</c> is written as a one-entry map keyed
    /// per Table 6 (clause 5.2.7.2) — <c>spURI</c>/<c>spUserNotice</c>/<c>spDSpec</c> use their fixed
    /// integer key (1/2/3 respectively); <c>otherQuals</c> uses the qualifier's own
    /// <see cref="AdESSignaturePolicyOtherQualifier.Label"/> as the map's single key, never a literal key
    /// <c>4</c>. See the remarks on <see cref="AdESSignaturePolicyQualifier"/> for the reading.
    /// </remarks>
    private static void WriteSignaturePolicyQualifier(CborWriter writer, AdESSignaturePolicyQualifier qualifier)
    {
        _ = qualifier switch
        {
            AdESSignaturePolicyUri spUri => WriteSpUri(writer, spUri),
            AdESSignaturePolicyUserNotice userNotice => WriteUserNotice(writer, userNotice),
            AdESSignaturePolicyDocumentSpecification docSpec => WriteSpDSpec(writer, docSpec),
            AdESSignaturePolicyOtherQualifier other => WriteOtherQualifier(writer, other),
            _ => throw new NotSupportedException($"Unknown SigPQual arm '{qualifier.GetType()}'.")
        };

        static bool WriteSpUri(CborWriter writer, AdESSignaturePolicyUri spUri)
        {
            writer.WriteStartMap(1);
            writer.WriteInt32(CBAdESWireKeys.SignaturePolicyQualifierSpUri);
            WriteUriText(writer, spUri.Location);
            writer.WriteEndMap();
            return true;
        }

        static bool WriteUserNotice(CborWriter writer, AdESSignaturePolicyUserNotice userNotice)
        {
            writer.WriteStartMap(1);
            writer.WriteInt32(CBAdESWireKeys.SignaturePolicyQualifierSpUserNotice);

            int memberCount = (userNotice.NoticeReference is not null ? 1 : 0) + (userNotice.ExplicitText is not null ? 1 : 0);
            writer.WriteStartMap(memberCount);

            if(userNotice.NoticeReference is not null)
            {
                writer.WriteInt32(CBAdESWireKeys.SignaturePolicyUserNoticeNoticeRef);
                WriteNoticeRef(writer, userNotice.NoticeReference);
            }

            if(userNotice.ExplicitText is not null)
            {
                writer.WriteInt32(CBAdESWireKeys.SignaturePolicyUserNoticeExplText);
                writer.WriteTextString(userNotice.ExplicitText);
            }

            writer.WriteEndMap();
            writer.WriteEndMap();
            return true;
        }

        static void WriteNoticeRef(CborWriter writer, AdESSignaturePolicyNoticeReference noticeRef)
        {
            writer.WriteStartMap(2);
            writer.WriteInt32(CBAdESWireKeys.SignaturePolicyNoticeReferenceOrg);
            writer.WriteTextString(noticeRef.Organization);
            writer.WriteInt32(CBAdESWireKeys.SignaturePolicyNoticeReferenceNoticeNumbers);
            writer.WriteUInt32Array(noticeRef.NoticeNumbers);
            writer.WriteEndMap();
        }

        static bool WriteSpDSpec(CborWriter writer, AdESSignaturePolicyDocumentSpecification docSpec)
        {
            writer.WriteStartMap(1);
            writer.WriteInt32(CBAdESWireKeys.SignaturePolicyQualifierSpDSpec);
            WriteObjectIdentifier(writer, docSpec.Specification);
            writer.WriteEndMap();
            return true;
        }

        static bool WriteOtherQualifier(CborWriter writer, AdESSignaturePolicyOtherQualifier other)
        {
            writer.WriteStartMap(1);

            _ = other.Label switch
            {
                AdESSignaturePolicyQualifierIntegerLabel intLabel => WriteIntLabel(writer, intLabel),
                AdESSignaturePolicyQualifierTextLabel textLabel => WriteTextLabel(writer, textLabel),
                _ => throw new NotSupportedException($"Unknown label arm '{other.Label.GetType()}'.")
            };

            CborValueConverter.WriteValue(writer, other.Value);
            writer.WriteEndMap();
            return true;

            static bool WriteIntLabel(CborWriter writer, AdESSignaturePolicyQualifierIntegerLabel intLabel)
            {
                writer.WriteInt32(intLabel.Value);
                return true;
            }

            static bool WriteTextLabel(CborWriter writer, AdESSignaturePolicyQualifierTextLabel textLabel)
            {
                writer.WriteTextString(textLabel.Value);
                return true;
            }
        }
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>sigPId</c> signed header parameter
    /// (<see cref="AdESSignaturePolicyIdentifier"/>). Fails closed: malformed or non-conformant input
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
    /// <c>spDSpec</c> qualifier) is enforced by <see cref="AdESSignaturePolicyIdentifier"/>'s own
    /// constructor, whose <see cref="ArgumentException"/> this method's catch already handles.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of digest transfers immediately into the returned AdESSignaturePolicyIdentifier on success; the trailing-bytes check and the catch block both dispose it explicitly on every failure path.")]
    public static bool TryParseSignaturePolicyIdentifier(
        ReadOnlyMemory<byte> encoded,
        BaseMemoryPool pool,
        out AdESSignaturePolicyIdentifier? result)
    {
        ArgumentNullException.ThrowIfNull(pool);

        DigestValue? digest = null;
        try
        {
            var reader = new CborReader(encoded, CborConformanceMode.Canonical);
            int count = reader.ReadStartMapExpectLengthRange(2, 4);

            AdESObjectIdentifier? id = null;
            AdESDigestAlgorithmIdentifier? hashAlgorithm = null;
            bool digestIsPerSpecification = false;
            List<AdESSignaturePolicyQualifier>? qualifiers = null;
            int previousKey = 0;

            for(int i = 0; i < count; i++)
            {
                int key = reader.ReadAscendingMapKey(ref previousKey);

                _ = key switch
                {
                    CBAdESWireKeys.SignaturePolicyIdentifierId => AssignId(reader, ref id),
                    CBAdESWireKeys.SignaturePolicyIdentifierDigAlgVal => AssignDigAlgVal(reader, pool, ref hashAlgorithm, ref digest),
                    CBAdESWireKeys.SignaturePolicyIdentifierDigPSp => AssignDigPSp(reader, ref digestIsPerSpecification),
                    CBAdESWireKeys.SignaturePolicyIdentifierSigPQuals => AssignQualifiers(reader, ref qualifiers),
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

            result = new AdESSignaturePolicyIdentifier(id, hashAlgorithm, digest, digestIsPerSpecification, qualifiers);
            return true;
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            digest?.Dispose();
            result = null;
            return false;
        }

        static bool AssignId(CborReader reader, ref AdESObjectIdentifier? id)
        {
            id = ReadObjectIdentifier(reader);
            return true;
        }

        static bool AssignDigAlgVal(CborReader reader, BaseMemoryPool pool, ref AdESDigestAlgorithmIdentifier? hashAlgorithm, ref DigestValue? digest)
        {
            ReadHashAlgorithmDigestPair(reader, pool, out AdESDigestAlgorithmIdentifier algorithm, out DigestValue value);
            hashAlgorithm = algorithm;
            digest = value;
            return true;
        }

        static bool AssignDigPSp(CborReader reader, ref bool digestIsPerSpecification)
        {
            digestIsPerSpecification = reader.ReadBoolean();
            return true;
        }

        static bool AssignQualifiers(CborReader reader, ref List<AdESSignaturePolicyQualifier>? qualifiers)
        {
            int qualifierCount = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var qs = new List<AdESSignaturePolicyQualifier>(Math.Min(qualifierCount, 64));
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
    /// A one-entry map's single key is read directly as the
    /// choice discriminator — <c>1</c>/<c>2</c>/<c>3</c> select <c>spURI</c>/<c>spUserNotice</c>/<c>spDSpec</c>
    /// (Table 6, clause 5.2.7.2); any other key (integer or text) is an <c>otherQuals</c> catch-all entry
    /// keyed by its own label, never a literal key <c>4</c>. See the remarks on
    /// <see cref="AdESSignaturePolicyQualifier"/> for the reading.
    /// </remarks>
    private static AdESSignaturePolicyQualifier ReadSignaturePolicyQualifier(CborReader reader)
    {
        _ = reader.ReadStartMapExpectLength(1);

        AdESSignaturePolicyQualifier result;
        if(reader.PeekState() == CborReaderState.TextString)
        {
            string textLabel = reader.ReadTextString();
            object value = CborValueConverter.ReadValue(reader)!;
            result = new AdESSignaturePolicyOtherQualifier(new AdESSignaturePolicyQualifierTextLabel(textLabel), value);
        }
        else
        {
            int key = reader.ReadInt32();
            result = key switch
            {
                CBAdESWireKeys.SignaturePolicyQualifierSpUri => new AdESSignaturePolicyUri(ReadUriText(reader)),
                CBAdESWireKeys.SignaturePolicyQualifierSpUserNotice => ReadUserNotice(reader),
                CBAdESWireKeys.SignaturePolicyQualifierSpDSpec => new AdESSignaturePolicyDocumentSpecification(ReadObjectIdentifier(reader)),
                _ => new AdESSignaturePolicyOtherQualifier(
                    new AdESSignaturePolicyQualifierIntegerLabel(key), CborValueConverter.ReadValue(reader)!)
            };
        }

        reader.ReadEndMap();
        return result;

        static AdESSignaturePolicyUserNotice ReadUserNotice(CborReader reader)
        {
            int count = reader.ReadStartMapExpectLengthRange(1, 2);

            AdESSignaturePolicyNoticeReference? noticeReference = null;
            string? explicitText = null;
            int previousKey = 0;

            for(int i = 0; i < count; i++)
            {
                int key = reader.ReadAscendingMapKey(ref previousKey);

                _ = key switch
                {
                    CBAdESWireKeys.SignaturePolicyUserNoticeNoticeRef => AssignNoticeRef(reader, ref noticeReference),
                    CBAdESWireKeys.SignaturePolicyUserNoticeExplText => AssignExplicitText(reader, ref explicitText),
                    _ => throw new CborContentException($"Unknown SpUserNotice map key {key}.")
                };
            }

            reader.ReadEndMap();

            return new AdESSignaturePolicyUserNotice(noticeReference, explicitText);

            static bool AssignNoticeRef(CborReader reader, ref AdESSignaturePolicyNoticeReference? noticeReference)
            {
                noticeReference = ReadNoticeRef(reader);
                return true;
            }

            static bool AssignExplicitText(CborReader reader, ref string? explicitText)
            {
                explicitText = reader.ReadTextString();
                return true;
            }

            static AdESSignaturePolicyNoticeReference ReadNoticeRef(CborReader reader)
            {
                _ = reader.ReadStartMapExpectLength(2);

                int orgKey = reader.ReadInt32();
                if(orgKey != CBAdESWireKeys.SignaturePolicyNoticeReferenceOrg)
                {
                    throw new CborContentException($"Expected NoticeRef map key {CBAdESWireKeys.SignaturePolicyNoticeReferenceOrg}, got {orgKey}.");
                }

                string organization = reader.ReadTextString();

                int numbersKey = reader.ReadInt32();
                if(numbersKey != CBAdESWireKeys.SignaturePolicyNoticeReferenceNoticeNumbers)
                {
                    throw new CborContentException(
                        $"Expected NoticeRef map key {CBAdESWireKeys.SignaturePolicyNoticeReferenceNoticeNumbers}, got {numbersKey}.");
                }

                List<uint> noticeNumbers = reader.ReadUInt32Array();

                reader.ReadEndMap();

                return new AdESSignaturePolicyNoticeReference(organization, noticeNumbers);
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
            AdESDigestAlgorithmIdentifier? hashAlgorithm = null;
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

        static bool AssignDigestAlgorithm(CborReader reader, ref AdESDigestAlgorithmIdentifier? hashAlgorithm)
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


    /// <summary>
    /// Encodes the <c>sigPSt</c> unsigned header parameter (<see cref="CBAdESSignaturePolicyStore"/>, label
    /// <see cref="CBAdESUnsignedHeaderElement.SignaturePolicyStoreLabel"/>) to canonical CBOR.
    /// </summary>
    /// <param name="signaturePolicyStore">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>sigPSt</c> map.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.3.2, Table 9</see>.
    /// </remarks>
    public static PooledMemory EncodeSignaturePolicyStore(CBAdESSignaturePolicyStore signaturePolicyStore, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(signaturePolicyStore);
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        WriteSignaturePolicyStore(writer, signaturePolicyStore);

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>sigPSt</c> unsigned header parameter
    /// (<see cref="CBAdESSignaturePolicyStore"/>). Fails closed: malformed or non-conformant input returns
    /// <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>sigPSt</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.3.2, Table 9</see>.
    /// </remarks>
    public static bool TryParseSignaturePolicyStore(ReadOnlyMemory<byte> encoded, out CBAdESSignaturePolicyStore? result)
    {
        try
        {
            var reader = new CborReader(encoded, CborConformanceMode.Canonical);
            result = ReadSignaturePolicyStore(reader);
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
    /// Writes a <c>sigPSt</c> map (clause 5.3.2, Table 9) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="signaturePolicyStore">The value to write.</param>
    private static void WriteSignaturePolicyStore(CborWriter writer, CBAdESSignaturePolicyStore signaturePolicyStore)
    {
        int memberCount = 1 + (signaturePolicyStore.SpDSpec is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(CBAdESSignaturePolicyStore.DocOrLocalUriKey);
        WriteSignaturePolicyStoreContent(writer, signaturePolicyStore.Content);

        if(signaturePolicyStore.SpDSpec is not null)
        {
            writer.WriteInt32(CBAdESSignaturePolicyStore.SpDSpecKey);
            WriteObjectIdentifier(writer, signaturePolicyStore.SpDSpec);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes a <c>DocOrLocalURI</c> one-entry map (clause 5.3.2) to <paramref name="writer"/> — the exclusive
    /// choice between the signature policy document itself and a local-store URI.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="content">The value to write.</param>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="content"/> is an unknown arm.</exception>
    private static void WriteSignaturePolicyStoreContent(CborWriter writer, CBAdESSignaturePolicyStoreContent content)
    {
        writer.WriteStartMap(1);

        _ = content switch
        {
            CBAdESSignaturePolicyStoreDocument document => WriteDocument(writer, document),
            CBAdESSignaturePolicyStoreLocalUri localUri => WriteLocalUri(writer, localUri),
            _ => throw new NotSupportedException($"Unknown DocOrLocalURI arm '{content.GetType()}'.")
        };

        writer.WriteEndMap();

        static bool WriteDocument(CborWriter writer, CBAdESSignaturePolicyStoreDocument document)
        {
            writer.WriteInt32(CBAdESSignaturePolicyStoreContent.SigPolDocKey);
            writer.WriteByteString(document.Document.Span);
            return true;
        }

        static bool WriteLocalUri(CborWriter writer, CBAdESSignaturePolicyStoreLocalUri localUri)
        {
            writer.WriteInt32(CBAdESSignaturePolicyStoreContent.SigPolLocalUriKey);
            writer.WriteUri(localUri.Location);
            return true;
        }
    }


    /// <summary>
    /// Reads a <c>sigPSt</c> map (clause 5.3.2, Table 9) from <paramref name="reader"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the map is malformed or the required <c>docOrLocalUri</c> member is absent.
    /// </exception>
    private static CBAdESSignaturePolicyStore ReadSignaturePolicyStore(CborReader reader)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 2);

        CBAdESSignaturePolicyStoreContent? content = null;
        AdESObjectIdentifier? spDSpec = null;
        int previousKey = 0;

        for(int i = 0; i < count; i++)
        {
            int key = reader.ReadAscendingMapKey(ref previousKey);

            _ = key switch
            {
                CBAdESSignaturePolicyStore.DocOrLocalUriKey => AssignContent(reader, ref content),
                CBAdESSignaturePolicyStore.SpDSpecKey => AssignSpDSpec(reader, ref spDSpec),
                _ => throw new CborContentException($"Unknown sigPSt map key {key}.")
            };
        }

        reader.ReadEndMap();

        if(content is null)
        {
            throw new CborContentException("sigPSt requires the 'docOrLocalUri' (map key 1) member.");
        }

        return new CBAdESSignaturePolicyStore(content, spDSpec);

        static bool AssignContent(CborReader reader, ref CBAdESSignaturePolicyStoreContent? content)
        {
            content = ReadSignaturePolicyStoreContent(reader);
            return true;
        }

        static bool AssignSpDSpec(CborReader reader, ref AdESObjectIdentifier? spDSpec)
        {
            spDSpec = ReadObjectIdentifier(reader);
            return true;
        }
    }


    /// <summary>
    /// Reads a <c>DocOrLocalURI</c> one-entry map (clause 5.3.2) from <paramref name="reader"/>. The printed
    /// CDDL carries a stray comma after the group's second arm; this method reads the
    /// prose's "either ... or ..." (CB-5.3.2-01) as an exclusive choice — exactly one entry, never both and
    /// never neither — enforced structurally by requiring the map length to be exactly 1.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">Thrown when the map key is not a known choice arm.</exception>
    private static CBAdESSignaturePolicyStoreContent ReadSignaturePolicyStoreContent(CborReader reader)
    {
        _ = reader.ReadStartMapExpectLength(1);
        int key = reader.ReadInt32();

        CBAdESSignaturePolicyStoreContent result = key switch
        {
            CBAdESSignaturePolicyStoreContent.SigPolDocKey => new CBAdESSignaturePolicyStoreDocument(reader.ReadByteString()),
            CBAdESSignaturePolicyStoreContent.SigPolLocalUriKey => new CBAdESSignaturePolicyStoreLocalUri(reader.ReadUri()),
            _ => throw new CborContentException($"Unknown DocOrLocalURI map key {key}.")
        };

        reader.ReadEndMap();
        return result;
    }


    /// <summary>
    /// Encodes the <c>valData</c> unsigned header parameter (<see cref="CBAdESValidationData"/>, label
    /// <see cref="CBAdESUnsignedHeaderElement.ValidationDataLabel"/>) to canonical CBOR.
    /// </summary>
    /// <param name="validationData">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>valData</c> map.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.3.4, Table 10</see>.
    /// </remarks>
    public static PooledMemory EncodeValidationData(CBAdESValidationData validationData, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(validationData);
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        WriteValidationData(writer, validationData);

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>valData</c> unsigned header parameter
    /// (<see cref="CBAdESValidationData"/>). Fails closed: malformed, non-conformant, or empty-map
    /// (CB-5.3.4-01/02/03) input returns <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>valData</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.3.4, Table 10</see>.
    /// </remarks>
    public static bool TryParseValidationData(ReadOnlyMemory<byte> encoded, out CBAdESValidationData? result)
    {
        try
        {
            var reader = new CborReader(encoded, CborConformanceMode.Canonical);
            result = ReadValidationData(reader);
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
    /// Writes a <c>valData</c> map (clause 5.3.4, Table 10) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="validationData">The value to write.</param>
    private static void WriteValidationData(CborWriter writer, CBAdESValidationData validationData)
    {
        int memberCount = (validationData.CertificateValues is not null ? 1 : 0)
            + (validationData.RevocationValues is not null ? 1 : 0);

        writer.WriteStartMap(memberCount);

        if(validationData.CertificateValues is not null)
        {
            writer.WriteInt32(CBAdESValidationData.XValsKey);
            writer.WriteStartArray(validationData.CertificateValues.Count);
            foreach(CBAdESX509OrOtherCertificate certificate in validationData.CertificateValues)
            {
                WriteX509OrOtherCertificate(writer, certificate);
            }

            writer.WriteEndArray();
        }

        if(validationData.RevocationValues is not null)
        {
            writer.WriteInt32(CBAdESValidationData.RValsKey);
            WriteRevocationValues(writer, validationData.RevocationValues);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes an <c>X509OrOther</c> one-entry map (clause 5.3.4, Table 10) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="certificate">The value to write.</param>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="certificate"/> is an unknown arm.</exception>
    private static void WriteX509OrOtherCertificate(CborWriter writer, CBAdESX509OrOtherCertificate certificate)
    {
        (int key, AdESPkiObject pkiObject) = certificate switch
        {
            CBAdESX509Certificate x509 => (CBAdESX509OrOtherCertificate.X509CertKey, x509.Certificate),
            CBAdESOtherCertificate other => (CBAdESX509OrOtherCertificate.OtherCertKey, other.Certificate),
            _ => throw new NotSupportedException($"Unknown X509OrOther arm '{certificate.GetType()}'.")
        };

        writer.WriteStartMap(1);
        writer.WriteInt32(key);
        WritePkiObject(writer, pkiObject);
        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes an <c>rVals</c> map (clause 5.3.4, Table 10) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="revocationValues">The value to write.</param>
    private static void WriteRevocationValues(CborWriter writer, CBAdESRevocationValues revocationValues)
    {
        int memberCount = (revocationValues.CrlValues is not null ? 1 : 0)
            + (revocationValues.OcspValues is not null ? 1 : 0)
            + (revocationValues.OtherValues is not null ? 1 : 0);

        writer.WriteStartMap(memberCount);

        if(revocationValues.CrlValues is not null)
        {
            writer.WriteInt32(CBAdESRevocationValues.CrlValsKey);
            WritePkiObjectArray(writer, revocationValues.CrlValues);
        }

        if(revocationValues.OcspValues is not null)
        {
            writer.WriteInt32(CBAdESRevocationValues.OcspValsKey);
            WritePkiObjectArray(writer, revocationValues.OcspValues);
        }

        if(revocationValues.OtherValues is not null)
        {
            writer.WriteInt32(CBAdESRevocationValues.OtherValsKey);
            WritePkiObjectArray(writer, revocationValues.OtherValues);
        }

        writer.WriteEndMap();

        static void WritePkiObjectArray(CborWriter writer, IReadOnlyList<AdESPkiObject> pkiObjects)
        {
            writer.WriteStartArray(pkiObjects.Count);
            foreach(AdESPkiObject pkiObject in pkiObjects)
            {
                WritePkiObject(writer, pkiObject);
            }

            writer.WriteEndArray();
        }
    }


    /// <summary>
    /// Reads a <c>valData</c> map (clause 5.3.4, Table 10) from <paramref name="reader"/>. No disposable
    /// resources are owned by any member of the returned value (every <c>pkiOb</c> carries only borrowed
    /// bytes), so no partial-failure disposal is required here.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">Thrown when the map is malformed.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when the parsed content violates <see cref="CBAdESValidationData"/>'s construction invariants
    /// (CB-5.3.4-01/02/03).
    /// </exception>
    private static CBAdESValidationData ReadValidationData(CborReader reader)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 2);

        List<CBAdESX509OrOtherCertificate>? certificateValues = null;
        CBAdESRevocationValues? revocationValues = null;
        int previousKey = 0;

        for(int i = 0; i < count; i++)
        {
            int key = reader.ReadAscendingMapKey(ref previousKey);

            _ = key switch
            {
                CBAdESValidationData.XValsKey => AssignCertificateValues(reader, ref certificateValues),
                CBAdESValidationData.RValsKey => AssignRevocationValues(reader, ref revocationValues),
                _ => throw new CborContentException($"Unknown valData map key {key}.")
            };
        }

        reader.ReadEndMap();

        return new CBAdESValidationData(certificateValues, revocationValues);

        static bool AssignCertificateValues(CborReader reader, ref List<CBAdESX509OrOtherCertificate>? certificateValues)
        {
            int entryCount = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var entries = new List<CBAdESX509OrOtherCertificate>(Math.Min(entryCount, 64));
            for(int i = 0; i < entryCount; i++)
            {
                entries.Add(ReadX509OrOtherCertificate(reader));
            }

            reader.ReadEndArray();
            certificateValues = entries;
            return true;
        }

        static bool AssignRevocationValues(CborReader reader, ref CBAdESRevocationValues? revocationValues)
        {
            revocationValues = ReadRevocationValues(reader);
            return true;
        }
    }


    /// <summary>
    /// Reads an <c>X509OrOther</c> one-entry map (clause 5.3.4, Table 10) from <paramref name="reader"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">Thrown when the map key is not a known choice arm.</exception>
    private static CBAdESX509OrOtherCertificate ReadX509OrOtherCertificate(CborReader reader)
    {
        _ = reader.ReadStartMapExpectLength(1);
        int key = reader.ReadInt32();
        AdESPkiObject pkiObject = ReadPkiObject(reader);
        reader.ReadEndMap();

        return key switch
        {
            CBAdESX509OrOtherCertificate.X509CertKey => new CBAdESX509Certificate(pkiObject),
            CBAdESX509OrOtherCertificate.OtherCertKey => new CBAdESOtherCertificate(pkiObject),
            _ => throw new CborContentException($"Unknown X509OrOther map key {key}.")
        };
    }


    /// <summary>
    /// Reads an <c>rVals</c> map (clause 5.3.4, Table 10) from <paramref name="reader"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">Thrown when the map is malformed.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when the parsed content violates <see cref="CBAdESRevocationValues"/>'s construction invariants
    /// (CB-5.3.4-05/06/09).
    /// </exception>
    private static CBAdESRevocationValues ReadRevocationValues(CborReader reader)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 3);

        List<AdESPkiObject>? crlValues = null;
        List<AdESPkiObject>? ocspValues = null;
        List<AdESPkiObject>? otherValues = null;
        int previousKey = 0;

        for(int i = 0; i < count; i++)
        {
            int key = reader.ReadAscendingMapKey(ref previousKey);

            _ = key switch
            {
                CBAdESRevocationValues.CrlValsKey => AssignPkiObjects(reader, ref crlValues),
                CBAdESRevocationValues.OcspValsKey => AssignPkiObjects(reader, ref ocspValues),
                CBAdESRevocationValues.OtherValsKey => AssignPkiObjects(reader, ref otherValues),
                _ => throw new CborContentException($"Unknown rVals map key {key}.")
            };
        }

        reader.ReadEndMap();

        return new CBAdESRevocationValues(crlValues, ocspValues, otherValues);

        static bool AssignPkiObjects(CborReader reader, ref List<AdESPkiObject>? values)
        {
            int entryCount = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var entries = new List<AdESPkiObject>(Math.Min(entryCount, 64));
            for(int i = 0; i < entryCount; i++)
            {
                entries.Add(ReadPkiObject(reader));
            }

            reader.ReadEndArray();
            values = entries;
            return true;
        }
    }


    /// <summary>
    /// Encodes the <c>refs</c> unsigned header parameter (<see cref="CBAdESReferences"/>, label
    /// <see cref="CBAdESUnsignedHeaderElement.ReferencesLabel"/>) to canonical CBOR.
    /// </summary>
    /// <param name="references">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>refs</c> map.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, Annex A.1.1, Table A.1</see>.
    /// </remarks>
    public static PooledMemory EncodeReferences(CBAdESReferences references, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(references);
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        WriteReferences(writer, references);

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>refs</c> unsigned header parameter
    /// (<see cref="CBAdESReferences"/>). Fails closed: malformed, non-conformant, or empty-map
    /// (CB-A.1.1-04/05/09) input returns <see langword="false"/>, never throws; every digest already
    /// constructed before a later failure is disposed before returning.
    /// </summary>
    /// <param name="encoded">The encoded <c>refs</c> map bytes.</param>
    /// <param name="pool">The memory pool each entry's digest buffer is rented from.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, Annex A.1.1, Table A.1</see>.
    /// </remarks>
    public static bool TryParseReferences(ReadOnlyMemory<byte> encoded, BaseMemoryPool pool, out CBAdESReferences? result)
    {
        ArgumentNullException.ThrowIfNull(pool);

        try
        {
            var reader = new CborReader(encoded, CborConformanceMode.Canonical);
            result = ReadReferences(reader, pool);
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
    /// Writes a <c>refs</c> map (Annex A.1.1, Table A.1) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="references">The value to write.</param>
    private static void WriteReferences(CborWriter writer, CBAdESReferences references)
    {
        int memberCount = (references.CertificateReferences is not null ? 1 : 0)
            + (references.RevocationReferences is not null ? 1 : 0);

        writer.WriteStartMap(memberCount);

        if(references.CertificateReferences is not null)
        {
            writer.WriteInt32(CBAdESReferences.CertificateReferencesKey);
            writer.WriteStartArray(references.CertificateReferences.Count);
            foreach(CBAdESCertificateReference certificateReference in references.CertificateReferences)
            {
                WriteCertId(writer, certificateReference);
            }

            writer.WriteEndArray();
        }

        if(references.RevocationReferences is not null)
        {
            writer.WriteInt32(CBAdESReferences.RevocationReferencesKey);
            WriteRevocationReferences(writer, references.RevocationReferences);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes a <c>CertId</c> map (Annex A.1.1, Table A.1) to <paramref name="writer"/>. <c>x5t</c> reuses the
    /// same <c>COSE_CertHash</c> shape <see cref="EncodeCertificateThumbprints"/> writes for <c>x5ts</c>
    /// (<see cref="WriteHashAlgorithmDigestPair"/>).
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="certificateReference">The value to write.</param>
    private static void WriteCertId(CborWriter writer, CBAdESCertificateReference certificateReference)
    {
        int memberCount = 1
            + (certificateReference.KeyIdentifier is not null ? 1 : 0)
            + (certificateReference.LocationHint is not null ? 1 : 0);

        writer.WriteStartMap(memberCount);

        writer.WriteInt32(CBAdESCertificateReference.ThumbprintKey);
        WriteHashAlgorithmDigestPair(writer, certificateReference.Thumbprint.HashAlgorithm, certificateReference.Thumbprint.Digest);

        if(certificateReference.KeyIdentifier is not null)
        {
            writer.WriteInt32(CBAdESCertificateReference.KeyIdentifierKey);
            WriteKeyIdentifier(writer, certificateReference.KeyIdentifier);
        }

        if(certificateReference.LocationHint is not null)
        {
            writer.WriteInt32(CBAdESCertificateReference.LocationHintKey);
            writer.WriteUri(certificateReference.LocationHint);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes the <c>kid</c> member's <c>int / tstr / bstr</c> CDDL union (Annex A.1.1, <c>CertId</c>) to
    /// <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="keyIdentifier">The value to write.</param>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="keyIdentifier"/> is an unknown arm.</exception>
    private static void WriteKeyIdentifier(CborWriter writer, CBAdESCertificateReferenceKeyIdentifier keyIdentifier)
    {
        _ = keyIdentifier switch
        {
            CBAdESCertificateReferenceKeyIdentifierInteger integerIdentifier => WriteIntegerIdentifier(writer, integerIdentifier),
            CBAdESCertificateReferenceKeyIdentifierText textIdentifier => WriteTextIdentifier(writer, textIdentifier),
            CBAdESCertificateReferenceKeyIdentifierBytes bytesIdentifier => WriteBytesIdentifier(writer, bytesIdentifier),
            _ => throw new NotSupportedException($"Unknown kid arm '{keyIdentifier.GetType()}'.")
        };

        static bool WriteIntegerIdentifier(CborWriter writer, CBAdESCertificateReferenceKeyIdentifierInteger integerIdentifier)
        {
            writer.WriteInt32(integerIdentifier.Value);
            return true;
        }

        static bool WriteTextIdentifier(CborWriter writer, CBAdESCertificateReferenceKeyIdentifierText textIdentifier)
        {
            writer.WriteTextString(textIdentifier.Value);
            return true;
        }

        static bool WriteBytesIdentifier(CborWriter writer, CBAdESCertificateReferenceKeyIdentifierBytes bytesIdentifier)
        {
            writer.WriteByteString(bytesIdentifier.Value.Span);
            return true;
        }
    }


    /// <summary>
    /// Writes an <c>rRefs</c> map (Annex A.1.1, Table A.1) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="revocationReferences">The value to write.</param>
    private static void WriteRevocationReferences(CborWriter writer, CBAdESRevocationReferences revocationReferences)
    {
        int memberCount = (revocationReferences.CrlReferences is not null ? 1 : 0)
            + (revocationReferences.OcspReferences is not null ? 1 : 0)
            + (revocationReferences.OtherReferences is not null ? 1 : 0);

        writer.WriteStartMap(memberCount);

        if(revocationReferences.CrlReferences is not null)
        {
            writer.WriteInt32(CBAdESRevocationReferences.CrlReferencesKey);
            writer.WriteStartArray(revocationReferences.CrlReferences.Count);
            foreach(CBAdESCrlReference crlReference in revocationReferences.CrlReferences)
            {
                WriteCrlRef(writer, crlReference);
            }

            writer.WriteEndArray();
        }

        if(revocationReferences.OcspReferences is not null)
        {
            writer.WriteInt32(CBAdESRevocationReferences.OcspReferencesKey);
            writer.WriteStartArray(revocationReferences.OcspReferences.Count);
            foreach(CBAdESOcspReference ocspReference in revocationReferences.OcspReferences)
            {
                WriteOcspRef(writer, ocspReference);
            }

            writer.WriteEndArray();
        }

        if(revocationReferences.OtherReferences is not null)
        {
            writer.WriteInt32(CBAdESRevocationReferences.OtherReferencesKey);
            writer.WriteStartArray(revocationReferences.OtherReferences.Count);
            foreach(ReadOnlyMemory<byte> otherReference in revocationReferences.OtherReferences)
            {
                writer.WriteEncodedValue(otherReference.Span);
            }

            writer.WriteEndArray();
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes a <c>CRLRef</c> map (Annex A.1.1, Table A.1) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="crlReference">The value to write.</param>
    private static void WriteCrlRef(CborWriter writer, CBAdESCrlReference crlReference)
    {
        int memberCount = 1 + (crlReference.CrlIdentifier is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(CBAdESCrlReference.DigAlgValKey);
        WriteHashAlgorithmDigestPair(writer, crlReference.HashAlgorithm, crlReference.Digest);

        if(crlReference.CrlIdentifier is not null)
        {
            writer.WriteInt32(CBAdESCrlReference.CrlIdentifierKey);
            WriteCrlId(writer, crlReference.CrlIdentifier);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes a <c>CRLId</c> map (Annex A.1.1, Table A.1) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="crlIdentifier">The value to write.</param>
    private static void WriteCrlId(CborWriter writer, CBAdESCrlIdentifier crlIdentifier)
    {
        int memberCount = 2
            + (crlIdentifier.Number is not null ? 1 : 0)
            + (crlIdentifier.LocationHint is not null ? 1 : 0);

        writer.WriteStartMap(memberCount);

        writer.WriteInt32(CBAdESCrlIdentifier.IssuerKey);
        writer.WriteByteString(crlIdentifier.Issuer.Span);

        writer.WriteInt32(CBAdESCrlIdentifier.IssueTimeKey);
        WriteTDate(writer, crlIdentifier.IssueTime);

        if(crlIdentifier.Number is not null)
        {
            writer.WriteInt32(CBAdESCrlIdentifier.NumberKey);
            writer.WriteUInt64(crlIdentifier.Number.Value);
        }

        if(crlIdentifier.LocationHint is not null)
        {
            writer.WriteInt32(CBAdESCrlIdentifier.LocationHintKey);
            writer.WriteUri(crlIdentifier.LocationHint);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes an <c>OCSPRef</c> map (Annex A.1.1, Table A.1) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="ocspReference">The value to write.</param>
    private static void WriteOcspRef(CborWriter writer, CBAdESOcspReference ocspReference)
    {
        writer.WriteStartMap(2);

        writer.WriteInt32(CBAdESOcspReference.DigAlgValKey);
        WriteHashAlgorithmDigestPair(writer, ocspReference.HashAlgorithm, ocspReference.Digest);

        writer.WriteInt32(CBAdESOcspReference.OcspIdentifierKey);
        WriteOcspId(writer, ocspReference.OcspIdentifier);

        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes an <c>OCSPId</c> map (Annex A.1.1, Table A.1) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="ocspIdentifier">The value to write.</param>
    private static void WriteOcspId(CborWriter writer, CBAdESOcspIdentifier ocspIdentifier)
    {
        int memberCount = 2 + (ocspIdentifier.LocationHint is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(CBAdESOcspIdentifier.ResponderKey);
        WriteResponderId(writer, ocspIdentifier.Responder);

        writer.WriteInt32(CBAdESOcspIdentifier.ProducedAtKey);
        WriteTDate(writer, ocspIdentifier.ProducedAt);

        if(ocspIdentifier.LocationHint is not null)
        {
            writer.WriteInt32(CBAdESOcspIdentifier.LocationHintKey);
            writer.WriteUri(ocspIdentifier.LocationHint);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes a <c>ResponderIdChoice</c> one-entry map (Annex A.1.1) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="responder">The value to write.</param>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="responder"/> is an unknown arm.</exception>
    /// <remarks>
    /// The <c>responderIdByKey</c> arm writes the raw DER
    /// <see href="https://www.rfc-editor.org/rfc/rfc6960">IETF RFC 6960</see> <c>ResponderID.byKey</c>
    /// (<c>KeyHash</c>) bytes directly into the <c>bstr</c> — no base64 step. See the remarks on
    /// <see cref="CBAdESOcspResponderIdentifierByKey"/> for the reading.
    /// </remarks>
    private static void WriteResponderId(CborWriter writer, CBAdESOcspResponderIdentifier responder)
    {
        (int key, ReadOnlyMemory<byte> value) = responder switch
        {
            CBAdESOcspResponderIdentifierByName byName => (CBAdESOcspResponderIdentifier.ByNameKey, byName.Name),
            CBAdESOcspResponderIdentifierByKey byKey => (CBAdESOcspResponderIdentifier.ByKeyKey, byKey.KeyDigest),
            _ => throw new NotSupportedException($"Unknown ResponderIdChoice arm '{responder.GetType()}'.")
        };

        writer.WriteStartMap(1);
        writer.WriteInt32(key);
        writer.WriteByteString(value.Span);
        writer.WriteEndMap();
    }


    /// <summary>
    /// Reads a <c>refs</c> map (Annex A.1.1, Table A.1) from <paramref name="reader"/>. Disposal-safe: every
    /// certificate-reference and revocation-reference digest already constructed is disposed before this
    /// method rethrows on any later failure within the same map.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <param name="pool">The memory pool each entry's digest buffer is rented from.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">Thrown when the map is malformed.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when the parsed content violates <see cref="CBAdESReferences"/>'s construction invariants
    /// (CB-A.1.1-04/05).
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The enclosing try/catch disposes every already-accumulated certificate/revocation-reference digest before rethrowing on any failure; on success ownership of the returned CBAdESReferences transfers to the caller.")]
    private static CBAdESReferences ReadReferences(CborReader reader, BaseMemoryPool pool)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 2);

        List<CBAdESCertificateReference>? certificateReferences = null;
        CBAdESRevocationReferences? revocationReferences = null;
        int previousKey = 0;

        try
        {
            for(int i = 0; i < count; i++)
            {
                int key = reader.ReadAscendingMapKey(ref previousKey);

                _ = key switch
                {
                    CBAdESReferences.CertificateReferencesKey => AssignCertificateReferences(reader, pool, ref certificateReferences),
                    CBAdESReferences.RevocationReferencesKey => AssignRevocationReferences(reader, pool, ref revocationReferences),
                    _ => throw new CborContentException($"Unknown refs map key {key}.")
                };
            }

            reader.ReadEndMap();

            return new CBAdESReferences(certificateReferences, revocationReferences);
        }
        catch
        {
            DisposeAll(certificateReferences);
            revocationReferences?.Dispose();
            throw;
        }

        static void DisposeAll(List<CBAdESCertificateReference>? items)
        {
            if(items is null)
            {
                return;
            }

            foreach(CBAdESCertificateReference item in items)
            {
                item.Dispose();
            }
        }

        static bool AssignCertificateReferences(CborReader reader, BaseMemoryPool pool, ref List<CBAdESCertificateReference>? certificateReferences)
        {
            int entryCount = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var entries = new List<CBAdESCertificateReference>(Math.Min(entryCount, 64));
            certificateReferences = entries;
            for(int i = 0; i < entryCount; i++)
            {
                entries.Add(ReadCertId(reader, pool));
            }

            reader.ReadEndArray();
            return true;
        }

        static bool AssignRevocationReferences(CborReader reader, BaseMemoryPool pool, ref CBAdESRevocationReferences? revocationReferences)
        {
            revocationReferences = ReadRevocationReferences(reader, pool);
            return true;
        }
    }


    /// <summary>
    /// Reads a <c>CertId</c> map (Annex A.1.1, Table A.1) from <paramref name="reader"/>. <c>x5t</c> reuses the
    /// same <c>COSE_CertHash</c> shape <see cref="TryParseCertificateThumbprints"/> reads for <c>x5ts</c>
    /// (<see cref="ReadHashAlgorithmDigestPair"/>). Disposal-safe: the in-flight <c>x5t</c> digest is disposed
    /// before this method rethrows on any later failure within the same map.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <param name="pool">The memory pool the digest's buffer is rented from.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the map is malformed or the required <c>x5t</c> member is absent.
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The enclosing try/catch disposes the in-flight x5t digest before rethrowing on any failure; on success ownership of the digest transfers into the returned CBAdESCertificateReference.")]
    private static CBAdESCertificateReference ReadCertId(CborReader reader, BaseMemoryPool pool)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 3);

        AdESDigestAlgorithmIdentifier? hashAlgorithm = null;
        DigestValue? digest = null;
        CBAdESCertificateReferenceKeyIdentifier? keyIdentifier = null;
        Uri? locationHint = null;
        int previousKey = 0;

        try
        {
            for(int i = 0; i < count; i++)
            {
                int key = reader.ReadAscendingMapKey(ref previousKey);

                _ = key switch
                {
                    CBAdESCertificateReference.ThumbprintKey => AssignThumbprint(reader, pool, ref hashAlgorithm, ref digest),
                    CBAdESCertificateReference.KeyIdentifierKey => AssignKeyIdentifier(reader, ref keyIdentifier),
                    CBAdESCertificateReference.LocationHintKey => AssignLocationHint(reader, ref locationHint),
                    _ => throw new CborContentException($"Unknown CertId map key {key}.")
                };
            }

            reader.ReadEndMap();

            if(hashAlgorithm is null || digest is null)
            {
                throw new CborContentException("CertId requires the 'x5t' (map key 1) member.");
            }

            return new CBAdESCertificateReference(new AdESCertificateThumbprint(hashAlgorithm, digest), keyIdentifier, locationHint);
        }
        catch
        {
            digest?.Dispose();
            throw;
        }

        static bool AssignThumbprint(
            CborReader reader,
            BaseMemoryPool pool,
            ref AdESDigestAlgorithmIdentifier? hashAlgorithm,
            ref DigestValue? digest)
        {
            ReadHashAlgorithmDigestPair(reader, pool, out AdESDigestAlgorithmIdentifier algorithm, out DigestValue value);
            hashAlgorithm = algorithm;
            digest = value;
            return true;
        }

        static bool AssignKeyIdentifier(CborReader reader, ref CBAdESCertificateReferenceKeyIdentifier? keyIdentifier)
        {
            keyIdentifier = ReadKeyIdentifier(reader);
            return true;
        }

        static bool AssignLocationHint(CborReader reader, ref Uri? locationHint)
        {
            locationHint = reader.ReadUri();
            return true;
        }
    }


    /// <summary>
    /// Reads the <c>kid</c> member's <c>int / tstr / bstr</c> CDDL union (Annex A.1.1, <c>CertId</c>) from
    /// <paramref name="reader"/>, selecting the arm from the wire's own major type.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    private static CBAdESCertificateReferenceKeyIdentifier ReadKeyIdentifier(CborReader reader)
    {
        return reader.PeekState() switch
        {
            CborReaderState.TextString => new CBAdESCertificateReferenceKeyIdentifierText(reader.ReadTextString()),
            CborReaderState.ByteString => new CBAdESCertificateReferenceKeyIdentifierBytes(reader.ReadByteString()),
            _ => new CBAdESCertificateReferenceKeyIdentifierInteger(reader.ReadInt32())
        };
    }


    /// <summary>
    /// Reads an <c>rRefs</c> map (Annex A.1.1, Table A.1) from <paramref name="reader"/>. Disposal-safe: every
    /// CRL-reference and OCSP-reference digest already constructed is disposed before this method rethrows on
    /// any later failure within the same map. <c>otherRefs</c> (the CDDL comment is a
    /// spec-original copy-paste defect, NOT OCSP-only — see the remarks on <see cref="CBAdESRevocationReferences"/>)
    /// is read as opaque, byte-exact raw CBOR items via <see cref="CborReader.ReadEncodedValue"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <param name="pool">The memory pool each entry's digest buffer is rented from.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">Thrown when the map is malformed.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when the parsed content violates <see cref="CBAdESRevocationReferences"/>'s construction
    /// invariants (CB-A.1.1-09/10/19).
    /// </exception>
    private static CBAdESRevocationReferences ReadRevocationReferences(CborReader reader, BaseMemoryPool pool)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 3);

        List<CBAdESCrlReference>? crlReferences = null;
        List<CBAdESOcspReference>? ocspReferences = null;
        List<ReadOnlyMemory<byte>>? otherReferences = null;
        int previousKey = 0;

        try
        {
            for(int i = 0; i < count; i++)
            {
                int key = reader.ReadAscendingMapKey(ref previousKey);

                _ = key switch
                {
                    CBAdESRevocationReferences.CrlReferencesKey => AssignCrlReferences(reader, pool, ref crlReferences),
                    CBAdESRevocationReferences.OcspReferencesKey => AssignOcspReferences(reader, pool, ref ocspReferences),
                    CBAdESRevocationReferences.OtherReferencesKey => AssignOtherReferences(reader, ref otherReferences),
                    _ => throw new CborContentException($"Unknown rRefs map key {key}.")
                };
            }

            reader.ReadEndMap();

            return new CBAdESRevocationReferences(crlReferences, ocspReferences, otherReferences);
        }
        catch
        {
            DisposeAll(crlReferences, ocspReferences);
            throw;
        }

        static void DisposeAll(List<CBAdESCrlReference>? crlItems, List<CBAdESOcspReference>? ocspItems)
        {
            if(crlItems is not null)
            {
                foreach(CBAdESCrlReference item in crlItems)
                {
                    item.Dispose();
                }
            }

            if(ocspItems is not null)
            {
                foreach(CBAdESOcspReference item in ocspItems)
                {
                    item.Dispose();
                }
            }
        }

        static bool AssignCrlReferences(CborReader reader, BaseMemoryPool pool, ref List<CBAdESCrlReference>? crlReferences)
        {
            int entryCount = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var entries = new List<CBAdESCrlReference>(Math.Min(entryCount, 64));
            crlReferences = entries;
            for(int i = 0; i < entryCount; i++)
            {
                entries.Add(ReadCrlRef(reader, pool));
            }

            reader.ReadEndArray();
            return true;
        }

        static bool AssignOcspReferences(CborReader reader, BaseMemoryPool pool, ref List<CBAdESOcspReference>? ocspReferences)
        {
            int entryCount = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var entries = new List<CBAdESOcspReference>(Math.Min(entryCount, 64));
            ocspReferences = entries;
            for(int i = 0; i < entryCount; i++)
            {
                entries.Add(ReadOcspRef(reader, pool));
            }

            reader.ReadEndArray();
            return true;
        }

        static bool AssignOtherReferences(CborReader reader, ref List<ReadOnlyMemory<byte>>? otherReferences)
        {
            int entryCount = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
            var entries = new List<ReadOnlyMemory<byte>>(Math.Min(entryCount, 64));
            for(int i = 0; i < entryCount; i++)
            {
                entries.Add(reader.ReadEncodedValue());
            }

            reader.ReadEndArray();
            otherReferences = entries;
            return true;
        }
    }


    /// <summary>
    /// Reads a <c>CRLRef</c> map (Annex A.1.1, Table A.1) from <paramref name="reader"/>. Disposal-safe: the
    /// in-flight digest is disposed before this method rethrows on any later failure within the same map.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <param name="pool">The memory pool the digest's buffer is rented from.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the map is malformed or the required <c>digAlgVal</c> member is absent.
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The enclosing try/catch disposes the in-flight digAlgVal digest before rethrowing on any failure; on success ownership of the digest transfers into the returned CBAdESCrlReference.")]
    private static CBAdESCrlReference ReadCrlRef(CborReader reader, BaseMemoryPool pool)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 2);

        AdESDigestAlgorithmIdentifier? hashAlgorithm = null;
        DigestValue? digest = null;
        CBAdESCrlIdentifier? crlIdentifier = null;
        int previousKey = 0;

        try
        {
            for(int i = 0; i < count; i++)
            {
                int key = reader.ReadAscendingMapKey(ref previousKey);

                _ = key switch
                {
                    CBAdESCrlReference.DigAlgValKey => AssignDigAlgVal(reader, pool, ref hashAlgorithm, ref digest),
                    CBAdESCrlReference.CrlIdentifierKey => AssignCrlIdentifier(reader, ref crlIdentifier),
                    _ => throw new CborContentException($"Unknown CRLRef map key {key}.")
                };
            }

            reader.ReadEndMap();

            if(hashAlgorithm is null || digest is null)
            {
                throw new CborContentException("CRLRef requires the 'digAlgVal' (map key 1) member.");
            }

            return new CBAdESCrlReference(hashAlgorithm, digest, crlIdentifier);
        }
        catch
        {
            digest?.Dispose();
            throw;
        }

        static bool AssignDigAlgVal(CborReader reader, BaseMemoryPool pool, ref AdESDigestAlgorithmIdentifier? hashAlgorithm, ref DigestValue? digest)
        {
            ReadHashAlgorithmDigestPair(reader, pool, out AdESDigestAlgorithmIdentifier algorithm, out DigestValue value);
            hashAlgorithm = algorithm;
            digest = value;
            return true;
        }

        static bool AssignCrlIdentifier(CborReader reader, ref CBAdESCrlIdentifier? crlIdentifier)
        {
            crlIdentifier = ReadCrlId(reader);
            return true;
        }
    }


    /// <summary>
    /// Reads a <c>CRLId</c> map (Annex A.1.1, Table A.1) from <paramref name="reader"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the map is malformed or a required member is absent.
    /// </exception>
    private static CBAdESCrlIdentifier ReadCrlId(CborReader reader)
    {
        int count = reader.ReadStartMapExpectLengthRange(2, 4);

        byte[]? issuer = null;
        DateTimeOffset? issueTime = null;
        ulong? number = null;
        Uri? locationHint = null;
        int previousKey = 0;

        for(int i = 0; i < count; i++)
        {
            int key = reader.ReadAscendingMapKey(ref previousKey);

            _ = key switch
            {
                CBAdESCrlIdentifier.IssuerKey => AssignIssuer(reader, ref issuer),
                CBAdESCrlIdentifier.IssueTimeKey => AssignIssueTime(reader, ref issueTime),
                CBAdESCrlIdentifier.NumberKey => AssignNumber(reader, ref number),
                CBAdESCrlIdentifier.LocationHintKey => AssignLocationHint(reader, ref locationHint),
                _ => throw new CborContentException($"Unknown CRLId map key {key}.")
            };
        }

        reader.ReadEndMap();

        if(issuer is null || issueTime is null)
        {
            throw new CborContentException("CRLId requires the 'issuer' (map key 1) and 'issueTime' (map key 2) members.");
        }

        return new CBAdESCrlIdentifier { Issuer = issuer, IssueTime = issueTime.Value, Number = number, LocationHint = locationHint };

        static bool AssignIssuer(CborReader reader, ref byte[]? issuer)
        {
            issuer = reader.ReadByteString();
            return true;
        }

        static bool AssignIssueTime(CborReader reader, ref DateTimeOffset? issueTime)
        {
            issueTime = ReadTDate(reader);
            return true;
        }

        static bool AssignNumber(CborReader reader, ref ulong? number)
        {
            number = reader.ReadUInt64();
            return true;
        }

        static bool AssignLocationHint(CborReader reader, ref Uri? locationHint)
        {
            locationHint = reader.ReadUri();
            return true;
        }
    }


    /// <summary>
    /// Reads an <c>OCSPRef</c> map (Annex A.1.1, Table A.1) from <paramref name="reader"/>. Disposal-safe: the
    /// in-flight digest is disposed before this method rethrows on any later failure within the same map.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <param name="pool">The memory pool the digest's buffer is rented from.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the map is malformed or a required member is absent.
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The enclosing try/catch disposes the in-flight digAlgVal digest before rethrowing on any failure; on success ownership of the digest transfers into the returned CBAdESOcspReference.")]
    private static CBAdESOcspReference ReadOcspRef(CborReader reader, BaseMemoryPool pool)
    {
        int count = reader.ReadStartMapExpectLengthRange(1, 2);

        AdESDigestAlgorithmIdentifier? hashAlgorithm = null;
        DigestValue? digest = null;
        CBAdESOcspIdentifier? ocspIdentifier = null;
        int previousKey = 0;

        try
        {
            for(int i = 0; i < count; i++)
            {
                int key = reader.ReadAscendingMapKey(ref previousKey);

                _ = key switch
                {
                    CBAdESOcspReference.DigAlgValKey => AssignDigAlgVal(reader, pool, ref hashAlgorithm, ref digest),
                    CBAdESOcspReference.OcspIdentifierKey => AssignOcspIdentifier(reader, ref ocspIdentifier),
                    _ => throw new CborContentException($"Unknown OCSPRef map key {key}.")
                };
            }

            reader.ReadEndMap();

            if(hashAlgorithm is null || digest is null || ocspIdentifier is null)
            {
                throw new CborContentException("OCSPRef requires the 'digAlgVal' (map key 1) and 'ocspId' (map key 2) members.");
            }

            return new CBAdESOcspReference(hashAlgorithm, digest, ocspIdentifier);
        }
        catch
        {
            digest?.Dispose();
            throw;
        }

        static bool AssignDigAlgVal(CborReader reader, BaseMemoryPool pool, ref AdESDigestAlgorithmIdentifier? hashAlgorithm, ref DigestValue? digest)
        {
            ReadHashAlgorithmDigestPair(reader, pool, out AdESDigestAlgorithmIdentifier algorithm, out DigestValue value);
            hashAlgorithm = algorithm;
            digest = value;
            return true;
        }

        static bool AssignOcspIdentifier(CborReader reader, ref CBAdESOcspIdentifier? ocspIdentifier)
        {
            ocspIdentifier = ReadOcspId(reader);
            return true;
        }
    }


    /// <summary>
    /// Reads an <c>OCSPId</c> map (Annex A.1.1, Table A.1) from <paramref name="reader"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the map is malformed or a required member is absent.
    /// </exception>
    private static CBAdESOcspIdentifier ReadOcspId(CborReader reader)
    {
        int count = reader.ReadStartMapExpectLengthRange(2, 3);

        CBAdESOcspResponderIdentifier? responder = null;
        DateTimeOffset? producedAt = null;
        Uri? locationHint = null;
        int previousKey = 0;

        for(int i = 0; i < count; i++)
        {
            int key = reader.ReadAscendingMapKey(ref previousKey);

            _ = key switch
            {
                CBAdESOcspIdentifier.ResponderKey => AssignResponder(reader, ref responder),
                CBAdESOcspIdentifier.ProducedAtKey => AssignProducedAt(reader, ref producedAt),
                CBAdESOcspIdentifier.LocationHintKey => AssignLocationHint(reader, ref locationHint),
                _ => throw new CborContentException($"Unknown OCSPId map key {key}.")
            };
        }

        reader.ReadEndMap();

        if(responder is null || producedAt is null)
        {
            throw new CborContentException("OCSPId requires the 'responderChoice' (map key 1) and 'producedAt' (map key 2) members.");
        }

        return new CBAdESOcspIdentifier(responder, producedAt.Value, locationHint);

        static bool AssignResponder(CborReader reader, ref CBAdESOcspResponderIdentifier? responder)
        {
            responder = ReadResponderId(reader);
            return true;
        }

        static bool AssignProducedAt(CborReader reader, ref DateTimeOffset? producedAt)
        {
            producedAt = ReadTDate(reader);
            return true;
        }

        static bool AssignLocationHint(CborReader reader, ref Uri? locationHint)
        {
            locationHint = reader.ReadUri();
            return true;
        }
    }


    /// <summary>
    /// Reads a <c>ResponderIdChoice</c> one-entry map (Annex A.1.1) from <paramref name="reader"/>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed value.</returns>
    /// <exception cref="CborContentException">Thrown when the map key is not a known choice arm.</exception>
    /// <remarks>
    /// The <c>responderIdByKey</c> arm reads the <c>bstr</c> as raw
    /// DER <see href="https://www.rfc-editor.org/rfc/rfc6960">IETF RFC 6960</see> <c>ResponderID.byKey</c>
    /// (<c>KeyHash</c>) bytes — no base64 decoding step. See the remarks on
    /// <see cref="CBAdESOcspResponderIdentifierByKey"/> for the reading.
    /// </remarks>
    private static CBAdESOcspResponderIdentifier ReadResponderId(CborReader reader)
    {
        _ = reader.ReadStartMapExpectLength(1);
        int key = reader.ReadInt32();
        byte[] value = reader.ReadByteString();
        reader.ReadEndMap();

        return key switch
        {
            CBAdESOcspResponderIdentifier.ByNameKey => new CBAdESOcspResponderIdentifierByName(value),
            CBAdESOcspResponderIdentifier.ByKeyKey => new CBAdESOcspResponderIdentifierByKey(value),
            _ => throw new CborContentException($"Unknown ResponderIdChoice map key {key}.")
        };
    }


    /// <summary>
    /// Encodes the <c>sigTst</c> unsigned header parameter (<see cref="CBAdESSignatureTimestamp"/>, label
    /// <see cref="CBAdESUnsignedHeaderElement.SignatureTimestampLabel"/>) to canonical CBOR. A straight
    /// <c>tstContainer</c> alias (clause 5.3.3): delegates to <see cref="EncodeTimestampContainer"/>.
    /// </summary>
    /// <param name="timestamp">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>sigTst</c> map.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.3.3</see>.
    /// </remarks>
    public static PooledMemory EncodeSignatureTimestamp(CBAdESSignatureTimestamp timestamp, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(timestamp);
        ArgumentNullException.ThrowIfNull(pool);

        return EncodeTimestampContainer(timestamp.TimestampContainer, pool);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>sigTst</c> unsigned header parameter
    /// (<see cref="CBAdESSignatureTimestamp"/>). A straight <c>tstContainer</c> alias (clause 5.3.3): delegates
    /// to <see cref="TryParseTimestampContainer"/>. Fails closed: malformed or non-conformant input returns
    /// <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>sigTst</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.3.3</see>.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of container transfers immediately into the returned CBAdESSignatureTimestamp on success; on failure this method returns before any container is ever constructed.")]
    public static bool TryParseSignatureTimestamp(ReadOnlyMemory<byte> encoded, out CBAdESSignatureTimestamp? result)
    {
        if(!TryParseTimestampContainer(encoded, out AdESTimestampContainer? container) || container is null)
        {
            result = null;
            return false;
        }

        result = new CBAdESSignatureTimestamp(container);
        return true;
    }


    /// <summary>
    /// Encodes the <c>arcTst</c> unsigned header parameter (<see cref="CBAdESArchiveTimestamp"/>, label
    /// <see cref="CBAdESUnsignedHeaderElement.ArchiveTimestampLabel"/>) to canonical CBOR. A straight
    /// <c>tstContainer</c> alias (clause 5.3.5.1): delegates to <see cref="EncodeTimestampContainer"/>.
    /// </summary>
    /// <param name="timestamp">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>arcTst</c> map.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.3.5.1</see>.
    /// </remarks>
    public static PooledMemory EncodeArchiveTimestamp(CBAdESArchiveTimestamp timestamp, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(timestamp);
        ArgumentNullException.ThrowIfNull(pool);

        return EncodeTimestampContainer(timestamp.TimestampContainer, pool);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>arcTst</c> unsigned header parameter
    /// (<see cref="CBAdESArchiveTimestamp"/>). A straight <c>tstContainer</c> alias (clause 5.3.5.1): delegates
    /// to <see cref="TryParseTimestampContainer"/>. Fails closed: malformed or non-conformant input returns
    /// <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>arcTst</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.3.5.1</see>.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of container transfers immediately into the returned CBAdESArchiveTimestamp on success; on failure this method returns before any container is ever constructed.")]
    public static bool TryParseArchiveTimestamp(ReadOnlyMemory<byte> encoded, out CBAdESArchiveTimestamp? result)
    {
        if(!TryParseTimestampContainer(encoded, out AdESTimestampContainer? container) || container is null)
        {
            result = null;
            return false;
        }

        result = new CBAdESArchiveTimestamp(container);
        return true;
    }


    /// <summary>
    /// Encodes the <c>sigRTst</c> unsigned header parameter (<see cref="CBAdESSignatureAndReferencesTimestamp"/>,
    /// label <see cref="CBAdESUnsignedHeaderElement.SignatureAndReferencesTimestampLabel"/>) to canonical CBOR.
    /// A straight <c>tstContainer</c> alias (Annex A.1.2.1.1): delegates to <see cref="EncodeTimestampContainer"/>.
    /// </summary>
    /// <param name="timestamp">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>sigRTst</c> map.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, Annex A.1.2.1.1</see>.
    /// </remarks>
    public static PooledMemory EncodeSignatureAndReferencesTimestamp(CBAdESSignatureAndReferencesTimestamp timestamp, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(timestamp);
        ArgumentNullException.ThrowIfNull(pool);

        return EncodeTimestampContainer(timestamp.TimestampContainer, pool);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>sigRTst</c> unsigned header parameter
    /// (<see cref="CBAdESSignatureAndReferencesTimestamp"/>). A straight <c>tstContainer</c> alias (Annex
    /// A.1.2.1.1): delegates to <see cref="TryParseTimestampContainer"/>. Fails closed: malformed or
    /// non-conformant input returns <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>sigRTst</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, Annex A.1.2.1.1</see>.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of container transfers immediately into the returned CBAdESSignatureAndReferencesTimestamp on success; on failure this method returns before any container is ever constructed.")]
    public static bool TryParseSignatureAndReferencesTimestamp(ReadOnlyMemory<byte> encoded, out CBAdESSignatureAndReferencesTimestamp? result)
    {
        if(!TryParseTimestampContainer(encoded, out AdESTimestampContainer? container) || container is null)
        {
            result = null;
            return false;
        }

        result = new CBAdESSignatureAndReferencesTimestamp(container);
        return true;
    }


    /// <summary>
    /// Encodes the <c>rfsTst</c> unsigned header parameter (<see cref="CBAdESReferencesTimestamp"/>, label
    /// <see cref="CBAdESUnsignedHeaderElement.ReferencesTimestampLabel"/>) to canonical CBOR. A straight
    /// <c>tstContainer</c> alias (Annex A.1.2.2.1): delegates to <see cref="EncodeTimestampContainer"/>.
    /// </summary>
    /// <param name="timestamp">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>rfsTst</c> map.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, Annex A.1.2.2.1</see>.
    /// </remarks>
    public static PooledMemory EncodeReferencesTimestamp(CBAdESReferencesTimestamp timestamp, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(timestamp);
        ArgumentNullException.ThrowIfNull(pool);

        return EncodeTimestampContainer(timestamp.TimestampContainer, pool);
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>rfsTst</c> unsigned header parameter
    /// (<see cref="CBAdESReferencesTimestamp"/>). A straight <c>tstContainer</c> alias (Annex A.1.2.2.1):
    /// delegates to <see cref="TryParseTimestampContainer"/>. Fails closed: malformed or non-conformant input
    /// returns <see langword="false"/>, never throws.
    /// </summary>
    /// <param name="encoded">The encoded <c>rfsTst</c> map bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, Annex A.1.2.2.1</see>.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of container transfers immediately into the returned CBAdESReferencesTimestamp on success; on failure this method returns before any container is ever constructed.")]
    public static bool TryParseReferencesTimestamp(ReadOnlyMemory<byte> encoded, out CBAdESReferencesTimestamp? result)
    {
        if(!TryParseTimestampContainer(encoded, out AdESTimestampContainer? container) || container is null)
        {
            result = null;
            return false;
        }

        result = new CBAdESReferencesTimestamp(container);
        return true;
    }


    /// <summary>
    /// Encodes the <c>uHeaders</c> unsigned header parameter (<see cref="CBAdESUnsignedHeaders"/>, label
    /// <c>268</c>) to canonical CBOR: a CBOR array with one <c>bstr</c> per element (CB-5.3.1-04), each
    /// encapsulating the one-entry <c>UHeaderInstance</c> map keyed by the element's Table 8 label.
    /// </summary>
    /// <param name="unsignedHeaders">The value to encode.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented, tagged carrier for the encoded <c>uHeaders</c> array.</returns>
    /// <remarks>
    /// <para>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.3.1, Table 8</see>.
    /// </para>
    /// <para>
    /// <strong>No <c>#6.268</c> tag around the array.</strong> Table 8's "tag" column names the IANA COSE
    /// header-parameter label under which <c>uHeaders</c> appears as a member of the unprotected headers map
    /// (clause 3, IETF RFC 9052) — not a CBOR major-type-6 tag applied to the array value itself; see the
    /// <see cref="CBAdESUnsignedHeaders"/> type remarks for the same reading. This method therefore writes the
    /// array untagged.
    /// </para>
    /// </remarks>
    public static PooledMemory EncodeUnsignedHeaders(CBAdESUnsignedHeaders unsignedHeaders, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(unsignedHeaders);
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(unsignedHeaders.Count);
        for(int i = 0; i < unsignedHeaders.Count; i++)
        {
            writer.WriteByteString(EncodeUnsignedHeaderElement(unsignedHeaders[i]));
        }

        writer.WriteEndArray();

        return PooledMemory.FromBytes(writer.Encode(), pool, ComponentTag);
    }


    /// <summary>
    /// Encodes one <c>UHeaderInstance</c> element — a one-entry map keyed by <paramref name="element"/>'s own
    /// <see cref="CBAdESUnsignedHeaderElement.Label"/> — to its own independent, canonical CBOR byte string,
    /// ready to be wrapped as one <c>uHeaders</c> array entry (CB-5.3.1-04).
    /// </summary>
    /// <param name="element">The element to encode.</param>
    /// <returns>The encoded <c>UHeaderInstance</c> map bytes.</returns>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="element"/> is an unknown arm.</exception>
    private static byte[] EncodeUnsignedHeaderElement(CBAdESUnsignedHeaderElement element)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        WriteUnsignedHeaderElementLabel(writer, element.Label);

        _ = element switch
        {
            CBAdESUnsignedHeaderElementSignatureTimestamp signatureTimestamp => WriteSignatureTimestampArm(writer, signatureTimestamp),
            CBAdESUnsignedHeaderElementValidationData validationData => WriteValidationDataArm(writer, validationData),
            CBAdESUnsignedHeaderElementArchiveTimestamp archiveTimestamp => WriteArchiveTimestampArm(writer, archiveTimestamp),
            CBAdESUnsignedHeaderElementReferences references => WriteReferencesArm(writer, references),
            CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp signatureAndReferencesTimestamp =>
                WriteSignatureAndReferencesTimestampArm(writer, signatureAndReferencesTimestamp),
            CBAdESUnsignedHeaderElementReferencesTimestamp referencesTimestamp => WriteReferencesTimestampArm(writer, referencesTimestamp),
            CBAdESUnsignedHeaderElementSignaturePolicyStore signaturePolicyStore => WriteSignaturePolicyStoreArm(writer, signaturePolicyStore),
            CBAdESUnsignedHeaderElementFullCounterSignature fullCounterSignature => WriteOpaqueArm(writer, fullCounterSignature.Value),
            CBAdESUnsignedHeaderElementAbbreviatedCounterSignature abbreviatedCounterSignature =>
                WriteOpaqueArm(writer, abbreviatedCounterSignature.Value),
            CBAdESUnsignedHeaderElementCertificateChain certificateChain => WriteOpaqueArm(writer, certificateChain.Value),
            CBAdESUnsignedHeaderElementUnknown unknown => WriteOpaqueArm(writer, unknown.Value),
            _ => throw new NotSupportedException($"Unknown UHeaderInstance arm '{element.GetType()}'.")
        };

        writer.WriteEndMap();
        return writer.Encode();

        static bool WriteSignatureTimestampArm(CborWriter writer, CBAdESUnsignedHeaderElementSignatureTimestamp signatureTimestamp)
        {
            WriteTimestampContainer(writer, signatureTimestamp.SignatureTimestamp.TimestampContainer);
            return true;
        }

        static bool WriteValidationDataArm(CborWriter writer, CBAdESUnsignedHeaderElementValidationData validationData)
        {
            WriteValidationData(writer, validationData.ValidationData);
            return true;
        }

        static bool WriteArchiveTimestampArm(CborWriter writer, CBAdESUnsignedHeaderElementArchiveTimestamp archiveTimestamp)
        {
            WriteTimestampContainer(writer, archiveTimestamp.ArchiveTimestamp.TimestampContainer);
            return true;
        }

        static bool WriteReferencesArm(CborWriter writer, CBAdESUnsignedHeaderElementReferences references)
        {
            WriteReferences(writer, references.References);
            return true;
        }

        static bool WriteSignatureAndReferencesTimestampArm(
            CborWriter writer,
            CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp signatureAndReferencesTimestamp)
        {
            WriteTimestampContainer(writer, signatureAndReferencesTimestamp.SignatureAndReferencesTimestamp.TimestampContainer);
            return true;
        }

        static bool WriteReferencesTimestampArm(CborWriter writer, CBAdESUnsignedHeaderElementReferencesTimestamp referencesTimestamp)
        {
            WriteTimestampContainer(writer, referencesTimestamp.ReferencesTimestamp.TimestampContainer);
            return true;
        }

        static bool WriteSignaturePolicyStoreArm(CborWriter writer, CBAdESUnsignedHeaderElementSignaturePolicyStore signaturePolicyStore)
        {
            WriteSignaturePolicyStore(writer, signaturePolicyStore.SignaturePolicyStore);
            return true;
        }

        static bool WriteOpaqueArm(CborWriter writer, ReadOnlyMemory<byte> value)
        {
            writer.WriteEncodedValue(value.Span);
            return true;
        }
    }


    /// <summary>
    /// Writes a <see cref="CBAdESUnsignedHeaderElementLabel"/> (the CDDL's <c>label = int / tstr</c> rule, as
    /// it applies to <see cref="CBAdESUnsignedHeaderElement.Label"/>) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="label">The value to write.</param>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="label"/> is an unknown arm.</exception>
    private static void WriteUnsignedHeaderElementLabel(CborWriter writer, CBAdESUnsignedHeaderElementLabel label)
    {
        _ = label switch
        {
            CBAdESUnsignedHeaderElementIntegerLabel integerLabel => WriteIntegerLabel(writer, integerLabel),
            CBAdESUnsignedHeaderElementTextLabel textLabel => WriteTextLabel(writer, textLabel),
            _ => throw new NotSupportedException($"Unknown uHeaders element label arm '{label.GetType()}'.")
        };

        static bool WriteIntegerLabel(CborWriter writer, CBAdESUnsignedHeaderElementIntegerLabel integerLabel)
        {
            writer.WriteInt32(integerLabel.Value);
            return true;
        }

        static bool WriteTextLabel(CborWriter writer, CBAdESUnsignedHeaderElementTextLabel textLabel)
        {
            writer.WriteTextString(textLabel.Value);
            return true;
        }
    }


    /// <summary>
    /// Parses canonical CBOR bytes into the <c>uHeaders</c> unsigned header parameter
    /// (<see cref="CBAdESUnsignedHeaders"/>). Fails closed: malformed, non-conformant, or empty-array
    /// (CB-5.3.1-07) input returns <see langword="false"/>, never throws; every element already constructed
    /// before a later failure — including any owned digest reachable through it — is disposed before
    /// returning.
    /// </summary>
    /// <param name="encoded">The encoded <c>uHeaders</c> array bytes.</param>
    /// <param name="pool">The memory pool used to reconstruct any digest carried by a typed element.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.3.1, Table 8</see>. Order is preserved element-for-element
    /// (CB-5.3.1-01/03); see the <see cref="EncodeUnsignedHeaders"/> remarks for why no <c>#6.268</c> tag is
    /// expected around the array.
    /// </remarks>
    public static bool TryParseUnsignedHeaders(ReadOnlyMemory<byte> encoded, BaseMemoryPool pool, out CBAdESUnsignedHeaders? result)
    {
        ArgumentNullException.ThrowIfNull(pool);

        List<CBAdESUnsignedHeaderElement>? elements = null;
        try
        {
            var reader = new CborReader(encoded, CborConformanceMode.Canonical);
            int count = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);

            var items = new List<CBAdESUnsignedHeaderElement>(Math.Min(count, 64));
            elements = items;
            for(int i = 0; i < count; i++)
            {
                byte[] elementBytes = reader.ReadByteString();
                items.Add(ReadUnsignedHeaderElement(elementBytes, pool));
            }

            reader.ReadEndArray();

            if(reader.BytesRemaining != 0)
            {
                DisposeAll(elements);
                result = null;
                return false;
            }

            result = new CBAdESUnsignedHeaders(items);
            return true;
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            DisposeAll(elements);
            result = null;
            return false;
        }

        static void DisposeAll(List<CBAdESUnsignedHeaderElement>? items)
        {
            if(items is null)
            {
                return;
            }

            foreach(CBAdESUnsignedHeaderElement item in items)
            {
                if(item is IDisposable disposable)
                {
                    disposable.Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Reads one <c>uHeaders</c> array element's bytes as an independent <c>UHeaderInstance</c> CBOR document —
    /// a one-entry map keyed by the element's Table 8 label (or a free-form <c>label</c> for the catch-all
    /// case). Labels <c>1</c>-<c>7</c> dispatch to their own component parser (any inner failure fails the
    /// whole element, fail-closed); labels <c>11</c>/<c>12</c>/<c>33</c> and any unrecognized integer label, or
    /// any text label, are read as opaque, byte-exact raw CBOR values via <see cref="CborReader.ReadEncodedValue"/>.
    /// </summary>
    /// <param name="elementBytes">One <c>uHeaders</c> array entry's <c>bstr</c> content.</param>
    /// <param name="pool">The memory pool used to reconstruct any digest carried by a typed element (<c>refs</c>).</param>
    /// <returns>The parsed element.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the map is malformed, or trailing bytes remain after the one-entry map.
    /// </exception>
    /// <remarks>
    /// Disposal-safe: the switch assignment through <see cref="CborReader.ReadEndMap"/> runs inside a
    /// try/catch that disposes an already-constructed <c>result</c> before rethrowing, matching the family's
    /// dispose-on-throw idiom (<see cref="ReadReferences"/>, <see cref="ReadCertId"/>, <see cref="ReadCrlRef"/>,
    /// <see cref="ReadOcspRef"/>). Under <see cref="CborConformanceMode.Canonical"/> a well-formed one-entry
    /// map's own <see cref="CborReader.ReadEndMap"/> call cannot itself throw once every entry has been
    /// consumed, so this is defense-in-depth rather than a reachable path today.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The enclosing try/catch disposes an already-constructed result before rethrowing on any failure (defense-in-depth; unreachable under Canonical mode today); the trailing-bytes check disposes it on that failure path too, and on success ownership transfers to the caller.")]
    private static CBAdESUnsignedHeaderElement ReadUnsignedHeaderElement(byte[] elementBytes, BaseMemoryPool pool)
    {
        var reader = new CborReader(elementBytes, CborConformanceMode.Canonical);
        _ = reader.ReadStartMapExpectLength(1);

        CBAdESUnsignedHeaderElement? result = null;
        try
        {
            if(reader.PeekState() == CborReaderState.TextString)
            {
                string textLabel = reader.ReadTextString();
                result = new CBAdESUnsignedHeaderElementUnknown(new CBAdESUnsignedHeaderElementTextLabel(textLabel), reader.ReadEncodedValue());
            }
            else
            {
                int label = reader.ReadInt32();
                result = label switch
                {
                    CBAdESUnsignedHeaderElement.SignatureTimestampLabel =>
                        new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(ReadTimestampContainer(reader))),
                    CBAdESUnsignedHeaderElement.ValidationDataLabel =>
                        new CBAdESUnsignedHeaderElementValidationData(ReadValidationData(reader)),
                    CBAdESUnsignedHeaderElement.ArchiveTimestampLabel =>
                        new CBAdESUnsignedHeaderElementArchiveTimestamp(new CBAdESArchiveTimestamp(ReadTimestampContainer(reader))),
                    CBAdESUnsignedHeaderElement.ReferencesLabel =>
                        new CBAdESUnsignedHeaderElementReferences(ReadReferences(reader, pool)),
                    CBAdESUnsignedHeaderElement.SignatureAndReferencesTimestampLabel =>
                        new CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp(
                            new CBAdESSignatureAndReferencesTimestamp(ReadTimestampContainer(reader))),
                    CBAdESUnsignedHeaderElement.ReferencesTimestampLabel =>
                        new CBAdESUnsignedHeaderElementReferencesTimestamp(new CBAdESReferencesTimestamp(ReadTimestampContainer(reader))),
                    CBAdESUnsignedHeaderElement.SignaturePolicyStoreLabel =>
                        new CBAdESUnsignedHeaderElementSignaturePolicyStore(ReadSignaturePolicyStore(reader)),
                    CBAdESUnsignedHeaderElement.FullCounterSignatureLabel =>
                        new CBAdESUnsignedHeaderElementFullCounterSignature(reader.ReadEncodedValue()),
                    CBAdESUnsignedHeaderElement.AbbreviatedCounterSignatureLabel =>
                        new CBAdESUnsignedHeaderElementAbbreviatedCounterSignature(reader.ReadEncodedValue()),
                    CBAdESUnsignedHeaderElement.CertificateChainLabel =>
                        new CBAdESUnsignedHeaderElementCertificateChain(reader.ReadEncodedValue()),
                    _ => new CBAdESUnsignedHeaderElementUnknown(new CBAdESUnsignedHeaderElementIntegerLabel(label), reader.ReadEncodedValue())
                };
            }

            reader.ReadEndMap();
        }
        catch
        {
            if(result is IDisposable disposable)
            {
                disposable.Dispose();
            }

            throw;
        }

        if(reader.BytesRemaining != 0)
        {
            if(result is IDisposable disposable)
            {
                disposable.Dispose();
            }

            throw new CborContentException("Trailing bytes after a uHeaders element's UHeaderInstance map.");
        }

        return result;
    }
}
