using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;

namespace Verifiable.Cbor;

/// <summary>
/// CBOR bindings for the CB-AdES stage-3 JCose seam delegates (<see cref="EncodeCBAdESProtectedHeaderDelegate"/>,
/// <see cref="EncodeCBAdESUnprotectedHeaderDelegate"/>, <see cref="ParseCBAdESSign1Delegate"/>) — the B-B
/// signed-header-set encoder/decoder and the fail-closed whole-message parser, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>A new file beside <see cref="CBAdESSerialization"/>, not an extension of it.</strong>
/// <see cref="CBAdESSerialization"/> is already the component-level codec (clause 5.2/5.3/5.4 + Annex A) at
/// over 4000 lines; this class is the CLASS-14 aggregate/message-envelope codec one layer up — it COMPOSES
/// <see cref="CBAdESSerialization"/>'s public <c>Encode*</c>/<c>TryParse*</c> entry points for the seven clause
/// 5.2 components (never duplicating their bodies) and adds the eight clause 5.1 IETF-profiled headers this
/// document does not otherwise codec (<c>alg</c>, <c>content type</c>, <c>kid</c>, <c>x5u</c>, <c>x5t</c>,
/// the SIGNED <c>x5chain</c> occurrence, the RFC 9597 CWT-Claims/<c>iat</c> container, <c>crit</c>) plus the
/// RFC 9052 §4.2 <c>COSE_Sign1</c> envelope itself.
/// </para>
/// <para>
/// <strong>Conformance mode: <see cref="CborConformanceMode.Canonical"/> throughout</strong> — for both the
/// per-member value writers and the whole-message/protected-header readers — matching
/// <see cref="CBAdESSerialization"/>'s own convention rather than <see cref="CoseSerialization"/>'s more
/// permissive <see cref="CborConformanceMode.Lax"/> reader. <see cref="CoseSerialization"/> parses ANY
/// COSE_Sign1 (multiple profiles share that substrate); this class parses ONLY CB-AdES wire bytes, which
/// clause 4.7/CB-4.7-02 already requires to be canonically (deterministically, RFC 9052 §9) encoded — so
/// Canonical-mode reading gets the framework's own definite-length/minimal-encoding rejection for free,
/// satisfying wavecb-contract.md R-5 with less hand-written validation, exactly as
/// <see cref="CBAdESSerialization"/>'s own class remarks document for the component codecs.
/// </para>
/// <para>
/// <strong>Accept both tagged and untagged, recorded loudly (CB-4.3, matrix-F4/wavecb S3 FX-F, superseding
/// the earlier tagged-only S3 coordinator ruling (7)).</strong> Clause 4.3 states CB-AdES signatures MAY be
/// encoded untagged (<c>COSE_Sign</c>/<c>COSE_Sign1</c>) or tagged (<c>COSE_Sign_Tagged</c>/<c>COSE_Sign1_Tagged</c>);
/// this is a CB-AdES-specific divergence from <see cref="CoseSerialization.ParseCoseSign1"/> and
/// <see cref="CoseSerialization.ParseCoseSign1AllowingNilPayload"/>, which both call <c>CborReader.ReadTag()</c>
/// unconditionally and so accept only the tagged form for the generic multi-profile COSE_Sign1 substrate — a
/// strict conformance oracle for THIS document must accept spec-legal untagged input too.
/// <see cref="ParseCBAdESSign1"/> peeks the next CBOR item: a <see cref="CborReaderState.Tag"/> is read and
/// MUST equal the <c>COSE_Sign1_Tagged</c> value 18 (any other tag value fails closed, clause 4.3); no tag at
/// all proceeds straight to the 4-element array read. <see cref="CoseSerialization.SerializeCoseSign1"/> always
/// emits tag 18; this stage has no separate encoder for the envelope (<c>Cose.SignAsync</c> composes
/// <see cref="CoseSerialization.SerializeCoseSign1"/> directly), so emission stays tagged-only and is
/// unaffected by this class — the accept-both behavior is parse-side only. The tagged-vs-untagged fact is not
/// threaded through <see cref="CBAdESSign1ParseResult"/> (no consumer needs it; a follow-up if one arises).
/// </para>
/// <para>
/// <strong><c>x5u</c> is a plain <c>tstr</c>, NOT a tag-32 URI, recorded loudly.</strong> Clause 5.1.5 gives no
/// local CDDL for <c>x5u</c> ("syntax specified in IETF RFC 9360 [3] clause 2"), unlike the shared-syntax
/// <c>oId</c>/<c>pkiOb</c>/<c>tstContainer</c> types (whose URI-typed members ARE tag-32-wrapped via
/// <see cref="CborWriterExtensions.WriteUri"/>/<see cref="CborReaderExtensions.ReadUri"/>) and unlike Annex
/// A.1.1's <c>CertId.x5u</c> member, whose CDDL is explicitly <c>#6.32(tstr)</c> — this document DOES tag a
/// URI when it means one. The absence of that notation at clause 5.1.5 is read as deliberate: RFC 9360 §2's
/// own IANA COSE Header Parameters registration for <c>x5u</c> gives its CBOR representation as a plain text
/// string (mirroring how JOSE's <c>x5u</c>, RFC 7515, carries a bare JSON string with no analogous CBOR-tag
/// concept). A study-only cross-read of the cached reference clone's CB-AdES signer (never executed, never
/// asset-referenced, cited by clause only) corroborates this: it writes the caller-supplied <c>x5u</c> URL as
/// a bare string header value, with no tag-32 wrapping step anywhere in that path — independent confirmation,
/// not the resolution's source. <see cref="EncodeX5Url"/>/<see cref="ReadX5Url"/> therefore write/read a plain
/// <c>tstr</c>.
/// </para>
/// <para>
/// <strong>CWT Claims (label 15) tolerates sibling claims; only <c>iat</c> is modeled (wavecb S3 FX-E).</strong>
/// <see cref="CBAdESCwtClaims"/> (M1's model) carries only <see cref="CBAdESCwtClaims.IssuedAt"/>, but RFC 9597
/// (the CWT-Claims header container this document reuses) carries an open RFC 8392 claims set, and clause 5.1.9
/// restricts nothing beyond requiring <c>iat</c>'s presence (CB-6.3-10) — an earlier revision of
/// <see cref="ReadCwtClaims"/> required the map to have exactly one member, citing CB-5.1.9-06 for that
/// exclusivity; CB-5.1.9-06 never established it, and the earlier check rejected spec-legal wire content
/// carrying a sibling claim (e.g. <c>sub</c>) alongside <c>iat</c>. <see cref="ReadCwtClaims"/> now iterates
/// every member of the map: claim key 6 (<c>iat</c>, <see cref="WellKnownCwtClaimNames.Iat"/>) decodes into the
/// result, and every sibling claim is skipped rather than modeled or rejected. When <c>iat</c> itself is absent
/// from a present CWT-Claims map, or label 15 is absent from the protected header map entirely,
/// <see cref="ReadCwtClaims"/>/<see cref="ParseCBAdESSign1"/> carry a <see langword="null"/>
/// <see cref="CBAdESProtectedHeaders.CwtClaims"/> rather than failing the parse —
/// <see cref="CBAdESHeaderRules.Check"/> reports that as <see cref="CBAdESCwtClaimsMissingViolation"/>
/// (CB-6.3-10), the rules surface's job, not the parser's. <c>NumericDate</c> (RFC 8392 §2) is written as a
/// plain CBOR integer of whole seconds (<see cref="EncodeCwtClaims"/> truncates sub-second precision, matching
/// <see cref="CBAdESSerialization"/>'s own <c>tdate</c> writer's second-only precision) but read tolerantly as
/// either an integer or a floating-point value (RFC 8392 §2's <c>NumericDate</c> CDDL is <c>int / float</c>,
/// with no CBOR tag) — corroborated by the same study-only cross-read, whose <c>NumericDate</c> reader accepts
/// both representations and whose signer writes a plain integer.
/// </para>
/// <para>
/// <strong><c>alg</c> stays parse-mandatory, deliberately (wavecb S3 FX-E).</strong> Unlike CWT Claims'
/// null-propagate-to-the-rules-surface treatment above, a missing <c>alg</c> (label 1) still fails
/// <see cref="ParseCBAdESSign1"/> outright as a <see cref="CBAdESSign1ParseResult.IsSuccess"/>
/// <see langword="false"/> result: RFC 9052 §3.1's base <c>COSE_Sign1</c> envelope requires <c>alg</c> to
/// select the verification algorithm before any signature check can even run, so its absence is a base-envelope
/// malformation, not a CB-AdES profile rule <see cref="CBAdESHeaderRules"/> could report as a B-B violation over
/// an already-decoded, otherwise-navigable aggregate — there is no legal <see cref="CBAdESProtectedHeaders"/>
/// with a missing <c>alg</c> for that rule surface to ever see.
/// </para>
/// <para>
/// <strong>The protected header's own label space is the general <c>int / tstr</c> union, not integer-only
/// (wavecb S3 FX-H).</strong> CB-4.6-01's integer-only requirement ("The keys of the new CBOR map pairs shall
/// be integers") binds the seven clause-5.2 CB-AdES component maps' OWN internals (clause 4.6), not this outer
/// protected-headers map's own keys or <c>crit</c>'s array elements — those reuse RFC 9052 §1.4/§3.1's general
/// <c>label: int / tstr</c> CDDL union unnarrowed (clause 4.4 NOTE 4 explicitly allows a <c>tstr</c>-labeled
/// unprofiled header parameter). <see cref="ParseCBAdESSign1"/>'s top-level map-key loop therefore decodes each
/// key into a <see cref="CoseHeaderLabel"/> via its own local <c>ReadProtectedHeaderMapKey</c> helper (reading
/// each key's raw encoded bytes and comparing them under RFC 8949 §4.2.3's canonical length-first-then-lex
/// ordering), rather than <see cref="CborReaderExtensions.ReadAscendingMapKey"/>'s integer-only comparison —
/// which stays exactly as it was for every S1/S2 component internal map, per CB-4.6-01. Every profiled label
/// this class assigns is, and stays, a <see cref="CoseHeaderIntegerLabel"/>; only <c>crit</c>'s elements and
/// <see cref="CBAdESProtectedHeaders.UnprofiledHeaders"/>'s keys can ever carry the <see cref="CoseHeaderTextLabel"/>
/// arm.
/// </para>
/// <para>
/// <strong>Cross-file edit, recorded loudly.</strong> <see cref="CBAdESSerialization.WriteHashAlgorithmDigestPair"/>
/// and <see cref="CBAdESSerialization.ReadHashAlgorithmDigestPair"/> were widened from <see langword="private"/>
/// to <see langword="internal"/> (same assembly, no <c>InternalsVisibleTo</c> needed) so
/// <see cref="EncodeCertificateThumbprintSingle"/>/the <c>x5t</c> case of <see cref="ParseCBAdESSign1"/> can
/// reuse the shared <c>COSE_CertHash</c> shape (clause 5.1.7) instead of duplicating the
/// <c>int/tstr</c>-union digest-algorithm-identifier writer/reader — the S1/S2 component codec has no
/// dedicated public entry point for a SINGLE <c>COSE_CertHash</c> (only the plural <c>x5ts</c> array). No
/// other member of <see cref="CBAdESSerialization"/> was touched.
/// </para>
/// <para>
/// <strong>Fourth member added by the t3 firewalled e2e wave, recorded loudly.</strong>
/// <see cref="SerializeCBAdESSign1"/> did not exist when this file's first three members were built — see its
/// own remarks and <see cref="SerializeCBAdESSign1Delegate"/>'s remarks for the gap it closes (a genuinely
/// detached <c>sigD</c> signature could not previously round-trip as detached through any shipped serializer).
/// </para>
/// <para>
/// <strong>Raw <c>uHeaders</c> capture, added at wavecb S4 (coordinator ruling (3)).</strong>
/// <see cref="ParseCBAdESSign1"/> now captures the <c>uHeaders</c> array's own verbatim wire bytes into
/// <see cref="CBAdESSign1ParseResult.RawUnsignedHeaders"/> — an <see cref="EncodedCBAdESUnsignedHeaders"/>
/// carrier mirroring <see cref="EncodedCoseProtectedHeader"/>'s "preserve the original encoding" shape
/// exactly, the same wavecb S3 FX-A precedent that motivated <see cref="CBAdESSign1ParseResult.RawProtectedHeader"/>.
/// The Annex A.1.2.1.2/A.1.2.2.2 <c>sigRTst</c>/<c>rfsTst</c> message-imprint builders consume THESE bytes at
/// validation time; there is no re-encode path.
/// </para>
/// <para>
/// <strong>Parse fail-closed convention, dispose-on-throw.</strong> <see cref="ParseCBAdESSign1"/> never
/// throws for malformed input (contract R-5) — every failure path inside its single try block, including a
/// failed component <c>TryParse*</c> call, is converted to a <see cref="CborContentException"/> throw so ALL
/// exits funnel through the one catch clause, which disposes every already-constructed disposable carrier
/// (the raw protected-header carrier, the five <see cref="CBAdESProtectedHeaders"/>-owned members, the decoded
/// <c>uHeaders</c> set, and the signature carrier) before returning <see cref="CBAdESSign1ParseResult.Failure"/>
/// — the S2 review's "misplaced early-return leaks a partially-parsed carrier" lesson, applied at the
/// message-envelope level; the wavecb S4 raw-<c>uHeaders</c> carrier joins that same cleanup set.
/// </para>
/// </remarks>
public static class CBAdESSignatureSerialization
{
    /// <summary>
    /// Gets a delegate that encodes a <see cref="CBAdESProtectedHeaders"/> aggregate into its canonical CBOR
    /// wire bytes.
    /// </summary>
    /// <remarks>
    /// Every present member is encoded to its own independent CBOR item bytes, collected as
    /// <c>(label, bytes)</c> pairs together with every <see cref="CBAdESProtectedHeaders.UnprofiledHeaders"/>
    /// entry, sorted ascending by label (mirroring <see cref="CoseSerialization.SerializeProtectedHeader"/>'s
    /// own <c>OrderBy(x =&gt; x.Key)</c> canonical-ordering approach), then spliced into one map via
    /// <see cref="CborWriter.WriteEncodedValue(ReadOnlySpan{byte})"/> — the same technique
    /// <see cref="CBAdESSerialization"/>'s <c>uHeaders</c> opaque-arm writers use. This is what makes
    /// interleaving the statically-known profiled labels with the dynamically-keyed unprofiled set correct
    /// without a fixed-position merge.
    /// </remarks>
    public static EncodeCBAdESProtectedHeaderDelegate EncodeCBAdESProtectedHeader { get; } = static (headers, pool) =>
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(pool);

        var entries = new List<(CoseHeaderLabel Label, ReadOnlyMemory<byte> Value)>();

        entries.Add((new CoseHeaderIntegerLabel(CoseHeaderParameters.Alg), EncodeAlgorithm(headers.Algorithm)));

        if(headers.CriticalLabels is not null)
        {
            entries.Add((new CoseHeaderIntegerLabel(CoseHeaderParameters.Crit), EncodeCritical(headers.CriticalLabels)));
        }

        if(headers.ContentType is not null)
        {
            entries.Add((new CoseHeaderIntegerLabel(CoseHeaderParameters.ContentType), EncodeContentType(headers.ContentType)));
        }

        if(headers.KeyId is not null)
        {
            entries.Add((new CoseHeaderIntegerLabel(CoseHeaderParameters.Kid), EncodeKeyId(headers.KeyId.Value)));
        }

        if(headers.CwtClaims is not null)
        {
            entries.Add((new CoseHeaderIntegerLabel(CoseHeaderParameters.CwtClaims), EncodeCwtClaims(headers.CwtClaims)));
        }

        if(headers.X5Chain is not null)
        {
            entries.Add((new CoseHeaderIntegerLabel(CoseHeaderParameters.X5Chain), EncodeSignedX5Chain(headers.X5Chain)));
        }

        if(headers.X5T is not null)
        {
            entries.Add((new CoseHeaderIntegerLabel(CoseHeaderParameters.X5T), EncodeCertificateThumbprintSingle(headers.X5T)));
        }

        if(headers.X5U is not null)
        {
            entries.Add((new CoseHeaderIntegerLabel(CoseHeaderParameters.X5U), EncodeX5Url(headers.X5U)));
        }

        if(headers.CertificateDigests is not null)
        {
            entries.Add((new CoseHeaderIntegerLabel(CBAdESHeaderParameters.X5ts),
                CopyAndDispose(CBAdESSerialization.EncodeCertificateThumbprints(headers.CertificateDigests, pool))));
        }

        if(headers.SignerCommitments is not null)
        {
            entries.Add((new CoseHeaderIntegerLabel(CBAdESHeaderParameters.SrCms),
                CopyAndDispose(CBAdESSerialization.EncodeSignerCommitments(headers.SignerCommitments, pool))));
        }

        if(headers.SignatureProductionPlace is not null)
        {
            entries.Add((new CoseHeaderIntegerLabel(CBAdESHeaderParameters.SigPl),
                CopyAndDispose(CBAdESSerialization.EncodeSignatureProductionPlace(headers.SignatureProductionPlace, pool))));
        }

        if(headers.SignerAttributes is not null)
        {
            entries.Add((new CoseHeaderIntegerLabel(CBAdESHeaderParameters.SrAts),
                CopyAndDispose(CBAdESSerialization.EncodeSignerAttributes(headers.SignerAttributes, pool))));
        }

        if(headers.PayloadTimestamps is not null)
        {
            entries.Add((new CoseHeaderIntegerLabel(CBAdESHeaderParameters.AdoTst),
                CopyAndDispose(CBAdESSerialization.EncodePayloadTimestamp(headers.PayloadTimestamps, pool))));
        }

        if(headers.SignaturePolicyIdentifier is not null)
        {
            entries.Add((new CoseHeaderIntegerLabel(CBAdESHeaderParameters.SigPId),
                CopyAndDispose(CBAdESSerialization.EncodeSignaturePolicyIdentifier(headers.SignaturePolicyIdentifier, pool))));
        }

        if(headers.DetachedObjects is not null)
        {
            entries.Add((new CoseHeaderIntegerLabel(CBAdESHeaderParameters.SigD),
                CopyAndDispose(CBAdESSerialization.EncodeDetachedObjects(headers.DetachedObjects, pool))));
        }

        if(headers.UnprofiledHeaders is not null)
        {
            foreach(KeyValuePair<CoseHeaderLabel, ReadOnlyMemory<byte>> unprofiled in headers.UnprofiledHeaders)
            {
                entries.Add((unprofiled.Key, unprofiled.Value));
            }
        }

        entries.Sort(static (left, right) => CompareByCanonicalLabelEncoding(left.Label, right.Label));

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(entries.Count);
        foreach((CoseHeaderLabel Label, ReadOnlyMemory<byte> Value) entry in entries)
        {
            switch(entry.Label)
            {
                case CoseHeaderIntegerLabel integerLabel:
                    writer.WriteInt32(integerLabel.Value);
                    break;

                case CoseHeaderTextLabel textLabel:
                    writer.WriteTextString(textLabel.Value);
                    break;
            }

            writer.WriteEncodedValue(entry.Value.Span);
        }

        writer.WriteEndMap();

        return EncodedCoseProtectedHeader.FromBytes(writer.Encode(), pool);

        /// <summary>
        /// Compares <paramref name="left"/> and <paramref name="right"/> under the RFC 8949 §4.2.3 canonical
        /// map-key ordering (length-first, then bytewise-lexicographic) over each label's OWN canonical CBOR
        /// encoding — the general <c>label: int / tstr</c> union's ordering (wavecb S3 FX-H), not merely the
        /// integer-only ordering <see cref="CborReaderExtensions.ReadAscendingMapKey"/> implements. The .NET
        /// <see cref="CborConformanceMode.Canonical"/> writer re-sorts the map's entries itself at
        /// <see cref="CborWriter.WriteEndMap"/>, so this explicit sort is documentation-of-intent, not the sole
        /// mechanism producing canonical wire order.
        /// </summary>
        /// <param name="left">The first label to compare.</param>
        /// <param name="right">The second label to compare.</param>
        /// <returns>A negative value, zero, or a positive value per the usual <see cref="IComparer{T}"/> contract.</returns>
        static int CompareByCanonicalLabelEncoding(CoseHeaderLabel left, CoseHeaderLabel right)
        {
            byte[] leftEncoded = EncodeLabelCanonical(left);
            byte[] rightEncoded = EncodeLabelCanonical(right);

            int lengthComparison = leftEncoded.Length.CompareTo(rightEncoded.Length);
            return lengthComparison != 0 ? lengthComparison : leftEncoded.AsSpan().SequenceCompareTo(rightEncoded);

            static byte[] EncodeLabelCanonical(CoseHeaderLabel label)
            {
                var labelWriter = new CborWriter(CborConformanceMode.Canonical);
                switch(label)
                {
                    case CoseHeaderIntegerLabel integerLabel:
                        labelWriter.WriteInt32(integerLabel.Value);
                        break;

                    case CoseHeaderTextLabel textLabel:
                        labelWriter.WriteTextString(textLabel.Value);
                        break;
                }

                return labelWriter.Encode();
            }
        }
    };


    /// <summary>
    /// Gets a delegate that produces the unprotected-header dictionary <see cref="Cose"/>'s signer accepts,
    /// from an optional decoded <see cref="CBAdESUnsignedHeaders"/> set.
    /// </summary>
    /// <remarks>
    /// Reuses <see cref="CBAdESSerialization.EncodeUnsignedHeaders"/> (the existing, tested S2 <c>uHeaders</c>
    /// encoder) rather than duplicating its per-element writer: the whole <c>[+bstr]</c> array is encoded once
    /// through the pool, then immediately read back element-by-element into the
    /// <c>IReadOnlyList&lt;object&gt;</c> of per-element <c>byte[]</c> the seam delegate's documented shape
    /// requires (<see cref="EncodeCBAdESUnprotectedHeaderDelegate"/>'s own remarks) — a deliberate encode-then-
    /// decompose round trip, literally following the task's "reuse the existing S2 uHeaders encode" framing,
    /// not a missed optimization; the alternative would need a THIRD visibility change to
    /// <see cref="CBAdESSerialization"/>'s private per-element writer.
    /// </remarks>
    public static EncodeCBAdESUnprotectedHeaderDelegate EncodeCBAdESUnprotectedHeader { get; } = static (unsignedHeaders, pool) =>
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(unsignedHeaders is null)
        {
            return null;
        }

        using PooledMemory encodedArray = CBAdESSerialization.EncodeUnsignedHeaders(unsignedHeaders, pool);

        var reader = new CborReader(encodedArray.AsReadOnlyMemory(), CborConformanceMode.Canonical);
        int count = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
        var elements = new List<object>(Math.Min(count, 64));
        for(int i = 0; i < count; i++)
        {
            elements.Add(reader.ReadByteString());
        }

        reader.ReadEndArray();

        return new Dictionary<int, object> { [CBAdESHeaderParameters.UHeaders] = elements };
    };


    /// <summary>
    /// Gets a delegate that splices the unprotected-header dictionary an AUGMENTATION verb needs: every
    /// retained <c>uHeaders</c> element's own CONTENT bytes copied verbatim from the raw wire array captured at
    /// parse, plus a freshly-encoded new element appended last. See
    /// <see cref="TrySpliceCBAdESUnprotectedHeaderDelegate"/>'s own remarks for why this exists beside
    /// <see cref="EncodeCBAdESUnprotectedHeader"/> (wavecb S4 FX-A).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Content-only preservation; the outer <c>bstr</c> framing is never carried forward as raw
    /// bytes, and that is provably lossless.</strong> Each retained element's bytes are read via
    /// <see cref="CborReader.ReadByteString"/> — the exact technique <see cref="EncodeCBAdESUnprotectedHeader"/>
    /// already applies to its own freshly re-encoded array — which unwraps the array element's outer
    /// <c>bstr</c> framing and returns only the encapsulated <c>UHeaderInstance</c> map's own content bytes,
    /// untouched. That content is placed into the returned dictionary exactly as
    /// <see cref="EncodeCBAdESUnprotectedHeader"/>'s own output shape requires, so the SAME downstream
    /// general-purpose writer (<see cref="CborValueConverter.WriteValue"/>) re-wraps it in a FRESH <c>bstr</c>
    /// at final serialize time — never a double-wrap, since neither delegate ever hands that writer an
    /// already-framed item. The freshly-written framing is byte-identical to the original: <see cref="ParseCBAdESSign1"/>
    /// reads the augmented signature's raw input under <see cref="CborConformanceMode.Canonical"/>, so every
    /// successfully-parsed element's <c>bstr</c> header is already the RFC 8949 section 9 minimal-length
    /// encoding for that exact content length — the same length-driven encoding the downstream Canonical-mode
    /// writer independently re-derives when it writes the fresh <c>bstr</c> over the identical content. Only a
    /// retained element's CONTENT is ever at risk of drifting (the FX-A defect: re-encoding the DECODED model,
    /// e.g. <see cref="CBAdESSerialization.WriteTDate"/>'s whole-second, forced-<c>Z</c> writer normalizing a
    /// sub-second or non-<c>Z</c>-offset wire <c>tdate</c>) — and this method never performs that re-encode for
    /// a retained element at all; it only ever freshly encodes the genuinely NEW element
    /// <paramref name="newElement" />'s remarks below name.
    /// </para>
    /// <para>
    /// <strong>The count-parity guard below (wavecb S4 FX-A regression) is defense-in-depth, not a reachable
    /// production path.</strong> <see cref="CBAdESSerialization.TryParseUnsignedHeaders"/> decodes exactly one
    /// <see cref="CBAdESUnsignedHeaderElement"/> per raw array entry read from the SAME bytes
    /// <see cref="ParseCBAdESSign1"/> captures verbatim into the <see cref="EncodedCBAdESUnsignedHeaders"/> it
    /// passes here as <c>rawUnsignedHeaders</c> — both walk the identical <c>uHeaders</c> CBOR array — or fails
    /// the WHOLE parse outright on any one element, never a partial/silently-skipped decode. Consequently, for
    /// every successful <see cref="CBAdESSign1ParseResult"/>, its raw array's own element count and its decoded
    /// <see cref="CBAdESSign1ParseResult.UnsignedHeaders"/> count agree BY CONSTRUCTION, and
    /// <see cref="CBAdESSignatureAugmentation"/>'s own <c>EncodeAndSerialize</c> always derives
    /// <c>decodedElementCount</c> from that same <see cref="CBAdESSign1ParseResult"/> instance's
    /// <see cref="CBAdESSign1ParseResult.UnsignedHeaders"/>. The guard below therefore can never fire through
    /// <see cref="ParseCBAdESSign1"/> followed by any shipped augmentation verb; reaching it would require
    /// either a genuine bug in <see cref="CBAdESSerialization.TryParseUnsignedHeaders"/> itself or a
    /// hand-fabricated <see cref="CBAdESSign1ParseResult"/> from a caller-supplied
    /// <see cref="ParseCBAdESSign1Delegate"/> test double — the latter blocked from outside this library's own
    /// assembly boundary by <see cref="CBAdESSign1ParseResult"/>'s <see langword="internal"/> constructor, which
    /// stays internal rather than growing an <c>InternalsVisibleTo</c> grant for this one defensive branch. The
    /// regression exercises this delegate DIRECTLY with a hand-fabricated mismatch instead — a caller-facing
    /// entry point this property already is, needing no internals access.
    /// </para>
    /// </remarks>
    public static TrySpliceCBAdESUnprotectedHeaderDelegate TrySpliceCBAdESUnprotectedHeader { get; } =
        static (EncodedCBAdESUnsignedHeaders? rawUnsignedHeaders, int decodedElementCount, IReadOnlySet<int>? skipDecodedIndexes,
            CBAdESUnsignedHeaderElement? newElement, BaseMemoryPool pool, out IReadOnlyDictionary<int, object>? result) =>
    {
        ArgumentNullException.ThrowIfNull(pool);

        try
        {
            var elements = new List<object>();

            if(rawUnsignedHeaders is not null)
            {
                var reader = new CborReader(rawUnsignedHeaders.AsReadOnlyMemory(), CborConformanceMode.Canonical);
                int rawCount = reader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
                if(rawCount != decodedElementCount)
                {
                    //An internal inconsistency between the parse step and this splice: the raw array's own
                    //element count must match what CBAdESSign1ParseResult.UnsignedHeaders decoded from these
                    //exact bytes, or the positional skipDecodedIndexes classification below would be
                    //meaningless. Fail closed; nothing is emitted. See this property's own remarks (wavecb S4
                    //FX-A) for why this branch is unreachable through ParseCBAdESSign1 + any shipped
                    //augmentation verb, and is instead exercised directly against this delegate.
                    result = null;
                    return false;
                }

                for(int i = 0; i < rawCount; ++i)
                {
                    byte[] elementContent = reader.ReadByteString();
                    if(skipDecodedIndexes is null || !skipDecodedIndexes.Contains(i))
                    {
                        elements.Add(elementContent);
                    }
                }

                reader.ReadEndArray();
                if(reader.BytesRemaining != 0)
                {
                    result = null;
                    return false;
                }
            }
            else if(decodedElementCount != 0)
            {
                //RawUnsignedHeaders is non-null iff UnsignedHeaders is non-null (CBAdESSign1ParseResult's own
                //invariant) -- a null raw array paired with a non-zero decoded count is the same internal
                //inconsistency the count-mismatch branch above guards, just for the absent-array arm.
                result = null;
                return false;
            }

            if(newElement is not null)
            {
                elements.Add(EncodeNewUnsignedHeaderElementContent(newElement, pool));
            }

            if(elements.Count == 0)
            {
                //Nothing retained and nothing new -- matches EncodeCBAdESUnprotectedHeader's own null-for-absent
                //convention (no uHeaders member at all), e.g. StripReferencesForLongTerm stripping everything.
                result = null;
                return true;
            }

            result = new Dictionary<int, object> { [CBAdESHeaderParameters.UHeaders] = elements };
            return true;
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            result = null;
            return false;
        }
    };


    /// <summary>
    /// Gets a delegate that performs the fail-closed full parse of CB-AdES <c>COSE_Sign1</c> wire bytes. See
    /// the class remarks for the tagged-and-untagged acceptance decision, the conformance mode, and the
    /// dispose-on-throw convention every failure path in this delegate follows.
    /// </summary>
    public static ParseCBAdESSign1Delegate ParseCBAdESSign1 { get; } = static (wireBytes, pool) =>
    {
        ArgumentNullException.ThrowIfNull(pool);

        CBAdESCertificateThumbprint? x5t = null;
        CBAdESCertificateThumbprints? certificateDigests = null;
        CBAdESPayloadTimestamp? payloadTimestamps = null;
        CBAdESSignaturePolicyIdentifier? signaturePolicyIdentifier = null;
        CBAdESDetachedObjects? detachedObjects = null;
        CBAdESUnsignedHeaders? unsignedHeaders = null;
        Signature? signatureCarrier = null;
        CBAdESProtectedHeaders? headers = null;
        EncodedCoseProtectedHeader? rawProtectedHeader = null;
        EncodedCBAdESUnsignedHeaders? rawUnsignedHeaders = null;

        try
        {
            var reader = new CborReader(wireBytes, CborConformanceMode.Canonical);

            //CB-4.3: clause 4.3's untagged MAY is CB-AdES-specific (see the class remarks) -- a tag, when
            //present, must be the COSE_Sign1_Tagged value 18; its absence is not itself a failure, unlike
            //CoseSerialization.ParseCoseSign1's tagged-only behavior for the generic COSE_Sign1 substrate.
            if(reader.PeekState() == CborReaderState.Tag)
            {
                CborTag tag = reader.ReadTag();
                if((int)tag != CoseTags.Sign1)
                {
                    throw new CborContentException(
                        $"Expected COSE_Sign1 tag ({CoseTags.Sign1}), got {(int)tag} (ETSI TS 119 152-1 V1.1.1, clause 4.3).");
                }
            }

            reader.ReadStartArrayExpectLength(4);

            //Element 0: body_protected, bstr -- decoded below with its own reader scoped to just these bytes.
            //RawProtectedHeader captures these exact bytes for the validation orchestrator's Sig_structure
            //(RFC 9052 section 4.4) -- never a re-encoding of the decoded headers (wavecb S3 FX-A).
            byte[] protectedHeaderBytes = reader.ReadByteString();
            rawProtectedHeader = EncodedCoseProtectedHeader.FromBytes(protectedHeaderBytes, pool);

            //Element 1: the unprotected headers map -- CB-4.4-01/S3 coordinator ruling (5): at most the one
            //uHeaders (268) member; an empty map means no uHeaders; any other shape fails closed.
            int? unprotectedMapLength = reader.ReadStartMap();
            if(unprotectedMapLength is null)
            {
                throw new CborContentException(
                    "The unprotected headers map shall be definite-length (IETF RFC 9052 section 9).");
            }

            if(unprotectedMapLength.Value > 1)
            {
                throw new CborContentException(
                    $"The unprotected headers map shall contain only the uHeaders member (ETSI TS 119 152-1 " +
                    $"V1.1.1, clause 4.4, CB-4.4-01); got {unprotectedMapLength.Value} members.");
            }

            if(unprotectedMapLength.Value == 1)
            {
                int unprotectedLabel = reader.ReadInt32();
                if(unprotectedLabel != CBAdESHeaderParameters.UHeaders)
                {
                    throw new CborContentException(
                        $"The unprotected headers map shall contain only the uHeaders member (ETSI TS 119 " +
                        $"152-1 V1.1.1, clause 4.4, CB-4.4-01); got label {unprotectedLabel}.");
                }

                //wavecb S4 coordinator ruling (3), the wavecb S3 FX-A raw-bytes precedent extended to
                //uHeaders: capture the exact wire bytes BEFORE handing them to the decoder, so the S4
                //sigRTst/rfsTst message-imprint builders can walk the verbatim encoding at validation time
                //rather than a re-encoding of the decoded CBAdESUnsignedHeaders model.
                ReadOnlyMemory<byte> uHeadersBytes = reader.ReadEncodedValue();
                rawUnsignedHeaders = EncodedCBAdESUnsignedHeaders.FromBytes(uHeadersBytes.Span, pool);

                if(!CBAdESSerialization.TryParseUnsignedHeaders(uHeadersBytes, pool, out unsignedHeaders) || unsignedHeaders is null)
                {
                    throw new CborContentException("Malformed uHeaders (label 268) value.");
                }
            }

            reader.ReadEndMap();

            //Element 2: payload, bstr / nil (clause 4.5).
            bool payloadIsPresent;
            ReadOnlyMemory<byte> payload;
            if(reader.PeekState() == CborReaderState.Null)
            {
                reader.ReadNull();
                payloadIsPresent = false;
                payload = ReadOnlyMemory<byte>.Empty;
            }
            else
            {
                payload = reader.ReadByteString();
                payloadIsPresent = true;
            }

            //Element 3: signature, bstr.
            byte[] signatureBytes = reader.ReadByteString();
            IMemoryOwner<byte> signatureOwner = pool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(signatureOwner.Memory.Span);
            signatureCarrier = new Signature(signatureOwner, CryptoTags.AlgorithmAgnosticSignature);

            reader.ReadEndArray();

            if(reader.BytesRemaining != 0)
            {
                throw new CborContentException("Trailing bytes after the COSE_Sign1 structure.");
            }

            //Decode the protected header map -- CB-4.6-01's integer-only requirement binds the seven clause-5.2
            //CB-AdES components' OWN internal maps (S1/S2, still ReadAscendingMapKey/ReadInt32Array-only), not
            //this outer map's own label space: RFC 9052's general label union (int / tstr) governs THIS map's
            //keys, so they are read via ReadProtectedHeaderMapKey below, enforcing the RFC 8949 section 4.2.3
            //canonical (length-first-then-lex) ordering over each key's ENCODED bytes rather than
            //ReadAscendingMapKey's integer-only comparison (wavecb S3 FX-H) -- unprofiled labels, of either
            //arm, are carried opaque (CB-4.4-07).
            var headerReader = new CborReader(protectedHeaderBytes, CborConformanceMode.Canonical);
            int? headerMapLength = headerReader.ReadStartMap();
            if(headerMapLength is null)
            {
                throw new CborContentException(
                    "The protected headers map shall be definite-length (IETF RFC 9052 section 9).");
            }

            int? algorithm = null;
            CBAdESCwtClaims? cwtClaims = null;
            CBAdESContentTypeIndicator? contentType = null;
            ReadOnlyMemory<byte>? keyId = null;
            Uri? x5u = null;
            CBAdESX5Chain? x5chain = null;
            CBAdESSignerCommitments? signerCommitments = null;
            CBAdESSignatureProductionPlace? signatureProductionPlace = null;
            CBAdESSignerAttributes? signerAttributes = null;
            List<CoseHeaderLabel>? criticalLabels = null;
            Dictionary<CoseHeaderLabel, ReadOnlyMemory<byte>>? unprofiledHeaders = null;
            byte[]? previousProtectedHeaderKeyBytes = null;

            for(int i = 0; i < headerMapLength.Value; i++)
            {
                CoseHeaderLabel label = ReadProtectedHeaderMapKey(headerReader, ref previousProtectedHeaderKeyBytes);
                switch(label)
                {
                    case CoseHeaderIntegerLabel { Value: CoseHeaderParameters.Alg }:
                        algorithm = headerReader.ReadInt32();
                        break;

                    case CoseHeaderIntegerLabel { Value: CoseHeaderParameters.Crit }:
                        criticalLabels = headerReader.ReadCoseHeaderLabelArray();
                        break;

                    case CoseHeaderIntegerLabel { Value: CoseHeaderParameters.ContentType }:
                        contentType = ReadContentType(headerReader);
                        break;

                    case CoseHeaderIntegerLabel { Value: CoseHeaderParameters.Kid }:
                        keyId = headerReader.ReadByteString();
                        break;

                    case CoseHeaderIntegerLabel { Value: CoseHeaderParameters.CwtClaims }:
                        cwtClaims = ReadCwtClaims(headerReader);
                        break;

                    case CoseHeaderIntegerLabel { Value: CoseHeaderParameters.X5Chain }:
                        x5chain = ReadSignedX5Chain(headerReader);
                        break;

                    case CoseHeaderIntegerLabel { Value: CoseHeaderParameters.X5T }:
                        CBAdESSerialization.ReadHashAlgorithmDigestPair(
                            headerReader, pool, out CBAdESDigestAlgorithmIdentifier x5tAlgorithm, out DigestValue x5tDigest);
                        x5t = new CBAdESCertificateThumbprint(x5tAlgorithm, x5tDigest);
                        break;

                    case CoseHeaderIntegerLabel { Value: CoseHeaderParameters.X5U }:
                        x5u = ReadX5Url(headerReader);
                        break;

                    case CoseHeaderIntegerLabel { Value: CBAdESHeaderParameters.X5ts }:
                        if(!CBAdESSerialization.TryParseCertificateThumbprints(headerReader.ReadEncodedValue(), pool, out certificateDigests)
                            || certificateDigests is null)
                        {
                            throw new CborContentException("Malformed x5ts (label 261) component.");
                        }
                        break;

                    case CoseHeaderIntegerLabel { Value: CBAdESHeaderParameters.SrCms }:
                        if(!CBAdESSerialization.TryParseSignerCommitments(headerReader.ReadEncodedValue(), out signerCommitments)
                            || signerCommitments is null)
                        {
                            throw new CborContentException("Malformed srCms (label 262) component.");
                        }
                        break;

                    case CoseHeaderIntegerLabel { Value: CBAdESHeaderParameters.SigPl }:
                        if(!CBAdESSerialization.TryParseSignatureProductionPlace(headerReader.ReadEncodedValue(), out signatureProductionPlace)
                            || signatureProductionPlace is null)
                        {
                            throw new CborContentException("Malformed sigPl (label 263) component.");
                        }
                        break;

                    case CoseHeaderIntegerLabel { Value: CBAdESHeaderParameters.SrAts }:
                        if(!CBAdESSerialization.TryParseSignerAttributes(headerReader.ReadEncodedValue(), out signerAttributes)
                            || signerAttributes is null)
                        {
                            throw new CborContentException("Malformed srAts (label 264) component.");
                        }
                        break;

                    case CoseHeaderIntegerLabel { Value: CBAdESHeaderParameters.AdoTst }:
                        if(!CBAdESSerialization.TryParsePayloadTimestamp(headerReader.ReadEncodedValue(), out payloadTimestamps)
                            || payloadTimestamps is null)
                        {
                            throw new CborContentException("Malformed adoTst (label 265) component.");
                        }
                        break;

                    case CoseHeaderIntegerLabel { Value: CBAdESHeaderParameters.SigPId }:
                        if(!CBAdESSerialization.TryParseSignaturePolicyIdentifier(headerReader.ReadEncodedValue(), pool, out signaturePolicyIdentifier)
                            || signaturePolicyIdentifier is null)
                        {
                            throw new CborContentException("Malformed sigPId (label 266) component.");
                        }
                        break;

                    case CoseHeaderIntegerLabel { Value: CBAdESHeaderParameters.SigD }:
                        if(!CBAdESSerialization.TryParseDetachedObjects(headerReader.ReadEncodedValue(), pool, out detachedObjects)
                            || detachedObjects is null)
                        {
                            throw new CborContentException("Malformed sigD (label 267) component.");
                        }
                        break;

                    default:
                        unprofiledHeaders ??= [];
                        unprofiledHeaders[label] = headerReader.ReadEncodedValue().ToArray();
                        break;
                }
            }

            headerReader.ReadEndMap();

            if(headerReader.BytesRemaining != 0)
            {
                throw new CborContentException("Trailing bytes after the protected headers map.");
            }

            if(algorithm is null)
            {
                throw new CborContentException(
                    "alg (label 1) is mandatory (ETSI TS 119 152-1 V1.1.1, clause 5.1.2, CB-5.1.2-01; clause 6.3, CB-6.3-04).");
            }

            //cwtClaims may be null here -- CWT Claims absent entirely, or present with no iat member -- a legal,
            //non-conformant parsed state (wavecb S3 FX-E): CBAdESHeaderRules.Check reports it as
            //CBAdESCwtClaimsMissingViolation (CB-6.3-10), never this parse step.
            headers = new CBAdESProtectedHeaders(
                algorithm.Value,
                cwtClaims,
                contentType,
                keyId,
                x5u,
                x5t,
                x5chain,
                certificateDigests,
                signerCommitments,
                signatureProductionPlace,
                signerAttributes,
                payloadTimestamps,
                signaturePolicyIdentifier,
                detachedObjects,
                criticalLabels,
                unprofiledHeaders);

            //Ownership of the five disposable components transferred into headers -- null the standalone
            //locals so the catch block's cleanup (defense-in-depth from here on) never double-disposes the
            //same underlying carrier through two reference paths.
            x5t = null;
            certificateDigests = null;
            payloadTimestamps = null;
            signaturePolicyIdentifier = null;
            detachedObjects = null;

            CBAdESSign1ParseResult success = CBAdESSign1ParseResult.Success(headers, rawProtectedHeader, payloadIsPresent, payload, signatureCarrier, unsignedHeaders, rawUnsignedHeaders);
            rawProtectedHeader = null;
            signatureCarrier = null;
            unsignedHeaders = null;
            rawUnsignedHeaders = null;

            return success;
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            headers?.Dispose();
            rawProtectedHeader?.Dispose();
            x5t?.Dispose();
            certificateDigests?.Dispose();
            payloadTimestamps?.Dispose();
            signaturePolicyIdentifier?.Dispose();
            detachedObjects?.Dispose();
            unsignedHeaders?.Dispose();
            rawUnsignedHeaders?.Dispose();
            signatureCarrier?.Dispose();

            return CBAdESSign1ParseResult.Failure();
        }


        /// <summary>
        /// Reads the next protected-header map entry's key as a <see cref="CoseHeaderLabel"/> — the general COSE
        /// <c>label: int / tstr</c> union (RFC 9052 §1.4) this outer map's own label space uses, unlike the
        /// integer-only component internals <see cref="CborReaderExtensions.ReadAscendingMapKey"/> serves
        /// (wavecb S3 FX-H). The key's own ENCODED bytes (<c>CborReader.ReadEncodedValue</c>) are read first and
        /// compared against <paramref name="previousKeyBytes"/> under RFC 8949 §4.2.3's canonical (length-first,
        /// then bytewise-lexicographic) ordering — the same comparison the write side and
        /// <see cref="CborReaderExtensions.ReadAscendingMapKey"/> apply, just over already-encoded bytes rather
        /// than a re-encoded <see langword="int"/> — which also rejects a duplicate key (identical encoded bytes
        /// never sort strictly after themselves). A naive "every integer key before every text key" shortcut
        /// would be WRONG here: a short text key can sort before a longer integer key (e.g. a 2-byte <c>tstr</c>
        /// key sorts before the 3-byte encoding of integer label 268) — this reader never assumes an arm-based
        /// ordering, only the byte-level one RFC 8949 actually defines.
        /// </summary>
        /// <param name="reader">The CBOR reader, positioned at the next map entry's key.</param>
        /// <param name="previousKeyBytes">
        /// The previously read key's encoded bytes, or <see langword="null"/> before the first entry. Updated to
        /// the newly read key's encoded bytes on return.
        /// </param>
        /// <returns>The decoded label.</returns>
        /// <exception cref="CborContentException">
        /// The key does not sort strictly after <paramref name="previousKeyBytes"/> under canonical order.
        /// </exception>
        static CoseHeaderLabel ReadProtectedHeaderMapKey(CborReader reader, ref byte[]? previousKeyBytes)
        {
            ReadOnlyMemory<byte> keyBytes = reader.ReadEncodedValue();
            if(previousKeyBytes is not null && !CborReaderExtensions.IsEncodedKeyAfterInCanonicalOrder(keyBytes.Span, previousKeyBytes))
            {
                throw new CborContentException(
                    "Protected header map keys must be strictly increasing under canonical encoding (IETF RFC " +
                    "8949 section 4.2.3; IETF RFC 7049 section 3.9).");
            }

            previousKeyBytes = keyBytes.ToArray();

            var labelReader = new CborReader(keyBytes, CborConformanceMode.Canonical);
            return labelReader.PeekState() == CborReaderState.TextString
                ? new CoseHeaderTextLabel(labelReader.ReadTextString())
                : new CoseHeaderIntegerLabel(labelReader.ReadInt32());
        }
    };


    /// <summary>
    /// Gets a delegate that serializes a signed CB-AdES <c>COSE_Sign1</c> message to canonical CBOR wire bytes,
    /// writing the CBOR <c>nil</c> sentinel into the <c>payload</c> slot whenever <c>payloadIsDetached</c> is
    /// <see langword="true"/> — see <see cref="SerializeCBAdESSign1Delegate"/>'s remarks for why this exists
    /// beside <see cref="CoseSerialization.SerializeCoseSign1"/> rather than reusing it (the firewalled-e2e
    /// finding that motivated this member).
    /// </summary>
    /// <remarks>
    /// Otherwise identical to <see cref="CoseSerialization.SerializeCoseSign1"/> — same tag-18 envelope, same
    /// unprotected-header-map writing (<see cref="CborValueConverter.WriteValue"/>), same pool-routed
    /// <see cref="EncodedCoseSign1"/> output — the payload branch is the only difference.
    /// </remarks>
    public static SerializeCBAdESSign1Delegate SerializeCBAdESSign1 { get; } = static (message, payloadIsDetached, pool) =>
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag((CborTag)CoseTags.Sign1);
        writer.WriteStartArray(4);

        writer.WriteByteString(message.ProtectedHeader.AsReadOnlySpan());

        if(message.UnprotectedHeader is not null && message.UnprotectedHeader.Count > 0)
        {
            writer.WriteStartMap(message.UnprotectedHeader.Count);
            foreach(KeyValuePair<int, object> entry in message.UnprotectedHeader)
            {
                writer.WriteInt32(entry.Key);
                CborValueConverter.WriteValue(writer, entry.Value);
            }

            writer.WriteEndMap();
        }
        else
        {
            writer.WriteStartMap(0);
            writer.WriteEndMap();
        }

        if(payloadIsDetached)
        {
            writer.WriteNull();
        }
        else
        {
            writer.WriteByteString(message.Payload.Span);
        }

        writer.WriteByteString(message.Signature.AsReadOnlySpan());
        writer.WriteEndArray();

        int size = writer.BytesWritten;
        IMemoryOwner<byte> owner = pool.Rent(size);
        int written = writer.Encode(owner.Memory.Span);
        if(written != size)
        {
            owner.Dispose();
            throw new InvalidOperationException($"CborWriter.Encode wrote {written} bytes, expected {size}.");
        }

        return new EncodedCoseSign1(owner, CryptoTags.CoseEncodedSign1);
    };


    /// <summary>
    /// Encodes <paramref name="algorithm"/> (the <c>alg</c> header, label 1) to its own canonical CBOR item
    /// bytes.
    /// </summary>
    /// <param name="algorithm">The IANA COSE Algorithms identifier.</param>
    /// <returns>The encoded item bytes.</returns>
    private static byte[] EncodeAlgorithm(int algorithm)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteInt32(algorithm);
        return writer.Encode();
    }


    /// <summary>
    /// Encodes <paramref name="criticalLabels"/> (the <c>crit</c> header, label 2) to its own canonical CBOR
    /// item bytes, per-arm (<see cref="CoseHeaderIntegerLabel"/> via <c>WriteInt32</c>,
    /// <see cref="CoseHeaderTextLabel"/> via <c>WriteTextString</c>) — the general <c>label: int / tstr</c>
    /// union RFC 9052 §3.1's <c>crit</c> syntax reuses unnarrowed (wavecb S3 FX-H).
    /// </summary>
    /// <param name="criticalLabels">The critical header-parameter labels, in wire order.</param>
    /// <returns>The encoded item bytes.</returns>
    /// <exception cref="NotSupportedException">A <paramref name="criticalLabels"/> entry is an unknown arm.</exception>
    private static byte[] EncodeCritical(IReadOnlyList<CoseHeaderLabel> criticalLabels)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(criticalLabels.Count);
        foreach(CoseHeaderLabel label in criticalLabels)
        {
            _ = label switch
            {
                CoseHeaderIntegerLabel integerLabel => WriteInteger(writer, integerLabel),
                CoseHeaderTextLabel textLabel => WriteText(writer, textLabel),
                _ => throw new NotSupportedException($"Unknown {nameof(CoseHeaderLabel)} arm '{label.GetType()}'.")
            };
        }

        writer.WriteEndArray();
        return writer.Encode();

        static bool WriteInteger(CborWriter writer, CoseHeaderIntegerLabel integerLabel)
        {
            writer.WriteInt32(integerLabel.Value);
            return true;
        }

        static bool WriteText(CborWriter writer, CoseHeaderTextLabel textLabel)
        {
            writer.WriteTextString(textLabel.Value);
            return true;
        }
    }


    /// <summary>
    /// Encodes <paramref name="contentType"/> (the <c>content type</c> header, label 3) to its own canonical
    /// CBOR item bytes, per the <c>tstr / uint</c> union
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-3.1">RFC 9052 §3.1</see>).
    /// </summary>
    /// <param name="contentType">The content-type indicator.</param>
    /// <returns>The encoded item bytes.</returns>
    /// <exception cref="NotSupportedException"><paramref name="contentType"/> is an unknown arm.</exception>
    private static byte[] EncodeContentType(CBAdESContentTypeIndicator contentType)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        _ = contentType switch
        {
            CBAdESContentTypeText text => WriteText(writer, text),
            CBAdESContentTypeNumeric numeric => WriteNumeric(writer, numeric),
            _ => throw new NotSupportedException($"Unknown content type indicator arm '{contentType.GetType()}'.")
        };

        return writer.Encode();

        static bool WriteText(CborWriter writer, CBAdESContentTypeText text)
        {
            writer.WriteTextString(text.Value);
            return true;
        }

        static bool WriteNumeric(CborWriter writer, CBAdESContentTypeNumeric numeric)
        {
            writer.WriteUInt32(numeric.Value);
            return true;
        }
    }


    /// <summary>
    /// Reads a <c>content type</c> header value (label 3) from <paramref name="reader"/>, per the
    /// <c>tstr / uint</c> union.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed content-type indicator.</returns>
    /// <exception cref="CborContentException">The current item is neither a text string nor an unsigned integer.</exception>
    private static CBAdESContentTypeIndicator ReadContentType(CborReader reader)
    {
        CborReaderState state = reader.PeekState();
        return state switch
        {
            CborReaderState.TextString => new CBAdESContentTypeText(reader.ReadTextString()),
            CborReaderState.UnsignedInteger => new CBAdESContentTypeNumeric(reader.ReadUInt32()),
            _ => throw new CborContentException(
                $"content type: expected tstr or uint (IETF RFC 9052 section 3.1), got {state}.")
        };
    }


    /// <summary>
    /// Encodes <paramref name="keyId"/> (the <c>kid</c> header, label 4) to its own canonical CBOR item bytes.
    /// </summary>
    /// <param name="keyId">The key-identifier bytes.</param>
    /// <returns>The encoded item bytes.</returns>
    private static byte[] EncodeKeyId(ReadOnlyMemory<byte> keyId)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteByteString(keyId.Span);
        return writer.Encode();
    }


    /// <summary>
    /// Encodes <paramref name="cwtClaims"/> (the RFC 9597 CWT-Claims header, label 15) to its own canonical
    /// CBOR item bytes — a one-member map, claim key 6 (<c>iat</c>) to a <c>NumericDate</c> integer of whole
    /// seconds. See the class remarks for the precision and wire-shape decisions.
    /// </summary>
    /// <param name="cwtClaims">The claimed signing-time container.</param>
    /// <returns>The encoded item bytes.</returns>
    private static byte[] EncodeCwtClaims(CBAdESCwtClaims cwtClaims)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCwtClaimNames.Iat);
        writer.WriteInt64(cwtClaims.IssuedAt.ToUnixTimeSeconds());
        writer.WriteEndMap();
        return writer.Encode();
    }


    /// <summary>
    /// Reads a CWT-Claims header value (label 15) from <paramref name="reader"/> — see the class remarks for
    /// the tolerant-sibling-claims decision (wavecb S3 FX-E) and how <c>NumericDate</c> is read.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>
    /// The parsed claimed signing-time container, or <see langword="null"/> when the map is present but carries
    /// no <c>iat</c> member (claim key 6) — a legal, non-conformant wire state
    /// <see cref="CBAdESHeaderRules.Check"/> reports as <see cref="CBAdESCwtClaimsMissingViolation"/>
    /// (CB-6.3-10), never a parse failure.
    /// </returns>
    /// <exception cref="CborContentException">
    /// The map is not definite-length, a claim key is not strictly ascending relative to the previous one
    /// (duplicate or out-of-order), or <c>iat</c>'s value is not a <c>NumericDate</c>.
    /// </exception>
    private static CBAdESCwtClaims? ReadCwtClaims(CborReader reader)
    {
        int? claimCount = reader.ReadStartMap();
        if(claimCount is null)
        {
            throw new CborContentException(
                "CWT Claims (label 15): the claims map shall be definite-length (IETF RFC 9052 section 9).");
        }

        DateTimeOffset? issuedAt = null;
        int previousClaimKey = 0;
        for(int i = 0; i < claimCount.Value; i++)
        {
            int claimKey = reader.ReadAscendingMapKey(ref previousClaimKey);
            if(claimKey == WellKnownCwtClaimNames.Iat)
            {
                issuedAt = ReadNumericDate(reader);
            }
            else
            {
                //RFC 9597's CWT-Claims header container carries an open RFC 8392 claims set; clause 5.1.9
                //restricts nothing beyond requiring iat's presence (CB-6.3-10, not CB-5.1.9-06, which never
                //established exclusivity) -- a sibling claim (e.g. sub, iss) is spec-legal wire content, skipped
                //rather than modeled or rejected.
                reader.SkipValue();
            }
        }

        reader.ReadEndMap();

        //iat absent from a present CWT-Claims map is legal, non-conformant wire content -- the caller
        //(ParseCBAdESSign1) carries this null forward into CBAdESProtectedHeaders.CwtClaims, and
        //CBAdESHeaderRules.Check reports it as CBAdESCwtClaimsMissingViolation (CB-6.3-10); this method never
        //fails closed over it.
        return issuedAt is null ? null : new CBAdESCwtClaims(issuedAt.Value);

        static DateTimeOffset ReadNumericDate(CborReader numericDateReader)
        {
            CborReaderState state = numericDateReader.PeekState();
            return state switch
            {
                CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger =>
                    DateTimeOffset.FromUnixTimeSeconds(numericDateReader.ReadInt64()),
                CborReaderState.HalfPrecisionFloat or CborReaderState.SinglePrecisionFloat or CborReaderState.DoublePrecisionFloat =>
                    DateTimeOffset.UnixEpoch.AddSeconds(numericDateReader.ReadDouble()),
                _ => throw new CborContentException(
                    $"NumericDate: expected an integer or floating-point value (IETF RFC 8392 section 2), got {state}.")
            };
        }
    }


    /// <summary>
    /// Encodes the SIGNED <c>x5chain</c> occurrence (label 33) to its own canonical CBOR item bytes, per the
    /// <c>COSE_X509</c> union (<see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">RFC 9360 §2</see>:
    /// <c>bstr / [2*certs: bstr]</c>).
    /// </summary>
    /// <param name="x5Chain">The signed certificate-chain value.</param>
    /// <returns>The encoded item bytes.</returns>
    /// <exception cref="NotSupportedException"><paramref name="x5Chain"/> is an unknown arm.</exception>
    private static byte[] EncodeSignedX5Chain(CBAdESX5Chain x5Chain)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        _ = x5Chain switch
        {
            CBAdESX5ChainSingleCertificate single => WriteSingle(writer, single),
            CBAdESX5ChainCertificatePath path => WritePath(writer, path),
            _ => throw new NotSupportedException($"Unknown signed x5chain arm '{x5Chain.GetType()}'.")
        };

        return writer.Encode();

        static bool WriteSingle(CborWriter writer, CBAdESX5ChainSingleCertificate single)
        {
            writer.WriteByteString(single.Certificate.Span);
            return true;
        }

        static bool WritePath(CborWriter writer, CBAdESX5ChainCertificatePath path)
        {
            writer.WriteStartArray(path.Certificates.Count);
            foreach(ReadOnlyMemory<byte> certificate in path.Certificates)
            {
                writer.WriteByteString(certificate.Span);
            }

            writer.WriteEndArray();
            return true;
        }
    }


    /// <summary>
    /// Reads the SIGNED <c>x5chain</c> occurrence (label 33) from <paramref name="reader"/>, per the
    /// <c>COSE_X509</c> union.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed signed certificate-chain value.</returns>
    private static CBAdESX5Chain ReadSignedX5Chain(CborReader reader)
    {
        if(reader.PeekState() == CborReaderState.ByteString)
        {
            return new CBAdESX5ChainSingleCertificate(reader.ReadByteString());
        }

        int count = reader.ReadStartArrayExpectLengthRange(CBAdESX5ChainCertificatePath.MinimumCertificateCount, int.MaxValue);
        var certificates = new List<ReadOnlyMemory<byte>>(Math.Min(count, 64));
        for(int i = 0; i < count; i++)
        {
            certificates.Add(reader.ReadByteString());
        }

        reader.ReadEndArray();

        return new CBAdESX5ChainCertificatePath(certificates);
    }


    /// <summary>
    /// Encodes the single-entry <c>x5t</c> header (label 34, <c>COSE_CertHash</c>) to its own canonical CBOR
    /// item bytes, reusing <see cref="CBAdESSerialization.WriteHashAlgorithmDigestPair"/> (see the class
    /// remarks for why this needed a visibility change rather than a duplicate writer).
    /// </summary>
    /// <param name="thumbprint">The signing certificate's digest reference.</param>
    /// <returns>The encoded item bytes.</returns>
    private static byte[] EncodeCertificateThumbprintSingle(CBAdESCertificateThumbprint thumbprint)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        CBAdESSerialization.WriteHashAlgorithmDigestPair(writer, thumbprint.HashAlgorithm, thumbprint.Digest);
        return writer.Encode();
    }


    /// <summary>
    /// Encodes <paramref name="x5u"/> (the <c>x5u</c> header, label 35) to its own canonical CBOR item bytes —
    /// a PLAIN <c>tstr</c>, not a tag-32 URI; see the class remarks for the wire-form decision.
    /// </summary>
    /// <param name="x5u">The certificate-retrieval hint URI.</param>
    /// <returns>The encoded item bytes.</returns>
    private static byte[] EncodeX5Url(Uri x5u)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTextString(x5u.IsAbsoluteUri ? x5u.AbsoluteUri : x5u.OriginalString);
        return writer.Encode();
    }


    /// <summary>
    /// Reads an <c>x5u</c> header value (label 35) from <paramref name="reader"/> — a plain <c>tstr</c>; see
    /// the class remarks.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The parsed certificate-retrieval hint URI.</returns>
    private static Uri ReadX5Url(CborReader reader)
    {
        string text = reader.ReadTextString();
        return new Uri(text, UriKind.RelativeOrAbsolute);
    }


    /// <summary>
    /// Encodes <paramref name="element"/> as a standalone, one-element <c>uHeaders</c> array through the
    /// existing, tested S2 <see cref="CBAdESSerialization.EncodeUnsignedHeaders"/> encoder, then unwraps that
    /// single array entry to return only its own CONTENT bytes — the exact shape
    /// <see cref="TrySpliceCBAdESUnprotectedHeader"/> needs to append a genuinely NEW element beside its
    /// raw-copied retained ones (wavecb S4 FX-A). Reuse over reinvention: this never duplicates
    /// <see cref="CBAdESSerialization"/>'s own per-element writer, which stays <see langword="private"/> to that
    /// class.
    /// </summary>
    /// <param name="element">The freshly-built element to encode.</param>
    /// <param name="pool">The memory pool the transient one-element array encoding rents from.</param>
    /// <returns>The element's own <c>UHeaderInstance</c> map content bytes, unwrapped.</returns>
    private static byte[] EncodeNewUnsignedHeaderElementContent(CBAdESUnsignedHeaderElement element, BaseMemoryPool pool)
    {
        using PooledMemory singleElementArray = CBAdESSerialization.EncodeUnsignedHeaders(new CBAdESUnsignedHeaders([element]), pool);

        var reader = new CborReader(singleElementArray.AsReadOnlyMemory(), CborConformanceMode.Canonical);
        reader.ReadStartArrayExpectLength(1);
        byte[] content = reader.ReadByteString();
        reader.ReadEndArray();

        return content;
    }


    /// <summary>
    /// Copies <paramref name="pooled"/>'s bytes into a freshly-allocated array and disposes
    /// <paramref name="pooled"/> — the boundary between a component's own pool-rented
    /// <see cref="CBAdESSerialization"/> encoding and this class's deferred, sorted-by-label embedding into the
    /// protected-headers map (see <see cref="EncodeCBAdESProtectedHeader"/>'s remarks).
    /// </summary>
    /// <param name="pooled">The pool-rented encoding to copy and dispose.</param>
    /// <returns>An independent copy of <paramref name="pooled"/>'s bytes.</returns>
    private static byte[] CopyAndDispose(PooledMemory pooled)
    {
        using(pooled)
        {
            return pooled.AsReadOnlySpan().ToArray();
        }
    }


    /// <summary>
    /// Determines whether <paramref name="exception"/> represents malformed or non-conformant untrusted CBOR
    /// input that <see cref="ParseCBAdESSign1"/> catches to fail closed, per contract R-5 — mirrors
    /// <see cref="CBAdESSerialization"/>'s own classifier exactly.
    /// </summary>
    /// <param name="exception">The exception to classify.</param>
    /// <returns><see langword="true"/> when the exception should be swallowed and reported as a parse failure.</returns>
    private static bool IsFailClosedParseException(Exception exception) =>
        exception is CborContentException or InvalidOperationException or ArgumentException
            or IndexOutOfRangeException or OverflowException or FormatException;
}
