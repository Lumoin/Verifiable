using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

//The CB-AdES CBOR serialization seam delegates: the shapes CBAdESSignatureCreation (and the later validation
//orchestrator) consume, implemented in Verifiable.Cbor. Verifiable.JCose cannot reference Verifiable.Cbor — the
//reference graph runs the other way (Verifiable.Cbor -> Verifiable.JCose -> Verifiable.Cryptography) — so every
//CBOR-shaped operation the creation/validation orchestrators need crosses one of these three seams. Mirrors
//CoseSerializationDelegates's shape and doc style (SerializeCoseSign1Delegate, ParseCoseSign1Delegate); each
//delegate and the mint-only parse-result type below is documented at its own declaration site, matching how
//CoseSerializationDelegates has no single containing type either.

/// <summary>
/// Encodes a <see cref="CBAdESProtectedHeaders"/> aggregate into its CBOR wire bytes — the protected-header
/// half of the seam <see cref="CBAdESSignatureCreation"/> composes before calling
/// <see cref="Cose.SignAsync(EncodedCoseProtectedHeader, IReadOnlyDictionary{int, object}?, ReadOnlyMemory{byte}, BuildSigStructureDelegate, PrivateKeyMemory, BaseMemoryPool, CancellationToken)"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The implementer's obligation (documented, not enforced by this delegate's shape).</strong> The
/// encoding shall be deterministic per
/// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-9">RFC 9052 §9</see>'s CBOR encoding
/// restrictions — the same canonical-encoding obligation clause 4.7 imposes on every CBOR component this
/// document encapsulates in a byte string (CB-4.7-02) applies to the protected headers map itself, because
/// the map's own encoded bytes become <c>body_protected</c> in the Sig_structure
/// (<see cref="BuildSigStructureDelegate"/>) both signer and verifier must reproduce byte-for-byte. The
/// implementation in <c>Verifiable.Cbor</c> (stage m4) is expected to route through the same
/// <c>CborConformanceMode.Canonical</c> writer <c>CoseSerialization</c> already uses for the substrate's own
/// protected-header encoding.
/// </para>
/// </remarks>
/// <param name="headers">The signed-header-set aggregate to encode.</param>
/// <param name="pool">Memory pool the returned carrier rents its buffer from.</param>
/// <returns>The encoded protected header, pool-routed. The caller owns and disposes it.</returns>
public delegate EncodedCoseProtectedHeader EncodeCBAdESProtectedHeaderDelegate(CBAdESProtectedHeaders headers, BaseMemoryPool pool);


/// <summary>
/// Produces the unprotected-header dictionary
/// <see cref="Cose.SignAsync(EncodedCoseProtectedHeader, IReadOnlyDictionary{int, object}?, ReadOnlyMemory{byte}, BuildSigStructureDelegate, PrivateKeyMemory, BaseMemoryPool, CancellationToken)"/>
/// accepts, from an optional decoded <see cref="CBAdESUnsignedHeaders"/> model (S3 coordinator ruling (1):
/// layer placement and header-map composition are COSE-structure semantics, so this seam — not the Pki
/// model — owns the projection onto <see cref="CoseSign1Message.UnprotectedHeader"/>'s shape).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Shape decision, recorded loudly.</strong> <see cref="CoseSign1Message.UnprotectedHeader"/> is
/// <c>IReadOnlyDictionary&lt;int, object&gt;?</c>. The general-purpose COSE wire writer
/// (<c>CborValueConverter.WriteValue</c> in <c>Verifiable.Cbor</c>, read in full before this decision was
/// made) already writes an <c>IEnumerable&lt;object?&gt;</c> dictionary value as a CBOR array, dispatching
/// each element back through itself — so a <c>byte[]</c> element inside that enumerable becomes a CBOR byte
/// string, with no further change to the shared writer. The <c>uHeaders</c> CDDL shape is exactly that array-
/// of-byte-strings form:
/// </para>
/// <code>
/// uHeaders = [+bstr .cbor UHeaderInstance]
/// </code>
/// <para>
/// per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.3.1</see> (CB-5.3.1-04: each unsigned attribute is encapsulated in a
/// CBOR byte string BEFORE being placed in the array — the S2 <see cref="CBAdESUnsignedHeaders"/> remarks make
/// the same point from the model side). This delegate therefore returns, when <paramref name="unsignedHeaders"/>
/// is non-null, a dictionary with EXACTLY one entry — <see cref="CBAdESHeaderParameters.UHeaders"/> (268)
/// mapped to an <c>IReadOnlyList&lt;object&gt;</c> whose elements are each one <c>UHeaderInstance</c>'s own
/// already-bstr-encapsulated encoded bytes (a <c>byte[]</c>). No new CBOR-specific carrier type crosses this
/// seam: the existing general-purpose writer produces the exact CDDL shape unmodified. The implementer
/// (<c>Verifiable.Cbor</c>, stage m4) supplies the per-element bstr encoding through the S2
/// <c>CBAdESSerialization</c>/<c>CBAdESMessageImprints</c> machinery; this seam only fixes the dictionary
/// shape both the JCose-layer caller
/// (<see cref="Cose.SignAsync(EncodedCoseProtectedHeader, IReadOnlyDictionary{int, object}?, ReadOnlyMemory{byte}, BuildSigStructureDelegate, PrivateKeyMemory, BaseMemoryPool, CancellationToken)"/>)
/// and the wire writer (<c>CoseSerialization.SerializeCoseSign1</c>) already agree on.
/// </para>
/// <para>
/// <see langword="null"/> <paramref name="unsignedHeaders"/> yields a <see langword="null"/> return — no
/// <c>uHeaders</c> member at all, matching S3 coordinator ruling (5): the unprotected map carries AT MOST
/// the one <c>uHeaders</c> member. <c>CoseSerialization.SerializeCoseSign1</c> already emits an empty map
/// (zero members) for a <see langword="null"/>/empty unprotected header, which satisfies CB-4.4-01's "only
/// one member" constraint by construction — zero is a legal special case of "at most one."
/// </para>
/// </remarks>
/// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set, or <see langword="null"/> to omit it.</param>
/// <param name="pool">Memory pool the per-element encodings rent their buffers from.</param>
/// <returns>
/// A single-entry dictionary keyed <see cref="CBAdESHeaderParameters.UHeaders"/> whose value is an
/// <c>IReadOnlyList&lt;object&gt;</c> of per-element bstr-encapsulated bytes, or <see langword="null"/> when
/// <paramref name="unsignedHeaders"/> is <see langword="null"/>.
/// </returns>
public delegate IReadOnlyDictionary<int, object>? EncodeCBAdESUnprotectedHeaderDelegate(CBAdESUnsignedHeaders? unsignedHeaders, BaseMemoryPool pool);


/// <summary>
/// Fail-closed parse of CB-AdES <c>COSE_Sign1</c> wire bytes into a <see cref="CBAdESSign1ParseResult"/>.
/// </summary>
/// <remarks>
/// <para>
/// Never throws on malformed input (R-5, wavecb-contract.md; matches the <see cref="ParseCoseSign1Delegate"/>/
/// <c>CoseVerification.VerifyAndDecodeAsync</c> fail-closed convention) — a decode failure at any point (bad
/// tag, truncated CBOR framing, a protected-header decode that violates a CB-AdES structural invariant, an
/// unprotected map carrying more than the one <c>uHeaders</c> member per CB-4.4-01) yields
/// <see cref="CBAdESSign1ParseResult.IsSuccess"/> <see langword="false"/>, never a thrown exception. This is
/// a PURE-COMPUTE CBOR decode (no I/O, no cryptography), so the delegate is synchronous, matching
/// <see cref="ParseCoseSign1Delegate"/>.
/// </para>
/// </remarks>
/// <param name="wireBytes">The CBOR-encoded CB-AdES <c>COSE_Sign1</c> wire bytes.</param>
/// <param name="pool">Memory pool the decoded carriers rent their buffers from.</param>
/// <returns>The parse outcome; see <see cref="CBAdESSign1ParseResult"/>. The caller owns and disposes it.</returns>
public delegate CBAdESSign1ParseResult ParseCBAdESSign1Delegate(ReadOnlyMemory<byte> wireBytes, BaseMemoryPool pool);


/// <summary>
/// The outcome of <see cref="ParseCBAdESSign1Delegate"/> — a mint-only decoded CB-AdES <c>COSE_Sign1</c>, or a
/// failure signal, never a thrown exception (see the delegate's remarks).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Mint-only.</strong> The constructor and the <see cref="Success"/>/<see cref="Failure"/> factories
/// are <see langword="internal"/>, so a result with <see cref="IsSuccess"/> <see langword="true"/> can only
/// originate from a CBOR parse implementation this library's own <c>InternalsVisibleTo</c> grants access to
/// (<c>Verifiable.Cbor</c>, which implements <see cref="ParseCBAdESSign1Delegate"/> at stage m4, and
/// <c>Verifiable.Tests</c>) — application code cannot fabricate a "successfully parsed" result. Mirrors
/// <see cref="Verifiable.Cbor.CoseVerificationResult"/>'s mint-only pattern.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Unlike <c>CoseVerificationResult</c> (which copies its payload/header out to
/// GC-owned arrays so it can outlive the parsed message's pooled buffers), this type carries the POOLED
/// carriers directly — <see cref="ProtectedHeaders"/>, <see cref="RawProtectedHeader"/>, <see cref="Signature"/>,
/// and <see cref="UnsignedHeaders"/> are owned by this instance when present; <see cref="Dispose"/> disposes each.
/// This follows R-4 (carriers, not naked bytes): a validation caller typically re-serializes or re-hashes
/// parts of the decoded structure (message-imprint recomputation, EN 319 102-1 checks), so avoiding an extra
/// GC copy on every parse is the right default for this fail-closed-but-otherwise-successful path.
/// <see cref="Payload"/> is a borrowed view (matches <see cref="CoseSign1Message.Payload"/>'s own convention)
/// — GC-owned by the CBOR reader's own allocation, safe to hold past this instance's disposal.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESSign1ParseResult: IsSuccess={IsSuccess}")]
public sealed class CBAdESSign1ParseResult: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new <see cref="CBAdESSign1ParseResult"/>. Ownership of <paramref name="protectedHeaders"/>,
    /// <paramref name="rawProtectedHeader"/>, <paramref name="signature"/>, and <paramref name="unsignedHeaders"/>,
    /// when supplied, transfers to this instance.
    /// </summary>
    /// <param name="isSuccess">See <see cref="IsSuccess"/>.</param>
    /// <param name="protectedHeaders">See <see cref="ProtectedHeaders"/>.</param>
    /// <param name="rawProtectedHeader">See <see cref="RawProtectedHeader"/>.</param>
    /// <param name="payloadIsPresent">See <see cref="PayloadIsPresent"/>.</param>
    /// <param name="payload">See <see cref="Payload"/>.</param>
    /// <param name="signature">See <see cref="Signature"/>.</param>
    /// <param name="unsignedHeaders">See <see cref="UnsignedHeaders"/>.</param>
    internal CBAdESSign1ParseResult(
        bool isSuccess,
        CBAdESProtectedHeaders? protectedHeaders,
        EncodedCoseProtectedHeader? rawProtectedHeader,
        bool payloadIsPresent,
        ReadOnlyMemory<byte> payload,
        Signature? signature,
        CBAdESUnsignedHeaders? unsignedHeaders)
    {
        IsSuccess = isSuccess;
        ProtectedHeaders = protectedHeaders;
        RawProtectedHeader = rawProtectedHeader;
        PayloadIsPresent = payloadIsPresent;
        Payload = payload;
        Signature = signature;
        UnsignedHeaders = unsignedHeaders;
    }


    /// <summary>
    /// Gets whether the wire bytes decoded into a structurally well-formed CB-AdES <c>COSE_Sign1</c>. When
    /// <see langword="false"/>, every other member is at its default (<see langword="null"/>/empty) —
    /// structural well-formedness only; B-B/B-T/B-LT/B-LTA conformance is the later validation orchestrator's
    /// concern (S3 coordinator ruling (6), the <c>CBAdESValidationResult</c> exemplar).
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// Gets the decoded signed-header-set aggregate, or <see langword="null"/> when <see cref="IsSuccess"/> is
    /// <see langword="false"/>. Owned by this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public CBAdESProtectedHeaders? ProtectedHeaders { get; }

    /// <summary>
    /// Gets the raw, undecoded protected-header wire bytes — RFC 9052 §4.4's <c>body_protected</c> byte string,
    /// verbatim — or <see langword="null"/> when <see cref="IsSuccess"/> is <see langword="false"/>. Non-null
    /// iff <see cref="IsSuccess"/> is <see langword="true"/>. A validator MUST build the Sig_structure from
    /// these exact bytes, never a re-encoding of <see cref="ProtectedHeaders"/>: RFC 9052 §4.4 sets
    /// <c>body_protected</c> to the ENCODED bytes as transmitted, and the CDDL that CB-AdES's own CWT-Claims
    /// <c>NumericDate</c> reads tolerantly (<c>int / float</c>, RFC 8392 §2) makes a chosen wire arm
    /// unrecoverable from the decoded value alone — re-encoding could silently pick the wrong arm. Owned by
    /// this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public EncodedCoseProtectedHeader? RawProtectedHeader { get; }

    /// <summary>
    /// Gets whether the wire COSE Payload slot carried a (possibly zero-length) byte string, as opposed to the
    /// CBOR <c>nil</c> detached sentinel (clause 4.5) — the distinction <see cref="Payload"/>'s own emptiness
    /// alone cannot express (a zero-length attached payload and a detached one both leave
    /// <see cref="Payload"/> empty).
    /// </summary>
    public bool PayloadIsPresent { get; }

    /// <summary>
    /// Gets the payload bytes when <see cref="PayloadIsPresent"/> is <see langword="true"/>; otherwise empty.
    /// <strong>Borrowed/GC-owned</strong> view (matches <see cref="CoseSign1Message.Payload"/>'s convention) —
    /// safe to hold past this instance's <see cref="Dispose"/>.
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; }

    /// <summary>
    /// Gets the decoded signature carrier, or <see langword="null"/> when <see cref="IsSuccess"/> is
    /// <see langword="false"/>. Owned by this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public Signature? Signature { get; }

    /// <summary>
    /// Gets the decoded <c>uHeaders</c> unsigned-header set, or <see langword="null"/> when absent from the
    /// wire OR when <see cref="IsSuccess"/> is <see langword="false"/>. Owned by this instance when present;
    /// disposed via <see cref="Dispose"/>.
    /// </summary>
    public CBAdESUnsignedHeaders? UnsignedHeaders { get; }


    /// <summary>
    /// Mints a successful result. Ownership of <paramref name="protectedHeaders"/>, <paramref name="rawProtectedHeader"/>,
    /// <paramref name="signature"/>, and <paramref name="unsignedHeaders"/>, when supplied, transfers to the
    /// returned instance.
    /// </summary>
    /// <param name="protectedHeaders">The decoded signed-header-set aggregate.</param>
    /// <param name="rawProtectedHeader">The raw protected-header wire bytes; see <see cref="RawProtectedHeader"/>.</param>
    /// <param name="payloadIsPresent">See <see cref="PayloadIsPresent"/>.</param>
    /// <param name="payload">The payload bytes; see <see cref="Payload"/>.</param>
    /// <param name="signature">The decoded signature carrier.</param>
    /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set, or <see langword="null"/> when absent.</param>
    /// <returns>A successful <see cref="CBAdESSign1ParseResult"/>.</returns>
    internal static CBAdESSign1ParseResult Success(
        CBAdESProtectedHeaders protectedHeaders,
        EncodedCoseProtectedHeader rawProtectedHeader,
        bool payloadIsPresent,
        ReadOnlyMemory<byte> payload,
        Signature signature,
        CBAdESUnsignedHeaders? unsignedHeaders) =>
        new(true, protectedHeaders, rawProtectedHeader, payloadIsPresent, payload, signature, unsignedHeaders);


    /// <summary>Mints a failed result carrying no decoded content.</summary>
    /// <returns>A failed <see cref="CBAdESSign1ParseResult"/>.</returns>
    internal static CBAdESSign1ParseResult Failure() => new(false, null, null, false, default, null, null);


    /// <summary>
    /// Disposes <see cref="ProtectedHeaders"/>, <see cref="RawProtectedHeader"/>, <see cref="Signature"/>, and
    /// <see cref="UnsignedHeaders"/> when present.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            ProtectedHeaders?.Dispose();
            RawProtectedHeader?.Dispose();
            Signature?.Dispose();
            UnsignedHeaders?.Dispose();
            disposed = true;
        }
    }
}


/// <summary>
/// Serializes a signed CB-AdES <c>COSE_Sign1</c> message to its canonical CBOR wire bytes, honoring clause
/// 4.5's payload-field convention: the wire <c>payload</c> slot
/// (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.2">RFC 9052 §4.2</see>'s <c>payload : bstr /
/// nil</c>) is the CBOR <c>nil</c> sentinel — never an empty byte string — whenever the COSE Payload is
/// detached, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>'s own message-imprint prose: "the bytes of the detached COSE Payload ... if
/// the COSE Payload is detached (the <c>payload</c> field is absent)".
/// </summary>
/// <remarks>
/// <para>
/// <strong>Firewalled-e2e finding (t3, wavecb S3), recorded loudly — a gap the shipped m2/m4 composition left
/// open, closed here.</strong> The generic <see cref="Verifiable.Cbor.CoseSerialization.SerializeCoseSign1"/>
/// delegate always writes the payload slot as a byte string: <see cref="CoseSign1Message.Payload"/> is a plain
/// <see cref="ReadOnlyMemory{T}"/> with no "absent" arm of its own, so that generic serializer cannot tell a
/// genuinely detached payload from an attached, zero-length one — it emits an empty <c>bstr</c> either way.
/// <see cref="CBAdESSignatureCreation"/>'s own class remarks already promise the resulting wire form for every
/// detached arm it produces ("the WIRE payload stays nil"), but before this delegate existed no shipped seam
/// honored that promise: round-tripping a CB-AdES <c>sigD</c>-detached signature through
/// <c>CoseSerialization.SerializeCoseSign1</c> then <see cref="ParseCBAdESSign1Delegate"/> made the parsed
/// payload look ATTACHED (an empty <c>bstr</c> parses as present-but-empty, not nil), which
/// <see cref="CBAdESHeaderRules.Check"/> then rejected as <c>CB-5.2.8-03</c> ("sigD shall not appear ... with
/// an attached COSE Payload") even for a signature <see cref="CBAdESSignatureCreation"/> built correctly. This
/// is precisely the codebase's own existing fix for the identical problem in the mdoc device-signed
/// <c>COSE_Sign1</c> path (a private, file-scoped nil-payload writer in that signer), generalized here into a
/// reusable seam delegate because the CB-AdES creation/validation orchestrators are format-agnostic callers
/// that cannot embed a CBOR writer directly (the same reason <see cref="EncodeCBAdESProtectedHeaderDelegate"/>
/// and <see cref="ParseCBAdESSign1Delegate"/> exist as seams rather than inline code).
/// </para>
/// </remarks>
/// <param name="message">
/// The signed COSE_Sign1 message. Its <see cref="CoseSign1Message.Payload"/> is ignored — never written —
/// when <paramref name="payloadIsDetached"/> is <see langword="true"/>.
/// </param>
/// <param name="payloadIsDetached">
/// Whether the wire <c>payload</c> slot shall be the <c>nil</c> sentinel (clause 4.5) rather than a byte
/// string. The caller supplies this explicitly — it is not derivable from <paramref name="message"/> alone,
/// since an attached, zero-length payload is a distinct, legal wire shape (see
/// <see cref="CBAdESSign1ParseResult.PayloadIsPresent"/>'s own remarks).
/// </param>
/// <param name="pool">Memory pool the returned carrier rents its buffer from.</param>
/// <returns>The encoded COSE_Sign1 wire bytes, pool-routed. The caller owns and disposes it.</returns>
public delegate EncodedCoseSign1 SerializeCBAdESSign1Delegate(CoseSign1Message message, bool payloadIsDetached, BaseMemoryPool pool);
