using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

//The JAdES JSON serialization seam delegates: the shapes the (later) JAdES creation/validation orchestrators
//consume, implemented in Verifiable.Json. Verifiable.JCose cannot reference
//Verifiable.Json -- the reference graph runs the other way (Verifiable.Json -> Verifiable.JCose ->
//Verifiable.Cryptography) -- so every JSON-shaped operation a JAdES orchestrator needs crosses one of these
//four seams. Mirrors CBAdESSerializationDelegates's shape and doc style; each delegate is documented at its own
//declaration site, matching how that file has no single containing type either.

/// <summary>
/// Encodes a <see cref="JAdESProtectedHeaders"/> aggregate into its base64url-encoded wire TEXT — the JWS
/// Protected Header segment (RFC 7515 §5.1) a JAdES signer's Signing Input embeds.
/// </summary>
/// <remarks>
/// <para>
/// The implementer (<c>Verifiable.Json</c>) serializes <paramref name="headers"/> to its JSON object
/// representation, then base64url-encodes those UTF-8 bytes via <paramref name="base64UrlEncoder"/> — the same
/// encoding delegate <see cref="JwsSerialization"/> already threads through every serialization form, so the
/// resulting <see cref="EncodedJoseProtectedHeader"/> is byte-identical to what a compact/flattened/general JWS
/// serializer would independently produce from the same header object and encoder.
/// </para>
/// </remarks>
/// <param name="headers">The signed-header-set aggregate to encode.</param>
/// <param name="base64UrlEncoder">Delegate for base64url-encoding the serialized JSON bytes (RFC 7515 §2).</param>
/// <param name="pool">Memory pool the returned carrier rents its buffer from.</param>
/// <returns>The encoded protected header, pool-routed. The caller owns and disposes it.</returns>
public delegate EncodedJoseProtectedHeader EncodeJAdESProtectedHeaderDelegate(
    JAdESProtectedHeaders headers, EncodeDelegate base64UrlEncoder, BaseMemoryPool pool);


/// <summary>
/// Decodes a JAdES JWS Protected Header's already base64url-DECODED JSON object bytes into a
/// <see cref="JAdESProtectedHeaders"/> aggregate — the inverse of <see cref="EncodeJAdESProtectedHeaderDelegate"/>
/// over the JSON layer (the base64url segment itself is decoded by the caller, e.g.
/// <see cref="JwsParsing"/>'s own <c>base64UrlDecoder</c> parameter, before these bytes reach this delegate).
/// </summary>
/// <remarks>
/// Fail-closed (contract IRON RULES: strict fail-closed parsing, no exception escapes a parse seam): never
/// throws for malformed input; returns <see langword="null"/> instead. <paramref name="base64UrlDecoder"/> is
/// needed only for the <c>x5t#S256</c> member (RFC 7515 §4.1.8's own base64url-encoded thumbprint) — every other
/// binary member (<c>x5c</c>, <c>x5t#o</c>/<c>sigX5ts</c>'s <c>digVal</c>) is base64-encoded per the Annex B.1
/// schema and decoded directly, needing no delegate.
/// </remarks>
/// <param name="protectedHeaderJsonBytes">The protected header's own UTF-8 JSON object bytes (already base64url-decoded).</param>
/// <param name="base64UrlDecoder">Delegate for base64url-decoding the <c>x5t#S256</c> member.</param>
/// <param name="pool">Memory pool the decoded carriers rent their buffers from.</param>
/// <returns>The decoded aggregate on success; <see langword="null"/> on malformed input.</returns>
public delegate JAdESProtectedHeaders? DecodeJAdESProtectedHeaderDelegate(
    ReadOnlySpan<byte> protectedHeaderJsonBytes, DecodeDelegate base64UrlDecoder, BaseMemoryPool pool);


/// <summary>
/// Fail-closed parse of a JAdES <c>etsiU</c> unsigned-header parameter's own JSON array wire bytes into a
/// <see cref="JAdESUnsignedHeaders"/> aggregate, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.3.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// Detects the whole-array incorporation-mode duality:
/// every array element is either a JSON string (base64url incorporation, JA-5.3.1-09) or a JSON object
/// (clear-JSON incorporation), uniformly — a mixed array is a fail-closed violation (JA-5.3.1-10/-11), reported
/// as a <see langword="false"/> return, never a thrown exception. A base64url-incorporated element's own wire
/// TEXT is captured byte-exact ("decode/re-encode never touches the imprint input") via a span-level scan
/// of <paramref name="etsiUJsonBytes"/> — <paramref name="base64UrlDecoder"/> is used only to determine each
/// such element's <see cref="JAdESUnsignedHeaderElement.Kind"/> (the array element's own decoded content is a
/// single-member <c>{Kind: ...}</c> JSON object), never to reconstruct the imprint-relevant bytes.
/// </para>
/// </remarks>
/// <param name="etsiUJsonBytes">The <c>etsiU</c> header parameter's own JSON array wire bytes (<c>[...]</c>).</param>
/// <param name="base64UrlDecoder">Delegate for base64url-decoding a base64url-incorporated element, for kind detection only.</param>
/// <param name="pool">Memory pool the decoded carriers rent their buffers from.</param>
/// <param name="result">The parsed aggregate on success; <see langword="null"/> on failure.</param>
/// <returns><see langword="true"/> on success; <see langword="false"/> on any malformed or mixed-mode input.</returns>
public delegate bool TryParseJAdESEtsiUDelegate(
    ReadOnlySpan<byte> etsiUJsonBytes, DecodeDelegate base64UrlDecoder, BaseMemoryPool pool, out JAdESUnsignedHeaders? result);


/// <summary>
/// Projects an already-built <see cref="JAdESUnsignedHeaders"/> aggregate onto the JWS Unprotected Header
/// dictionary shape a generic JOSE JSON writer (e.g. <see cref="JwsSerialization.SerializeFlattenedJson"/>/
/// <see cref="JwsSerialization.SerializeGeneralJson"/>'s <c>jsonSerializer</c> parameter) accepts —
/// <see cref="JwsSignatureComponent.UnprotectedHeader"/>'s own <c>IReadOnlyDictionary&lt;string, object&gt;</c>
/// shape, mirroring <see cref="EncodeCBAdESUnprotectedHeaderDelegate"/>'s identical role for CB-AdES's
/// dictionary-shaped COSE unprotected header.
/// </summary>
/// <remarks>
/// <para>
/// Returns, when <paramref name="unsignedHeaders"/> is non-null, a dictionary with EXACTLY one entry —
/// <see cref="WellKnownJAdESHeaderNames.EtsiU"/> mapped to an <c>IReadOnlyList&lt;object&gt;</c> whose elements
/// are each either a <see langword="string"/> (a base64url-incorporated element's own wire TEXT, copied verbatim
/// from <see cref="JAdESOpaqueUnsignedValue{TValue}.WireText"/> — never re-encoded) or a
/// <c>Dictionary&lt;string, object&gt;</c> of shape <c>{Kind: &lt;value&gt;}</c> (a clear-JSON-incorporated
/// element, projected from its decoded <see cref="JAdESClearUnsignedValue{TValue}.Value"/>) — matching JA-5.3.1-03's
/// append-at-end requirement by construction, since this method walks <paramref name="unsignedHeaders"/> in its
/// own already-ordered enumeration order and performs no reordering of its own.
/// </para>
/// <para>
/// <see langword="null"/> <paramref name="unsignedHeaders"/> yields a <see langword="null"/> return — no
/// unprotected header at all, matching <see cref="EncodeCBAdESUnprotectedHeaderDelegate"/>'s identical
/// null-for-absent convention.
/// </para>
/// </remarks>
/// <param name="unsignedHeaders">The already-built <c>etsiU</c> container, or <see langword="null"/> to omit it.</param>
/// <returns>
/// A single-entry dictionary keyed <see cref="WellKnownJAdESHeaderNames.EtsiU"/>, or <see langword="null"/> when
/// <paramref name="unsignedHeaders"/> is <see langword="null"/>.
/// </returns>
public delegate IReadOnlyDictionary<string, object>? EncodeJAdESUnprotectedHeaderDelegate(JAdESUnsignedHeaders? unsignedHeaders);


/// <summary>
/// Fail-closed parse of candidate JAdES wire bytes — any of the three JWS serializations (Compact, Flattened
/// JSON, General JSON) — into an <see cref="UnverifiedJAdESMessage"/>, the validation entry seam (the
/// parse-produces-an-Unverified-result template every parse seam in this family follows).
/// </summary>
/// <remarks>
/// <para>
/// Never throws for malformed input (contract IRON RULES: strict fail-closed parsing, no exception escapes a
/// parse seam); returns <see langword="false"/> instead, mirroring <see cref="TryParseJAdESEtsiUDelegate"/>'s own
/// contract.
/// </para>
/// <para>
/// <strong>Scope: exactly one signature, mirroring the COSE_Sign1-only scope this mirrors on the CB-AdES side.</strong>
/// <see cref="JAdESSignatureCreation"/> always produces a <see cref="JwsMessage"/> carrying exactly one
/// <see cref="JwsSignatureComponent"/> — a General JSON serialization whose <c>signatures</c> array carries more
/// than one element is out of scope here and is reported as a parse failure, not silently truncated to
/// the first entry.
/// </para>
/// </remarks>
/// <param name="wireBytes">The candidate JAdES wire bytes.</param>
/// <param name="base64UrlDecoder">Delegate for base64url-decoding every segment.</param>
/// <param name="pool">Memory pool the decoded carriers rent their buffers from.</param>
/// <param name="message">The parsed message on success; <see langword="null"/> on failure. The caller owns and disposes it.</param>
/// <param name="format">The detected serialization form on success; <see cref="JoseSerializationFormat.Compact"/> on failure (carries no meaning there).</param>
/// <returns><see langword="true"/> on success; <see langword="false"/> on any malformed or out-of-scope input.</returns>
public delegate bool TryParseJAdESMessageDelegate(
    ReadOnlySpan<byte> wireBytes, DecodeDelegate base64UrlDecoder, BaseMemoryPool pool, out UnverifiedJAdESMessage? message, out JoseSerializationFormat format);


/// <summary>
/// Detects whether a JAdES JWS Protected Header's own decoded JSON object bytes carry the forbidden RFC 7515
/// §4.1.8 <c>x5t</c> member (JA-5.1.6-01) — the read-path obligation <see cref="JAdESProtectedHeaders"/>'s
/// own remarks name (its constructor cannot represent the forbidden member at all, so a wire decoder must
/// observe its presence independently).
/// </summary>
/// <remarks>
/// Independent of whether the rest of the header decodes successfully via
/// <see cref="DecodeJAdESProtectedHeaderDelegate"/> — a present <c>x5t</c> is a COLLECTED conformance violation
/// (<see cref="JAdESX5tForbiddenViolation"/>), never a parse failure, so this is a SEPARATE seam rather than an
/// additional out-parameter on <see cref="DecodeJAdESProtectedHeaderDelegate"/> (which already has an established
/// null-on-failure contract and existing callers that do not need this fact). Fail-closed: malformed input
/// returns <see langword="false"/> (no x5t observed) rather than throwing — <see cref="DecodeJAdESProtectedHeaderDelegate"/>
/// would already have reported the same bytes as undecodable via its own <see langword="null"/> return.
/// </remarks>
/// <param name="protectedHeaderJsonBytes">The protected header's own UTF-8 JSON object bytes (already base64url-decoded).</param>
/// <returns><see langword="true"/> when a top-level <c>x5t</c> member is present; otherwise <see langword="false"/>.</returns>
public delegate bool DetectJAdESX5tPresenceDelegate(ReadOnlySpan<byte> protectedHeaderJsonBytes);


/// <summary>
/// Fail-closed decode-for-inspection of a <c>cSig</c> element's own opaque wire text (clause 5.3.2) into
/// the nested JWS/JAdES message it carries — <see cref="JAdESUnsignedHeaderElementCounterSignature"/>'s "gains
/// its decoded view" extension point.
/// </summary>
/// <remarks>
/// <para>
/// The implementer (<c>Verifiable.Json</c>) reproduces the SAME base64url-vs-clear-JSON split
/// <see cref="TryParseJAdESEtsiUDelegate"/>'s own implementer already applies to every other named
/// <c>etsiU</c> arm — <paramref name="containerMode"/> says which — then extracts the single-member <c>cSig</c>
/// JSON object's own value (JA-5.3.2-03: "the <c>cSig</c> JSON object contains one JSON Web Signature"), which
/// is itself EITHER a JSON string (a compact-serialized nested JWS, JA-5.3.2-04) OR a JSON object (a
/// Flattened/General-JSON-serialized nested JWS/JAdES signature, JA-5.3.2-05), and hands the resolved bytes to
/// <see cref="TryParseJAdESMessageDelegate"/> — the SAME parse entry seam a top-level JAdES message uses,
/// reused rather than duplicated.
/// </para>
/// <para>
/// Never throws for malformed input (contract IRON RULES: strict fail-closed parsing); returns
/// <see langword="false"/> instead, mirroring every other <c>TryParse*</c>/<c>TryDecode*</c> seam in this
/// family. This is a decode-for-INSPECTION seam, distinct from the strict etsiU element parse itself
/// (<see cref="TryParseJAdESEtsiUDelegate"/>) — a <c>cSig</c> element whose own nested content fails to decode
/// still parses successfully as an OPAQUE <c>etsiU</c> element (its <see cref="PooledMemory"/> WireText is the
/// message-imprint truth regardless); this seam is called separately, on demand, by a caller that wants the
/// decoded view (typically <see cref="JAdESLevelRules.CheckCounterSignaturesAsync"/>).
/// </para>
/// </remarks>
/// <param name="element">The <c>cSig</c> element to decode.</param>
/// <param name="containerMode">The enclosing <c>etsiU</c> container's whole-array incorporation mode.</param>
/// <param name="base64UrlDecoder">Delegate for base64url-decoding, both for the outer container mode and (via <see cref="TryParseJAdESMessageDelegate"/>) the nested message's own segments.</param>
/// <param name="pool">Memory pool the decoded carriers rent their buffers from.</param>
/// <param name="decoded">The decoded nested message on success; <see langword="null"/> on failure. The caller owns and disposes it.</param>
/// <returns><see langword="true"/> on success; <see langword="false"/> on any malformed or unrecognized shape.</returns>
public delegate bool TryDecodeJAdESCounterSignatureDelegate(
    JAdESUnsignedHeaderElementCounterSignature element,
    JAdESEtsiUIncorporationMode containerMode,
    DecodeDelegate base64UrlDecoder,
    BaseMemoryPool pool,
    out UnverifiedJAdESMessage? decoded);
