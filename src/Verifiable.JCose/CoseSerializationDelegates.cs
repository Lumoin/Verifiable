namespace Verifiable.JCose;

/// <summary>
/// Delegate for building the COSE Sig_structure for signing or verification.
/// </summary>
/// <remarks>
/// <para>
/// The Sig_structure is the data that gets signed/verified in COSE_Sign1.
/// Per RFC 9052 §4.4:
/// </para>
/// <code>
/// Sig_structure = [
///     context : "Signature1",
///     body_protected : bstr,  ; Serialized protected header
///     external_aad : bstr,    ; External additional authenticated data
///     payload : bstr          ; The payload
/// ]
/// </code>
/// <para>
/// Implementations should use deterministic CBOR encoding (RFC 8949 §4.2).
/// </para>
/// </remarks>
/// <param name="protectedHeader">The serialized protected header bytes.</param>
/// <param name="payload">The payload bytes.</param>
/// <param name="externalAad">External additional authenticated data (usually empty).</param>
/// <returns>The serialized Sig_structure bytes ready for signing.</returns>
public delegate byte[] BuildSigStructureDelegate(
    ReadOnlySpan<byte> protectedHeader,
    ReadOnlySpan<byte> payload,
    ReadOnlySpan<byte> externalAad);


/// <summary>
/// Delegate for serializing a COSE_Sign1 message to CBOR bytes.
/// </summary>
/// <remarks>
/// <para>
/// The output is wrapped in <see cref="EncodedCoseSign1"/>: a pool-routed
/// semantic carrier holding the CBOR tag(18)-prefixed wire form. Caller
/// owns the returned carrier and disposes it.
/// </para>
/// </remarks>
/// <param name="message">The COSE_Sign1 message to serialize.</param>
/// <param name="pool">Memory pool the carrier rents its buffer from.</param>
/// <returns>The encoded message wrapped in a pool-routed carrier.</returns>
public delegate EncodedCoseSign1 SerializeCoseSign1Delegate(CoseSign1Message message, BaseMemoryPool pool);


/// <summary>
/// Delegate for parsing COSE_Sign1 bytes into a message.
/// </summary>
/// <remarks>
/// <para>
/// The protected header and signature inside the parsed message are
/// pool-routed semantic carriers; the caller owns the returned message
/// and disposes it.
/// </para>
/// </remarks>
/// <param name="coseSign1Bytes">The CBOR-encoded COSE_Sign1 bytes.</param>
/// <param name="pool">Memory pool the inner carriers rent their buffers from.</param>
/// <returns>The parsed COSE_Sign1 message.</returns>
public delegate CoseSign1Message ParseCoseSign1Delegate(ReadOnlyMemory<byte> coseSign1Bytes, BaseMemoryPool pool);


/// <summary>
/// Delegate for building the COSE Sig_structure for signing or verifying a
/// <c>COSE_Signature</c> entry within a <c>COSE_Sign</c> multi-signer message.
/// </summary>
/// <remarks>
/// <para>
/// Per <see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.4">RFC 9052 §4.4</see>,
/// the Sig_structure for the "Signature" context (used with <c>COSE_Signature</c> — i.e.
/// every per-signer entry of a <c>COSE_Sign</c> message) carries a <c>sign_protected</c>
/// field the "Signature1" context's <see cref="BuildSigStructureDelegate"/> has no slot
/// for:
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
/// <para>
/// A sibling delegate, not a widened <see cref="BuildSigStructureDelegate"/>: the two
/// contexts write structurally different array shapes (four elements vs five), so a single
/// widened delegate would need an optional-field discriminator at every call site instead
/// of the type system doing it. <see cref="BuildSigStructureDelegate"/> and its
/// <c>CoseSerialization.BuildSigStructure</c> implementation are unchanged — every existing
/// COSE_Sign1 caller keeps working through them exactly as before.
/// </para>
/// </remarks>
/// <param name="bodyProtectedHeader">The COSE_Sign body layer's serialized protected header bytes.</param>
/// <param name="signProtectedHeader">
/// The signer's own serialized protected header bytes — zero-length when the signer has no
/// protected attributes, per RFC 9052 §4.4's "If there are no protected attributes, a
/// zero-length byte string is used."
/// </param>
/// <param name="payload">The payload bytes.</param>
/// <param name="externalAad">External additional authenticated data (usually empty).</param>
/// <returns>The serialized Sig_structure bytes ready for signing.</returns>
public delegate byte[] BuildCoseSignatureSigStructureDelegate(
    ReadOnlySpan<byte> bodyProtectedHeader,
    ReadOnlySpan<byte> signProtectedHeader,
    ReadOnlySpan<byte> payload,
    ReadOnlySpan<byte> externalAad);


/// <summary>
/// Delegate for serializing a COSE_Sign message to CBOR bytes.
/// </summary>
/// <remarks>
/// <para>
/// The output is wrapped in <see cref="EncodedCoseSign"/>: a pool-routed semantic carrier
/// holding the CBOR tag(98)-prefixed wire form. Caller owns the returned carrier and
/// disposes it.
/// </para>
/// </remarks>
/// <param name="message">The COSE_Sign message to serialize.</param>
/// <param name="pool">Memory pool the carrier rents its buffer from.</param>
/// <returns>The encoded message wrapped in a pool-routed carrier.</returns>
public delegate EncodedCoseSign SerializeCoseSignDelegate(CoseSignMessage message, BaseMemoryPool pool);


/// <summary>
/// Delegate for the fail-closed parse of COSE_Sign bytes into a message.
/// </summary>
/// <remarks>
/// <para>
/// Never throws for malformed input — every failure path returns a
/// <see cref="CoseSignParseResult"/> with <see cref="CoseSignParseResult.IsSuccess"/>
/// <see langword="false"/>, mirroring the CB-AdES <c>ParseCBAdESSign1</c> fail-closed
/// convention (parsing of untrusted bytes never throws). Accepts both the
/// tagged (<c>COSE_Sign_Tagged</c>, CBOR tag 98) and untagged wire forms per RFC 9052
/// §4.1's own "can be encoded as either tagged or untagged, depending on the context" text;
/// any OTHER tag value fails closed.
/// </para>
/// </remarks>
/// <param name="coseSignBytes">The CBOR-encoded COSE_Sign bytes.</param>
/// <param name="pool">Memory pool the inner carriers rent their buffers from.</param>
/// <returns>The parse result.</returns>
public delegate CoseSignParseResult ParseCoseSignDelegate(ReadOnlyMemory<byte> coseSignBytes, BaseMemoryPool pool);


/// <summary>
/// Delegate for serializing a protected header map to CBOR bytes.
/// </summary>
/// <remarks>
/// <para>
/// The protected header is an integer-keyed CBOR map containing parameters
/// like algorithm (1), key ID (4), and content type (3).
/// </para>
/// </remarks>
/// <param name="header">The header parameters as an integer-keyed dictionary.</param>
/// <returns>The CBOR-encoded header bytes.</returns>
public delegate byte[] SerializeProtectedHeaderDelegate(IReadOnlyDictionary<int, object> header);


/// <summary>
/// Delegate for parsing protected header bytes into a dictionary.
/// </summary>
/// <param name="headerBytes">The CBOR-encoded header bytes.</param>
/// <returns>The parsed header as an integer-keyed dictionary.</returns>
public delegate IReadOnlyDictionary<int, object> ParseProtectedHeaderDelegate(ReadOnlySpan<byte> headerBytes);


/// <summary>
/// Context for COSE key resolution containing header and payload information.
/// </summary>
/// <remarks>
/// <para>
/// This is the COSE equivalent of <see cref="JoseKeyContext"/>.
/// Resolvers can examine header parameters (alg, kid) and payload claims
/// to determine which key to load and from where.
/// </para>
/// <para>
/// Unlike JOSE which uses string keys, COSE uses integer keys for headers
/// and may use integer keys for CWT claims.
/// </para>
/// </remarks>
/// <param name="ProtectedHeader">The protected header bytes.</param>
/// <param name="UnprotectedHeader">The unprotected header map, if available.</param>
/// <param name="Payload">The payload bytes.</param>
/// <param name="Algorithm">The algorithm from protected header, if parsed.</param>
/// <param name="KeyId">The key ID from header, if present.</param>
public readonly record struct CoseKeyContext(
    ReadOnlyMemory<byte> ProtectedHeader,
    IReadOnlyDictionary<int, object>? UnprotectedHeader,
    ReadOnlyMemory<byte> Payload,
    int? Algorithm = null,
    string? KeyId = null);
