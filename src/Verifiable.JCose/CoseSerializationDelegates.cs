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
/// The output includes the CBOR tag(18) for COSE_Sign1.
/// </para>
/// </remarks>
/// <param name="message">The COSE_Sign1 message to serialize.</param>
/// <returns>The CBOR-encoded COSE_Sign1 bytes with tag(18).</returns>
public delegate byte[] SerializeCoseSign1Delegate(CoseSign1Message message);


/// <summary>
/// Delegate for parsing COSE_Sign1 bytes into a message.
/// </summary>
/// <param name="coseSign1Bytes">The CBOR-encoded COSE_Sign1 bytes.</param>
/// <returns>The parsed COSE_Sign1 message.</returns>
public delegate CoseSign1Message ParseCoseSign1Delegate(ReadOnlyMemory<byte> coseSign1Bytes);


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
/// This is the COSE equivalent of <see cref="JoseKeyContext{TJwtPart}"/>.
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