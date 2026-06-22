using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.DidComm;

/// <summary>
/// Serializes a <see cref="DidCommMessage"/> to its <c>application/didcomm-plain+json</c> wire form.
/// </summary>
/// <remarks>
/// The concrete implementation lives in the leaf serialization package; this project is
/// serialization-agnostic and receives the delegate as a parameter, matching the JOSE layer's
/// part-encoder seams. The result is a named, pooled <see cref="DidCommPlaintextMessage"/> artifact
/// rather than a bare buffer — the plaintext JWM that a signed or encrypted envelope subsequently wraps.
/// </remarks>
/// <param name="message">The message to serialize.</param>
/// <param name="memoryPool">The pool the returned artifact's owned buffer is drawn from.</param>
/// <returns>The serialized plaintext message artifact.</returns>
public delegate DidCommPlaintextMessage DidCommMessageSerializer(DidCommMessage message, MemoryPool<byte> memoryPool);


/// <summary>
/// Parses the <c>application/didcomm-plain+json</c> bytes of a DIDComm plaintext message into a
/// <see cref="DidCommMessage"/>.
/// </summary>
/// <remarks>
/// The concrete implementation lives in the leaf serialization package. The parser is responsible
/// for the wire-level type discipline — for example mapping the integer <c>created_time</c> /
/// <c>expires_time</c> members to integers and rejecting non-integer values — and for carrying any
/// unrecognized top-level header into <see cref="DidCommMessage.AdditionalHeaders"/>. The
/// domain-level structural validation (required headers, message-type-URI shape, recipient
/// identifier shape) is applied by <see cref="DidCommPlaintextExtensions.UnpackPlaintext"/> after
/// parsing.
/// </remarks>
/// <param name="plaintextJson">The UTF-8 <c>application/didcomm-plain+json</c> bytes.</param>
/// <returns>The parsed message.</returns>
public delegate DidCommMessage DidCommMessageParser(ReadOnlySpan<byte> plaintextJson);


/// <summary>
/// Serializes a signed JWS <paramref name="message"/> to its <see cref="DidCommSignedMessage"/> wire
/// form (General or Flattened JSON serialization).
/// </summary>
/// <remarks>
/// The concrete implementation lives in the leaf serialization package; it owns the JWS JSON
/// serialization (RFC 7515 §7.2), Base64Url-encoding the envelope members through
/// <paramref name="base64UrlEncoder"/>, keeping that machinery out of this transport-agnostic project.
/// </remarks>
/// <param name="message">The signed JWS message (the sender signature over the plaintext JWM).</param>
/// <param name="format">The JWS JSON serialization to emit (General or Flattened).</param>
/// <param name="base64UrlEncoder">Base64Url encoder for the envelope's payload and signature members.</param>
/// <param name="memoryPool">The pool the returned artifact's owned buffer is drawn from.</param>
/// <returns>The serialized signed message artifact.</returns>
public delegate DidCommSignedMessage JwsMessageSerializer(
    JwsMessage message,
    JoseSerializationFormat format,
    EncodeDelegate base64UrlEncoder,
    MemoryPool<byte> memoryPool);


/// <summary>
/// Parses DIDComm signed-message wire bytes (General or Flattened JSON) into the
/// parsed-but-unverified <see cref="UnverifiedJwsMessage"/>.
/// </summary>
/// <remarks>
/// The concrete implementation lives in the leaf serialization package; it owns the JWS JSON parsing
/// (RFC 7515 §7.2), Base64Url-decoding the envelope members through <paramref name="base64UrlDecoder"/>.
/// The returned message is UNTRUSTED — its signature is verified by
/// <see cref="DidCommSignedExtensions.UnpackSignedAsync"/> after the addressing-consistency checks.
/// It owns pooled payload and signature buffers drawn from <paramref name="memoryPool"/> and is
/// disposed by the caller.
/// </remarks>
/// <param name="signedJson">The UTF-8 <c>application/didcomm-signed+json</c> bytes.</param>
/// <param name="base64UrlDecoder">Base64Url decoder for the envelope's payload and signature members.</param>
/// <param name="memoryPool">The pool the parsed payload and signature buffers are drawn from.</param>
/// <returns>The parsed, unverified JWS message.</returns>
public delegate UnverifiedJwsMessage JwsMessageParser(
    ReadOnlySpan<byte> signedJson,
    DecodeDelegate base64UrlDecoder,
    MemoryPool<byte> memoryPool);
