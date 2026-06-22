using System;
using System.Buffers;

namespace Verifiable.DidComm;

/// <summary>
/// Serializes a DIDComm attachment <c>data.json</c> value — the directly embedded JSON content
/// (DIDComm Messaging v2.1 §Attachments) — to its pooled UTF-8 bytes.
/// </summary>
/// <remarks>
/// <para>
/// The concrete implementation lives in the leaf serialization package (<c>Verifiable.Json</c>); this
/// project is serialization-agnostic and receives the delegate as a parameter, matching the
/// <see cref="DidCommMessageSerializer"/> seam. This is the only place
/// <see cref="System.Text.Json"/> touches a json attachment value, keeping <c>Verifiable.DidComm</c>
/// free of the serializer.
/// </para>
/// <para>
/// The <paramref name="jsonValue"/> is the parsed embedded JSON value (an object graph produced by the
/// plaintext parser). The implementation MUST translate a serialization failure into the
/// framework-neutral <see cref="FormatException"/> so no serializer type escapes the leaf; the resolver
/// then maps that to <see cref="AttachmentResolutionError.MalformedInline"/>.
/// </para>
/// </remarks>
/// <param name="jsonValue">The embedded JSON value to serialize.</param>
/// <param name="memoryPool">The pool the returned owned buffer is drawn from.</param>
/// <returns>An owned buffer holding the value's UTF-8 JSON bytes — exactly the rented length.</returns>
/// <exception cref="FormatException">The value cannot be serialized to JSON.</exception>
public delegate IMemoryOwner<byte> JsonValueSerializer(object jsonValue, MemoryPool<byte> memoryPool);


/// <summary>
/// Selects the hash function for a self-describing multihash algorithm code, or <see langword="null"/>
/// when the code is not supported — the established selector pattern (mirrors
/// <c>Verifiable.Cryptography.DecoderSelector</c> and the DID <c>TypeSelector</c> delegates).
/// </summary>
/// <remarks>
/// <para>
/// An attachment <c>hash</c> is a self-describing multihash whose leading varint <em>code</em> names the
/// digest algorithm (e.g. <c>0x12</c> = sha2-256). The resolver reads that code from the decoded multihash
/// FIRST and asks this selector for the matching <see cref="Verifiable.Cryptography.HashFunctionDelegate"/>;
/// a returned <see langword="null"/> means "no algorithm" — the resolver fails closed as
/// <see cref="AttachmentResolutionError.UnsupportedHashAlgorithm"/> rather than guessing one. The algorithm
/// choice therefore lives in the data, never hardcoded in the resolver.
/// </para>
/// <para>
/// There is no library-baked default: a hash function is cryptographic policy the application (or the test
/// setup) supplies, exactly as the decode/serialize seams are supplied. A typical selector returns
/// <c>SHA256.HashData</c> for the sha2-256 code and <see langword="null"/> for every other code.
/// </para>
/// </remarks>
/// <param name="multihashCode">The self-describing multihash algorithm code read from the decoded <c>hash</c> (e.g. <c>0x12</c> for sha2-256).</param>
/// <returns>The hash function for the code, or <see langword="null"/> when the code is unsupported.</returns>
public delegate Verifiable.Cryptography.HashFunctionDelegate? HashFunctionSelector(int multihashCode);
