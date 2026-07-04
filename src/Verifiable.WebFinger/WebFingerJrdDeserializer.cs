using System;

namespace Verifiable.WebFinger;

/// <summary>
/// Deserializes a fetched JSON Resource Descriptor (UTF-8 JSON bytes) into a
/// <see cref="JsonResourceDescriptor"/>. Supplied by the JSON layer so <see cref="Verifiable.WebFinger"/>
/// takes no serializer dependency; returns <see langword="null"/> on malformed input rather than throwing.
/// </summary>
/// <remarks>
/// A conforming implementation MUST ignore any unknown member and MUST NOT treat its presence as an error,
/// per <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4">RFC 7033 §4.4</see>; the
/// <see cref="JsonResourceDescriptor"/> model carries only the specified members, so unknown members are
/// dropped by construction.
/// </remarks>
/// <param name="jrdJsonUtf8">The fetched descriptor as UTF-8 JSON bytes.</param>
/// <returns>The parsed descriptor, or <see langword="null"/> when the bytes are not a valid JRD.</returns>
public delegate JsonResourceDescriptor? WebFingerJrdDeserializer(ReadOnlySpan<byte> jrdJsonUtf8);
