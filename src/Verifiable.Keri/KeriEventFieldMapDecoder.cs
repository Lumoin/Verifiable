using System;
using Verifiable.Cesr;
using Verifiable.Cryptography;

namespace Verifiable.Keri;

/// <summary>
/// Decodes the bytes of one KERI event serialization into a neutral <see cref="MessageFieldMap"/> for
/// <see cref="KeriEventReader"/> to read. This is the per-serialization seam a KEL stream replay is parameterized
/// by: <see cref="Verifiable.Keri"/> takes no dependency on a concrete serializer (JSON, CBOR, MGPK), so the
/// caller supplies the decoder that matches the stream's serialization — for a KERIpy-style <c>keri.cesr</c>, a
/// JSON decoder.
/// </summary>
/// <param name="serialization">The bytes of one event serialization (an interleaved non-native item read from the stream).</param>
/// <param name="serializationKind">The serialization the bytes are in, as the stream item declared (JSON, CBOR, or MGPK).</param>
/// <returns>The decoded field map in serialization order (an order-preserving map, as <see cref="KeriEventReader"/> requires).</returns>
public delegate MessageFieldMap KeriEventFieldMapDecoder(ReadOnlyMemory<byte> serialization, CesrSerializationKind serializationKind);
