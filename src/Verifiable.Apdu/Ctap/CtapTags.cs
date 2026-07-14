namespace Verifiable.Apdu.Ctap;

/// <summary>
/// The <see cref="BufferKind"/> values the CTAP2-over-NFC binding registers on the domain-neutral
/// <see cref="BufferKind"/> discriminator.
/// </summary>
/// <remarks>
/// Registered via <see cref="BufferKind.Create"/> with a code above 1000, per the documented custom
/// buffer-kind seam (<see cref="BufferKind"/> remarks) — a CTAP2 envelope (a status/command byte
/// followed by CBOR data) is neither plain JSON nor plain CBOR from this transport's point of view.
/// </remarks>
public static class CtapBufferKinds
{
    /// <summary>
    /// A complete CTAP2 request or response envelope: a command or status byte followed by
    /// CBOR-encoded data, opaque to the NFC transport.
    /// </summary>
    public static BufferKind CtapEnvelope { get; } = BufferKind.Create(1101);
}


/// <summary>
/// Predefined <see cref="Tag"/> instances for CTAP2-over-NFC pooled buffers.
/// </summary>
public static class CtapTags
{
    /// <summary>
    /// Tag for a CTAP2 response envelope handed back from <see cref="CtapNfcTransport"/> in a
    /// <see cref="PooledMemory"/>, or accepted by <see cref="CtapNfcResponder"/> in the same carrier.
    /// </summary>
    public static Tag ResponseEnvelope { get; } = Tag.Create(CtapBufferKinds.CtapEnvelope);
}
