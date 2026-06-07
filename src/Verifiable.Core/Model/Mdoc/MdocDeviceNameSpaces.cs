namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// The <c>DeviceNameSpaces</c> structure per ISO/IEC 18013-5 §8.3.2.1.2.3 —
/// the device-half claim map presented at presentation time.
/// </summary>
/// <remarks>
/// <para>
/// Unlike <see cref="MdocIssuerSigned.NameSpaces"/> (which carries items the
/// issuer committed to via the MSO), <see cref="Entries"/> here holds
/// claims the device asserts on its own, identified by namespace and
/// element identifier. There are no per-item randoms or digestIDs because
/// these claims are not committed by the issuer — they are bound only by
/// the COSE_Sign1 / COSE_Mac0 over the enclosing
/// <c>DeviceAuthentication</c> structure.
/// </para>
/// <para>
/// In most ISO 18013-5 presentation flows <see cref="Entries"/> is empty
/// (the issuer's items in <c>IssuerSigned</c> carry the data and the
/// device signature merely proves the wallet possesses the bound device
/// key). The data model supports non-empty entries for flows that need
/// them — for example wallet-side timestamps or session-specific values.
/// </para>
/// </remarks>
public sealed class MdocDeviceNameSpaces
{
    /// <summary>
    /// Initializes a <c>DeviceNameSpaces</c> from caller-supplied entries.
    /// </summary>
    /// <param name="entries">
    /// The namespace → element-identifier → encoded-element-value map.
    /// May be empty (the typical case).
    /// </param>
    public MdocDeviceNameSpaces(
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, ReadOnlyMemory<byte>>> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        Entries = entries;
    }


    /// <summary>
    /// The namespace → element-identifier → encoded-element-value map.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyDictionary<string, ReadOnlyMemory<byte>>> Entries { get; }


    /// <summary>An empty <c>DeviceNameSpaces</c> — the common case where the device asserts no claims of its own.</summary>
    public static MdocDeviceNameSpaces Empty { get; } =
        new(new Dictionary<string, IReadOnlyDictionary<string, ReadOnlyMemory<byte>>>(StringComparer.Ordinal));
}
