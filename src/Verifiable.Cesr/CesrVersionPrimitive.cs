using Verifiable.Cesr.Text;

namespace Verifiable.Cesr;

/// <summary>
/// Reconstructs and deconstructs the in-memory placeholder version string of a CESR-native message, whose version
/// field is carried as a compact version primitive (a tag) rather than as an embedded version string. The primitive's
/// soft part carries only the protocol and its protocol and genus versions; the serialization kind (always CESR for a
/// native message) and the total byte length come from the native framing, not from the field. This is the native
/// counterpart of <see cref="CesrVersionString"/>, which reads the version string a non-native (JSON, CBOR, MGPK)
/// serialization embeds, and it is shared by the KERI and ACDC native serializations.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#version-string-field">
/// Version String field</see>: a native message body opens with the version primitive, and a decoder reconstructs the
/// placeholder version string the specification prescribes — the protocol and version the primitive carries, the CESR
/// serialization-kind marker, and the total length taken from the framing, terminated by <c>.</c> (the version 2.XX
/// format <c>PPPPMmmGggKKKKBBBB.</c>). The size is not signed in the field because it is carried by the surrounding
/// count code, so the placeholder the specification's worked examples show is what a re-serialization keys on.
/// </para>
/// </remarks>
public static class CesrVersionPrimitive
{
    /// <summary>The serialization-kind marker of a native message's reconstructed version string.</summary>
    private const string NativeKind = "CESR";

    /// <summary>The version 2.XX version-string terminator character.</summary>
    private const string Terminator = ".";

    /// <summary>The number of base-64 characters in the reconstructed version string's length field.</summary>
    private const int LengthCharacters = 4;

    /// <summary>The number of characters in a version string's serialization-kind field.</summary>
    private const int KindCharacters = 4;

    /// <summary>
    /// The number of trailing characters a version 2.XX version string carries that the native version primitive
    /// omits: the serialization kind, the length, and the terminator, all supplied by the native framing.
    /// </summary>
    private const int FramedSuffixLength = KindCharacters + LengthCharacters + 1;


    /// <summary>
    /// Reconstructs the in-memory placeholder version string from the version primitive's protocol-and-version soft:
    /// the serialization kind is CESR and the length is the message's total byte count, since the native framing (not
    /// an embedded version string) carries the size.
    /// </summary>
    /// <param name="protocolAndVersion">The version primitive's soft value: the protocol and its protocol and genus versions.</param>
    /// <param name="totalLength">The total length of the native serialization in bytes.</param>
    /// <returns>The reconstructed version 2.XX placeholder version string.</returns>
    public static string Reconstruct(string protocolAndVersion, int totalLength)
    {
        ArgumentNullException.ThrowIfNull(protocolAndVersion);
        ArgumentOutOfRangeException.ThrowIfNegative(totalLength);

        return protocolAndVersion + NativeKind + CesrTextCodec.IntToBase64(totalLength, LengthCharacters) + Terminator;
    }


    /// <summary>
    /// Extracts the protocol-and-version prefix a native version primitive carries from a full version 2.XX version
    /// string, dropping the serialization kind, length, and terminator (which the native framing carries). This is the
    /// inverse of <see cref="Reconstruct(string, int)"/>, used to encode the version field as its native primitive.
    /// </summary>
    /// <param name="versionString">A complete version 2.XX version string.</param>
    /// <returns>The protocol-and-version prefix, the version primitive's soft value.</returns>
    /// <exception cref="CesrFormatException">The input is too short to be a version 2.XX version string.</exception>
    public static string ProtocolAndVersion(string versionString)
    {
        ArgumentNullException.ThrowIfNull(versionString);

        if(versionString.Length < FramedSuffixLength)
        {
            throw new CesrFormatException($"'{versionString}' is too short to be a version 2.XX version string.");
        }

        return versionString[..^FramedSuffixLength];
    }
}
