using Verifiable.Cryptography.Text;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Version strings an authenticator may report in <c>authenticatorGetInfo</c>'s <c>versions</c> member.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetInfo">
/// CTAP 2.3, section 6.4: authenticatorGetInfo (0x04)</see>: "Supported versions are: 'FIDO_2_3' for
/// CTAP2.3, 'FIDO_2_1' for CTAP2.1, 'FIDO_2_0' for CTAP2.0, 'FIDO_2_1_PRE' for CTAP2.1 Preview
/// features and 'U2F_V2' for CTAP1/U2F authenticators." The same section notes that
/// <c>"FIDO_2_2"</c> was never defined and MUST NOT appear. This is distinct from the NFC
/// binding's Select-response version string (<c>U2F_V2</c>/<c>FIDO_2_0</c> only,
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-applet-selection">
/// section 11.3.3</see>): <c>FIDO_2_3</c> is reported only here, never at Select time.
/// </remarks>
public static class WellKnownCtapVersions
{
    /// <summary>The UTF-8 source literal of <see cref="Fido23"/>.</summary>
    public static ReadOnlySpan<byte> Fido23Utf8 => "FIDO_2_3"u8;

    /// <summary>CTAP2.3.</summary>
    public static readonly string Fido23 = Utf8Constants.ToInternedString(Fido23Utf8);

    /// <summary>The UTF-8 source literal of <see cref="Fido21"/>.</summary>
    public static ReadOnlySpan<byte> Fido21Utf8 => "FIDO_2_1"u8;

    /// <summary>CTAP2.1.</summary>
    public static readonly string Fido21 = Utf8Constants.ToInternedString(Fido21Utf8);

    /// <summary>The UTF-8 source literal of <see cref="Fido21Pre"/>.</summary>
    public static ReadOnlySpan<byte> Fido21PreUtf8 => "FIDO_2_1_PRE"u8;

    /// <summary>CTAP2.1 preview features.</summary>
    public static readonly string Fido21Pre = Utf8Constants.ToInternedString(Fido21PreUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Fido20"/>.</summary>
    public static ReadOnlySpan<byte> Fido20Utf8 => "FIDO_2_0"u8;

    /// <summary>CTAP2.0.</summary>
    public static readonly string Fido20 = Utf8Constants.ToInternedString(Fido20Utf8);

    /// <summary>The UTF-8 source literal of <see cref="U2fV2"/>.</summary>
    public static ReadOnlySpan<byte> U2fV2Utf8 => "U2F_V2"u8;

    /// <summary>CTAP1/U2F.</summary>
    public static readonly string U2fV2 = Utf8Constants.ToInternedString(U2fV2Utf8);


    /// <summary>
    /// Gets a value indicating whether <paramref name="version"/> is <see cref="Fido23"/>.
    /// </summary>
    /// <param name="version">The version string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="version"/> is <c>FIDO_2_3</c>.</returns>
    public static bool IsFido23(string version) => Equals(Fido23, version);

    /// <summary>
    /// Gets a value indicating whether <paramref name="version"/> is <see cref="Fido21"/>.
    /// </summary>
    /// <param name="version">The version string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="version"/> is <c>FIDO_2_1</c>.</returns>
    public static bool IsFido21(string version) => Equals(Fido21, version);

    /// <summary>
    /// Gets a value indicating whether <paramref name="version"/> is <see cref="Fido21Pre"/>.
    /// </summary>
    /// <param name="version">The version string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="version"/> is <c>FIDO_2_1_PRE</c>.</returns>
    public static bool IsFido21Pre(string version) => Equals(Fido21Pre, version);

    /// <summary>
    /// Gets a value indicating whether <paramref name="version"/> is <see cref="Fido20"/>.
    /// </summary>
    /// <param name="version">The version string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="version"/> is <c>FIDO_2_0</c>.</returns>
    public static bool IsFido20(string version) => Equals(Fido20, version);

    /// <summary>
    /// Gets a value indicating whether <paramref name="version"/> is <see cref="U2fV2"/>.
    /// </summary>
    /// <param name="version">The version string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="version"/> is <c>U2F_V2</c>.</returns>
    public static bool IsU2fV2(string version) => Equals(U2fV2, version);


    /// <summary>
    /// Gets a value indicating whether <paramref name="version"/> is one of the version strings
    /// this section defines.
    /// </summary>
    /// <param name="version">The version string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="version"/> is a defined CTAP/U2F version string.</returns>
    public static bool IsKnownVersion(string version) =>
        IsFido23(version) || IsFido21(version) || IsFido21Pre(version) || IsFido20(version) || IsU2fV2(version);


    /// <summary>
    /// Returns a value that indicates if the versions are the same.
    /// </summary>
    /// <param name="versionA">The first version to compare.</param>
    /// <param name="versionB">The second version to compare.</param>
    /// <returns>
    /// <see langword="true" /> if <paramref name="versionA"/> and <paramref name="versionB"/> are the same; otherwise, <see langword="false" />.
    /// </returns>
    public static bool Equals(string versionA, string versionB)
    {
        return object.ReferenceEquals(versionA, versionB) || StringComparer.Ordinal.Equals(versionA, versionB);
    }
}
