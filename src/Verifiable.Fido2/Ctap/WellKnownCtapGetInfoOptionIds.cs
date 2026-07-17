using Verifiable.Cryptography.Text;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Option IDs of the <c>authenticatorGetInfo</c> response's <c>options</c> member.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetInfo">
/// CTAP 2.3, section 6.4: authenticatorGetInfo (0x04)</see>: "All options are in the form key-value
/// pairs with string IDs and boolean values." Unlike the outer response structure's integer keys,
/// option IDs are wire strings, so this follows the library's <c>WellKnown*</c> wire-name
/// convention rather than <see cref="WellKnownCtapGetInfoMemberKeys"/>'s integer-literal table.
/// <see cref="Ep"/>, <see cref="Plat"/>, <see cref="Rk"/>, <see cref="Uv"/>, <see cref="AlwaysUv"/>,
/// <see cref="CredMgmt"/>, <see cref="AuthnrCfg"/>, <see cref="BioEnroll"/>, <see cref="ClientPin"/>,
/// <see cref="LargeBlobs"/>, <see cref="UvBioEnroll"/>, <see cref="PinUvAuthToken"/>,
/// <see cref="SetMinPinLength"/>, and
/// <see cref="MakeCredUvNotRqd"/> are the option IDs this simulator can truthfully report; the
/// remaining option-ID table entries (<c>uvAcfg</c>, <c>noMcGaPermissionsWithClientPin</c>, and so on)
/// describe built-in user-verification surface this authenticator does not implement.
/// <see cref="Ep"/> declares FIRST, ahead of <see cref="Plat"/>/<see cref="Rk"/> even though it is the
/// NEWEST option modeled — R10: this file's declaration order equals canonical wire order, and
/// <c>"ep"</c> (length 2, <c>'e'</c> 0x65) sorts before every other length-2 key (<c>"rk"</c>,
/// <c>"uv"</c>) and every longer one alike.
/// </remarks>
public static class WellKnownCtapGetInfoOptionIds
{
    /// <summary>The UTF-8 source literal of <see cref="Ep"/>.</summary>
    public static ReadOnlySpan<byte> EpUtf8 => "ep"u8;

    /// <summary>
    /// <c>ep</c>: Enterprise Attestation feature support (CTAP 2.3 §7.1.1, snapshot lines 4730-4748) —
    /// present and <see langword="true"/> if capable and enabled, present and <see langword="false"/>
    /// if capable and disabled, absent if the feature is not supported at all (default "not supported"
    /// when absent).
    /// </summary>
    public static readonly string Ep = Utf8Constants.ToInternedString(EpUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Plat"/>.</summary>
    public static ReadOnlySpan<byte> PlatUtf8 => "plat"u8;

    /// <summary>
    /// <c>plat</c>: whether the authenticator is a platform device attached to the client
    /// (default <see langword="false"/> when absent).
    /// </summary>
    public static readonly string Plat = Utf8Constants.ToInternedString(PlatUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Rk"/>.</summary>
    public static ReadOnlySpan<byte> RkUtf8 => "rk"u8;

    /// <summary>
    /// <c>rk</c>: whether the authenticator can create discoverable credentials (default
    /// <see langword="false"/> when absent).
    /// </summary>
    public static readonly string Rk = Utf8Constants.ToInternedString(RkUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Uv"/>.</summary>
    public static ReadOnlySpan<byte> UvUtf8 => "uv"u8;

    /// <summary>
    /// <c>uv</c>: whether the authenticator has a built-in user verification method and, if so, whether
    /// it is presently configured (default "no built-in user verification capability" when absent).
    /// This simulator reports this option present unconditionally from the wave the fingerprint-
    /// enrollment surface ships, tri-state on enrollment count.
    /// </summary>
    public static readonly string Uv = Utf8Constants.ToInternedString(UvUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AlwaysUv"/>.</summary>
    public static ReadOnlySpan<byte> AlwaysUvUtf8 => "alwaysUv"u8;

    /// <summary>
    /// <c>alwaysUv</c>: support for the Always Require User Verification feature — present and
    /// <see langword="true"/> if enabled, present and <see langword="false"/> if supported but
    /// disabled, absent if the feature is not supported at all (default "not supported" when absent).
    /// </summary>
    public static readonly string AlwaysUv = Utf8Constants.ToInternedString(AlwaysUvUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredMgmt"/>.</summary>
    public static ReadOnlySpan<byte> CredMgmtUtf8 => "credMgmt"u8;

    /// <summary>
    /// <c>credMgmt</c>: <c>authenticatorCredentialManagement</c> command support (default "not
    /// supported" when absent). This simulator reports this option present and <see langword="true"/>
    /// unconditionally — support is a static capability of this build.
    /// </summary>
    public static readonly string CredMgmt = Utf8Constants.ToInternedString(CredMgmtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthnrCfg"/>.</summary>
    public static ReadOnlySpan<byte> AuthnrCfgUtf8 => "authnrCfg"u8;

    /// <summary>
    /// <c>authnrCfg</c>: <c>authenticatorConfig</c> command support (default "not supported" when
    /// absent). Platforms MUST NOT invoke <c>authenticatorConfig</c> unless this is present and
    /// <see langword="true"/>.
    /// </summary>
    public static readonly string AuthnrCfg = Utf8Constants.ToInternedString(AuthnrCfgUtf8);

    /// <summary>The UTF-8 source literal of <see cref="BioEnroll"/>.</summary>
    public static ReadOnlySpan<byte> BioEnrollUtf8 => "bioEnroll"u8;

    /// <summary>
    /// <c>bioEnroll</c>: <c>authenticatorBioEnrollment</c> command support, a THREE-valued tri-state
    /// (present-true: supports the commands and has ≥1 enrollment; present-false: supports the
    /// commands with zero enrollments; absent: commands not supported). This simulator reports this
    /// option present unconditionally from the wave the fingerprint-enrollment surface ships.
    /// </summary>
    public static readonly string BioEnroll = Utf8Constants.ToInternedString(BioEnrollUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientPin"/>.</summary>
    public static ReadOnlySpan<byte> ClientPinUtf8 => "clientPin"u8;

    /// <summary>
    /// <c>clientPin</c>: ClientPIN feature support — <see langword="true"/> if a PIN is set,
    /// <see langword="false"/> if the authenticator can accept a PIN but none is set, absent if the
    /// authenticator cannot accept a PIN at all (default "not supported" when absent).
    /// </summary>
    public static readonly string ClientPin = Utf8Constants.ToInternedString(ClientPinUtf8);

    /// <summary>The UTF-8 source literal of <see cref="LargeBlobs"/>.</summary>
    public static ReadOnlySpan<byte> LargeBlobsUtf8 => "largeBlobs"u8;

    /// <summary>
    /// <c>largeBlobs</c>: <c>authenticatorLargeBlobs</c> command support — BINARY, never tri-state
    /// (default "not supported" when absent OR present-false). This simulator reports this option
    /// present and <see langword="true"/> unconditionally — support is a static capability of this
    /// build.
    /// </summary>
    public static readonly string LargeBlobs = Utf8Constants.ToInternedString(LargeBlobsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UvBioEnroll"/>.</summary>
    public static ReadOnlySpan<byte> UvBioEnrollUtf8 => "uvBioEnroll"u8;

    /// <summary>
    /// <c>uvBioEnroll</c>: whether <c>getPinUvAuthTokenUsingUvWithPermissions</c> can grant the
    /// <c>be</c> permission (default "not supported" when absent; MUST only be present if
    /// <see cref="BioEnroll"/> is also present). This simulator reports this option present and
    /// <see langword="true"/> unconditionally — support is a static capability of this build.
    /// </summary>
    public static readonly string UvBioEnroll = Utf8Constants.ToInternedString(UvBioEnrollUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PinUvAuthToken"/>.</summary>
    public static ReadOnlySpan<byte> PinUvAuthTokenUtf8 => "pinUvAuthToken"u8;

    /// <summary>
    /// <c>pinUvAuthToken</c>: whether <c>authenticatorClientPIN</c>'s token-issuing subcommands are
    /// supported (default "not supported" when absent).
    /// </summary>
    public static readonly string PinUvAuthToken = Utf8Constants.ToInternedString(PinUvAuthTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SetMinPinLength"/>.</summary>
    public static ReadOnlySpan<byte> SetMinPinLengthUtf8 => "setMinPINLength"u8;

    /// <summary>
    /// <c>setMinPINLength</c>: support for the <c>authenticatorConfig</c> <c>setMinPINLength</c>
    /// subcommand (default "not supported" when absent).
    /// </summary>
    public static readonly string SetMinPinLength = Utf8Constants.ToInternedString(SetMinPinLengthUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MakeCredUvNotRqd"/>.</summary>
    public static ReadOnlySpan<byte> MakeCredUvNotRqdUtf8 => "makeCredUvNotRqd"u8;

    /// <summary>
    /// <c>makeCredUvNotRqd</c>: whether the authenticator allows creation of non-discoverable
    /// credentials without requiring some form of user verification, when the platform requests that
    /// behaviour (default "some form of user verification is required" when absent).
    /// </summary>
    public static readonly string MakeCredUvNotRqd = Utf8Constants.ToInternedString(MakeCredUvNotRqdUtf8);


    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="Ep"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>ep</c>.</returns>
    public static bool IsEp(string optionId) => Equals(Ep, optionId);

    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="Plat"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>plat</c>.</returns>
    public static bool IsPlat(string optionId) => Equals(Plat, optionId);

    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="Rk"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>rk</c>.</returns>
    public static bool IsRk(string optionId) => Equals(Rk, optionId);

    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="Uv"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>uv</c>.</returns>
    public static bool IsUv(string optionId) => Equals(Uv, optionId);

    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="AlwaysUv"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>alwaysUv</c>.</returns>
    public static bool IsAlwaysUv(string optionId) => Equals(AlwaysUv, optionId);

    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="CredMgmt"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>credMgmt</c>.</returns>
    public static bool IsCredMgmt(string optionId) => Equals(CredMgmt, optionId);

    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="AuthnrCfg"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>authnrCfg</c>.</returns>
    public static bool IsAuthnrCfg(string optionId) => Equals(AuthnrCfg, optionId);

    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="BioEnroll"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>bioEnroll</c>.</returns>
    public static bool IsBioEnroll(string optionId) => Equals(BioEnroll, optionId);

    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="ClientPin"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>clientPin</c>.</returns>
    public static bool IsClientPin(string optionId) => Equals(ClientPin, optionId);

    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="LargeBlobs"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>largeBlobs</c>.</returns>
    public static bool IsLargeBlobs(string optionId) => Equals(LargeBlobs, optionId);

    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="UvBioEnroll"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>uvBioEnroll</c>.</returns>
    public static bool IsUvBioEnroll(string optionId) => Equals(UvBioEnroll, optionId);

    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="PinUvAuthToken"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>pinUvAuthToken</c>.</returns>
    public static bool IsPinUvAuthToken(string optionId) => Equals(PinUvAuthToken, optionId);

    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="SetMinPinLength"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>setMinPINLength</c>.</returns>
    public static bool IsSetMinPinLength(string optionId) => Equals(SetMinPinLength, optionId);

    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="MakeCredUvNotRqd"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>makeCredUvNotRqd</c>.</returns>
    public static bool IsMakeCredUvNotRqd(string optionId) => Equals(MakeCredUvNotRqd, optionId);


    /// <summary>
    /// Returns a value that indicates if the option IDs are the same.
    /// </summary>
    /// <param name="optionIdA">The first option ID to compare.</param>
    /// <param name="optionIdB">The second option ID to compare.</param>
    /// <returns>
    /// <see langword="true" /> if <paramref name="optionIdA"/> and <paramref name="optionIdB"/> are the same; otherwise, <see langword="false" />.
    /// </returns>
    public static bool Equals(string optionIdA, string optionIdB)
    {
        return object.ReferenceEquals(optionIdA, optionIdB) || StringComparer.Ordinal.Equals(optionIdA, optionIdB);
    }
}
