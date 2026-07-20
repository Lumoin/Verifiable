namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of the <c>authenticatorGetInfo</c> response structure's members this
/// library models.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetInfo">
/// CTAP 2.3, section 6.4: authenticatorGetInfo (0x04)</see> assigns each response member a small
/// integer key (the CTAP2 wire representation is a CBOR map with integer keys, distinct from the
/// text-string keys WebAuthn-level structures such as <c>attestationObject</c> use). These are true
/// spec literals, hence <see langword="const"/> rather than static getters. Only the members this
/// library's <c>CtapGetInfoResponse</c> model carries are listed; the response structure's ~30-member
/// table has further optional keys this wave does not model. Every integer below was re-verified
/// directly against the response-structure table (never inherited from a prior extraction's
/// paraphrase), per the wave's own R4 ruling.
/// </remarks>
public static class WellKnownCtapGetInfoMemberKeys
{
    /// <summary>The <c>versions</c> member (<c>0x01</c>, Required): the list of supported CTAP/U2F version strings.</summary>
    public const int Versions = 0x01;

    /// <summary>The <c>extensions</c> member (<c>0x02</c>, Optional): the list of supported extension identifiers.</summary>
    public const int Extensions = 0x02;

    /// <summary>The <c>aaguid</c> member (<c>0x03</c>, Required): the 16-byte claimed AAGUID.</summary>
    public const int Aaguid = 0x03;

    /// <summary>The <c>options</c> member (<c>0x04</c>, Optional): the map of supported option IDs to booleans.</summary>
    public const int Options = 0x04;

    /// <summary>
    /// The <c>pinUvAuthProtocols</c> member (<c>0x06</c>, Optional): the list of supported PIN/UV auth
    /// protocols in order of decreasing authenticator preference. MUST NOT contain duplicate values nor
    /// be empty if present.
    /// </summary>
    public const int PinUvAuthProtocols = 0x06;

    /// <summary>
    /// The <c>maxCredentialCountInList</c> member (<c>0x07</c>, Optional): the maximum number of
    /// credentials supported in a <c>credentialID</c> list (<c>excludeList</c>/<c>allowList</c>) at a
    /// time by this authenticator. MUST be greater than zero if present (CTAP 2.3, snapshot lines
    /// 4405-4409).
    /// </summary>
    public const int MaxCredentialCountInList = 0x07;

    /// <summary>
    /// The <c>algorithms</c> member (<c>0x0A</c>, Optional): the list of supported algorithms for
    /// credential generation, an array of <c>PublicKeyCredentialParameters</c> ordered from most
    /// preferred to least preferred. MUST NOT include duplicate entries nor be empty if present (CTAP
    /// 2.3, snapshot lines 4424-4427).
    /// </summary>
    public const int Algorithms = 0x0A;

    /// <summary>
    /// The <c>maxSerializedLargeBlobArray</c> member (<c>0x0B</c>, Optional): the maximum size, in
    /// bytes, of the serialized large-blob array this authenticator can store. MUST be specified iff
    /// <c>authenticatorLargeBlobs</c> is supported (line 4434), and MUST be ≥ 1024 when present (line
    /// 4435). This authenticator always supports the command, so this member is always emitted.
    /// </summary>
    public const int MaxSerializedLargeBlobArray = 0x0B;

    /// <summary>
    /// The <c>forcePINChange</c> member (<c>0x0C</c>, Optional): present and <see langword="true"/>
    /// until a successful PIN change, forcing <c>getPinToken</c>/
    /// <c>getPinUvAuthTokenUsingPinWithPermissions</c> to fail.
    /// </summary>
    public const int ForcePinChange = 0x0C;

    /// <summary>
    /// The <c>minPINLength</c> member (<c>0x0D</c>, Optional): the current minimum PIN length, in
    /// Unicode code points, enforced for ClientPIN.
    /// </summary>
    public const int MinPinLength = 0x0D;

    /// <summary>
    /// The <c>firmwareVersion</c> member (<c>0x0E</c>, Optional): the firmware version of the
    /// authenticator model identified by <c>aaguid</c>. Whenever releasing any code change to the
    /// authenticator firmware, the authenticator MUST increase this version (CTAP 2.3, snapshot lines
    /// 4469-4475).
    /// </summary>
    public const int FirmwareVersion = 0x0E;

    /// <summary>
    /// The <c>maxRPIDsForSetMinPINLength</c> member (<c>0x10</c>, Optional): the maximum number of RP
    /// IDs the authenticator will accept via the <c>setMinPINLength</c> subcommand; <c>0</c> if the
    /// authenticator does not support adding additional RP IDs.
    /// </summary>
    public const int MaxRpIdsForSetMinPinLength = 0x10;

    /// <summary>
    /// The <c>preferredPlatformUvAttempts</c> member (<c>0x11</c>, Optional): the preferred number of
    /// <c>getPinUvAuthTokenUsingUvWithPermissions</c> invocations before the platform falls back to the
    /// PIN path or an error.
    /// </summary>
    public const int PreferredPlatformUvAttempts = 0x11;

    /// <summary>
    /// The <c>uvModality</c> member (<c>0x12</c>, Optional): the FIDO Registry user-verification-method
    /// bit-flags supported via <c>getPinUvAuthTokenUsingUvWithPermissions</c>, a hint for the
    /// platform's own dialog construction.
    /// </summary>
    public const int UvModality = 0x12;

    /// <summary>
    /// The <c>remainingDiscoverableCredentials</c> member (<c>0x14</c>, Optional): the estimated
    /// number of additional discoverable credentials that can be stored. Zero is a legal value.
    /// </summary>
    public const int RemainingDiscoverableCredentials = 0x14;

    /// <summary>
    /// The <c>authenticatorConfigCommands</c> member (<c>0x1F</c>, Optional): present if
    /// <c>authenticatorConfig</c> is supported, listing the <c>authenticatorConfig</c> subcommand
    /// values this authenticator implements (which MAY be empty).
    /// </summary>
    public const int AuthenticatorConfigCommands = 0x1F;


    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Versions"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>versions</c> key.</returns>
    public static bool IsVersions(int key) => key == Versions;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Extensions"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>extensions</c> key.</returns>
    public static bool IsExtensions(int key) => key == Extensions;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Aaguid"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>aaguid</c> key.</returns>
    public static bool IsAaguid(int key) => key == Aaguid;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Options"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>options</c> key.</returns>
    public static bool IsOptions(int key) => key == Options;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PinUvAuthProtocols"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>pinUvAuthProtocols</c> key.</returns>
    public static bool IsPinUvAuthProtocols(int key) => key == PinUvAuthProtocols;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="MaxCredentialCountInList"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>maxCredentialCountInList</c> key.</returns>
    public static bool IsMaxCredentialCountInList(int key) => key == MaxCredentialCountInList;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Algorithms"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>algorithms</c> key.</returns>
    public static bool IsAlgorithms(int key) => key == Algorithms;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="MaxSerializedLargeBlobArray"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>maxSerializedLargeBlobArray</c> key.</returns>
    public static bool IsMaxSerializedLargeBlobArray(int key) => key == MaxSerializedLargeBlobArray;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="ForcePinChange"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>forcePINChange</c> key.</returns>
    public static bool IsForcePinChange(int key) => key == ForcePinChange;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="MinPinLength"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>minPINLength</c> key.</returns>
    public static bool IsMinPinLength(int key) => key == MinPinLength;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="FirmwareVersion"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>firmwareVersion</c> key.</returns>
    public static bool IsFirmwareVersion(int key) => key == FirmwareVersion;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="MaxRpIdsForSetMinPinLength"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>maxRPIDsForSetMinPINLength</c> key.</returns>
    public static bool IsMaxRpIdsForSetMinPinLength(int key) => key == MaxRpIdsForSetMinPinLength;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PreferredPlatformUvAttempts"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>preferredPlatformUvAttempts</c> key.</returns>
    public static bool IsPreferredPlatformUvAttempts(int key) => key == PreferredPlatformUvAttempts;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="UvModality"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>uvModality</c> key.</returns>
    public static bool IsUvModality(int key) => key == UvModality;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="RemainingDiscoverableCredentials"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>remainingDiscoverableCredentials</c> key.</returns>
    public static bool IsRemainingDiscoverableCredentials(int key) => key == RemainingDiscoverableCredentials;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="AuthenticatorConfigCommands"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>authenticatorConfigCommands</c> key.</returns>
    public static bool IsAuthenticatorConfigCommands(int key) => key == AuthenticatorConfigCommands;
}
