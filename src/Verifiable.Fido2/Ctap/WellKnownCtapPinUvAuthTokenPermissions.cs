namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>pinUvAuthToken</c> permission bitfield values <c>authenticatorClientPIN</c>'s
/// <c>getPinUvAuthTokenUsingPinWithPermissions</c>/<c>getPinUvAuthTokenUsingUvWithPermissions</c>
/// subcommands' <c>permissions</c> parameter carries, and that a token's own permissions set
/// (<c>CtapPinUvAuthTokenState.Permissions</c>) stores.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN">
/// CTAP 2.3, section 6.5.5: authenticatorClientPIN Command Definition</see>, the "pinUvAuthToken
/// permissions" table (line 5758-5827). The full seven-value table is modeled so a later package's
/// permission-statement gating (line 5955-5971) does not need a new vocabulary type, mirroring
/// <see cref="WellKnownCtapClientPinSubCommands"/>'s "model the full shape now" convention. This
/// authenticator's <c>getInfo</c> advertises no <c>perCredMgmtRO</c> option (and always advertises
/// <c>authnrCfg:true</c>, <c>credMgmt:true</c>, <c>largeBlobs:true</c>, and <c>bioEnroll</c> present
/// tri-state) — so <see cref="Mc"/>, <see cref="Ga"/>, <see cref="Acfg"/>, <see cref="Cm"/>,
/// <see cref="Be"/>, and <see cref="Lbw"/> are the only permissions ever grantable (via the PIN path;
/// <c>getPinUvAuthTokenUsingUvWithPermissions</c>'s own §6.5.5.7.3 statement list denies <see cref="Acfg"/>
/// while granting the same other five, R5) — <see cref="Pcmr"/> is the sole permission this profile can
/// never grant on either token path. Every bit's value is spec-fixed regardless of which are reachable.
/// </remarks>
public static class WellKnownCtapPinUvAuthTokenPermissions
{
    /// <summary>
    /// <c>mc</c> (<c>0x01</c>, MakeCredential, RP ID Required): permits the token for
    /// <c>authenticatorMakeCredential</c> operations against the token's permissions RP ID.
    /// </summary>
    public const int Mc = 0x01;

    /// <summary>
    /// <c>ga</c> (<c>0x02</c>, GetAssertion, RP ID Required): permits the token for
    /// <c>authenticatorGetAssertion</c> operations against the token's permissions RP ID.
    /// </summary>
    public const int Ga = 0x02;

    /// <summary>
    /// <c>cm</c> (<c>0x04</c>, Credential Management, RP ID Optional): permits the token for
    /// <c>authenticatorCredentialManagement</c>. Grantable via
    /// <c>getPinUvAuthTokenUsingPinWithPermissions</c> — this authenticator always advertises
    /// <c>credMgmt:true</c>, so the permission-statement gate's <c>cm</c> bullet (line 5958,
    /// "credMgmt is false or absent") never denies it. Unlike <see cref="Mc"/>/<see cref="Ga"/>'s
    /// "Required" RP ID column, a <c>cm</c> request's <c>rpId</c> is Optional: present associates the
    /// token with that RP (line 6024's unconditional association), absent leaves it unbound.
    /// </summary>
    public const int Cm = 0x04;

    /// <summary>
    /// <c>be</c> (<c>0x08</c>, Bio Enrollment, RP ID Ignored): permits the token for
    /// <c>authenticatorBioEnrollment</c>. Grantable via
    /// <c>getPinUvAuthTokenUsingPinWithPermissions</c> — this authenticator always advertises
    /// <c>bioEnroll</c> present (true or false tri-state), so the permission-statement gate's
    /// <c>be</c> bullet (line 5960, "bioEnroll is absent") never denies it. Its RP ID column is
    /// "Ignored", like <see cref="Acfg"/>'s: it never joins the <c>mc</c>/<c>ga</c>-only "RP ID
    /// Required" check, and a <c>be</c>-permissioned token's <c>rpId</c> is never consulted by any
    /// <c>authenticatorBioEnrollment</c> handler.
    /// </summary>
    public const int Be = 0x08;

    /// <summary>
    /// <c>lbw</c> (<c>0x10</c>, Large Blob Write, RP ID Ignored): permits the token for
    /// <c>authenticatorLargeBlobs</c>. The one permission a user-presence-testing operation preserves
    /// when it otherwise clears a token's permissions set (line 5828). Grantable on BOTH token paths —
    /// <c>getPinUvAuthTokenUsingPinWithPermissions</c> AND <c>getPinUvAuthTokenUsingUvWithPermissions</c>
    /// — since this authenticator always advertises <c>largeBlobs:true</c> in <c>getInfo</c>, and both
    /// paths' own denial bullets read identically: "largeBlobs is <see langword="false"/> or absent"
    /// (lines 5962/6070), which never holds here.
    /// </summary>
    public const int Lbw = 0x10;

    /// <summary>
    /// <c>acfg</c> (<c>0x20</c>, Authenticator Configuration, RP ID Ignored): permits the token for
    /// <c>authenticatorConfig</c>. Grantable via <c>getPinUvAuthTokenUsingPinWithPermissions</c> — this
    /// authenticator always advertises <c>authnrCfg:true</c>, so the permission-statement gate's
    /// <c>acfg</c> bullet (line 5964, "authnrCfg is false or absent") never denies it. Not grantable via
    /// <c>getPinUvAuthTokenUsingUvWithPermissions</c>: <c>uvAcfg</c> stays permanently absent, so 0x06's
    /// own §6.5.5.7.3 statement list (distinct from the PIN path's, R5) denies <c>acfg</c> outright —
    /// <c>CTAP2_ERR_UNAUTHORIZED_PERMISSION</c> — regardless of which other permissions accompany the
    /// request.
    /// </summary>
    public const int Acfg = 0x20;

    /// <summary>
    /// <c>pcmr</c> (<c>0x40</c>, Persistent Credential Management Read Only, RP ID Ignored): binds
    /// <c>persistentPinUvAuthToken</c>, not <c>pinUvAuthToken</c>. Not grantable under this
    /// authenticator's profile (<c>perCredMgmtRO</c> is absent from <c>getInfo</c>), which makes
    /// <c>persistentPinUvAuthToken</c> issuance structurally unreachable. Whenever <c>perCredMgmtRO</c>
    /// ships, its own denial bullet is a CONJUNCTION, not a simple gate (line 5970): "perCredMgmtRO is
    /// <see langword="false"/> or absent, OR any other pinUvAuthToken permission is requested" —
    /// <c>pcmr</c> must be requested ALONE in the <c>permissions</c> parameter; combining it with
    /// <see cref="Cm"/> or anything else denies it even when <c>perCredMgmtRO</c> is advertised
    /// <see langword="true"/>.
    /// </summary>
    public const int Pcmr = 0x40;


    /// <summary>Gets a value indicating whether <paramref name="permissions"/> is exactly <see cref="Mc"/>.</summary>
    /// <param name="permissions">The permissions bitfield value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="permissions"/> is exactly the <c>mc</c> bit.</returns>
    public static bool IsMc(int permissions) => permissions == Mc;

    /// <summary>Gets a value indicating whether <paramref name="permissions"/> is exactly <see cref="Ga"/>.</summary>
    /// <param name="permissions">The permissions bitfield value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="permissions"/> is exactly the <c>ga</c> bit.</returns>
    public static bool IsGa(int permissions) => permissions == Ga;

    /// <summary>Gets a value indicating whether <paramref name="permissions"/> is exactly <see cref="Cm"/>.</summary>
    /// <param name="permissions">The permissions bitfield value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="permissions"/> is exactly the <c>cm</c> bit.</returns>
    public static bool IsCm(int permissions) => permissions == Cm;

    /// <summary>Gets a value indicating whether <paramref name="permissions"/> is exactly <see cref="Be"/>.</summary>
    /// <param name="permissions">The permissions bitfield value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="permissions"/> is exactly the <c>be</c> bit.</returns>
    public static bool IsBe(int permissions) => permissions == Be;

    /// <summary>Gets a value indicating whether <paramref name="permissions"/> is exactly <see cref="Lbw"/>.</summary>
    /// <param name="permissions">The permissions bitfield value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="permissions"/> is exactly the <c>lbw</c> bit.</returns>
    public static bool IsLbw(int permissions) => permissions == Lbw;

    /// <summary>Gets a value indicating whether <paramref name="permissions"/> is exactly <see cref="Acfg"/>.</summary>
    /// <param name="permissions">The permissions bitfield value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="permissions"/> is exactly the <c>acfg</c> bit.</returns>
    public static bool IsAcfg(int permissions) => permissions == Acfg;

    /// <summary>Gets a value indicating whether <paramref name="permissions"/> is exactly <see cref="Pcmr"/>.</summary>
    /// <param name="permissions">The permissions bitfield value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="permissions"/> is exactly the <c>pcmr</c> bit.</returns>
    public static bool IsPcmr(int permissions) => permissions == Pcmr;
}
