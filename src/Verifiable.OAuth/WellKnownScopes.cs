using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// Well-known OAuth 2.0 and OpenID Connect scope value constants.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Authentication versus authorization — the critical distinction.</strong>
/// </para>
/// <para>
/// OAuth 2.0 was designed for <em>authorization</em> — delegating access to resources.
/// OpenID Connect adds <em>authentication</em> on top of OAuth by defining the
/// <c>openid</c> scope and the ID Token. These two concerns must not be confused:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <c>openid</c> triggers authentication. Its presence causes the authorization
///       server to issue an ID Token asserting who the user is. It does <em>not</em>
///       by itself grant access to any resource.
///     </description>
///   </item>
///   <item>
///     <description>
///       Resource access scopes (e.g. <c>read:orders</c>, <c>offline_access</c>) are
///       authorization. They grant the access token specific permissions at a resource
///       server. They do not authenticate the user.
///     </description>
///   </item>
///   <item>
///     <description>
///       An access token issued without <c>openid</c> does not identify the user —
///       it only authorizes actions. Do not use the access token's presence as proof
///       of identity. Use the ID Token instead.
///     </description>
///   </item>
/// </list>
/// <para>
/// <strong>Scope-to-claims mapping (OIDC Core 1.0 §5.4).</strong>
/// </para>
/// <list type="bullet">
///   <item><description>
///     <c>profile</c> — <c>name</c>, <c>family_name</c>, <c>given_name</c>,
///     <c>middle_name</c>, <c>nickname</c>, <c>preferred_username</c>, <c>profile</c>,
///     <c>picture</c>, <c>website</c>, <c>gender</c>, <c>birthdate</c>,
///     <c>zoneinfo</c>, <c>locale</c>, <c>updated_at</c>.
///   </description></item>
///   <item><description>
///     <c>email</c> — <c>email</c>, <c>email_verified</c>.
///   </description></item>
///   <item><description>
///     <c>address</c> — <c>address</c> (structured claim).
///   </description></item>
///   <item><description>
///     <c>phone</c> — <c>phone_number</c>, <c>phone_number_verified</c>.
///   </description></item>
/// </list>
/// <para>
/// <strong>HAIP 1.0 / FAPI 2.0 requirements.</strong>
/// </para>
/// <para>
/// High-assurance profiles require <c>openid</c> to always be present, and
/// <c>offline_access</c> is permitted only when explicitly supported by the
/// authorization server's metadata. <c>vp_token</c> is required when the relying
/// party requests a Verifiable Presentation via OID4VP.
/// </para>
/// </remarks>
[DebuggerDisplay("WellKnownScopes")]
public static class WellKnownScopes
{
    //OpenID Connect authentication scopes — OIDC Core 1.0 §3.1.2.1 and §5.4.

    /// <summary>
    /// Triggers OpenID Connect authentication and causes the authorization server to
    /// issue an ID Token per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OIDC Core §3.1.2.1</see>.
    /// </summary>
    /// <remarks>
    /// This is an authentication scope, not an authorization scope. Its presence does
    /// not grant access to any resource — it only identifies the user via the ID Token.
    /// </remarks>
    public static readonly string OpenId = "openid";

    /// <summary>
    /// Requests the standard profile claims per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims">OIDC Core §5.4</see>.
    /// Claims returned: <c>name</c>, <c>family_name</c>, <c>given_name</c>,
    /// <c>middle_name</c>, <c>nickname</c>, <c>preferred_username</c>, <c>profile</c>,
    /// <c>picture</c>, <c>website</c>, <c>gender</c>, <c>birthdate</c>,
    /// <c>zoneinfo</c>, <c>locale</c>, <c>updated_at</c>.
    /// </summary>
    public static readonly string Profile = "profile";

    /// <summary>
    /// Requests the <c>email</c> and <c>email_verified</c> claims per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims">OIDC Core §5.4</see>.
    /// </summary>
    public static readonly string Email = "email";

    /// <summary>
    /// Requests the <c>address</c> structured claim per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims">OIDC Core §5.4</see>.
    /// </summary>
    public static readonly string Address = "address";

    /// <summary>
    /// Requests the <c>phone_number</c> and <c>phone_number_verified</c> claims per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims">OIDC Core §5.4</see>.
    /// </summary>
    public static readonly string Phone = "phone";

    //OAuth 2.0 authorization scopes.

    /// <summary>
    /// Requests a refresh token per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess">OIDC Core §11</see>
    /// and <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>.
    /// </summary>
    /// <remarks>
    /// FAPI 2.0 restricts its use — verify the authorization server's metadata for
    /// <c>grant_types_supported</c> before requesting it. Refresh token rotation is
    /// considered bad practice in FAPI 2.0 contexts.
    /// </remarks>
    public static readonly string OfflineAccess = "offline_access";

    //OID4VP scopes.

    /// <summary>
    /// Requests a Verifiable Presentation via OID4VP per the
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP specification</see>.
    /// </summary>
    public static readonly string VpToken = "vp_token";

    //OID4VCI scopes.

    /// <summary>
    /// Requests authorization to obtain Verifiable Credentials from a credential
    /// endpoint per the
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI specification</see>.
    /// </summary>
    public static readonly string CredentialIssuance = "credential";

    //OpenID Shared Signals Framework scopes — CAEP Interoperability Profile §2.7.2.

    /// <summary>
    /// Grants the SSF stream-configuration Read API operations (Read Stream
    /// Configuration, Get Stream Status) on a Shared Signals Transmitter, per
    /// CAEP Interoperability Profile 1.0 §2.7.2.
    /// </summary>
    /// <remarks>
    /// These fixed scopes are the fallback: when the Transmitter (as a Resource
    /// Server) publishes OAuth Protected Resource Metadata (RFC 9728), the client
    /// MUST discover the required scopes from it instead. An authorization server
    /// MAY postfix more granular operations (for example <c>ssf.manage.create</c>).
    /// </remarks>
    public static readonly string SsfRead = "ssf.read";

    /// <summary>
    /// Grants all SSF stream-configuration management API operations on a Shared
    /// Signals Transmitter and includes all <see cref="SsfRead"/> permissions, per
    /// CAEP Interoperability Profile 1.0 §2.7.2.
    /// </summary>
    /// <remarks>
    /// Subject to the same RFC 9728 discovery-first rule and granular-postfix
    /// convention as <see cref="SsfRead"/>.
    /// </remarks>
    public static readonly string SsfManage = "ssf.manage";


    //Single-value identity predicates — parallel to WellKnownCurveValues.IsP256 etc.

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="scope"/> is exactly
    /// <c>openid</c>. Use <see cref="ContainsOpenId"/> to check a space-separated
    /// scope string.
    /// </summary>
    public static bool IsOpenId(string scope) => Equals(scope, OpenId);

    /// <summary>Returns <see langword="true"/> when <paramref name="scope"/> is exactly <c>profile</c>.</summary>
    public static bool IsProfile(string scope) => Equals(scope, Profile);

    /// <summary>Returns <see langword="true"/> when <paramref name="scope"/> is exactly <c>email</c>.</summary>
    public static bool IsEmail(string scope) => Equals(scope, Email);

    /// <summary>Returns <see langword="true"/> when <paramref name="scope"/> is exactly <c>address</c>.</summary>
    public static bool IsAddress(string scope) => Equals(scope, Address);

    /// <summary>Returns <see langword="true"/> when <paramref name="scope"/> is exactly <c>phone</c>.</summary>
    public static bool IsPhone(string scope) => Equals(scope, Phone);

    /// <summary>Returns <see langword="true"/> when <paramref name="scope"/> is exactly <c>offline_access</c>.</summary>
    public static bool IsOfflineAccess(string scope) => Equals(scope, OfflineAccess);

    /// <summary>Returns <see langword="true"/> when <paramref name="scope"/> is exactly <c>vp_token</c>.</summary>
    public static bool IsVpToken(string scope) => Equals(scope, VpToken);

    /// <summary>Returns <see langword="true"/> when <paramref name="scope"/> is exactly <c>credential</c>.</summary>
    public static bool IsCredentialIssuance(string scope) => Equals(scope, CredentialIssuance);

    /// <summary>Returns <see langword="true"/> when <paramref name="scope"/> is exactly <c>ssf.read</c>.</summary>
    public static bool IsSsfRead(string scope) => Equals(scope, SsfRead);

    /// <summary>Returns <see langword="true"/> when <paramref name="scope"/> is exactly <c>ssf.manage</c>.</summary>
    public static bool IsSsfManage(string scope) => Equals(scope, SsfManage);


    private static readonly string SsfManageGranularPrefix = SsfManage + ".";


    /// <summary>
    /// Whether a granted SSF scope satisfies a required one per CAEP Interoperability
    /// Profile 1.0 §2.7.2: an exact match always satisfies; a granted
    /// <see cref="SsfManage"/> satisfies a required <see cref="SsfRead"/> because
    /// <c>ssf.manage</c> includes all <c>ssf.read</c> permissions; and a granted
    /// <see cref="SsfManage"/> satisfies a granular <c>ssf.manage.*</c> requirement
    /// (for example <c>ssf.manage.create</c>), because every management API operation
    /// MUST accept <c>ssf.manage</c>. A granular grant never satisfies a broader
    /// requirement.
    /// </summary>
    public static bool SsfScopeSatisfies(string grantedScope, string requiredScope)
    {
        ArgumentNullException.ThrowIfNull(grantedScope);
        ArgumentNullException.ThrowIfNull(requiredScope);

        return Equals(grantedScope, requiredScope)
            || (IsSsfManage(grantedScope)
                && (IsSsfRead(requiredScope) || requiredScope.StartsWith(SsfManageGranularPrefix, StringComparison.Ordinal)));
    }


    //Space-separated scope string membership checks.

    /// <summary>
    /// Returns <see langword="true"/> when the space-separated <paramref name="scopeString"/>
    /// contains <c>openid</c>.
    /// </summary>
    public static bool ContainsOpenId(string scopeString) =>
        ContainsScopeValue(scopeString, OpenId);

    /// <summary>
    /// Returns <see langword="true"/> when the space-separated <paramref name="scopeString"/>
    /// contains <c>profile</c>.
    /// </summary>
    public static bool ContainsProfile(string scopeString) =>
        ContainsScopeValue(scopeString, Profile);

    /// <summary>
    /// Returns <see langword="true"/> when the space-separated <paramref name="scopeString"/>
    /// contains <c>email</c>.
    /// </summary>
    public static bool ContainsEmail(string scopeString) =>
        ContainsScopeValue(scopeString, Email);

    /// <summary>
    /// Returns <see langword="true"/> when the space-separated <paramref name="scopeString"/>
    /// contains <c>address</c>.
    /// </summary>
    public static bool ContainsAddress(string scopeString) =>
        ContainsScopeValue(scopeString, Address);

    /// <summary>
    /// Returns <see langword="true"/> when the space-separated <paramref name="scopeString"/>
    /// contains <c>phone</c>.
    /// </summary>
    public static bool ContainsPhone(string scopeString) =>
        ContainsScopeValue(scopeString, Phone);

    /// <summary>
    /// Returns <see langword="true"/> when the space-separated <paramref name="scopeString"/>
    /// contains <c>offline_access</c>.
    /// </summary>
    public static bool ContainsOfflineAccess(string scopeString) =>
        ContainsScopeValue(scopeString, OfflineAccess);

    /// <summary>
    /// Returns <see langword="true"/> when the space-separated <paramref name="scopeString"/>
    /// contains <c>vp_token</c>.
    /// </summary>
    public static bool ContainsVpToken(string scopeString) =>
        ContainsScopeValue(scopeString, VpToken);


    //Canonicalization — parallel to WellKnownCurveValues.GetCanonicalizedValue.

    /// <summary>
    /// Returns the canonical form of a well-known scope value, or the original
    /// value when it is not a recognized well-known scope.
    /// Comparison is case-sensitive per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>.
    /// </summary>
    public static string GetCanonicalizedValue(string scope) => scope switch
    {
        _ when IsOpenId(scope) => OpenId,
        _ when IsProfile(scope) => Profile,
        _ when IsEmail(scope) => Email,
        _ when IsAddress(scope) => Address,
        _ when IsPhone(scope) => Phone,
        _ when IsOfflineAccess(scope) => OfflineAccess,
        _ when IsVpToken(scope) => VpToken,
        _ when IsCredentialIssuance(scope) => CredentialIssuance,
        _ => scope
    };


    //Core membership check used by all Contains* methods.

    /// <summary>
    /// Returns <see langword="true"/> when the space-separated <paramref name="scopeString"/>
    /// contains <paramref name="value"/> as a complete token. Comparison is
    /// case-sensitive per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>.
    /// </summary>
    public static bool ContainsScopeValue(string scopeString, string value)
    {
        ArgumentNullException.ThrowIfNull(scopeString);
        ArgumentNullException.ThrowIfNull(value);

        ReadOnlySpan<char> remaining = scopeString.AsSpan();
        while(!remaining.IsEmpty)
        {
            int spaceIndex = remaining.IndexOf(' ');
            ReadOnlySpan<char> token = spaceIndex < 0
                ? remaining
                : remaining[..spaceIndex];

            if(token.Equals(value.AsSpan(), StringComparison.Ordinal))
            {
                return true;
            }

            remaining = spaceIndex < 0 ? [] : remaining[(spaceIndex + 1)..];
        }

        return false;
    }


    //Private equality helper — same pattern as WellKnownCurveValues.
    private static bool Equals(string scopeA, string scopeB) =>
        string.Equals(scopeA, scopeB, StringComparison.Ordinal);
}
