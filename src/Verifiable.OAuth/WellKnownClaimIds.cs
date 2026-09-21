using Verifiable.Core.Assessment;

namespace Verifiable.OAuth;

/// <summary>
/// Well-known <see cref="ClaimId"/> values identifying claim
/// contribution rules in the OAuth/OIDC contributor surface. Each ID
/// names a logical contribution rule, distinct from
/// <see cref="Verifiable.JCose.WellKnownJwtClaimNames"/> which names the wire-format JWT
/// claim names.
/// </summary>
/// <remarks>
/// <para>
/// Code range 1000–1099 is reserved for OAuth contributor rule
/// IDs. Broader registry reservations:
/// </para>
/// <list type="bullet">
///   <item><description>1–602: cryptography / DID</description></item>
///   <item><description>700–999: <see cref="Validation.ValidationClaimIds"/></description></item>
///   <item><description>1000–1099: OAuth contributor rule IDs (this class)</description></item>
///   <item><description>1100+: reserved for future tracks (Federation,
///     OID4VP completion, OID4VCI, SIOPv2, logout, Identity Assurance)</description></item>
/// </list>
/// </remarks>
public static class WellKnownClaimIds
{
    //OIDC Core §5.4 standard claim families (codes 1000–1019).
    /// <summary>The contribution rule for the <c>profile</c> standard claim family (<see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.4</see>).</summary>
    public static ClaimId OidcProfile { get; } = ClaimId.Create(1000, "OidcProfile");

    /// <summary>The contribution rule for the <c>email</c> standard claim family (<see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.4</see>).</summary>
    public static ClaimId OidcEmail { get; } = ClaimId.Create(1001, "OidcEmail");

    /// <summary>The contribution rule for the <c>address</c> standard claim family (<see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.4</see>).</summary>
    public static ClaimId OidcAddress { get; } = ClaimId.Create(1002, "OidcAddress");

    /// <summary>The contribution rule for the <c>phone_number</c> standard claim family (<see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.4</see>).</summary>
    public static ClaimId OidcPhone { get; } = ClaimId.Create(1003, "OidcPhone");

    //OIDC authentication context (codes 1020–1029).
    /// <summary>The contribution rule for the <c>auth_time</c> claim (<see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0 §2</see>).</summary>
    public static ClaimId OidcAuthTime { get; } = ClaimId.Create(1020, "OidcAuthTime");

    /// <summary>The contribution rule for the <c>acr</c> authentication context class reference claim (<see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0 §2</see>).</summary>
    public static ClaimId OidcAuthClass { get; } = ClaimId.Create(1021, "OidcAuthClass");

    /// <summary>The contribution rule for the <c>sid</c> session identifier claim (<see href="https://openid.net/specs/openid-connect-frontchannel-1_0.html">OpenID Connect Front-Channel Logout 1.0</see>).</summary>
    public static ClaimId OidcSessionId { get; } = ClaimId.Create(1022, "OidcSessionId");

    //RFC 7800 confirmation method (codes 1030–1039).
    /// <summary>The contribution rule for the <c>cnf</c> confirmation method claim (<see href="https://www.rfc-editor.org/rfc/rfc7800#section-3.1">RFC 7800 §3.1</see>).</summary>
    public static ClaimId CnfBinding { get; } = ClaimId.Create(1030, "CnfBinding");

    //Subject identifier (code 1040). Carries the result of
    //ResolveSubjectIdentifierAsync — public-identity by default,
    //pairwise-hash for deployments that wire one.
    /// <summary>The contribution rule for the <c>sub</c> subject identifier claim (<see href="https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes">OpenID Connect Core 1.0 §8</see>), public-identity by default or pairwise-hash where the deployment wires one.</summary>
    public static ClaimId SubjectIdentifier { get; } = ClaimId.Create(1040, "SubjectIdentifier");

    //Future OAuth contributor rule IDs land in 1050–1099. Downstream tracks
    //reserve 1100+ in their own WellKnown* classes.
}
