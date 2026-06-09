using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.OAuth;

/// <summary>
/// Well-known <see cref="ClaimId"/> values identifying claim
/// contribution rules in the OAuth/OIDC contributor surface. Each ID
/// names a logical contribution rule, distinct from
/// <see cref="WellKnownJwtClaimNames"/> which names the wire-format JWT
/// claim names.
/// </summary>
/// <remarks>
/// <para>
/// Phase A reserves code range 1000–1099 for OAuth contributor rule
/// IDs. Broader registry reservations:
/// </para>
/// <list type="bullet">
///   <item><description>1–602: cryptography / DID</description></item>
///   <item><description>700–999: <see cref="Validation.ValidationClaimIds"/></description></item>
///   <item><description>1000–1099: Phase A (this class)</description></item>
///   <item><description>1100+: reserved for future tracks (Federation,
///     OID4VP completion, OID4VCI, SIOPv2, logout, Identity Assurance)</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("WellKnownClaimIds")]
public static class WellKnownClaimIds
{
    //OIDC Core §5.4 standard claim families (codes 1000–1019).
    public static readonly ClaimId OidcProfile = ClaimId.Create(1000, "OidcProfile");
    public static readonly ClaimId OidcEmail = ClaimId.Create(1001, "OidcEmail");
    public static readonly ClaimId OidcAddress = ClaimId.Create(1002, "OidcAddress");
    public static readonly ClaimId OidcPhone = ClaimId.Create(1003, "OidcPhone");

    //OIDC authentication context (codes 1020–1029).
    public static readonly ClaimId OidcAuthTime = ClaimId.Create(1020, "OidcAuthTime");
    public static readonly ClaimId OidcAuthClass = ClaimId.Create(1021, "OidcAuthClass");
    public static readonly ClaimId OidcSessionId = ClaimId.Create(1022, "OidcSessionId");

    //RFC 7800 confirmation method (codes 1030–1039).
    public static readonly ClaimId CnfBinding = ClaimId.Create(1030, "CnfBinding");

    //Subject identifier (code 1040). Carries the result of
    //ResolveSubjectIdentifierAsync — public-identity by default,
    //pairwise-hash for deployments that wire one.
    public static readonly ClaimId SubjectIdentifier = ClaimId.Create(1040, "SubjectIdentifier");

    //Future Phase A IDs land in 1050–1099. Downstream tracks reserve
    //1100+ in their own WellKnown* classes.
}
