using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared DCQL query fixtures for tests across the DCQL, serialisation,
/// data-integrity, and OAuth flow test categories. Single source of truth
/// for the shapes the test corpus consults repeatedly; per-test variants
/// stay inline.
/// </summary>
/// <remarks>
/// <para>
/// Factory names describe what the query <i>represents</i> rather than
/// which test first needed it, so that as new tests reuse a shape they can
/// pick the existing factory without grep-and-copy. Wire-shape changes
/// (claim names, formats, credential IDs) land here once.
/// </para>
/// <para>
/// Every factory returns a fresh instance — DCQL queries carry mutable
/// collections internally and the tests sometimes mutate during setup
/// (mostly to add or remove credentials).
/// </para>
/// </remarks>
internal static class DcqlFixtures
{
    /// <summary>The conventional credential identifier used across single-credential PID tests.</summary>
    public const string PidCredentialId = "pid";

    /// <summary>Primary credential identifier for the two-credential PID fixture.</summary>
    public const string PidPrimaryCredentialId = "pid_primary";

    /// <summary>Secondary credential identifier for the two-credential PID fixture.</summary>
    public const string PidSecondaryCredentialId = "pid_secondary";


    /// <summary>
    /// Single PID credential query against the <c>family_name</c> claim
    /// formatted as SD-JWT VC (<c>dc+sd-jwt</c>). The canonical "ask for
    /// one thing from one credential" fixture used by the OID4VP cross-
    /// device, presentation-automaton, and inspection-stage tests.
    /// </summary>
    public static DcqlQuery PidFamilyName() => new()
    {
        Credentials =
        [
            new CredentialQuery
            {
                Id = PidCredentialId,
                Format = WellKnownMediaTypes.Jwt.DcSdJwt,
                Meta = new CredentialQueryMeta { VctValues = [EudiPid.SdJwtVct] },
                Claims =
                [
                    new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("family_name") }
                ]
            }
        ]
    };


    /// <summary>
    /// <see cref="PidFamilyName"/> passed through <see cref="DcqlPreparer.Prepare"/>.
    /// Most tests that drive the OID4VP PDA need the prepared form.
    /// </summary>
    public static PreparedDcqlQuery PidFamilyNamePrepared() =>
        DcqlPreparer.Prepare(PidFamilyName());


    /// <summary>
    /// Single PID credential query (SD-JWT VC, <c>dc+sd-jwt</c>) asking for both
    /// <c>given_name</c> and <c>family_name</c>. The two-claim shape used by the JAR
    /// client-identifier and signed-JAR integration tests; the single-claim
    /// <see cref="PidFamilyName"/> covers the minimal-disclosure path.
    /// </summary>
    public static DcqlQuery PidGivenAndFamilyName() => new()
    {
        Credentials =
        [
            new CredentialQuery
            {
                Id = PidCredentialId,
                Format = WellKnownMediaTypes.Jwt.DcSdJwt,
                Meta = new CredentialQueryMeta { VctValues = [EudiPid.SdJwtVct] },
                Claims =
                [
                    new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(EudiPid.SdJwt.GivenName) },
                    new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(EudiPid.SdJwt.FamilyName) }
                ]
            }
        ]
    };


    /// <summary>
    /// Two-credential PID query — <c>pid_primary</c> and <c>pid_secondary</c>
    /// — each asking for <c>family_name</c>. Drives the multi-credential
    /// aggregation path through the wallet client and verifier flow.
    /// </summary>
    public static DcqlQuery PidPrimaryAndSecondaryFamilyName() => new()
    {
        Credentials =
        [
            new CredentialQuery
            {
                Id = PidPrimaryCredentialId,
                Format = WellKnownMediaTypes.Jwt.DcSdJwt,
                Meta = new CredentialQueryMeta { VctValues = [EudiPid.SdJwtVct] },
                Claims =
                [
                    new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("family_name") }
                ]
            },
            new CredentialQuery
            {
                Id = PidSecondaryCredentialId,
                Format = WellKnownMediaTypes.Jwt.DcSdJwt,
                Meta = new CredentialQueryMeta { VctValues = [EudiPid.SdJwtVct] },
                Claims =
                [
                    new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("family_name") }
                ]
            }
        ]
    };


    /// <summary>
    /// <see cref="PidPrimaryAndSecondaryFamilyName"/> passed through
    /// <see cref="DcqlPreparer.Prepare"/>.
    /// </summary>
    public static PreparedDcqlQuery PidPrimaryAndSecondaryFamilyNamePrepared() =>
        DcqlPreparer.Prepare(PidPrimaryAndSecondaryFamilyName());


    /// <summary>
    /// <see cref="PidFamilyName"/> carrying a DCQL <c>trusted_authorities</c> constraint
    /// (OID4VP 1.0 §6.1.1): the credential matches only when its verified issuer is one of
    /// <paramref name="trustedIssuers"/>. Used to drive the verifier's fail-closed
    /// <c>trusted_authorities</c> enforcement end-to-end — pass the issuing entity for the
    /// accept case and a stranger for the reject case.
    /// </summary>
    /// <param name="trustedIssuers">The issuer entity identifiers the verifier accepts.</param>
    public static DcqlQuery PidFamilyNameTrustedAuthorities(params string[] trustedIssuers) => new()
    {
        Credentials =
        [
            new CredentialQuery
            {
                Id = PidCredentialId,
                Format = WellKnownMediaTypes.Jwt.DcSdJwt,
                Meta = new CredentialQueryMeta { VctValues = [EudiPid.SdJwtVct] },
                //openid_federation: the authority is identified by its entity
                //identifier (the credential's iss) per OID4VP 1.0 §6.1.1.3.
                //DcqlEvaluator matches the verified issuer against Values.
                TrustedAuthorities =
                [
                    new TrustedAuthoritiesQuery
                    {
                        Type = DcqlTrustedAuthorityTypes.OpenIdFederation,
                        Values = trustedIssuers
                    }
                ],
                Claims =
                [
                    new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("family_name") }
                ]
            }
        ]
    };


    /// <summary>
    /// <see cref="PidFamilyNameTrustedAuthorities"/> passed through <see cref="DcqlPreparer.Prepare"/>.
    /// </summary>
    public static PreparedDcqlQuery PidFamilyNameTrustedAuthoritiesPrepared(params string[] trustedIssuers) =>
        DcqlPreparer.Prepare(PidFamilyNameTrustedAuthorities(trustedIssuers));


    /// <summary>
    /// PID query (SD-JWT VC) for <c>given_name</c> + <c>family_name</c>, with a DCQL claim
    /// <c>values</c> constraint on <c>family_name</c>: the credential matches only when the
    /// disclosed <c>family_name</c> is one of <paramref name="acceptableFamilyNames"/>. Asks
    /// for both claims so a reveal-all wallet does not also trip the over-disclosure rule —
    /// isolating the value-constraint as the sole reason the verifier accepts or rejects.
    /// </summary>
    /// <param name="acceptableFamilyNames">The accepted <c>family_name</c> values.</param>
    public static DcqlQuery PidFamilyNameValueConstraint(params object[] acceptableFamilyNames) => new()
    {
        Credentials =
        [
            new CredentialQuery
            {
                Id = PidCredentialId,
                Format = WellKnownMediaTypes.Jwt.DcSdJwt,
                Meta = new CredentialQueryMeta { VctValues = [EudiPid.SdJwtVct] },
                Claims =
                [
                    new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(EudiPid.SdJwt.GivenName) },
                    new ClaimsQuery
                    {
                        Path = DcqlClaimPattern.FromKeys(EudiPid.SdJwt.FamilyName),
                        Values = acceptableFamilyNames
                    }
                ]
            }
        ]
    };


    /// <summary>
    /// <see cref="PidFamilyNameValueConstraint"/> passed through <see cref="DcqlPreparer.Prepare"/>.
    /// </summary>
    public static PreparedDcqlQuery PidFamilyNameValueConstraintPrepared(params object[] acceptableFamilyNames) =>
        DcqlPreparer.Prepare(PidFamilyNameValueConstraint(acceptableFamilyNames));
}
