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
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.1">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.1</see>'s non-normative <c>aki</c> example entry value —
    /// the Base64url-encoded Authority Key Identifier the <c>trusted_authorities</c> DCQL evaluation, wire and
    /// verifier-seat test corpus reuses as a fixed, spec-faithful <c>aki</c> value.
    /// </summary>
    public const string AkiExampleValue = "s9tIpPmhxdiuNkHMEWNpYim8S8Y";


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
    /// <see cref="PidFamilyName"/> carrying a DCQL <c>openid_federation</c> <c>trusted_authorities</c>
    /// constraint (OID4VP 1.0 §6.1.1.3): the credential matches only when one of
    /// <paramref name="trustedIssuers"/> is a subject on a validated federation trust path from the
    /// credential's issuer. Used to drive the verifier's fail-closed <c>trusted_authorities</c>
    /// enforcement end-to-end — pass the issuing entity's own identifier for the accept case (it is
    /// itself a subject on its own trust path) and a stranger identifier for the reject case.
    /// </summary>
    /// <param name="trustedIssuers">The Entity Identifiers the verifier accepts.</param>
    public static DcqlQuery PidFamilyNameTrustedAuthorities(params string[] trustedIssuers) => new()
    {
        Credentials =
        [
            new CredentialQuery
            {
                Id = PidCredentialId,
                Format = WellKnownMediaTypes.Jwt.DcSdJwt,
                Meta = new CredentialQueryMeta { VctValues = [EudiPid.SdJwtVct] },
                //openid_federation (OID4VP 1.0 §6.1.1.3): each value is an Entity Identifier;
                //DcqlEvaluator matches it against the credential's TrustedAuthorityEvidence
                //.FederationTrustPathEntities — every statement subject on a validated
                //federation trust chain from the credential's issuer to a familiar anchor.
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


    /// <summary>
    /// A DCQL query targeting an embedded VC-DM 2.0 credential rather than an SD-JWT / mdoc, for the
    /// VCALM §3.4 <c>DigitalCredentialQueryLanguage</c> co-equal query type. The <c>format</c> is the
    /// credential's most-specific <c>type</c> token (the VC-2.0 DCQL adapter's format projection) and
    /// the claim path navigates the credential's <c>credentialSubject</c>.
    /// </summary>
    /// <param name="credentialType">The VC-DM 2.0 credential type to match (becomes the DCQL format).</param>
    /// <param name="subjectField">The <c>credentialSubject</c> field the query requires.</param>
    public static DcqlQuery VcDataModelSubjectField(string credentialType, string subjectField) => new()
    {
        Credentials =
        [
            new CredentialQuery
            {
                Id = "vc",
                Format = credentialType,
                Meta = new CredentialQueryMeta(),
                Claims =
                [
                    new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("credentialSubject", subjectField) }
                ]
            }
        ]
    };


    /// <summary>
    /// Single PID credential query (SD-JWT VC, <c>dc+sd-jwt</c>) asking for <c>given_name</c> and
    /// <c>family_name</c> via <c>ClaimsQuery.ForPath</c> and carrying no <c>meta</c> (no
    /// <c>vct_values</c> constraint) — the client-identifier and X.509 trust-resolver test corpus's
    /// own shape, distinct from <see cref="PidGivenAndFamilyName"/>'s <c>vct</c>-constrained one.
    /// </summary>
    public static DcqlQuery BuildPidDcqlQuery() => new()
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
                    ClaimsQuery.ForPath(["given_name"]),
                    ClaimsQuery.ForPath(["family_name"])
                ]
            }
        ]
    };
}
