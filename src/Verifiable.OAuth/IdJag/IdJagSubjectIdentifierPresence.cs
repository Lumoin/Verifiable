namespace Verifiable.OAuth.IdJag;

/// <summary>
/// Whether a Resource Authorization Server requires the <c>sub_id</c> claim of an Identity Assertion JWT
/// Authorization Grant (ID-JAG) for subject resolution, as the <see cref="IdJagSubjectIdentifierRule.Presence"/>
/// of the rule the grant's redeem applies.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>
/// makes <c>sub_id</c> OPTIONAL, so <see cref="Optional"/> is the default: a grant without the claim is
/// redeemed. A server that resolves its users by the identifier the claim carries selects
/// <see cref="Required"/>, and the refusals of
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">Section 3.2.2</see>
/// apply.
/// </para>
/// <para>
/// The choice is the application's and travels with the rule it hands to each redeem, so one validator
/// serves every server configuration.
/// </para>
/// </remarks>
public enum IdJagSubjectIdentifierPresence
{
    /// <summary>
    /// A grant without <c>sub_id</c> is redeemed: the claim is OPTIONAL in
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>.
    /// A comparison the rule asks for that nothing can decide gives
    /// <see cref="Verifiable.Core.Relations.ComparisonDecision.Permit"/>, and its record keeps that nothing
    /// decided it.
    /// </summary>
    Optional,

    /// <summary>
    /// The server requires <c>sub_id</c> for subject resolution and refuses a grant whose claim is absent,
    /// malformed, of a format it does not accept, or not associated with the validated grant by the
    /// application's local policy.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>
    /// states the rule for the SAML NameID format: "If the Resource Authorization Server requires a SAML
    /// NameID Subject Identifier for subject resolution, it MUST reject the token request with an
    /// invalid_grant error as defined in Section 5.2 of [RFC6749] if any of the following is true"; this
    /// library applies the same refusals to every format the rule accepts.
    /// </summary>
    Required
}
