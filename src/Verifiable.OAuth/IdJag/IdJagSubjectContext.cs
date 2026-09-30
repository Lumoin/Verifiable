using System.Diagnostics;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// The subject of an Identity Assertion JWT Authorization Grant (ID-JAG) as its redeem validated it: the
/// grant's <c>iss</c>, its <c>sub</c> and, for a multi-tenant issuer, its <c>tenant</c>. It is the reference
/// the grant's <c>sub_id</c> claim is compared with under an <see cref="IdJagSubjectIdentifierRule"/>.
/// </summary>
/// <remarks>
/// <para>
/// The library builds it only from claims every rule of
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.4.1</see>
/// and the trust-domain rule of
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.3">Section 9.3</see>
/// has passed, and it carries those values as they are, with no factory of its own that could refuse a value
/// the validator accepted. An application's <see cref="IdJagSubjectIdentifierRule.Association"/> receives it
/// as the subject the <c>sub_id</c> claim has to name.
/// </para>
/// <para>
/// The three values together name one End-User.
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">Section 3.1</see>:
/// "A public subject identifier MUST be unique when scoped with issuer (iss+sub) for a single-tenant issuer
/// and MUST be unique when scoped with issuer and tenant (iss+tenant+sub) for multi-tenant issuer."
/// </para>
/// <para>
/// The subject and the tenant can identify a person, so the debugger display and <see cref="ToString"/> show
/// the issuer and whether a tenant is present only.
/// </para>
/// </remarks>
[DebuggerDisplay("IdJagSubjectContext(Issuer={Issuer}, HasTenant={Tenant != null})")]
public sealed record IdJagSubjectContext
{
    /// <summary>
    /// The grant's validated <c>iss</c> claim: the issuer identifier of the IdP Authorization Server
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>).
    /// </summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// The grant's validated <c>sub</c> claim: the End-User in the subject namespace of the grant's issuer
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>).
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The grant's <c>tenant</c> claim, the tenant identifier of a multi-tenant issuer
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>);
    /// <see langword="null"/> when the grant carries none.
    /// </summary>
    public string? Tenant { get; init; }


    /// <summary>
    /// Renders the grant's issuer and whether a tenant is present, in the words of the debugger display, and
    /// neither <see cref="Subject"/> nor the value of <see cref="Tenant"/>.
    /// </summary>
    /// <remarks>
    /// A record's generated text prints every property, and the subject and the tenant can identify a person;
    /// a context that reaches a log, a trace or an exception message through its text carries neither value.
    /// </remarks>
    /// <returns>The text <c>IdJagSubjectContext(Issuer=..., HasTenant=...)</c>.</returns>
    public override string ToString() => $"IdJagSubjectContext(Issuer={Issuer}, HasTenant={Tenant is not null})";
}
