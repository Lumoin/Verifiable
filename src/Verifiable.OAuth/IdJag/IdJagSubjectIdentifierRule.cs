using System.Collections.Frozen;
using Verifiable.Core.Relations;
using Verifiable.Core.SecurityEvents;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// How a Resource Authorization Server treats the <c>sub_id</c> claim of an Identity Assertion JWT
/// Authorization Grant (ID-JAG) it redeems: whether the claim is required, which Subject Identifier Formats it
/// accepts, whether the claim is compared with the grant's validated subject, and the application's
/// association that decides what the library's own rule cannot.
/// </summary>
/// <remarks>
/// <para>
/// A server that requires the claim takes on three obligations of
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04">draft-ietf-oauth-identity-assertion-authz-grant-04</see>.
/// Presence: a grant without the claim is refused
/// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">Section 3.2.2</see>).
/// Authorization by local policy: a claim "not authorized by local policy for the validated ID-JAG issuer" is
/// refused (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">Section 3.2.2</see>).
/// Identity with the grant's subject: "When both sub and sub_id are present, they MUST identify the same
/// End-User." (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">Section 3.1</see>).
/// The library checks the first and the shape of the claim; the second is the application's knowledge, which
/// <see cref="Association"/> supplies. The third the library decides itself in one case only: under
/// <see cref="IdJagSubjectIdentifierPresence.Optional"/>, for an <c>iss_sub</c> claim whose <c>iss</c> is the
/// grant's issuer, in a grant that carries no <c>tenant</c>, the claim's <c>sub</c> ordinally equal to the
/// grant's <c>sub</c> holds, and another <c>sub</c> fails unless an <see cref="Association"/> is wired, which
/// then decides it (<see cref="IdJagSubjectIdentifierComparison"/>). The application's
/// <see cref="Association"/> decides every other claim, and under
/// <see cref="IdJagSubjectIdentifierPresence.Required"/> every claim.
/// </para>
/// <para>
/// The failure of another <c>sub</c> of the grant's own issuer is this library's reading of
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">Section 3.1</see>;
/// no clause states that refusal. The section reads "When both sub and sub_id are present, they MUST identify
/// the same End-User." and "A public subject identifier MUST be unique when scoped with issuer (iss+sub) for a
/// single-tenant issuer", and the library reads the two together: two subjects of one issuer are two End-Users
/// unless the application says they are one. An application whose issuer hands out pairwise identifiers wires
/// an <see cref="Association"/>, which then decides:
/// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-4.2">RFC 9493 Section 4.2</see> reads "Similarly,
/// the JWT's "sub" Claim and the Subject Identifier's "sub" member MAY be different."
/// </para>
/// <para>
/// Before the claim is compared, the library has completed the rules of
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>
/// on the <c>typ</c> header and on the <c>iss</c>, <c>aud</c>, <c>client_id</c> and <c>sub</c> claims and the
/// time claims, the trust-domain rule of
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.3">Section 9.3</see>,
/// and the shapes of the <c>cnf</c>, <c>act</c> and <c>may_act</c> claims, so the subject it compares with is
/// the validated one (<see cref="IdJagSubjectContext"/>).
/// </para>
/// <para>
/// What stays the application's: the grant's signature and the trust in its issuer, which the application's
/// seam establishes
/// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.5">Section 9.5</see>:
/// "The ID-JAG MUST first be validated using the iss claim, signature, audience, expiration, and client
/// binding according to this specification."); the policy over the grant's <c>resource</c>, <c>scope</c> and
/// <c>authorization_details</c>; and the subject resolution itself.
/// </para>
/// </remarks>
public sealed record IdJagSubjectIdentifierRule
{
    /// <summary>
    /// The rule that accepts a grant without <c>sub_id</c>, accepts every format, compares nothing and wires no
    /// association: the OPTIONAL claim of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Under this rule a well-formed claim is surfaced on
    /// <see cref="IdJagAssertionValidationResult.SubjectIdentifier"/> and judged by nothing: no format is
    /// refused and the claim is not compared with the grant's subject; a claim that is not well formed is
    /// surfaced as <see langword="null"/>.
    /// </para>
    /// <para>
    /// An application that resolves a subject by the surfaced claim takes on what the texts ask of the party
    /// that does: the same End-User as the grant's <c>sub</c>
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">Section 3.1</see>),
    /// the refusals of a server that requires the claim
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">Section 3.2.2</see>),
    /// the association of the validated issuer with a SAML issuer
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.5">Section 9.5</see>),
    /// and <see href="https://www.rfc-editor.org/rfc/rfc9493#section-4.1">RFC 9493 Section 4.1</see>: "When
    /// processing a JWT with both JWT "sub" and "sub_id" Claims, implementations MUST NOT rely on both claims to
    /// determine the JWT Subject." Or it validates with a rule that compares the claim, one that names a
    /// <see cref="Relation"/> or requires the claim through <see cref="Presence"/>.
    /// </para>
    /// </remarks>
    public static IdJagSubjectIdentifierRule Default { get; } = new();

    /// <summary>
    /// Whether the server requires the <c>sub_id</c> claim for subject resolution;
    /// <see cref="IdJagSubjectIdentifierPresence.Optional"/> by default.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Under <see cref="IdJagSubjectIdentifierPresence.Optional"/>, a comparison nothing could decide does not
    /// refuse the grant: the record says <see cref="ComparisonOutcome.Indeterminate"/> with the decision
    /// <see cref="ComparisonDecision.Permit"/>, because the claim is OPTIONAL
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>).
    /// Under <see cref="IdJagSubjectIdentifierPresence.Required"/> the same comparison decides
    /// <see cref="ComparisonDecision.IndeterminateDeny"/> and the grant is refused.
    /// </para>
    /// <para>
    /// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-lineage-guardrail-spec.txt">PIC Sandboxed Execution (pic-sandboxed-execution-02) Section 2.6</see>
    /// reads "Failure, unavailable policy, indeterminate result, inconsistent semantic mapping, or missing
    /// committed inputs produce deny." This library follows that sentence where the claim is required and not
    /// where it is optional: it adopts the vocabulary of that specification and claims no conformance to it.
    /// </para>
    /// </remarks>
    public IdJagSubjectIdentifierPresence Presence { get; init; } = IdJagSubjectIdentifierPresence.Optional;

    /// <summary>
    /// The names of the Subject Identifier Formats
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>) the server
    /// supports for subject resolution, matched ordinally; empty, the default, accepts every format.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>:
    /// "The Resource Authorization Server MAY use sub_id for subject resolution when it supports the indicated
    /// Subject Identifier Format." A format outside a non-empty set is one the server does not support, which
    /// <see cref="IdJagValidationFailureReason.UnsupportedSubjectIdentifierFormat"/> names.
    /// </para>
    /// <para>
    /// The init accessor keeps an immutable ordinal snapshot of the set it is given, so a change the caller
    /// makes to its own set afterwards does not reach a rule already in use.
    /// </para>
    /// </remarks>
    public IReadOnlySet<string> AcceptedFormats
    {
        get;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            field = value.ToFrozenSet(StringComparer.Ordinal);
        }
    } = FrozenSet<string>.Empty;

    /// <summary>
    /// The relation the <c>sub_id</c> claim is compared under, read "claim RELATION validated subject".
    /// </summary>
    /// <remarks>
    /// <see langword="null"/>, the default, asks for no comparison under
    /// <see cref="IdJagSubjectIdentifierPresence.Optional"/>; under
    /// <see cref="IdJagSubjectIdentifierPresence.Required"/> the claim is compared under
    /// <see cref="ComparisonRelation.Equal"/> all the same, because a required claim is decided by
    /// <see cref="Association"/>. <see cref="ComparisonRelation.Equal"/> judges whether the claim names the
    /// End-User the grant's <c>iss</c> and <c>sub</c> name. Any other relation is a comparison the <c>sub_id</c>
    /// profile does not define: the rule is accepted as given, and the comparison records
    /// <see cref="ComparisonOutcome.Indeterminate"/>.
    /// </remarks>
    public ComparisonRelation? Relation { get; init; }

    /// <summary>
    /// The application's association between the <c>sub_id</c> claim and the grant's validated subject;
    /// <see langword="null"/> when none is wired.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The delegate decides every candidate the profile's own rule cannot decide, and under
    /// <see cref="IdJagSubjectIdentifierPresence.Required"/> every candidate. It is called at most once per
    /// validation, and an exception it throws is not caught: it is a defect of the application's delegate. A
    /// claim of a format outside a non-empty <see cref="AcceptedFormats"/> is not put to it: the server does not
    /// resolve subjects by that format, and the claim is recorded undecided or, where it is required, refused.
    /// </para>
    /// <para>
    /// It answers two questions at once, both the application's: whether the claim is authorized by local
    /// policy for the grant's issuer, and whether it names the same person. The first is the refusal of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>
    /// when "the sub_id claim is not authorized by local policy for the validated ID-JAG issuer." The second is
    /// the rule of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">Section 3.1</see>:
    /// "When both sub and sub_id are present, they MUST identify the same End-User."
    /// </para>
    /// <para>
    /// For a candidate the delegate decides, the outcome it returns is the comparison's outcome, whatever the
    /// candidate's members hold. The obligations the texts place on the party that resolves a subject by the
    /// claim are therefore the delegate's. For a <c>saml-nameid</c> candidate,
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">Section 3.2.2</see>
    /// reads "The Resource Authorization Server MUST compare every member of the SAML NameID Subject Identifier
    /// that is part of the set of identifier fields it uses for subject resolution for that SAML issuer. The
    /// Resource Authorization Server MUST NOT resolve the subject using only the nameid value unless local policy
    /// explicitly defines nameid alone as the subject identifier for that SAML issuer. In particular, when the
    /// SAML Assertion Subject &lt;NameID&gt; is scoped to a Service Provider, the sp_name_qualifier value is part
    /// of the subject namespace." and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.5">Section 9.5</see>
    /// reads "The Resource Authorization Server MUST use a SAML NameID sub_id only when the validated ID-JAG
    /// issuer is explicitly associated with the SAML issuer identified by sub_id.issuer through local
    /// configuration or trusted federation metadata." For an <c>email</c> candidate,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.2.1">RFC 9493 Section 3.2.2.1</see> reads
    /// "Therefore, the recipient SHOULD apply its own canonicalization algorithm to incoming events in order to
    /// reproduce the translation done by the local email system." For an <c>aliases</c> candidate,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.8">RFC 9493 Section 3.2.8</see> reads "Each
    /// Subject Identifier in the array MUST identify the same entity." For a <c>complex</c> candidate,
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.3.1">OpenID Shared Signals Framework 1.0 Section 3.3.1</see>
    /// reads "All members within a Complex Subject MUST represent attributes of the same Subject Principal."
    /// </para>
    /// <para>
    /// The library's table-shaped association is <see cref="IdJagSubjectAssociationDictionary"/>: the
    /// application lists, under each validated grant subject, the Subject Identifiers it knows that End-User by,
    /// changes the entries at any time, and wires <see cref="IdJagSubjectAssociationDictionary.CompareAsync"/>
    /// here. It compares every member of a candidate with the listed identifiers and decides nothing for a
    /// subject it holds no entry for; an application that resolves a subject by fewer members, by a single
    /// alias or by a canonicalized value supplies its own delegate.
    /// </para>
    /// </remarks>
    public CompareDelegate<SubjectIdentifier, IdJagSubjectContext>? Association { get; init; }
}
