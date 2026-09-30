using Verifiable.Core.Relations;
using Verifiable.Core.SecurityEvents;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// The comparison profile of the <c>sub_id</c> claim of an Identity Assertion JWT Authorization Grant
/// (ID-JAG): compares the claim with the grant's validated subject under an
/// <see cref="IdJagSubjectIdentifierRule"/> and records the outcome, whose rule decided it, and the decision.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-prover-verifier-spec.txt">PIC Prover and Verifier (pic-prover-verifier-02) Section 4.2</see>
/// asks a profile to define "its syntax, its equivalence relation, its attenuation order" and "a
/// deterministic comparison sufficient for non-expansion validation." This profile defines the four parts as
/// follows. The syntax is the Subject Identifier of
/// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>, read as
/// <see cref="SubjectIdentifier"/>. The equivalence is ordinal equality of the members, each read from
/// <see cref="SubjectIdentifier.Members"/> by the names of <see cref="SubjectIdentifierMemberNames"/>. The
/// order is equality only: <see cref="ComparisonRelation.Equal"/> is the one relation the profile defines. The
/// comparison is <see cref="CompareAsync"/>.
/// </para>
/// <para>
/// The claim's own values settle the comparison only where they are in the grant's own subject namespace: an
/// <c>iss_sub</c> identifier whose <c>iss</c> is the grant's issuer, for an issuer that carries no tenant.
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
/// "A public subject identifier MUST be unique when scoped with issuer (iss+sub) for a single-tenant issuer
/// and MUST be unique when scoped with issuer and tenant (iss+tenant+sub) for multi-tenant issuer." Every
/// other candidate of a format the rule accepts names the End-User in a namespace only the application can map,
/// so its <see cref="IdJagSubjectIdentifierRule.Association"/> decides it.
/// </para>
/// </remarks>
internal static class IdJagSubjectIdentifierComparison
{
    /// <summary>
    /// Compares the <c>sub_id</c> claim <paramref name="candidate"/> with the grant's validated subject
    /// <paramref name="reference"/> under <paramref name="rule"/>, and returns the record of the comparison.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The comparison runs under the rule's <see cref="IdJagSubjectIdentifierRule.Relation"/>, or under
    /// <see cref="ComparisonRelation.Equal"/> when the rule names none, and decides in this order:
    /// </para>
    /// <list type="number">
    /// <item><description>
    /// A candidate of a format outside a non-empty <see cref="IdJagSubjectIdentifierRule.AcceptedFormats"/> is
    /// one the server does not resolve subjects by: <see cref="ComparisonOutcome.Indeterminate"/>, basis
    /// <see cref="ComparisonBasis.None"/>, and the association is not asked.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>:
    /// "The Resource Authorization Server MAY use sub_id for subject resolution when it supports the indicated
    /// Subject Identifier Format." Under <see cref="IdJagSubjectIdentifierPresence.Required"/> the validator
    /// refuses such a candidate before it is compared
    /// (<see cref="IdJagValidationFailureReason.UnsupportedSubjectIdentifierFormat"/>).
    /// </description></item>
    /// <item><description>
    /// A relation other than <see cref="ComparisonRelation.Equal"/> is a comparison this profile does not
    /// define: <see cref="ComparisonOutcome.Indeterminate"/>, basis <see cref="ComparisonBasis.None"/>, and
    /// the association is not asked.
    /// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-prover-verifier-spec.txt">PIC Prover and Verifier Section 4.2</see>:
    /// "a Verifier MUST reject a PCA whose profile is unknown or does not define a deterministic comparison."
    /// </description></item>
    /// <item><description>
    /// Under <see cref="IdJagSubjectIdentifierPresence.Required"/> the association decides every candidate,
    /// the one textually identical to the grant's subject included, because whether the claim is authorized
    /// by local policy is the application's
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>):
    /// its outcome, basis <see cref="ComparisonBasis.ApplicationRule"/>; with none wired,
    /// <see cref="ComparisonOutcome.Indeterminate"/>, basis <see cref="ComparisonBasis.None"/>. A presence
    /// value outside <see cref="IdJagSubjectIdentifierPresence"/> is read as
    /// <see cref="IdJagSubjectIdentifierPresence.Required"/>.
    /// </description></item>
    /// <item><description>
    /// Under <see cref="IdJagSubjectIdentifierPresence.Optional"/>, an <c>iss_sub</c> candidate whose
    /// <c>iss</c> equals the validated issuer, for a grant that carries no tenant, holds, basis
    /// <see cref="ComparisonBasis.ProfileRule"/>, when its <c>sub</c> equals the validated subject; the
    /// association is not asked. With another <c>sub</c> the association decides when one is wired, basis
    /// <see cref="ComparisonBasis.ApplicationRule"/>, and otherwise the comparison fails, basis
    /// <see cref="ComparisonBasis.ProfileRule"/>. That failure is this library's reading of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>,
    /// and no clause states it: "When both sub and sub_id are present, they MUST identify the same End-User."
    /// with "A public subject identifier MUST be unique when scoped with issuer (iss+sub) for a single-tenant
    /// issuer" reads as two subjects of one issuer being two End-Users unless the application says they are one.
    /// An application whose issuer hands out pairwise identifiers, whose <c>sub</c> member
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-4.2">RFC 9493 Section 4.2</see> says "MAY be
    /// different" from the grant's, wires the association, which then decides
    /// (<see cref="IdJagSubjectIdentifierRule"/>).
    /// </description></item>
    /// <item><description>
    /// Every other candidate (another issuer, another format, or a grant that carries a tenant) takes the
    /// association's outcome, basis <see cref="ComparisonBasis.ApplicationRule"/>, or with none wired
    /// <see cref="ComparisonOutcome.Indeterminate"/>, basis <see cref="ComparisonBasis.None"/>.
    /// </description></item>
    /// </list>
    /// <para>
    /// The decision follows from the outcome in one place: <see cref="ComparisonOutcome.Holds"/> gives
    /// <see cref="ComparisonDecision.Permit"/>, <see cref="ComparisonOutcome.Fails"/> gives
    /// <see cref="ComparisonDecision.Deny"/>, and <see cref="ComparisonOutcome.Indeterminate"/> gives
    /// <see cref="ComparisonDecision.IndeterminateDeny"/> under
    /// <see cref="IdJagSubjectIdentifierPresence.Required"/> and <see cref="ComparisonDecision.Permit"/> under
    /// <see cref="IdJagSubjectIdentifierPresence.Optional"/>, where the claim is not required and the record
    /// keeps that nothing decided it. An outcome value outside <see cref="ComparisonOutcome"/> gives
    /// <see cref="ComparisonDecision.IndeterminateDeny"/>.
    /// </para>
    /// <para>
    /// The association is called at most once. An exception it throws is not caught: it is a defect of the
    /// application's delegate.
    /// </para>
    /// </remarks>
    /// <param name="candidate">The grant's <c>sub_id</c> claim as read.</param>
    /// <param name="reference">The grant's validated subject.</param>
    /// <param name="rule">The rule the redeem applies to the claim.</param>
    /// <param name="cancellationToken">The token that cancels the association's comparison.</param>
    /// <returns>The record of the comparison, its decision included.</returns>
    public static async ValueTask<ComparisonRecord<SubjectIdentifier, IdJagSubjectContext>> CompareAsync(
        SubjectIdentifier candidate,
        IdJagSubjectContext reference,
        IdJagSubjectIdentifierRule rule,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(reference);
        ArgumentNullException.ThrowIfNull(rule);

        ComparisonRelation relation = rule.Relation ?? ComparisonRelation.Equal;
        CompareDelegate<SubjectIdentifier, IdJagSubjectContext>? association = rule.Association;
        bool isOptional = rule.Presence is IdJagSubjectIdentifierPresence.Optional;

        //An iss_sub identifier in the grant's own subject namespace: its iss is the grant's issuer and the
        //grant carries no tenant, so iss and sub together name one End-User.
        bool isInGrantNamespace = SubjectIdentifierFormats.IsIssuerSubject(candidate.Format)
            && reference.Tenant is null
            && candidate.Members.TryGetValue(SubjectIdentifierMemberNames.Iss, out object? issuer)
            && issuer is string issuerText
            && string.Equals(issuerText, reference.Issuer, StringComparison.Ordinal);

        bool isGrantSubject = candidate.Members.TryGetValue(SubjectIdentifierMemberNames.Sub, out object? subject)
            && subject is string subjectText
            && string.Equals(subjectText, reference.Subject, StringComparison.Ordinal);

        //A format outside a non-empty set of accepted formats is one the server does not resolve subjects by.
        bool isAcceptedFormat = rule.AcceptedFormats.Count == 0 || rule.AcceptedFormats.Contains(candidate.Format);

        //The answer of the profile's own rule, or null where the association decides.
        (ComparisonOutcome Outcome, ComparisonBasis Basis)? profileAnswer = (isAcceptedFormat, relation, isOptional, isInGrantNamespace, isGrantSubject, association) switch
        {
            (false, _, _, _, _, _) => (ComparisonOutcome.Indeterminate, ComparisonBasis.None),
            (_, not ComparisonRelation.Equal, _, _, _, _) => (ComparisonOutcome.Indeterminate, ComparisonBasis.None),
            (_, _, true, true, true, _) => (ComparisonOutcome.Holds, ComparisonBasis.ProfileRule),
            (_, _, true, true, false, null) => (ComparisonOutcome.Fails, ComparisonBasis.ProfileRule),
            _ => null
        };

        (ComparisonOutcome outcome, ComparisonBasis basis) = (profileAnswer, association) switch
        {
            ({ } answer, _) => answer,
            (null, { } decide) => (await decide(candidate, reference, relation, cancellationToken).ConfigureAwait(false), ComparisonBasis.ApplicationRule),
            (null, null) => (ComparisonOutcome.Indeterminate, ComparisonBasis.None)
        };

        //The one place an outcome becomes a decision: an undecided comparison refuses only where the claim is
        //required, and an outcome outside the enumeration refuses as undecided.
        ComparisonDecision decision = (outcome, isOptional) switch
        {
            (ComparisonOutcome.Holds, _) => ComparisonDecision.Permit,
            (ComparisonOutcome.Fails, _) => ComparisonDecision.Deny,
            (ComparisonOutcome.Indeterminate, true) => ComparisonDecision.Permit,
            _ => ComparisonDecision.IndeterminateDeny
        };

        return new ComparisonRecord<SubjectIdentifier, IdJagSubjectContext>
        {
            Relation = relation,
            Outcome = outcome,
            Basis = basis,
            Decision = decision,
            Candidate = candidate,
            Reference = reference
        };
    }
}
