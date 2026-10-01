using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using Verifiable.Core.Relations;
using Verifiable.Core.SecurityEvents;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// The Subject Identifiers a Resource Authorization Server knows each validated subject of an Identity
/// Assertion JWT Authorization Grant (ID-JAG) by: the application's table of <c>sub_id</c> associations, whose
/// <see cref="CompareAsync"/> is the <see cref="IdJagSubjectIdentifierRule.Association"/> of an
/// <see cref="IdJagSubjectIdentifierRule"/>.
/// </summary>
/// <remarks>
/// <para>
/// Each entry maps one validated grant subject, an <see cref="IdJagSubjectContext"/> (the grant's <c>iss</c>,
/// its <c>sub</c> and, for a multi-tenant issuer, its <c>tenant</c>), to the Subject Identifiers this server
/// knows that End-User by, as an immutable array the application replaces whole. The context is a sealed
/// record, so the dictionary key compares by value: an entry for one tenant of an issuer is not an entry for
/// another tenant of the same issuer and subject.
/// </para>
/// <para>
/// An entry is the application's local configuration in the words of
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.5">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 9.5</see>:
/// "The Resource Authorization Server MUST use a SAML NameID sub_id only when the validated ID-JAG issuer is
/// explicitly associated with the SAML issuer identified by sub_id.issuer through local configuration or
/// trusted federation metadata." Listing an identifier under a grant subject says two things at once. It
/// authorizes that identifier's namespace for the grant's issuer, the refusal of
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">Section 3.2.2</see>
/// when "the sub_id claim is not authorized by local policy for the validated ID-JAG issuer." And it states
/// that the identifier names the same End-User as the grant's subject,
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">Section 3.1</see>:
/// "When both sub and sub_id are present, they MUST identify the same End-User."
/// </para>
/// <para>
/// <see cref="CompareAsync"/> decides, in this order: a relation other than <see cref="ComparisonRelation.Equal"/>
/// is <see cref="ComparisonOutcome.Indeterminate"/>, because the <c>sub_id</c> profile defines equality only; a
/// grant subject with no entry is <see cref="ComparisonOutcome.Indeterminate"/>, because the dictionary holds
/// no association for it and so decides nothing; an entry listing an identifier equal to the candidate is
/// <see cref="ComparisonOutcome.Holds"/>; every other candidate <see cref="ComparisonOutcome.Fails"/>. Two
/// identifiers are equal when their <see cref="SubjectIdentifier.Format"/> values are ordinally equal and their
/// <see cref="SubjectIdentifier.Members"/> are structurally equal by
/// <see cref="StructuralEquality.JsonEqual"/>: every member, nested arrays and objects included, member names
/// and string values by their ordinal values. Member names compare ordinally whatever comparer either
/// identifier's member map carries, so a listed map over a comparer that ignores letter case does not match a
/// candidate's <c>ACCOUNT</c> under its <c>account</c>, the comparison
/// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.3">RFC 8259 Section 8.3</see> names
/// interoperable: "Implementations that transform the textual representation into sequences of Unicode code
/// units and then perform the comparison numerically, code unit by code unit, are interoperable in the sense
/// that implementations will agree in all cases on equality or inequality of two strings." A listed member map
/// that holds one name twice, possible only under a comparer that tells two strings of the same code units
/// apart, equals no candidate. An identifier parsed from the wire and one built by a factory of the same format hold their members in the same
/// materialized shapes, so the two compare equal when their values are equal.
/// </para>
/// <para>
/// Every member is compared, the strictest reading of
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">Section 3.2.2</see>:
/// "The Resource Authorization Server MUST compare every member of the SAML NameID Subject Identifier that is
/// part of the set of identifier fields it uses for subject resolution for that SAML issuer." An application
/// that resolves a subject by fewer members supplies its own <see cref="CompareDelegate{TCandidate, TReference}"/>.
/// So does one that canonicalizes an <c>email</c> before comparing,
/// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.2.1">RFC 9493 Section 3.2.2.1</see>:
/// "Therefore, the recipient SHOULD apply its own canonicalization algorithm to incoming events in order to
/// reproduce the translation done by the local email system."
/// </para>
/// <para>
/// An <c>aliases</c> candidate is compared as one identifier, whole, and is not expanded into its elements: it
/// equals an associated <c>aliases</c> identifier only. That is this library's reading against the intent
/// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.8">RFC 9493 Section 3.2.8</see> states for the
/// format: "It is intended for use when a variety of identifiers have been shared with the party that will be
/// interpreting the Subject Identifier, and it is unknown which of those identifiers they will recognize or
/// support." The reason: an <c>aliases</c> candidate whose elements this server lists under two different grant
/// subjects would, compared element by element, hold for either of them. An application that resolves a
/// subject by any single alias supplies its own delegate.
/// </para>
/// <para>
/// The application adds, replaces and removes entries at any time, under traffic, through the inherited
/// concurrent dictionary operations. <see cref="CompareAsync"/> reads the entry at the moment of each
/// comparison, so a change applies to the next validation. A listed identifier, and every map and list
/// reachable from its <see cref="SubjectIdentifier.Members"/>, is not changed after it is listed: an entry
/// changes by replacing its array with an array of new identifiers. Under that rule the values are immutable
/// arrays replaced whole, so a comparison never observes a half-written entry. The dictionary holds no cache,
/// no expiry and no bound: what it holds and for how long is the application's. It is wired on a rule as
/// <c>Association = associations.CompareAsync</c>.
/// </para>
/// <para>
/// A grant subject without an entry is undecided, and under
/// <see cref="IdJagSubjectIdentifierPresence.Optional"/> an undecided comparison permits the grant: as the
/// remarks of <see cref="IdJagSubjectIdentifierRule.Presence"/> state, the comparison record
/// (<see cref="IdJagAssertionValidationResult.SubjectIdentifierComparison"/>) says
/// <see cref="ComparisonOutcome.Indeterminate"/> with the decision <see cref="ComparisonDecision.Permit"/> there,
/// because the claim is OPTIONAL
/// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">Section 3.1</see>),
/// and <see cref="ComparisonDecision.IndeterminateDeny"/> under
/// <see cref="IdJagSubjectIdentifierPresence.Required"/>. Under
/// <see cref="IdJagSubjectIdentifierPresence.Optional"/> with no <see cref="IdJagSubjectIdentifierRule.Relation"/>,
/// the default, the association is not called at all, so an identifier the dictionary does not list is surfaced
/// too. An application that resolves the subject by the <c>sub_id</c> the validation surfaces therefore pairs
/// the dictionary with <see cref="IdJagSubjectIdentifierPresence.Required"/>.
/// </para>
/// <para>
/// A grant subject and a Subject Identifier can name a person, so the debugger display and
/// <see cref="ToString"/> show the number of entries only.
/// </para>
/// </remarks>
[DebuggerDisplay("IdJagSubjectAssociationDictionary(Count={Count})")]
public sealed class IdJagSubjectAssociationDictionary: ConcurrentDictionary<IdJagSubjectContext, ImmutableArray<SubjectIdentifier>>
{
    /// <summary>
    /// Creates an empty dictionary the application fills with the associations it keeps.
    /// </summary>
    public IdJagSubjectAssociationDictionary()
    {
    }


    /// <summary>
    /// Decides whether <paramref name="candidate"/>, the <c>sub_id</c> claim of a grant, names the End-User of
    /// <paramref name="reference"/>, the grant's validated subject, by the entry the dictionary holds for that
    /// subject at the moment of the call. Its method group is a
    /// <see cref="CompareDelegate{TCandidate, TReference}"/> of <see cref="SubjectIdentifier"/> and
    /// <see cref="IdJagSubjectContext"/>.
    /// </summary>
    /// <remarks>
    /// The work is synchronous and the result a completed <see cref="ValueTask{TResult}"/>. An entry whose
    /// array is the default value lists no identifier.
    /// </remarks>
    /// <param name="candidate">The Subject Identifier the grant carries.</param>
    /// <param name="reference">The grant's validated subject, the dictionary key looked up.</param>
    /// <param name="relation">The relation asked to hold, read "candidate RELATION reference".</param>
    /// <param name="cancellationToken">The token that cancels the comparison, honoured at entry.</param>
    /// <returns>
    /// <see cref="ComparisonOutcome.Holds"/> when the subject's entry lists an identifier equal to the candidate,
    /// <see cref="ComparisonOutcome.Fails"/> when the entry lists none, and
    /// <see cref="ComparisonOutcome.Indeterminate"/> for a relation other than
    /// <see cref="ComparisonRelation.Equal"/> or a subject without an entry.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="candidate"/> or <paramref name="reference"/> is <see langword="null"/>.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> is cancelled at entry.</exception>
    public ValueTask<ComparisonOutcome> CompareAsync(SubjectIdentifier candidate, IdJagSubjectContext reference, ComparisonRelation relation, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(reference);

        bool hasEntry = TryGetValue(reference, out ImmutableArray<SubjectIdentifier> associated);
        ComparisonOutcome outcome = (relation, hasEntry) switch
        {
            (not ComparisonRelation.Equal, _) => ComparisonOutcome.Indeterminate,
            (_, false) => ComparisonOutcome.Indeterminate,
            _ when IsListed(candidate, associated) => ComparisonOutcome.Holds,
            _ => ComparisonOutcome.Fails
        };

        return ValueTask.FromResult(outcome);
    }


    /// <summary>
    /// Renders the number of entries, in the words of the debugger display, and neither a grant subject nor a
    /// Subject Identifier.
    /// </summary>
    /// <remarks>
    /// A grant subject and a Subject Identifier can identify a person; a dictionary that reaches a log, a trace
    /// or an exception message through its text carries neither.
    /// </remarks>
    /// <returns>The text <c>IdJagSubjectAssociationDictionary(Count=...)</c>.</returns>
    public override string ToString() => string.Create(CultureInfo.InvariantCulture, $"IdJagSubjectAssociationDictionary(Count={Count})");


    /// <summary>
    /// Whether <paramref name="associated"/>, the identifiers an entry lists, holds one equal to
    /// <paramref name="candidate"/>; the default array lists none.
    /// </summary>
    /// <param name="candidate">The Subject Identifier the grant carries.</param>
    /// <param name="associated">The identifiers the grant subject's entry lists.</param>
    /// <returns><see langword="true"/> when an equal identifier is listed.</returns>
    private static bool IsListed(SubjectIdentifier candidate, ImmutableArray<SubjectIdentifier> associated) =>
        !associated.IsDefault && associated.Any(listed => listed is not null && IsSameIdentifier(candidate, listed));


    /// <summary>
    /// Whether two Subject Identifiers are equal: their formats ordinally equal and their members structurally
    /// equal by <see cref="StructuralEquality.JsonEqual"/>, every member compared.
    /// </summary>
    /// <param name="candidate">The Subject Identifier the grant carries.</param>
    /// <param name="listed">An identifier the grant subject's entry lists.</param>
    /// <returns><see langword="true"/> when the two are the same identifier.</returns>
    private static bool IsSameIdentifier(SubjectIdentifier candidate, SubjectIdentifier listed) =>
        string.Equals(candidate.Format, listed.Format, StringComparison.Ordinal)
        && StructuralEquality.JsonEqual(candidate.Members, listed.Members);
}
