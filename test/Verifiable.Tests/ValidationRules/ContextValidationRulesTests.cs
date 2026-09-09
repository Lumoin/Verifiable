using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Core.Assessment;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Validation;

namespace Verifiable.Tests.ValidationRules;

/// <summary>
/// Tests for <see cref="ContextValidationRules"/>: the <c>@context</c> validation claims shared
/// by DID documents, Verifiable Credentials, Verifiable Presentations, and the two Enveloped types.
/// </summary>
[TestClass]
internal sealed class ContextValidationRulesTests
{
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>: "the first item is a URL with the value
    /// <c>https://www.w3.org/ns/credentials/v2</c>." A matching first entry succeeds.
    /// </summary>
    [TestMethod]
    public void ValidateFirstEntrySucceedsWhenFirstEntryMatches()
    {
        var correct = Context.FromIris(Context.Credentials20, Context.DataIntegrity20);

        Assert.AreEqual(ClaimOutcome.Success, ContextValidationRules.ValidateFirstEntry(correct, Context.Credentials20).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>: the first item MUST be a URL with the value
    /// <c>https://www.w3.org/ns/credentials/v2</c>. A first entry naming a different IRI fails the claim.
    /// </summary>
    [TestMethod]
    public void ValidateFirstEntryFailsWhenFirstEntryIsAWrongIri()
    {
        var wrongFirst = Context.FromIris(Context.DataIntegrity20, Context.Credentials20);

        Assert.AreEqual(ClaimOutcome.Failure, ContextValidationRules.ValidateFirstEntry(wrongFirst, Context.Credentials20).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see> requires the first item to be a specific URL; a missing context has no first
    /// item, so it fails the claim rather than throwing.
    /// </summary>
    [TestMethod]
    public void ValidateFirstEntryFailsWhenContextIsMissing()
    {
        Assert.AreEqual(ClaimOutcome.Failure, ContextValidationRules.ValidateFirstEntry(null, Context.Credentials20).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see> requires the first item of the ordered set to be a specific URL; a context
    /// with zero entries has no first item, so it fails the claim rather than throwing.
    /// </summary>
    [TestMethod]
    public void ValidateFirstEntryFailsWhenContextIsEmpty()
    {
        var empty = new Context([], ContextForm.Array);

        Assert.AreEqual(ClaimOutcome.Failure, ContextValidationRules.ValidateFirstEntry(empty, Context.Credentials20).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>: the first item MUST be a URL. A first entry that is an inline definition
    /// rather than an IRI fails the claim, and the diagnostic context reports no found IRI (the
    /// entry is not one).
    /// </summary>
    [TestMethod]
    public void ValidateFirstEntryFailsWhenFirstEntryIsADefinition()
    {
        var definition = new Dictionary<string, object> { ["@vocab"] = "https://example.com/" };
        var withDefinitionFirst = new Context([ContextEntry.FromDefinition(definition), ContextEntry.FromIri(Context.Credentials20)], ContextForm.Array);

        Claim claim = ContextValidationRules.ValidateFirstEntry(withDefinitionFirst, Context.Credentials20);
        var claimContext = (ContextFirstEntryClaimContext)claim.Context;

        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        Assert.IsNull(claimContext.FoundIri);
    }


    /// <summary>
    /// The <see cref="ContextFirstEntryClaimContext"/> on a
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see> first-entry failure names which IRI was actually found, for diagnostics.
    /// </summary>
    [TestMethod]
    public void ValidateFirstEntryClaimNamesTheFoundIri()
    {
        var wrongFirst = Context.FromIris(Context.DataIntegrity20);

        Claim claim = ContextValidationRules.ValidateFirstEntry(wrongFirst, Context.Credentials20);
        var claimContext = (ContextFirstEntryClaimContext)claim.Context;
        string? recordedExpectedIri = claimContext.ExpectedIri;

        Assert.AreEqual(Context.DataIntegrity20, claimContext.FoundIri);
        Assert.AreEqual(Context.Credentials20, recordedExpectedIri);
    }


    /// <summary>
    /// The multi-candidate overload — the DID Core profile's shape, where either
    /// <see href="https://www.w3.org/TR/did-1.0/#x6-3-1-production">DID Core 1.0 §6.3.1
    /// Production</see>'s or <see href="https://www.w3.org/TR/did-1.1/#json-ld-processors">DID Core
    /// 1.1 §6.2.3 JSON-LD Processors</see>'s context is an acceptable first entry — succeeds when
    /// the first entry is EITHER candidate.
    /// </summary>
    [TestMethod]
    public void ValidateFirstEntryWithCandidateListSucceedsForEitherCandidate()
    {
        var didCore11First = Context.FromIris(Context.DidCore11, Context.Multikey10);

        Assert.AreEqual(
            ClaimOutcome.Success,
            ContextValidationRules.ValidateFirstEntry(didCore11First, [Context.DidCore10, Context.DidCore11]).Outcome);
    }


    /// <summary>
    /// The multi-candidate overload fails <see href="https://www.w3.org/TR/did-1.0/#x6-3-1-production">DID
    /// Core 1.0 §6.3.1 Production</see>'s (and DID Core 1.1's) first-entry requirement when the
    /// first entry matches neither candidate.
    /// </summary>
    [TestMethod]
    public void ValidateFirstEntryWithCandidateListFailsWhenNeitherCandidateMatches()
    {
        var neither = Context.FromIris(Context.Credentials20);

        Assert.AreEqual(
            ClaimOutcome.Failure,
            ContextValidationRules.ValidateFirstEntry(neither, [Context.DidCore10, Context.DidCore11]).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>'s "combination of URLs and objects": an absolute URL succeeds.
    /// </summary>
    [TestMethod]
    public void ValidateEntriesAreUrlsOrDefinitionsSucceedsForAnHttpsIri()
    {
        var httpsOnly = Context.FromIris(Context.Credentials20);

        Assert.AreEqual(ClaimOutcome.Success, ContextValidationRules.ValidateEntriesAreUrlsOrDefinitions(httpsOnly).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>'s "combination of URLs and objects": an inline definition entry succeeds
    /// regardless of scheme concerns (it carries no IRI).
    /// </summary>
    [TestMethod]
    public void ValidateEntriesAreUrlsOrDefinitionsSucceedsForADefinition()
    {
        var definition = new Dictionary<string, object> { ["name"] = "http://schema.org/name" };
        var withDefinition = new Context([ContextEntry.FromDefinition(definition)], ContextForm.Scalar);

        Assert.AreEqual(ClaimOutcome.Success, ContextValidationRules.ValidateEntriesAreUrlsOrDefinitions(withDefinition).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>'s "combination of URLs and objects": a bare path carries no scheme at all, so
    /// it is not a URL even though <see cref="System.Uri.TryCreate(string, System.UriKind, out System.Uri)"/>
    /// can misparse it as an absolute <c>file</c>-scheme URI on some platforms; the claim context
    /// names the offending entry.
    /// </summary>
    [TestMethod]
    public void ValidateEntriesAreUrlsOrDefinitionsFailsForABarePath()
    {
        var barePath = Context.FromIris("/vocab/v1");

        Claim claim = ContextValidationRules.ValidateEntriesAreUrlsOrDefinitions(barePath);
        var claimContext = (ContextEntriesAreUrlsOrDefinitionsClaimContext)claim.Context;

        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        Assert.AreEqual(0, claimContext.OffendingIndex);
    }


    /// <summary>
    /// A <c>did:</c> IRI is an absolute URL under the
    /// <see href="https://url.spec.whatwg.org/">WHATWG URL Standard</see> that
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#dfn-url">VC Data Model 2.0's own "URL"
    /// term</see> defers to — that standard's parser is scheme-agnostic — so a <c>did:</c> entry
    /// succeeds <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>'s "combination of URLs and objects" claim.
    /// </summary>
    [TestMethod]
    public void ValidateEntriesAreUrlsOrDefinitionsSucceedsForADidScheme()
    {
        var didScheme = Context.FromIris("did:example:context");

        Assert.AreEqual(ClaimOutcome.Success, ContextValidationRules.ValidateEntriesAreUrlsOrDefinitions(didScheme).Outcome);
    }


    /// <summary>
    /// A <c>urn:</c> IRI is likewise a URL under the
    /// <see href="https://url.spec.whatwg.org/">WHATWG URL Standard</see> that
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#dfn-url">VC Data Model 2.0's own "URL"
    /// term</see> defers to, and succeeds
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>'s "combination of URLs and objects" claim.
    /// </summary>
    [TestMethod]
    public void ValidateEntriesAreUrlsOrDefinitionsSucceedsForAUrnScheme()
    {
        var urnScheme = Context.FromIris("urn:example:context");

        Assert.AreEqual(ClaimOutcome.Success, ContextValidationRules.ValidateEntriesAreUrlsOrDefinitions(urnScheme).Outcome);
    }


    /// <summary>
    /// An https IRI carrying a fragment is still an absolute http(s) URL under
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see> and succeeds.
    /// </summary>
    [TestMethod]
    public void ValidateEntriesAreUrlsOrDefinitionsSucceedsForAnIriWithAFragment()
    {
        var withFragment = Context.FromIris("https://example.com/context#fragment");

        Assert.AreEqual(ClaimOutcome.Success, ContextValidationRules.ValidateEntriesAreUrlsOrDefinitions(withFragment).Outcome);
    }


    /// <summary>
    /// An https IRI carrying a query component is still an absolute http(s) URL under
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see> and succeeds.
    /// </summary>
    [TestMethod]
    public void ValidateEntriesAreUrlsOrDefinitionsSucceedsForAnIriWithAQuery()
    {
        var withQuery = Context.FromIris("https://example.com/context?version=2");

        Assert.AreEqual(ClaimOutcome.Success, ContextValidationRules.ValidateEntriesAreUrlsOrDefinitions(withQuery).Outcome);
    }


    /// <summary>
    /// A missing context is not applicable to
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>'s per-entry shape check — there are no entries to check, and
    /// <see cref="ContextValidationRules.ValidateContextIsPresent"/> is what reports absence.
    /// </summary>
    [TestMethod]
    public void ValidateEntriesAreUrlsOrDefinitionsIsNotApplicableWhenContextIsMissing()
    {
        Assert.AreEqual(ClaimOutcome.NotApplicable, ContextValidationRules.ValidateEntriesAreUrlsOrDefinitions(null).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">VC Data Integrity
    /// 1.0 §2.4.1 Validating Contexts</see>'s check-against-known-values mechanism: every entry on
    /// the caller's allowlist succeeds.
    /// </summary>
    [TestMethod]
    public void ValidateKnownContextsSucceedsWhenEveryEntryIsKnown()
    {
        var known = Context.FromIris(Context.Credentials20, Context.DataIntegrity20);

        Assert.AreEqual(
            ClaimOutcome.Success,
            ContextValidationRules.ValidateKnownContexts(known, WellKnownContextAllowlists.Credentials20, isInlineDefinitionAllowed: false).Outcome);
    }


    /// <summary>
    /// An IRI not on the caller's allowlist fails
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">VC Data Integrity
    /// 1.0 §2.4.1 Validating Contexts</see>'s check, and the claim context names it.
    /// </summary>
    [TestMethod]
    public void ValidateKnownContextsFailsWhenAnEntryIsUnknown()
    {
        var unknown = Context.FromIris(Context.Credentials20, "https://example.com/unknown/v1");

        Claim claim = ContextValidationRules.ValidateKnownContexts(unknown, WellKnownContextAllowlists.Credentials20, isInlineDefinitionAllowed: false);
        var claimContext = (ContextKnownContextsClaimContext)claim.Context;

        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        Assert.AreEqual("https://example.com/unknown/v1", claimContext.OffendingIri);
        Assert.IsFalse(claimContext.WasDisallowedDefinition);
    }


    /// <summary>
    /// An inline definition fails
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">VC Data Integrity
    /// 1.0 §2.4.1 Validating Contexts</see>'s check when the caller does not allow one, and the
    /// claim context marks it as a disallowed definition rather than an unknown IRI.
    /// </summary>
    [TestMethod]
    public void ValidateKnownContextsFailsForADefinitionWhenNotAllowed()
    {
        var definition = new Dictionary<string, object> { ["name"] = "http://schema.org/name" };
        var withDefinition = new Context([ContextEntry.FromIri(Context.Credentials20), ContextEntry.FromDefinition(definition)], ContextForm.Array);

        Claim claim = ContextValidationRules.ValidateKnownContexts(withDefinition, WellKnownContextAllowlists.Credentials20, isInlineDefinitionAllowed: false);
        var claimContext = (ContextKnownContextsClaimContext)claim.Context;

        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        Assert.IsTrue(claimContext.WasDisallowedDefinition);
        Assert.AreEqual(1, claimContext.OffendingIndex);
    }


    /// <summary>
    /// An inline definition succeeds under
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">VC Data Integrity
    /// 1.0 §2.4.1 Validating Contexts</see>'s check once the caller allows one.
    /// </summary>
    [TestMethod]
    public void ValidateKnownContextsSucceedsForADefinitionWhenAllowed()
    {
        var definition = new Dictionary<string, object> { ["name"] = "http://schema.org/name" };
        var withDefinition = new Context([ContextEntry.FromIri(Context.Credentials20), ContextEntry.FromDefinition(definition)], ContextForm.Array);

        Assert.AreEqual(
            ClaimOutcome.Success,
            ContextValidationRules.ValidateKnownContexts(withDefinition, WellKnownContextAllowlists.Credentials20, isInlineDefinitionAllowed: true).Outcome);
    }


    /// <summary>
    /// A missing context is not applicable to
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">VC Data Integrity
    /// 1.0 §2.4.1 Validating Contexts</see>'s check — there are no entries to compare to the
    /// allowlist.
    /// </summary>
    [TestMethod]
    public void ValidateKnownContextsIsNotApplicableWhenContextIsMissing()
    {
        Assert.AreEqual(
            ClaimOutcome.NotApplicable,
            ContextValidationRules.ValidateKnownContexts(null, WellKnownContextAllowlists.Credentials20, isInlineDefinitionAllowed: true).Outcome);
    }


    /// <summary>
    /// Distinct entries succeed, per
    /// <see href="https://infra.spec.whatwg.org/#ordered-set">the Infra Standard's ordered set</see>
    /// definition, which VC Data Model 2.0 §4.3 requires of <c>@context</c>.
    /// </summary>
    [TestMethod]
    public void ValidateNoDuplicateEntriesSucceedsForDistinctEntries()
    {
        var distinct = Context.FromIris(Context.Credentials20, Context.DataIntegrity20);

        Assert.AreEqual(ClaimOutcome.Success, ContextValidationRules.ValidateNoDuplicateEntries(distinct).Outcome);
    }


    /// <summary>
    /// A repeated IRI fails, per <see href="https://infra.spec.whatwg.org/#ordered-set">the Infra
    /// Standard's ordered set</see>: "must not contain the same item twice."
    /// </summary>
    [TestMethod]
    public void ValidateNoDuplicateEntriesFailsForARepeatedIri()
    {
        var duplicateIri = Context.FromIris(Context.Credentials20, Context.Credentials20);

        Assert.AreEqual(ClaimOutcome.Failure, ContextValidationRules.ValidateNoDuplicateEntries(duplicateIri).Outcome);
    }


    /// <summary>
    /// A repeated inline definition, its properties in a different order, still fails
    /// <see href="https://infra.spec.whatwg.org/#ordered-set">the Infra Standard's ordered set</see>
    /// requirement, since <see cref="ContextEntry.Equals(ContextEntry)"/> compares definitions
    /// structurally rather than by property order, and the claim context names the pair.
    /// </summary>
    [TestMethod]
    public void ValidateNoDuplicateEntriesFailsForARepeatedDefinitionWithReorderedProperties()
    {
        var firstOrder = new Dictionary<string, object> { ["a"] = "http://example.com/a", ["b"] = "http://example.com/b" };
        var secondOrder = new Dictionary<string, object> { ["b"] = "http://example.com/b", ["a"] = "http://example.com/a" };
        var duplicateDefinition = new Context([ContextEntry.FromDefinition(firstOrder), ContextEntry.FromDefinition(secondOrder)], ContextForm.Array);

        Claim claim = ContextValidationRules.ValidateNoDuplicateEntries(duplicateDefinition);
        var claimContext = (ContextDuplicateEntryClaimContext)claim.Context;

        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        Assert.AreEqual(0, claimContext.FirstIndex);
        Assert.AreEqual(1, claimContext.DuplicateIndex);
    }


    /// <summary>
    /// A missing context is not applicable to
    /// <see href="https://infra.spec.whatwg.org/#ordered-set">the Infra Standard's ordered set</see>
    /// requirement — there are no entries to compare.
    /// </summary>
    [TestMethod]
    public void ValidateNoDuplicateEntriesIsNotApplicableWhenContextIsMissing()
    {
        Assert.AreEqual(ClaimOutcome.NotApplicable, ContextValidationRules.ValidateNoDuplicateEntries(null).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>: "Verifiable credentials and verifiable presentations MUST include a
    /// <c>@context</c> property." A present context succeeds.
    /// </summary>
    [TestMethod]
    public void ValidateContextIsPresentSucceedsWhenContextIsPresent()
    {
        Assert.AreEqual(ClaimOutcome.Success, ContextValidationRules.ValidateContextIsPresent(Context.FromIris(Context.Credentials20)).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>: "Verifiable credentials and verifiable presentations MUST include a
    /// <c>@context</c> property." An absent context fails the presence claim.
    /// </summary>
    [TestMethod]
    public void ValidateContextIsPresentFailsWhenContextIsAbsent()
    {
        Assert.AreEqual(ClaimOutcome.Failure, ContextValidationRules.ValidateContextIsPresent(null).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>: "Verifiable credentials and verifiable presentations MUST include a
    /// <c>@context</c> property." An empty entry list is still a present <c>@context</c> member for
    /// this rule — its emptiness is <see cref="ContextValidationRules.ValidateFirstEntry(Context?, string)"/>'s
    /// concern, not this rule's.
    /// </summary>
    [TestMethod]
    public void ValidateContextIsPresentSucceedsWhenContextIsPresentButEmpty()
    {
        Assert.AreEqual(ClaimOutcome.Success, ContextValidationRules.ValidateContextIsPresent(new Context([], ContextForm.Array)).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>'s ordered-set (array) requirement succeeds for a context in
    /// <see cref="ContextForm.Array"/>.
    /// </summary>
    [TestMethod]
    public void ValidateFormIsOrderedSetSucceedsForArrayForm()
    {
        var array = new Context([ContextEntry.FromIri(Context.Credentials20)], ContextForm.Array);

        Assert.AreEqual(ClaimOutcome.Success, ContextValidationRules.ValidateFormIsOrderedSet(array).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>'s ordered-set (array) requirement: a bare scalar form fails it.
    /// </summary>
    [TestMethod]
    public void ValidateFormIsOrderedSetFailsForScalarForm()
    {
        var scalar = new Context([ContextEntry.FromIri(Context.Credentials20)], ContextForm.Scalar);

        Assert.AreEqual(ClaimOutcome.Failure, ContextValidationRules.ValidateFormIsOrderedSet(scalar).Outcome);
    }


    /// <summary>
    /// A missing context is not applicable to
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>'s ordered-set requirement —
    /// <see cref="ContextValidationRules.ValidateContextIsPresent"/> reports absence.
    /// </summary>
    [TestMethod]
    public void ValidateFormIsOrderedSetIsNotApplicableWhenContextIsMissing()
    {
        Assert.AreEqual(ClaimOutcome.NotApplicable, ContextValidationRules.ValidateFormIsOrderedSet(null).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#extensibility">VC Data Model 2.0 §5.2
    /// Extensibility</see>'s undefined-terms context succeeds when it is the last entry.
    /// </summary>
    [TestMethod]
    public void ValidateUndefinedTermsLastWhenPresentSucceedsWhenLast()
    {
        var last = Context.FromIris(Context.Credentials20, Context.UndefinedTerms20);

        Assert.AreEqual(ClaimOutcome.Success, ContextValidationRules.ValidateUndefinedTermsLastWhenPresent(last).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#extensibility">VC Data Model 2.0 §5.2
    /// Extensibility</see>: the undefined-terms context fails the claim when it is not the last
    /// entry, and the claim context names where it was actually found.
    /// </summary>
    [TestMethod]
    public void ValidateUndefinedTermsLastWhenPresentFailsWhenNotLast()
    {
        var notLast = Context.FromIris(Context.UndefinedTerms20, Context.Credentials20);

        Claim claim = ContextValidationRules.ValidateUndefinedTermsLastWhenPresent(notLast);
        var claimContext = (ContextUndefinedTermsPositionClaimContext)claim.Context;

        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        Assert.AreEqual(0, claimContext.FoundAt);
        Assert.AreEqual(1, claimContext.LastIndex);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#extensibility">VC Data Model 2.0 §5.2
    /// Extensibility</see>'s undefined-terms context is optional — its absence is not applicable,
    /// not a failure.
    /// </summary>
    [TestMethod]
    public void ValidateUndefinedTermsLastWhenPresentIsNotApplicableWhenAbsent()
    {
        var withoutIt = Context.FromIris(Context.Credentials20);

        Assert.AreEqual(ClaimOutcome.NotApplicable, ContextValidationRules.ValidateUndefinedTermsLastWhenPresent(withoutIt).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#extensibility">VC Data Model 2.0 §5.2
    /// Extensibility</see>: "A conforming document SHOULD NOT use the <c>@vocab</c> feature in
    /// production." A context with no <c>@vocab</c> in any inline definition succeeds.
    /// </summary>
    [TestMethod]
    public void ValidateNoVocabInDefinitionSucceedsWhenNoDefinitionDeclaresVocab()
    {
        var definition = new Dictionary<string, object> { ["name"] = "http://schema.org/name" };
        var withDefinition = new Context([ContextEntry.FromIri(Context.Credentials20), ContextEntry.FromDefinition(definition)], ContextForm.Array);

        Assert.AreEqual(ClaimOutcome.Success, ContextValidationRules.ValidateNoVocabInDefinition(withDefinition).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#extensibility">VC Data Model 2.0 §5.2
    /// Extensibility</see>: "A conforming document SHOULD NOT use the <c>@vocab</c> feature in
    /// production." An inline definition declaring <c>@vocab</c> fails the claim, and the claim
    /// context names the offending entry.
    /// </summary>
    [TestMethod]
    public void ValidateNoVocabInDefinitionFailsWhenADefinitionDeclaresVocab()
    {
        var definitionWithVocab = new Dictionary<string, object> { ["@vocab"] = "https://example.com/" };
        var withVocab = new Context([ContextEntry.FromIri(Context.Credentials20), ContextEntry.FromDefinition(definitionWithVocab)], ContextForm.Array);

        Claim claim = ContextValidationRules.ValidateNoVocabInDefinition(withVocab);
        var claimContext = (ContextVocabInDefinitionClaimContext)claim.Context;

        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        Assert.AreEqual(1, claimContext.OffendingIndex);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/json-ld11-api/#context-processing-algorithm">JSON-LD 1.1
    /// Processing Algorithms and API §4.1 Context Processing Algorithm</see>: "If value is
    /// <see langword="null"/>, remove any vocabulary mapping from result." A null-valued
    /// <c>@vocab</c> CLEARS a vocabulary mapping rather than declaring one, the safe direction
    /// <see cref="ContextValidationRules.ValidateNoVocabInDefinition"/> exists to permit, so it
    /// succeeds rather than failing on bare key presence.
    /// </summary>
    [TestMethod]
    public void ValidateNoVocabInDefinitionSucceedsWhenVocabIsExplicitlyNull()
    {
        var definitionClearingVocab = new Dictionary<string, object> { ["@vocab"] = null! };
        var withClearedVocab = new Context(
            [ContextEntry.FromIri(Context.Credentials20), ContextEntry.FromDefinition(definitionClearingVocab)],
            ContextForm.Array);

        Assert.AreEqual(ClaimOutcome.Success, ContextValidationRules.ValidateNoVocabInDefinition(withClearedVocab).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#context-injection">VC Data Integrity
    /// 1.0 §2.4.2 Context Injection</see>'s context-adequacy claim does not apply without a Data
    /// Integrity proof to secure.
    /// </summary>
    [TestMethod]
    public void ValidateDataIntegrityContextPresentWhenProofPresentIsNotApplicableWithoutAProof()
    {
        Assert.AreEqual(
            ClaimOutcome.NotApplicable,
            ContextValidationRules.ValidateDataIntegrityContextPresentWhenProofPresent(null, hasDataIntegrityProof: false).Outcome);
    }


    /// <summary>
    /// With a Data Integrity proof, <see cref="Context.Credentials20"/> alone satisfies
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#context-injection">VC Data Integrity
    /// 1.0 §2.4.2 Context Injection</see>'s "one or more contexts with at least the same
    /// declarations" alternative.
    /// </summary>
    [TestMethod]
    public void ValidateDataIntegrityContextPresentWhenProofPresentSucceedsForCredentials20()
    {
        var withCredentials20 = Context.FromIris(Context.Credentials20);

        Assert.AreEqual(
            ClaimOutcome.Success,
            ContextValidationRules.ValidateDataIntegrityContextPresentWhenProofPresent(withCredentials20, hasDataIntegrityProof: true).Outcome);
    }


    /// <summary>
    /// With a Data Integrity proof, the explicit <see cref="Context.DataIntegrity20"/> context
    /// named by <see href="https://www.w3.org/TR/vc-data-integrity/#context-injection">VC Data
    /// Integrity 1.0 §2.4.2 Context Injection</see> also satisfies the claim.
    /// </summary>
    [TestMethod]
    public void ValidateDataIntegrityContextPresentWhenProofPresentSucceedsForDataIntegrity20()
    {
        var withDataIntegrity20 = Context.FromIris(Context.DataIntegrity20);

        Assert.AreEqual(
            ClaimOutcome.Success,
            ContextValidationRules.ValidateDataIntegrityContextPresentWhenProofPresent(withDataIntegrity20, hasDataIntegrityProof: true).Outcome);
    }


    /// <summary>
    /// With a Data Integrity proof but neither context
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#context-injection">VC Data Integrity
    /// 1.0 §2.4.2 Context Injection</see> names as adequate, the claim fails.
    /// </summary>
    [TestMethod]
    public void ValidateDataIntegrityContextPresentWhenProofPresentFailsWhenNeitherContextIsPresent()
    {
        var neither = Context.FromIris("https://example.com/unrelated/v1");

        Assert.AreEqual(
            ClaimOutcome.Failure,
            ContextValidationRules.ValidateDataIntegrityContextPresentWhenProofPresent(neither, hasDataIntegrityProof: true).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-credentials">VC Data
    /// Model 2.0 §4.13 Verifiable Presentations, "Enveloped Verifiable Credentials"</see>: "The
    /// <c>@context</c> property of the object MUST be present and include a context, such as the
    /// base context for this specification [...]." Including the base context succeeds.
    /// </summary>
    [TestMethod]
    public void ValidateEnvelopedContextPresentAndIncludesBaseContextSucceedsWhenBaseContextIsIncluded()
    {
        var withBaseContext = Context.FromIris(Context.Credentials20);

        Assert.AreEqual(ClaimOutcome.Success, ContextValidationRules.ValidateEnvelopedContextPresentAndIncludesBaseContext(withBaseContext).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-credentials">VC
    /// Data Model 2.0 §4.13 Verifiable Credentials</see>: the clause requires a context "such as"
    /// the base context, not the base context specifically. A present context this method does not
    /// recognize is <see cref="ClaimOutcome.Inconclusive"/> — it may still define the required
    /// terms through a context this method, having no JSON-LD term-expansion machinery, cannot
    /// evaluate — never <see cref="ClaimOutcome.Failure"/> on a MUST the document may not actually violate.
    /// </summary>
    [TestMethod]
    public void ValidateEnvelopedContextPresentAndIncludesBaseContextIsInconclusiveWhenBaseContextIsMissing()
    {
        var withoutBaseContext = Context.FromIris("https://example.com/unrelated/v1");

        Assert.AreEqual(ClaimOutcome.Inconclusive, ContextValidationRules.ValidateEnvelopedContextPresentAndIncludesBaseContext(withoutBaseContext).Outcome);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-credentials">VC
    /// Data Model 2.0 §4.13 Verifiable Presentations, "Enveloped Verifiable Credentials"</see>: an
    /// absent context fails the claim outright — presence is mandatory for the enveloped types.
    /// </summary>
    [TestMethod]
    public void ValidateEnvelopedContextPresentAndIncludesBaseContextFailsWhenContextIsAbsent()
    {
        Assert.AreEqual(ClaimOutcome.Failure, ContextValidationRules.ValidateEnvelopedContextPresentAndIncludesBaseContext(null).Outcome);
    }


    /// <summary>
    /// <see cref="ContextValidationRules.ValidateCredentialContextAsync"/> (the NORMATIVE pipeline)
    /// issues every MUST-level
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see> Credentials20 profile claim as a <see cref="ClaimOutcome.Success"/> for a
    /// fully conformant credential.
    /// </summary>
    [TestMethod]
    public async Task ValidateCredentialContextAsyncSucceedsForAConformantCredential()
    {
        var credential = new VerifiableCredential
        {
            Context = Context.FromIris(Context.Credentials20, Context.UndefinedTerms20),
            Id = "urn:uuid:1",
            Type = ["VerifiableCredential"],
            Issuer = Issuer.FromUri("did:example:issuer"),
            CredentialSubject = [new CredentialSubject { Id = "did:example:subject" }]
        };

        List<Claim> claims = await ContextValidationRules.ValidateCredentialContextAsync(credential, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.DoesNotContain(ClaimOutcome.Failure, claims.ConvertAll(static claim => claim.Outcome));
    }


    /// <summary>
    /// <see cref="ContextValidationRules.ValidateCredentialContextAsync"/> (the NORMATIVE
    /// pipeline) succeeds for a credential whose <c>@context</c> carries a well-formed but
    /// unrecognized <c>https</c> IRI — <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC
    /// Data Model 2.0 §4.3 Contexts</see>'s "Subsequent items in the ordered set MUST be composed of
    /// any combination of URLs and objects" names no allowlist, so a use-case context outside this
    /// library's own <see cref="WellKnownContextAllowlists.Credentials20"/> violates no MUST.
    /// </summary>
    [TestMethod]
    public async Task ValidateCredentialContextAsyncSucceedsForAnUnknownWellFormedContextIri()
    {
        var credential = new VerifiableCredential
        {
            Context = Context.FromIris(Context.Credentials20, "https://example.com/use-case-context/v1"),
            Id = "urn:uuid:use-case",
            Type = ["VerifiableCredential"],
            Issuer = Issuer.FromUri("did:example:issuer"),
            CredentialSubject = [new CredentialSubject { Id = "did:example:subject" }]
        };

        List<Claim> claims = await ContextValidationRules.ValidateCredentialContextAsync(credential, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.DoesNotContain(ClaimOutcome.Failure, claims.ConvertAll(static claim => claim.Outcome));
    }


    /// <summary>
    /// <see cref="ContextValidationRules.ValidateCredentialContextAsync"/> (the NORMATIVE pipeline)
    /// succeeds for a credential whose <c>@context</c> carries a <c>urn:</c> entry.
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#dfn-url">VC Data Model 2.0's own "URL"
    /// term</see> is "a Uniform Resource Locator, as defined by the
    /// <see href="https://url.spec.whatwg.org/">URL Standard</see> [...] the rules for
    /// dereferencing, or fetching, a URL are defined by the URL scheme" — that scheme-agnostic
    /// parser accepts <c>urn:</c>, so <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC
    /// Data Model 2.0 §4.3 Contexts</see>'s "combination of URLs and objects" MUST names no
    /// http(s)-only restriction for the NORMATIVE gate to enforce.
    /// </summary>
    [TestMethod]
    public async Task ValidateCredentialContextAsyncSucceedsForAUrnSchemeContextIri()
    {
        var credential = new VerifiableCredential
        {
            Context = Context.FromIris(Context.Credentials20, "urn:example:profile:v1"),
            Id = "urn:uuid:urn-scheme",
            Type = ["VerifiableCredential"],
            Issuer = Issuer.FromUri("did:example:issuer"),
            CredentialSubject = [new CredentialSubject { Id = "did:example:subject" }]
        };

        List<Claim> claims = await ContextValidationRules.ValidateCredentialContextAsync(credential, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.DoesNotContain(ClaimOutcome.Failure, claims.ConvertAll(static claim => claim.Outcome));
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">Data Integrity 1.0
    /// §2.4.1 Validating Contexts</see>: "It is necessary to ensure that a consuming application has
    /// explicitly approved of the types, and therefore the semantics, of input documents that it
    /// will process. Not checking JSON-LD context values against known good values can lead to
    /// security vulnerabilities [...]" — the allowlist check
    /// <see cref="ContextValidationRules.ValidateKnownContexts"/> implements this and reports
    /// <see cref="ClaimOutcome.Failure"/> for the SAME credential
    /// <see cref="ValidateCredentialContextAsyncSucceedsForAnUnknownWellFormedContextIri"/> proves
    /// the NORMATIVE pipeline accepts: §2.4.1 names this technique a SHOULD-level, out-of-band
    /// check the library layers on top, never a VC Data Model 2.0 MUST.
    /// </summary>
    [TestMethod]
    public async Task ValidateCredentialContextStrictProfileAsyncFailsAllowlistClaimForAnUnknownContextIri()
    {
        var credential = new VerifiableCredential
        {
            Context = Context.FromIris(Context.Credentials20, "https://example.com/use-case-context/v1"),
            Id = "urn:uuid:use-case",
            Type = ["VerifiableCredential"],
            Issuer = Issuer.FromUri("did:example:issuer"),
            CredentialSubject = [new CredentialSubject { Id = "did:example:subject" }]
        };

        List<Claim> claims = await ContextValidationRules.ValidateCredentialContextStrictProfileAsync(credential, TestContext.CancellationToken).ConfigureAwait(false);

        Claim allowlistClaim = claims.Find(static claim => claim.Id.Equals(ClaimId.ContextKnownContexts))!;
        Assert.AreEqual(ClaimOutcome.Failure, allowlistClaim.Outcome);
    }


    /// <summary>
    /// <see cref="ContextValidationRules.ValidateCredentialContextStrictProfileAsync"/> reports the
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#context-injection">VC Data Integrity
    /// 1.0 §2.4.2 Context Injection</see> context-adequacy claim as <see cref="ClaimOutcome.Failure"/>
    /// for a secured credential whose context does not cover Data Integrity terms.
    /// </summary>
    [TestMethod]
    public async Task ValidateCredentialContextStrictProfileAsyncFailsDataIntegrityClaimWhenSecuredContextIsInadequate()
    {
        var credential = new DataIntegritySecuredCredential
        {
            Context = Context.FromIris("https://example.com/unrelated/v1"),
            Proof = [new DataIntegrityProof { Type = "DataIntegrityProof" }]
        };

        List<Claim> claims = await ContextValidationRules.ValidateCredentialContextStrictProfileAsync(credential, TestContext.CancellationToken).ConfigureAwait(false);

        Claim dataIntegrityClaim = claims.Find(static claim => claim.Id.Equals(ClaimId.ContextDataIntegrityPresentWhenProofPresent))!;
        Assert.AreEqual(ClaimOutcome.Failure, dataIntegrityClaim.Outcome);
    }


    /// <summary>
    /// <see cref="ContextValidationRules.ValidatePresentationContextAsync"/> mirrors the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see> credential profile for a conformant presentation.
    /// </summary>
    [TestMethod]
    public async Task ValidatePresentationContextAsyncSucceedsForAConformantPresentation()
    {
        var presentation = new VerifiablePresentation
        {
            Context = Context.FromIris(Context.Credentials20),
            Id = "urn:uuid:2",
            Type = ["VerifiablePresentation"]
        };

        List<Claim> claims = await ContextValidationRules.ValidatePresentationContextAsync(presentation, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.DoesNotContain(ClaimOutcome.Failure, claims.ConvertAll(static claim => claim.Outcome));
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">Data Integrity 1.0
    /// §2.4.1 Validating Contexts</see>: "It is necessary to ensure that a consuming application has
    /// explicitly approved of the types, and therefore the semantics, of input documents that it
    /// will process [...]" —
    /// <see cref="ContextValidationRules.ValidatePresentationContextStrictProfileAsync"/> mirrors
    /// <see cref="ContextValidationRules.ValidateCredentialContextStrictProfileAsync"/>: it reports
    /// the allowlist claim as <see cref="ClaimOutcome.Failure"/> for a presentation context carrying
    /// a well-formed IRI absent from <see cref="WellKnownContextAllowlists.Credentials20"/>, even
    /// though that same context passes <see cref="ContextValidationRules.ValidatePresentationContextAsync"/>'s
    /// NORMATIVE pipeline.
    /// </summary>
    [TestMethod]
    public async Task ValidatePresentationContextStrictProfileAsyncFailsAllowlistClaimForAnUnknownContextIri()
    {
        var presentation = new VerifiablePresentation
        {
            Context = Context.FromIris(Context.Credentials20, "https://example.com/use-case-context/v1"),
            Id = "urn:uuid:3",
            Type = ["VerifiablePresentation"]
        };

        List<Claim> normativeClaims = await ContextValidationRules.ValidatePresentationContextAsync(presentation, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.DoesNotContain(ClaimOutcome.Failure, normativeClaims.ConvertAll(static claim => claim.Outcome));

        List<Claim> strictClaims = await ContextValidationRules.ValidatePresentationContextStrictProfileAsync(presentation, TestContext.CancellationToken).ConfigureAwait(false);
        Claim allowlistClaim = strictClaims.Find(static claim => claim.Id.Equals(ClaimId.ContextKnownContexts))!;
        Assert.AreEqual(ClaimOutcome.Failure, allowlistClaim.Outcome);
    }


    /// <summary>
    /// <see cref="ContextValidationRules.ValidateEnvelopedCredentialContextAsync"/> succeeds under
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-credentials">VC
    /// Data Model 2.0 §4.13 Verifiable Presentations, "Enveloped Verifiable Credentials"</see> when
    /// the enveloped credential's context includes the base context.
    /// </summary>
    [TestMethod]
    public async Task ValidateEnvelopedCredentialContextAsyncSucceedsWhenBaseContextIsIncluded()
    {
        var enveloped = new EnvelopedVerifiableCredential
        {
            Context = Context.FromIris(Context.Credentials20),
            Id = "data:application/vc+jwt,abc",
            Type = ["EnvelopedVerifiableCredential"]
        };

        List<Claim> claims = await ContextValidationRules.ValidateEnvelopedCredentialContextAsync(enveloped, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.Success, claims[0].Outcome);
    }


    /// <summary>
    /// <see cref="ContextValidationRules.ValidateEnvelopedPresentationContextAsync"/> fails under
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-presentations">VC
    /// Data Model 2.0 §4.13 Verifiable Presentations, "Enveloped Verifiable Presentations"</see>
    /// when the enveloped presentation's context is absent.
    /// </summary>
    [TestMethod]
    public async Task ValidateEnvelopedPresentationContextAsyncFailsWhenContextIsAbsent()
    {
        var enveloped = new EnvelopedVerifiablePresentation
        {
            Id = "data:application/vp+jwt,abc",
            Type = ["EnvelopedVerifiablePresentation"]
        };

        List<Claim> claims = await ContextValidationRules.ValidateEnvelopedPresentationContextAsync(enveloped, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.Failure, claims[0].Outcome);
    }


    /// <summary>
    /// <see cref="ContextValidationRules.ValidateDidDocumentContextAsync"/> reports every claim as
    /// <see cref="ClaimOutcome.NotApplicable"/> for a DID document with no <c>@context</c> at all —
    /// <see href="https://www.w3.org/TR/did-1.0/#json-ld">DID Core 1.0 §6.3 JSON-LD</see> names
    /// <c>@context</c> a representation-specific entry of the JSON-LD representation, so a legal
    /// plain-JSON representation carries none.
    /// </summary>
    [TestMethod]
    public async Task ValidateDidDocumentContextAsyncIsNotApplicableWhenContextIsAbsent()
    {
        var document = new DidDocument { Id = new GenericDidMethod("did:example:123") };

        List<Claim> claims = await ContextValidationRules.ValidateDidDocumentContextAsync(document, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.DoesNotContain(ClaimOutcome.Success, claims.ConvertAll(static claim => claim.Outcome));
        Assert.DoesNotContain(ClaimOutcome.Failure, claims.ConvertAll(static claim => claim.Outcome));
    }


    /// <summary>
    /// <see cref="ContextValidationRules.ValidateDidDocumentContextAsync"/> succeeds for a
    /// <see href="https://www.w3.org/TR/did-1.1/#json-ld-processors">DID Core 1.1 §6.2.3 JSON-LD
    /// Processors</see> document.
    /// </summary>
    [TestMethod]
    public async Task ValidateDidDocumentContextAsyncSucceedsForDidCore11()
    {
        var document = new DidDocument
        {
            Id = new GenericDidMethod("did:example:123"),
            Context = Context.FromIris(Context.DidCore11)
        };

        List<Claim> claims = await ContextValidationRules.ValidateDidDocumentContextAsync(document, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.DoesNotContain(ClaimOutcome.Failure, claims.ConvertAll(static claim => claim.Outcome));
    }
}
