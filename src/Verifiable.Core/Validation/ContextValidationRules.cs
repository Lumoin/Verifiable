using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Assessment;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;

namespace Verifiable.Core.Validation;

/// <summary>
/// Carries the outcome detail for <see cref="ContextValidationRules.ValidateFirstEntry"/>: which
/// IRI (if any) the first <c>@context</c> entry actually carried, alongside the IRI the caller
/// required.
/// </summary>
/// <param name="FoundIri">
/// The first entry's IRI, or <see langword="null"/> when the context was absent, empty, or its
/// first entry was an inline definition rather than an IRI.
/// </param>
/// <param name="ExpectedIri">The IRI the caller required as the first entry.</param>
public sealed record ContextFirstEntryClaimContext(string? FoundIri, string ExpectedIri): ClaimContext;


/// <summary>
/// Carries the outcome detail for <see cref="ContextValidationRules.ValidateEntriesAreUrlsOrDefinitions"/>:
/// which entry, if any, is neither an inline definition nor an absolute URL.
/// </summary>
/// <param name="OffendingIndex">
/// The zero-based index of the first non-conforming entry, or <see langword="null"/> when every entry conforms.
/// </param>
/// <param name="OffendingIri">
/// The offending entry's IRI, or <see langword="null"/> when the offending entry was not an IRI at all.
/// </param>
public sealed record ContextEntriesAreUrlsOrDefinitionsClaimContext(int? OffendingIndex, string? OffendingIri): ClaimContext;


/// <summary>
/// Carries the outcome detail for <see cref="ContextValidationRules.ValidateKnownContexts"/>: which entry, if
/// any, is not on the caller's allowlist, or carries an inline definition the caller does not permit.
/// </summary>
/// <param name="OffendingIndex">
/// The zero-based index of the first disallowed entry, or <see langword="null"/> when every entry is allowed.
/// </param>
/// <param name="OffendingIri">The disallowed entry's IRI, or <see langword="null"/> when it was an inline definition.</param>
/// <param name="WasDisallowedDefinition">
/// <see langword="true"/> when the offending entry was an inline definition the caller does not permit;
/// <see langword="false"/> when it was an IRI absent from the allowlist.
/// </param>
public sealed record ContextKnownContextsClaimContext(int? OffendingIndex, string? OffendingIri, bool WasDisallowedDefinition): ClaimContext;


/// <summary>
/// Carries the outcome detail for <see cref="ContextValidationRules.ValidateNoDuplicateEntries"/>: the
/// positions of the first duplicate pair found.
/// </summary>
/// <param name="FirstIndex">The zero-based index of the earlier of the two duplicate entries.</param>
/// <param name="DuplicateIndex">The zero-based index of the later entry that duplicates <paramref name="FirstIndex"/>.</param>
public sealed record ContextDuplicateEntryClaimContext(int FirstIndex, int DuplicateIndex): ClaimContext;


/// <summary>
/// Carries the outcome detail for <see cref="ContextValidationRules.ValidateUndefinedTermsLastWhenPresent"/>:
/// where <see cref="Context.UndefinedTerms20"/> was actually found versus the context's last valid position.
/// </summary>
/// <param name="FoundAt">The zero-based index at which <see cref="Context.UndefinedTerms20"/> was found.</param>
/// <param name="LastIndex">The zero-based index of the context's last entry.</param>
public sealed record ContextUndefinedTermsPositionClaimContext(int FoundAt, int LastIndex): ClaimContext;


/// <summary>
/// Carries the outcome detail for <see cref="ContextValidationRules.ValidateNoVocabInDefinition"/>: which
/// inline definition declares the disallowed <c>@vocab</c> keyword.
/// </summary>
/// <param name="OffendingIndex">The zero-based index of the first inline definition declaring <c>@vocab</c>.</param>
public sealed record ContextVocabInDefinitionClaimContext(int OffendingIndex): ClaimContext;


/// <summary>
/// Validation rules for the JSON-LD <c>@context</c> value carried by <see cref="Context"/>,
/// applicable to DID documents, Verifiable Credentials, and Verifiable Presentations alike.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Available Rules:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see cref="ValidateContextIsPresent"/>: a context MUST be present (credentials and presentations).
/// </description></item>
/// <item><description>
/// <see cref="ValidateFormIsOrderedSet(Context?)"/>: the context's wire form MUST be an ordered set (array).
/// </description></item>
/// <item><description>
/// <see cref="ValidateFirstEntry(Context?, string)"/> and its
/// <see cref="ValidateFirstEntry(Context?, IReadOnlyList{string})"/> overload: the first entry MUST
/// be a specific, caller-supplied IRI (or one of several acceptable IRIs, for the DID Core profile).
/// </description></item>
/// <item><description>
/// <see cref="ValidateEntriesAreUrlsOrDefinitions"/>: every entry is either an inline definition or
/// an absolute URL.
/// </description></item>
/// <item><description>
/// <see cref="ValidateNoDuplicateEntries"/>: no entry repeats.
/// </description></item>
/// <item><description>
/// <see cref="ValidateUndefinedTermsLastWhenPresent"/>: when <see cref="Context.UndefinedTerms20"/>
/// is present it MUST be the last entry.
/// </description></item>
/// <item><description>
/// <see cref="ValidateEnvelopedContextPresentAndIncludesBaseContext"/>: an enveloped credential's or
/// presentation's context MUST be present, and including <see cref="Context.Credentials20"/> is
/// recognized as satisfying the base-context requirement (a different, unrecognized context is
/// Inconclusive rather than refused).
/// </description></item>
/// <item><description>
/// <see cref="ValidateKnownContexts"/> (strict-profile): every IRI entry is on the caller's
/// allowlist, and inline definitions appear only when the caller permits them.
/// </description></item>
/// <item><description>
/// <see cref="ValidateNoVocabInDefinition"/> (strict-profile): no inline definition declares a
/// non-<see langword="null"/> <c>@vocab</c>.
/// </description></item>
/// <item><description>
/// <see cref="ValidateDataIntegrityContextPresentWhenProofPresent"/> (strict-profile): a Data
/// Integrity-secured document's context includes <see cref="Context.DataIntegrity20"/> or
/// <see cref="Context.Credentials20"/>.
/// </description></item>
/// </list>
/// <para>
/// Every rule here is synchronous and returns exactly one <see cref="Claim"/> — there is no I/O
/// and no JSON-LD processing (term expansion, framing, dereferencing a context document); a
/// caller that needs those runs them separately and layers this validation on top, per
/// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">Data Integrity 1.0
/// §2.4.1 Validating Contexts</see>: "Not checking JSON-LD context values against known good
/// values can lead to security vulnerabilities, due to variance in the semantics that they
/// convey."
/// </para>
/// <para>
/// <strong>Normative vs. strict-profile pipelines:</strong> each pipeline-shaped
/// <c>Validate*ContextAsync</c> method holds only rules whose OWN cited clause is RFC 2119
/// MUST-level (<see cref="ValidateCredentialContextAsync"/>,
/// <see cref="ValidatePresentationContextAsync"/>, <see cref="ValidateDidDocumentContextAsync"/>,
/// <see cref="ValidateEnvelopedCredentialContextAsync"/>,
/// <see cref="ValidateEnvelopedPresentationContextAsync"/>) — refusing a document on one of these
/// is refusing it on a MUST the base specifications themselves impose. A sibling
/// <c>Validate*ContextStrictProfileAsync</c> method (currently
/// <see cref="ValidateCredentialContextStrictProfileAsync"/> and
/// <see cref="ValidatePresentationContextStrictProfileAsync"/>) holds the rules whose cited clause
/// is SHOULD-level, or advisory guidance naming no MUST at all — the allowlist
/// (<see cref="ValidateKnownContexts"/>), the <c>@vocab</c> prohibition
/// (<see cref="ValidateNoVocabInDefinition"/>), and the Data Integrity context-injection
/// recommendation (<see cref="ValidateDataIntegrityContextPresentWhenProofPresent"/>). A caller
/// enforcing only base-specification conformance runs the normative pipeline alone; one enforcing
/// this library's own stricter deployment profile runs both.
/// </para>
/// </remarks>
public static class ContextValidationRules
{
    /// <summary>
    /// Validates that a context's first entry is the specific IRI <paramref name="expectedIri"/>.
    /// </summary>
    /// <param name="context">The context to validate, or <see langword="null"/> when absent.</param>
    /// <param name="expectedIri">The IRI required as the first entry.</param>
    /// <returns>
    /// A <see cref="ClaimId.ContextFirstEntry"/> claim, carrying a <see cref="ContextFirstEntryClaimContext"/>
    /// naming which IRI (if any) was actually found.
    /// </returns>
    /// <remarks>
    /// <para>
    /// A <see langword="null"/> <paramref name="context"/> or one with zero <see cref="Context.Entries"/>
    /// is a <see cref="ClaimOutcome.Failure"/>, never an exception — an absent or empty
    /// <c>@context</c> is exactly the condition this rule exists to catch.
    /// </para>
    /// <para>
    /// For a Verifiable Credential or Presentation, <paramref name="expectedIri"/> is
    /// <see cref="Context.Credentials20"/> per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>: "The value of the <c>@context</c> property MUST be an ordered set where
    /// the first item is a URL with the value <c>https://www.w3.org/ns/credentials/v2</c>."
    /// </para>
    /// <para>
    /// For a DID document, <paramref name="expectedIri"/> is <see cref="Context.DidCore10"/> or
    /// <see cref="Context.DidCore11"/> per
    /// <see href="https://www.w3.org/TR/did-1.0/#x6-3-1-production">DID Core 1.0 §6.3.1 Production</see>:
    /// "The serialized value of <c>@context</c> MUST be the JSON String
    /// <c>https://www.w3.org/ns/did/v1</c>, or a JSON Array where the first item is the JSON
    /// String <c>https://www.w3.org/ns/did/v1</c> [...]", and equivalently
    /// <see href="https://www.w3.org/TR/did-1.1/#json-ld-processors">DID Core 1.1 §6.2.3 JSON-LD
    /// Processors</see> for <c>https://www.w3.org/ns/did/v1.1</c>.
    /// </para>
    /// </remarks>
    public static Claim ValidateFirstEntry(Context? context, string expectedIri)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedIri);

        if(context is null || context.Entries.Count == 0)
        {
            return new Claim(
                ClaimId.ContextFirstEntry,
                ClaimOutcome.Failure,
                new ContextFirstEntryClaimContext(FoundIri: null, expectedIri),
                Claim.NoSubClaims);
        }

        ContextEntry first = context.Entries[0];
        string? foundIri = first.IsIri ? first.Iri : null;
        bool isSuccess = first.IsIri && string.Equals(first.Iri, expectedIri, StringComparison.Ordinal);

        return new Claim(
            ClaimId.ContextFirstEntry,
            isSuccess ? ClaimOutcome.Success : ClaimOutcome.Failure,
            new ContextFirstEntryClaimContext(foundIri, expectedIri),
            Claim.NoSubClaims);
    }


    /// <summary>
    /// Validates that a context's first entry is one of <paramref name="acceptableIris"/> — the DID
    /// Core profile's shape, where a document may target DID Core 1.0 or DID Core 1.1.
    /// </summary>
    /// <param name="context">The context to validate, or <see langword="null"/> when absent.</param>
    /// <param name="acceptableIris">The IRIs any one of which is an acceptable first entry.</param>
    /// <returns>
    /// A <see cref="ClaimId.ContextFirstEntry"/> claim — the same identifier <see cref="ValidateFirstEntry(Context?, string)"/>
    /// uses, since both check the same normative position; <see cref="ContextFirstEntryClaimContext.ExpectedIri"/>
    /// carries the candidates joined with <c>" or "</c> for diagnostics.
    /// </returns>
    public static Claim ValidateFirstEntry(Context? context, IReadOnlyList<string> acceptableIris)
    {
        ArgumentNullException.ThrowIfNull(acceptableIris);

        string joinedExpectation = string.Join(" or ", acceptableIris);

        if(context is null || context.Entries.Count == 0)
        {
            return new Claim(
                ClaimId.ContextFirstEntry,
                ClaimOutcome.Failure,
                new ContextFirstEntryClaimContext(FoundIri: null, joinedExpectation),
                Claim.NoSubClaims);
        }

        ContextEntry first = context.Entries[0];
        string? foundIri = first.IsIri ? first.Iri : null;
        bool isSuccess = false;
        for(int i = 0; i < acceptableIris.Count && !isSuccess; ++i)
        {
            isSuccess = first.IsIri && string.Equals(first.Iri, acceptableIris[i], StringComparison.Ordinal);
        }

        return new Claim(
            ClaimId.ContextFirstEntry,
            isSuccess ? ClaimOutcome.Success : ClaimOutcome.Failure,
            new ContextFirstEntryClaimContext(foundIri, joinedExpectation),
            Claim.NoSubClaims);
    }


    /// <summary>
    /// Validates that every entry in a context is either an inline definition, or an absolute URL.
    /// </summary>
    /// <param name="context">The context to validate, or <see langword="null"/> when absent.</param>
    /// <returns>A <see cref="ClaimId.ContextEntriesAreUrlsOrDefinitions"/> claim.</returns>
    /// <remarks>
    /// <para>
    /// Per <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>: "Subsequent items in the ordered set MUST be composed of any combination
    /// of URLs and objects [...]". <see href="https://www.w3.org/TR/vc-data-model-2.0/#dfn-url">VC
    /// Data Model 2.0's own "URL" term</see> defines the word as "a Uniform Resource Locator, as
    /// defined by the URL Standard [...] the rules for dereferencing, or fetching, a URL are
    /// defined by the URL scheme" — the
    /// <see href="https://url.spec.whatwg.org/">WHATWG URL Standard</see> this references parses
    /// any syntactically valid scheme, not only <c>http</c>/<c>https</c>, so a <c>did:</c> or
    /// <c>urn:</c> IRI is itself a URL under this clause and this rule accepts it rather than
    /// narrowing to a subset the clause does not name. <c>JsonLdContextConverter</c> already
    /// refuses a non-string, non-object entry at parse time, so this rule's URL check runs only on
    /// entries that DID parse as strings.
    /// </para>
    /// <para>
    /// <see cref="Uri.TryCreate(string, UriKind, out Uri)"/> alone is not sufficient: on some
    /// platforms it accepts a bare path such as <c>/x</c>, or a Windows drive-letter path such as
    /// <c>C:\x</c>, as an absolute <c>file</c>-scheme URI even though the original text carries no
    /// scheme prefix at all — this rule rejects that misparse rather than restricting the set of
    /// schemes a genuine URL may carry.
    /// </para>
    /// <para>
    /// A <see langword="null"/> context is <see cref="ClaimOutcome.NotApplicable"/>: there are no
    /// entries to check, and the absence of a context is the concern of
    /// <see cref="ValidateFirstEntry"/>, not this rule.
    /// </para>
    /// </remarks>
    public static Claim ValidateEntriesAreUrlsOrDefinitions(Context? context)
    {
        if(context is null)
        {
            return new Claim(ClaimId.ContextEntriesAreUrlsOrDefinitions, ClaimOutcome.NotApplicable);
        }

        for(int i = 0; i < context.Entries.Count; ++i)
        {
            ContextEntry entry = context.Entries[i];
            if(entry.IsDefinition)
            {
                continue;
            }

            if(!entry.IsIri || !IsAbsoluteUrl(entry.Iri!))
            {
                return new Claim(
                    ClaimId.ContextEntriesAreUrlsOrDefinitions,
                    ClaimOutcome.Failure,
                    new ContextEntriesAreUrlsOrDefinitionsClaimContext(i, entry.Iri),
                    Claim.NoSubClaims);
            }
        }

        return new Claim(ClaimId.ContextEntriesAreUrlsOrDefinitions, ClaimOutcome.Success);
    }


    /// <summary>
    /// Validates that every IRI entry in a context is on <paramref name="allowlist"/>, and that
    /// an inline definition entry appears only when <paramref name="isInlineDefinitionAllowed"/>
    /// permits it.
    /// </summary>
    /// <param name="context">The context to validate, or <see langword="null"/> when absent.</param>
    /// <param name="allowlist">The IRIs this caller has explicitly approved.</param>
    /// <param name="isInlineDefinitionAllowed">
    /// Whether an inline context definition is acceptable at all; when <see langword="false"/>,
    /// any <see cref="ContextEntry.IsDefinition"/> entry fails the claim.
    /// </param>
    /// <returns>A <see cref="ClaimId.ContextKnownContexts"/> claim.</returns>
    /// <remarks>
    /// <para>
    /// This is the check-against-known-values mechanism that VC Data Model 2.0 §4.3 Contexts
    /// points to for consuming applications that do not run full JSON-LD processing —
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">Data Integrity
    /// 1.0 §2.4.1 Validating Contexts</see>: "It is necessary to ensure that a consuming
    /// application has explicitly approved of the types, and therefore the semantics, of input
    /// documents that it will process. Not checking JSON-LD context values against known good
    /// values can lead to security vulnerabilities [...]", and: "if no JSON-LD processing is to
    /// occur, then, rather than performing this check, an application could follow the guidance
    /// in whatever trusted documentation is provided out of band [...]" — this rule is that
    /// out-of-band check, driven by <paramref name="allowlist"/> instead of a JSON-LD context
    /// loader. §2.4.1 itself names this allowlist technique only one of several equivalent
    /// options — "implementers MAY use alternative approaches" and "another alternative approach
    /// [...] would be for an application to keep a list of well known context URLs" — so no
    /// individual entry on <paramref name="allowlist"/> carries its own MUST; this is a
    /// <see cref="ContextValidationRules"/> strict-profile rule (see
    /// <see cref="ValidateCredentialContextStrictProfileAsync"/>), not a normative-pipeline one.
    /// </para>
    /// <para>
    /// §2.4.1 also carries two clauses this MAY-level latitude does not reach: "Applications MUST
    /// use the algorithm in Section 4.6 Context Validation, or one that achieves equivalent
    /// protections, to validate contexts in a conforming secured document" and "Context
    /// validation MUST be run after running the applicable algorithm in either Section 4.4 Verify
    /// Proof or Section 4.5 Verify Proof Sets and Chains." This method (together with
    /// <see cref="ValidateCredentialContextStrictProfileAsync"/> and
    /// <see cref="ValidatePresentationContextStrictProfileAsync"/>, which call it) is the
    /// equivalent-protections mechanism the first MUST permits in place of §4.6 itself, but this
    /// library does not invoke it from any Data Integrity verification pipeline
    /// (<see cref="CredentialDataIntegrityExtensions"/>'s and
    /// <see cref="PresentationDataIntegrityExtensions"/>'s <c>VerifyAsync</c>, or the VCALM
    /// verifier) — the second MUST's ordering (after proof verification) is therefore left to the
    /// calling application to enforce by invoking the strict-profile method itself post-verify.
    /// This is a spec deviation, not a library conformance guarantee, and is owner-visible until
    /// one of the verification pipelines is wired to call it.
    /// </para>
    /// <para>
    /// A <see langword="null"/> context is <see cref="ClaimOutcome.NotApplicable"/>, matching
    /// <see cref="ValidateEntriesAreUrlsOrDefinitions"/>.
    /// </para>
    /// </remarks>
    public static Claim ValidateKnownContexts(Context? context, IReadOnlySet<string> allowlist, bool isInlineDefinitionAllowed)
    {
        ArgumentNullException.ThrowIfNull(allowlist);

        if(context is null)
        {
            return new Claim(ClaimId.ContextKnownContexts, ClaimOutcome.NotApplicable);
        }

        for(int i = 0; i < context.Entries.Count; ++i)
        {
            ContextEntry entry = context.Entries[i];
            if(entry.IsDefinition)
            {
                if(!isInlineDefinitionAllowed)
                {
                    return new Claim(
                        ClaimId.ContextKnownContexts,
                        ClaimOutcome.Failure,
                        new ContextKnownContextsClaimContext(i, OffendingIri: null, WasDisallowedDefinition: true),
                        Claim.NoSubClaims);
                }

                continue;
            }

            if(!entry.IsIri || !allowlist.Contains(entry.Iri!))
            {
                return new Claim(
                    ClaimId.ContextKnownContexts,
                    ClaimOutcome.Failure,
                    new ContextKnownContextsClaimContext(i, entry.Iri, WasDisallowedDefinition: false),
                    Claim.NoSubClaims);
            }
        }

        return new Claim(ClaimId.ContextKnownContexts, ClaimOutcome.Success);
    }


    /// <summary>
    /// Validates that a context carries no duplicate entries.
    /// </summary>
    /// <param name="context">The context to validate, or <see langword="null"/> when absent.</param>
    /// <returns>A <see cref="ClaimId.ContextNoDuplicateEntries"/> claim.</returns>
    /// <remarks>
    /// <para>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see> requires the <c>@context</c> value to be an
    /// <see href="https://infra.spec.whatwg.org/#ordered-set">ordered set</see>: "An ordered set is
    /// a list with the additional semantic that it must not contain the same item twice." Two
    /// entries are duplicates under the same rule <see cref="ContextEntry.Equals(ContextEntry)"/>
    /// uses: IRIs compared ordinally, inline definitions compared structurally regardless of
    /// property order.
    /// </para>
    /// <para>
    /// A <see langword="null"/> context is <see cref="ClaimOutcome.NotApplicable"/>, matching
    /// <see cref="ValidateEntriesAreUrlsOrDefinitions"/>.
    /// </para>
    /// </remarks>
    public static Claim ValidateNoDuplicateEntries(Context? context)
    {
        if(context is null)
        {
            return new Claim(ClaimId.ContextNoDuplicateEntries, ClaimOutcome.NotApplicable);
        }

        for(int i = 0; i < context.Entries.Count; ++i)
        {
            for(int j = i + 1; j < context.Entries.Count; ++j)
            {
                if(context.Entries[i].Equals(context.Entries[j]))
                {
                    return new Claim(
                        ClaimId.ContextNoDuplicateEntries,
                        ClaimOutcome.Failure,
                        new ContextDuplicateEntryClaimContext(i, j),
                        Claim.NoSubClaims);
                }
            }
        }

        return new Claim(ClaimId.ContextNoDuplicateEntries, ClaimOutcome.Success);
    }


    /// <summary>
    /// Validates that a context is present at all.
    /// </summary>
    /// <param name="context">The context to validate, or <see langword="null"/> when absent.</param>
    /// <returns>A <see cref="ClaimId.ContextPresent"/> claim.</returns>
    /// <remarks>
    /// Per <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>: "Verifiable credentials and verifiable presentations MUST include a
    /// <c>@context</c> property." Unlike <see cref="ValidateEntriesAreUrlsOrDefinitions"/> and its
    /// siblings, absence here is <see cref="ClaimOutcome.Failure"/>, not <see cref="ClaimOutcome.NotApplicable"/>
    /// — presence is exactly what a credential or presentation profile requires, whereas a DID
    /// document's <c>@context</c> is genuinely optional (a plain-JSON, non-LD representation), so
    /// <see cref="ValidateDidDocumentContextAsync"/> never calls this rule. A present-but-empty
    /// context (<see cref="Context.Entries"/> holding zero entries) is still a present
    /// <c>@context</c> member for this rule and is therefore <see cref="ClaimOutcome.Success"/>;
    /// its emptiness — the ordered set having no members — is <see cref="ValidateFirstEntry(Context?, string)"/>'s
    /// concern, not this one's.
    /// </remarks>
    public static Claim ValidateContextIsPresent(Context? context)
    {
        return new Claim(ClaimId.ContextPresent, context is null ? ClaimOutcome.Failure : ClaimOutcome.Success);
    }


    /// <summary>
    /// Validates that a context's wire <see cref="ContextForm"/> is <see cref="ContextForm.Array"/>.
    /// </summary>
    /// <param name="context">The context to validate, or <see langword="null"/> when absent.</param>
    /// <returns>A <see cref="ClaimId.ContextFormIsOrderedSet"/> claim.</returns>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>: "The value of the <c>@context</c> property MUST be an
    /// <see href="https://infra.spec.whatwg.org/#ordered-set">ordered set</see>" — a JSON array,
    /// never a bare scalar, for a credential or presentation. A <see langword="null"/> context is
    /// <see cref="ClaimOutcome.NotApplicable"/>: <see cref="ValidateContextIsPresent"/> is what
    /// reports absence.
    /// </remarks>
    public static Claim ValidateFormIsOrderedSet(Context? context)
    {
        if(context is null)
        {
            return new Claim(ClaimId.ContextFormIsOrderedSet, ClaimOutcome.NotApplicable);
        }

        return new Claim(ClaimId.ContextFormIsOrderedSet, context.Form == ContextForm.Array ? ClaimOutcome.Success : ClaimOutcome.Failure);
    }


    /// <summary>
    /// Validates that <see cref="Context.UndefinedTerms20"/>, when present, is the LAST entry.
    /// </summary>
    /// <param name="context">The context to validate, or <see langword="null"/> when absent.</param>
    /// <returns>A <see cref="ClaimId.ContextUndefinedTermsLast"/> claim.</returns>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#extensibility">VC Data Model 2.0 §5.2
    /// Extensibility</see>: "it MUST include the <c>https://www.w3.org/ns/credentials/undefined-terms/v2</c>
    /// as the last value in the <c>@context</c> property." <see cref="ClaimOutcome.NotApplicable"/>
    /// when the context is absent, or present without that entry — the entry is optional; only its
    /// position, once it appears, is this rule's concern.
    /// </remarks>
    public static Claim ValidateUndefinedTermsLastWhenPresent(Context? context)
    {
        if(context is null)
        {
            return new Claim(ClaimId.ContextUndefinedTermsLast, ClaimOutcome.NotApplicable);
        }

        int foundAt = -1;
        for(int i = 0; i < context.Entries.Count; ++i)
        {
            if(context.Entries[i].IsIri && string.Equals(context.Entries[i].Iri, Context.UndefinedTerms20, StringComparison.Ordinal))
            {
                foundAt = i;
                break;
            }
        }

        if(foundAt == -1)
        {
            return new Claim(ClaimId.ContextUndefinedTermsLast, ClaimOutcome.NotApplicable);
        }

        int lastIndex = context.Entries.Count - 1;
        if(foundAt == lastIndex)
        {
            return new Claim(ClaimId.ContextUndefinedTermsLast, ClaimOutcome.Success);
        }

        return new Claim(
            ClaimId.ContextUndefinedTermsLast,
            ClaimOutcome.Failure,
            new ContextUndefinedTermsPositionClaimContext(foundAt, lastIndex),
            Claim.NoSubClaims);
    }


    /// <summary>
    /// Validates that no inline <c>@context</c> definition declares the <c>@vocab</c> keyword with a
    /// non-<see langword="null"/> value.
    /// </summary>
    /// <param name="context">The context to validate, or <see langword="null"/> when absent.</param>
    /// <returns>A <see cref="ClaimId.ContextNoVocabInDefinition"/> claim.</returns>
    /// <remarks>
    /// <para>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#extensibility">VC Data Model 2.0 §5.2
    /// Extensibility</see>: "A conforming document SHOULD NOT use the <c>@vocab</c> feature in
    /// production as it can lead to JSON term clashes, resulting in semantic ambiguities with other
    /// applications." That is a SHOULD NOT, so this is a
    /// <see cref="ContextValidationRules"/> strict-profile rule (see
    /// <see cref="ValidateCredentialContextStrictProfileAsync"/>) rather than a normative-pipeline
    /// one, enforced as a hard gate (<see cref="ClaimOutcome.Failure"/>, not
    /// <see cref="ClaimOutcome.Inconclusive"/>) since <c>@vocab</c> inside a credential's own inline
    /// definition is exactly the term-clash risk the clause warns about.
    /// </para>
    /// <para>
    /// A <c>@vocab</c> entry mapped to <see langword="null"/> is not that risk: per
    /// <see href="https://www.w3.org/TR/json-ld11-api/#context-processing-algorithm">JSON-LD 1.1
    /// Processing Algorithms and API §4.1 Context Processing Algorithm</see>, "If value is
    /// <see langword="null"/>, remove any vocabulary mapping from result" — a null-valued
    /// <c>@vocab</c> is JSON-LD 1.1's own mechanism for CLEARING a previously declared vocabulary
    /// mapping, the safe direction this rule exists to permit, so only a non-null value fails the
    /// claim. A <see langword="null"/> <paramref name="context"/> is
    /// <see cref="ClaimOutcome.NotApplicable"/>.
    /// </para>
    /// </remarks>
    public static Claim ValidateNoVocabInDefinition(Context? context)
    {
        if(context is null)
        {
            return new Claim(ClaimId.ContextNoVocabInDefinition, ClaimOutcome.NotApplicable);
        }

        for(int i = 0; i < context.Entries.Count; ++i)
        {
            ContextEntry entry = context.Entries[i];
            if(entry.IsDefinition
                && entry.Definition!.TryGetValue("@vocab", out object? vocabValue)
                && vocabValue is not null)
            {
                return new Claim(
                    ClaimId.ContextNoVocabInDefinition,
                    ClaimOutcome.Failure,
                    new ContextVocabInDefinitionClaimContext(i),
                    Claim.NoSubClaims);
            }
        }

        return new Claim(ClaimId.ContextNoVocabInDefinition, ClaimOutcome.Success);
    }


    /// <summary>
    /// Validates that, when the document carries a Data Integrity proof, the context includes
    /// either <see cref="Context.DataIntegrity20"/> or a context the specification treats as already
    /// covering it.
    /// </summary>
    /// <param name="context">The context to validate, or <see langword="null"/> when absent.</param>
    /// <param name="hasDataIntegrityProof">Whether the document carries a Data Integrity proof.</param>
    /// <returns>A <see cref="ClaimId.ContextDataIntegrityPresentWhenProofPresent"/> claim.</returns>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#context-injection">VC Data Integrity 1.0
    /// §2.4.2 Context Injection</see>: "When an application is securing a document, if an
    /// <c>@context</c> property is not provided in the document or the Data Integrity terms used in
    /// the document are not mapped by existing values in the <c>@context</c> property,
    /// implementations SHOULD inject or append an <c>@context</c> property with a value of
    /// <c>https://w3id.org/security/data-integrity/v2</c> or one or more contexts with at least the
    /// same declarations, such as the Verifiable Credential Data Model v2.0 context
    /// (<c>https://www.w3.org/ns/credentials/v2</c>)." That is a SHOULD, so this is a
    /// <see cref="ContextValidationRules"/> strict-profile rule (see
    /// <see cref="ValidateCredentialContextStrictProfileAsync"/>), not a normative-pipeline one.
    /// <see cref="Context.Credentials20"/> therefore satisfies this claim on its own — it is what
    /// every VC-DM 2.0 credential already carries as its first entry — and
    /// <see cref="ClaimOutcome.NotApplicable"/> when there is no Data Integrity proof to begin with.
    /// </remarks>
    public static Claim ValidateDataIntegrityContextPresentWhenProofPresent(Context? context, bool hasDataIntegrityProof)
    {
        if(!hasDataIntegrityProof)
        {
            return new Claim(ClaimId.ContextDataIntegrityPresentWhenProofPresent, ClaimOutcome.NotApplicable);
        }

        if(context is null)
        {
            return new Claim(ClaimId.ContextDataIntegrityPresentWhenProofPresent, ClaimOutcome.Failure);
        }

        for(int i = 0; i < context.Entries.Count; ++i)
        {
            ContextEntry entry = context.Entries[i];
            if(entry.IsIri
                && (string.Equals(entry.Iri, Context.DataIntegrity20, StringComparison.Ordinal)
                    || string.Equals(entry.Iri, Context.Credentials20, StringComparison.Ordinal)))
            {
                return new Claim(ClaimId.ContextDataIntegrityPresentWhenProofPresent, ClaimOutcome.Success);
            }
        }

        return new Claim(ClaimId.ContextDataIntegrityPresentWhenProofPresent, ClaimOutcome.Failure);
    }


    /// <summary>
    /// Validates that an enveloped credential's or presentation's <c>@context</c> is present and
    /// includes <see cref="Context.Credentials20"/>.
    /// </summary>
    /// <param name="context">The context to validate, or <see langword="null"/> when absent.</param>
    /// <returns>A <see cref="ClaimId.ContextEnvelopedPresentAndIncludesBaseContext"/> claim.</returns>
    /// <remarks>
    /// <para>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-credentials">VC Data
    /// Model 2.0 §4.13 Verifiable Presentations, "Enveloped Verifiable Credentials"</see> (the
    /// sibling "Enveloped Verifiable Presentations" subsection states the identical requirement for
    /// the presentation form): "The <c>@context</c> property of the object MUST be present and
    /// include a context, such as the base context for this specification, that defines at least
    /// the <c>id</c>, <c>type</c>, and <c>EnvelopedVerifiableCredential</c> terms as defined by the
    /// base context provided by this specification." Never <see cref="ClaimOutcome.NotApplicable"/>:
    /// presence is mandatory for both enveloped types, so an absent or empty context is
    /// <see cref="ClaimOutcome.Failure"/> regardless of which context is later checked for.
    /// </para>
    /// <para>
    /// The clause's "such as" only names <see cref="Context.Credentials20"/> as one acceptable way
    /// to define the required terms; any context defining <c>id</c>, <c>type</c>, and
    /// <c>EnvelopedVerifiableCredential</c> conforms. This method has no JSON-LD term-expansion
    /// machinery to check an arbitrary context's term definitions, so it only recognizes the named
    /// base context by IRI: a present context that includes <see cref="Context.Credentials20"/> is
    /// <see cref="ClaimOutcome.Success"/>, and a present, non-empty context that does not is
    /// <see cref="ClaimOutcome.Inconclusive"/> rather than <see cref="ClaimOutcome.Failure"/> — the
    /// document may still be conformant through a different context this check cannot evaluate, so
    /// it is not refused on a MUST the base specification does not in fact impose on that document.
    /// </para>
    /// </remarks>
    public static Claim ValidateEnvelopedContextPresentAndIncludesBaseContext(Context? context)
    {
        if(context is null || context.Entries.Count == 0)
        {
            return new Claim(ClaimId.ContextEnvelopedPresentAndIncludesBaseContext, ClaimOutcome.Failure);
        }

        for(int i = 0; i < context.Entries.Count; ++i)
        {
            if(context.Entries[i].IsIri && string.Equals(context.Entries[i].Iri, Context.Credentials20, StringComparison.Ordinal))
            {
                return new Claim(ClaimId.ContextEnvelopedPresentAndIncludesBaseContext, ClaimOutcome.Success);
            }
        }

        return new Claim(ClaimId.ContextEnvelopedPresentAndIncludesBaseContext, ClaimOutcome.Inconclusive);
    }


    /// <summary>
    /// The NORMATIVE pipeline-shaped Credentials20 profile: every MUST-level claim
    /// <see cref="ValidateCredentialContextAsync"/> issues for a Verifiable Credential's
    /// <c>@context</c>. A gate that refuses a credential failing any claim here is refusing it on a
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0</see> MUST,
    /// never on this library's own added preference.
    /// </summary>
    /// <param name="credential">The credential to validate.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>
    /// The claims from <see cref="ValidateContextIsPresent"/>, <see cref="ValidateFormIsOrderedSet"/>,
    /// <see cref="ValidateFirstEntry(Context?, string)"/> against <see cref="Context.Credentials20"/>,
    /// <see cref="ValidateEntriesAreUrlsOrDefinitions"/>, <see cref="ValidateNoDuplicateEntries"/>,
    /// and <see cref="ValidateUndefinedTermsLastWhenPresent"/>, in that order — every rule here cites
    /// a MUST-level clause. <see cref="ValidateCredentialContextStrictProfileAsync"/> is the sibling
    /// pipeline for this credential's SHOULD-level claims.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="credential"/> is <see langword="null"/>.</exception>
    public static ValueTask<List<Claim>> ValidateCredentialContextAsync(
        VerifiableCredential credential,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        cancellationToken.ThrowIfCancellationRequested();

        Context? context = credential.Context;

        List<Claim> claims =
        [
            ValidateContextIsPresent(context),
            ValidateFormIsOrderedSet(context),
            ValidateFirstEntry(context, Context.Credentials20),
            ValidateEntriesAreUrlsOrDefinitions(context),
            ValidateNoDuplicateEntries(context),
            ValidateUndefinedTermsLastWhenPresent(context)
        ];

        return ValueTask.FromResult(claims);
    }


    /// <summary>
    /// The STRICT-PROFILE pipeline-shaped Credentials20 profile: every SHOULD-level (or advisory,
    /// MUST-free) claim this library additionally enforces for a Verifiable Credential's
    /// <c>@context</c>, beyond what <see cref="ValidateCredentialContextAsync"/>'s base-specification
    /// MUSTs require.
    /// </summary>
    /// <param name="credential">The credential to validate.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>
    /// The claims from <see cref="ValidateKnownContexts"/> against
    /// <see cref="WellKnownContextAllowlists.Credentials20"/>, <see cref="ValidateNoVocabInDefinition"/>,
    /// and <see cref="ValidateDataIntegrityContextPresentWhenProofPresent"/>, in that order.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="credential"/> is <see langword="null"/>.</exception>
    public static ValueTask<List<Claim>> ValidateCredentialContextStrictProfileAsync(
        VerifiableCredential credential,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        cancellationToken.ThrowIfCancellationRequested();

        Context? context = credential.Context;
        bool hasDataIntegrityProof = credential is DataIntegritySecuredCredential { Proof.Count: > 0 };

        List<Claim> claims =
        [
            ValidateKnownContexts(context, WellKnownContextAllowlists.Credentials20, isInlineDefinitionAllowed: true),
            ValidateNoVocabInDefinition(context),
            ValidateDataIntegrityContextPresentWhenProofPresent(context, hasDataIntegrityProof)
        ];

        return ValueTask.FromResult(claims);
    }


    /// <summary>
    /// The NORMATIVE pipeline-shaped Credentials20 profile for a Verifiable Presentation's
    /// <c>@context</c>, mirroring <see cref="ValidateCredentialContextAsync"/>.
    /// </summary>
    /// <param name="presentation">The presentation to validate.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The same claim sequence as <see cref="ValidateCredentialContextAsync"/>, over the presentation's context.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="presentation"/> is <see langword="null"/>.</exception>
    public static ValueTask<List<Claim>> ValidatePresentationContextAsync(
        VerifiablePresentation presentation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        cancellationToken.ThrowIfCancellationRequested();

        Context? context = presentation.Context;

        List<Claim> claims =
        [
            ValidateContextIsPresent(context),
            ValidateFormIsOrderedSet(context),
            ValidateFirstEntry(context, Context.Credentials20),
            ValidateEntriesAreUrlsOrDefinitions(context),
            ValidateNoDuplicateEntries(context),
            ValidateUndefinedTermsLastWhenPresent(context)
        ];

        return ValueTask.FromResult(claims);
    }


    /// <summary>
    /// The STRICT-PROFILE pipeline-shaped Credentials20 profile for a Verifiable Presentation's
    /// <c>@context</c>, mirroring <see cref="ValidateCredentialContextStrictProfileAsync"/>.
    /// </summary>
    /// <param name="presentation">The presentation to validate.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The same claim sequence as <see cref="ValidateCredentialContextStrictProfileAsync"/>, over the presentation's context.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="presentation"/> is <see langword="null"/>.</exception>
    public static ValueTask<List<Claim>> ValidatePresentationContextStrictProfileAsync(
        VerifiablePresentation presentation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        cancellationToken.ThrowIfCancellationRequested();

        Context? context = presentation.Context;
        bool hasDataIntegrityProof = presentation is DataIntegritySecuredPresentation { Proof.Count: > 0 };

        List<Claim> claims =
        [
            ValidateKnownContexts(context, WellKnownContextAllowlists.Credentials20, isInlineDefinitionAllowed: true),
            ValidateNoVocabInDefinition(context),
            ValidateDataIntegrityContextPresentWhenProofPresent(context, hasDataIntegrityProof)
        ];

        return ValueTask.FromResult(claims);
    }


    /// <summary>
    /// The pipeline-shaped profile for an <see cref="EnvelopedVerifiableCredential"/>'s <c>@context</c>.
    /// </summary>
    /// <param name="enveloped">The enveloped credential to validate.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The claim from <see cref="ValidateEnvelopedContextPresentAndIncludesBaseContext"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="enveloped"/> is <see langword="null"/>.</exception>
    public static ValueTask<List<Claim>> ValidateEnvelopedCredentialContextAsync(
        EnvelopedVerifiableCredential enveloped,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(enveloped);
        cancellationToken.ThrowIfCancellationRequested();

        List<Claim> claims = [ValidateEnvelopedContextPresentAndIncludesBaseContext(enveloped.Context)];

        return ValueTask.FromResult(claims);
    }


    /// <summary>
    /// The pipeline-shaped profile for an <see cref="EnvelopedVerifiablePresentation"/>'s <c>@context</c>,
    /// mirroring <see cref="ValidateEnvelopedCredentialContextAsync"/>.
    /// </summary>
    /// <param name="enveloped">The enveloped presentation to validate.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The claim from <see cref="ValidateEnvelopedContextPresentAndIncludesBaseContext"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="enveloped"/> is <see langword="null"/>.</exception>
    public static ValueTask<List<Claim>> ValidateEnvelopedPresentationContextAsync(
        EnvelopedVerifiablePresentation enveloped,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(enveloped);
        cancellationToken.ThrowIfCancellationRequested();

        List<Claim> claims = [ValidateEnvelopedContextPresentAndIncludesBaseContext(enveloped.Context)];

        return ValueTask.FromResult(claims);
    }


    /// <summary>
    /// The pipeline-shaped DidCore profile: every claim <see cref="ValidateDidDocumentContextAsync"/>
    /// issues for a <see cref="DidDocument"/>'s <c>@context</c>.
    /// </summary>
    /// <param name="document">The DID document to validate.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>
    /// <see cref="ClaimOutcome.NotApplicable"/> claims when <paramref name="document"/> carries no
    /// <c>@context</c> at all — a plain-JSON, non-LD DID document representation is legal per DID
    /// Core, unlike an absent <c>@context</c> on a credential or presentation. Otherwise the claims
    /// from <see cref="ValidateFirstEntry(Context?, IReadOnlyList{string})"/> against
    /// <see cref="Context.DidCore10"/>/<see cref="Context.DidCore11"/>,
    /// <see cref="ValidateEntriesAreUrlsOrDefinitions"/>, and <see cref="ValidateNoDuplicateEntries"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="document"/> is <see langword="null"/>.</exception>
    public static ValueTask<List<Claim>> ValidateDidDocumentContextAsync(
        DidDocument document,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);
        cancellationToken.ThrowIfCancellationRequested();

        Context? context = document.Context;
        if(context is null)
        {
            List<Claim> notApplicableClaims =
            [
                new Claim(ClaimId.ContextFirstEntry, ClaimOutcome.NotApplicable),
                new Claim(ClaimId.ContextEntriesAreUrlsOrDefinitions, ClaimOutcome.NotApplicable),
                new Claim(ClaimId.ContextNoDuplicateEntries, ClaimOutcome.NotApplicable)
            ];

            return ValueTask.FromResult(notApplicableClaims);
        }

        List<Claim> claims =
        [
            ValidateFirstEntry(context, (IReadOnlyList<string>)[Context.DidCore10, Context.DidCore11]),
            ValidateEntriesAreUrlsOrDefinitions(context),
            ValidateNoDuplicateEntries(context)
        ];

        return ValueTask.FromResult(claims);
    }


    /// <summary>
    /// Reports whether <paramref name="iri"/> is an absolute URL under the
    /// <see href="https://url.spec.whatwg.org/">WHATWG URL Standard</see>: any scheme is accepted,
    /// since that standard's parser is scheme-agnostic and <see href="https://www.w3.org/TR/vc-data-model-2.0/#dfn-url">VC
    /// Data Model 2.0's own "URL" term</see> defers to it rather than naming a closed scheme list.
    /// <see cref="Uri.TryCreate(string?, UriKind, out Uri?)"/> alone is not sufficient: on some
    /// platforms it accepts a bare path (such as <c>/x</c>) or a Windows drive-letter path (such as
    /// <c>C:\x</c>) as an absolute <c>file</c>-scheme URI even though neither carries an explicit
    /// scheme prefix in the original text, so the parsed scheme is also checked against the text
    /// that produced it.
    /// </summary>
    /// <param name="iri">The candidate IRI string.</param>
    /// <returns>
    /// <see langword="true"/> if <paramref name="iri"/> parses as an absolute URI and its own text
    /// begins with that URI's scheme followed by <c>:</c>; otherwise <see langword="false"/>.
    /// </returns>
    private static bool IsAbsoluteUrl(string iri)
    {
        if(!Uri.TryCreate(iri, UriKind.Absolute, out Uri? parsed))
        {
            return false;
        }

        return iri.StartsWith(parsed.Scheme + ":", StringComparison.OrdinalIgnoreCase);
    }
}


/// <summary>
/// Well-known sets of <c>@context</c> IRIs a caller has explicitly approved, for use with
/// <see cref="ContextValidationRules.ValidateKnownContexts"/>.
/// </summary>
/// <remarks>
/// These sets name IRIs this library itself understands and issues or accepts elsewhere in its
/// own model and converters; they are a starting point for a consumer's own allowlist, not a
/// closed registry of every context a conforming document may use.
/// </remarks>
public static class WellKnownContextAllowlists
{
    /// <summary>
    /// The IRIs a Verifiable Credential or Verifiable Presentation built by this library may
    /// carry: <see cref="Context.Credentials20"/>, <see cref="Context.CredentialsExamples20"/>,
    /// <see cref="Context.UndefinedTerms20"/>, <see cref="Context.DataIntegrity20"/>,
    /// <see cref="Context.Multikey10"/>, and <see cref="Context.Cid10"/>.
    /// </summary>
    public static FrozenSet<string> Credentials20 { get; } = new[]
    {
        Context.Credentials20,
        Context.CredentialsExamples20,
        Context.UndefinedTerms20,
        Context.DataIntegrity20,
        Context.Multikey10,
        Context.Cid10
    }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>
    /// The IRIs a DID document built or resolved by this library may carry:
    /// <see cref="Context.DidCore10"/>, <see cref="Context.DidCore11"/>,
    /// <see cref="Context.Multikey10"/>, and <see cref="Context.Cid10"/>.
    /// </summary>
    public static FrozenSet<string> DidCore { get; } = new[]
    {
        Context.DidCore10,
        Context.DidCore11,
        Context.Multikey10,
        Context.Cid10
    }.ToFrozenSet(StringComparer.Ordinal);
}
