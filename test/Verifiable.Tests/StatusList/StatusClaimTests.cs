using System;
using System.Collections.Generic;
using Verifiable.Core.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="StatusClaim"/>, the one carrier of a Referenced Token's status statement —
/// the JOSE <c>status</c> claim object of Token Status List Section 6.1/6.2 and the COSE Status CBOR
/// structure of Section 6.3 alike. Every invariant asserted here is stated by those sections; no
/// input is produced by a reader or a writer, so the type is measured against the specification text
/// rather than against a sibling encoder.
/// </summary>
/// <remarks>
/// The mechanism set is what makes the claim a three-way answer: no claim at all, a claim naming only
/// mechanisms this library cannot evaluate, or a claim carrying a resolvable
/// <see cref="StatusListReference"/>. The wire-format readers that build the claim are proved by
/// <see cref="StatusClaimReaderTests"/> (JOSE) and <see cref="StatusClaimCborReaderTests"/> (COSE).
/// </remarks>
[TestClass]
internal sealed class StatusClaimTests
{
    /// <summary>
    /// The index the fixtures reference in the Status List.
    /// </summary>
    private int SuspendedCredentialIndex { get; } = StatusListTestConstants.SuspendedCredentialIndex;

    /// <summary>
    /// The Status List Token URI the fixtures reference, taken from the Section 6.2 example.
    /// </summary>
    private string ExampleTokenSubject { get; } = StatusListTestConstants.ExampleTokenSubject;

    /// <summary>
    /// Gets or sets the context information for the current test run.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// "status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least
    /// one reference to a status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status List, Section 6.1</see>,
    /// and for the COSE encoding of the same structure "The Status CBOR structure is a Map that MUST
    /// include at least one data item that refers to a status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token Status List, Section 6.3</see>.
    /// A claim naming nothing states nothing, so it cannot be constructed in either encoding.
    /// </summary>
    [TestMethod]
    public void AStatusClaimNamingNoMechanismIsRefused()
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => new StatusClaim(statusList: null, mechanisms: new HashSet<string>(StringComparer.Ordinal)));

        Assert.Contains("at least one", exception.Message, "The refusal must name Section 6.1/6.3's at-least-one-mechanism requirement.");
    }


    /// <summary>
    /// "status_list: REQUIRED when the status mechanism defined in this specification is used. It MUST
    /// specify a JSON Object that contains a reference to a Status List Token."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status List, Section 6.2</see>.
    /// The mechanism name and the reference it introduces are one member: a reference that no member
    /// name introduces is not something an issuer can have stated, so it is refused rather than
    /// silently renamed.
    /// </summary>
    [TestMethod]
    public void AStatusListReferenceWithoutTheStatusListMechanismNameIsRefused()
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => new StatusClaim(
                statusList: new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject),
                mechanisms: new HashSet<string>(StringComparer.Ordinal) { StatusMechanismNames.IdentifierList }));

        Assert.Contains(StatusMechanismNames.StatusList, exception.Message, "The refusal must name the mechanism the reference belongs to.");
    }


    /// <summary>
    /// "status_list: REQUIRED when the status mechanism defined in this specification is used. It MUST
    /// specify a JSON Object that contains a reference to a Status List Token."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status List, Section 6.2</see>.
    /// The converse of the same sentence: naming the mechanism obliges the claim to carry its
    /// reference, so the name without a reference is refused too — otherwise a verifier holding the
    /// claim would read "status_list is used" and have nothing to resolve.
    /// </summary>
    [TestMethod]
    public void TheStatusListMechanismNamedWithoutItsReferenceIsRefused()
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => new StatusClaim(
                statusList: null,
                mechanisms: new HashSet<string>(StringComparer.Ordinal) { StatusMechanismNames.StatusList }));

        Assert.Contains(StatusMechanismNames.StatusList, exception.Message, "The refusal must name the mechanism whose reference is missing.");
    }


    /// <summary>
    /// "status_list: REQUIRED when the status mechanism defined in this specification is used."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status List, Section 6.2</see>.
    /// An issuer that publishes only the Token Status List mechanism states exactly that one
    /// mechanism, so the claim its factory builds names <c>status_list</c> and nothing else.
    /// </summary>
    [TestMethod]
    public void FromStatusListNamesTheStatusListMechanismAlone()
    {
        var claim = StatusClaim.FromStatusList(SuspendedCredentialIndex, ExampleTokenSubject);

        Assert.IsTrue(claim.HasStatusList, "A claim carrying the status_list mechanism carries a reference a verifier can resolve.");
        Assert.AreEqual(SuspendedCredentialIndex, claim.StatusList!.Value.Index, "idx is the index the issuer stated.");
        Assert.AreEqual(ExampleTokenSubject, claim.StatusList.Value.Uri, "uri identifies the Status List Token the issuer stated.");
        Assert.HasCount(1, claim.Mechanisms, "Exactly one status mechanism is named.");
        Assert.Contains(StatusMechanismNames.StatusList, claim.Mechanisms, "The named mechanism is status_list.");
    }


    /// <summary>
    /// "status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least
    /// one reference to a status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status List, Section 6.1</see>.
    /// The Token Status List mechanism is one mechanism among others: a claim naming only a mechanism
    /// this library does not evaluate is a well-formed statement carrying no resolvable reference. It
    /// is a different answer from a token that carries no <c>status</c> claim at all, and collapsing
    /// the two would make a credential whose issuer gated its validity on that mechanism look
    /// unconditioned.
    /// </summary>
    [TestMethod]
    public void AClaimNamingOnlyAnUnevaluableMechanismCarriesNoReference()
    {
        var claim = new StatusClaim(
            statusList: null,
            mechanisms: new HashSet<string>(StringComparer.Ordinal) { StatusMechanismNames.IdentifierList });

        Assert.IsFalse(claim.HasStatusList, "No status_list mechanism is named, so there is no reference a verifier can resolve.");
        Assert.IsNull(claim.StatusList, "The absent mechanism leaves the reference null rather than a default value.");
        Assert.HasCount(1, claim.Mechanisms, "The one mechanism the issuer named is recorded.");
        Assert.Contains(StatusMechanismNames.IdentifierList, claim.Mechanisms, "The mechanism must reach the caller by name so it can state what it cannot evaluate.");
    }


    /// <summary>
    /// "The Status CBOR structure is a Map that MUST include at least one data item that refers to a
    /// status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token Status List, Section 6.3</see>.
    /// A map and a JSON object are unordered, so two claims decoded from wire content that names the
    /// same mechanisms are the same claim whatever order the decoder happened to enumerate them in,
    /// and hash alike so either can key a lookup the other filled.
    /// </summary>
    [TestMethod]
    public void TwoClaimsNamingTheSameMechanismsAreEqualAndHashEqualWhateverOrderTheyWereBuiltIn()
    {
        var first = new StatusClaim(
            new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject),
            new HashSet<string>(StringComparer.Ordinal) { StatusMechanismNames.StatusList, StatusMechanismNames.IdentifierList });
        var second = new StatusClaim(
            new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject),
            new HashSet<string>(StringComparer.Ordinal) { StatusMechanismNames.IdentifierList, StatusMechanismNames.StatusList });

        Assert.AreEqual(first, second, "Mechanism names form an unordered set, so enumeration order must not change equality.");
        Assert.AreEqual(first.GetHashCode(), second.GetHashCode(), "Equal claims must hash equal.");
    }


    /// <summary>
    /// "status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least
    /// one reference to a status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status List, Section 6.1</see>.
    /// The constructor validates that requirement once, so it copies the caller's collection: a caller
    /// still holding the source set cannot afterwards empty it, or add a mechanism the issuer never
    /// stated, and leave a claim that no longer satisfies what was checked.
    /// </summary>
    [TestMethod]
    public void MutatingTheSuppliedMechanismSetAfterConstructionDoesNotChangeTheClaim()
    {
        var supplied = new HashSet<string>(StringComparer.Ordinal) { StatusMechanismNames.StatusList };
        var claim = new StatusClaim(new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject), supplied);

        supplied.Add(StatusMechanismNames.IdentifierList);
        supplied.Remove(StatusMechanismNames.StatusList);

        Assert.HasCount(1, claim.Mechanisms, "The claim's own set is unaffected by mutating the caller's source collection.");
        Assert.Contains(StatusMechanismNames.StatusList, claim.Mechanisms, "The mechanism present at construction time must survive.");
        Assert.DoesNotContain(StatusMechanismNames.IdentifierList, claim.Mechanisms, "A mechanism added to the source afterwards must never appear on the claim.");
    }


    /// <summary>
    /// "the key MUST be a CBOR text string (major type 3) specifying the identifier of the status
    /// mechanism and the corresponding value defines its contents."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token Status List, Section 6.3</see>.
    /// The identifier is the exact text the issuer wrote: a differently cased spelling identifies a
    /// different mechanism. The claim therefore normalizes whatever comparer the caller's collection
    /// carried down to an ordinal one, so a case-insensitive source set cannot make one producer's
    /// claim answer a membership question differently from another's.
    /// </summary>
    [TestMethod]
    public void TheMechanismSetComparesOrdinallyWhateverComparerTheCallerSupplied()
    {
        const string UppercaseIdentifierList = "IDENTIFIER_LIST";

        var supplied = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { UppercaseIdentifierList };
        var claim = new StatusClaim(statusList: null, mechanisms: supplied);

        Assert.Contains(StatusMechanismNames.IdentifierList, supplied, "The caller's own set matches case-insensitively, which is what makes the normalization observable.");
        Assert.DoesNotContain(StatusMechanismNames.IdentifierList, claim.Mechanisms, "Mechanism identifiers are compared ordinally, so a differently cased spelling is a different mechanism.");
        Assert.Contains(UppercaseIdentifierList, claim.Mechanisms, "The identifier is carried through exactly as the issuer spelled it.");
    }


    /// <summary>
    /// "status_list: REQUIRED when the status mechanism defined in this specification is used. It MUST
    /// specify a JSON Object that contains a reference to a Status List Token."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status List, Section 6.2</see>.
    /// The coherence between the reference and the mechanism set is decided on the ordinal set the
    /// claim stores, not on whatever comparer the caller's collection carried: a case-insensitive
    /// source set spelling the mechanism <c>STATUS_LIST</c> names no <c>status_list</c> mechanism
    /// ordinally, so a reference supplied alongside it is a reference the stored set does not
    /// account for.
    /// </summary>
    [TestMethod]
    public void ACaseInsensitiveMechanismSpellingWithAReferenceIsRefused()
    {
        const string UppercaseStatusList = "STATUS_LIST";

        var supplied = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { UppercaseStatusList };

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => new StatusClaim(new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject), supplied));

        Assert.Contains(StatusMechanismNames.StatusList, exception.Message,
            "The refusal must name the status_list mechanism the stored ordinal set does not contain.");
    }


    /// <summary>
    /// "The status (status) claim MUST specify a JSON Object that contains at least one reference to a
    /// status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status List, Section 6.1</see>.
    /// A case-insensitive source set spelling a mechanism <c>STATUS_LIST</c> without a reference names
    /// an unmodelled mechanism ordinally, which is a claim this library can hold but cannot evaluate.
    /// It therefore constructs, and the state it stores agrees with the invariant that was checked:
    /// the mechanism set does not contain <c>status_list</c>.
    /// </summary>
    [TestMethod]
    public void ACaseInsensitiveMechanismSpellingWithoutAReferenceConstructsAsAnUnmodelledMechanism()
    {
        const string UppercaseStatusList = "STATUS_LIST";

        var supplied = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { UppercaseStatusList };
        var claim = new StatusClaim(statusList: null, mechanisms: supplied);

        Assert.IsFalse(claim.HasStatusList, "A claim built without a reference carries none.");
        Assert.DoesNotContain(StatusMechanismNames.StatusList, claim.Mechanisms,
            "The stored set compares ordinally, so the uppercase spelling is not the status_list mechanism.");
        Assert.Contains(UppercaseStatusList, claim.Mechanisms, "The identifier is carried through exactly as the issuer spelled it.");
    }
}
