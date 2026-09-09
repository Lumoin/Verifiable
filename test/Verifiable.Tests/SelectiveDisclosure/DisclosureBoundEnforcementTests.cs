using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.Model.SelectiveDisclosure.Strategy;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Adversarial tests for the lattice bounds <see cref="DisclosureComputation{TCredential}"/>
/// enforces on every set a policy component hands back — the Layer 4a
/// <see cref="PolicyAssessorDelegate{TCredential}"/> pipeline and the Layer 4b
/// <see cref="CrossCredentialOptimizerDelegate{TCredential}"/> pipeline alike.
/// </summary>
/// <remarks>
/// <para>
/// The architecture admits components whose reasoning cannot be inspected — rule engines,
/// solvers, model-driven reasoners — so the tests here play that component hostile: each one
/// returns a set that leaves the credential's lattice in one of the three distinguishable ways
/// (above <see cref="SetDisclosureLattice{TClaim}.Top"/>, below
/// <see cref="SetDisclosureLattice{TClaim}.Bottom"/>, or without the ancestors closure requires)
/// and asserts that the disclosure the pipeline adopts is the clamped one while the attempt
/// survives in the provenance trail.
/// </para>
/// <para>
/// Expected sets are derived from the lattice algebra the documentation states — the clamp is
/// (proposal ∩ A) ∪ M closed upward — never read back from what the pipeline produced. Every
/// clamped outcome is additionally checked against
/// <see cref="SetDisclosureLattice{TClaim}.IsValid"/>, which re-derives the bounds and the
/// closure from the lattice itself rather than trusting the computation's account of its own
/// work. The fixture is deliberately hierarchical and carries a non-empty mandatory floor,
/// because a flat credential with no mandatory paths makes the clamp vacuous.
/// </para>
/// </remarks>
[SuppressMessage(
    "Reliability", "CA2000:Dispose objects before losing scope",
    Justification =
        "The fixture builders construct Salt/SdDisclosure instances that transfer ownership " +
        "into the SdToken built from them (SdJwtSerializer.ParseToken), which the tests dispose " +
        "via using declarations; the analyzer cannot see ownership transfer through the wire " +
        "round-trip.")]
[TestClass]
internal sealed class DisclosureBoundEnforcementTests
{
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The pool the wire-reach test allocates disclosure salt buffers from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The issuer identifier, part of the mandatory floor.</summary>
    private static CredentialPath Iss { get; } = CredentialPath.FromJsonPointer("/iss");

    /// <summary>The credential type, part of the mandatory floor.</summary>
    private static CredentialPath Vct { get; } = CredentialPath.FromJsonPointer("/vct");

    /// <summary>The selectable claim the verifier requires.</summary>
    private static CredentialPath GivenName { get; } = CredentialPath.FromJsonPointer("/given_name");

    /// <summary>A selectable claim the verifier does not require.</summary>
    private static CredentialPath FamilyName { get; } = CredentialPath.FromJsonPointer("/family_name");

    /// <summary>A selectable claim used as the legitimate within-bounds expansion.</summary>
    private static CredentialPath Email { get; } = CredentialPath.FromJsonPointer("/email");

    /// <summary>The container claim that <see cref="AddressCity"/> and <see cref="AddressStreet"/> nest under.</summary>
    private static CredentialPath Address { get; } = CredentialPath.FromJsonPointer("/address");

    /// <summary>A nested claim whose ancestor is <see cref="Address"/>.</summary>
    private static CredentialPath AddressCity { get; } = CredentialPath.FromJsonPointer("/address/city");

    /// <summary>A second nested claim whose ancestor is <see cref="Address"/>.</summary>
    private static CredentialPath AddressStreet { get; } = CredentialPath.FromJsonPointer("/address/street");

    /// <summary>A path the credential does not carry, used to probe the ceiling.</summary>
    private static CredentialPath Ssn { get; } = CredentialPath.FromJsonPointer("/ssn");

    /// <summary>A second path the credential does not carry, used to probe the ceiling.</summary>
    private static CredentialPath PassportNumber { get; } = CredentialPath.FromJsonPointer("/passport_number");


    /// <summary>
    /// An assessor returning a path the credential does not carry cannot disclose it: the clamp
    /// intersects the proposal with the lattice top before anything adopts it, and the dropped
    /// path is kept as <see cref="PolicyAssessmentRecord.OutOfBoundsPaths"/>. The decision still
    /// proceeds, carrying the part of the proposal the lattice does admit.
    /// </summary>
    [TestMethod]
    public async Task AssessorPathAboveTheCeilingIsClampedAwayAndRecorded()
    {
        var assessor = Assessor<string>("CeilingEscape", context =>
        {
            var proposed = new HashSet<CredentialPath>(context.ProposedPaths) { Email, Ssn };

            return proposed;
        });

        var computation = new DisclosureComputation<string>([assessor], new FakeTimeProvider(TestClock.CanonicalEpoch));

        var graph = await computation.ComputeAsync([NestedMatch()],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //(proposal ∩ A) ∪ M closed upward: /ssn is not in A so it is dropped, /email is.
        var expected = new HashSet<CredentialPath> { Iss, Vct, GivenName, Email };

        Assert.HasCount(1, graph.Decisions, "The clamp bounds the disclosure rather than dropping the credential.");
        Assert.IsTrue(graph.Decisions[0].SelectedPaths.SetEquals(expected),
            "The adopted set is the proposal intersected with the available paths, with the mandatory floor kept.");
        Assert.DoesNotContain(Ssn, graph.Decisions[0].SelectedPaths,
            "A path the credential does not carry must not reach the disclosure.");
        AssertLatticeAdmitsSelection(graph.Decisions[0]);

        var assessment = SingleAssessment(graph);
        Assert.IsNotNull(assessment.OutOfBoundsPaths, "The escape above the ceiling is an auditable event.");
        Assert.IsTrue(assessment.OutOfBoundsPaths!.SetEquals(new HashSet<CredentialPath> { Ssn }),
            "Exactly the paths outside the lattice top are recorded as out of bounds.");
        Assert.IsNull(assessment.RestoredMandatoryPaths, "The proposal kept the mandatory floor.");
        Assert.IsNull(assessment.RestoredAncestorPaths, "The proposal named no claim missing an ancestor.");
    }


    /// <summary>
    /// An assessor dropping the mandatory floor cannot strip it: the clamp re-unions
    /// <see cref="SetDisclosureLattice{TClaim}.Bottom"/> and the omission is kept as
    /// <see cref="PolicyAssessmentRecord.RestoredMandatoryPaths"/>. This is the enforcement
    /// behind the mandatory-inviolability invariant, which states that mandatory paths cannot
    /// be excluded by any means.
    /// </summary>
    [TestMethod]
    public async Task AssessorDroppingTheMandatoryFloorHasItRestoredAndRecorded()
    {
        var assessor = Assessor<string>("FloorEscape", _ => [GivenName]);

        var computation = new DisclosureComputation<string>([assessor], new FakeTimeProvider(TestClock.CanonicalEpoch));

        var graph = await computation.ComputeAsync([NestedMatch()],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var expected = new HashSet<CredentialPath> { Iss, Vct, GivenName };

        Assert.HasCount(1, graph.Decisions);
        Assert.IsTrue(graph.Decisions[0].SelectedPaths.SetEquals(expected),
            "The mandatory floor is unioned back into the proposal.");
        AssertLatticeAdmitsSelection(graph.Decisions[0]);

        var assessment = SingleAssessment(graph);
        Assert.IsNotNull(assessment.RestoredMandatoryPaths, "The escape below the floor is an auditable event.");
        Assert.IsTrue(assessment.RestoredMandatoryPaths!.SetEquals(new HashSet<CredentialPath> { Iss, Vct }),
            "Exactly the dropped mandatory paths are recorded as restored.");
        Assert.IsNull(assessment.OutOfBoundsPaths, "The proposal named nothing above the ceiling.");
        Assert.IsNull(assessment.RestoredAncestorPaths, "Restored mandatory paths are reported apart from restored ancestors.");
    }


    /// <summary>
    /// An assessor naming a nested claim without the claim containing it produces a structurally
    /// unusable set — a verifier cannot place a value whose container is absent. Upward closure
    /// restores the ancestor and
    /// <see cref="PolicyAssessmentRecord.RestoredAncestorPaths"/> keeps the omission.
    /// </summary>
    [TestMethod]
    public async Task AssessorNamingDescendantWithoutAncestorHasClosureRestoreIt()
    {
        var assessor = Assessor<string>("ClosureEscape", context =>
        {
            var proposed = new HashSet<CredentialPath>(context.ProposedPaths) { AddressCity };

            return proposed;
        });

        var computation = new DisclosureComputation<string>([assessor], new FakeTimeProvider(TestClock.CanonicalEpoch));

        var graph = await computation.ComputeAsync([NestedMatch()],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Closure over /address/city pulls /address in; the document root is not an available path.
        var expected = new HashSet<CredentialPath> { Iss, Vct, GivenName, AddressCity, Address };

        Assert.HasCount(1, graph.Decisions);
        Assert.IsTrue(graph.Decisions[0].SelectedPaths.SetEquals(expected),
            "Upward closure carries every available ancestor of a selected claim.");
        AssertLatticeAdmitsSelection(graph.Decisions[0]);

        var assessment = SingleAssessment(graph);
        Assert.IsNotNull(assessment.RestoredAncestorPaths, "A structurally invalid proposal is an auditable event.");
        Assert.IsTrue(assessment.RestoredAncestorPaths!.SetEquals(new HashSet<CredentialPath> { Address }),
            "Exactly the omitted ancestors are recorded as restored.");
        Assert.IsNull(assessment.OutOfBoundsPaths);
        Assert.IsNull(assessment.RestoredMandatoryPaths);

        Assert.AreEqual(PolicyAssessmentEffect.Expanded, assessment.Effect,
            "The effect diff runs against the clamped set, which grew by the nested claim and its container.");
        Assert.IsNotNull(assessment.AddedPaths);
        Assert.IsTrue(assessment.AddedPaths!.SetEquals(new HashSet<CredentialPath> { AddressCity, Address }),
            "The ancestor closure restored is part of what actually happened to the disclosure set.");
    }


    /// <summary>
    /// Rejection keeps its meaning: the credential leaves the plan, its requirement goes
    /// unsatisfied, and no clamp runs because there is no adopted set to bound.
    /// </summary>
    [TestMethod]
    public async Task AssessorRejectionKeepsUnchangedSemanticsAndRecordsNoClampEvent()
    {
        var rejecter = new PolicyAssessorDelegate<string>((context, cancellationToken) =>
            Task.FromResult(new PolicyAssessmentOutcome
            {
                Approved = false,
                AssessorName = "Rejecter"
            }));

        var computation = new DisclosureComputation<string>([rejecter], new FakeTimeProvider(TestClock.CanonicalEpoch));

        var graph = await computation.ComputeAsync([NestedMatch()],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(graph.Satisfied);
        Assert.IsEmpty(graph.Decisions, "A rejected credential contributes no disclosure.");
        Assert.IsNotNull(graph.UnsatisfiedRequirements);
        Assert.Contains("req-1", graph.UnsatisfiedRequirements!);

        var assessment = SingleAssessment(graph);
        Assert.AreEqual(PolicyAssessmentEffect.Rejected, assessment.Effect);
        Assert.IsNull(assessment.OutOfBoundsPaths, "Rejection is not a bound violation.");
        Assert.IsNull(assessment.RestoredMandatoryPaths);
        Assert.IsNull(assessment.RestoredAncestorPaths);
        Assert.IsNull(assessment.AddedPaths);
        Assert.IsNull(assessment.RemovedPaths);
    }


    /// <summary>
    /// An assessor may widen the disclosure — a regulatory context claim added on top of what the
    /// verifier asked for — and a widening that stays inside the lattice takes effect exactly as
    /// returned, with no violation recorded anywhere.
    /// </summary>
    [TestMethod]
    public async Task WithinBoundsExpansionTakesEffectWithoutAnyClampEvent()
    {
        var assessor = Assessor<string>("RegulatoryContext", context =>
        {
            var proposed = new HashSet<CredentialPath>(context.ProposedPaths) { Email };

            return proposed;
        });

        var computation = new DisclosureComputation<string>([assessor], new FakeTimeProvider(TestClock.CanonicalEpoch));

        var graph = await computation.ComputeAsync([NestedMatch()],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var expected = new HashSet<CredentialPath> { Iss, Vct, GivenName, Email };

        Assert.HasCount(1, graph.Decisions);
        Assert.IsTrue(graph.Decisions[0].SelectedPaths.SetEquals(expected),
            "A proposal already inside the lattice is adopted unchanged.");
        AssertLatticeAdmitsSelection(graph.Decisions[0]);

        var assessment = SingleAssessment(graph);
        Assert.IsNull(assessment.OutOfBoundsPaths, "Legitimate expansion is not an escape.");
        Assert.IsNull(assessment.RestoredMandatoryPaths);
        Assert.IsNull(assessment.RestoredAncestorPaths);
        Assert.AreEqual(PolicyAssessmentEffect.Expanded, assessment.Effect);
        Assert.IsNotNull(assessment.AddedPaths);
        Assert.IsTrue(assessment.AddedPaths!.SetEquals(new HashSet<CredentialPath> { Email }));
        Assert.IsNull(graph.DecisionRecord!.BoundViolations, "No optimizer ran and no bound was crossed.");
    }


    /// <summary>
    /// The effect diff describes what happened to the disclosure set, never what the assessor
    /// attempted: an "expansion" made entirely of paths the credential does not carry moves the
    /// set nowhere, so the effect is <see cref="PolicyAssessmentEffect.Unchanged"/> while the
    /// escape fields carry the attempt. Both facts are recorded, and neither is stated as the
    /// other.
    /// </summary>
    [TestMethod]
    public async Task ExpansionEntirelyAboveTheCeilingRecordsUnchangedEffectWithEscapeFields()
    {
        var assessor = Assessor<string>("PhantomExpansion", context =>
        {
            var proposed = new HashSet<CredentialPath>(context.ProposedPaths) { Ssn, PassportNumber };

            return proposed;
        });

        var computation = new DisclosureComputation<string>([assessor], new FakeTimeProvider(TestClock.CanonicalEpoch));

        var graph = await computation.ComputeAsync([NestedMatch()],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, graph.Decisions);
        Assert.IsTrue(graph.Decisions[0].SelectedPaths.SetEquals(BaselineSelection()),
            "Nothing outside the lattice top survives the clamp, so the set is where it started.");
        AssertLatticeAdmitsSelection(graph.Decisions[0]);

        var assessment = SingleAssessment(graph);
        Assert.AreEqual(PolicyAssessmentEffect.Unchanged, assessment.Effect,
            "The disclosure set did not move, which is what the effect reports.");
        Assert.IsNull(assessment.AddedPaths, "Nothing was added to the disclosure set.");
        Assert.IsNull(assessment.RemovedPaths, "Nothing was removed from the disclosure set.");
        Assert.IsNotNull(assessment.OutOfBoundsPaths, "The attempt is recorded even though it had no effect.");
        Assert.IsTrue(assessment.OutOfBoundsPaths!.SetEquals(new HashSet<CredentialPath> { Ssn, PassportNumber }));
    }


    /// <summary>
    /// A cross-credential optimizer returning a path above the lattice top is bounded the same way
    /// an assessor is, and the attempt lands in
    /// <see cref="DisclosureDecisionRecord{TCredential}.BoundViolations"/> identified by the
    /// requirement and by the pass that produced it.
    /// </summary>
    [TestMethod]
    public async Task OptimizerPathAboveTheCeilingIsClampedAwayAndRecorded()
    {
        var optimizer = Optimizer(decision =>
        {
            var rewritten = new HashSet<CredentialPath>(decision.SelectedPaths) { Ssn };

            return rewritten;
        });

        var computation = new DisclosureComputation<string>([], new FakeTimeProvider(TestClock.CanonicalEpoch), crossCredentialOptimizers: [optimizer]);

        var graph = await computation.ComputeAsync([NestedMatch()],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var finalDecisions = graph.DecisionRecord!.FinalDecisions;

        Assert.HasCount(1, finalDecisions);
        Assert.IsTrue(finalDecisions[0].SelectedPaths.SetEquals(BaselineSelection()),
            "The optimizer's out-of-bounds addition is clamped away.");
        AssertLatticeAdmitsSelection(finalDecisions[0]);

        var violation = SingleViolation(graph);
        Assert.AreEqual("req-1", violation.QueryRequirementId);
        Assert.AreEqual(0, violation.OptimizerIndex);
        Assert.IsNotNull(violation.OutOfBoundsPaths);
        Assert.IsTrue(violation.OutOfBoundsPaths!.SetEquals(new HashSet<CredentialPath> { Ssn }));
        Assert.IsNull(violation.RestoredMandatoryPaths);
        Assert.IsNull(violation.RestoredAncestorPaths);
    }


    /// <summary>
    /// A cross-credential optimizer cannot strip the mandatory floor either: redistributing paths
    /// across credentials still leaves every credential's bottom in place.
    /// </summary>
    [TestMethod]
    public async Task OptimizerDroppingTheMandatoryFloorHasItRestoredAndRecorded()
    {
        var optimizer = Optimizer(_ => [GivenName]);

        var computation = new DisclosureComputation<string>([], new FakeTimeProvider(TestClock.CanonicalEpoch), crossCredentialOptimizers: [optimizer]);

        var graph = await computation.ComputeAsync([NestedMatch()],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var finalDecisions = graph.DecisionRecord!.FinalDecisions;

        Assert.IsTrue(finalDecisions[0].SelectedPaths.SetEquals(BaselineSelection()),
            "The mandatory floor is unioned back into the optimizer's set.");
        AssertLatticeAdmitsSelection(finalDecisions[0]);

        var violation = SingleViolation(graph);
        Assert.IsNotNull(violation.RestoredMandatoryPaths);
        Assert.IsTrue(violation.RestoredMandatoryPaths!.SetEquals(new HashSet<CredentialPath> { Iss, Vct }));
        Assert.IsNull(violation.OutOfBoundsPaths);
    }


    /// <summary>
    /// A cross-credential optimizer selecting a nested claim without its container has upward
    /// closure applied to its result, so a redistribution cannot produce a structurally unusable
    /// presentation.
    /// </summary>
    [TestMethod]
    public async Task OptimizerNamingDescendantWithoutAncestorHasClosureRestoreIt()
    {
        var optimizer = Optimizer(decision =>
        {
            var rewritten = new HashSet<CredentialPath>(decision.SelectedPaths) { AddressStreet };

            return rewritten;
        });

        var computation = new DisclosureComputation<string>([], new FakeTimeProvider(TestClock.CanonicalEpoch), crossCredentialOptimizers: [optimizer]);

        var graph = await computation.ComputeAsync([NestedMatch()],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var finalDecisions = graph.DecisionRecord!.FinalDecisions;
        var expected = new HashSet<CredentialPath> { Iss, Vct, GivenName, AddressStreet, Address };

        Assert.IsTrue(finalDecisions[0].SelectedPaths.SetEquals(expected));
        AssertLatticeAdmitsSelection(finalDecisions[0]);

        var violation = SingleViolation(graph);
        Assert.IsNotNull(violation.RestoredAncestorPaths);
        Assert.IsTrue(violation.RestoredAncestorPaths!.SetEquals(new HashSet<CredentialPath> { Address }));
    }


    /// <summary>
    /// An optimizer that redistributes within every credential's bounds is left alone: the
    /// bound-violation list stays absent, so the provenance trail distinguishes a legitimate
    /// global optimization from one that had to be corrected.
    /// </summary>
    [TestMethod]
    public async Task OptimizerStayingWithinBoundsRecordsNoBoundViolation()
    {
        var optimizer = Optimizer(decision =>
        {
            var rewritten = new HashSet<CredentialPath>(decision.SelectedPaths) { FamilyName };

            return rewritten;
        });

        var computation = new DisclosureComputation<string>([], new FakeTimeProvider(TestClock.CanonicalEpoch), crossCredentialOptimizers: [optimizer]);

        var graph = await computation.ComputeAsync([NestedMatch()],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var finalDecisions = graph.DecisionRecord!.FinalDecisions;
        var expected = new HashSet<CredentialPath> { Iss, Vct, GivenName, FamilyName };

        Assert.IsTrue(finalDecisions[0].SelectedPaths.SetEquals(expected),
            "A within-bounds redistribution is adopted exactly as the optimizer returned it.");
        Assert.IsNull(graph.DecisionRecord!.BoundViolations);
        AssertLatticeAdmitsSelection(finalDecisions[0]);
    }


    /// <summary>
    /// Each decision is clamped against its own credential's lattice, not against some merged
    /// bound: an optimizer that hands one credential's paths to another credential discloses
    /// nothing extra from either, and both attempts are recorded under their own requirement.
    /// </summary>
    [TestMethod]
    public async Task EachDecisionIsClampedAgainstItsOwnLattice()
    {
        var swapAcrossCredentials = new CrossCredentialOptimizerDelegate<string>(
            (decisions, signals, cancellationToken) =>
            {
                var swapped = new List<CredentialDisclosureDecision<string>>(decisions.Count);
                for(int i = 0; i < decisions.Count; i++)
                {
                    var source = decisions[decisions.Count - 1 - i];
                    swapped.Add(new CredentialDisclosureDecision<string>
                    {
                        Credential = decisions[i].Credential,
                        QueryRequirementId = decisions[i].QueryRequirementId,
                        SelectedPaths = new HashSet<CredentialPath>(source.SelectedPaths),
                        SatisfiesRequirements = decisions[i].SatisfiesRequirements,
                        Lattice = decisions[i].Lattice
                    });
                }

                return Task.FromResult<IReadOnlyList<CredentialDisclosureDecision<string>>>(swapped);
            });

        var computation = new DisclosureComputation<string>([], new FakeTimeProvider(TestClock.CanonicalEpoch), crossCredentialOptimizers: [swapAcrossCredentials]);

        //Two credentials whose available paths are disjoint, so every path one decision receives
        //from the other lies above its own ceiling.
        var matches = new[]
        {
            CreateMatch("cred-a", "req-a",
                required: [GivenName],
                available: [Iss, GivenName, Email],
                mandatory: [Iss]),
            CreateMatch("cred-b", "req-b",
                required: [FamilyName],
                available: [Vct, FamilyName, Address, AddressCity],
                mandatory: [Vct])
        };

        var graph = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var finalDecisions = graph.DecisionRecord!.FinalDecisions;
        Assert.HasCount(2, finalDecisions);

        var decisionA = FindDecision(finalDecisions, "req-a");
        var decisionB = FindDecision(finalDecisions, "req-b");

        //Every path swapped in is outside the receiving lattice, so only that lattice's own
        //mandatory floor survives the clamp.
        Assert.IsTrue(decisionA.SelectedPaths.SetEquals(new HashSet<CredentialPath> { Iss }),
            "Nothing from the other credential's lattice enters this credential's disclosure.");
        Assert.IsTrue(decisionB.SelectedPaths.SetEquals(new HashSet<CredentialPath> { Vct }),
            "Nothing from the other credential's lattice enters this credential's disclosure.");
        AssertLatticeAdmitsSelection(decisionA);
        AssertLatticeAdmitsSelection(decisionB);

        var violations = graph.DecisionRecord!.BoundViolations;
        Assert.IsNotNull(violations);
        Assert.HasCount(2, violations!, "Each decision that left its own bounds is recorded separately.");

        var violationA = FindViolation(violations!, "req-a");
        var violationB = FindViolation(violations!, "req-b");

        Assert.IsNotNull(violationA.OutOfBoundsPaths);
        Assert.IsTrue(violationA.OutOfBoundsPaths!.SetEquals(new HashSet<CredentialPath> { Vct, FamilyName }),
            "The record names the paths this credential's lattice refused.");
        Assert.IsNotNull(violationA.RestoredMandatoryPaths);
        Assert.IsTrue(violationA.RestoredMandatoryPaths!.SetEquals(new HashSet<CredentialPath> { Iss }));

        Assert.IsNotNull(violationB.OutOfBoundsPaths);
        Assert.IsTrue(violationB.OutOfBoundsPaths!.SetEquals(new HashSet<CredentialPath> { Iss, GivenName }));
        Assert.IsNotNull(violationB.RestoredMandatoryPaths);
        Assert.IsTrue(violationB.RestoredMandatoryPaths!.SetEquals(new HashSet<CredentialPath> { Vct }));
    }


    /// <summary>
    /// <see cref="BoundViolationRecord.OptimizerIndex"/> identifies which pass in a
    /// multi-optimizer pipeline produced the out-of-bounds decision, which is what makes the
    /// record usable when several passes run in sequence.
    /// </summary>
    [TestMethod]
    public async Task BoundViolationIdentifiesTheOffendingOptimizerPass()
    {
        var passThrough = new CrossCredentialOptimizerDelegate<string>(
            (decisions, signals, cancellationToken) => Task.FromResult(decisions));

        var escaping = Optimizer(decision =>
        {
            var rewritten = new HashSet<CredentialPath>(decision.SelectedPaths) { PassportNumber };

            return rewritten;
        });

        var computation = new DisclosureComputation<string>([], new FakeTimeProvider(TestClock.CanonicalEpoch), crossCredentialOptimizers: [passThrough, escaping]);

        var graph = await computation.ComputeAsync([NestedMatch()],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var violation = SingleViolation(graph);
        Assert.AreEqual(1, violation.OptimizerIndex, "The second pass is the one that left the bounds.");
        Assert.IsTrue(violation.OutOfBoundsPaths!.SetEquals(new HashSet<CredentialPath> { PassportNumber }));
        AssertLatticeAdmitsSelection(graph.DecisionRecord!.FinalDecisions[0]);
    }


    /// <summary>
    /// Lattice bounds — "M ⊆ S ⊆ A (the disclosure set is bounded by mandatory below and
    /// available above)". Proven against a pipeline in which the assessor and the optimizer both
    /// return sets violating the bound in both directions at once.
    /// </summary>
    [TestMethod]
    public async Task LatticeBoundsHoldThroughHostileAssessorAndOptimizer()
    {
        var assessor = Assessor<string>("BoundBreaker", _ => [Ssn, Email]);
        var optimizer = Optimizer(_ => [PassportNumber, AddressCity]);

        var computation = new DisclosureComputation<string>([assessor], new FakeTimeProvider(TestClock.CanonicalEpoch), crossCredentialOptimizers: [optimizer]);

        var graph = await computation.ComputeAsync([NestedMatch()],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        foreach(var decision in graph.DecisionRecord!.FinalDecisions)
        {
            Assert.IsTrue(decision.Lattice!.Bottom.IsSubsetOf(decision.SelectedPaths),
                "The mandatory floor bounds the disclosure set from below.");
            Assert.IsTrue(decision.SelectedPaths.IsSubsetOf(decision.Lattice!.Top),
                "The available paths bound the disclosure set from above.");
            AssertLatticeAdmitsSelection(decision);
        }
    }


    /// <summary>
    /// Mandatory inviolability — "∀p ∈ M → p ∈ S (mandatory paths cannot be excluded by any
    /// means)". Proven against an assessor and an optimizer that each strip the whole floor, one
    /// after the other.
    /// </summary>
    [TestMethod]
    public async Task MandatoryInviolabilityHoldsAgainstRepeatedStripping()
    {
        var assessor = Assessor<string>("FloorStripper", _ => [GivenName]);
        var optimizer = Optimizer(_ => [GivenName]);

        var computation = new DisclosureComputation<string>([assessor], new FakeTimeProvider(TestClock.CanonicalEpoch), crossCredentialOptimizers: [optimizer]);

        var graph = await computation.ComputeAsync([NestedMatch()],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var decision = graph.DecisionRecord!.FinalDecisions[0];

        Assert.Contains(Iss, decision.SelectedPaths, "A mandatory path survives every component that drops it.");
        Assert.Contains(Vct, decision.SelectedPaths, "A mandatory path survives every component that drops it.");
        AssertLatticeAdmitsSelection(decision);
    }


    /// <summary>
    /// Minimality — "S = M ∪ ((V \ E) ∩ A) when no policy component runs — the lattice adds
    /// nothing the verifier did not ask for". Proven with a request that names a path the
    /// credential lacks and an exclusion aimed at the mandatory floor, so the formula is exercised
    /// on all three of its terms.
    /// </summary>
    [TestMethod]
    public async Task MinimalityHoldsWhenNoPolicyComponentRuns()
    {
        var computation = new DisclosureComputation<string>([], new FakeTimeProvider(TestClock.CanonicalEpoch));

        var verifierRequested = new HashSet<CredentialPath> { GivenName, Ssn };
        var userExcluded = new HashSet<CredentialPath> { Iss, Email };

        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [.. verifierRequested],
                available: [Iss, Vct, GivenName, FamilyName, Email, Address, AddressCity, AddressStreet],
                mandatory: [Iss, Vct])
        };

        var exclusions = new Dictionary<string, IReadOnlySet<CredentialPath>>
        {
            ["req-1"] = userExcluded
        };

        var graph = await computation.ComputeAsync(matches, exclusions,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var decision = graph.Decisions[0];

        //M ∪ ((V \ E) ∩ A), computed from the inputs rather than read back from the pipeline.
        var expected = new HashSet<CredentialPath>(decision.Lattice!.Bottom);
        var requestedMinusExcluded = new HashSet<CredentialPath>(verifierRequested);
        requestedMinusExcluded.ExceptWith(userExcluded);
        requestedMinusExcluded.IntersectWith(decision.Lattice!.Top);
        expected.UnionWith(requestedMinusExcluded);

        Assert.IsTrue(decision.SelectedPaths.SetEquals(expected),
            "With no policy component the selection is exactly the minimal set the formula names.");
        AssertLatticeAdmitsSelection(decision);
    }


    /// <summary>
    /// Upward closure — "∀p ∈ S, ∀q ancestor of p with q ∈ A → q ∈ S, for every S a policy
    /// component contributes (structural validity is preserved)". Proven by having both a policy
    /// assessor and a cross-credential optimizer contribute nested claims without their container.
    /// </summary>
    [TestMethod]
    public async Task UpwardClosureHoldsForEverySetAPolicyComponentContributes()
    {
        var assessor = Assessor<string>("NestedSelector", _ => [AddressCity]);
        var optimizer = Optimizer(_ => [AddressStreet]);

        var computation = new DisclosureComputation<string>([assessor], new FakeTimeProvider(TestClock.CanonicalEpoch), crossCredentialOptimizers: [optimizer]);

        var graph = await computation.ComputeAsync([NestedMatch()],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var decision = graph.DecisionRecord!.FinalDecisions[0];

        foreach(var path in decision.SelectedPaths)
        {
            foreach(var ancestor in path.Ancestors())
            {
                if(decision.Lattice!.Top.Contains(ancestor))
                {
                    Assert.Contains(ancestor, decision.SelectedPaths,
                        "A selected claim carries every ancestor the credential can disclose.");
                }
            }
        }

        Assert.Contains(Address, decision.SelectedPaths, "The container of the selected nested claim is present.");
        AssertLatticeAdmitsSelection(decision);
    }


    /// <summary>
    /// Policy bounding — "an assessor or optimizer may narrow S or expand it, and either way the
    /// result is clamped to M ⊆ S ⊆ A and closed upward; the returned set is never adopted as
    /// given". Proven by comparing the set the assessor returned against the set the pipeline
    /// adopted: the two differ, the adopted one is admissible, and the difference is on record.
    /// </summary>
    [TestMethod]
    public async Task PolicyBoundingNeverAdoptsTheReturnedSetAsGiven()
    {
        var returnedByAssessor = new HashSet<CredentialPath> { AddressCity, Ssn };
        var assessor = Assessor<string>("UnboundedProposal", _ => new HashSet<CredentialPath>(returnedByAssessor));

        var computation = new DisclosureComputation<string>([assessor], new FakeTimeProvider(TestClock.CanonicalEpoch));

        var graph = await computation.ComputeAsync([NestedMatch()],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var decision = graph.Decisions[0];

        Assert.IsFalse(decision.SelectedPaths.SetEquals(returnedByAssessor),
            "The proposal is not what the pipeline adopts.");
        Assert.IsTrue(decision.SelectedPaths.SetEquals(
            new HashSet<CredentialPath> { Iss, Vct, AddressCity, Address }),
            "The adopted set is the proposal bounded by the lattice and closed upward.");
        AssertLatticeAdmitsSelection(decision);

        var assessment = SingleAssessment(graph);
        Assert.IsNotNull(assessment.OutOfBoundsPaths);
        Assert.IsNotNull(assessment.RestoredMandatoryPaths);
        Assert.IsNotNull(assessment.RestoredAncestorPaths,
            "All three violation shapes occurred in one proposal and each is reported on its own field.");
    }


    /// <summary>
    /// Exclusion safety — "E ∩ M = ∅ semantically (user exclusions of mandatory paths are
    /// silently ignored)". Proven with a user exclusion aimed at the mandatory floor followed by
    /// an assessor that drops the same paths: neither route removes them, and the exclusion raises
    /// no conflict because a mandatory path was never the user's to exclude.
    /// </summary>
    [TestMethod]
    public async Task ExclusionSafetyKeepsMandatoryPathsAgainstUserAndPolicy()
    {
        var assessor = Assessor<string>("ExclusionAmplifier", context =>
        {
            var proposed = new HashSet<CredentialPath>(context.ProposedPaths);
            proposed.Remove(Iss);
            proposed.Remove(Vct);

            return proposed;
        });

        var computation = new DisclosureComputation<string>([assessor], new FakeTimeProvider(TestClock.CanonicalEpoch));

        var exclusions = new Dictionary<string, IReadOnlySet<CredentialPath>>
        {
            ["req-1"] = new HashSet<CredentialPath> { Iss, Vct }
        };

        var graph = await computation.ComputeAsync([NestedMatch()], exclusions,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var decision = graph.Decisions[0];

        Assert.Contains(Iss, decision.SelectedPaths, "An excluded mandatory path stays in the disclosure.");
        Assert.Contains(Vct, decision.SelectedPaths, "An excluded mandatory path stays in the disclosure.");
        Assert.IsNull(decision.ConflictingPaths, "Excluding a mandatory path is not a conflict, it is a no-op.");
        AssertLatticeAdmitsSelection(decision);
    }


    /// <summary>
    /// The clamped set reaches the wire. An assessor strips the mandatory floor, the clamp
    /// restores it, and the restored path's disclosure is the one
    /// <see cref="SdDisclosureSelection.SelectDisclosures(SdDisclosurePaths, IReadOnlySet{CredentialPath})"/>
    /// emits, survives serialization to the SD-JWT wire format, and is present again after
    /// parsing the wire form back.
    /// </summary>
    [SuppressMessage(
        "Reliability", "CA2000:Dispose objects before losing scope",
        Justification =
            "Ownership of each disclosure transfers to the SdToken constructed from them, and " +
            "the tokens are disposed through using declarations; the cascade disposes the " +
            "disclosures and their salts.")]
    [TestMethod]
    public async Task StrippedMandatoryDisclosuresStillReachTheWire()
    {
        var nationality = CredentialPath.FromJsonPointer("/nationality");

        using SdToken<string> issuedToken = BuildFlatParsedToken();

        //The issuer made nationality always-visible, so it is the lattice bottom for this token.
        var assessor = Assessor<SdToken<string>>("NationalityStripper", _ => [GivenName]);
        var computation = new DisclosureComputation<SdToken<string>>([assessor], new FakeTimeProvider(TestClock.CanonicalEpoch));

        var match = new DisclosureMatch<SdToken<string>>
        {
            Credential = issuedToken,
            QueryRequirementId = "req-1",
            RequiredPaths = new HashSet<CredentialPath> { GivenName },
            MatchedPaths = new HashSet<CredentialPath> { GivenName },
            AllAvailablePaths = new HashSet<CredentialPath> { GivenName, FamilyName, nationality },
            MandatoryPaths = new HashSet<CredentialPath> { nationality }
        };

        var graph = await computation.ComputeAsync([match],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var decision = graph.Decisions[0];
        Assert.Contains(nationality, decision.SelectedPaths, "The clamp restored the stripped mandatory path.");
        AssertLatticeAdmitsSelection(decision);

        var selected = SdDisclosureSelection.SelectDisclosures(issuedToken.DisclosurePaths, decision.SelectedPaths);
        var emittedClaimNames = selected.Select(d => d.ClaimName!).ToHashSet(StringComparer.Ordinal);

        Assert.HasCount(2, selected, "The emitted disclosures are the clamped set's disclosures.");
        Assert.Contains("nationality", emittedClaimNames,
            "The disclosure the assessor tried to strip is emitted.");

        using SdToken<string> presentationToken = issuedToken.SelectDisclosures(selected, Pool);
        string wireFormat = SdJwtSerializer.SerializeToken(presentationToken, TestSetup.Base64UrlEncoder);

        using SdToken<string> parsed = SdJwtSerializer.ParseToken(
            wireFormat, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag);

        var claimNamesOnTheWire = parsed.Disclosures
            .Select(d => d.ClaimName!)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Contains("nationality", claimNamesOnTheWire, "The restored mandatory claim is on the wire.");
        Assert.Contains("given_name", claimNamesOnTheWire);
        Assert.DoesNotContain("family_name", claimNamesOnTheWire,
            "A claim outside the clamped set is not on the wire.");
    }


    /// <summary>
    /// A pipeline whose components stay inside the lattice observes no clamp at all: the adopted
    /// set is byte-for-byte the assessor's return value, no violation field is populated, and no
    /// bound-violation record exists. Enforcement changes the outcome only for a component that
    /// left the bounds.
    /// </summary>
    [TestMethod]
    public async Task ClampIsANoOpForAWellBehavedPipeline()
    {
        var narrowed = new HashSet<CredentialPath> { GivenName };
        var assessor = Assessor<string>("DataMinimization", _ => new HashSet<CredentialPath>(narrowed));

        var computation = new DisclosureComputation<string>([assessor], new FakeTimeProvider(TestClock.CanonicalEpoch));

        //A flat credential with no mandatory floor: the shape of an ordinary narrowing policy.
        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName, FamilyName],
                available: [GivenName, FamilyName, Email])
        };

        var graph = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var decision = graph.Decisions[0];

        Assert.IsTrue(decision.SelectedPaths.SetEquals(narrowed),
            "A within-bounds narrowing is adopted exactly as returned.");
        Assert.IsFalse(decision.SatisfiesRequirements, "The policy narrowed below the verifier's requirements.");
        AssertLatticeAdmitsSelection(decision);

        var assessment = SingleAssessment(graph);
        Assert.AreEqual(PolicyAssessmentEffect.Narrowed, assessment.Effect);
        Assert.IsNull(assessment.OutOfBoundsPaths);
        Assert.IsNull(assessment.RestoredMandatoryPaths);
        Assert.IsNull(assessment.RestoredAncestorPaths);
        Assert.IsNull(graph.DecisionRecord!.BoundViolations);
    }


    /// <summary>
    /// Asserts the independent structural check on a decision: the credential's own lattice
    /// admits the selected set. <see cref="SetDisclosureLattice{TClaim}.IsValid"/> re-derives
    /// M ⊆ S ⊆ A and upward closure from the lattice, so it answers the question without
    /// consulting the computation's account of what it did.
    /// </summary>
    /// <typeparam name="TCredential">The credential representation the decision carries.</typeparam>
    /// <param name="decision">The decision whose selected paths are checked.</param>
    /// <summary>
    /// Builds a genuinely parsed, flat SD-JWT token with three top-level disclosures
    /// (<c>given_name</c>, <c>family_name</c>, <c>nationality</c>) — only a parsed token carries
    /// <see cref="SdToken{TEnvelope}.DisclosurePaths"/>, which
    /// <see cref="SdDisclosureSelection.SelectDisclosures(SdDisclosurePaths, IReadOnlySet{CredentialPath})"/>
    /// reads.
    /// </summary>
    private static SdToken<string> BuildFlatParsedToken()
    {
        SdDisclosure givenName = CreateFlatDisclosure("salt-given-name", "given_name", "Erika");
        SdDisclosure familyName = CreateFlatDisclosure("salt-family-name", "family_name", "Mustermann");
        SdDisclosure nationality = CreateFlatDisclosure("salt-nationality", "nationality", "DE");

        string givenNameEncoded = SdJwtSerializer.SerializeDisclosure(givenName, TestSetup.Base64UrlEncoder);
        string familyNameEncoded = SdJwtSerializer.SerializeDisclosure(familyName, TestSetup.Base64UrlEncoder);
        string nationalityEncoded = SdJwtSerializer.SerializeDisclosure(nationality, TestSetup.Base64UrlEncoder);

        string givenNameDigest = SdJwtPathExtraction.ComputeDisclosureDigest(
            givenNameEncoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string familyNameDigest = SdJwtPathExtraction.ComputeDisclosureDigest(
            familyNameEncoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string nationalityDigest = SdJwtPathExtraction.ComputeDisclosureDigest(
            nationalityEncoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string payloadJson = /*lang=json,strict*/ $$"""
        {
            "_sd_alg": "sha-256",
            "iss": "https://issuer.example.com",
            "_sd": ["{{givenNameDigest}}", "{{familyNameDigest}}", "{{nationalityDigest}}"]
        }
        """;

        string header = /*lang=json,strict*/ """{"alg":"ES256","typ":"JWT"}""";
        string headerEncoded = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(header));
        string payloadEncoded = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(payloadJson));
        string fakeSignature = TestSetup.Base64UrlEncoder(new byte[64]);
        string jwt = $"{headerEncoded}.{payloadEncoded}.{fakeSignature}";

        string wireFormat = $"{jwt}~{givenNameEncoded}~{familyNameEncoded}~{nationalityEncoded}~";

        return SdJwtSerializer.ParseToken(
            wireFormat, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag);
    }


    /// <summary>
    /// <see cref="SdDisclosurePaths.TryFindEnclosingDisclosurePath"/> resolves a node to the
    /// INNERMOST enclosing disclosure position, never a farther ancestor: releasing the nearest
    /// disclosure reveals the node, and releasing a farther one would disclose more than the path
    /// requires (RFC 9901 Section 7.2 step 2.b — the disclosable ancestor a selection carries).
    /// The map's ancestor walk is nearest-first over <see cref="CredentialPath.Parent"/>, so the
    /// result does not depend on the root-first order of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901</see>-path ancestry enumeration.
    /// </summary>
    [TestMethod]
    public void EnclosingDisclosureIsTheInnermostAncestorPosition()
    {
        using SdDisclosure address = CreateFlatDisclosure("salt-address", "address", "outer");
        using SdDisclosure streetAddress = CreateFlatDisclosure("salt-street", "street_address", "inner");
        using SdDisclosure shallow = CreateFlatDisclosure("salt-shallow", "shallow", "a");
        using SdDisclosure deep = CreateFlatDisclosure("salt-deep", "deep", "c");

        var paths = new SdDisclosurePaths(new Dictionary<SdDisclosure, CredentialPath>
        {
            [address] = CredentialPath.FromJsonPointer("/address"),
            [streetAddress] = CredentialPath.FromJsonPointer("/address/street_address"),
            [shallow] = CredentialPath.FromJsonPointer("/a"),
            [deep] = CredentialPath.FromJsonPointer("/a/b/c")
        });

        Assert.IsTrue(
            paths.TryFindEnclosingDisclosurePath(CredentialPath.FromJsonPointer("/address/region"), out CredentialPath interiorOwner),
            "A node inside a disclosure resolves to the disclosure that carries it.");
        Assert.AreEqual(CredentialPath.FromJsonPointer("/address"), interiorOwner,
            "The enclosing position of /address/region is the /address disclosure (Section 7.2 step 2.b).");

        Assert.IsTrue(
            paths.TryFindEnclosingDisclosurePath(CredentialPath.FromJsonPointer("/a/b/c/d"), out CredentialPath deepOwner),
            "A deeply nested node resolves to a disclosure position that encloses it.");
        Assert.AreEqual(CredentialPath.FromJsonPointer("/a/b/c"), deepOwner,
            "The INNERMOST enclosing disclosure (/a/b/c) is chosen, not the farther /a — releasing the nearest discloses least.");

        Assert.IsTrue(
            paths.TryFindEnclosingDisclosurePath(CredentialPath.FromJsonPointer("/address/street_address"), out CredentialPath positionOwner),
            "A position that is itself a disclosure still has an enclosing disclosure — its nearest ancestor position.");
        Assert.AreEqual(CredentialPath.FromJsonPointer("/address"), positionOwner,
            "The walk is over STRICT ancestors, so /address/street_address encloses to /address, not to itself.");

        Assert.IsFalse(
            paths.TryFindEnclosingDisclosurePath(CredentialPath.FromJsonPointer("/nowhere"), out _),
            "A path with no disclosure ancestor has no enclosing disclosure.");
    }


    /// <summary>
    /// Creates a top-level object-property disclosure (RFC 9901 Section 4.2.1's three-element
    /// array) from a deterministic salt, for the hand-minted wire form the reach test parses.
    /// </summary>
    /// <param name="salt">The salt text, taken as its UTF-8 bytes.</param>
    /// <param name="claimName">The claim name, local to the root object.</param>
    /// <param name="claimValue">The claim's string value.</param>
    /// <returns>The disclosure, whose ownership passes to the token parsed from the wire form.</returns>
    private static SdDisclosure CreateFlatDisclosure(string salt, string claimName, string claimValue) =>
        SdDisclosure.CreateProperty(
            TestSalts.FromBytes(Encoding.UTF8.GetBytes(salt)),
            claimName,
            JsonDocument.Parse($"\"{claimValue}\"").RootElement);


    /// <summary>
    /// Re-derives the bounds from the decision's own lattice and asserts the adopted set lies
    /// within them, so a clamped outcome is checked against the lattice algebra rather than
    /// against the computation's account of its own work.
    /// </summary>
    /// <typeparam name="TCredential">The credential representation the computation ran over.</typeparam>
    /// <param name="decision">The decision whose selected set is checked.</param>
    private static void AssertLatticeAdmitsSelection<TCredential>(
        CredentialDisclosureDecision<TCredential> decision)
    {
        Assert.IsNotNull(decision.Lattice, "A decision the computation produced carries the lattice bounding it.");
        Assert.IsTrue(decision.Lattice!.IsValid(decision.SelectedPaths),
            "The lattice must admit the selected set: mandatory floor kept, available ceiling respected, ancestors carried.");
    }


    /// <summary>
    /// Builds an approving assessor whose returned set is <paramref name="propose"/> applied to
    /// the context, so a test states only the proposal it wants the pipeline to face.
    /// </summary>
    /// <typeparam name="TCredential">The credential representation the computation runs over.</typeparam>
    /// <param name="name">The assessor name carried into the provenance record.</param>
    /// <param name="propose">Produces the set the assessor returns for a given context.</param>
    /// <returns>The assessor delegate.</returns>
    private static PolicyAssessorDelegate<TCredential> Assessor<TCredential>(
        string name,
        Func<PolicyAssessmentContext<TCredential>, HashSet<CredentialPath>> propose)
    {
        return (context, cancellationToken) => Task.FromResult(new PolicyAssessmentOutcome
        {
            Approved = true,
            ApprovedPaths = propose(context),
            AssessorName = name
        });
    }


    /// <summary>
    /// Builds a cross-credential optimizer that rewrites every decision's selected set with
    /// <paramref name="rewrite"/> while carrying each decision's own lattice forward, which is
    /// the shape a redistributing pass has.
    /// </summary>
    /// <param name="rewrite">Produces the set the optimizer assigns to a given decision.</param>
    /// <returns>The optimizer delegate.</returns>
    private static CrossCredentialOptimizerDelegate<string> Optimizer(
        Func<CredentialDisclosureDecision<string>, HashSet<CredentialPath>> rewrite)
    {
        return (decisions, signals, cancellationToken) =>
        {
            var rewritten = new List<CredentialDisclosureDecision<string>>(decisions.Count);
            foreach(var decision in decisions)
            {
                rewritten.Add(new CredentialDisclosureDecision<string>
                {
                    Credential = decision.Credential,
                    QueryRequirementId = decision.QueryRequirementId,
                    SelectedPaths = rewrite(decision),
                    SatisfiesRequirements = decision.SatisfiesRequirements,
                    ConflictingPaths = decision.ConflictingPaths,
                    UnavailablePaths = decision.UnavailablePaths,
                    Format = decision.Format,
                    Lattice = decision.Lattice
                });
            }

            return Task.FromResult<IReadOnlyList<CredentialDisclosureDecision<string>>>(rewritten);
        };
    }


    /// <summary>
    /// The single policy assessment the graph recorded, which is where the escape fields for a
    /// one-assessor pipeline live.
    /// </summary>
    /// <typeparam name="TCredential">The credential representation the computation runs over.</typeparam>
    /// <param name="graph">The graph the computation produced.</param>
    /// <returns>The one assessment record.</returns>
    private static PolicyAssessmentRecord SingleAssessment<TCredential>(DisclosureStrategyGraph<TCredential> graph)
    {
        Assert.IsNotNull(graph.DecisionRecord!.PolicyAssessments);
        Assert.HasCount(1, graph.DecisionRecord!.PolicyAssessments!);

        return graph.DecisionRecord!.PolicyAssessments![0];
    }


    /// <summary>
    /// The single bound violation the graph recorded, which is where a one-optimizer pipeline's
    /// escape lands.
    /// </summary>
    /// <typeparam name="TCredential">The credential representation the computation runs over.</typeparam>
    /// <param name="graph">The graph the computation produced.</param>
    /// <returns>The one bound violation record.</returns>
    private static BoundViolationRecord SingleViolation<TCredential>(DisclosureStrategyGraph<TCredential> graph)
    {
        Assert.IsNotNull(graph.DecisionRecord!.BoundViolations);
        Assert.HasCount(1, graph.DecisionRecord!.BoundViolations!);

        return graph.DecisionRecord!.BoundViolations![0];
    }


    /// <summary>
    /// The decision for a given query requirement, so a multi-credential assertion names the
    /// credential it means rather than a list position.
    /// </summary>
    /// <param name="decisions">The decisions to search.</param>
    /// <param name="requirementId">The query requirement identifier.</param>
    /// <returns>The matching decision.</returns>
    private static CredentialDisclosureDecision<string> FindDecision(
        IReadOnlyList<CredentialDisclosureDecision<string>> decisions,
        string requirementId)
    {
        CredentialDisclosureDecision<string>? found = null;
        foreach(var decision in decisions)
        {
            if(string.Equals(decision.QueryRequirementId, requirementId, StringComparison.Ordinal))
            {
                found = decision;
                break;
            }
        }

        Assert.IsNotNull(found, $"A decision for requirement '{requirementId}' must exist.");

        return found!;
    }


    /// <summary>
    /// The bound violation for a given query requirement, so a multi-credential assertion names
    /// the credential it means rather than a list position.
    /// </summary>
    /// <param name="violations">The violations to search.</param>
    /// <param name="requirementId">The query requirement identifier.</param>
    /// <returns>The matching violation record.</returns>
    private static BoundViolationRecord FindViolation(
        IReadOnlyList<BoundViolationRecord> violations,
        string requirementId)
    {
        BoundViolationRecord? found = null;
        foreach(var violation in violations)
        {
            if(string.Equals(violation.QueryRequirementId, requirementId, StringComparison.Ordinal))
            {
                found = violation;
                break;
            }
        }

        Assert.IsNotNull(found, $"A bound violation for requirement '{requirementId}' must exist.");

        return found!;
    }


    /// <summary>
    /// The hierarchical fixture every Layer 4 test runs against: a non-empty mandatory floor and
    /// a nested address container, so the clamp has something to restore in each of its three
    /// directions.
    /// </summary>
    /// <returns>The match the computation consumes.</returns>
    private static DisclosureMatch<string> NestedMatch()
    {
        return CreateMatch("cred-1", "req-1",
            required: [GivenName],
            available: [Iss, Vct, GivenName, FamilyName, Email, Address, AddressCity, AddressStreet],
            mandatory: [Iss, Vct]);
    }


    /// <summary>
    /// The selection <see cref="NestedMatch"/> yields before any policy component runs, which the
    /// minimality invariant fixes at M ∪ ((V \ E) ∩ A) with no exclusions in play.
    /// </summary>
    /// <returns>The baseline set.</returns>
    private static HashSet<CredentialPath> BaselineSelection() => [Iss, Vct, GivenName];


    /// <summary>
    /// Creates a <see cref="DisclosureMatch{TCredential}"/> for testing. In production a DCQL
    /// evaluator produces these from an actual query against the wallet's credential store; here
    /// they are constructed directly so the bound enforcement is isolated from query evaluation.
    /// </summary>
    /// <param name="credential">The opaque credential the match carries.</param>
    /// <param name="requirementId">The query requirement identifier.</param>
    /// <param name="required">The paths the verifier requires.</param>
    /// <param name="available">The paths the credential carries (the lattice top).</param>
    /// <param name="mandatory">The always-disclosed paths (the lattice bottom).</param>
    /// <returns>The match.</returns>
    private static DisclosureMatch<string> CreateMatch(
        string credential,
        string requirementId,
        CredentialPath[] required,
        CredentialPath[] available,
        CredentialPath[]? mandatory = null)
    {
        return new DisclosureMatch<string>
        {
            Credential = credential,
            QueryRequirementId = requirementId,
            RequiredPaths = new HashSet<CredentialPath>(required),
            MatchedPaths = new HashSet<CredentialPath>(available),
            AllAvailablePaths = new HashSet<CredentialPath>(available),
            MandatoryPaths = mandatory is not null ? new HashSet<CredentialPath>(mandatory) : null
        };
    }
}
