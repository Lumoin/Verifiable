using Verifiable.JCose;
using Verifiable.OAuth.IdJag;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Unit coverage for <see cref="IdJagActorDecision"/> — the composition that decides which
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> <c>act</c> claim
/// the access token minted from a redeemed Identity Assertion JWT Authorization Grant carries, and
/// enforces the grant's <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">§4.4</see>
/// <c>may_act</c> statement against the redeeming client. Each test pins one
/// <see cref="IdJagActorDecisionKind"/> to the clause that decides it, the fail-closed guards included:
/// those sit behind <see cref="IdJagAssertionValidation"/>, which refuses such grants before the
/// endpoint path ever reaches the decision, so this is where they are exercised.
/// </summary>
[TestClass]
internal sealed class IdJagActorDecisionTests
{
    /// <summary>
    /// This Resource Authorization Server's issuer identifier — the namespace a redeeming
    /// <c>client_id</c> is an identifier in.
    /// </summary>
    private const string ResourceServerIssuer = "https://rs.example.com/";

    /// <summary>
    /// The <c>client_id</c> of the client authenticated on the redeem request — the party that acts at
    /// the redemption boundary.
    /// </summary>
    private const string RedeemingClientId = "resource-client-1";

    /// <summary>The principal the access is requested for — the issued token's <c>sub</c>.</summary>
    private const string Subject = "U019488227";

    /// <summary>
    /// A party that acted before the redeeming client — the prior actor a nested <c>act</c> claim
    /// records per RFC 8693 §4.1 ("nested 'act' claims represent prior actors").
    /// </summary>
    private const string PriorActorSubject = "https://svc.example/first-hop";

    /// <summary>
    /// A trust domain that is not this Resource Authorization Server's, so an identity stated in it is
    /// stated in a different namespace than a <c>client_id</c> of this server.
    /// </summary>
    private const string ForeignIssuer = "https://idp.example.com/";

    /// <summary>A party that is neither the redeeming client nor the subject.</summary>
    private const string OtherPartySubject = "https://svc.example/other-agent";


    /// <summary>
    /// The fourth composition case and the declined half of the composite-token capability:
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-1.1">RFC 8693 §1.1</see> — "When a
    /// principal is acting directly on its own behalf, for example, neither delegation nor
    /// impersonation are in play." The grant records no prior actor and the redeeming client is the
    /// token's own subject, so no party acts for another and no <c>act</c> claim is composed; a
    /// self-referential actor would assert a delegation that never occurred.
    /// </summary>
    [TestMethod]
    public void GrantWithoutActorRedeemedByItsOwnSubjectRecordsNoDelegation()
    {
        IdJagActorDecision decision = IdJagActorDecision.Evaluate(
            grantActor: null,
            grantAuthorizedActor: null,
            RedeemingClientId,
            subject: RedeemingClientId,
            ResourceServerIssuer);

        Assert.AreEqual(IdJagActorDecisionKind.NoDelegation, decision.Kind);
        Assert.IsFalse(decision.IsRefused);
        Assert.IsNull(decision.Act, "No delegation occurred, so the issued token carries no act claim.");
    }


    /// <summary>
    /// The third composition case:
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> — the
    /// <c>act</c> claim "provides a means within a JWT to express that delegation has occurred and
    /// identify the acting party to whom authority has been delegated". The grant records no prior
    /// actor and the redeeming client is not the subject, so the single hop that just happened is
    /// recorded as the current actor in the shape §4.1 Figure 5 shows, and the token's <c>sub</c> stays
    /// the subject — <see href="https://www.rfc-editor.org/rfc/rfc8693#section-1.1">§1.1</see>
    /// delegation ("principal A still has its own identity separate from B"), not impersonation.
    /// </summary>
    [TestMethod]
    public void GrantWithoutActorRedeemedByAnotherPartyRecordsTheDelegationStep()
    {
        IdJagActorDecision decision = IdJagActorDecision.Evaluate(
            grantActor: null,
            grantAuthorizedActor: null,
            RedeemingClientId,
            Subject,
            ResourceServerIssuer);

        Assert.AreEqual(IdJagActorDecisionKind.DelegationRecorded, decision.Kind);
        Assert.IsNotNull(decision.Act);
        Assert.AreEqual(RedeemingClientId, ActorSubject(decision.Act!));
        Assert.IsFalse(decision.Act!.ContainsKey(WellKnownJwtClaimNames.Act),
            "Exactly one hop occurred, so the chain has exactly one link.");
    }


    /// <summary>
    /// The first composition case:
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> — "The
    /// outermost 'act' claim represents the current actor while nested 'act' claims represent prior
    /// actors." The grant's chain already names the redeeming client as its current actor, so the
    /// current actor is unchanged at this boundary and the chain crosses it verbatim; nesting it under
    /// a copy of itself would record a delegation hop that did not occur.
    /// </summary>
    [TestMethod]
    public void ChainWhoseCurrentActorIsTheRedeemingClientCrossesUnchanged()
    {
        IReadOnlyDictionary<string, object> grantActor =
            Actor(RedeemingClientId, priorActor: Actor(PriorActorSubject));

        IdJagActorDecision decision = IdJagActorDecision.Evaluate(
            grantActor,
            grantAuthorizedActor: null,
            RedeemingClientId,
            Subject,
            ResourceServerIssuer);

        Assert.AreEqual(IdJagActorDecisionKind.ChainPreserved, decision.Kind);
        Assert.IsNotNull(decision.Act);
        Assert.AreEqual(RedeemingClientId, ActorSubject(decision.Act!));
        Assert.AreEqual(PriorActorSubject, ActorSubject(NestedActor(decision.Act!)),
            "The prior actor stays exactly one level deep — the chain crossed verbatim.");
        Assert.IsFalse(NestedActor(decision.Act!).ContainsKey(WellKnownJwtClaimNames.Act),
            "A boundary that changes no actor adds no nesting level.");
    }


    /// <summary>
    /// The same first composition case with the actor's namespace stated explicitly:
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> — "the
    /// combination of the two claims 'iss' and 'sub' might be necessary to uniquely identify an actor".
    /// An actor naming this Resource Authorization Server's own issuer alongside the redeeming client's
    /// identifier is that client, fully qualified, so the chain crosses unchanged exactly as it does
    /// when the actor leaves the namespace unstated.
    /// </summary>
    [TestMethod]
    public void ChainWhoseCurrentActorMatchesTheClientAndThisIssuerCrossesUnchanged()
    {
        IReadOnlyDictionary<string, object> grantActor = Actor(RedeemingClientId, issuer: ResourceServerIssuer);

        IdJagActorDecision decision = IdJagActorDecision.Evaluate(
            grantActor,
            grantAuthorizedActor: null,
            RedeemingClientId,
            Subject,
            ResourceServerIssuer);

        Assert.AreEqual(IdJagActorDecisionKind.ChainPreserved, decision.Kind);
        Assert.AreEqual(RedeemingClientId, ActorSubject(decision.Act!));
        Assert.IsFalse(decision.Act!.ContainsKey(WellKnownJwtClaimNames.Act),
            "The chain is the grant's own single link, unchanged.");
    }


    /// <summary>
    /// The second composition case:
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> — "A chain of
    /// delegation can be expressed by nesting one 'act' claim within another ... The least recent actor
    /// is the most deeply nested." The grant's chain names another party as its current actor, so the
    /// redeeming client becomes the new current actor and that chain becomes the prior actors beneath
    /// it.
    /// </summary>
    [TestMethod]
    public void ChainWhoseCurrentActorIsAnotherPartyNestsBeneathTheRedeemingClient()
    {
        IReadOnlyDictionary<string, object> grantActor = Actor(PriorActorSubject);

        IdJagActorDecision decision = IdJagActorDecision.Evaluate(
            grantActor,
            grantAuthorizedActor: null,
            RedeemingClientId,
            Subject,
            ResourceServerIssuer);

        Assert.AreEqual(IdJagActorDecisionKind.ChainExtended, decision.Kind);
        Assert.AreEqual(RedeemingClientId, ActorSubject(decision.Act!),
            "The redeeming client is the new current actor and is therefore the outermost act.");
        Assert.AreEqual(PriorActorSubject, ActorSubject(NestedActor(decision.Act!)),
            "The grant's chain becomes the prior actor nested beneath the new current actor.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> at the
    /// composition's most dangerous input: "the combination of the two claims 'iss' and 'sub' might be
    /// necessary to uniquely identify an actor." A grant minted in a foreign issuer's namespace can
    /// name a current actor whose <c>sub</c> is byte-identical to a <c>client_id</c> of this Resource
    /// Authorization Server while being an entirely different party, so the pair decides and not the
    /// subject string alone. The colliding actor is another party, which makes the redeeming client the
    /// new current actor with the foreign chain nested beneath it — the delegation record survives the
    /// collision instead of being suppressed by it.
    /// </summary>
    [TestMethod]
    public void CurrentActorCollidingBySubjectUnderAForeignIssuerIsADifferentParty()
    {
        IReadOnlyDictionary<string, object> grantActor = Actor(RedeemingClientId, issuer: ForeignIssuer);

        IdJagActorDecision decision = IdJagActorDecision.Evaluate(
            grantActor,
            grantAuthorizedActor: null,
            RedeemingClientId,
            Subject,
            ResourceServerIssuer);

        Assert.AreEqual(IdJagActorDecisionKind.ChainExtended, decision.Kind,
            "A matching sub under a different issuer is a different actor, so the boundary is a delegation hop.");

        IReadOnlyDictionary<string, object> nested = NestedActor(decision.Act!);
        Assert.AreEqual(RedeemingClientId, ActorSubject(nested));
        Assert.AreEqual(ForeignIssuer, (string)nested[WellKnownJwtClaimNames.Iss],
            "The foreign-namespace actor is recorded as the prior actor, qualified by the issuer that names it.");
        Assert.AreEqual(RedeemingClientId, ActorSubject(decision.Act!),
            "The current actor is the client this server authenticated, in this server's own namespace.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>: "The 'act'
    /// claim value is a JSON object, and members in the JSON object are claims that identify the
    /// actor." A chain whose outermost object names no actor identifies nobody, so neither preserving
    /// nor extending it can establish who is acting and the redemption is refused — issuing the token
    /// with the unreadable chain dropped would downgrade a delegated grant to an undelegated one.
    /// </summary>
    [TestMethod]
    public void ActorObjectNamingNoSubjectRefusesTheRedemption()
    {
        IdJagActorDecision decision = IdJagActorDecision.Evaluate(
            grantActor: new Dictionary<string, object>(StringComparer.Ordinal),
            grantAuthorizedActor: null,
            RedeemingClientId,
            Subject,
            ResourceServerIssuer);

        Assert.AreEqual(IdJagActorDecisionKind.RefuseMalformedActor, decision.Kind);
        Assert.IsTrue(decision.IsRefused);
        Assert.IsNull(decision.Act, "A refused redemption composes no act claim.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see>: the
    /// <c>may_act</c> claim "makes a statement that one party is authorized to become the actor and act
    /// on behalf of another party", and its members "identify the party that is asserted as being
    /// eligible to act". Every non-refusing outcome makes the redeeming client the current actor, so a
    /// client the grant's <c>may_act</c> does not name may not become one and the redemption is refused
    /// rather than issuing a token whose actor the grant's issuer never authorized.
    /// </summary>
    [TestMethod]
    public void AuthorizedActorNamingAnotherPartyRefusesTheRedeemingClient()
    {
        IdJagActorDecision decision = IdJagActorDecision.Evaluate(
            grantActor: null,
            grantAuthorizedActor: Actor(OtherPartySubject),
            RedeemingClientId,
            Subject,
            ResourceServerIssuer);

        Assert.AreEqual(IdJagActorDecisionKind.RefuseUnauthorizedActor, decision.Kind);
        Assert.IsTrue(decision.IsRefused);
        Assert.IsNull(decision.Act);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see>: "the
    /// combination of the two claims 'iss' and 'sub' are sometimes necessary to uniquely identify an
    /// authorized actor." A <c>may_act</c> naming both authorizes only the party that is that subject
    /// within that issuer's namespace, so the same subject asserted under a different issuer is a
    /// different, unauthorized party — and the matching combination is the party it names.
    /// </summary>
    [TestMethod]
    public void AuthorizedActorIssuerAndSubjectAreEnforcedAsAPair()
    {
        IdJagActorDecision matching = IdJagActorDecision.Evaluate(
            grantActor: null,
            grantAuthorizedActor: Actor(RedeemingClientId, issuer: ResourceServerIssuer),
            RedeemingClientId,
            Subject,
            ResourceServerIssuer);

        Assert.AreEqual(IdJagActorDecisionKind.DelegationRecorded, matching.Kind);
        Assert.AreEqual(RedeemingClientId, ActorSubject(matching.Act!));

        IdJagActorDecision foreignNamespace = IdJagActorDecision.Evaluate(
            grantActor: null,
            grantAuthorizedActor: Actor(RedeemingClientId, issuer: ForeignIssuer),
            RedeemingClientId,
            Subject,
            ResourceServerIssuer);

        Assert.AreEqual(IdJagActorDecisionKind.RefuseUnauthorizedActor, foreignNamespace.Kind,
            "The authorized party is that subject in that issuer's namespace, which this client is not.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see>: the members
    /// of a <c>may_act</c> object exist to "identify the party that is asserted as being eligible to
    /// act", so an object naming neither a <c>sub</c> nor an <c>iss</c> identifies no party and
    /// therefore authorizes none. Reading it as "no constraint" would turn the malformed claim into a
    /// bypass of the restriction it was written to state.
    /// </summary>
    [TestMethod]
    public void AuthorizedActorIdentifyingNoPartyAuthorizesNobody()
    {
        IdJagActorDecision decision = IdJagActorDecision.Evaluate(
            grantActor: null,
            grantAuthorizedActor: new Dictionary<string, object>(StringComparer.Ordinal),
            RedeemingClientId,
            Subject,
            ResourceServerIssuer);

        Assert.AreEqual(IdJagActorDecisionKind.RefuseUnauthorizedActor, decision.Kind);
        Assert.IsNull(decision.Act);
    }


    /// <summary>
    /// Builds an <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>
    /// actor object: the <c>sub</c> identifying the party, optionally the <c>iss</c> naming the
    /// namespace that identifier lives in, and optionally the nested <c>act</c> carrying the prior
    /// actor beneath it.
    /// </summary>
    /// <param name="subject">The party's identifier.</param>
    /// <param name="issuer">The namespace the identifier belongs to, or <see langword="null"/> to leave it unstated.</param>
    /// <param name="priorActor">The actor nested one level deeper, or <see langword="null"/> for a single-link chain.</param>
    /// <returns>The actor object.</returns>
    private static Dictionary<string, object> Actor(
        string subject,
        string? issuer = null,
        IReadOnlyDictionary<string, object>? priorActor = null)
    {
        Dictionary<string, object> actor = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = subject
        };

        if(issuer is not null)
        {
            actor[WellKnownJwtClaimNames.Iss] = issuer;
        }

        if(priorActor is not null)
        {
            actor[WellKnownJwtClaimNames.Act] = priorActor;
        }

        return actor;
    }


    /// <summary>Reads the <c>sub</c> member identifying the actor of one <c>act</c> object.</summary>
    /// <param name="actor">The actor object.</param>
    /// <returns>The actor's identifier.</returns>
    private static string ActorSubject(IReadOnlyDictionary<string, object> actor) =>
        (string)actor[WellKnownJwtClaimNames.Sub];


    /// <summary>Reads the actor nested one level within an <c>act</c> object — the prior actor.</summary>
    /// <param name="actor">The actor object.</param>
    /// <returns>The nested actor object.</returns>
    private static IReadOnlyDictionary<string, object> NestedActor(IReadOnlyDictionary<string, object> actor) =>
        (IReadOnlyDictionary<string, object>)actor[WellKnownJwtClaimNames.Act];
}
