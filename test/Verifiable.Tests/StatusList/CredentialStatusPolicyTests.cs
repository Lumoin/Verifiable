using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Core.Dcql;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="CredentialStatusPolicy"/> and the two policies the library ships,
/// <see cref="CredentialStatusPolicies.Surface"/> and <see cref="CredentialStatusPolicies.RefuseNotValid"/>.
/// These exercise the policy as a bare delegate call over an outcome map — no verifier executor, no server
/// pipeline — because the seam is the relying party's, not the protocol's: a peer wallet, an agent or an RP
/// server all judge the same map the same way.
/// </summary>
/// <remarks>
/// Every outcome fed to a policy here is read by <see cref="CredentialStatusGate"/> from a real
/// <see cref="StatusListType"/> carrying the status value under test, so the map the policy judges is the map a
/// verifier would hand it rather than a hand-set <see cref="CredentialStatusOutcome.IsValid"/> flag.
/// </remarks>
[TestClass]
internal sealed class CredentialStatusPolicyTests
{
    /// <summary>The status list URI every credential in these tests references.</summary>
    private const string ListUri = "https://issuer.example/statuslists/1";

    /// <summary>The index each credential's status entry occupies in the list the gate reads.</summary>
    private const int CredentialIndex = 7;

    /// <summary>Entry capacity of the lists these tests build; far more than the single entry each one sets.</summary>
    private const int ListCapacity = 64;

    /// <summary>The instant the gate evaluates the status list at.</summary>
    private static DateTimeOffset Now { get; } = TestClock.CanonicalEpoch;

    /// <summary>The pool every status list in this class rents its bytes from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>Supplies the ambient cancellation token and the test identity.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18">SD-JWT VC</see>: "If status
    /// is present in the verified payload of the SD-JWT, the status SHOULD be checked.  Verifier policy decides
    /// whether to reject or accept a presentation of a SD-JWT VC based on the status of the Verifiable Digital
    /// Credential." <see cref="CredentialStatusPolicies.Surface"/> is the deciding policy that accepts: it refuses
    /// no status value <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1">
    /// Token Status List, Section 7.1</see> defines — not the two named not-valid states (<c>0x01</c> "INVALID",
    /// <c>0x02</c> "SUSPENDED") and not the application-specific values (<c>0x03</c>, <c>0x0C</c>-<c>0x0F</c>) whose
    /// "processing ... is application specific" — so the outcome is merely surfaced to the relying party.
    /// </summary>
    /// <param name="status">The Section 7.1 status value the credential's list entry carries.</param>
    [TestMethod]
    [DataRow(StatusTypes.Valid)]
    [DataRow(StatusTypes.Invalid)]
    [DataRow(StatusTypes.Suspended)]
    [DataRow(StatusTypes.ApplicationSpecific03)]
    [DataRow(StatusTypes.ApplicationSpecific0C)]
    public async Task SurfaceRefusesNoDeterminableStatusValue(byte status)
    {
        CredentialStatusOutcome outcome = await ReadOutcomeAsync(status).ConfigureAwait(false);

        CredentialStatusRefusal? refusal = CredentialStatusPolicies.Surface(
            new Dictionary<CredentialQueryId, CredentialStatusOutcome> { [new CredentialQueryId("pid")] = outcome });

        Assert.IsNull(refusal,
            $"SD-JWT VC leaves the accept/reject decision to Verifier policy, and Surface is the policy that " +
            $"accepts: status 0x{status:X2} must be surfaced, never refused.");
    }


    /// <summary>
    /// The same "Verifier policy decides whether to reject or accept" sentence of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18">SD-JWT VC</see> over a
    /// presentation carrying several credentials: <see cref="CredentialStatusPolicies.Surface"/> judges the
    /// complete map at once and refuses none of it, however many entries read not valid.
    /// </summary>
    [TestMethod]
    public async Task SurfaceRefusesNoMixedOutcomeMap()
    {
        Dictionary<CredentialQueryId, CredentialStatusOutcome> statuses = new()
        {
            [new CredentialQueryId("pid_primary")] = await ReadOutcomeAsync(StatusTypes.Valid).ConfigureAwait(false),
            [new CredentialQueryId("pid_secondary")] = await ReadOutcomeAsync(StatusTypes.Invalid).ConfigureAwait(false),
            [new CredentialQueryId("mdl")] = await ReadOutcomeAsync(StatusTypes.Suspended).ConfigureAwait(false)
        };

        CredentialStatusRefusal? refusal = CredentialStatusPolicies.Surface(statuses);

        Assert.IsNull(refusal,
            "Surface accepts a presentation whatever its credentials' statuses read, so a map mixing valid, " +
            "revoked and suspended entries still yields no refusal.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> step 1 is "Check for the existence of a status claim", so a presentation whose
    /// credentials carry no status claim leaves nothing for step 7's "Check the status value as described in
    /// Section 7" to judge. <see cref="CredentialStatusPolicies.Surface"/> answers an empty map with no refusal.
    /// </summary>
    [TestMethod]
    public void SurfaceRefusesNoEmptyOutcomeMap()
    {
        CredentialStatusRefusal? refusal = CredentialStatusPolicies.Surface(
            new Dictionary<CredentialQueryId, CredentialStatusOutcome>());

        Assert.IsNull(refusal,
            "A presentation whose credentials carried no status claim surfaces an empty map, which Surface " +
            "must answer with no refusal.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1">Token Status
    /// List, Section 7.1</see> gives exactly one value the credential is good under — "0x00 - "VALID" - The status
    /// of the Referenced Token is valid, correct or legal." — while <c>0x01</c> is "revoked, annulled, taken back,
    /// recalled or cancelled", <c>0x02</c> is "temporarily invalid, hanging, debarred from privilege" and "The
    /// Status Type value 0x03 and Status Type values in the range 0x0C until 0x0F are permanently reserved as
    /// application specific." <see cref="CredentialStatusPolicies.RefuseNotValid"/> is the deciding policy of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18">SD-JWT VC</see>'s "Verifier
    /// policy decides whether to reject or accept" that rejects every one of them.
    /// </summary>
    /// <param name="status">The Section 7.1 status value the credential's list entry carries.</param>
    [TestMethod]
    [DataRow(StatusTypes.Invalid)]
    [DataRow(StatusTypes.Suspended)]
    [DataRow(StatusTypes.ApplicationSpecific03)]
    [DataRow(StatusTypes.ApplicationSpecific0C)]
    [DataRow(StatusTypes.ApplicationSpecific0F)]
    public async Task RefuseNotValidRefusesEveryStatusOutsideValid(byte status)
    {
        CredentialStatusOutcome outcome = await ReadOutcomeAsync(status).ConfigureAwait(false);

        CredentialStatusRefusal? refusal = CredentialStatusPolicies.RefuseNotValid(
            new Dictionary<CredentialQueryId, CredentialStatusOutcome> { [new CredentialQueryId("pid")] = outcome });

        Assert.IsNotNull(refusal,
            $"Section 7.1 marks only 0x00 valid, so RefuseNotValid must refuse status 0x{status:X2}.");
        Assert.HasCount(1, refusal.Credentials,
            "One presented credential read not valid, so the refusal names exactly one credential.");
        Assert.AreEqual("pid", refusal.Credentials[0].CredentialQueryId.Value,
            "The refusal names the refused credential by the DCQL credential query identifier it answered.");
        Assert.AreEqual(status, refusal.Credentials[0].Outcome.Status,
            "The refusal carries the raw Section 7.1 status value the gate read, not a re-derived one.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1">Token Status
    /// List, Section 7.1</see>: "0x00 - "VALID" - The status of the Referenced Token is valid, correct or legal."
    /// <see cref="CredentialStatusPolicies.RefuseNotValid"/> refuses nothing when every presented credential reads
    /// that value, so a wholly valid presentation stands.
    /// </summary>
    [TestMethod]
    public async Task RefuseNotValidAcceptsAnAllValidOutcomeMap()
    {
        Dictionary<CredentialQueryId, CredentialStatusOutcome> statuses = new()
        {
            [new CredentialQueryId("pid_primary")] = await ReadOutcomeAsync(StatusTypes.Valid).ConfigureAwait(false),
            [new CredentialQueryId("pid_secondary")] = await ReadOutcomeAsync(StatusTypes.Valid).ConfigureAwait(false)
        };

        CredentialStatusRefusal? refusal = CredentialStatusPolicies.RefuseNotValid(statuses);

        Assert.IsNull(refusal,
            "Every presented credential read 0x00 VALID, so RefuseNotValid must let the presentation stand.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> step 1 is "Check for the existence of a status claim": with no status claim on any
    /// presented credential there is no status value for step 7 to check, so even the refusing policy has nothing
    /// to refuse.
    /// </summary>
    [TestMethod]
    public void RefuseNotValidAcceptsAnEmptyOutcomeMap()
    {
        CredentialStatusRefusal? refusal = CredentialStatusPolicies.RefuseNotValid(
            new Dictionary<CredentialQueryId, CredentialStatusOutcome>());

        Assert.IsNull(refusal,
            "An empty outcome map carries no status value to check, so RefuseNotValid must not refuse.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> step 7 — "Check the status value as described in Section 7" — is run per Referenced
    /// Token, so a policy judging a multi-credential presentation must report every credential it refuses, not the
    /// first. The refusal lists each not-valid entry in the order the map presents them and passes the valid ones
    /// over.
    /// </summary>
    [TestMethod]
    public async Task RefuseNotValidNamesEveryNotValidCredentialInMapOrder()
    {
        Dictionary<CredentialQueryId, CredentialStatusOutcome> statuses = new()
        {
            [new CredentialQueryId("a")] = await ReadOutcomeAsync(StatusTypes.Invalid).ConfigureAwait(false),
            [new CredentialQueryId("b")] = await ReadOutcomeAsync(StatusTypes.Valid).ConfigureAwait(false),
            [new CredentialQueryId("c")] = await ReadOutcomeAsync(StatusTypes.Suspended).ConfigureAwait(false),
            [new CredentialQueryId("d")] = await ReadOutcomeAsync(StatusTypes.ApplicationSpecific0C).ConfigureAwait(false)
        };

        CredentialStatusRefusal? refusal = CredentialStatusPolicies.RefuseNotValid(statuses);

        Assert.IsNotNull(refusal, "Three of the four presented credentials read not valid, so the policy refuses.");
        Assert.HasCount(3, refusal.Credentials,
            "The refusal names every not-valid credential and no valid one.");
        Assert.AreEqual("a", refusal.Credentials[0].CredentialQueryId.Value,
            "The refused credentials are reported in the order the outcome map presents them.");
        Assert.AreEqual("c", refusal.Credentials[1].CredentialQueryId.Value,
            "The valid entry between them is passed over, not reported.");
        Assert.AreEqual("d", refusal.Credentials[2].CredentialQueryId.Value,
            "An application-specific status is refused alongside the two named not-valid states.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1">Token Status
    /// List, Section 7.1</see> names each status value: <c>0x01</c> "INVALID" is "revoked, annulled, taken back,
    /// recalled or cancelled", <c>0x02</c> "SUSPENDED" is "temporarily invalid, hanging, debarred from privilege",
    /// and "The Status Type value 0x03 and Status Type values in the range 0x0C until 0x0F are permanently reserved
    /// as application specific." <see cref="RefusedCredentialStatus.Disposition"/> reads the raw value into exactly
    /// those three readings, and into none under which the credential would still be valid.
    /// </summary>
    /// <param name="status">The Section 7.1 status value the credential's list entry carries.</param>
    /// <param name="expectedDisposition">The reading Section 7.1 assigns that value.</param>
    /// <param name="expectedDispositionName">The word the reading reads as inside the composed description.</param>
    [TestMethod]
    [DataRow(StatusTypes.Invalid, CredentialStatusDisposition.Revoked, "revoked")]
    [DataRow(StatusTypes.Suspended, CredentialStatusDisposition.Suspended, "suspended")]
    [DataRow(StatusTypes.ApplicationSpecific03, CredentialStatusDisposition.ApplicationSpecific, "application-specific")]
    [DataRow(StatusTypes.ApplicationSpecific0C, CredentialStatusDisposition.ApplicationSpecific, "application-specific")]
    [DataRow(StatusTypes.ApplicationSpecific0F, CredentialStatusDisposition.ApplicationSpecific, "application-specific")]
    public async Task RefusedCredentialDispositionReadsTheStatusTypeValue(
        byte status,
        CredentialStatusDisposition expectedDisposition,
        string expectedDispositionName)
    {
        CredentialStatusOutcome outcome = await ReadOutcomeAsync(status).ConfigureAwait(false);

        CredentialStatusRefusal? refusal = CredentialStatusPolicies.RefuseNotValid(
            new Dictionary<CredentialQueryId, CredentialStatusOutcome> { [new CredentialQueryId("pid")] = outcome });

        Assert.IsNotNull(refusal, $"Status 0x{status:X2} is not 0x00 VALID, so the policy refuses.");
        Assert.AreEqual(expectedDisposition, refusal.Credentials[0].Disposition,
            $"Section 7.1 reads status 0x{status:X2} as {expectedDisposition}.");
        Assert.AreEqual(expectedDispositionName, refusal.Credentials[0].DispositionName,
            "The disposition's word is the one the composed description reads.");
    }


    /// <summary>
    /// The relying party's own detail — which credential query, the raw status, its reading — is composed once, in
    /// full, for the log and the failed flow state, because
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 15.9</see> keeps the wire answer generic: "Error responses SHOULD avoid including
    /// sensitive or detailed contextual information that could be used to infer the End-User's data." The
    /// composition names every refused credential in map order with the
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1">Token Status
    /// List, Section 7.1</see> value it read and that value's reading.
    /// </summary>
    [TestMethod]
    public async Task RefusalDescriptionComposesEveryRefusedCredentialQueryStatusAndReading()
    {
        Dictionary<CredentialQueryId, CredentialStatusOutcome> statuses = new()
        {
            [new CredentialQueryId("a")] = await ReadOutcomeAsync(StatusTypes.Invalid).ConfigureAwait(false),
            [new CredentialQueryId("b")] = await ReadOutcomeAsync(StatusTypes.Suspended).ConfigureAwait(false)
        };

        CredentialStatusRefusal? refusal = CredentialStatusPolicies.RefuseNotValid(statuses);

        Assert.IsNotNull(refusal, "Both presented credentials read not valid, so the policy refuses.");
        Assert.AreEqual(
            "credential_status_not_valid: credential query 'a' reads status 0x01 (revoked); "
                + "credential query 'b' reads status 0x02 (suspended)",
            refusal.Description,
            "The typed detail names each refused credential query, its Section 7.1 status value and that " +
            "value's reading, in map order.");
    }


    /// <summary>
    /// The composed detail opens with <see cref="CredentialStatusRefusal.ReasonCode"/>, a machine-readable code, so
    /// a reader of the failed flow state can tell a credential-status refusal from another refusal without parsing
    /// prose — the same separation
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see> draws on
    /// the wire between the "single ASCII [USASCII] error code" and the "Human-readable ASCII [USASCII] text
    /// providing additional information".
    /// </summary>
    [TestMethod]
    public async Task RefusalDescriptionOpensWithTheMachineReadableReasonCode()
    {
        CredentialStatusOutcome outcome = await ReadOutcomeAsync(StatusTypes.Invalid).ConfigureAwait(false);

        CredentialStatusRefusal? refusal = CredentialStatusPolicies.RefuseNotValid(
            new Dictionary<CredentialQueryId, CredentialStatusOutcome> { [new CredentialQueryId("pid")] = outcome });

        Assert.IsNotNull(refusal, "A revoked credential is refused by RefuseNotValid.");
        Assert.StartsWith("credential_status_not_valid:", refusal.Description,
            "The composed detail opens with the machine-readable code a relying party keys on, then the " +
            "human-readable text.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> step 4.d: "If the Relying Party is using a system for caching the Status List Token,
    /// it SHOULD check the ttl claim of the Status List Token and retrieve a fresh copy if (time status was
    /// resolved + ttl &lt; current time)". That check is a caching hint rather than a validity verdict, so the
    /// refusal carries the gate's verdict through untouched on the refused credential's outcome instead of folding
    /// it into the refusal.
    /// </summary>
    [TestMethod]
    public async Task RefusalCarriesTheOutcomeCacheRefreshHintThrough()
    {
        CredentialStatusOutcome outcome = await ReadOutcomeAsync(
            StatusTypes.Invalid,
            timeToLive: 60,
            resolvedAt: Now.AddHours(-1)).ConfigureAwait(false);

        Assert.IsTrue(outcome.ShouldRefresh,
            "A token resolved an hour ago under a 60-second ttl is one Section 8.3 step 4.d says to re-fetch.");

        CredentialStatusRefusal? refusal = CredentialStatusPolicies.RefuseNotValid(
            new Dictionary<CredentialQueryId, CredentialStatusOutcome> { [new CredentialQueryId("pid")] = outcome });

        Assert.IsNotNull(refusal, "The credential read 0x01 INVALID, so the policy refuses.");
        Assert.IsTrue(refusal.Credentials[0].Outcome.ShouldRefresh,
            "The ttl caching hint rides the refused credential's outcome, unchanged by the policy.");
    }


    /// <summary>
    /// <see cref="CredentialStatusRefusal.Credentials"/> is a snapshot taken at construction: a custom policy
    /// that retains its own mutable list and hands it to <see cref="CredentialStatusRefusal"/> cannot mutate
    /// the refusal already riding a failed flow state out from under it by mutating that list afterward.
    /// </summary>
    [TestMethod]
    public async Task MutatingThePolicysOwnListAfterConstructionDoesNotChangeTheRefusal()
    {
        CredentialStatusOutcome outcome = await ReadOutcomeAsync(StatusTypes.Invalid).ConfigureAwait(false);

        List<RefusedCredentialStatus> policyOwnedList =
        [
            new RefusedCredentialStatus { CredentialQueryId = new CredentialQueryId("pid"), Outcome = outcome }
        ];

        CredentialStatusRefusal refusal = new() { Credentials = policyOwnedList };
        string descriptionAtConstruction = refusal.Description;

        policyOwnedList.Add(new RefusedCredentialStatus { CredentialQueryId = new CredentialQueryId("pid_secondary"), Outcome = outcome });

        Assert.HasCount(1, refusal.Credentials,
            "The refusal's Credentials must not grow when the policy's own retained list grows afterward.");
        Assert.AreEqual(descriptionAtConstruction, refusal.Description,
            "The refusal's composed Description must not change when the policy's own retained list changes afterward.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">OpenID for
    /// Verifiable Presentations 1.0, Section 8.1</see> keys a presentation's credentials by "the id value used
    /// for a Credential Query in the DCQL query", and
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">Section
    /// 6.1</see> makes that value "a non-empty string consisting of alphanumeric, underscore (_), or hyphen (-)
    /// characters" — a string compared as written. <see cref="CredentialStatusPolicies.RefuseNotValid"/> judges
    /// the outcome map under those identifiers and names each refused credential by the very
    /// <see cref="CredentialQueryId"/> it answered, so two queries whose ids differ only in case stay two
    /// credentials rather than collapsing into one.
    /// </summary>
    [TestMethod]
    public async Task RefuseNotValidNamesTheRefusedCredentialsByTheirCredentialQueryIdentifiers()
    {
        CredentialQueryId lowerCaseId = new("pid");
        CredentialQueryId upperCaseId = new("PID");

        Dictionary<CredentialQueryId, CredentialStatusOutcome> statuses = new()
        {
            [lowerCaseId] = await ReadOutcomeAsync(StatusTypes.Invalid).ConfigureAwait(false),
            [upperCaseId] = await ReadOutcomeAsync(StatusTypes.Suspended).ConfigureAwait(false)
        };

        CredentialStatusRefusal? refusal = CredentialStatusPolicies.RefuseNotValid(statuses);

        Assert.IsNotNull(refusal, "Both credentials read not valid, so the policy refuses.");
        Assert.HasCount(2, refusal.Credentials,
            "Two identifiers that differ only in case are two Section 6.1 identifiers, so both are refused.");
        Assert.AreEqual(lowerCaseId, refusal.Credentials[0].CredentialQueryId,
            "The refusal names the refused credential by the identifier that keyed its outcome.");
        Assert.AreEqual(upperCaseId, refusal.Credentials[1].CredentialQueryId,
            "The second refused credential is named by its own identifier, never by the first one's.");
    }


    /// <summary>
    /// The relying party's own detail is composed for the log and the failed flow state, and
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">OpenID for
    /// Verifiable Presentations 1.0, Section 6.1</see> defines the credential query identifier as "a non-empty
    /// string consisting of alphanumeric, underscore (_), or hyphen (-) characters". The composition therefore
    /// reads that string itself — the value the Verifier put in its DCQL query and the Wallet keyed the
    /// <c>vp_token</c> by — rather than any decoration around it.
    /// </summary>
    [TestMethod]
    public async Task RefusalDescriptionNamesTheCredentialQueryIdentifierByItsValue()
    {
        CredentialStatusOutcome outcome = await ReadOutcomeAsync(StatusTypes.Invalid).ConfigureAwait(false);

        CredentialStatusRefusal refusal = new()
        {
            Credentials =
            [
                new RefusedCredentialStatus { CredentialQueryId = new CredentialQueryId("pid"), Outcome = outcome }
            ]
        };

        Assert.AreEqual(
            "credential_status_not_valid: credential query 'pid' reads status 0x01 (revoked)",
            refusal.Description,
            "The composed detail names the credential query by the Section 6.1 string the query carried.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18">SD-JWT VC</see>: "If
    /// status is present in the verified payload of the SD-JWT, the status SHOULD be checked.  Verifier policy
    /// decides whether to reject or accept a presentation of a SD-JWT VC based on the status of the Verifiable
    /// Digital Credential." <see cref="CredentialStatusPolicies.Surface"/> is the deciding policy that accepts,
    /// and it accepts whatever the credentials are keyed by: a map naming several
    /// <see cref="CredentialQueryId"/> values, each reading not valid, still yields no refusal.
    /// </summary>
    [TestMethod]
    public async Task SurfaceRefusesNoCredentialHoweverManyIdentifiersTheMapNames()
    {
        Dictionary<CredentialQueryId, CredentialStatusOutcome> statuses = new()
        {
            [new CredentialQueryId("pid")] = await ReadOutcomeAsync(StatusTypes.Invalid).ConfigureAwait(false),
            [new CredentialQueryId("PID")] = await ReadOutcomeAsync(StatusTypes.Suspended).ConfigureAwait(false),
            [new CredentialQueryId("mdl-2")] = await ReadOutcomeAsync(StatusTypes.ApplicationSpecific0F).ConfigureAwait(false)
        };

        CredentialStatusRefusal? refusal = CredentialStatusPolicies.Surface(statuses);

        Assert.IsNull(refusal,
            "Surface is the policy that accepts, so no credential it is handed is ever refused, whichever " +
            "credential query identifier keys it.");
    }


    /// <summary>
    /// Reads the outcome <see cref="CredentialStatusGate"/> produces for a credential whose status list entry
    /// carries <paramref name="status"/>, so a policy under test judges an outcome a verifier really read rather
    /// than a hand-set one. The list is eight bits per entry so every
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1">Section 7.1</see>
    /// value, application-specific ones included, is representable.
    /// </summary>
    /// <param name="status">The Section 7.1 status value written at <see cref="CredentialIndex"/>.</param>
    /// <param name="timeToLive">The token's <c>ttl</c> claim in seconds, or <see langword="null"/> for none.</param>
    /// <param name="resolvedAt">
    /// The instant the caller's cache resolved the token, or <see langword="null"/> when the resolver always
    /// fetches fresh.
    /// </param>
    /// <returns>The gate's outcome for that credential.</returns>
    private async ValueTask<CredentialStatusOutcome> ReadOutcomeAsync(
        byte status,
        long? timeToLive = null,
        DateTimeOffset? resolvedAt = null)
    {
        using StatusListType list = StatusListType.Create(
            ListCapacity, StatusListBitSize.EightBits, Pool, BitOrder.LeastSignificantFirst);
        list[CredentialIndex] = status;

        StatusListToken token = new(ListUri, Now, list) { TimeToLive = timeToLive };

        return await CredentialStatusGate.CheckAsync(
            StatusListFixtures.ContextFor(CredentialIndex, ListUri),
            StatusListFixtures.ResolverFor(token, resolvedAt ?? Now),
            Now,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }
}
