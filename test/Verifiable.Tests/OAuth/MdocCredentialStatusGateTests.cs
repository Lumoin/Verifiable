using System.Buffers;
using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Oid4Vp.Wallet.States;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The IETF Token Status List gate as it runs for an ISO mdoc (<c>mso_mdoc</c>) presentation on the OID4VP
/// verifier seat, driven end to end over the in-process listener: a real issuer mints a PID mdoc whose Mobile
/// Security Object references a Status List entry, the toy wallet device-signs and presents it, and the
/// verifier reads that entry, surfaces the outcome, or refuses the presentation.
/// </summary>
/// <remarks>
/// <para>
/// The mdoc twin of <see cref="Oid4VpFlowIntegrationTests.ExecutorSurfacesCredentialStatusOnPresentationVerified"/>
/// and of <see cref="Oid4VpCredentialStatusPolicyFlowTests"/>, which prove the same gate over
/// <c>dc+sd-jwt</c> on the same wire. The gate itself is one implementation for every credential format: the
/// entry reaches it as the presentation's status reference, so what these tests pin is that an
/// <c>mso_mdoc</c> presentation reaches it at all, and that the answers — surfaced, refused, undeterminable,
/// unchecked — are the ones the format-agnostic step already gives.
/// </para>
/// <para>
/// The status structure the MSO carries is the one
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token Status
/// List, Section 6.3</see> defines for Referenced Tokens in CBOR: "The Status CBOR structure is a Map that
/// MUST include at least one data item that refers to a status mechanism." The second edition of
/// ISO/IEC 18013-5, under ballot as ISO/IEC DIS 18013-5 (expected publication 2026-11-30), places that
/// structure on the MSO under the text string key <c>status</c>, carrying the MSO's revocation information;
/// the entry's own shape (<c>idx</c>, <c>uri</c>) is Section 6.3's.
/// </para>
/// <para>
/// Every credential here is minted through <see cref="MdocVpFixture.IssueAsync"/>, presented through
/// <see cref="MdocVpFixture.BuildMdocProduceDelegate"/> against
/// <see cref="MdocVpFixture.BuildMdocPreparedQuery"/>, and driven through <see cref="TestHostShell"/>, so the
/// presentations are the ones the sibling mdoc flow tests present.
/// </para>
/// </remarks>
[TestClass]
internal sealed class MdocCredentialStatusGateTests
{
    /// <summary>The ambient MSTest context, supplying the cancellation token this class's flows run under.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock every host, credential and status list in this class shares.</summary>
    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    /// <summary>The Verifier's client identifier, as registered on the host.</summary>
    private const string VerifierClientId = "https://verifier.example.com";

    /// <summary>The Verifier's base URI, from which its endpoint paths are composed.</summary>
    private static Uri VerifierBaseUri { get; } = new("https://verifier.example.com");

    /// <summary>
    /// The DCQL credential query identifier <see cref="MdocVpFixture.BuildMdocPreparedQuery"/> asks the PID
    /// under, and therefore the key the verifier records this presentation's status outcome against.
    /// </summary>
    private const string MdocCredentialQueryId = "pid";

    /// <summary>The Status List Token URI every status-bearing MSO in this class references.</summary>
    private const string StatusListUri = "https://issuer.example/statuslists/1";

    /// <summary>Entry capacity of the status lists these tests build.</summary>
    private const int StatusListCapacity = 64;

    /// <summary>The pool every buffer in this class is rented from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The capabilities a Verifier host must advertise to serve the OID4VP flow.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1">Token Status
    /// List, Section 7.1</see>: "0x00 - "VALID" - The status of the Referenced Token is valid, correct or legal."
    /// An <c>mso_mdoc</c> presentation whose Mobile Security Object references an entry reading that value stands,
    /// and the outcome the verifier read is surfaced on the verified state under the DCQL credential query the
    /// mdoc answered, so the relying party never re-parses the verified <c>vp_token</c> to learn it. Reaching that
    /// outcome means the verifier took
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> step 2, "Resolve the Status List Token from the provided URI", for this
    /// presentation — the positive control for the tests below that require it never to be taken.
    /// </summary>
    [TestMethod]
    public async Task AnMdocWhoseStatusEntryReadsValidVerifiesAndSurfacesTheOutcome()
    {
        const int credentialIndex = 17;

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate resolver, Func<int> invocationCount) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using FormatRun run = await StartMdocRunAsync(
            new StatusListReference(credentialIndex, StatusListUri),
            resolver,
            credentialStatusPolicy: null).ConfigureAwait(false);

        (string parHandle, PresentationResult? result, string? refusalMessage) = await PresentAsync(
            run, run.Produce, "nonce-mdoc-status-valid").ConfigureAwait(false);

        Assert.IsNull(refusalMessage,
            "The entry reads 0x00 VALID, so the Response URI answers the OID4VP 1.0 Section 8.2 success.");
        Assert.IsInstanceOfType<ResponseSent>(result!.TerminalState,
            "The wallet reaches its ResponseSent terminal once the Response URI answers 200.");

        PresentationVerifiedState verified = ReadVerifiedState(run.App, parHandle);
        run.AssertClaims(verified);

        Assert.IsNotNull(verified.CredentialStatuses,
            "An mdoc whose MSO carries a status structure is checked, so the outcome is surfaced.");
        Assert.IsTrue(
            verified.CredentialStatuses!.TryGetValue(new CredentialQueryId(MdocCredentialQueryId), out CredentialStatusOutcome? outcome),
            "The surfaced outcomes are keyed by the DCQL credential query identifier the mdoc answered.");
        Assert.IsTrue(outcome!.IsValid,
            "Section 7.1 reads an unset entry as 0x00 VALID, under which the credential still stands.");
        Assert.AreEqual(StatusTypes.Valid, outcome.Status,
            "The surfaced outcome carries the raw Section 7.1 status value the gate read.");
        Assert.AreEqual(1, invocationCount(),
            "Section 8.3 step 2 resolves the Status List Token from the provided URI once for the one status "
            + "structure the presented Mobile Security Object carries.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1">Token Status
    /// List, Section 7.1</see>: "0x01 - "INVALID" - The status of the Referenced Token is revoked, annulled, taken
    /// back, recalled or cancelled." Under the shipped default policy the relying party decides for itself what a
    /// determinable not-valid status means, so an <c>mso_mdoc</c> presentation whose entry reads that value still
    /// verifies and the outcome is surfaced for the relying party to act on — the mdoc twin of
    /// <see cref="Oid4VpFlowIntegrationTests.ExecutorSurfacesCredentialStatusOnPresentationVerified"/>.
    /// </summary>
    [TestMethod]
    public async Task AnMdocWhoseStatusEntryReadsInvalidStillVerifiesUnderTheDefaultPolicy()
    {
        const int credentialIndex = 18;

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        statusList[credentialIndex] = StatusTypes.Invalid;

        //No policy is wired, so the seat runs the shipped default: surface every determinable outcome and
        //refuse none of them.
        await using FormatRun run = await StartMdocRunAsync(
            new StatusListReference(credentialIndex, StatusListUri),
            StatusListFixtures.ResolverFor(StatusListUri, statusList, TimeProvider),
            credentialStatusPolicy: null).ConfigureAwait(false);

        (string parHandle, PresentationResult? result, string? refusalMessage) = await PresentAsync(
            run, run.Produce, "nonce-mdoc-status-revoked").ConfigureAwait(false);

        Assert.IsNull(refusalMessage,
            "The default policy refuses nothing, so the Response URI answers the OID4VP 1.0 Section 8.2 success.");
        Assert.IsInstanceOfType<ResponseSent>(result!.TerminalState,
            "The wallet reaches its ResponseSent terminal once the Response URI answers 200.");

        PresentationVerifiedState verified = ReadVerifiedState(run.App, parHandle);

        Assert.IsNotNull(verified.CredentialStatuses,
            "A determinable not-valid status is surfaced, never silently dropped.");
        Assert.IsTrue(
            verified.CredentialStatuses!.TryGetValue(new CredentialQueryId(MdocCredentialQueryId), out CredentialStatusOutcome? outcome),
            "The surfaced outcomes are keyed by the DCQL credential query identifier the mdoc answered.");
        Assert.IsFalse(outcome!.IsValid,
            "Section 7.1 reads 0x01 INVALID as a status under which the Referenced Token is not valid.");
        Assert.AreEqual(StatusTypes.Invalid, outcome.Status,
            "The surfaced outcome carries the raw Section 7.1 status value the gate read.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1">Token Status
    /// List, Section 7.1</see>'s "0x01 - "INVALID" - The status of the Referenced Token is revoked, annulled, taken
    /// back, recalled or cancelled." is a status a deployment may refuse on. When it does, the Response URI answers
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>access_denied</c> — "The resource owner or authorization server denied the request." — as an HTTP 400
    /// body, and
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 15.9</see>'s "Error responses SHOULD avoid including sensitive or detailed
    /// contextual information that could be used to infer the End-User's data." keeps the credential query, the
    /// raw status value and the not-valid state it read off the wire; that detail rides the failed flow state.
    /// </summary>
    [TestMethod]
    public async Task AnMdocWhoseStatusEntryReadsInvalidIsRefusedAsAccessDeniedUnderTheRefusingPolicy()
    {
        const int credentialIndex = 19;

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        statusList[credentialIndex] = StatusTypes.Invalid;

        await using FormatRun run = await StartMdocRunAsync(
            new StatusListReference(credentialIndex, StatusListUri),
            StatusListFixtures.ResolverFor(StatusListUri, statusList, TimeProvider),
            CredentialStatusPolicies.RefuseNotValid).ConfigureAwait(false);

        (string parHandle, PresentationResult? _, string? refusalMessage) = await PresentAsync(
            run, run.Produce, "nonce-mdoc-status-policy-refused").ConfigureAwait(false);

        Assert.IsNotNull(refusalMessage,
            "A policy that refuses a not-valid status makes the Response URI answer a non-200, which the wallet raises.");
        OAuthErrorAssertions.AssertWireStatusCode(400, refusalMessage!,
            "RFC 6749 Section 4.1.2.1: a relying party's denial of a presentation is answered as HTTP 400, never 500.");

        (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(refusalMessage!);
        Assert.AreEqual(OAuthErrors.AccessDenied, wireError,
            "RFC 6749 Section 4.1.2.1's access_denied is the code for a request the relying party denied.");
        AssertDescriptionCarriesNoEndUserDetail(wireDescription);

        VerifierFlowFailedState failed = ReadFailedState(run.App, parHandle);
        Assert.AreEqual(VerifierFlowRefusalKind.PolicyRefused, failed.Refusal!.Value.Kind,
            "A relying-party policy refusal is the refusal class that answers access_denied.");
        Assert.AreEqual(OAuthErrors.AccessDenied, failed.Refusal!.Value.ErrorCode,
            "The typed refusal selects the RFC 6749 Section 4.1.2.1 code the wire carries.");

        Assert.IsNotNull(failed.CredentialStatusRefusal,
            "The detail the wire withholds rides the failed state as the typed credential-status refusal.");
        Assert.HasCount(1, failed.CredentialStatusRefusal!.Credentials,
            "One credential was presented and its entry read not valid, so exactly one is named.");
        Assert.AreEqual(MdocCredentialQueryId, failed.CredentialStatusRefusal.Credentials[0].CredentialQueryId.Value,
            "The typed refusal names the mdoc by the credential query it answered.");
        Assert.AreEqual(StatusTypes.Invalid, failed.CredentialStatusRefusal.Credentials[0].Outcome.Status,
            "The typed refusal carries the raw Section 7.1 status value the wire description does not.");
        Assert.AreEqual(CredentialStatusDisposition.Revoked,
            failed.CredentialStatusRefusal.Credentials[0].Disposition,
            "Section 7.1 reads 0x01 INVALID as revoked.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> step 6: "If the provided index is out of bounds of the Status List, no statement
    /// about the status of the Referenced Token can be made and the Referenced Token MUST be rejected." An
    /// <c>mso_mdoc</c> presentation whose Mobile Security Object names such an index fails closed: the Response URI
    /// answers RFC 6749, Section 4.1.2.1's <c>invalid_request</c> as an HTTP 400 body and the verifier's terminal
    /// state carries the typed <see cref="VerifierFlowRefusalKind.StatusUndeterminable"/>.
    /// </summary>
    [TestMethod]
    public async Task AnMdocWhoseStatusIndexLiesBeyondTheListIsRefusedAsInvalidRequest()
    {
        const int outOfBoundsIndex = 999;

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        await using FormatRun run = await StartMdocRunAsync(
            new StatusListReference(outOfBoundsIndex, StatusListUri),
            StatusListFixtures.ResolverFor(StatusListUri, statusList, TimeProvider),
            credentialStatusPolicy: null).ConfigureAwait(false);

        (string parHandle, PresentationResult? _, string? refusalMessage) = await PresentAsync(
            run, run.Produce, "nonce-mdoc-status-undeterminable").ConfigureAwait(false);

        Assert.IsNotNull(refusalMessage,
            "An undeterminable status fails closed, so the Response URI answers a non-200 the wallet raises.");
        OAuthErrorAssertions.AssertWireStatusCode(400, refusalMessage!,
            "RFC 6749 Section 4.1.2.1: a status no statement can be made about is answered as HTTP 400, never 500.");

        (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(refusalMessage!);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "An undeterminable status is not a pass, so it is answered invalid_request like any other unverifiable presentation.");
        AssertDescriptionCarriesNoEndUserDetail(wireDescription);

        VerifierFlowFailedState failed = ReadFailedState(run.App, parHandle);
        Assert.AreEqual(VerifierFlowRefusalKind.StatusUndeterminable, failed.Refusal!.Value.Kind,
            "An index outside the Status List leaves the status undeterminable, which is the verifier's own rejection.");
        Assert.IsNull(failed.CredentialStatusRefusal,
            "The typed credential-status refusal is a policy's product; an undeterminable status carries none.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> opens its evaluation with step 1, "Check for the existence of a status claim, check
    /// for the existence of a status_list claim within the status claim", and only then step 2, "Resolve the Status
    /// List Token from the provided URI". An <c>mso_mdoc</c> whose Mobile Security Object carries no <c>status</c>
    /// structure has nothing for step 1 to find, so no Status List Token is resolved for it at all and no outcome
    /// is recorded — a verifier that reads status lists does not thereby require every issuer to publish one.
    /// </summary>
    [TestMethod]
    public async Task AnMdocWithNoStatusStructureResolvesNoStatusListAndRecordsNoOutcome()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate resolver, Func<int> invocationCount) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using FormatRun run = await StartMdocRunAsync(
            status: null, resolver, CredentialStatusPolicies.RefuseNotValid).ConfigureAwait(false);

        (string parHandle, PresentationResult? result, string? refusalMessage) = await PresentAsync(
            run, run.Produce, "nonce-mdoc-status-absent").ConfigureAwait(false);

        Assert.IsNull(refusalMessage,
            "An mdoc with no status structure has no status to refuse, so the Response URI answers 200.");
        Assert.IsInstanceOfType<ResponseSent>(result!.TerminalState,
            "The wallet reaches its ResponseSent terminal once the Response URI answers 200.");

        PresentationVerifiedState verified = ReadVerifiedState(run.App, parHandle);
        run.AssertClaims(verified);

        Assert.IsNull(verified.CredentialStatuses,
            "An mdoc whose Mobile Security Object carries no status structure is never an entry in the outcome map.");
        Assert.AreEqual(0, invocationCount(),
            "Step 1 finds no status claim, so step 2 never resolves a Status List Token for this presentation.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see>: "Upon receiving a Referenced Token, a Relying Party MUST first perform the
    /// validation of the Referenced Token - e.g., checking for expected attributes, valid signature and expiration
    /// time." and "If the validation procedures for the Referenced Token determine it is invalid, further
    /// procedures regarding Status List MUST NOT be performed, e.g. fetching a Status List Token, unless the
    /// Referenced Token procedures or the use case require further evaluation." A status-bearing <c>mso_mdoc</c>
    /// presented as a truncated DeviceResponse is rejected on its own processing rules, and no Status List Token is
    /// resolved for it.
    /// </summary>
    [TestMethod]
    public async Task AStatusBearingMdocThatDoesNotItselfVerifyResolvesNoStatusList()
    {
        const int credentialIndex = 20;

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        statusList[credentialIndex] = StatusTypes.Invalid;

        (ResolveVerifiedStatusListTokenDelegate resolver, Func<int> invocationCount) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using FormatRun run = await StartMdocRunAsync(
            new StatusListReference(credentialIndex, StatusListUri),
            resolver,
            CredentialStatusPolicies.RefuseNotValid).ConfigureAwait(false);

        (string parHandle, PresentationResult? _, string? refusalMessage) = await PresentAsync(
            run, TruncateDeviceResponse(run.Produce), "nonce-mdoc-status-unverifiable").ConfigureAwait(false);

        Assert.IsNotNull(refusalMessage,
            "A DeviceResponse the verifier cannot parse is refused, so the Response URI answers a non-200.");
        OAuthErrorAssertions.AssertWireStatusCode(400, refusalMessage!,
            "RFC 6749 Section 4.1.2.1: a truncated DeviceResponse is answered as HTTP 400, not as a verifier fault.");

        (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(refusalMessage!);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "RFC 6749 Section 4.1.2.1: an otherwise malformed request is invalid_request.");
        AssertDescriptionCarriesNoEndUserDetail(wireDescription);

        VerifierFlowFailedState failed = ReadFailedState(run.App, parHandle);
        Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
            "A truncated mso_mdoc DeviceResponse is refused on the Referenced Token's own processing rules.");
        Assert.IsNull(failed.CredentialStatusRefusal,
            "No status was evaluated, so no credential-status refusal was produced.");
        Assert.AreEqual(0, invocationCount(),
            "The Referenced Token's validation determined it invalid, so no Status List Token was fetched.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see>: "If the validation procedures for the Referenced Token determine it is invalid,
    /// further procedures regarding Status List MUST NOT be performed, e.g. fetching a Status List Token, unless
    /// the Referenced Token procedures or the use case require further evaluation." Unlike the truncation row
    /// above, which short-circuits at the parse before verification ever runs, this <c>mso_mdoc</c> parses
    /// cleanly and populates its status reference, then fails only the issuer-auth signature — the verifier
    /// resolves a key that never signed the MSO — so no Status List Token may be resolved for it either.
    /// </summary>
    [TestMethod]
    public async Task AStatusBearingMdocThatFailsItsOwnSignatureVerificationResolvesNoStatusList()
    {
        const int credentialIndex = 23;

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        statusList[credentialIndex] = StatusTypes.Invalid;

        (ResolveVerifiedStatusListTokenDelegate resolver, Func<int> invocationCount) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> strangerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        TestHostShell app = new(
            TimeProvider,
            //Resolves a key that never signed the MSO, so the issuer-auth signature fails: the Referenced
            //Token's own validation, not the status step, determines this presentation invalid.
            mdocSeams: MdocVpFixture.BuildSeams(strangerKeys.PublicKey),
            resolveVerifiedStatusListToken: resolver,
            credentialStatusPolicy: null);

        MdocDocument issued = await MdocVpFixture.IssueAsync(
            issuerKeys, deviceKeys, new StatusListReference(credentialIndex, StatusListUri),
            TestContext.CancellationToken).ConfigureAwait(false);

        await using FormatRun run = new()
        {
            App = app,
            Query = MdocVpFixture.BuildMdocPreparedQuery(),
            Produce = MdocVpFixture.BuildMdocProduceDelegate(issued, deviceKeys.PrivateKey),
            AssertClaims = AssertDisclosedPidClaims,
            Owned =
            [
                issued,
                issuerKeys.PublicKey, issuerKeys.PrivateKey,
                deviceKeys.PublicKey, deviceKeys.PrivateKey,
                strangerKeys.PublicKey, strangerKeys.PrivateKey
            ]
        };

        (string parHandle, PresentationResult? _, string? refusalMessage) = await PresentAsync(
            run, run.Produce, "nonce-mdoc-status-unverifiable-signature").ConfigureAwait(false);

        Assert.IsNotNull(refusalMessage,
            "An mdoc whose issuer-auth signature does not verify is refused, so the Response URI answers a non-200.");
        OAuthErrorAssertions.AssertWireStatusCode(400, refusalMessage!,
            "RFC 6749 Section 4.1.2.1: a Referenced Token that fails its own validation is answered as HTTP 400.");

        (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(refusalMessage!);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "RFC 6749 Section 4.1.2.1: an unverifiable presentation is answered invalid_request.");
        AssertDescriptionCarriesNoEndUserDetail(wireDescription);

        VerifierFlowFailedState failed = ReadFailedState(run.App, parHandle);
        Assert.AreEqual(VerifierFlowRefusalKind.Unverifiable, failed.Refusal!.Value.Kind,
            "A parsed mdoc whose own signature fails to verify is refused as Unverifiable — distinct from the " +
            "Malformed row above, which never reaches a parsed MSO at all.");
        Assert.IsNull(failed.CredentialStatusRefusal,
            "No status was evaluated, so no credential-status refusal was produced.");
        Assert.AreEqual(0, invocationCount(),
            "Section 8.3's MUST NOT: the Referenced Token's own validation determined it invalid, so no Status " +
            "List Token was resolved for it.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> requires steps its verifier cannot take without a way to obtain the Status List
    /// Token — step 2, "Resolve the Status List Token from the provided URI". A deployment that verifies
    /// <c>mso_mdoc</c> presentations whose issuer gated validity on a status list, but wired no resolver to read
    /// it, has a configuration fault rather than a wire answer: the Response URI answers HTTP 500 with no
    /// RFC 6749, Section 4.1.2.1 error object, the verifier's flow takes no terminal refusal, and the presentation
    /// is not accepted. Silently reading the unreadable status as valid would be the security gap. The
    /// <c>dc+sd-jwt</c> twin is
    /// <see cref="Oid4VpFlowIntegrationTests.ExecutorFailsClosedWhenCredentialReferencesStatusListButNoResolverWired"/>.
    /// </summary>
    [TestMethod]
    public async Task AStatusBearingMdocIsNotAcceptedWhenNoStatusResolverIsWired()
    {
        const int credentialIndex = 21;

        await using FormatRun run = await StartMdocRunAsync(
            new StatusListReference(credentialIndex, StatusListUri),
            resolveVerifiedStatusListToken: null,
            credentialStatusPolicy: null).ConfigureAwait(false);

        (string parHandle, PresentationResult? result, string? refusalMessage) = await PresentAsync(
            run, run.Produce, "nonce-mdoc-status-no-resolver").ConfigureAwait(false);

        Assert.IsNull(result,
            "A configuration fault is not an answer the wallet can complete its presentation against.");
        Assert.IsNotNull(refusalMessage,
            "The verifier fails closed, so the wallet sees the failure rather than a 200.");
        OAuthErrorAssertions.AssertWireStatusCode(500, refusalMessage!,
            "A verifier the deployment did not wire a status resolver into faults on its own configuration; the "
            + "endpoint answers the state it cannot classify, not a refusal it composed.");
        Assert.DoesNotContain("returned status 400", refusalMessage!, StringComparison.Ordinal,
            "A configuration fault is not an RFC 6749 Section 4.1.2.1 refusal the wallet is told to act on.");

        FlowState state = run.App.GetFlowState(parHandle).State;
        Assert.IsNotInstanceOfType<PresentationVerifiedState>(state,
            "An mdoc whose issuer gated its validity on a status list the verifier cannot read must not be accepted.");
        Assert.IsNotInstanceOfType<VerifierFlowFailedState>(state,
            "The flow takes no terminal refusal for a fault the verifier never classified as one.");
    }


    /// <summary>
    /// Starts one mdoc run: a fresh issuer and device key pair, a host wired with the <c>mso_mdoc</c> verification
    /// seams plus the supplied status resolver and relying-party policy, and a PID mdoc issued under
    /// <paramref name="status"/>. Host construction and issuance are fused because the seams bind the issuer key
    /// the host resolves out of band, which must therefore exist first.
    /// </summary>
    /// <param name="status">The Status List entry the issued MSO references, or <see langword="null"/> for none.</param>
    /// <param name="resolveVerifiedStatusListToken">The verified Status List Token resolver the seat reads through, or <see langword="null"/> for none.</param>
    /// <param name="credentialStatusPolicy">The relying party's policy over the read outcomes, or <see langword="null"/> for the shipped default.</param>
    /// <returns>The run, owning the host and every key and credential it allocated.</returns>
    private async ValueTask<FormatRun> StartMdocRunAsync(
        StatusListReference? status,
        ResolveVerifiedStatusListTokenDelegate? resolveVerifiedStatusListToken,
        CredentialStatusPolicy? credentialStatusPolicy)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        TestHostShell? app = null;

        try
        {
            app = new TestHostShell(
                TimeProvider,
                mdocSeams: MdocVpFixture.BuildSeams(issuerKeys.PublicKey),
                resolveVerifiedStatusListToken: resolveVerifiedStatusListToken,
                credentialStatusPolicy: credentialStatusPolicy);

            MdocDocument issued = await MdocVpFixture.IssueAsync(
                issuerKeys, deviceKeys, status, TestContext.CancellationToken).ConfigureAwait(false);

            return new FormatRun
            {
                App = app,
                Query = MdocVpFixture.BuildMdocPreparedQuery(),
                Produce = MdocVpFixture.BuildMdocProduceDelegate(issued, deviceKeys.PrivateKey),
                AssertClaims = AssertDisclosedPidClaims,
                //The issuer key resolver clones the public key per call, so the source must outlive verification;
                //the device key drives the presentation. The host owns neither, so the run disposes both pairs.
                Owned =
                [
                    issued,
                    issuerKeys.PublicKey, issuerKeys.PrivateKey,
                    deviceKeys.PublicKey, deviceKeys.PrivateKey
                ]
            };
        }
        catch
        {
            //Issuance can throw after the host and both key pairs already exist; none of them has a
            //FormatRun to own them yet, so this path disposes all three itself before rethrowing.
            if(app is not null)
            {
                await app.DisposeAsync().ConfigureAwait(false);
            }

            issuerKeys.PublicKey.Dispose();
            issuerKeys.PrivateKey.Dispose();
            deviceKeys.PublicKey.Dispose();
            deviceKeys.PrivateKey.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Asserts the disclosed PID claims the DCQL query asked for round-trip through the flow, and that the
    /// element the query did not ask for stays withheld.
    /// </summary>
    /// <param name="verified">The verifier's terminal verified state.</param>
    private static void AssertDisclosedPidClaims(PresentationVerifiedState verified)
    {
        Assert.IsTrue(verified.Credentials.TryGetValue(new CredentialQueryId(MdocCredentialQueryId),
            out VpCredentialClaims? credential),
            "Verified credentials are keyed by the DCQL credential query identifier.");
        IReadOnlyDictionary<CredentialPath, string> claims = credential!.Extracted;

        CredentialPath familyNamePath =
            CredentialPath.Root.Append(EudiPid.Mdoc.Namespace).Append(EudiPid.Mdoc.FamilyName);
        CredentialPath birthDatePath =
            CredentialPath.Root.Append(EudiPid.Mdoc.Namespace).Append(EudiPid.Mdoc.BirthDate);

        Assert.AreEqual("Mustermann", claims[familyNamePath],
            "The disclosed family_name must round-trip through the full flow.");
        Assert.IsFalse(claims.ContainsKey(birthDatePath),
            "The query asks for no birth_date, so element-level trimming must withhold it.");
    }


    /// <summary>
    /// Wraps a presentation drop-out so the assembled DeviceResponse it returns is cut to half its byte length —
    /// a well-formed base64url wrapping of malformed CBOR content, which is a shape no conformant wallet produces
    /// and which the verifier rejects on the presentation's own processing rules.
    /// </summary>
    /// <param name="produce">The drop-out producing the valid presentation.</param>
    /// <returns>The wrapping drop-out.</returns>
    private static ProduceVpTokenPresentationsDelegate TruncateDeviceResponse(
        ProduceVpTokenPresentationsDelegate produce)
    {
        return async (context, cancellationToken) =>
        {
            Oid4VpPresentationSet valid = await produce(context, cancellationToken).ConfigureAwait(false);

            using IMemoryOwner<byte> deviceResponseBytes = Oid4VpMdocPresentation.DecodeVpTokenValue(
                valid.PresentationsByQueryId[MdocCredentialQueryId], TestSetup.Base64UrlDecoder, context.MemoryPool);
            string truncated = TestSetup.Base64UrlEncoder(
                deviceResponseBytes.Memory.Span[..(deviceResponseBytes.Memory.Length / 2)]);

            return new Oid4VpPresentationSet
            {
                PresentationsByQueryId =
                    new Dictionary<string, string>(valid.PresentationsByQueryId, StringComparer.Ordinal)
                    {
                        [MdocCredentialQueryId] = truncated
                    },
                ResponseEncryptionApu = valid.ResponseEncryptionApu
            };
        };
    }


    /// <summary>
    /// Drives one full cross-device mdoc presentation over the in-process listener: the verifier's PAR, the
    /// wallet's HTTP GET of the JAR, and the wallet's encrypted <c>direct_post.jwt</c> POST to the Response URI.
    /// mdoc binds its SessionTranscript to the wallet's <c>mdoc_generated_nonce</c> riding the response JWE's
    /// <c>apu</c>, so the encrypted cross-device flow is the one an mdoc presentation runs.
    /// </summary>
    /// <param name="run">The run whose host, query and owned material the presentation uses.</param>
    /// <param name="produce">The presentation drop-out the wallet answers the request with.</param>
    /// <param name="nonce">The transaction nonce binding the presentation to this request.</param>
    /// <returns>
    /// The flow's external handle, the wallet's result when the Response URI answered 200, and the wallet-side
    /// detail of a non-200 answer otherwise.
    /// </returns>
    private async ValueTask<(string ParHandle, PresentationResult? Result, string? RefusalMessage)> PresentAsync(
        FormatRun run,
        ProduceVpTokenPresentationsDelegate produce,
        string nonce)
    {
        TestHostShell app = run.App;
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        //Building the HTTP-backed wallet starts the listener and aligns the registration's Response URI onto
        //its base address, so the request_uri PAR generates and the response_uri inside the JAR both point at
        //the listener the wallet posts to.
        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys,
            produce,
            TestHostShell.PinnedVerifierKeyResolver(verifierKeys.SigningPublicKey),
            TestContext.CancellationToken).ConfigureAwait(false);

        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys, new TransactionNonce(nonce), run.Query, TestContext.CancellationToken)
            .ConfigureAwait(false);

        using HttpResponseMessage jarResponse = await app.Host("default").SharedHttpClient!
            .GetAsync(requestUri, TestContext.CancellationToken).ConfigureAwait(false);
        jarResponse.EnsureSuccessStatusCode();
        string compactJar = await jarResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PresentationResult? result = null;
        string? refusalMessage = null;
        try
        {
            result = await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = compactJar,
                    RequestUri = requestUri,
                    ExpectedVerifierClientId = VerifierClientId,
                    FlowId = $"wallet-{nonce}-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException exception)
        {
            //The Response URI answered a non-200, or failed closed on a fault it does not report as one; the
            //wallet client raises what it read.
            refusalMessage = exception.Message;
        }

        return (parHandle, result, refusalMessage);
    }


    /// <summary>
    /// Asserts a wire <c>error_description</c> discloses none of the contextual detail OID4VP 1.0, Section 15.9
    /// keeps out of an error response.
    /// </summary>
    /// <param name="description">The description the Response URI wrote.</param>
    private static void AssertDescriptionCarriesNoEndUserDetail(string description)
    {
        Assert.IsFalse(string.IsNullOrWhiteSpace(description),
            "RFC 6749 Section 4.1.2.1's error_description is the human-readable text a refused client reads.");
        Assert.DoesNotContain(MdocCredentialQueryId, description, StringComparison.OrdinalIgnoreCase,
            "OID4VP 1.0 Section 15.9 keeps the credential query out of the wire description.");
        Assert.DoesNotContain("0x01", description, StringComparison.Ordinal,
            "OID4VP 1.0 Section 15.9 keeps the raw status value out of the wire description.");
        Assert.DoesNotContain("revoked", description, StringComparison.OrdinalIgnoreCase,
            "OID4VP 1.0 Section 15.9 keeps which not-valid state was read out of the wire description.");
        Assert.DoesNotContain("suspended", description, StringComparison.OrdinalIgnoreCase,
            "OID4VP 1.0 Section 15.9 keeps which not-valid state was read out of the wire description.");
    }


    /// <summary>Reads the verifier's terminal verified state for <paramref name="parHandle"/>.</summary>
    /// <param name="app">The verifier host the flow ran against.</param>
    /// <param name="parHandle">The flow's <c>state</c> handle.</param>
    /// <returns>The terminal verified state.</returns>
    private static PresentationVerifiedState ReadVerifiedState(TestHostShell app, string parHandle)
    {
        FlowState state = app.GetFlowState(parHandle).State;

        Assert.IsInstanceOfType<PresentationVerifiedState>(state,
            "A presentation the verifier accepts leaves its flow in the verified terminal state.");

        return (PresentationVerifiedState)state;
    }


    /// <summary>Reads the verifier's terminal failure state for <paramref name="parHandle"/>.</summary>
    /// <param name="app">The verifier host the flow ran against.</param>
    /// <param name="parHandle">The flow's <c>state</c> handle.</param>
    /// <returns>The terminal failure state carrying the typed refusal.</returns>
    private static VerifierFlowFailedState ReadFailedState(TestHostShell app, string parHandle)
    {
        FlowState state = app.GetFlowState(parHandle).State;

        Assert.IsInstanceOfType<VerifierFlowFailedState>(state,
            "A refused presentation leaves the verifier's flow in its terminal failure state.");

        var failed = (VerifierFlowFailedState)state;
        Assert.IsNotNull(failed.Refusal,
            "A refusal the Response URI answers as RFC 6749 Section 4.1.2.1 carries its typed classification.");

        return failed;
    }
}
