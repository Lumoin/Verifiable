using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The Token Status List <c>status</c> claim an SD-CWT (<c>dc+sd-cwt</c>) credential carries under CWT
/// claim key 65535, read back through <see cref="SdCwtVpTokenVerification.VerifyAsync"/> at the parse
/// boundary and driven through the OID4VP verifier seat over the real wire — the SD-CWT counterpart of
/// <see cref="MdocVpTokenVerificationStatusTests"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token
/// Status List, Section 6.3</see> states the Referenced Token "MAY be encoded as a "CBOR Web Token
/// (CWT)" object according to [RFC8392], as an SD-CWTs [I-D.ietf-spice-sd-cwt] or as an ISO mdoc
/// according to [ISO.mdoc] or other formats based on COSE", and "If the Referenced Token is a CWT, the
/// following content applies to the CWT Claims Set: 65535 (status): REQUIRED. The status claim contains
/// the Status CBOR structure as described in this section." The wallet side issues through
/// <see cref="SdCwtVpFixture.IssueSdCwtTokenAsync(FakeTimeProvider, PrivateKeyMemory, PublicKeyMemory, IReadOnlyDictionary{string, object}, System.Threading.CancellationToken)"/>
/// and signs a Key Binding Token; the verifier side receives nothing but the base64url <c>vp_token</c>
/// value, so every value asserted here travelled as CBOR and was decoded from it.
/// </para>
/// <para>
/// <see cref="SdCwtVpVerificationSeams.ExtractStatus"/> is a required member: a seam set composed
/// without it does not compile, so no deployment of this seat can silently skip the status read that
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Section
/// 8.3</see>'s step 1 asks for. <see cref="SdCwtVpFixture.BuildSeams"/> wires it to the
/// <c>Verifiable.Cbor.Sd</c> extraction, which
/// <see cref="TheWiredSeamsReadTheStatusClaimFromTheIssuedCredential"/> proves by invoking the seam.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SdCwtVpTokenVerificationStatusTests
{
    /// <summary>The ambient MSTest context, supplying the cancellation token this class's flows run under.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The clock every host, credential and status list in this class shares.</summary>
    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2026, 5, 26, 12, 0, 0, TimeSpan.Zero));

    /// <summary>The Verifier's <c>client_id</c> for the registrations in this class.</summary>
    private const string VerifierClientId = "https://verifier.example.com";

    /// <summary>The Verifier identifier the parse-boundary Key Binding Tokens bind to as <c>aud</c>.</summary>
    private const string VerifierAud = "https://verifier.example.com/response";

    /// <summary>The Verifier nonce the parse-boundary Key Binding Tokens bind to as <c>cnonce</c>.</summary>
    private const string Cnonce = "n-vptoken-cwt-status-01";

    /// <summary>The Status List Token URI every status-bearing credential in this class references.</summary>
    private const string StatusListUri = "https://issuer.example/statuslists/1";

    /// <summary>The Status List index every status-bearing credential in this class references.</summary>
    private const int CredentialIndex = 42;

    /// <summary>Entry capacity of the status lists these tests build.</summary>
    private const int StatusListCapacity = 64;

    /// <summary>The identifier the <c>identifier_list</c> mechanism's own member carries.</summary>
    private const string IdentifierListEntry = "d7d1c0f0";

    /// <summary>The pool every buffer in this class is rented from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary><see cref="VerifierClientId"/> as the <see cref="Uri"/> a verifier registration requires.</summary>
    private static Uri VerifierBaseUri { get; } = new("https://verifier.example.com");

    /// <summary>The DCQL credential query every presentation in this class answers, as the typed identifier.</summary>
    private static CredentialQueryId EmployeeCwtQueryId { get; } =
        new(SdCwtVpFixture.EmployeeCwtCredentialQueryId);

    /// <summary>The capabilities a Verifier host must advertise to serve the OID4VP flow.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token
    /// Status List, Section 6.3</see>: "status_list (status list): REQUIRED when the status mechanism
    /// defined in this specification is used. It has the same definition as the status_list claim in
    /// Section 6.2 but MUST be encoded as a StatusListInfo CBOR structure with the following fields:
    /// idx: REQUIRED. Unsigned integer (major type 0). The idx (index) claim MUST specify a non-negative
    /// Integer that represents the index to check for status information in the Status List for the
    /// current Referenced Token. uri: REQUIRED. Text string (major type 3). The uri (URI) claim MUST
    /// specify a String value that identifies the Status List Token containing the status information for
    /// the Referenced Token." An SD-CWT issued with that structure under CWT claim key 65535 presents
    /// both fields unchanged to the verifier, alongside the one mechanism the issuer named.
    /// </summary>
    [TestMethod]
    public async Task AStatusListStatusClaimSurfacesItsIndexAndUri()
    {
        VpTokenParsed parsed = await ParseStatusPresentationAsync(
            SdCwtWireFixtures.BuildStatusWithStatusList(CredentialIndex, StatusListUri)).ConfigureAwait(false);

        Assert.IsNotNull(parsed.Credential.Status,
            "Section 6.3's Status structure rides CWT claim key 65535, so the verifier must surface a status claim.");
        Assert.IsNotNull(parsed.Credential.Status!.StatusList,
            "Section 6.3: the status_list mechanism's StatusListInfo must decode into a resolvable reference.");
        Assert.AreEqual(CredentialIndex, parsed.Credential.Status.StatusList!.Value.Index,
            "Section 6.3: idx is REQUIRED and must reach the verifier as the issued non-negative index.");
        Assert.AreEqual(StatusListUri, parsed.Credential.Status.StatusList!.Value.Uri,
            "Section 6.3: uri is REQUIRED and must reach the verifier as the issued Status List Token URI.");
        Assert.HasCount(1, parsed.Credential.Status.Mechanisms,
            "The Status structure named exactly one mechanism, so exactly one is surfaced.");
        Assert.Contains(StatusMechanismNames.StatusList, parsed.Credential.Status.Mechanisms,
            "Section 6.3 keys each data item by \"the identifier of the status mechanism\", which the verifier records by name.");

        Assert.IsTrue(parsed.CredentialSignatureValid,
            "A well-formed presentation must still verify: the status claim changes neither the issuer signature nor the digest binding.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token
    /// Status List, Section 6.3</see>: "The Status CBOR structure is a Map that MUST include at least one
    /// data item that refers to a status mechanism. Each data item in the Status CBOR structure comprises
    /// a key-value pair, where the key MUST be a CBOR text string (major type 3) specifying the identifier
    /// of the status mechanism and the corresponding value defines its contents." A structure naming only
    /// <c>identifier_list</c> — a mechanism this library records by name and does not evaluate — carries
    /// no <c>status_list</c> entry, so the claim surfaces with its mechanism named and no reference,
    /// which is what separates "a status was stated but cannot be evaluated here" from "no status at all".
    /// </summary>
    [TestMethod]
    public async Task AnIdentifierListOnlyStatusClaimSurfacesItsMechanismWithoutAReference()
    {
        VpTokenParsed parsed = await ParseStatusPresentationAsync(
            SdCwtWireFixtures.BuildStatusWithIdentifierList(IdentifierListEntry)).ConfigureAwait(false);

        Assert.IsNotNull(parsed.Credential.Status,
            "identifier_list is a status mechanism the issuer stated, so the credential carries a status claim.");
        Assert.IsNull(parsed.Credential.Status!.StatusList,
            "identifier_list carries no status_list mechanism, so there is no reference the verifier can resolve.");
        Assert.HasCount(1, parsed.Credential.Status.Mechanisms,
            "The Status structure named exactly one mechanism, so exactly one is surfaced.");
        Assert.Contains(StatusMechanismNames.IdentifierList, parsed.Credential.Status.Mechanisms,
            "The mechanism the issuer named must reach the verifier by name so the relying party can evaluate it out of band.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>, the first evaluation step: "Check for the existence of a status
    /// claim, check for the existence of a status_list claim within the status claim and validate that
    /// the content of status_list adheres to the rules defined in Section 6.2 for JOSE-based Referenced
    /// Tokens and Section 6.3 for COSE-based Referenced Tokens." CWT claim key 65535 is optional in a
    /// Referenced Token that references no Status List, so an SD-CWT issued without it must surface no
    /// claim — the state from which a verifier concludes there is nothing to check.
    /// </summary>
    [TestMethod]
    public async Task AnSdCwtWithoutTheStatusClaimSurfacesNoClaim()
    {
        VpTokenParsed parsed = await ParseStatusPresentationAsync(status: null).ConfigureAwait(false);

        Assert.IsNull(parsed.Credential.Status,
            "Section 8.3 step 1 checks for the existence of the status claim: a credential carrying none must surface none.");
        Assert.IsTrue(parsed.CredentialSignatureValid,
            "The absent status claim must not disturb the issuer signature or the digest binding.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token
    /// Status List, Section 6.3</see>: "The Status CBOR structure is a Map that MUST include at least one
    /// data item that refers to a status mechanism." A structure with no data item states nothing at all,
    /// so the verifier refuses it as a malformed presentation rather than reading it as a credential that
    /// references no Status List.
    /// </summary>
    [TestMethod]
    public async Task AStatusStructureWithNoMechanismIsRefusedAtTheParseBoundary()
    {
        FormatException refusal = await Assert.ThrowsExactlyAsync<FormatException>(
            async () => await ParseStatusPresentationAsync(
                SdCwtWireFixtures.BuildStatusWithNoMechanism()).ConfigureAwait(false),
            "Section 6.3's \"MUST include at least one data item\" makes an empty Status structure malformed, " +
            "which the parse boundary reports as a format failure rather than as an absent status.").ConfigureAwait(false);

        Assert.IsNotNull(refusal.Message,
            "The malformed status structure is reported with a message the seat can log.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token
    /// Status List, Section 6.3</see>: "idx: REQUIRED. Unsigned integer (major type 0). The idx (index)
    /// claim MUST specify a non-negative Integer that represents the index to check for status information
    /// in the Status List for the current Referenced Token." An <c>idx</c> encoded as a text string is
    /// outside that value domain, so the StatusListInfo does not decode and the presentation is malformed.
    /// </summary>
    [TestMethod]
    public async Task AStatusListIndexEncodedAsATextStringIsRefusedAtTheParseBoundary()
    {
        _ = await Assert.ThrowsExactlyAsync<FormatException>(
            async () => await ParseStatusPresentationAsync(
                SdCwtWireFixtures.BuildStatusWithRawStatusList("42", StatusListUri)).ConfigureAwait(false),
            "Section 6.3 requires idx to be an unsigned integer (major type 0); a text string leaves that " +
            "value domain and must not be coerced into an index.").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token
    /// Status List, Section 6.3</see>: "uri: REQUIRED. Text string (major type 3). The uri (URI) claim
    /// MUST specify a String value that identifies the Status List Token containing the status information
    /// for the Referenced Token. The value of uri MUST be a URI conforming to [RFC3986]." A value that is
    /// not such a URI identifies no Status List Token, so the StatusListInfo does not decode.
    /// </summary>
    [TestMethod]
    public async Task AStatusListUriThatIsNotAConformingUriIsRefusedAtTheParseBoundary()
    {
        _ = await Assert.ThrowsExactlyAsync<FormatException>(
            async () => await ParseStatusPresentationAsync(
                SdCwtWireFixtures.BuildStatusWithRawStatusList(CredentialIndex, "not a uri")).ConfigureAwait(false),
            "Section 6.3 requires uri to be a URI conforming to RFC 3986; a value that is not one cannot " +
            "identify a Status List Token and must not be carried as if it did.").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>: "1. Check for the existence of a status claim, check for the
    /// existence of a status_list claim within the status claim ... 2. Resolve the Status List Token from
    /// the provided URI ... 7. Check the status value as described in Section 7." An SD-CWT whose status
    /// claim carries a resolvable <c>status_list</c> reference is checked on the OID4VP seat like the
    /// other two credential formats, and the value read is surfaced on the verified state so the relying
    /// party never re-parses the verified <c>vp_token</c> to learn it.
    /// </summary>
    [TestMethod]
    public async Task AResolvableStatusListEntryIsCheckedAndSurfacedOnTheVerifiedState()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate resolver, Func<int> invocationCount) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        StatusFlowOutcome outcome = await DriveFlowAsync(
            SdCwtWireFixtures.BuildStatusWithStatusList(CredentialIndex, StatusListUri),
            UnsupportedStatusMechanismDisposition.Refuse,
            resolver,
            credentialStatusPolicy: null,
            "nonce-sdcwt-status-valid").ConfigureAwait(false);

        Assert.IsNull(outcome.RefusalDetail,
            "The entry reads 0x00 VALID, so the Response URI answers OID4VP 1.0 Section 8.2's success.");
        Assert.IsInstanceOfType<PresentationVerifiedState>(outcome.State,
            "A presentation whose credential status was determined and accepted reaches the verified terminal state.");
        var verified = (PresentationVerifiedState)outcome.State;

        Assert.AreEqual(1, invocationCount(),
            "Section 8.3 step 2 resolves the Status List Token from the provided URI exactly once for the one status claim presented.");
        Assert.IsNotNull(verified.CredentialStatuses,
            "The outcome the verifier read is surfaced on the verified state.");
        Assert.IsTrue(verified.CredentialStatuses![EmployeeCwtQueryId].IsValid,
            "Section 7.1: an unset entry reads 0x00 VALID, so the credential the SD-CWT presented is valid.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1">Token
    /// Status List, Section 7.1</see>: "0x01 - "INVALID" - The status of the Referenced Token is revoked,
    /// annulled, taken back, rescinded or otherwise cancelled." A relying party that wired
    /// <see cref="CredentialStatusPolicies.RefuseNotValid"/> refuses such a presentation, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>
    /// answers as <c>access_denied</c> ("The resource owner or authorization server denied the request.")
    /// with HTTP 400 — never as a Verifier fault, and never as the <c>invalid_request</c> an undeterminable
    /// status draws.
    /// </summary>
    [TestMethod]
    public async Task ARevokedCredentialIsRefusedAsAccessDeniedUnderTheRefusingPolicy()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        statusList[CredentialIndex] = StatusTypes.Invalid;

        StatusFlowOutcome outcome = await DriveFlowAsync(
            SdCwtWireFixtures.BuildStatusWithStatusList(CredentialIndex, StatusListUri),
            UnsupportedStatusMechanismDisposition.Refuse,
            StatusListFixtures.ResolverFor(StatusListUri, statusList, TimeProvider),
            CredentialStatusPolicies.RefuseNotValid,
            "nonce-sdcwt-status-revoked").ConfigureAwait(false);

        Assert.IsNotNull(outcome.RefusalDetail,
            "A refused presentation is answered as a non-200 Response URI answer the wallet reports.");
        Assert.Contains("returned status 400", outcome.RefusalDetail!, StringComparison.Ordinal,
            "RFC 6749 Section 4.1.2.1's error shape is answered as HTTP 400, not as an HTTP 500 Verifier fault.");

        (string wireError, string _) = OAuthErrorAssertions.ReadOAuthErrorBody(outcome.RefusalDetail!);
        Assert.AreEqual(OAuthErrors.AccessDenied, wireError,
            "RFC 6749 Section 4.1.2.1's access_denied is the code for a request the relying party denied.");

        Assert.IsInstanceOfType<VerifierFlowFailedState>(outcome.State,
            "The refused presentation leaves the verifier's flow in its failed terminal state.");
        var failed = (VerifierFlowFailedState)outcome.State;

        Assert.AreEqual(VerifierFlowRefusalKind.PolicyRefused, failed.Refusal!.Value.Kind,
            "A relying-party policy refusal over a determined status is the refusal kind that answers access_denied.");
        Assert.IsNotNull(failed.CredentialStatusRefusal,
            "The detail the wire withholds rides the failed state as the typed credential-status refusal.");
        Assert.HasCount(1, failed.CredentialStatusRefusal!.Credentials,
            "One credential was presented and its entry read 0x01 INVALID, so exactly one credential is refused.");
        Assert.AreEqual(EmployeeCwtQueryId, failed.CredentialStatusRefusal.Credentials[0].CredentialQueryId,
            "The typed refusal names the revoked credential by the credential query it answered.");
        Assert.AreEqual(StatusTypes.Invalid, failed.CredentialStatusRefusal.Credentials[0].Outcome.Status,
            "The typed refusal carries the raw Section 7.1 status value the gate read.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>, closing: "If any of these checks fails, no statement about the
    /// status of the Referenced Token can be made and the Referenced Token SHOULD be rejected." A status
    /// claim naming only <c>identifier_list</c> makes no statement this verifier can evaluate, so the seat
    /// rejects it by default, answered as
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>invalid_request</c> ("The request is missing a required parameter, includes an invalid parameter
    /// value, includes a parameter more than once, or is otherwise malformed.") with HTTP 400. Nothing is
    /// resolved: Section 8.3's step 2 has no URI to resolve from, so the status resolver is never called.
    /// </summary>
    [TestMethod]
    public async Task AnIdentifierListOnlyStatusIsRefusedAsInvalidRequestAndResolvesNoStatusList()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate resolver, Func<int> invocationCount) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        StatusFlowOutcome outcome = await DriveFlowAsync(
            SdCwtWireFixtures.BuildStatusWithIdentifierList(IdentifierListEntry),
            UnsupportedStatusMechanismDisposition.Refuse,
            resolver,
            credentialStatusPolicy: null,
            "nonce-sdcwt-status-identifier-list").ConfigureAwait(false);

        Assert.IsNotNull(outcome.RefusalDetail,
            "A status no statement can be made about is rejected, which the Response URI answers as a non-200.");
        Assert.Contains("returned status 400", outcome.RefusalDetail!, StringComparison.Ordinal,
            "RFC 6749 Section 4.1.2.1's error shape is answered as HTTP 400, not as an HTTP 500 Verifier fault.");

        (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(outcome.RefusalDetail!);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "An undeterminable credential status is invalid_request, not the access_denied a policy refusal answers.");

        Assert.IsInstanceOfType<VerifierFlowFailedState>(outcome.State,
            "The rejected presentation leaves the verifier's flow in its failed terminal state.");
        var failed = (VerifierFlowFailedState)outcome.State;

        Assert.AreEqual(VerifierFlowRefusalKind.StatusUndeterminable, failed.Refusal!.Value.Kind,
            "A status claim naming only mechanisms the verifier does not evaluate is the undeterminable refusal kind.");
        Assert.AreEqual(failed.Refusal!.Value.Description, wireDescription,
            "The wire carries the typed refusal's one fixed, generic sentence.");
        Assert.DoesNotContain(SdCwtVpFixture.EmployeeCwtCredentialQueryId, wireDescription, StringComparison.Ordinal,
            "OID4VP 1.0 Section 15.9 keeps the credential query out of the wire description.");
        Assert.DoesNotContain(StatusMechanismNames.IdentifierList, wireDescription, StringComparison.Ordinal,
            "OID4VP 1.0 Section 15.9 keeps the mechanism the issuer named out of the wire description.");

        Assert.Contains(SdCwtVpFixture.EmployeeCwtCredentialQueryId, failed.Reason, StringComparison.Ordinal,
            "The log-only reason names the credential query the wire description does not.");
        Assert.Contains(StatusMechanismNames.IdentifierList, failed.Reason, StringComparison.Ordinal,
            "The log-only reason names the mechanism the issuer stated, so an operator can see why no statement could be made.");

        Assert.AreEqual(0, invocationCount(),
            "Section 8.3 step 2 resolves from a provided URI; a claim naming no status_list provides none, so nothing is fetched.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>, closing: "If any of these checks fails, no statement about the
    /// status of the Referenced Token can be made and the Referenced Token SHOULD be rejected." SHOULD,
    /// not MUST — a relying party that evaluates the named mechanism out of band chooses
    /// <see cref="UnsupportedStatusMechanismDisposition.Surface"/> instead, and the presentation stands
    /// with the mechanism set surfaced on the verified state and no status outcome recorded, because none
    /// was determined.
    /// </summary>
    [TestMethod]
    public async Task AnIdentifierListOnlyStatusReachesTheVerifiedStateWhenSurfacingIsChosen()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate resolver, Func<int> invocationCount) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        StatusFlowOutcome outcome = await DriveFlowAsync(
            SdCwtWireFixtures.BuildStatusWithIdentifierList(IdentifierListEntry),
            UnsupportedStatusMechanismDisposition.Surface,
            resolver,
            credentialStatusPolicy: null,
            "nonce-sdcwt-status-surface").ConfigureAwait(false);

        Assert.IsNull(outcome.RefusalDetail,
            "The SHOULD admits a relying party that evaluates the mechanism itself, so the Response URI answers the success.");
        Assert.IsInstanceOfType<PresentationVerifiedState>(outcome.State,
            "A presentation whose unevaluable status the relying party chose to surface reaches the verified terminal state.");
        var verified = (PresentationVerifiedState)outcome.State;

        Assert.IsTrue(verified.Credentials.TryGetValue(EmployeeCwtQueryId, out VpCredentialClaims? credential),
            "The verified credentials are keyed by the DCQL credential query identifier the vp_token is keyed by.");
        Assert.IsNotNull(credential!.Status,
            "The status the issuer stated is surfaced so the relying party can evaluate the mechanism out of band.");
        Assert.IsNull(credential.Status!.StatusList,
            "identifier_list carries no status_list mechanism, so there is no reference on the surfaced claim.");
        Assert.HasCount(1, credential.Status.Mechanisms,
            "The Status structure named exactly one mechanism, so exactly one is surfaced.");
        Assert.Contains(StatusMechanismNames.IdentifierList, credential.Status.Mechanisms,
            "The surfaced mechanism is the one the issuer named, by name.");

        Assert.IsNull(verified.CredentialStatuses,
            "No status value was determined for any presented credential, so no outcome is recorded.");
        Assert.AreEqual(0, invocationCount(),
            "Surfacing an unevaluable status resolves nothing: Section 8.3 step 2 has no URI to resolve from.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>, step 1: "Check for the existence of a status claim, check for the
    /// existence of a status_list claim within the status claim and validate that the content of
    /// status_list adheres to the rules defined in Section 6.2 for JOSE-based Referenced Tokens and
    /// Section 6.3 for COSE-based Referenced Tokens." A present-but-malformed Status structure fails that
    /// check as a wallet-attributable malformation, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>
    /// answers as <c>invalid_request</c> with HTTP 400 under the Malformed refusal class — the presentation
    /// could not be parsed, so no status question is reached at all.
    /// </summary>
    [TestMethod]
    public async Task AMalformedStatusStructureIsRefusedAsAMalformedPresentation()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        StatusFlowOutcome outcome = await DriveFlowAsync(
            SdCwtWireFixtures.BuildStatusWithNoMechanism(),
            UnsupportedStatusMechanismDisposition.Refuse,
            StatusListFixtures.ResolverFor(StatusListUri, statusList, TimeProvider),
            credentialStatusPolicy: null,
            "nonce-sdcwt-status-malformed").ConfigureAwait(false);

        Assert.IsNotNull(outcome.RefusalDetail,
            "A malformed status structure is refused, which the Response URI answers as a non-200.");
        Assert.Contains("returned status 400", outcome.RefusalDetail!, StringComparison.Ordinal,
            "RFC 6749 Section 4.1.2.1's error shape is answered as HTTP 400, not as an HTTP 500 Verifier fault.");

        (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(outcome.RefusalDetail!);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "RFC 6749 Section 4.1.2.1: an otherwise malformed request is invalid_request.");

        Assert.IsInstanceOfType<VerifierFlowFailedState>(outcome.State,
            "The refused presentation leaves the verifier's flow in its failed terminal state.");
        var failed = (VerifierFlowFailedState)outcome.State;

        Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
            "A Status structure that does not adhere to Section 6.3 is a malformed presentation, not an undeterminable status.");
        Assert.AreEqual(failed.Refusal!.Value.Description, wireDescription,
            "The wire carries the typed refusal's one fixed, generic sentence.");
        Assert.DoesNotContain(SdCwtVpFixture.EmployeeCwtCredentialQueryId, wireDescription, StringComparison.Ordinal,
            "OID4VP 1.0 Section 15.9 keeps the credential query out of the wire description.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>, step 1: "Check for the existence of a status claim, check for the
    /// existence of a status_list claim within the status claim and validate that the content of
    /// status_list adheres to the rules defined in Section 6.2 for JOSE-based Referenced Tokens and
    /// Section 6.3 for COSE-based Referenced Tokens." The seat performs that step through
    /// <see cref="SdCwtVpVerificationSeams.ExtractStatus"/>, so the seam the application composes is what
    /// decides whether the step happens at all: the wired seam reads the Status structure out of the
    /// issuer-signed claims of the credential the wallet holds.
    /// </summary>
    [TestMethod]
    public async Task TheWiredSeamsReadTheStatusClaimFromTheIssuedCredential()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            using SdToken<ReadOnlyMemory<byte>> issued = await SdCwtVpFixture.IssueSdCwtTokenAsync(
                TimeProvider,
                issuerKeys.PrivateKey,
                holderKeys.PublicKey,
                SdCwtWireFixtures.BuildStatusWithStatusList(CredentialIndex, StatusListUri),
                TestContext.CancellationToken).ConfigureAwait(false);

            SdCwtVpVerificationSeams seams = SdCwtVpFixture.BuildSeams(issuerKeys.PublicKey);

            StatusClaim? claim = seams.ExtractStatus(issued);

            Assert.IsNotNull(claim,
                "The wired extraction must read CWT claim key 65535 out of the issuer-signed claims, or Section 8.3 step 1 never runs.");
            Assert.IsNotNull(claim!.StatusList,
                "Section 6.3's status_list mechanism must decode into the reference the status step resolves.");
            Assert.AreEqual(CredentialIndex, claim.StatusList!.Value.Index,
                "The seam must read the issued idx unchanged.");
            Assert.AreEqual(StatusListUri, claim.StatusList!.Value.Uri,
                "The seam must read the issued uri unchanged.");
        }
        finally
        {
            issuerKeys.PublicKey.Dispose();
            issuerKeys.PrivateKey.Dispose();
            holderKeys.PublicKey.Dispose();
            holderKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Parse boundary: issues an SD-CWT carrying <paramref name="status"/>, has the wallet select the
    /// queried claims and sign a Key Binding Token, and runs
    /// <see cref="SdCwtVpTokenVerification.VerifyAsync"/> over nothing but the resulting base64url
    /// <c>vp_token</c> value, with the seams
    /// <see cref="HaipOid4VpVerifierExecutor"/> dispatches <c>dc+sd-cwt</c> through.
    /// </summary>
    /// <param name="status">The Status structure the issuer states, or <see langword="null"/> for none.</param>
    /// <returns>The parsed presentation.</returns>
    private async ValueTask<VpTokenParsed> ParseStatusPresentationAsync(IReadOnlyDictionary<string, object>? status)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            using SdToken<ReadOnlyMemory<byte>> issued = await SdCwtVpFixture.IssueSdCwtTokenAsync(
                TimeProvider,
                issuerKeys.PrivateKey,
                holderKeys.PublicKey,
                status,
                TestContext.CancellationToken).ConfigureAwait(false);

            string vpTokenValue = await SdCwtVpFixture.ProduceVpTokenValueAsync(
                issued,
                holderKeys.PrivateKey,
                VerifierAud,
                Cnonce,
                TimeProvider.GetUtcNow(),
                TestContext.CancellationToken).ConfigureAwait(false);

            return await SdCwtVpTokenVerification.VerifyAsync(
                vpTokenValue,
                EmployeeCwtQueryId,
                SdCwtVpFixture.BuildSeams(issuerKeys.PublicKey),
                TestSetup.Base64UrlDecoder,
                saltReuseSeam: null,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            issuerKeys.PublicKey.Dispose();
            issuerKeys.PrivateKey.Dispose();
            holderKeys.PublicKey.Dispose();
            holderKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Drives the OID4VP verifier through PAR, the wallet's HTTP GET of the JAR, and the
    /// <c>direct_post</c> of the SD-CWT presentation over the in-process listener, with the host wired to
    /// the supplied status resolver, credential-status policy and unsupported-mechanism disposition. Only
    /// the compact JAR (in) and the encrypted response (out) cross the party boundary.
    /// </summary>
    /// <param name="status">The Status structure the issued credential carries, or <see langword="null"/> for none.</param>
    /// <param name="unsupportedStatusMechanisms">The relying party's disposition toward a status naming no mechanism this verifier evaluates.</param>
    /// <param name="resolveVerifiedStatusListToken">The resolver standing in for whatever the deployment fetched and verified.</param>
    /// <param name="credentialStatusPolicy">The relying party's policy over determined outcomes, or <see langword="null"/> for the shipped default.</param>
    /// <param name="nonceValue">The Authorization Request nonce this flow runs under.</param>
    /// <returns>The verifier's terminal flow state and the refusal detail a non-200 answer carried.</returns>
    private async Task<StatusFlowOutcome> DriveFlowAsync(
        IReadOnlyDictionary<string, object>? status,
        UnsupportedStatusMechanismDisposition unsupportedStatusMechanisms,
        ResolveVerifiedStatusListTokenDelegate resolveVerifiedStatusListToken,
        CredentialStatusPolicy? credentialStatusPolicy,
        string nonceValue)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            SdCwtVpVerificationSeams seams = SdCwtVpFixture.BuildSeams(issuerKeys.PublicKey);

            await using TestHostShell app = new(
                TimeProvider,
                sdCwtSeams: seams,
                resolveVerifiedStatusListToken: resolveVerifiedStatusListToken,
                credentialStatusPolicy: credentialStatusPolicy,
                unsupportedStatusMechanisms: unsupportedStatusMechanisms);

            using VerifierKeyMaterial verifierKeys = app.RegisterClient(
                VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

            using SdToken<ReadOnlyMemory<byte>> issued = await SdCwtVpFixture.IssueSdCwtTokenAsync(
                TimeProvider,
                issuerKeys.PrivateKey,
                holderKeys.PublicKey,
                status,
                TestContext.CancellationToken).ConfigureAwait(false);

            //Building the HTTP-backed wallet first starts the listener and aligns the verifier
            //registration's IssuerUri and ResponseUri to it, so the request_uri PAR generates and the
            //response_uri inside the JAR both point at the running listener.
            Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                SdCwtVpFixture.BuildSdCwtProduceDelegate(issued, holderKeys.PrivateKey),
                TestHostShell.PinnedVerifierKeyResolver(verifierKeys.SigningPublicKey),
                TestContext.CancellationToken).ConfigureAwait(false);

            (Uri requestUri, string parHandle) = await app.HandleParAsync(
                verifierKeys,
                new TransactionNonce(nonceValue),
                SdCwtVpFixture.BuildSdCwtPreparedQuery(),
                TestContext.CancellationToken).ConfigureAwait(false);

            using HttpResponseMessage jarResponse = await app.Host("default").SharedHttpClient!
                .GetAsync(requestUri, TestContext.CancellationToken).ConfigureAwait(false);
            jarResponse.EnsureSuccessStatusCode();
            string compactJar = await jarResponse.Content
                .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

            string? refusalDetail = null;
            try
            {
                _ = await walletClient.PresentJarAsync(
                    new PresentJarOptions
                    {
                        CompactJar = compactJar,
                        RequestUri = requestUri,
                        ExpectedVerifierClientId = VerifierClientId,
                        FlowId = $"wallet-sdcwt-status-{Guid.NewGuid():N}"
                    },
                    TestContext.CancellationToken).ConfigureAwait(false);
            }
            catch(InvalidOperationException exception)
            {
                //A refused presentation is a non-200 direct_post answer; the wallet client throws and its
                //message carries the HTTP status and the RFC 6749 Section 4.1.2.1 body the verifier answered.
                refusalDetail = exception.Message;
            }

            return new StatusFlowOutcome(app.GetFlowState(parHandle).State, refusalDetail);
        }
        finally
        {
            issuerKeys.PublicKey.Dispose();
            issuerKeys.PrivateKey.Dispose();
            holderKeys.PublicKey.Dispose();
            holderKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// What one driven flow answered: the verifier's terminal state and, when the Response URI refused,
    /// the detail the wallet client reported for it.
    /// </summary>
    /// <param name="State">The verifier's terminal flow state.</param>
    /// <param name="RefusalDetail">The refusal detail of a non-200 answer, or <see langword="null"/> on success.</param>
    private sealed record StatusFlowOutcome(FlowState State, string? RefusalDetail);
}
