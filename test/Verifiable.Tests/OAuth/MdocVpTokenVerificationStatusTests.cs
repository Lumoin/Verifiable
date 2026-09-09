using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using Lumoin.Veritas.Cbor;
using System.Net.Http;
using Verifiable.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.MdocTestFixtures;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The Token Status List reference an ISO mdoc's Mobile Security Object carries, read back through
/// <see cref="MdocVpTokenVerification.VerifyAsync"/> — the seam
/// <see cref="HaipOid4VpVerifierExecutor"/> dispatches <c>mso_mdoc</c> vp_tokens through.
/// </summary>
/// <remarks>
/// <para>
/// The wallet side issues through <see cref="MdocVpFixture.IssueAsync"/> and assembles a
/// DeviceResponse; the verifier side receives nothing but the base64url vp_token string and the
/// transmitted <c>mdoc_generated_nonce</c>, so every value asserted here travelled the wire as CBOR
/// and was decoded from it. The parsed surface is
/// <see cref="VpCredentialClaims.Status"/>, taken from the MSO's optional <c>status</c> member.
/// </para>
/// <para>
/// The structure inside that member is
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token
/// Status List, Section 6.3</see>: "The Status CBOR structure is a Map that MUST include at least one
/// data item that refers to a status mechanism. Each data item in the Status CBOR structure comprises
/// a key-value pair, where the key MUST be a CBOR text string (major type 3) specifying the identifier
/// of the status mechanism and the corresponding value defines its contents." The second edition of
/// ISO/IEC 18013-5 (ISO/IEC DIS 18013-5, expected 2026-11-30) places that structure on the
/// MobileSecurityObject under the text-string key <c>status</c>; the published ISO/IEC 18013-5:2021
/// the six-member MSO was built against carries no such member.
/// </para>
/// <para>
/// The SD-JWT VC twin of this surfacing — the same
/// <see cref="VpCredentialClaims.Status"/> assertion over the JOSE parser — is
/// <see cref="Oid4VpFlowIntegrationTests.SdJwtVcStatusReferenceSurfacesAndDrivesRevocationGate"/>;
/// what the shared status step and the deployment's
/// <see cref="Verifiable.Core.StatusList.CredentialStatusPolicy"/> then do with the reference is
/// proved over the executor in <see cref="Oid4VpCredentialStatusPolicyFlowTests"/>. This class stops
/// at the parse boundary.
/// </para>
/// </remarks>
[TestClass]
internal sealed class MdocVpTokenVerificationStatusTests
{
    /// <summary>The DCQL credential query identifier every presentation in this class answers under.</summary>
    private const string PidCredentialQueryId = "pid";

    /// <summary>The Verifier's <c>client_id</c>, bound into the SessionTranscript every device-signed presentation reconstructs.</summary>
    private const string VerifierClientId = "https://verifier.example/oid4vp/client";

    /// <summary>The Verifier's <c>response_uri</c>, bound into the SessionTranscript alongside <see cref="VerifierClientId"/>.</summary>
    private const string VerifierResponseUri = "https://verifier.example/oid4vp/response";

    /// <summary>The authorization request's <c>nonce</c>, the third SessionTranscript binding value.</summary>
    private const string AuthorizationRequestNonce = "auth-req-nonce-mdoc-status-01";

    /// <summary>The Status List Token URI every status-bearing MSO in this class references.</summary>
    private const string StatusListUri = "https://issuer.example/statuslists/1";

    /// <summary>The Status List index every status-bearing MSO in this class references, other than the index-zero case.</summary>
    private const int CredentialIndex = 42;

    /// <summary>The mDL document type the fixture issues into, matching the sibling reader tests.</summary>
    private const string MdlDocType = "org.iso.18013.5.1.mDL";

    /// <summary>The single namespace the shared <c>valueDigests</c> writer fills.</summary>
    private const string MdlNamespace = "org.iso.18013.5.1";

    /// <summary>The entry an <c>identifier_list</c>-only Mobile Security Object in this class claims.</summary>
    private const string IdentifierListEntryId = "d7d1c0f0";

    /// <summary>The Verifier's <c>client_id</c> as registered on the host the wire cases present to.</summary>
    private const string HostedVerifierClientId = "https://verifier.example.com";

    /// <summary>The Verifier's base URI on that host, from which its endpoint paths are composed.</summary>
    private static Uri HostedVerifierBaseUri { get; } = new("https://verifier.example.com");

    /// <summary>The capabilities a Verifier host must advertise to serve the OID4VP flow.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);

    /// <summary>Entry capacity of the status lists the wire cases build.</summary>
    private const int StatusListCapacity = 64;

    /// <summary>The pool every buffer in this class is rented from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The clock every host and status list in this class shares.</summary>
    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    /// <summary>The ambient MSTest context, supplying the cancellation token this class's flows run under.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token
    /// Status List, Section 6.3</see>: "status_list (status list): REQUIRED when the status mechanism
    /// defined in this specification is used. It has the same definition as the status_list claim in
    /// Section 6.2 but MUST be encoded as a StatusListInfo CBOR structure with the following fields:
    /// idx: REQUIRED. Unsigned integer (major type 0). … uri: REQUIRED. Text string (major type 3). The
    /// uri (URI) claim MUST specify a String value that identifies the Status List Token containing the
    /// status information for the Referenced Token." An mdoc issued with that entry on its MSO — the
    /// placement ISO/IEC DIS 18013-5 gives the text-string key <c>status</c> — presents both fields
    /// unchanged to the verifier, alongside the document's own verdict.
    /// </summary>
    [TestMethod]
    public async Task StatusListEntryOnTheMobileSecurityObjectSurfacesWithItsIndexAndUri()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, string transmittedNonce) = await ProduceVpTokenAsync(
                issuerKeys, deviceKeys, new StatusListReference(CredentialIndex, StatusListUri)).ConfigureAwait(false);

            using IMemoryOwner<byte> nonceOwner = Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                transmittedNonce, TestSetup.Base64UrlDecoder, Pool);

            using MdocVpVerificationResult verification = await VerifyAsync(
                vpTokenValue, MdocVpFixture.TrustAnchorFor(issuerKeys.PublicKey), nonceOwner.Memory).ConfigureAwait(false);
            VpTokenParsed parsed = verification.Parsed;

            Assert.IsNotNull(parsed.Credential.Status?.StatusList,
                "Section 6.3's Status structure is carried on the MSO under the text-string key 'status'; the " +
                "verifier must surface its status_list entry rather than drop it as an unknown member.");
            Assert.AreEqual(CredentialIndex, parsed.Credential.Status!.StatusList!.Value.Index,
                "Section 6.3: idx is REQUIRED and must reach the verifier as the issued non-negative index.");
            Assert.AreEqual(StatusListUri, parsed.Credential.Status.StatusList!.Value.Uri,
                "Section 6.3: uri is REQUIRED and must reach the verifier as the issued Status List Token URI.");

            Assert.IsTrue(parsed.CredentialSignatureValid,
                "A well-formed presentation must still verify: adding the status member changes neither the " +
                "issuer-auth signature nor the MSO digest binding.");
            Assert.IsTrue(parsed.SessionTranscriptValid,
                "A well-formed presentation's device signature over the reconstructed SessionTranscript must hold.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token
    /// Status List, Section 6.3</see>: "idx: REQUIRED. Unsigned integer (major type 0). The idx (index)
    /// claim MUST specify a non-negative Integer that represents the index to check for status
    /// information in the Status List for the current Referenced Token." Zero is a non-negative Integer
    /// and therefore a real entry: an mdoc referencing index 0 must surface a reference whose index is
    /// 0, never be read as a credential that references no Status List at all.
    /// </summary>
    [TestMethod]
    public async Task IndexZeroSurfacesAsAnEntryAndNotAsAnAbsentReference()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, string transmittedNonce) = await ProduceVpTokenAsync(
                issuerKeys, deviceKeys, new StatusListReference(0, StatusListUri)).ConfigureAwait(false);

            using IMemoryOwner<byte> nonceOwner = Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                transmittedNonce, TestSetup.Base64UrlDecoder, Pool);

            using MdocVpVerificationResult verification = await VerifyAsync(
                vpTokenValue, MdocVpFixture.TrustAnchorFor(issuerKeys.PublicKey), nonceOwner.Memory).ConfigureAwait(false);
            VpTokenParsed parsed = verification.Parsed;

            Assert.IsNotNull(parsed.Credential.Status?.StatusList,
                "Section 6.3: idx 0 is a non-negative Integer and a valid entry, so the reference must be present.");
            Assert.AreEqual(0, parsed.Credential.Status!.StatusList!.Value.Index,
                "Section 6.3: the surfaced idx must be the issued index 0, not a defaulted or shifted value.");
            Assert.AreEqual(StatusListUri, parsed.Credential.Status.StatusList!.Value.Uri,
                "Section 6.3: uri is REQUIRED and must accompany idx 0 unchanged.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>, the first evaluation step: "Check for the existence of a status
    /// claim, check for the existence of a status_list claim within the status claim and validate that
    /// the content of status_list adheres to the rules defined in Section 6.2 for JOSE-based Referenced
    /// Tokens and Section 6.3 for COSE-based Referenced Tokens." The <c>status</c> member is optional on
    /// the MSO, so an mdoc issued without one must present no reference at all — the state from which a
    /// verifier concludes there is nothing to check.
    /// </summary>
    [TestMethod]
    public async Task AMobileSecurityObjectWithoutTheStatusMemberSurfacesNoReference()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, string transmittedNonce) =
                await ProduceVpTokenAsync(issuerKeys, deviceKeys, status: null).ConfigureAwait(false);

            using IMemoryOwner<byte> nonceOwner = Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                transmittedNonce, TestSetup.Base64UrlDecoder, Pool);

            using MdocVpVerificationResult verification = await VerifyAsync(
                vpTokenValue, MdocVpFixture.TrustAnchorFor(issuerKeys.PublicKey), nonceOwner.Memory).ConfigureAwait(false);
            VpTokenParsed parsed = verification.Parsed;

            Assert.IsNull(parsed.Credential.Status,
                "Section 8.3 step 1 checks for the existence of the status claim: an MSO carrying no status " +
                "member must surface no claim, so the verifier has nothing to evaluate.");
            Assert.IsTrue(parsed.CredentialSignatureValid,
                "The absent status member must not disturb the issuer-auth signature or the MSO digest binding.");
            Assert.IsTrue(parsed.SessionTranscriptValid,
                "The absent status member must not disturb the device signature over the SessionTranscript.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// The draft EU implementing act amending the EAA implementing regulations states: "When
    /// implementing the identifier list mechanism, the status element shall contain the
    /// identifier_list element as set out in EAA-6.2.10.1-11." Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token
    /// Status List, Section 6.3</see>, <c>identifier_list</c> is a recognised mechanism key whose value
    /// this library does not model, so the Status structure decodes with no <c>status_list</c> entry.
    /// <see cref="VpCredentialClaims.Status"/> therefore surfaces a claim whose
    /// <see cref="StatusClaim.StatusList"/> is <see langword="null"/> while its
    /// <see cref="StatusClaim.Mechanisms"/> names <c>identifier_list</c> — distinguishable from an MSO
    /// carrying no <c>status</c> member at all, which surfaces no claim.
    /// </summary>
    [TestMethod]
    public async Task AnIdentifierListOnlyMobileSecurityObjectSurfacesNoStatusListReference()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        MdocIssuerAuth? issuerAuth = null;

        try
        {
            byte[] msoBytes = BuildMsoWithIdentifierListOnlyStatus();
            byte[] issuerAuthBytes = await SignMsoAsIssuerAuthAsync(msoBytes, issuerKeys.PrivateKey).ConfigureAwait(false);

            issuerAuth = MdocCborIssuerAuthReader.Read(issuerAuthBytes, Pool);

            Assert.IsNotNull(issuerAuth.Mso.Status,
                "identifier_list is a recognised Section 6.3 mechanism key, so the Status structure decodes.");
            Assert.IsNull(issuerAuth.Mso.Status!.StatusList,
                "identifier_list carries no status_list mechanism, so no StatusListInfo decodes.");

            var issuerSigned = new MdocIssuerSignedView(
                new Dictionary<string, IReadOnlyList<MdocIssuerSignedItem>>(StringComparer.Ordinal), issuerAuth);
            using var presented = new MdocPresentationDocument(MdlDocType, issuerSigned);
            using var deviceResponse = new MdocDeviceResponse(
                MdocWellKnownKeys.Version10, [presented], MdocWellKnownKeys.StatusOk);

            string vpTokenValue = Oid4VpMdocPresentation.AssembleVpTokenValue(deviceResponse, TestSetup.Base64UrlEncoder);

            using MdocVpVerificationResult verification = await VerifyAsync(
                vpTokenValue, MdocVpFixture.TrustAnchorFor(issuerKeys.PublicKey), ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            VpTokenParsed parsed = verification.Parsed;

            Assert.IsNotNull(parsed.Credential.Status,
                "identifier_list is a status mechanism the issuer stated, so the credential carries a status claim.");
            Assert.IsNull(parsed.Credential.Status!.StatusList,
                "identifier_list carries no status_list mechanism, so there is no reference the verifier can resolve.");
            Assert.HasCount(1, parsed.Credential.Status.Mechanisms,
                "The Status structure named exactly one mechanism, so exactly one is surfaced.");
            Assert.Contains(StatusMechanismNames.IdentifierList, parsed.Credential.Status.Mechanisms,
                "The mechanism the issuer named must reach the verifier by name, which is what separates " +
                "\"status present but unevaluable here\" from \"no status at all\".");
        }
        finally
        {
            issuerAuth?.Dispose();
            DisposeKeyMaterial(issuerKeys);
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>: "Upon receiving a Referenced Token, a Relying Party MUST first
    /// perform the validation of the Referenced Token - e.g., checking for expected attributes, valid
    /// signature and expiration time." and "If the validation procedures for the Referenced Token
    /// determine it is invalid, further procedures regarding Status List MUST NOT be performed, e.g.
    /// fetching a Status List Token, unless the Referenced Token procedures or the use case require
    /// further evaluation." Parsing is not evaluation: a presentation whose issuer-auth signature and
    /// whose device signature both fail still reports what its MSO said, and reports the failures
    /// beside it, so the ordering can be enforced by whoever decides to fetch the Status List Token.
    /// </summary>
    [TestMethod]
    public async Task AFailedDocumentStillReportsItsReferenceBesideTheFailedVerdicts()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> strangerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, _) = await ProduceVpTokenAsync(
                issuerKeys, deviceKeys, new StatusListReference(CredentialIndex, StatusListUri)).ConfigureAwait(false);

            //A nonce the wallet never signed under reconstructs a different SessionTranscript, so the
            //device signature fails; resolving a key that never signed the MSO fails the issuer-auth
            //signature. Both verdict axes are therefore false for this presentation.
            using IMemoryOwner<byte> strangerNonce = Oid4VpMdocSessionTranscriptEncoder.GenerateMdocGeneratedNonce(
                System.Security.Cryptography.RandomNumberGenerator.Fill, Pool);
            ReadOnlyMemory<byte> strangerNonceMemory =
                strangerNonce.Memory[..Oid4VpMdocSessionTranscriptEncoder.MinimumMdocGeneratedNonceLength];

            using MdocVpVerificationResult verification = await VerifyAsync(
                vpTokenValue, MdocVpFixture.TrustAnchorFor(strangerKeys.PublicKey), strangerNonceMemory).ConfigureAwait(false);
            VpTokenParsed parsed = verification.Parsed;

            Assert.IsFalse(parsed.CredentialSignatureValid,
                "Section 8.3's first validation is the Referenced Token's own: an issuer key that never signed " +
                "the MSO must leave the credential signature invalid.");
            Assert.IsFalse(parsed.SessionTranscriptValid,
                "Section 8.3's first validation is the Referenced Token's own: a SessionTranscript the wallet " +
                "never signed over must leave the device signature invalid.");

            Assert.IsNotNull(parsed.Credential.Status?.StatusList,
                "Reading the MSO's status member is parsing, not status evaluation: the reference must be " +
                "reported so that Section 8.3's ordering — the token's own validation first, the Status List " +
                "Token fetched only afterwards — is decided on complete information.");
            Assert.AreEqual(CredentialIndex, parsed.Credential.Status!.StatusList!.Value.Index,
                "Section 6.3: the reported idx must be the issued index even when the document's verdicts fail.");
            Assert.AreEqual(StatusListUri, parsed.Credential.Status.StatusList!.Value.Uri,
                "Section 6.3: the reported uri must be the issued URI even when the document's verdicts fail.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
            DisposeKeyMaterial(strangerKeys);
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see> closing: "If any of these checks fails, no statement about the status of
    /// the Referenced Token can be made and the Referenced Token SHOULD be rejected." Step 1's check reads the
    /// Status structure "for COSE-based Referenced Tokens" per Section 6.3, so an MSO naming only
    /// <c>identifier_list</c> passes the existence check and fails the <c>status_list</c> one: presented over
    /// the wire, the mdoc is rejected as
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>invalid_request</c> with HTTP 400, the same answer the <c>dc+sd-jwt</c> seat gives the same shape,
    /// and never as the Verifier-side fault a missing status resolver would be.
    /// </summary>
    [TestMethod]
    public async Task AnIdentifierListOnlyMobileSecurityObjectIsRefusedOverTheWire()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            using StatusListType statusList = StatusListType.Create(
                StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

            (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
                StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

            using MdocDocument issued = await IssueWithIdentifierListOnlyStatusAsync(issuerKeys, deviceKeys)
                .ConfigureAwait(false);

            await using TestHostShell app = new(
                TimeProvider,
                mdocSeams: MdocVpFixture.BuildSeams(issuerKeys.PublicKey),
                resolveVerifiedStatusListToken: countingResolver);

            (string parHandle, string? refusalDetail) = await PresentOverTheWireAsync(
                app, issued, deviceKeys.PrivateKey, "nonce-mdoc-identifier-list-refused").ConfigureAwait(false);

            Assert.IsNotNull(refusalDetail,
                "No statement about the mdoc's status can be made, so the Response URI answers a non-200.");
            Assert.Contains("returned status 400", refusalDetail!, StringComparison.Ordinal,
                "RFC 6749 Section 4.1.2.1's error vocabulary is answered as HTTP 400, never as a 500 fault.");
            Assert.Contains($"\"{OAuthErrors.InvalidRequest}\"", refusalDetail!, StringComparison.Ordinal,
                "A presentation whose status cannot be determined rides invalid_request, never access_denied.");

            Assert.IsInstanceOfType<VerifierFlowFailedState>(app.GetFlowState(parHandle).State,
                "An mdoc whose status structure names no mechanism this verifier evaluates fails closed.");
            var failed = (VerifierFlowFailedState)app.GetFlowState(parHandle).State;

            Assert.AreEqual(VerifierFlowRefusalKind.StatusUndeterminable, failed.Refusal!.Value.Kind,
                "A Status structure the verifier cannot evaluate is the same undeterminable rejection an "
                + "unreadable Status List Token is.");
            Assert.Contains(StatusMechanismNames.IdentifierList, failed.Reason, StringComparison.Ordinal,
                "The mechanism the issuer stated rides the flow state's reason, which is where the detail "
                + "OID4VP 1.0 Section 15.9 keeps off the wire belongs.");
            Assert.AreEqual(0, resolverInvocations(),
                "Step 1 finds no status_list within the Status structure, so step 2's resolution never runs.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// Section 8.3's closing rejection is a SHOULD, so a relying party that evaluates the named mechanism out
    /// of band may accept the presentation and then read what the issuer stated. Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token
    /// Status List, Section 6.3</see>: "Each data item in the Status CBOR structure comprises a key-value
    /// pair, where the key MUST be a CBOR text string (major type 3) specifying the identifier of the status
    /// mechanism" — that identifier is what reaches the relying party on the verified state, with no
    /// <c>status_list</c> reference beside it and no status outcome recorded, because the verifier evaluated
    /// nothing.
    /// </summary>
    [TestMethod]
    public async Task AnIdentifierListOnlyMobileSecurityObjectIsSurfacedOverTheWireWhenSurfacingIsChosen()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            using StatusListType statusList = StatusListType.Create(
                StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

            (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
                StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

            using MdocDocument issued = await IssueWithIdentifierListOnlyStatusAsync(issuerKeys, deviceKeys)
                .ConfigureAwait(false);

            await using TestHostShell app = new(
                TimeProvider,
                mdocSeams: MdocVpFixture.BuildSeams(issuerKeys.PublicKey),
                resolveVerifiedStatusListToken: countingResolver,
                unsupportedStatusMechanisms: UnsupportedStatusMechanismDisposition.Surface);

            (string parHandle, string? refusalDetail) = await PresentOverTheWireAsync(
                app, issued, deviceKeys.PrivateKey, "nonce-mdoc-identifier-list-surfaced").ConfigureAwait(false);

            Assert.IsNull(refusalDetail,
                "The relying party took the SHOULD's exception, so the Response URI answers the OID4VP 1.0 "
                + "Section 8.2 success.");
            Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State,
                "A presentation the relying party chose to accept reaches the verified terminal state.");
            var verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;

            Assert.IsTrue(verified.Credentials.TryGetValue(
                new CredentialQueryId(PidCredentialQueryId), out VpCredentialClaims? credential),
                "The verified credentials are keyed by the DCQL credential query identifier the mdoc answered.");
            Assert.IsNotNull(credential!.Status,
                "Section 6.3 requires the Status structure to include at least one data item and the issuer "
                + "included one, so the credential carries a status claim.");
            Assert.IsNull(credential.Status!.StatusList,
                "The structure carries no status_list data item, so there is no reference to resolve.");
            Assert.HasCount(1, credential.Status.Mechanisms,
                "The issuer named exactly one mechanism, so exactly one is surfaced.");
            Assert.Contains(StatusMechanismNames.IdentifierList, credential.Status.Mechanisms,
                "The text-string key naming the mechanism reaches the relying party, which is what makes its "
                + "own out-of-band evaluation possible.");
            Assert.IsNull(verified.CredentialStatuses,
                "The verifier evaluated no status, so it records no outcome.");
            Assert.AreEqual(0, resolverInvocations(),
                "Step 2's resolution is for a status_list reference; a structure carrying none reaches no "
                + "resolver.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token
    /// Status List, Section 6.3</see>: "The Status CBOR structure is a Map that MUST include at least one data
    /// item that refers to a status mechanism." An MSO whose <c>status</c> member is an empty map states a
    /// status claim naming nothing, so Section 8.3 step 1's "Check for the existence of a status claim ... and
    /// validate that the content of status_list adheres to the rules defined in ... Section 6.3 for COSE-based
    /// Referenced Tokens" fails on a claim that IS present — a malformed presentation. Presented over the wire
    /// the mdoc is answered with
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>invalid_request</c> at HTTP 400, the same answer the <c>dc+sd-jwt</c> and <c>dc+sd-cwt</c> seats give
    /// their own malformed status claims, and never as a Verifier-side fault.
    /// </summary>
    [TestMethod]
    public async Task AMalformedStatusStructureIsRefusedAsAMalformedPresentationOverTheWire()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            using StatusListType statusList = StatusListType.Create(
                StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

            (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
                StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

            using MdocDocument issued = await IssueWithEmptyStatusStructureAsync(issuerKeys, deviceKeys)
                .ConfigureAwait(false);

            await using TestHostShell app = new(
                TimeProvider,
                mdocSeams: MdocVpFixture.BuildSeams(issuerKeys.PublicKey),
                resolveVerifiedStatusListToken: countingResolver);

            (string parHandle, string? refusalDetail) = await PresentOverTheWireAsync(
                app, issued, deviceKeys.PrivateKey, "nonce-mdoc-empty-status-structure").ConfigureAwait(false);

            Assert.IsNotNull(refusalDetail,
                "Section 6.3: a Status structure naming no mechanism is not a presentation the verifier accepts.");
            Assert.Contains("returned status 400", refusalDetail!, StringComparison.Ordinal,
                "RFC 6749 Section 4.1.2.1's error vocabulary is answered as HTTP 400, never as a 500 fault.");
            Assert.Contains($"\"{OAuthErrors.InvalidRequest}\"", refusalDetail!, StringComparison.Ordinal,
                "Section 4.1.2.1: a malformed vp_token presentation is answered with invalid_request.");

            Assert.IsInstanceOfType<VerifierFlowFailedState>(app.GetFlowState(parHandle).State,
                "An mdoc whose Status structure fails Section 6.3 fails closed.");
            var failed = (VerifierFlowFailedState)app.GetFlowState(parHandle).State;

            Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
                "Section 6.3: a Status structure carrying no data item is a malformed presentation, not a "
                + "status the verifier merely cannot evaluate.");
            Assert.AreEqual(0, resolverInvocations(),
                "The refusal happens at the parse boundary, before any Status List Token would be resolved.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// Wallet side: issues the shared PID mdoc through <see cref="MdocVpFixture.IssueAsync"/> with the
    /// given Status List entry, device-signs it over a fresh OID4VP SessionTranscript, and assembles the
    /// base64url DeviceResponse plus the transmitted <c>mdoc_generated_nonce</c> the verifier needs to
    /// reconstruct that transcript.
    /// </summary>
    /// <param name="issuerKeys">The issuer's P-256 key material; its public half is the verifier's trust anchor.</param>
    /// <param name="deviceKeys">The wallet's device key material the MSO commits to.</param>
    /// <param name="status">The Status List entry the issued MSO references, or <see langword="null"/> for none.</param>
    private async ValueTask<(string VpTokenValue, string TransmittedNonce)> ProduceVpTokenAsync(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys,
        StatusListReference? status)
    {
        using MdocDocument issued = await MdocVpFixture.IssueAsync(
            issuerKeys, deviceKeys, status, TestContext.CancellationToken).ConfigureAwait(false);

        using IMemoryOwner<byte> mdocGeneratedNonce = Oid4VpMdocSessionTranscriptEncoder.GenerateMdocGeneratedNonce(
            System.Security.Cryptography.RandomNumberGenerator.Fill, Pool);
        ReadOnlyMemory<byte> nonceMemory =
            mdocGeneratedNonce.Memory[..Oid4VpMdocSessionTranscriptEncoder.MinimumMdocGeneratedNonceLength];
        ReadOnlyMemory<byte> sessionTranscript = Oid4VpMdocSessionTranscriptEncoder.Encode(
            VerifierClientId, VerifierResponseUri, AuthorizationRequestNonce, nonceMemory.Span, BaseMemoryPool.Shared);

        using MdocPresentationDocument intermediate = new(
            docType: issued.DocType,
            issuerSigned: MdocIssuerSignedView.FromOwned(issued.IssuerSigned));
        using MdocPresentationDocument presented = await intermediate.DeviceSignAsync(
            MdocDeviceNameSpaces.Empty,
            sessionTranscript,
            deviceKeys.PrivateKey,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        using MdocDeviceResponse deviceResponse = new(
            version: MdocWellKnownKeys.Version10,
            documents: [presented],
            status: MdocWellKnownKeys.StatusOk);

        string vpTokenValue = Oid4VpMdocPresentation.AssembleVpTokenValue(deviceResponse, TestSetup.Base64UrlEncoder);
        string transmittedNonce = Oid4VpMdocPresentation.EncodeMdocGeneratedNonceForTransmission(
            nonceMemory.Span, TestSetup.Base64UrlEncoder);

        return (vpTokenValue, transmittedNonce);
    }


    /// <summary>
    /// Verifier side: runs <see cref="MdocVpTokenVerification.VerifyAsync"/> with the CBOR/COSE seams
    /// wired to the concrete serialization implementations, exactly as
    /// <see cref="HaipOid4VpVerifierExecutor"/> wires them from
    /// <see cref="Verifiable.OAuth.Oid4Vp.Server.MdocVpVerificationSeams"/>.
    /// </summary>
    /// <param name="vpTokenValue">The base64url DeviceResponse received in the vp_token slot.</param>
    /// <param name="resolveIssuerKey">The trust framework's issuer-key resolver.</param>
    /// <param name="mdocGeneratedNonce">The decoded <c>mdoc_generated_nonce</c> the transcript is reconstructed from.</param>
    /// <returns>
    /// The parsed presentation and the IACA trust resolution owning the key
    /// <see cref="VpTokenParsed.CredentialIssuerKey"/> borrows; the caller releases it.
    /// </returns>
    private ValueTask<MdocVpVerificationResult> VerifyAsync(
        string vpTokenValue,
        ResolveMdocIssuerKeyDelegate resolveIssuerKey,
        ReadOnlyMemory<byte> mdocGeneratedNonce)
    {
        return MdocVpTokenVerification.VerifyAsync(
            vpTokenValue,
            new CredentialQueryId(PidCredentialQueryId),
            resolveIssuerKey,
            //No trust-evidence extractor: these tests do not exercise trusted_authorities.
            extractTrustedAuthorityEvidence: null,
            VerifierClientId,
            VerifierResponseUri,
            AuthorizationRequestNonce,
            mdocGeneratedNonce,
            MdocCborDeviceResponseReader.Read,
            Oid4VpMdocSessionTranscriptEncoder.Encode,
            MdocVpFixture.DecodeElementValue,
            CoseSerialization.ParseCoseSign1,
            CoseSerialization.ParseCoseSign1AllowingNilPayload,
            MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes,
            CoseSerialization.BuildSigStructure,
            TestSetup.Base64UrlDecoder,
            Pool,
            TestContext.CancellationToken);
    }


    /// <summary>
    /// Builds an MSO map carrying the six required members plus a <c>status</c> member whose only
    /// mechanism is <c>identifier_list</c> — a mechanism this library records by name but does not
    /// model the value of, so no <see cref="StatusClaim"/> constructor call can mint this shape
    /// (its <c>status_list</c>-coherence rule has nothing to say about other mechanisms); the wire
    /// bytes are hand-composed the same way <c>MdocCborMsoStatusTests</c> does.
    /// </summary>
    private static byte[] BuildMsoWithIdentifierListOnlyStatus()
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);

        writer.WriteStartMap(7);

        writer.WriteTextString(MdocMsoWellKnownKeys.DeviceKeyInfo);
        WriteDeviceKeyInfo(writer);

        writer.WriteTextString(MdocMsoWellKnownKeys.DigestAlgorithm);
        writer.WriteTextString(MdocMsoWellKnownKeys.DigestAlgorithmSha256);

        writer.WriteTextString(MdocMsoWellKnownKeys.DocType);
        writer.WriteTextString(MdlDocType);

        writer.WriteTextString(MdocMsoWellKnownKeys.ValidityInfo);
        WriteValidityInfo(writer);

        writer.WriteTextString(MdocMsoWellKnownKeys.ValueDigests);
        WriteValueDigests(writer, MdlNamespace);

        writer.WriteTextString(MdocMsoWellKnownKeys.Version);
        writer.WriteTextString(MdocMsoWellKnownKeys.Version10);

        writer.WriteTextString(MdocMsoWellKnownKeys.Status);
        writer.WriteStartMap(1);
        writer.WriteTextString(StatusMechanismNames.IdentifierList);
        writer.WriteStartMap(1);
        writer.WriteTextString("id");
        writer.WriteTextString("d7d1c0f0");
        writer.WriteEndMap();
        writer.WriteEndMap();

        writer.WriteEndMap();

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Issues the shared PID mdoc and restates its Mobile Security Object with a <c>status</c> member whose
    /// only mechanism is <c>identifier_list</c>.
    /// </summary>
    /// <param name="issuerKeys">The issuer's P-256 key material; its public half is the verifier's trust anchor.</param>
    /// <param name="deviceKeys">The wallet's device key material the MSO commits to.</param>
    /// <returns>The restated document; the caller owns it and every item under it.</returns>
    private ValueTask<MdocDocument> IssueWithIdentifierListOnlyStatusAsync(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys) =>
        IssueWithRestatedMobileSecurityObjectAsync(issuerKeys, deviceKeys, WithIdentifierListOnlyStatus);


    /// <summary>
    /// Issues the shared PID mdoc and restates its Mobile Security Object with a <c>status</c> member whose
    /// Status structure is an empty CBOR map.
    /// </summary>
    /// <param name="issuerKeys">The issuer's P-256 key material; its public half is the verifier's trust anchor.</param>
    /// <param name="deviceKeys">The wallet's device key material the MSO commits to.</param>
    /// <returns>The restated document; the caller owns it and every item under it.</returns>
    private ValueTask<MdocDocument> IssueWithEmptyStatusStructureAsync(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys) =>
        IssueWithRestatedMobileSecurityObjectAsync(issuerKeys, deviceKeys, WithEmptyStatusStructure);


    /// <summary>
    /// Issues the shared PID mdoc and restates its Mobile Security Object through
    /// <paramref name="restateMobileSecurityObject"/>: the six issued members are copied verbatim, so the
    /// <c>valueDigests</c> commitments and the committed device key are the ones the issued document's items
    /// and the wallet's device signature answer to, and the restated MSO is signed again by the same issuer.
    /// The library's own issuance cannot mint these documents — its MSO writer refuses a mechanism it does not
    /// model and a Status structure with no mechanism at all — so the wire bytes are composed here, the way
    /// the parse-level cases above compose theirs.
    /// </summary>
    /// <param name="issuerKeys">The issuer's P-256 key material; its public half is the verifier's trust anchor.</param>
    /// <param name="deviceKeys">The wallet's device key material the MSO commits to.</param>
    /// <param name="restateMobileSecurityObject">Rewrites the encoded MSO map into the shape under test.</param>
    /// <returns>The restated document; the caller owns it and every item under it.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the constructed MdocIssuerSigned transfers to the returned MdocDocument.")]
    private async ValueTask<MdocDocument> IssueWithRestatedMobileSecurityObjectAsync(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys,
        Func<ReadOnlyMemory<byte>, byte[]> restateMobileSecurityObject)
    {
        MdocDocument issued = await MdocVpFixture.IssueAsync(
            issuerKeys, deviceKeys, status: null, TestContext.CancellationToken).ConfigureAwait(false);

        try
        {
            byte[] restatedMso = restateMobileSecurityObject(ReadMobileSecurityObjectBytes(issued.IssuerSigned.IssuerAuth));
            byte[] issuerAuthBytes = await SignMsoAsIssuerAuthAsync(restatedMso, issuerKeys.PrivateKey).ConfigureAwait(false);

            //The restated wire bytes are paired with the issued document's own parsed Mobile Security
            //Object rather than re-read into one: what travels to the Verifier is the COSE_Sign1 the wallet
            //re-emits verbatim, and some of the shapes under test are exactly the ones a reader refuses —
            //re-reading them here would refuse the fixture before any Verifier ever saw it.
            IMemoryOwner<byte> issuerAuthOwner = Pool.Rent(issuerAuthBytes.Length);
            issuerAuthBytes.CopyTo(issuerAuthOwner.Memory.Span);

            MdocIssuerAuth restatedIssuerAuth = new(
                issued.IssuerSigned.IssuerAuth.Mso,
                new EncodedCoseSign1(issuerAuthOwner, CryptoTags.CoseEncodedSign1));

            MdocDocument restated = new(
                issued.DocType,
                new MdocIssuerSigned(issued.IssuerSigned.NameSpaces, restatedIssuerAuth));

            //The items moved to the restated document, which now owns them; only the superseded issuerAuth
            //wire-bytes carrier is left to release here.
            issued.IssuerSigned.IssuerAuth.Dispose();

            return restated;
        }
        catch
        {
            issued.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Reads the Mobile Security Object map bytes out of an <c>issuerAuth</c> COSE_Sign1: its payload is the
    /// Tag 24 wrapper ISO/IEC 18013-5 §9.1.2.4 puts the MSO in, unwrapped once.
    /// </summary>
    /// <param name="issuerAuth">The issuer-signed carrier whose payload is read.</param>
    /// <returns>The encoded MSO map.</returns>
    private static byte[] ReadMobileSecurityObjectBytes(MdocIssuerAuth issuerAuth)
    {
        using CoseSign1Message parsed = CoseSerialization.ParseCoseSign1(
            issuerAuth.EncodedCoseSign1.AsReadOnlyMemory(), Pool);

        EncodedCborItem wrapper = EncodedCborItem.Read(
            new CborReader(parsed.Payload.ToArray(), CborOptions.Lax));

        return wrapper.InnerBytes.ToArray();
    }


    /// <summary>
    /// Copies an encoded Mobile Security Object map member for member and appends a <c>status</c> member whose
    /// only mechanism is <c>identifier_list</c> — every other member, <c>valueDigests</c> and
    /// <c>deviceKeyInfo</c> included, reaches the output byte-identical, so nothing the document's own
    /// verification turns on changes.
    /// </summary>
    /// <param name="msoBytes">The encoded MSO map to restate.</param>
    /// <returns>The restated MSO map.</returns>
    private static byte[] WithIdentifierListOnlyStatus(ReadOnlyMemory<byte> msoBytes)
    {
        var reader = new CborReader(msoBytes, CborOptions.Lax);
        int? memberCount = reader.ReadStartMap();

        Assert.IsNotNull(memberCount,
            "The issued MSO is a definite-length map, so its member count is known before the copy begins.");

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(memberCount!.Value + 1);

        while(reader.PeekState() != CborReaderState.EndMap)
        {
            writer.WriteTextString(reader.ReadTextString());
            writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
        }

        reader.ReadEndMap();

        writer.WriteTextString(MdocMsoWellKnownKeys.Status);
        writer.WriteStartMap(1);
        writer.WriteTextString(StatusMechanismNames.IdentifierList);
        writer.WriteStartMap(1);
        writer.WriteTextString("id");
        writer.WriteTextString(IdentifierListEntryId);
        writer.WriteEndMap();
        writer.WriteEndMap();

        writer.WriteEndMap();

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Copies an encoded Mobile Security Object map member for member and appends a <c>status</c> member whose
    /// Status structure is an empty map — every other member reaches the output byte-identical, so nothing the
    /// document's own verification turns on changes and the only thing under test is the structure's shape.
    /// </summary>
    /// <param name="msoBytes">The encoded MSO map to restate.</param>
    /// <returns>The restated MSO map.</returns>
    private static byte[] WithEmptyStatusStructure(ReadOnlyMemory<byte> msoBytes)
    {
        var reader = new CborReader(msoBytes, CborOptions.Lax);
        int? memberCount = reader.ReadStartMap();

        Assert.IsNotNull(memberCount,
            "The issued MSO is a definite-length map, so its member count is known before the copy begins.");

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(memberCount!.Value + 1);

        while(reader.PeekState() != CborReaderState.EndMap)
        {
            writer.WriteTextString(reader.ReadTextString());
            writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
        }

        reader.ReadEndMap();

        writer.WriteTextString(MdocMsoWellKnownKeys.Status);
        writer.WriteStartMap(0);
        writer.WriteEndMap();

        writer.WriteEndMap();

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Drives one full cross-device mdoc presentation over the in-process listener: the Verifier's PAR, the
    /// Wallet's HTTP GET of the JAR, and the Wallet's Authorization Response POST to the Response URI. The
    /// SessionTranscript binding rides the wallet's <c>mdoc_generated_nonce</c>, which the shared presentation
    /// drop-out generates and transmits.
    /// </summary>
    /// <param name="app">The Verifier host shell.</param>
    /// <param name="issued">The stored mdoc the Wallet presents.</param>
    /// <param name="deviceKey">The device key the presentation is signed with.</param>
    /// <param name="nonce">The transaction nonce binding the presentation to this request.</param>
    /// <returns>
    /// The flow's external handle, and the Wallet-side detail of a non-200 answer from the Response URI when
    /// the Verifier refused the presentation.
    /// </returns>
    private async ValueTask<(string ParHandle, string? RefusalDetail)> PresentOverTheWireAsync(
        TestHostShell app,
        MdocDocument issued,
        PrivateKeyMemory deviceKey,
        string nonce)
    {
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            HostedVerifierClientId, HostedVerifierBaseUri, Oid4VpCapabilities);

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys,
            MdocVpFixture.BuildMdocProduceDelegate(issued, deviceKey),
            TestHostShell.PinnedVerifierKeyResolver(verifierKeys.SigningPublicKey),
            TestContext.CancellationToken).ConfigureAwait(false);

        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce(nonce),
            MdocVpFixture.BuildMdocPreparedQuery(),
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
                    ExpectedVerifierClientId = HostedVerifierClientId,
                    FlowId = $"wallet-{nonce}-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException exception)
        {
            //The Response URI answered a non-200; the Wallet client raises the status and body it read.
            refusalDetail = exception.Message;
        }

        return (parHandle, refusalDetail);
    }


    /// <summary>
    /// Wraps <paramref name="msoBytes"/> in a Tag 24 payload and signs it as a real COSE_Sign1 under
    /// <paramref name="signingKey"/>, returning the wire bytes an <c>issuerAuth</c> slot carries —
    /// the minimal composition <c>MdocCborIssuance.SignVerboseAsync</c> performs internally, built
    /// here from public APIs so the fixture can sign a hand-composed MSO that library's own signing
    /// entry point cannot mint (identifier_list-only status).
    /// </summary>
    /// <param name="msoBytes">The encoded MSO map bytes (not yet Tag-24-wrapped).</param>
    /// <param name="signingKey">The issuer's signing key.</param>
    private async ValueTask<byte[]> SignMsoAsIssuerAuthAsync(byte[] msoBytes, PrivateKeyMemory signingKey)
    {
        EncodedCborItem tag24 = EncodedCborItem.Wrap(msoBytes);

        using EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(
            CoseSerialization.SerializeProtectedHeader(
                new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 }),
            Pool);

        using CoseSign1Message message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader, null, tag24.WireBytes, CoseSerialization.BuildSigStructure, signingKey, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        using EncodedCoseSign1 encoded = CoseSerialization.SerializeCoseSign1(message, Pool);

        return encoded.AsReadOnlySpan().ToArray();
    }
}
