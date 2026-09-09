using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A test-side WebAuthn relying party, exposing the four conventional ceremony endpoints
/// (<c>/attestation/options</c>, <c>/attestation/result</c>, <c>/assertion/options</c>,
/// <c>/assertion/result</c>) as a <see cref="MinimalHttpHandlerDelegate"/> for
/// <see cref="MinimalHttpHost.StartAsync"/> — the same "one caller-supplied handler over a real Kestrel
/// loopback listener" pattern <see cref="MinimalHttpHost"/>'s own remarks describe as mirroring
/// <c>AuthorizationServerHttpApplication</c>'s raw <c>IHttpApplication</c> shape without the OAuth
/// dispatcher.
/// </summary>
/// <remarks>
/// <para>
/// Single relying party, single user, single credential at a time: challenge/session state (the
/// pending registration or assertion challenge) and the one stored <see cref="Fido2CredentialRecord"/>
/// live as plain mutable fields here rather than in a database — this is ceremony orchestration glue
/// for one capstone flow, not a general-purpose relying party. Options responses are produced with the
/// shipped <see cref="PublicKeyCredentialCreationOptionsJsonWriter"/>/<see cref="PublicKeyCredentialRequestOptionsJsonWriter"/>;
/// result requests are parsed with the new <see cref="RegistrationResponseJsonReader"/>/<see cref="AuthenticationResponseJsonReader"/>
/// and verified with the SHIPPED <see cref="Fido2RegistrationVerifier"/>/<see cref="Fido2AssertionVerifier"/> —
/// this class adds no verification logic of its own, only the HTTP-facing plumbing around them.
/// </para>
/// <para>
/// <strong>Wire-crossing proof.</strong> <see cref="AttestationResultRequestCount"/> and
/// <see cref="AssertionResultRequestCount"/> increment once per request this handler actually
/// processes, so a capstone can assert the verification path was reached only via the socket, not some
/// in-process shortcut.
/// </para>
/// </remarks>
internal sealed class WebAuthnRelyingPartyCeremonySkin
{
    /// <summary>The <c>/attestation/options</c> endpoint path.</summary>
    public const string AttestationOptionsPath = "/attestation/options";

    /// <summary>The <c>/attestation/result</c> endpoint path.</summary>
    public const string AttestationResultPath = "/attestation/result";

    /// <summary>The <c>/assertion/options</c> endpoint path.</summary>
    public const string AssertionOptionsPath = "/assertion/options";

    /// <summary>The <c>/assertion/result</c> endpoint path.</summary>
    public const string AssertionResultPath = "/assertion/result";

    /// <summary>The JSON content type every response this skin produces carries.</summary>
    private const string JsonContentType = "application/json";

    /// <summary>The relying party identifier every ceremony is scoped to.</summary>
    private string RpId { get; }

    /// <summary>The relying party origin every ceremony's <c>clientDataJSON</c> is checked against.</summary>
    private string Origin { get; }

    /// <summary>The single test user's WebAuthn user handle bytes.</summary>
    private byte[] UserIdSeed { get; }

    /// <summary>The single test user's account name.</summary>
    private string UserName { get; }

    /// <summary>The single test user's display name.</summary>
    private string UserDisplayName { get; }

    /// <summary>The memory pool every ceremony's working buffers rent from.</summary>
    private BaseMemoryPool Pool { get; }

    /// <summary>The user verification requirement every ceremony's options and verification input carry.</summary>
    private UserVerificationRequirement UserVerification { get; }

    /// <summary>The resident-key requirement the registration ceremony's options carry, or <see langword="null"/> for the builder's own default.</summary>
    private ResidentKeyRequirement? ResidentKey { get; }

    /// <summary>Builds the registration ceremony's <c>PublicKeyCredentialCreationOptions</c>.</summary>
    private Fido2RegistrationOptionsBuilder RegistrationOptionsBuilder { get; } = new();

    /// <summary>Builds the authentication ceremony's <c>PublicKeyCredentialRequestOptions</c>.</summary>
    private Fido2AssertionOptionsBuilder AssertionOptionsBuilder { get; } = new();

    /// <summary>The challenge issued by the most recent <see cref="HandleAttestationOptionsAsync"/> call, or <see langword="null"/> once consumed.</summary>
    private string? pendingRegistrationChallenge;

    /// <summary>
    /// The exact <c>pubKeyCredParams</c> offered by the most recent <see cref="HandleAttestationOptionsAsync"/>
    /// call, or <see langword="null"/> once consumed. Carried alongside <see cref="pendingRegistrationChallenge"/>
    /// so <see cref="HandleAttestationResultAsync"/> can hand it straight to
    /// <see cref="RegistrationCeremonyInput.ExpectedPubKeyCredParams"/> — the accepted algorithm set is
    /// therefore always exactly what this skin offered, never a hand-authored list that could drift from it.
    /// </summary>
    private IReadOnlyList<PublicKeyCredentialParameters>? pendingRegistrationPubKeyCredParams;

    /// <summary>The challenge issued by the most recent <see cref="HandleAssertionOptionsAsync"/> call, or <see langword="null"/> once consumed.</summary>
    private string? pendingAssertionChallenge;

    /// <summary>The one credential record this skin tracks, backing <see cref="StoredCredential"/>.</summary>
    private Fido2CredentialRecord? storedCredential;


    /// <summary>
    /// Initializes the skin for one relying party identity and one test user.
    /// </summary>
    /// <param name="rpId">The relying party identifier every ceremony is scoped to.</param>
    /// <param name="origin">The relying party origin every ceremony's <c>clientDataJSON</c> is checked against.</param>
    /// <param name="userIdSeed">The single test user's WebAuthn user handle bytes.</param>
    /// <param name="userName">The single test user's account name.</param>
    /// <param name="userDisplayName">The single test user's display name.</param>
    /// <param name="pool">The memory pool every ceremony's working buffers rent from.</param>
    /// <param name="userVerification">
    /// The user verification requirement every ceremony's options and verification input carry, or
    /// <see cref="UserVerificationRequirement.Discouraged"/> when omitted — the requirement every
    /// capstone predating the PIN/UV token leg exercised.
    /// </param>
    /// <param name="residentKey">
    /// The resident-key requirement the registration ceremony's options carry, or <see langword="null"/>
    /// to leave it to <see cref="Fido2RegistrationOptionsBuilder"/>'s own default
    /// (<see cref="ResidentKeyRequirement.Discouraged"/>) — the credential-management capstone's own credMgmt-visible
    /// discoverable credential passes <see cref="ResidentKeyRequirement.Required"/> here.
    /// </param>
    public WebAuthnRelyingPartyCeremonySkin(
        string rpId, string origin, byte[] userIdSeed, string userName, string userDisplayName, BaseMemoryPool pool,
        UserVerificationRequirement userVerification = UserVerificationRequirement.Discouraged,
        ResidentKeyRequirement? residentKey = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rpId);
        ArgumentException.ThrowIfNullOrWhiteSpace(origin);
        ArgumentNullException.ThrowIfNull(userIdSeed);
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        ArgumentException.ThrowIfNullOrWhiteSpace(userDisplayName);
        ArgumentNullException.ThrowIfNull(pool);

        this.RpId = rpId;
        this.Origin = origin;
        this.UserIdSeed = userIdSeed;
        this.UserName = userName;
        this.UserDisplayName = userDisplayName;
        this.Pool = pool;
        this.UserVerification = userVerification;
        this.ResidentKey = residentKey;
    }


    /// <summary>The number of requests <see cref="HandleAttestationResultAsync"/> has processed.</summary>
    public int AttestationResultRequestCount { get; private set; }

    /// <summary>The number of requests <see cref="HandleAssertionResultAsync"/> has processed.</summary>
    public int AssertionResultRequestCount { get; private set; }

    /// <summary>The credential record stored after the most recent successful registration, or <see langword="null"/> before one succeeds.</summary>
    public Fido2CredentialRecord? StoredCredential => storedCredential;


    /// <summary>
    /// Browser-glue: composes the W3C WebAuthn Level 3 <c>RegistrationResponseJSON</c> envelope
    /// (<see href="https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson">section 5.1.3</see>)
    /// a real client's <c>PublicKeyCredential.toJSON()</c> would produce — this library ships no writer
    /// for this shape (it is the client's own serialization, not a relying party or authenticator
    /// concern), so composing it here, alongside the server-side skin that consumes it, is a real-wire
    /// HTTP capstone's legitimate role.
    /// </summary>
    /// <param name="credentialId">The credential identifier bytes, reused for both <c>id</c> and <c>rawId</c>.</param>
    /// <param name="clientDataJson">The UTF-8 <c>clientDataJSON</c> bytes.</param>
    /// <param name="attestationObject">The CBOR-encoded <c>attestationObject</c> bytes.</param>
    /// <returns>The <c>RegistrationResponseJSON</c> envelope as a JSON string.</returns>
    public static string BuildRegistrationResponseJson(ReadOnlySpan<byte> credentialId, ReadOnlySpan<byte> clientDataJson, ReadOnlySpan<byte> attestationObject)
    {
        string id = Base64Url.EncodeToString(credentialId);
        string clientDataJsonBase64 = Base64Url.EncodeToString(clientDataJson);
        string attestationObjectBase64 = Base64Url.EncodeToString(attestationObject);

        return $$"""{"id":"{{id}}","rawId":"{{id}}","response":{"clientDataJSON":"{{clientDataJsonBase64}}","attestationObject":"{{attestationObjectBase64}}"},"clientExtensionResults":{},"type":"public-key"}""";
    }


    /// <summary>
    /// Browser-glue: composes the W3C WebAuthn Level 3 <c>AuthenticationResponseJSON</c> envelope
    /// (<see href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticationresponsejson">section 5.1.3</see>),
    /// for the same reason <see cref="BuildRegistrationResponseJson"/> documents.
    /// </summary>
    /// <param name="credentialId">The credential identifier bytes, reused for both <c>id</c> and <c>rawId</c>.</param>
    /// <param name="clientDataJson">The UTF-8 <c>clientDataJSON</c> bytes.</param>
    /// <param name="authenticatorData">The raw <c>authenticatorData</c> bytes.</param>
    /// <param name="signature">The assertion signature bytes.</param>
    /// <param name="hasUserHandle">Whether the response carries a <c>userHandle</c> member.</param>
    /// <param name="userHandle">The user handle bytes, consulted only when <paramref name="hasUserHandle"/> is <see langword="true"/>.</param>
    /// <returns>The <c>AuthenticationResponseJSON</c> envelope as a JSON string.</returns>
    public static string BuildAssertionResponseJson(
        ReadOnlySpan<byte> credentialId, ReadOnlySpan<byte> clientDataJson, ReadOnlySpan<byte> authenticatorData,
        ReadOnlySpan<byte> signature, bool hasUserHandle, ReadOnlySpan<byte> userHandle)
    {
        string id = Base64Url.EncodeToString(credentialId);
        string clientDataJsonBase64 = Base64Url.EncodeToString(clientDataJson);
        string authenticatorDataBase64 = Base64Url.EncodeToString(authenticatorData);
        string signatureBase64 = Base64Url.EncodeToString(signature);
        string userHandleMember = hasUserHandle
            ? $",\"userHandle\":\"{Base64Url.EncodeToString(userHandle)}\""
            : string.Empty;

        return $$"""{"id":"{{id}}","rawId":"{{id}}","response":{"clientDataJSON":"{{clientDataJsonBase64}}","authenticatorData":"{{authenticatorDataBase64}}","signature":"{{signatureBase64}}"{{userHandleMember}}},"clientExtensionResults":{},"type":"public-key"}""";
    }


    /// <summary>
    /// Routes a buffered request to one of the four ceremony endpoints. Matches
    /// <see cref="MinimalHttpHandlerDelegate"/>, so an instance method group converts directly for
    /// <see cref="MinimalHttpHost.StartAsync"/>.
    /// </summary>
    /// <param name="request">The buffered request.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The response to send.</returns>
    public Task<MinimalHttpResponse> HandleAsync(MinimalHttpRequest request, CancellationToken cancellationToken)
    {
        return (request.Method, request.Path) switch
        {
            ("POST", AttestationOptionsPath) => HandleAttestationOptionsAsync(cancellationToken),
            ("POST", AttestationResultPath) => HandleAttestationResultAsync(request, cancellationToken),
            ("POST", AssertionOptionsPath) => HandleAssertionOptionsAsync(cancellationToken),
            ("POST", AssertionResultPath) => HandleAssertionResultAsync(request, cancellationToken),
            _ => Task.FromResult(new MinimalHttpResponse { StatusCode = 404 })
        };
    }


    /// <summary>
    /// Builds fresh <c>PublicKeyCredentialCreationOptions</c>, remembers the issued challenge, and
    /// writes the options as the CR's own <c>PublicKeyCredentialCreationOptionsJSON</c> wire shape.
    /// </summary>
    private async Task<MinimalHttpResponse> HandleAttestationOptionsAsync(CancellationToken cancellationToken)
    {
        using UserHandle registrationUserId = UserHandle.Create(UserIdSeed, Pool);

        PublicKeyCredentialCreationOptions options = await RegistrationOptionsBuilder.BuildAsync(
            rpId: RpId,
            rpName: RpId,
            userId: registrationUserId,
            userName: UserName,
            userDisplayName: UserDisplayName,
            pool: Pool,
            userVerification: UserVerification,
            residentKey: ResidentKey,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        pendingRegistrationChallenge = options.Challenge;
        pendingRegistrationPubKeyCredParams = options.PubKeyCredParams;

        ArrayBufferWriter<byte> buffer = new();
        PublicKeyCredentialCreationOptionsJsonWriter.Write(options, buffer);

        return new MinimalHttpResponse { StatusCode = 200, ContentType = JsonContentType, Body = Encoding.UTF8.GetString(buffer.WrittenSpan) };
    }


    /// <summary>
    /// Parses the <c>RegistrationResponseJSON</c> body, splits its <c>attestationObject</c>, and runs
    /// the SHIPPED <see cref="Fido2RegistrationVerifier"/> against the challenge issued by the most
    /// recent <see cref="HandleAttestationOptionsAsync"/> call. Stores the resulting credential record
    /// on success.
    /// </summary>
    private async Task<MinimalHttpResponse> HandleAttestationResultAsync(MinimalHttpRequest request, CancellationToken cancellationToken)
    {
        AttestationResultRequestCount++;

        if(pendingRegistrationChallenge is not string expectedChallenge
            || pendingRegistrationPubKeyCredParams is not IReadOnlyList<PublicKeyCredentialParameters> expectedPubKeyCredParams)
        {
            return new MinimalHttpResponse { StatusCode = 400, ContentType = JsonContentType, Body = """{"verified":false,"error":"no pending registration"}""" };
        }

        //envelope is declared null and assigned once inside the try body below; a using declaration cannot
        //target a variable assigned after its declaration (CS1656).
        WebAuthnRegistrationResponseEnvelope? envelope = null;
        try
        {
            envelope = RegistrationResponseJsonReader.Read(Encoding.UTF8.GetBytes(request.Body), Pool);
            AttestationObjectParts attestationParts = AttestationObjectCborReader.Parse(envelope.AttestationObject.AsReadOnlyMemory());
            AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(attestationParts.AuthenticatorData, CredentialPublicKeyCborReader.Read, Pool);

            using RegistrationCeremonyInput ceremonyInput = new()
            {
                ClientData = ClientDataJsonReader.Read(envelope.ClientDataJson.AsReadOnlyMemory()),
                AuthenticatorData = authenticatorData,
                ExpectedChallenge = expectedChallenge,
                ExpectedOrigins = new HashSet<string> { Origin },
                ExpectedRpIdHash = CtapCapstoneFixtures.ComputeExpectedRpIdHash(RpId, Pool),
                UserVerification = UserVerification,
                ExpectedPubKeyCredParams = expectedPubKeyCredParams,
                ExtensionProcessingPool = Pool
            };

            SelectAttestationVerifierDelegate selectAttestationVerifier = Fido2AttestationSelectors.FromFormats(
                (WellKnownWebAuthnAttestationFormats.None, NoneAttestation.Build()));

            Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(attestationParts.Format, attestationParts.AttestationStatement, attestationParts.AuthenticatorData, envelope.ClientDataJson.AsReadOnlyMemory(), ceremonyInput, selectAttestationVerifier, static (_, _) => ValueTask.FromResult(true),
                trustAnchors: [],
                validationTime: TestClock.CanonicalEpoch,
                correlationId: "webauthn-rp-ceremony-skin-registration",
                Pool,
                cancellationToken: cancellationToken, timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch)).ConfigureAwait(false);

            pendingRegistrationChallenge = null;
            pendingRegistrationPubKeyCredParams = null;

            if(!outcome.IsAcceptable || outcome.CredentialRecord is not Fido2CredentialRecord credentialRecord)
            {
                outcome.CredentialRecord?.Dispose();

                return new MinimalHttpResponse { StatusCode = 401, ContentType = JsonContentType, Body = """{"verified":false}""" };
            }

            storedCredential?.Dispose();
            storedCredential = credentialRecord;

            return new MinimalHttpResponse { StatusCode = 200, ContentType = JsonContentType, Body = """{"verified":true}""" };
        }
        catch(Fido2FormatException)
        {
            return new MinimalHttpResponse { StatusCode = 400, ContentType = JsonContentType, Body = """{"verified":false,"error":"malformed envelope"}""" };
        }
        finally
        {
            envelope?.Dispose();
        }
    }


    /// <summary>
    /// Builds fresh <c>PublicKeyCredentialRequestOptions</c> — allow-listing the stored credential when
    /// one is registered — remembers the issued challenge, and writes the options as the CR's own
    /// <c>PublicKeyCredentialRequestOptionsJSON</c> wire shape.
    /// </summary>
    private async Task<MinimalHttpResponse> HandleAssertionOptionsAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<Fido2CredentialRecord>? allowedCredentials = storedCredential is Fido2CredentialRecord credential
            ? [credential]
            : null;

        PublicKeyCredentialRequestOptions options = await AssertionOptionsBuilder.BuildAsync(
            rpId: RpId,
            pool: Pool,
            allowedCredentials: allowedCredentials,
            userVerification: UserVerification,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        pendingAssertionChallenge = options.Challenge;

        ArrayBufferWriter<byte> buffer = new();
        PublicKeyCredentialRequestOptionsJsonWriter.Write(options, buffer);

        return new MinimalHttpResponse { StatusCode = 200, ContentType = JsonContentType, Body = Encoding.UTF8.GetString(buffer.WrittenSpan) };
    }


    /// <summary>
    /// Parses the <c>AuthenticationResponseJSON</c> body and runs the SHIPPED
    /// <see cref="Fido2AssertionVerifier"/> against the stored credential and the challenge issued by
    /// the most recent <see cref="HandleAssertionOptionsAsync"/> call. Bumps the stored sign count on
    /// success, per the ceremony's own step 24.
    /// </summary>
    private async Task<MinimalHttpResponse> HandleAssertionResultAsync(MinimalHttpRequest request, CancellationToken cancellationToken)
    {
        AssertionResultRequestCount++;

        if(pendingAssertionChallenge is not string expectedChallenge || storedCredential is not Fido2CredentialRecord credential)
        {
            return new MinimalHttpResponse { StatusCode = 400, ContentType = JsonContentType, Body = """{"verified":false,"error":"no pending assertion"}""" };
        }

        //envelope is declared null and assigned once inside the try body below; a using declaration cannot
        //target a variable assigned after its declaration (CS1656).
        WebAuthnAssertionResponseEnvelope? envelope = null;
        try
        {
            envelope = AuthenticationResponseJsonReader.Read(Encoding.UTF8.GetBytes(request.Body), Pool);
            AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(envelope.AuthenticatorData.AsReadOnlyMemory(), CredentialPublicKeyCborReader.Read, Pool);

            using UserHandle storedUserHandle = UserHandle.Create(UserIdSeed, Pool);
            using CredentialId allowedCredentialId = CredentialId.Create(credential.Id.AsReadOnlySpan(), Pool);
            using CredentialId assertedCredentialId = CredentialId.Create(envelope.RawId.AsReadOnlySpan(), Pool);

            using AssertionCeremonyInput ceremonyInput = new()
            {
                ClientData = ClientDataJsonReader.Read(envelope.ClientDataJson.AsReadOnlyMemory()),
                AuthenticatorData = authenticatorData,
                ExpectedChallenge = expectedChallenge,
                ExpectedOrigins = new HashSet<string> { Origin },
                ExpectedRpIdHash = CtapCapstoneFixtures.ComputeExpectedRpIdHash(RpId, Pool),
                UserVerification = UserVerification,
                AllowedCredentialIds = [allowedCredentialId],
                CredentialId = assertedCredentialId,
                StoredSignCount = credential.SignCount,
                StoredUvInitialized = credential.UvInitialized,
                StoredBackupEligible = credential.BackupEligible,
                StoredBackupState = credential.BackupState,
                ResponseUserHandle = envelope.UserHandle is UserHandle responseUserHandle
                    ? UserHandle.Create(responseUserHandle.AsReadOnlySpan(), Pool)
                    : null,
                StoredUserHandle = UserHandle.Create(storedUserHandle.AsReadOnlySpan(), Pool),
                ExtensionProcessingPool = Pool
            };

            Fido2AssertionOutcome outcome = await Fido2AssertionVerifier.VerifyAsync(credential.PublicKey, envelope.Signature.AsReadOnlyMemory(), envelope.AuthenticatorData.AsReadOnlyMemory(), envelope.ClientDataJson.AsReadOnlyMemory(), ceremonyInput, correlationId: "webauthn-rp-ceremony-skin-assertion", Pool, cancellationToken: cancellationToken, timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch)).ConfigureAwait(false);

            pendingAssertionChallenge = null;

            if(!outcome.IsAcceptable)
            {
                return new MinimalHttpResponse { StatusCode = 401, ContentType = JsonContentType, Body = """{"verified":false}""" };
            }

            storedCredential = credential with { SignCount = authenticatorData.SignCount };

            return new MinimalHttpResponse { StatusCode = 200, ContentType = JsonContentType, Body = """{"verified":true}""" };
        }
        catch(Fido2FormatException)
        {
            return new MinimalHttpResponse { StatusCode = 400, ContentType = JsonContentType, Body = """{"verified":false,"error":"malformed envelope"}""" };
        }
        finally
        {
            envelope?.Dispose();
        }
    }
}
