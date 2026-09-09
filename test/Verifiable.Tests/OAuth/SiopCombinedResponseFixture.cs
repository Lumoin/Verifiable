using System.Collections.Immutable;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Siop.Wallet;
using Verifiable.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The Self-Issued OpenID Provider v2 Section 12 combined-response driver every combined-response test
/// class shares: the relying party's identity and registration shape, the JWT header/payload
/// serializers, minting the Self-Issued ID Token, binding the wallet's presentation, and posting both
/// artifacts plus <c>state</c> to the response endpoint. <see cref="SiopCombinedResponseFlowTests"/>
/// drives the surrounding transaction shape; the classes that vary only the credential, its
/// <c>status</c> claim or the credential query identifier call this driver instead of re-minting it.
/// </summary>
internal static class SiopCombinedResponseFixture
{
    /// <summary>The relying party's Client ID and, by default, the audience the key-binding JWT binds to.</summary>
    public const string RelyingPartyClientId = "https://rp.example.com";

    /// <summary>The credential issuer identifier the tests register as trusted.</summary>
    public const string IssuerId = "https://issuer.example.com";

    /// <summary>The credential issuer's signing key identifier.</summary>
    public const string IssuerKeyId = "did:web:issuer.example.com#key-1";

    /// <summary>The relying party's registered base URI, equal in value to <see cref="RelyingPartyClientId"/>.</summary>
    public static Uri RelyingPartyBaseUri { get; } = new(RelyingPartyClientId);

    /// <summary>The capability a Self-Issued OpenID Provider registration carries.</summary>
    public static ImmutableHashSet<CapabilityIdentifier> SiopCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.SiopSelfIssuedOp);

    /// <summary>The signing algorithm the relying party accepts for the Self-Issued ID Token and the key-binding JWT.</summary>
    public static string[] AllowedSiopAlgorithms { get; } = [WellKnownJwaValues.Es256];

    /// <summary>Serializes a JWT header for the Self-Issued ID Token and the key-binding JWT.</summary>
    public static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    /// <summary>Serializes a JWT payload for the Self-Issued ID Token and the key-binding JWT.</summary>
    public static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// Mints a JWK-Thumbprint Self-Issued ID Token for <paramref name="nonce"/> against
    /// <see cref="RelyingPartyClientId"/>, on a fresh P-256 subject key — Self-Issued OpenID Provider v2
    /// Section 2.2.1 keeps that key unrelated to the credential's holder binding.
    /// </summary>
    /// <param name="nonce">The nonce the relying party provided, echoed by the token.</param>
    /// <param name="timeProvider">The clock the token's <c>iat</c> claim is read from.</param>
    /// <param name="pool">The pool the signing rents transient buffers from.</param>
    /// <param name="cancellationToken">Cancels the signing.</param>
    /// <returns>The compact Self-Issued ID Token.</returns>
    public static async Task<string> IssueSelfIssuedIdTokenAsync(
        string nonce, TimeProvider timeProvider, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> siopKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

        return await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            siopPrivate, siopPublic, RelyingPartyClientId, nonce,
            issuedAt: timeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The wallet-side presentation step: parse the stored SD-JWT, sign a key-binding JWT over its hash
    /// input with the holder key bound to the request's <c>nonce</c> and the given audience, and
    /// serialise the presentation with key binding per RFC 9901 Section 4.3. Delegates to
    /// <see cref="SdJwtVpFixture.PresentWithKeyBindingAsync"/>, the same construction every SD-JWT VC
    /// presentation step shares.
    /// </summary>
    /// <param name="sdJwtWithoutKb">The stored credential as issued, without key binding.</param>
    /// <param name="holderPrivateKey">The holder key the credential's <c>cnf</c> binds to.</param>
    /// <param name="nonce">The nonce the key-binding JWT is bound to.</param>
    /// <param name="audience">The audience the key-binding JWT is bound to.</param>
    /// <param name="timeProvider">The clock the key-binding JWT's <c>iat</c> claim is read from.</param>
    /// <param name="pool">The pool the parse and re-serialization rent transient buffers from.</param>
    /// <param name="cancellationToken">Cancels the key-binding JWT signing.</param>
    /// <returns>The serialized presentation with its key-binding JWT appended.</returns>
    public static ValueTask<string> PresentWithKeyBindingAsync(
        string sdJwtWithoutKb,
        PrivateKeyMemory holderPrivateKey,
        string nonce,
        string audience,
        TimeProvider timeProvider,
        BaseMemoryPool pool,
        CancellationToken cancellationToken) =>
        SdJwtVpFixture.PresentWithKeyBindingAsync(
            sdJwtWithoutKb, holderPrivateKey, nonce, audience,
            timeProvider, HeaderSerializer, PayloadSerializer, pool, cancellationToken);


    /// <summary>
    /// Drives one Self-Issued OpenID Provider v2 Section 12 combined response end to end on
    /// <paramref name="host"/>: registers the relying party, prepares the transaction, mints the ID
    /// Token and the key-bound presentation, POSTs both plus <c>state</c> to the response endpoint, and
    /// answers the endpoint's response together with the verifier's terminal flow state.
    /// </summary>
    /// <param name="host">The hosted relying party, already carrying whatever status resolver and policy the case wires.</param>
    /// <param name="serializedSdJwt">The stored credential the wallet presents.</param>
    /// <param name="holderPrivateKey">The holder key the credential's <c>cnf</c> binds to.</param>
    /// <param name="nonce">The nonce the relying party provides and both artifacts are bound to.</param>
    /// <param name="keyBindingAudience">The audience the key-binding JWT is bound to — the relying party's Client ID, unless the case deliberately misses it.</param>
    /// <param name="timeProvider">The clock the transaction's tokens read their timestamps from.</param>
    /// <param name="pool">The pool the transaction rents transient buffers from.</param>
    /// <param name="cancellationToken">Cancels the transaction.</param>
    /// <returns>The endpoint's response and the relying party's terminal flow state.</returns>
    public static async Task<(ServerHttpResponse Response, FlowState State)> PostCombinedResponseAsync(
        TestHostShell host,
        string serializedSdJwt,
        PrivateKeyMemory holderPrivateKey,
        string nonce,
        string keyBindingAudience,
        TimeProvider timeProvider,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        string requestHandle = await host.HandleSiopRequestPreparationAsync(
            rpKeys, nonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            cancellationToken).ConfigureAwait(false);

        string idToken = await IssueSelfIssuedIdTokenAsync(
            nonce, timeProvider, pool, cancellationToken).ConfigureAwait(false);
        string vpToken = await PresentWithKeyBindingAsync(
            serializedSdJwt, holderPrivateKey, nonce, keyBindingAudience,
            timeProvider, pool, cancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            tenant,
            WellKnownEndpointNames.SiopResponse,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.IdToken] = idToken,
                [AuthorizationResponseParameters.VpToken] = vpToken,
                [OAuthRequestParameterNames.State] = requestHandle
            },
            new ExchangeContext(),
            cancellationToken).ConfigureAwait(false);

        return (response, host.GetFlowState(requestHandle).State);
    }
}
