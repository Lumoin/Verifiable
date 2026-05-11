using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using Verifiable.Core.Automata;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Oid4Vp.Wallet.States;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// The OID4VP Wallet-side sub-client of <see cref="OAuthClient"/>. Drives a
/// single-credential SD-JWT VC presentation in HAIP 1.0 cross-device shape:
/// verify the JAR, evaluate DCQL, sign the KB-JWT, assemble the spec-shaped
/// <c>vp_token</c>, encrypt to the Verifier's JWKS, POST the JWE to
/// <c>response_uri</c>, and walk the Wallet PDA to the
/// <see cref="ResponseSent"/> terminal state.
/// </summary>
/// <typeparam name="TCredential">
/// The application-supplied credential type carried through the resolver and
/// disclosure-selection delegates. The wallet client extracts the compact
/// SD-JWT via <see cref="SdJwtVcCredential.CompactSdJwt"/>; applications that
/// attach extra context derive from <see cref="SdJwtVcCredential"/>.
/// </typeparam>
/// <remarks>
/// <para>
/// Each <see cref="PresentJarAsync"/> invocation is a complete presentation:
/// it constructs a fresh Wallet PDA, advances it through all transitions, and
/// returns the encrypted JWE and the terminal state. Persisted-state Wallet
/// scenarios (resume across processes, deferred user interaction) compose
/// <see cref="WalletFlowAutomaton.CreateFromSnapshot"/> directly rather than
/// going through this client.
/// </para>
/// <para>
/// The wallet client handles the single-credential case per OID4VP 1.0 §8.1.
/// Multi-credential presentations are a future round.
/// </para>
/// </remarks>
[DebuggerDisplay("Oid4VpWalletClient")]
public sealed class Oid4VpWalletClient<TCredential> where TCredential : SdJwtVcCredential
{
    private readonly OAuthClientOptions options;
    private readonly Oid4VpWalletConfiguration<TCredential> walletConfiguration;


    /// <summary>The shared OAuth client options carrying transport, time, and encoding delegates.</summary>
    public OAuthClientOptions Options => options;


    /// <summary>The wallet-specific configuration carrying delegates for JAR parsing, KB-JWT signing, and response encryption.</summary>
    public Oid4VpWalletConfiguration<TCredential> WalletConfiguration => walletConfiguration;


    /// <summary>
    /// Creates a new OID4VP Wallet client.
    /// </summary>
    /// <param name="options">The shared client options.</param>
    /// <param name="walletConfiguration">The wallet-specific delegate bundle.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when either argument is <see langword="null"/>.
    /// </exception>
    public Oid4VpWalletClient(
        OAuthClientOptions options,
        Oid4VpWalletConfiguration<TCredential> walletConfiguration)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(walletConfiguration);

        this.options = options;
        this.walletConfiguration = walletConfiguration;
    }


    /// <summary>
    /// Drives one OID4VP presentation end-to-end. Verifies the inbound JAR,
    /// resolves a matching credential, signs the KB-JWT, encrypts the
    /// <c>vp_token</c> response to the Verifier's JWKS, and POSTs the JWE to
    /// the Verifier's <c>response_uri</c>.
    /// </summary>
    /// <param name="presentJarOptions">Per-call inputs.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact JWE that was POSTed and the terminal PDA state.</returns>
    public async ValueTask<PresentationResult> PresentJarAsync(
        PresentJarOptions<TCredential> presentJarOptions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(presentJarOptions);

        AuthorizationRequestObject request = await JarExtensions.VerifyAndParseJarAsync(
            presentJarOptions.CompactJar,
            presentJarOptions.VerifierSigningPublicKey,
            walletConfiguration.Base64UrlDecoder,
            walletConfiguration.JarHeaderDeserializer,
            walletConfiguration.JarPayloadDeserializer,
            walletConfiguration.DcqlQueryDeserializer,
            walletConfiguration.ClientMetadataDeserializer,
            walletConfiguration.MemoryPool,
            cancellationToken).ConfigureAwait(false);

        if(request.DcqlQuery is null
            || request.DcqlQuery.Credentials is null
            || request.DcqlQuery.Credentials.Count == 0)
        {
            throw new InvalidOperationException(
                "Authorization Request Object does not carry a non-empty dcql_query. " +
                "OID4VP single-credential presentation requires at least one credential query.");
        }

        string credentialQueryId = request.DcqlQuery.Credentials[0].Id
            ?? throw new InvalidOperationException(
                "DCQL credential query is missing the 'id' field; OID4VP §7 requires it.");

        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, WalletFlowStackSymbol> pda =
            WalletFlowAutomaton.Create(
                runId: Guid.NewGuid().ToString(),
                requestUri: presentJarOptions.RequestUri,
                expectedVerifierClientId: presentJarOptions.ExpectedVerifierClientId,
                flowId: presentJarOptions.FlowId ?? Guid.NewGuid().ToString(),
                timeProvider: options.TimeProvider);

        await pda.StepAsync(
            new JarReceived(presentJarOptions.RequestUri, request, options.TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);

        IReadOnlyList<TCredential> candidates = await walletConfiguration.ResolveCandidateCredentials(
            request.DcqlQuery, cancellationToken).ConfigureAwait(false);

        if(candidates.Count == 0)
        {
            throw new InvalidOperationException(
                $"ResolveCandidateCredentials returned no candidates for credential query '{credentialQueryId}'.");
        }

        TCredential chosenCredential = candidates[0];
        PreparedDcqlQuery preparedQuery = DcqlPreparer.Prepare(request.DcqlQuery);

        await pda.StepAsync(
            new DcqlMatched(
                preparedQuery,
                new Dictionary<string, string> { [credentialQueryId] = chosenCredential.CompactSdJwt },
                options.TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);

        string vpTokenJson = await BuildVpTokenJsonAsync(
            credentialQueryId,
            chosenCredential,
            preparedQuery,
            request,
            presentJarOptions,
            cancellationToken).ConfigureAwait(false);

        await pda.StepAsync(
            new PresentationSelected(vpTokenJson, options.TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);

        byte[] vpTokenBytes = Encoding.UTF8.GetBytes(vpTokenJson);
        string compactJwe = await HaipProfile.EncryptResponseAsync(
            request,
            vpTokenBytes,
            walletConfiguration.JwtHeaderSerializer,
            walletConfiguration.TagToEpkCrvConverter,
            walletConfiguration.KeyAgreementEncrypt,
            walletConfiguration.KeyDerivation,
            walletConfiguration.AeadEncrypt,
            options.Base64UrlEncoder,
            walletConfiguration.Base64UrlDecoder,
            walletConfiguration.MemoryPool,
            cancellationToken).ConfigureAwait(false);

        Dictionary<string, string> postFields = new(StringComparer.Ordinal)
        {
            [AuthorizationResponseParameters.Response] = compactJwe
        };
        if(!string.IsNullOrEmpty(request.State))
        {
            postFields[OAuthRequestParameters.State] = request.State;
        }

        HttpResponseData postResponse = await options.SendFormPostAsync(
            request.ResponseUri,
            postFields,
            cancellationToken).ConfigureAwait(false);

        if(postResponse.StatusCode != 200)
        {
            throw new InvalidOperationException(
                $"direct_post to {request.ResponseUri} returned status {postResponse.StatusCode}: " +
                $"{postResponse.Body}");
        }

        await pda.StepAsync(
            new ResponsePostedByWallet(
                request.ResponseUri,
                request.State,
                options.TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);

        return new PresentationResult
        {
            EncryptedJweResponse = compactJwe,
            TerminalState = pda.CurrentState
        };
    }


    private async ValueTask<string> BuildVpTokenJsonAsync(
        string credentialQueryId,
        TCredential chosenCredential,
        PreparedDcqlQuery preparedQuery,
        AuthorizationRequestObject request,
        PresentJarOptions<TCredential> presentJarOptions,
        CancellationToken cancellationToken)
    {
        using SdToken<string> parsedToken =
            walletConfiguration.ParseSdJwt(chosenCredential.CompactSdJwt);

        SdToken<string> selectedToken = presentJarOptions.DisclosureSelection is null
            ? parsedToken.SelectDisclosures(static _ => true, walletConfiguration.MemoryPool)
            : SelectByClaimNames(
                parsedToken,
                presentJarOptions.DisclosureSelection(chosenCredential, preparedQuery),
                walletConfiguration.MemoryPool);

        try
        {
            string hashInput = walletConfiguration.ComputeSdJwtHashInput(selectedToken);
            byte[] hashInputBytes = Encoding.UTF8.GetBytes(hashInput);

            string compactKbJwt = await KbJwtIssuance.IssueAsync(
                hashInputBytes,
                presentJarOptions.HolderKey,
                request.Nonce,
                request.ClientId,
                options.TimeProvider.GetUtcNow(),
                options.Base64UrlEncoder,
                walletConfiguration.JwtHeaderSerializer,
                walletConfiguration.JwtPayloadSerializer,
                walletConfiguration.MemoryPool,
                cancellationToken).ConfigureAwait(false);

            using SdToken<string> tokenWithKb = selectedToken.WithKeyBinding(
                compactKbJwt, walletConfiguration.MemoryPool);
            string compactPresentation = walletConfiguration.SerializeSdJwt(tokenWithKb);

            return VpTokenSerializer.SerializeSingleSdJwtVc(
                credentialQueryId,
                compactPresentation,
                walletConfiguration.JwtPayloadSerializer);
        }
        finally
        {
            selectedToken.Dispose();
        }
    }


    private static SdToken<string> SelectByClaimNames(
        SdToken<string> source,
        IReadOnlySet<string> selectedClaimNames,
        MemoryPool<byte> pool) =>
        source.SelectDisclosures(
            d => d.ClaimName is not null && selectedClaimNames.Contains(d.ClaimName),
            pool);
}
