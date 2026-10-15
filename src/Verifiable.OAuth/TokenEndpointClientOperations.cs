using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.Cryptography;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// The token-endpoint plumbing shared by every client-side grant that ends at an authorization
/// server's token endpoint: metadata resolution and issuer validation, the outbound-fetch policy
/// gate, confidential-client authentication attachment, and the DPoP-nonce-retrying send. The
/// Authorization Code token/refresh legs (<see cref="AuthCodeFlowHandlers"/>) and the
/// <c>client_credentials</c> grant (<see cref="Verifiable.OAuth.ClientCredentials.ClientCredentialsFlowHandlers"/>)
/// both call these rather than each keeping its own copy.
/// </summary>
internal static class TokenEndpointClientOperations
{
    /// <summary>
    /// Resolves the authorization server's metadata via
    /// <see cref="OAuthClientInfrastructure.ResolveAuthorizationServerMetadataAsync"/>, maps a
    /// non-<see cref="AuthorizationServerMetadataResolved"/> outcome to the
    /// caller's own <see cref="AuthCodeFlowEndpointResult"/> failure, and otherwise verifies the
    /// resolved <see cref="AuthorizationServerMetadata.Issuer"/> against the pinned
    /// <see cref="ClientRegistration.AuthorizationServerIssuer"/> via
    /// <see cref="AuthorizationServerMetadataValidation.IsIssuerMatch"/> — RFC 8414 §3.3's
    /// issuer-match requirement, which for a client relying on OAuth metadata is also RFC 9207
    /// §2.4's "clients ... MUST compare the iss parameter value to the issuer value in the
    /// server's metadata document" reduced to the metadata-consistency half. Every caller resolves
    /// metadata through this one seam so the check applies uniformly rather than needing to be
    /// repeated per call site.
    /// </summary>
    internal static async ValueTask<Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult>> ResolveValidatedAuthorizationServerMetadataAsync(
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        AuthorizationServerMetadataResolution resolution = await infrastructure
            .ResolveAuthorizationServerMetadataAsync(registration.AuthorizationServerIssuer, context, cancellationToken)
            .ConfigureAwait(false);

        if(resolution is not AuthorizationServerMetadataResolved resolved)
        {
            return Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult>.Failure(
                BuildAuthorizationServerMetadataResolutionFailure(resolution));
        }

        AuthorizationServerMetadata metadata = resolved.Metadata;

        if(!AuthorizationServerMetadataValidation.IsIssuerMatch(metadata, registration.AuthorizationServerIssuer))
        {
            return Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult>.Failure(
                new AuthCodeFlowEndpointResult
                {
                    Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                    ErrorCode = "invalid_request",
                    ErrorDescription =
                        "The authorization server metadata issuer does not match this registration's " +
                        "pinned AuthorizationServerIssuer (RFC 8414 §3.3 / RFC 9207 §2.4)."
                });
        }

        return Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult>.Success(metadata);
    }


    /// <summary>
    /// Builds the fixed, non-revealing server error for a failed resolution. Only the outcome type
    /// name enters the trace; server-controlled values never enter the wire response.
    /// </summary>
    private static AuthCodeFlowEndpointResult BuildAuthorizationServerMetadataResolutionFailure(
        AuthorizationServerMetadataResolution resolution)
    {
        ActivityTagsCollection tags = new()
        {
            [OAuthEventNames.AuthorizationServerMetadataResolutionOutcomeTagName] = resolution.GetType().Name
        };

        _ = (Activity.Current?.AddEvent(new ActivityEvent(
            OAuthEventNames.AuthorizationServerMetadataResolutionFailed, tags: tags)));

        return new AuthCodeFlowEndpointResult
        {
            Outcome = AuthCodeFlowEndpointOutcome.InternalError,
            ErrorCode = "server_error",
            ErrorDescription = "The authorization server metadata could not be resolved."
        };
    }


    /// <summary>
    /// Evaluates <paramref name="target"/> against <paramref name="context"/>'s
    /// <see cref="OutboundFetchPolicy"/> before a client-side dial to an endpoint taken from
    /// discovered authorization-server metadata. <see cref="OutboundRequest"/>'s remarks: "the
    /// endpoints a client POSTs to ... are themselves taken from discovered metadata, so a
    /// malicious or misconfigured metadata document could point them at an internal, loopback, or
    /// cloud-metadata address ... The OutboundFetchPolicy must therefore gate every method." A
    /// denial never reaches the transport delegate; the reason and the denied endpoint ride an
    /// <see cref="OAuthEventNames.OutboundFetchPolicyDenied"/> trace event rather than the
    /// caller-visible <see cref="AuthCodeFlowEndpointResult.ErrorDescription"/>, since the denied
    /// endpoint came from a document the authorization server itself controls.
    /// </summary>
    /// <param name="target">The endpoint the caller is about to dial.</param>
    /// <param name="context">The per-operation exchange context carrying the policy.</param>
    /// <param name="infrastructure">
    /// Supplies <see cref="OAuthClientInfrastructure.OutboundFetchPolicy"/>, the deployment
    /// default applied when <paramref name="context"/> carries none.
    /// </param>
    /// <returns>
    /// <see langword="null"/> when <paramref name="target"/> is allowed; otherwise a fixed,
    /// non-revealing denial result.
    /// </returns>
    internal static AuthCodeFlowEndpointResult? EvaluateOutboundPolicy(
        Uri target, ExchangeContext context, OAuthClientInfrastructure infrastructure)
    {
        OutboundFetchPolicy policy = context.ResolveOutboundFetchPolicy(infrastructure.OutboundFetchPolicy);
        OutboundFetchDecision decision = policy.Evaluate(target);

        if(decision.IsAllowed)
        {
            return null;
        }

        ActivityTagsCollection tags = new()
        {
            [OAuthEventNames.OutboundFetchPolicyDenialReasonTagName] = decision.DenyReason,
            [OAuthEventNames.OutboundFetchPolicyDenialEndpointTagName] = target.ToString()
        };

        _ = (Activity.Current?.AddEvent(new ActivityEvent(OAuthEventNames.OutboundFetchPolicyDenied, tags: tags)));

        return new AuthCodeFlowEndpointResult
        {
            Outcome = AuthCodeFlowEndpointOutcome.InternalError,
            ErrorCode = "server_error",
            ErrorDescription = "The endpoint was refused by the outbound fetch policy."
        };
    }


    /// <summary>
    /// Forms, before anything is composed or sent, the key a registration's assertion method composes its assertions under
    /// (<see cref="ClientAssertionCredential.Of"/>): for <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/> and
    /// <see cref="ClientAuthenticationMethod.ClientSecretJwt"/> the key, or the caller's failure carrying the typed
    /// <see cref="ClientAssertionRefusal"/> (<see cref="AuthCodeFlowEndpointResult.ClientAssertionRefusal"/>) of options
    /// or a secret the assertion refuses; for every other method no key.
    /// </summary>
    /// <param name="registration">The registration naming the method.</param>
    /// <param name="clientAssertionOptions">The assertion options, required for an assertion method.</param>
    /// <returns>The key, <see langword="null"/> for a method presenting no assertion, or the refusal.</returns>
    /// <exception cref="InvalidOperationException">An assertion method is handed no options.</exception>
    internal static Result<ClientAssertionCredential?, AuthCodeFlowEndpointResult> ResolveClientAssertionKey(
        ClientRegistration registration,
        ClientAssertionOptions? clientAssertionOptions)
    {
        if(!PresentsAssertion(registration))
        {
            return Result<ClientAssertionCredential?, AuthCodeFlowEndpointResult>.Success(null);
        }

        if(clientAssertionOptions is null)
        {
            throw new InvalidOperationException(
                $"ClientAuthenticationMethod.{ClientAuthenticationMethodNames.GetName(registration.AuthenticationMethod)} "
                + "requires a ClientAssertionOptions instance to compose the client_assertion.");
        }

        var key = ClientAssertionCredential.Of(registration, clientAssertionOptions);
        if(!key.IsSuccess)
        {
            return Result<ClientAssertionCredential?, AuthCodeFlowEndpointResult>.Failure(new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.InternalError,
                ErrorCode = "server_error",
                ErrorDescription = key.Error.Describe(),
                ClientAssertionRefusal = key.Error
            });
        }

        return Result<ClientAssertionCredential?, AuthCodeFlowEndpointResult>.Success(key.Value);
    }


    /// <summary>
    /// Attaches confidential-client authentication to <paramref name="form"/> (and, for
    /// <c>client_secret_basic</c>, to the returned <see cref="OutgoingHeaders"/>) per
    /// <see cref="ClientRegistration.AuthenticationMethod"/>: <see cref="ClientAuthenticationMethod.None"/>
    /// attaches nothing (the request relies on PKCE alone on the Authorization Code leg, RFC 7636,
    /// or on nothing beyond the client identifier on the client_credentials leg);
    /// <see cref="ClientAuthenticationMethod.ClientSecretPost"/> and
    /// <see cref="ClientAuthenticationMethod.ClientSecretBasic"/> present
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/>'s private-key bytes as the shared
    /// secret (RFC 6749 §2.3.1); and <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/> and
    /// <see cref="ClientAuthenticationMethod.ClientSecretJwt"/> attach a <c>client_assertion</c> composed under the key
    /// <see cref="ResolveClientAssertionKey"/> formed via
    /// <see cref="ClientTokenEndpointAuthentication.AttachClientAssertionAsync"/> (RFC 7523 §2.2; OpenID Connect Core 1.0 §9).
    /// </summary>
    /// <param name="form">The outgoing form fields.</param>
    /// <param name="registration">The registration naming the method.</param>
    /// <param name="tokenEndpoint">The resolved token endpoint.</param>
    /// <param name="assertionKey">The key <see cref="ResolveClientAssertionKey"/> formed, <see langword="null"/> for a method presenting no assertion.</param>
    /// <param name="clientAssertionOptions">The assertion options, read for an assertion method.</param>
    /// <param name="infrastructure">The client infrastructure.</param>
    /// <param name="now">The instant of this attempt.</param>
    /// <param name="context">The per-operation exchange context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The header fields the authentication adds.</returns>
    internal static ValueTask<OutgoingHeaders> AttachClientAuthenticationAsync(
        OutgoingFormFields form,
        ClientRegistration registration,
        Uri tokenEndpoint,
        ClientAssertionCredential? assertionKey,
        ClientAssertionOptions? clientAssertionOptions,
        OAuthClientInfrastructure infrastructure,
        DateTimeOffset now,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        static ValueTask<OutgoingHeaders> AttachNone() =>
            ValueTask.FromResult(OutgoingHeaders.Empty);

        static ValueTask<OutgoingHeaders> AttachClientSecretPost(OutgoingFormFields form, ClientRegistration registration)
        {
            var secret = RequireAuthenticationKey(registration);
            _ = form.WithClientSecretPost(registration.ClientId.Value, secret.AsReadOnlySpan());

            return ValueTask.FromResult(OutgoingHeaders.Empty);
        }

        static ValueTask<OutgoingHeaders> AttachClientSecretBasic(ClientRegistration registration)
        {
            var secret = RequireAuthenticationKey(registration);
            var headers = OutgoingHeaders.Empty.WithClientSecretBasic(registration.ClientId.Value, secret.AsReadOnlySpan());

            return ValueTask.FromResult(headers);
        }

        static async ValueTask<OutgoingHeaders> AttachAssertion(
            OutgoingFormFields form,
            ClientRegistration registration,
            Uri tokenEndpoint,
            ClientAssertionCredential? assertionKey,
            ClientAssertionOptions? clientAssertionOptions,
            OAuthClientInfrastructure infrastructure,
            DateTimeOffset now,
            ExchangeContext context,
            CancellationToken cancellationToken)
        {
            if(assertionKey is null || clientAssertionOptions is null)
            {
                throw new InvalidOperationException(
                    "A client assertion is attached under the key and the options ResolveClientAssertionKey formed before the request was composed.");
            }

            await ClientTokenEndpointAuthentication.AttachClientAssertionAsync(
                form,
                registration,
                tokenEndpoint,
                assertionKey,
                clientAssertionOptions.HeaderSerializer,
                clientAssertionOptions.PayloadSerializer,
                clientAssertionOptions.ClientAssertionLifetime,
                infrastructure,
                now,
                context,
                cancellationToken).ConfigureAwait(false);

            return OutgoingHeaders.Empty;
        }

        return registration.AuthenticationMethod.Code switch
        {
            var c when c == ClientAuthenticationMethod.None.Code => AttachNone(),
            var c when c == ClientAuthenticationMethod.ClientSecretPost.Code => AttachClientSecretPost(form, registration),
            var c when c == ClientAuthenticationMethod.ClientSecretBasic.Code => AttachClientSecretBasic(registration),
            _ when PresentsAssertion(registration) => AttachAssertion(
                form, registration, tokenEndpoint, assertionKey, clientAssertionOptions, infrastructure, now, context, cancellationToken),
            _ => throw new NotSupportedException(
                $"Client authentication method '{ClientAuthenticationMethodNames.GetName(registration.AuthenticationMethod)}' " +
                "is not supported at the token endpoint.")
        };
    }


    /// <summary>
    /// Whether a registration's method presents a client assertion: <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/>
    /// or <see cref="ClientAuthenticationMethod.ClientSecretJwt"/> (RFC 7523 §2.2).
    /// </summary>
    /// <param name="registration">The registration.</param>
    /// <returns><see langword="true"/> for an assertion method.</returns>
    private static bool PresentsAssertion(ClientRegistration registration) =>
        registration.AuthenticationMethod.Code == ClientAuthenticationMethod.PrivateKeyJwt.Code
        || registration.AuthenticationMethod.Code == ClientAuthenticationMethod.ClientSecretJwt.Code;


    /// <summary>
    /// Reads the confidential-client secret or signing key from
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/>, non-owning per its own remarks —
    /// the caller reads the key's bytes via <see cref="SensitiveMemory.AsReadOnlySpan"/> for the
    /// duration of the call and does not retain or copy them.
    /// </summary>
    private static PrivateKeyMemory RequireAuthenticationKey(ClientRegistration registration) =>
        registration.AuthenticationKeyMaterial?.PrivateKey
        ?? throw new InvalidOperationException(
            $"ClientAuthenticationMethod.{ClientAuthenticationMethodNames.GetName(registration.AuthenticationMethod)} " +
            "requires ClientRegistration.AuthenticationKeyMaterial to carry the client secret or signing key.");


    /// <summary>
    /// Sends a token-endpoint request with a DPoP proof attached when
    /// <paramref name="infrastructure"/> has DPoP wired, retrying once on a
    /// <c>use_dpop_nonce</c> challenge per RFC 9449 §8.1. Evaluates the outbound-fetch policy via
    /// <see cref="EvaluateOutboundPolicy"/> before the first send.
    /// </summary>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, DPoP, and time delegates.</param>
    /// <param name="tokenEndpoint">The token endpoint to dial.</param>
    /// <param name="tokenFields">The outgoing form fields to send; mutated in place by <paramref name="attachClientAuthenticationAsync"/> on each attempt.</param>
    /// <param name="attachClientAuthenticationAsync">
    /// Re-attaches confidential-client authentication to the outgoing request for one attempt,
    /// given that attempt's instant. Called once per attempt (see <see cref="SendWithDpopRetryAsync"/>)
    /// rather than once for the whole call, because RFC 9449 §8's retry re-sends the request the
    /// server just challenged: under <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/> the
    /// assertion carries its own <c>jti</c> (RFC 7523 §3.1), and an authorization server that also
    /// runs a client-assertion replay defense on it would refuse a retry that presented the same
    /// signed assertion twice. A caller wires this from
    /// <see cref="AttachClientAuthenticationAsync"/> bound to every parameter except <c>now</c>.
    /// </param>
    /// <param name="context">The per-operation exchange context threaded into the transport delegate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <remarks>
    /// The policy gate and the send are separated so a caller that maps a denial to its own
    /// failure type — <see cref="Verifiable.OAuth.IdJag.IdJagFlowHandlers"/> maps it to
    /// <see cref="OAuthOutboundFetchPolicyDenied"/> rather than <see cref="AuthCodeFlowEndpointResult"/> —
    /// can evaluate the policy itself and call <see cref="SendWithDpopRetryAsync"/> directly,
    /// still through this one DPoP-retrying sender. See <see cref="SendWithDpopRetryAsync"/> for
    /// the retry mechanics.
    /// </remarks>
    internal static async ValueTask<Result<HttpResponseData, AuthCodeFlowEndpointResult>> SendTokenRequestWithDpopRetryAsync(
        OAuthClientInfrastructure infrastructure,
        Uri tokenEndpoint,
        OutgoingFormFields tokenFields,
        Func<DateTimeOffset, CancellationToken, ValueTask<OutgoingHeaders>> attachClientAuthenticationAsync,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(EvaluateOutboundPolicy(tokenEndpoint, context, infrastructure) is AuthCodeFlowEndpointResult tokenPolicyDenial)
        {
            return Result<HttpResponseData, AuthCodeFlowEndpointResult>.Failure(tokenPolicyDenial);
        }

        HttpResponseData response = await SendWithDpopRetryAsync(
            infrastructure, tokenEndpoint, tokenFields, attachClientAuthenticationAsync, context, cancellationToken)
            .ConfigureAwait(false);

        return Result<HttpResponseData, AuthCodeFlowEndpointResult>.Success(response);
    }


    /// <summary>
    /// Sends a token-endpoint request with a DPoP proof attached when
    /// <paramref name="infrastructure"/> has DPoP wired, retrying once on a
    /// <c>use_dpop_nonce</c> challenge per RFC 9449 §8.1. Performs no outbound-fetch policy
    /// check of its own — every caller evaluates the policy against <paramref name="tokenEndpoint"/>
    /// first, since a denial maps to a different failure type per caller
    /// (<see cref="SendTokenRequestWithDpopRetryAsync"/> for <see cref="AuthCodeFlowEndpointResult"/>
    /// callers; <see cref="Verifiable.OAuth.IdJag.IdJagFlowHandlers"/> for its own
    /// <see cref="OAuthOutboundFetchPolicyDenied"/>).
    /// </summary>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, DPoP, and time delegates.</param>
    /// <param name="tokenEndpoint">The token endpoint to dial.</param>
    /// <param name="tokenFields">The outgoing form fields to send; mutated in place by <paramref name="attachClientAuthenticationAsync"/> on each attempt.</param>
    /// <param name="attachClientAuthenticationAsync">See <see cref="SendTokenRequestWithDpopRetryAsync"/>'s parameter of the same name.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport delegate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <remarks>
    /// <para>
    /// The retry-once mechanics (nonce lookup, challenge detection, storing the fresh nonce,
    /// resending) are <see cref="DpopNonceRetry.SendWithNonceRetryAsync"/> — the same helper the
    /// OID4VCI Wallet client's token and resource requests use, so the rule lives in one place.
    /// Here the retry applies only when the AS responds with HTTP 400 + <c>error=use_dpop_nonce</c>
    /// in the body and a fresh nonce in the <c>DPoP-Nonce</c> response header. There is no
    /// exponential backoff and no second retry — applications wanting elaborate retry policies
    /// wrap this call.
    /// </para>
    /// <para>
    /// <paramref name="attachClientAuthenticationAsync"/> runs again on every attempt, including
    /// the retry — RFC 9449 §8's retry is the SAME request re-sent, and re-running the attachment
    /// per attempt is what lets a <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/> assertion
    /// carry a fresh <c>jti</c>/<c>iat</c> each time rather than the one the server just saw.
    /// </para>
    /// <para>
    /// When DPoP is not wired (proof construction or key absent), the
    /// request is sent without DPoP and the response is returned
    /// unchanged.
    /// </para>
    /// </remarks>
    internal static async ValueTask<HttpResponseData> SendWithDpopRetryAsync(
        OAuthClientInfrastructure infrastructure,
        Uri tokenEndpoint,
        OutgoingFormFields tokenFields,
        Func<DateTimeOffset, CancellationToken, ValueTask<OutgoingHeaders>> attachClientAuthenticationAsync,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(infrastructure.ConstructDpopProofAsync is null || infrastructure.DpopKey is null)
        {
            //DPoP not wired — a single attempt, so there is no retry to refresh the attachment for.
            OutgoingHeaders authenticationHeaders = await attachClientAuthenticationAsync(
                infrastructure.TimeProvider.GetUtcNow(), cancellationToken).ConfigureAwait(false);

            return await infrastructure.SendFormPostAsync(
                tokenEndpoint, tokenFields, authenticationHeaders, context, cancellationToken)
                .ConfigureAwait(false);
        }

        string authority = InMemoryDpopNonceCache.AuthorityFor(tokenEndpoint);

        //RFC 9449 §8.1: 400 + error=use_dpop_nonce in the JSON body + a DPoP-Nonce header is the
        //token endpoint's challenge form; DpopNonceRetry owns the retry-once mechanics shared with
        //the OID4VCI Wallet client's token and resource requests.
        return await DpopNonceRetry.SendWithNonceRetryAsync(
            (nonce, ct) => SendOnceWithDpopAsync(infrastructure, tokenEndpoint, tokenFields, attachClientAuthenticationAsync, nonce, context, ct),
            static candidate => candidate.StatusCode == 400 && candidate.Body.Contains(OAuthErrors.UseDpopNonce, StringComparison.Ordinal),
            authority,
            infrastructure.LookupDpopNonce,
            infrastructure.StoreDpopNonce,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Re-attaches confidential-client authentication for this attempt, mints one fresh DPoP proof
    /// bound to <paramref name="tokenEndpoint"/> — embedding <paramref name="nonce"/> when the caller
    /// supplies one — and sends the token request once. The
    /// <see cref="DpopNonceRetry.SendWithNonceRetryAsync"/> caller supplies this as its per-attempt
    /// send delegate, so it runs once per attempt, including the retry.
    /// </summary>
    private static async ValueTask<HttpResponseData> SendOnceWithDpopAsync(
        OAuthClientInfrastructure infrastructure,
        Uri tokenEndpoint,
        OutgoingFormFields tokenFields,
        Func<DateTimeOffset, CancellationToken, ValueTask<OutgoingHeaders>> attachClientAuthenticationAsync,
        string? nonce,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();

        //RFC 9449 §8.1's retry re-sends the SAME request; re-attaching here rather than once before
        //the first attempt is what gives a private_key_jwt assertion a fresh jti/iat on the retry
        //(see SendWithDpopRetryAsync's remarks) instead of the assertion the challenged attempt
        //already presented.
        OutgoingHeaders authenticationHeaders = await attachClientAuthenticationAsync(now, cancellationToken)
            .ConfigureAwait(false);

        string jti = await infrastructure.GenerateIdentifierAsync(
            WellKnownIdentifierPurposes.OAuthJti, null, cancellationToken)
            .ConfigureAwait(false);

        DpopProofClaims claims = new()
        {
            Htm = WellKnownHttpMethods.Post,
            Htu = tokenEndpoint.GetLeftPart(UriPartial.Path),
            Iat = now,
            Jti = jti,
            Nonce = nonce
        };

        string proof = await infrastructure.ConstructDpopProofAsync!(
            claims, infrastructure.DpopKey!, cancellationToken).ConfigureAwait(false);

        OutgoingHeaders headers = authenticationHeaders.WithDpop(proof);

        return await infrastructure.SendFormPostAsync(
            tokenEndpoint, tokenFields, headers, context, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Maps an <see cref="OAuthParseError"/> to an <see cref="AuthCodeFlowEndpointResult"/>,
    /// surfacing the decision support summary as the error description so callers have actionable
    /// information without needing to pattern-match the full error hierarchy.
    /// </summary>
    internal static AuthCodeFlowEndpointResult BuildEndpointResultFromParseError(
        OAuthParseError error)
    {
        return error switch
        {
            OAuthProtocolError pe => new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = pe.ErrorCode,
                ErrorDescription = pe.ErrorDescription ?? pe.Support.Summary
            },
            OAuthInvalidFieldValue ifv => new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "invalid_response",
                ErrorDescription = $"{ifv.FieldName}: {ifv.Reason}"
            },
            OAuthMalformedResponse mr => new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.InternalError,
                ErrorCode = "server_error",
                ErrorDescription = mr.Support.Summary
            },
            _ => new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.InternalError,
                ErrorCode = "server_error",
                ErrorDescription = error.Support.Summary
            }
        };
    }


    /// <summary>
    /// Appends each entry of <paramref name="resource"/> as its OWN <c>resource</c> occurrence
    /// onto <paramref name="fields"/> (<see cref="OutgoingFormFields.Add"/>) — RFC 8707 §2's
    /// genuine multi-resource wire form, never several indicators joined by a space into one
    /// occurrence. A <see langword="null"/>, empty, or all-whitespace entry is skipped rather
    /// than emitted as a blank occurrence.
    /// </summary>
    /// <param name="fields">The outgoing form fields the resource occurrences are appended to.</param>
    /// <param name="resource">The resource indicator(s) to append, or <see langword="null"/> to append none.</param>
    internal static void AddResourceOccurrences(OutgoingFormFields fields, IReadOnlyList<string>? resource)
    {
        if(resource is null)
        {
            return;
        }

        foreach(string indicator in resource)
        {
            if(!string.IsNullOrWhiteSpace(indicator))
            {
                fields.Add(OAuthRequestParameterNames.Resource, indicator);
            }
        }
    }
}
