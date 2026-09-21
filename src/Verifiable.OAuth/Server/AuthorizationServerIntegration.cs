using System.Collections.Immutable;
using System.Diagnostics;
using System.Text;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server.Keys;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Groups the integration delegates by which the Authorization Server asks the
/// application to resolve request data and read or write persistent state.
/// </summary>
/// <remarks>
/// <para>
/// Every delegate on this group has the same shape: <em>the library has a question,
/// the application supplies an answer</em>. None of the delegates perform protocol
/// logic — that lives entirely inside <see cref="EndpointServer"/>. They only
/// answer questions that depend on the application's deployment choices: which
/// signal identifies a tenant, where flow state is persisted, what URLs endpoints
/// are exposed at, and so on.
/// </para>
/// <para>
/// The seams are set at construction and altered while serving through the requested,
/// drained, candidate-validated alteration operation described in
/// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration</see>.
/// A serving setter throws a named configuration fault. Candidate validation names missing
/// delegates before a complete wiring copy is published. Delegates share application resources;
/// the application owns their synchronization and retirement after requests drain.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationServerIntegration Validated={IsValidated}")]
public sealed class AuthorizationServerIntegration: ServerIntegration
{
    /// <summary>Preserves RFC 7592 section 2.1 authentication refusal at the configured management URI when its client is absent.</summary>
    /// <param name="tenantId">The resolved tenant whose record is absent.</param>
    /// <param name="context">The admitted request context.</param>
    /// <param name="cancellationToken">Cancellation of endpoint URI resolution.</param>
    public override async ValueTask<ServerHttpResponse> ResolveMissingRegistrationAsync(
        TenantId tenantId, ExchangeContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        if(ValidateRegistrationAccessTokenAsync is not null && ResolveEndpointUriAsync is not null)
        {
            ClientRecord route = new()
            {
                ClientId = string.Empty,
                TenantId = tenantId,
                AllowedCapabilities = [],
                AllowedRedirectUris = [],
                AllowedScopes = [],
                TokenLifetimes = System.Collections.Immutable.ImmutableDictionary<string, TimeSpan>.Empty,
                SigningKeys = System.Collections.Immutable.ImmutableDictionary<Verifiable.Cryptography.Context.KeyUsageContext, SigningKeySet>.Empty
            };
            Uri? uri = await ResolveEndpointUriAsync(WellKnownEndpointNames.RegistrationRegister,
                route, context, cancellationToken).ConfigureAwait(false);
            if(uri is { IsAbsoluteUri: true } && context.IncomingRequest is { } request
                && PathEquals.Equals(request.Path, uri.AbsolutePath))
            {

                return ServerHttpResponse.Unauthorized(OAuthErrors.InvalidToken, "Registration access token is invalid.");
            }
        }

        return await base.ResolveMissingRegistrationAsync(tenantId, context, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The cryptographic-material delegate group (signing, verification, decryption, JWKS
    /// assembly) the OAuth/OpenID endpoints and token producers use.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// <para>Candidate assignments copy this container and refuse components attached to another server.
    /// Application resources and delegate targets remain shared references.</para>
    /// </remarks>
    public AuthorizationServerCryptography Cryptography
    {
        get;
        set
        {
            WithComponentLocks([this, value], () =>
            {
                EnsureMutable();
                field = AdoptComponent(value)!;
            });
        }
    } = new();


    /// <summary>
    /// The encoding, decoding, hashing, and JWT-serialization delegate group the OAuth/OpenID
    /// endpoints use.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// <para>Candidate assignments copy this container and refuse components attached to another server.
    /// Application resources and delegate targets remain shared references.</para>
    /// </remarks>
    public AuthorizationServerCodecs Codecs
    {
        get;
        set
        {
            WithComponentLocks([this, value], () =>
            {
                EnsureMutable();
                field = AdoptComponent(value)!;
            });
        }
    } = new();


    /// <summary>
    /// The token producers that compose the response of a token-issuing endpoint.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// <para>
    /// Membership and order are immutable. Producer delegates retain shared application targets whose
    /// synchronization and lifetime remain application responsibilities.
    /// </para>
    /// </remarks>
    public TokenProducerSet TokenProducers
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    } = TokenProducerSet.Empty;


    /// <summary>
    /// The composed claim-contribution issuer that emits the additional claims merged into
    /// token payloads.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Verifiable.Core.Assessment.ClaimIssuer<ClaimContributionTarget>? ClaimIssuer
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Drives effectful work between pure PDA transitions for OAuth flows that emit
    /// <see cref="OAuthAction"/> values (e.g. the OID4VP Verifier flow).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// <para>
    /// The host action bridge must resolve this executor from context.RequestServer so direct endpoint
    /// actions and the generic flow loop use the same admitted registry.
    /// </para>
    /// <para>Candidate assignments copy this container and refuse components attached to another server.
    /// Application resources and delegate targets remain shared references.</para>
    /// </remarks>
    public OAuthActionExecutor? ActionExecutor
    {
        get;
        set
        {
            WithComponentLocks([this, value], () =>
            {
                EnsureMutable();
                field = AdoptComponent(value);
            });
        }
    }


    /// <summary>
    /// The deployment defaults consulted by selected timing sites. Policy profiles and token producers
    /// also define independent defaults and registration overrides. Defaults to <see cref="TimingPolicy.Default"/>.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public TimingPolicy Timings
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    } = TimingPolicy.Default;


    /// <summary>
    /// The memory pool every OAuth/OpenID endpoint handler rents its transient
    /// signing/verification/parsing buffers from. Required at construction: the
    /// compiler enforces its presence, and <see cref="Validate"/> refuses a null pool.
    /// The host keeps the pool alive until requests using its wiring complete.
    /// </summary>
    public required BaseMemoryPool MemoryPool { get; init; }


    /// <summary>
    /// Loads a <see cref="ClientRecord"/> by tenant identifier. Required.
    /// </summary>
    /// <remarks>
    /// Aliases LoadRegistrationAsync and follows its validation invalidation and serving setter rule.
    /// The route resolves the tenant; this delegate selects the EFFECTIVE registration for it,
    /// reading the incoming request off the <see cref="ExchangeContext"/> it is called with when
    /// the application serves several clients under one tenant route. Its return value is the
    /// SELECTED registration for the request: the OAuth endpoint families that read a
    /// caller-presented <c>client_id</c> identify it against that registration before consuming or
    /// mutating any grant-bearing record; client authentication validates the declared
    /// authentication method's own credentials, separately. The
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1">OID4VCI
    /// 1.0 §6.1</see> Pre-Authorized Code grant's Token Request is the one exception: its wallet
    /// identifier is a class the application vouches for through
    /// <see cref="ValidatePreAuthorizedCodeAsync"/>, never a library comparison against this
    /// selected registration.
    /// </remarks>
    public LoadRegistrationDelegate? LoadClientRegistrationAsync
    {
        get => LoadRegistrationAsync;
        set => LoadRegistrationAsync = value;
    }


    /// <summary>
    /// Maps the authenticated end-user identifier to the subject identifier
    /// emitted in tokens for a registration — public (identity) or pairwise
    /// (per-sector hash) per OIDC Core §8. Wire to
    /// <see cref="Verifiable.OAuth.Server.Pipeline.DefaultSubjectIdentifierResolver.PublicAsync"/> for the
    /// identity default.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A structural slot the UserInfo wiring resolves the subject identifier
    /// through.
    /// </para>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// </remarks>
    public ResolveSubjectIdentifierDelegate? ResolveSubjectIdentifierAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Fetches and validates Client ID Metadata Documents for CIMD clients.
    /// Optional.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ResolveClientMetadataDelegate? ResolveClientMetadataAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Parses an incoming RFC 7591 client metadata document body into a typed
    /// <see cref="Client.ClientMetadata"/>. Required when
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration"/> is
    /// advertised. No default implementation is shipped — the application
    /// supplies its own, following the shape of
    /// <see cref="Verifiable.OAuth.OAuthResponseParsers.ParseParResponse"/> and
    /// <see cref="Verifiable.OAuth.OAuthResponseParsers.ParseTokenResponse"/>.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ParseClientMetadataServerDelegate? ParseClientMetadataAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Validates a bearer token presented at an RFC 7592 management endpoint.
    /// Required when
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration"/> is
    /// advertised — the application implements the constant-time comparison
    /// against its persisted form.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ValidateRegistrationAccessTokenDelegate? ValidateRegistrationAccessTokenAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Contributes additional fields to the discovery document
    /// (<c>/.well-known/openid-configuration</c> and equivalents). Optional.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The library's discovery endpoint emits its base OAuth 2.0 and OIDC fields
    /// first, then merges the contributed fields over the top. Applications use
    /// this delegate to advertise OIDC, FAPI, OID4VP, OID4VCI, OpenID Federation
    /// or deployment-specific capability fields without replacing the discovery
    /// endpoint.
    /// </para>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// </remarks>
    public ContributeDiscoveryFieldsDelegate? ContributeDiscoveryFieldsAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Contributes the per-entity-type metadata blocks, authority hints, and
    /// extension claims that populate the entity's own OpenID Federation 1.0
    /// Entity Configuration JWT at <c>/.well-known/openid-federation</c>.
    /// Optional.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.PublishEntityConfiguration"/>.
    /// The library emits the EC's structural claims (<c>iss</c>, <c>sub</c>,
    /// <c>iat</c>, <c>exp</c>, <c>jwks</c>) on its own; this delegate supplies
    /// the per-entity-type metadata blocks and federation extension claims.
    /// </para>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// </remarks>
    public ContributeFederationMetadataDelegate? ContributeFederationMetadataAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves the Subordinate Statement body the issuing entity asserts
    /// about a queried subject. Optional.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.PublishSubordinateStatement"/>.
    /// The library emits the SS's structural claims and signs the result;
    /// this delegate supplies the subject's <c>jwks</c> plus any per-subject
    /// metadata-policy / metadata / constraints / extension claims.
    /// Return <see langword="null"/> when the queried subject is not a
    /// known subordinate — the endpoint then responds 404.
    /// </para>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// </remarks>
    public ResolveSubordinateStatementDelegate? ResolveSubordinateStatementAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves the immediate subordinates the issuing entity lists at its
    /// <c>federation_list_endpoint</c>. Optional.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.ListSubordinates"/>.
    /// The library matches the request, parses the optional
    /// <c>entity_type</c> filter, and serialises the returned identifiers
    /// as the unsigned JSON array OpenID Federation 1.0 §8.2 mandates; this
    /// delegate supplies the membership list itself. Returning an empty
    /// list is valid — the endpoint then responds with an empty JSON array.
    /// </para>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// </remarks>
    public ResolveSubordinateListDelegate? ResolveSubordinateListAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves a subject's effective metadata, trust chain, and trust marks
    /// for the <c>federation_resolve_endpoint</c>. Optional.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.ResolveTrustChain"/>.
    /// The library matches the request, parses the <c>sub</c> / <c>anchor</c>
    /// / <c>type</c> parameters, assembles the OpenID Federation 1.0 §8.3
    /// Resolve Response from the returned contribution, and signs it with the
    /// resolver's federation signing key; this delegate supplies the
    /// resolution result. Return <see langword="null"/> when the subject
    /// cannot be resolved — the endpoint then responds 404.
    /// </para>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// </remarks>
    public ResolveSubjectTrustChainDelegate? ResolveSubjectTrustChainAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Processes a Relying Party's explicit client registration request at the
    /// <c>federation_registration_endpoint</c>. Optional.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.RegisterClientsExplicitly"/>.
    /// The library hands the RP's posted Entity Configuration (raw compact
    /// JWS) to this delegate, assembles the OpenID Federation 1.0 §12.2
    /// Explicit Registration Response from the returned contribution, and
    /// signs it with the OP's federation signing key. Return
    /// <see langword="null"/> when the RP cannot be registered — the endpoint
    /// then responds 400.
    /// </para>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// </remarks>
    public ResolveExplicitRegistrationDelegate? ResolveExplicitRegistrationAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves the entity's historical (rotated and revoked) Federation
    /// Entity Keys for the <c>federation_historical_keys_endpoint</c>.
    /// Optional.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.PublishHistoricalKeys"/>.
    /// The library matches the request, assembles the OpenID Federation 1.0
    /// §8.7.3 Historical Keys payload (<c>iss</c>, <c>iat</c>, <c>keys</c>)
    /// from the returned contribution, and signs it with the entity's
    /// federation signing key; this delegate supplies the historical
    /// <c>keys</c> array itself. Return <see langword="null"/> when the entity
    /// has no historical keys to publish — the endpoint then responds 404.
    /// </para>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// </remarks>
    public ResolveHistoricalKeysDelegate? ResolveHistoricalKeysAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves the Trust Mark JWT the issuing entity serves at its
    /// <c>federation_trust_mark_endpoint</c>. Optional.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.PublishTrustMark"/>.
    /// The library matches the request, parses the <c>trust_mark_type</c> and
    /// <c>sub</c> parameters, and serves the returned compact JWS verbatim as
    /// OpenID Federation 1.0 §8.6 mandates (<c>application/trust-mark+jwt</c>);
    /// the library signs nothing — the Trust Mark was signed when it was issued.
    /// This delegate supplies the Trust Mark JWT itself. Return
    /// <see langword="null"/> when the entity has no Trust Mark of the queried
    /// type for the queried subject — the endpoint then responds 404.
    /// </para>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// </remarks>
    public Federation.ResolveTrustMarkDelegate? ResolveTrustMarkAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves the entities holding a given Trust Mark type the issuing entity
    /// lists at its <c>federation_trust_mark_list_endpoint</c>. Optional.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.PublishTrustMarkedList"/>.
    /// The library matches the request, parses the REQUIRED <c>trust_mark_type</c>
    /// and the OPTIONAL <c>sub</c> filter, and serialises the returned identifiers
    /// as the unsigned JSON array OpenID Federation 1.0 §8.5 mandates; this
    /// delegate supplies the membership list itself. Returning an empty list is
    /// valid — the endpoint then responds with an empty JSON array. Return
    /// <see langword="null"/> when the issuer does not know the queried Trust Mark
    /// type — the endpoint then responds 404.
    /// </para>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// </remarks>
    public Federation.ResolveTrustMarkedListDelegate? ResolveTrustMarkedListAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves the status of a Trust Mark the issuing entity reports at its
    /// <c>federation_trust_mark_status_endpoint</c>. Optional.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.PublishTrustMarkStatus"/>.
    /// The library matches the POST request, reads the <c>trust_mark</c> form
    /// parameter, assembles the OpenID Federation 1.0 §8.4 status payload
    /// (<c>iss</c>, <c>iat</c>, <c>trust_mark</c>, <c>status</c>) from the
    /// returned status string, and signs it with the entity's federation signing
    /// key; this delegate supplies the status string itself. Return
    /// <see langword="null"/> when the issuer does not know the queried Trust
    /// Mark — the endpoint then responds 404.
    /// </para>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// </remarks>
    public Federation.ResolveTrustMarkStatusDelegate? ResolveTrustMarkStatusAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Gates the federation endpoints on OpenID Federation 1.0 §8.8 client
    /// authentication. Optional.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When set, the library invokes this at the start of each federation
    /// endpoint it serves (fetch, list, resolve, trust mark, trust marked
    /// listing, trust mark status, historical keys), before producing the
    /// response. Client authentication is not used by default; a deployment that
    /// declares <c>*_auth_methods</c> on an endpoint (§8.8.1) wires this delegate
    /// to require it. The delegate resolves the requester's Federation Entity
    /// Key, verifies the client authentication JWT, and validates its claims via
    /// <see cref="Federation.FederationClientAuthentication.Validate"/>; returning
    /// a failed result rejects the request with HTTP 401 <c>invalid_client</c>,
    /// and <see langword="null"/> means client authentication is not required at
    /// that endpoint so the request proceeds.
    /// </para>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// </remarks>
    public Federation.AuthenticateFederationClientDelegate? AuthenticateFederationClientAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Parses an OpenID AuthZEN Authorization API 1.0 Access Evaluation
    /// request JSON body into the neutral information model. Required when
    /// <see cref="WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi"/> is
    /// advertised. The shipped default,
    /// <c>Verifiable.Json.AuthZen.AuthZenJsonParsing.ParseAccessEvaluationRequest</c>,
    /// is wired by <c>Verifiable.Json.AuthZen.AuthZenJsonExtensions.UseDefaultAuthZenJsonParsing</c>
    /// (that project depends on this one, so it cannot be named by
    /// <c>cref</c> here).
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ParseAccessEvaluationRequestDelegate? ParseAccessEvaluationRequestAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Parses an OpenID AuthZEN Authorization API 1.0 Access Evaluations API
    /// (batch) request JSON body into the neutral information model. Required
    /// for the <c>access_evaluations_endpoint</c> when
    /// <see cref="WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi"/> is
    /// advertised. The shipped default,
    /// <c>Verifiable.Json.AuthZen.AuthZenJsonParsing.ParseAccessEvaluationsRequest</c>,
    /// is wired by <c>Verifiable.Json.AuthZen.AuthZenJsonExtensions.UseDefaultAuthZenJsonParsing</c>
    /// (that project depends on this one, so it cannot be named by
    /// <c>cref</c> here). The
    /// single-evaluation PDP seam <see cref="EvaluateAccessAsync"/> is reused
    /// for each resolved item.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ParseAccessEvaluationsRequestDelegate? ParseAccessEvaluationsRequestAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// The Policy Decision Point seam — evaluates a parsed AuthZEN Access
    /// Evaluation request and returns the decision. Required when
    /// <see cref="WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi"/> is
    /// advertised. The library owns the wire; this delegate owns the policy.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public EvaluateAccessDelegate? EvaluateAccessAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Parses an OpenID AuthZEN Authorization API 1.0 Search API request JSON
    /// body into the neutral information model. Required for any search
    /// endpoint that is wired. The shipped default,
    /// <c>Verifiable.Json.AuthZen.AuthZenJsonParsing.ParseAccessSearchRequest</c>,
    /// is wired by <c>Verifiable.Json.AuthZen.AuthZenJsonExtensions.UseDefaultAuthZenJsonParsing</c>
    /// (that project depends on this one, so it cannot be named by
    /// <c>cref</c> here).
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ParseAccessSearchRequestDelegate? ParseAccessSearchRequestAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// The Subject Search seam (§7). Optional — wiring it activates and
    /// advertises the <c>search_subject_endpoint</c>. The library owns the
    /// wire; this delegate owns enumeration and paging.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public SearchSubjectsDelegate? SearchSubjectsAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// The Resource Search seam (§7). Optional — wiring it activates and
    /// advertises the <c>search_resource_endpoint</c>.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public SearchResourcesDelegate? SearchResourcesAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// The Action Search seam (§7). Optional — wiring it activates and
    /// advertises the <c>search_action_endpoint</c>.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public SearchActionsDelegate? SearchActionsAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Contributes application-supplied values (currently <c>capabilities</c>)
    /// to the AuthZEN §9.1 PDP metadata document. Optional.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ContributeAuthZenMetadataDelegate? ContributeAuthZenMetadataAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Signs the assembled AuthZEN §9.1 PDP metadata as a <c>signed_metadata</c>
    /// JWT. Optional — when set, the returned JWT is embedded in the metadata
    /// document. The application owns the signing key and algorithm.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public SignAuthZenMetadataDelegate? SignAuthZenMetadataAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Contributes application-supplied values (delivery methods, critical subject
    /// members, authorization schemes, default subjects) to the Shared Signals
    /// Transmitter Configuration Metadata document (SSF 1.0 §7.1). Optional.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ContributeSsfTransmitterMetadataDelegate? ContributeSsfTransmitterMetadataAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Contributes application-supplied values (authorization servers, scopes,
    /// bearer methods, human-readable fields, feature booleans) to the OAuth 2.0
    /// Protected Resource Metadata document (RFC 9728 §2). Optional.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ContributeProtectedResourceMetadataDelegate? ContributeProtectedResourceMetadataAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Signs the assembled RFC 9728 Protected Resource Metadata as a
    /// <c>signed_metadata</c> JWT (§2.2). Optional — when set, the returned JWT
    /// is embedded in the metadata document. The application owns the signing
    /// key, the algorithm, and the spec-required <c>iss</c> claim.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public SignProtectedResourceMetadataDelegate? SignProtectedResourceMetadataAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Parses a Create Stream request body (SSF §8.1.1.1). Wire the shipped
    /// default with <c>UseDefaultSsfJsonParsing</c>.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.ParseSsfStreamCreateRequestDelegate? ParseSsfStreamCreateRequestAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Parses an Update/Replace Stream request body (SSF §8.1.1.3/§8.1.1.4).
    /// Wire the shipped default with <c>UseDefaultSsfJsonParsing</c>.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.ParseSsfStreamUpdateRequestDelegate? ParseSsfStreamUpdateRequestAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// The Transmitter's stream store: create (SSF §8.1.1.1). Optional — wiring it
    /// (with the create parser) activates and advertises the Configuration Endpoint.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.CreateSsfStreamDelegate? CreateSsfStreamAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>The Transmitter's stream store: read one or all (SSF §8.1.1.2). Optional.</summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.ReadSsfStreamsDelegate? ReadSsfStreamsAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>The Transmitter's stream store: PATCH update (SSF §8.1.1.3). Optional.</summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.UpdateSsfStreamDelegate? UpdateSsfStreamAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>The Transmitter's stream store: PUT replace (SSF §8.1.1.4). Optional.</summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.ReplaceSsfStreamDelegate? ReplaceSsfStreamAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>The Transmitter's stream store: delete (SSF §8.1.1.5). Optional.</summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.DeleteSsfStreamDelegate? DeleteSsfStreamAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>Parses a Stream Status update body (SSF §8.1.2.2). Wire via <c>UseDefaultSsfJsonParsing</c>.</summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.ParseSsfStreamStatusDelegate? ParseSsfStreamStatusAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>Parses an Add Subject body (SSF §8.1.3.2). Wire via <c>UseDefaultSsfJsonParsing</c>.</summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.ParseSsfAddSubjectRequestDelegate? ParseSsfAddSubjectRequestAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>Parses a Remove Subject body (SSF §8.1.3.3). Wire via <c>UseDefaultSsfJsonParsing</c>.</summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.ParseSsfRemoveSubjectRequestDelegate? ParseSsfRemoveSubjectRequestAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>Parses a Trigger Verification body (SSF §8.1.4.2). Wire via <c>UseDefaultSsfJsonParsing</c>.</summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.ParseSsfVerificationRequestDelegate? ParseSsfVerificationRequestAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>The Transmitter's stream store: read status (SSF §8.1.2.1). Optional.</summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.ReadSsfStreamStatusDelegate? ReadSsfStreamStatusAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>The Transmitter's stream store: update status (SSF §8.1.2.2). Optional.</summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.UpdateSsfStreamStatusDelegate? UpdateSsfStreamStatusAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>The Transmitter's stream store: add a subject (SSF §8.1.3.2). Optional.</summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.AddSsfSubjectDelegate? AddSsfSubjectAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>The Transmitter's stream store: remove a subject (SSF §8.1.3.3). Optional.</summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.RemoveSsfSubjectDelegate? RemoveSsfSubjectAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>The Transmitter's verification trigger (SSF §8.1.4.2). Optional.</summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.TriggerSsfVerificationDelegate? TriggerSsfVerificationAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Authorizes stream-management requests: Bearer token validity, the
    /// <c>ssf.read</c>/<c>ssf.manage</c> scope per CAEP Interoperability Profile §2.7.3, and the
    /// caller's authority on the request's tenant per
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8-3">SSF 1.0 §8</see>.
    /// Optional — unset means the Stream Management API candidates are not built at all
    /// (fail-closed), the same materialize-only-when-wired rule the grant seams use; the
    /// well-known discovery document stays public per SSF §7.1.1 regardless.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Ssf.AuthorizeSsfRequestDelegate? AuthorizeSsfRequestAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Authenticates a confidential client for the <c>client_credentials</c> grant
    /// (RFC 6749 §4.4). The grant endpoint activates only when this seam is wired —
    /// the application owns credential storage and the authentication method.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ValidateClientCredentialsDelegate? ValidateClientCredentialsAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// The client authentication methods this token endpoint actually judges — the
    /// declaration <c>token_endpoint_auth_methods_supported</c> (RFC 8414, Section 2)
    /// is emitted from. Defaults to <c>[</c><see cref="ClientAuthenticationMethod.None"/><c>]</c>:
    /// the library's token endpoint accepts PKCE-only public clients per OAuth 2.1 and
    /// judges no other method unless the deployment declares it here AND wires
    /// <see cref="ValidateClientCredentialsAsync"/> to actually check the presented
    /// credential (<see cref="Validate"/> refuses a declaration the wiring cannot
    /// honour). A registration whose <see cref="ClientRecord.TokenEndpointAuthMethod"/>
    /// names a method outside this set is refused before any validator runs — the
    /// advertisement and the endpoint's judgment are the one set the deployment
    /// declares, never two independently maintained facts.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// <para>
    /// Assignment copies the declaration into an immutable array so edits to the caller collection cannot
    /// change admitted discovery or authentication behavior.
    /// </para>
    /// </remarks>
    public IReadOnlyCollection<ClientAuthenticationMethod> ClientAuthenticationMethodsSupported
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value is null ? null! : value.ToImmutableArray();
            }
        }
    } =
        [ClientAuthenticationMethod.None];

    /// <summary>
    /// The JWA <c>alg</c> names (<see cref="WellKnownJwaValues"/>) this token endpoint
    /// accepts on the client-assertion JWT for <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/>
    /// and <see cref="ClientAuthenticationMethod.ClientSecretJwt"/> — the declaration
    /// <c>token_endpoint_auth_signing_alg_values_supported</c> (RFC 8414, Section 2) is
    /// emitted from whenever it is non-empty. RFC 8414, Section 2: "Servers SHOULD
    /// support "RS256"." — which algorithms to declare beyond that SHOULD is the
    /// deployment's own choice; the algorithm set is not itself validated against the
    /// presented assertion's <c>alg</c> here, only advertised. Empty by default; a
    /// deployment that declares <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/> or
    /// <see cref="ClientAuthenticationMethod.ClientSecretJwt"/> on
    /// <see cref="ClientAuthenticationMethodsSupported"/> must populate this with at
    /// least one algorithm, and never with <see cref="WellKnownJwaValues.None"/> (RFC
    /// 8414, Section 2: "The value "none" MUST NOT be used.") — <see cref="Validate"/>
    /// enforces both.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// <para>
    /// Assignment copies the declaration into an immutable array retained by admitted requests.
    /// </para>
    /// </remarks>
    public IReadOnlyCollection<string> ClientAssertionSigningAlgorithmsSupported
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value is null ? null! : value.ToImmutableArray();
            }
        }
    } = [];


    /// <summary>
    /// Validates a Token Exchange <c>subject_token</c> (RFC 8693 §2.1) and returns its accepted
    /// claims, or rejects it. The grant activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/> capability is allowed and
    /// BOTH this seam and <see cref="AuthorizeTokenExchangeAsync"/> are wired — an advertised
    /// token-exchange grant with no validation seam would mint tokens for any subject-token string
    /// (fail-closed, the §3.2.1-style materialization the other grants use). The application is the
    /// trust authority: it owns which issuers and keys it accepts, and any remote key fetch is its
    /// concern (the library takes no <c>System.Net.*</c> dependency).
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ValidateTokenExchangeTokenDelegate? ValidateTokenExchangeTokenAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Decides whether a validated Token Exchange <c>subject_token</c> may be exchanged for the
    /// requested target and shapes the issued token (RFC 8693 §2.1). The grant activates only when
    /// the <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/> capability is allowed and
    /// BOTH this seam and <see cref="ValidateTokenExchangeTokenAsync"/> are wired — an advertised
    /// grant that cannot make the impersonation policy decision would be a fail-open authorization
    /// boundary (fail-closed, the §3.2.1-style materialization). The application owns the policy
    /// "which entities are permitted to impersonate other entities" (§2.1); a <see langword="null"/>
    /// return denies the exchange and the endpoint answers <c>invalid_target</c> (§2.2.2).
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public AuthorizeTokenExchangeDelegate? AuthorizeTokenExchangeAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Validates a JWT Bearer authorization-grant <c>assertion</c> (RFC 7523 §2.1/§3.1) and returns
    /// the token shape to issue, or rejects it. The grant activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthJwtBearer"/> capability is allowed and this seam
    /// is wired — an advertised jwt-bearer grant with no validation seam would mint tokens for any
    /// assertion string (fail-closed, the §3.2.1-style materialization the other grants use). The
    /// application is the trust authority: it owns which issuers and keys it accepts, performs the full
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 §3</see> processing —
    /// signature (rule 9), trusted <c>iss</c> (rule 1), the <c>aud</c>-names-this-AS check (rule 3,
    /// which only the application can make), and the <c>exp</c>/<c>nbf</c> window (rules 4–5) — and any
    /// remote JWKS fetch is its concern (the library takes no <c>System.Net.*</c> dependency). A
    /// <see langword="null"/> return refuses the grant; the endpoint answers <c>invalid_grant</c> (§3.1).
    /// Client authentication is OPTIONAL for this grant (§3.1): when the request carries client
    /// credentials the endpoint validates them through <see cref="ValidateClientCredentialsAsync"/>, but
    /// the grant does not require that seam — the assertion is the grant.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ValidateJwtBearerAssertionDelegate? ValidateJwtBearerAssertionAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Revokes a token at the RFC 7009 revocation endpoint on behalf of an
    /// authenticated client. The endpoint activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthTokenRevocation"/> capability
    /// is allowed and BOTH this seam and <see cref="ValidateClientCredentialsAsync"/>
    /// are wired — a revocation endpoint that cannot authenticate the client or
    /// cannot revoke would be a silent no-op that misleads clients into believing a
    /// token was killed. The application owns the token store and the
    /// refresh-to-access cascade.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public RevokeTokenDelegate? RevokeTokenAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Revokes one issued token by its persisted <c>jti</c> for the library-driven revocation
    /// paths — a valid replay of an already-redeemed authorization code and reuse of a
    /// rotated-out refresh token. Optional: see <see cref="RevokeIssuedTokenDelegate"/> for the
    /// documented degradation when this is left unwired. Distinct from
    /// <see cref="RevokeTokenAsync"/>, which answers the client-driven RFC 7009 request.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public RevokeIssuedTokenDelegate? RevokeIssuedTokenAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Reads every retained record of one grant in a single call for a VALID code replay or
    /// refresh reuse to revoke. Required — see <see cref="LoadGrantFlowStatesDelegate"/> for the
    /// full contract.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public LoadGrantFlowStatesDelegate? LoadGrantFlowStatesAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Introspects a token at the RFC 7662 introspection endpoint on behalf of an
    /// authenticated protected resource. The endpoint activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthTokenIntrospection"/> capability
    /// is allowed and BOTH this seam and <see cref="ValidateClientCredentialsAsync"/>
    /// are wired — an introspection endpoint that cannot authenticate the caller would
    /// leak token state to anyone, and one that cannot read the token store could only
    /// answer <c>active:false</c>, misleading a resource into rejecting live tokens. The
    /// application owns the token store; the library owns the wire shape and the
    /// inactive-discloses-nothing rule.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public IntrospectTokenDelegate? IntrospectTokenAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Mints a fresh OID4VCI 1.0 §7 <c>c_nonce</c>. The Nonce Endpoint activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.Oid4VciNonceEndpoint"/> capability is allowed
    /// and this seam is wired — an advertised Nonce Endpoint that cannot mint a challenge would
    /// break every key-bound Credential Request. The application owns the nonce store so it can
    /// validate the nonce later at the Credential Endpoint.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public IssueCredentialNonceDelegate? IssueCredentialNonceAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Validates an OID4VCI 1.0 §6 Pre-Authorized Code grant. The grant activates only when
    /// the <see cref="WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant"/> capability
    /// is allowed and this seam is wired — an advertised grant with no code-validation seam would
    /// mint access tokens for any code string (fail-closed). The application owns the
    /// pre-authorized code store, so it resolves the subject and distinguishes the §6.3 error
    /// cases the library cannot.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ValidatePreAuthorizedCodeDelegate? ValidatePreAuthorizedCodeAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Parses an OID4VCI 1.0 §8.2 Credential Request body into the neutral
    /// <see cref="Oid4Vci.CredentialRequest"/>. Required when
    /// <see cref="WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint"/> is advertised.
    /// The shipped default,
    /// <c>Verifiable.Json.Oid4Vci.CredentialRequestJsonParsing.ParseCredentialRequest</c>, is
    /// wired by <c>Verifiable.Json.Oid4Vci.CredentialRequestJsonExtensions.UseDefaultCredentialRequestJsonParsing</c>
    /// (that project depends on this one, so it cannot be named by <c>cref</c> here).
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ParseCredentialRequestDelegate? ParseCredentialRequestAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Parses an RFC 9396 <c>authorization_details</c> request parameter into the neutral
    /// <see cref="AuthorizationDetail"/> list. Required when the server processes
    /// <c>authorization_details</c> (RFC 9396 §2; OID4VCI 1.0 §5.1.1 / §6.1.1) — a request
    /// carrying the parameter while this seam is unwired is refused with
    /// <c>invalid_authorization_details</c> (the server does not support the parameter). The
    /// shipped default,
    /// <c>Verifiable.Json.Oid4Vci.AuthorizationDetailsJsonParsing.ParseAuthorizationDetails</c>,
    /// is wired by <c>Verifiable.Json.Oid4Vci.AuthorizationDetailsJsonExtensions.UseDefaultAuthorizationDetailsJsonParsing</c>
    /// (that project depends on this one, so it cannot be named by <c>cref</c> here).
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ParseAuthorizationDetailListDelegate? ParseAuthorizationDetailsAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// The RFC 9396 authorization details <c>type</c> → handler registry the AS dispatches
    /// every parsed authorization details object through (§5/§7 multi-type dispatch). Created
    /// pre-populated with the built-in <c>openid_credential</c> handler
    /// (<see cref="Oid4Vci.OpenIdCredentialAuthorizationDetailHandler"/>); a deployment registers
    /// further handlers to support additional types. Its
    /// <see cref="AuthorizationDetailTypeRegistry.RegisteredTypes"/> is what the AS metadata
    /// advertises as <c>authorization_details_types_supported</c> (§10).
    /// </summary>
    /// <remarks>
    /// Register additional types during construction or on the candidate registry. A serving Register call
    /// throws a named configuration fault; discarded candidates do not change live membership.
    /// </remarks>
    public AuthorizationDetailTypeRegistry AuthorizationDetailTypes { get; private set; } =
        CreateDefaultAuthorizationDetailTypeRegistry();

    /// <summary>
    /// Decides an <c>openid_credential</c> authorization details request at the token endpoint
    /// and mints the OID4VCI 1.0 §6.2 <c>credential_identifiers</c> per granted configuration.
    /// Required when the server processes <c>authorization_details</c>; a token request whose
    /// grant carries authorization details while this seam is unwired is refused with
    /// <c>invalid_authorization_details</c> (fail-closed — the library cannot mint Credential
    /// Dataset identifiers). The application owns the configuration catalog and dataset store.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ResolveCredentialAuthorizationDelegate? ResolveCredentialAuthorizationAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Issues an OID4VCI 1.0 §8 Credential. The Credential Endpoint activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint"/> capability is
    /// allowed and BOTH this seam and <see cref="ParseCredentialRequestAsync"/> are wired — an
    /// advertised Credential Endpoint that cannot parse the request or cannot mint would be a
    /// fail-open authorization boundary. The application owns proof verification (its
    /// <c>c_nonce</c> store), the supported Credential Configurations, and the signing key; the
    /// library owns bearer-token validation and the wire shape.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public IssueCredentialDelegate? IssueCredentialAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves what a §8 Credential Request's <c>jwt</c> key proof(s) must satisfy (the expected
    /// <c>c_nonce</c>, the acceptable proof-signing algorithms, the <c>iat</c> window). Wiring this
    /// seam OPTS IN to library-side Appendix F.4 proof validation at the Credential Endpoint: the
    /// library validates each proof with <see cref="Oid4Vci.CredentialProofValidator"/> BEFORE
    /// <see cref="IssueCredentialAsync"/> is consulted, mapping a failure to the §8.3.1.2
    /// <c>invalid_proof</c> / <c>invalid_nonce</c> error. When this seam is unwired the endpoint
    /// validates no proofs and hands the whole §F.4 check to <see cref="IssueCredentialAsync"/> (the
    /// established default), so every Credential Endpoint deployment that does not set it is
    /// unchanged. The application owns the <c>c_nonce</c> store and its single-use retirement
    /// either way.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ResolveCredentialProofExpectationDelegate? ResolveCredentialProofExpectationAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Encrypts an OID4VCI 1.0 §10 (Deferred) Credential Response to the Wallet-supplied key.
    /// Optional — when unwired, a request carrying <c>credential_response_encryption</c> is
    /// refused with <c>invalid_encryption_parameters</c> (fail-closed: §8.3 forbids answering
    /// such a request in clear).
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public EncryptCredentialResponseDelegate? EncryptCredentialResponseAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Decrypts an OID4VCI 1.0 §10 encrypted Credential Request with the Issuer's key from
    /// <c>credential_request_encryption.jwks</c>. Optional — when unwired, a compact-JWE
    /// request body is refused with <c>invalid_credential_request</c>.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public DecryptCredentialRequestDelegate? DecryptCredentialRequestAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves an OID4VCI 1.0 §9 Deferred Credential Request from the application's
    /// deferred-transaction store. The Deferred Credential Endpoint activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.Oid4VciDeferredCredentialEndpoint"/> capability
    /// is allowed and this seam is wired — fail-closed: an advertised endpoint without the
    /// store could only refuse every <c>transaction_id</c>.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ResolveDeferredCredentialDelegate? ResolveDeferredCredentialAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Processes an OID4VCI 1.0 §11.1 Notification Request. The Notification Endpoint activates
    /// only when the <see cref="WellKnownCapabilityIdentifiers.Oid4VciNotificationEndpoint"/>
    /// capability is allowed and this seam is wired — fail-closed: an advertised endpoint
    /// without the <c>notification_id</c> store could only reject every notification.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ProcessCredentialNotificationDelegate? ProcessCredentialNotificationAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves an OID4VCI 1.0 §4.1.3 by-reference Credential Offer from the application's offer
    /// store. The Credential Offer Endpoint activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.Oid4VciCredentialOfferEndpoint"/> capability is
    /// allowed and this seam is wired — fail-closed: only the application's offer store, keyed by
    /// the id the <c>credential_offer_uri</c> carries, can produce the offer the Wallet fetches.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ResolveCredentialOfferDelegate? ResolveCredentialOfferAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Contributes the application-owned values of the OID4VCI 1.0 §12.2 Credential Issuer
    /// Metadata document (<c>credential_configurations_supported</c> and the optional
    /// <c>authorization_servers</c> / <c>display</c> / <c>batch_credential_issuance</c>). The
    /// Credential Issuer Metadata endpoint activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.Oid4VciCredentialIssuerMetadata"/> capability is
    /// allowed and this seam is wired — the document's REQUIRED
    /// <c>credential_configurations_supported</c> is application data the library cannot derive.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ContributeCredentialIssuerMetadataDelegate? ContributeCredentialIssuerMetadataAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Signs the assembled OID4VCI 1.0 §12.2.3 Credential Issuer Metadata as a
    /// <c>signed_metadata</c> JWT. Optional — when set, the returned JWT is embedded in the
    /// document. The application owns the signing key, the algorithm, and the §12.2.3
    /// structural claims (<c>typ</c>, <c>sub</c>, <c>iat</c>).
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public SignCredentialIssuerMetadataDelegate? SignCredentialIssuerMetadataAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Parses a Global Token Revocation request body
    /// (draft-parecki-oauth-global-token-revocation §3) into the neutral
    /// <see cref="Logout.GlobalTokenRevocationRequest"/>. Required when
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthGlobalTokenRevocation"/> is
    /// advertised. The shipped default,
    /// <c>Verifiable.Json.Logout.GlobalTokenRevocationJsonParsing.ParseGlobalTokenRevocationRequest</c>,
    /// is wired by <c>Verifiable.Json.Logout.GlobalTokenRevocationJsonExtensions.UseDefaultGlobalTokenRevocationJsonParsing</c>
    /// (that project depends on this one, so it cannot be named by <c>cref</c> here).
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ParseGlobalTokenRevocationRequestDelegate? ParseGlobalTokenRevocationRequestAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Revokes all of a subject's tokens for a Global Token Revocation command
    /// (draft-parecki-oauth-global-token-revocation §3). The endpoint activates
    /// only when the <see cref="WellKnownCapabilityIdentifiers.OAuthGlobalTokenRevocation"/>
    /// capability is allowed and the parse seam, this seam, and
    /// <see cref="ValidateClientCredentialsAsync"/> are all wired (fail-closed —
    /// an unauthenticated or no-op global revocation would be dangerous). The
    /// application owns the fan-out (revoke the subject's grants, optionally emit a
    /// CAEP <c>session-revoked</c> signal); the library owns the wire.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public RevokeSubjectTokensDelegate? RevokeSubjectTokensAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Terminates the End-User's authentication session for an RP-Initiated Logout
    /// (OIDC RP-Initiated Logout 1.0). The <c>end_session_endpoint</c> activates only
    /// when the <see cref="WellKnownCapabilityIdentifiers.OidcRpInitiatedLogout"/>
    /// capability is allowed and this seam plus the verification-key resolver are wired
    /// (the endpoint must verify the <c>id_token_hint</c>). The application owns the
    /// session store and the cascade.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public TerminateSessionDelegate? TerminateSessionAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Terminates a session identified only by a <c>logout_hint</c> — the sessionless
    /// RP-Initiated Logout path (OIDC RP-Initiated Logout 1.0 §3), taken when the request
    /// carries a <c>logout_hint</c> but no <c>id_token_hint</c>. Optional: when unset the
    /// <c>end_session_endpoint</c> still requires an <c>id_token_hint</c>; wiring it enables
    /// the sessionless branch. The application resolves the opaque hint to a session.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public TerminateSessionByHintDelegate? TerminateSessionByHintAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Fans a terminated session out to registered RPs as an OIDC Back-Channel Logout
    /// (OIDC Back-Channel Logout 1.0). Optional: when unset the OP performs no back-channel
    /// fan-out and does not advertise <c>backchannel_logout_supported</c>; wiring it activates
    /// the fan-out the end-session endpoint runs after <see cref="TerminateSessionAsync"/>. The
    /// application owns the session→RP list, builds each Logout Token, and delivers it.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public DeliverBackChannelLogoutDelegate? DeliverBackChannelLogoutAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    //Resolves the per-request policy values for the loaded registration and populates them on the
    //ExchangeContext at dispatch entry. Required. The dispatcher invokes this delegate once per
    //request after the registration is loaded but before any matcher executes. Matchers, validators,
    //and token producers downstream consult policy via the typed extensions in
    //PolicyExchangeContextExtensions. Wire to PolicyProfiles.DefaultResolvePolicyAsync for the
    //library's named-profile dispatch (strict, haip, rfc6749), or supply a custom delegate for
    //bespoke policy.
    //ResolvePolicyAsync is the host-generic base seam (ResolveServerPolicyDelegate over
    //IRegistrationRecord); the OAuth wiring adapts its ClientRecord resolver to it.

    /// <summary>
    /// Resolves the <c>aud</c> claim audience(s) for an RFC 9068 access token
    /// at issuance time. Optional — when <see langword="null"/>, the library's
    /// default <see cref="Rfc9068AccessTokenProducer.DefaultResolveAccessTokenAudienceAsync"/>
    /// runs (reads from <see cref="ClientRecord.ScopeToAudience"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The producer consults the active
    /// <see cref="AccessTokenAudPolicy"/> from the resolved policy and uses
    /// the audience(s) this delegate returns to populate the <c>aud</c> claim
    /// per <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2">RFC 9068 §2.2</see>.
    /// </para>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// </remarks>
    public ResolveAccessTokenAudienceDelegate? ResolveAccessTokenAudienceAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Validates inbound DPoP proofs at the token endpoint per RFC 9449 §4.3.
    /// Library default backing: <see cref="Verifiable.OAuth.Dpop.DpopProofValidator.ValidateAsync"/>
    /// adapted to the <see cref="Verifiable.OAuth.Dpop.ValidateDpopProofDelegate"/>
    /// shape. Required when any registration's <see cref="PolicyProfile"/>
    /// requires DPoP (HAIP 1.0, FAPI 2.0).
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Verifiable.OAuth.Dpop.ValidateDpopProofDelegate? ValidateDpopProofAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Issues a fresh DPoP nonce on a 401 <c>use_dpop_nonce</c> challenge or
    /// any other condition where the AS wants the client to refresh its
    /// nonce. Library default backing:
    /// <see cref="Verifiable.OAuth.Dpop.DefaultDpopNonceIssuance.IssueAsync"/>.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Verifiable.OAuth.Dpop.IssueDpopNonceDelegate? IssueDpopNonceAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Validates a presented DPoP nonce. Library default backing:
    /// <see cref="Verifiable.OAuth.Dpop.DefaultDpopNonceValidation.ValidateAsync"/>.
    /// Issuance and validation must agree on the wire format.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public Verifiable.OAuth.Dpop.ValidateDpopNonceDelegate? ValidateDpopNonceAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Loads the HMAC key material for a kid chosen by
    /// <see cref="SelectHmacKeyAsync"/> at issuance or extracted from the
    /// wire artefact at validation. Library default backing:
    /// <see cref="Keys.InProcessKeySet.ResolveMaterial"/> wrapped as the
    /// delegate. Multi-instance deployments wire a Vault/KMS-backed
    /// implementation per the same contract.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ResolveServerHmacKeyDelegate? ResolveServerHmacKeyAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Returns the current HMAC <see cref="Keys.KeySet"/> for the given
    /// tenant. Issuance feeds this into <see cref="SelectHmacKeyAsync"/>;
    /// validation reads it to check slot membership
    /// (<see cref="Keys.KeySet.IsKidValidForVerification"/>) before
    /// accepting a presented kid; JWKS publication reads it via
    /// <c>Publishable()</c> when the application's
    /// <see cref="AuthorizationServerCryptography.BuildJwksDocumentAsync"/>
    /// opts to publish HMAC keys as <c>kty=oct</c> JWKs per RFC 7518 §6.4
    /// (typically for HS256 access-token verifiers in a private federation,
    /// not for DPoP nonce keys which are server-internal).
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public GetHmacKeySetDelegate? GetHmacKeySetAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Selects which kid to use for a given HMAC operation. When
    /// <see langword="null"/>, the library uses the kid of the first entry
    /// in the keyset's <see cref="Keys.KeySet.Current"/> list.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public SelectHmacKeyDelegate? SelectHmacKeyAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves the OpenID Connect claim set for an authenticated subject.
    /// Consumed by <see cref="Oidc10IdTokenProducer"/> during ID Token
    /// issuance and by the UserInfo endpoint per OIDC Core §5.3. Required
    /// when the application's <see cref="TokenProducer"/> list includes
    /// <c>TokenProducer.Oidc10IdToken</c> or when the UserInfo
    /// endpoint is registered.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ResolveOidcClaimsDelegate? ResolveOidcClaimsAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Application seam making the authorization decision at the authorization endpoint
    /// after authentication and the library's own checks. The application may permit or
    /// deny on any requested/established fact — an unsatisfied <c>acr</c> (RFC 9470 §5
    /// step-up), resource-owner consent, or deployment policy — and the library maps a
    /// denial to its OAuth error. See <see cref="EvaluateAuthorizationRequestDelegate"/>
    /// for the delegate documentation. Unset means the authorization server applies no additional
    /// decision at this point (the achieved <c>acr</c> is still conveyed in the issued
    /// tokens, and the resource server's step-up challenge remains the backstop). The
    /// temporal <c>max_age</c> recency requirement is enforced by the library directly (it
    /// needs no deployment semantics) and does not go through this seam.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public EvaluateAuthorizationRequestDelegate? EvaluateAuthorizationRequestAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>Copies nested containers while preserving the instance registration-event stream.</summary>
    protected override WiringComponent CloneCore()
    {
        AuthorizationServerIntegration copy = (AuthorizationServerIntegration)base.CloneCore();
        copy.Cryptography = Cryptography is null ? null! : CopyComponent(Cryptography);
        copy.Codecs = Codecs is null ? null! : CopyComponent(Codecs);
        copy.ActionExecutor = ActionExecutor is null ? null : CopyComponent(ActionExecutor);
        copy.AuthorizationDetailTypes = CopyComponent(AuthorizationDetailTypes);

        return copy;
    }


    /// <summary>The nested containers frozen and invalidated with the authorization wiring.</summary>
    protected override IEnumerable<WiringComponent> Children
    {
        get
        {
            if(Cryptography is not null)
            {
                yield return Cryptography;
            }

            if(Codecs is not null)
            {
                yield return Codecs;
            }

            if(ActionExecutor is not null)
            {
                yield return ActionExecutor;
            }

            yield return AuthorizationDetailTypes;
        }
    }


    /// <summary>
    /// Validates that the required delegates on this group are set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The required host seams include <see cref="ServerIntegration.DeleteFlowStateAsync"/>.
    /// A valid code replay or refresh reuse deletes the claimed live refresh record even when
    /// <see cref="RevokeIssuedTokenAsync"/> is unavailable, implementing the refresh-token part of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>'s
    /// "SHOULD revoke (when possible)" and OAuth 2.1 draft-16 §4.3.1 family revocation.
    /// </para>
    /// <para>
    /// Checks required host seams, nested groups, authentication declarations and enabled feature dependencies.
    /// Success describes the current wiring only. It cannot validate application storage atomicity,
    /// cryptographic behavior, policy correctness, or mutable delegate targets.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// Thrown when one or more required delegates are missing.
    /// </exception>
    public override void Validate()
    {
        IsValidated = false;
        var missing = new List<string>();

        CollectMissingHostSeams(missing);
        if(ResolveSubjectIdentifierAsync is null) { missing.Add(nameof(ResolveSubjectIdentifierAsync)); }
        if(LoadGrantFlowStatesAsync is null) { missing.Add(nameof(LoadGrantFlowStatesAsync)); }

        if(missing.Count > 0)
        {
            var sb = new StringBuilder(
                "AuthorizationServerIntegration is missing required delegates: ");
            _ = sb.AppendJoin(", ", missing);
            _ = sb.Append('.');
            throw new InvalidOperationException(sb.ToString());
        }

        if(Cryptography is null)
        {
            missing.Add(nameof(Cryptography));
        }
        if(Codecs is null)
        {
            missing.Add(nameof(Codecs));
        }
        if(MemoryPool is null)
        {
            missing.Add(nameof(MemoryPool));
        }
        if(Timings is null)
        {
            missing.Add(nameof(Timings));
        }
        if(TokenProducers is null)
        {
            missing.Add(nameof(TokenProducers));
        }
        if(ClientAuthenticationMethodsSupported is null)
        {
            missing.Add(nameof(ClientAuthenticationMethodsSupported));
        }
        if(ClientAssertionSigningAlgorithmsSupported is null)
        {
            missing.Add(nameof(ClientAssertionSigningAlgorithmsSupported));
        }

        if(missing.Count > 0)
        {
            throw new InvalidOperationException($"AuthorizationServerIntegration requires {string.Join(", ", missing)}.");
        }

        Cryptography!.Validate();
        Codecs!.Validate();
        ValidateClientAuthenticationDeclaration();
        ValidateFeatureDependencies();
        AuthorizationDetailTypes.Validate();

        IsValidated = true;
    }


    /// <summary>Requires authorization-family helpers to use the same primary host integration.</summary>
    /// <param name="primaryIntegration">The composition's validated shared host operations.</param>
    public override void ValidateFamily(ServerIntegration primaryIntegration)
    {
        if(!ReferenceEquals(this, primaryIntegration))
        {
            throw new InvalidOperationException("AuthorizationServerIntegration must be EndpointServer.Integration and its registered authorization family together.");
        }

        Validate();
    }


    /// <summary>
    /// Checks coupled optional operations without requiring disabled endpoint modules, including the
    /// <see cref="ParseAuthorizationDetailsAsync"/> / <see cref="ResolveCredentialAuthorizationAsync"/>
    /// pairing.
    /// </summary>
    /// <remarks>
    /// RFC 9396 §5: "The AS MUST refuse to process any unknown authorization details type or
    /// authorization details not conforming to the respective type definition. The AS MUST abort
    /// processing and respond with an error <c>invalid_authorization_details</c>..." — both seams,
    /// wired or not, already answer that same wire error independently of each other, so a deployment
    /// that half-wires the pair gets no composition-time signal, only a wallet's first request. The two
    /// checks below close that gap for the two shapes this composition can never validly reach: a
    /// resolver with no parser feeding it, and a parser wired for the built-in <c>openid_credential</c>
    /// type with no resolver to decide it. A deployment that also registered a further authorization
    /// details type has visibly signaled it uses the parameter for something other than credential
    /// issuance, so the second check stays silent for it.
    /// </remarks>
    private void ValidateFeatureDependencies()
    {
        if(ResolveCredentialAuthorizationAsync is not null && ParseAuthorizationDetailsAsync is null)
        {
            throw new InvalidOperationException("AuthorizationServerIntegration.ResolveCredentialAuthorizationAsync requires ParseAuthorizationDetailsAsync.");
        }

        if(ParseAuthorizationDetailsAsync is not null
            && ResolveCredentialAuthorizationAsync is null
            && AuthorizationDetailTypes.RegisteredTypes.Count == 1
            && AuthorizationDetailTypes.IsRegistered(AuthorizationDetailsTypeValues.OpenIdCredential))
        {
            throw new InvalidOperationException("AuthorizationServerIntegration.ParseAuthorizationDetailsAsync requires ResolveCredentialAuthorizationAsync when no authorization details type beyond the built-in openid_credential is registered.");
        }

        if((ParseClientMetadataAsync is not null || ValidateRegistrationAccessTokenAsync is not null)
            && ClientRegistrationStore is null)
        {
            throw new InvalidOperationException("AuthorizationServerIntegration registration requires ClientRegistrationStore.");
        }


        foreach(TokenProducer producer in TokenProducers)
        {
            if(producer is null || string.IsNullOrEmpty(producer.Name) || string.IsNullOrEmpty(producer.ResponseField)
                || producer.IsApplicable is null || producer.BuildAsync is null)
            {
                throw new InvalidOperationException("TokenProducers requires Name, ResponseField, IsApplicable and BuildAsync for every producer.");
            }
        }

        if(TokenProducers.Contains(TokenProducer.Oidc10IdToken) && ClaimIssuer is null)
        {
            throw new InvalidOperationException("TokenProducers.Oidc10IdToken requires ClaimIssuer for the mandatory subject claim.");
        }

        if((ValidateTokenExchangeTokenAsync is not null || AuthorizeTokenExchangeAsync is not null)
            && (ValidateTokenExchangeTokenAsync is null || AuthorizeTokenExchangeAsync is null || ValidateClientCredentialsAsync is null))
        {
            throw new InvalidOperationException("AuthorizationServerIntegration token exchange requires ValidateTokenExchangeTokenAsync, AuthorizeTokenExchangeAsync and ValidateClientCredentialsAsync.");
        }

        if(ValidateDpopProofAsync is not null
            && (IssueDpopNonceAsync is null || ValidateDpopNonceAsync is null || ResolveServerHmacKeyAsync is null || GetHmacKeySetAsync is null))
        {
            throw new InvalidOperationException("AuthorizationServerIntegration DPoP requires IssueDpopNonceAsync, ValidateDpopNonceAsync, ResolveServerHmacKeyAsync and GetHmacKeySetAsync.");
        }

        if(IssueCredentialAsync is not null && ParseCredentialRequestAsync is null)
        {
            throw new InvalidOperationException("AuthorizationServerIntegration.IssueCredentialAsync requires ParseCredentialRequestAsync.");
        }
    }


    /// <summary>
    /// Enforces that <see cref="ClientAuthenticationMethodsSupported"/> and
    /// <see cref="ClientAssertionSigningAlgorithmsSupported"/> describe a token
    /// endpoint the library can actually operate — CIMD -02 §8.2 and RFC 8414
    /// Section 2's rules on the pair of declarations. Every failure here is a
    /// composition defect (a deployment declaring something the wiring cannot
    /// honour), not a runtime condition, so each is thrown rather than folded
    /// into the missing-delegates report.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// <see cref="ClientAuthenticationMethodsSupported"/> is empty; it declares a
    /// method other than <see cref="ClientAuthenticationMethod.None"/> while
    /// <see cref="ValidateClientCredentialsAsync"/> is unwired; it declares
    /// <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/> or
    /// <see cref="ClientAuthenticationMethod.ClientSecretJwt"/> while
    /// <see cref="ClientAssertionSigningAlgorithmsSupported"/> is empty; or
    /// <see cref="ClientAssertionSigningAlgorithmsSupported"/> contains
    /// <see cref="WellKnownJwaValues.None"/>.
    /// </exception>
    private void ValidateClientAuthenticationDeclaration()
    {
        if(ClientAuthenticationMethodsSupported.Count == 0)
        {
            throw new InvalidOperationException(
                "AuthorizationServerIntegration.ClientAuthenticationMethodsSupported is empty. "
                + "RFC 8414, Section 2 defaults an omitted declaration to \"client_secret_basic\", "
                + "a method this library never judges by default; declare at least "
                + $"{nameof(ClientAuthenticationMethod)}.{nameof(ClientAuthenticationMethod.None)} "
                + "for a token endpoint that accepts only PKCE-only public clients.");
        }

        bool hasNonNoneMethod = false;
        bool hasJwtAssertionMethod = false;
        foreach(ClientAuthenticationMethod method in ClientAuthenticationMethodsSupported)
        {
            if(method != ClientAuthenticationMethod.None)
            {
                hasNonNoneMethod = true;
            }

            if(method == ClientAuthenticationMethod.PrivateKeyJwt || method == ClientAuthenticationMethod.ClientSecretJwt)
            {
                hasJwtAssertionMethod = true;
            }
        }

        if(hasNonNoneMethod && ValidateClientCredentialsAsync is null)
        {
            throw new InvalidOperationException(
                "AuthorizationServerIntegration.ClientAuthenticationMethodsSupported declares a "
                + $"method other than {nameof(ClientAuthenticationMethod)}.{nameof(ClientAuthenticationMethod.None)}, "
                + $"but {nameof(ValidateClientCredentialsAsync)} is not wired to judge it. A "
                + "declaration the wiring cannot honour would advertise client authentication "
                + "this token endpoint never actually checks.");
        }

        if(hasJwtAssertionMethod && ClientAssertionSigningAlgorithmsSupported.Count == 0)
        {
            throw new InvalidOperationException(
                $"AuthorizationServerIntegration.{nameof(ClientAuthenticationMethodsSupported)} declares "
                + $"{nameof(ClientAuthenticationMethod.PrivateKeyJwt)} or "
                + $"{nameof(ClientAuthenticationMethod.ClientSecretJwt)}, but "
                + $"{nameof(ClientAssertionSigningAlgorithmsSupported)} is empty. RFC 8414, Section 2: "
                + "\"This metadata entry MUST be present if either of these authentication methods "
                + "are specified in the 'token_endpoint_auth_methods_supported' entry.\"");
        }

        foreach(string algorithm in ClientAssertionSigningAlgorithmsSupported)
        {
            if(WellKnownJwaValues.IsNone(algorithm))
            {
                throw new InvalidOperationException(
                    $"AuthorizationServerIntegration.{nameof(ClientAssertionSigningAlgorithmsSupported)} "
                    + "contains \"none\". RFC 8414, Section 2: \"The value 'none' MUST NOT be used.\"");
            }
        }
    }


    /// <summary>
    /// Creates the authorization details <c>type</c> registry every integration starts with,
    /// carrying the built-in <c>openid_credential</c> handler so the OID4VCI 1.0 §5.1.1 profile
    /// works without further wiring.
    /// </summary>
    private static AuthorizationDetailTypeRegistry CreateDefaultAuthorizationDetailTypeRegistry()
    {
        AuthorizationDetailTypeRegistry registry = new();
        registry.Register(Oid4Vci.OpenIdCredentialAuthorizationDetailHandler.Handler);

        return registry;
    }


    /// <summary>
    /// The authoritative store for registration operations, required when registration parsing
    /// or management-token validation is configured. Store completion precedes optional observers.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate; a serving setter throws a named
    /// InvalidOperationException. Store data changes under traffic through its atomic operations.
    /// </remarks>
    public IClientRegistrationStore? ClientRegistrationStore
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// The registration-event subject shared by the serving integration and its candidate copies.
    /// Subscription membership belongs to the stream and survives accepted or rejected candidates.
    /// </summary>
    private EventSubject ClientRegistrationEventSubject { get; } = new();


    /// <summary>The instance-scoped stream of immutable registration notifications.</summary>
    /// <remarks>
    /// Delivery invokes each captured subscription once. An optional observer exception is isolated
    /// and reported through InspectAsync; diagnostics at that stage are also isolated. Concurrent
    /// emitters may call the same observer concurrently, without ordering or replay. Disposal removes
    /// only its unique entry and cannot cancel delivery already captured by an emission. Persistence
    /// must commit before notification. Capability signals require an application state effect.
    /// A callback may queue RequestAlterationAsync and return without awaiting its own dispatch drain.
    /// </remarks>
    public IObservable<ClientRegistrationEvent> Events => ClientRegistrationEventSubject;


    /// <summary>Notifies optional observers after the caller commits the registration operation.</summary>
    /// <remarks>Delivery follows the isolation and concurrent membership rules of <see cref="Events"/>.</remarks>
    public ValueTask RegisterClientAsync(
        ClientRecord registration,
        ExchangeContext context,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(timeProvider);

        return ClientRegistrationEventSubject.EmitAsync(new ClientRegistered
        {
            EventId = ClientRegistrationEventSubject.NextEventId(),
            Projection = ClientRegistrationProjection.From(registration),
            OccurredAt = timeProvider.GetUtcNow(),
        }, InspectAsync, context);
    }


    /// <summary>Notifies optional observers after the caller commits the registration operation.</summary>
    /// <remarks>Delivery follows the isolation and concurrent membership rules of <see cref="Events"/>.</remarks>
    public ValueTask UpdateClientAsync(
        ClientRecord previous,
        ClientRecord current,
        ExchangeContext context,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(timeProvider);

        return ClientRegistrationEventSubject.EmitAsync(new ClientUpdated
        {
            EventId = ClientRegistrationEventSubject.NextEventId(),
            Projection = ClientRegistrationProjection.From(current),
            OccurredAt = timeProvider.GetUtcNow(),
            Previous = ClientRegistrationProjection.From(previous),
        }, InspectAsync, context);
    }


    /// <summary>Emits a tombstone one revision beyond the atomically deleted record after storage commitment.</summary>
    /// <remarks>Pass the final removed record; delivery follows the isolation and concurrent membership rules of <see cref="Events"/>.</remarks>
    public ValueTask DeregisterClientAsync(
        ClientRecord registration,
        string reason,
        ExchangeContext context,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(timeProvider);

        return ClientRegistrationEventSubject.EmitAsync(new ClientDeregistered
        {
            EventId = ClientRegistrationEventSubject.NextEventId(),
            Projection = ClientRegistrationProjection.From(registration) with { Revision = checked(registration.Revision + 1) },
            OccurredAt = timeProvider.GetUtcNow(),
            Reason = reason,
        }, InspectAsync, context);
    }


    /// <summary>Signals a capability change requiring an application state effect before reachability changes.</summary>
    /// <remarks>Delivery follows the isolation and concurrent membership rules of <see cref="Events"/>.</remarks>
    public ValueTask GrantCapabilityAsync(
        ClientRecord registration,
        CapabilityIdentifier capability,
        ExchangeContext context,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(timeProvider);

        return ClientRegistrationEventSubject.EmitAsync(new CapabilityGranted
        {
            EventId = ClientRegistrationEventSubject.NextEventId(),
            Projection = ClientRegistrationProjection.From(registration),
            OccurredAt = timeProvider.GetUtcNow(),
            Capability = capability,
        }, InspectAsync, context);
    }


    /// <summary>Signals a capability change requiring an application state effect before reachability changes.</summary>
    /// <remarks>Delivery follows the isolation and concurrent membership rules of <see cref="Events"/>.</remarks>
    public ValueTask RevokeCapabilityAsync(
        ClientRecord registration,
        CapabilityIdentifier capability,
        string reason,
        ExchangeContext context,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(timeProvider);

        return ClientRegistrationEventSubject.EmitAsync(new CapabilityRevoked
        {
            EventId = ClientRegistrationEventSubject.NextEventId(),
            Projection = ClientRegistrationProjection.From(registration),
            OccurredAt = timeProvider.GetUtcNow(),
            Capability = capability,
            Reason = reason,
        }, InspectAsync, context);
    }


    /// <summary>The copied subscription membership shared by this stream's integration views.</summary>
    private sealed class EventSubject: IObservable<ClientRegistrationEvent>
    {
        /// <summary>A field enables volatile publication of immutable membership arrays across emitters.</summary>
        private volatile Subscription[] subscriptions = [];


        /// <summary>A field permits atomic increment of the stream-local event identity without application I/O after commitment.</summary>
        private long eventSequence;


        /// <summary>Allocates a unique event identifier within this instance-scoped stream.</summary>
        public long NextEventId()
        {

            return Interlocked.Increment(ref eventSequence);
        }


        /// <summary>The stable synchronization target for publishing subscription membership.</summary>
        private object Gate { get; } = new();


        /// <summary>Creates one unique entry even when the observer already has another subscription.</summary>
        public IDisposable Subscribe(IObserver<ClientRegistrationEvent> observer)
        {
            ArgumentNullException.ThrowIfNull(observer);
            Subscription subscription = new(this, observer);
            lock(Gate)
            {
                subscriptions = [.. subscriptions, subscription];
            }

            return subscription;
        }


        /// <summary>Delivers to the captured entries and reports each isolated observer exception.</summary>
        public async ValueTask EmitAsync(ClientRegistrationEvent value, InspectDelegate? inspect, ExchangeContext context)
        {
            Subscription[] current = subscriptions;
            foreach(Subscription subscription in current)
            {
                try
                {
                    subscription.Observer.OnNext(value);
                }
                catch(Exception exception)
                {
                    if(inspect is not null)
                    {
                        try
                        {
                            await inspect(new RegistrationObserverFailureStage(value, exception),
                                [], CancellationToken.None).ConfigureAwait(false);
                        }
                        catch(Exception)
                        {
                            //A diagnostic failure cannot change the committed result or stop delivery.
                        }
                    }
                }
            }
        }


        /// <summary>Removes this exact token under one lock, making repeated concurrent disposal idempotent.</summary>
        private void Remove(Subscription subscription)
        {
            lock(Gate)
            {
                int index = Array.IndexOf(subscriptions, subscription);
                if(index < 0)
                {

                    return;
                }

                Subscription[] updated = new Subscription[subscriptions.Length - 1];
                Array.Copy(subscriptions, 0, updated, 0, index);
                Array.Copy(subscriptions, index + 1, updated, index, subscriptions.Length - index - 1);
                subscriptions = updated;
            }
        }


        /// <summary>The unique identity of one subscription, independent of observer equality.</summary>
        private sealed class Subscription(EventSubject subject, IObserver<ClientRegistrationEvent> observer): IDisposable
        {
            /// <summary>The observer captured by this subscription.</summary>
            public IObserver<ClientRegistrationEvent> Observer { get; } = observer;


            /// <summary>Removes only this membership token; repeated calls have no effect.</summary>
            public void Dispose()
            {
                subject.Remove(this);
            }
        }
    }
}
