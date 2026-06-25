using Verifiable.Core;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Assembles an OpenID Federation 1.0 trust chain by fetching, starting from a
/// leaf entity and walking its <c>authority_hints</c> graph upward until a
/// configured Trust Anchor is reached, per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-10.1">Federation §10.1</see>.
/// The assembled chain is the input the <see cref="TrustChainValidation"/>
/// validator consumes.
/// </summary>
/// <remarks>
/// <para>
/// This is the fetching half of trust establishment (§10.1); it does not
/// verify signatures. The returned chain is structurally coherent (each
/// Subordinate Statement is issued by the superior about the entity below it,
/// in leaf → anchor order) but UNVERIFIED — the caller runs it through
/// <see cref="ValidateTrustChainAsyncDelegate"/> to verify every link
/// signature and the §10.2 rules before trusting it.
/// </para>
/// <para>
/// Loop prevention follows §10.1: an <c>authority_hints</c> value that points
/// to an entity already on the current path is not followed, so a cyclic
/// authority graph cannot loop the walk. The walk is bounded by
/// <c>maxChainLength</c> (depth) and an internal fetch budget derived from it
/// (breadth), and every fetch is routed through the SSRF-policed transport the
/// fetch delegates wrap, since the graph is discovered from untrusted entity
/// configurations.
/// </para>
/// </remarks>
public static class TrustChainResolver
{
    //Per pushed entity the walk may fan out across its authority_hints; the
    //fetch budget bounds total work on a wide (but acyclic) authority graph so
    //a hostile configuration cannot force unbounded fetching within the depth
    //limit.
    private const int FetchFanoutPerLevel = 8;


    /// <summary>
    /// Builds a trust chain from <paramref name="leaf"/> to one of
    /// <paramref name="trustAnchors"/> by fetching and walking
    /// <c>authority_hints</c>.
    /// </summary>
    /// <param name="leaf">The leaf entity the chain is built for.</param>
    /// <param name="trustAnchors">
    /// The Trust Anchor allow-list. The walk terminates at the first reached
    /// entity whose identifier is in this set.
    /// </param>
    /// <param name="fetchEntityConfiguration">
    /// Fetches an entity's self-issued Entity Configuration (§9). Wire to
    /// <see cref="FederationHttpTransport.BuildFetchEntityConfiguration"/>.
    /// </param>
    /// <param name="fetchSubordinateStatement">
    /// Fetches the Subordinate Statement a superior issues about a subject from
    /// the superior's <c>federation_fetch_endpoint</c> (§8.1). Wire to
    /// <see cref="FederationHttpTransport.BuildFetchEntityStatement"/>.
    /// </param>
    /// <param name="context">The per-call exchange context carrying the outbound-fetch policy.</param>
    /// <param name="maxChainLength">
    /// The maximum number of entities (Entity Configurations) on the path,
    /// leaf through anchor inclusive. Must be at least 2.
    /// </param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>
    /// The assembled compact-JWS chain in leaf → anchor order
    /// (<c>[leafConfig, subordinate, superiorConfig, ...]</c>), or
    /// <see langword="null"/> when the leaf configuration cannot be fetched or
    /// no path reaches a Trust Anchor within the bounds.
    /// </returns>
    public static async ValueTask<IReadOnlyList<string>?> BuildAsync(
        EntityIdentifier leaf,
        IReadOnlyCollection<EntityIdentifier> trustAnchors,
        FetchEntityConfigurationDelegate fetchEntityConfiguration,
        FetchEntityStatementDelegate fetchSubordinateStatement,
        ExchangeContext context,
        int maxChainLength,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(trustAnchors);
        ArgumentNullException.ThrowIfNull(fetchEntityConfiguration);
        ArgumentNullException.ThrowIfNull(fetchSubordinateStatement);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxChainLength, 2);

        int fetchBudget = maxChainLength * FetchFanoutPerLevel;

        FetchedEntityStatement? leafConfiguration =
            await fetchEntityConfiguration(leaf, context, cancellationToken).ConfigureAwait(false);
        fetchBudget--;
        if(leafConfiguration is null)
        {
            return null;
        }

        //Explicit stack of frames, leaf at the bottom: the path currently under
        //exploration. Each frame above the leaf carries the Subordinate
        //Statement linking the entity below it to itself. NextHintIndex makes
        //the depth-first walk resumable without recursion.
        Stack<WalkFrame> path = new();
        HashSet<string> onPath = new(StringComparer.Ordinal);

        path.Push(new WalkFrame
        {
            Entity = leaf,
            Configuration = leafConfiguration,
            SubordinateStatement = null,
            AuthorityHints = ReadAuthorityHints(leafConfiguration),
        });
        onPath.Add(leaf.Value);

        while(path.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            WalkFrame top = path.Peek();

            if(trustAnchors.Contains(top.Entity))
            {
                return AssembleChain(path);
            }

            if(top.NextHintIndex >= top.AuthorityHints.Count)
            {
                //Exhausted this entity's hints — backtrack.
                onPath.Remove(top.Entity.Value);
                path.Pop();
                continue;
            }

            EntityIdentifier superior = top.AuthorityHints[top.NextHintIndex];
            top.NextHintIndex++;

            //§10.1 loop prevention: a hint that points back to an entity already
            //on the path is not followed.
            if(onPath.Contains(superior.Value))
            {
                continue;
            }

            //Depth bound: do not grow the path beyond the configured length.
            if(path.Count >= maxChainLength)
            {
                continue;
            }

            if(fetchBudget <= 0)
            {
                return null;
            }

            FetchedEntityStatement? superiorConfiguration =
                await fetchEntityConfiguration(superior, context, cancellationToken).ConfigureAwait(false);
            fetchBudget--;
            if(superiorConfiguration is null)
            {
                continue;
            }

            Uri? fetchEndpoint = ReadFederationFetchEndpoint(superiorConfiguration);
            if(fetchEndpoint is null)
            {
                continue;
            }

            if(fetchBudget <= 0)
            {
                return null;
            }

            FetchedEntityStatement? subordinate = await fetchSubordinateStatement(
                top.Entity, fetchEndpoint, context, cancellationToken).ConfigureAwait(false);
            fetchBudget--;
            if(subordinate is null)
            {
                continue;
            }

            //Structural adjacency: the Subordinate Statement must be issued by
            //the superior about the entity below it. Signature verification is
            //the validator's job (§10.2); this only keeps the assembled path
            //coherent so a mismatched statement is not stitched in.
            if(!subordinate.Statement.Issuer.Equals(superior)
                || !subordinate.Statement.Subject.Equals(top.Entity))
            {
                continue;
            }

            onPath.Add(superior.Value);
            path.Push(new WalkFrame
            {
                Entity = superior,
                Configuration = superiorConfiguration,
                SubordinateStatement = subordinate,
                AuthorityHints = ReadAuthorityHints(superiorConfiguration),
            });
        }

        return null;
    }


    /// <summary>
    /// Flattens the path stack into a leaf → anchor compact-JWS chain:
    /// the leaf configuration, then for each higher entity its linking
    /// Subordinate Statement followed by its configuration.
    /// </summary>
    private static List<string> AssembleChain(Stack<WalkFrame> path)
    {
        //Stack enumerates top → bottom; reverse to leaf → anchor order.
        WalkFrame[] frames = path.ToArray();
        Array.Reverse(frames);

        List<string> chain = new((frames.Length * 2) - 1) { frames[0].Configuration.CompactJws };
        for(int i = 1; i < frames.Length; i++)
        {
            chain.Add(frames[i].SubordinateStatement!.CompactJws);
            chain.Add(frames[i].Configuration.CompactJws);
        }

        return chain;
    }


    /// <summary>
    /// Reads the <c>authority_hints</c> array of an Entity Configuration into a
    /// list of <see cref="EntityIdentifier"/>. Non-string entries and values
    /// that are not valid Entity Identifiers are skipped; an absent claim yields
    /// an empty list.
    /// </summary>
    private static List<EntityIdentifier> ReadAuthorityHints(FetchedEntityStatement configuration)
    {
        if(!configuration.Statement.Payload.TryGetValue(
                WellKnownFederationClaimNames.AuthorityHints, out object? value)
            || value is not IEnumerable<object> hints)
        {
            return [];
        }

        List<EntityIdentifier> result = [];
        foreach(object hint in hints)
        {
            if(hint is string text && TryCreateIdentifier(text) is { } identifier)
            {
                result.Add(identifier);
            }
        }

        return result;
    }


    /// <summary>
    /// Reads the <c>federation_fetch_endpoint</c> URL from an Entity
    /// Configuration's <c>federation_entity</c> metadata, or
    /// <see langword="null"/> when it is absent or not an absolute URL.
    /// </summary>
    private static Uri? ReadFederationFetchEndpoint(FetchedEntityStatement configuration)
    {
        if(configuration.Statement.Payload.TryGetValue(
                WellKnownFederationClaimNames.Metadata, out object? metadataObject)
            && metadataObject is IReadOnlyDictionary<string, object> metadata
            && metadata.TryGetValue(WellKnownEntityTypeIdentifiers.FederationEntity.Value, out object? federationEntityObject)
            && federationEntityObject is IReadOnlyDictionary<string, object> federationEntity
            && federationEntity.TryGetValue(FederationMetadataParameterNames.FetchEndpoint, out object? endpointObject)
            && endpointObject is string endpoint
            && Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri))
        {
            return uri;
        }

        return null;
    }


    /// <summary>
    /// Constructs an <see cref="EntityIdentifier"/> from a string, returning
    /// <see langword="null"/> when the value is not a valid Entity Identifier.
    /// </summary>
    private static EntityIdentifier? TryCreateIdentifier(string value)
    {
        try
        {
            return new EntityIdentifier(value);
        }
        catch(ArgumentException)
        {
            return null;
        }
    }


    /// <summary>
    /// A frame in the depth-first <c>authority_hints</c> walk: an entity, its
    /// configuration, the Subordinate Statement linking the entity below it
    /// (null for the leaf), its authority hints, and the resumable position in
    /// that hint list.
    /// </summary>
    private sealed class WalkFrame
    {
        /// <summary>The entity this frame represents.</summary>
        public required EntityIdentifier Entity { get; init; }

        /// <summary>The entity's self-issued Entity Configuration.</summary>
        public required FetchedEntityStatement Configuration { get; init; }

        /// <summary>The Subordinate Statement issued about the entity below this one; null for the leaf.</summary>
        public required FetchedEntityStatement? SubordinateStatement { get; init; }

        /// <summary>The entity's <c>authority_hints</c>.</summary>
        public required List<EntityIdentifier> AuthorityHints { get; init; }

        /// <summary>The next unexplored index into <see cref="AuthorityHints"/>.</summary>
        public int NextHintIndex { get; set; }
    }
}
