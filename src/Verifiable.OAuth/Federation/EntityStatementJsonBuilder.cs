using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Hand-written JSON construction for the OpenID Federation 1.0 Entity
/// Configuration JWT. Builds the protected-header and payload dictionaries
/// the JWS signer expects, and emits each dictionary to UTF-8 JSON via a
/// <see cref="StringBuilder"/> walker — no <c>System.Text.Json</c> or other
/// JSON-library dependency is taken on, matching the
/// <c>Verifiable.OAuth</c> serialization-firewall discipline.
/// </summary>
/// <remarks>
/// <para>
/// Each function in this class is the source of truth for one piece of
/// wire output and is intentionally small enough to be audited
/// individually. Federation EC claim shapes are arbitrary nested JSON
/// — primitives, arrays, and recursive dictionaries — so the
/// <see cref="AppendValue"/> walker is recursive. The walker accepts the
/// CLR types an application naturally constructs:
/// <see cref="string"/>, <see cref="bool"/>, integer and floating-point
/// numeric primitives, <see cref="Uri"/>, nested
/// <see cref="IReadOnlyDictionary{TKey,TValue}"/> with <see cref="string"/>
/// keys, and <see cref="IEnumerable{T}"/> of <see cref="object"/>.
/// <see cref="IFormattable"/> values format with <see cref="CultureInfo.InvariantCulture"/>.
/// </para>
/// <para>
/// The companion <see cref="EncodeJwtPart"/> wraps the UTF-8 bytes in a
/// <see cref="TaggedMemory{T}"/> tagged with
/// <see cref="BufferTags.Json"/> so callers can pass it directly to
/// <see cref="Jws.SignAsync{TJwtPart}(TJwtPart, TJwtPart, JwtPartEncoder{TJwtPart}, EncodeDelegate, Cryptography.PrivateKeyMemory, MemoryPool{byte}, CancellationToken)"/>
/// as the <see cref="JwtPartEncoder{TJwtPart}"/> argument.
/// </para>
/// </remarks>
[DebuggerDisplay("EntityStatementJsonBuilder")]
public static class EntityStatementJsonBuilder
{
    /// <summary>
    /// Builds the protected-header dictionary for an Entity Configuration
    /// JWS: <c>typ = entity-statement+jwt</c>, <c>alg = &lt;jwa&gt;</c>,
    /// <c>kid = &lt;kid&gt;</c>.
    /// </summary>
    /// <param name="kid">The <c>kid</c> identifying the signing key.</param>
    /// <param name="alg">
    /// The JWA algorithm identifier for the signing key (e.g.
    /// <c>ES256</c>, <c>RS256</c>, <c>Ed25519</c>). The caller derives this
    /// from the key's tag through
    /// <see cref="CryptoFormatConversions.DefaultTagToJwaConverter"/> so
    /// no algorithm choice is hardcoded here.
    /// </param>
    public static Dictionary<string, object> BuildHeader(string kid, string alg) =>
        BuildHeader(kid, alg, WellKnownFederationMediaTypes.EntityStatementJwt);


    /// <summary>
    /// Builds the protected-header dictionary for a Federation JWS with an
    /// explicit <c>typ</c>. Entity Configurations and Subordinate Statements
    /// carry <c>entity-statement+jwt</c> (the <see cref="BuildHeader(string, string)"/>
    /// default); a Resolve Response carries <c>resolve-response+jwt</c> per
    /// Federation §8.3, so cross-JWT confusion between a resolver's
    /// resolution and an Entity Statement is structurally impossible.
    /// </summary>
    /// <param name="kid">The <c>kid</c> identifying the signing key.</param>
    /// <param name="alg">
    /// The JWA algorithm identifier for the signing key, derived by the
    /// caller from the key's tag through
    /// <see cref="CryptoFormatConversions.DefaultTagToJwaConverter"/>.
    /// </param>
    /// <param name="typ">
    /// The <c>typ</c> header value — a member of
    /// <see cref="WellKnownFederationMediaTypes"/>.
    /// </param>
    public static Dictionary<string, object> BuildHeader(string kid, string alg, string typ)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kid);
        ArgumentException.ThrowIfNullOrWhiteSpace(alg);
        ArgumentException.ThrowIfNullOrWhiteSpace(typ);

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJoseHeaderNames.Typ] = typ,
            [WellKnownJwkMemberNames.Alg] = alg,
            [WellKnownJwkMemberNames.Kid] = kid
        };
    }


    /// <summary>
    /// Builds the EC payload dictionary with the structural claims
    /// (<c>iss</c>, <c>sub</c>, <c>iat</c>, <c>exp</c>, <c>jwks</c>) plus
    /// the application-supplied <c>metadata</c>, <c>authority_hints</c>,
    /// and any additional top-level claims.
    /// </summary>
    /// <param name="entityIdentifier">
    /// The entity's identifier — used as both <c>iss</c> and <c>sub</c>
    /// per Federation §3.1 (an Entity Configuration is self-issued).
    /// </param>
    /// <param name="issuedAt">The <c>iat</c> claim value.</param>
    /// <param name="expiresAt">The <c>exp</c> claim value.</param>
    /// <param name="jwks">
    /// The JWKS document carrying the entity's federation signing keys
    /// (<c>{ "keys": [...] }</c>).
    /// </param>
    /// <param name="contribution">
    /// Application-supplied metadata, authority hints, and additional
    /// claims. May be <see cref="FederationEntityConfigurationContribution.Empty"/>
    /// when only the structural claims are needed.
    /// </param>
    public static Dictionary<string, object> BuildConfigurationPayload(
        Uri entityIdentifier,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        IReadOnlyDictionary<string, object> jwks,
        FederationEntityConfigurationContribution contribution,
        IReadOnlyList<string> clientRegistrationTypesSupported)
    {
        ArgumentNullException.ThrowIfNull(entityIdentifier);
        ArgumentNullException.ThrowIfNull(jwks);
        ArgumentNullException.ThrowIfNull(contribution);
        ArgumentNullException.ThrowIfNull(clientRegistrationTypesSupported);

        string entityId = entityIdentifier.ToString();

        Dictionary<string, object> payload = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Iss] = entityId,
            [WellKnownJwtClaimNames.Sub] = entityId,
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = expiresAt.ToUnixTimeSeconds(),
            [WellKnownFederationClaimNames.Jwks] = jwks
        };

        if(contribution.Metadata.Count > 0 || clientRegistrationTypesSupported.Count > 0)
        {
            Dictionary<string, object> metadataClaim = new(StringComparer.Ordinal);
            foreach(KeyValuePair<EntityTypeIdentifier, IReadOnlyDictionary<string, object>> entry in contribution.Metadata)
            {
                metadataClaim[entry.Key.Value] = entry.Value;
            }

            //Advertise the registration types this OP supports (Federation §12)
            //inside the openid_provider metadata block. Derived from the entity's
            //enabled federation capabilities, so it appears only for an entity
            //acting as an OP that accepts registrations. An application-contributed
            //value wins — the library never overwrites an explicit choice.
            if(clientRegistrationTypesSupported.Count > 0)
            {
                string openIdProviderKey = WellKnownEntityTypeIdentifiers.OpenIdProvider.Value;
                Dictionary<string, object> openIdProviderBlock = new(StringComparer.Ordinal);
                if(metadataClaim.TryGetValue(openIdProviderKey, out object? existing)
                    && existing is IReadOnlyDictionary<string, object> existingBlock)
                {
                    foreach(KeyValuePair<string, object> member in existingBlock)
                    {
                        openIdProviderBlock[member.Key] = member.Value;
                    }
                }

                if(!openIdProviderBlock.ContainsKey(WellKnownFederationClaimNames.ClientRegistrationTypesSupported))
                {
                    List<object> types = new(clientRegistrationTypesSupported.Count);
                    foreach(string registrationType in clientRegistrationTypesSupported)
                    {
                        types.Add(registrationType);
                    }

                    openIdProviderBlock[WellKnownFederationClaimNames.ClientRegistrationTypesSupported] = types;
                }

                metadataClaim[openIdProviderKey] = openIdProviderBlock;
            }

            payload[WellKnownFederationClaimNames.Metadata] = metadataClaim;
        }

        if(contribution.AuthorityHints is { Count: > 0 } hints)
        {
            List<object> hintsList = new(hints.Count);
            foreach(Uri hint in hints)
            {
                hintsList.Add(hint.ToString());
            }

            payload[WellKnownFederationClaimNames.AuthorityHints] = hintsList;
        }

        if(contribution.AdditionalClaims is { Count: > 0 })
        {
            foreach(KeyValuePair<string, object> extra in contribution.AdditionalClaims)
            {
                //Structural claims take precedence — skip any extra that
                //would shadow the library-emitted iss/sub/iat/exp/jwks.
                if(payload.ContainsKey(extra.Key))
                {
                    continue;
                }

                payload[extra.Key] = extra.Value;
            }
        }

        return payload;
    }


    /// <summary>
    /// Builds a Subordinate Statement payload — the wire body of a
    /// <c>federation_fetch_endpoint</c> response per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.1">Federation §8.1</see>.
    /// Structural claims (<c>iss</c>, <c>sub</c>, <c>iat</c>, <c>exp</c>,
    /// <c>jwks</c>) come from the library; per-subject
    /// <c>metadata_policy</c>, <c>metadata</c>, <c>constraints</c>, and
    /// extension claims come from the application-supplied contribution.
    /// </summary>
    /// <param name="issuerEntityIdentifier">
    /// The Entity Identifier of the issuing entity (the anchor serving
    /// the endpoint). Becomes the <c>iss</c> claim.
    /// </param>
    /// <param name="subjectEntityIdentifier">
    /// The Entity Identifier of the subject the statement is about.
    /// Becomes the <c>sub</c> claim. Distinct from <c>iss</c> — that
    /// distinction is the structural marker separating a Subordinate
    /// Statement from an Entity Configuration per Federation §3.
    /// </param>
    /// <param name="issuedAt">The <c>iat</c> claim value.</param>
    /// <param name="expiresAt">The <c>exp</c> claim value.</param>
    /// <param name="contribution">
    /// Application-supplied subject <c>jwks</c> plus optional
    /// <c>metadata_policy</c>, <c>metadata</c>, <c>constraints</c>, and
    /// extension claims.
    /// </param>
    public static Dictionary<string, object> BuildSubordinatePayload(
        Uri issuerEntityIdentifier,
        Uri subjectEntityIdentifier,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        SubordinateStatementContribution contribution)
    {
        ArgumentNullException.ThrowIfNull(issuerEntityIdentifier);
        ArgumentNullException.ThrowIfNull(subjectEntityIdentifier);
        ArgumentNullException.ThrowIfNull(contribution);
        ArgumentNullException.ThrowIfNull(contribution.Jwks);

        Dictionary<string, object> payload = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Iss] = issuerEntityIdentifier.ToString(),
            [WellKnownJwtClaimNames.Sub] = subjectEntityIdentifier.ToString(),
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = expiresAt.ToUnixTimeSeconds(),
            [WellKnownFederationClaimNames.Jwks] = contribution.Jwks
        };

        if(contribution.MetadataPolicy is { Count: > 0 } policy)
        {
            payload[WellKnownFederationClaimNames.MetadataPolicy] = policy;
        }

        if(contribution.Metadata is { Count: > 0 } metadata)
        {
            payload[WellKnownFederationClaimNames.Metadata] = metadata;
        }

        if(contribution.Constraints is { Count: > 0 } constraints)
        {
            payload[WellKnownFederationClaimNames.Constraints] = constraints;
        }

        if(contribution.AdditionalClaims is { Count: > 0 })
        {
            foreach(KeyValuePair<string, object> extra in contribution.AdditionalClaims)
            {
                if(payload.ContainsKey(extra.Key))
                {
                    continue;
                }

                payload[extra.Key] = extra.Value;
            }
        }

        return payload;
    }


    /// <summary>
    /// Builds a Resolve Response payload — the wire body of a
    /// <c>federation_resolve_endpoint</c> response per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3">Federation §8.3</see>.
    /// Structural claims (<c>iss</c> = the resolver, <c>sub</c> = the
    /// resolved subject, <c>iat</c>, <c>exp</c>) and the required resolved
    /// <c>metadata</c> are always emitted; the optional <c>trust_chain</c>
    /// and <c>trust_marks</c> come from the application-supplied contribution.
    /// </summary>
    /// <param name="resolverEntityIdentifier">
    /// The Entity Identifier of the resolver serving the endpoint. Becomes
    /// the <c>iss</c> claim.
    /// </param>
    /// <param name="subjectEntityIdentifier">
    /// The exact Entity Identifier string of the resolved subject — echoed
    /// verbatim as the <c>sub</c> claim. Passed as the wire string rather
    /// than a <see cref="Uri"/> so the requester's identifier is reflected
    /// without authority-normalisation (Entity Identifiers are compared as
    /// ordinal strings per Federation §3, so a trailing-slash normalisation
    /// would change the identity).
    /// </param>
    /// <param name="issuedAt">The <c>iat</c> claim value.</param>
    /// <param name="expiresAt">The <c>exp</c> claim value.</param>
    /// <param name="contribution">
    /// The resolved <c>metadata</c> (required) plus the optional
    /// <c>trust_chain</c> (compact Entity Statement JWS strings),
    /// <c>trust_marks</c>, and extension claims.
    /// </param>
    public static Dictionary<string, object> BuildResolveResponsePayload(
        Uri resolverEntityIdentifier,
        string subjectEntityIdentifier,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        ResolveResponseContribution contribution)
    {
        ArgumentNullException.ThrowIfNull(resolverEntityIdentifier);
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectEntityIdentifier);
        ArgumentNullException.ThrowIfNull(contribution);
        ArgumentNullException.ThrowIfNull(contribution.Metadata);

        Dictionary<string, object> payload = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Iss] = resolverEntityIdentifier.ToString(),
            [WellKnownJwtClaimNames.Sub] = subjectEntityIdentifier,
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = expiresAt.ToUnixTimeSeconds(),
            [WellKnownFederationClaimNames.Metadata] = contribution.Metadata
        };

        if(contribution.TrustChain is { Count: > 0 } trustChain)
        {
            //The chain is a JSON array of compact Entity Statement JWS
            //strings; box each into the object-typed list the JSON walker
            //emits as a string array.
            List<object> chainList = new(trustChain.Count);
            foreach(string statement in trustChain)
            {
                chainList.Add(statement);
            }

            payload[WellKnownFederationClaimNames.TrustChain] = chainList;
        }

        if(contribution.TrustMarks is { Count: > 0 } trustMarks)
        {
            payload[WellKnownFederationClaimNames.TrustMarks] = new List<object>(trustMarks);
        }

        if(contribution.AdditionalClaims is { Count: > 0 })
        {
            foreach(KeyValuePair<string, object> extra in contribution.AdditionalClaims)
            {
                if(payload.ContainsKey(extra.Key))
                {
                    continue;
                }

                payload[extra.Key] = extra.Value;
            }
        }

        return payload;
    }


    /// <summary>
    /// Builds a Historical Keys payload — the wire body of a
    /// <c>federation_historical_keys_endpoint</c> response per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.7.3">Federation §8.7.3</see>.
    /// The structural claims (<c>iss</c> = the entity, <c>iat</c>) are always
    /// emitted; the <c>keys</c> array (the historical JWK objects, each
    /// carrying at least <c>kid</c> and <c>exp</c>) comes from the
    /// application-supplied contribution.
    /// </summary>
    /// <param name="entityIdentifier">
    /// The Entity Identifier of the entity serving the endpoint. Becomes the
    /// <c>iss</c> claim.
    /// </param>
    /// <param name="issuedAt">The <c>iat</c> claim value.</param>
    /// <param name="contribution">
    /// The historical <c>keys</c> array (required) plus any extension claims.
    /// </param>
    public static Dictionary<string, object> BuildHistoricalKeysPayload(
        Uri entityIdentifier,
        DateTimeOffset issuedAt,
        HistoricalKeysContribution contribution)
    {
        ArgumentNullException.ThrowIfNull(entityIdentifier);
        ArgumentNullException.ThrowIfNull(contribution);
        ArgumentNullException.ThrowIfNull(contribution.Keys);

        //The §8.7.3 keys array is a JSON array of JWK objects; box each into
        //the object-typed list the JSON walker emits as an array of objects.
        List<object> keysList = new(contribution.Keys.Count);
        foreach(IReadOnlyDictionary<string, object> key in contribution.Keys)
        {
            keysList.Add(key);
        }

        Dictionary<string, object> payload = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Iss] = entityIdentifier.ToString(),
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownFederationClaimNames.Keys] = keysList
        };

        if(contribution.AdditionalClaims is { Count: > 0 })
        {
            foreach(KeyValuePair<string, object> extra in contribution.AdditionalClaims)
            {
                if(payload.ContainsKey(extra.Key))
                {
                    continue;
                }

                payload[extra.Key] = extra.Value;
            }
        }

        return payload;
    }


    /// <summary>
    /// Builds an Explicit Registration Response payload — the wire body of a
    /// <c>federation_registration_endpoint</c> response per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-12.2">Federation §12.2</see> / §3.1.5.
    /// Structural claims (<c>iss</c> = the OP, <c>sub</c> = <c>aud</c> = the
    /// RP, <c>iat</c>, <c>exp</c>) and the registered <c>metadata</c> are
    /// always emitted; the optional <c>trust_anchor</c> and <c>jwks</c> come
    /// from the application-supplied contribution.
    /// </summary>
    /// <param name="opEntityIdentifier">
    /// The OP's Entity Identifier (the entity serving the endpoint). Becomes
    /// the <c>iss</c> claim.
    /// </param>
    /// <param name="rpEntityIdentifier">
    /// The Relying Party's Entity Identifier. Becomes both the <c>sub</c> and
    /// the <c>aud</c> claim — §3.1.5 requires <c>aud</c> to be the RP and to
    /// carry no other value, so it is emitted as a single string, not an
    /// array.
    /// </param>
    /// <param name="issuedAt">The <c>iat</c> claim value.</param>
    /// <param name="expiresAt">The <c>exp</c> claim value.</param>
    /// <param name="contribution">
    /// The registered <c>metadata</c> (required) plus the optional
    /// <c>trust_anchor</c>, <c>jwks</c>, and extension claims.
    /// </param>
    public static Dictionary<string, object> BuildExplicitRegistrationResponsePayload(
        Uri opEntityIdentifier,
        Uri rpEntityIdentifier,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        ExplicitRegistrationContribution contribution)
    {
        ArgumentNullException.ThrowIfNull(opEntityIdentifier);
        ArgumentNullException.ThrowIfNull(rpEntityIdentifier);
        ArgumentNullException.ThrowIfNull(contribution);
        ArgumentNullException.ThrowIfNull(contribution.Metadata);

        Dictionary<string, object> payload = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Iss] = opEntityIdentifier.ToString(),
            [WellKnownJwtClaimNames.Sub] = rpEntityIdentifier.ToString(),
            [WellKnownJwtClaimNames.Aud] = rpEntityIdentifier.ToString(),
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = expiresAt.ToUnixTimeSeconds(),
            [WellKnownFederationClaimNames.Metadata] = contribution.Metadata
        };

        if(contribution.TrustAnchor is not null)
        {
            payload[WellKnownFederationClaimNames.TrustAnchor] = contribution.TrustAnchor.ToString();
        }

        if(contribution.Jwks is { Count: > 0 } jwks)
        {
            payload[WellKnownFederationClaimNames.Jwks] = jwks;
        }

        if(contribution.AdditionalClaims is { Count: > 0 })
        {
            foreach(KeyValuePair<string, object> extra in contribution.AdditionalClaims)
            {
                if(payload.ContainsKey(extra.Key))
                {
                    continue;
                }

                payload[extra.Key] = extra.Value;
            }
        }

        return payload;
    }


    /// <summary>
    /// Encodes a dictionary into UTF-8 JSON bytes tagged with
    /// <see cref="BufferTags.Json"/>. Suitable for passing as the
    /// <see cref="JwtPartEncoder{TJwtPart}"/> argument to
    /// <see cref="Jws.SignAsync{TJwtPart}(TJwtPart, TJwtPart, JwtPartEncoder{TJwtPart}, EncodeDelegate, Cryptography.PrivateKeyMemory, MemoryPool{byte}, CancellationToken)"/>.
    /// </summary>
    public static TaggedMemory<byte> EncodeJwtPart(Dictionary<string, object> part)
    {
        ArgumentNullException.ThrowIfNull(part);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            JsonAppender.AppendObject(sb, part);

            return new TaggedMemory<byte>(JsonAppender.ToUtf8Bytes(sb), BufferTags.Json);
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }
}
