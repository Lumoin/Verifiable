using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Factory for the library's default
/// <see cref="ResolveEntityKeyDelegate"/> — resolves verification keys
/// against in-chain <c>jwks</c> claims by walking the issuer statement's
/// declared keys and matching the kid header.
/// </summary>
/// <remarks>
/// <para>
/// The "in-chain" qualifier matters. This resolver assumes the chain
/// already carries every statement that contributes a verification key.
/// Resolvers that fetch keys over HTTP from a
/// <c>federation_fetch_endpoint</c> are a separate concern; deployments
/// that want both behaviours wire a composite resolver that tries
/// in-chain first and falls back to fetch.
/// </para>
/// <para>
/// Closes the no-default state of
/// <see cref="ResolveEntityKeyDelegate"/> noted in
/// <see cref="FederationDefaultHooks"/>'s class remark — applications no
/// longer have to write the jwks-walk themselves for the common case.
/// </para>
/// </remarks>
public static class FederationKeyResolver
{
    /// <summary>
    /// Builds a <see cref="ResolveEntityKeyDelegate"/> that resolves the
    /// verification key for a statement from the issuer statement's
    /// <c>jwks</c> claim. The returned delegate matches on the
    /// to-be-verified statement's <c>kid</c> header; an absent <c>kid</c> is
    /// a resolution miss (<see langword="null"/>), never a silent
    /// first-key selection, because
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-3.1">Federation §3.1</see>
    /// makes the <c>kid</c> header a MUST on Entity Statement JWTs.
    /// </summary>
    /// <param name="base64UrlDecoder">
    /// Base64url decoder used by <see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/>
    /// when reconstructing key bytes from the JWK's encoded coordinates.
    /// </param>
    /// <param name="memoryPool">
    /// Memory pool the reconstructed key material rents from. The caller
    /// owns the returned <see cref="PublicKeyMemory"/> and is responsible
    /// for disposing it after the verification call completes.
    /// </param>
    public static ResolveEntityKeyDelegate BuildInChainResolver(
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        return (statementToVerify, headerOfStatementToVerify, issuerStatement, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            var targetKid = ReadKid(headerOfStatementToVerify);

            //One issuer statement is the only source, so a miss and a refusal of its key set both resolve no key.
            return ValueTask.FromResult(
                SelectInChainKey(issuerStatement, targetKid, memoryPool) is InChainKeySelected { Jwk: var matchedJwk }
                    ? KeyOf(matchedJwk, base64UrlDecoder, memoryPool)
                    : null);
        };
    }


    /// <summary>
    /// Resolves a verification key keyed by issuer Entity Identifier and <c>kid</c> across the whole
    /// <paramref name="chain"/>, rather than from a single issuer link. This is the resolver a trust-mark
    /// verifier needs: a mark's issuer may be any entity in the chain — the Trust Anchor (its self-asserted
    /// Entity Configuration) or a subordinate whose keys a superior attests — and in both shapes the entity's
    /// <c>jwks</c> rides on the statement whose <c>sub</c> is that entity. The first statement whose
    /// <see cref="EntityStatement.Subject"/> equals <paramref name="issuerEntityId"/> and that carries a key
    /// matching <paramref name="kid"/> wins, a statement carrying no key of the kid passes the walk on to the next, and a statement
    /// whose key set is refused, or whose selected key builds no key, ends it with none, so no later statement stands in for a key
    /// set the chain refused; an absent <paramref name="kid"/> is a resolution miss
    /// (<see langword="null"/>), never a silent first-key selection —
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-7">Federation §7</see> (and §8.4.2
    /// for the Trust Mark Status Response) makes the <c>kid</c> header a MUST on Trust Mark JWTs.
    /// </summary>
    /// <param name="chain">The resolved trust chain carrying the candidate statements.</param>
    /// <param name="issuerEntityId">The Entity Identifier whose key is sought (a trust mark's <c>iss</c>).</param>
    /// <param name="kid">The key id to match. A <see langword="null"/> value is a resolution miss, not a wildcard.</param>
    /// <param name="base64UrlDecoder">
    /// Base64url decoder used by <see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/> when
    /// reconstructing key bytes from the JWK's encoded coordinates.
    /// </param>
    /// <param name="memoryPool">
    /// Memory pool the reconstructed key material rents from. The caller owns the returned
    /// <see cref="PublicKeyMemory"/> and is responsible for disposing it.
    /// </param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>
    /// The resolved <see cref="PublicKeyMemory"/>, or <see langword="null"/> when no chain statement declares a
    /// matching key for the issuer.
    /// </returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The resolved PublicKeyMemory is the method's return value — ownership transfers to the caller, who disposes it after the verify call, as the parameter docs state.")]
    public static ValueTask<PublicKeyMemory?> ResolveInChainKeyAsync(
        TrustChain chain,
        string issuerEntityId,
        string? kid,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerEntityId);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        cancellationToken.ThrowIfCancellationRequested();

        foreach(EntityStatement statement in chain.Statements)
        {
            if(!string.Equals(statement.Subject.Value, issuerEntityId, StringComparison.Ordinal))
            {
                continue;
            }

            //A statement whose key set carries no key of the kid, an empty keys array among them, is an ordinary miss, and the walk
            //moves on to the next statement about the entity. A statement whose key set is refused - no key set where it carries
            //one, a set that is no JWK Set, a keys member absent or no array (RFC 7517 section 5), one naming the kid twice or
            //publishing private material - or whose selected key builds no key, ends the walk with no key: a later statement never
            //stands in for a key set of the entity the chain refused.
            var selection = SelectInChainKey(statement, kid, memoryPool);

            if(selection is InChainKeyMissed)
            {
                continue;
            }

            //The resolved key is owned by and returned to the caller, who disposes it after the verify call.
            return selection switch
            {
                InChainKeySelected { Jwk: var matchedJwk } => ValueTask.FromResult(KeyOf(matchedJwk, base64UrlDecoder, memoryPool)),
                InChainKeySetRefused => ValueTask.FromResult<PublicKeyMemory?>(null),
                _ => throw new InvalidOperationException("The in-chain key selection answered a selection it never answers.")
            };
        }

        return ValueTask.FromResult<PublicKeyMemory?>(null);
    }


    /// <summary>
    /// The key a selected JWK builds, which the caller owns, or <see langword="null"/> when it builds none: a set of one
    /// eligible-but-malformed element (a missing kty, or missing coordinates for its kty) is selected and still is not one the
    /// converter can build, refused as no key instead of letting the converter's exception escape into the verification pipeline.
    /// </summary>
    /// <param name="jwk">The selected JWK's members.</param>
    /// <param name="base64UrlDecoder">The decoder of the key's coordinates.</param>
    /// <param name="memoryPool">The pool the key material is rented from.</param>
    /// <returns>The key, or <see langword="null"/>.</returns>
    private static PublicKeyMemory? KeyOf(Dictionary<string, object> jwk, DecodeDelegate base64UrlDecoder, BaseMemoryPool memoryPool)
    {
        try
        {
            var (algorithm, purpose, scheme, keyMaterial) =
                CryptoFormatConversions.DefaultJwkToAlgorithmConverter(jwk, memoryPool, base64UrlDecoder);

            return new PublicKeyMemory(keyMaterial, Tag.Create(algorithm).With(purpose).With(scheme));
        }
        catch(Exception ex) when(ex is FormatException or InvalidOperationException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }


    /// <summary>
    /// Reads the <c>kid</c> header value from a to-be-verified statement's protected header, or
    /// <see langword="null"/> when absent.
    /// </summary>
    /// <param name="header">The protected header to read the <c>kid</c> from.</param>
    /// <returns>The <c>kid</c> string, or <see langword="null"/> when the header carries no string <c>kid</c>.</returns>
    private static string? ReadKid(UnverifiedJwtHeader header)
    {
        if(header.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidObj) && kidObj is string kid)
        {
            return kid;
        }

        return null;
    }


    /// <summary>
    /// Selects the JWK from <paramref name="issuerStatement"/>'s <c>jwks</c> claim whose <c>kid</c> equals
    /// <paramref name="targetKid"/> and whose <c>use</c> is eligible for signature verification, returned
    /// as the mutable dictionary <see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/>
    /// expects. Re-emits the already-parsed <c>jwks</c> claim to UTF-8 JSON via
    /// <see cref="JsonAppender"/> and composes
    /// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?, ReadOnlySpan{byte})"/> on the
    /// result — the same combinator
    /// <see cref="Verifiable.OAuth.Server.PrivateKeyJwtClientAuthentication"/>'s client-authentication key
    /// selection composes, so the duplicate-<c>kid</c> refusal AND the private-or-symmetric-material
    /// refusal are shared rather than re-implemented. Selection reads the library's RE-EMISSION of the
    /// parsed <c>jwks</c> claim, not the wire bytes of the Entity Statement: what the JWT payload
    /// deserializer did with a duplicated or escaped member name in the original claim, before it
    /// reached this dictionary, is outside what this selection sees.
    /// A statement carrying no <c>jwks</c>, and a set carrying no eligible key of the kid, are ordinary misses; a <c>jwks</c>
    /// that is no JSON object, a <paramref name="targetKid"/> that is <see langword="null"/> (an absent <c>kid</c> header is
    /// malformed input per <see href="https://openid.net/specs/openid-federation-1_0.html#section-3.1">Federation §3.1</see>,
    /// not a wildcard), a <paramref name="targetKid"/> on more than one key
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see>), a key carrying private or
    /// symmetric material, and every other refusal of the set, are refusals of the key set, never misses.
    /// </summary>
    /// <param name="issuerStatement">The statement whose <c>jwks</c> claim supplies the candidate keys.</param>
    /// <param name="targetKid">The <c>kid</c> to match. A <see langword="null"/> value never matches: the set is refused for it.</param>
    /// <param name="memoryPool">
    /// Pool the UTF-8 rendering of the <c>jwks</c> claim rents from. The buffer is consumed by the selection
    /// scan and returned before this method exits, so no ownership leaves it.
    /// </param>
    /// <returns>
    /// The matched JWK as a mutable dictionary (<see cref="InChainKeySelected"/>); an ordinary miss, a statement carrying no
    /// <c>jwks</c> or a set carrying no eligible key of the kid (<see cref="InChainKeyMissed"/>); or the refusal of a key set the
    /// statement carries - a <c>jwks</c> that is no JSON object, a set the selection refuses, the kid required and absent among
    /// them (<see cref="InChainKeySetRefused"/>).
    /// </returns>
    private static InChainKeySelection SelectInChainKey(EntityStatement issuerStatement, string? targetKid, BaseMemoryPool memoryPool)
    {
        if(!issuerStatement.Payload.TryGetValue(WellKnownFederationClaimNames.Jwks, out var jwksObj))
        {
            return new InChainKeyMissed();
        }

        if(jwksObj is not IReadOnlyDictionary<string, object> jwksDict)
        {
            return new InChainKeySetRefused(JwkSelectionOutcome.MalformedDocument);
        }

        StringBuilder builder = JsonAppender.Rent();
        try
        {
            JsonAppender.AppendObject(builder, jwksDict);

            Encoding utf8 = Encoding.UTF8;
            int byteCount = 0;
            foreach(ReadOnlyMemory<char> chunk in builder.GetChunks())
            {
                byteCount += utf8.GetByteCount(chunk.Span);
            }

            using IMemoryOwner<byte> jwksJson = memoryPool.Rent(byteCount);
            Span<byte> destination = jwksJson.Memory.Span;
            int written = 0;
            foreach(ReadOnlyMemory<char> chunk in builder.GetChunks())
            {
                written += utf8.GetBytes(chunk.Span, destination[written..]);
            }

            var result = JwkJsonReader.SelectKeyByKeyId(destination[..written], targetKid, WellKnownJwkValues.UseSigUtf8);

            return result switch
            {
                { Outcome: JwkSelectionOutcome.Selected, Members: { } members } => new InChainKeySelected(CopyJwk(members)),
                { Outcome: JwkSelectionOutcome.NoMatch } => new InChainKeyMissed(),
                {
                    Outcome: (JwkSelectionOutcome.MultipleKeysMatched
                        or JwkSelectionOutcome.KeyIdRequired
                        or JwkSelectionOutcome.MalformedDocument
                        or JwkSelectionOutcome.PrivateOrSymmetricMemberPresent
                        or JwkSelectionOutcome.RepeatedMemberName
                        or JwkSelectionOutcome.UndecodableMember) and var refused
                } => new InChainKeySetRefused(refused),
                _ => throw new InvalidOperationException(
                    $"The key selection answered {result.Outcome} without the members a selection carries, or an outcome it never answers.")
            };
        }
        finally
        {
            JsonAppender.Return(builder);
        }
    }


    /// <summary>
    /// What selecting a statement's key of a kid found: the key, an ordinary miss, or the refusal of the key set, which the walk
    /// over a chain tells apart, moving on after a miss and ending after a refusal.
    /// </summary>
    private abstract record InChainKeySelection;


    /// <summary>The statement's key set carries exactly one eligible key of the kid.</summary>
    /// <param name="Jwk">The key's members, in the dictionary the key converter takes.</param>
    private sealed record InChainKeySelected(Dictionary<string, object> Jwk) : InChainKeySelection;


    /// <summary>The statement carries no key set, or its key set carries no eligible key of the kid: an ordinary miss.</summary>
    private sealed record InChainKeyMissed : InChainKeySelection;


    /// <summary>
    /// The statement carries a key set that is refused: a <c>jwks</c> that is no JSON object, or a set the selection refuses
    /// (<see cref="JwkSelectionOutcome"/>) - no one well-formed object, a repeated or undecodable member, private or symmetric
    /// material, a kid on more than one key, or a kid required and absent.
    /// </summary>
    /// <param name="Outcome">The selection's refusal.</param>
    private sealed record InChainKeySetRefused(JwkSelectionOutcome Outcome) : InChainKeySelection;


    /// <summary>
    /// Copies a selected JWK's members into the mutable dictionary
    /// <see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/> expects — boxing each
    /// already-string-typed member from the selection result rather than casting. The one copy
    /// this assembly's key-selection call sites share, rather than each re-implementing it.
    /// </summary>
    /// <param name="source">The selected JWK's members, as a key selection result carries them.</param>
    /// <returns>The members copied into a mutable <see cref="Dictionary{TKey, TValue}"/>.</returns>
    internal static Dictionary<string, object> CopyJwk(IReadOnlyDictionary<string, string> source)
    {
        Dictionary<string, object> result = new(source.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, string> kvp in source)
        {
            result[kvp.Key] = kvp.Value;
        }
        return result;
    }
}
