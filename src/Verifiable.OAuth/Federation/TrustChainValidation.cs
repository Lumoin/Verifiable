using System.Buffers;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Builds the library's production <see cref="ValidateTrustChainAsyncDelegate"/>
/// for an already-assembled inline OpenID Federation 1.0 trust chain (the
/// <c>trust_chain</c> JOSE header parameter of §4.3): it parses each compact
/// JWS into a typed <see cref="EntityStatement"/>, verifies every per-link
/// signature against the key the chain itself vouches for, runs the
/// <see cref="TrustChainValidator"/> rules, and returns the outcome.
/// </summary>
/// <remarks>
/// <para>
/// Key resolution is the security-critical step and is done strictly from the
/// chain: a self-signed Entity Configuration is verified against its own
/// <c>jwks</c>, and a Subordinate Statement against the <c>jwks</c> of the
/// next-higher statement (its issuer's superior-attested keys). There is no
/// fallback to a key resolved out of band for an unrecognized issuer — an
/// unresolved key fails the chain closed, so a statement signed by a key the
/// chain does not vouch for cannot validate.
/// </para>
/// <para>
/// The validator only validates an inline chain; it does not fetch the chain.
/// A fetch-driven builder that assembles the chain by walking
/// <c>authority_hints</c> produces the input this delegate consumes.
/// </para>
/// </remarks>
public static class TrustChainValidation
{
    /// <summary>
    /// Builds a <see cref="ValidateTrustChainAsyncDelegate"/> over the supplied
    /// JSON/decoding seams and key resolver. Wire <paramref name="keyResolver"/>
    /// to <see cref="FederationKeyResolver.BuildInChainResolver"/> for the
    /// in-chain key resolution the library intends.
    /// </summary>
    /// <param name="headerDeserializer">
    /// Deserializes a compact JWS protected-header segment's bytes into a claim
    /// dictionary. Carried as a seam so the serialization firewall is honored.
    /// </param>
    /// <param name="payloadDeserializer">
    /// Deserializes a compact JWS payload segment's bytes into a claim dictionary.
    /// </param>
    /// <param name="base64UrlDecoder">
    /// Decodes the base64url segments of each compact JWS — used both to
    /// materialize the header/payload bytes and by <see cref="Jws.VerifyAsync"/>.
    /// </param>
    /// <param name="keyResolver">
    /// Resolves the verification key for each statement from its issuer
    /// statement's <c>jwks</c>. The returned key is owned by this orchestrator
    /// and disposed after the verify call.
    /// </param>
    /// <returns>The composed validation delegate.</returns>
    public static ValidateTrustChainAsyncDelegate BuildInlineValidator(
        JwtHeaderDeserializer headerDeserializer,
        JwtPayloadDeserializer payloadDeserializer,
        DecodeDelegate base64UrlDecoder,
        ResolveEntityKeyDelegate keyResolver)
    {
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(payloadDeserializer);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(keyResolver);

        return async (compactJwsChain, trustAnchors, validationTime, clockSkew, pool, cancellationToken) =>
        {
            ArgumentNullException.ThrowIfNull(compactJwsChain);
            ArgumentNullException.ThrowIfNull(trustAnchors);
            ArgumentNullException.ThrowIfNull(pool);

            if(compactJwsChain.Count == 0)
            {
                return TrustChainValidationOutcome.Rejected("The trust chain is empty.");
            }

            //Parse every link into a typed statement plus its protected header.
            //The header is retained per link so the key resolver can read the
            //kid of the statement whose signature it is about to verify.
            List<EntityStatement> parsedStatements = new(compactJwsChain.Count);
            List<UnverifiedJwtHeader> parsedHeaders = new(compactJwsChain.Count);
            for(int i = 0; i < compactJwsChain.Count; i++)
            {
                FetchedEntityStatement? parsed = EntityStatementJwsReader.TryRead(
                    compactJwsChain[i], headerDeserializer, payloadDeserializer, base64UrlDecoder, pool);

                if(parsed is null)
                {
                    return TrustChainValidationOutcome.Rejected(
                        $"Chain entry at position {i} is not a valid Entity Statement compact JWS.");
                }

                parsedStatements.Add(parsed.Statement);
                parsedHeaders.Add(parsed.Header);
            }

            //Resolve each link's verification key from the chain and verify the
            //signature. A self-signed Entity Configuration is verified against
            //its own jwks; a Subordinate Statement against the next-higher
            //statement (its issuer's superior-attested keys). An unresolved key
            //fails the chain closed.
            bool[] linkVerified = new bool[parsedStatements.Count];
            for(int i = 0; i < parsedStatements.Count; i++)
            {
                EntityStatement statementToVerify = parsedStatements[i];
                EntityStatement issuerStatement =
                    statementToVerify is EntityConfiguration || i + 1 >= parsedStatements.Count
                        ? statementToVerify
                        : parsedStatements[i + 1];

                PublicKeyMemory? verificationKey = await keyResolver(
                    statementToVerify, parsedHeaders[i], issuerStatement, cancellationToken).ConfigureAwait(false);

                if(verificationKey is null)
                {
                    return TrustChainValidationOutcome.Rejected(
                        $"No verification key could be resolved from the chain for the statement at position {i}.");
                }

                using(verificationKey)
                {
                    try
                    {
                        linkVerified[i] = await Jws.VerifyAsync(
                            compactJwsChain[i], base64UrlDecoder, pool, verificationKey, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    catch(Exception ex) when(ex is FormatException or InvalidOperationException)
                    {
                        return TrustChainValidationOutcome.Rejected(
                            $"Signature verification raised for the statement at position {i}: {ex.Message}");
                    }
                }
            }

            TrustChain chain = new() { Statements = parsedStatements };
            TrustChainValidationContext context = new()
            {
                Chain = chain,
                TrustAnchors = trustAnchors,
                LinkSignaturesVerified = linkVerified,
                Now = validationTime,
                ClockSkew = clockSkew,
            };

            ClaimIssueResult result = await TrustChainValidator.Default()
                .ValidateAsync(context, "inline-trust-chain-validation", cancellationToken)
                .ConfigureAwait(false);

            foreach(Claim claim in result.Claims)
            {
                if(claim.Outcome is not (ClaimOutcome.Success or ClaimOutcome.NotApplicable))
                {
                    return TrustChainValidationOutcome.Rejected(
                        $"Chain validation produced non-success claim {claim.Id} ({claim.Outcome}).");
                }
            }

            return TrustChainValidationOutcome.Validated(chain, result);
        };
    }
}
