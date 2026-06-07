using System.Buffers;
using Verifiable.Core.Assessment;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Federation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Test-side <see cref="ValidateTrustChainAsyncDelegate"/> implementation
/// that walks an inline trust chain using the production
/// <see cref="EntityStatementParser"/> + <see cref="TrustChainValidator"/>
/// primitives plus a caller-supplied per-link signature verifier.
/// </summary>
/// <remarks>
/// <para>
/// Parallel of <c>MicrosoftX509Functions</c> / <c>BouncyCastleX509Functions</c>
/// on the X.509 side: a concrete driver that an application can wire into
/// the federation key-resolution pipeline. Lives in the test project for
/// now per the project's "promote when stable" rhythm; suitable for
/// upstreaming into a library if real federation deployments emerge that
/// need it.
/// </para>
/// <para>
/// Per-link signature verification is plugged in via a delegate so the
/// driver composes against the existing test-side
/// <see cref="FederationTestRing"/> primitives. A production driver would
/// wire <c>Jws.VerifyAsync</c> with a real
/// <see cref="VerificationDelegate"/> dispatch.
/// </para>
/// </remarks>
internal static class InlineTrustChainValidationDriver
{
    /// <summary>
    /// Per-link signature verifier: given the compact JWS string and the
    /// public key from the issuer's jwks, return whether the signature
    /// verifies. Plugged in by the consumer (test fixture supplies one
    /// using <see cref="FederationTestRing.VerifyAsync"/>; production
    /// would compose against <c>Jws.VerifyAsync</c>).
    /// </summary>
    internal delegate ValueTask<bool> VerifyLinkSignatureAsyncDelegate(
        int chainPosition,
        string compactJws,
        CancellationToken cancellationToken);


    /// <summary>
    /// Builds a <see cref="ValidateTrustChainAsyncDelegate"/> that uses the
    /// supplied per-link verifier and runs the parsed chain through
    /// <see cref="TrustChainValidator.Default"/>.
    /// </summary>
    public static ValidateTrustChainAsyncDelegate Build(VerifyLinkSignatureAsyncDelegate verifyLink)
    {
        ArgumentNullException.ThrowIfNull(verifyLink);

        return async (compactJwsChain, trustAnchors, validationTime, clockSkew, pool, ct) =>
        {
            //Parse each statement.
            List<EntityStatement> parsedStatements = new(compactJwsChain.Count);
            for(int i = 0; i < compactJwsChain.Count; i++)
            {
                string[] parts = compactJwsChain[i].Split('.');
                if(parts.Length != 3)
                {
                    return TrustChainValidationOutcome.Rejected(
                        $"Chain entry at position {i} is not a 3-part compact JWS.");
                }

                Dictionary<string, object> headerDict;
                Dictionary<string, object> payloadDict;
                try
                {
                    using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(parts[0], pool);
                    using IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(parts[1], pool);
                    headerDict = JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                        headerBytes.Memory.Span, TestSetup.DefaultSerializationOptions)!;
                    payloadDict = JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                        payloadBytes.Memory.Span, TestSetup.DefaultSerializationOptions)!;
                }
                catch(Exception ex)
                {
                    return TrustChainValidationOutcome.Rejected(
                        $"Chain entry at position {i} could not be decoded: {ex.Message}");
                }

                UnverifiedJwtHeader header = new(headerDict);
                UnverifiedJwtPayload payload = new(payloadDict);
                EntityStatementParseResult parseResult = EntityStatementParser.Parse(header, payload);
                if(!parseResult.IsSuccess)
                {
                    return TrustChainValidationOutcome.Rejected(
                        $"Chain entry at position {i} did not parse as an Entity Statement: {parseResult.FailureReason}");
                }
                parsedStatements.Add(parseResult.Statement!);
            }

            //Per-link signature verification.
            bool[] linkVerified = new bool[parsedStatements.Count];
            for(int i = 0; i < parsedStatements.Count; i++)
            {
                linkVerified[i] = await verifyLink(i, compactJwsChain[i], ct).ConfigureAwait(false);
            }

            //Run TrustChainValidator.
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
                .ValidateAsync(context, "inline-trust-chain-validation", ct)
                .ConfigureAwait(false);

            foreach(Claim claim in result.Claims)
            {
                if(claim.Outcome != ClaimOutcome.Success)
                {
                    return TrustChainValidationOutcome.Rejected(
                        $"Chain validation produced non-Success claim {claim.Id} ({claim.Outcome}).");
                }
            }

            return TrustChainValidationOutcome.Validated(chain, result);
        };
    }
}
