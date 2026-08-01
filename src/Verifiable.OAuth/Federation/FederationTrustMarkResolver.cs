using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Composes the OpenID Federation 1.0 §7 trust-mark verification pipeline end-to-end — the trust-mark analogue
/// of <see cref="FederationEffectiveMetadataResolver"/>. For each candidate mark it runs, in order:
/// issuer-signature verification (the issuer key resolved across the chain via
/// <see cref="FederationKeyResolver.ResolveInChainKeyAsync"/>), §7.3 shape validation
/// (<see cref="TrustMarkValidator"/>), §6.2 direct issuer authorization
/// (<see cref="TrustMarkIssuerAuthorizationEvaluator"/>), and §7.2.2 delegation validation
/// (<see cref="TrustMarkDelegationEvaluator"/>), then combines them into an admit/reject
/// <see cref="TrustMarkVerdict"/>.
/// </summary>
/// <remarks>
/// <para>
/// Combine rule: a mark is admitted when its shape checks all pass AND it is authorized either directly (§6.2)
/// OR by a valid delegation (§7.2.2) — either successful authorization path suffices, as documented on
/// <see cref="TrustMarkIssuerAuthorizationEvaluator"/>.
/// </para>
/// <para>
/// Parsing is the caller's concern (the subject's <c>trust_marks</c> entries become
/// <see cref="TrustMarkCandidate"/> values via <see cref="TrustMarkParser"/> /
/// <see cref="TrustMarkDelegationParser"/>); the signature primitive is the app's
/// (<see cref="VerifyCompactJwsDelegate"/> wraps <c>Jws.VerifyAsync</c>). The resolver owns only the
/// verification orchestration, mirroring how the rest of the federation namespace separates parse,
/// key-resolution, and the cryptographic primitive.
/// </para>
/// </remarks>
[DebuggerDisplay("FederationTrustMarkResolver")]
public static class FederationTrustMarkResolver
{
    /// <summary>
    /// Verifies each candidate mark against <paramref name="chain"/> and returns one
    /// <see cref="TrustMarkVerdict"/> per candidate, in input order.
    /// </summary>
    /// <param name="chain">
    /// The resolved trust chain. Its Trust Anchor carries the <c>trust_mark_issuers</c> / <c>trust_mark_owners</c>
    /// claims; its statements carry the issuer and owner verification keys.
    /// </param>
    /// <param name="candidates">The parsed candidate marks to verify.</param>
    /// <param name="verifySignature">The app's compact-JWS signature primitive (wraps <c>Jws.VerifyAsync</c>).</param>
    /// <param name="base64UrlDecoder">Base64url decoder used when reconstructing chain keys.</param>
    /// <param name="memoryPool">Pool the resolved key material rents from.</param>
    /// <param name="timeProvider">Time source for the §7.3 exp/iat checks and result stamping; <see langword="null"/> uses system time.</param>
    /// <param name="clockSkew">Tolerance for the exp/iat checks.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>One verdict per candidate, in input order.</returns>
    public static async ValueTask<IReadOnlyList<TrustMarkVerdict>> ResolveVerifiedAsync(
        TrustChain chain,
        IReadOnlyList<TrustMarkCandidate> candidates,
        VerifyCompactJwsDelegate verifySignature,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool memoryPool,
        TimeProvider? timeProvider,
        TimeSpan clockSkew,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(candidates);
        ArgumentNullException.ThrowIfNull(verifySignature);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        TimeProvider time = timeProvider ?? TimeProvider.System;
        DateTimeOffset now = time.GetUtcNow();
        TrustMarkValidator validator = TrustMarkValidator.Default(time);

        var verdicts = new List<TrustMarkVerdict>(candidates.Count);
        foreach(TrustMarkCandidate candidate in candidates)
        {
            verdicts.Add(await VerifyOneAsync(
                chain, candidate, validator, verifySignature, base64UrlDecoder, memoryPool, now, clockSkew, cancellationToken)
                .ConfigureAwait(false));
        }

        return verdicts;
    }


    /// <summary>Runs the full pipeline for one candidate and combines the stages into a verdict.</summary>
    private static async ValueTask<TrustMarkVerdict> VerifyOneAsync(
        TrustChain chain,
        TrustMarkCandidate candidate,
        TrustMarkValidator validator,
        VerifyCompactJwsDelegate verifySignature,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool memoryPool,
        DateTimeOffset now,
        TimeSpan clockSkew,
        CancellationToken cancellationToken)
    {
        TrustMark mark = candidate.Mark;

        //Issuer-signature: resolve the issuer's key across the chain, then verify the mark JWS against it.
        bool signatureVerified = await VerifyJwsAsync(
            chain, mark.Issuer.Value, ReadKid(candidate.Header), candidate.CompactJws,
            verifySignature, base64UrlDecoder, memoryPool, cancellationToken).ConfigureAwait(false);

        //§7.3 shape — the signature outcome is one of its claims.
        TrustMarkValidationContext shapeContext = new()
        {
            Header = candidate.Header,
            Mark = mark,
            SignatureVerified = signatureVerified,
            Now = now,
            ClockSkew = clockSkew,
        };
        ClaimIssueResult shape = await validator.ValidateAsync(
            shapeContext, CorrelationId(mark), cancellationToken).ConfigureAwait(false);
        bool shapeOk = ShapeSatisfied(shape);

        //§6.2 direct issuer authorization.
        Claim issuerAuthorization = TrustMarkIssuerAuthorizationEvaluator.Evaluate(mark, chain);

        //§7.2.2 delegation, when the mark carries one.
        Claim delegation = await EvaluateDelegationAsync(
            chain, candidate, verifySignature, base64UrlDecoder, memoryPool, now, clockSkew, cancellationToken)
            .ConfigureAwait(false);

        //Combine: shape must pass AND the mark must be authorized directly OR by a valid delegation.
        bool authorized = issuerAuthorization.Outcome == ClaimOutcome.Success
            || delegation.Outcome == ClaimOutcome.Success;

        return new TrustMarkVerdict
        {
            Mark = mark,
            Admitted = shapeOk && authorized,
            SignatureVerified = signatureVerified,
            Shape = shape,
            IssuerAuthorization = issuerAuthorization,
            Delegation = delegation,
        };
    }


    /// <summary>
    /// Evaluates the §7.2.2 delegation pathway for a candidate, or returns the not-applicable claim when the
    /// mark carries no delegation.
    /// </summary>
    private static async ValueTask<Claim> EvaluateDelegationAsync(
        TrustChain chain,
        TrustMarkCandidate candidate,
        VerifyCompactJwsDelegate verifySignature,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool memoryPool,
        DateTimeOffset now,
        TimeSpan clockSkew,
        CancellationToken cancellationToken)
    {
        if(candidate.Delegation is not { } delegationCandidate)
        {
            return TrustMarkDelegationEvaluator.NotApplicable();
        }

        bool delegationSignatureVerified = await VerifyJwsAsync(
            chain, delegationCandidate.Delegation.Owner.Value, ReadKid(delegationCandidate.Header),
            delegationCandidate.CompactJws, verifySignature, base64UrlDecoder, memoryPool, cancellationToken)
            .ConfigureAwait(false);

        return TrustMarkDelegationEvaluator.Evaluate(
            candidate.Mark, delegationCandidate.Delegation, chain, delegationSignatureVerified, now, clockSkew);
    }


    /// <summary>
    /// Resolves <paramref name="issuerEntityId"/>'s key from the chain and verifies <paramref name="compactJws"/>
    /// against it. Returns <see langword="false"/> when no key resolves (an unverifiable signer).
    /// </summary>
    private static async ValueTask<bool> VerifyJwsAsync(
        TrustChain chain,
        string issuerEntityId,
        string? kid,
        string compactJws,
        VerifyCompactJwsDelegate verifySignature,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool memoryPool,
        CancellationToken cancellationToken)
    {
        using PublicKeyMemory? key = await FederationKeyResolver.ResolveInChainKeyAsync(
            chain, issuerEntityId, kid, base64UrlDecoder, memoryPool, cancellationToken).ConfigureAwait(false);

        if(key is null)
        {
            return false;
        }

        return await verifySignature(compactJws, key, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Whether no claim in <paramref name="shape"/> failed (success and not-applicable both pass).</summary>
    private static bool ShapeSatisfied(ClaimIssueResult shape)
    {
        foreach(Claim claim in shape.Claims)
        {
            if(claim.Outcome == ClaimOutcome.Failure)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>Reads the <c>kid</c> value from a JWS protected header, or <see langword="null"/> when absent.</summary>
    private static string? ReadKid(UnverifiedJwtHeader header)
    {
        if(header.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidObj) && kidObj is string kid)
        {
            return kid;
        }

        return null;
    }


    /// <summary>A deterministic, non-empty correlation id for a mark's shape-validation claim result.</summary>
    private static string CorrelationId(TrustMark mark) => $"{mark.Issuer.Value}|{mark.MarkId}";
}
