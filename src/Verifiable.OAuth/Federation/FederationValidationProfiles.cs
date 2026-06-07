using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Pre-built <see cref="ClaimDelegate{TInput}"/> lists for OpenID Federation
/// 1.0 validation points, composable via <see cref="ClaimIssuer{TInput}"/>.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors the
/// <see cref="Verifiable.OAuth.Validation.ValidationProfiles"/> precedent.
/// Each method returns a mutable <see cref="IList{T}"/> the application
/// can extend with deployment-specific rules before passing to a
/// <see cref="ClaimIssuer{TInput}"/>.
/// </para>
/// </remarks>
public static class FederationValidationProfiles
{
    /// <summary>
    /// Entity Statement validation rules per OpenID Federation 1.0 §3.2.
    /// Emits the claims with codes 1100-1109 against an
    /// <see cref="EntityStatementValidationContext"/>.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    public static IList<ClaimDelegate<EntityStatementValidationContext>> EntityStatementRules() =>
        new List<ClaimDelegate<EntityStatementValidationContext>>
        {
            new(FederationValidationChecks.CheckAlgPresent,
                [WellKnownFederationClaimIds.AlgPresent]),

            new(FederationValidationChecks.CheckTypMatchesEntityStatement,
                [WellKnownFederationClaimIds.TypMatchesEntityStatement]),

            new(FederationValidationChecks.CheckIssPresent,
                [WellKnownFederationClaimIds.IssPresent]),

            new(FederationValidationChecks.CheckSubPresent,
                [WellKnownFederationClaimIds.SubPresent]),

            new(FederationValidationChecks.CheckIatInRange,
                [WellKnownFederationClaimIds.IatInRange]),

            new(FederationValidationChecks.CheckExpInFuture,
                [WellKnownFederationClaimIds.ExpInFuture]),

            new(FederationValidationChecks.CheckExpAfterIat,
                [WellKnownFederationClaimIds.ExpAfterIat]),

            new(FederationValidationChecks.CheckSignatureVerifies,
                [WellKnownFederationClaimIds.SignatureVerifies]),

            new(FederationValidationChecks.CheckJwksPresentWhenSelfSigned,
                [WellKnownFederationClaimIds.JwksPresentWhenSelfSigned]),

            new(FederationValidationChecks.CheckJwksContainsNoPrivateOrSymmetricKeys,
                [WellKnownFederationClaimIds.JwksContainsNoPrivateOrSymmetricKeys]),

            new(FederationValidationChecks.CheckJwksKeyIdsDistinct,
                [WellKnownFederationClaimIds.JwksKeyIdsDistinct]),

            new(FederationValidationChecks.CheckJwksKeysMeetMinimumKeyLength,
                [WellKnownFederationClaimIds.JwksKeysMeetMinimumKeyLength]),

            new(FederationValidationChecks.CheckAuthorityHintsWellFormed,
                [WellKnownFederationClaimIds.AuthorityHintsWellFormed]),

            new(FederationValidationChecks.CheckMetadataWellFormed,
                [WellKnownFederationClaimIds.MetadataWellFormed]),
        };


    /// <summary>
    /// Trust mark validation rules covering the §7.3 mark-shape checks
    /// (signature, exp). Issuer-authorization (1171) and delegation-chain
    /// (1173) checks live on their own chain-aware evaluators and are not
    /// part of this list.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    public static IList<ClaimDelegate<TrustMarkValidationContext>> TrustMarkRules() =>
        new List<ClaimDelegate<TrustMarkValidationContext>>
        {
            new(FederationValidationChecks.CheckTrustMarkSignatureVerifies,
                [WellKnownFederationClaimIds.TrustMarkSignatureVerifies]),

            new(FederationValidationChecks.CheckTrustMarkExpInFuture,
                [WellKnownFederationClaimIds.TrustMarkExpInFuture]),

            new(FederationValidationChecks.CheckTrustMarkExpAfterIat,
                [WellKnownFederationClaimIds.TrustMarkExpAfterIat]),
        };


    /// <summary>
    /// Trust chain validation rules per OpenID Federation 1.0 §4.3 / §10
    /// (inline path). Emits the claims with codes 1120-1125 against a
    /// <see cref="TrustChainValidationContext"/>.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    public static IList<ClaimDelegate<TrustChainValidationContext>> TrustChainRules() =>
        new List<ClaimDelegate<TrustChainValidationContext>>
        {
            new(FederationValidationChecks.CheckChainStartsAtSubject,
                [WellKnownFederationClaimIds.ChainStartsAtSubject]),

            new(FederationValidationChecks.CheckChainTerminatesAtTrustAnchor,
                [WellKnownFederationClaimIds.ChainTerminatesAtTrustAnchor]),

            new(FederationValidationChecks.CheckChainNoCycles,
                [WellKnownFederationClaimIds.ChainNoCycles]),

            new(FederationValidationChecks.CheckChainWithinMaxPathLength,
                [WellKnownFederationClaimIds.ChainWithinMaxPathLength]),

            new(FederationValidationChecks.CheckChainAllLinksVerified,
                [WellKnownFederationClaimIds.ChainAllLinksVerified]),

            new(FederationValidationChecks.CheckChainExpIsMinOfLinks,
                [WellKnownFederationClaimIds.ChainExpIsMinOfLinks]),

            new(FederationValidationChecks.CheckChainSatisfiesNamingConstraints,
                [WellKnownFederationClaimIds.ChainSatisfiesNamingConstraints]),
        };
}
