using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.JCose;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Library-shipped contributor for the OIDC Core §2 / §5.3 <c>sub</c>
/// claim. Pattern-matches on <see cref="IdTokenTarget"/> and
/// <see cref="UserInfoTarget"/>; invokes
/// <see cref="AuthorizationServerIntegration.ResolveSubjectIdentifierAsync"/>
/// to translate the end-user identifier into the subject identifier the
/// server emits on the wire.
/// </summary>
/// <remarks>
/// <para>
/// The library default
/// (<see cref="Server.Pipeline.DefaultSubjectIdentifierResolver.PublicAsync"/>)
/// returns the end-user identifier unchanged — the
/// <c>subject_type=public</c> behaviour per OIDC Core §8.1. Pairwise
/// deployments wire a delegate that computes a per-sector hash
/// (typically <c>SHA-256(sector_identifier_uri ‖ sub ‖ salt)</c>) so a
/// single end-user appears under different identifiers to different
/// relying parties.
/// </para>
/// <para>
/// Other targets (<see cref="AccessTokenTarget"/>,
/// <see cref="IntrospectionTarget"/>) return
/// <see cref="ClaimOutcome.NotApplicable"/>: access tokens emit the raw
/// end-user identifier on <see cref="IssuanceContext.Subject"/> via the
/// RFC 9068 producer's own composition, and introspection responses
/// echo the presented token's <c>sub</c> verbatim per RFC 7662.
/// </para>
/// </remarks>
[DebuggerDisplay("SubjectIdentifierContributor")]
public static class SubjectIdentifierContributor
{
    /// <summary>
    /// Emits the <c>sub</c> claim by invoking
    /// <see cref="AuthorizationServerIntegration.ResolveSubjectIdentifierAsync"/>
    /// for the target's end-user identifier.
    /// </summary>
    public static async ValueTask<List<Claim>> GenerateSubjectClaim(
        ClaimContributionTarget target,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        if(!TryExtractContext(target, out SubjectContext? ctx))
        {
            return [new Claim(WellKnownClaimIds.SubjectIdentifier, ClaimOutcome.NotApplicable)];
        }

        AuthorizationServer? server = ctx.ExchangeContext.Server;
        ResolveSubjectIdentifierDelegate? resolve = server?.Integration.ResolveSubjectIdentifierAsync;
        if(resolve is null)
        {
            return [new Claim(WellKnownClaimIds.SubjectIdentifier, ClaimOutcome.NotApplicable)];
        }

        string resolvedSubject = await resolve(
            ctx.EndUserId, ctx.Registration, ctx.ExchangeContext, cancellationToken)
            .ConfigureAwait(false);

        return
        [
            new Claim(
                WellKnownClaimIds.SubjectIdentifier,
                ClaimOutcome.Success,
                new ClaimContributionContext(WellKnownJwtClaimNames.Sub, resolvedSubject),
                Claim.NoSubClaims)
        ];
    }


    private sealed record SubjectContext(
        ClientRecord Registration,
        string EndUserId,
        ExchangeContext ExchangeContext);


    private static bool TryExtractContext(
        ClaimContributionTarget target,
        [NotNullWhen(true)] out SubjectContext? context)
    {
        switch(target)
        {
            case IdTokenTarget idt:
                context = new SubjectContext(
                    idt.Issuance.Registration,
                    idt.Issuance.Subject,
                    idt.Issuance.Context);
                return true;

            case UserInfoTarget uit:
                context = new SubjectContext(
                    uit.Registration,
                    uit.Subject,
                    uit.Context);
                return true;

            default:
                context = null;
                return false;
        }
    }
}
