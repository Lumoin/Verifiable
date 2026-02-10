using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Common;

namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// Builds <see cref="DcqlQuery"/> instances using the fold/aggregate pattern.
/// Transformation functions are registered via <see cref="Builder{TResult, TState, TBuilder}.With"/>
/// and applied sequentially during <see cref="BuildAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// The builder follows the same fold/aggregate pattern as <c>KeyDidBuilder</c> and
/// <c>CredentialBuilder</c>. Transformation functions are registered once and reused
/// across multiple <see cref="BuildAsync"/> invocations, enabling verifier services
/// to configure query patterns at startup and apply them per-request.
/// </para>
/// <para>
/// The <see cref="DcqlQueryBuildState"/> accumulates credential queries and credential
/// set entries as transformations add them. After all transformations have run,
/// <see cref="BuildAsync"/> validates referential integrity and assembles the
/// <see cref="DcqlQuery"/>.
/// </para>
/// <para>
/// Domain-specific construction methods are provided via extension methods in
/// <see cref="DcqlBuilderExtensions"/> using the modern C# <c>extension</c> syntax.
/// This keeps the builder focused on the fold mechanics while enabling composable,
/// named transformations.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Configure a reusable builder.
/// var builder = new DcqlQueryBuilder()
///     .WithSdJwtCredential("pid",
///         [new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(["given_name"]) },
///          new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(["family_name"]) }])
///     .WithSdJwtCredential("email",
///         [new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(["email"]) }])
///     .WithCredentialSet(true, [["pid"], ["email"]]);
///
/// // Reuse across requests.
/// var query1 = await builder.BuildAsync(ct);
/// var query2 = await builder.BuildAsync(ct);
/// </code>
/// </example>
public sealed class DcqlQueryBuilder: Builder<DcqlQuery, DcqlQueryBuildState, DcqlQueryBuilder>
{
    /// <summary>
    /// Builds the <see cref="DcqlQuery"/> by executing the fold/aggregate pipeline.
    /// Each invocation creates a fresh <see cref="DcqlQueryBuildState"/>, so the
    /// builder is safely reusable across multiple calls. After all registered
    /// transformations have run, validates referential integrity and assembles
    /// the final query from accumulated state.
    /// </summary>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
    /// <returns>A fully constructed and validated <see cref="DcqlQuery"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no credential queries have been added by the transformations,
    /// or when credential set references point to unknown credential IDs.
    /// </exception>
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Calls inherited instance method BuildAsync which accesses WithActions.")]
    public async ValueTask<DcqlQuery> BuildAsync(CancellationToken cancellationToken = default)
    {
        //Run all registered transformations to accumulate state.
        DcqlQueryBuildState? capturedState = null;

        await BuildAsync(
            seedGeneratorAsync: static (_, _) => ValueTask.FromResult(new DcqlQuery()),
            seedGeneratorParameter: (object?)null,
            preBuildActionAsync: (_, _, _) =>
            {
                capturedState = new DcqlQueryBuildState();
                return ValueTask.FromResult(capturedState);
            },
            cancellationToken: cancellationToken).ConfigureAwait(false);

        //Validate and assemble from accumulated state.
        if(capturedState is null || capturedState.Credentials.Count == 0)
        {
            throw new InvalidOperationException("At least one credential query is required.");
        }

        capturedState.ValidateReferentialIntegrity();

        return new DcqlQuery
        {
            Credentials = capturedState.Credentials.AsReadOnly(),
            CredentialSets = capturedState.CredentialSets.Count > 0
                ? capturedState.CredentialSets.AsReadOnly()
                : null
        };
    }
}