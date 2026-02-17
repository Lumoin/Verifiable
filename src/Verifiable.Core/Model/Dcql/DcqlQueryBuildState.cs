using System;
using System.Collections.Generic;

namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// Represents the build state for constructing <see cref="DcqlQuery"/> instances.
/// This state is passed between transformation functions during the fold/aggregate
/// process and carries accumulated credential queries, credential set definitions,
/// and validation context.
/// </summary>
/// <remarks>
/// <para>
/// The build state accumulates credential queries and credential set entries as
/// transformations add them. At build completion, the builder validates referential
/// integrity: all credential IDs referenced in credential sets must exist in the
/// accumulated credential list.
/// </para>
/// <para>
/// Transformations can read the current state to make decisions based on what has
/// already been added (e.g., adding credential sets that reference previously added
/// credential IDs, or conditionally adding claims based on format).
/// </para>
/// </remarks>
public sealed class DcqlQueryBuildState
{
    /// <summary>
    /// Gets the accumulated credential queries.
    /// </summary>
    public List<CredentialQuery> Credentials { get; } = [];

    /// <summary>
    /// Gets the accumulated credential set entries.
    /// </summary>
    public List<CredentialSetQuery> CredentialSets { get; } = [];

    /// <summary>
    /// Gets the set of credential IDs that have been added so far.
    /// Used for referential integrity validation.
    /// </summary>
    public HashSet<string> KnownCredentialIds { get; } = [];

    /// <summary>
    /// Registers a credential query in the build state.
    /// </summary>
    /// <param name="credential">The credential query to register.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="credential"/> is null.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a credential with the same ID has already been registered.
    /// </exception>
    public void AddCredential(CredentialQuery credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(credential.Id);

        if(!KnownCredentialIds.Add(credential.Id))
        {
            throw new InvalidOperationException(
                $"A credential with ID '{credential.Id}' has already been added.");
        }

        Credentials.Add(credential);
    }

    /// <summary>
    /// Registers a credential set in the build state.
    /// </summary>
    /// <param name="credentialSet">The credential set to register.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="credentialSet"/> is null.
    /// </exception>
    public void AddCredentialSet(CredentialSetQuery credentialSet)
    {
        ArgumentNullException.ThrowIfNull(credentialSet);
        CredentialSets.Add(credentialSet);
    }

    /// <summary>
    /// Validates that all credential set references point to known credential IDs.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a credential set references an ID that does not exist
    /// in the accumulated credentials.
    /// </exception>
    public void ValidateReferentialIntegrity()
    {
        foreach(var set in CredentialSets)
        {
            foreach(var option in set.Options)
            {
                foreach(var id in option)
                {
                    if(!KnownCredentialIds.Contains(id))
                    {
                        throw new InvalidOperationException(
                            $"Credential set references unknown credential ID '{id}'. Known IDs: {string.Join(", ", KnownCredentialIds)}.");
                    }
                }
            }
        }
    }
}