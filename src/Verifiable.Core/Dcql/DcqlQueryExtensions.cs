using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.Core.Dcql;

/// <summary>
/// Extension methods for DCQL query model types.
/// </summary>
/// <remarks>
/// These methods provide query evaluation, validation, and inspection operations
/// over the pure data types in <see cref="Verifiable.Core.Model.Dcql"/>. Separating
/// behavior from data keeps the model types serialization-friendly and
/// allows different consumers to use different subsets of operations.
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer is not yet up to date with new extension syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "Analyzer is not yet up to date with new extension syntax.")]
public static class DcqlQueryExtensions
{
    /// <summary>
    /// Extensions for <see cref="DcqlQuery"/> providing query inspection and validation.
    /// </summary>
    extension(DcqlQuery query)
    {
        /// <summary>
        /// Gets a credential query by its ID.
        /// </summary>
        /// <param name="id">The credential query ID.</param>
        /// <returns>The credential query, or null if not found.</returns>
        public CredentialQuery? GetCredentialQuery(string id)
        {
            ArgumentNullException.ThrowIfNull(id);

            if(query.Credentials is null)
            {
                return null;
            }

            foreach(var credential in query.Credentials)
            {
                if(string.Equals(credential.Id, id, StringComparison.Ordinal))
                {
                    return credential;
                }
            }

            return null;
        }

        /// <summary>
        /// Gets all unique credential formats requested by this query.
        /// </summary>
        /// <returns>A set of credential format identifiers.</returns>
        public IReadOnlySet<string> GetRequestedFormats()
        {
            var formats = new HashSet<string>();
            if(query.Credentials is null)
            {
                return formats;
            }

            foreach(var credential in query.Credentials)
            {
                if(credential.Format is not null)
                {
                    formats.Add(credential.Format);
                }
            }

            return formats;
        }

        /// <summary>
        /// Gets all unique claim patterns requested across all credential queries.
        /// </summary>
        /// <returns>A set of all requested claim patterns.</returns>
        public IReadOnlySet<DcqlClaimPattern> GetAllRequestedPatterns()
        {
            var patterns = new HashSet<DcqlClaimPattern>();
            if(query.Credentials is null)
            {
                return patterns;
            }

            foreach(var credential in query.Credentials)
            {
                if(credential.Claims is null)
                {
                    continue;
                }

                foreach(var claim in credential.Claims)
                {
                    if(claim.Path is not null)
                    {
                        patterns.Add(claim.Path);
                    }
                }
            }

            return patterns;
        }

        /// <summary>
        /// Gets the credential query IDs that are referenced by credential sets
        /// but not defined in the credentials list.
        /// </summary>
        /// <returns>A set of undefined credential IDs, empty if all are valid.</returns>
        public IReadOnlySet<string> GetUndefinedCredentialReferences()
        {
            if(query.CredentialSets is null or { Count: 0 } || query.Credentials is null)
            {
                return new HashSet<string>();
            }

            var definedIds = new HashSet<string>();
            foreach(var credential in query.Credentials)
            {
                if(credential.Id is not null)
                {
                    definedIds.Add(credential.Id);
                }
            }

            var undefined = new HashSet<string>();
            foreach(var credentialSet in query.CredentialSets)
            {
                if(credentialSet.Options is null)
                {
                    continue;
                }

                foreach(var option in credentialSet.Options)
                {
                    foreach(var credentialId in option)
                    {
                        if(!definedIds.Contains(credentialId))
                        {
                            undefined.Add(credentialId);
                        }
                    }
                }
            }

            return undefined;
        }

        /// <summary>
        /// Validates the query structure and returns any issues found.
        /// </summary>
        /// <returns>A list of validation issues, empty if valid.</returns>
        public IReadOnlyList<string> Validate()
        {
            var issues = new List<string>();

            if(query.Credentials is null or { Count: 0 })
            {
                issues.Add("At least one credential query is required.");
                return issues;
            }

            //Check for duplicate IDs.
            var seenIds = new HashSet<string>();
            foreach(var credential in query.Credentials)
            {
                if(string.IsNullOrEmpty(credential.Id))
                {
                    issues.Add("Credential query ID is required.");
                }
                else if(!seenIds.Add(credential.Id))
                {
                    issues.Add($"Duplicate credential query ID: {credential.Id}");
                }

                if(string.IsNullOrEmpty(credential.Format))
                {
                    issues.Add($"Credential query '{credential.Id}' is missing required format.");
                }
            }

            //Check credential set references.
            var undefinedRefs = query.GetUndefinedCredentialReferences();
            foreach(var undefinedRef in undefinedRefs)
            {
                issues.Add($"Credential set references undefined credential ID: {undefinedRef}");
            }

            return issues;
        }
    }


    /// <summary>
    /// Extensions for <see cref="CredentialQuery"/> providing claim pattern inspection.
    /// </summary>
    extension(CredentialQuery credentialQuery)
    {
        /// <summary>
        /// Gets all required claim patterns for a credential query.
        /// </summary>
        /// <returns>Required claim patterns where <see cref="ClaimsQuery.Required"/> is <see langword="true"/>.</returns>
        public IEnumerable<DcqlClaimPattern> RequiredPatterns()
        {
            if(credentialQuery.Claims is null)
            {
                yield break;
            }

            foreach(var claim in credentialQuery.Claims)
            {
                if(claim.Required && claim.Path is not null)
                {
                    yield return claim.Path;
                }
            }
        }

        /// <summary>
        /// Gets all claim patterns for a credential query.
        /// </summary>
        /// <returns>All claim patterns regardless of required status.</returns>
        public IEnumerable<DcqlClaimPattern> AllPatterns()
        {
            if(credentialQuery.Claims is null)
            {
                yield break;
            }

            foreach(var claim in credentialQuery.Claims)
            {
                if(claim.Path is not null)
                {
                    yield return claim.Path;
                }
            }
        }
    }


    /// <summary>
    /// Extensions for <see cref="ClaimSetQuery"/> providing satisfaction checking.
    /// </summary>
    extension(ClaimSetQuery claimSet)
    {
        /// <summary>
        /// Determines whether a given set of available claim IDs satisfies any option in this claim set.
        /// </summary>
        /// <param name="availableClaimIds">The set of claim IDs available in a credential.</param>
        /// <returns><see langword="true"/> if at least one option is satisfied.</returns>
        public bool IsSatisfiedBy(IReadOnlySet<string> availableClaimIds)
        {
            ArgumentNullException.ThrowIfNull(availableClaimIds);

            if(claimSet.Options is null)
            {
                return false;
            }

            foreach(var option in claimSet.Options)
            {
                if(IsOptionSatisfied(option, availableClaimIds))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Returns the first option that is satisfied by the available claim IDs.
        /// </summary>
        /// <param name="availableClaimIds">The set of claim IDs available in a credential.</param>
        /// <returns>The first satisfying option, or null if none satisfy.</returns>
        public IReadOnlyList<string>? FirstSatisfyingOption(IReadOnlySet<string> availableClaimIds)
        {
            ArgumentNullException.ThrowIfNull(availableClaimIds);

            if(claimSet.Options is null)
            {
                return null;
            }

            foreach(var option in claimSet.Options)
            {
                if(IsOptionSatisfied(option, availableClaimIds))
                {
                    return option;
                }
            }

            return null;
        }
    }


    /// <summary>
    /// Extensions for <see cref="CredentialSetQuery"/> providing satisfaction checking
    /// and credential ID inspection.
    /// </summary>
    extension(CredentialSetQuery credentialSet)
    {
        /// <summary>
        /// Determines whether a given set of available credential IDs satisfies any option.
        /// </summary>
        /// <param name="availableCredentialIds">The set of credential IDs that can be satisfied.</param>
        /// <returns><see langword="true"/> if at least one option is satisfied.</returns>
        public bool IsSatisfiedBy(IReadOnlySet<string> availableCredentialIds)
        {
            ArgumentNullException.ThrowIfNull(availableCredentialIds);

            if(credentialSet.Options is null)
            {
                return false;
            }

            foreach(var option in credentialSet.Options)
            {
                if(IsOptionSatisfied(option, availableCredentialIds))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Gets all credential IDs referenced by any option in this query.
        /// </summary>
        /// <returns>A set of all referenced credential IDs.</returns>
        public IReadOnlySet<string> GetAllReferencedCredentialIds()
        {
            var ids = new HashSet<string>();
            if(credentialSet.Options is null)
            {
                return ids;
            }

            foreach(var option in credentialSet.Options)
            {
                foreach(var credentialId in option)
                {
                    ids.Add(credentialId);
                }
            }

            return ids;
        }
    }


    /// <summary>
    /// Extensions for <see cref="TrustedAuthoritiesQuery"/> providing trust checking.
    /// </summary>
    extension(TrustedAuthoritiesQuery authorities)
    {
        /// <summary>
        /// Determines whether the given authority identifier is trusted.
        /// </summary>
        /// <param name="authorityId">The authority identifier to check.</param>
        /// <returns><see langword="true"/> if the authority is in the trusted list.</returns>
        public bool IsTrusted(string authorityId)
        {
            ArgumentNullException.ThrowIfNull(authorityId);

            if(authorities.Values is null)
            {
                return false;
            }

            foreach(var value in authorities.Values)
            {
                if(string.Equals(value, authorityId, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>
    /// Checks whether all IDs in an option are present in the available set.
    /// </summary>
    private static bool IsOptionSatisfied(IReadOnlyList<string> option, IReadOnlySet<string> availableIds)
    {
        foreach(var requiredId in option)
        {
            if(!availableIds.Contains(requiredId))
            {
                return false;
            }
        }

        return true;
    }
}