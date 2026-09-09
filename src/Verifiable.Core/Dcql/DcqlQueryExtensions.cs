using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography.Pki;

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
        /// Validates the query structure and returns any issues found: a missing or
        /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
        /// OID4VP 1.0 §6.1</see>-invalid credential query <c>id</c>, a repeated <c>id</c>, and a
        /// <c>dc+sd-jwt</c> credential query whose <c>meta.vct_values</c> is absent or empty
        /// (OpenID4VP 1.0 Appendix B.3.5 makes it REQUIRED).
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

            //Check for a §6.1-invalid or duplicate id. The position is named because an id that is
            //absent or empty renders as nothing at all, leaving the operator no way to tell which
            //entry of credentials the issue is about.
            var seenIds = new HashSet<string>();
            for(int credentialPosition = 0; credentialPosition < query.Credentials.Count; credentialPosition++)
            {
                var credential = query.Credentials[credentialPosition];

                if(!CredentialQueryId.TryCreate(credential.Id, out _))
                {
                    issues.Add(
                        $"Credential query at position {credentialPosition} carries no usable ID. Per " +
                        "OID4VP 1.0 §6.1 the ID is required and MUST be a " +
                        "non-empty string consisting of alphanumeric, underscore (_), or hyphen (-) " +
                        $"characters: '{credential.Id}'.");
                }
                else if(!seenIds.Add(credential.Id!))
                {
                    issues.Add(
                        $"Duplicate credential query ID: {credential.Id}. Per OID4VP 1.0 §6.1, " +
                        "\"Within the Authorization Request, the same id MUST NOT be present more than once\".");
                }

                if(string.IsNullOrEmpty(credential.Format))
                {
                    issues.Add($"Credential query '{credential.Id}' is missing required format.");
                }

                if(string.Equals(credential.Format, DcqlCredentialFormats.SdJwt, StringComparison.Ordinal)
                    && credential.Meta?.VctValues is not { Count: > 0 })
                {
                    issues.Add($"Credential query '{credential.Id}' uses format '{DcqlCredentialFormats.SdJwt}' but does not specify a non-empty meta.{DcqlParameterNames.VctValues}, required by OpenID4VP 1.0 Appendix B.3.5.");
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
    /// Extensions for <see cref="TrustedAuthoritiesQuery"/> providing evidence matching per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>.
    /// </summary>
    extension(TrustedAuthoritiesQuery authorities)
    {
        /// <summary>
        /// Determines whether <paramref name="evidence"/> matches this entry, per
        /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
        /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: "A Credential is identified
        /// as a match to a Trusted Authorities Query if it matches with one of the provided values in
        /// one of the provided types." Dispatch is on <see cref="TrustedAuthoritiesQuery.Type"/>
        /// through <see cref="DcqlTrustedAuthorityTypes"/>; a value that does not parse into the
        /// type's identifier shape matches nothing rather than throwing, and an entry whose
        /// <see cref="TrustedAuthoritiesQuery.Type"/> is none of the three registered values matches
        /// nothing (fail-closed, per Section 6.4.2's MUST NOT).
        /// </summary>
        /// <param name="evidence">The credential's trust evidence.</param>
        /// <returns><see langword="true"/> when any of <see cref="TrustedAuthoritiesQuery.Values"/> matches under this entry's type; otherwise <see langword="false"/>.</returns>
        public bool Matches(TrustedAuthorityEvidence evidence)
        {
            ArgumentNullException.ThrowIfNull(evidence);

            return authorities.Type switch
            {
                var type when DcqlTrustedAuthorityTypes.IsAki(type) =>
                    MatchesAnyValue(authorities.Values, evidence.AuthorityKeyIdentifiers, AuthorityKeyIdentifier.TryParse),
                var type when DcqlTrustedAuthorityTypes.IsEtsiTrustedList(type) =>
                    MatchesAnyValue(authorities.Values, evidence.TrustedListMemberships, TrustedListIdentifier.TryCreate),
                var type when DcqlTrustedAuthorityTypes.IsOpenIdFederation(type) =>
                    MatchesAnyValue(authorities.Values, evidence.FederationTrustPathEntities, EntityIdentifier.TryCreate),
                _ => false
            };
        }
    }


    /// <summary>Parses a candidate string into an identifier of type <typeparamref name="T"/>, failing closed rather than throwing.</summary>
    /// <typeparam name="T">The identifier type.</typeparam>
    /// <param name="value">The candidate string.</param>
    /// <param name="identifier">The parsed identifier when parsing succeeds; <see langword="default"/> otherwise.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> parses; otherwise <see langword="false"/>.</returns>
    private delegate bool TryParseIdentifier<T>(string? value, out T identifier);


    /// <summary>
    /// Reports whether any of <paramref name="values"/> parses into an identifier contained in
    /// <paramref name="evidenceSet"/>. A value that does not parse contributes no match; it is never
    /// an error, since a DCQL <c>trusted_authorities</c> value that another Wallet's evidence would
    /// have parsed simply cannot be tested against this credential's evidence.
    /// </summary>
    /// <typeparam name="T">The identifier type the evidence set carries.</typeparam>
    /// <param name="values">The query entry's candidate values.</param>
    /// <param name="evidenceSet">The credential's evidence set of the matching identifier type.</param>
    /// <param name="tryParse">Parses one candidate value into the identifier type.</param>
    /// <returns><see langword="true"/> when any value parses and is contained in <paramref name="evidenceSet"/>; otherwise <see langword="false"/>.</returns>
    private static bool MatchesAnyValue<T>(IReadOnlyList<string> values, IReadOnlySet<T> evidenceSet, TryParseIdentifier<T> tryParse)
    {
        foreach(string value in values)
        {
            if(tryParse(value, out T identifier) && evidenceSet.Contains(identifier))
            {
                return true;
            }
        }

        return false;
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
