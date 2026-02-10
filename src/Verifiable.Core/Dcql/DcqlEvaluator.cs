using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.Core.Dcql;

/// <summary>
/// Delegate for extracting claim values from credentials.
/// </summary>
/// <typeparam name="TCredential">The credential type.</typeparam>
/// <param name="credential">The credential to extract from.</param>
/// <param name="pattern">The claim path pattern to extract.</param>
/// <param name="value">The extracted value, if found.</param>
/// <returns><see langword="true"/> if the claim exists at the path; otherwise, <see langword="false"/>.</returns>
/// <remarks>
/// <para>
/// Implementations are format-specific. For SD-JWT, this navigates JSON structure
/// and handles disclosed claims. For mdoc, this accesses namespace/element pairs.
/// </para>
/// <para>
/// The value returned should be the native representation (string, number, boolean, etc.)
/// for comparison with <see cref="ClaimsQuery.Values"/> constraints.
/// </para>
/// </remarks>
public delegate bool DcqlClaimExtractor<TCredential>(
    TCredential credential,
    DcqlClaimPattern pattern,
    out object? value);

/// <summary>
/// Delegate for extracting credential metadata for coarse matching.
/// </summary>
/// <typeparam name="TCredential">The credential type.</typeparam>
/// <param name="credential">The credential to extract metadata from.</param>
/// <returns>The credential metadata.</returns>
public delegate DcqlCredentialMetadata DcqlMetadataExtractor<TCredential>(TCredential credential);

/// <summary>
/// Metadata about a credential for DCQL matching.
/// </summary>
[DebuggerDisplay("Format={Format} Type={CredentialType} Issuer={Issuer}")]
public record DcqlCredentialMetadata
{
    /// <summary>
    /// The credential format (e.g., "dc+sd-jwt", "mso_mdoc").
    /// </summary>
    public required string Format { get; init; }

    /// <summary>
    /// The credential type (vct for SD-JWT, doctype for mdoc).
    /// </summary>
    public string? CredentialType { get; init; }

    /// <summary>
    /// The issuer identifier.
    /// </summary>
    public string? Issuer { get; init; }

    /// <summary>
    /// All claim paths present in the credential as concrete <see cref="CredentialPath"/> values.
    /// </summary>
    /// <remarks>
    /// For selective disclosure credentials, this includes all paths
    /// that could potentially be disclosed, not just currently disclosed ones.
    /// </remarks>
    public IReadOnlySet<CredentialPath>? AvailablePaths { get; init; }
}

/// <summary>
/// Result of evaluating a credential against a DCQL credential query.
/// </summary>
/// <remarks>
/// <para>
/// The match carries both the DCQL claim patterns that matched and the resolved
/// concrete <see cref="CredentialPath"/> values for the disclosure computation.
/// </para>
/// </remarks>
/// <typeparam name="TCredential">The credential type.</typeparam>
[DebuggerDisplay("CredentialQueryId={CredentialQueryId} MatchedPatterns={MatchedPatterns.Count}")]
public record DcqlMatch<TCredential>
{
    /// <summary>
    /// The credential that matched.
    /// </summary>
    public required TCredential Credential { get; init; }

    /// <summary>
    /// The ID of the credential query that was matched.
    /// </summary>
    public required string CredentialQueryId { get; init; }

    /// <summary>
    /// The DCQL claim patterns that were successfully matched.
    /// </summary>
    public required IReadOnlySet<DcqlClaimPattern> MatchedPatterns { get; init; }

    /// <summary>
    /// The DCQL claim patterns that are required for disclosure.
    /// </summary>
    public required IReadOnlySet<DcqlClaimPattern> RequiredDisclosurePatterns { get; init; }
}

/// <summary>
/// Result of evaluating a credential against a single credential query.
/// </summary>
[DebuggerDisplay("Matches={Matches} CredentialQueryId={CredentialQueryId} FailureReason={FailureReason}")]
public record DcqlEvaluationResult
{
    /// <summary>
    /// Whether the credential matches the query requirements.
    /// </summary>
    public required bool Matches { get; init; }

    /// <summary>
    /// The credential query ID.
    /// </summary>
    public required string CredentialQueryId { get; init; }

    /// <summary>
    /// Claim patterns that were found and matched.
    /// </summary>
    public IReadOnlySet<DcqlClaimPattern>? MatchedPatterns { get; init; }

    /// <summary>
    /// Required claim patterns that were missing from the credential.
    /// </summary>
    public IReadOnlyList<DcqlClaimPattern>? MissingRequiredPatterns { get; init; }

    /// <summary>
    /// Claim patterns where value constraints failed.
    /// </summary>
    public IReadOnlyList<DcqlClaimPattern>? FailedValueConstraints { get; init; }

    /// <summary>
    /// Reason for non-match, if applicable.
    /// </summary>
    public string? FailureReason { get; init; }
}

/// <summary>
/// Evaluates credentials against DCQL queries.
/// </summary>
public static class DcqlEvaluator
{
    /// <summary>
    /// Evaluates credentials against a prepared DCQL query.
    /// </summary>
    /// <typeparam name="TCredential">The credential type.</typeparam>
    /// <param name="preparedQuery">The prepared DCQL query.</param>
    /// <param name="credentials">The credentials to evaluate.</param>
    /// <param name="metadataExtractor">Extracts credential metadata for coarse matching.</param>
    /// <param name="claimExtractor">Extracts claim values for fine matching.</param>
    /// <returns>Matches for credentials that satisfy credential queries.</returns>
    public static IEnumerable<DcqlMatch<TCredential>> Evaluate<TCredential>(
        PreparedDcqlQuery preparedQuery,
        IEnumerable<TCredential> credentials,
        DcqlMetadataExtractor<TCredential> metadataExtractor,
        DcqlClaimExtractor<TCredential> claimExtractor)
    {
        ArgumentNullException.ThrowIfNull(preparedQuery);
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentNullException.ThrowIfNull(metadataExtractor);
        ArgumentNullException.ThrowIfNull(claimExtractor);

        if(preparedQuery.Query.Credentials is null)
        {
            yield break;
        }

        foreach(var credential in credentials)
        {
            var metadata = metadataExtractor(credential);

            foreach(var credentialQuery in preparedQuery.Query.Credentials)
            {
                var result = EvaluateSingle(credentialQuery, credential, metadata, claimExtractor);

                if(result.Matches)
                {
                    yield return new DcqlMatch<TCredential>
                    {
                        Credential = credential,
                        CredentialQueryId = credentialQuery.Id ?? string.Empty,
                        MatchedPatterns = result.MatchedPatterns ?? new HashSet<DcqlClaimPattern>(),
                        RequiredDisclosurePatterns = CollectRequiredPatterns(credentialQuery)
                    };
                }
            }
        }
    }

    /// <summary>
    /// Evaluates a single credential against a single credential query.
    /// </summary>
    /// <typeparam name="TCredential">The credential type.</typeparam>
    /// <param name="credentialQuery">The credential query.</param>
    /// <param name="credential">The credential to evaluate.</param>
    /// <param name="metadata">The credential metadata.</param>
    /// <param name="claimExtractor">Extracts claim values for matching.</param>
    /// <returns>The evaluation result.</returns>
    public static DcqlEvaluationResult EvaluateSingle<TCredential>(
        CredentialQuery credentialQuery,
        TCredential credential,
        DcqlCredentialMetadata metadata,
        DcqlClaimExtractor<TCredential> claimExtractor)
    {
        ArgumentNullException.ThrowIfNull(credentialQuery);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(claimExtractor);

        //Check format match.
        if(!string.Equals(credentialQuery.Format, metadata.Format, StringComparison.Ordinal))
        {
            return new DcqlEvaluationResult
            {
                Matches = false,
                CredentialQueryId = credentialQuery.Id ?? string.Empty,
                FailureReason = $"Format mismatch: expected '{credentialQuery.Format}', got '{metadata.Format}'."
            };
        }

        //Check type constraint.
        if(credentialQuery.Meta?.HasTypeConstraints == true && credentialQuery.Format is not null)
        {
            var typeConstraints = credentialQuery.Meta.GetTypeConstraints(credentialQuery.Format);
            if(typeConstraints is not null && metadata.CredentialType is not null)
            {
                bool typeMatches = false;
                foreach(var constraint in typeConstraints)
                {
                    if(string.Equals(constraint, metadata.CredentialType, StringComparison.Ordinal))
                    {
                        typeMatches = true;
                        break;
                    }
                }

                if(!typeMatches)
                {
                    return new DcqlEvaluationResult
                    {
                        Matches = false,
                        CredentialQueryId = credentialQuery.Id ?? string.Empty,
                        FailureReason = $"Credential type '{metadata.CredentialType}' not in accepted types."
                    };
                }
            }
        }

        //Check trusted authorities.
        if(credentialQuery.TrustedAuthorities is { Count: > 0 } && metadata.Issuer is not null)
        {
            bool issuerTrusted = false;
            foreach(var authority in credentialQuery.TrustedAuthorities)
            {
                if(authority.IsTrusted(metadata.Issuer))
                {
                    issuerTrusted = true;
                    break;
                }
            }

            if(!issuerTrusted)
            {
                return new DcqlEvaluationResult
                {
                    Matches = false,
                    CredentialQueryId = credentialQuery.Id ?? string.Empty,
                    FailureReason = $"Issuer '{metadata.Issuer}' not in trusted authorities."
                };
            }
        }

        //Check claims.
        if(credentialQuery.Claims is null or { Count: 0 })
        {
            //No claim requirements, format/type match is sufficient.
            return new DcqlEvaluationResult
            {
                Matches = true,
                CredentialQueryId = credentialQuery.Id ?? string.Empty,
                MatchedPatterns = new HashSet<DcqlClaimPattern>()
            };
        }

        var matchedPatterns = new HashSet<DcqlClaimPattern>();
        var missingRequired = new List<DcqlClaimPattern>();
        var failedValueConstraints = new List<DcqlClaimPattern>();

        //When claim_sets is present, individual Required flags are ignored.
        bool hasClaimSets = credentialQuery.ClaimSets is { Count: > 0 };

        foreach(var claimQuery in credentialQuery.Claims)
        {
            if(claimQuery.Path is null)
            {
                continue;
            }

            bool claimExists = claimExtractor(credential, claimQuery.Path, out var value);

            if(!claimExists)
            {
                if(claimQuery.Required && !hasClaimSets)
                {
                    missingRequired.Add(claimQuery.Path);
                }

                continue;
            }

            //Check value constraint if specified.
            if(claimQuery.Values is { Count: > 0 })
            {
                bool valueMatches = false;
                foreach(var acceptableValue in claimQuery.Values)
                {
                    if(ValuesMatch(value, acceptableValue))
                    {
                        valueMatches = true;
                        break;
                    }
                }

                if(!valueMatches)
                {
                    if(claimQuery.Required && !hasClaimSets)
                    {
                        failedValueConstraints.Add(claimQuery.Path);
                    }

                    continue;
                }
            }

            matchedPatterns.Add(claimQuery.Path);
        }

        if(missingRequired.Count > 0 || failedValueConstraints.Count > 0)
        {
            return new DcqlEvaluationResult
            {
                Matches = false,
                CredentialQueryId = credentialQuery.Id ?? string.Empty,
                MatchedPatterns = matchedPatterns,
                MissingRequiredPatterns = missingRequired.Count > 0 ? missingRequired : null,
                FailedValueConstraints = failedValueConstraints.Count > 0 ? failedValueConstraints : null,
                FailureReason = missingRequired.Count > 0
                    ? $"Missing required claims: {string.Join(", ", missingRequired)}"
                    : $"Value constraints failed: {string.Join(", ", failedValueConstraints)}"
            };
        }

        //Check claim sets if specified.
        if(hasClaimSets)
        {
            var availableClaimIds = new HashSet<string>();
            foreach(var claimQuery in credentialQuery.Claims)
            {
                if(claimQuery.Path is not null && matchedPatterns.Contains(claimQuery.Path))
                {
                    availableClaimIds.Add(claimQuery.EffectiveId);
                }
            }

            foreach(var claimSet in credentialQuery.ClaimSets!)
            {
                if(claimSet.Required && !claimSet.IsSatisfiedBy(availableClaimIds))
                {
                    return new DcqlEvaluationResult
                    {
                        Matches = false,
                        CredentialQueryId = credentialQuery.Id ?? string.Empty,
                        MatchedPatterns = matchedPatterns,
                        FailureReason = "Required claim set not satisfied."
                    };
                }
            }
        }

        return new DcqlEvaluationResult
        {
            Matches = true,
            CredentialQueryId = credentialQuery.Id ?? string.Empty,
            MatchedPatterns = matchedPatterns
        };
    }


    private static HashSet<DcqlClaimPattern> CollectRequiredPatterns(CredentialQuery credentialQuery)
    {
        var result = new HashSet<DcqlClaimPattern>();
        foreach(var pattern in credentialQuery.RequiredPatterns())
        {
            result.Add(pattern);
        }

        return result;
    }


    private static bool ValuesMatch(object? actual, object? expected)
    {
        if(actual is null && expected is null)
        {
            return true;
        }

        if(actual is null || expected is null)
        {
            return false;
        }

        //String comparison.
        if(actual is string actualStr && expected is string expectedStr)
        {
            return string.Equals(actualStr, expectedStr, StringComparison.Ordinal);
        }

        //Numeric comparison (handle different numeric types).
        if(IsNumeric(actual) && IsNumeric(expected))
        {
            return Convert.ToDouble(actual, CultureInfo.InvariantCulture)
                == Convert.ToDouble(expected, CultureInfo.InvariantCulture);
        }

        //Boolean comparison.
        if(actual is bool actualBool && expected is bool expectedBool)
        {
            return actualBool == expectedBool;
        }

        //Fall back to Equals.
        return actual.Equals(expected);
    }

    private static bool IsNumeric(object value)
    {
        return value is byte or sbyte or short or ushort or int or uint
            or long or ulong or float or double or decimal;
    }
}