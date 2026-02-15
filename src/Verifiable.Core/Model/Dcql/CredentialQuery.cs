using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// Represents a single credential requirement within a DCQL query.
/// </summary>
/// <remarks>
/// <para>
/// Each credential query specifies:
/// <list type="bullet">
///   <item><description>A unique <see cref="Id"/> for referencing in credential sets.</description></item>
///   <item><description>A <see cref="Format"/> identifying the credential format (e.g., "dc+sd-jwt", "mso_mdoc").</description></item>
///   <item><description>Optional <see cref="Meta"/> with format-specific constraints.</description></item>
///   <item><description>Optional <see cref="Claims"/> specifying required or desired claim paths.</description></item>
///   <item><description>Optional <see cref="ClaimSets"/> grouping claims into alternative sets.</description></item>
/// </list>
/// </para>
/// </remarks>
[DebuggerDisplay("CredentialQuery(Id={Id}, Format={Format})")]
public record CredentialQuery
{
    /// <summary>
    /// The JSON property name for <see cref="Id"/>.
    /// </summary>
    public const string IdPropertyName = "id";

    /// <summary>
    /// The JSON property name for <see cref="Format"/>.
    /// </summary>
    public const string FormatPropertyName = "format";

    /// <summary>
    /// The JSON property name for <see cref="Meta"/>.
    /// </summary>
    public const string MetaPropertyName = "meta";

    /// <summary>
    /// The JSON property name for <see cref="Claims"/>.
    /// </summary>
    public const string ClaimsPropertyName = "claims";

    /// <summary>
    /// The JSON property name for <see cref="ClaimSets"/>.
    /// </summary>
    public const string ClaimSetsPropertyName = "claim_sets";

    /// <summary>
    /// The JSON property name for <see cref="TrustedAuthorities"/>.
    /// </summary>
    public const string TrustedAuthoritiesPropertyName = "trusted_authorities";

    /// <summary>
    /// Unique identifier for this credential query within the DCQL query.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// The credential format identifier (e.g., "dc+sd-jwt", "mso_mdoc", "jwt_vc_json").
    /// </summary>
    public string? Format { get; set; }

    /// <summary>
    /// Format-specific metadata constraints.
    /// </summary>
    public CredentialQueryMeta? Meta { get; set; }

    /// <summary>
    /// The individual claim requirements for this credential.
    /// </summary>
    public IReadOnlyList<ClaimsQuery>? Claims { get; set; }

    /// <summary>
    /// Optional claim set groupings expressing alternative claim combinations.
    /// </summary>
    public IReadOnlyList<ClaimSetQuery>? ClaimSets { get; set; }

    /// <summary>
    /// Optional trusted authorities constraints.
    /// </summary>
    public IReadOnlyList<TrustedAuthoritiesQuery>? TrustedAuthorities { get; set; }
}