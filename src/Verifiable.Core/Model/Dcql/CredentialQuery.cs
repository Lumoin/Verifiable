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

    /// <summary>
    /// Whether the Verifier accepts more than one matching credential to be
    /// presented for this query per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">OID4VP 1.0 §6.1</see>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Wire-omitted (<see langword="null"/>) means the spec default applies:
    /// at most one credential per query. The default lives at the processing
    /// layer rather than this type, so absence on the wire round-trips to
    /// <see langword="null"/> here. Application code that needs the spec-
    /// default value should treat <see langword="null"/> as <c>false</c>.
    /// </para>
    /// </remarks>
    public bool? Multiple { get; set; }

    /// <summary>
    /// Whether the Verifier requires the Wallet to demonstrate cryptographic
    /// holder binding (Key Binding JWT or equivalent) for the presented
    /// credential per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.3">OID4VP 1.0 §6.3</see>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Wire-omitted (<see langword="null"/>) means the spec default applies:
    /// the Verifier requires cryptographic holder binding. The default lives
    /// at the processing layer rather than this type, so absence on the wire
    /// round-trips to <see langword="null"/> here. Application code that
    /// needs the spec-default value should treat <see langword="null"/> as
    /// <c>true</c>.
    /// </para>
    /// </remarks>
    public bool? RequireCryptographicHolderBinding { get; set; }
}
