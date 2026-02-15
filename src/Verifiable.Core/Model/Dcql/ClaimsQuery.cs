using System.Collections.Generic;
using System.Diagnostics;


namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// Represents a single claim requirement within a credential query.
/// </summary>
/// <remarks>
/// <para>
/// Each claims query identifies a specific claim within a credential by its
/// <see cref="Path"/> (a <see cref="DcqlClaimPattern"/>). The claim can be
/// marked as <see cref="Required"/> (default <see langword="true"/>) and
/// optionally constrained to specific <see cref="Values"/>.
/// </para>
/// <para>
/// The <see cref="Id"/> is used to reference this claim in <see cref="ClaimSetQuery"/>
/// options. When not explicitly set, the string representation of the <see cref="Path"/>
/// serves as the effective identifier.
/// </para>
/// </remarks>
[DebuggerDisplay("Claim(Path={Path}, Required={Required})")]
public record ClaimsQuery
{
    /// <summary>
    /// The JSON property name for <see cref="Id"/>.
    /// </summary>
    public const string IdPropertyName = "id";

    /// <summary>
    /// The JSON property name for <see cref="Path"/>.
    /// </summary>
    public const string PathPropertyName = "path";

    /// <summary>
    /// The JSON property name for <see cref="Values"/>.
    /// </summary>
    public const string ValuesPropertyName = "values";

    /// <summary>
    /// The JSON property name for <see cref="IntentToRetain"/>.
    /// </summary>
    public const string IntentToRetainPropertyName = "intent_to_retain";

    /// <summary>
    /// Optional identifier for referencing in claim sets. Defaults to the path string.
    /// </summary>
    public string? Id { get; init; }

    /// <summary>
    /// The claim path pattern identifying the claim within the credential.
    /// </summary>
    public DcqlClaimPattern? Path { get; set; }

    /// <summary>
    /// Whether this claim is required for the credential to match. Defaults to <see langword="true"/>.
    /// </summary>
    public bool Required { get; init; } = true;

    /// <summary>
    /// Optional set of acceptable values for the claim. When non-null, the claim value
    /// must match one of these values for the credential to be considered a match.
    /// </summary>
    public IReadOnlyList<object>? Values { get; set; }

    /// <summary>
    /// Indicates whether the verifier intends to retain the disclosed claim value
    /// after the transaction completes.
    /// </summary>
    /// <remarks>
    /// Defined in Annex B.3.1 of the OpenID4VP specification for the <c>mso_mdoc</c>
    /// credential format, aligning with the ISO/IEC 18013-5 IntentToRetain element.
    /// Wallets may display this to help the user make an informed consent decision.
    /// </remarks>
    public bool? IntentToRetain { get; set; }

    /// <summary>
    /// The effective identifier for this claim query.
    /// </summary>
    /// <remarks>
    /// Returns <see cref="Id"/> when explicitly set, otherwise the string representation
    /// of <see cref="Path"/>. Used by claim sets to reference specific claims.
    /// </remarks>
    public string EffectiveId => Id ?? Path?.ToString() ?? string.Empty;
}