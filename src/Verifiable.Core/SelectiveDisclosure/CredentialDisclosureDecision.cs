using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// A per-credential disclosure decision produced by <see cref="DisclosureComputation{TCredential}"/>.
/// </summary>
/// <remarks>
/// <para>
/// Each entry represents one credential and the paths selected for disclosure after
/// lattice computation and policy pipeline evaluation (Layers 3–4 of the DCQL Disclosure
/// Architecture). The application uses this to drive format-specific encoding (Layer 5):
/// </para>
/// <list type="bullet">
/// <item><description>
/// For SD-JWT: use <see cref="SdDisclosureSelection.SelectDisclosures"/> or
/// <c>SdJwtToken.SelectDisclosures</c> to filter disclosures to only those
/// whose paths are in <see cref="SelectedPaths"/>.
/// </description></item>
/// <item><description>
/// For ECDSA-SD-2023: construct a derived proof including only the N-Quad
/// statements whose indexes correspond to <see cref="SelectedPaths"/>.
/// </description></item>
/// <item><description>
/// For mso_mdoc: include only the namespace/element pairs matching
/// <see cref="SelectedPaths"/>.
/// </description></item>
/// </list>
/// <para>
/// <strong>Issuance direction:</strong> When used for issuance, the decision determines
/// which paths become mandatory (always visible in the token) versus selectively
/// disclosable (redacted with digests). The <see cref="SelectedPaths"/> represent the
/// mandatory set, and the complement within <see cref="Lattice"/> top becomes the set
/// for which <c>SdDisclosure</c> objects are created.
/// </para>
/// <para>
/// <strong>Partial satisfaction:</strong> When <see cref="SatisfiesRequirements"/> is
/// <see langword="false"/>, the application decides the next step — present anyway with
/// reduced disclosure, negotiate with the verifier (e.g., propose alternative claims),
/// prompt the user for conflict resolution, or decline the request entirely.
/// </para>
/// </remarks>
/// <typeparam name="TCredential">The application-specific credential type.</typeparam>
[DebuggerDisplay("Disclosure(QueryId={QueryRequirementId}, Selected={SelectedPaths.Count}, Satisfies={SatisfiesRequirements})")]
public sealed class CredentialDisclosureDecision<TCredential>
{
    /// <summary>
    /// The credential from which claims will be disclosed.
    /// </summary>
    public required TCredential Credential { get; init; }

    /// <summary>
    /// The query requirement ID this disclosure satisfies.
    /// </summary>
    public required string QueryRequirementId { get; init; }

    /// <summary>
    /// The credential paths selected for disclosure.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This set always includes mandatory paths (the lattice bottom) and the
    /// verifier-required paths that survived policy evaluation. It is the
    /// final, approved set of paths to disclose.
    /// </para>
    /// </remarks>
    public required IReadOnlySet<CredentialPath> SelectedPaths { get; init; }

    /// <summary>
    /// Whether all verifier requirements are satisfied by the selected paths.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is <see langword="false"/> when user exclusions or policy decisions
    /// conflict with verifier requirements. The application decides how to handle
    /// partial satisfaction — it may present anyway, negotiate, or decline.
    /// </para>
    /// </remarks>
    public required bool SatisfiesRequirements { get; init; }

    /// <summary>
    /// Paths the verifier required but that conflict with user exclusions or policy.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Present only when <see cref="SatisfiesRequirements"/> is <see langword="false"/>.
    /// The application can use this to show the user which claims are in conflict
    /// and request resolution, or to generate a SHAP-style explanation of why the
    /// policy pipeline narrowed the disclosure.
    /// </para>
    /// </remarks>
    public IReadOnlySet<CredentialPath>? ConflictingPaths { get; init; }

    /// <summary>
    /// Paths the verifier required but that are not available in the credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These are candidates for credential discovery (Layer 2 extensibility):
    /// a discovery plugin could attempt to locate or issue a credential containing
    /// the missing paths.
    /// </para>
    /// </remarks>
    public IReadOnlySet<CredentialPath>? UnavailablePaths { get; init; }

    /// <summary>
    /// The credential format, carried forward from the match for downstream encoding.
    /// </summary>
    public string? Format { get; init; }

    /// <summary>
    /// The lattice that was constructed for this credential's disclosure computation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Exposed for auditing, decision record construction, and downstream operations.
    /// The lattice captures the full mathematical context: all available paths (top),
    /// mandatory paths (bottom), and the selectable set. Downstream code can re-derive
    /// the minimum and maximum disclosure sets, verify structural validity, or feed the
    /// lattice into additional optimization passes (e.g., a SAT solver for cross-credential
    /// constraint optimization).
    /// </para>
    /// </remarks>
    public IBoundedDisclosureLattice<CredentialPath>? Lattice { get; init; }
}