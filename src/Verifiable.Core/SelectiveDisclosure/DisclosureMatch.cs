using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Represents a credential that matched a query requirement, carrying the
/// concrete paths required for disclosure.
/// </summary>
/// <remarks>
/// <para>
/// This is the query-language-neutral contract between evaluators (Layer 1–2 of
/// the DCQL Disclosure Architecture) and the disclosure computation (Layer 3).
/// Evaluators resolve query patterns (which may contain wildcards or abstract
/// references) into concrete <see cref="CredentialPath"/> values that the lattice
/// can operate on directly.
/// </para>
/// <para>
/// <strong>Storage agnosticism:</strong> The <typeparamref name="TCredential"/> type
/// parameter allows the match to carry any credential representation — an in-memory
/// object, a database record identifier, a hardware token reference, or a serialized
/// wire format string. The disclosure computation treats it as opaque and passes it
/// through to the <see cref="CredentialDisclosureDecision{TCredential}"/>. This enables
/// credential retrieval from any backend: persistent databases, cloud vaults, hardware
/// security modules, or agent-to-agent protocols.
/// </para>
/// <para>
/// <strong>Evaluator responsibility:</strong> Produce one <see cref="DisclosureMatch{TCredential}"/>
/// per credential that satisfies the query. The evaluator determines which claims are
/// present and which paths are required; the disclosure computation determines the
/// optimal disclosure set respecting lattice bounds, user preferences, and policy
/// constraints. Multiple evaluators can feed into a single computation — DCQL, DIF
/// Presentation Definition, SPARQL-based semantic queries, or manual selections all
/// produce the same <see cref="DisclosureMatch{TCredential}"/> shape.
/// </para>
/// <para>
/// <strong>Issuance-side usage:</strong> For the issuance direction, the match represents
/// the issuer's view of the credential being constructed. The <see cref="AllAvailablePaths"/>
/// are all claims in the unsigned credential, <see cref="MandatoryPaths"/> are claims that
/// must remain always-visible, and the complement (available minus mandatory) becomes the
/// set of selectively disclosable claims. The lattice and policy pipeline then refine this
/// classification before format-specific encoding.
/// </para>
/// </remarks>
/// <typeparam name="TCredential">The application-specific credential type.</typeparam>
[DebuggerDisplay("Match(QueryId={QueryRequirementId}, Required={RequiredPaths.Count}, Matched={MatchedPaths.Count})")]
public sealed class DisclosureMatch<TCredential>
{
    /// <summary>
    /// The credential that matched the query requirement.
    /// </summary>
    public required TCredential Credential { get; init; }

    /// <summary>
    /// An identifier for the query requirement this credential satisfies.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For DCQL, this is the credential query ID. For Presentation Definition,
    /// this would be the input descriptor ID. The disclosure computation uses
    /// this to correlate matches with user exclusions and policy decisions.
    /// </para>
    /// </remarks>
    public required string QueryRequirementId { get; init; }

    /// <summary>
    /// Concrete credential paths that the verifier requires for disclosure.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These paths have been resolved from query patterns to concrete addresses.
    /// For example, a DCQL <c>ClaimPath</c> pattern <c>["items", null, "name"]</c>
    /// (with wildcard) resolves to concrete paths like <c>/items/0/name</c>,
    /// <c>/items/1/name</c> based on the credential's actual structure.
    /// </para>
    /// </remarks>
    public required IReadOnlySet<CredentialPath> RequiredPaths { get; init; }

    /// <summary>
    /// All concrete credential paths that the evaluator found present in the credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a superset of <see cref="RequiredPaths"/> when optional claims were
    /// also found. The disclosure computation uses this to inform the lattice about
    /// what is available.
    /// </para>
    /// </remarks>
    public required IReadOnlySet<CredentialPath> MatchedPaths { get; init; }

    /// <summary>
    /// All paths available in the credential, both selectively disclosable and mandatory.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used to construct the lattice's top element. This includes claims the verifier
    /// did not ask for but that exist in the credential. The lattice uses this to
    /// compute the maximum disclosure bound.
    /// </para>
    /// </remarks>
    public required IReadOnlySet<CredentialPath> AllAvailablePaths { get; init; }

    /// <summary>
    /// Paths that are mandatory and cannot be excluded from any disclosure.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used to construct the lattice's bottom element. Examples include issuer
    /// identifiers, credential type declarations, and structurally required
    /// parent paths. These are always disclosed regardless of verifier request
    /// or user preference.
    /// </para>
    /// </remarks>
    public IReadOnlySet<CredentialPath>? MandatoryPaths { get; init; }

    /// <summary>
    /// The credential format (e.g., <c>dc+sd-jwt</c>, <c>mso_mdoc</c>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Carried forward to <see cref="CredentialDisclosureDecision{TCredential}"/> for
    /// downstream format-specific encoding (Layer 5 of the DCQL Disclosure Architecture).
    /// The disclosure computation itself is format-neutral.
    /// </para>
    /// </remarks>
    public string? Format { get; init; }
}