using System.Collections.Generic;
using Verifiable.Core.SelectiveDisclosure.Strategy;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// The complete disclosure plan produced by <see cref="DisclosureComputation{TCredential}"/>.
/// </summary>
/// <remarks>
/// <para>
/// A disclosure plan is a <em>view</em> into the <see cref="StrategyGraph"/>: the selected
/// strategy's decisions projected into the flat format downstream consumers expect. Protocol
/// handlers (SD-JWT, ECDSA-SD, mso_mdoc) consume the flat <see cref="Decisions"/>; wallets,
/// AI agents, and debugging tools navigate the full <see cref="StrategyGraph"/> to inspect
/// alternatives, entropy trade-offs, and the Pareto frontier.
/// </para>
/// <para>
/// The plan is the primary input for Layer 5 (format-specific encoding) and downstream builders:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Format-specific presenters</strong> that encode derived credentials.
/// For SD-JWT: <see cref="SdDisclosureSelection"/> maps decisions to disclosure triples.
/// For ECDSA-SD-2023: decisions drive N-Quad statement selection for derived proofs.
/// For mso_mdoc: decisions map to namespace/element pairs.
/// </description></item>
/// <item><description>
/// <strong>Presentation builders</strong> that wrap derived credentials into verifiable
/// presentations (e.g., OID4VP VP Token keyed by query requirement IDs).
/// </description></item>
/// <item><description>
/// <strong>Consent record builders</strong> that construct ISO 27560 receipts, GDPR
/// Article 30 processing records, or other compliance artifacts from the
/// <see cref="DecisionRecord"/>.
/// </description></item>
/// <item><description>
/// <strong>Wallet UI / AI agent</strong> that presents the Pareto frontier from
/// <see cref="StrategyGraph"/> to the holder, explaining trade-offs between entropy,
/// credential count, and ZKP utilization. The holder selects a strategy; the plan's
/// <see cref="Decisions"/> reflect that selection.
/// </description></item>
/// </list>
/// <para>
/// The plan does not contain the derived credentials themselves. Format encoding
/// (SD-JWT disclosure filtering, ECDSA-SD derived proof construction, mso_mdoc
/// element selection, SD-CWT CBOR construction) is performed by the application
/// using the paths in each <see cref="CredentialDisclosureDecision{TCredential}"/>.
/// This separation keeps the computation layer format-neutral while enabling any
/// output format.
/// </para>
/// </remarks>
/// <typeparam name="TCredential">The application-specific credential type.</typeparam>
public sealed class DisclosurePlan<TCredential>
{
    /// <summary>
    /// Whether all query requirements were satisfied.
    /// </summary>
    public required bool Satisfied { get; init; }

    /// <summary>
    /// Per-credential disclosure decisions from the selected strategy.
    /// </summary>
    public required IReadOnlyList<CredentialDisclosureDecision<TCredential>> Decisions { get; init; }

    /// <summary>
    /// Query requirement IDs that could not be satisfied by any credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These are candidates for credential discovery (Layer 2 extensibility): a
    /// discovery plugin could attempt to locate or issue credentials containing
    /// the missing claims. See the DCQL Disclosure Architecture for the credential
    /// discovery trigger pattern.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string>? UnsatisfiedRequirements { get; init; }

    /// <summary>
    /// The decision record capturing the full computation trace for audit and consent.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Contains all intermediate results: evaluation records, lattice computations,
    /// policy assessments, and final decisions. Includes W3C Trace Context identifiers
    /// for OpenTelemetry correlation. This record is the raw data source for downstream
    /// builders that produce ISO 27560 consent receipts, GDPR audit logs, or operational
    /// analytics dashboards.
    /// </para>
    /// </remarks>
    public required DisclosureDecisionRecord<TCredential> DecisionRecord { get; init; }

    /// <summary>
    /// The full strategy graph from which this plan was projected.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The graph contains all enumerated strategies (feasible, pruned, dominated),
    /// the Pareto frontier, entropy scores, and the selected strategy. Callers who
    /// need only the flat decisions can ignore this property. Callers who need to
    /// present alternatives (wallet UI), reason over trade-offs (AI agents), or
    /// log the full decision space (audit) use the graph directly.
    /// </para>
    /// <para>
    /// <see langword="null"/> when no strategy enumeration was performed (e.g., when
    /// all matches failed lattice construction or policy assessment, leaving zero
    /// surviving decisions).
    /// </para>
    /// </remarks>
    public DisclosureStrategyGraph<TCredential>? StrategyGraph { get; init; }
}
