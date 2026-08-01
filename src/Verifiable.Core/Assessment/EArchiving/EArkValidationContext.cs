using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Core.Assessment.EArchiving;

/// <summary>
/// Everything one E-ARK information package validation is given.
/// </summary>
/// <remarks>
/// <para>
/// The package reaches validation as a value snapshot, never as a live file system: the caller states the
/// entries it read, and no rule walks a directory or opens a file of its own. That is what lets the same rule
/// list run over a folder tree, over an archive and over a package rebuilt from wire octets, and what keeps a
/// rule a pure function of what it was handed.
/// </para>
/// <para>
/// <strong>This record grows by addition.</strong> The stages that follow state the classified package facts,
/// the seams a manifest and a preservation-metadata document are parsed through, and the memory pool a
/// digest-recomputing rule rents from; each arrives as a further init member with a default that leaves the
/// rules that do not read it unaffected. Nothing here is renamed or retyped to make room for them.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EArkValidationContext
{
    /// <summary>
    /// The name of every entry the package holds, root-relative and <c>/</c>-separated, a folder entry ending
    /// in the separator. Names are compared exactly as the source specifications state them, so a name
    /// differing only in case is a different entry.
    /// </summary>
    public required IReadOnlyList<string> EntryNames { get; init; }

    /// <summary>
    /// The instant the package is validated at. Stated by the caller rather than read from a clock, so a rule
    /// stays a pure function of its inputs and a validation can be replayed at the instant it originally ran.
    /// </summary>
    public required DateTimeOffset CurrentTime { get; init; }

    /// <summary>The bounds the package is validated within.</summary>
    public EArkPackageLimits Limits { get; init; } = EArkPackageLimits.Conformant;

    /// <summary>
    /// What the package's layout states about itself — which named folders exist, which files sit where, how
    /// many representations there are — or <see langword="null"/> when the caller did not classify the tree.
    /// </summary>
    /// <remarks>
    /// A rule that reads these and finds none issues its claim with
    /// <see cref="EArkClaimReason.SubjectNotSupplied"/>: nothing was decided, which is a statement about the
    /// caller rather than about the package. Not owned by this instance; whoever built the snapshot the facts
    /// point into disposes it.
    /// </remarks>
    public EArkPackageFacts? PackageFacts { get; init; }

    /// <summary>
    /// The package's own root manifest as a parsed document, or <see langword="null"/> when the caller did not
    /// parse one.
    /// </summary>
    /// <remarks>
    /// This library ships no manifest parser — the document arrives through the parse seam a caller registered
    /// — so a rule over the manifest is a rule over whatever that seam produced. Not owned by this instance.
    /// </remarks>
    public MetsDocument? PackageManifest { get; init; }

    /// <summary>
    /// Each representation's own manifest as a parsed document, in whatever order the caller states them.
    /// Empty when the caller parsed none.
    /// </summary>
    /// <remarks>Not owned by this instance.</remarks>
    public IReadOnlyList<MetsDocument> RepresentationManifests { get; init; } = [];

    /// <summary>
    /// The preservation-metadata documents the package carries, as parsed documents. Empty when the caller
    /// parsed none.
    /// </summary>
    /// <remarks>Not owned by this instance.</remarks>
    public IReadOnlyList<PremisDocument> PreservationMetadata { get; init; } = [];

    /// <summary>
    /// The memory pool a rule that recomputes a digest rents from, or <see langword="null"/> when the caller
    /// supplied none.
    /// </summary>
    /// <remarks>
    /// Only the fixity rules read it, and a fixity rule without a pool concludes
    /// <see cref="EArkClaimReason.SubjectNotSupplied"/> rather than renting from somewhere of its own.
    /// </remarks>
    public BaseMemoryPool? MemoryPool { get; init; }

    /// <summary>
    /// What the caller states about the evidential artifacts the package carries — where each sits, what it
    /// covers, and what it says about the preservation service, policy and profile it was produced under. Empty
    /// when the caller states none.
    /// </summary>
    /// <remarks>
    /// The facts are stated rather than parsed here for the reason every other subject on this record is: a rule
    /// judges what it was handed and never opens a file of its own. Reading an Evidence Record's attributes or a
    /// signer's unsigned attributes is <see cref="EArkEvidencePlacement"/>'s business, and its result travels
    /// here as a value. A rule given none answers <see cref="EArkClaimReason.SubjectNotSupplied"/>, which is a
    /// statement about the caller rather than about the package. Not owned by this instance.
    /// </remarks>
    public IReadOnlyList<EArkEvidenceArtifactFacts> EvidenceArtifacts { get; init; } = [];

    /// <summary>The documented departures from the default reading of the requirements that are in force.</summary>
    public EArkValidationDeviations Deviations { get; init; } = EArkValidationDeviations.Conformant;


    /// <summary>A short debugger string showing the snapshot size and the instant.</summary>
    private string DebuggerDisplay => $"EArkValidationContext({EntryNames.Count} entries at {CurrentTime:O})";
}
