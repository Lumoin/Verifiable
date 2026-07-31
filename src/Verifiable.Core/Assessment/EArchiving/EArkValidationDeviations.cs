using System.Diagnostics;

namespace Verifiable.Core.Assessment.EArchiving;

/// <summary>
/// The documented departures from this library's default reading of the E-ARK requirements that a caller may
/// choose, and the defaults it gets when it chooses nothing.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Every knob here exists because two defensible readings of a requirement exist</strong>, not because
/// a caller might find a rule inconvenient. Each one names the requirement it departs from and states which
/// way the default goes and why, so a package validated under a non-default policy can say so.
/// </para>
/// <para>
/// <strong>The defaults are the secure reading in every case.</strong> Where the source specification permits
/// something this library will not treat as evidence, the default flags it rather than accepting it silently;
/// where the specification is silent, the default is the stricter reading. A caller raises a floor by setting
/// a knob, and <see cref="Conformant"/> is what it gets when it sets none.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EArkValidationDeviations
{
    /// <summary>
    /// Gets the default policy: fixity stated under a weak or non-cryptographic algorithm is flagged rather
    /// than failed, and a fixity the library cannot recompute is not by itself a defect.
    /// </summary>
    public static EArkValidationDeviations Conformant { get; } = new();


    /// <summary>
    /// Gets whether a fixity stated under an algorithm this library will not treat as evidence of authenticity
    /// fails the package rather than being flagged.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The default is <see langword="false"/>, which flags. The metadata-encoding vocabulary admits
    /// <c>Adler-32</c>, <c>CRC32</c>, <c>MNP</c>, <c>MD5</c> and <c>SHA-1</c> as first-class checksum types and
    /// imposes no minimum strength — the reference material's own worked packages use <c>MD5</c> — so a
    /// package that states one is doing exactly what
    /// <see href="https://earkcsip.dilcis.eu/specification/implementation/metadata/">E-ARK CSIP v2.2.0 clause
    /// 5</see> permits, and failing it would be this library inventing a requirement. What the library will
    /// not do is treat the value as evidence: the claim is issued with
    /// <see cref="EArkClaimReason.FixityAlgorithmFlagged"/> and never reaches success.
    /// </para>
    /// <para>
    /// Set it when the caller's own policy states a floor the specification does not — an archive that has
    /// committed to the SHA-2 family, say — and wants a package below that floor refused rather than reported.
    /// </para>
    /// </remarks>
    public bool WeakFixityAlgorithmFailsThePackage { get; init; }

    /// <summary>
    /// Gets whether a package whose fixity values cannot be recomputed at all — because no referenced entry
    /// carries octets, or because every stated algorithm is one the library does not compute — fails rather
    /// than being reported as undecided.
    /// </summary>
    /// <remarks>
    /// The default is <see langword="false"/>. A caller that hands over a name-only snapshot has asked a
    /// structural question and not a fixity question, and answering it with a failure would confuse the two.
    /// </remarks>
    public bool UnrecomputableFixityFailsThePackage { get; init; }

    /// <summary>
    /// Gets whether the two requirements the preservation-metadata specification states with the keyword
    /// <c>COULD</c> are read as MAY.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The default is <see langword="true"/>, which reads them as MAY. <c>PM53</c> and <c>PM66</c> of
    /// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> carry the literal
    /// keyword <c>COULD</c> in their cardinality-and-level cell, which is not one of the five terms the
    /// specification's own conformance section defines. Both rows are <c>0..1</c> and <c>0..n</c>
    /// respectively and both describe optional conveniences — a content location "for easy access" and a link
    /// to rights statements the object "may relate to" — so MAY is the reading their cardinality and their
    /// prose agree on. The claim is issued with <see cref="EArkClaimReason.InterpretationApplied"/> so that
    /// the interpretation is visible in the claim set rather than buried here.
    /// </para>
    /// <para>
    /// Clearing it makes the two rows report <see cref="EArkClaimReason.InterpretationApplied"/> with
    /// <see cref="ClaimOutcome.Inconclusive"/> whatever the document says, which is what a caller that will
    /// not accept an undefined keyword at all wants.
    /// </para>
    /// </remarks>
    public bool UndefinedKeywordReadsAsOptional { get; init; } = true;


    /// <summary>A short debugger string showing which knobs are off their defaults.</summary>
    private string DebuggerDisplay =>
        $"EArkValidationDeviations(weakFixityFails {WeakFixityAlgorithmFailsThePackage}, unrecomputableFails {UnrecomputableFixityFailsThePackage}, undefinedKeywordOptional {UndefinedKeywordReadsAsOptional})";
}
