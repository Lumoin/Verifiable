using System.Collections.Generic;

namespace Verifiable.Core.Assessment.EArchiving;

/// <summary>
/// Pre-built <see cref="ClaimDelegate{TInput}"/> lists for validating an E-ARK information package,
/// composable through <see cref="ClaimIssuer{TInput}"/>.
/// </summary>
/// <remarks>
/// <para>
/// Each method returns a mutable <see cref="IList{T}"/> the application extends with rules of its own before
/// handing it to a <see cref="ClaimIssuer{TInput}"/>. Adding a package profile — the METS profile rows, the
/// archival-package preservation layer, a preservation service's own capability checks — means adding methods
/// here, not new files, and each list states the requirement identifiers its rules issue so a missing claim is
/// visible in the result rather than silent.
/// </para>
/// <para>
/// Example: extending the structural rules with a check of one's own.
/// </para>
/// <code>
/// var rules = EArkValidationProfiles.CsipStructuralRules();
/// rules.Add(new ClaimDelegate&lt;EArkValidationContext&gt;(
///     MyChecks.CheckHouseNamingConvention,
///     [MyClaimIds.HouseNamingConvention]));
///
/// var issuer = new ClaimIssuer&lt;EArkValidationContext&gt;("eark-package-validator", rules, timeProvider);
/// </code>
/// </remarks>
public static class EArkValidationProfiles
{
    /// <summary>
    /// The rules that apply to any package shape whatsoever: the package stays inside the bounds the caller
    /// stated. Composed by every other profile, and usable on its own by a caller that only wants to know
    /// whether a snapshot is safe to go on reading.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    public static IList<ClaimDelegate<EArkValidationContext>> PackageIntegrityRules() =>
        new List<ClaimDelegate<EArkValidationContext>>
        {
            new(EArkValidationChecks.CheckPackageWithinStatedLimits,
                [EArkClaimIds.PackageWithinStatedLimits]),
        };


    /// <summary>
    /// The folder-structure rules of
    /// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 clause 4.1</see>,
    /// on top of <see cref="PackageIntegrityRules"/>. The list issues the whole folder catalogue —
    /// <c>CSIPSTR1</c>…<c>CSIPSTR16</c>, one rule per row, in the catalogue's own order — so what it returns is
    /// sixteen folder rules on top of whatever <see cref="PackageIntegrityRules"/> contributes, and a caller
    /// running it over one package reads sixteen <c>CSIPSTR</c> claims and the integrity claim beside them. All
    /// three keyword-to-outcome mappings the catalogue is stated in are present among those rows: <c>CSIPSTR4</c>
    /// is a MUST, <c>CSIPSTR5</c> a SHOULD and <c>CSIPSTR8</c> a MAY.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    public static IList<ClaimDelegate<EArkValidationContext>> CsipStructuralRules()
    {
        IList<ClaimDelegate<EArkValidationContext>> rules = PackageIntegrityRules();
        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckSingleRootFolder,
            [EArkClaimIds.CsipStr1]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckRootFolderNamedByPackageIdentifier,
            [EArkClaimIds.CsipStr2]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckPackageArchived,
            [EArkClaimIds.CsipStr3]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckRootManifestPresent,
            [EArkClaimIds.CsipStr4]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckMetadataFolderPresent,
            [EArkClaimIds.CsipStr5]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckPreservationMetadataFolderPresent,
            [EArkClaimIds.CsipStr6]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckDescriptiveMetadataFolderPresent,
            [EArkClaimIds.CsipStr7]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckOtherMetadataFolderWhenPresent,
            [EArkClaimIds.CsipStr8]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckRepresentationsFolderPresent,
            [EArkClaimIds.CsipStr9]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckRepresentationsAreSubFolders,
            [EArkClaimIds.CsipStr10]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckRepresentationDataFolders,
            [EArkClaimIds.CsipStr11]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckRepresentationManifests,
            [EArkClaimIds.CsipStr12]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckRepresentationMetadataFolders,
            [EArkClaimIds.CsipStr13]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckExtensionFolders,
            [EArkClaimIds.CsipStr14]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckSchemaFolders,
            [EArkClaimIds.CsipStr15]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckDocumentationFolders,
            [EArkClaimIds.CsipStr16]));

        return rules;
    }


    /// <summary>
    /// The METS profile rules of
    /// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see>,
    /// <c>CSIP1</c>…<c>CSIP119</c>, one rule per structural-element block of the profile's own catalogue.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    /// <remarks>
    /// These rules read the parsed manifest the caller states on the context, never the package tree. A caller
    /// that supplies no manifest gets one inconclusive claim per row saying so, which is what keeps a
    /// structural-only validation from reading as a conformant package.
    /// </remarks>
    public static IList<ClaimDelegate<EArkValidationContext>> CsipMetsProfileRules() =>
        new List<ClaimDelegate<EArkValidationContext>>
        {
            new(EArkValidationChecks.CheckMetsRootElement, [.. EArkValidationChecks.MetsRootElementClaimIds]),
            new(EArkValidationChecks.CheckMetsHeader, [.. EArkValidationChecks.MetsHeaderClaimIds]),
            new(EArkValidationChecks.CheckDescriptiveMetadataSections, [.. EArkValidationChecks.DescriptiveMetadataClaimIds]),
            new(EArkValidationChecks.CheckAdministrativeMetadata, [.. EArkValidationChecks.AdministrativeMetadataClaimIds]),
            new(EArkValidationChecks.CheckFileSection, [.. EArkValidationChecks.FileSectionClaimIds]),
            new(EArkValidationChecks.CheckStructuralMap, [.. EArkValidationChecks.StructuralMapClaimIds]),
        };


    /// <summary>
    /// The rules this library states over a package's own integrity where the source specifications state
    /// none: every fixity value recomputed and the strength of the algorithm it was computed under reported,
    /// every reference resolved, and every identifier a legal <c>NCName</c>.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    /// <remarks>
    /// The two prose obligations of
    /// <see href="https://earkcsip.dilcis.eu/specification/implementation/metadata/general-requirements/">E-ARK
    /// CSIP v2.2.0 clause 5.1</see> that carry no requirement identifier — references adhering to the
    /// specification, and identifiers conforming to the <c>NCName</c> production — are issued here under house
    /// claims, so that a requirements matrix can name them rather than leave them silent.
    /// </remarks>
    public static IList<ClaimDelegate<EArkValidationContext>> PackageFixityAndReferenceRules() =>
        new List<ClaimDelegate<EArkValidationContext>>
        {
            new(EArkValidationChecks.CheckPackageFixityAsync, [.. EArkValidationChecks.PackageFixityClaimIds]),
            new(EArkValidationChecks.CheckManifestReferencesResolve, [EArkClaimIds.PackageReferencesResolve]),
            new(EArkValidationChecks.CheckManifestIdentifiersAreNCNames, [EArkClaimIds.PackageIdentifiersAreNCNames]),
        };


    /// <summary>
    /// The preservation-metadata rules of
    /// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see>,
    /// <c>PM1</c>…<c>PM125</c>, one rule per entity group of the specification's own tables.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    public static IList<ClaimDelegate<EArkValidationContext>> PreservationMetadataRules() =>
        new List<ClaimDelegate<EArkValidationContext>>
        {
            new(EArkValidationChecks.CheckPreservationMetadataRoot, [.. EArkValidationChecks.PreservationRootClaimIds]),
            new(EArkValidationChecks.CheckPreservationIntellectualEntities, [.. EArkValidationChecks.PreservationIntellectualEntityClaimIds]),
            new(EArkValidationChecks.CheckPreservationRepresentations, [.. EArkValidationChecks.PreservationRepresentationClaimIds]),
            new(EArkValidationChecks.CheckPreservationFiles, [.. EArkValidationChecks.PreservationFileClaimIds]),
            new(EArkValidationChecks.CheckPreservationAgents, [.. EArkValidationChecks.PreservationAgentClaimIds]),
            new(EArkValidationChecks.CheckPreservationEvents, [.. EArkValidationChecks.PreservationEventClaimIds]),
            new(EArkValidationChecks.CheckPreservationRights, [.. EArkValidationChecks.PreservationRightsClaimIds]),
        };


    /// <summary>
    /// The rules of this library's evidence-placement convention: where an evidential artifact sits and how the
    /// package records what it attests, what the artifact says about the preservation service, policy and
    /// profile it was produced under, and whether the package's own digital-provenance content is inside what
    /// one of those artifacts proves.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    /// <remarks>
    /// <para>
    /// These rules read <c>EArkValidationContext.EvidenceArtifacts</c>, which a caller states from what
    /// <see href="https://earkcsip.dilcis.eu/">E-ARK CSIP v2.2.0</see> and
    /// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> treat as ordinary content
    /// files — neither specification has any notion of a signature, a time assertion or an evidence record, so
    /// the whole subject of this profile is a convention this library states and documents as one.
    /// </para>
    /// <para>
    /// Two of the claims are rows of
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
    /// ETSI TS 119 511 V1.2.1</see> rather than house claims — <c>OVR-9.2-04</c> and <c>OVR-9.2-05</c> — because
    /// a package carrying evidence is where those two are decidable at all.
    /// </para>
    /// </remarks>
    public static IList<ClaimDelegate<EArkValidationContext>> EvidencePlacementRules() =>
        new List<ClaimDelegate<EArkValidationContext>>
        {
            new(EArkValidationChecks.CheckPackageEvidencePlacement, [.. EArkValidationChecks.PackageEvidencePlacementClaimIds]),
            new(EArkValidationChecks.CheckPackageEvidenceSelfDescription, [.. EArkValidationChecks.PackageEvidenceSelfDescriptionClaimIds]),
            new(EArkValidationChecks.CheckPackageProvenanceAnchoredAsync, [.. EArkValidationChecks.PackageProvenanceAnchorClaimIds]),
        };


    /// <summary>
    /// Everything the Common Specification asks of one Information Package: the folder structure, the METS
    /// profile catalogue, and this library's own integrity rules over the two.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    public static IList<ClaimDelegate<EArkValidationContext>> CsipPackageRules()
    {
        IList<ClaimDelegate<EArkValidationContext>> rules = CsipStructuralRules();
        AppendAll(rules, CsipMetsProfileRules());
        AppendAll(rules, PackageFixityAndReferenceRules());

        return rules;
    }


    /// <summary>
    /// Everything an Archival Information Package is judged by: the whole Common Specification profile, the
    /// preservation-metadata catalogue, and the archival specification's own preservation layer — the
    /// provenance references its metadata hangs from, the events and agents that record what was done to the
    /// package, and the pointers a parent generation carries to its children.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    /// <remarks>
    /// <para>
    /// The archival layer is deliberately narrow. Almost every remaining requirement of
    /// <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0</see> binds a repository rather than a
    /// package — that an identifier never changed across a life-cycle, that a package can be retrieved by it,
    /// that a container's file name derives from a stated policy — and none of those can be answered from a
    /// single package, however it is parsed. They are allocated claim identifiers so a matrix can name them
    /// and are not issued here.
    /// </para>
    /// <para>
    /// The provenance chain these rules check is plain text: nothing in the archival specification binds an
    /// event to the one before it cryptographically, and the specification names the fragility itself. Closing
    /// that gap is what this library's evidence machinery is for, and <see cref="EvidencePlacementRules"/> —
    /// appended here — is where the package is asked whether it was closed.
    /// </para>
    /// </remarks>
    public static IList<ClaimDelegate<EArkValidationContext>> ArchivalPackageRules()
    {
        IList<ClaimDelegate<EArkValidationContext>> rules = CsipPackageRules();
        AppendAll(rules, PreservationMetadataRules());
        AppendAll(rules, EvidencePlacementRules());
        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckArchivalPackageProvenanceReferences,
            [.. EArkValidationChecks.ArchivalPackageProvenanceClaimIds]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckArchivalPackagePreservationLayer,
            [.. EArkValidationChecks.ArchivalPackagePreservationClaimIds]));

        rules.Add(new ClaimDelegate<EArkValidationContext>(
            EArkValidationChecks.CheckArchivalPackageParentChain,
            [.. EArkValidationChecks.ArchivalPackageParentChainClaimIds]));

        return rules;
    }


    /// <summary>Appends one profile's rules to another's list.</summary>
    /// <param name="destination">The list being built.</param>
    /// <param name="source">The rules to append.</param>
    private static void AppendAll(
        IList<ClaimDelegate<EArkValidationContext>> destination,
        IList<ClaimDelegate<EArkValidationContext>> source)
    {
        for(int i = 0; i < source.Count; ++i)
        {
            destination.Add(source[i]);
        }
    }
}
