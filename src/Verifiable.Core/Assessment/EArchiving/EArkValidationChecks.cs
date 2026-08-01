using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Core.Assessment.EArchiving;

/// <summary>
/// The validation check functions an E-ARK information package's rule lists are built from. Each one matches
/// <see cref="ClaimDelegateAsync{TInput}"/> exactly, so it composes into a
/// <see cref="ClaimIssuer{TInput}"/> through <see cref="EArkValidationProfiles"/>.
/// </summary>
/// <remarks>
/// <para>
/// Adding a requirement group — the METS profile rows, the preservation-metadata rows, the archival-package
/// rows — means adding methods here, not new files. Every check takes
/// <see cref="EArkValidationContext"/> and returns the claims it is responsible for, one per requirement
/// identifier, and reads only what it needs from the context.
/// </para>
/// <para>
/// <strong>How a requirement's own keyword becomes an outcome.</strong> A MUST that does not hold is
/// <see cref="ClaimOutcome.Failure"/>. A SHOULD that does not hold is
/// <see cref="ClaimOutcome.Inconclusive"/>: the specification permits the deviation, and a package that took it
/// is not conformant-by-silence either, so the claim says what happened and leaves the decision to whoever
/// assesses the claim set. A MAY whose subject is absent is
/// <see cref="ClaimOutcome.NotApplicable"/> — the rule had nothing to judge. No check returns an empty claim
/// list: a rule that could not evaluate says so with a claim rather than by saying nothing.
/// </para>
/// <para>
/// <strong>The keyword is the catalogue's <c>REQLEVEL</c>, never the requirement's prose.</strong> Several rows
/// of <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> are rated SHOULD or
/// MAY in the catalogue and then word their own consequent with "MUST" or "must" once their condition holds —
/// <c>CSIP3</c>, <c>CSIP5</c> and <c>CSIP63</c> are the three. The rated level decides here, because that is the
/// specification's own normative statement about the requirement while the sentence is prose about what the
/// requirement is for, and because holding a row to one level in a rule and to another in the corpus sweep would
/// let the same package read as conformant and non-conformant at once. So a package that leaves such a value
/// unstated departs from a recommendation or leaves a permission untaken, and says which through its reason,
/// rather than failing.
/// </para>
/// <para>
/// <strong>Every claim carries an <see cref="EArkClaimContext"/> saying which road it took.</strong> The
/// outcome vocabulary is the shipped one and gains nothing, but <see cref="ClaimOutcome.Inconclusive"/> is
/// reached from two opposite places — a package that declined a recommendation, and a rule that was never
/// given the document it judges — and a claim set in which those read alike cannot be acted on. The reason is
/// therefore stated beside the outcome rather than encoded into it. The four helpers
/// <see cref="Mandatory"/>, <see cref="Recommended"/>, <see cref="Optional"/> and <see cref="Conditional"/>
/// are the only places the mapping is written, so no rule can spell it differently.
/// </para>
/// <para>
/// <strong>Some MUST rows are met by construction.</strong> The serialization-agnostic model a document is
/// parsed into makes several mandatory particles unrepresentable-if-absent — a manifest without a header or a
/// file entry without a locator cannot be built at all — so the rules over them state what was checked and
/// reach success by construction. That is not a rule doing nothing: it is the obligation being enforced one
/// layer down, at the parse seam, and the claim records that the package met it.
/// </para>
/// <para>
/// <strong>A group of requirements is one rule.</strong> The METS profile catalogue and the preservation
/// metadata catalogue each group their rows by the element the rows constrain, and every row in a group asks
/// something about the same parsed subtree; one check per group therefore reads that subtree once and answers
/// every row of it. The folder-structure catalogue is the opposite case — sixteen independent questions about
/// the tree on disk — and gets one check per row.
/// </para>
/// </remarks>
public static class EArkValidationChecks
{
    /// <summary>
    /// Checks that the package snapshot stays inside the bounds the caller stated: the number of entries, the
    /// length of each entry name and the depth each entry sits at. The byte bound of
    /// <see cref="EArkPackageLimits.MaximumTotalByteLength"/> is applied where the octets are read, which a
    /// name snapshot does not carry.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.PackageWithinStatedLimits"/>.</returns>
    public static ValueTask<List<Claim>> CheckPackageWithinStatedLimits(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        bool withinLimits = context.EntryNames.Count <= context.Limits.MaximumEntryCount;
        if(withinLimits)
        {
            for(int i = 0; i < context.EntryNames.Count; ++i)
            {
                string entryName = context.EntryNames[i];
                if(entryName is null
                    || Encoding.UTF8.GetByteCount(entryName) > context.Limits.MaximumEntryNameByteLength
                    || SegmentDepthOf(entryName) > context.Limits.MaximumFolderDepth)
                {
                    withinLimits = false;
                    break;
                }
            }
        }

        return ValueTask.FromResult<List<Claim>>(
            [Mandatory(EArkClaimIds.PackageWithinStatedLimits, withinLimits, "the entry count, entry name length and folder depth the caller stated")]);

        //How deep below the package root an entry sits, counted in path segments. A folder entry's trailing
        //separator names no segment of its own, so it is not counted.
        static int SegmentDepthOf(string entryName)
        {
            int depth = 0;
            int lastIndex = entryName.Length - 1;
            for(int i = 0; i < entryName.Length; ++i)
            {
                if(entryName[i] == EArkWellKnown.PathSeparator && i != lastIndex)
                {
                    ++depth;
                }
            }

            return depth;
        }
    }


    /// <summary>
    /// Checks <c>CSIPSTR4</c>: the package root holds a file named <c>METS.xml</c>. A MUST, so its absence is
    /// a failure.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.CsipStr4"/>.</returns>
    public static ValueTask<List<Claim>> CheckRootManifestPresent(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult<List<Claim>>(
        [
            Mandatory(
                EArkClaimIds.CsipStr4,
                AnyEntry(context, EArkWellKnown.IsPackageManifestEntryName),
                EArkWellKnown.PackageManifestFileName + " at the package root")
        ]);
    }


    /// <summary>
    /// Checks <c>CSIPSTR5</c>: the package root holds a <c>metadata</c> folder for whole-package metadata. A
    /// SHOULD, so its absence is inconclusive rather than a failure — the specification permits a package that
    /// carries no package-level metadata at all.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.CsipStr5"/>.</returns>
    public static ValueTask<List<Claim>> CheckMetadataFolderPresent(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult<List<Claim>>(
        [
            Recommended(
                EArkClaimIds.CsipStr5,
                AnyEntry(context, EArkWellKnown.IsMetadataEntryName),
                EArkWellKnown.MetadataFolderName + " at the package root")
        ]);
    }


    /// <summary>
    /// Checks <c>CSIPSTR8</c>: metadata of any other kind sits in a further sub-folder, <c>metadata/other</c>.
    /// A MAY, so a package that has no such folder gave the rule nothing to judge and the claim is not
    /// applicable rather than failed.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.CsipStr8"/>.</returns>
    public static ValueTask<List<Claim>> CheckOtherMetadataFolderWhenPresent(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult<List<Claim>>(
        [
            Optional(
                EArkClaimIds.CsipStr8,
                AnyEntry(context, EArkWellKnown.IsOtherMetadataEntryName),
                EArkWellKnown.OtherMetadataFolderName + " at the package root")
        ]);
    }


    /// <summary>
    /// Checks <c>CSIPSTR1</c>: the package's entries were found under a single root folder, which an archived
    /// package unpacks to. A MUST, so a package whose entries sit under more than one root is a failure.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.CsipStr1"/>.</returns>
    /// <remarks>
    /// The fact is stated by the package reader rather than recomputed here: a snapshot a caller handed over
    /// entry by entry has already been read relative to a root, and an archived package's reader reports
    /// whether the archive really unpacked to exactly one folder.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckSingleRootFolder(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        EArkPackageFacts? facts = context.PackageFacts;

        return ValueTask.FromResult<List<Claim>>(
        [
            facts is null
                ? NotSupplied(EArkClaimIds.CsipStr1, "the classified package facts")
                : Mandatory(EArkClaimIds.CsipStr1, facts.HasSingleRootFolder, "a single package root folder")
        ]);
    }


    /// <summary>
    /// Checks <c>CSIPSTR2</c>: the package root folder is named with the package's own <c>mets/@OBJID</c>
    /// value. A SHOULD, so a differently named root folder is a deviation rather than a failure.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.CsipStr2"/>.</returns>
    /// <remarks>
    /// A package that did not arrive under a named root folder — one whose entries a caller stated directly —
    /// gives the recommendation no subject, and the claim is not applicable rather than deviating.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckRootFolderNamedByPackageIdentifier(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        EArkPackageFacts? facts = context.PackageFacts;
        MetsDocument? manifest = context.PackageManifest;
        Claim claim;
        if(facts is null || manifest is null)
        {
            claim = NotSupplied(EArkClaimIds.CsipStr2, "the classified package facts and the package manifest");
        }
        else if(facts.RootFolderName is null)
        {
            claim = Conditional(EArkClaimIds.CsipStr2, applies: false, holds: false, "a named package root folder");
        }
        else
        {
            claim = Recommended(
                EArkClaimIds.CsipStr2,
                string.Equals(facts.RootFolderName, manifest.ObjectIdentifier, StringComparison.Ordinal),
                "the root folder name against mets/@OBJID");
        }

        return ValueTask.FromResult<List<Claim>>([claim]);
    }


    /// <summary>
    /// Checks <c>CSIPSTR3</c>: the package may be archived or compressed for storage and transfer. A MAY, so a
    /// package that arrived as a folder tree gave the rule nothing to judge.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.CsipStr3"/>.</returns>
    /// <remarks>
    /// Only the first half of the requirement is a document's to answer. Which archive format the parties use
    /// is settled by their own agreement, which the requirement says outright — that half binds the parties
    /// rather than the package, and no rule over one package can reach it.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckPackageArchived(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        EArkPackageFacts? facts = context.PackageFacts;

        return ValueTask.FromResult<List<Claim>>(
        [
            facts is null
                ? NotSupplied(EArkClaimIds.CsipStr3, "the classified package facts")
                : Optional(EArkClaimIds.CsipStr3, facts.RootFolderName is not null, "an archived package")
        ]);
    }


    /// <summary>
    /// Checks <c>CSIPSTR6</c>: preservation metadata, when the package has any, sits in
    /// <c>metadata/preservation</c>. A conditional SHOULD.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.CsipStr6"/>.</returns>
    /// <remarks>
    /// The requirement reads "If preservation metadata are available, they SHOULD be included in sub-folder
    /// preservation", so its antecedent is a fact about the package rather than about the tree, and a package
    /// that holds no preservation metadata at all never triggered it. The antecedent is answered from what the
    /// package states it holds — a PREMIS-typed digital-provenance section of the manifest, or a preservation
    /// document handed to the validation directly — because a claim saying a recommendation was unmet has to be
    /// a true statement about the package, and it is what keeps the specification's own minimal example
    /// distinguishable from a package that has preservation metadata and files it somewhere else.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckPreservationMetadataFolderPresent(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        MetsDocument? manifest = context.PackageManifest;
        if(manifest is null && context.PreservationMetadata.Count == 0)
        {
            return ValueTask.FromResult<List<Claim>>(
            [
                NotSupplied(EArkClaimIds.CsipStr6, "the package manifest the preservation metadata would be stated in")
            ]);
        }

        return ValueTask.FromResult<List<Claim>>(
        [
            Conditional(
                EArkClaimIds.CsipStr6,
                applies: context.PreservationMetadata.Count > 0 || StatesPreservationMetadata(manifest),
                holds: AnyEntry(context, EArkWellKnown.IsPreservationMetadataEntryName),
                EArkWellKnown.PreservationMetadataFolderName,
                recommendation: true)
        ]);

        //Whether the manifest states preservation metadata of its own — a digital-provenance section whose
        //reference names PREMIS, which is the same scan the AIP preservation rules read that section with.
        static bool StatesPreservationMetadata(MetsDocument? manifest)
        {
            IReadOnlyList<MetsAdministrativeMetadataSection> provenance =
                manifest?.AdministrativeMetadata?.DigitalProvenanceSections ?? [];
            for(int i = 0; i < provenance.Count; ++i)
            {
                if(string.Equals(provenance[i].Reference?.MetadataType, MetsWellKnown.PremisMetadataType, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>
    /// Checks <c>CSIPSTR7</c>: descriptive metadata, when the package has any, sits in
    /// <c>metadata/descriptive</c>. A conditional SHOULD.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.CsipStr7"/>.</returns>
    /// <remarks>
    /// The requirement reads "If descriptive metadata are available, they SHOULD be included in sub-folder
    /// descriptive", the same conditional shape <see cref="CheckPreservationMetadataFolderPresent"/> answers,
    /// and its antecedent is what the manifest's descriptive sections state.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckDescriptiveMetadataFolderPresent(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        MetsDocument? manifest = context.PackageManifest;
        if(manifest is null)
        {
            return ValueTask.FromResult<List<Claim>>(
            [
                NotSupplied(EArkClaimIds.CsipStr7, "the package manifest the descriptive metadata would be stated in")
            ]);
        }

        return ValueTask.FromResult<List<Claim>>(
        [
            Conditional(
                EArkClaimIds.CsipStr7,
                applies: manifest.DescriptiveMetadataSections.Count > 0,
                holds: AnyEntry(context, EArkWellKnown.IsDescriptiveMetadataEntryName),
                EArkWellKnown.DescriptiveMetadataFolderName,
                recommendation: true)
        ]);
    }


    /// <summary>
    /// Checks <c>CSIPSTR9</c>: the package holds a <c>representations</c> folder. A SHOULD, so a package with
    /// no representations at all — which the specification's own minimal example is — deviates rather than
    /// fails.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.CsipStr9"/>.</returns>
    public static ValueTask<List<Claim>> CheckRepresentationsFolderPresent(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        EArkPackageFacts? facts = context.PackageFacts;

        return ValueTask.FromResult<List<Claim>>(
        [
            facts is null
                ? NotSupplied(EArkClaimIds.CsipStr9, "the classified package facts")
                : Recommended(EArkClaimIds.CsipStr9, facts.HasRepresentationsFolder, EArkWellKnown.RepresentationsFolderName)
        ]);
    }


    /// <summary>
    /// Checks <c>CSIPSTR10</c>: the <c>representations</c> folder holds one uniquely named sub-folder per
    /// representation, and nothing else. A SHOULD.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.CsipStr10"/>.</returns>
    /// <remarks>
    /// Uniqueness needs no comparison of its own: a package holding the same folder name twice does not read
    /// as one tree and the package reader refuses it before a rule sees it. What is left to judge is that the
    /// folder holds sub-folders — a file sitting directly under it is classified as a name at a position the
    /// specification does not put it at, and this rule is where that classification becomes a finding.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckRepresentationsAreSubFolders(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        EArkPackageFacts? facts = context.PackageFacts;
        Claim claim;
        if(facts is null)
        {
            claim = NotSupplied(EArkClaimIds.CsipStr10, "the classified package facts");
        }
        else if(!facts.HasRepresentationsFolder)
        {
            claim = Conditional(EArkClaimIds.CsipStr10, applies: false, holds: false, EArkWellKnown.RepresentationsFolderName);
        }
        else
        {
            bool misplacedUnderRepresentations = false;
            for(int i = 0; i < facts.Entries.Count; ++i)
            {
                EArkClassifiedEntry entry = facts.Entries[i];
                if(entry.Placement == EArkPackageEntryPlacement.Misplaced
                    && EArkWellKnown.IsRepresentationsEntryName(entry.Entry.Name))
                {
                    misplacedUnderRepresentations = true;
                    break;
                }
            }

            claim = Recommended(
                EArkClaimIds.CsipStr10,
                facts.Representations.Count > 0 && !misplacedUnderRepresentations,
                "one sub-folder per representation under " + EArkWellKnown.RepresentationsFolderName);
        }

        return ValueTask.FromResult<List<Claim>>([claim]);
    }


    /// <summary>
    /// Checks <c>CSIPSTR11</c>: each representation folder holds a <c>data</c> sub-folder. A SHOULD.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.CsipStr11"/>.</returns>
    public static ValueTask<List<Claim>> CheckRepresentationDataFolders(
        EArkValidationContext context,
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(PerRepresentation(
            context,
            EArkClaimIds.CsipStr11,
            static representation => representation.Contents.HasDataFolder,
            EArkWellKnown.RepresentationDataFolderName + " inside each representation"));


    /// <summary>
    /// Checks <c>CSIPSTR12</c>: each representation folder holds its own <c>METS.xml</c>. A SHOULD, which the
    /// specification's own companion text calls the recommended best practice to always follow.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.CsipStr12"/>.</returns>
    public static ValueTask<List<Claim>> CheckRepresentationManifests(
        EArkValidationContext context,
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(PerRepresentation(
            context,
            EArkClaimIds.CsipStr12,
            static representation => representation.Contents.HasManifest,
            EArkWellKnown.PackageManifestFileName + " inside each representation"));


    /// <summary>
    /// Checks <c>CSIPSTR13</c>: each representation folder holds its own <c>metadata</c> sub-folder. A SHOULD.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.CsipStr13"/>.</returns>
    public static ValueTask<List<Claim>> CheckRepresentationMetadataFolders(
        EArkValidationContext context,
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(PerRepresentation(
            context,
            EArkClaimIds.CsipStr13,
            static representation => representation.Contents.HasMetadataFolder,
            EArkWellKnown.MetadataFolderName + " inside each representation"));


    /// <summary>
    /// Checks <c>CSIPSTR14</c>: the package may be extended with additional sub-folders. A MAY, and the
    /// specification's own extension point, so a package that took it succeeds and one that did not gave the
    /// rule nothing to judge.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.CsipStr14"/>.</returns>
    public static ValueTask<List<Claim>> CheckExtensionFolders(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        EArkPackageFacts? facts = context.PackageFacts;
        Claim claim;
        if(facts is null)
        {
            claim = NotSupplied(EArkClaimIds.CsipStr14, "the classified package facts");
        }
        else
        {
            bool anyExtension = false;
            for(int i = 0; i < facts.Entries.Count; ++i)
            {
                if(facts.Entries[i].Placement == EArkPackageEntryPlacement.Extension)
                {
                    anyExtension = true;
                    break;
                }
            }

            claim = Optional(EArkClaimIds.CsipStr14, anyExtension, "an entry at a position the specification names none for");
        }

        return ValueTask.FromResult<List<Claim>>([claim]);
    }


    /// <summary>
    /// Checks <c>CSIPSTR15</c>: XML schema documents sit in a <c>schemas</c> sub-folder at package level, at
    /// representation level, or both. A SHOULD.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.CsipStr15"/>.</returns>
    public static ValueTask<List<Claim>> CheckSchemaFolders(
        EArkValidationContext context,
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(AtEitherLevel(
            context,
            EArkClaimIds.CsipStr15,
            static level => level.HasSchemasFolder,
            EArkWellKnown.SchemasFolderName + " at package or representation level"));


    /// <summary>
    /// Checks <c>CSIPSTR16</c>: supplementary documentation sits in a <c>documentation</c> sub-folder at
    /// package level, at representation level, or both. A SHOULD.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.CsipStr16"/>.</returns>
    public static ValueTask<List<Claim>> CheckDocumentationFolders(
        EArkValidationContext context,
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(AtEitherLevel(
            context,
            EArkClaimIds.CsipStr16,
            static level => level.HasDocumentationFolder,
            EArkWellKnown.DocumentationFolderName + " at package or representation level"));


    /// <summary>
    /// States whether any entry of the package satisfies a recognition helper of
    /// <see cref="EArkWellKnown"/>. The predicate is passed in rather than captured, so a check states its
    /// subject at the call site and nothing walks the snapshot twice.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="recognises">The recognition helper an entry name is offered to.</param>
    /// <returns><see langword="true"/> when at least one entry is recognised.</returns>
    private static bool AnyEntry(EArkValidationContext context, Func<string?, bool> recognises)
    {
        for(int i = 0; i < context.EntryNames.Count; ++i)
        {
            if(recognises(context.EntryNames[i]))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>The requirements <see cref="CheckMetsRootElement"/> issues, <c>CSIP1</c>…<c>CSIP6</c>.</summary>
    public static IReadOnlyList<ClaimId> MetsRootElementClaimIds { get; } =
    [
        EArkClaimIds.Csip1, EArkClaimIds.Csip2, EArkClaimIds.Csip3,
        EArkClaimIds.Csip4, EArkClaimIds.Csip5, EArkClaimIds.Csip6
    ];

    /// <summary>The requirements <see cref="CheckMetsHeader"/> issues, <c>CSIP117</c> and <c>CSIP7</c>…<c>CSIP16</c>.</summary>
    public static IReadOnlyList<ClaimId> MetsHeaderClaimIds { get; } =
    [
        EArkClaimIds.Csip117, EArkClaimIds.Csip7, EArkClaimIds.Csip8, EArkClaimIds.Csip9,
        EArkClaimIds.Csip10, EArkClaimIds.Csip11, EArkClaimIds.Csip12, EArkClaimIds.Csip13,
        EArkClaimIds.Csip14, EArkClaimIds.Csip15, EArkClaimIds.Csip16
    ];

    /// <summary>The requirements <see cref="CheckDescriptiveMetadataSections"/> issues, <c>CSIP17</c>…<c>CSIP30</c>.</summary>
    public static IReadOnlyList<ClaimId> DescriptiveMetadataClaimIds { get; } =
    [
        EArkClaimIds.Csip17, EArkClaimIds.Csip18, EArkClaimIds.Csip19, EArkClaimIds.Csip20,
        EArkClaimIds.Csip21, EArkClaimIds.Csip22, EArkClaimIds.Csip23, EArkClaimIds.Csip24,
        EArkClaimIds.Csip25, EArkClaimIds.Csip26, EArkClaimIds.Csip27, EArkClaimIds.Csip28,
        EArkClaimIds.Csip29, EArkClaimIds.Csip30
    ];

    /// <summary>The requirements <see cref="CheckAdministrativeMetadata"/> issues, <c>CSIP31</c>…<c>CSIP57</c>.</summary>
    public static IReadOnlyList<ClaimId> AdministrativeMetadataClaimIds { get; } =
    [
        EArkClaimIds.Csip31, EArkClaimIds.Csip32, EArkClaimIds.Csip33, EArkClaimIds.Csip34,
        EArkClaimIds.Csip35, EArkClaimIds.Csip36, EArkClaimIds.Csip37, EArkClaimIds.Csip38,
        EArkClaimIds.Csip39, EArkClaimIds.Csip40, EArkClaimIds.Csip41, EArkClaimIds.Csip42,
        EArkClaimIds.Csip43, EArkClaimIds.Csip44, EArkClaimIds.Csip45, EArkClaimIds.Csip46,
        EArkClaimIds.Csip47, EArkClaimIds.Csip48, EArkClaimIds.Csip49, EArkClaimIds.Csip50,
        EArkClaimIds.Csip51, EArkClaimIds.Csip52, EArkClaimIds.Csip53, EArkClaimIds.Csip54,
        EArkClaimIds.Csip55, EArkClaimIds.Csip56, EArkClaimIds.Csip57
    ];

    /// <summary>The requirements <see cref="CheckFileSection"/> issues, <c>CSIP58</c>…<c>CSIP79</c> with <c>CSIP113</c> and <c>CSIP114</c>.</summary>
    public static IReadOnlyList<ClaimId> FileSectionClaimIds { get; } =
    [
        EArkClaimIds.Csip58, EArkClaimIds.Csip59, EArkClaimIds.Csip60, EArkClaimIds.Csip113,
        EArkClaimIds.Csip114, EArkClaimIds.Csip61, EArkClaimIds.Csip62, EArkClaimIds.Csip63,
        EArkClaimIds.Csip64, EArkClaimIds.Csip65, EArkClaimIds.Csip66, EArkClaimIds.Csip67,
        EArkClaimIds.Csip68, EArkClaimIds.Csip69, EArkClaimIds.Csip70, EArkClaimIds.Csip71,
        EArkClaimIds.Csip72, EArkClaimIds.Csip73, EArkClaimIds.Csip74, EArkClaimIds.Csip75,
        EArkClaimIds.Csip76, EArkClaimIds.Csip77, EArkClaimIds.Csip78, EArkClaimIds.Csip79
    ];

    /// <summary>The requirements <see cref="CheckStructuralMap"/> issues, <c>CSIP80</c>…<c>CSIP112</c> with <c>CSIP116</c>, <c>CSIP118</c> and <c>CSIP119</c>.</summary>
    public static IReadOnlyList<ClaimId> StructuralMapClaimIds { get; } =
    [
        EArkClaimIds.Csip80, EArkClaimIds.Csip81, EArkClaimIds.Csip82, EArkClaimIds.Csip83,
        EArkClaimIds.Csip84, EArkClaimIds.Csip85, EArkClaimIds.Csip88, EArkClaimIds.Csip89,
        EArkClaimIds.Csip90, EArkClaimIds.Csip91, EArkClaimIds.Csip92, EArkClaimIds.Csip93,
        EArkClaimIds.Csip94, EArkClaimIds.Csip95, EArkClaimIds.Csip96, EArkClaimIds.Csip116,
        EArkClaimIds.Csip97, EArkClaimIds.Csip98, EArkClaimIds.Csip99, EArkClaimIds.Csip100,
        EArkClaimIds.Csip118, EArkClaimIds.Csip101, EArkClaimIds.Csip102, EArkClaimIds.Csip103,
        EArkClaimIds.Csip104, EArkClaimIds.Csip119, EArkClaimIds.Csip105, EArkClaimIds.Csip106,
        EArkClaimIds.Csip107, EArkClaimIds.Csip108, EArkClaimIds.Csip109, EArkClaimIds.Csip110,
        EArkClaimIds.Csip111, EArkClaimIds.Csip112
    ];


    /// <summary>
    /// Checks the manifest's root element, <c>CSIP1</c>…<c>CSIP6</c>: the package identifier, the content
    /// category and its spelled-out form, the content information type and its spelled-out form, and the
    /// profile the package claims.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim per requirement of <see cref="MetsRootElementClaimIds"/>.</returns>
    /// <remarks>
    /// <c>CSIP3</c> and <c>CSIP5</c> bind only when the value they qualify says the vocabulary does not name
    /// what the package is, so a package that named itself from the vocabulary reaches them not-applicable.
    /// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 METS Profile</see>.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckMetsRootElement(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        MetsDocument? manifest = context.PackageManifest;
        if(manifest is null)
        {
            return ValueTask.FromResult(NotSuppliedFor(MetsRootElementClaimIds, "the package manifest"));
        }

        bool categoryIsOther = string.Equals(manifest.ContentCategory, MetsWellKnown.OtherContentCategory, StringComparison.Ordinal);
        bool informationTypeIsOther = string.Equals(manifest.ContentInformationType, MetsWellKnown.OtherContentInformationType, StringComparison.Ordinal);

        return ValueTask.FromResult<List<Claim>>(
        [
            Mandatory(EArkClaimIds.Csip1, !string.IsNullOrEmpty(manifest.ObjectIdentifier), "mets/@OBJID"),
            Mandatory(EArkClaimIds.Csip2, !string.IsNullOrEmpty(manifest.ContentCategory), "mets/@TYPE"),
            Conditional(EArkClaimIds.Csip3, categoryIsOther, !string.IsNullOrEmpty(manifest.OtherContentCategory), "mets/@csip:OTHERTYPE", recommendation: true),
            Recommended(EArkClaimIds.Csip4, !string.IsNullOrEmpty(manifest.ContentInformationType), "mets/@csip:CONTENTINFORMATIONTYPE"),
            Conditional(EArkClaimIds.Csip5, informationTypeIsOther, !string.IsNullOrEmpty(manifest.OtherContentInformationType), "mets/@csip:OTHERCONTENTINFORMATIONTYPE", optional: true),
            Mandatory(EArkClaimIds.Csip6, !string.IsNullOrEmpty(manifest.Profile), "mets/@PROFILE")
        ]);
    }


    /// <summary>
    /// Checks the manifest's header, <c>CSIP117</c> and <c>CSIP7</c>…<c>CSIP16</c>: the header itself, its two
    /// datetimes, the package type, and the closed-form agent stamp naming the software that made the package.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim per requirement of <see cref="MetsHeaderClaimIds"/>.</returns>
    /// <remarks>
    /// <c>CSIP10</c> together with <c>CSIP11</c>…<c>CSIP16</c> amounts to one mandatory agent carrying a fixed
    /// role, a fixed type, a fixed other-type, a name and a note classified as the software's version — a
    /// closed "who made this" stamp rather than four independent attributes, and it is judged as one.
    /// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 METS Profile</see>.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckMetsHeader(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        MetsDocument? manifest = context.PackageManifest;
        if(manifest is null)
        {
            return ValueTask.FromResult(NotSuppliedFor(MetsHeaderClaimIds, "the package manifest"));
        }

        MetsHeader header = manifest.Header;
        IReadOnlyList<MetsAgent> agents = header.Agents;

        MetsAgent? creator = null;
        for(int i = 0; i < agents.Count; ++i)
        {
            if(string.Equals(agents[i].Role, MetsWellKnown.CreatorAgentRole, StringComparison.Ordinal))
            {
                creator = agents[i];
                break;
            }
        }

        bool creatorTypeIsOther = creator is not null
            && string.Equals(creator.Type, MetsWellKnown.OtherAgentType, StringComparison.Ordinal);
        bool creatorOtherTypeIsSoftware = creator is not null
            && string.Equals(creator.OtherType, MetsWellKnown.SoftwareAgentOtherType, StringComparison.Ordinal);
        bool creatorHasName = !string.IsNullOrEmpty(creator?.Name);
        bool creatorHasNote = creator is not null && creator.Notes.Count > 0;

        bool creatorHasVersionNote = false;
        if(creator is not null)
        {
            for(int i = 0; i < creator.Notes.Count; ++i)
            {
                if(string.Equals(creator.Notes[i].NoteType, MetsWellKnown.SoftwareVersionNoteType, StringComparison.Ordinal)
                    && !string.IsNullOrEmpty(creator.Notes[i].Text))
                {
                    creatorHasVersionNote = true;
                    break;
                }
            }
        }

        return ValueTask.FromResult<List<Claim>>(
        [
            Mandatory(EArkClaimIds.Csip117, true, "mets/metsHdr, which the manifest model cannot omit"),
            Mandatory(EArkClaimIds.Csip7, true, "mets/metsHdr/@CREATEDATE, which the manifest model carries as a date and a time"),
            Recommended(EArkClaimIds.Csip8, header.LastModificationDate is not null, "mets/metsHdr/@LASTMODDATE"),
            Mandatory(EArkClaimIds.Csip9, MetsWellKnown.IsOaisPackageType(header.OaisPackageType), "mets/metsHdr/@csip:OAISPACKAGETYPE"),
            Mandatory(EArkClaimIds.Csip10, agents.Count > 0, "mets/metsHdr/agent"),
            Mandatory(EArkClaimIds.Csip11, creator is not null, "mets/metsHdr/agent[@ROLE='CREATOR']"),
            Mandatory(EArkClaimIds.Csip12, creatorTypeIsOther, "mets/metsHdr/agent[@TYPE='OTHER']"),
            Mandatory(EArkClaimIds.Csip13, creatorOtherTypeIsSoftware, "mets/metsHdr/agent[@OTHERTYPE='SOFTWARE']"),
            Mandatory(EArkClaimIds.Csip14, creatorHasName, "mets/metsHdr/agent/name"),
            Mandatory(EArkClaimIds.Csip15, creatorHasNote, "mets/metsHdr/agent/note"),
            Mandatory(EArkClaimIds.Csip16, creatorHasVersionNote, "mets/metsHdr/agent/note[@csip:NOTETYPE='SOFTWARE VERSION']")
        ]);
    }


    /// <summary>
    /// Checks the manifest's descriptive metadata sections, <c>CSIP17</c>…<c>CSIP30</c>: the sections
    /// themselves, their identifiers, datetimes and status, and the shape of the reference each one makes to
    /// the document it describes.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim per requirement of <see cref="DescriptiveMetadataClaimIds"/>.</returns>
    /// <remarks>
    /// The catalogue states the reference rows as mandatory <em>once the reference is present</em>, and the
    /// reference itself is only recommended, so a package carrying no sections and a package whose sections
    /// carry no reference both reach the rows below not-applicable rather than failed.
    /// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 METS Profile</see>.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckDescriptiveMetadataSections(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        MetsDocument? manifest = context.PackageManifest;
        if(manifest is null)
        {
            return ValueTask.FromResult(NotSuppliedFor(DescriptiveMetadataClaimIds, "the package manifest"));
        }

        IReadOnlyList<MetsDescriptiveMetadataSection> sections = manifest.DescriptiveMetadataSections;
        bool anySection = sections.Count > 0;

        bool everyIdIsNCName = true;
        bool everyStatusStated = true;
        bool everySectionReferences = true;
        var references = new List<MetsMetadataReference>(sections.Count);
        for(int i = 0; i < sections.Count; ++i)
        {
            MetsDescriptiveMetadataSection section = sections[i];
            everyIdIsNCName &= MetsWellKnown.IsNCName(section.Id);
            everyStatusStated &= !string.IsNullOrEmpty(section.Status);
            if(section.Reference is null)
            {
                everySectionReferences = false;
            }
            else
            {
                references.Add(section.Reference);
            }
        }

        var claims = new List<Claim>(DescriptiveMetadataClaimIds.Count)
        {
            Recommended(EArkClaimIds.Csip17, anySection, "mets/dmdSec"),
            Conditional(EArkClaimIds.Csip18, anySection, everyIdIsNCName, "mets/dmdSec/@ID"),
            Conditional(EArkClaimIds.Csip19, anySection, true, "mets/dmdSec/@CREATED, which the manifest model cannot omit"),
            Conditional(EArkClaimIds.Csip20, anySection, everyStatusStated, "mets/dmdSec/@STATUS", recommendation: true),
            Conditional(EArkClaimIds.Csip21, anySection, everySectionReferences, "mets/dmdSec/mdRef", recommendation: true)
        };

        AddMetadataReferenceClaims(
            claims,
            references,
            "mets/dmdSec/mdRef",
            EArkClaimIds.Csip22, EArkClaimIds.Csip23, EArkClaimIds.Csip24, EArkClaimIds.Csip25,
            EArkClaimIds.Csip26, EArkClaimIds.Csip27, EArkClaimIds.Csip28, EArkClaimIds.Csip29,
            EArkClaimIds.Csip30);

        return ValueTask.FromResult(claims);
    }


    /// <summary>
    /// Checks the manifest's administrative metadata, <c>CSIP31</c>…<c>CSIP57</c>: the section itself, the
    /// digital-provenance sub-sections through which preservation metadata is moored to the manifest, and the
    /// rights sub-sections.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim per requirement of <see cref="AdministrativeMetadataClaimIds"/>.</returns>
    /// <remarks>
    /// The two sub-sections repeat the same nine reference rows, which is why they are judged by one helper
    /// rather than by two transcriptions of the same rule. The catalogue gives no requirements at all for the
    /// technical and source sub-sections the base encoding also defines, so nothing here judges them.
    /// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 METS Profile</see>.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckAdministrativeMetadata(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        MetsDocument? manifest = context.PackageManifest;
        if(manifest is null)
        {
            return ValueTask.FromResult(NotSuppliedFor(AdministrativeMetadataClaimIds, "the package manifest"));
        }

        MetsAdministrativeMetadata? administrative = manifest.AdministrativeMetadata;
        IReadOnlyList<MetsAdministrativeMetadataSection> provenance =
            administrative?.DigitalProvenanceSections ?? [];
        IReadOnlyList<MetsAdministrativeMetadataSection> rights =
            administrative?.RightsSections ?? [];

        var claims = new List<Claim>(AdministrativeMetadataClaimIds.Count)
        {
            Recommended(EArkClaimIds.Csip31, administrative is not null, "mets/amdSec")
        };

        AddAdministrativeSectionClaims(
            claims,
            provenance,
            "mets/amdSec/digiprovMD",
            sectionPresence: EArkClaimIds.Csip32,
            sectionPresenceIsRecommendation: true,
            identifier: EArkClaimIds.Csip33,
            status: EArkClaimIds.Csip34,
            reference: EArkClaimIds.Csip35,
            EArkClaimIds.Csip36, EArkClaimIds.Csip37, EArkClaimIds.Csip38, EArkClaimIds.Csip39,
            EArkClaimIds.Csip40, EArkClaimIds.Csip41, EArkClaimIds.Csip42, EArkClaimIds.Csip43,
            EArkClaimIds.Csip44);

        AddAdministrativeSectionClaims(
            claims,
            rights,
            "mets/amdSec/rightsMD",
            sectionPresence: EArkClaimIds.Csip45,
            sectionPresenceIsRecommendation: false,
            identifier: EArkClaimIds.Csip46,
            status: EArkClaimIds.Csip47,
            reference: EArkClaimIds.Csip48,
            EArkClaimIds.Csip49, EArkClaimIds.Csip50, EArkClaimIds.Csip51, EArkClaimIds.Csip52,
            EArkClaimIds.Csip53, EArkClaimIds.Csip54, EArkClaimIds.Csip55, EArkClaimIds.Csip56,
            EArkClaimIds.Csip57);

        return ValueTask.FromResult(claims);
    }


    /// <summary>
    /// Checks the manifest's file section, <c>CSIP58</c>…<c>CSIP79</c> with <c>CSIP113</c> and
    /// <c>CSIP114</c>: the section itself, the three mandatory file groups, and the shape every file entry
    /// takes — identifier, media type, size, datetime, the fixity pair and one locator.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim per requirement of <see cref="FileSectionClaimIds"/>.</returns>
    /// <remarks>
    /// <para>
    /// This section is the package's fixity manifest: <c>CSIP71</c> and <c>CSIP72</c> require every file entry
    /// to carry a checksum and the name of the algorithm it was computed under. Whether that value is right —
    /// and whether the algorithm is one worth believing — is not asked here but by the recomputation rule,
    /// which is this library's own obligation rather than the catalogue's.
    /// </para>
    /// <para>
    /// <strong><c>CSIP62</c>'s condition is a disjunction, and both disjuncts are read.</strong> The catalogue
    /// states the antecedent as "when the element 'Content Information Type Specification' (<c>CSIP4</c>) has
    /// the value 'MIXED' or the file group describes a representation", and restates the second disjunct on its
    /// own as a stronger obligation on a file group whose use begins with the representations label. Its
    /// location is the union of the two. Gating the row on the package-level value alone would answer every
    /// package that is not mixed with a row nothing triggered, however bare its representations groups are.
    /// </para>
    /// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 METS Profile</see>.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckFileSection(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        MetsDocument? manifest = context.PackageManifest;
        if(manifest is null)
        {
            return ValueTask.FromResult(NotSuppliedFor(FileSectionClaimIds, "the package manifest"));
        }

        MetsFileSection? fileSection = manifest.FileSection;
        bool hasFileSection = fileSection is not null;
        IReadOnlyList<MetsFileGroup> groups = fileSection?.FileGroups ?? [];

        bool hasDocumentationGroup = false;
        bool hasSchemasGroup = false;
        bool hasRepresentationsGroup = false;
        bool anyGroupReferencesAdministrative = false;
        bool everyRepresentationGroupStatesInformationType = true;
        bool everyOtherInformationTypeSpelledOut = true;
        bool anyOtherInformationType = false;
        bool everyGroupUseStated = true;
        bool everyGroupIdIsNCName = true;
        bool everyGroupHasFiles = true;
        var files = new List<MetsFile>();
        for(int i = 0; i < groups.Count; ++i)
        {
            MetsFileGroup group = groups[i];
            hasDocumentationGroup |= string.Equals(group.Use, MetsWellKnown.DocumentationLabel, StringComparison.Ordinal);
            hasSchemasGroup |= string.Equals(group.Use, MetsWellKnown.SchemasLabel, StringComparison.Ordinal);

            bool isRepresentationGroup = MetsWellKnown.IsRepresentationLabel(group.Use);
            hasRepresentationsGroup |= isRepresentationGroup;
            anyGroupReferencesAdministrative |= group.AdministrativeMetadataIds.Count > 0;
            if(isRepresentationGroup)
            {
                everyRepresentationGroupStatesInformationType &= !string.IsNullOrEmpty(group.ContentInformationType);
            }

            if(string.Equals(group.ContentInformationType, MetsWellKnown.OtherContentInformationType, StringComparison.Ordinal))
            {
                anyOtherInformationType = true;
                everyOtherInformationTypeSpelledOut &= !string.IsNullOrEmpty(group.OtherContentInformationType);
            }

            everyGroupUseStated &= !string.IsNullOrEmpty(group.Use);
            everyGroupIdIsNCName &= MetsWellKnown.IsNCName(group.Id);
            everyGroupHasFiles &= group.Files.Count > 0;
            for(int fileIndex = 0; fileIndex < group.Files.Count; ++fileIndex)
            {
                files.Add(group.Files[fileIndex]);
            }
        }

        bool everyFileIdIsNCName = true;
        bool everyFileMediaTypeStated = true;
        bool everyFileSizeStated = true;
        bool everyFileStatesChecksum = true;
        bool everyFileStatesChecksumType = true;
        bool anyFileOwnerId = false;
        bool anyFileAdministrativeReference = false;
        bool anyFileDescriptiveReference = false;
        bool everyLocatorTypeIsUrl = true;
        bool everyLinkTypeIsSimple = true;
        bool everyLocatorHrefStated = true;
        for(int i = 0; i < files.Count; ++i)
        {
            MetsFile file = files[i];
            everyFileIdIsNCName &= MetsWellKnown.IsNCName(file.Id);
            everyFileMediaTypeStated &= !string.IsNullOrEmpty(file.MediaType);
            everyFileSizeStated &= file.Size >= 0;
            everyFileStatesChecksum &= StatesChecksum(file.Fixity);
            everyFileStatesChecksumType &= StatesChecksumType(file.Fixity);
            anyFileOwnerId |= !string.IsNullOrEmpty(file.OwnerId);
            anyFileAdministrativeReference |= file.AdministrativeMetadataIds.Count > 0;
            anyFileDescriptiveReference |= file.DescriptiveMetadataIds.Count > 0;
            everyLocatorTypeIsUrl &= string.Equals(file.Locator.LocatorType, MetsWellKnown.UrlLocatorType, StringComparison.Ordinal);
            everyLinkTypeIsSimple &= string.Equals(file.Locator.LinkType, MetsWellKnown.SimpleLinkType, StringComparison.Ordinal);
            everyLocatorHrefStated &= !string.IsNullOrEmpty(file.Locator.Href);
        }

        bool packageIsMixed = string.Equals(manifest.ContentInformationType, MetsWellKnown.MixedContentInformationType, StringComparison.Ordinal);
        bool anyFile = files.Count > 0;

        return ValueTask.FromResult<List<Claim>>(
        [
            Recommended(EArkClaimIds.Csip58, hasFileSection, "mets/fileSec"),
            Conditional(EArkClaimIds.Csip59, hasFileSection, MetsWellKnown.IsNCName(fileSection?.Id), "mets/fileSec/@ID"),
            Conditional(EArkClaimIds.Csip60, hasFileSection, hasDocumentationGroup, "mets/fileSec/fileGrp[@USE='Documentation']"),
            Conditional(EArkClaimIds.Csip113, hasFileSection, hasSchemasGroup, "mets/fileSec/fileGrp[@USE='Schemas']"),
            Conditional(EArkClaimIds.Csip114, hasFileSection, hasRepresentationsGroup, "mets/fileSec/fileGrp[@USE starting with 'Representations']"),
            Optional(EArkClaimIds.Csip61, anyGroupReferencesAdministrative, "mets/fileSec/fileGrp/@ADMID"),
            Conditional(EArkClaimIds.Csip62, packageIsMixed || hasRepresentationsGroup, everyRepresentationGroupStatesInformationType, "mets/fileSec/fileGrp/@csip:CONTENTINFORMATIONTYPE", recommendation: true),
            Conditional(EArkClaimIds.Csip63, anyOtherInformationType, everyOtherInformationTypeSpelledOut, "mets/fileSec/fileGrp/@csip:OTHERCONTENTINFORMATIONTYPE", optional: true),
            Conditional(EArkClaimIds.Csip64, groups.Count > 0, everyGroupUseStated, "mets/fileSec/fileGrp/@USE"),
            Conditional(EArkClaimIds.Csip65, groups.Count > 0, everyGroupIdIsNCName, "mets/fileSec/fileGrp/@ID"),
            Conditional(EArkClaimIds.Csip66, groups.Count > 0, everyGroupHasFiles, "mets/fileSec/fileGrp/file"),
            Conditional(EArkClaimIds.Csip67, anyFile, everyFileIdIsNCName, "mets/fileSec/fileGrp/file/@ID"),
            Conditional(EArkClaimIds.Csip68, anyFile, everyFileMediaTypeStated, "mets/fileSec/fileGrp/file/@MIMETYPE"),
            Conditional(EArkClaimIds.Csip69, anyFile, everyFileSizeStated, "mets/fileSec/fileGrp/file/@SIZE"),
            Conditional(EArkClaimIds.Csip70, anyFile, true, "mets/fileSec/fileGrp/file/@CREATED, which the manifest model cannot omit"),
            Conditional(EArkClaimIds.Csip71, anyFile, everyFileStatesChecksum, "mets/fileSec/fileGrp/file/@CHECKSUM"),
            Conditional(EArkClaimIds.Csip72, anyFile, everyFileStatesChecksumType, "mets/fileSec/fileGrp/file/@CHECKSUMTYPE"),
            Optional(EArkClaimIds.Csip73, anyFileOwnerId, "mets/fileSec/fileGrp/file/@OWNERID"),
            Optional(EArkClaimIds.Csip74, anyFileAdministrativeReference, "mets/fileSec/fileGrp/file/@ADMID"),
            Optional(EArkClaimIds.Csip75, anyFileDescriptiveReference, "mets/fileSec/fileGrp/file/@DMDID"),
            Conditional(EArkClaimIds.Csip76, anyFile, true, "mets/fileSec/fileGrp/file/FLocat, which the manifest model cannot omit"),
            Conditional(EArkClaimIds.Csip77, anyFile, everyLocatorTypeIsUrl, "mets/fileSec/fileGrp/file/FLocat[@LOCTYPE='URL']"),
            Conditional(EArkClaimIds.Csip78, anyFile, everyLinkTypeIsSimple, "mets/fileSec/fileGrp/file/FLocat[@xlink:type='simple']"),
            Conditional(EArkClaimIds.Csip79, anyFile, everyLocatorHrefStated, "mets/fileSec/fileGrp/file/FLocat/@xlink:href")
        ]);
    }


    /// <summary>
    /// Checks the manifest's structural map, <c>CSIP80</c>…<c>CSIP112</c> with <c>CSIP116</c>,
    /// <c>CSIP118</c> and <c>CSIP119</c>: the map the specification mandates, its four named divisions, the
    /// file pointers each carries, and the pointer chain from the package to each representation's own
    /// manifest.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim per requirement of <see cref="StructuralMapClaimIds"/>.</returns>
    /// <remarks>
    /// The mandated map is found by its label rather than by position, which the specification asks for
    /// outright so that a package may carry structural maps of its own beside it without colliding. When the
    /// package carries no such map, the two rows that require one fail and the rows about its contents are
    /// not-applicable — the finding is reported once rather than thirty-two times.
    /// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 METS Profile</see>.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckStructuralMap(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        MetsDocument? manifest = context.PackageManifest;
        if(manifest is null)
        {
            return ValueTask.FromResult(NotSuppliedFor(StructuralMapClaimIds, "the package manifest"));
        }

        IReadOnlyList<MetsStructuralMap> maps = manifest.StructuralMaps;
        MetsStructuralMap? mandated = null;
        for(int i = 0; i < maps.Count; ++i)
        {
            if(string.Equals(maps[i].Label, MetsWellKnown.CsipStructuralMapLabel, StringComparison.Ordinal))
            {
                mandated = maps[i];
                break;
            }
        }

        var claims = new List<Claim>(StructuralMapClaimIds.Count)
        {
            Mandatory(EArkClaimIds.Csip80, maps.Count > 0, "mets/structMap"),
            Mandatory(EArkClaimIds.Csip81, mandated is not null && string.Equals(mandated.Type, MetsWellKnown.PhysicalStructuralMapType, StringComparison.Ordinal), "mets/structMap[@TYPE='PHYSICAL']"),
            Mandatory(EArkClaimIds.Csip82, mandated is not null, "mets/structMap[@LABEL='CSIP']")
        };

        if(mandated is null)
        {
            AddNotApplicableFor(
                claims,
                "the structural map the specification mandates",
                EArkClaimIds.Csip83, EArkClaimIds.Csip84, EArkClaimIds.Csip85, EArkClaimIds.Csip88,
                EArkClaimIds.Csip89, EArkClaimIds.Csip90, EArkClaimIds.Csip91, EArkClaimIds.Csip92,
                EArkClaimIds.Csip93, EArkClaimIds.Csip94, EArkClaimIds.Csip95, EArkClaimIds.Csip96,
                EArkClaimIds.Csip116, EArkClaimIds.Csip97, EArkClaimIds.Csip98, EArkClaimIds.Csip99,
                EArkClaimIds.Csip100, EArkClaimIds.Csip118, EArkClaimIds.Csip101, EArkClaimIds.Csip102,
                EArkClaimIds.Csip103, EArkClaimIds.Csip104, EArkClaimIds.Csip119, EArkClaimIds.Csip105,
                EArkClaimIds.Csip106, EArkClaimIds.Csip107, EArkClaimIds.Csip108, EArkClaimIds.Csip109,
                EArkClaimIds.Csip110, EArkClaimIds.Csip111, EArkClaimIds.Csip112);

            return ValueTask.FromResult(claims);
        }

        MetsDivision root = mandated.RootDivision;
        MetsDivision? metadata = FindDivision(root, MetsWellKnown.MetadataLabel);
        MetsDivision? documentation = FindDivision(root, MetsWellKnown.DocumentationLabel);
        MetsDivision? schemas = FindDivision(root, MetsWellKnown.SchemasLabel);
        MetsDivision? representations = FindDivision(root, MetsWellKnown.RepresentationsLabel);

        var representationDivisions = new List<MetsDivision>(root.Divisions.Count);
        for(int i = 0; i < root.Divisions.Count; ++i)
        {
            if(MetsWellKnown.IsRepresentationLabel(root.Divisions[i].Label))
            {
                representationDivisions.Add(root.Divisions[i]);
            }
        }

        bool anyRepresentationDivision = representationDivisions.Count > 0;
        bool everyRepresentationIdIsNCName = true;
        bool everyRepresentationLabelWellFormed = true;
        bool everyRepresentationHasOnePointer = true;
        bool everyPointerTitled = true;
        bool everyPointerHrefStated = true;
        bool everyPointerLinkTypeIsSimple = true;
        bool everyPointerLocatorTypeIsUrl = true;
        for(int i = 0; i < representationDivisions.Count; ++i)
        {
            MetsDivision division = representationDivisions[i];
            everyRepresentationIdIsNCName &= MetsWellKnown.IsNCName(division.Id);
            everyRepresentationLabelWellFormed &= MetsWellKnown.IsRepresentationLabel(division.Label);
            everyRepresentationHasOnePointer &= division.MetsPointers.Count == 1;
            for(int pointerIndex = 0; pointerIndex < division.MetsPointers.Count; ++pointerIndex)
            {
                MetsPointer pointer = division.MetsPointers[pointerIndex];
                everyPointerTitled &= !string.IsNullOrEmpty(pointer.Title);
                everyPointerHrefStated &= !string.IsNullOrEmpty(pointer.Href);
                everyPointerLinkTypeIsSimple &= string.Equals(pointer.LinkType, MetsWellKnown.SimpleLinkType, StringComparison.Ordinal);
                everyPointerLocatorTypeIsUrl &= string.Equals(pointer.LocatorType, MetsWellKnown.UrlLocatorType, StringComparison.Ordinal);
            }
        }

        claims.Add(Mandatory(EArkClaimIds.Csip83, MetsWellKnown.IsNCName(mandated.Id), "mets/structMap[@LABEL='CSIP']/@ID"));
        claims.Add(Mandatory(EArkClaimIds.Csip84, true, "the map's single root division, which the manifest model cannot omit"));
        claims.Add(Mandatory(EArkClaimIds.Csip85, MetsWellKnown.IsNCName(root.Id), "the root division's @ID"));

        AddDivisionClaims(claims, metadata, MetsWellKnown.MetadataLabel,
            presence: EArkClaimIds.Csip88, presenceIsRecommendation: false,
            identifier: EArkClaimIds.Csip89, label: EArkClaimIds.Csip90);
        claims.Add(Conditional(EArkClaimIds.Csip91, metadata is not null, metadata?.AdministrativeMetadataIds.Count > 0, "the metadata division's @ADMID", recommendation: true));
        claims.Add(Conditional(EArkClaimIds.Csip92, metadata is not null, metadata?.DescriptiveMetadataIds.Count > 0, "the metadata division's @DMDID", recommendation: true));

        AddDivisionClaims(claims, documentation, MetsWellKnown.DocumentationLabel,
            presence: EArkClaimIds.Csip93, presenceIsRecommendation: true,
            identifier: EArkClaimIds.Csip94, label: EArkClaimIds.Csip95);
        AddFilePointerClaims(claims, documentation, "the documentation division's fptr", EArkClaimIds.Csip96, EArkClaimIds.Csip116);

        AddDivisionClaims(claims, schemas, MetsWellKnown.SchemasLabel,
            presence: EArkClaimIds.Csip97, presenceIsRecommendation: true,
            identifier: EArkClaimIds.Csip98, label: EArkClaimIds.Csip99);
        AddFilePointerClaims(claims, schemas, "the schema division's fptr", EArkClaimIds.Csip100, EArkClaimIds.Csip118);

        AddDivisionClaims(claims, representations, MetsWellKnown.RepresentationsLabel,
            presence: EArkClaimIds.Csip101, presenceIsRecommendation: true,
            identifier: EArkClaimIds.Csip102, label: EArkClaimIds.Csip103);
        AddFilePointerClaims(claims, representations, "the content division's fptr", EArkClaimIds.Csip104, EArkClaimIds.Csip119);

        claims.Add(Recommended(EArkClaimIds.Csip105, anyRepresentationDivision, "a division per representation"));
        claims.Add(Conditional(EArkClaimIds.Csip106, anyRepresentationDivision, everyRepresentationIdIsNCName, "each representation division's @ID"));
        claims.Add(Conditional(EArkClaimIds.Csip107, anyRepresentationDivision, everyRepresentationLabelWellFormed, "each representation division's @LABEL"));
        claims.Add(Conditional(EArkClaimIds.Csip108, anyRepresentationDivision, everyPointerTitled, "each representation pointer's @xlink:title"));
        claims.Add(Conditional(EArkClaimIds.Csip109, anyRepresentationDivision, everyRepresentationHasOnePointer, "exactly one mptr per representation division"));
        claims.Add(Conditional(EArkClaimIds.Csip110, anyRepresentationDivision, everyPointerHrefStated, "each representation pointer's @xlink:href"));
        claims.Add(Conditional(EArkClaimIds.Csip111, anyRepresentationDivision, everyPointerLinkTypeIsSimple, "each representation pointer's @xlink:type"));
        claims.Add(Conditional(EArkClaimIds.Csip112, anyRepresentationDivision, everyPointerLocatorTypeIsUrl, "each representation pointer's @LOCTYPE"));

        return ValueTask.FromResult(claims);
    }


    /// <summary>The requirement <see cref="CheckPreservationMetadataRoot"/> issues, <c>PM1</c>.</summary>
    public static IReadOnlyList<ClaimId> PreservationRootClaimIds { get; } = [PremisClaimIds.Pm1];

    /// <summary>The requirements <see cref="CheckPreservationIntellectualEntities"/> issues, <c>PM2</c>…<c>PM13</c>.</summary>
    public static IReadOnlyList<ClaimId> PreservationIntellectualEntityClaimIds { get; } =
    [
        PremisClaimIds.Pm2, PremisClaimIds.Pm3, PremisClaimIds.Pm4, PremisClaimIds.Pm5,
        PremisClaimIds.Pm6, PremisClaimIds.Pm7, PremisClaimIds.Pm8, PremisClaimIds.Pm9,
        PremisClaimIds.Pm10, PremisClaimIds.Pm11, PremisClaimIds.Pm12, PremisClaimIds.Pm13
    ];

    /// <summary>The requirements <see cref="CheckPreservationRepresentations"/> issues, <c>PM14</c>…<c>PM27</c>.</summary>
    public static IReadOnlyList<ClaimId> PreservationRepresentationClaimIds { get; } =
    [
        PremisClaimIds.Pm14, PremisClaimIds.Pm15, PremisClaimIds.Pm16, PremisClaimIds.Pm17,
        PremisClaimIds.Pm18, PremisClaimIds.Pm19, PremisClaimIds.Pm20, PremisClaimIds.Pm21,
        PremisClaimIds.Pm22, PremisClaimIds.Pm23, PremisClaimIds.Pm24, PremisClaimIds.Pm25,
        PremisClaimIds.Pm26, PremisClaimIds.Pm27
    ];

    /// <summary>The requirements <see cref="CheckPreservationFiles"/> issues, <c>PM28</c>…<c>PM68</c>.</summary>
    public static IReadOnlyList<ClaimId> PreservationFileClaimIds { get; } =
    [
        PremisClaimIds.Pm28, PremisClaimIds.Pm29, PremisClaimIds.Pm30, PremisClaimIds.Pm31,
        PremisClaimIds.Pm32, PremisClaimIds.Pm33, PremisClaimIds.Pm34, PremisClaimIds.Pm35,
        PremisClaimIds.Pm36, PremisClaimIds.Pm37, PremisClaimIds.Pm38, PremisClaimIds.Pm39,
        PremisClaimIds.Pm40, PremisClaimIds.Pm41, PremisClaimIds.Pm42, PremisClaimIds.Pm43,
        PremisClaimIds.Pm44, PremisClaimIds.Pm45, PremisClaimIds.Pm46, PremisClaimIds.Pm47,
        PremisClaimIds.Pm48, PremisClaimIds.Pm49, PremisClaimIds.Pm50, PremisClaimIds.Pm51,
        PremisClaimIds.Pm52, PremisClaimIds.Pm53, PremisClaimIds.Pm54, PremisClaimIds.Pm55,
        PremisClaimIds.Pm56, PremisClaimIds.Pm57, PremisClaimIds.Pm58, PremisClaimIds.Pm59,
        PremisClaimIds.Pm60, PremisClaimIds.Pm61, PremisClaimIds.Pm62, PremisClaimIds.Pm63,
        PremisClaimIds.Pm64, PremisClaimIds.Pm65, PremisClaimIds.Pm66, PremisClaimIds.Pm67,
        PremisClaimIds.Pm68
    ];

    /// <summary>The requirements <see cref="CheckPreservationAgents"/> issues, <c>PM69</c>…<c>PM79</c>.</summary>
    public static IReadOnlyList<ClaimId> PreservationAgentClaimIds { get; } =
    [
        PremisClaimIds.Pm69, PremisClaimIds.Pm70, PremisClaimIds.Pm71, PremisClaimIds.Pm72,
        PremisClaimIds.Pm73, PremisClaimIds.Pm74, PremisClaimIds.Pm75, PremisClaimIds.Pm76,
        PremisClaimIds.Pm77, PremisClaimIds.Pm78, PremisClaimIds.Pm79
    ];

    /// <summary>The requirements <see cref="CheckPreservationEvents"/> issues, <c>PM80</c>…<c>PM92</c>.</summary>
    public static IReadOnlyList<ClaimId> PreservationEventClaimIds { get; } =
    [
        PremisClaimIds.Pm80, PremisClaimIds.Pm81, PremisClaimIds.Pm82, PremisClaimIds.Pm83,
        PremisClaimIds.Pm84, PremisClaimIds.Pm85, PremisClaimIds.Pm86, PremisClaimIds.Pm87,
        PremisClaimIds.Pm88, PremisClaimIds.Pm89, PremisClaimIds.Pm90, PremisClaimIds.Pm91,
        PremisClaimIds.Pm92
    ];

    /// <summary>The requirements <see cref="CheckPreservationRights"/> issues, <c>PM93</c>…<c>PM125</c>.</summary>
    public static IReadOnlyList<ClaimId> PreservationRightsClaimIds { get; } =
    [
        PremisClaimIds.Pm93, PremisClaimIds.Pm94, PremisClaimIds.Pm95, PremisClaimIds.Pm96,
        PremisClaimIds.Pm97, PremisClaimIds.Pm98, PremisClaimIds.Pm99, PremisClaimIds.Pm100,
        PremisClaimIds.Pm101, PremisClaimIds.Pm102, PremisClaimIds.Pm103, PremisClaimIds.Pm104,
        PremisClaimIds.Pm105, PremisClaimIds.Pm106, PremisClaimIds.Pm107, PremisClaimIds.Pm108,
        PremisClaimIds.Pm109, PremisClaimIds.Pm110, PremisClaimIds.Pm111, PremisClaimIds.Pm112,
        PremisClaimIds.Pm113, PremisClaimIds.Pm114, PremisClaimIds.Pm115, PremisClaimIds.Pm116,
        PremisClaimIds.Pm117, PremisClaimIds.Pm118, PremisClaimIds.Pm119, PremisClaimIds.Pm120,
        PremisClaimIds.Pm121, PremisClaimIds.Pm122, PremisClaimIds.Pm123, PremisClaimIds.Pm124,
        PremisClaimIds.Pm125
    ];


    /// <summary>
    /// Checks the preservation-metadata documents' root element, <c>PM1</c>: each states the version of the
    /// vocabulary it is written in.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <c>PM1</c>.</returns>
    /// <remarks>
    /// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM1</see>.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckPreservationMetadataRoot(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<PremisDocument> documents = context.PreservationMetadata;
        if(documents.Count == 0)
        {
            return ValueTask.FromResult(NotSuppliedFor(PreservationRootClaimIds, "the preservation-metadata documents"));
        }

        bool everyVersionStated = true;
        for(int i = 0; i < documents.Count; ++i)
        {
            everyVersionStated &= PremisWellKnown.IsPremisVersion(documents[i].Version);
        }

        return ValueTask.FromResult<List<Claim>>(
            [Mandatory(PremisClaimIds.Pm1, everyVersionStated, "premis/@version")]);
    }


    /// <summary>
    /// Checks the intellectual-entity objects, <c>PM2</c>…<c>PM13</c>: the object category, the identification,
    /// and the environment an entity that describes one has to describe completely.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim per requirement of <see cref="PreservationIntellectualEntityClaimIds"/>.</returns>
    /// <remarks>
    /// The catalogue heads this group <c>object[intellectualEntity/environment]</c> and then states the
    /// environment rows as mandatory, which taken flatly would fail every intellectual entity that describes
    /// no environment at all — the ordinary case. The reading here is the one the group heading gives: the
    /// environment rows bind an entity that describes an environment, and an entity that describes none
    /// reaches them not-applicable. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata
    /// v1.0.1 PM2–PM13</see>.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckPreservationIntellectualEntities(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<PremisDocument> documents = context.PreservationMetadata;
        if(documents.Count == 0)
        {
            return ValueTask.FromResult(NotSuppliedFor(PreservationIntellectualEntityClaimIds, "the preservation-metadata documents"));
        }

        bool everyCategoryRecognised = EveryObjectCategoryRecognised(documents);
        var entities = ObjectsOfCategory(documents, PremisWellKnown.IntellectualEntityObjectCategory);
        bool anyEntity = entities.Count > 0;

        bool everyEntityIdentified = true;
        bool everyIdentifierTypeStated = true;
        bool everyIdentifierValueStated = true;
        bool anyEnvironment = false;
        bool everyEnvironmentHasFunction = true;
        bool everyEnvironmentHasDesignation = true;
        bool anyFunction = false;
        bool everyFunctionTypeStated = true;
        bool everyFunctionLevelStated = true;
        bool anyDesignation = false;
        bool everyDesignationNamed = true;
        bool everyDesignationVersioned = true;
        bool everyDesignationOriginStated = true;
        bool anyDesignationNote = false;
        for(int i = 0; i < entities.Count; ++i)
        {
            PremisObject entity = entities[i];
            everyEntityIdentified &= entity.Identifiers.Count > 0;
            for(int identifierIndex = 0; identifierIndex < entity.Identifiers.Count; ++identifierIndex)
            {
                everyIdentifierTypeStated &= !string.IsNullOrEmpty(entity.Identifiers[identifierIndex].Type);
                everyIdentifierValueStated &= !string.IsNullOrEmpty(entity.Identifiers[identifierIndex].Value);
            }

            bool describesEnvironment = entity.EnvironmentFunctions.Count > 0 || entity.EnvironmentDesignation is not null;
            if(describesEnvironment)
            {
                anyEnvironment = true;
                everyEnvironmentHasFunction &= entity.EnvironmentFunctions.Count > 0;
                everyEnvironmentHasDesignation &= entity.EnvironmentDesignation is not null;
            }

            for(int functionIndex = 0; functionIndex < entity.EnvironmentFunctions.Count; ++functionIndex)
            {
                anyFunction = true;
                everyFunctionTypeStated &= !string.IsNullOrEmpty(entity.EnvironmentFunctions[functionIndex].Type);
                everyFunctionLevelStated &= !string.IsNullOrEmpty(entity.EnvironmentFunctions[functionIndex].Level);
            }

            if(entity.EnvironmentDesignation is PremisEnvironmentDesignation designation)
            {
                anyDesignation = true;
                everyDesignationNamed &= !string.IsNullOrEmpty(designation.Name);
                everyDesignationVersioned &= !string.IsNullOrEmpty(designation.Version);
                everyDesignationOriginStated &= !string.IsNullOrEmpty(designation.Origin);
                anyDesignationNote |= !string.IsNullOrEmpty(designation.Note);
            }
        }

        return ValueTask.FromResult<List<Claim>>(
        [
            Mandatory(PremisClaimIds.Pm2, everyCategoryRecognised, "object/@xsi:type against the object-category vocabulary"),
            Conditional(PremisClaimIds.Pm3, anyEntity, everyEntityIdentified, "object/objectIdentifier of each intellectual entity"),
            Conditional(PremisClaimIds.Pm4, anyEntity, everyIdentifierTypeStated, "objectIdentifier/objectIdentifierType"),
            Conditional(PremisClaimIds.Pm5, anyEntity, everyIdentifierValueStated, "objectIdentifier/objectIdentifierValue"),
            Conditional(PremisClaimIds.Pm6, anyEnvironment, everyEnvironmentHasFunction, "object/environmentFunction"),
            Conditional(PremisClaimIds.Pm7, anyFunction, everyFunctionTypeStated, "environmentFunction/environmentFunctionType"),
            Conditional(PremisClaimIds.Pm8, anyFunction, everyFunctionLevelStated, "environmentFunction/environmentFunctionLevel"),
            Conditional(PremisClaimIds.Pm9, anyEnvironment, everyEnvironmentHasDesignation, "object/environmentDesignation"),
            Conditional(PremisClaimIds.Pm10, anyDesignation, everyDesignationNamed, "environmentDesignation/environmentName"),
            Conditional(PremisClaimIds.Pm11, anyDesignation, everyDesignationVersioned, "environmentDesignation/environmentVersion", recommendation: true),
            Conditional(PremisClaimIds.Pm12, anyDesignation, everyDesignationOriginStated, "environmentDesignation/environmentOrigin", recommendation: true),
            Optional(PremisClaimIds.Pm13, anyDesignationNote, "environmentDesignation/environmentDesignationNote")
        ]);
    }


    /// <summary>
    /// Checks the representation objects, <c>PM14</c>…<c>PM27</c>: the object category, the identification, the
    /// significant properties, and the relationship a representation states to the software that renders it.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim per requirement of <see cref="PreservationRepresentationClaimIds"/>.</returns>
    /// <remarks>
    /// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM14–PM27</see>.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckPreservationRepresentations(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<PremisDocument> documents = context.PreservationMetadata;
        if(documents.Count == 0)
        {
            return ValueTask.FromResult(NotSuppliedFor(PreservationRepresentationClaimIds, "the preservation-metadata documents"));
        }

        bool everyCategoryRecognised = EveryObjectCategoryRecognised(documents);
        var representations = ObjectsOfCategory(documents, PremisWellKnown.RepresentationObjectCategory);
        bool anyRepresentation = representations.Count > 0;

        bool everyRepresentationIdentified = true;
        bool everyIdentifierTypeStated = true;
        bool everyIdentifierValueStated = true;
        bool anySignificantProperty = false;
        bool everyPropertyTypeStated = true;
        bool everyPropertyValueStated = true;
        bool everyRepresentationRelated = true;
        var relationships = new List<PremisRelationship>();
        for(int i = 0; i < representations.Count; ++i)
        {
            PremisObject representation = representations[i];
            everyRepresentationIdentified &= representation.Identifiers.Count > 0;
            for(int identifierIndex = 0; identifierIndex < representation.Identifiers.Count; ++identifierIndex)
            {
                everyIdentifierTypeStated &= !string.IsNullOrEmpty(representation.Identifiers[identifierIndex].Type);
                everyIdentifierValueStated &= !string.IsNullOrEmpty(representation.Identifiers[identifierIndex].Value);
            }

            for(int propertyIndex = 0; propertyIndex < representation.SignificantProperties.Count; ++propertyIndex)
            {
                anySignificantProperty = true;
                everyPropertyTypeStated &= !string.IsNullOrEmpty(representation.SignificantProperties[propertyIndex].Type);
                everyPropertyValueStated &= !string.IsNullOrEmpty(representation.SignificantProperties[propertyIndex].Value);
            }

            everyRepresentationRelated &= representation.Relationships.Count > 0;
            for(int relationshipIndex = 0; relationshipIndex < representation.Relationships.Count; ++relationshipIndex)
            {
                relationships.Add(representation.Relationships[relationshipIndex]);
            }
        }

        var claims = new List<Claim>(PreservationRepresentationClaimIds.Count)
        {
            Mandatory(PremisClaimIds.Pm14, everyCategoryRecognised, "object/@xsi:type against the object-category vocabulary"),
            Conditional(PremisClaimIds.Pm15, anyRepresentation, everyRepresentationIdentified, "object/objectIdentifier of each representation"),
            Conditional(PremisClaimIds.Pm16, anyRepresentation, everyIdentifierTypeStated, "objectIdentifier/objectIdentifierType"),
            Conditional(PremisClaimIds.Pm17, anyRepresentation, everyIdentifierValueStated, "objectIdentifier/objectIdentifierValue"),
            Conditional(PremisClaimIds.Pm18, anyRepresentation, anySignificantProperty, "object/significantProperties", recommendation: true),
            Conditional(PremisClaimIds.Pm19, anySignificantProperty, everyPropertyTypeStated, "significantProperties/significantPropertiesType"),
            Conditional(PremisClaimIds.Pm20, anySignificantProperty, everyPropertyValueStated, "significantProperties/significantPropertiesValue"),
            Conditional(PremisClaimIds.Pm21, anyRepresentation, everyRepresentationRelated, "object/relationship of each representation")
        };

        AddRelationshipClaims(
            claims,
            relationships,
            "a representation's relationship",
            type: PremisClaimIds.Pm22,
            subType: PremisClaimIds.Pm23,
            relatedObject: PremisClaimIds.Pm24,
            relatedObjectType: PremisClaimIds.Pm25,
            relatedObjectValue: PremisClaimIds.Pm26);

        bool anyEnvironmentPurpose = false;
        for(int i = 0; i < relationships.Count; ++i)
        {
            anyEnvironmentPurpose |= !string.IsNullOrEmpty(relationships[i].RelatedEnvironmentPurpose);
        }

        claims.Add(Conditional(PremisClaimIds.Pm27, relationships.Count > 0, anyEnvironmentPurpose, "relationship/relatedEnvironmentPurpose", recommendation: true));

        return ValueTask.FromResult(claims);
    }


    /// <summary>
    /// Checks the file objects, <c>PM28</c>…<c>PM68</c>: the object category and identification, the object
    /// characteristics with their fixity and format blocks, the storage location, the relationships to other
    /// objects and to events, and the links to rights statements.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim per requirement of <see cref="PreservationFileClaimIds"/>.</returns>
    /// <remarks>
    /// <para>
    /// Three rows have no subject in this library's model and are therefore reported as undecided rather than
    /// as met or absent: <c>PM36</c>'s fixity originator, <c>PM49</c>'s creating-application extension and
    /// <c>PM50</c>'s object-characteristics extension are elements the model does not carry, so no rule over it
    /// can answer them.
    /// </para>
    /// <para>
    /// <c>PM53</c> and <c>PM66</c> are the two rows whose keyword is <c>COULD</c>, which the specification's
    /// own conformance section does not define. They are read as MAY under the deviation policy's default and
    /// the claim says so; see <see cref="EArkValidationDeviations.UndefinedKeywordReadsAsOptional"/>.
    /// <c>PM64</c> names its element with the related-object prefix while its sibling <c>PM65</c> uses the
    /// related-event one, a transcription defect the vocabulary's own schema settles in favour of the
    /// related-event reading; the claim carries that interpretation.
    /// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM28–PM68</see>.
    /// </para>
    /// </remarks>
    public static ValueTask<List<Claim>> CheckPreservationFiles(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<PremisDocument> documents = context.PreservationMetadata;
        if(documents.Count == 0)
        {
            return ValueTask.FromResult(NotSuppliedFor(PreservationFileClaimIds, "the preservation-metadata documents"));
        }

        bool everyCategoryRecognised = EveryObjectCategoryRecognised(documents);
        var files = ObjectsOfCategory(documents, PremisWellKnown.FileObjectCategory);
        bool anyFile = files.Count > 0;

        bool everyFileIdentified = true;
        bool everyIdentifierTypeStated = true;
        bool everyIdentifierValueStated = true;
        bool everyFileCharacterised = true;
        bool anyFixity = false;
        bool everyFixityAlgorithmStated = true;
        bool everyFixityValueStated = true;
        bool anyFormat = false;
        bool anyDesignation = false;
        bool everyDesignationNamed = true;
        bool everyDesignationVersioned = true;
        bool anyRegistry = false;
        bool everyRegistryNamed = true;
        bool everyRegistryKeyed = true;
        bool anyRegistryRole = false;
        bool anyCreatingApplication = false;
        bool everyApplicationNamed = true;
        bool anyApplicationVersion = false;
        bool anyApplicationDate = false;
        bool anyOriginalName = false;
        bool anyStorage = false;
        bool anyContentLocation = false;
        bool everyContentLocationTyped = true;
        bool everyContentLocationValued = true;
        bool anyStorageMedium = false;
        bool anyRightsLink = false;
        bool everyRightsLinkTyped = true;
        bool everyRightsLinkValued = true;
        var relationships = new List<PremisRelationship>();
        for(int i = 0; i < files.Count; ++i)
        {
            PremisObject file = files[i];
            everyFileIdentified &= file.Identifiers.Count > 0;
            for(int identifierIndex = 0; identifierIndex < file.Identifiers.Count; ++identifierIndex)
            {
                everyIdentifierTypeStated &= !string.IsNullOrEmpty(file.Identifiers[identifierIndex].Type);
                everyIdentifierValueStated &= !string.IsNullOrEmpty(file.Identifiers[identifierIndex].Value);
            }

            everyFileCharacterised &= file.Characteristics.Count > 0;
            for(int characteristicIndex = 0; characteristicIndex < file.Characteristics.Count; ++characteristicIndex)
            {
                PremisObjectCharacteristics characteristics = file.Characteristics[characteristicIndex];
                for(int fixityIndex = 0; fixityIndex < characteristics.Fixities.Count; ++fixityIndex)
                {
                    anyFixity = true;
                    everyFixityAlgorithmStated &= StatesChecksumAlgorithmName(characteristics.Fixities[fixityIndex]);
                    everyFixityValueStated &= StatesChecksum(characteristics.Fixities[fixityIndex]);
                }

                if(characteristics.Format is PremisFormat format)
                {
                    anyFormat = true;
                    if(format.Designation is PremisFormatDesignation designation)
                    {
                        anyDesignation = true;
                        everyDesignationNamed &= !string.IsNullOrEmpty(designation.Name);
                        everyDesignationVersioned &= !string.IsNullOrEmpty(designation.Version);
                    }

                    if(format.Registry is PremisFormatRegistry registry)
                    {
                        anyRegistry = true;
                        everyRegistryNamed &= !string.IsNullOrEmpty(registry.Name);
                        everyRegistryKeyed &= !string.IsNullOrEmpty(registry.Key);
                        anyRegistryRole |= !string.IsNullOrEmpty(registry.Role);
                    }
                }

                for(int applicationIndex = 0; applicationIndex < characteristics.CreatingApplications.Count; ++applicationIndex)
                {
                    PremisCreatingApplication application = characteristics.CreatingApplications[applicationIndex];
                    anyCreatingApplication = true;
                    everyApplicationNamed &= !string.IsNullOrEmpty(application.Name);
                    anyApplicationVersion |= !string.IsNullOrEmpty(application.Version);
                    anyApplicationDate |= !string.IsNullOrEmpty(application.DateCreatedByApplication);
                }
            }

            anyOriginalName |= !string.IsNullOrEmpty(file.OriginalName);
            for(int storageIndex = 0; storageIndex < file.Storage.Count; ++storageIndex)
            {
                PremisStorage storage = file.Storage[storageIndex];
                anyStorage = true;
                anyStorageMedium |= !string.IsNullOrEmpty(storage.Medium);
                if(storage.ContentLocation is PremisContentLocation location)
                {
                    anyContentLocation = true;
                    everyContentLocationTyped &= !string.IsNullOrEmpty(location.Type);
                    everyContentLocationValued &= !string.IsNullOrEmpty(location.Value);
                }
            }

            for(int relationshipIndex = 0; relationshipIndex < file.Relationships.Count; ++relationshipIndex)
            {
                relationships.Add(file.Relationships[relationshipIndex]);
            }

            for(int rightsIndex = 0; rightsIndex < file.RightsStatementIdentifiers.Count; ++rightsIndex)
            {
                anyRightsLink = true;
                everyRightsLinkTyped &= !string.IsNullOrEmpty(file.RightsStatementIdentifiers[rightsIndex].Type);
                everyRightsLinkValued &= !string.IsNullOrEmpty(file.RightsStatementIdentifiers[rightsIndex].Value);
            }
        }

        bool anyRelationship = relationships.Count > 0;
        bool anyRelatedEvent = false;
        bool everyRelatedEventTyped = true;
        bool everyRelatedEventValued = true;
        for(int i = 0; i < relationships.Count; ++i)
        {
            PremisRelationship relationship = relationships[i];
            for(int eventIndex = 0; eventIndex < relationship.RelatedEventIdentifiers.Count; ++eventIndex)
            {
                anyRelatedEvent = true;
                everyRelatedEventTyped &= !string.IsNullOrEmpty(relationship.RelatedEventIdentifiers[eventIndex].Type);
                everyRelatedEventValued &= !string.IsNullOrEmpty(relationship.RelatedEventIdentifiers[eventIndex].Value);
            }
        }

        var claims = new List<Claim>(PreservationFileClaimIds.Count)
        {
            Mandatory(PremisClaimIds.Pm28, everyCategoryRecognised, "object/@xsi:type against the object-category vocabulary"),
            Conditional(PremisClaimIds.Pm29, anyFile, everyFileIdentified, "object/objectIdentifier of each file"),
            Conditional(PremisClaimIds.Pm30, anyFile, everyIdentifierTypeStated, "objectIdentifier/objectIdentifierType"),
            Conditional(PremisClaimIds.Pm31, anyFile, everyIdentifierValueStated, "objectIdentifier/objectIdentifierValue"),
            Conditional(PremisClaimIds.Pm32, anyFile, everyFileCharacterised, "object/objectCharacteristics"),
            Conditional(PremisClaimIds.Pm33, anyFile, anyFixity, "objectCharacteristics/fixity", recommendation: true),
            Conditional(PremisClaimIds.Pm34, anyFixity, everyFixityAlgorithmStated, "fixity/messageDigestAlgorithm"),
            Conditional(PremisClaimIds.Pm35, anyFixity, everyFixityValueStated, "fixity/messageDigest"),
            NotSupplied(PremisClaimIds.Pm36, "fixity/messageDigestOriginator, which the preservation-metadata model does not carry"),
            Conditional(PremisClaimIds.Pm37, anyFile, anyFormat, "objectCharacteristics/format", recommendation: true),
            Conditional(PremisClaimIds.Pm38, anyFormat, anyDesignation, "format/formatDesignation", recommendation: true),
            Conditional(PremisClaimIds.Pm39, anyDesignation, everyDesignationNamed, "formatDesignation/formatName"),
            Conditional(PremisClaimIds.Pm40, anyDesignation, everyDesignationVersioned, "formatDesignation/formatVersion", recommendation: true),
            Conditional(PremisClaimIds.Pm41, anyFormat, anyRegistry, "format/formatRegistry", recommendation: true),
            Conditional(PremisClaimIds.Pm42, anyRegistry, everyRegistryNamed, "formatRegistry/formatRegistryName"),
            Conditional(PremisClaimIds.Pm43, anyRegistry, everyRegistryKeyed, "formatRegistry/formatRegistryKey"),
            Optional(PremisClaimIds.Pm44, anyRegistryRole, "formatRegistry/formatRegistryRole"),
            Optional(PremisClaimIds.Pm45, anyCreatingApplication, "objectCharacteristics/creatingApplication"),
            Conditional(PremisClaimIds.Pm46, anyCreatingApplication, everyApplicationNamed, "creatingApplication/creatingApplicationName"),
            Optional(PremisClaimIds.Pm47, anyApplicationVersion, "creatingApplication/creatingApplicationVersion"),
            Optional(PremisClaimIds.Pm48, anyApplicationDate, "creatingApplication/dateCreatedByApplication"),
            NotSupplied(PremisClaimIds.Pm49, "creatingApplication/creatingApplicationExtension, which the preservation-metadata model does not carry"),
            NotSupplied(PremisClaimIds.Pm50, "objectCharacteristics/objectCharacteristicsExtension, which the preservation-metadata model does not carry"),
            Conditional(PremisClaimIds.Pm51, anyFile, anyOriginalName, "object/originalName", recommendation: true),
            Optional(PremisClaimIds.Pm52, anyStorage, "object/storage"),
            UndefinedKeyword(context, PremisClaimIds.Pm53, anyContentLocation, "storage/contentLocation"),
            Conditional(PremisClaimIds.Pm54, anyContentLocation, everyContentLocationTyped, "contentLocation/contentLocationType"),
            Conditional(PremisClaimIds.Pm55, anyContentLocation, everyContentLocationValued, "contentLocation/contentLocationValue"),
            Optional(PremisClaimIds.Pm56, anyStorageMedium, "storage/storageMedium"),
            Conditional(PremisClaimIds.Pm57, anyFile, anyRelationship, "object/relationship of each file", recommendation: true)
        };

        AddRelationshipClaims(
            claims,
            relationships,
            "a file's relationship",
            type: PremisClaimIds.Pm58,
            subType: PremisClaimIds.Pm59,
            relatedObject: PremisClaimIds.Pm60,
            relatedObjectType: PremisClaimIds.Pm61,
            relatedObjectValue: PremisClaimIds.Pm62);

        claims.Add(Conditional(PremisClaimIds.Pm63, anyRelationship, anyRelatedEvent, "relationship/relatedEventIdentifier", recommendation: true));
        claims.Add(Interpreted(
            PremisClaimIds.Pm64,
            anyRelatedEvent ? (everyRelatedEventTyped ? ClaimOutcome.Success : ClaimOutcome.Failure) : ClaimOutcome.NotApplicable,
            "relatedEventIdentifier/relatedEventIdentifierType, which the requirement table names with the related-object prefix and the vocabulary's own schema settles as the related-event one"));
        claims.Add(Conditional(PremisClaimIds.Pm65, anyRelatedEvent, everyRelatedEventValued, "relatedEventIdentifier/relatedEventIdentifierValue"));
        claims.Add(UndefinedKeyword(context, PremisClaimIds.Pm66, anyRightsLink, "object/linkingRightsStatementIdentifier"));
        claims.Add(Conditional(PremisClaimIds.Pm67, anyRightsLink, everyRightsLinkTyped, "linkingRightsStatementIdentifier/linkingRightsStatementIdentifierType"));
        claims.Add(Conditional(PremisClaimIds.Pm68, anyRightsLink, everyRightsLinkValued, "linkingRightsStatementIdentifier/linkingRightsStatementIdentifierValue"));

        return ValueTask.FromResult(claims);
    }


    /// <summary>
    /// Checks the agents, <c>PM69</c>…<c>PM79</c>: the agent entity itself, its identification, its name and
    /// type, and the rights statements it links to.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim per requirement of <see cref="PreservationAgentClaimIds"/>.</returns>
    /// <remarks>
    /// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM69–PM79</see>.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckPreservationAgents(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<PremisDocument> documents = context.PreservationMetadata;
        if(documents.Count == 0)
        {
            return ValueTask.FromResult(NotSuppliedFor(PreservationAgentClaimIds, "the preservation-metadata documents"));
        }

        var agents = new List<PremisAgent>();
        for(int i = 0; i < documents.Count; ++i)
        {
            for(int agentIndex = 0; agentIndex < documents[i].Agents.Count; ++agentIndex)
            {
                agents.Add(documents[i].Agents[agentIndex]);
            }
        }

        bool anyAgent = agents.Count > 0;
        bool everyAgentIdentified = true;
        bool everyIdentifierTypeStated = true;
        bool everyIdentifierValueStated = true;
        bool everyAgentNamed = true;
        bool everyAgentTyped = true;
        bool everyAgentVersioned = true;
        bool anyAgentNote = false;
        bool anyRightsLink = false;
        bool everyRightsLinkTyped = true;
        bool everyRightsLinkValued = true;
        for(int i = 0; i < agents.Count; ++i)
        {
            PremisAgent agent = agents[i];
            everyAgentIdentified &= agent.Identifiers.Count > 0;
            for(int identifierIndex = 0; identifierIndex < agent.Identifiers.Count; ++identifierIndex)
            {
                everyIdentifierTypeStated &= !string.IsNullOrEmpty(agent.Identifiers[identifierIndex].Type);
                everyIdentifierValueStated &= !string.IsNullOrEmpty(agent.Identifiers[identifierIndex].Value);
            }

            everyAgentNamed &= !string.IsNullOrEmpty(agent.Name);
            everyAgentTyped &= !string.IsNullOrEmpty(agent.Type);
            everyAgentVersioned &= !string.IsNullOrEmpty(agent.Version);
            anyAgentNote |= !string.IsNullOrEmpty(agent.Note);
            for(int rightsIndex = 0; rightsIndex < agent.RightsStatementIdentifiers.Count; ++rightsIndex)
            {
                anyRightsLink = true;
                everyRightsLinkTyped &= !string.IsNullOrEmpty(agent.RightsStatementIdentifiers[rightsIndex].Type);
                everyRightsLinkValued &= !string.IsNullOrEmpty(agent.RightsStatementIdentifiers[rightsIndex].Value);
            }
        }

        return ValueTask.FromResult<List<Claim>>(
        [
            Recommended(PremisClaimIds.Pm69, anyAgent, "agent"),
            Conditional(PremisClaimIds.Pm70, anyAgent, everyAgentIdentified, "agent/agentIdentifier"),
            Conditional(PremisClaimIds.Pm71, anyAgent, everyIdentifierTypeStated, "agentIdentifier/agentIdentifierType"),
            Conditional(PremisClaimIds.Pm72, anyAgent, everyIdentifierValueStated, "agentIdentifier/agentIdentifierValue"),
            Conditional(PremisClaimIds.Pm73, anyAgent, everyAgentNamed, "agent/agentName"),
            Conditional(PremisClaimIds.Pm74, anyAgent, everyAgentTyped, "agent/agentType"),
            Conditional(PremisClaimIds.Pm75, anyAgent, everyAgentVersioned, "agent/agentVersion", recommendation: true),
            Optional(PremisClaimIds.Pm76, anyAgentNote, "agent/agentNote"),
            Conditional(PremisClaimIds.Pm77, anyAgent, anyRightsLink, "agent/linkingRightsStatementIdentifier", recommendation: true),
            Conditional(PremisClaimIds.Pm78, anyRightsLink, everyRightsLinkTyped, "linkingRightsStatementIdentifier/linkingRightsStatementIdentifierType"),
            Conditional(PremisClaimIds.Pm79, anyRightsLink, everyRightsLinkValued, "linkingRightsStatementIdentifier/linkingRightsStatementIdentifierValue")
        ]);
    }


    /// <summary>
    /// Checks the events, <c>PM80</c>…<c>PM92</c>: the event entity, its identification, its type, instant and
    /// outcome, the agent that performed it and the object it affected.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim per requirement of <see cref="PreservationEventClaimIds"/>.</returns>
    /// <remarks>
    /// <c>PM80</c> and <c>PM90</c> state a cardinality and no keyword at all, unlike every other row of the
    /// catalogue. Both are <c>0..n</c>, so they are read at the level their own cardinality gives — optional —
    /// and the claims say that the reading is an interpretation rather than a transcription.
    /// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM80–PM92</see>.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckPreservationEvents(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<PremisDocument> documents = context.PreservationMetadata;
        if(documents.Count == 0)
        {
            return ValueTask.FromResult(NotSuppliedFor(PreservationEventClaimIds, "the preservation-metadata documents"));
        }

        var events = new List<PremisEvent>();
        for(int i = 0; i < documents.Count; ++i)
        {
            for(int eventIndex = 0; eventIndex < documents[i].Events.Count; ++eventIndex)
            {
                events.Add(documents[i].Events[eventIndex]);
            }
        }

        bool anyEvent = events.Count > 0;
        bool everyEventIdentified = true;
        bool everyIdentifierTypeStated = true;
        bool everyIdentifierValueStated = true;
        bool everyEventTyped = true;
        bool everyEventDated = true;
        bool everyEventOutcomeStated = true;
        bool anyAgentLink = false;
        bool everyAgentLinkTyped = true;
        bool everyAgentLinkValued = true;
        bool anyObjectLink = false;
        bool everyObjectLinkTyped = true;
        bool everyObjectLinkValued = true;
        for(int i = 0; i < events.Count; ++i)
        {
            PremisEvent preservationEvent = events[i];
            everyEventIdentified &= preservationEvent.Identifiers.Count > 0;
            for(int identifierIndex = 0; identifierIndex < preservationEvent.Identifiers.Count; ++identifierIndex)
            {
                everyIdentifierTypeStated &= !string.IsNullOrEmpty(preservationEvent.Identifiers[identifierIndex].Type);
                everyIdentifierValueStated &= !string.IsNullOrEmpty(preservationEvent.Identifiers[identifierIndex].Value);
            }

            everyEventTyped &= !string.IsNullOrEmpty(preservationEvent.Type);
            everyEventDated &= !string.IsNullOrEmpty(preservationEvent.EventDateTime);
            everyEventOutcomeStated &= !string.IsNullOrEmpty(preservationEvent.Outcome);
            for(int agentIndex = 0; agentIndex < preservationEvent.LinkingAgentIdentifiers.Count; ++agentIndex)
            {
                anyAgentLink = true;
                everyAgentLinkTyped &= !string.IsNullOrEmpty(preservationEvent.LinkingAgentIdentifiers[agentIndex].Type);
                everyAgentLinkValued &= !string.IsNullOrEmpty(preservationEvent.LinkingAgentIdentifiers[agentIndex].Value);
            }

            for(int objectIndex = 0; objectIndex < preservationEvent.LinkingObjectIdentifiers.Count; ++objectIndex)
            {
                anyObjectLink = true;
                everyObjectLinkTyped &= !string.IsNullOrEmpty(preservationEvent.LinkingObjectIdentifiers[objectIndex].Type);
                everyObjectLinkValued &= !string.IsNullOrEmpty(preservationEvent.LinkingObjectIdentifiers[objectIndex].Value);
            }
        }

        return ValueTask.FromResult<List<Claim>>(
        [
            Interpreted(PremisClaimIds.Pm80, anyEvent ? ClaimOutcome.Success : ClaimOutcome.NotApplicable, "event, a row stated with a cardinality of 0..n and no keyword, read as optional"),
            Conditional(PremisClaimIds.Pm81, anyEvent, everyEventIdentified, "event/eventIdentifier"),
            Conditional(PremisClaimIds.Pm82, anyEvent, everyIdentifierTypeStated, "eventIdentifier/eventIdentifierType"),
            Conditional(PremisClaimIds.Pm83, anyEvent, everyIdentifierValueStated, "eventIdentifier/eventIdentifierValue"),
            Conditional(PremisClaimIds.Pm84, anyEvent, everyEventTyped, "event/eventType"),
            Conditional(PremisClaimIds.Pm85, anyEvent, everyEventDated, "event/eventDateTime"),
            Conditional(PremisClaimIds.Pm86, anyEvent, everyEventOutcomeStated, "eventOutcomeInformation/eventOutcome"),
            Conditional(PremisClaimIds.Pm87, anyEvent, anyAgentLink, "event/linkingAgentIdentifier", recommendation: true),
            Conditional(PremisClaimIds.Pm88, anyAgentLink, everyAgentLinkTyped, "linkingAgentIdentifier/linkingAgentIdentifierType"),
            Conditional(PremisClaimIds.Pm89, anyAgentLink, everyAgentLinkValued, "linkingAgentIdentifier/linkingAgentIdentifierValue"),
            Interpreted(PremisClaimIds.Pm90, anyObjectLink ? ClaimOutcome.Success : ClaimOutcome.NotApplicable, "event/linkingObjectIdentifier, a row stated with a cardinality of 0..n and no keyword, read as optional"),
            Conditional(PremisClaimIds.Pm91, anyObjectLink, everyObjectLinkTyped, "linkingObjectIdentifier/linkingObjectIdentifierType"),
            Conditional(PremisClaimIds.Pm92, anyObjectLink, everyObjectLinkValued, "linkingObjectIdentifier/linkingObjectIdentifierValue")
        ]);
    }


    /// <summary>
    /// Checks the rights statements, <c>PM93</c>…<c>PM125</c>: the statements, their identification, the basis
    /// each rests on with the four alternative bases the vocabulary names, and the acts a statement grants.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim per requirement of <see cref="PreservationRightsClaimIds"/>.</returns>
    /// <remarks>
    /// The four bases are alternatives: a statement resting on one of them leaves the other three's rows
    /// not-applicable rather than unmet, which is what the vocabulary's own predicate notation says.
    /// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM93–PM125</see>.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckPreservationRights(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<PremisDocument> documents = context.PreservationMetadata;
        if(documents.Count == 0)
        {
            return ValueTask.FromResult(NotSuppliedFor(PreservationRightsClaimIds, "the preservation-metadata documents"));
        }

        var statements = new List<PremisRightsStatement>();
        for(int i = 0; i < documents.Count; ++i)
        {
            for(int statementIndex = 0; statementIndex < documents[i].RightsStatements.Count; ++statementIndex)
            {
                statements.Add(documents[i].RightsStatements[statementIndex]);
            }
        }

        bool anyStatement = statements.Count > 0;
        bool everyStatementIdentified = true;
        bool everyIdentifierTypeStated = true;
        bool everyIdentifierValueStated = true;
        bool everyBasisRecognised = true;
        bool anyCopyrightBasis = false;
        bool anyCopyrightInformation = false;
        bool everyCopyrightStatusStated = true;
        bool everyCopyrightJurisdictionStated = true;
        bool anyCopyrightDocumentation = false;
        bool anyLicenseBasis = false;
        bool anyLicenseInformation = false;
        bool anyLicenseDocumentation = false;
        bool anyStatuteBasis = false;
        bool anyStatuteInformation = false;
        bool everyStatuteJurisdictionStated = true;
        bool everyStatuteCitationStated = true;
        bool anyStatuteDocumentation = false;
        bool anyOtherBasis = false;
        bool anyOtherInformation = false;
        bool anyOtherDocumentation = false;
        bool everyOtherBasisStated = true;
        bool anyGrant = false;
        bool everyGrantHasAct = true;
        bool anyTermOfGrant = false;
        bool everyTermStarts = true;
        bool anyTermEnds = false;
        bool anyGrantNote = false;
        var documentationIdentifiers = new List<PremisIdentifier>();
        for(int i = 0; i < statements.Count; ++i)
        {
            PremisRightsStatement statement = statements[i];
            everyStatementIdentified &= statement.Identifiers.Count > 0;
            for(int identifierIndex = 0; identifierIndex < statement.Identifiers.Count; ++identifierIndex)
            {
                everyIdentifierTypeStated &= !string.IsNullOrEmpty(statement.Identifiers[identifierIndex].Type);
                everyIdentifierValueStated &= !string.IsNullOrEmpty(statement.Identifiers[identifierIndex].Value);
            }

            everyBasisRecognised &= PremisWellKnown.IsRightsBasis(statement.Basis);
            anyCopyrightBasis |= string.Equals(statement.Basis, PremisWellKnown.CopyrightRightsBasis, StringComparison.Ordinal);
            anyLicenseBasis |= string.Equals(statement.Basis, PremisWellKnown.LicenseRightsBasis, StringComparison.Ordinal);
            anyStatuteBasis |= string.Equals(statement.Basis, PremisWellKnown.StatuteRightsBasis, StringComparison.Ordinal);
            anyOtherBasis |= string.Equals(statement.Basis, PremisWellKnown.OtherRightsBasis, StringComparison.Ordinal);

            if(statement.CopyrightInformation is PremisCopyrightInformation copyright)
            {
                anyCopyrightInformation = true;
                everyCopyrightStatusStated &= !string.IsNullOrEmpty(copyright.Status);
                everyCopyrightJurisdictionStated &= !string.IsNullOrEmpty(copyright.Jurisdiction);
                anyCopyrightDocumentation |= copyright.DocumentationIdentifiers.Count > 0;
                documentationIdentifiers.AddRange(copyright.DocumentationIdentifiers);
            }

            if(statement.LicenseInformation is PremisLicenseInformation license)
            {
                anyLicenseInformation = true;
                anyLicenseDocumentation |= license.DocumentationIdentifiers.Count > 0;
                documentationIdentifiers.AddRange(license.DocumentationIdentifiers);
            }

            if(statement.StatuteInformation is PremisStatuteInformation statute)
            {
                anyStatuteInformation = true;
                everyStatuteJurisdictionStated &= !string.IsNullOrEmpty(statute.Jurisdiction);
                everyStatuteCitationStated &= !string.IsNullOrEmpty(statute.Citation);
                anyStatuteDocumentation |= statute.DocumentationIdentifiers.Count > 0;
                documentationIdentifiers.AddRange(statute.DocumentationIdentifiers);
            }

            if(statement.OtherRightsInformation is PremisOtherRightsInformation other)
            {
                anyOtherInformation = true;
                everyOtherBasisStated &= !string.IsNullOrEmpty(other.Basis);
                anyOtherDocumentation |= other.DocumentationIdentifiers.Count > 0;
                documentationIdentifiers.AddRange(other.DocumentationIdentifiers);
            }

            if(statement.RightsGranted is PremisRightsGranted granted)
            {
                anyGrant = true;
                everyGrantHasAct &= granted.Acts.Count > 0;
                anyGrantNote |= !string.IsNullOrEmpty(granted.Note);
                if(granted.TermOfGrant is PremisTermOfGrant term)
                {
                    anyTermOfGrant = true;
                    everyTermStarts &= !string.IsNullOrEmpty(term.StartDate);
                    anyTermEnds |= !string.IsNullOrEmpty(term.EndDate);
                }
            }
        }

        bool anyDocumentationIdentifier = documentationIdentifiers.Count > 0;
        bool everyDocumentationTyped = true;
        bool everyDocumentationValued = true;
        for(int i = 0; i < documentationIdentifiers.Count; ++i)
        {
            everyDocumentationTyped &= !string.IsNullOrEmpty(documentationIdentifiers[i].Type);
            everyDocumentationValued &= !string.IsNullOrEmpty(documentationIdentifiers[i].Value);
        }

        return ValueTask.FromResult<List<Claim>>(
        [
            Recommended(PremisClaimIds.Pm93, anyStatement, "rights"),
            Conditional(PremisClaimIds.Pm94, anyStatement, anyStatement, "rights/rightsStatement"),
            Conditional(PremisClaimIds.Pm95, anyStatement, everyStatementIdentified, "rightsStatement/rightsStatementIdentifier"),
            Conditional(PremisClaimIds.Pm96, anyStatement, everyIdentifierTypeStated, "rightsStatementIdentifier/rightsStatementIdentifierType"),
            Conditional(PremisClaimIds.Pm97, anyStatement, everyIdentifierValueStated, "rightsStatementIdentifier/rightsStatementIdentifierValue"),
            Conditional(PremisClaimIds.Pm98, anyStatement, everyBasisRecognised, "rightsStatement/rightsBasis against the rights-basis vocabulary"),
            Conditional(PremisClaimIds.Pm99, anyCopyrightBasis, anyCopyrightInformation, "copyrightInformation", recommendation: true),
            Conditional(PremisClaimIds.Pm100, anyCopyrightInformation, everyCopyrightStatusStated, "copyrightInformation/copyrightStatus"),
            Conditional(PremisClaimIds.Pm101, anyCopyrightInformation, everyCopyrightJurisdictionStated, "copyrightInformation/copyrightJurisdiction"),
            Conditional(PremisClaimIds.Pm102, anyCopyrightInformation, anyCopyrightDocumentation, "copyrightInformation/copyrightDocumentationIdentifier", recommendation: false, optional: true),
            Conditional(PremisClaimIds.Pm103, anyDocumentationIdentifier, everyDocumentationTyped, "a documentation identifier's type"),
            Conditional(PremisClaimIds.Pm104, anyDocumentationIdentifier, everyDocumentationValued, "a documentation identifier's value"),
            Conditional(PremisClaimIds.Pm105, anyLicenseBasis, anyLicenseInformation, "licenseInformation", recommendation: true),
            Conditional(PremisClaimIds.Pm106, anyLicenseInformation, anyLicenseDocumentation, "licenseInformation/licenseDocumentationIdentifier", recommendation: false, optional: true),
            Conditional(PremisClaimIds.Pm107, anyDocumentationIdentifier, everyDocumentationTyped, "a licence documentation identifier's type"),
            Conditional(PremisClaimIds.Pm108, anyDocumentationIdentifier, everyDocumentationValued, "a licence documentation identifier's value"),
            Conditional(PremisClaimIds.Pm109, anyStatuteBasis, anyStatuteInformation, "statuteInformation", recommendation: true),
            Conditional(PremisClaimIds.Pm110, anyStatuteInformation, everyStatuteJurisdictionStated, "statuteInformation/statuteJurisdiction"),
            Conditional(PremisClaimIds.Pm111, anyStatuteInformation, everyStatuteCitationStated, "statuteInformation/statuteCitation"),
            Conditional(PremisClaimIds.Pm112, anyStatuteInformation, anyStatuteDocumentation, "statuteInformation/statuteDocumentationIdentifier", recommendation: false, optional: true),
            Conditional(PremisClaimIds.Pm113, anyDocumentationIdentifier, everyDocumentationTyped, "a statute documentation identifier's type"),
            Conditional(PremisClaimIds.Pm114, anyDocumentationIdentifier, everyDocumentationValued, "a statute documentation identifier's value"),
            Conditional(PremisClaimIds.Pm115, anyOtherBasis, anyOtherInformation, "otherRightsInformation", recommendation: true),
            Conditional(PremisClaimIds.Pm116, anyOtherInformation, anyOtherDocumentation, "otherRightsInformation/otherRightsDocumentationIdentifier", recommendation: false, optional: true),
            Conditional(PremisClaimIds.Pm117, anyDocumentationIdentifier, everyDocumentationTyped, "an other-rights documentation identifier's type"),
            Conditional(PremisClaimIds.Pm118, anyDocumentationIdentifier, everyDocumentationValued, "an other-rights documentation identifier's value"),
            Conditional(PremisClaimIds.Pm119, anyOtherInformation, everyOtherBasisStated, "otherRightsInformation/otherRightsBasis"),
            Conditional(PremisClaimIds.Pm120, anyStatement, anyGrant, "rightsStatement/rightsGranted", recommendation: true),
            Conditional(PremisClaimIds.Pm121, anyGrant, everyGrantHasAct, "rightsGranted/act"),
            Conditional(PremisClaimIds.Pm122, anyGrant, anyTermOfGrant, "rightsGranted/termOfGrant", recommendation: true),
            Conditional(PremisClaimIds.Pm123, anyTermOfGrant, everyTermStarts, "termOfGrant/startDate"),
            Optional(PremisClaimIds.Pm124, anyTermEnds, "termOfGrant/endDate"),
            Optional(PremisClaimIds.Pm125, anyGrantNote, "rightsGranted/rightsGrantedNote")
        ]);
    }


    /// <summary>The requirements <see cref="CheckArchivalPackageProvenanceReferences"/> issues, <c>AIPM5</c>…<c>AIPM7</c>.</summary>
    public static IReadOnlyList<ClaimId> ArchivalPackageProvenanceClaimIds { get; } =
        [AipClaimIds.Aipm5, AipClaimIds.Aipm6, AipClaimIds.Aipm7];

    /// <summary>The requirements <see cref="CheckArchivalPackagePreservationLayer"/> issues: <c>AIP12</c>, <c>AIP13</c> and <c>AIP15</c>…<c>AIP18</c>.</summary>
    public static IReadOnlyList<ClaimId> ArchivalPackagePreservationClaimIds { get; } =
    [
        AipClaimIds.Aip12, AipClaimIds.Aip13, AipClaimIds.Aip15,
        AipClaimIds.Aip16, AipClaimIds.Aip17, AipClaimIds.Aip18
    ];

    /// <summary>The requirement <see cref="CheckArchivalPackageParentChain"/> issues, the parent-chain obligation the specification states with no identifier of its own.</summary>
    public static IReadOnlyList<ClaimId> ArchivalPackageParentChainClaimIds { get; } =
        [AipClaimIds.ArchivalPackageParentChainListed];

    /// <summary>The requirements <see cref="CheckPackageFixityAsync"/> issues.</summary>
    public static IReadOnlyList<ClaimId> PackageFixityClaimIds { get; } =
        [EArkClaimIds.PackageFixityRecomputed, EArkClaimIds.PackageFixityAlgorithmStrength];


    /// <summary>
    /// Checks the archival package's digital-provenance references, <c>AIPM5</c>…<c>AIPM7</c>: provenance
    /// metadata is referenced from the administrative section, at least one such reference names the
    /// preservation-metadata vocabulary, and it states the vocabulary's major version.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim per requirement of <see cref="ArchivalPackageProvenanceClaimIds"/>.</returns>
    /// <remarks>
    /// This is the pointer mechanism the whole archival preservation layer hangs from: the manifest's
    /// digital-provenance sub-sections are where the preservation-metadata documents are moored, and a package
    /// whose provenance is not referenced this way has no place to record what was done to it.
    /// <see href="https://earkaip.dilcis.eu/profile/E-ARK-AIP.xml">E-ARK AIP v2.2.0 METS Profile</see>.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckArchivalPackageProvenanceReferences(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        MetsDocument? manifest = context.PackageManifest;
        if(manifest is null)
        {
            return ValueTask.FromResult(NotSuppliedFor(ArchivalPackageProvenanceClaimIds, "the package manifest"));
        }

        IReadOnlyList<MetsAdministrativeMetadataSection> provenance =
            manifest.AdministrativeMetadata?.DigitalProvenanceSections ?? [];

        bool everySectionReferences = provenance.Count > 0;
        bool anyPreservationReference = false;
        bool everyPreservationReferenceVersioned = true;
        for(int i = 0; i < provenance.Count; ++i)
        {
            MetsMetadataReference? reference = provenance[i].Reference;
            if(reference is null)
            {
                everySectionReferences = false;
                continue;
            }

            if(string.Equals(reference.MetadataType, MetsWellKnown.PremisMetadataType, StringComparison.Ordinal))
            {
                anyPreservationReference = true;
                everyPreservationReferenceVersioned &= PremisWellKnown.IsPremisMajorVersion(reference.MetadataTypeVersion);
            }
        }

        return ValueTask.FromResult<List<Claim>>(
        [
            Mandatory(AipClaimIds.Aipm5, everySectionReferences, "mets/amdSec/digiprovMD/mdRef"),
            Recommended(AipClaimIds.Aipm6, anyPreservationReference, "mets/amdSec/digiprovMD/mdRef[@MDTYPE='PREMIS']"),
            Conditional(AipClaimIds.Aipm7, anyPreservationReference, everyPreservationReferenceVersioned, "the preservation-metadata reference's @MDTYPEVERSION", recommendation: true)
        ]);
    }


    /// <summary>
    /// Checks the archival package's preservation layer: <c>AIP12</c> and <c>AIP13</c> over the objects'
    /// relationships, and <c>AIP15</c>…<c>AIP18</c> over the events that record what was done to the package
    /// and the agents that did it.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim per requirement of <see cref="ArchivalPackagePreservationClaimIds"/>.</returns>
    /// <remarks>
    /// <para>
    /// <c>AIP18</c> is the only cross-entity rule of the group and the one worth having: every agent an event
    /// names has to be described by an agent entity, so a provenance record cannot point at a performer that
    /// the package never identifies.
    /// </para>
    /// <para>
    /// <c>AIP13</c> is split by what a single package can answer. That a package which is part of another
    /// names the superordinate one through the relationship subtype is half a document question and half a
    /// repository question: the document half — every relationship states a subtype — is checked here, and
    /// whether the subtype names the right package needs the repository's own catalogue, which no rule over
    /// one package reaches. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0</see>.
    /// </para>
    /// </remarks>
    public static ValueTask<List<Claim>> CheckArchivalPackagePreservationLayer(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<PremisDocument> documents = context.PreservationMetadata;
        if(documents.Count == 0)
        {
            return ValueTask.FromResult(NotSuppliedFor(ArchivalPackagePreservationClaimIds, "the preservation-metadata documents"));
        }

        var relationships = new List<PremisRelationship>();
        var events = new List<PremisEvent>();
        var agentIdentifiers = new List<PremisIdentifier>();
        bool anyObject = false;
        bool anyObjectRelated = false;
        for(int i = 0; i < documents.Count; ++i)
        {
            PremisDocument document = documents[i];
            for(int objectIndex = 0; objectIndex < document.Objects.Count; ++objectIndex)
            {
                PremisObject premisObject = document.Objects[objectIndex];
                anyObject = true;
                anyObjectRelated |= premisObject.Relationships.Count > 0;
                relationships.AddRange(premisObject.Relationships);
            }

            events.AddRange(document.Events);
            for(int agentIndex = 0; agentIndex < document.Agents.Count; ++agentIndex)
            {
                agentIdentifiers.AddRange(document.Agents[agentIndex].Identifiers);
            }
        }

        bool anyRelationship = relationships.Count > 0;
        bool everyRelationshipSubTyped = true;
        bool anyRelatedEvent = false;
        for(int i = 0; i < relationships.Count; ++i)
        {
            everyRelationshipSubTyped &= !string.IsNullOrEmpty(relationships[i].SubType);
            anyRelatedEvent |= relationships[i].RelatedEventIdentifiers.Count > 0;
        }

        bool anyEvent = events.Count > 0;
        bool everyEventIdentified = true;
        bool everyEventNamesAnAgent = true;
        bool anyAgentLink = false;
        bool everyLinkedAgentDescribed = true;
        for(int i = 0; i < events.Count; ++i)
        {
            PremisEvent preservationEvent = events[i];
            bool identified = false;
            for(int identifierIndex = 0; identifierIndex < preservationEvent.Identifiers.Count; ++identifierIndex)
            {
                identified |= !string.IsNullOrEmpty(preservationEvent.Identifiers[identifierIndex].Value);
            }

            everyEventIdentified &= identified;
            everyEventNamesAnAgent &= preservationEvent.LinkingAgentIdentifiers.Count > 0;
            for(int agentIndex = 0; agentIndex < preservationEvent.LinkingAgentIdentifiers.Count; ++agentIndex)
            {
                anyAgentLink = true;
                everyLinkedAgentDescribed &= ContainsIdentifier(agentIdentifiers, preservationEvent.LinkingAgentIdentifiers[agentIndex]);
            }
        }

        return ValueTask.FromResult<List<Claim>>(
        [
            Conditional(AipClaimIds.Aip12, anyObject, anyObjectRelated, "object/relationship", recommendation: true),
            Conditional(AipClaimIds.Aip13, anyRelationship, everyRelationshipSubTyped, "relationship/relationshipSubType"),
            Conditional(AipClaimIds.Aip15, anyEvent, everyEventIdentified, "event/eventIdentifier", recommendation: true),
            Conditional(AipClaimIds.Aip16, anyEvent, everyEventNamesAnAgent, "event/linkingAgentIdentifier"),
            Conditional(AipClaimIds.Aip17, anyRelationship, anyRelatedEvent, "relationship/relatedEventIdentifier, which chains an event back to the one that created its source", recommendation: true),
            Conditional(AipClaimIds.Aip18, anyAgentLink, everyLinkedAgentDescribed, "each agent an event names, described by an agent entity")
        ]);
    }


    /// <summary>
    /// Checks the parent-chain obligation the archival-package specification states with no identifier of its
    /// own: a parent package referenced by child packages carries a structural map listing all of them.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="AipClaimIds.ArchivalPackageParentChainListed"/>.</returns>
    /// <remarks>
    /// <para>
    /// The chain is append-only and backward-pointing — a new parent generation references every child while
    /// the children stay unchanged — and the specification itself names the fragility that follows: losing the
    /// newest parent endangers the integrity of the whole logical package, because nothing beyond the
    /// reference itself binds a generation to its predecessor. That gap is what this library's evidence
    /// machinery exists to close, and closing it is a placement convention rather than a rule of this
    /// catalogue.
    /// </para>
    /// <para>
    /// What one package can answer is that the pointers it carries are well formed: each names a target, uses
    /// the locator and link types the enclosing specification fixes, and sits in a division of its own so the
    /// map really lists the children rather than naming one twice. That the list is COMPLETE needs the
    /// repository's own record of which children exist, which no rule over a single package reaches.
    /// <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0, "Parent AIP references child AIPs"</see>.
    /// </para>
    /// </remarks>
    public static ValueTask<List<Claim>> CheckArchivalPackageParentChain(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        MetsDocument? manifest = context.PackageManifest;
        if(manifest is null)
        {
            return ValueTask.FromResult(NotSuppliedFor(ArchivalPackageParentChainClaimIds, "the package manifest"));
        }

        var pointers = new List<MetsPointer>();
        var divisionsCarryingPointers = new List<MetsDivision>();
        for(int i = 0; i < manifest.StructuralMaps.Count; ++i)
        {
            var pending = new Stack<MetsDivision>();
            pending.Push(manifest.StructuralMaps[i].RootDivision);
            while(pending.Count > 0)
            {
                MetsDivision division = pending.Pop();
                if(division.MetsPointers.Count > 0)
                {
                    divisionsCarryingPointers.Add(division);
                    pointers.AddRange(division.MetsPointers);
                }

                for(int childIndex = 0; childIndex < division.Divisions.Count; ++childIndex)
                {
                    pending.Push(division.Divisions[childIndex]);
                }
            }
        }

        bool everyPointerWellFormed = true;
        for(int i = 0; i < pointers.Count; ++i)
        {
            MetsPointer pointer = pointers[i];
            everyPointerWellFormed &= !string.IsNullOrEmpty(pointer.Href)
                && string.Equals(pointer.LocatorType, MetsWellKnown.UrlLocatorType, StringComparison.Ordinal)
                && string.Equals(pointer.LinkType, MetsWellKnown.SimpleLinkType, StringComparison.Ordinal);
        }

        bool oneDivisionPerPointer = divisionsCarryingPointers.Count == pointers.Count;

        return ValueTask.FromResult<List<Claim>>(
        [
            Conditional(
                AipClaimIds.ArchivalPackageParentChainListed,
                pointers.Count > 0,
                everyPointerWellFormed && oneDivisionPerPointer,
                "a structural-map division per package the manifest points at")
        ]);
    }


    /// <summary>
    /// Recomputes every fixity value the package's manifest states, over the octets the package holds, and
    /// states whether the algorithms those values were computed under are ones this library treats as evidence
    /// of authenticity.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim per requirement of <see cref="PackageFixityClaimIds"/>.</returns>
    /// <remarks>
    /// <para>
    /// <strong>Every digest is computed through the registered digest seam</strong>, the same one every other
    /// digest in this repository goes through, so a package's fixity is recomputed by whatever implementation
    /// the application registered and by nothing else.
    /// </para>
    /// <para>
    /// <strong>A weak algorithm is flagged, never failed by default.</strong> The checksum-type enumeration of
    /// the enclosing specification admits error-detection codes and broken hash functions as equally legal
    /// values and states no minimum strength, so a package that uses one is conformant — the reference
    /// material's own worked packages do. The claim therefore reports the strength rather than refusing the
    /// package, and a caller whose own policy states a floor raises it through
    /// <see cref="EArkValidationDeviations.WeakFixityAlgorithmFailsThePackage"/>.
    /// <see href="https://earkcsip.dilcis.eu/specification/implementation/metadata/">E-ARK CSIP v2.2.0 clause
    /// 5</see>.
    /// </para>
    /// <para>
    /// <strong>A stated fixity that cannot be recomputed is said, never dropped.</strong> A location resolving
    /// to nothing is the reference rule's answer and is left to it, since both rules walk the same locations. A
    /// location resolving to a FOLDER entry is nobody else's answer — the reference rule sees a real entry and
    /// reports the reference met — so it refuses the recomputation here: a fixity stated over a directory names
    /// no octets, and a claim reporting the values it did recompute while silently shrinking the number it was
    /// asked about would be a true sentence about a false denominator.
    /// </para>
    /// </remarks>
    public static async ValueTask<List<Claim>> CheckPackageFixityAsync(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        MetsDocument? manifest = context.PackageManifest;
        EArkPackageFacts? facts = context.PackageFacts;
        BaseMemoryPool? pool = context.MemoryPool;
        if(manifest is null || facts is null || pool is null)
        {
            return NotSuppliedFor(PackageFixityClaimIds, "the package manifest, the classified package facts and a memory pool");
        }

        var stated = new List<(string? Href, EArkFixity Fixity)>();
        CollectFixities(manifest, stated);

        int recomputed = 0;
        int mismatched = 0;
        int weak = 0;
        int overAFolder = 0;
        for(int i = 0; i < stated.Count; ++i)
        {
            (string? href, EArkFixity fixity) = stated[i];
            if(fixity is not EArkRecomputableFixity recomputable)
            {
                ++weak;
                continue;
            }

            EArkPackageEntry? entry = ResolveHref(facts.Snapshot, href);
            if(entry is null)
            {
                //A location resolving to nothing is what CheckManifestReferencesResolve answers, over the very
                //same locations, so it is left to that rule rather than reported twice.
                continue;
            }

            if(entry.IsFolder)
            {
                //A location resolving to a folder is answered by no other rule: the reference rule sees a real
                //entry and reports the reference met. Counted here so that a fixity stated over something no
                //octets can be read from refuses the recomputation instead of vanishing from its count.
                ++overAFolder;
                continue;
            }

            using DigestValue computed = await CryptographicKeyEvents.ComputeDigestAsync(
                entry.Content.AsReadOnlyMemory(),
                recomputable.Algorithm.OutputByteLength,
                recomputable.Algorithm.DigestTag,
                pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            ++recomputed;
            if(!computed.AsReadOnlyMemory().Span[..recomputable.Algorithm.OutputByteLength]
                .SequenceEqual(recomputable.Digest.AsReadOnlyMemory().Span[..recomputable.Algorithm.OutputByteLength]))
            {
                ++mismatched;
            }
        }

        Claim recomputationClaim;
        if(mismatched > 0)
        {
            recomputationClaim = new Claim(
                EArkClaimIds.PackageFixityRecomputed,
                ClaimOutcome.Failure,
                new EArkClaimContext(EArkClaimReason.FixityMismatch, $"{mismatched} of {recomputed} recomputed fixity values"),
                Claim.NoSubClaims);
        }
        else if(overAFolder > 0)
        {
            recomputationClaim = new Claim(
                EArkClaimIds.PackageFixityRecomputed,
                ClaimOutcome.Failure,
                new EArkClaimContext(
                    EArkClaimReason.ReferenceUnresolved,
                    $"{overAFolder} of {stated.Count} stated fixity values name a folder rather than a file, so no octets could be read to recompute them"),
                Claim.NoSubClaims);
        }
        else if(recomputed > 0)
        {
            recomputationClaim = Met(EArkClaimIds.PackageFixityRecomputed, $"{recomputed} recomputed fixity values");
        }
        else if(context.Deviations.UnrecomputableFixityFailsThePackage)
        {
            recomputationClaim = new Claim(
                EArkClaimIds.PackageFixityRecomputed,
                ClaimOutcome.Failure,
                new EArkClaimContext(EArkClaimReason.MandatoryRequirementUnmet, "a fixity value this library can recompute"),
                Claim.NoSubClaims);
        }
        else
        {
            recomputationClaim = NotSupplied(EArkClaimIds.PackageFixityRecomputed, "octets and an algorithm a fixity value could be recomputed from");
        }

        Claim strengthClaim;
        if(stated.Count == 0)
        {
            strengthClaim = Conditional(EArkClaimIds.PackageFixityAlgorithmStrength, applies: false, holds: false, "a stated fixity value");
        }
        else if(weak == 0)
        {
            strengthClaim = Met(EArkClaimIds.PackageFixityAlgorithmStrength, $"{stated.Count} fixity values, all under an algorithm this library recomputes");
        }
        else
        {
            strengthClaim = new Claim(
                EArkClaimIds.PackageFixityAlgorithmStrength,
                context.Deviations.WeakFixityAlgorithmFailsThePackage ? ClaimOutcome.Failure : ClaimOutcome.Inconclusive,
                new EArkClaimContext(EArkClaimReason.FixityAlgorithmFlagged, $"{weak} of {stated.Count} fixity values under an algorithm this library will not treat as evidence"),
                Claim.NoSubClaims);
        }

        return [recomputationClaim, strengthClaim];
    }


    /// <summary>
    /// Checks that every reference the package's manifest makes to a file of its own resolves to an entry the
    /// package holds — the blanket obligation clause 5.1 states in prose and gives no identifier of its own.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.PackageReferencesResolve"/>.</returns>
    /// <remarks>
    /// A reference is resolved by comparing it against the package's entry names exactly, after stripping the
    /// leading current-directory marker a relative path may carry. Comparison is ordinal for the reason every
    /// other name comparison in this wave is: a reader that folded case would resolve a reference to a file the
    /// producer did not name.
    /// <see href="https://earkcsip.dilcis.eu/specification/implementation/metadata/general-requirements/">E-ARK
    /// CSIP v2.2.0 clause 5.1</see>.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckManifestReferencesResolve(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        MetsDocument? manifest = context.PackageManifest;
        EArkPackageFacts? facts = context.PackageFacts;
        if(manifest is null || facts is null)
        {
            return ValueTask.FromResult<List<Claim>>(
                [NotSupplied(EArkClaimIds.PackageReferencesResolve, "the package manifest and the classified package facts")]);
        }

        var hrefs = new List<string?>();
        CollectReferenceHrefs(manifest, hrefs);

        int unresolved = 0;
        for(int i = 0; i < hrefs.Count; ++i)
        {
            if(ResolveHref(facts.Snapshot, hrefs[i]) is null)
            {
                ++unresolved;
            }
        }

        Claim claim;
        if(hrefs.Count == 0)
        {
            claim = Conditional(EArkClaimIds.PackageReferencesResolve, applies: false, holds: false, "a reference the manifest makes");
        }
        else if(unresolved == 0)
        {
            claim = Met(EArkClaimIds.PackageReferencesResolve, $"{hrefs.Count} references");
        }
        else
        {
            claim = new Claim(
                EArkClaimIds.PackageReferencesResolve,
                ClaimOutcome.Failure,
                new EArkClaimContext(EArkClaimReason.ReferenceUnresolved, $"{unresolved} of {hrefs.Count} references"),
                Claim.NoSubClaims);
        }

        return ValueTask.FromResult<List<Claim>>([claim]);
    }


    /// <summary>
    /// Checks that every identifier the package's manifest carries is a legal <c>NCName</c> — the second
    /// obligation clause 5.1 states in prose and gives no identifier of its own, and the one whose practical
    /// trap the specification itself calls out: a bare universally-unique identifier may begin with a digit
    /// and is therefore not one.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.PackageIdentifiersAreNCNames"/>.</returns>
    /// <remarks>
    /// <see href="https://earkcsip.dilcis.eu/specification/implementation/metadata/general-requirements/">E-ARK
    /// CSIP v2.2.0 clause 5.1</see>.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckManifestIdentifiersAreNCNames(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        MetsDocument? manifest = context.PackageManifest;
        if(manifest is null)
        {
            return ValueTask.FromResult<List<Claim>>(
                [NotSupplied(EArkClaimIds.PackageIdentifiersAreNCNames, "the package manifest")]);
        }

        var identifiers = new List<string?>();
        CollectIdentifiers(manifest, identifiers);

        int malformed = 0;
        for(int i = 0; i < identifiers.Count; ++i)
        {
            if(!MetsWellKnown.IsNCName(identifiers[i]))
            {
                ++malformed;
            }
        }

        Claim claim = identifiers.Count == 0
            ? Conditional(EArkClaimIds.PackageIdentifiersAreNCNames, applies: false, holds: false, "an identifier the manifest carries")
            : Mandatory(EArkClaimIds.PackageIdentifiersAreNCNames, malformed == 0, $"{identifiers.Count} identifiers");

        return ValueTask.FromResult<List<Claim>>([claim]);
    }


    /// <summary>The requirements <see cref="CheckPackageEvidencePlacement"/> issues.</summary>
    public static IReadOnlyList<ClaimId> PackageEvidencePlacementClaimIds { get; } =
    [
        EArkClaimIds.PackageEvidencePlacement
    ];

    /// <summary>The requirements <see cref="CheckPackageEvidenceSelfDescription"/> issues.</summary>
    public static IReadOnlyList<ClaimId> PackageEvidenceSelfDescriptionClaimIds { get; } =
    [
        EArkClaimIds.PackageEvidenceSelfDescription,
        PreservationClaimIds.Ovr92Item04,
        PreservationClaimIds.Ovr92Item05
    ];

    /// <summary>The requirements <see cref="CheckPackageProvenanceAnchoredAsync"/> issues.</summary>
    public static IReadOnlyList<ClaimId> PackageProvenanceAnchorClaimIds { get; } =
    [
        EArkClaimIds.PackageProvenanceAnchored
    ];


    /// <summary>
    /// Checks that every evidential artifact the caller found in the package sits where this library's placement
    /// convention puts one, is named by the manifest with a digest this library can recompute, and is recorded by
    /// a preservation event and a relationship saying what it attests.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.PackageEvidencePlacement"/>.</returns>
    /// <remarks>
    /// <para>
    /// <strong>Why this is a house rule and reads as a MUST.</strong> Neither source specification has any
    /// notion of a signature, a time assertion or an evidence record, so nothing here restates a requirement
    /// they make. What it does state is that a package this library judges either follows the placement
    /// convention completely or does not claim it: a signature file sitting somewhere the convention does not
    /// put one, or named by no event, is a file a reader cannot tell from ordinary content — which is the
    /// failure mode the convention exists to prevent, so a stated artifact that departs from it fails rather
    /// than being noted.
    /// </para>
    /// <para>
    /// A caller that states no artifacts gets <see cref="EArkClaimReason.SubjectNotSupplied"/>, never success:
    /// a package holding no evidence and a caller that never looked for any are indistinguishable from here,
    /// and reporting the second as conformance would be the worst answer available.
    /// </para>
    /// </remarks>
    public static ValueTask<List<Claim>> CheckPackageEvidencePlacement(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<EArkEvidenceArtifactFacts> artifacts = context.EvidenceArtifacts;
        MetsDocument? manifest = context.PackageManifest;
        EArkPackageFacts? facts = context.PackageFacts;
        if(artifacts.Count == 0 || manifest is null || facts is null)
        {
            return ValueTask.FromResult<List<Claim>>(
                [NotSupplied(EArkClaimIds.PackageEvidencePlacement, "the evidential artifacts the package carries, the package manifest and the classified package facts")]);
        }

        int placed = 0;
        for(int i = 0; i < artifacts.Count; ++i)
        {
            EArkEvidenceArtifactFacts artifact = artifacts[i];
            if(SitsWhereTheConventionPutsIt(facts, artifact.EntryName)
                && ManifestNamesItWithARecomputableDigest(manifest, facts, artifact.EntryName)
                && PreservationMetadataRecordsIt(context.PreservationMetadata, artifact.EntryName))
            {
                ++placed;
            }
        }

        return ValueTask.FromResult<List<Claim>>(
            [Mandatory(EArkClaimIds.PackageEvidencePlacement, placed == artifacts.Count, $"{placed} of {artifacts.Count} evidential artifacts placed by the convention")]);

        //Whether the tree classifier put the artifact at one of the two positions the convention states.
        static bool SitsWhereTheConventionPutsIt(EArkPackageFacts facts, string entryName)
        {
            for(int i = 0; i < facts.Entries.Count; ++i)
            {
                if(string.Equals(facts.Entries[i].Entry.Name, entryName, StringComparison.Ordinal))
                {
                    return EArkEvidenceWellKnown.IsEvidencePlacement(facts.Entries[i].Placement);
                }
            }

            return false;
        }

        //Whether some file entry of the manifest names the artifact and states a fixity this library recomputes.
        static bool ManifestNamesItWithARecomputableDigest(MetsDocument manifest, EArkPackageFacts facts, string entryName)
        {
            MetsFileSection? fileSection = manifest.FileSection;
            if(fileSection is null)
            {
                return false;
            }

            for(int i = 0; i < fileSection.FileGroups.Count; ++i)
            {
                IReadOnlyList<MetsFile> files = fileSection.FileGroups[i].Files;
                for(int j = 0; j < files.Count; ++j)
                {
                    EArkPackageEntry? resolved = ResolveHref(facts.Snapshot, files[j].Locator.Href);
                    if(resolved is not null
                        && string.Equals(resolved.Name, entryName, StringComparison.Ordinal)
                        && files[j].Fixity.IsRecomputable)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        //Whether a preservation-metadata document records the artifact with both halves of the convention: an
        //event of one of its types linking the artifact's object identifier, and a relationship of its type.
        static bool PreservationMetadataRecordsIt(IReadOnlyList<PremisDocument> documents, string entryName)
        {
            PremisIdentifier identifier = EArkEvidenceWellKnown.EvidenceObjectIdentifier(entryName);
            bool eventFound = false;
            bool relationshipFound = false;
            for(int i = 0; i < documents.Count && !(eventFound && relationshipFound); ++i)
            {
                IReadOnlyList<PremisEvent> events = documents[i].Events;
                for(int j = 0; j < events.Count && !eventFound; ++j)
                {
                    eventFound = EArkEvidenceWellKnown.IsEvidenceEventType(events[j].Type)
                        && ContainsIdentifier([.. events[j].LinkingObjectIdentifiers], identifier);
                }

                IReadOnlyList<PremisObject> objects = documents[i].Objects;
                for(int j = 0; j < objects.Count && !relationshipFound; ++j)
                {
                    IReadOnlyList<PremisRelationship> relationships = objects[j].Relationships;
                    for(int k = 0; k < relationships.Count && !relationshipFound; ++k)
                    {
                        relationshipFound = EArkEvidenceWellKnown.IsEvidenceRelationship(relationships[k].Type, relationships[k].SubType)
                            && (ContainsIdentifier([.. objects[j].Identifiers], identifier)
                                || ContainsIdentifier([.. relationships[k].RelatedObjectIdentifiers], identifier));
                    }
                }
            }

            return eventFound && relationshipFound;
        }
    }


    /// <summary>
    /// Checks that every evidential artifact the caller found describes the preservation service, the evidence
    /// policy and the preservation profile it was produced under, and that an embedded policy reference sits
    /// where something proves it.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim per requirement of <see cref="PackageEvidenceSelfDescriptionClaimIds"/>.</returns>
    /// <remarks>
    /// <para>
    /// <c>OVR-9.2-04</c> binds under a condition a package cannot decide — "if the preservation evidence policy
    /// can't be identified from the context" — because whether context supplies it is a fact about the archive's
    /// operation and not about the octets. The rule therefore reports the decidable half: an evidence carrying
    /// the reference satisfies the requirement whatever the context, and one not carrying it leaves the
    /// requirement undecided rather than failing a package that identifies its policy some other way.
    /// <c>OVR-9.2-05</c> binds only once something is embedded, which is a condition the artifacts do decide.
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
    /// ETSI TS 119 511 V1.2.1 clause 9.2</see>.
    /// </para>
    /// </remarks>
    public static ValueTask<List<Claim>> CheckPackageEvidenceSelfDescription(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<EArkEvidenceArtifactFacts> artifacts = context.EvidenceArtifacts;
        if(artifacts.Count == 0)
        {
            return ValueTask.FromResult(NotSuppliedFor(PackageEvidenceSelfDescriptionClaimIds, "the evidential artifacts the package carries"));
        }

        int described = 0;
        int policyStated = 0;
        int embedded = 0;
        int protectedEmbedded = 0;
        for(int i = 0; i < artifacts.Count; ++i)
        {
            EArkEvidenceArtifactFacts artifact = artifacts[i];
            if(artifact.SelfDescription is not EArkEvidenceSelfDescription description)
            {
                continue;
            }

            ++described;
            if(description.EvidencePolicyIdentifier is not null)
            {
                ++policyStated;
                ++embedded;
                if(artifact.SelfDescriptionIsProtected)
                {
                    ++protectedEmbedded;
                }
            }
        }

        return ValueTask.FromResult<List<Claim>>(
        [
            Recommended(
                EArkClaimIds.PackageEvidenceSelfDescription,
                described == artifacts.Count,
                $"{described} of {artifacts.Count} evidential artifacts carrying a self-description"),
            Recommended(
                PreservationClaimIds.Ovr92Item04,
                policyStated == artifacts.Count,
                $"{policyStated} of {artifacts.Count} evidential artifacts carrying an evidence policy identifier"),
            Conditional(
                PreservationClaimIds.Ovr92Item05,
                applies: embedded > 0,
                holds: embedded > 0 && protectedEmbedded == embedded,
                $"{protectedEmbedded} of {embedded} embedded evidence policy identifiers protected by a later structure of their own artifact",
                recommendation: true)
        ]);
    }


    /// <summary>
    /// Checks that every digital-provenance document the package's manifest references, and the manifest that
    /// references them, are inside what one of the package's evidential artifacts proves.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, <see cref="EArkClaimIds.PackageProvenanceAnchored"/>.</returns>
    /// <remarks>
    /// <para>
    /// <strong>What this rule is for.</strong> An archival package's provenance is a chain of preservation
    /// events pointing at one another in plain text, and the manifest's own digests over those documents are
    /// plain text too — a producer rewriting a document and its stated digest together leaves a package that
    /// satisfies every structural, metadata and fixity rule of both specifications. What such a package does not
    /// satisfy is an evidential artifact created over those same octets at a time a Time-Stamping Authority
    /// asserted. This rule asks whether one exists.
    /// </para>
    /// <para>
    /// <strong>The answer is computed from the octets, never from the names.</strong>
    /// <see cref="EArkEvidenceArtifactFacts.CoveredEntryNames"/> is a list the caller states, and for a container
    /// it is established over the container's own copies rather than over the package's — so a producer who
    /// rewrites the package's copy leaves every name matching. The names are therefore read only as a cheap
    /// precondition: a package whose provenance the artifacts do not even claim to cover is refused without
    /// hashing anything. Where they do claim it, the claim is settled by
    /// <see cref="EArkEvidenceAnchoring.VerifyProvenanceAnchorAsync"/> over
    /// <see cref="EArkEvidenceArtifactFacts.Evidence"/>, which re-states the plan from the package as it now
    /// stands and walks
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.3">IETF RFC 4998 clause 4.3</see> for every
    /// covered entry with the group check.
    /// </para>
    /// <para>
    /// <strong>An artifact that states no evidence leaves the row undecided, never met.</strong> A caller who
    /// names coverage without handing over what proves it has told the rule nothing it can check, and the wave's
    /// fail-closed reading of that is <see cref="EArkClaimReason.SubjectNotSupplied"/> — the same answer a rule
    /// given no artifacts at all reaches. Reading it as met would put a cryptographic assurance in the claim set
    /// on the strength of a name list the package produced about itself.
    /// </para>
    /// <para>
    /// The row reads as a recommendation rather than as a MUST because no source specification asks for it: a
    /// package without an anchor is conformant to both, and the claim exists to make the absence visible rather
    /// than to declare a conformant package broken.
    /// <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0</see>.
    /// </para>
    /// </remarks>
    public static async ValueTask<List<Claim>> CheckPackageProvenanceAnchoredAsync(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        MetsDocument? manifest = context.PackageManifest;
        IReadOnlyList<EArkEvidenceArtifactFacts> artifacts = context.EvidenceArtifacts;
        if(manifest is null || artifacts.Count == 0)
        {
            return [NotSupplied(EArkClaimIds.PackageProvenanceAnchored, "the package manifest and the evidential artifacts the package carries")];
        }

        var toAnchor = new List<string> { EArkWellKnown.PackageManifestFileName };
        IReadOnlyList<MetsAdministrativeMetadataSection> provenanceSections =
            manifest.AdministrativeMetadata?.DigitalProvenanceSections ?? [];

        for(int i = 0; i < provenanceSections.Count; ++i)
        {
            string? href = provenanceSections[i].Reference?.Href;
            if(href is not null)
            {
                toAnchor.Add(href.StartsWith(CurrentFolderMarker, StringComparison.Ordinal) ? href[CurrentFolderMarker.Length..] : href);
            }
        }

        if(provenanceSections.Count == 0)
        {
            return [Conditional(EArkClaimIds.PackageProvenanceAnchored, applies: false, holds: false, "a digital-provenance section to anchor", recommendation: true)];
        }

        int named = 0;
        for(int i = 0; i < toAnchor.Count; ++i)
        {
            for(int j = 0; j < artifacts.Count; ++j)
            {
                if(artifacts[j].Covers(toAnchor[i]))
                {
                    ++named;
                    break;
                }
            }
        }

        if(named != toAnchor.Count)
        {
            return
            [
                Recommended(
                    EArkClaimIds.PackageProvenanceAnchored,
                    holds: false,
                    $"{named} of {toAnchor.Count} provenance documents, the manifest included, named by what an evidential artifact covers")
            ];
        }

        EArkPackageSnapshot? snapshot = context.PackageFacts?.Snapshot;
        if(snapshot is null || context.MemoryPool is null)
        {
            return [NotSupplied(EArkClaimIds.PackageProvenanceAnchored, "the package snapshot and the memory pool the covered octets are verified through")];
        }

        var anchorContext = new EArkProvenanceAnchorContext { Snapshot = snapshot, PackageManifest = manifest };
        int verifiable = 0;
        string? refusal = null;
        for(int i = 0; i < artifacts.Count; ++i)
        {
            if(artifacts[i].Evidence is not EvidenceRecord evidence || !CoversEvery(artifacts[i], toAnchor))
            {
                continue;
            }

            ++verifiable;
            using EArkProvenanceAnchorVerification verification = await EArkEvidenceAnchoring.VerifyProvenanceAnchorAsync(
                new EArkProvenanceAnchorVerificationContext { EvidenceRecord = evidence, Package = anchorContext },
                context.MemoryPool,
                cancellationToken).ConfigureAwait(false);

            if(verification.IsAnchored)
            {
                return
                [
                    Met(
                        EArkClaimIds.PackageProvenanceAnchored,
                        $"{toAnchor.Count} provenance documents, the manifest included, verified against the evidence of '{artifacts[i].EntryName}'")
                ];
            }

            refusal ??= verification.UncoveredEntryName is string uncovered
                ? $"'{uncovered}' is not inside what the evidence of '{artifacts[i].EntryName}' proves"
                : $"the package states {DescribePlan(verification.Plan?.Status ?? EArkProvenanceAnchorStatus.NotEvaluated)}";
        }

        return verifiable == 0
            ?
            [
                NotSupplied(
                    EArkClaimIds.PackageProvenanceAnchored,
                    $"an evidential artifact stating the evidence its coverage of the {toAnchor.Count} provenance documents, the manifest included, rests on")
            ]
            : [Recommended(EArkClaimIds.PackageProvenanceAnchored, holds: false, refusal!)];

        //Whether one artifact's stated coverage names every document the anchor has to reach. The rule verifies
        //against an artifact only when it does, because a partial anchor proves a different statement than the
        //one the claim makes and would fail the group check anyway.
        static bool CoversEvery(EArkEvidenceArtifactFacts artifact, List<string> toAnchor)
        {
            for(int i = 0; i < toAnchor.Count; ++i)
            {
                if(!artifact.Covers(toAnchor[i]))
                {
                    return false;
                }
            }

            return true;
        }

        //Why no plan could be stated, in the words the claim's subject reads in. Kept exhaustive so that a
        //further status added to the plan is a compilation decision rather than a silent default.
        static string DescribePlan(EArkProvenanceAnchorStatus status) => status switch
        {
            EArkProvenanceAnchorStatus.Stated => "a plan whose entries the evidence does not prove",
            EArkProvenanceAnchorStatus.NoProvenanceReferenced => "no digital-provenance reference to anchor",
            EArkProvenanceAnchorStatus.ReferencedEntryMissing => "a digital-provenance reference naming an entry it does not hold",
            EArkProvenanceAnchorStatus.ManifestMissing => "no manifest entry for the references to be anchored with",
            EArkProvenanceAnchorStatus.LimitExceeded => "more entries to anchor than the anchor admits",
            _ => "no anchor plan at all"
        };
    }


    /// <summary>The marker a relative reference may lead with to name the folder it sits in, <c>./</c>.</summary>
    private static string CurrentFolderMarker { get; } = "./";


    /// <summary>Builds the claim a requirement stated as a MUST reaches.</summary>
    /// <param name="claimId">The requirement.</param>
    /// <param name="holds">Whether the requirement holds of what the rule looked at.</param>
    /// <param name="subject">A short phrase naming what the rule looked at.</param>
    /// <returns>The claim, successful when the requirement holds and failed when it does not.</returns>
    private static Claim Mandatory(ClaimId claimId, bool holds, string subject) =>
        holds
            ? Met(claimId, subject)
            : new Claim(claimId, ClaimOutcome.Failure, new EArkClaimContext(EArkClaimReason.MandatoryRequirementUnmet, subject), Claim.NoSubClaims);


    /// <summary>Builds the claim a requirement stated as a SHOULD reaches.</summary>
    /// <param name="claimId">The requirement.</param>
    /// <param name="holds">Whether the requirement holds of what the rule looked at.</param>
    /// <param name="subject">A short phrase naming what the rule looked at.</param>
    /// <returns>The claim, successful when the requirement holds and inconclusive when the package declined it.</returns>
    private static Claim Recommended(ClaimId claimId, bool holds, string subject) =>
        holds
            ? Met(claimId, subject)
            : new Claim(claimId, ClaimOutcome.Inconclusive, new EArkClaimContext(EArkClaimReason.RecommendedRequirementUnmet, subject), Claim.NoSubClaims);


    /// <summary>Builds the claim a requirement stated as a MAY reaches.</summary>
    /// <param name="claimId">The requirement.</param>
    /// <param name="present">Whether the subject the requirement permits is present.</param>
    /// <param name="subject">A short phrase naming what the rule looked at.</param>
    /// <returns>The claim, successful when the package took the permission and not applicable when it did not.</returns>
    private static Claim Optional(ClaimId claimId, bool present, string subject) =>
        present
            ? Met(claimId, subject)
            : new Claim(claimId, ClaimOutcome.NotApplicable, new EArkClaimContext(EArkClaimReason.OptionalSubjectAbsent, subject), Claim.NoSubClaims);


    /// <summary>
    /// Builds the claim a requirement that binds only under a condition reaches — the shape most rows of the
    /// requirement catalogues take, because they constrain an element that a higher-level row makes optional.
    /// </summary>
    /// <param name="claimId">The requirement.</param>
    /// <param name="applies">Whether the condition the requirement binds under holds.</param>
    /// <param name="holds">Whether the requirement itself holds, read only when the condition does.</param>
    /// <param name="subject">A short phrase naming what the rule looked at.</param>
    /// <param name="recommendation">Whether the requirement is a SHOULD rather than a MUST.</param>
    /// <param name="optional">Whether the requirement is a MAY, in which case an absent subject is not applicable rather than unmet.</param>
    /// <returns>The claim.</returns>
    private static Claim Conditional(
        ClaimId claimId,
        bool applies,
        bool holds,
        string subject,
        bool recommendation = false,
        bool optional = false)
    {
        if(!applies)
        {
            return new Claim(claimId, ClaimOutcome.NotApplicable, new EArkClaimContext(EArkClaimReason.ConditionNotTriggered, subject), Claim.NoSubClaims);
        }

        if(holds)
        {
            return Met(claimId, subject);
        }

        return optional
            ? new Claim(claimId, ClaimOutcome.NotApplicable, new EArkClaimContext(EArkClaimReason.OptionalSubjectAbsent, subject), Claim.NoSubClaims)
            : recommendation
                ? new Claim(claimId, ClaimOutcome.Inconclusive, new EArkClaimContext(EArkClaimReason.RecommendedRequirementUnmet, subject), Claim.NoSubClaims)
                : new Claim(claimId, ClaimOutcome.Failure, new EArkClaimContext(EArkClaimReason.MandatoryRequirementUnmet, subject), Claim.NoSubClaims);
    }


    /// <summary>Builds the claim a requirement that holds reaches.</summary>
    /// <param name="claimId">The requirement.</param>
    /// <param name="subject">A short phrase naming what the rule looked at.</param>
    /// <returns>A successful claim.</returns>
    private static Claim Met(ClaimId claimId, string subject) =>
        new(claimId, ClaimOutcome.Success, new EArkClaimContext(EArkClaimReason.RequirementMet, subject), Claim.NoSubClaims);


    /// <summary>Builds the claim a rule the caller gave nothing to judge reaches.</summary>
    /// <param name="claimId">The requirement.</param>
    /// <param name="subject">A short phrase naming what the rule needed and was not given.</param>
    /// <returns>An inconclusive claim, which is never mistaken for success and never reported as a package defect.</returns>
    private static Claim NotSupplied(ClaimId claimId, string subject) =>
        new(claimId, ClaimOutcome.Inconclusive, new EArkClaimContext(EArkClaimReason.SubjectNotSupplied, subject), Claim.NoSubClaims);


    /// <summary>Builds the claim a rule that applied a documented interpretation of a defect in the source specification reaches.</summary>
    /// <param name="claimId">The requirement.</param>
    /// <param name="outcome">The outcome the interpretation reached.</param>
    /// <param name="subject">A short phrase naming what the rule looked at and which interpretation it applied.</param>
    /// <returns>The claim, carrying the interpretation as its reason so that it is visible in the claim set.</returns>
    private static Claim Interpreted(ClaimId claimId, ClaimOutcome outcome, string subject) =>
        new(claimId, outcome, new EArkClaimContext(EArkClaimReason.InterpretationApplied, subject), Claim.NoSubClaims);


    /// <summary>
    /// Builds the claim a requirement stated with the keyword <c>COULD</c> reaches — a keyword the source
    /// specification's own conformance section does not define.
    /// </summary>
    /// <param name="context">The package validation is given, whose deviation policy states how to read it.</param>
    /// <param name="claimId">The requirement.</param>
    /// <param name="present">Whether the subject the requirement describes is present.</param>
    /// <param name="subject">A short phrase naming what the rule looked at.</param>
    /// <returns>The claim, always carrying <see cref="EArkClaimReason.InterpretationApplied"/>.</returns>
    private static Claim UndefinedKeyword(EArkValidationContext context, ClaimId claimId, bool present, string subject) =>
        context.Deviations.UndefinedKeywordReadsAsOptional
            ? Interpreted(claimId, present ? ClaimOutcome.Success : ClaimOutcome.NotApplicable, subject + ", stated with the undefined keyword COULD and read as MAY")
            : Interpreted(claimId, ClaimOutcome.Inconclusive, subject + ", stated with the undefined keyword COULD, which this validation declines to read as any defined term");


    /// <summary>Builds one not-supplied claim per requirement of a group.</summary>
    /// <param name="claimIds">The requirements the group issues.</param>
    /// <param name="subject">A short phrase naming what the group needed and was not given.</param>
    /// <returns>One claim per requirement, so a group that could not run still answers for every row it owns.</returns>
    private static List<Claim> NotSuppliedFor(IReadOnlyList<ClaimId> claimIds, string subject)
    {
        var claims = new List<Claim>(claimIds.Count);
        for(int i = 0; i < claimIds.Count; ++i)
        {
            claims.Add(NotSupplied(claimIds[i], subject));
        }

        return claims;
    }


    /// <summary>Adds one not-applicable claim per requirement whose condition the package did not trigger.</summary>
    /// <param name="claims">The claim list being built.</param>
    /// <param name="subject">A short phrase naming the condition that did not hold.</param>
    /// <param name="claimIds">The requirements the condition gates.</param>
    private static void AddNotApplicableFor(List<Claim> claims, string subject, params ClaimId[] claimIds)
    {
        for(int i = 0; i < claimIds.Length; ++i)
        {
            claims.Add(Conditional(claimIds[i], applies: false, holds: false, subject));
        }
    }


    /// <summary>Builds the single claim a folder requirement stated over every representation reaches.</summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="claimId">The requirement.</param>
    /// <param name="holds">What the requirement asks of one representation.</param>
    /// <param name="subject">A short phrase naming what the rule looked at.</param>
    /// <returns>One claim: not supplied without facts, not applicable without representations, and a recommendation otherwise.</returns>
    private static List<Claim> PerRepresentation(
        EArkValidationContext context,
        ClaimId claimId,
        Func<EArkRepresentationFacts, bool> holds,
        string subject)
    {
        ArgumentNullException.ThrowIfNull(context);

        EArkPackageFacts? facts = context.PackageFacts;
        if(facts is null)
        {
            return [NotSupplied(claimId, "the classified package facts")];
        }

        bool everyRepresentation = true;
        for(int i = 0; i < facts.Representations.Count; ++i)
        {
            everyRepresentation &= holds(facts.Representations[i]);
        }

        return [Conditional(claimId, facts.Representations.Count > 0, everyRepresentation, subject, recommendation: true)];
    }


    /// <summary>Builds the single claim a folder requirement stated at package level, representation level or both reaches.</summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="claimId">The requirement.</param>
    /// <param name="holds">What the requirement asks of one level.</param>
    /// <param name="subject">A short phrase naming what the rule looked at.</param>
    /// <returns>One claim: not supplied without facts, and a recommendation otherwise.</returns>
    private static List<Claim> AtEitherLevel(
        EArkValidationContext context,
        ClaimId claimId,
        Func<EArkLevelFacts, bool> holds,
        string subject)
    {
        ArgumentNullException.ThrowIfNull(context);

        EArkPackageFacts? facts = context.PackageFacts;
        if(facts is null)
        {
            return [NotSupplied(claimId, "the classified package facts")];
        }

        bool anyLevel = holds(facts.Package);
        for(int i = 0; i < facts.Representations.Count && !anyLevel; ++i)
        {
            anyLevel = holds(facts.Representations[i].Contents);
        }

        return [Recommended(claimId, anyLevel, subject)];
    }


    /// <summary>Determines whether a fixity states a checksum value at all.</summary>
    /// <param name="fixity">The fixity the document stated.</param>
    /// <returns><see langword="true"/> when a value is stated, whether or not this library can recompute it.</returns>
    private static bool StatesChecksum(EArkFixity fixity) => fixity switch
    {
        EArkRecomputableFixity => true,
        EArkStatedFixity stated => stated.Checksum.Length > 0,
        _ => false
    };


    /// <summary>Determines whether a fixity states an algorithm name the enclosing specification's enumeration admits.</summary>
    /// <param name="fixity">The fixity the document stated.</param>
    /// <returns><see langword="true"/> when the name is one the enumeration states.</returns>
    private static bool StatesChecksumType(EArkFixity fixity) => fixity switch
    {
        EArkRecomputableFixity => true,
        EArkStatedFixity stated => MetsWellKnown.IsChecksumType(stated.ChecksumType),
        _ => false
    };


    /// <summary>
    /// Determines whether a fixity states an algorithm name at all, which the preservation-metadata
    /// vocabulary — whose hash-function vocabulary is externally hosted and open — asks for rather than
    /// membership of a closed enumeration.
    /// </summary>
    /// <param name="fixity">The fixity the document stated.</param>
    /// <returns><see langword="true"/> when a name is stated.</returns>
    private static bool StatesChecksumAlgorithmName(EArkFixity fixity) => fixity switch
    {
        EArkRecomputableFixity => true,
        EArkStatedFixity stated => stated.ChecksumType.Length > 0,
        _ => false
    };


    /// <summary>
    /// Adds the nine claims the metadata-reference rows make, which the descriptive, digital-provenance and
    /// rights sections each repeat verbatim.
    /// </summary>
    /// <param name="claims">The claim list being built.</param>
    /// <param name="references">The references the sections carried.</param>
    /// <param name="subject">A short phrase naming the element path the references sit at.</param>
    /// <param name="locatorType">The locator-type requirement.</param>
    /// <param name="linkType">The link-type requirement.</param>
    /// <param name="href">The resource-location requirement.</param>
    /// <param name="metadataType">The metadata-type requirement.</param>
    /// <param name="mediaType">The media-type requirement.</param>
    /// <param name="size">The file-size requirement.</param>
    /// <param name="created">The creation-datetime requirement.</param>
    /// <param name="checksum">The checksum requirement.</param>
    /// <param name="checksumType">The checksum-type requirement.</param>
    private static void AddMetadataReferenceClaims(
        List<Claim> claims,
        List<MetsMetadataReference> references,
        string subject,
        ClaimId locatorType,
        ClaimId linkType,
        ClaimId href,
        ClaimId metadataType,
        ClaimId mediaType,
        ClaimId size,
        ClaimId created,
        ClaimId checksum,
        ClaimId checksumType)
    {
        bool anyReference = references.Count > 0;
        bool everyLocatorTypeIsUrl = true;
        bool everyLinkTypeIsSimple = true;
        bool everyHrefStated = true;
        bool everyMetadataTypeStated = true;
        bool everyMediaTypeStated = true;
        bool everySizeStated = true;
        bool everyChecksumStated = true;
        bool everyChecksumTypeStated = true;
        for(int i = 0; i < references.Count; ++i)
        {
            MetsMetadataReference reference = references[i];
            everyLocatorTypeIsUrl &= string.Equals(reference.LocatorType, MetsWellKnown.UrlLocatorType, StringComparison.Ordinal);
            everyLinkTypeIsSimple &= string.Equals(reference.LinkType, MetsWellKnown.SimpleLinkType, StringComparison.Ordinal);
            everyHrefStated &= !string.IsNullOrEmpty(reference.Href);
            everyMetadataTypeStated &= !string.IsNullOrEmpty(reference.MetadataType);
            everyMediaTypeStated &= !string.IsNullOrEmpty(reference.MediaType);
            everySizeStated &= reference.Size >= 0;
            everyChecksumStated &= StatesChecksum(reference.Fixity);
            everyChecksumTypeStated &= StatesChecksumType(reference.Fixity);
        }

        claims.Add(Conditional(locatorType, anyReference, everyLocatorTypeIsUrl, subject + "[@LOCTYPE='URL']"));
        claims.Add(Conditional(linkType, anyReference, everyLinkTypeIsSimple, subject + "[@xlink:type='simple']"));
        claims.Add(Conditional(href, anyReference, everyHrefStated, subject + "/@xlink:href"));
        claims.Add(Conditional(metadataType, anyReference, everyMetadataTypeStated, subject + "/@MDTYPE"));
        claims.Add(Conditional(mediaType, anyReference, everyMediaTypeStated, subject + "/@MIMETYPE"));
        claims.Add(Conditional(size, anyReference, everySizeStated, subject + "/@SIZE"));
        claims.Add(Conditional(created, anyReference, true, subject + "/@CREATED, which the manifest model cannot omit"));
        claims.Add(Conditional(checksum, anyReference, everyChecksumStated, subject + "/@CHECKSUM"));
        claims.Add(Conditional(checksumType, anyReference, everyChecksumTypeStated, subject + "/@CHECKSUMTYPE"));
    }


    /// <summary>
    /// Adds the twelve claims one administrative sub-section makes: its own presence, identifier and status,
    /// its reference, and the nine reference rows.
    /// </summary>
    /// <param name="claims">The claim list being built.</param>
    /// <param name="sections">The sub-sections the manifest carried.</param>
    /// <param name="subject">A short phrase naming the element path the sub-sections sit at.</param>
    /// <param name="sectionPresence">The requirement over the sub-section's own presence.</param>
    /// <param name="sectionPresenceIsRecommendation">Whether that requirement is a SHOULD rather than a MAY.</param>
    /// <param name="identifier">The identifier requirement.</param>
    /// <param name="status">The status requirement.</param>
    /// <param name="reference">The reference-presence requirement.</param>
    /// <param name="locatorType">The locator-type requirement.</param>
    /// <param name="linkType">The link-type requirement.</param>
    /// <param name="href">The resource-location requirement.</param>
    /// <param name="metadataType">The metadata-type requirement.</param>
    /// <param name="mediaType">The media-type requirement.</param>
    /// <param name="size">The file-size requirement.</param>
    /// <param name="created">The creation-datetime requirement.</param>
    /// <param name="checksum">The checksum requirement.</param>
    /// <param name="checksumType">The checksum-type requirement.</param>
    private static void AddAdministrativeSectionClaims(
        List<Claim> claims,
        IReadOnlyList<MetsAdministrativeMetadataSection> sections,
        string subject,
        ClaimId sectionPresence,
        bool sectionPresenceIsRecommendation,
        ClaimId identifier,
        ClaimId status,
        ClaimId reference,
        ClaimId locatorType,
        ClaimId linkType,
        ClaimId href,
        ClaimId metadataType,
        ClaimId mediaType,
        ClaimId size,
        ClaimId created,
        ClaimId checksum,
        ClaimId checksumType)
    {
        bool anySection = sections.Count > 0;
        bool everyIdIsNCName = true;
        bool everyStatusStated = true;
        bool everySectionReferences = true;
        var references = new List<MetsMetadataReference>(sections.Count);
        for(int i = 0; i < sections.Count; ++i)
        {
            MetsAdministrativeMetadataSection section = sections[i];
            everyIdIsNCName &= MetsWellKnown.IsNCName(section.Id);
            everyStatusStated &= !string.IsNullOrEmpty(section.Status);
            if(section.Reference is null)
            {
                everySectionReferences = false;
            }
            else
            {
                references.Add(section.Reference);
            }
        }

        claims.Add(sectionPresenceIsRecommendation
            ? Recommended(sectionPresence, anySection, subject)
            : Optional(sectionPresence, anySection, subject));
        claims.Add(Conditional(identifier, anySection, everyIdIsNCName, subject + "/@ID"));
        claims.Add(Conditional(status, anySection, everyStatusStated, subject + "/@STATUS", recommendation: true));
        claims.Add(Conditional(reference, anySection, everySectionReferences, subject + "/mdRef", recommendation: true));

        AddMetadataReferenceClaims(
            claims, references, subject + "/mdRef",
            locatorType, linkType, href, metadataType, mediaType, size, created, checksum, checksumType);
    }


    /// <summary>Adds the three claims one named structural-map division makes: its presence, its identifier and its label.</summary>
    /// <param name="claims">The claim list being built.</param>
    /// <param name="division">The division, or <see langword="null"/> when the map carries none under that label.</param>
    /// <param name="labelValue">The label the specification fixes for the division.</param>
    /// <param name="presence">The requirement over the division's own presence.</param>
    /// <param name="presenceIsRecommendation">Whether that requirement is a SHOULD rather than a MUST.</param>
    /// <param name="identifier">The identifier requirement.</param>
    /// <param name="label">The label requirement.</param>
    private static void AddDivisionClaims(
        List<Claim> claims,
        MetsDivision? division,
        string labelValue,
        ClaimId presence,
        bool presenceIsRecommendation,
        ClaimId identifier,
        ClaimId label)
    {
        claims.Add(presenceIsRecommendation
            ? Recommended(presence, division is not null, $"the division labelled '{labelValue}'")
            : Mandatory(presence, division is not null, $"the division labelled '{labelValue}'"));
        claims.Add(Conditional(identifier, division is not null, MetsWellKnown.IsNCName(division?.Id), $"the '{labelValue}' division's @ID"));
        claims.Add(Conditional(label, division is not null, string.Equals(division?.Label, labelValue, StringComparison.Ordinal), $"the '{labelValue}' division's @LABEL"));
    }


    /// <summary>Adds the two claims one named division's file pointers make: their presence and their file identifiers.</summary>
    /// <param name="claims">The claim list being built.</param>
    /// <param name="division">The division, or <see langword="null"/> when the map carries none under that label.</param>
    /// <param name="subject">A short phrase naming the pointers.</param>
    /// <param name="presence">The requirement over the pointers' presence.</param>
    /// <param name="fileId">The requirement over each pointer's file identifier.</param>
    private static void AddFilePointerClaims(
        List<Claim> claims,
        MetsDivision? division,
        string subject,
        ClaimId presence,
        ClaimId fileId)
    {
        IReadOnlyList<MetsFilePointer> pointers = division?.FilePointers ?? [];
        bool anyPointer = pointers.Count > 0;
        bool everyPointerIdentifiesAFile = true;
        for(int i = 0; i < pointers.Count; ++i)
        {
            everyPointerIdentifiesAFile &= !string.IsNullOrEmpty(pointers[i].FileId);
        }

        claims.Add(Conditional(presence, division is not null, anyPointer, subject, recommendation: true));
        claims.Add(Conditional(fileId, anyPointer, everyPointerIdentifiesAFile, subject + "/@FILEID"));
    }


    /// <summary>Adds the five claims one group of relationships makes: the type, the subtype and the related object's identification.</summary>
    /// <param name="claims">The claim list being built.</param>
    /// <param name="relationships">The relationships the objects carried.</param>
    /// <param name="subject">A short phrase naming the relationships.</param>
    /// <param name="type">The relationship-type requirement.</param>
    /// <param name="subType">The relationship-subtype requirement.</param>
    /// <param name="relatedObject">The related-object-identifier presence requirement.</param>
    /// <param name="relatedObjectType">The related-object-identifier type requirement.</param>
    /// <param name="relatedObjectValue">The related-object-identifier value requirement.</param>
    private static void AddRelationshipClaims(
        List<Claim> claims,
        List<PremisRelationship> relationships,
        string subject,
        ClaimId type,
        ClaimId subType,
        ClaimId relatedObject,
        ClaimId relatedObjectType,
        ClaimId relatedObjectValue)
    {
        bool anyRelationship = relationships.Count > 0;
        bool everyTypeStated = true;
        bool everySubTypeStated = true;
        bool everyRelationshipNamesAnObject = true;
        bool anyRelatedObject = false;
        bool everyRelatedObjectTyped = true;
        bool everyRelatedObjectValued = true;
        for(int i = 0; i < relationships.Count; ++i)
        {
            PremisRelationship relationship = relationships[i];
            everyTypeStated &= !string.IsNullOrEmpty(relationship.Type);
            everySubTypeStated &= !string.IsNullOrEmpty(relationship.SubType);
            everyRelationshipNamesAnObject &= relationship.RelatedObjectIdentifiers.Count > 0;
            for(int identifierIndex = 0; identifierIndex < relationship.RelatedObjectIdentifiers.Count; ++identifierIndex)
            {
                anyRelatedObject = true;
                everyRelatedObjectTyped &= !string.IsNullOrEmpty(relationship.RelatedObjectIdentifiers[identifierIndex].Type);
                everyRelatedObjectValued &= !string.IsNullOrEmpty(relationship.RelatedObjectIdentifiers[identifierIndex].Value);
            }
        }

        claims.Add(Conditional(type, anyRelationship, everyTypeStated, subject + " type"));
        claims.Add(Conditional(subType, anyRelationship, everySubTypeStated, subject + " subtype"));
        claims.Add(Conditional(relatedObject, anyRelationship, everyRelationshipNamesAnObject, subject + "'s relatedObjectIdentifier"));
        claims.Add(Conditional(relatedObjectType, anyRelatedObject, everyRelatedObjectTyped, subject + "'s relatedObjectIdentifierType"));
        claims.Add(Conditional(relatedObjectValue, anyRelatedObject, everyRelatedObjectValued, subject + "'s relatedObjectIdentifierValue"));
    }


    /// <summary>Determines whether every object of every document states a category the vocabulary names.</summary>
    /// <param name="documents">The preservation-metadata documents.</param>
    /// <returns><see langword="true"/> when no object states a category outside the vocabulary.</returns>
    private static bool EveryObjectCategoryRecognised(IReadOnlyList<PremisDocument> documents)
    {
        for(int i = 0; i < documents.Count; ++i)
        {
            for(int objectIndex = 0; objectIndex < documents[i].Objects.Count; ++objectIndex)
            {
                if(!PremisWellKnown.IsObjectCategory(documents[i].Objects[objectIndex].Category))
                {
                    return false;
                }
            }
        }

        return true;
    }


    /// <summary>Collects every object of one category across the documents.</summary>
    /// <param name="documents">The preservation-metadata documents.</param>
    /// <param name="category">The category, compared ordinally.</param>
    /// <returns>The objects, in document order.</returns>
    private static List<PremisObject> ObjectsOfCategory(IReadOnlyList<PremisDocument> documents, string category)
    {
        var objects = new List<PremisObject>();
        for(int i = 0; i < documents.Count; ++i)
        {
            for(int objectIndex = 0; objectIndex < documents[i].Objects.Count; ++objectIndex)
            {
                PremisObject premisObject = documents[i].Objects[objectIndex];
                if(string.Equals(premisObject.Category, category, StringComparison.Ordinal))
                {
                    objects.Add(premisObject);
                }
            }
        }

        return objects;
    }


    /// <summary>Determines whether a list of identifiers holds one equal to a candidate, type and value both.</summary>
    /// <param name="identifiers">The identifiers to search.</param>
    /// <param name="candidate">The identifier to look for.</param>
    /// <returns><see langword="true"/> when an equal identifier is present.</returns>
    private static bool ContainsIdentifier(List<PremisIdentifier> identifiers, PremisIdentifier candidate)
    {
        for(int i = 0; i < identifiers.Count; ++i)
        {
            if(string.Equals(identifiers[i].Type, candidate.Type, StringComparison.Ordinal)
                && string.Equals(identifiers[i].Value, candidate.Value, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>Collects every fixity the manifest states, beside the reference it was stated about.</summary>
    /// <param name="manifest">The manifest.</param>
    /// <param name="stated">The list the pairs are appended to.</param>
    private static void CollectFixities(MetsDocument manifest, List<(string? Href, EArkFixity Fixity)> stated)
    {
        for(int i = 0; i < manifest.DescriptiveMetadataSections.Count; ++i)
        {
            MetsMetadataReference? reference = manifest.DescriptiveMetadataSections[i].Reference;
            if(reference is not null)
            {
                stated.Add((reference.Href, reference.Fixity));
            }
        }

        MetsAdministrativeMetadata? administrative = manifest.AdministrativeMetadata;
        if(administrative is not null)
        {
            AppendSectionFixities(administrative.DigitalProvenanceSections, stated);
            AppendSectionFixities(administrative.RightsSections, stated);
        }

        MetsFileSection? fileSection = manifest.FileSection;
        if(fileSection is not null)
        {
            for(int i = 0; i < fileSection.FileGroups.Count; ++i)
            {
                MetsFileGroup group = fileSection.FileGroups[i];
                for(int fileIndex = 0; fileIndex < group.Files.Count; ++fileIndex)
                {
                    MetsFile file = group.Files[fileIndex];
                    stated.Add((file.Locator.Href, file.Fixity));
                }
            }
        }

        //One administrative sub-section list contributes the same way whichever of the two it is, and both
        //are reached only from here.
        static void AppendSectionFixities(
            IReadOnlyList<MetsAdministrativeMetadataSection> sections,
            List<(string? Href, EArkFixity Fixity)> destination)
        {
            for(int i = 0; i < sections.Count; ++i)
            {
                MetsMetadataReference? reference = sections[i].Reference;
                if(reference is not null)
                {
                    destination.Add((reference.Href, reference.Fixity));
                }
            }
        }
    }


    /// <summary>Collects every resource location the manifest states about a file of the package's own.</summary>
    /// <param name="manifest">The manifest.</param>
    /// <param name="hrefs">The list the locations are appended to.</param>
    /// <remarks>
    /// The package-to-package pointers of a divided or parent-child arrangement are deliberately not collected:
    /// they name a target by its own package identifier rather than by a location inside this package, so
    /// resolving them against this package's entries would report a defect where there is none.
    /// </remarks>
    private static void CollectReferenceHrefs(MetsDocument manifest, List<string?> hrefs)
    {
        for(int i = 0; i < manifest.DescriptiveMetadataSections.Count; ++i)
        {
            MetsMetadataReference? reference = manifest.DescriptiveMetadataSections[i].Reference;
            if(reference is not null)
            {
                hrefs.Add(reference.Href);
            }
        }

        MetsAdministrativeMetadata? administrative = manifest.AdministrativeMetadata;
        if(administrative is not null)
        {
            AppendSectionHrefs(administrative.DigitalProvenanceSections, hrefs);
            AppendSectionHrefs(administrative.RightsSections, hrefs);
        }

        MetsFileSection? fileSection = manifest.FileSection;
        if(fileSection is not null)
        {
            for(int i = 0; i < fileSection.FileGroups.Count; ++i)
            {
                MetsFileGroup group = fileSection.FileGroups[i];
                for(int fileIndex = 0; fileIndex < group.Files.Count; ++fileIndex)
                {
                    hrefs.Add(group.Files[fileIndex].Locator.Href);
                }
            }
        }

        //One administrative sub-section list contributes the same way whichever of the two it is, and both
        //are reached only from here.
        static void AppendSectionHrefs(
            IReadOnlyList<MetsAdministrativeMetadataSection> sections,
            List<string?> destination)
        {
            for(int i = 0; i < sections.Count; ++i)
            {
                MetsMetadataReference? reference = sections[i].Reference;
                if(reference is not null)
                {
                    destination.Add(reference.Href);
                }
            }
        }
    }


    /// <summary>Collects every identifier the manifest carries, the structural-map divisions walked iteratively.</summary>
    /// <param name="manifest">The manifest.</param>
    /// <param name="identifiers">The list the identifiers are appended to.</param>
    private static void CollectIdentifiers(MetsDocument manifest, List<string?> identifiers)
    {
        for(int i = 0; i < manifest.DescriptiveMetadataSections.Count; ++i)
        {
            identifiers.Add(manifest.DescriptiveMetadataSections[i].Id);
        }

        MetsAdministrativeMetadata? administrative = manifest.AdministrativeMetadata;
        if(administrative is not null)
        {
            for(int i = 0; i < administrative.DigitalProvenanceSections.Count; ++i)
            {
                identifiers.Add(administrative.DigitalProvenanceSections[i].Id);
            }

            for(int i = 0; i < administrative.RightsSections.Count; ++i)
            {
                identifiers.Add(administrative.RightsSections[i].Id);
            }
        }

        MetsFileSection? fileSection = manifest.FileSection;
        if(fileSection is not null)
        {
            identifiers.Add(fileSection.Id);
            for(int i = 0; i < fileSection.FileGroups.Count; ++i)
            {
                MetsFileGroup group = fileSection.FileGroups[i];
                identifiers.Add(group.Id);
                for(int fileIndex = 0; fileIndex < group.Files.Count; ++fileIndex)
                {
                    identifiers.Add(group.Files[fileIndex].Id);
                }
            }
        }

        for(int i = 0; i < manifest.StructuralMaps.Count; ++i)
        {
            identifiers.Add(manifest.StructuralMaps[i].Id);
            var pending = new Stack<MetsDivision>();
            pending.Push(manifest.StructuralMaps[i].RootDivision);
            while(pending.Count > 0)
            {
                MetsDivision division = pending.Pop();
                identifiers.Add(division.Id);
                for(int childIndex = 0; childIndex < division.Divisions.Count; ++childIndex)
                {
                    pending.Push(division.Divisions[childIndex]);
                }
            }
        }
    }


    /// <summary>Finds one direct child division of the root by the label the specification fixes for it.</summary>
    /// <param name="root">The structural map's root division.</param>
    /// <param name="label">The label, compared ordinally.</param>
    /// <returns>The division, or <see langword="null"/> when the root carries none under that label.</returns>
    private static MetsDivision? FindDivision(MetsDivision root, string label)
    {
        for(int i = 0; i < root.Divisions.Count; ++i)
        {
            if(string.Equals(root.Divisions[i].Label, label, StringComparison.Ordinal))
            {
                return root.Divisions[i];
            }
        }

        return null;
    }


    /// <summary>Resolves a resource location against the package's entries.</summary>
    /// <param name="snapshot">The package the location is resolved against.</param>
    /// <param name="href">The location, or <see langword="null"/>.</param>
    /// <returns>The entry, or <see langword="null"/> when the package holds none under that name.</returns>
    private static EArkPackageEntry? ResolveHref(EArkPackageSnapshot snapshot, string? href)
    {
        if(string.IsNullOrEmpty(href))
        {
            return null;
        }

        string candidate = href.StartsWith(CurrentFolderMarker, StringComparison.Ordinal)
            ? href[CurrentFolderMarker.Length..]
            : href;

        return snapshot.FindEntry(candidate);
    }
}
