namespace Verifiable.Core.Assessment.EArchiving;

/// <summary>
/// The <see cref="ClaimId"/> allocation for the E-ARK Specification for Archival Information Packages (AIP)
/// v2.2.0 — its prose catalogue <c>AIP1</c>…<c>AIP28</c>, its METS profile catalogue <c>AIPM1</c>…<c>AIPM7</c>,
/// and the obligations its prose states with no identifier of its own.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The code ranges below are STABLE</strong>, on the same terms <see cref="EArkClaimIds"/> states for
/// the whole eArchiving band: a code allocated here is never reassigned and never re-used, so a consuming
/// system may key a requirements-to-code graph on the integer code alone.
/// </para>
/// <para>
/// This class owns <c>2 800 000</c>–<c>2 869 999</c> inside the eArchiving range, stated as three rows of the
/// whole-band map <see cref="EArkClaimIds"/> carries. It is divided in three because the specification carries
/// three disjoint identifier spaces rather than one:
/// </para>
/// <list type="table">
///   <item><description><c>2 800 000</c>–<c>2 849 999</c>: the prose catalogue, code = start + <em>n</em> of <c>AIPn</c>.</description></item>
///   <item><description><c>2 850 000</c>–<c>2 859 999</c>: the METS profile catalogue, code = start + <em>n</em> of <c>AIPMn</c>.</description></item>
///   <item><description><c>2 860 000</c>–<c>2 869 999</c>: obligations the prose states without an identifier, allocated in specification order.</description></item>
/// </list>
/// <para>
/// <strong>Two identifier spaces with the same prefix.</strong> <c>AIPMn</c> comes from the machine-readable
/// METS profile and <c>AIPn</c> from the narrative specification; they are independent numberings and
/// <c>AIP5</c> is not <c>AIPM5</c>. Keeping them in separate sub-bands is what makes a code unambiguous
/// about which of the two documents it came from.
/// </para>
/// <para>
/// <strong>The prose catalogue is non-contiguous.</strong> <c>AIP4</c>–<c>AIP6</c>, <c>AIP9</c>,
/// <c>AIP10</c>, <c>AIP14</c>, <c>AIP19</c> and <c>AIP23</c>–<c>AIP26</c> are numbers the specification never
/// assigns — eleven of the twenty-eight. Their codes stay permanently unallocated here, so the numbering of
/// every requirement that does exist keeps matching the specification's own. That is a defect of the source
/// document rather than of this transcription, and it is recorded as such at the requirements matrix.
/// </para>
/// <para>
/// <strong>An allocation is not an implementation</strong>, on the same terms
/// <see cref="EArkClaimIds"/> states: every identifier the source catalogue carries gets a code, including the
/// requirements that bind a repository rather than a document, so a matrix and a consuming graph can name
/// every row. Which of them a rule list issues is the business of <see cref="EArkValidationProfiles"/>.
/// </para>
/// <para>
/// The catalogues are
/// <see href="https://earkaip.dilcis.eu/profile/E-ARK-AIP.xml">E-ARK AIP v2.2.0 METS Profile</see>, whose
/// <c>structural_requirements</c> block carries <c>AIPM1</c>…<c>AIPM7</c>, and
/// <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0</see>, whose narrative carries
/// <c>AIP1</c>…<c>AIP28</c>.
/// </para>
/// </remarks>
public static class AipClaimIds
{
    /// <summary>The first code of the band holding the E-ARK AIP prose requirements, <c>2 800 000</c>.</summary>
    public static int ProseRangeStart { get; } = 2_800_000;

    /// <summary>The last code of the band holding the E-ARK AIP prose requirements, <c>2 849 999</c>.</summary>
    public static int ProseRangeEnd { get; } = 2_849_999;

    /// <summary>The first code of the band holding the E-ARK AIP METS profile requirements, <c>2 850 000</c>.</summary>
    public static int MetsProfileRangeStart { get; } = 2_850_000;

    /// <summary>The last code of the band holding the E-ARK AIP METS profile requirements, <c>2 859 999</c>.</summary>
    public static int MetsProfileRangeEnd { get; } = 2_859_999;

    /// <summary>The first code of the band holding the E-ARK AIP obligations stated without an identifier, <c>2 860 000</c>.</summary>
    public static int NarrativeRangeStart { get; } = 2_860_000;

    /// <summary>The last code of the band holding the E-ARK AIP obligations stated without an identifier, <c>2 869 999</c>.</summary>
    public static int NarrativeRangeEnd { get; } = 2_869_999;


    /// <summary><c>AIP1</c> — MUST: a representation divided into parts uses the same component name in every container. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP1</see>.</summary>
    public static ClaimId Aip1 { get; } = ClaimId.Create(ProseRangeStart + 1, "AIP1");

    /// <summary><c>AIP2</c> — MUST: the sub-paths of items are unique across the different containers. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP2</see>.</summary>
    public static ClaimId Aip2 { get; } = ClaimId.Create(ProseRangeStart + 2, "AIP2");

    /// <summary><c>AIP3</c> — MUST: a divided package's <c>structMap</c> carries an <c>mptr</c> and a matching <c>fptr</c> per representation. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP3</see>.</summary>
    public static ClaimId Aip3 { get; } = ClaimId.Create(ProseRangeStart + 3, "AIP3");

    //AIP4, AIP5 and AIP6 are numbers the specification's prose never assigns; their codes stay unallocated.

    /// <summary><c>AIP7</c> — COULD: format information is given through <c>formatRegistry</c>, <c>formatDesignation</c> or both. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP7</see>.</summary>
    public static ClaimId Aip7 { get; } = ClaimId.Create(ProseRangeStart + 7, "AIP7");

    /// <summary><c>AIP8</c> — COULD: <c>formatRegistry</c> uses a persistent format-registry identifier. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP8</see>.</summary>
    public static ClaimId Aip8 { get; } = ClaimId.Create(ProseRangeStart + 8, "AIP8");

    //AIP9 and AIP10 are numbers the specification's prose never assigns; their codes stay unallocated.

    /// <summary><c>AIP11</c> — COULD: <c>storage</c> holds the object's physical location. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP11</see>.</summary>
    public static ClaimId Aip11 { get; } = ClaimId.Create(ProseRangeStart + 11, "AIP11");

    /// <summary><c>AIP12</c> — SHOULD: the <c>relationship</c> element describes the digital object's relationships. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP12</see>.</summary>
    public static ClaimId Aip12 { get; } = ClaimId.Create(ProseRangeStart + 12, "AIP12");

    /// <summary><c>AIP13</c> — MUST: a package that is part of another names the superordinate package through <c>relationshipSubType</c>. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP13</see>.</summary>
    public static ClaimId Aip13 { get; } = ClaimId.Create(ProseRangeStart + 13, "AIP13");

    //AIP14 is a number the specification's prose never assigns; its code stays unallocated.

    /// <summary><c>AIP15</c> — SHOULD: <c>eventIdentifier</c> identifies the preservation events. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP15</see>.</summary>
    public static ClaimId Aip15 { get; } = ClaimId.Create(ProseRangeStart + 15, "AIP15");

    /// <summary><c>AIP16</c> — MUST: a described event names the agent that caused it through <c>linkingAgentIdentifier</c>. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP16</see>.</summary>
    public static ClaimId Aip16 { get; } = ClaimId.Create(ProseRangeStart + 16, "AIP16");

    /// <summary><c>AIP17</c> — SHOULD: the event a resource was created by is recorded through the related-event identification. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP17</see>.</summary>
    public static ClaimId Aip17 { get; } = ClaimId.Create(ProseRangeStart + 17, "AIP17");

    /// <summary><c>AIP18</c> — MUST: agents referenced in events are described through the <c>agent</c> element. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP18</see>.</summary>
    public static ClaimId Aip18 { get; } = ClaimId.Create(ProseRangeStart + 18, "AIP18");

    //AIP19 is a number the specification's prose never assigns; its code stays unallocated.

    /// <summary><c>AIP20</c> — SHOULD: the package identifier is used to derive the physical container's file name. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP20</see>.</summary>
    public static ClaimId Aip20 { get; } = ClaimId.Create(ProseRangeStart + 20, "AIP20");

    /// <summary><c>AIP21</c> — SHOULD: a stated policy allows deriving a portable file-name part from the identifier and back. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP21</see>.</summary>
    public static ClaimId Aip21 { get; } = ClaimId.Create(ProseRangeStart + 21, "AIP21");

    /// <summary><c>AIP22</c> — SHOULD: the container file name starts with a part stable across every version and generation. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP22</see>.</summary>
    public static ClaimId Aip22 { get; } = ClaimId.Create(ProseRangeStart + 22, "AIP22");

    //AIP23, AIP24, AIP25 and AIP26 are numbers the specification's prose never assigns; their codes stay unallocated.

    /// <summary><c>AIP27</c> — MUST: the package content is contained in a single folder once unpacked. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP27</see>.</summary>
    public static ClaimId Aip27 { get; } = ClaimId.Create(ProseRangeStart + 27, "AIP27");

    /// <summary><c>AIP28</c> — SHOULD: a tape-archive packaging format aggregates the content without compression. <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0 AIP28</see>.</summary>
    public static ClaimId Aip28 { get; } = ClaimId.Create(ProseRangeStart + 28, "AIP28");


    /// <summary><c>AIPM1</c> — MUST: <c>mets/@OBJID</c> does not change during the package's life-cycle. <see href="https://earkaip.dilcis.eu/profile/E-ARK-AIP.xml">E-ARK AIP v2.2.0 AIPM1</see>.</summary>
    public static ClaimId Aipm1 { get; } = ClaimId.Create(MetsProfileRangeStart + 1, "AIPM1");

    /// <summary><c>AIPM2</c> — MUST: <c>mets/@PROFILE</c> states the archival-package profile. <see href="https://earkaip.dilcis.eu/profile/E-ARK-AIP.xml">E-ARK AIP v2.2.0 AIPM2</see>.</summary>
    public static ClaimId Aipm2 { get; } = ClaimId.Create(MetsProfileRangeStart + 2, "AIPM2");

    /// <summary><c>AIPM3</c> — MUST: <c>mets/metsHdr/@csip:OAISPACKAGETYPE</c> is <c>AIP</c>. <see href="https://earkaip.dilcis.eu/profile/E-ARK-AIP.xml">E-ARK AIP v2.2.0 AIPM3</see>.</summary>
    public static ClaimId Aipm3 { get; } = ClaimId.Create(MetsProfileRangeStart + 3, "AIPM3");

    /// <summary><c>AIPM4</c> — SHOULD: <c>dmdSec/@STATUS</c> uses the fixed vocabulary and exactly one section is current. <see href="https://earkaip.dilcis.eu/profile/E-ARK-AIP.xml">E-ARK AIP v2.2.0 AIPM4</see>.</summary>
    public static ClaimId Aipm4 { get; } = ClaimId.Create(MetsProfileRangeStart + 4, "AIPM4");

    /// <summary><c>AIPM5</c> — MUST: digital provenance metadata is referenced through <c>amdSec/digiprovMD/mdRef</c>. <see href="https://earkaip.dilcis.eu/profile/E-ARK-AIP.xml">E-ARK AIP v2.2.0 AIPM5</see>.</summary>
    public static ClaimId Aipm5 { get; } = ClaimId.Create(MetsProfileRangeStart + 5, "AIPM5");

    /// <summary><c>AIPM6</c> — SHOULD: at least one such reference states the preservation-metadata type. <see href="https://earkaip.dilcis.eu/profile/E-ARK-AIP.xml">E-ARK AIP v2.2.0 AIPM6</see>.</summary>
    public static ClaimId Aipm6 { get; } = ClaimId.Create(MetsProfileRangeStart + 6, "AIPM6");

    /// <summary><c>AIPM7</c> — SHOULD: that reference's <c>@MDTYPEVERSION</c> starts with the major version <c>3</c>. <see href="https://earkaip.dilcis.eu/profile/E-ARK-AIP.xml">E-ARK AIP v2.2.0 AIPM7</see>.</summary>
    public static ClaimId Aipm7 { get; } = ClaimId.Create(MetsProfileRangeStart + 7, "AIPM7");


    /// <summary>
    /// The archival package's root manifest carries a persistent and unique identifier — a lowercase
    /// <c>must</c> the specification's "METS identifier" section states with no identifier of its own, and
    /// distinct from <c>AIPM1</c>, which is about that identifier not changing once it exists.
    /// <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0, "METS identifier"</see>.
    /// </summary>
    public static ClaimId ArchivalPackageIdentifierAssigned { get; } =
        ClaimId.Create(NarrativeRangeStart + 1, "AIP-IDENTIFIER-ASSIGNED");

    /// <summary>
    /// A parent package referenced by child packages carries a structural map listing all of them — a
    /// lowercase <c>must</c> the specification's "Parent AIP references child AIPs" section states with no
    /// identifier of its own, and the structural-map half of the parent-child relationship whose object-level
    /// half is <c>AIP13</c>.
    /// <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0, "Parent AIP references child AIPs"</see>.
    /// </summary>
    public static ClaimId ArchivalPackageParentChainListed { get; } =
        ClaimId.Create(NarrativeRangeStart + 2, "AIP-PARENT-CHAIN-LISTED");

    /// <summary>
    /// A package is retrievable from the repository by its identifier — a lowercase <c>must</c> of the same
    /// section, allocated so a matrix can name it and tagged service-operational: it binds a repository's
    /// storage system, not a document.
    /// <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0, "METS identifier"</see>.
    /// </summary>
    public static ClaimId ArchivalPackageRetrievableByIdentifier { get; } =
        ClaimId.Create(NarrativeRangeStart + 3, "AIP-RETRIEVABLE-BY-IDENTIFIER");

    /// <summary>
    /// A conformant archival solution incorporates existing packages without transforming them — the
    /// specification's only <c>shall</c>, allocated so a matrix can name it and tagged service-operational:
    /// it binds an archive system's import capability, not a document.
    /// <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0, introduction</see>.
    /// </summary>
    public static ClaimId ArchivalSolutionIncorporatesPackagesUntransformed { get; } =
        ClaimId.Create(NarrativeRangeStart + 4, "AIP-SOLUTION-INCORPORATES-UNTRANSFORMED");


    /// <summary>Determines whether a claim identifier was allocated from the E-ARK AIP prose band.</summary>
    /// <param name="claimId">The claim identifier to test.</param>
    /// <returns><see langword="true"/> when the code lies in <c>2 800 000</c>–<c>2 849 999</c>.</returns>
    public static bool IsProseRequirement(ClaimId claimId) =>
        claimId.Code >= ProseRangeStart && claimId.Code <= ProseRangeEnd;


    /// <summary>Determines whether a claim identifier was allocated from the E-ARK AIP METS profile band.</summary>
    /// <param name="claimId">The claim identifier to test.</param>
    /// <returns><see langword="true"/> when the code lies in <c>2 850 000</c>–<c>2 859 999</c>.</returns>
    public static bool IsMetsProfileRequirement(ClaimId claimId) =>
        claimId.Code >= MetsProfileRangeStart && claimId.Code <= MetsProfileRangeEnd;


    /// <summary>Determines whether a claim identifier was allocated from the E-ARK AIP narrative band.</summary>
    /// <param name="claimId">The claim identifier to test.</param>
    /// <returns><see langword="true"/> when the code lies in <c>2 860 000</c>–<c>2 869 999</c>.</returns>
    public static bool IsNarrativeObligation(ClaimId claimId) =>
        claimId.Code >= NarrativeRangeStart && claimId.Code <= NarrativeRangeEnd;
}
