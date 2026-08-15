namespace Verifiable.Core.Assessment.EArchiving;

/// <summary>
/// The <see cref="ClaimId"/> allocation for the E-ARK Common Specification for Information Packages (CSIP)
/// v2.2.0 — its METS profile catalogue <c>CSIP1</c>…<c>CSIP119</c> and its folder-structure catalogue
/// <c>CSIPSTR1</c>…<c>CSIPSTR16</c> — together with the house-convention claims this library states where the
/// specification states none.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The code ranges below are STABLE.</strong> A code allocated here is never reassigned and never
/// re-used for another requirement: a consuming system may key a requirements-to-code graph on the integer
/// code alone. New requirements append inside their own band; a requirement withdrawn by a later edition of
/// the source specification keeps its code permanently reserved rather than freeing it.
/// </para>
/// <para>
/// The whole eArchiving band is <c>2 000 000</c>…<c>2 999 999</c>, divided one sub-band per identifier space
/// of one source specification. The other three sub-band owners are <see cref="PremisClaimIds"/> (CS
/// Preservation Metadata), <see cref="PreservationClaimIds"/> (ETSI TS 119 511 and TS 119 512) and
/// <see cref="AipClaimIds"/> (E-ARK AIP). The map below is the whole of it — twelve sub-bands, no gaps left
/// unaccounted for, and every code any of the four classes allocates falls inside one of these rows:
/// </para>
/// <list type="table">
///   <item><description><c>2 000 000</c>–<c>2 099 999</c>: E-ARK CSIP METS profile, code = start + <em>n</em> of <c>CSIPn</c> (this class).</description></item>
///   <item><description><c>2 100 000</c>–<c>2 199 999</c>: E-ARK CSIP folder structure, code = start + <em>n</em> of <c>CSIPSTRn</c> (this class).</description></item>
///   <item><description><c>2 200 000</c>–<c>2 299 999</c>: CS Preservation Metadata tables, code = start + <em>n</em> of <c>PMn</c> (<see cref="PremisClaimIds"/>).</description></item>
///   <item><description><c>2 300 000</c>–<c>2 399 999</c>: CS Preservation Metadata narrative mnemonics, allocated in specification order (<see cref="PremisClaimIds"/>).</description></item>
///   <item><description><c>2 400 000</c>–<c>2 499 999</c>: ETSI TS 119 511 <c>OVR-</c> requirements, whose annex requirements take the nested <c>2 499 000</c>+ range (<see cref="PreservationClaimIds"/>).</description></item>
///   <item><description><c>2 500 000</c>–<c>2 599 999</c>: ETSI TS 119 511 <c>PRP-</c> requirements (<see cref="PreservationClaimIds"/>).</description></item>
///   <item><description><c>2 600 000</c>–<c>2 699 999</c>: ETSI TS 119 512 operations (<see cref="PreservationClaimIds"/>).</description></item>
///   <item><description><c>2 700 000</c>–<c>2 799 999</c>: ETSI TS 119 512 result codes (<see cref="PreservationClaimIds"/>).</description></item>
///   <item><description><c>2 800 000</c>–<c>2 849 999</c>: E-ARK AIP prose catalogue, code = start + <em>n</em> of <c>AIPn</c> (<see cref="AipClaimIds"/>).</description></item>
///   <item><description><c>2 850 000</c>–<c>2 859 999</c>: E-ARK AIP METS profile catalogue, code = start + <em>n</em> of <c>AIPMn</c> (<see cref="AipClaimIds"/>).</description></item>
///   <item><description><c>2 860 000</c>–<c>2 869 999</c>: E-ARK AIP obligations the prose states without an identifier, allocated in specification order (<see cref="AipClaimIds"/>).</description></item>
///   <item><description><c>2 900 000</c>–<c>2 999 999</c>: this library's own eArchiving conventions, which no source specification states (this class).</description></item>
/// </list>
/// <para>
/// <strong>An unlisted range is not a free range.</strong> A later stage allocating for a new source
/// specification takes its band from a row added here in the same change, never from a number this map happens
/// not to mention: the map is what a consuming graph and the next allocator both read, so a band that exists in
/// code and not in the map is exactly how two specifications end up sharing codes.
/// <c>2 870 000</c>–<c>2 899 999</c> is the range left over today.
/// </para>
/// <para>
/// <strong>An allocation is not an implementation.</strong> Every identifier the source catalogue states is
/// allocated a code, including the requirements that are organizational rather than technical, so that a
/// requirements matrix and a consuming graph can name every row. Which of them a rule list actually issues is
/// the business of the validation profiles.
/// </para>
/// <para>
/// <c>CSIP86</c> and <c>CSIP87</c> were deprecated by the specification (2021-10-15 and 2019-05-09) and
/// <c>CSIP115</c> was never allocated by it; their three codes stay permanently unallocated here, so the
/// numbering of every other requirement keeps matching the specification's own.
/// </para>
/// <para>
/// The requirement catalogue is the METS Profile document itself rather than the prose:
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 METS Profile</see>, whose
/// <c>structural_requirements</c> block carries <c>CSIP1</c>…<c>CSIP119</c>; the folder-structure catalogue is
/// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 clause 4.1</see>.
/// </para>
/// </remarks>
public static class EArkClaimIds
{
    /// <summary>The first code of the band holding the E-ARK CSIP METS profile requirements, <c>2 000 000</c>.</summary>
    public static int MetsProfileRangeStart { get; } = 2_000_000;

    /// <summary>The last code of the band holding the E-ARK CSIP METS profile requirements, <c>2 099 999</c>.</summary>
    public static int MetsProfileRangeEnd { get; } = 2_099_999;

    /// <summary>The first code of the band holding the E-ARK CSIP folder-structure requirements, <c>2 100 000</c>.</summary>
    public static int FolderStructureRangeStart { get; } = 2_100_000;

    /// <summary>The last code of the band holding the E-ARK CSIP folder-structure requirements, <c>2 199 999</c>.</summary>
    public static int FolderStructureRangeEnd { get; } = 2_199_999;

    /// <summary>The first code of the band holding this library's own eArchiving conventions, <c>2 900 000</c>.</summary>
    public static int HouseConventionRangeStart { get; } = 2_900_000;

    /// <summary>The last code of the band holding this library's own eArchiving conventions, <c>2 999 999</c>.</summary>
    public static int HouseConventionRangeEnd { get; } = 2_999_999;


    /// <summary><c>CSIP1</c> — MUST, <c>mets/@OBJID</c>, 1..1: package identifier. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP1</see>.</summary>
    public static ClaimId Csip1 { get; } = ClaimId.Create(MetsProfileRangeStart + 1, "CSIP1");

    /// <summary><c>CSIP2</c> — MUST, <c>mets/@TYPE</c>, 1..1: content category. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP2</see>.</summary>
    public static ClaimId Csip2 { get; } = ClaimId.Create(MetsProfileRangeStart + 2, "CSIP2");

    /// <summary><c>CSIP3</c> — SHOULD, <c>mets[@TYPE='OTHER']/@csip:OTHERTYPE</c>, 0..1: other content category. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP3</see>.</summary>
    public static ClaimId Csip3 { get; } = ClaimId.Create(MetsProfileRangeStart + 3, "CSIP3");

    /// <summary><c>CSIP4</c> — SHOULD, <c>mets/@csip:CONTENTINFORMATIONTYPE</c>, 0..1 (1..1 at representation level): content information type specification. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP4</see>.</summary>
    public static ClaimId Csip4 { get; } = ClaimId.Create(MetsProfileRangeStart + 4, "CSIP4");

    /// <summary><c>CSIP5</c> — MAY, <c>mets[@csip:CONTENTINFORMATIONTYPE='OTHER']/@csip:OTHERCONTENTINFORMATIONTYPE</c>, 0..1: other content information type specification. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP5</see>.</summary>
    public static ClaimId Csip5 { get; } = ClaimId.Create(MetsProfileRangeStart + 5, "CSIP5");

    /// <summary><c>CSIP6</c> — MUST, <c>mets/@PROFILE</c>, 1..1: the METS profile the package claims. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP6</see>.</summary>
    public static ClaimId Csip6 { get; } = ClaimId.Create(MetsProfileRangeStart + 6, "CSIP6");

    /// <summary><c>CSIP7</c> — MUST, <c>mets/metsHdr/@CREATEDATE</c>, 1..1: package creation datetime. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP7</see>.</summary>
    public static ClaimId Csip7 { get; } = ClaimId.Create(MetsProfileRangeStart + 7, "CSIP7");

    /// <summary><c>CSIP8</c> — SHOULD, <c>mets/metsHdr/@LASTMODDATE</c>, 0..1: package last modification datetime. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP8</see>.</summary>
    public static ClaimId Csip8 { get; } = ClaimId.Create(MetsProfileRangeStart + 8, "CSIP8");

    /// <summary><c>CSIP9</c> — MUST, <c>mets/metsHdr/@csip:OAISPACKAGETYPE</c>, 1..1: OAIS package type information. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP9</see>.</summary>
    public static ClaimId Csip9 { get; } = ClaimId.Create(MetsProfileRangeStart + 9, "CSIP9");

    /// <summary><c>CSIP10</c> — MUST, <c>mets/metsHdr/agent</c>, 1..n: agent. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP10</see>.</summary>
    public static ClaimId Csip10 { get; } = ClaimId.Create(MetsProfileRangeStart + 10, "CSIP10");

    /// <summary><c>CSIP11</c> — MUST, <c>mets/metsHdr/agent[@ROLE='CREATOR']</c>, 1..1: agent role, fixed value. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP11</see>.</summary>
    public static ClaimId Csip11 { get; } = ClaimId.Create(MetsProfileRangeStart + 11, "CSIP11");

    /// <summary><c>CSIP12</c> — MUST, <c>mets/metsHdr/agent[@TYPE='OTHER']</c>, 1..1: agent type, fixed value. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP12</see>.</summary>
    public static ClaimId Csip12 { get; } = ClaimId.Create(MetsProfileRangeStart + 12, "CSIP12");

    /// <summary><c>CSIP13</c> — MUST, <c>mets/metsHdr/agent[@OTHERTYPE='SOFTWARE']</c>, 1..1: agent other type, fixed value. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP13</see>.</summary>
    public static ClaimId Csip13 { get; } = ClaimId.Create(MetsProfileRangeStart + 13, "CSIP13");

    /// <summary><c>CSIP14</c> — MUST, <c>mets/metsHdr/agent/name</c>, 1..1: agent name. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP14</see>.</summary>
    public static ClaimId Csip14 { get; } = ClaimId.Create(MetsProfileRangeStart + 14, "CSIP14");

    /// <summary><c>CSIP15</c> — MUST, <c>mets/metsHdr/agent/note</c>, 1..1: agent additional information. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP15</see>.</summary>
    public static ClaimId Csip15 { get; } = ClaimId.Create(MetsProfileRangeStart + 15, "CSIP15");

    /// <summary><c>CSIP16</c> — MUST, <c>mets/metsHdr/agent/note[@csip:NOTETYPE='SOFTWARE VERSION']</c>, 1..1: classification of the agent note, fixed value. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP16</see>.</summary>
    public static ClaimId Csip16 { get; } = ClaimId.Create(MetsProfileRangeStart + 16, "CSIP16");

    /// <summary><c>CSIP17</c> — SHOULD, <c>mets/dmdSec</c>, 0..n: descriptive metadata section. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP17</see>.</summary>
    public static ClaimId Csip17 { get; } = ClaimId.Create(MetsProfileRangeStart + 17, "CSIP17");

    /// <summary><c>CSIP18</c> — MUST, <c>mets/dmdSec/@ID</c>, 1..1: descriptive metadata identifier. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP18</see>.</summary>
    public static ClaimId Csip18 { get; } = ClaimId.Create(MetsProfileRangeStart + 18, "CSIP18");

    /// <summary><c>CSIP19</c> — MUST, <c>mets/dmdSec/@CREATED</c>, 1..1: descriptive metadata creation datetime. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP19</see>.</summary>
    public static ClaimId Csip19 { get; } = ClaimId.Create(MetsProfileRangeStart + 19, "CSIP19");

    /// <summary><c>CSIP20</c> — SHOULD, <c>mets/dmdSec/@STATUS</c>, 0..1: status of the descriptive metadata. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP20</see>.</summary>
    public static ClaimId Csip20 { get; } = ClaimId.Create(MetsProfileRangeStart + 20, "CSIP20");

    /// <summary><c>CSIP21</c> — SHOULD, <c>mets/dmdSec/mdRef</c>, 0..1: reference to the descriptive metadata document. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP21</see>.</summary>
    public static ClaimId Csip21 { get; } = ClaimId.Create(MetsProfileRangeStart + 21, "CSIP21");

    /// <summary><c>CSIP22</c> — MUST, <c>mets/dmdSec/mdRef[@LOCTYPE='URL']</c>, 1..1: type of locator, fixed value. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP22</see>.</summary>
    public static ClaimId Csip22 { get; } = ClaimId.Create(MetsProfileRangeStart + 22, "CSIP22");

    /// <summary><c>CSIP23</c> — MUST, <c>mets/dmdSec/mdRef[@xlink:type='simple']</c>, 1..1: type of link, fixed value. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP23</see>.</summary>
    public static ClaimId Csip23 { get; } = ClaimId.Create(MetsProfileRangeStart + 23, "CSIP23");

    /// <summary><c>CSIP24</c> — MUST, <c>mets/dmdSec/mdRef/@xlink:href</c>, 1..1: resource location. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP24</see>.</summary>
    public static ClaimId Csip24 { get; } = ClaimId.Create(MetsProfileRangeStart + 24, "CSIP24");

    /// <summary><c>CSIP25</c> — MUST, <c>mets/dmdSec/mdRef/@MDTYPE</c>, 1..1: type of metadata. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP25</see>.</summary>
    public static ClaimId Csip25 { get; } = ClaimId.Create(MetsProfileRangeStart + 25, "CSIP25");

    /// <summary><c>CSIP26</c> — MUST, <c>mets/dmdSec/mdRef/@MIMETYPE</c>, 1..1: file media type. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP26</see>.</summary>
    public static ClaimId Csip26 { get; } = ClaimId.Create(MetsProfileRangeStart + 26, "CSIP26");

    /// <summary><c>CSIP27</c> — MUST, <c>mets/dmdSec/mdRef/@SIZE</c>, 1..1: file size. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP27</see>.</summary>
    public static ClaimId Csip27 { get; } = ClaimId.Create(MetsProfileRangeStart + 27, "CSIP27");

    /// <summary><c>CSIP28</c> — MUST, <c>mets/dmdSec/mdRef/@CREATED</c>, 1..1: file creation datetime. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP28</see>.</summary>
    public static ClaimId Csip28 { get; } = ClaimId.Create(MetsProfileRangeStart + 28, "CSIP28");

    /// <summary><c>CSIP29</c> — MUST, <c>mets/dmdSec/mdRef/@CHECKSUM</c>, 1..1: file checksum. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP29</see>.</summary>
    public static ClaimId Csip29 { get; } = ClaimId.Create(MetsProfileRangeStart + 29, "CSIP29");

    /// <summary><c>CSIP30</c> — MUST, <c>mets/dmdSec/mdRef/@CHECKSUMTYPE</c>, 1..1: file checksum type. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP30</see>.</summary>
    public static ClaimId Csip30 { get; } = ClaimId.Create(MetsProfileRangeStart + 30, "CSIP30");

    /// <summary><c>CSIP31</c> — SHOULD, <c>mets/amdSec</c>, 0..1: administrative metadata section. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP31</see>.</summary>
    public static ClaimId Csip31 { get; } = ClaimId.Create(MetsProfileRangeStart + 31, "CSIP31");

    /// <summary><c>CSIP32</c> — SHOULD, <c>mets/amdSec/digiprovMD</c>, 0..n: digital provenance metadata, the mooring point of a preservation-metadata document. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP32</see>.</summary>
    public static ClaimId Csip32 { get; } = ClaimId.Create(MetsProfileRangeStart + 32, "CSIP32");

    /// <summary><c>CSIP33</c> — MUST, <c>mets/amdSec/digiprovMD/@ID</c>, 1..1: digital provenance metadata identifier. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP33</see>.</summary>
    public static ClaimId Csip33 { get; } = ClaimId.Create(MetsProfileRangeStart + 33, "CSIP33");

    /// <summary><c>CSIP34</c> — SHOULD, <c>mets/amdSec/digiprovMD/@STATUS</c>, 0..1: status of the digital provenance metadata. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP34</see>.</summary>
    public static ClaimId Csip34 { get; } = ClaimId.Create(MetsProfileRangeStart + 34, "CSIP34");

    /// <summary><c>CSIP35</c> — SHOULD, <c>mets/amdSec/digiprovMD/mdRef</c>, 0..1: reference to the digital provenance metadata document. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP35</see>.</summary>
    public static ClaimId Csip35 { get; } = ClaimId.Create(MetsProfileRangeStart + 35, "CSIP35");

    /// <summary><c>CSIP36</c> — MUST, <c>mets/amdSec/digiprovMD/mdRef[@LOCTYPE='URL']</c>, 1..1: type of locator, fixed value. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP36</see>.</summary>
    public static ClaimId Csip36 { get; } = ClaimId.Create(MetsProfileRangeStart + 36, "CSIP36");

    /// <summary><c>CSIP37</c> — MUST, <c>mets/amdSec/digiprovMD/mdRef[@xlink:type='simple']</c>, 1..1: type of link, fixed value. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP37</see>.</summary>
    public static ClaimId Csip37 { get; } = ClaimId.Create(MetsProfileRangeStart + 37, "CSIP37");

    /// <summary><c>CSIP38</c> — MUST, <c>mets/amdSec/digiprovMD/mdRef/@xlink:href</c>, 1..1: resource location. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP38</see>.</summary>
    public static ClaimId Csip38 { get; } = ClaimId.Create(MetsProfileRangeStart + 38, "CSIP38");

    /// <summary><c>CSIP39</c> — MUST, <c>mets/amdSec/digiprovMD/mdRef/@MDTYPE</c>, 1..1: type of metadata, <c>PREMIS</c> for a preservation-metadata document. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP39</see>.</summary>
    public static ClaimId Csip39 { get; } = ClaimId.Create(MetsProfileRangeStart + 39, "CSIP39");

    /// <summary><c>CSIP40</c> — MUST, <c>mets/amdSec/digiprovMD/mdRef/@MIMETYPE</c>, 1..1: file media type. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP40</see>.</summary>
    public static ClaimId Csip40 { get; } = ClaimId.Create(MetsProfileRangeStart + 40, "CSIP40");

    /// <summary><c>CSIP41</c> — MUST, <c>mets/amdSec/digiprovMD/mdRef/@SIZE</c>, 1..1: file size. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP41</see>.</summary>
    public static ClaimId Csip41 { get; } = ClaimId.Create(MetsProfileRangeStart + 41, "CSIP41");

    /// <summary><c>CSIP42</c> — MUST, <c>mets/amdSec/digiprovMD/mdRef/@CREATED</c>, 1..1: file creation datetime. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP42</see>.</summary>
    public static ClaimId Csip42 { get; } = ClaimId.Create(MetsProfileRangeStart + 42, "CSIP42");

    /// <summary><c>CSIP43</c> — MUST, <c>mets/amdSec/digiprovMD/mdRef/@CHECKSUM</c>, 1..1: file checksum. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP43</see>.</summary>
    public static ClaimId Csip43 { get; } = ClaimId.Create(MetsProfileRangeStart + 43, "CSIP43");

    /// <summary><c>CSIP44</c> — MUST, <c>mets/amdSec/digiprovMD/mdRef/@CHECKSUMTYPE</c>, 1..1: file checksum type. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP44</see>.</summary>
    public static ClaimId Csip44 { get; } = ClaimId.Create(MetsProfileRangeStart + 44, "CSIP44");

    /// <summary><c>CSIP45</c> — MAY, <c>mets/amdSec/rightsMD</c>, 0..n: rights metadata. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP45</see>.</summary>
    public static ClaimId Csip45 { get; } = ClaimId.Create(MetsProfileRangeStart + 45, "CSIP45");

    /// <summary><c>CSIP46</c> — MUST, <c>mets/amdSec/rightsMD/@ID</c>, 1..1: rights metadata identifier. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP46</see>.</summary>
    public static ClaimId Csip46 { get; } = ClaimId.Create(MetsProfileRangeStart + 46, "CSIP46");

    /// <summary><c>CSIP47</c> — SHOULD, <c>mets/amdSec/rightsMD/@STATUS</c>, 0..1: status of the rights metadata. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP47</see>.</summary>
    public static ClaimId Csip47 { get; } = ClaimId.Create(MetsProfileRangeStart + 47, "CSIP47");

    /// <summary><c>CSIP48</c> — SHOULD, <c>mets/amdSec/rightsMD/mdRef</c>, 0..1: reference to the rights metadata document. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP48</see>.</summary>
    public static ClaimId Csip48 { get; } = ClaimId.Create(MetsProfileRangeStart + 48, "CSIP48");

    /// <summary><c>CSIP49</c> — MUST, <c>mets/amdSec/rightsMD/mdRef[@LOCTYPE='URL']</c>, 1..1: type of locator, fixed value. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP49</see>.</summary>
    public static ClaimId Csip49 { get; } = ClaimId.Create(MetsProfileRangeStart + 49, "CSIP49");

    /// <summary><c>CSIP50</c> — MUST, <c>mets/amdSec/rightsMD/mdRef[@xlink:type='simple']</c>, 1..1: type of link, fixed value. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP50</see>.</summary>
    public static ClaimId Csip50 { get; } = ClaimId.Create(MetsProfileRangeStart + 50, "CSIP50");

    /// <summary><c>CSIP51</c> — MUST, <c>mets/amdSec/rightsMD/mdRef/@xlink:href</c>, 1..1: resource location. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP51</see>.</summary>
    public static ClaimId Csip51 { get; } = ClaimId.Create(MetsProfileRangeStart + 51, "CSIP51");

    /// <summary><c>CSIP52</c> — MUST, <c>mets/amdSec/rightsMD/mdRef/@MDTYPE</c>, 1..1: type of metadata. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP52</see>.</summary>
    public static ClaimId Csip52 { get; } = ClaimId.Create(MetsProfileRangeStart + 52, "CSIP52");

    /// <summary><c>CSIP53</c> — MUST, <c>mets/amdSec/rightsMD/mdRef/@MIMETYPE</c>, 1..1: file media type. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP53</see>.</summary>
    public static ClaimId Csip53 { get; } = ClaimId.Create(MetsProfileRangeStart + 53, "CSIP53");

    /// <summary><c>CSIP54</c> — MUST, <c>mets/amdSec/rightsMD/mdRef/@SIZE</c>, 1..1: file size. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP54</see>.</summary>
    public static ClaimId Csip54 { get; } = ClaimId.Create(MetsProfileRangeStart + 54, "CSIP54");

    /// <summary><c>CSIP55</c> — MUST, <c>mets/amdSec/rightsMD/mdRef/@CREATED</c>, 1..1: file creation datetime. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP55</see>.</summary>
    public static ClaimId Csip55 { get; } = ClaimId.Create(MetsProfileRangeStart + 55, "CSIP55");

    /// <summary><c>CSIP56</c> — MUST, <c>mets/amdSec/rightsMD/mdRef/@CHECKSUM</c>, 1..1: file checksum. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP56</see>.</summary>
    public static ClaimId Csip56 { get; } = ClaimId.Create(MetsProfileRangeStart + 56, "CSIP56");

    /// <summary><c>CSIP57</c> — MUST, <c>mets/amdSec/rightsMD/mdRef/@CHECKSUMTYPE</c>, 1..1: file checksum type. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP57</see>.</summary>
    public static ClaimId Csip57 { get; } = ClaimId.Create(MetsProfileRangeStart + 57, "CSIP57");

    /// <summary><c>CSIP58</c> — SHOULD, <c>mets/fileSec</c>, 0..1: file section. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP58</see>.</summary>
    public static ClaimId Csip58 { get; } = ClaimId.Create(MetsProfileRangeStart + 58, "CSIP58");

    /// <summary><c>CSIP59</c> — MUST, <c>mets/fileSec/@ID</c>, 1..1: file section identifier. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP59</see>.</summary>
    public static ClaimId Csip59 { get; } = ClaimId.Create(MetsProfileRangeStart + 59, "CSIP59");

    /// <summary><c>CSIP60</c> — MUST, <c>mets/fileSec/fileGrp[@USE='Documentation']</c>, 1..n: documentation file group. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP60</see>.</summary>
    public static ClaimId Csip60 { get; } = ClaimId.Create(MetsProfileRangeStart + 60, "CSIP60");

    /// <summary><c>CSIP61</c> — MAY, <c>mets/fileSec/fileGrp/@ADMID</c>, 0..1: reference to administrative metadata. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP61</see>.</summary>
    public static ClaimId Csip61 { get; } = ClaimId.Create(MetsProfileRangeStart + 61, "CSIP61");

    /// <summary><c>CSIP62</c> — SHOULD, <c>mets/fileSec/fileGrp/@csip:CONTENTINFORMATIONTYPE</c>, 0..1: content information type specification per file group. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP62</see>.</summary>
    public static ClaimId Csip62 { get; } = ClaimId.Create(MetsProfileRangeStart + 62, "CSIP62");

    /// <summary><c>CSIP63</c> — MAY, <c>mets/fileSec/fileGrp[@csip:CONTENTINFORMATIONTYPE='OTHER']/@csip:OTHERCONTENTINFORMATIONTYPE</c>, 0..1: other content information type specification. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP63</see>.</summary>
    public static ClaimId Csip63 { get; } = ClaimId.Create(MetsProfileRangeStart + 63, "CSIP63");

    /// <summary><c>CSIP64</c> — MUST, <c>mets/fileSec/fileGrp/@USE</c>, 1..1: description of the use of the file group. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP64</see>.</summary>
    public static ClaimId Csip64 { get; } = ClaimId.Create(MetsProfileRangeStart + 64, "CSIP64");

    /// <summary><c>CSIP65</c> — MUST, <c>mets/fileSec/fileGrp/@ID</c>, 1..1: file group identifier. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP65</see>.</summary>
    public static ClaimId Csip65 { get; } = ClaimId.Create(MetsProfileRangeStart + 65, "CSIP65");

    /// <summary><c>CSIP66</c> — MUST, <c>mets/fileSec/fileGrp/file</c>, 1..n: file. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP66</see>.</summary>
    public static ClaimId Csip66 { get; } = ClaimId.Create(MetsProfileRangeStart + 66, "CSIP66");

    /// <summary><c>CSIP67</c> — MUST, <c>mets/fileSec/fileGrp/file/@ID</c>, 1..1: file identifier. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP67</see>.</summary>
    public static ClaimId Csip67 { get; } = ClaimId.Create(MetsProfileRangeStart + 67, "CSIP67");

    /// <summary><c>CSIP68</c> — MUST, <c>mets/fileSec/fileGrp/file/@MIMETYPE</c>, 1..1: file media type. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP68</see>.</summary>
    public static ClaimId Csip68 { get; } = ClaimId.Create(MetsProfileRangeStart + 68, "CSIP68");

    /// <summary><c>CSIP69</c> — MUST, <c>mets/fileSec/fileGrp/file/@SIZE</c>, 1..1: file size. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP69</see>.</summary>
    public static ClaimId Csip69 { get; } = ClaimId.Create(MetsProfileRangeStart + 69, "CSIP69");

    /// <summary><c>CSIP70</c> — MUST, <c>mets/fileSec/fileGrp/file/@CREATED</c>, 1..1: file creation datetime. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP70</see>.</summary>
    public static ClaimId Csip70 { get; } = ClaimId.Create(MetsProfileRangeStart + 70, "CSIP70");

    /// <summary><c>CSIP71</c> — MUST, <c>mets/fileSec/fileGrp/file/@CHECKSUM</c>, 1..1: file checksum. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP71</see>.</summary>
    public static ClaimId Csip71 { get; } = ClaimId.Create(MetsProfileRangeStart + 71, "CSIP71");

    /// <summary><c>CSIP72</c> — MUST, <c>mets/fileSec/fileGrp/file/@CHECKSUMTYPE</c>, 1..1: file checksum type. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP72</see>.</summary>
    public static ClaimId Csip72 { get; } = ClaimId.Create(MetsProfileRangeStart + 72, "CSIP72");

    /// <summary><c>CSIP73</c> — MAY, <c>mets/fileSec/fileGrp/file/@OWNERID</c>, 0..1: file original identification. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP73</see>.</summary>
    public static ClaimId Csip73 { get; } = ClaimId.Create(MetsProfileRangeStart + 73, "CSIP73");

    /// <summary><c>CSIP74</c> — MAY, <c>mets/fileSec/fileGrp/file/@ADMID</c>, 0..1: file reference to administrative metadata. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP74</see>.</summary>
    public static ClaimId Csip74 { get; } = ClaimId.Create(MetsProfileRangeStart + 74, "CSIP74");

    /// <summary><c>CSIP75</c> — MAY, <c>mets/fileSec/fileGrp/file/@DMDID</c>, 0..1: file reference to descriptive metadata. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP75</see>.</summary>
    public static ClaimId Csip75 { get; } = ClaimId.Create(MetsProfileRangeStart + 75, "CSIP75");

    /// <summary><c>CSIP76</c> — MUST, <c>mets/fileSec/fileGrp/file/FLocat</c>, 1..1: file locator reference. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP76</see>.</summary>
    public static ClaimId Csip76 { get; } = ClaimId.Create(MetsProfileRangeStart + 76, "CSIP76");

    /// <summary><c>CSIP77</c> — MUST, <c>mets/fileSec/fileGrp/file/FLocat[@LOCTYPE='URL']</c>, 1..1: type of locator, fixed value. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP77</see>.</summary>
    public static ClaimId Csip77 { get; } = ClaimId.Create(MetsProfileRangeStart + 77, "CSIP77");

    /// <summary><c>CSIP78</c> — MUST, <c>mets/fileSec/fileGrp/file/FLocat[@xlink:type='simple']</c>, 1..1: type of link, fixed value. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP78</see>.</summary>
    public static ClaimId Csip78 { get; } = ClaimId.Create(MetsProfileRangeStart + 78, "CSIP78");

    /// <summary><c>CSIP79</c> — MUST, <c>mets/fileSec/fileGrp/file/FLocat/@xlink:href</c>, 1..1: resource location. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP79</see>.</summary>
    public static ClaimId Csip79 { get; } = ClaimId.Create(MetsProfileRangeStart + 79, "CSIP79");

    /// <summary><c>CSIP80</c> — MUST, <c>mets/structMap</c>, 1..n: structural description of the package. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP80</see>.</summary>
    public static ClaimId Csip80 { get; } = ClaimId.Create(MetsProfileRangeStart + 80, "CSIP80");

    /// <summary><c>CSIP81</c> — MUST, <c>mets/structMap[@TYPE='PHYSICAL']</c>, 1..1: type of structural description, fixed value. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP81</see>.</summary>
    public static ClaimId Csip81 { get; } = ClaimId.Create(MetsProfileRangeStart + 81, "CSIP81");

    /// <summary><c>CSIP82</c> — MUST, <c>mets/structMap[@LABEL='CSIP']</c>, 1..1: the name of the CSIP-mandated structural map, treated as a unique identifier. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP82</see>.</summary>
    public static ClaimId Csip82 { get; } = ClaimId.Create(MetsProfileRangeStart + 82, "CSIP82");

    /// <summary><c>CSIP83</c> — MUST, <c>mets/structMap[@LABEL='CSIP']/@ID</c>, 1..1: structural description identifier. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP83</see>.</summary>
    public static ClaimId Csip83 { get; } = ClaimId.Create(MetsProfileRangeStart + 83, "CSIP83");

    /// <summary><c>CSIP84</c> — MUST, <c>mets/structMap[@LABEL='CSIP']/div</c>, 1..1: the single main structural division. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP84</see>.</summary>
    public static ClaimId Csip84 { get; } = ClaimId.Create(MetsProfileRangeStart + 84, "CSIP84");

    /// <summary><c>CSIP85</c> — MUST, <c>mets/structMap[@LABEL='CSIP']/div/@ID</c>, 1..1: main structural division identifier. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP85</see>.</summary>
    public static ClaimId Csip85 { get; } = ClaimId.Create(MetsProfileRangeStart + 85, "CSIP85");

    //CSIP86 (deprecated 2021-10-15) and CSIP87 (deprecated 2019-05-09) are stated by no current requirement;
    //their codes, MetsProfileRangeStart + 86 and + 87, stay permanently unallocated.

    /// <summary><c>CSIP88</c> — MUST, <c>.../div/div[@LABEL='Metadata']</c>, 1..1: metadata division. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP88</see>.</summary>
    public static ClaimId Csip88 { get; } = ClaimId.Create(MetsProfileRangeStart + 88, "CSIP88");

    /// <summary><c>CSIP89</c> — MUST, <c>.../div/div[@LABEL='Metadata']/@ID</c>, 1..1: metadata division identifier. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP89</see>.</summary>
    public static ClaimId Csip89 { get; } = ClaimId.Create(MetsProfileRangeStart + 89, "CSIP89");

    /// <summary><c>CSIP90</c> — MUST, <c>.../div/div[@LABEL='Metadata']</c>, 1..1: metadata division label, a controlled-vocabulary value. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP90</see>.</summary>
    public static ClaimId Csip90 { get; } = ClaimId.Create(MetsProfileRangeStart + 90, "CSIP90");

    /// <summary><c>CSIP91</c> — SHOULD, <c>.../div/div[@LABEL='Metadata']/@ADMID</c>, 0..1: metadata division reference to administrative metadata. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP91</see>.</summary>
    public static ClaimId Csip91 { get; } = ClaimId.Create(MetsProfileRangeStart + 91, "CSIP91");

    /// <summary><c>CSIP92</c> — SHOULD, <c>.../div/div[@LABEL='Metadata']/@DMDID</c>, 0..1: metadata division reference to descriptive metadata. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP92</see>.</summary>
    public static ClaimId Csip92 { get; } = ClaimId.Create(MetsProfileRangeStart + 92, "CSIP92");

    /// <summary><c>CSIP93</c> — SHOULD, <c>.../div/div[@LABEL='Documentation']</c>, 0..1: documentation division. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP93</see>.</summary>
    public static ClaimId Csip93 { get; } = ClaimId.Create(MetsProfileRangeStart + 93, "CSIP93");

    /// <summary><c>CSIP94</c> — MUST, <c>.../div/div[@LABEL='Documentation']/@ID</c>, 1..1: documentation division identifier. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP94</see>.</summary>
    public static ClaimId Csip94 { get; } = ClaimId.Create(MetsProfileRangeStart + 94, "CSIP94");

    /// <summary><c>CSIP95</c> — MUST, <c>.../div/div[@LABEL='Documentation']</c>, 1..1: documentation division label. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP95</see>.</summary>
    public static ClaimId Csip95 { get; } = ClaimId.Create(MetsProfileRangeStart + 95, "CSIP95");

    /// <summary><c>CSIP96</c> — SHOULD, <c>.../div/div[@LABEL='Documentation']/fptr</c>, 0..n: documentation file references. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP96</see>.</summary>
    public static ClaimId Csip96 { get; } = ClaimId.Create(MetsProfileRangeStart + 96, "CSIP96");

    /// <summary><c>CSIP97</c> — SHOULD, <c>.../div/div[@LABEL='Schemas']</c>, 0..1: schema division. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP97</see>.</summary>
    public static ClaimId Csip97 { get; } = ClaimId.Create(MetsProfileRangeStart + 97, "CSIP97");

    /// <summary><c>CSIP98</c> — MUST, <c>.../div/div[@LABEL='Schemas']/@ID</c>, 1..1: schema division identifier. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP98</see>.</summary>
    public static ClaimId Csip98 { get; } = ClaimId.Create(MetsProfileRangeStart + 98, "CSIP98");

    /// <summary><c>CSIP99</c> — MUST, <c>.../div/div[@LABEL='Schemas']</c>, 1..1: schema division label. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP99</see>.</summary>
    public static ClaimId Csip99 { get; } = ClaimId.Create(MetsProfileRangeStart + 99, "CSIP99");

    /// <summary><c>CSIP100</c> — SHOULD, <c>.../div/div[@LABEL='Schemas']/fptr</c>, 0..n: schema file reference. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP100</see>.</summary>
    public static ClaimId Csip100 { get; } = ClaimId.Create(MetsProfileRangeStart + 100, "CSIP100");

    /// <summary><c>CSIP101</c> — SHOULD, <c>.../div/div[@LABEL='Representations']</c>, 0..1: content division. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP101</see>.</summary>
    public static ClaimId Csip101 { get; } = ClaimId.Create(MetsProfileRangeStart + 101, "CSIP101");

    /// <summary><c>CSIP102</c> — MUST, <c>.../div/div[@LABEL='Representations']/@ID</c>, 1..1: content division identifier. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP102</see>.</summary>
    public static ClaimId Csip102 { get; } = ClaimId.Create(MetsProfileRangeStart + 102, "CSIP102");

    /// <summary><c>CSIP103</c> — MUST, <c>.../div/div[@LABEL='Representations']</c>, 1..1: content division label. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP103</see>.</summary>
    public static ClaimId Csip103 { get; } = ClaimId.Create(MetsProfileRangeStart + 103, "CSIP103");

    /// <summary><c>CSIP104</c> — SHOULD, <c>.../div/div[@LABEL='Representations']/fptr</c>, 0..n: content division file references. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP104</see>.</summary>
    public static ClaimId Csip104 { get; } = ClaimId.Create(MetsProfileRangeStart + 104, "CSIP104");

    /// <summary><c>CSIP105</c> — SHOULD, <c>.../div/div</c>, 0..n: one representation division per representation. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP105</see>.</summary>
    public static ClaimId Csip105 { get; } = ClaimId.Create(MetsProfileRangeStart + 105, "CSIP105");

    /// <summary><c>CSIP106</c> — MUST, <c>.../div/div/@ID</c>, 1..1: representations division identifier. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP106</see>.</summary>
    public static ClaimId Csip106 { get; } = ClaimId.Create(MetsProfileRangeStart + 106, "CSIP106");

    /// <summary><c>CSIP107</c> — MUST, <c>.../div/div/@LABEL</c>, 1..1: representations division label, the representation's folder name. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP107</see>.</summary>
    public static ClaimId Csip107 { get; } = ClaimId.Create(MetsProfileRangeStart + 107, "CSIP107");

    /// <summary><c>CSIP108</c> — MUST, <c>.../div/div/mptr/@xlink:title</c>, 1..1: representations division file references. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP108</see>.</summary>
    public static ClaimId Csip108 { get; } = ClaimId.Create(MetsProfileRangeStart + 108, "CSIP108");

    /// <summary><c>CSIP109</c> — MUST, <c>.../div/div/mptr</c>, 1..1: the representation METS pointer. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP109</see>.</summary>
    public static ClaimId Csip109 { get; } = ClaimId.Create(MetsProfileRangeStart + 109, "CSIP109");

    /// <summary><c>CSIP110</c> — MUST, <c>mets/structMap/div/div/mptr/@xlink:href</c>, 1..1: resource location of the representation's <c>METS.xml</c>. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP110</see>.</summary>
    public static ClaimId Csip110 { get; } = ClaimId.Create(MetsProfileRangeStart + 110, "CSIP110");

    /// <summary><c>CSIP111</c> — MUST, <c>.../mptr[@xlink:type='simple']</c>, 1..1: type of link, fixed value. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP111</see>.</summary>
    public static ClaimId Csip111 { get; } = ClaimId.Create(MetsProfileRangeStart + 111, "CSIP111");

    /// <summary><c>CSIP112</c> — MUST, <c>.../mptr[@LOCTYPE='URL']</c>, 1..1: type of locator, fixed value. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP112</see>.</summary>
    public static ClaimId Csip112 { get; } = ClaimId.Create(MetsProfileRangeStart + 112, "CSIP112");

    /// <summary><c>CSIP113</c> — MUST, <c>mets/fileSec/fileGrp[@USE='Schemas']</c>, 1..n: schema file group. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP113</see>.</summary>
    public static ClaimId Csip113 { get; } = ClaimId.Create(MetsProfileRangeStart + 113, "CSIP113");

    /// <summary><c>CSIP114</c> — MUST, <c>mets/fileSec/fileGrp</c> whose <c>@USE</c> starts with <c>Representations</c>, 1..n: representations file group. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP114</see>.</summary>
    public static ClaimId Csip114 { get; } = ClaimId.Create(MetsProfileRangeStart + 114, "CSIP114");

    //CSIP115 was never allocated by the specification in either v2.1.0 or v2.2.0; the code
    //MetsProfileRangeStart + 115 stays permanently unallocated so every other number keeps matching.

    /// <summary><c>CSIP116</c> — MUST, <c>.../div/div[@LABEL='Documentation']/fptr/@FILEID</c>, 1..1: documentation file group reference pointer. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP116</see>.</summary>
    public static ClaimId Csip116 { get; } = ClaimId.Create(MetsProfileRangeStart + 116, "CSIP116");

    /// <summary><c>CSIP117</c> — MUST, <c>mets/metsHdr</c>, 1..1: package header. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP117</see>.</summary>
    public static ClaimId Csip117 { get; } = ClaimId.Create(MetsProfileRangeStart + 117, "CSIP117");

    /// <summary><c>CSIP118</c> — MUST, <c>.../div/div[@LABEL='Schemas']/fptr/@FILEID</c>, 1..1: schema file group reference. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP118</see>.</summary>
    public static ClaimId Csip118 { get; } = ClaimId.Create(MetsProfileRangeStart + 118, "CSIP118");

    /// <summary><c>CSIP119</c> — MUST, <c>.../div/div[@LABEL='Representations']/fptr/@FILEID</c>, 1..1: content division file group references. <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP119</see>.</summary>
    public static ClaimId Csip119 { get; } = ClaimId.Create(MetsProfileRangeStart + 119, "CSIP119");


    /// <summary><c>CSIPSTR1</c> — MUST: the package is included within a single physical root folder, and an archived package unpacks to one. <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 CSIPSTR1</see>.</summary>
    public static ClaimId CsipStr1 { get; } = ClaimId.Create(FolderStructureRangeStart + 1, "CSIPSTR1");

    /// <summary><c>CSIPSTR2</c> — SHOULD: the root folder is named with the value of <c>mets/@OBJID</c>. <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 CSIPSTR2</see>.</summary>
    public static ClaimId CsipStr2 { get; } = ClaimId.Create(FolderStructureRangeStart + 2, "CSIPSTR2");

    /// <summary><c>CSIPSTR3</c> — MAY: the package may be archived or compressed for storage and transfer, the format being decided by the interested parties. <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 CSIPSTR3</see>.</summary>
    public static ClaimId CsipStr3 { get; } = ClaimId.Create(FolderStructureRangeStart + 3, "CSIPSTR3");

    /// <summary><c>CSIPSTR4</c> — MUST: the root folder includes a file named <c>METS.xml</c> identifying the package. <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 CSIPSTR4</see>.</summary>
    public static ClaimId CsipStr4 { get; } = ClaimId.Create(FolderStructureRangeStart + 4, "CSIPSTR4");

    /// <summary><c>CSIPSTR5</c> — SHOULD: the root folder includes a <c>metadata</c> folder for whole-package metadata. <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 CSIPSTR5</see>.</summary>
    public static ClaimId CsipStr5 { get; } = ClaimId.Create(FolderStructureRangeStart + 5, "CSIPSTR5");

    /// <summary><c>CSIPSTR6</c> — SHOULD: preservation metadata, when available, is placed in <c>metadata/preservation</c>. <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 CSIPSTR6</see>.</summary>
    public static ClaimId CsipStr6 { get; } = ClaimId.Create(FolderStructureRangeStart + 6, "CSIPSTR6");

    /// <summary><c>CSIPSTR7</c> — SHOULD: descriptive metadata, when available, is placed in <c>metadata/descriptive</c>. <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 CSIPSTR7</see>.</summary>
    public static ClaimId CsipStr7 { get; } = ClaimId.Create(FolderStructureRangeStart + 7, "CSIPSTR7");

    /// <summary><c>CSIPSTR8</c> — MAY: other metadata may be placed in additional sub-folders, for example <c>metadata/other</c>. <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 CSIPSTR8</see>.</summary>
    public static ClaimId CsipStr8 { get; } = ClaimId.Create(FolderStructureRangeStart + 8, "CSIPSTR8");

    /// <summary><c>CSIPSTR9</c> — SHOULD: the package folder includes a <c>representations</c> folder. <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 CSIPSTR9</see>.</summary>
    public static ClaimId CsipStr9 { get; } = ClaimId.Create(FolderStructureRangeStart + 9, "CSIPSTR9");

    /// <summary><c>CSIPSTR10</c> — SHOULD: <c>representations</c> includes one sub-folder per representation, uniquely named within the package. <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 CSIPSTR10</see>.</summary>
    public static ClaimId CsipStr10 { get; } = ClaimId.Create(FolderStructureRangeStart + 10, "CSIPSTR10");

    /// <summary><c>CSIPSTR11</c> — SHOULD: each representation folder includes a <c>data</c> sub-folder holding the representation's data. <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 CSIPSTR11</see>.</summary>
    public static ClaimId CsipStr11 { get; } = ClaimId.Create(FolderStructureRangeStart + 11, "CSIPSTR11");

    /// <summary><c>CSIPSTR12</c> — SHOULD: each representation folder includes its own <c>METS.xml</c>. <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 CSIPSTR12</see>.</summary>
    public static ClaimId CsipStr12 { get; } = ClaimId.Create(FolderStructureRangeStart + 12, "CSIPSTR12");

    /// <summary><c>CSIPSTR13</c> — SHOULD: each representation folder includes its own <c>metadata</c> sub-folder. <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 CSIPSTR13</see>.</summary>
    public static ClaimId CsipStr13 { get; } = ClaimId.Create(FolderStructureRangeStart + 13, "CSIPSTR13");

    /// <summary><c>CSIPSTR14</c> — MAY: the package may be extended with additional sub-folders, the specification's own extension point. <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 CSIPSTR14</see>.</summary>
    public static ClaimId CsipStr14 { get; } = ClaimId.Create(FolderStructureRangeStart + 14, "CSIPSTR14");

    /// <summary><c>CSIPSTR15</c> — SHOULD: XML schema documents are placed in a <c>schemas</c> sub-folder at package and/or representation level. <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 CSIPSTR15</see>.</summary>
    public static ClaimId CsipStr15 { get; } = ClaimId.Create(FolderStructureRangeStart + 15, "CSIPSTR15");

    /// <summary><c>CSIPSTR16</c> — SHOULD: supplementary documentation is placed in a <c>documentation</c> sub-folder at package and/or representation level. <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 CSIPSTR16</see>.</summary>
    public static ClaimId CsipStr16 { get; } = ClaimId.Create(FolderStructureRangeStart + 16, "CSIPSTR16");


    /// <summary>
    /// The package snapshot stays inside the bounds the caller stated. A house claim: no source specification
    /// states a bound, because none of them contemplates a hostile package, and validation runs over a snapshot
    /// that arrived from whoever built the package.
    /// </summary>
    public static ClaimId PackageWithinStatedLimits { get; } = ClaimId.Create(HouseConventionRangeStart + 1, "EArkPackageWithinStatedLimits");

    /// <summary>
    /// Every fixity value the package's manifest states was recomputed over the octets the package holds and
    /// equals what the document states. A house claim: the specification requires the attribute pair to be
    /// present (<c>CSIP29</c>/<c>30</c>, <c>CSIP43</c>/<c>44</c>, <c>CSIP56</c>/<c>57</c>, <c>CSIP71</c>/<c>72</c>)
    /// and never requires anyone to recompute it, so recomputation is this library's own obligation and gets
    /// its own row rather than borrowing a presence row's.
    /// </summary>
    public static ClaimId PackageFixityRecomputed { get; } = ClaimId.Create(HouseConventionRangeStart + 2, "EArkPackageFixityRecomputed");

    /// <summary>
    /// Every fixity value the package states names an algorithm this library will treat as evidence of
    /// authenticity. A house claim, and a floor the specification does not impose: the checksum-type
    /// enumeration admits error-detection codes and broken hash functions as equally legal values, so a
    /// package below the floor is conformant and is flagged here rather than failed.
    /// </summary>
    public static ClaimId PackageFixityAlgorithmStrength { get; } = ClaimId.Create(HouseConventionRangeStart + 3, "EArkPackageFixityAlgorithmStrength");

    /// <summary>
    /// Every reference the package's manifest makes to a file of its own resolves to an entry the package
    /// holds. A house claim standing for the un-numbered blanket obligation of
    /// <see href="https://earkcsip.dilcis.eu/specification/implementation/metadata/general-requirements/">E-ARK
    /// CSIP v2.2.0 clause 5.1</see>, "All references within a CSIP Information Package must adhere to the
    /// requirements stated in this specification", which the specification states in prose and gives no
    /// identifier of its own.
    /// </summary>
    public static ClaimId PackageReferencesResolve { get; } = ClaimId.Create(HouseConventionRangeStart + 4, "EArkPackageReferencesResolve");

    /// <summary>
    /// Every identifier the package's manifest carries is a legal <c>NCName</c>. A house claim standing for
    /// the second un-numbered obligation of the same clause — "Valid XML IDs must also conform to the NCName
    /// restrictions" — which binds every <c>@ID</c> row of the catalogue and carries no identifier of its own.
    /// </summary>
    public static ClaimId PackageIdentifiersAreNCNames { get; } = ClaimId.Create(HouseConventionRangeStart + 5, "EArkPackageIdentifiersAreNCNames");

    /// <summary>
    /// Every evidential artifact the package carries sits where this library's placement convention puts one,
    /// is named by the manifest with a digest this library can recompute, and is recorded by a preservation
    /// event and a relationship saying what it attests. A house claim, and it has to be: a systematic search of
    /// <see href="https://earkcsip.dilcis.eu/">E-ARK CSIP v2.2.0</see> and
    /// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> finds no mention of
    /// signatures, time assertions or evidence records at all, so where such a file goes and how its role is
    /// recorded is a convention rather than a requirement either specification states.
    /// </summary>
    public static ClaimId PackageEvidencePlacement { get; } = ClaimId.Create(HouseConventionRangeStart + 6, "EArkPackageEvidencePlacement");

    /// <summary>
    /// Every evidential artifact the package carries describes the preservation service, evidence policy and
    /// preservation profile it was produced under, in the one extension point its own format has for it. A
    /// house claim standing beside <c>OVR-6.5-09</c> of
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
    /// ETSI TS 119 511 V1.2.1</see>, which asks an evidence policy to state whether and how an evidence carries
    /// that information and leaves the carrying itself to whoever builds the format.
    /// </summary>
    public static ClaimId PackageEvidenceSelfDescription { get; } = ClaimId.Create(HouseConventionRangeStart + 7, "EArkPackageEvidenceSelfDescription");

    /// <summary>
    /// Every digital-provenance document the package's manifest references is inside what one of the package's
    /// evidential artifacts proves. A house claim closing the gap
    /// <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0</see> names itself: its provenance events chain to
    /// one another in plain text, nothing binds that chain cryptographically, and how it is to be bound is out
    /// of that specification's scope.
    /// </summary>
    public static ClaimId PackageProvenanceAnchored { get; } = ClaimId.Create(HouseConventionRangeStart + 8, "EArkPackageProvenanceAnchored");


    /// <summary>Determines whether a claim identifier names an E-ARK CSIP METS profile requirement, <c>CSIP1</c>…<c>CSIP119</c>.</summary>
    /// <param name="claimId">The claim identifier to test.</param>
    /// <returns><see langword="true"/> when the code falls in the METS profile band.</returns>
    public static bool IsMetsProfileRequirement(ClaimId claimId) =>
        claimId.Code >= MetsProfileRangeStart && claimId.Code <= MetsProfileRangeEnd;


    /// <summary>Determines whether a claim identifier names an E-ARK CSIP folder-structure requirement, <c>CSIPSTR1</c>…<c>CSIPSTR16</c>.</summary>
    /// <param name="claimId">The claim identifier to test.</param>
    /// <returns><see langword="true"/> when the code falls in the folder-structure band.</returns>
    public static bool IsFolderStructureRequirement(ClaimId claimId) =>
        claimId.Code >= FolderStructureRangeStart && claimId.Code <= FolderStructureRangeEnd;


    /// <summary>Determines whether a claim identifier names an E-ARK CSIP requirement of either catalogue.</summary>
    /// <param name="claimId">The claim identifier to test.</param>
    /// <returns><see langword="true"/> when the code falls in either E-ARK CSIP band.</returns>
    public static bool IsEArkRequirement(ClaimId claimId) =>
        IsMetsProfileRequirement(claimId) || IsFolderStructureRequirement(claimId);


    /// <summary>
    /// Determines whether a claim identifier names a convention of this library rather than a requirement any
    /// source specification states.
    /// </summary>
    /// <param name="claimId">The claim identifier to test.</param>
    /// <returns><see langword="true"/> when the code falls in the house-convention band.</returns>
    public static bool IsHouseConvention(ClaimId claimId) =>
        claimId.Code >= HouseConventionRangeStart && claimId.Code <= HouseConventionRangeEnd;
}
