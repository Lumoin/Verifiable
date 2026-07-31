namespace Verifiable.Core.Assessment.EArchiving;

/// <summary>
/// The <see cref="ClaimId"/> allocation for the Common Specification for Preservation Metadata v1.0.1 — its
/// tabulated catalogue <c>PM1</c>…<c>PM125</c> and the fourteen named mnemonic requirements its narrative
/// states beside them.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The code ranges below are STABLE</strong> on the same terms as
/// <see cref="EArkClaimIds"/>, whose remarks carry the whole eArchiving band map: a code allocated here is
/// never reassigned, and a consuming system may key a requirements-to-code graph on the integer code alone.
/// </para>
/// <list type="table">
///   <item><description><c>2 200 000</c>–<c>2 299 999</c>: the tabulated catalogue, code = start + <em>n</em> of <c>PMn</c>.</description></item>
///   <item><description><c>2 300 000</c>–<c>2 399 999</c>: the narrative mnemonics, allocated in the order clause 4 states them.</description></item>
/// </list>
/// <para>
/// The specification uses a fifth, non-RFC 2119 keyword: <c>PM53</c> and <c>PM66</c> state <c>COULD</c> where
/// every other row states MUST, SHOULD or MAY. Both rows are optional in cardinality (0..1 and 0..n), so this
/// library reads <c>COULD</c> as MAY and says so at each of the two allocations rather than dropping the rows.
/// </para>
/// <para>
/// Source: <see href="https://citspremis.dilcis.eu/">Common Specification for Preservation Metadata v1.0.1</see>
/// — the catalogue in its clause 6 tables, the mnemonics in its clause 4 narrative.
/// </para>
/// </remarks>
public static class PremisClaimIds
{
    /// <summary>The first code of the band holding the tabulated preservation-metadata requirements, <c>2 200 000</c>.</summary>
    public static int TableRequirementRangeStart { get; } = 2_200_000;

    /// <summary>The last code of the band holding the tabulated preservation-metadata requirements, <c>2 299 999</c>.</summary>
    public static int TableRequirementRangeEnd { get; } = 2_299_999;

    /// <summary>The first code of the band holding the narrative mnemonic requirements, <c>2 300 000</c>.</summary>
    public static int NarrativeRequirementRangeStart { get; } = 2_300_000;

    /// <summary>The last code of the band holding the narrative mnemonic requirements, <c>2 399 999</c>.</summary>
    public static int NarrativeRequirementRangeEnd { get; } = 2_399_999;


    /// <summary><c>PM1</c> — MUST, 1..1: the preservation-metadata version, <c>premis/@version="3.0"</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM1</see>.</summary>
    public static ClaimId Pm1 { get; } = ClaimId.Create(TableRequirementRangeStart + 1, "PM1");

    /// <summary><c>PM2</c> — MUST, 1..1: object category of an intellectual-entity or environment object. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM2</see>.</summary>
    public static ClaimId Pm2 { get; } = ClaimId.Create(TableRequirementRangeStart + 2, "PM2");

    /// <summary><c>PM3</c> — MUST, 1..1: the object carries an <c>objectIdentifier</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM3</see>.</summary>
    public static ClaimId Pm3 { get; } = ClaimId.Create(TableRequirementRangeStart + 3, "PM3");

    /// <summary><c>PM4</c> — MUST, 1..1: <c>objectIdentifier/objectIdentifierType</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM4</see>.</summary>
    public static ClaimId Pm4 { get; } = ClaimId.Create(TableRequirementRangeStart + 4, "PM4");

    /// <summary><c>PM5</c> — MUST, 1..1: <c>objectIdentifier/objectIdentifierValue</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM5</see>.</summary>
    public static ClaimId Pm5 { get; } = ClaimId.Create(TableRequirementRangeStart + 5, "PM5");

    /// <summary><c>PM6</c> — MUST, 1..n: <c>object/environmentFunction</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM6</see>.</summary>
    public static ClaimId Pm6 { get; } = ClaimId.Create(TableRequirementRangeStart + 6, "PM6");

    /// <summary><c>PM7</c> — MUST, 1..1: <c>environmentFunction/environmentFunctionType</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM7</see>.</summary>
    public static ClaimId Pm7 { get; } = ClaimId.Create(TableRequirementRangeStart + 7, "PM7");

    /// <summary><c>PM8</c> — MUST, 1..1: <c>environmentFunction/environmentFunctionLevel</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM8</see>.</summary>
    public static ClaimId Pm8 { get; } = ClaimId.Create(TableRequirementRangeStart + 8, "PM8");

    /// <summary><c>PM9</c> — MUST, 1..1: <c>object/environmentDesignation</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM9</see>.</summary>
    public static ClaimId Pm9 { get; } = ClaimId.Create(TableRequirementRangeStart + 9, "PM9");

    /// <summary><c>PM10</c> — MUST, 1..1: <c>environmentDesignation/environmentName</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM10</see>.</summary>
    public static ClaimId Pm10 { get; } = ClaimId.Create(TableRequirementRangeStart + 10, "PM10");

    /// <summary><c>PM11</c> — SHOULD, 0..1: <c>environmentDesignation/environmentVersion</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM11</see>.</summary>
    public static ClaimId Pm11 { get; } = ClaimId.Create(TableRequirementRangeStart + 11, "PM11");

    /// <summary><c>PM12</c> — SHOULD, 0..1: <c>environmentDesignation/environmentOrigin</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM12</see>.</summary>
    public static ClaimId Pm12 { get; } = ClaimId.Create(TableRequirementRangeStart + 12, "PM12");

    /// <summary><c>PM13</c> — MAY, 0..1: <c>environmentDesignation/environmentDesignationNote</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM13</see>.</summary>
    public static ClaimId Pm13 { get; } = ClaimId.Create(TableRequirementRangeStart + 13, "PM13");

    /// <summary><c>PM14</c> — MUST, 1..1: object category of a representation object. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM14</see>.</summary>
    public static ClaimId Pm14 { get; } = ClaimId.Create(TableRequirementRangeStart + 14, "PM14");

    /// <summary><c>PM15</c> — MUST, 1..1: the representation object carries an <c>objectIdentifier</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM15</see>.</summary>
    public static ClaimId Pm15 { get; } = ClaimId.Create(TableRequirementRangeStart + 15, "PM15");

    /// <summary><c>PM16</c> — MUST, 1..1: <c>objectIdentifier/objectIdentifierType</c> of the representation object. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM16</see>.</summary>
    public static ClaimId Pm16 { get; } = ClaimId.Create(TableRequirementRangeStart + 16, "PM16");

    /// <summary><c>PM17</c> — MUST, 1..1: <c>objectIdentifier/objectIdentifierValue</c> of the representation object. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM17</see>.</summary>
    public static ClaimId Pm17 { get; } = ClaimId.Create(TableRequirementRangeStart + 17, "PM17");

    /// <summary><c>PM18</c> — SHOULD, 0..n: the representation object carries significant properties. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM18</see>.</summary>
    public static ClaimId Pm18 { get; } = ClaimId.Create(TableRequirementRangeStart + 18, "PM18");

    /// <summary><c>PM19</c> — MUST, 1..1: <c>significantProperties/significantPropertiesType</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM19</see>.</summary>
    public static ClaimId Pm19 { get; } = ClaimId.Create(TableRequirementRangeStart + 19, "PM19");

    /// <summary><c>PM20</c> — MUST, 1..1: <c>significantProperties/significantPropertiesValue</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM20</see>.</summary>
    public static ClaimId Pm20 { get; } = ClaimId.Create(TableRequirementRangeStart + 20, "PM20");

    /// <summary><c>PM21</c> — MUST, 1..n: <c>object/relationship</c> connecting the representation to its rendering software. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM21</see>.</summary>
    public static ClaimId Pm21 { get; } = ClaimId.Create(TableRequirementRangeStart + 21, "PM21");

    /// <summary><c>PM22</c> — MUST, 1..1: <c>relationship/relationshipType</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM22</see>.</summary>
    public static ClaimId Pm22 { get; } = ClaimId.Create(TableRequirementRangeStart + 22, "PM22");

    /// <summary><c>PM23</c> — MUST, 1..1: <c>relationship/relationshipSubType</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM23</see>.</summary>
    public static ClaimId Pm23 { get; } = ClaimId.Create(TableRequirementRangeStart + 23, "PM23");

    /// <summary><c>PM24</c> — MUST, 1..1: <c>relationship/relatedObjectIdentifier</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM24</see>.</summary>
    public static ClaimId Pm24 { get; } = ClaimId.Create(TableRequirementRangeStart + 24, "PM24");

    /// <summary><c>PM25</c> — MUST, 1..1: <c>relatedObjectIdentifier/relatedObjectIdentifierType</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM25</see>.</summary>
    public static ClaimId Pm25 { get; } = ClaimId.Create(TableRequirementRangeStart + 25, "PM25");

    /// <summary><c>PM26</c> — MUST, 1..1: <c>relatedObjectIdentifier/relatedObjectIdentifierValue</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM26</see>.</summary>
    public static ClaimId Pm26 { get; } = ClaimId.Create(TableRequirementRangeStart + 26, "PM26");

    /// <summary><c>PM27</c> — SHOULD, 0..1: <c>relationship/relatedEnvironmentPurpose</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM27</see>.</summary>
    public static ClaimId Pm27 { get; } = ClaimId.Create(TableRequirementRangeStart + 27, "PM27");

    /// <summary><c>PM28</c> — MUST, 1..1: object category of a file object. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM28</see>.</summary>
    public static ClaimId Pm28 { get; } = ClaimId.Create(TableRequirementRangeStart + 28, "PM28");

    /// <summary><c>PM29</c> — MUST, 1..n: the file object carries an <c>objectIdentifier</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM29</see>.</summary>
    public static ClaimId Pm29 { get; } = ClaimId.Create(TableRequirementRangeStart + 29, "PM29");

    /// <summary><c>PM30</c> — MUST, 1..1: <c>objectIdentifier/objectIdentifierType</c> of the file object. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM30</see>.</summary>
    public static ClaimId Pm30 { get; } = ClaimId.Create(TableRequirementRangeStart + 30, "PM30");

    /// <summary><c>PM31</c> — MUST, 1..1: <c>objectIdentifier/objectIdentifierValue</c> of the file object. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM31</see>.</summary>
    public static ClaimId Pm31 { get; } = ClaimId.Create(TableRequirementRangeStart + 31, "PM31");

    /// <summary><c>PM32</c> — MUST, 1..n: <c>object/objectCharacteristics</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM32</see>.</summary>
    public static ClaimId Pm32 { get; } = ClaimId.Create(TableRequirementRangeStart + 32, "PM32");

    /// <summary><c>PM33</c> — SHOULD, 0..n: <c>objectCharacteristics/fixity</c>, the file object's checksum block. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM33</see>.</summary>
    public static ClaimId Pm33 { get; } = ClaimId.Create(TableRequirementRangeStart + 33, "PM33");

    /// <summary><c>PM34</c> — MUST, 1..1: <c>fixity/messageDigestAlgorithm</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM34</see>.</summary>
    public static ClaimId Pm34 { get; } = ClaimId.Create(TableRequirementRangeStart + 34, "PM34");

    /// <summary><c>PM35</c> — MUST, 1..1: <c>fixity/messageDigest</c>, the calculated checksum. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM35</see>.</summary>
    public static ClaimId Pm35 { get; } = ClaimId.Create(TableRequirementRangeStart + 35, "PM35");

    /// <summary><c>PM36</c> — MAY, 0..1: <c>fixity/messageDigestOriginator</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM36</see>.</summary>
    public static ClaimId Pm36 { get; } = ClaimId.Create(TableRequirementRangeStart + 36, "PM36");

    /// <summary><c>PM37</c> — SHOULD, 0..1: <c>objectCharacteristics/format</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM37</see>.</summary>
    public static ClaimId Pm37 { get; } = ClaimId.Create(TableRequirementRangeStart + 37, "PM37");

    /// <summary><c>PM38</c> — SHOULD, 0..1: <c>format/formatDesignation</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM38</see>.</summary>
    public static ClaimId Pm38 { get; } = ClaimId.Create(TableRequirementRangeStart + 38, "PM38");

    /// <summary><c>PM39</c> — MUST, 1..1: <c>formatDesignation/formatName</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM39</see>.</summary>
    public static ClaimId Pm39 { get; } = ClaimId.Create(TableRequirementRangeStart + 39, "PM39");

    /// <summary><c>PM40</c> — SHOULD, 0..1: <c>formatDesignation/formatVersion</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM40</see>.</summary>
    public static ClaimId Pm40 { get; } = ClaimId.Create(TableRequirementRangeStart + 40, "PM40");

    /// <summary><c>PM41</c> — SHOULD, 0..1: <c>format/formatRegistry</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM41</see>.</summary>
    public static ClaimId Pm41 { get; } = ClaimId.Create(TableRequirementRangeStart + 41, "PM41");

    /// <summary><c>PM42</c> — MUST, 1..1: <c>formatRegistry/formatRegistryName</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM42</see>.</summary>
    public static ClaimId Pm42 { get; } = ClaimId.Create(TableRequirementRangeStart + 42, "PM42");

    /// <summary><c>PM43</c> — MUST, 1..1: <c>formatRegistry/formatRegistryKey</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM43</see>.</summary>
    public static ClaimId Pm43 { get; } = ClaimId.Create(TableRequirementRangeStart + 43, "PM43");

    /// <summary><c>PM44</c> — MAY, 0..1: <c>formatRegistry/formatRegistryRole</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM44</see>.</summary>
    public static ClaimId Pm44 { get; } = ClaimId.Create(TableRequirementRangeStart + 44, "PM44");

    /// <summary><c>PM45</c> — MAY, 0..n: <c>objectCharacteristics/creatingApplication</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM45</see>.</summary>
    public static ClaimId Pm45 { get; } = ClaimId.Create(TableRequirementRangeStart + 45, "PM45");

    /// <summary><c>PM46</c> — MUST, 1..1: <c>creatingApplication/creatingApplicationName</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM46</see>.</summary>
    public static ClaimId Pm46 { get; } = ClaimId.Create(TableRequirementRangeStart + 46, "PM46");

    /// <summary><c>PM47</c> — MAY, 0..1: <c>creatingApplication/creatingApplicationVersion</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM47</see>.</summary>
    public static ClaimId Pm47 { get; } = ClaimId.Create(TableRequirementRangeStart + 47, "PM47");

    /// <summary><c>PM48</c> — MAY, 0..1: <c>creatingApplication/dateCreatedByApplication</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM48</see>.</summary>
    public static ClaimId Pm48 { get; } = ClaimId.Create(TableRequirementRangeStart + 48, "PM48");

    /// <summary><c>PM49</c> — MAY, 0..n: <c>creatingApplication/creatingApplicationExtension</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM49</see>.</summary>
    public static ClaimId Pm49 { get; } = ClaimId.Create(TableRequirementRangeStart + 49, "PM49");

    /// <summary><c>PM50</c> — MAY, 0..1: <c>objectCharacteristics/objectCharacteristicsExtension</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM50</see>.</summary>
    public static ClaimId Pm50 { get; } = ClaimId.Create(TableRequirementRangeStart + 50, "PM50");

    /// <summary><c>PM51</c> — SHOULD, 0..1: <c>object/originalName</c>, given when the name changed during preservation. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM51</see>.</summary>
    public static ClaimId Pm51 { get; } = ClaimId.Create(TableRequirementRangeStart + 51, "PM51");

    /// <summary><c>PM52</c> — MAY, 0..n: <c>object/storage</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM52</see>.</summary>
    public static ClaimId Pm52 { get; } = ClaimId.Create(TableRequirementRangeStart + 52, "PM52");

    /// <summary><c>PM53</c> — <c>COULD</c>, 0..1: <c>storage/contentLocation</c>. The specification's own fifth keyword; read as MAY here, per this class's remarks. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM53</see>.</summary>
    public static ClaimId Pm53 { get; } = ClaimId.Create(TableRequirementRangeStart + 53, "PM53");

    /// <summary><c>PM54</c> — MUST, 1..1: <c>contentLocation/contentLocationType</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM54</see>.</summary>
    public static ClaimId Pm54 { get; } = ClaimId.Create(TableRequirementRangeStart + 54, "PM54");

    /// <summary><c>PM55</c> — MUST, 1..1: <c>contentLocation/contentLocationValue</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM55</see>.</summary>
    public static ClaimId Pm55 { get; } = ClaimId.Create(TableRequirementRangeStart + 55, "PM55");

    /// <summary><c>PM56</c> — MAY, 0..1: <c>storage/storageMedium</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM56</see>.</summary>
    public static ClaimId Pm56 { get; } = ClaimId.Create(TableRequirementRangeStart + 56, "PM56");

    /// <summary><c>PM57</c> — SHOULD, 0..n: <c>object/relationship</c> to other objects and events. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM57</see>.</summary>
    public static ClaimId Pm57 { get; } = ClaimId.Create(TableRequirementRangeStart + 57, "PM57");

    /// <summary><c>PM58</c> — MUST, 1..1: <c>relationship/relationshipType</c> of a file object's relationship. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM58</see>.</summary>
    public static ClaimId Pm58 { get; } = ClaimId.Create(TableRequirementRangeStart + 58, "PM58");

    /// <summary><c>PM59</c> — MUST, 1..1: <c>relationship/relationshipSubType</c> of a file object's relationship. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM59</see>.</summary>
    public static ClaimId Pm59 { get; } = ClaimId.Create(TableRequirementRangeStart + 59, "PM59");

    /// <summary><c>PM60</c> — MUST, 1..n: <c>relationship/relatedObjectIdentifier</c> of a file object's relationship. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM60</see>.</summary>
    public static ClaimId Pm60 { get; } = ClaimId.Create(TableRequirementRangeStart + 60, "PM60");

    /// <summary><c>PM61</c> — MUST, 1..1: <c>relatedObjectIdentifier/relatedObjectIdentifierType</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM61</see>.</summary>
    public static ClaimId Pm61 { get; } = ClaimId.Create(TableRequirementRangeStart + 61, "PM61");

    /// <summary><c>PM62</c> — MUST, 1..1: <c>relatedObjectIdentifier/relatedObjectIdentifierValue</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM62</see>.</summary>
    public static ClaimId Pm62 { get; } = ClaimId.Create(TableRequirementRangeStart + 62, "PM62");

    /// <summary><c>PM63</c> — SHOULD, 0..n: <c>relationship/relatedEventIdentifier</c>; the keyword was downgraded from MUST in v1.0.1. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM63</see>.</summary>
    public static ClaimId Pm63 { get; } = ClaimId.Create(TableRequirementRangeStart + 63, "PM63");

    /// <summary><c>PM64</c> — MUST, 1..1: the type of a related event's identifier. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM64</see>.</summary>
    public static ClaimId Pm64 { get; } = ClaimId.Create(TableRequirementRangeStart + 64, "PM64");

    /// <summary><c>PM65</c> — MUST, 1..1: <c>relatedEventIdentifier/relatedEventIdentifierValue</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM65</see>.</summary>
    public static ClaimId Pm65 { get; } = ClaimId.Create(TableRequirementRangeStart + 65, "PM65");

    /// <summary><c>PM66</c> — <c>COULD</c>, 0..n: <c>object/linkingRightsStatementIdentifier</c>. The specification's own fifth keyword; read as MAY here, per this class's remarks. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM66</see>.</summary>
    public static ClaimId Pm66 { get; } = ClaimId.Create(TableRequirementRangeStart + 66, "PM66");

    /// <summary><c>PM67</c> — MUST, 1..1: the type of an object's linked rights-statement identifier. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM67</see>.</summary>
    public static ClaimId Pm67 { get; } = ClaimId.Create(TableRequirementRangeStart + 67, "PM67");

    /// <summary><c>PM68</c> — MUST, 1..1: the value of an object's linked rights-statement identifier. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM68</see>.</summary>
    public static ClaimId Pm68 { get; } = ClaimId.Create(TableRequirementRangeStart + 68, "PM68");

    /// <summary><c>PM69</c> — SHOULD, 0..n: <c>agent</c>, an agent connected with an event on a digital object. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM69</see>.</summary>
    public static ClaimId Pm69 { get; } = ClaimId.Create(TableRequirementRangeStart + 69, "PM69");

    /// <summary><c>PM70</c> — MUST, 1..n: <c>agent/agentIdentifier</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM70</see>.</summary>
    public static ClaimId Pm70 { get; } = ClaimId.Create(TableRequirementRangeStart + 70, "PM70");

    /// <summary><c>PM71</c> — MUST, 1..1: <c>agentIdentifier/agentIdentifierType</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM71</see>.</summary>
    public static ClaimId Pm71 { get; } = ClaimId.Create(TableRequirementRangeStart + 71, "PM71");

    /// <summary><c>PM72</c> — MUST, 1..1: <c>agentIdentifier/agentIdentifierValue</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM72</see>.</summary>
    public static ClaimId Pm72 { get; } = ClaimId.Create(TableRequirementRangeStart + 72, "PM72");

    /// <summary><c>PM73</c> — MUST, 1..1: <c>agent/agentName</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM73</see>.</summary>
    public static ClaimId Pm73 { get; } = ClaimId.Create(TableRequirementRangeStart + 73, "PM73");

    /// <summary><c>PM74</c> — MUST, 1..1: <c>agent/agentType</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM74</see>.</summary>
    public static ClaimId Pm74 { get; } = ClaimId.Create(TableRequirementRangeStart + 74, "PM74");

    /// <summary><c>PM75</c> — SHOULD, 0..1: <c>agent/agentVersion</c>, when the agent is software. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM75</see>.</summary>
    public static ClaimId Pm75 { get; } = ClaimId.Create(TableRequirementRangeStart + 75, "PM75");

    /// <summary><c>PM76</c> — MAY, 0..1: <c>agent/agentNote</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM76</see>.</summary>
    public static ClaimId Pm76 { get; } = ClaimId.Create(TableRequirementRangeStart + 76, "PM76");

    /// <summary><c>PM77</c> — SHOULD, 0..n: the agent's linked rights statements. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM77</see>.</summary>
    public static ClaimId Pm77 { get; } = ClaimId.Create(TableRequirementRangeStart + 77, "PM77");

    /// <summary><c>PM78</c> — MUST, 1..1: the type of the agent's linked rights-statement identifier. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM78</see>.</summary>
    public static ClaimId Pm78 { get; } = ClaimId.Create(TableRequirementRangeStart + 78, "PM78");

    /// <summary><c>PM79</c> — MUST, 1..1: the value of the agent's linked rights-statement identifier. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM79</see>.</summary>
    public static ClaimId Pm79 { get; } = ClaimId.Create(TableRequirementRangeStart + 79, "PM79");

    /// <summary><c>PM80</c> — 0..n: <c>event</c>, one per recorded event on a digital object. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM80</see>.</summary>
    public static ClaimId Pm80 { get; } = ClaimId.Create(TableRequirementRangeStart + 80, "PM80");

    /// <summary><c>PM81</c> — MUST, 1..n: <c>event/eventIdentifier</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM81</see>.</summary>
    public static ClaimId Pm81 { get; } = ClaimId.Create(TableRequirementRangeStart + 81, "PM81");

    /// <summary><c>PM82</c> — MUST, 1..1: <c>eventIdentifier/eventIdentifierType</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM82</see>.</summary>
    public static ClaimId Pm82 { get; } = ClaimId.Create(TableRequirementRangeStart + 82, "PM82");

    /// <summary><c>PM83</c> — MUST, 1..1: <c>eventIdentifier/eventIdentifierValue</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM83</see>.</summary>
    public static ClaimId Pm83 { get; } = ClaimId.Create(TableRequirementRangeStart + 83, "PM83");

    /// <summary><c>PM84</c> — MUST, 1..1: <c>event/eventType</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM84</see>.</summary>
    public static ClaimId Pm84 { get; } = ClaimId.Create(TableRequirementRangeStart + 84, "PM84");

    /// <summary><c>PM85</c> — MUST, 1..1: <c>event/eventDateTime</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM85</see>.</summary>
    public static ClaimId Pm85 { get; } = ClaimId.Create(TableRequirementRangeStart + 85, "PM85");

    /// <summary><c>PM86</c> — MUST, 1..1: <c>eventOutcomeInformation/eventOutcome</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM86</see>.</summary>
    public static ClaimId Pm86 { get; } = ClaimId.Create(TableRequirementRangeStart + 86, "PM86");

    /// <summary><c>PM87</c> — SHOULD, 0..n: <c>event/linkingAgentIdentifier</c>, the agent that carried the event out. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM87</see>.</summary>
    public static ClaimId Pm87 { get; } = ClaimId.Create(TableRequirementRangeStart + 87, "PM87");

    /// <summary><c>PM88</c> — MUST, 1..1: <c>linkingAgentIdentifier/linkingAgentIdentifierType</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM88</see>.</summary>
    public static ClaimId Pm88 { get; } = ClaimId.Create(TableRequirementRangeStart + 88, "PM88");

    /// <summary><c>PM89</c> — MUST, 1..1: <c>linkingAgentIdentifier/linkingAgentIdentifierValue</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM89</see>.</summary>
    public static ClaimId Pm89 { get; } = ClaimId.Create(TableRequirementRangeStart + 89, "PM89");

    /// <summary><c>PM90</c> — 0..n: the object an event affected. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM90</see>.</summary>
    public static ClaimId Pm90 { get; } = ClaimId.Create(TableRequirementRangeStart + 90, "PM90");

    /// <summary><c>PM91</c> — MUST, 1..1: <c>linkingObjectIdentifier/linkingObjectIdentifierType</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM91</see>.</summary>
    public static ClaimId Pm91 { get; } = ClaimId.Create(TableRequirementRangeStart + 91, "PM91");

    /// <summary><c>PM92</c> — MUST, 1..1: <c>linkingObjectIdentifier/linkingObjectIdentifierValue</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM92</see>.</summary>
    public static ClaimId Pm92 { get; } = ClaimId.Create(TableRequirementRangeStart + 92, "PM92");

    /// <summary><c>PM93</c> — SHOULD, 0..1: <c>rights</c>, all rights statements for the objects and agents. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM93</see>.</summary>
    public static ClaimId Pm93 { get; } = ClaimId.Create(TableRequirementRangeStart + 93, "PM93");

    /// <summary><c>PM94</c> — MUST, 1..n: <c>rights/rightsStatement</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM94</see>.</summary>
    public static ClaimId Pm94 { get; } = ClaimId.Create(TableRequirementRangeStart + 94, "PM94");

    /// <summary><c>PM95</c> — MUST, 1..n: <c>rightsStatement/rightsStatementIdentifier</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM95</see>.</summary>
    public static ClaimId Pm95 { get; } = ClaimId.Create(TableRequirementRangeStart + 95, "PM95");

    /// <summary><c>PM96</c> — MUST, 1..1: <c>rightsStatementIdentifier/rightsStatementIdentifierType</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM96</see>.</summary>
    public static ClaimId Pm96 { get; } = ClaimId.Create(TableRequirementRangeStart + 96, "PM96");

    /// <summary><c>PM97</c> — MUST, 1..1: <c>rightsStatementIdentifier/rightsStatementIdentifierValue</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM97</see>.</summary>
    public static ClaimId Pm97 { get; } = ClaimId.Create(TableRequirementRangeStart + 97, "PM97");

    /// <summary><c>PM98</c> — MUST, 1..1: <c>rightsStatement/rightsBasis</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM98</see>.</summary>
    public static ClaimId Pm98 { get; } = ClaimId.Create(TableRequirementRangeStart + 98, "PM98");

    /// <summary><c>PM99</c> — SHOULD, 0..1: <c>copyrightInformation</c> when the rights basis is copyright. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM99</see>.</summary>
    public static ClaimId Pm99 { get; } = ClaimId.Create(TableRequirementRangeStart + 99, "PM99");

    /// <summary><c>PM100</c> — MUST, 1..1: <c>copyrightInformation/copyrightStatus</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM100</see>.</summary>
    public static ClaimId Pm100 { get; } = ClaimId.Create(TableRequirementRangeStart + 100, "PM100");

    /// <summary><c>PM101</c> — MUST, 1..1: the copyright jurisdiction, an ISO 3166 country. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM101</see>.</summary>
    public static ClaimId Pm101 { get; } = ClaimId.Create(TableRequirementRangeStart + 101, "PM101");

    /// <summary><c>PM102</c> — MAY, 0..1: <c>copyrightInformation/copyrightDocumentationIdentifier</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM102</see>.</summary>
    public static ClaimId Pm102 { get; } = ClaimId.Create(TableRequirementRangeStart + 102, "PM102");

    /// <summary><c>PM103</c> — MUST, 1..1: the type of the copyright documentation identifier. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM103</see>.</summary>
    public static ClaimId Pm103 { get; } = ClaimId.Create(TableRequirementRangeStart + 103, "PM103");

    /// <summary><c>PM104</c> — MUST, 1..1: the value of the copyright documentation identifier. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM104</see>.</summary>
    public static ClaimId Pm104 { get; } = ClaimId.Create(TableRequirementRangeStart + 104, "PM104");

    /// <summary><c>PM105</c> — SHOULD, 0..1: <c>licenseInformation</c> when the rights basis is license. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM105</see>.</summary>
    public static ClaimId Pm105 { get; } = ClaimId.Create(TableRequirementRangeStart + 105, "PM105");

    /// <summary><c>PM106</c> — MAY, 0..1: <c>licenseInformation/licenseDocumentationIdentifier</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM106</see>.</summary>
    public static ClaimId Pm106 { get; } = ClaimId.Create(TableRequirementRangeStart + 106, "PM106");

    /// <summary><c>PM107</c> — MUST, 1..1: the type of the license documentation identifier. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM107</see>.</summary>
    public static ClaimId Pm107 { get; } = ClaimId.Create(TableRequirementRangeStart + 107, "PM107");

    /// <summary><c>PM108</c> — MUST, 1..1: the value of the license documentation identifier. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM108</see>.</summary>
    public static ClaimId Pm108 { get; } = ClaimId.Create(TableRequirementRangeStart + 108, "PM108");

    /// <summary><c>PM109</c> — SHOULD, 0..1: <c>statuteInformation</c> when the rights basis is statute. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM109</see>.</summary>
    public static ClaimId Pm109 { get; } = ClaimId.Create(TableRequirementRangeStart + 109, "PM109");

    /// <summary><c>PM110</c> — MUST, 1..1: <c>statuteInformation/statuteJurisdiction</c>, an ISO 3166 country. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM110</see>.</summary>
    public static ClaimId Pm110 { get; } = ClaimId.Create(TableRequirementRangeStart + 110, "PM110");

    /// <summary><c>PM111</c> — MUST, 1..1: <c>statuteInformation/statuteCitation</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM111</see>.</summary>
    public static ClaimId Pm111 { get; } = ClaimId.Create(TableRequirementRangeStart + 111, "PM111");

    /// <summary><c>PM112</c> — MAY, 0..1: <c>statuteInformation/statuteDocumentationIdentifier</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM112</see>.</summary>
    public static ClaimId Pm112 { get; } = ClaimId.Create(TableRequirementRangeStart + 112, "PM112");

    /// <summary><c>PM113</c> — MUST, 1..1: the type of the statute documentation identifier. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM113</see>.</summary>
    public static ClaimId Pm113 { get; } = ClaimId.Create(TableRequirementRangeStart + 113, "PM113");

    /// <summary><c>PM114</c> — MUST, 1..1: the value of the statute documentation identifier. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM114</see>.</summary>
    public static ClaimId Pm114 { get; } = ClaimId.Create(TableRequirementRangeStart + 114, "PM114");

    /// <summary><c>PM115</c> — SHOULD, 0..1: other rights information when the rights basis is other. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM115</see>.</summary>
    public static ClaimId Pm115 { get; } = ClaimId.Create(TableRequirementRangeStart + 115, "PM115");

    /// <summary><c>PM116</c> — MAY, 0..1: <c>otherRightsInformation/otherRightsDocumentationIdentifier</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM116</see>.</summary>
    public static ClaimId Pm116 { get; } = ClaimId.Create(TableRequirementRangeStart + 116, "PM116");

    /// <summary><c>PM117</c> — MUST, 1..1: the type of the other-rights documentation identifier. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM117</see>.</summary>
    public static ClaimId Pm117 { get; } = ClaimId.Create(TableRequirementRangeStart + 117, "PM117");

    /// <summary><c>PM118</c> — MUST, 1..1: the value of the other-rights documentation identifier. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM118</see>.</summary>
    public static ClaimId Pm118 { get; } = ClaimId.Create(TableRequirementRangeStart + 118, "PM118");

    /// <summary><c>PM119</c> — MUST, 1..1: <c>otherRightsInformation/otherRightsBasis</c>, a locally maintained vocabulary. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM119</see>.</summary>
    public static ClaimId Pm119 { get; } = ClaimId.Create(TableRequirementRangeStart + 119, "PM119");

    /// <summary><c>PM120</c> — SHOULD, 0..1: <c>rightsStatement/rightsGranted</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM120</see>.</summary>
    public static ClaimId Pm120 { get; } = ClaimId.Create(TableRequirementRangeStart + 120, "PM120");

    /// <summary><c>PM121</c> — MUST, 1..1: <c>rightsGranted/act</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM121</see>.</summary>
    public static ClaimId Pm121 { get; } = ClaimId.Create(TableRequirementRangeStart + 121, "PM121");

    /// <summary><c>PM122</c> — SHOULD, 0..1: <c>rightsGranted/termOfGrant</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM122</see>.</summary>
    public static ClaimId Pm122 { get; } = ClaimId.Create(TableRequirementRangeStart + 122, "PM122");

    /// <summary><c>PM123</c> — MUST, 1..1: <c>termOfGrant/startDate</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM123</see>.</summary>
    public static ClaimId Pm123 { get; } = ClaimId.Create(TableRequirementRangeStart + 123, "PM123");

    /// <summary><c>PM124</c> — MAY, 0..1: <c>termOfGrant/endDate</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM124</see>.</summary>
    public static ClaimId Pm124 { get; } = ClaimId.Create(TableRequirementRangeStart + 124, "PM124");

    /// <summary><c>PM125</c> — MAY, 0..1: <c>rightsGranted/rightsGrantedNote</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 PM125</see>.</summary>
    public static ClaimId Pm125 { get; } = ClaimId.Create(TableRequirementRangeStart + 125, "PM125");


    /// <summary><c>PREMIS-ID-LOCAL</c> — clause 4.1.1, SHOULD: an identifier of type <c>local</c> is unique within both the document and the repository. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 clause 4.1.1</see>.</summary>
    public static ClaimId PremisIdLocal { get; } = ClaimId.Create(NarrativeRequirementRangeStart + 1, "PREMIS-ID-LOCAL");

    /// <summary><c>PREMIS-ID-OTHER</c> — clause 4.1.1, MAY: other identifier types are added beside <c>local</c> by repeating <c>objectIdentifier</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 clause 4.1.1</see>.</summary>
    public static ClaimId PremisIdOther { get; } = ClaimId.Create(NarrativeRequirementRangeStart + 2, "PREMIS-ID-OTHER");

    /// <summary><c>PREMIS-CHECKSUMS</c> — clause 4.1.2, SHOULD: checksums are provided under <c>objectCharacteristics</c>, SHA-256 recommended. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 clause 4.1.2</see>.</summary>
    public static ClaimId PremisChecksums { get; } = ClaimId.Create(NarrativeRequirementRangeStart + 3, "PREMIS-CHECKSUMS");

    /// <summary><c>PREMIS-FILE-FORMAT</c> — clause 4.1.3, SHOULD: <c>format</c> uses <c>formatRegistry</c> and/or <c>formatDesignation</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 clause 4.1.3</see>.</summary>
    public static ClaimId PremisFileFormat { get; } = ClaimId.Create(NarrativeRequirementRangeStart + 4, "PREMIS-FILE-FORMAT");

    /// <summary><c>PREMIS-FILE-FORMAT-PUID</c> — clause 4.1.3, SHOULD: <c>formatRegistry</c> uses a persistent unique format identifier. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 clause 4.1.3</see>.</summary>
    public static ClaimId PremisFileFormatPuid { get; } = ClaimId.Create(NarrativeRequirementRangeStart + 5, "PREMIS-FILE-FORMAT-PUID");

    /// <summary><c>PREMIS-CHARACTERISATION</c> — clause 4.1.4, MAY: technical-characterisation output is embedded under <c>objectCharacteristicsExtension</c>. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 clause 4.1.4</see>.</summary>
    public static ClaimId PremisCharacterisation { get; } = ClaimId.Create(NarrativeRequirementRangeStart + 6, "PREMIS-CHARACTERISATION");

    /// <summary><c>PREMIS-ORIGINAL-NAME</c> — clause 4.1.5, MAY: <c>originalName</c> records a file's pre-rename name. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 clause 4.1.5</see>.</summary>
    public static ClaimId PremisOriginalName { get; } = ClaimId.Create(NarrativeRequirementRangeStart + 7, "PREMIS-ORIGINAL-NAME");

    /// <summary><c>PREMIS-STORAGE</c> — clause 4.1.6, MAY: <c>storage</c> holds the digital object's storage location. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 clause 4.1.6</see>.</summary>
    public static ClaimId PremisStorage { get; } = ClaimId.Create(NarrativeRequirementRangeStart + 8, "PREMIS-STORAGE");

    /// <summary><c>PREMIS-RELATIONSHIP</c> — clause 4.1.7, SHOULD: <c>relationship</c> describes the digital object's relationships. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 clause 4.1.7</see>.</summary>
    public static ClaimId PremisRelationship { get; } = ClaimId.Create(NarrativeRequirementRangeStart + 9, "PREMIS-RELATIONSHIP");

    /// <summary><c>PREMIS-IP-INCLUDED</c> — clause 4.1.7, MUST: when a package is part of another package, <c>relationshipSubType</c> references the superordinate one. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 clause 4.1.7</see>.</summary>
    public static ClaimId PremisIpIncluded { get; } = ClaimId.Create(NarrativeRequirementRangeStart + 10, "PREMIS-IP-INCLUDED");

    /// <summary><c>PREMIS-RIGHTS</c> — clauses 4.1.8 and 4.4, MAY/MUST: rights are linked from an object and described in a rights statement. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 clauses 4.1.8 and 4.4</see>.</summary>
    public static ClaimId PremisRights { get; } = ClaimId.Create(NarrativeRequirementRangeStart + 11, "PREMIS-RIGHTS");

    /// <summary><c>PREMIS-EVENT-ID</c> — clause 4.2.1, SHOULD: <c>eventIdentifier</c> identifies preservation-action events. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 clause 4.2.1</see>.</summary>
    public static ClaimId PremisEventId { get; } = ClaimId.Create(NarrativeRequirementRangeStart + 12, "PREMIS-EVENT-ID");

    /// <summary><c>PREMIS-EVENT-AGENT</c> — clauses 4.2.2 and 4.2.3, MUST/SHOULD: an event's causing agent is linked, and the creating event is recorded on the object. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 clauses 4.2.2 and 4.2.3</see>.</summary>
    public static ClaimId PremisEventAgent { get; } = ClaimId.Create(NarrativeRequirementRangeStart + 13, "PREMIS-EVENT-AGENT");

    /// <summary><c>PREMIS-AGENT</c> — clause 4.3, MUST: agents referenced in events are described by an <c>agent</c> element. <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1 clause 4.3</see>.</summary>
    public static ClaimId PremisAgent { get; } = ClaimId.Create(NarrativeRequirementRangeStart + 14, "PREMIS-AGENT");


    /// <summary>Determines whether a claim identifier names a tabulated preservation-metadata requirement, <c>PM1</c>…<c>PM125</c>.</summary>
    /// <param name="claimId">The claim identifier to test.</param>
    /// <returns><see langword="true"/> when the code falls in the tabulated-requirement band.</returns>
    public static bool IsTableRequirement(ClaimId claimId) =>
        claimId.Code >= TableRequirementRangeStart && claimId.Code <= TableRequirementRangeEnd;


    /// <summary>Determines whether a claim identifier names one of the fourteen narrative <c>PREMIS-*</c> requirements.</summary>
    /// <param name="claimId">The claim identifier to test.</param>
    /// <returns><see langword="true"/> when the code falls in the narrative-requirement band.</returns>
    public static bool IsNarrativeRequirement(ClaimId claimId) =>
        claimId.Code >= NarrativeRequirementRangeStart && claimId.Code <= NarrativeRequirementRangeEnd;


    /// <summary>Determines whether a claim identifier names a preservation-metadata requirement of either catalogue.</summary>
    /// <param name="claimId">The claim identifier to test.</param>
    /// <returns><see langword="true"/> when the code falls in either preservation-metadata band.</returns>
    public static bool IsPreservationMetadataRequirement(ClaimId claimId) =>
        IsTableRequirement(claimId) || IsNarrativeRequirement(claimId);
}
