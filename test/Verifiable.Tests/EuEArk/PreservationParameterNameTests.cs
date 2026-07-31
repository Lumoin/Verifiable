using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the wire-name registry of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> — the XML element name and the JSON member name each component's own mapping
/// table states for each of its sub-components.
/// </summary>
/// <remarks>
/// <para>
/// The expected values below are transcribed from the specification's Tables 1 to 23, not from the classes under
/// test: a test that read the registry to state its own expectation would pass whatever the registry said. Each
/// table is restated once, in the order the table lists its rows.
/// </para>
/// <para>
/// The load-bearing property is the one the document itself never states: <strong>no rule derives one spelling
/// from the other</strong>. Three element names even map to two different member names depending on which
/// component they appear in, which no derivation could reproduce, and which is why every pair is hardcoded.
/// </para>
/// </remarks>
[TestClass]
internal sealed class PreservationParameterNameTests
{
    /// <summary>The three element names the document maps to two different JSON member names, in ordinal order.</summary>
    private static string[] ElementNamesWithTwoMemberNames { get; } = ["EvidenceFormat", "VersionID", "value"];


    /// <summary>The two names the request base component's sub-components are stated under, per clause 5.3.1.1.</summary>
    [TestMethod]
    public void TheRequestBaseComponentStatesTheNamesTheOperationTablesRestate()
    {
        AssertPair(PreservationRequestParameterNames.OptionalInputs, "OptionalInputs", "optIn");
        AssertPair(PreservationRequestParameterNames.RequestId, "RequestID", "reqId");
    }


    /// <summary>
    /// The response base component's names, per clause 5.3.1.2 — and the one element of the protocol that has an
    /// XML name and no stated JSON member name at all.
    /// </summary>
    [TestMethod]
    public void TheResponseBaseComponentStatesTwoPairsAndOneNameWithoutAMember()
    {
        AssertPair(PreservationResponseParameterNames.OptionalOutputs, "OptionalOutputs", "optOut");
        AssertPair(PreservationResponseParameterNames.RequestId, "RequestID", "reqId");

        Assert.AreEqual("Result", PreservationResponseParameterNames.ResultElementName, "No table of the document maps the Result element to a JSON member name.");
    }


    /// <summary>Every operation message's names are the ones its own table lists, in the order it lists them.</summary>
    [TestMethod]
    public void EveryOperationMessageStatesTheNamesItsOwnTableLists()
    {
        AssertNames(
            "Table 1, RetrieveInfo request",
            [
                (RetrieveInfoRequestParameterNames.Profile, "Profile", "pro"),
                (RetrieveInfoRequestParameterNames.Status, "Status", "stat")
            ]);

        AssertNames(
            "Table 2, RetrieveInfoResponse",
            [(RetrieveInfoResponseParameterNames.Profile, "Profile", "pro")]);

        AssertNames(
            "Table 3, PreservePO request",
            [
                (PreservePreservationObjectRequestParameterNames.OptionalInputs, "OptionalInputs", "optIn"),
                (PreservePreservationObjectRequestParameterNames.RequestId, "RequestID", "reqId"),
                (PreservePreservationObjectRequestParameterNames.Profile, "Profile", "pro"),
                (PreservePreservationObjectRequestParameterNames.PreservationObject, "PO", "po")
            ]);

        AssertNames(
            "Table 4, PreservePOResponse",
            [
                (PreservePreservationObjectResponseParameterNames.OptionalOutputs, "OptionalOutputs", "optOut"),
                (PreservePreservationObjectResponseParameterNames.RequestId, "RequestID", "reqId"),
                (PreservePreservationObjectResponseParameterNames.PreservationObjectId, "POID", "poId"),
                (PreservePreservationObjectResponseParameterNames.PreservationObject, "PO", "po")
            ]);

        AssertNames(
            "Table 5, RetrievePO request",
            [
                (RetrievePreservationObjectRequestParameterNames.OptionalInputs, "OptionalInputs", "optIn"),
                (RetrievePreservationObjectRequestParameterNames.RequestId, "RequestID", "reqId"),
                (RetrievePreservationObjectRequestParameterNames.PreservationObjectId, "POID", "poId"),
                (RetrievePreservationObjectRequestParameterNames.VersionId, "VersionID", "versionId"),
                (RetrievePreservationObjectRequestParameterNames.SubjectOfRetrieval, "SubjectOfRetrieval", "sor"),
                (RetrievePreservationObjectRequestParameterNames.PreservationObjectFormat, "POFormat", "poFormat"),
                (RetrievePreservationObjectRequestParameterNames.EvidenceFormat, "EvidenceFormat", "evFormat")
            ]);

        AssertNames(
            "Table 6, RetrievePOResponse",
            [
                (RetrievePreservationObjectResponseParameterNames.OptionalOutputs, "OptionalOutputs", "optOut"),
                (RetrievePreservationObjectResponseParameterNames.RequestId, "RequestID", "reqId"),
                (RetrievePreservationObjectResponseParameterNames.PreservationObject, "PO", "po")
            ]);

        AssertNames(
            "Table 7, DeletePO request",
            [
                (DeletePreservationObjectRequestParameterNames.OptionalInputs, "OptionalInputs", "optIn"),
                (DeletePreservationObjectRequestParameterNames.RequestId, "RequestID", "reqId"),
                (DeletePreservationObjectRequestParameterNames.PreservationObjectId, "POID", "poId"),
                (DeletePreservationObjectRequestParameterNames.Mode, "Mode", "mod"),
                (DeletePreservationObjectRequestParameterNames.ClaimedRequestorName, "ClaimedRequestorName", "crn"),
                (DeletePreservationObjectRequestParameterNames.Reason, "Reason", "reason")
            ]);

        AssertNames(
            "Table 8, UpdatePOC request",
            [
                (UpdatePreservationObjectContainerRequestParameterNames.OptionalInputs, "OptionalInputs", "optIn"),
                (UpdatePreservationObjectContainerRequestParameterNames.RequestId, "RequestID", "reqId"),
                (UpdatePreservationObjectContainerRequestParameterNames.PreservationObjectId, "POID", "poId"),
                (UpdatePreservationObjectContainerRequestParameterNames.DeltaContainer, "DeltaPOC", "deltaPoc")
            ]);

        AssertNames(
            "Table 9, UpdatePOCResponse",
            [
                (UpdatePreservationObjectContainerResponseParameterNames.OptionalOutputs, "OptionalOutputs", "optOut"),
                (UpdatePreservationObjectContainerResponseParameterNames.RequestId, "RequestID", "reqId"),
                (UpdatePreservationObjectContainerResponseParameterNames.VersionId, "VersionID", "versionId")
            ]);

        AssertNames(
            "Table 10, RetrieveTrace request",
            [
                (RetrieveTraceRequestParameterNames.OptionalInputs, "OptionalInputs", "optIn"),
                (RetrieveTraceRequestParameterNames.RequestId, "RequestID", "reqId"),
                (RetrieveTraceRequestParameterNames.PreservationObjectId, "POID", "poId")
            ]);

        AssertNames(
            "Table 11, RetrieveTraceResponse",
            [
                (RetrieveTraceResponseParameterNames.OptionalOutputs, "OptionalOutputs", "optOut"),
                (RetrieveTraceResponseParameterNames.RequestId, "RequestID", "reqId"),
                (RetrieveTraceResponseParameterNames.Trace, "Trace", "trace")
            ]);

        AssertNames(
            "Table 12, ValidateEvidence request",
            [
                (ValidateEvidenceRequestParameterNames.OptionalInputs, "OptionalInputs", "optIn"),
                (ValidateEvidenceRequestParameterNames.RequestId, "RequestID", "reqId"),
                (ValidateEvidenceRequestParameterNames.Evidence, "Evidence", "ev"),
                (ValidateEvidenceRequestParameterNames.PreservationObject, "PO", "po")
            ]);

        AssertNames(
            "Table 13, ValidateEvidenceResponse",
            [
                (ValidateEvidenceResponseParameterNames.OptionalOutputs, "OptionalOutputs", "optOut"),
                (ValidateEvidenceResponseParameterNames.RequestId, "RequestID", "reqId"),
                (ValidateEvidenceResponseParameterNames.ValidationReport, "ValidationReport", "valRep"),
                (ValidateEvidenceResponseParameterNames.ProofOfExistence, "ProofOfExistence", "poe")
            ]);

        AssertNames(
            "Table 14, Search request",
            [(SearchRequestParameterNames.Filter, "Filter", "fi")]);

        AssertNames(
            "Table 15, SearchResponse",
            [(SearchResponseParameterNames.PreservationObjectId, "POID", "poId")]);
    }


    /// <summary>Every shared component's names are the ones its own table lists, in the order it lists them.</summary>
    [TestMethod]
    public void EverySharedComponentStatesTheNamesItsOwnTableLists()
    {
        AssertNames(
            "Table 17, DeletionMode",
            [(PreservationDeletionModeParameterNames.Value, "value", "Value")]);

        AssertNames(
            "Table 18, Event",
            [
                (PreservationEventParameterNames.Time, "Time", "time"),
                (PreservationEventParameterNames.Subject, "Subject", "sub"),
                (PreservationEventParameterNames.Operation, "Operation", "op"),
                (PreservationEventParameterNames.Object, "Object", "obj"),
                (PreservationEventParameterNames.Detail, "Detail", "det")
            ]);

        AssertNames(
            "Table 19, Evidence",
            [
                (PreservationEvidenceParameterNames.BinaryData, "binaryData", "binaryData"),
                (PreservationEvidenceParameterNames.FormatId, "FormatId", "formatId"),
                (PreservationEvidenceParameterNames.MimeType, "MimeType", "mimeType"),
                (PreservationEvidenceParameterNames.PronomId, "PronomId", "pronomId"),
                (PreservationEvidenceParameterNames.Id, "ID", "id"),
                (PreservationEvidenceParameterNames.RelatedObjects, "RelatedObjects", "relObj"),
                (PreservationEvidenceParameterNames.PreservationObjectId, "POID", "poId"),
                (PreservationEvidenceParameterNames.VersionId, "VersionID", "verId")
            ]);

        AssertNames(
            "Table 20, PO",
            [
                (PreservationObjectParameterNames.BinaryData, "binaryData", "binaryData"),
                (PreservationObjectParameterNames.FormatId, "FormatId", "formatId"),
                (PreservationObjectParameterNames.MimeType, "MimeType", "mimeType"),
                (PreservationObjectParameterNames.PronomId, "PronomId", "pronomId"),
                (PreservationObjectParameterNames.Id, "ID", "id"),
                (PreservationObjectParameterNames.RelatedObjects, "RelatedObjects", "relObj")
            ]);

        AssertNames(
            "Table 21, Profile",
            [
                (PreservationProfileParameterNames.ProfileIdentifier, "ProfileIdentifier", "pid"),
                (PreservationProfileParameterNames.Operation, "Operation", "op"),
                (PreservationProfileParameterNames.Policy, "Policy", "pol"),
                (PreservationProfileParameterNames.ProfileValidityPeriod, "ProfileValidityPeriod", "pvp"),
                (PreservationProfileParameterNames.PreservationStorageModel, "PreservationStorageModel", "psm"),
                (PreservationProfileParameterNames.PreservationGoal, "PreservationGoal", "pg"),
                (PreservationProfileParameterNames.EvidenceFormat, "EvidenceFormat", "ef"),
                (PreservationProfileParameterNames.Specification, "Specification", "spec"),
                (PreservationProfileParameterNames.Description, "Description", "desc"),
                (PreservationProfileParameterNames.SchemeIdentifier, "SchemeIdentifier", "sid"),
                (PreservationProfileParameterNames.ExpectedEvidenceDuration, "ExpectedEvidenceDuration", "eed"),
                (PreservationProfileParameterNames.PreservationEvidenceRetentionPeriod, "PreservationEvidenceRetentionPeriod", "perp"),
                (PreservationProfileParameterNames.Extension, "Extension", "ext")
            ]);

        AssertNames(
            "Table 22, SubjectOfRetrieval",
            [(PreservationSubjectOfRetrievalParameterNames.Value, "value", "value")]);

        AssertNames(
            "Table 23, Trace",
            [(PreservationTraceParameterNames.Event, "Event", "event")]);

        AssertNames(
            "Table 24, DigestList",
            [
                (PreservationDigestListParameterNames.DigestMethod, "DigestMethod", "digAlg"),
                (PreservationDigestListParameterNames.DigestValue, "DigestValue", "digVal"),
                (PreservationDigestListParameterNames.Evidence, "Evidence", "ev")
            ]);
    }


    /// <summary>
    /// The registry as a whole: every declaration site carries both spellings, the sites are as many as the
    /// tables have rows, and the distinct pairs are fewer because several components restate the same row.
    /// </summary>
    [TestMethod]
    public void TheRegistryDeclaresOnePairPerTableRowAndNoBlankSpellings()
    {
        IReadOnlyList<(string ClassName, string PropertyName, PreservationName Name)> declarations = EveryDeclaredName();

        Assert.HasCount(92, declarations, "One declaration per row of Tables 1 to 24, base components included.");

        foreach((string className, string propertyName, PreservationName name) in declarations)
        {
            Assert.IsFalse(
                string.IsNullOrWhiteSpace(name.XmlElementName),
                $"{className}.{propertyName} states no XML element name.");
            Assert.IsFalse(
                string.IsNullOrWhiteSpace(name.JsonMemberName),
                $"{className}.{propertyName} states no JSON member name.");
        }

        int distinctPairs = declarations
            .Select(declaration => (declaration.Name.XmlElementName, declaration.Name.JsonMemberName))
            .Distinct()
            .Count();
        Assert.AreEqual(49, distinctPairs, "The rows of the tables reduce to this many distinct pairs; Table 24 adds the digest method and the digest value and restates the evidence.");

        int distinctElementNames = declarations
            .Select(declaration => declaration.Name.XmlElementName)
            .Distinct(StringComparer.Ordinal)
            .Count();
        Assert.AreEqual(46, distinctElementNames, "Three element names carry two member names each, so there are three fewer element names than pairs.");
    }


    /// <summary>
    /// The three element names that map to two different JSON member names — the sharpest evidence in the
    /// document that no derivation rule exists.
    /// </summary>
    [TestMethod]
    public void ThreeElementNamesMapToTwoDifferentMemberNamesEach()
    {
        Dictionary<string, HashSet<string>> membersByElement = new(StringComparer.Ordinal);
        foreach((_, _, PreservationName name) in EveryDeclaredName())
        {
            if(!membersByElement.TryGetValue(name.XmlElementName, out HashSet<string>? members))
            {
                members = new HashSet<string>(StringComparer.Ordinal);
                membersByElement.Add(name.XmlElementName, members);
            }

            _ = members.Add(name.JsonMemberName);
        }

        List<string> ambiguous = membersByElement
            .Where(entry => entry.Value.Count > 1)
            .Select(entry => entry.Key)
            .OrderBy(element => element, StringComparer.Ordinal)
            .ToList();

        Assert.AreSequenceEqual(ElementNamesWithTwoMemberNames, ambiguous);

        Assert.AreEqual("versionId", RetrievePreservationObjectRequestParameterNames.VersionId.JsonMemberName);
        Assert.AreEqual("verId", PreservationEvidenceParameterNames.VersionId.JsonMemberName);
        Assert.AreEqual("evFormat", RetrievePreservationObjectRequestParameterNames.EvidenceFormat.JsonMemberName);
        Assert.AreEqual("ef", PreservationProfileParameterNames.EvidenceFormat.JsonMemberName);
        Assert.AreEqual("Value", PreservationDeletionModeParameterNames.Value.JsonMemberName);
        Assert.AreEqual("value", PreservationSubjectOfRetrievalParameterNames.Value.JsonMemberName);
    }


    /// <summary>
    /// No mechanical transformation of an element name reproduces the member names: each candidate derivation is
    /// shown to disagree with the registry, which is why every pair is transcribed rather than computed. The
    /// comparison ignores case, so the finding is about the spellings themselves rather than about capitalisation.
    /// </summary>
    /// <param name="derivation">Which candidate derivation is applied to every element name.</param>
    [TestMethod]
    [DataRow("the whole element name", DisplayName = "the element name itself, ignoring case")]
    [DataRow("the initials", DisplayName = "the initials of the element name's words")]
    [DataRow("the first three characters", DisplayName = "the first three characters of the element name")]
    public void NoMechanicalDerivationReproducesTheMemberNames(string derivation)
    {
        int disagreements = 0;
        foreach((_, _, PreservationName name) in EveryDeclaredName())
        {
            string derived = derivation switch
            {
                "the whole element name" => name.XmlElementName,
                "the initials" => new string([.. name.XmlElementName.Where(char.IsUpper)]),
                _ => name.XmlElementName[..Math.Min(3, name.XmlElementName.Length)]
            };

            if(!string.Equals(derived, name.JsonMemberName, StringComparison.OrdinalIgnoreCase))
            {
                ++disagreements;
            }
        }

        Assert.IsGreaterThan(0, disagreements, $"A derivation by {derivation} would have to reproduce every member name to be a rule.");
    }


    /// <summary>Each pair recognises its own two spellings and refuses everything else, ordinally.</summary>
    [TestMethod]
    public void EachPairRecognisesItsOwnSpellingsAndNothingElse()
    {
        PreservationName claimedRequestorName = DeletePreservationObjectRequestParameterNames.ClaimedRequestorName;

        Assert.IsTrue(claimedRequestorName.IsXmlElementName("ClaimedRequestorName"));
        Assert.IsFalse(claimedRequestorName.IsXmlElementName("claimedrequestorname"), "An element name matches by exact character sequence.");
        Assert.IsFalse(claimedRequestorName.IsXmlElementName("ClaimedRequestorName "));
        Assert.IsFalse(claimedRequestorName.IsXmlElementName(null));
        Assert.IsFalse(claimedRequestorName.IsXmlElementName("crn"), "The member name is not the element name.");

        Assert.IsTrue(claimedRequestorName.IsJsonMemberName("crn"));
        Assert.IsFalse(claimedRequestorName.IsJsonMemberName("CRN"));
        Assert.IsFalse(claimedRequestorName.IsJsonMemberName(null));
        Assert.IsFalse(claimedRequestorName.IsJsonMemberName("ClaimedRequestorName"));

        PreservationName deletionMode = PreservationDeletionModeParameterNames.Value;
        Assert.IsTrue(deletionMode.IsXmlElementName("value"));
        Assert.IsTrue(deletionMode.IsJsonMemberName("Value"));
        Assert.IsFalse(deletionMode.IsJsonMemberName("value"), "The deletion mode's member name carries a capital, unlike the subject of retrieval's.");
    }


    /// <summary>A pair with a half missing is not a name, and the constructor refuses to build one.</summary>
    [TestMethod]
    public void APairCannotBeBuiltWithAHalfMissing()
    {
        _ = Assert.Throws<ArgumentException>(() => new PreservationName(null!, "po"));
        _ = Assert.Throws<ArgumentException>(() => new PreservationName("PO", null!));
        _ = Assert.Throws<ArgumentException>(() => new PreservationName(string.Empty, "po"));
        _ = Assert.Throws<ArgumentException>(() => new PreservationName("PO", string.Empty));

        PreservationName unstated = default;
        Assert.IsFalse(unstated.IsXmlElementName("PO"), "A default-initialised name recognises nothing.");
        Assert.IsFalse(unstated.IsJsonMemberName("po"));
    }


    /// <summary>
    /// The value choice's second alternative has an XML name and no JSON member name of its own, because the
    /// reproduced JSON schema of the payload component omits the alternative altogether.
    /// </summary>
    [TestMethod]
    public void TheValueChoicesSecondAlternativeHasNoMemberName()
    {
        Assert.AreEqual("xmlData", PreservationObjectParameterNames.XmlDataElementName);
        Assert.AreEqual("binaryData", PreservationObjectParameterNames.BinaryData.XmlElementName);
        Assert.AreEqual("binaryData", PreservationObjectParameterNames.BinaryData.JsonMemberName);

        List<string> elementNames = [.. EveryDeclaredName().Select(declaration => declaration.Name.XmlElementName)];
        Assert.DoesNotContain(
            "xmlData",
            elementNames,
            "Nothing may state a member name for an alternative the JSON binding does not carry.");
    }


    /// <summary>
    /// The operation classes restate the two inherited base names exactly where their own tables do — six of the
    /// fifteen tables list them and four do not, which is a property of the document and not of this registry.
    /// </summary>
    [TestMethod]
    public void TheBaseNamesAreRestatedExactlyWhereTheTablesRestateThem()
    {
        string[] restating =
        [
            nameof(PreservePreservationObjectRequestParameterNames),
            nameof(PreservePreservationObjectResponseParameterNames),
            nameof(RetrievePreservationObjectRequestParameterNames),
            nameof(RetrievePreservationObjectResponseParameterNames),
            nameof(DeletePreservationObjectRequestParameterNames),
            nameof(UpdatePreservationObjectContainerRequestParameterNames),
            nameof(UpdatePreservationObjectContainerResponseParameterNames),
            nameof(RetrieveTraceRequestParameterNames),
            nameof(RetrieveTraceResponseParameterNames),
            nameof(ValidateEvidenceRequestParameterNames),
            nameof(ValidateEvidenceResponseParameterNames)
        ];

        string[] notRestating =
        [
            nameof(RetrieveInfoRequestParameterNames),
            nameof(RetrieveInfoResponseParameterNames),
            nameof(SearchRequestParameterNames),
            nameof(SearchResponseParameterNames)
        ];

        foreach(string className in restating)
        {
            Assert.Contains("RequestID", ElementNamesOf(className), $"{className}'s table restates the inherited request identifier.");
        }

        foreach(string className in notRestating)
        {
            Assert.DoesNotContain("RequestID", ElementNamesOf(className), $"{className}'s table lists only the message's own elements.");
        }

        //The element names one class declares, which is what a table's rows amount to.
        static List<string> ElementNamesOf(string className) =>
        [
            .. EveryDeclaredName()
                .Where(declaration => string.Equals(declaration.ClassName, className, StringComparison.Ordinal))
                .Select(declaration => declaration.Name.XmlElementName)
        ];
    }


    /// <summary>Asserts one pair against the two spellings its table states.</summary>
    /// <param name="name">The pair the registry declares.</param>
    /// <param name="expectedElementName">The element name the table states.</param>
    /// <param name="expectedMemberName">The member name the table states.</param>
    private static void AssertPair(PreservationName name, string expectedElementName, string expectedMemberName)
    {
        Assert.AreEqual(expectedElementName, name.XmlElementName);
        Assert.AreEqual(expectedMemberName, name.JsonMemberName);
    }


    /// <summary>Asserts one table's rows against the pairs the matching class declares, row by row.</summary>
    /// <param name="table">Which table is being checked, for the failure message.</param>
    /// <param name="rows">The declared pair and the two spellings the table states, in the table's own order.</param>
    private static void AssertNames(string table, IReadOnlyList<(PreservationName Declared, string ElementName, string MemberName)> rows)
    {
        for(int i = 0; i < rows.Count; ++i)
        {
            (PreservationName declared, string elementName, string memberName) = rows[i];
            Assert.AreEqual(elementName, declared.XmlElementName, $"{table}, row {i + 1}.");
            Assert.AreEqual(memberName, declared.JsonMemberName, $"{table}, row {i + 1}.");
        }
    }


    /// <summary>
    /// Every name pair the registry declares, found by reflection over the classes rather than by a list this
    /// test keeps, so a class added without a test row still shows up in the counts.
    /// </summary>
    /// <returns>The declaring class, the property and the pair.</returns>
    private static List<(string ClassName, string PropertyName, PreservationName Name)> EveryDeclaredName()
    {
        List<(string ClassName, string PropertyName, PreservationName Name)> declarations = [];
        foreach(Type type in typeof(PreservationName).Assembly.GetTypes())
        {
            bool isParameterNameClass = type.IsAbstract
                && type.IsSealed
                && type.IsPublic
                && type.Name.EndsWith("ParameterNames", StringComparison.Ordinal);
            if(!isParameterNameClass)
            {
                continue;
            }

            foreach(PropertyInfo property in type.GetProperties(BindingFlags.Public | BindingFlags.Static))
            {
                if(property.PropertyType == typeof(PreservationName))
                {
                    declarations.Add((type.Name, property.Name, (PreservationName)property.GetValue(null)!));
                }
            }
        }

        return declarations;
    }
}
