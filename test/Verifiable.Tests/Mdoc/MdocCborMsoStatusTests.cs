using System.Buffers;
using Lumoin.Veritas.Cbor;
using Verifiable.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Cbor.StatusList;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Core.StatusList;
using Verifiable.JCose;
using static Verifiable.Tests.TestInfrastructure.MdocTestFixtures;

namespace Verifiable.Tests.Mdoc;

/// <summary>
/// Tests for the Mobile Security Object's optional <c>status</c> member as
/// <see cref="MdocCborMsoReader"/> reads it and <see cref="MdocCborMsoWriter"/>
/// writes it. Per
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
/// Token Status List, Section 6.3</see>: "The Referenced Token MAY be encoded as a
/// 'CBOR Web Token (CWT)' object according to [RFC8392], as an SD-CWTs
/// [I-D.ietf-spice-sd-cwt] or as an ISO mdoc according to [ISO.mdoc] or other formats
/// based on COSE. Referenced Tokens in CBOR SHOULD share the same core data structure
/// for a status list reference".
/// </summary>
/// <remarks>
/// <para>
/// Every read fixture here is composed by hand with <see cref="CborWriter"/> straight
/// from the Section 6.3 structure, and every write assertion walks the produced bytes
/// with a raw <see cref="CborReader"/>; neither side is derived from the other's
/// production code. The six required members come from the shared hand-built writers in
/// <c>MdocTestFixtures</c>, the same ones <see cref="MdocCborMsoReaderTests"/> uses.
/// </para>
/// <para>
/// Placement of the member inside the Mobile Security Object comes from the second
/// edition of ISO/IEC 18013-5, under ballot as a DIS (ISO/IEC DIS 18013-5; expected
/// publication 2026-11-30). The published ISO/IEC 18013-5:2021 carries no <c>status</c>
/// member; the draft EU implementing act amending the EAA implementing regulations
/// witnesses the placement: "its MobileSecurityObject (MSO) shall contain the status
/// structure, as specified in EAA-6.2.10.1-17, which contains MSO revocation
/// information."
/// </para>
/// <para>
/// The forward-compatibility pin for an unknown top-level member that is not
/// <c>status</c> lives in
/// <see cref="MdocCborMsoReaderTests.ReadMsoSkipsUnknownTopLevelFieldPerForwardCompat"/>
/// and is not duplicated here.
/// </para>
/// </remarks>
[TestClass]
internal sealed class MdocCborMsoStatusTests
{
    /// <summary>The mDL document type the fixtures issue into, matching the sibling reader tests.</summary>
    private const string MdlDocType = "org.iso.18013.5.1.mDL";

    /// <summary>The single namespace the shared <c>valueDigests</c> writer fills.</summary>
    private const string MdlNamespace = "org.iso.18013.5.1";

    /// <summary>
    /// The MSO map key carrying the Status CBOR structure, spelled as the draft EU
    /// implementing act's "the status element" witnesses it. Held as a literal here so
    /// the fixtures pin the wire spelling independently of the model's own constant.
    /// </summary>
    private const string StatusKey = "status";

    /// <summary>
    /// The Section 6.3 mechanism key "status_list", held as a literal so the fixtures
    /// pin the wire spelling independently of the model's own constant.
    /// </summary>
    private const string StatusListMechanismKey = "status_list";

    /// <summary>
    /// The mechanism key "identifier_list" the second edition of ISO/IEC 18013-5 names
    /// for the attestation revocation list, held as a literal for the same reason.
    /// </summary>
    private const string IdentifierListMechanismKey = "identifier_list";

    /// <summary>A mechanism name no specification defines, used to prove an unrecognised key is recorded and skipped.</summary>
    private const string UnmodelledMechanismKey = "acme_mechanism";

    /// <summary>The Section 6.3 StatusListInfo index field key.</summary>
    private const string IndexKey = "idx";

    /// <summary>The Section 6.3 StatusListInfo URI field key.</summary>
    private const string UriKey = "uri";

    /// <summary>
    /// The decimal spelling of the CWT Claims Set claim key 65535, used to prove that key
    /// belongs to the CWT and not to the MSO's named-key map.
    /// </summary>
    private const string CwtStatusClaimKeySpelling = "65535";

    /// <summary>The index the fixtures reference in the Status List.</summary>
    private const int SampleStatusIndex = 42;

    /// <summary>The Status List Token URI the fixtures reference, taken from the Section 6 examples.</summary>
    private const string SampleStatusUri = "https://example.com/statuslists/1";


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "status_list (status list): REQUIRED when the
    /// status mechanism defined in this specification is used. It has the same definition as
    /// the status_list claim in Section 6.2 but MUST be encoded as a StatusListInfo CBOR
    /// structure with the following fields: idx: REQUIRED. Unsigned integer (major type 0).
    /// ... uri: REQUIRED. Text string (major type 3)." An MSO carrying that structure decodes
    /// into the index and URI it was written with, and records the mechanism by name.
    /// </summary>
    [TestMethod]
    public void ReadMsoDecodesStatusListMechanismIndexAndUri()
    {
        byte[] msoBytes = BuildMsoWithStatusValue(static writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString(StatusListMechanismKey);
            WriteStatusListInfo(writer, SampleStatusIndex, SampleStatusUri);
            writer.WriteEndMap();
        });

        MdocMobileSecurityObject mso = MdocCborMsoReader.Read(msoBytes);

        Assert.IsNotNull(mso.Status, "Section 6.3's Status structure must decode onto the MSO's status member.");
        Assert.IsNotNull(mso.Status.StatusList, "The status_list mechanism carries a StatusListInfo that must decode.");
        Assert.AreEqual(SampleStatusIndex, mso.Status.StatusList.Value.Index, "Section 6.3 requires idx to be carried through unchanged.");
        Assert.AreEqual(SampleStatusUri, mso.Status.StatusList.Value.Uri, "Section 6.3 requires uri to be carried through unchanged.");
        Assert.Contains(StatusMechanismNames.StatusList, mso.Status.Mechanisms, "The status_list mechanism must be recorded by name.");
        Assert.HasCount(1, mso.Status.Mechanisms, "Only the status_list mechanism was on the wire.");
    }


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "idx: REQUIRED. Unsigned integer (major type 0).
    /// ... uri: REQUIRED. Text string (major type 3)." An MSO holding a Status structure emits
    /// a seven-entry map whose <c>status</c> value carries that same StatusListInfo, read back
    /// here with a raw <see cref="CborReader"/> so the assertion never leans on the reader
    /// under test.
    /// </summary>
    [TestMethod]
    public void WriteMsoEmitsStatusListMechanismIndexAndUri()
    {
        MdocMobileSecurityObject mso = BuildMsoModel(
            new StatusClaim(
                statusList: new StatusListReference(SampleStatusIndex, SampleStatusUri),
                mechanisms: new HashSet<string>(StringComparer.Ordinal) { StatusMechanismNames.StatusList }));

        ReadOnlyMemory<byte> encoded = MdocCborMsoWriter.Write(mso);

        (int declaredEntryCount, IReadOnlyList<string> keys) = ReadTopLevelMap(encoded);
        Assert.AreEqual(7, declaredEntryCount, "The six required members plus status make seven entries.");
        Assert.Contains(StatusKey, keys, "The Status structure is carried under the text-string key 'status'.");

        (int index, string uri) = ReadStatusListInfoWithRawReader(encoded);
        Assert.AreEqual(SampleStatusIndex, index, "Section 6.3's idx must be written as supplied.");
        Assert.AreEqual(SampleStatusUri, uri, "Section 6.3's uri must be written as supplied.");
    }


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "Referenced Tokens in CBOR SHOULD share the same
    /// core data structure for a status list reference". The structure is optional on an mdoc,
    /// so an MSO map without it decodes with no Status structure at all rather than an empty one.
    /// </summary>
    [TestMethod]
    public void ReadMsoWithoutStatusMemberLeavesStatusAbsent()
    {
        byte[] msoBytes = MdocCborMsoReaderTestFixtures.BuildSampleMso();

        MdocMobileSecurityObject mso = MdocCborMsoReader.Read(msoBytes);

        Assert.IsNull(mso.Status, "An MSO map with no 'status' key must decode with no Status structure.");
        Assert.AreEqual(MdlDocType, mso.DocType, "The rest of the MSO must decode unchanged.");
    }


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "Referenced Tokens in CBOR SHOULD share the same
    /// core data structure for a status list reference". The structure is optional, so an MSO
    /// without one writes the six required members of ISO/IEC 18013-5 and no <c>status</c> key,
    /// asserted here by walking the produced bytes with a raw <see cref="CborReader"/>.
    /// </summary>
    [TestMethod]
    public void WriteMsoWithoutStatusEmitsSixEntryMapAndNoStatusKey()
    {
        MdocMobileSecurityObject mso = BuildMsoModel(status: null);

        ReadOnlyMemory<byte> encoded = MdocCborMsoWriter.Write(mso);

        (int declaredEntryCount, IReadOnlyList<string> keys) = ReadTopLevelMap(encoded);
        Assert.AreEqual(6, declaredEntryCount, "Without a Status structure the MSO map holds only the six required members.");
        Assert.DoesNotContain(StatusKey, keys, "No 'status' key may be emitted when the MSO carries no Status structure.");
    }


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "The Status CBOR structure is a Map that MUST
    /// include at least one data item that refers to a status mechanism." A <c>status</c> map
    /// with no entries therefore cannot be decoded.
    /// </summary>
    [TestMethod]
    public void ReadMsoRefusesStatusMapWithNoMechanismEntry()
    {
        byte[] msoBytes = BuildMsoWithStatusValue(static writer =>
        {
            writer.WriteStartMap(0);
            writer.WriteEndMap();
        });

        CborContentException exception = Assert.ThrowsExactly<CborContentException>(() => MdocCborMsoReader.Read(msoBytes));
        Assert.Contains("at least one", exception.Message, "The refusal must name Section 6.3's at-least-one-mechanism requirement.");
    }


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "Each data item in the Status CBOR structure
    /// comprises a key-value pair, where the key MUST be a CBOR text string (major type 3)
    /// specifying the identifier of the status mechanism and the corresponding value defines
    /// its contents." A mechanism this library does not model is therefore still a mechanism:
    /// its key is recorded and its value skipped, and the rest of the MSO decodes intact.
    /// </summary>
    [TestMethod]
    public void ReadMsoRecordsUnmodelledMechanismByNameAndSkipsItsValue()
    {
        byte[] msoBytes = BuildMsoWithStatusValue(static writer =>
        {
            writer.WriteStartMap(2);
            writer.WriteTextString(StatusListMechanismKey);
            WriteStatusListInfo(writer, SampleStatusIndex, SampleStatusUri);
            writer.WriteTextString(UnmodelledMechanismKey);
            writer.WriteStartMap(1);
            writer.WriteTextString("anything");
            writer.WriteInt32(7);
            writer.WriteEndMap();
            writer.WriteEndMap();
        });

        MdocMobileSecurityObject mso = MdocCborMsoReader.Read(msoBytes);

        Assert.IsNotNull(mso.Status, "A Status structure carrying an unmodelled mechanism still decodes.");
        Assert.HasCount(2, mso.Status.Mechanisms, "Both mechanism keys must be recorded by name.");
        Assert.Contains(UnmodelledMechanismKey, mso.Status.Mechanisms, "The unmodelled mechanism must be recorded by name.");
        Assert.IsNotNull(mso.Status.StatusList, "The modelled status_list mechanism must still decode.");
        Assert.AreEqual(SampleStatusIndex, mso.Status.StatusList.Value.Index, "The unmodelled mechanism's value must be skipped without disturbing idx.");
        Assert.AreEqual(MdlDocType, mso.DocType, "The rest of the MSO must decode intact after the skipped value.");
    }


    /// <summary>
    /// The draft EU implementing act amending the EAA implementing regulations states: "When
    /// implementing the identifier list mechanism, the status element shall contain the
    /// identifier_list element as set out in EAA-6.2.10.1-11." The element's own shape belongs
    /// to the second edition of ISO/IEC 18013-5 (under ballot as a DIS) and is not modelled, so
    /// per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>'s key-value shape the mechanism is recorded by name
    /// and its value skipped.
    /// </summary>
    [TestMethod]
    public void ReadMsoRecordsIdentifierListMechanismByNameAndSkipsItsValue()
    {
        byte[] msoBytes = BuildMsoWithStatusValue(static writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString(IdentifierListMechanismKey);
            writer.WriteStartMap(2);
            writer.WriteTextString("id");
            writer.WriteTextString("d7d1c0f0");
            writer.WriteTextString(UriKey);
            writer.WriteTextString(SampleStatusUri);
            writer.WriteEndMap();
            writer.WriteEndMap();
        });

        MdocMobileSecurityObject mso = MdocCborMsoReader.Read(msoBytes);

        Assert.IsNotNull(mso.Status, "An identifier list mechanism alone still forms a Status structure.");
        Assert.HasCount(1, mso.Status.Mechanisms, "Exactly the one mechanism key was on the wire.");
        Assert.Contains(StatusMechanismNames.IdentifierList, mso.Status.Mechanisms, "The identifier_list mechanism must be recorded by name.");
        Assert.IsNull(mso.Status.StatusList, "No status_list mechanism was present, so no StatusListInfo decodes.");
        Assert.AreEqual(MdlDocType, mso.DocType, "The rest of the MSO must decode intact after the skipped value.");
    }


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "idx: REQUIRED. Unsigned integer (major type 0).
    /// The idx (index) claim MUST specify a non-negative Integer that represents the index to
    /// check for status information in the Status List for the current Referenced Token." An
    /// <c>idx</c> encoded under any other major type is therefore not a StatusListInfo.
    /// </summary>
    /// <param name="indexEncoding">Names the offending encoding the fixture writes for <c>idx</c>.</param>
    /// <param name="expectedReaderState">The CBOR reader state name the refusal must name.</param>
    [TestMethod]
    [DataRow("text-string", "TextString")]
    [DataRow("negative-integer", "NegativeInteger")]
    public void ReadMsoRefusesStatusListIndexNotEncodedAsUnsignedInteger(string indexEncoding, string expectedReaderState)
    {
        Action<CborWriter> writeIndexValue = indexEncoding switch
        {
            "text-string" => static writer => writer.WriteTextString("42"),
            "negative-integer" => static writer => writer.WriteInt32(-1),
            _ => throw new ArgumentOutOfRangeException(nameof(indexEncoding))
        };

        byte[] msoBytes = BuildMsoWithStatusValue(writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString(StatusListMechanismKey);
            writer.WriteStartMap(2);
            writer.WriteTextString(IndexKey);
            writeIndexValue(writer);
            writer.WriteTextString(UriKey);
            writer.WriteTextString(SampleStatusUri);
            writer.WriteEndMap();
            writer.WriteEndMap();
        });

        CborContentException exception = Assert.ThrowsExactly<CborContentException>(() => MdocCborMsoReader.Read(msoBytes));
        Assert.Contains(IndexKey, exception.Message, "The refusal must name the offending StatusListInfo field.");
        Assert.Contains(expectedReaderState, exception.Message, "The refusal must name the major type actually encountered.");
    }


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "uri: REQUIRED. Text string (major type 3). The uri
    /// (URI) claim MUST specify a String value that identifies the Status List Token containing
    /// the status information for the Referenced Token." A <c>uri</c> encoded as an integer is
    /// therefore not a StatusListInfo.
    /// </summary>
    [TestMethod]
    public void ReadMsoRefusesStatusListUriNotEncodedAsTextString()
    {
        byte[] msoBytes = BuildMsoWithStatusValue(static writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString(StatusListMechanismKey);
            writer.WriteStartMap(2);
            writer.WriteTextString(IndexKey);
            writer.WriteInt32(SampleStatusIndex);
            writer.WriteTextString(UriKey);
            writer.WriteInt32(1);
            writer.WriteEndMap();
            writer.WriteEndMap();
        });

        CborContentException exception = Assert.ThrowsExactly<CborContentException>(() => MdocCborMsoReader.Read(msoBytes));
        Assert.Contains(UriKey, exception.Message, "The refusal must name the offending StatusListInfo field.");
        Assert.Contains("TextString", exception.Message, "The refusal must name the major type Section 6.3 requires.");
    }


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "idx: REQUIRED. Unsigned integer (major type 0). The
    /// idx (index) claim MUST specify a non-negative Integer that represents the index to check
    /// for status information in the Status List for the current Referenced Token." An unsigned
    /// integer this library cannot represent as a non-negative Integer (above
    /// <see cref="int.MaxValue"/>) is therefore refused before
    /// <see cref="CborReader.ReadInt32"/> would overflow on it.
    /// </summary>
    /// <param name="wireIndex">The unsigned idx value the fixture writes.</param>
    [TestMethod]
    [DataRow((ulong)int.MaxValue + 1)]
    [DataRow(ulong.MaxValue)]
    public void ReadMsoRefusesStatusListIndexAboveInt32MaxValue(ulong wireIndex)
    {
        byte[] msoBytes = BuildMsoWithStatusValue(writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString(StatusListMechanismKey);
            writer.WriteStartMap(2);
            writer.WriteTextString(IndexKey);
            writer.WriteUInt64(wireIndex);
            writer.WriteTextString(UriKey);
            writer.WriteTextString(SampleStatusUri);
            writer.WriteEndMap();
            writer.WriteEndMap();
        });

        CborContentException exception = Assert.ThrowsExactly<CborContentException>(() => MdocCborMsoReader.Read(msoBytes));
        Assert.Contains(IndexKey, exception.Message, "The refusal must name the offending StatusListInfo field.");
        Assert.Contains("Int32.MaxValue", exception.Message, "The refusal must name the bound the reader enforces.");
    }


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "The value of uri MUST be a URI conforming to
    /// [RFC3986]." An empty or all-whitespace text string is not a URI, and is refused as the
    /// reader's own read failure rather than escaping into <see cref="StatusListReference"/>'s
    /// constructor as an API-misuse exception.
    /// </summary>
    /// <param name="wireUri">The offending <c>uri</c> text the fixture writes.</param>
    [TestMethod]
    [DataRow("")]
    [DataRow("   ")]
    public void ReadMsoRefusesStatusListUriThatIsEmptyOrWhitespace(string wireUri)
    {
        byte[] msoBytes = BuildMsoWithStatusValue(writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString(StatusListMechanismKey);
            writer.WriteStartMap(2);
            writer.WriteTextString(IndexKey);
            writer.WriteInt32(SampleStatusIndex);
            writer.WriteTextString(UriKey);
            writer.WriteTextString(wireUri);
            writer.WriteEndMap();
            writer.WriteEndMap();
        });

        CborContentException exception = Assert.ThrowsExactly<CborContentException>(() => MdocCborMsoReader.Read(msoBytes));
        Assert.Contains(UriKey, exception.Message, "The refusal must name the offending StatusListInfo field.");
        Assert.Contains("RFC 3986", exception.Message, "The refusal must name the conformance rule Section 6.3 requires.");
    }


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "The value of uri MUST be a URI conforming to
    /// [RFC3986]." A relative reference such as <c>/statuslists/1</c> carries no scheme and
    /// therefore does not conform, refused before <see cref="StatusListReferenceCborConverter"/>
    /// ever constructs a <see cref="StatusListReference"/> from it.
    /// </summary>
    [TestMethod]
    public void ReadMsoRefusesStatusListUriThatIsARelativeReference()
    {
        byte[] msoBytes = BuildMsoWithStatusValue(static writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString(StatusListMechanismKey);
            writer.WriteStartMap(2);
            writer.WriteTextString(IndexKey);
            writer.WriteInt32(SampleStatusIndex);
            writer.WriteTextString(UriKey);
            writer.WriteTextString("/statuslists/1");
            writer.WriteEndMap();
            writer.WriteEndMap();
        });

        CborContentException exception = Assert.ThrowsExactly<CborContentException>(() => MdocCborMsoReader.Read(msoBytes));
        Assert.Contains(UriKey, exception.Message, "The refusal must name the offending StatusListInfo field.");
        Assert.Contains("RFC 3986", exception.Message, "The refusal must name the conformance rule Section 6.3 requires.");
    }


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "Each data item in the Status CBOR structure
    /// comprises a key-value pair, where the key MUST be a CBOR text string (major type 3)
    /// specifying the identifier of the status mechanism and the corresponding value defines
    /// its contents." A Status map keyed by an integer is therefore refused rather than skipped.
    /// </summary>
    [TestMethod]
    public void ReadMsoRefusesStatusMapKeyNotEncodedAsTextString()
    {
        byte[] msoBytes = BuildMsoWithStatusValue(static writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteInt32(1);
            WriteStatusListInfo(writer, SampleStatusIndex, SampleStatusUri);
            writer.WriteEndMap();
        });

        _ = Assert.ThrowsExactly<CborContentException>(
            () => MdocCborMsoReader.Read(msoBytes),
            "A Status map key that is not a CBOR text string cannot identify a status mechanism.");
    }


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>, the CWT claim key applies only to a CWT: "If the
    /// Referenced Token is a CWT, the following content applies to the CWT Claims Set: 65535
    /// (status): REQUIRED. The status claim contains the Status CBOR structure as described in
    /// this section." A Mobile Security Object is a named-key map (ISO/IEC 18013-5 §9.1.2.4), and
    /// the draft EU implementing act witnesses its member as "the status element", so the Status
    /// structure binds to the text-string key <c>status</c> only; the CWT's claim key spelling
    /// is an unknown MSO member and is skipped.
    /// </summary>
    [TestMethod]
    public void ReadMsoBindsStatusStructureToTheTextStringKeyAndNotTheCwtClaimKey()
    {
        byte[] underStatusKey = BuildMsoWithStatusValue(static writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString(StatusListMechanismKey);
            WriteStatusListInfo(writer, SampleStatusIndex, SampleStatusUri);
            writer.WriteEndMap();
        });

        byte[] underCwtClaimKey = BuildMsoWithExtraMember(CwtStatusClaimKeySpelling, static writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString(StatusListMechanismKey);
            WriteStatusListInfo(writer, SampleStatusIndex, SampleStatusUri);
            writer.WriteEndMap();
        });

        MdocMobileSecurityObject fromStatusKey = MdocCborMsoReader.Read(underStatusKey);
        MdocMobileSecurityObject fromCwtClaimKey = MdocCborMsoReader.Read(underCwtClaimKey);

        Assert.IsNotNull(fromStatusKey.Status, "The MSO's Status structure is carried under the text-string key 'status'.");
        Assert.IsNull(fromCwtClaimKey.Status, "The CWT's claim key 65535 is not an MSO member name and must be skipped.");
        Assert.AreEqual(MdlDocType, fromCwtClaimKey.DocType, "The rest of the MSO must decode intact after the skipped member.");
    }


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "status_list (status list): REQUIRED when the status
    /// mechanism defined in this specification is used." The status list mechanism is the only one
    /// whose value shape is specified there, so a Status structure naming any other mechanism
    /// cannot be encoded and the attempt is refused rather than silently dropped.
    /// </summary>
    [TestMethod]
    public void WriteMsoRefusesStatusMechanismOtherThanStatusList()
    {
        MdocMobileSecurityObject mso = BuildMsoModel(
            new StatusClaim(
                statusList: null,
                mechanisms: new HashSet<string>(StringComparer.Ordinal) { StatusMechanismNames.IdentifierList }));

        NotSupportedException exception = Assert.ThrowsExactly<NotSupportedException>(() => MdocCborMsoWriter.Write(mso));
        Assert.Contains(IdentifierListMechanismKey, exception.Message, "The refusal must name the mechanism that cannot be encoded.");
    }


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "status_list (status list): REQUIRED when the status
    /// mechanism defined in this specification is used. It has the same definition as the
    /// status_list claim in Section 6.2 but MUST be encoded as a StatusListInfo CBOR structure."
    /// An issuer states the status list mechanism and nothing else; that whole statement — the
    /// mechanism set as well as the reference — must survive the encoding an issuer emits and the
    /// decoding a verifier performs, so a relying party reads back exactly what was stated. The two
    /// directions are each pinned against the wire on their own by
    /// <see cref="WriteMsoEmitsStatusListMechanismIndexAndUri"/> and
    /// <see cref="ReadMsoDecodesStatusListMechanismIndexAndUri"/>; this is the composition of the
    /// pair, the COSE twin of the JSON round trip proved by
    /// <see cref="Verifiable.Tests.StatusList.StatusListJsonConverterTests.StatusClaimRoundTrips"/>.
    /// </summary>
    [TestMethod]
    public void AStatusClaimNamingTheStatusListMechanismSurvivesWritingAndReadingUnchanged()
    {
        var stated = StatusClaim.FromStatusList(SampleStatusIndex, SampleStatusUri);
        MdocMobileSecurityObject mso = BuildMsoModel(stated);

        ReadOnlyMemory<byte> encoded = MdocCborMsoWriter.Write(mso);
        MdocMobileSecurityObject decoded = MdocCborMsoReader.Read(encoded.Span);

        Assert.AreEqual(stated, decoded.Status, "The status statement an issuer wrote is the status statement a verifier reads.");
    }


    /// <summary>
    /// ISO/IEC 18013-5 §9.1.2.4 fixes the Mobile Security Object's six required members, over which
    /// the digests are taken; the second edition adds <c>status</c> beside them. Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see> the Status structure is one more data item, so writing
    /// it must leave every required member present, asserted with a raw <see cref="CborReader"/>.
    /// </summary>
    /// <param name="requiredMemberKey">The §9.1.2.4 member key that must still be emitted.</param>
    [TestMethod]
    [DataRow(MdocMsoWellKnownKeys.Version)]
    [DataRow(MdocMsoWellKnownKeys.DigestAlgorithm)]
    [DataRow(MdocMsoWellKnownKeys.ValueDigests)]
    [DataRow(MdocMsoWellKnownKeys.DeviceKeyInfo)]
    [DataRow(MdocMsoWellKnownKeys.DocType)]
    [DataRow(MdocMsoWellKnownKeys.ValidityInfo)]
    public void WriteMsoWithStatusKeepsEveryRequiredMemberPresent(string requiredMemberKey)
    {
        MdocMobileSecurityObject mso = BuildMsoModel(
            new StatusClaim(
                statusList: new StatusListReference(SampleStatusIndex, SampleStatusUri),
                mechanisms: new HashSet<string>(StringComparer.Ordinal) { StatusMechanismNames.StatusList }));

        ReadOnlyMemory<byte> encoded = MdocCborMsoWriter.Write(mso);

        (int declaredEntryCount, IReadOnlyList<string> keys) = ReadTopLevelMap(encoded);
        Assert.AreEqual(7, declaredEntryCount, "The six required members plus status make seven entries.");
        Assert.Contains(requiredMemberKey, keys, $"The required member '{requiredMemberKey}' must survive the added Status structure.");
    }


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "The Status CBOR structure is a Map that MUST include
    /// at least one data item that refers to a status mechanism." A <c>status</c> value that is not
    /// itself a CBOR map — an unsigned integer, say — cannot carry that data item and is refused.
    /// </summary>
    [TestMethod]
    public void ReadMsoRefusesStatusValueThatIsNotAMap()
    {
        byte[] msoBytes = BuildMsoWithStatusValue(static writer => writer.WriteUInt32(42));

        Exception? caught = null;
        try
        {
            MdocCborMsoReader.Read(msoBytes);
        }
        catch(Exception ex)
        {
            caught = ex;
        }

        Assert.IsTrue(caught is CborContentException or InvalidOperationException,
            $"A status value that is not a CBOR map cannot carry the Section 6.3 Status structure; got {caught?.GetType().Name}.");
    }


    /// <summary>
    /// Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "idx: REQUIRED. ... uri: REQUIRED." A
    /// <c>status_list</c> entry missing either field is refused by
    /// <see cref="StatusListReferenceCborConverter"/>, which names the missing field.
    /// </summary>
    /// <param name="omitIdx">When <see langword="true"/>, the fixture writes only <c>uri</c>; otherwise only <c>idx</c>.</param>
    /// <param name="omittedFieldKey">The field key the refusal must name as missing.</param>
    [TestMethod]
    [DataRow(true, IndexKey)]
    [DataRow(false, UriKey)]
    public void ReadMsoRefusesStatusListMissingIdxOrUri(bool omitIdx, string omittedFieldKey)
    {
        byte[] msoBytes = BuildMsoWithStatusValue(writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString(StatusListMechanismKey);
            writer.WriteStartMap(1);
            if(omitIdx)
            {
                writer.WriteTextString(UriKey);
                writer.WriteTextString(SampleStatusUri);
            }
            else
            {
                writer.WriteTextString(IndexKey);
                writer.WriteInt32(SampleStatusIndex);
            }

            writer.WriteEndMap();
            writer.WriteEndMap();
        });

        CborContentException exception = Assert.ThrowsExactly<CborContentException>(() => MdocCborMsoReader.Read(msoBytes));
        Assert.Contains(omittedFieldKey, exception.Message, "The refusal must name the field Section 6.3 requires but the wire omitted.");
    }


    /// <summary>
    /// Hand-writes the Section 6.3 StatusListInfo structure: a map of <c>idx</c> (unsigned
    /// integer) and <c>uri</c> (text string).
    /// </summary>
    /// <param name="writer">The CBOR writer to append to.</param>
    /// <param name="index">The index to check in the Status List.</param>
    /// <param name="uri">The URI identifying the Status List Token.</param>
    private static void WriteStatusListInfo(CborWriter writer, int index, string uri)
    {
        writer.WriteStartMap(2);
        writer.WriteTextString(IndexKey);
        writer.WriteInt32(index);
        writer.WriteTextString(UriKey);
        writer.WriteTextString(uri);
        writer.WriteEndMap();
    }


    /// <summary>
    /// Hand-builds an MSO map carrying the six members of ISO/IEC 18013-5 §9.1.2.4 plus a
    /// <c>status</c> member whose value <paramref name="writeStatusValue"/> composes.
    /// </summary>
    /// <param name="writeStatusValue">Writes the Status structure's CBOR value.</param>
    /// <returns>The encoded MSO map bytes.</returns>
    private static byte[] BuildMsoWithStatusValue(Action<CborWriter> writeStatusValue)
    {
        return BuildMsoWithExtraMember(StatusKey, writeStatusValue);
    }


    /// <summary>
    /// Hand-builds an MSO map carrying the six members of ISO/IEC 18013-5 §9.1.2.4 plus one
    /// further member under <paramref name="extraMemberKey"/>. Lax conformance mode keeps the
    /// member order as written so the fixture states its own shape.
    /// </summary>
    /// <param name="extraMemberKey">The seventh member's text-string key.</param>
    /// <param name="writeExtraValue">Writes the seventh member's CBOR value.</param>
    /// <returns>The encoded MSO map bytes.</returns>
    private static byte[] BuildMsoWithExtraMember(string extraMemberKey, Action<CborWriter> writeExtraValue)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);

        writer.WriteStartMap(7);

        writer.WriteTextString(MdocMsoWellKnownKeys.Version);
        writer.WriteTextString(MdocMsoWellKnownKeys.Version10);

        writer.WriteTextString(MdocMsoWellKnownKeys.DigestAlgorithm);
        writer.WriteTextString(MdocMsoWellKnownKeys.DigestAlgorithmSha256);

        writer.WriteTextString(MdocMsoWellKnownKeys.ValueDigests);
        WriteValueDigests(writer, MdlNamespace);

        writer.WriteTextString(MdocMsoWellKnownKeys.DeviceKeyInfo);
        WriteDeviceKeyInfo(writer);

        writer.WriteTextString(MdocMsoWellKnownKeys.DocType);
        writer.WriteTextString(MdlDocType);

        writer.WriteTextString(MdocMsoWellKnownKeys.ValidityInfo);
        WriteValidityInfo(writer);

        writer.WriteTextString(extraMemberKey);
        writeExtraValue(writer);

        writer.WriteEndMap();

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Builds the model-side Mobile Security Object the writer tests encode: the six members of
    /// ISO/IEC 18013-5 §9.1.2.4 with a P-256 device key, plus <paramref name="status"/>.
    /// </summary>
    /// <param name="status">The Status structure to attach, or <see langword="null"/> for none.</param>
    /// <returns>The assembled Mobile Security Object.</returns>
    private static MdocMobileSecurityObject BuildMsoModel(StatusClaim? status)
    {
        var deviceKey = new CoseKey(
            kty: CoseKeyTypes.Ec2,
            curve: CoseKeyCurves.P256,
            x: new byte[32],
            y: new byte[32]);

        var signed = new DateTimeOffset(2026, 5, 24, 12, 0, 0, TimeSpan.Zero);

        return new MdocMobileSecurityObject(
            version: MdocMsoWellKnownKeys.Version10,
            digestAlgorithm: MdocMsoWellKnownKeys.DigestAlgorithmSha256,
            valueDigests: new Dictionary<string, IReadOnlyDictionary<uint, ReadOnlyMemory<byte>>>(StringComparer.Ordinal)
            {
                [MdlNamespace] = new Dictionary<uint, ReadOnlyMemory<byte>> { [0u] = new byte[32], [1u] = new byte[32] }
            },
            deviceKeyInfo: new MdocDeviceKeyInfo(deviceKey),
            docType: MdlDocType,
            validityInfo: new MdocValidityInfo(signed, signed, signed.AddYears(1)),
            status: status);
    }


    /// <summary>
    /// Walks an encoded MSO map with a raw <see cref="CborReader"/>, returning the map's declared
    /// entry count and its member keys in wire order without consulting the reader under test.
    /// </summary>
    /// <param name="encodedMso">The encoded MSO map bytes.</param>
    /// <returns>The declared entry count and the member keys.</returns>
    private static (int DeclaredEntryCount, IReadOnlyList<string> Keys) ReadTopLevelMap(ReadOnlyMemory<byte> encodedMso)
    {
        var reader = new CborReader(encodedMso, CborOptions.Lax);

        int? declaredEntryCount = reader.ReadStartMap();
        Assert.IsNotNull(declaredEntryCount, "The MSO map must be written with a definite length.");

        List<string> keys = [];
        for(int i = 0; i < declaredEntryCount.Value; i++)
        {
            keys.Add(reader.ReadTextString());
            reader.SkipValue();
        }

        reader.ReadEndMap();

        return (declaredEntryCount.Value, keys);
    }


    /// <summary>
    /// Walks an encoded MSO map with a raw <see cref="CborReader"/> down to the <c>status</c>
    /// member's <c>status_list</c> mechanism, returning its <c>idx</c> and <c>uri</c> without
    /// consulting the reader under test.
    /// </summary>
    /// <param name="encodedMso">The encoded MSO map bytes.</param>
    /// <returns>The StatusListInfo index and URI found on the wire.</returns>
    private static (int Index, string Uri) ReadStatusListInfoWithRawReader(ReadOnlyMemory<byte> encodedMso)
    {
        var reader = new CborReader(encodedMso, CborOptions.Lax);

        SeekToMember(reader, StatusKey);
        SeekToMember(reader, StatusListMechanismKey);

        int? fieldCount = reader.ReadStartMap();
        Assert.IsNotNull(fieldCount, "The StatusListInfo map must be written with a definite length.");

        int index = -1;
        string uri = string.Empty;
        for(int i = 0; i < fieldCount.Value; i++)
        {
            string key = reader.ReadTextString();
            if(string.Equals(key, IndexKey, StringComparison.Ordinal))
            {
                index = reader.ReadInt32();
            }
            else if(string.Equals(key, UriKey, StringComparison.Ordinal))
            {
                uri = reader.ReadTextString();
            }
            else
            {
                reader.SkipValue();
            }
        }

        reader.ReadEndMap();

        return (index, uri);
    }


    /// <summary>
    /// Advances a raw <see cref="CborReader"/> positioned at the start of a definite-length
    /// text-keyed map to the value of <paramref name="memberKey"/>, failing the test when the
    /// member is absent.
    /// </summary>
    /// <param name="reader">The reader positioned at the map's start.</param>
    /// <param name="memberKey">The member key to seek.</param>
    private static void SeekToMember(CborReader reader, string memberKey)
    {
        int? entryCount = reader.ReadStartMap();
        Assert.IsNotNull(entryCount, $"The map holding '{memberKey}' must be written with a definite length.");

        for(int i = 0; i < entryCount.Value; i++)
        {
            string key = reader.ReadTextString();
            if(string.Equals(key, memberKey, StringComparison.Ordinal))
            {
                return;
            }

            reader.SkipValue();
        }

        Assert.Fail($"The encoded map carries no '{memberKey}' member.");
    }
}
