using Lumoin.Veritas.Cbor;
using System.Buffers;
using System.Globalization;
using System.Text;
using Verifiable.Cbor;
using Verifiable.Cbor.StatusList;
using Verifiable.Core.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="StatusClaimCborReader"/>, the decoder of the Status CBOR structure a
/// COSE-based Referenced Token carries. Per
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token Status List, Section 6.3</see>
/// the Referenced Token "MAY be encoded as a "CBOR Web Token (CWT)" object according to [RFC8392], as
/// an SD-CWTs [I-D.ietf-spice-sd-cwt] or as an ISO mdoc according to [ISO.mdoc] or other formats based
/// on COSE", so one reader serves every COSE format's status claim and is measured here on its own,
/// outside any of them.
/// </summary>
/// <remarks>
/// Every fixture is composed by hand with a <see cref="CborWriter"/> straight from the Section 6.3
/// structure — never by the Mobile Security Object writer or any other production encoder — so the
/// reader is measured against the specification's own wire shape rather than against a sibling
/// writer's output. Lax conformance mode keeps each map's entries in the order the fixture states
/// them. How the same reader behaves once it is reached through the Mobile Security Object's
/// <c>status</c> member is proved by <see cref="Verifiable.Tests.Mdoc.MdocCborMsoStatusTests"/> and is
/// not repeated here.
/// </remarks>
[TestClass]
internal sealed class StatusClaimCborReaderTests
{
    /// <summary>
    /// The Section 6.3 mechanism key <c>status_list</c>, held as a literal so the fixtures pin the
    /// wire spelling independently of the model's own constant.
    /// </summary>
    private const string StatusListMechanismKey = "status_list";

    /// <summary>
    /// The mechanism key <c>identifier_list</c> the draft EU implementing act names for the
    /// attestation revocation list, held as a literal for the same reason.
    /// </summary>
    private const string IdentifierListMechanismKey = "identifier_list";

    /// <summary>A mechanism name no specification defines, used to prove an unrecognised key is recorded and skipped.</summary>
    private const string UnmodelledMechanismKey = "acme_mechanism";

    /// <summary>The Section 6.3 StatusListInfo index field key.</summary>
    private const string IndexKey = "idx";

    /// <summary>The Section 6.3 StatusListInfo URI field key.</summary>
    private const string UriKey = "uri";

    /// <summary>The index the fixtures reference in the Status List.</summary>
    private const int SampleStatusIndex = 42;

    /// <summary>The Status List Token URI the fixtures reference, taken from the Section 6 examples.</summary>
    private const string SampleStatusUri = "https://example.com/statuslists/1";

    /// <summary>Names an unmodelled mechanism value written as a nested CBOR map.</summary>
    private const string NestedMapValue = "map";

    /// <summary>Names an unmodelled mechanism value written as a nested CBOR array.</summary>
    private const string NestedArrayValue = "array";

    /// <summary>Names an <c>idx</c> written as a CBOR negative integer (major type 1).</summary>
    private const string NegativeIntegerIndex = "negative-integer";

    /// <summary>Names an <c>idx</c> written as a CBOR text string (major type 3).</summary>
    private const string TextStringIndex = "text-string";

    /// <summary>Names an <c>idx</c> written as an unsigned integer above <see cref="int.MaxValue"/>.</summary>
    private const string AboveInt32MaxIndex = "above-int32-max";

    /// <summary>Names a <c>uri</c> written as a CBOR unsigned integer (major type 0).</summary>
    private const string UnsignedIntegerUri = "unsigned-integer";

    /// <summary>Names a <c>uri</c> written as a text string carrying a relative reference.</summary>
    private const string RelativeReferenceUri = "relative-reference";

    /// <summary>A relative reference, which RFC 3986 distinguishes from the URI the claim requires.</summary>
    private const string RelativeStatusListReference = "/statuslists/1";

    /// <summary>The member key an unmodelled mechanism's skipped value carries.</summary>
    private const string UnmodelledMechanismMemberKey = "anything";

    /// <summary>The member value an unmodelled mechanism's skipped value carries.</summary>
    private const int UnmodelledMechanismMemberValue = 7;

    /// <summary>
    /// Gets or sets the context information for the current test run.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// "status_list (status list): REQUIRED when the status mechanism defined in this specification is
    /// used. It has the same definition as the status_list claim in Section 6.2 but MUST be encoded as
    /// a StatusListInfo CBOR structure with the following fields: idx: REQUIRED. Unsigned integer
    /// (major type 0). … uri: REQUIRED. Text string (major type 3)."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token Status List, Section 6.3</see>.
    /// A structure naming that one mechanism decodes into the reference it carries, and records the
    /// mechanism by name.
    /// </summary>
    [TestMethod]
    public void AStatusStructureNamingTheStatusListMechanismDecodesItsIndexAndUri()
    {
        byte[] statusBytes = BuildStatusStructure(static writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString(StatusListMechanismKey);
            WriteStatusListInfo(writer, SampleStatusIndex, SampleStatusUri);
            writer.WriteEndMap();
        });

        StatusClaim claim = StatusClaimCborReader.Read(new CborReader(statusBytes, CborOptions.Lax));

        Assert.HasCount(1, claim.Mechanisms, "Exactly the one mechanism key was on the wire.");
        Assert.Contains(StatusMechanismNames.StatusList, claim.Mechanisms, "The status_list mechanism must be recorded by name.");
        Assert.AreEqual(SampleStatusIndex, claim.StatusList!.Value.Index, "idx is the unsigned integer the StatusListInfo carries.");
        Assert.AreEqual(SampleStatusUri, claim.StatusList!.Value.Uri, "uri is the text string identifying the Status List Token.");
    }


    /// <summary>
    /// "The Status CBOR structure is a Map that MUST include at least one data item that refers to a
    /// status mechanism. Each data item in the Status CBOR structure comprises a key-value pair, where
    /// the key MUST be a CBOR text string (major type 3) specifying the identifier of the status
    /// mechanism and the corresponding value defines its contents."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token Status List, Section 6.3</see>.
    /// The value shape belongs to the mechanism, not to this specification, so a mechanism this
    /// library does not model is still a mechanism: its key is recorded and its value skipped whole,
    /// whatever CBOR item that value is, leaving the structure's remaining data items readable.
    /// </summary>
    /// <param name="unmodelledValueKind">Names the CBOR item the fixture writes as the unmodelled mechanism's value.</param>
    [TestMethod]
    [DataRow(NestedMapValue)]
    [DataRow(NestedArrayValue)]
    public void AnUnmodelledMechanismIsRecordedByNameAndItsValueSkipped(string unmodelledValueKind)
    {
        byte[] statusBytes = BuildStatusStructure(writer =>
        {
            writer.WriteStartMap(2);
            writer.WriteTextString(UnmodelledMechanismKey);
            WriteUnmodelledMechanismValue(writer, unmodelledValueKind);
            writer.WriteTextString(StatusListMechanismKey);
            WriteStatusListInfo(writer, SampleStatusIndex, SampleStatusUri);
            writer.WriteEndMap();
        });

        StatusClaim claim = StatusClaimCborReader.Read(new CborReader(statusBytes, CborOptions.Lax));

        Assert.HasCount(2, claim.Mechanisms, "Both mechanism keys must be recorded by name.");
        Assert.Contains(UnmodelledMechanismKey, claim.Mechanisms, "The unmodelled mechanism must reach the caller by name.");
        Assert.Contains(StatusMechanismNames.StatusList, claim.Mechanisms, "The modelled mechanism must be recorded beside it.");
        Assert.AreEqual(SampleStatusIndex, claim.StatusList!.Value.Index, $"An unmodelled mechanism whose value is a CBOR {unmodelledValueKind} must be skipped whole, leaving idx readable.");
        Assert.AreEqual(SampleStatusUri, claim.StatusList!.Value.Uri, $"An unmodelled mechanism whose value is a CBOR {unmodelledValueKind} must be skipped whole, leaving uri readable.");
    }


    /// <summary>
    /// "The Status CBOR structure is a Map that MUST include at least one data item that refers to a
    /// status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token Status List, Section 6.3</see>.
    /// An empty map refers to no mechanism, so it is not a Status structure and is refused rather than
    /// decoded into a claim that names nothing.
    /// </summary>
    [TestMethod]
    public void AStatusStructureWithNoDataItemIsRefused()
    {
        byte[] statusBytes = BuildStatusStructure(static writer =>
        {
            writer.WriteStartMap(0);
            writer.WriteEndMap();
        });

        CborContentException exception = Assert.ThrowsExactly<CborContentException>(
            () => StatusClaimCborReader.Read(new CborReader(statusBytes, CborOptions.Lax)));

        Assert.Contains("at least one", exception.Message, "The refusal must name Section 6.3's at-least-one-data-item requirement.");
    }


    /// <summary>
    /// "Each data item in the Status CBOR structure comprises a key-value pair, where the key MUST be
    /// a CBOR text string (major type 3) specifying the identifier of the status mechanism and the
    /// corresponding value defines its contents."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token Status List, Section 6.3</see>.
    /// A key of any other major type identifies no mechanism, so the structure is refused rather than
    /// having the entry skipped as if the issuer had named nothing there.
    /// </summary>
    [TestMethod]
    public void AStatusStructureKeyThatIsNotATextStringIsRefused()
    {
        byte[] statusBytes = BuildStatusStructure(static writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteInt32(1);
            WriteStatusListInfo(writer, SampleStatusIndex, SampleStatusUri);
            writer.WriteEndMap();
        });

        _ = Assert.ThrowsExactly<CborContentException>(
            () => StatusClaimCborReader.Read(new CborReader(statusBytes, CborOptions.Lax)),
            "A Status map key that is not a CBOR text string cannot identify a status mechanism.");
    }


    /// <summary>
    /// "Each data item in the Status CBOR structure comprises a key-value pair, where the key MUST be
    /// a CBOR text string (major type 3) specifying the identifier of the status mechanism and the
    /// corresponding value defines its contents."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token Status List, Section 6.3</see>.
    /// One data item names one mechanism, so a structure repeating <c>status_list</c> states two
    /// contents for one mechanism: a reader taking the first entry and a reader taking the last would
    /// resolve different Status List Tokens for the same credential. The structure is refused rather
    /// than one of the two silently winning.
    /// </summary>
    [TestMethod]
    public void AStatusStructureRepeatingTheStatusListMechanismIsRefused()
    {
        byte[] statusBytes = BuildStatusStructure(static writer =>
        {
            writer.WriteStartMap(2);
            writer.WriteTextString(StatusListMechanismKey);
            WriteStatusListInfo(writer, SampleStatusIndex, SampleStatusUri);
            writer.WriteTextString(StatusListMechanismKey);
            WriteStatusListInfo(writer, SampleStatusIndex + 1, SampleStatusUri);
            writer.WriteEndMap();
        });

        CborContentException exception = Assert.ThrowsExactly<CborContentException>(
            () => StatusClaimCborReader.Read(new CborReader(statusBytes, CborOptions.Lax)),
            "A repeated mechanism key states two contents for one mechanism and is refused.");

        Assert.Contains(StatusListMechanismKey, exception.Message, "The refusal must name the repeated mechanism key.");
    }


    /// <summary>
    /// "Each data item in the Status CBOR structure comprises a key-value pair, where the key MUST be
    /// a CBOR text string (major type 3) specifying the identifier of the status mechanism and the
    /// corresponding value defines its contents."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token Status List, Section 6.3</see>.
    /// The rule is the data item's, not the modelled mechanism's: a mechanism this library does not
    /// evaluate is repeated with the same ambiguity, and collapsing it into a single recorded name
    /// would hide from the relying party that the issuer stated the mechanism twice.
    /// </summary>
    [TestMethod]
    public void AStatusStructureRepeatingAnUnmodelledMechanismIsRefused()
    {
        byte[] statusBytes = BuildStatusStructure(static writer =>
        {
            writer.WriteStartMap(2);
            writer.WriteTextString(UnmodelledMechanismKey);
            WriteUnmodelledMechanismValue(writer, NestedMapValue);
            writer.WriteTextString(UnmodelledMechanismKey);
            WriteUnmodelledMechanismValue(writer, NestedArrayValue);
            writer.WriteEndMap();
        });

        CborContentException exception = Assert.ThrowsExactly<CborContentException>(
            () => StatusClaimCborReader.Read(new CborReader(statusBytes, CborOptions.Lax)),
            "A repeated mechanism key is refused whether or not this library models that mechanism.");

        Assert.Contains(UnmodelledMechanismKey, exception.Message, "The refusal must name the repeated mechanism key.");
    }


    /// <summary>
    /// "idx: REQUIRED. Unsigned integer (major type 0). The idx (index) claim MUST specify a
    /// non-negative Integer that represents the index to check for status information in the Status
    /// List for the current Referenced Token."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token Status List, Section 6.3</see>.
    /// A negative integer is not non-negative, another major type is not major type 0, and an index no
    /// entry of a Status List this library can address could carry is not an index it can check — each
    /// leaves the StatusListInfo undecodable rather than truncated to something addressable.
    /// </summary>
    /// <param name="indexEncoding">Names the offending <c>idx</c> encoding the fixture writes.</param>
    [TestMethod]
    [DataRow(NegativeIntegerIndex)]
    [DataRow(TextStringIndex)]
    [DataRow(AboveInt32MaxIndex)]
    public void AStatusListIndexOutsideTheValueDomainIsRefused(string indexEncoding)
    {
        byte[] statusBytes = BuildStatusStructure(writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString(StatusListMechanismKey);
            writer.WriteStartMap(2);
            writer.WriteTextString(IndexKey);
            WriteOffendingIndex(writer, indexEncoding);
            writer.WriteTextString(UriKey);
            writer.WriteTextString(SampleStatusUri);
            writer.WriteEndMap();
            writer.WriteEndMap();
        });

        _ = Assert.ThrowsExactly<CborContentException>(
            () => StatusClaimCborReader.Read(new CborReader(statusBytes, CborOptions.Lax)),
            $"An idx encoded as {indexEncoding} leaves Section 6.3's value domain for a non-negative Integer.");
    }


    /// <summary>
    /// "uri: REQUIRED. Text string (major type 3). The uri (URI) claim MUST specify a String value
    /// that identifies the Status List Token containing the status information for the Referenced
    /// Token. The value of uri MUST be a URI conforming to [RFC3986]."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token Status List, Section 6.3</see>.
    /// Two requirements ride that sentence — the major type and RFC 3986 conformance — and a value
    /// failing either identifies no Status List Token, so neither is a URI the reader may hand a
    /// resolver.
    /// </summary>
    /// <param name="uriEncoding">Names the offending <c>uri</c> encoding the fixture writes.</param>
    [TestMethod]
    [DataRow(UnsignedIntegerUri)]
    [DataRow(RelativeReferenceUri)]
    public void AStatusListUriOutsideTheValueDomainIsRefused(string uriEncoding)
    {
        byte[] statusBytes = BuildStatusStructure(writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString(StatusListMechanismKey);
            writer.WriteStartMap(2);
            writer.WriteTextString(IndexKey);
            writer.WriteInt32(SampleStatusIndex);
            writer.WriteTextString(UriKey);
            WriteOffendingUri(writer, uriEncoding);
            writer.WriteEndMap();
            writer.WriteEndMap();
        });

        _ = Assert.ThrowsExactly<CborContentException>(
            () => StatusClaimCborReader.Read(new CborReader(statusBytes, CborOptions.Lax)),
            $"A uri encoded as {uriEncoding} leaves Section 6.3's value domain for an RFC 3986 URI.");
    }


    /// <summary>
    /// "The Status CBOR structure is a Map that MUST include at least one data item that refers to a
    /// status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token Status List, Section 6.3</see>.
    /// Section 6.3 constrains the structure to a map and its data items, not to how the encoder framed
    /// that map's length: RFC 8949 lets a streaming issuer emit an indefinite-length map, which carries
    /// the same data items and must therefore decode to the same claim.
    /// </summary>
    [TestMethod]
    public void AnIndefiniteLengthStatusStructureIsRead()
    {
        byte[] indefiniteBytes = BuildStatusStructure(static writer =>
        {
            writer.WriteStartMap(null);
            writer.WriteTextString(StatusListMechanismKey);
            WriteStatusListInfo(writer, SampleStatusIndex, SampleStatusUri);
            writer.WriteEndMap();
        });
        byte[] definiteBytes = BuildStatusStructure(static writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString(StatusListMechanismKey);
            WriteStatusListInfo(writer, SampleStatusIndex, SampleStatusUri);
            writer.WriteEndMap();
        });

        StatusClaim fromIndefinite = StatusClaimCborReader.Read(new CborReader(indefiniteBytes, CborOptions.Lax));
        StatusClaim fromDefinite = StatusClaimCborReader.Read(new CborReader(definiteBytes, CborOptions.Lax));

        Assert.AreNotEqual(definiteBytes.Length, indefiniteBytes.Length, "The two framings must genuinely differ on the wire for the comparison to mean anything.");
        Assert.AreEqual(fromDefinite, fromIndefinite, "Map framing is an encoding choice; the data items it carries are the claim.");
    }


    /// <summary>
    /// "The Referenced Token MAY be encoded as a "CBOR Web Token (CWT)" object according to [RFC8392],
    /// as an SD-CWTs [I-D.ietf-spice-sd-cwt] or as an ISO mdoc according to [ISO.mdoc] or other formats
    /// based on COSE. Referenced Tokens in CBOR SHOULD share the same core data structure for a status
    /// list reference" — and Section 6.3's <c>status_list</c> "has the same definition as the
    /// status_list claim in Section 6.2 but MUST be encoded as a StatusListInfo CBOR structure".
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token Status List, Section 6.3</see>.
    /// The two encodings are one statement, so a verifier that reads a COSE-based credential and one
    /// that reads the JOSE-based credential of the same issuer must hold claims that compare equal —
    /// otherwise the format, not the issuer, would decide what the status statement is.
    /// </summary>
    [TestMethod]
    public void TheCoseAndJoseEncodingsOfOneStatusStatementReadAsTheSameClaim()
    {
        byte[] statusBytes = BuildStatusStructure(static writer =>
        {
            writer.WriteStartMap(2);
            writer.WriteTextString(IdentifierListMechanismKey);
            writer.WriteStartMap(1);
            writer.WriteTextString("id");
            writer.WriteTextString("6fc2-a3b1");
            writer.WriteEndMap();
            writer.WriteTextString(StatusListMechanismKey);
            WriteStatusListInfo(writer, SampleStatusIndex, SampleStatusUri);
            writer.WriteEndMap();
        });
        byte[] statusObjectUtf8Json = Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ """
            {"identifier_list":{"id":"6fc2-a3b1"},"status_list":{"idx":42,"uri":"https://example.com/statuslists/1"}}
            """);

        StatusClaim fromCose = StatusClaimCborReader.Read(new CborReader(statusBytes, CborOptions.Lax));
        bool isJoseRead = StatusClaimReader.TryRead(statusObjectUtf8Json, out StatusClaim? fromJose);

        Assert.IsTrue(isJoseRead, "The JOSE encoding of the same statement is itself well-formed.");
        Assert.AreEqual(fromJose, fromCose, "One status statement in two encodings must read as one claim.");
    }


    /// <summary>
    /// Hand-writes the Section 6.3 StatusListInfo structure: a map of <c>idx</c> (unsigned integer)
    /// and <c>uri</c> (text string).
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
    /// Writes the value of a mechanism whose contents this library does not model, in the CBOR shape
    /// <paramref name="valueKind"/> names.
    /// </summary>
    /// <param name="writer">The CBOR writer to append to.</param>
    /// <param name="valueKind">Either <c>map</c> or <c>array</c>.</param>
    private static void WriteUnmodelledMechanismValue(CborWriter writer, string valueKind)
    {
        _ = valueKind switch
        {
            NestedMapValue => WriteNestedMap(writer),
            _ => WriteNestedArray(writer)
        };

        //A mechanism whose contents are a nested map of its own members.
        static bool WriteNestedMap(CborWriter writer)
        {
            writer.WriteStartMap(1);
            writer.WriteTextString(UnmodelledMechanismMemberKey);
            writer.WriteInt32(UnmodelledMechanismMemberValue);
            writer.WriteEndMap();

            return true;
        }

        //A mechanism whose contents are a nested array, the other composite CBOR item.
        static bool WriteNestedArray(CborWriter writer)
        {
            writer.WriteStartArray(2);
            writer.WriteTextString(UnmodelledMechanismMemberKey);
            writer.WriteInt32(UnmodelledMechanismMemberValue);
            writer.WriteEndArray();

            return true;
        }
    }


    /// <summary>
    /// Writes an <c>idx</c> value that leaves Section 6.3's value domain, in the form
    /// <paramref name="indexEncoding"/> names.
    /// </summary>
    /// <param name="writer">The CBOR writer to append to.</param>
    /// <param name="indexEncoding">One of <c>negative-integer</c>, <c>text-string</c> or <c>above-int32-max</c>.</param>
    private static void WriteOffendingIndex(CborWriter writer, string indexEncoding)
    {
        _ = indexEncoding switch
        {
            NegativeIntegerIndex => WriteNegativeInteger(writer),
            TextStringIndex => WriteIndexAsTextString(writer),
            _ => WriteIndexAboveInt32Max(writer)
        };

        //An index below zero, which "non-negative Integer" excludes.
        static bool WriteNegativeInteger(CborWriter writer)
        {
            writer.WriteInt32(-1);

            return true;
        }

        //An index under major type 3, which "Unsigned integer (major type 0)" excludes.
        static bool WriteIndexAsTextString(CborWriter writer)
        {
            writer.WriteTextString(SampleStatusIndex.ToString(CultureInfo.InvariantCulture));

            return true;
        }

        //An index no Status List entry this library can address could carry.
        static bool WriteIndexAboveInt32Max(CborWriter writer)
        {
            writer.WriteUInt64((ulong)int.MaxValue + 1);

            return true;
        }
    }


    /// <summary>
    /// Writes a <c>uri</c> value that leaves Section 6.3's value domain, in the form
    /// <paramref name="uriEncoding"/> names.
    /// </summary>
    /// <param name="writer">The CBOR writer to append to.</param>
    /// <param name="uriEncoding">One of <c>unsigned-integer</c> or <c>relative-reference</c>.</param>
    private static void WriteOffendingUri(CborWriter writer, string uriEncoding)
    {
        _ = uriEncoding switch
        {
            UnsignedIntegerUri => WriteUriAsUnsignedInteger(writer),
            _ => WriteUriAsRelativeReference(writer)
        };

        //A uri under major type 0, which "Text string (major type 3)" excludes.
        static bool WriteUriAsUnsignedInteger(CborWriter writer)
        {
            writer.WriteUInt32(1);

            return true;
        }

        //A relative reference, which RFC 3986 distinguishes from the URI the claim requires.
        static bool WriteUriAsRelativeReference(CborWriter writer)
        {
            writer.WriteTextString(RelativeStatusListReference);

            return true;
        }
    }


    /// <summary>
    /// Encodes a Status CBOR structure <paramref name="writeStatusStructure"/> composes. Lax
    /// conformance mode keeps the entries in the order the fixture states them and permits the
    /// indefinite-length framing one fixture needs.
    /// </summary>
    /// <param name="writeStatusStructure">Writes the Status structure's CBOR map.</param>
    /// <returns>The encoded Status structure bytes.</returns>
    private static byte[] BuildStatusStructure(Action<CborWriter> writeStatusStructure)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);
        writeStatusStructure(writer);

        return buffer.WrittenSpan.ToArray();
    }
}
