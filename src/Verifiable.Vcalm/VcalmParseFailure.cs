namespace Verifiable.Vcalm;

/// <summary>
/// Why a VCALM 1.0 request body failed STRICT parsing, each reason answered with its own problem type.
/// <see cref="None"/> means the body parsed.
/// </summary>
/// <remarks>
/// A body the JSON reader refuses is <see cref="Unparseable"/>, answered with HTTP 400 and
/// <see cref="VcalmProblemTypes.ParsingError"/>. A JSON text whose content the parser refuses is
/// <see cref="Malformed"/>, answered with HTTP 400 and <see cref="VcalmProblemTypes.MalformedValueError"/>. A JSON text
/// whose <c>options</c> object carries a member the endpoint does not understand is <see cref="UnknownOption"/>,
/// answered with HTTP 400 and <see cref="VcalmProblemTypes.UnknownOptionProvided"/>. Keeping them apart lets each
/// endpoint answer with the type the data model or VCALM defines for the reason.
/// </remarks>
public enum VcalmParseFailure
{
    /// <summary>No failure; the body parsed into a request.</summary>
    None = 0,

    /// <summary>
    /// The body is a JSON text whose content the parser refuses: a top-level value that is not an object, a missing
    /// REQUIRED member, an unrecognized top-level member, or a member of the wrong kind or value, such as a credential
    /// or presentation that is not a recognized secured shape. The endpoints answer it with HTTP 400 and
    /// <see cref="VcalmProblemTypes.MalformedValueError"/>, the type the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#MALFORMED_VALUE_ERROR">VC Data Model 2.0 Section 7.2</see>
    /// defines as "The value associated with a particular property is malformed."
    /// </summary>
    Malformed,

    /// <summary>
    /// The <c>options</c> object carried a member the verifier does not understand. The §2.4
    /// unknown-option MUST → HTTP 400 with the §3.8
    /// <see cref="VcalmProblemTypes.UnknownOptionProvided"/> problem type.
    /// </summary>
    UnknownOption,

    /// <summary>
    /// The JSON reader refuses the body: the body is not a JSON text, against
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 Section 2</see>: "A JSON text is a
    /// serialized value.", or it is a JSON text that exceeds a limit the reader sets, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-9">RFC 8259 Section 9</see> permits: "An implementation
    /// may set limits on the maximum depth of nesting." The operations that parse their body through the parse seam
    /// answer it with HTTP 400 and <see cref="VcalmProblemTypes.ParsingError"/>, the type the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#PARSING_ERROR">VC Data Model 2.0 Section 7.2</see> defines as
    /// "There was an error while parsing input.", and answer an empty body and bytes that are not UTF-8 the same way
    /// before any parser reads them.
    /// </summary>
    Unparseable
}
