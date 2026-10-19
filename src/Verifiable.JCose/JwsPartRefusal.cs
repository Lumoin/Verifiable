namespace Verifiable.JCose;

/// <summary>The segment of a compact JWS (RFC 7515 section 7.1) a reading of one of its parts concerns.</summary>
public enum JwsPart
{
    /// <summary>The JWS Protected Header, the first segment base64url-decoded.</summary>
    ProtectedHeader,

    /// <summary>The JWS Payload, the second segment base64url-decoded: a JWT's claims set.</summary>
    Payload
}


/// <summary>
/// Why the reading of one part of a JWS refused it, carried whole into the result of the validation that read the part, beside
/// the validation's coarse category, so a receiver records the reading's own answer and never reads the part again. The JSON
/// reader's refusal of the part's document (<see cref="JwsPartDocumentRefusal"/>) is the case every reading of a JOSE part
/// shares; a profile whose reading also judges the kind of the members it requires adds its own case beside it. Every fact of a
/// refusal is fixed by its construction: none is settable afterwards, by an object initializer or a <c>with</c> expression,
/// so the segment a refusal names is the one its construction established.
/// </summary>
public abstract record JwsPartRefusal
{
    /// <summary>The segment the refused part is.</summary>
    public abstract JwsPart Part { get; }
}


/// <summary>
/// The JSON reader refused the document a part of a JWS is: no one well-formed JSON object (<see cref="JsonNotOneObject"/>), an
/// object repeating a member name at any depth (<see cref="JsonRepeatedMemberName"/>), or one holding a name or a string naming
/// no Unicode text (<see cref="JsonUndecodableMember"/>), carried as the reader answered it.
/// </summary>
public sealed record JwsPartDocumentRefusal : JwsPartRefusal
{
    /// <summary>Creates the refusal of a part's document.</summary>
    /// <param name="part">The segment the refused part is.</param>
    /// <param name="refusal">The reader's refusal of the part's document.</param>
    public JwsPartDocumentRefusal(JwsPart part, JsonTopLevelReading refusal)
    {
        ArgumentNullException.ThrowIfNull(refusal);

        Part = part;
        Refusal = refusal;
    }


    /// <inheritdoc/>
    public override JwsPart Part { get; }

    /// <summary>The reader's refusal of the part's document.</summary>
    public JsonTopLevelReading Refusal { get; }
}
