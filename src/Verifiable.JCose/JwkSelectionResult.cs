namespace Verifiable.JCose;

/// <summary>
/// The outcome of selecting one JWK from a JWK Set's <c>keys</c> array via one of the
/// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?)"/>,
/// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?, ReadOnlySpan{byte})"/>,
/// <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte})"/> or
/// <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/> overloads.
/// </summary>
public enum JwkSelectionOutcome
{
    /// <summary>
    /// Exactly one key satisfied the selection query; its string-valued members are on
    /// <see cref="JwkSelectionResult.Members"/>.
    /// </summary>
    Selected,

    /// <summary>
    /// No key in the set satisfied the selection query; a set whose <c>keys</c> array is empty among them. A set carrying no
    /// <c>keys</c> array is <see cref="MalformedDocument"/>, never this.
    /// </summary>
    NoMatch,

    /// <summary>
    /// More than one key satisfied the selection query. In <c>kid</c> mode
    /// (<see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?)"/> and
    /// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?, ReadOnlySpan{byte})"/>)
    /// this counts every element whose <c>kid</c> matched the requested identifier, whatever each
    /// match's <c>use</c>; in sole-key mode
    /// (<see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte})"/> and
    /// <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>) it counts
    /// every key the unfiltered overload holds, or every ELIGIBLE key the filtered overload holds,
    /// when more than one was required to be exactly one.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see> states that
    /// "different keys within the JWK Set SHOULD use distinct <c>kid</c> values", and names one
    /// legitimate duplicate: keys of differing <c>kty</c> that the application treats as equivalent
    /// alternatives. Selection refuses such a set rather than letting the order of the array decide
    /// which key a signature is trusted under, so a caller relying on that exception picks between
    /// the alternatives itself.
    /// </summary>
    MultipleKeysMatched,

    /// <summary>
    /// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?)"/> or
    /// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?, ReadOnlySpan{byte})"/>
    /// was called with no, or an empty, key identifier. An absent identifier is never treated as a
    /// wildcard match. Answered once the set is admitted, so <see cref="MalformedDocument"/>,
    /// <see cref="RepeatedMemberName"/> and <see cref="UndecodableMember"/> outrank it.
    /// </summary>
    KeyIdRequired,

    /// <summary>
    /// The supplied JWK Set is not one well-formed JSON object (<see cref="JsonNotOneObject"/>: not
    /// exactly one well-formed JSON value within the reader's bounds, or one that is no object, which
    /// RFC 7517 section 5 has a JWK Set be) and was refused before any key was scanned, OR one whose REQUIRED <c>keys</c> member
    /// (RFC 7517 section 5) is absent or carries a value other than an array, on every overload, OR — on
    /// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?, ReadOnlySpan{byte})"/>
    /// and <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/> — an
    /// element of a well-formed document's <c>keys</c> array was not itself a JSON object per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5.1">RFC 7517 §5.1</see>, or its
    /// braces never balanced. The second case is reached mid-walk, after zero or more elements have
    /// already been scanned.
    /// </summary>
    MalformedDocument,

    /// <summary>
    /// An element of the <c>keys</c> array — whether or not it was itself a candidate — carried a
    /// top-level member whose decoded name is one of
    /// <see cref="WellKnownJwkMemberNames.PrivateAndSymmetricMembers"/>. Reported only by
    /// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?, ReadOnlySpan{byte})"/>
    /// and <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>: this
    /// library's own policy for a JWK Set of verification keys, not a requirement of any RFC — a set
    /// that publishes private or symmetric material is not a source of verification keys, whatever
    /// key a caller asked for. Outranks every other outcome except <see cref="MalformedDocument"/>,
    /// <see cref="RepeatedMemberName"/>, <see cref="UndecodableMember"/> and <see cref="KeyIdRequired"/>.
    /// </summary>
    PrivateOrSymmetricMemberPresent,

    /// <summary>
    /// The supplied JWK Set is one well-formed JSON object, but one of its objects - the set's own, a key, or an extension
    /// member's - names a member more than once, where
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 §4</see> says the names within an object SHOULD be
    /// unique: readers of a repeated name differ in which value they take, so the set names no key one way. Refused before any
    /// key is scanned and before a key identifier is required, as the first defect in document order; the repetition is on
    /// <see cref="JwkSelectionResult.Repetition"/>, its name and the depth of the object repeating it, and no value. Outranked
    /// by <see cref="MalformedDocument"/> alone.
    /// </summary>
    RepeatedMemberName,

    /// <summary>
    /// The supplied JWK Set is one well-formed JSON object, but a member of one of its objects - the set's own, a key, or an
    /// extension member no scan reads - has a name or a string value whose escapes name an unpaired surrogate, which names no
    /// Unicode text (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.2">RFC 8259 §8.2</see>). The library's strict
    /// admission refuses the whole set for it, its own choice, as no text such a set holds is one its readers agree on.
    /// Refused before any key is scanned and before a key identifier is required, as the first defect in document order; the
    /// member is on <see cref="JwkSelectionResult.Undecodable"/>, its name as it can be written, the depth of the object
    /// carrying it and which part names no text, and no value. Outranked by <see cref="MalformedDocument"/> alone.
    /// </summary>
    UndecodableMember
}


/// <summary>
/// The Result-shaped return of every <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?)"/>,
/// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?, ReadOnlySpan{byte})"/>,
/// <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte})"/> and
/// <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/> overload: a
/// <see cref="JwkSelectionOutcome"/> plus, when
/// <see cref="Outcome"/> is <see cref="JwkSelectionOutcome.Selected"/>, the chosen key's
/// string-valued members.
/// </summary>
public sealed record JwkSelectionResult
{
    /// <summary>The selection outcome.</summary>
    public required JwkSelectionOutcome Outcome { get; init; }

    /// <summary>
    /// The selected key's string-valued members, keyed by JWK member name. <see langword="null"/>
    /// unless <see cref="Outcome"/> is <see cref="JwkSelectionOutcome.Selected"/>.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Members { get; init; }

    /// <summary>
    /// The repeated member name the set was refused for - the name and the depth of the object repeating it, never a value -
    /// when <see cref="Outcome"/> is <see cref="JwkSelectionOutcome.RepeatedMemberName"/>; otherwise <see langword="null"/>.
    /// </summary>
    public JsonRepeatedMemberName? Repetition { get; init; }

    /// <summary>
    /// The member naming no Unicode text the set was refused for - its name as it can be written, the depth of the object
    /// carrying it and which part names no text, never a value - when <see cref="Outcome"/> is
    /// <see cref="JwkSelectionOutcome.UndecodableMember"/>; otherwise <see langword="null"/>.
    /// </summary>
    public JsonUndecodableMember? Undecodable { get; init; }

    /// <summary><see langword="true"/> when <see cref="Outcome"/> is <see cref="JwkSelectionOutcome.Selected"/>.</summary>
    public bool IsSelected => Outcome == JwkSelectionOutcome.Selected;


    /// <summary>Builds a successful result carrying the selected key's string-valued members.</summary>
    /// <param name="members">The selected key's string-valued members.</param>
    public static JwkSelectionResult Selected(IReadOnlyDictionary<string, string> members)
    {
        ArgumentNullException.ThrowIfNull(members);

        return new JwkSelectionResult { Outcome = JwkSelectionOutcome.Selected, Members = members };
    }


    /// <summary>Builds a result reporting that no key satisfied the selection query.</summary>
    public static JwkSelectionResult NoMatch() =>
        new() { Outcome = JwkSelectionOutcome.NoMatch };


    /// <summary>Builds a refusal reporting that more than one key satisfied the selection query.</summary>
    public static JwkSelectionResult MultipleKeysMatched() =>
        new() { Outcome = JwkSelectionOutcome.MultipleKeysMatched };


    /// <summary>Builds a refusal reporting that a key identifier was required but none was supplied.</summary>
    public static JwkSelectionResult KeyIdRequired() =>
        new() { Outcome = JwkSelectionOutcome.KeyIdRequired };


    /// <summary>Builds a refusal reporting that the JWK Set document is not well formed.</summary>
    public static JwkSelectionResult MalformedDocument() =>
        new() { Outcome = JwkSelectionOutcome.MalformedDocument };


    /// <summary>
    /// Builds a refusal reporting that an element of the <c>keys</c> array carries private or
    /// symmetric key material.
    /// </summary>
    public static JwkSelectionResult PrivateOrSymmetricMemberPresent() =>
        new() { Outcome = JwkSelectionOutcome.PrivateOrSymmetricMemberPresent };


    /// <summary>Builds a refusal reporting that one of the set's objects repeats a member name.</summary>
    /// <param name="repetition">The repetition, as the strict judgement of the document answered it.</param>
    public static JwkSelectionResult RepeatedMemberName(JsonRepeatedMemberName repetition)
    {
        ArgumentNullException.ThrowIfNull(repetition);

        return new JwkSelectionResult { Outcome = JwkSelectionOutcome.RepeatedMemberName, Repetition = repetition };
    }


    /// <summary>Builds a refusal reporting that a member of one of the set's objects has a name or a string value naming no Unicode text.</summary>
    /// <param name="undecodable">The member, as the strict judgement of the document answered it.</param>
    public static JwkSelectionResult UndecodableMember(JsonUndecodableMember undecodable)
    {
        ArgumentNullException.ThrowIfNull(undecodable);

        return new JwkSelectionResult { Outcome = JwkSelectionOutcome.UndecodableMember, Undecodable = undecodable };
    }
}
