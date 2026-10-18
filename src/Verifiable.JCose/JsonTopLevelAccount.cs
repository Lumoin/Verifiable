namespace Verifiable.JCose;

/// <summary>
/// The members at the top level of the one well-formed JSON object a document is, in document order, each observed without its
/// value (<see cref="JsonValueObservation"/>): the account <see cref="JwkJsonReader.ReadTopLevelMembers"/> gives of a document it
/// reads as that object, whether it answers its members or refuses it for a repeated name or for a member naming no Unicode text,
/// so a reader of one occurrence of a member learns of it from the very reading that judged the document, refused or not, and
/// never by reading the document again. A member whose own name names no Unicode text is no member any reader can ask for by its
/// name, and is not in the account. Two accounts are equal when they hold equal observations in the same order.
/// </summary>
public sealed record JsonTopLevelAccount
{
    /// <summary>The account of a document that is no one well-formed JSON object, which carries no member to observe.</summary>
    public static JsonTopLevelAccount None { get; } = new([]);


    /// <summary>Creates the account of the members observed.</summary>
    /// <param name="members">The members observed, in document order.</param>
    public JsonTopLevelAccount(IReadOnlyList<JsonTopLevelObservation> members)
    {
        ArgumentNullException.ThrowIfNull(members);

        Members = members;
    }


    /// <summary>The members observed, in document order, each name decoded once (RFC 8259 section 7).</summary>
    public IReadOnlyList<JsonTopLevelObservation> Members { get; }


    /// <summary>
    /// Every occurrence of the member of a name, in document order, each observed without its value: none for a member the
    /// object does not carry, and more than one for a name the object repeats (RFC 8259 section 4), which a reader of the members
    /// refuses and the account still observes.
    /// </summary>
    /// <param name="name">The member's name, decoded.</param>
    /// <returns>The occurrences.</returns>
    public IReadOnlyList<JsonValueObservation> OccurrencesOf(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        var occurrences = new List<JsonValueObservation>();

        foreach(var member in Members)
        {
            if(string.Equals(member.Name, name, StringComparison.Ordinal))
            {
                occurrences.Add(member.Value);
            }
        }

        return occurrences;
    }


    /// <summary>Whether another account holds equal observations in the same order.</summary>
    /// <param name="other">The other account.</param>
    /// <returns><see langword="true"/> when both hold the same observations.</returns>
    public bool Equals(JsonTopLevelAccount? other) => other is not null && Members.SequenceEqual(other.Members);


    /// <summary>A hash of the observations, in order.</summary>
    /// <returns>The hash.</returns>
    public override int GetHashCode()
    {
        var hash = new HashCode();

        foreach(var member in Members)
        {
            hash.Add(member);
        }

        return hash.ToHashCode();
    }
}


/// <summary>One member at the top level of a well-formed JSON object, observed without its value.</summary>
/// <param name="Name">The member's name, decoded once (RFC 8259 section 7), which is Unicode text.</param>
/// <param name="Value">What its value holds.</param>
public sealed record JsonTopLevelObservation(string Name, JsonValueObservation Value);
