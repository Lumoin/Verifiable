namespace Verifiable.JCose;

/// <summary>
/// The selection of one verification key from a JWK Set (RFC 7517 section 5) a document's reader has already decoded - the
/// <c>jwks</c> a federation Entity Statement or Trust Anchor declares, held as the claims set holds it - judged whole by the same
/// judgement <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?, ReadOnlySpan{byte})"/> applies to the set's
/// wire bytes (<see cref="JwkSetJudgement"/>), with no rendering of the decoded set back to JSON in between.
/// </summary>
/// <remarks>
/// The decoded set has already been read by its document's reader, which owns the refusal of a set whose names repeat or name no
/// Unicode text; this selection judges what that reading decoded: a set that is no object, a <c>keys</c> that is no array
/// (RFC 7517 section 5) or holds an element that is no object (section 5.1) is <see cref="JwkSelectionOutcome.MalformedDocument"/>;
/// an element carrying private or symmetric material refuses the set; a <c>kid</c> matched by more than one key, or more than one
/// eligible key where none is named, is <see cref="JwkSelectionOutcome.MultipleKeysMatched"/>.
/// </remarks>
public static class JwkSetSelection
{
    /// <summary>
    /// The key of a decoded JWK Set whose <c>kid</c> equals <paramref name="keyId"/> and whose <c>use</c> is eligible for
    /// <paramref name="publicKeyUse"/>; an absent or empty <paramref name="keyId"/> is never a match
    /// (<see cref="JwkSelectionOutcome.KeyIdRequired"/>).
    /// </summary>
    /// <param name="jwkSet">The decoded set.</param>
    /// <param name="keyId">The requested <c>kid</c>.</param>
    /// <param name="publicKeyUse">The eligible <c>use</c> value; never empty.</param>
    /// <returns>The selection.</returns>
    public static JwkSelectionResult SelectKeyByKeyId(object? jwkSet, string? keyId, string publicKeyUse)
    {
        ArgumentException.ThrowIfNullOrEmpty(publicKeyUse);

        if(jwkSet is not IReadOnlyDictionary<string, object> set)
        {
            return JwkSelectionResult.MalformedDocument();
        }

        return string.IsNullOrEmpty(keyId) ? JwkSelectionResult.KeyIdRequired() : Select(set, keyId, publicKeyUse);
    }


    /// <summary>The sole key of a decoded JWK Set whose <c>use</c> is eligible for <paramref name="publicKeyUse"/>.</summary>
    /// <param name="jwkSet">The decoded set.</param>
    /// <param name="publicKeyUse">The eligible <c>use</c> value; never empty.</param>
    /// <returns>The selection.</returns>
    public static JwkSelectionResult SelectSoleKey(object? jwkSet, string publicKeyUse)
    {
        ArgumentException.ThrowIfNullOrEmpty(publicKeyUse);

        return jwkSet is IReadOnlyDictionary<string, object> set ? Select(set, null, publicKeyUse) : JwkSelectionResult.MalformedDocument();
    }


    /// <summary>Walks every element of the set's <c>keys</c> to its end through the shared judgement.</summary>
    /// <param name="set">The decoded set.</param>
    /// <param name="keyId">The <c>kid</c> to match, or <see langword="null"/> for the sole-key query.</param>
    /// <param name="publicKeyUse">The eligible <c>use</c> value.</param>
    /// <returns>The selection.</returns>
    private static JwkSelectionResult Select(IReadOnlyDictionary<string, object> set, string? keyId, string publicKeyUse)
    {
        if(!set.TryGetValue(WellKnownJwkMemberNames.Keys, out var keysValue) || keysValue is string || keysValue is not IEnumerable<object?> keys)
        {
            return JwkSelectionResult.MalformedDocument();
        }

        var judgement = new JwkSetJudgement(keyId is not null);
        IReadOnlyDictionary<string, object>? selected = null;

        foreach(var element in keys)
        {
            if(element is not IReadOnlyDictionary<string, object> key)
            {
                return JwkSelectionResult.MalformedDocument();
            }

            var keyIdMatches = keyId is not null && key.TryGetValue(WellKnownJwkMemberNames.Kid, out var kid) && kid is string kidText
                && string.Equals(kidText, keyId, StringComparison.Ordinal);
            var useEligible = !key.TryGetValue(WellKnownJwkMemberNames.Use, out var use)
                || (use is string useText && string.Equals(useText, publicKeyUse, StringComparison.Ordinal));

            if(judgement.Observe(WellKnownJwkMemberNames.ContainsPrivateOrSymmetricMember(key.Keys), keyIdMatches, useEligible))
            {
                selected = key;
            }
        }

        return judgement.Outcome switch
        {
            JwkSelectionOutcome.Selected when selected is not null => JwkSelectionResult.Selected(StringMembersOf(selected)),
            JwkSelectionOutcome.NoMatch => JwkSelectionResult.NoMatch(),
            JwkSelectionOutcome.MultipleKeysMatched => JwkSelectionResult.MultipleKeysMatched(),
            JwkSelectionOutcome.PrivateOrSymmetricMemberPresent => JwkSelectionResult.PrivateOrSymmetricMemberPresent(),
            var outcome => throw new InvalidOperationException($"The key set's judgement answered {outcome}, an outcome it never answers.")
        };
    }


    /// <summary>A selected key's string-valued members, as every selection of a JWK Set answers them.</summary>
    /// <param name="key">The key's decoded members.</param>
    /// <returns>The string-valued members.</returns>
    private static Dictionary<string, string> StringMembersOf(IReadOnlyDictionary<string, object> key)
    {
        var members = new Dictionary<string, string>(key.Count, StringComparer.Ordinal);
        foreach(var member in key)
        {
            if(member.Value is string text)
            {
                members[member.Key] = text;
            }
        }

        return members;
    }
}


/// <summary>
/// The whole-set judgement of a JWK Set selection, fed one element at a time whatever the set is read from - its wire bytes or a
/// decoded claim - so every selection of a set decides alike: an element carrying private or symmetric material refuses the set
/// whatever is asked; with a <c>kid</c> named, every element matching it counts, whatever its <c>use</c>, and the first match is
/// selected only when its <c>use</c> is eligible; with none named, every eligible element counts and the first is selected.
/// Precedence once every element is observed: <see cref="JwkSelectionOutcome.PrivateOrSymmetricMemberPresent"/> outranks
/// <see cref="JwkSelectionOutcome.MultipleKeysMatched"/> outranks <see cref="JwkSelectionOutcome.Selected"/> and
/// <see cref="JwkSelectionOutcome.NoMatch"/>.
/// </summary>
internal sealed class JwkSetJudgement
{
    /// <summary>Starts the judgement of a set.</summary>
    /// <param name="keyIdNamed">Whether the selection names a <c>kid</c>.</param>
    internal JwkSetJudgement(bool keyIdNamed)
    {
        KeyIdNamed = keyIdNamed;
    }


    /// <summary>Whether the selection names a <c>kid</c>.</summary>
    private bool KeyIdNamed { get; }

    /// <summary>Whether an element observed carries private or symmetric material.</summary>
    private bool CarriesPrivateOrSymmetricMember { get; set; }

    /// <summary>How many elements count toward the selection.</summary>
    private int MatchCount { get; set; }

    /// <summary>Whether the first counted element was selected.</summary>
    private bool FirstMatchSelected { get; set; }


    /// <summary>Observes one element of the set's <c>keys</c>.</summary>
    /// <param name="carriesPrivateOrSymmetricMember">Whether the element carries private or symmetric material.</param>
    /// <param name="keyIdMatches">Whether the element's <c>kid</c> is the one named.</param>
    /// <param name="useEligible">Whether the element's <c>use</c> is eligible.</param>
    /// <returns><see langword="true"/> when this element is the one the selection answers, if it answers one.</returns>
    internal bool Observe(bool carriesPrivateOrSymmetricMember, bool keyIdMatches, bool useEligible)
    {
        CarriesPrivateOrSymmetricMember |= carriesPrivateOrSymmetricMember;

        if(!(KeyIdNamed ? keyIdMatches : useEligible))
        {
            return false;
        }

        MatchCount++;

        if(MatchCount == 1 && useEligible)
        {
            FirstMatchSelected = true;

            return true;
        }

        return false;
    }


    /// <summary>The outcome the observed elements decide.</summary>
    internal JwkSelectionOutcome Outcome => CarriesPrivateOrSymmetricMember
        ? JwkSelectionOutcome.PrivateOrSymmetricMemberPresent
        : MatchCount switch
        {
            0 => JwkSelectionOutcome.NoMatch,
            1 => FirstMatchSelected ? JwkSelectionOutcome.Selected : JwkSelectionOutcome.NoMatch,
            _ => JwkSelectionOutcome.MultipleKeysMatched
        };
}
