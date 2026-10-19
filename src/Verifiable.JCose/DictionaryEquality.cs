using System.ComponentModel;

namespace Verifiable.JCose;

/// <summary>
/// Shared dictionary equality and hash code computation for JWT types.
/// </summary>
/// <remarks>
/// The value type is the dictionary's own: a JOSE part holds a present JSON <c>null</c> as a member with no value, so
/// its values are nullable, while a JSON Web Key's are not; both compare through this one implementation.
/// </remarks>
[EditorBrowsable(EditorBrowsableState.Never)]
public static class DictionaryEquality
{
    /// <summary>
    /// Compares two dictionaries for value equality.
    /// </summary>
    /// <typeparam name="TValue">The dictionaries' value type.</typeparam>
    /// <param name="left">The first dictionary to compare.</param>
    /// <param name="right">The second dictionary to compare.</param>
    /// <returns><see langword="true"/> if the dictionaries have the same key-value pairs; otherwise, <see langword="false"/>.</returns>
    public static bool DictionariesEqual<TValue>(Dictionary<string, TValue>? left, Dictionary<string, TValue>? right)
    {
        if(left is null && right is null)
        {
            return true;
        }

        if(left is null || right is null)
        {
            return false;
        }

        if(left.Count != right.Count)
        {
            return false;
        }

        foreach(KeyValuePair<string, TValue> kvp in left)
        {
            if(!right.TryGetValue(kvp.Key, out TValue? value) || !Equals(kvp.Value, value))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Computes a hash code from dictionary contents, ordered by key.
    /// </summary>
    /// <typeparam name="TValue">The dictionary's value type.</typeparam>
    /// <param name="dictionary">The dictionary to hash.</param>
    /// <returns>A hash code based on the dictionary's key-value pairs.</returns>
    public static int GetDictionaryHashCode<TValue>(Dictionary<string, TValue>? dictionary)
    {
        if(dictionary is null)
        {
            return 0;
        }

        var hash = new HashCode();
        foreach(KeyValuePair<string, TValue> kvp in dictionary.OrderBy(x => x.Key, StringComparer.Ordinal))
        {
            hash.Add(kvp.Key);
            hash.Add(kvp.Value);
        }

        return hash.ToHashCode();
    }
}
