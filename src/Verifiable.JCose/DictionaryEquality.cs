using System.ComponentModel;

namespace Verifiable.JCose;

/// <summary>
/// Shared dictionary equality and hash code computation for JWT types.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public static class DictionaryEquality
{
    /// <summary>
    /// Compares two dictionaries for value equality.
    /// </summary>
    /// <param name="left">The first dictionary to compare.</param>
    /// <param name="right">The second dictionary to compare.</param>
    /// <returns><see langword="true"/> if the dictionaries have the same key-value pairs; otherwise, <see langword="false"/>.</returns>
    public static bool DictionariesEqual(Dictionary<string, object>? left, Dictionary<string, object>? right)
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

        foreach(KeyValuePair<string, object> kvp in left)
        {
            if(!right.TryGetValue(kvp.Key, out object? value) || !Equals(kvp.Value, value))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Computes a hash code from dictionary contents, ordered by key.
    /// </summary>
    /// <param name="dictionary">The dictionary to hash.</param>
    /// <returns>A hash code based on the dictionary's key-value pairs.</returns>
    public static int GetDictionaryHashCode(Dictionary<string, object>? dictionary)
    {
        if(dictionary is null)
        {
            return 0;
        }

        var hash = new HashCode();
        foreach(KeyValuePair<string, object> kvp in dictionary.OrderBy(x => x.Key))
        {
            hash.Add(kvp.Key);
            hash.Add(kvp.Value);
        }

        return hash.ToHashCode();
    }
}