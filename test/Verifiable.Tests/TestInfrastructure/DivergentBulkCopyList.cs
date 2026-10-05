namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A read-only collection list whose bulk copy disagrees with its entries: its enumerator, its indexer and
/// <see cref="Count"/> answer <c>entries</c>, and <see cref="CopyTo"/> writes <c>bulkEntries</c> into the array it is
/// handed instead and counts its calls. It stands for an application's list that is an <see cref="IList{T}"/>, which
/// a reader that copies it in bulk reads through <see cref="Count"/> and <see cref="CopyTo"/> rather than through its
/// enumerator, handing the reader's own array to the application. Every mutator throws
/// <see cref="NotSupportedException"/>.
/// </summary>
/// <param name="entries">The entries the enumerator, the indexer and <see cref="Count"/> answer.</param>
/// <param name="bulkEntries">The entries <see cref="CopyTo"/> writes; at most as many as <paramref name="entries"/>.</param>
internal sealed class DivergentBulkCopyList(IReadOnlyList<string> entries, IReadOnlyList<string> bulkEntries): IReadOnlyList<string>, IList<string>
{
    /// <summary>How many times <see cref="CopyTo"/> has been called.</summary>
    public int CopyToCalls { get; private set; }


    /// <summary>The number of the entries.</summary>
    public int Count => entries.Count;


    /// <summary>The list refuses every mutation.</summary>
    public bool IsReadOnly => true;


    /// <summary>Reads one of the entries; a write is refused.</summary>
    /// <param name="index">The entry's position.</param>
    /// <returns>The entry at <paramref name="index"/>.</returns>
    public string this[int index]
    {
        get => entries[index];
        set => throw new NotSupportedException();
    }


    /// <summary>Writes the bulk entries into <paramref name="array"/> from <paramref name="arrayIndex"/> on, in place of the entries, and counts the call.</summary>
    /// <param name="array">The array the caller hands over.</param>
    /// <param name="arrayIndex">The position in <paramref name="array"/> of the first written entry.</param>
    public void CopyTo(string[] array, int arrayIndex)
    {
        ArgumentNullException.ThrowIfNull(array);
        CopyToCalls++;
        for(int position = 0; position < bulkEntries.Count; position++)
        {
            array[arrayIndex + position] = bulkEntries[position];
        }
    }


    /// <summary>Answers whether <paramref name="item"/> is among the entries.</summary>
    /// <param name="item">The entry looked for.</param>
    /// <returns><see langword="true"/> when an entry equals <paramref name="item"/> by ordinal comparison.</returns>
    public bool Contains(string item) => IndexOf(item) >= 0;


    /// <summary>Finds <paramref name="item"/> among the entries.</summary>
    /// <param name="item">The entry looked for.</param>
    /// <returns>The position of the first entry equal to <paramref name="item"/> by ordinal comparison, or -1.</returns>
    public int IndexOf(string item)
    {
        for(int position = 0; position < entries.Count; position++)
        {
            if(string.Equals(entries[position], item, StringComparison.Ordinal))
            {
                return position;
            }
        }

        return -1;
    }


    /// <summary>Enumerates the entries.</summary>
    /// <returns>An enumerator over the entries.</returns>
    public IEnumerator<string> GetEnumerator() => entries.GetEnumerator();


    /// <summary>Enumerates the entries as <see cref="GetEnumerator"/> does.</summary>
    /// <returns>An enumerator over the entries.</returns>
    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();


    /// <summary>Refuses the mutation; the list is read-only.</summary>
    /// <param name="item">The entry that would be added.</param>
    public void Add(string item) => throw new NotSupportedException();


    /// <summary>Refuses the mutation; the list is read-only.</summary>
    public void Clear() => throw new NotSupportedException();


    /// <summary>Refuses the mutation; the list is read-only.</summary>
    /// <param name="index">The position the entry would take.</param>
    /// <param name="item">The entry that would be inserted.</param>
    public void Insert(int index, string item) => throw new NotSupportedException();


    /// <summary>Refuses the mutation; the list is read-only.</summary>
    /// <param name="item">The entry that would be removed.</param>
    /// <returns>Never returns; the call throws.</returns>
    public bool Remove(string item) => throw new NotSupportedException();


    /// <summary>Refuses the mutation; the list is read-only.</summary>
    /// <param name="index">The position of the entry that would be removed.</param>
    public void RemoveAt(int index) => throw new NotSupportedException();


    /// <summary>Renders the count of bulk copies for an assertion message.</summary>
    /// <returns>The number of <see cref="CopyTo"/> calls.</returns>
    public override string ToString() => $"copyto calls {CopyToCalls}";
}
