namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A read-only list that reads differently when it is read again: its first enumeration yields
/// <c>checkedEntries</c>, and every later enumeration yields <c>laterEntries</c>; <see cref="Count"/> and the
/// indexer answer the shape of <c>laterEntries</c> at every read. It stands for an application's lazily computed
/// list, which a reader that reads it more than once reads differently after the first time. It is an
/// <see cref="IReadOnlyList{T}"/> only, never an <see cref="ICollection{T}"/>, so no bulk copy reaches it, and it
/// counts its enumerations, its <see cref="Count"/> reads and its indexer reads apart.
/// </summary>
/// <param name="checkedEntries">The entries the first enumeration yields.</param>
/// <param name="laterEntries">The entries every later enumeration, every <see cref="Count"/> read and every indexer read answer.</param>
internal sealed class ShiftingReadOnlyList(IReadOnlyList<string> checkedEntries, IReadOnlyList<string> laterEntries): IReadOnlyList<string>
{
    /// <summary>How many times the list has been enumerated.</summary>
    public int Enumerations { get; private set; }

    /// <summary>How many times <see cref="Count"/> has been read.</summary>
    public int CountReads { get; private set; }

    /// <summary>How many times an entry has been read through the indexer.</summary>
    public int IndexerReads { get; private set; }


    /// <summary>The number of the later entries, counted as one <see cref="Count"/> read.</summary>
    public int Count
    {
        get
        {
            CountReads++;

            return laterEntries.Count;
        }
    }


    /// <summary>Reads one of the later entries through the indexer, counted as one indexer read.</summary>
    /// <param name="index">The entry's position among the later entries.</param>
    /// <returns>The later entry at <paramref name="index"/>.</returns>
    public string this[int index]
    {
        get
        {
            IndexerReads++;

            return laterEntries[index];
        }
    }


    /// <summary>Enumerates the entries of this reading, counted as one enumeration.</summary>
    /// <returns>An enumerator over <c>checkedEntries</c> for the first enumeration, over <c>laterEntries</c> afterwards.</returns>
    public IEnumerator<string> GetEnumerator()
    {
        Enumerations++;
        IEnumerable<string> entries = Enumerations == 1 ? checkedEntries : laterEntries;

        return entries.GetEnumerator();
    }


    /// <summary>Enumerates the entries of this reading as <see cref="GetEnumerator"/> does.</summary>
    /// <returns>An enumerator over the entries of this reading.</returns>
    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();


    /// <summary>Renders the three counts for an assertion message.</summary>
    /// <returns>The enumerations, the <see cref="Count"/> reads and the indexer reads, in that order.</returns>
    public override string ToString() => $"enumerations {Enumerations} count reads {CountReads} indexer reads {IndexerReads}";
}
