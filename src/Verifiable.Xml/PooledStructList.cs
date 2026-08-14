using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Verifiable.Xml;

/// <summary>
/// A growable list of unmanaged structs stored in buffers rented from a caller-supplied
/// <see cref="MemoryPool{T}"/> of bytes, so every buffer the XML reading surface holds is pool-allocated
/// and returned on <see cref="Dispose"/>. Growth rents a larger buffer, copies and returns the old one.
/// </summary>
/// <typeparam name="T">The unmanaged element type; reinterpreted over the rented byte buffer.</typeparam>
internal sealed class PooledStructList<T>: IDisposable where T: unmanaged
{
    /// <summary>The pool the backing buffer is rented from.</summary>
    private MemoryPool<byte> Pool { get; }

    /// <summary>The currently rented backing buffer.</summary>
    private IMemoryOwner<byte>? owner;

    /// <summary>The number of elements in the list.</summary>
    private int count;


    /// <summary>
    /// The number of elements in the list.
    /// </summary>
    public int Count => count;

    /// <summary>
    /// The number of elements the current backing buffer can hold.
    /// </summary>
    public int Capacity => owner is null ? 0 : owner.Memory.Length / Unsafe.SizeOf<T>();


    /// <summary>
    /// Creates the list with an initial capacity rented from the pool.
    /// </summary>
    /// <param name="pool">The pool to rent from.</param>
    /// <param name="initialCapacity">The initial element capacity; at least one.</param>
    public PooledStructList(MemoryPool<byte> pool, int initialCapacity)
    {
        Pool = pool;
        owner = pool.Rent(checked(Math.Max(1, initialCapacity) * Unsafe.SizeOf<T>()));
    }


    /// <summary>
    /// A mutable reference to the element at the given index.
    /// </summary>
    /// <param name="index">The element index; less than <see cref="Count"/>.</param>
    public ref T this[int index] => ref MemoryMarshal.Cast<byte, T>(owner!.Memory.Span)[index];


    /// <summary>
    /// The elements as a read-only span. Invalidated by any operation that grows the list.
    /// </summary>
    /// <returns>A span over the current elements.</returns>
    public ReadOnlySpan<T> AsSpan()
    {
        return MemoryMarshal.Cast<byte, T>(owner!.Memory.Span)[..count];
    }


    /// <summary>
    /// The elements as a mutable span. Invalidated by any operation that grows the list.
    /// </summary>
    /// <returns>A mutable span over the current elements.</returns>
    public Span<T> AsMutableSpan()
    {
        return MemoryMarshal.Cast<byte, T>(owner!.Memory.Span)[..count];
    }


    /// <summary>
    /// Appends one element.
    /// </summary>
    /// <param name="item">The element to append.</param>
    /// <returns>The index the element was stored at.</returns>
    public int Add(in T item)
    {
        EnsureCapacity(count + 1);
        MemoryMarshal.Cast<byte, T>(owner!.Memory.Span)[count] = item;

        return count++;
    }


    /// <summary>
    /// Appends a run of elements.
    /// </summary>
    /// <param name="items">The elements to append.</param>
    /// <returns>The index the first appended element was stored at.</returns>
    public int AddRange(ReadOnlySpan<T> items)
    {
        EnsureCapacity(count + items.Length);
        items.CopyTo(MemoryMarshal.Cast<byte, T>(owner!.Memory.Span)[count..]);
        int start = count;
        count += items.Length;

        return start;
    }


    /// <summary>
    /// Inserts one element at the given index, shifting the elements at and after it one position up.
    /// </summary>
    /// <param name="index">The insertion index; at most <see cref="Count"/>.</param>
    /// <param name="item">The element to insert.</param>
    public void Insert(int index, in T item)
    {
        EnsureCapacity(count + 1);
        Span<T> span = MemoryMarshal.Cast<byte, T>(owner!.Memory.Span);
        span[index..count].CopyTo(span[(index + 1)..]);
        span[index] = item;
        count++;
    }


    /// <summary>
    /// Removes the element at the given index, shifting the elements after it one position down.
    /// </summary>
    /// <param name="index">The element index; less than <see cref="Count"/>.</param>
    public void RemoveAt(int index)
    {
        Span<T> span = MemoryMarshal.Cast<byte, T>(owner!.Memory.Span);
        span[(index + 1)..count].CopyTo(span[index..]);
        count--;
    }


    /// <summary>
    /// Cuts the list back to the given element count without releasing capacity.
    /// </summary>
    /// <param name="newCount">The new element count; at most <see cref="Count"/>.</param>
    public void Truncate(int newCount)
    {
        count = newCount;
    }


    /// <summary>
    /// Returns the backing buffer to the pool.
    /// </summary>
    public void Dispose()
    {
        owner?.Dispose();
        owner = null;
        count = 0;
    }


    /// <summary>
    /// Grows the backing buffer so it can hold at least the required element count.
    /// </summary>
    /// <param name="requiredCount">The element count the buffer must hold.</param>
    private void EnsureCapacity(int requiredCount)
    {
        if(requiredCount <= Capacity)
        {
            return;
        }

        int newCapacity = Math.Max(Capacity * 2, requiredCount);
        IMemoryOwner<byte> newOwner = Pool.Rent(checked(newCapacity * Unsafe.SizeOf<T>()));
        owner!.Memory.Span[..(count * Unsafe.SizeOf<T>())].CopyTo(newOwner.Memory.Span);
        owner.Dispose();
        owner = newOwner;
    }
}
