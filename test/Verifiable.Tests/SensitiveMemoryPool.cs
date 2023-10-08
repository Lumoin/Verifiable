using System;
using System.Buffers;

namespace Verifiable.Core
{
    /// <summary>
    /// A <see cref="MemoryPool{T}"/> implementation that separates and tracks
    /// memory for cryptographic operations separately from other memory.    
    /// </summary>
    /// <typeparam name="T">The cryptographic data type.</typeparam>
    /// <remarks>The rented memory is cleared when returned but it will not be garbage collected.</remarks>    
    public abstract class SensitiveMemoryPool<T>: MemoryPool<T>
    {
        /// <summary>
        /// The backing <see cref="ArrayPool{T}"/> for the data to be rented.
        /// </summary>
        /// <remarks>
        /// The .NET ArrayPool implementation does not release the created buffers
        /// for the garbage collector.
        /// </remarks>
        private static ArrayPool<T> ArrayPool => ArrayPool<T>.Create();

        /// <inheritdoc />
        public override int MaxBufferSize => int.MaxValue;

        /// <summary>
        /// Gets a singleton instance of a memory pool based on arrays.
        /// </summary>
        /// <remarks>A singleton instance of memory pool for cryptographic material.</remarks>
        public static new SensitiveMemoryPool<T>.ConcreteImplementation Shared => new();


        /// <summary>
        /// Returns a memory block capable of holding exactly <paramref name="exactBufferSize"/> elements of <typeparamref name="T"/>.
        /// </summary>
        /// <param name="exactBufferSize">The exact buffer size to rent.</param>
        /// <returns>Returns a memory block capable of holding exactly <paramref name="exactBufferSize"/> elements of <typeparamref name="T"/></returns>        
        public override IMemoryOwner<T> Rent(int exactBufferSize) => SensitiveMemoryPool<T>.RentCore(SensitiveMemoryPool<T>.ArrayPool, exactBufferSize);


        /// <inheritdoc />        
        protected override void Dispose(bool disposing) { }


        /// <summary>
        /// Creates a new instance of <see cref="SensitiveMemoryOwner"/>.
        /// </summary>
        /// <param name="arrayPool">The <see cref="ArrayPool{T}"/> instance to use to rent cryptographic data.</param>
        /// <param name="exactBufferSize">The exact buffer size to rent.</param>
        /// <returns></returns>
        private static SensitiveMemoryOwner RentCore(ArrayPool<T> arrayPool, int exactBufferSize) => new(arrayPool, exactBufferSize);


        /// <summary>
        /// The concrete implementation of renting from the pool
        /// for cryptographic material.
        /// </summary>
        public sealed class ConcreteImplementation: SensitiveMemoryPool<T>
        {
            /// <summary>
            /// Rents exactly the requested size memory block to track cryptographic material.
            /// </summary>
            /// <param name="exactBufferSize">The exact size of the buffer.</param>
            /// <returns>The tracked block of cryptographic memory material.</returns>
            public new SensitiveMemoryOwner Rent(int exactBufferSize) => RentCore(ArrayPool, exactBufferSize);
        }


        /// <summary>
        /// Tracks cryptographic memory blocks in a separate pool.
        /// </summary>
        /// <remarks>The memory tracked is exactly the size requested.</remarks>
        public struct SensitiveMemoryOwner: IMemoryOwner<T>
        {
            /// <summary>
            /// The rented array. This may be larger than the exactBufferSize parameter received.
            /// </summary>
            private T[]? rentedArray;

            /// <summary>
            /// This is the instance tracking the actual data
            /// </summary>
            private Memory<T> memory;

            /// <summary>
            /// This is the pool from which the data was rented.
            /// </summary>
            private readonly ArrayPool<T> arrayPool;


            /// <summary>
            /// A constructor for cryptographic material.
            /// </summary>
            /// <param name="arrayPool">The pool from which to rent the data.</param>
            /// <param name="exactBufferSize">The exact buffer size to rent.</param>
            /// <exception cref="ArgumentOutOfRangeException">If <paramref name="exactBufferSize"/> is less than 0.</exception>
            public SensitiveMemoryOwner(ArrayPool<T> arrayPool, int exactBufferSize)
            {
                ArgumentNullException.ThrowIfNull(arrayPool);
                if(exactBufferSize < 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(exactBufferSize));
                }

                this.arrayPool = arrayPool;
                rentedArray = arrayPool.Rent(exactBufferSize);
                memory = new Memory<T>(rentedArray, 0, exactBufferSize);
            }


            /// <summary>
            /// A <see cref="Memory{T}"/> of the rented instance.
            /// </summary>
            /// <exception cref="ObjectDisposedException" />
            public Memory<T> Memory
            {
                get
                {
                    if(rentedArray == null)
                    {
                        throw new ObjectDisposedException(nameof(SensitiveMemoryOwner));
                    }

                    return memory;
                }
            }


            /// <summary>
            /// Returns the rented buffer to the pool. Clears the memory.
            /// </summary>
            public void Dispose()
            {
                if(rentedArray != null)
                {
                    ((Span<T>)rentedArray).Clear();
                    ArrayPool<T>.Shared.Return(rentedArray);
                    memory = null;
                    rentedArray = null;
                }
            }
        }
    }
}
