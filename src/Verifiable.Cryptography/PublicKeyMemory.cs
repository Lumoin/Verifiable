using System.Buffers;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography
{
    /// <summary>
    /// A wrapper for public key memory that has the capability to
    /// unwrap the data during public key operations.
    /// </summary>
    /// <remarks>If counters, statistics or other statistics or functionality
    /// is needed this class can be inherited.</remarks>
    public class PublicKeyMemory: SensitiveMemory, IEquatable<PublicKeyMemory>
    {
        /// <summary>
        /// KeyMemory constructor.
        /// </summary>
        /// <param name="sensitiveMemory">The piece of sensitive data.</param>
        /// <param name="tag">Tags the memory with out-of-band information such as key material information.</param>
        public PublicKeyMemory(IMemoryOwner<byte> sensitiveMemory, Tag tag): base(sensitiveMemory, tag)
        {
            ArgumentNullException.ThrowIfNull(sensitiveMemory);
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool Equals([NotNullWhen(true)] PublicKeyMemory? other)
        {
            //The reason for this is that Memory<T> does not implement deep hashing
            //due to performance concerns.
            return other is not null && base.Equals(other);
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([NotNullWhen(true)] object? obj) => (obj is PublicKeyMemory p) && Equals(p);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in PublicKeyMemory p1, in PublicKeyMemory p2) => Equals(p1, p2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in PublicKeyMemory p1, in PublicKeyMemory p2) => !Equals(p1, p2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in object p1, in PublicKeyMemory p2) => Equals(p1, p2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in PublicKeyMemory p1, in object p2) => Equals(p1, p2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in object p1, in PublicKeyMemory p2) => !Equals(p1, p2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in PublicKeyMemory p1, in object p2) => !Equals(p1, p2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            return base.GetHashCode();
        }


        /// <summary>
        /// An unwrap function for this memory.
        /// </summary>
        /// <typeparam name="TArg0">The type of the argument given to sensitive function.</typeparam>
        /// <typeparam name="TArg1"> argument that can be given for the function.</typeparam>
        /// <typeparam name="TResult">The result type of the function.</typeparam>
        /// <param name="sensitiveFunc">The function that uses this memory. Example caller: <see cref="PublicKey"/>.</param>
        /// <param name="arg0">An argument given to <paramref name="sensitiveFunc"/>.</param>
        /// <param name="arg1">An argument given to <paramref name="sensitiveFunc"/>.</param>
        /// <returns>The result of calling An argument given to <paramref name="sensitiveFunc"/>.</returns>
        public ValueTask<TResult> WithKeyBytesAsync<TArg0, TArg1, TResult>(VerificationFunction<byte, TArg0, TArg1, ValueTask<TResult>> sensitiveFunc, ReadOnlyMemory<TArg0> arg0, TArg1 arg1)
        {
            ArgumentNullException.ThrowIfNull(sensitiveFunc);
            return sensitiveFunc(MemoryOwner.Memory, arg0, arg1);
        }
    }
}
