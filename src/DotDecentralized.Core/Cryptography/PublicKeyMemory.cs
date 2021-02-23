using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace DotDecentralized.Core.Cryptography
{
    /// <summary>
    /// A wrapper for public key memory that has the capability to
    /// unwrap the data during public key operations.
    /// </summary>
    /// <remarks>If counters, statistics or other statistics or functionality
    /// is needed this class can be inherited.</remarks>
    public class PublicKeyMemory: SensitiveMemory
    {
        /// <summary>
        /// KeyMemory constructor.
        /// </summary>
        /// <param name="sensitiveData">The piece of sensitive data.</param>
        public PublicKeyMemory(IMemoryOwner<byte> sensitiveData): base(sensitiveData)
        {
            if(sensitiveData == null)
            {
                throw new ArgumentNullException(nameof(sensitiveData));
            }
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
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public TResult WithKeyBytes<TArg0, TArg1, TResult>(VerificationFunction<byte, TArg0, TArg1, TResult> sensitiveFunc, ReadOnlySpan<TArg0> arg0, TArg1 arg1)
        {
            return sensitiveFunc(sensitiveData.Memory.Span, arg0, arg1);
        }
    }
}
