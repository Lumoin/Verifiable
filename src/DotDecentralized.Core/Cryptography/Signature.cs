using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace DotDecentralized.Core.Cryptography
{
    /// <summary>
    /// Represents a signature.
    /// </summary>
    public class Signature: SensitiveMemory
    {
        /// <summary>
        /// A Signature constructor.
        /// </summary>
        /// <param name="sensitiveMemory">The byte array that represents a signature.</param>
        public Signature(IMemoryOwner<byte> sensitiveMemory): base(sensitiveMemory) { }

        /// <summary>
        /// An implicit conversion from <see cref="Signature"/> to <see cref="ReadOnlySpan{byte}"/>.
        /// </summary>
        /// <param name="signature"></param>
        [DebuggerStepThrough, MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static implicit operator ReadOnlySpan<byte>(Signature signature) => signature.sensitiveData.Memory.Span;
    }
}
