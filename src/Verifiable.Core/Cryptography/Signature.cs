using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Verifiable.Core.Cryptography
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
        /// <param name="tag">Tags the memory with out-of-band information such as key material information.</param>
        public Signature(IMemoryOwner<byte> sensitiveMemory, Tag tag): base(sensitiveMemory, tag) { }

        /// <summary>
        /// An implicit conversion from <see cref="Signature"/> to <see cref="ReadOnlySpan{byte}"/>.
        /// </summary>
        /// <param name="signature"></param>
        [DebuggerStepThrough]
        public static implicit operator ReadOnlySpan<byte>(Signature signature) => signature.AsReadOnlySpan();
    }
}
