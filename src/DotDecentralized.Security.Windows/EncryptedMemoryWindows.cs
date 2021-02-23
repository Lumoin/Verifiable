using DotDecentralized.Core.Cryptography;
using System;
using System.Buffers;
using System.Runtime.Versioning;
using System.Security.Cryptography;

[assembly: SupportedOSPlatform("windows")]
namespace DotDecentralized.Security.Windows
{
    /// <summary>
    /// A Windows specific memory encryption wrapper.
    /// </summary>
    /// <remarks>
    /// This can only limit exposure of secrets in memory if they are held for
    /// a longer time. See more at <see cref="SecureMemory"/> remarks.</remarks>
    public sealed class EncryptedMemoryWindows: SensitiveMemory
    {
        /// <summary>
        /// The entropy used to encrypt memory.
        /// </summary>
        private readonly byte[] entropy;

        /// <summary>
        /// The scope used for data protection.
        /// </summary>
        private readonly DataProtectionScope dataProtectionScope;


        /// <summary>
        /// A default constructor.
        /// </summary>
        /// <param name="sensitiveMemory">The data to encrypt.</param>
        /// <param name="entropy">The entropy to use in encryption decryption actions.</param>
        /// <param name="protectionScope">The data protection scope.</param>
        /// <param name="protectedMemoryPool">The more pool in which to store the encrypted data.</param>
        public EncryptedMemoryWindows(byte[] sensitiveMemory, byte[] entropy, DataProtectionScope protectionScope, MemoryPool<byte> protectedMemoryPool): base(EncryptedMemory(sensitiveMemory, entropy, protectionScope, protectedMemoryPool))
        {
            if(entropy == null)
            {
                throw new ArgumentNullException(nameof(entropy));
            }

            this.entropy = entropy;
            this.dataProtectionScope = protectionScope;
        }


        /// <inheritdoc />
        public TResult WithSensitiveMemory<TResult>(ReadOnlySpanFunc<byte, TResult> sensitiveFunc)
        {
            ReadOnlySpan<byte> unEncryptedData = ProtectedData.Unprotect(this.sensitiveData.Memory.ToArray(), this.entropy, DataProtectionScope.LocalMachine);
            return sensitiveFunc(unEncryptedData);
        }


        /// <summary>
        /// A helper function to turn data received in constructor to encrypted in a buffer and stored in the base class.
        /// </summary>
        /// <param name="sensitiveMemory">The data to encrypt.</param>
        /// <param name="entropy">The entropy to use in encryption decryption actions.</param>
        /// <param name="protectionScope">The data protection scope.</param>
        /// <param name="protectedMemoryPool">The more pool in which to store the encrypted data.</param>
        /// <returns>The encrypted memory in a buffer.</returns>
        private static IMemoryOwner<byte> EncryptedMemory(byte[] sensitiveMemory, byte[] entropy, DataProtectionScope protectionScope, MemoryPool<byte> protectedMemoryPool)
        {
            if(sensitiveMemory == null)
            {
                throw new ArgumentNullException(nameof(sensitiveMemory));
            }

            //TODO: Look if https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.Cryptography.ProtectedData/src/System/Security/Cryptography/ProtectedData.cs#L78
            //ought to be replicated and use pool directly.
            var encryptedData = ProtectedData.Protect(sensitiveMemory!, entropy, protectionScope);
            var bufferedMemory = protectedMemoryPool.Rent(encryptedData.Length);
            encryptedData.CopyTo(bufferedMemory.Memory.Span);

            return bufferedMemory;
        }
    }
}
