using System;
using System.Buffers;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Verifiable.Cryptography;


namespace Verifiable.Security.Windows
{
    /// <summary>
    /// A Windows specific memory encryption wrapper.
    /// </summary>
    /// <remarks>
    /// This can only limit exposure of secrets in memory if they are held for
    /// a longer time. See more at <see cref="SecureMemory"/> remarks.</remarks>
    [SupportedOSPlatform("windows")]
    public sealed class EncryptedMemoryWindows: SensitiveMemory
    {
        /// <summary>
        /// The entropy used to encrypt memory.
        /// </summary>
        private byte[] Entropy { get; }

        /// <summary>
        /// The scope used for data protection.
        /// </summary>
        private DataProtectionScope DataProtectionScope { get; }


        /// <summary>
        /// A default constructor.
        /// </summary>
        /// <param name="sensitiveMemory">The data to encrypt.</param>
        /// <param name="entropy">The entropy to use in encryption decryption actions.</param>
        /// <param name="protectionScope">The data protection scope.</param>
        /// <param name="protectedMemoryPool">The more pool in which to store the encrypted data.</param>
        public EncryptedMemoryWindows(byte[] sensitiveMemory, byte[] entropy, DataProtectionScope protectionScope, MemoryPool<byte> protectedMemoryPool): 
            base(TransformToEncryptedMemory(sensitiveMemory, entropy, protectionScope, protectedMemoryPool), CryptoTags.WindowsPlatformEncrypted)
        {
            ArgumentNullException.ThrowIfNull(sensitiveMemory);
            ArgumentNullException.ThrowIfNull(entropy);
            ArgumentNullException.ThrowIfNull(protectedMemoryPool);

            Entropy = entropy;
            DataProtectionScope = protectionScope;
        }


        /// <inheritdoc />
        public TResult WithSensitiveMemory<TResult>(ReadOnlySpanFunc<byte, TResult> sensitiveFunc)
        {
            ReadOnlySpan<byte> unEncryptedData = ProtectedData.Unprotect(AsReadOnlySpan().ToArray(), Entropy, DataProtectionScope);
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
        private static IMemoryOwner<byte> TransformToEncryptedMemory(byte[] sensitiveMemory, byte[] entropy, DataProtectionScope protectionScope, MemoryPool<byte> protectedMemoryPool)
        {
            //The parameters are known to be non-null as they're checked in the constructor.
            
            var encryptedData = ProtectedData.Protect(sensitiveMemory, entropy, protectionScope);
            var bufferedMemory = protectedMemoryPool.Rent(encryptedData.Length);
            encryptedData.CopyTo(bufferedMemory.Memory.Span);

            return bufferedMemory;
        }
    }
}
