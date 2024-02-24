using System;
using System.Buffers;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// Encapsulates a method that receives objects of type read-only span <typeparamref name="TPublicKeyBytes"/>
    /// and return a result of type <typeparamref name="TResult"/> that is likely <see cref="bool"/>.
    /// The function should verify the data using key and signature.
    /// </summary>
    /// <typeparam name="TPublicKeyBytes">The type of the objects in the read-only span. Likely <see cref="byte"/>.</typeparam>
    /// <typeparam name="TDataToVerify">Verification data type. Likely <see cref="byte"/>.</typeparam>
    /// <typeparam name="TSignature">A previously calcuated signature.</typeparam>
    /// <typeparam name="TResult">The result of verification type. Likely <see cref="bool"/>.</typeparam>
    /// <param name="publicKeyBytes">The public key bytes representation.</param>
    /// <param name="dataToVerify">The data to verify.</param>
    /// <param name="signature">The signature.</param>
    /// <returns>The verification result. <em>True</em> if verification succeeeds. <em>False</em> otherwise.</returns>
    public delegate TResult VerificationFunction<TPublicKeyBytes, TDataToVerify, in TSignature, out TResult>(ReadOnlySpan<TPublicKeyBytes> publicKeyBytes, ReadOnlySpan<TDataToVerify> dataToVerify, TSignature signature);

    /// <summary>
    /// Encapsulates a method that receives objects of type read-only span <typeparamref name="TPublicKeyBytes"/>
    /// and return a result of type <typeparamref name="TResult"/> that is likely <see cref="bool"/>.
    /// The function should verify the data using key and signature.
    /// </summary>
    /// <typeparam name="TPublicKeyBytes">The type of the objects in the read-only span. Likely <see cref="byte"/>.</typeparam>
    /// <typeparam name="TDataToVerify">Verification data type. Likely <see cref="byte"/>.</typeparam>
    /// <typeparam name="TSignatureBytes">Bytes of a previously calcuated signature.</typeparam>
    /// <typeparam name="TResult">The result of verification type. Likely <see cref="bool"/>.</typeparam>
    /// <param name="publicKeyBytes">The public key bytes representation.</param>
    /// <param name="dataToVerify">The data to verify.</param>
    /// <param name="signatureBytes">The signature.</param>
    /// <returns>The verification result. <em>True</em> if verification succeeeds. <em>False</em> otherwise.</returns>
    public delegate TResult VerificationFunctionWithBytes<TPublicKeyBytes, TDataToVerify, TSignatureBytes, out TResult>(ReadOnlySpan<TPublicKeyBytes> publicKeyBytes, ReadOnlySpan<TDataToVerify> dataToVerify, ReadOnlySpan<TSignatureBytes> signatureBytes);

    /// <summary>
    /// Encapsulates a method that receives objects of type read-only span <typeparamref name="TPrivateKeyBytes"/>
    /// and return a result of type <typeparamref name="TResult"/> that is likely <see cref="bool"/>.
    /// The function should calculate a signature of the data.
    /// </summary>
    /// <typeparam name="TPrivateKeyBytes">The type of the objects in the read-only span. Likely <see cref="byte"/>.</typeparam>
    /// <typeparam name="TDataToSign">The data type from which to calculate signature. Likely <see cref="byte"/>.</typeparam>
    /// <typeparam name="TResult">The result of verification type.</typeparam>
    /// <param name="privateKeyTypes">The private key bytes representation.</param>
    /// <param name="dataToSign">The data to calculate a signature from.</param>
    /// <param name="signaturePool">The memory pool from which to rent signature space.</param>
    /// <returns>The signing result.</returns>
    public delegate TResult SigningFunction<TPrivateKeyBytes, TDataToSign, out TResult>(ReadOnlySpan<TPrivateKeyBytes> privateKeyTypes, ReadOnlySpan<TDataToSign> dataToSign, MemoryPool<byte> signaturePool);

    /// <summary>
    /// Encapsulates a method that receives objects of type read-only span <typeparamref name="T"/>
    /// and return a result of type <typeparamref name="TResult"/>.
    /// </summary>
    /// <typeparam name="T">The type of the objects in the read-only span.</typeparam>
    /// <typeparam name="TResult">The type of the result object.</typeparam>
    /// <param name="input">A read-only span of objects of type <typeparamref name="T"/>.</param>
    /// <returns>A result of type <typeparamref name="TResult"/>.</returns>
    public delegate TResult ReadOnlySpanFunc<T, out TResult>(ReadOnlySpan<T> input);

    
    public abstract class SensitiveData
    {
        public Tag Tag { get; }


        protected SensitiveData(Tag tag)
        {
            ArgumentNullException.ThrowIfNull(tag, nameof(tag));
            Tag = tag;
        }
    }

    

    /// <summary>
    /// A base class for memory that makes it implicit the wrapped memory is sensitive in some specific way.
    /// It could be private key, public key or other sensitive data. The implementation is responsible for
    /// unwrapping the memory during operations.
    /// </summary>
    /// <remarks>
    /// Sensitive data may be present in crash dumps, page files or temporary variables in memory
    /// or in other places. When possible, security sensitive operations should be done on locked systems
    /// with restricted privileges (e.g. no crash dumps sent anywhere).
    /// </remarks>
    public abstract class SensitiveMemory: SensitiveData, IDisposable, IEquatable<SensitiveMemory>
    {
        /// <summary>
        /// Detects and prevents redundant dispose calls.
        /// </summary>
        private bool disposed;
        
        /// <summary>
        /// The piece of sensitive data.
        /// </summary>
        private readonly IMemoryOwner<byte> sensitiveMemory;

        
        /// <summary>
        /// Sensitive memory default constructor.
        /// </summary>
        /// <param name="sensitiveMemory">The piece of sensitive memory that is wrapped and owned.</param>
        /// <param name="tag">Tags the memory with out-of-band information such as key material information.</param>
        protected SensitiveMemory(IMemoryOwner<byte> sensitiveMemory, Tag tag): base(tag)
        {
            ArgumentNullException.ThrowIfNull(sensitiveMemory);            
            this.sensitiveMemory = sensitiveMemory;            
        }


        /// <summary>
        /// Exposes the internal sensitive memory for some special purposes, such as formatting.
        /// </summary>
        public ReadOnlySpan<byte> AsReadOnlySpan()
        {
            return (ReadOnlySpan<byte>)sensitiveMemory.Memory.Span;
        }


        /// <inheritdoc />
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }


        /// <summary>
        /// Allows inherited resources to hook into application defined tasks with freeing,
        /// releasing, or resetting unmanaged resources.
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if(disposed)
            {
                return;
            }

            if(disposing)
            {
                //Clearing the memory is in case there is not a pooled memory owner
                //that clears it. One example is Verifiable.Core.SensitiveMemoryPool.
                sensitiveMemory.Memory.Span.Clear();
                sensitiveMemory?.Dispose();                
            }

            disposed = true;
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool Equals([NotNullWhen(true)] SensitiveMemory? other)
        {
            //The reason for this is that Memory<T> does not implement deep hashing
            //due to performance concerns.
            return other is not null
                && MemoryExtensions.SequenceEqual(sensitiveMemory.Memory.Span, other.sensitiveMemory.Memory.Span);
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([NotNullWhen(true)] object? o) => (o is SensitiveMemory s) && Equals(s);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in SensitiveMemory s1, in SensitiveMemory s2) => Equals(s1, s2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in SensitiveMemory s1, in SensitiveMemory s2) => !Equals(s1, s2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in object s1, in SensitiveMemory s2) => Equals(s1, s2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in SensitiveMemory s1, in object s2) => Equals(s1, s2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in object s1, in SensitiveMemory s2) => !Equals(s1, s2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in SensitiveMemory s1, in object s2) => !Equals(s1, s2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            //The reason for this is that Memory<T> does not implement deep hashing
            //due to performance concerns.
            var hash = new HashCode();
            ReadOnlySpan<byte> memorySpan = sensitiveMemory.Memory.Span;
            for(int i = 0; i < memorySpan.Length; ++i)
            {
                hash.Add(memorySpan[i].GetHashCode());
            }

            return hash.ToHashCode();
        }
    }
}
