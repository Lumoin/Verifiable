using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace DotDecentralized.Core.Cryptography
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
    /// <returns>The signing result</returns>
    public delegate TResult SigningFunction<TPrivateKeyBytes, TDataToSign, out TResult>(ReadOnlySpan<TPrivateKeyBytes> privateKeyTypes, ReadOnlySpan<TDataToSign> dataToSign, MemoryPool<byte> signaturePool) where TResult: Signature;

    /// <summary>
    /// Encapsulates a method that receives objects of type read-only span <typeparamref name="T"/>
    /// and return a result of type <typeparamref name="TResult"/>.
    /// </summary>
    /// <typeparam name="T">The type of the objects in the read-only span.</typeparam>
    /// <typeparam name="TResult">The type of the result object.</typeparam>
    /// <param name="input">A read-only span of objects of type <typeparamref name="T"/>.</param>
    /// <returns>A result of type <typeparamref name="TResult"/>.</returns>
    public delegate TResult ReadOnlySpanFunc<T, out TResult>(ReadOnlySpan<T> input);


    /// <summary>
    /// A base class for memory that makes it implicit the wrapped memory is sensitive in some specific way.
    /// It could be private key, public key or other sensitive data. The implementation is responsible for
    /// unwrapping the memory during operations.
    /// </summary>
    /// <remarks>
    /// Sensitive data may be present in crash dumps, page files or temporary variables in memory
    /// or in other places. When possible, security sensitive operations should be done on locked systems
    /// with restricted priviledges (e.g. no crash dumps sent anywhere).
    /// </remarks>
    public abstract class SensitiveMemory: IDisposable
    {
        /// <summary>
        /// Detects and prevents redudant dispose calls.
        /// </summary>
        private bool disposed;

        /// <summary>
        /// The piece of sensitive data.
        /// </summary>
        protected readonly IMemoryOwner<byte> sensitiveData;


        /// <summary>
        /// Sensitive memory default constructor.
        /// </summary>
        /// <param name="sensitiveMemory">The piece of sensitive memory that is wrapped and owned.</param>
        protected SensitiveMemory(IMemoryOwner<byte> sensitiveMemory)
        {
            sensitiveData = sensitiveMemory ?? throw new ArgumentNullException(nameof(sensitiveMemory));
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
                // Dispose managed state (managed objects).
                sensitiveData?.Dispose();
            }

            disposed = true;
        }
    }
}
