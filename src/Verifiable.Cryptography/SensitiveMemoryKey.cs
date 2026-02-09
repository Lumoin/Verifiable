using System;

namespace Verifiable.Cryptography
{
    /// <summary>
    /// Represent a cryptographic key that is held in memory.
    /// </summary>
    public abstract class SensitiveMemoryKey: IDisposable
    {
        /// <summary>
        /// Detects and prevents redundant dispose calls.
        /// </summary>
        private bool disposed;

        /// <summary>
        /// The piece of memory held by this key.
        /// </summary>
        protected SensitiveMemory KeyMaterial { get; }

        /// <summary>
        /// The key identity.
        /// </summary>
        public string Id { get; }

        /// <summary>
        /// Key constructor.
        /// </summary>
        /// <param name="keyMaterial">The piece of memory representing this key.</param>
        /// <param name="id">The identity of this key.</param>
        protected SensitiveMemoryKey(SensitiveMemory keyMaterial, string id)
        {
            KeyMaterial = keyMaterial ?? throw new ArgumentNullException(nameof(keyMaterial));
            Id = id ?? throw new ArgumentNullException(nameof(id));
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
                KeyMaterial.Dispose();
            }

            disposed = true;
        }
    }
}
