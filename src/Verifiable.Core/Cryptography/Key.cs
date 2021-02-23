using System;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// Represent a cryptographic key.
    /// </summary>
    public abstract class Key: IDisposable
    {
        /// <summary>
        /// Detects and prevents redudant dispose calls.
        /// </summary>
        private bool disposed;

        /// <summary>
        /// The piece of memory held by this key.
        /// </summary>
        protected readonly SensitiveMemory KeyMemory;

        /// <summary>
        /// The key identity.
        /// </summary>
        public string Id { get; }

        /// <summary>
        /// PlainMemory constructor.
        /// </summary>
        /// <param name="sensitiveMemory">The piece of memory representing this key.</param>
        protected Key(SensitiveMemory sensitiveMemory, string id)
        {
            KeyMemory = sensitiveMemory ?? throw new ArgumentNullException(nameof(sensitiveMemory));
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
                KeyMemory.Dispose();
            }

            disposed = true;
        }
    }
}
