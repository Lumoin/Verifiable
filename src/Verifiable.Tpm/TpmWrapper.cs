using System;
using Tpm2Lib;

namespace Verifiable.Tpm
{
    /// <summary>
    /// Creates and wraps a <see cref="Tpm2Device"/> and initiates the
    /// correct connection logic based on its type.
    /// </summary>
    public class TpmWrapper: IDisposable
    {
        /// <summary>
        /// Detects and prevents redudant dispose calls.
        /// </summary>
        private bool disposed;

        /// <summary>
        /// The TPM instance <see cref="Tpm"/> refers to.
        /// </summary>
        protected Tpm2Device TpmDevice { get; }

        /// <summary>
        /// The piece of trusted platform module that is used.
        /// </summary>
        public Tpm2 Tpm { get; }


        /// <summary>
        /// Default constructor for the TPM.
        /// </summary>
        /// <remarks>Connects to the TPM device.</remarks>
        public TpmWrapper()
        {
            TpmDevice = TpmUtilities.CreateTpmDevice(isSimulator: false);
            TpmDevice.Connect();
            Tpm = new Tpm2(TpmDevice);
            TpmDevice.Connect();
        }


        /// <inheritdoc />
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }


        /// <summary>
        /// Default constructor for the TPM.
        /// </summary>
        /// <remarks>Does not connect to the TPM device.</remarks>
        protected TpmWrapper(bool isSimulator = true)
        {
            TpmDevice = TpmUtilities.CreateTpmDevice(isSimulator);
            Tpm = new Tpm2(TpmDevice);
        }


        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting umanaged resources.
        /// </summary>
        /// <param name="disposing">If this instance is currently disposing.</param>
        protected virtual void Dispose(bool disposing)
        {
            if(disposed)
            {
                return;
            }

            if(disposing)
            {
                //TPM looks like also disposing TpmDevice, but better to ensure.
                TpmDevice?.Dispose();
                Tpm?.Dispose();
            }

            disposed = true;
        }
    }
}
