using System;
using System.Runtime.InteropServices;
using Tpm2Lib;

namespace Verifable.Tpm
{
    /// <summary>
    /// Utility functions to interact with trusted platform module.
    /// </summary>
    public static class TpmUtilities
    {
        /// <summary>
        /// Creates a <see cref="Tpm2Device" /> that works either on <see cref="OSPlatform.Windows"/> or
        /// <see cref="OSPlatform.Linux"/> as a simulator.
        /// </summary>
        /// <param name="isSimulator"><see cref="TcpTpmDevice" /> with parameters <c>127.0.0.1:2321 stopTpm: true</c> will be created.</param>
        /// <returns>The platform specific <see cref="Tpm2Device"/>.</returns>
        /// <exception cref="PlatformNotSupportedException" />.
        public static Tpm2Device CreateTpmDevice(bool isSimulator)
        {
            if(isSimulator)
            {
                return new TcpTpmDevice("127.0.0.1", 2321, stopTpm: true);
            }

            if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return new TbsDevice();
            }

            if(RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                //Note, it appears Linux version derives from TbsDevice, which is by default
                //a Windows version.
                return new LinuxTpmDevice();
            }

            throw new PlatformNotSupportedException($"The library doesn't support the current OS platform: {RuntimeInformation.OSDescription}.");
        }
    }
}
