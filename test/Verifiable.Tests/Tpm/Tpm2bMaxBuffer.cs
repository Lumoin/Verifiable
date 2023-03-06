using System;
using System.Linq;

namespace Verifiable.Tpm
{
    /// <summary>
    /// This structure is used to pass a buffer of bytes when the size of the buffer is known to be less than the
    /// maximum allowed for a TPM2B_DIGEST (<see cref="Tpm2PtConstants.TPM2_PT_MAX_DIGEST"/>).
    /// </summary>
    /// <remarks>
    /// <see href="https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38-code.pdf">TPM 2.0 Specification, Part 2: Structures, Section 10.5.1 TPM2B_DIGEST</see>
    /// </remarks>
    public class Tpm2bMaxBuffer
    {
        /// <summary>
        /// The size of the buffer.
        /// </summary>
        public ushort Size { get; set; }

        /// <summary>
        /// The buffer that contains the data.
        /// </summary>
        public byte[] Buffer { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="Tpm2bMaxBuffer"/> class.
        /// </summary>
        /// <param name="buffer">The buffer that contains the data.</param>
        public Tpm2bMaxBuffer(byte[] buffer)
        {
            Buffer = buffer;
            Size = (ushort)buffer.Length;
        }

        /// <summary>
        /// Returns the TPM2B_MAX_BUFFER as a byte array.
        /// </summary>
        /// <returns>A byte array representing the TPM2B_MAX_BUFFER.</returns>
        public byte[] ToByteArray()
        {
            return BitConverter.GetBytes(Size).Reverse().Concat(Buffer).ToArray();
        }
    }
}
