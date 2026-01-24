using System;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm;

/// <summary>
/// Exception thrown when a TPM command fails.
/// </summary>
/// <remarks>
/// <para>
/// This exception is thrown when the TPM returns an error response code.
/// The <see cref="ResponseCode"/> property contains the specific error.
/// </para>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 2: Structures, Section 6.6 for response code details.
/// </para>
/// </remarks>
public sealed class TpmCommandException : Exception
{
    /// <summary>
    /// Gets the command code that failed.
    /// </summary>
    public Tpm2CcConstants CommandCode { get; }

    /// <summary>
    /// Gets the TPM response code indicating the error.
    /// </summary>
    public TpmRc ResponseCode { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="TpmCommandException"/> class.
    /// </summary>
    /// <param name="commandCode">The command code that failed.</param>
    /// <param name="responseCode">The error response code.</param>
    public TpmCommandException(Tpm2CcConstants commandCode, TpmRc responseCode)
        : base($"TPM command '{commandCode}' failed with response code '{responseCode}'.")
    {
        CommandCode = commandCode;
        ResponseCode = responseCode;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TpmCommandException"/> class.
    /// </summary>
    /// <param name="responseCode">The error response code.</param>
    public TpmCommandException(TpmRc responseCode)
        : base($"TPM command failed with response code '{responseCode}'.")
    {
        ResponseCode = responseCode;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TpmCommandException"/> class.
    /// </summary>
    /// <param name="commandCode">The command code that failed.</param>
    /// <param name="responseCode">The error response code.</param>
    /// <param name="innerException">The inner exception.</param>
    public TpmCommandException(Tpm2CcConstants commandCode, TpmRc responseCode, Exception innerException)
        : base($"TPM command '{commandCode}' failed with response code '{responseCode}'.", innerException)
    {
        CommandCode = commandCode;
        ResponseCode = responseCode;
    }
}
