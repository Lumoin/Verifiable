namespace Verifiable.Tpm;

/// <summary>
/// TPM protocol constants.
/// </summary>
public static class TpmConstants
{
    /// <summary>
    /// Size of the TPM command/response header in bytes.
    /// </summary>
    /// <remarks>
    /// The header consists of:
    /// <list type="bullet">
    ///   <item><description>Tag (2 bytes) - TPM_ST value.</description></item>
    ///   <item><description>Size (4 bytes) - total size including header.</description></item>
    ///   <item><description>Code (4 bytes) - command code or response code.</description></item>
    /// </list>
    /// </remarks>
    public const int HeaderSize = 10;

    /// <summary>
    /// Maximum allowed response size in bytes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a safety limit to prevent allocating excessive memory if the
    /// response header contains garbage data. 64 KiB is sufficient for all
    /// standard TPM responses including large capability dumps.
    /// </para>
    /// <para>
    /// The actual response size comes from the response header's size field.
    /// This constant is only used as an upper bound validation.
    /// </para>
    /// </remarks>
    public const int MaxResponseSize = 64 * 1024;
}