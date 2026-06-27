using System;
using Verifiable.Cryptography;

namespace Verifiable.Apdu.SecureMessaging;

/// <summary>
/// The result of unprotecting an ICAO Doc 9303 Secure Messaging response: the decrypted,
/// unpadded response data (if any) and the protected status word carried in DO'99'.
/// </summary>
/// <remarks>
/// <para>
/// A <see cref="SecureMessagingResponse"/> is produced only after the response MAC (DO'8E')
/// has been verified, so its contents are authenticated. The decrypted data is held in a
/// <see cref="DecryptedContent"/> carrier and cleared on disposal. The
/// <see cref="StatusWord"/> is the card's real status (from DO'99'), distinct from the
/// transport-level <c>9000</c> that wraps every Secure Messaging response.
/// </para>
/// </remarks>
public sealed class SecureMessagingResponse: IDisposable
{
    private DecryptedContent? DecryptedData { get; }
    private bool disposed;

    /// <summary>
    /// Gets the protected status word the card returned inside DO'99'.
    /// </summary>
    public StatusWord StatusWord { get; }

    /// <summary>
    /// Gets the decrypted, unpadded response data. Empty when the response carried no DO'87'
    /// (for example a SELECT whose protected response is only DO'99' and DO'8E').
    /// </summary>
    public ReadOnlySpan<byte> Data => DecryptedData is null ? ReadOnlySpan<byte>.Empty : DecryptedData.AsReadOnlySpan();

    /// <summary>Gets the length of <see cref="Data"/> in bytes.</summary>
    public int Length => DecryptedData?.AsReadOnlySpan().Length ?? 0;


    /// <summary>
    /// Initialises a new <see cref="SecureMessagingResponse"/>.
    /// </summary>
    /// <param name="data">
    /// The decrypted response data, or <see langword="null"/> when the response carried no DO'87'.
    /// Ownership transfers to this instance.
    /// </param>
    /// <param name="statusWord">The status word from DO'99'.</param>
    internal SecureMessagingResponse(DecryptedContent? data, StatusWord statusWord)
    {
        DecryptedData = data;
        StatusWord = statusWord;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            DecryptedData?.Dispose();
            disposed = true;
        }
    }
}
