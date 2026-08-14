namespace Verifiable.JCose;

/// <summary>
/// The result of a fail-closed <c>COSE_Sign</c> parse attempt.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors the fail-closed convention <c>CBAdESSignatureSerialization.ParseCBAdESSign1</c>
/// established: a parse of malformed or non-conformant wire bytes never throws — every
/// failure path inside <c>CoseSerialization.ParseCoseSign</c> funnels into
/// <see cref="Failure"/>, which carries no message because nothing survives to return. A
/// caller checks <see cref="IsSuccess"/> before touching <see cref="Message"/>.
/// </para>
/// <para>
/// Unlike <c>CBAdESSign1ParseResult</c>, no separate raw-bytes/decoded-model split is
/// needed here: <see cref="CoseSignMessage"/> already carries every protected header as
/// its raw wire bytes (<see cref="EncodedCoseProtectedHeader"/>), never a re-encoded
/// dictionary, so the message itself is the byte-exact form a Sig_structure rebuild needs.
/// </para>
/// </remarks>
public sealed class CoseSignParseResult: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new instance of the <see cref="CoseSignParseResult"/> class. Ownership
    /// of <paramref name="message"/>, when supplied, transfers to this instance.
    /// </summary>
    /// <param name="isSuccess">See <see cref="IsSuccess"/>.</param>
    /// <param name="message">See <see cref="Message"/>.</param>
    internal CoseSignParseResult(bool isSuccess, CoseSignMessage? message)
    {
        IsSuccess = isSuccess;
        Message = message;
    }


    /// <summary>
    /// Gets whether the wire bytes decoded into a structurally well-formed
    /// <c>COSE_Sign</c> message. When <see langword="false"/>, <see cref="Message"/> is
    /// <see langword="null"/>.
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// Gets the decoded message, or <see langword="null"/> when <see cref="IsSuccess"/> is
    /// <see langword="false"/>. Owned by this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public CoseSignMessage? Message { get; }


    /// <summary>
    /// Mints a successful result. Ownership of <paramref name="message"/> transfers to the
    /// returned instance.
    /// </summary>
    /// <param name="message">The decoded message.</param>
    /// <returns>A successful <see cref="CoseSignParseResult"/>.</returns>
    internal static CoseSignParseResult Success(CoseSignMessage message) => new(true, message);


    /// <summary>Mints a failed result carrying no decoded content.</summary>
    /// <returns>A failed <see cref="CoseSignParseResult"/>.</returns>
    internal static CoseSignParseResult Failure() => new(false, null);


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        Message?.Dispose();
        disposed = true;
    }
}
