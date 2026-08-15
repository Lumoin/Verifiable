namespace Verifiable.JCose;

/// <summary>
/// The result of a fail-closed countersignature header-value parse attempt (COSE header
/// label 11 or 12), including fail-closed rejection of the deprecated RFC 8152 version 1
/// countersignature labels (7, 9).
/// </summary>
/// <remarks>
/// Mirrors the <see cref="CoseSignParseResult"/> fail-closed convention: a parse of malformed,
/// unsupported, or deprecated-V1 input never throws — every failure path inside
/// <c>CoseSerialization.ParseCounterSignatureHeaderValue</c> funnels into <see cref="Failure"/>.
/// A caller checks <see cref="IsSuccess"/> before touching <see cref="CounterSignature"/>.
/// </remarks>
public sealed class CoseCounterSignatureParseResult: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new instance of the <see cref="CoseCounterSignatureParseResult"/> class.
    /// Ownership of <paramref name="counterSignature"/>, when supplied, transfers to this
    /// instance.
    /// </summary>
    /// <param name="isSuccess">See <see cref="IsSuccess"/>.</param>
    /// <param name="counterSignature">See <see cref="CounterSignature"/>.</param>
    internal CoseCounterSignatureParseResult(bool isSuccess, CoseCounterSignature? counterSignature)
    {
        IsSuccess = isSuccess;
        CounterSignature = counterSignature;
    }


    /// <summary>
    /// Gets whether the header value decoded into a supported version 2 countersignature.
    /// When <see langword="false"/>, <see cref="CounterSignature"/> is <see langword="null"/>
    /// — including when the label was one of the deprecated RFC 8152 V1 forms (7, 9).
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// Gets the decoded countersignature, or <see langword="null"/> when <see cref="IsSuccess"/>
    /// is <see langword="false"/>. Owned by this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public CoseCounterSignature? CounterSignature { get; }


    /// <summary>
    /// Mints a successful result. Ownership of <paramref name="counterSignature"/> transfers
    /// to the returned instance.
    /// </summary>
    /// <param name="counterSignature">The decoded countersignature.</param>
    /// <returns>A successful <see cref="CoseCounterSignatureParseResult"/>.</returns>
    internal static CoseCounterSignatureParseResult Success(CoseCounterSignature counterSignature) => new(true, counterSignature);


    /// <summary>Mints a failed result carrying no decoded content.</summary>
    /// <returns>A failed <see cref="CoseCounterSignatureParseResult"/>.</returns>
    internal static CoseCounterSignatureParseResult Failure() => new(false, null);


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        CounterSignature?.Dispose();
        disposed = true;
    }
}
