namespace Verifiable.Core.Outbound;

/// <summary>
/// The closed result of reading a single hop. Only the guarded fetch's response reader creates it;
/// a transport returns the reader's result unchanged, including a refusal that stopped its read early.
/// </summary>
public sealed class OutboundTransportResult
{
    /// <summary>Creates a completed response.</summary>
    internal OutboundTransportResult(OutboundResponse response)
    {
        Response = response;
    }


    /// <summary>Creates a size refusal without a usable or partial response body.</summary>
    internal OutboundTransportResult(OutboundResponseTooLarge tooLarge)
    {
        TooLarge = tooLarge;
    }


    /// <summary>The completed response, or null when reading stopped for size.</summary>
    public OutboundResponse? Response { get; }

    /// <summary>The size evidence, or null when the response completed.</summary>
    public OutboundResponseTooLarge? TooLarge { get; }
}


/// <summary>The source of the length that exceeded the guarded fetch's limit.</summary>
public enum OutboundResponseLengthKind
{
    /// <summary>A Content-Length value received before reading the body.</summary>
    Declared,

    /// <summary>The number of body bytes actually read, which is a lower bound on the total length.</summary>
    Observed
}


/// <summary>The evidence for a guarded fetch's size refusal.</summary>
/// <param name="Limit">The maximum number of response body bytes the fetch accepts.</param>
/// <param name="Length">The declared length or the number of bytes observed when reading stopped.</param>
/// <param name="LengthKind">Whether the length was declared or observed.</param>
public sealed record OutboundResponseTooLarge(long Limit, long Length, OutboundResponseLengthKind LengthKind);
