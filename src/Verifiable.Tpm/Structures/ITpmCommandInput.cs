using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Interface for TPM command input types.
/// </summary>
/// <typeparam name="TSelf">The implementing type.</typeparam>
public interface ITpmCommandInput<TSelf> : ITpmParseable<TSelf>
    where TSelf : ITpmCommandInput<TSelf>
{
    /// <summary>
    /// Gets the command code for this input type.
    /// </summary>
    static abstract Tpm2CcConstants CommandCode { get; }
}
