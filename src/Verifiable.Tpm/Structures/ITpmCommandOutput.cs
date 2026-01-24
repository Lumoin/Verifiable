namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Interface for TPM command output types.
/// </summary>
/// <typeparam name="TSelf">The implementing type.</typeparam>
/// <remarks>
/// <para>
/// Outputs are associated with their corresponding input type via the registry.
/// The output type itself does not carry command code information.
/// </para>
/// </remarks>
public interface ITpmCommandOutput<TSelf> : ITpmParseable<TSelf>
    where TSelf : ITpmCommandOutput<TSelf>
{
}
