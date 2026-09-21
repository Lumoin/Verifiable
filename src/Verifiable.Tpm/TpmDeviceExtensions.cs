using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Tpm;

/// <summary>
/// High-level TPM operations as extensions for <see cref="TpmDevice"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Architecture:</b> These extensions provide the intent API layer that translates
/// high-level operations into typed command/response pairs. The flow is:
/// </para>
/// <list type="number">
///   <item><description>Create typed input struct (e.g., <see cref="Infrastructure.Commands.GetRandomInput"/>).</description></item>
///   <item><description>Serialize to bytes via <see cref="TpmWriter"/>.</description></item>
///   <item><description>Submit raw bytes via <see cref="TpmDevice.SubmitAsync"/>.</description></item>
///   <item><description>Parse response via <see cref="TpmReader"/>.</description></item>
///   <item><description>Return typed output struct (e.g., <see cref="Infrastructure.Commands.GetRandomResponse"/>).</description></item>
/// </list>
/// <para>
/// <b>Error handling:</b> If the TPM returns an error response code, the result carries that code as a
/// <c>TpmError</c> on <see cref="TpmResult{T}"/> rather than throwing.
/// </para>
/// <para>
/// <b>Memory:</b> <see cref="TpmDevice"/> carries the <see cref="BaseMemoryPool"/> its extension verbs rent
/// command/response buffers from (<see cref="TpmDevice.Pool"/>); <see cref="TpmDevice.SubmitAsync"/> still
/// takes the pool for one submission as an explicit parameter, letting a caller route a single exchange
/// through a different pool than the device's own.
/// </para>
/// </remarks>
/// <seealso cref="TpmDevice"/>
/// <seealso cref="TpmWriter"/>
/// <seealso cref="TpmReader"/>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with latest syntax.")]
public static class TpmDeviceExtensions
{
    extension(TpmDevice device)
    {

    }
}
