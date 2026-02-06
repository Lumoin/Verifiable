using System.Buffers;
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
///   <item><description>Create typed input struct (e.g., <see cref="GetRandomInput"/>).</description></item>
///   <item><description>Serialize to bytes via <see cref="TpmBufferBuilder"/>.</description></item>
///   <item><description>Submit raw bytes via <see cref="TpmDevice.Submit"/>.</description></item>
///   <item><description>Parse response via <see cref="TpmBufferParser"/>.</description></item>
///   <item><description>Return typed output struct (e.g., <see cref="GetRandomOutput"/>).</description></item>
/// </list>
/// <para>
/// <b>Error handling:</b> If the TPM returns an error response code, a
/// <see cref="TpmCommandException"/> is thrown containing the command and response codes.
/// </para>
/// <para>
/// <b>Memory:</b> Operations use the device's configured <see cref="TpmDevice.Pool"/>
/// if available, otherwise <see cref="MemoryPool{T}.Shared"/>.
/// </para>
/// </remarks>
/// <seealso cref="TpmDevice"/>
/// <seealso cref="TpmBufferBuilder"/>
/// <seealso cref="TpmBufferParser"/>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with latest syntax.")]
public static class TpmDeviceExtensions
{
    extension(TpmDevice device)
    {
     
    }
}