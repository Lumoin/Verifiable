using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Registry mapping TPM command codes to their response codecs.
/// </summary>
/// <remarks>
/// <para>
/// The registry provides a lookup from command code to codec, enabling the
/// executor to determine how to parse each command's response.
/// </para>
/// <para>
/// <b>Usage:</b>
/// </para>
/// <code>
/// var registry = new TpmResponseRegistry();
///
/// //Register codecs for commands you intend to use.
/// registry.Register(TpmCcConstants.TPM_CC_GetRandom,
///     TpmResponseCodec.Create(GetRandomResponse.Parse));
/// registry.Register(TpmCcConstants.TPM_CC_GetCapability,
///     TpmResponseCodec.Create(GetCapabilityResponse.Parse));
/// registry.Register(TpmCcConstants.TPM_CC_CreatePrimary,
///     TpmResponseCodec.Create(1, CreatePrimaryResponse.Parse));
///
/// //The executor uses the registry to find the codec.
/// var result = TpmCommandExecutor.Execute&lt;GetRandomResponse&gt;(device, input, pool, registry);
/// </code>
/// <para>
/// <b>Thread safety:</b> This class is not thread-safe. Register all codecs
/// before concurrent use, or use external synchronization.
/// </para>
/// </remarks>
public sealed class TpmResponseRegistry
{
    private readonly Dictionary<TpmCcConstants, TpmResponseCodec> codecs = [];

    /// <summary>
    /// Registers a codec for the specified command.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="codec">The codec.</param>
    /// <returns>This registry for method chaining.</returns>
    public TpmResponseRegistry Register(TpmCcConstants commandCode, TpmResponseCodec codec)
    {
        codecs[commandCode] = codec;
        return this;
    }

    /// <summary>
    /// Attempts to get the codec for the specified command.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="codec">The codec if found.</param>
    /// <returns><c>true</c> if the codec was found; otherwise, <c>false</c>.</returns>
    public bool TryGet(TpmCcConstants commandCode, [NotNullWhen(true)] out TpmResponseCodec? codec)
    {
        return codecs.TryGetValue(commandCode, out codec);
    }

    /// <summary>
    /// Gets whether a codec is registered for the specified command.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <returns><c>true</c> if a codec is registered; otherwise, <c>false</c>.</returns>
    public bool Contains(TpmCcConstants commandCode)
    {
        return codecs.ContainsKey(commandCode);
    }

    /// <summary>
    /// Gets the number of registered codecs.
    /// </summary>
    public int Count => codecs.Count;
}