using System;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Parses complete TPM command and response buffers using a type registry.
/// </summary>
public static class TpmBufferParser
{
    /// <summary>
    /// Parses a complete TPM command buffer.
    /// </summary>
    /// <param name="commandBuffer">The raw command bytes.</param>
    /// <param name="registry">The type registry to use for parsing.</param>
    /// <returns>The parsed command.</returns>
    public static TpmParsedCommand ParseCommand(ReadOnlySpan<byte> commandBuffer, TpmTypeRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);

        var (header, headerConsumed) = TpmHeader.Parse(commandBuffer);
        ReadOnlySpan<byte> parametersSpan = commandBuffer[headerConsumed..];

        if (registry.TryParseInput(header.CommandCode, parametersSpan, out object? input, out int paramsConsumed))
        {
            return new TpmParsedCommand(header, input, headerConsumed + paramsConsumed);
        }

        //Unknown command - return raw bytes.
        return new TpmParsedCommand(
            header,
            new UnknownInput(header.CommandCode, parametersSpan.ToArray()),
            commandBuffer.Length);
    }

    /// <summary>
    /// Parses a complete TPM response buffer.
    /// </summary>
    /// <param name="responseBuffer">The raw response bytes.</param>
    /// <param name="commandCode">The command code that produced this response.</param>
    /// <param name="registry">The type registry to use for parsing.</param>
    /// <returns>The parsed response.</returns>
    public static TpmParsedResponse ParseResponse(
        ReadOnlySpan<byte> responseBuffer,
        Tpm2CcConstants commandCode,
        TpmTypeRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);

        var (header, headerConsumed) = TpmHeader.Parse(responseBuffer);

        if (!header.IsSuccess)
        {
            return new TpmParsedResponse(header, null, headerConsumed);
        }

        ReadOnlySpan<byte> bodySpan = responseBuffer[headerConsumed..];

        if (registry.TryParseOutput(commandCode, bodySpan, out object? output, out int bodyConsumed))
        {
            return new TpmParsedResponse(header, output, headerConsumed + bodyConsumed);
        }

        //Unknown response - return raw bytes.
        return new TpmParsedResponse(
            header,
            new UnknownOutput(bodySpan.ToArray()),
            responseBuffer.Length);
    }

    /// <summary>
    /// Parses command parameters only (without header).
    /// </summary>
    /// <param name="parametersBuffer">The raw parameter bytes.</param>
    /// <param name="commandCode">The command code.</param>
    /// <param name="registry">The type registry to use for parsing.</param>
    /// <param name="input">The parsed input if successful.</param>
    /// <param name="bytesConsumed">The number of bytes consumed.</param>
    /// <returns><c>true</c> if parsing succeeded; otherwise, <c>false</c>.</returns>
    public static bool TryParseCommandParameters(
        ReadOnlySpan<byte> parametersBuffer,
        Tpm2CcConstants commandCode,
        TpmTypeRegistry registry,
        out object? input,
        out int bytesConsumed)
    {
        ArgumentNullException.ThrowIfNull(registry);

        return registry.TryParseInput(commandCode, parametersBuffer, out input, out bytesConsumed);
    }

    /// <summary>
    /// Parses response body only (without header).
    /// </summary>
    /// <param name="bodyBuffer">The raw response body bytes.</param>
    /// <param name="commandCode">The command code that produced this response.</param>
    /// <param name="registry">The type registry to use for parsing.</param>
    /// <param name="output">The parsed output if successful.</param>
    /// <param name="bytesConsumed">The number of bytes consumed.</param>
    /// <returns><c>true</c> if parsing succeeded; otherwise, <c>false</c>.</returns>
    public static bool TryParseResponseBody(
        ReadOnlySpan<byte> bodyBuffer,
        Tpm2CcConstants commandCode,
        TpmTypeRegistry registry,
        out object? output,
        out int bytesConsumed)
    {
        ArgumentNullException.ThrowIfNull(registry);

        return registry.TryParseOutput(commandCode, bodyBuffer, out output, out bytesConsumed);
    }
}
