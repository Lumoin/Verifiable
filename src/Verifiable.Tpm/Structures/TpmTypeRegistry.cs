using System;
using System.Collections.Generic;
using Verifiable.Tpm.Commands;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Registry mapping command codes to input/output parsers.
/// </summary>
/// <remarks>
/// <para>
/// The registry enables the <see cref="TpmBufferParser"/> to parse command and response
/// buffers without hardcoded knowledge of specific command types. Types self-describe
/// their serialization via <see cref="ITpmParseable{TSelf}"/>.
/// </para>
/// <para>
/// <b>Usage:</b> Register command types at startup, then use the registry for parsing:
/// </para>
/// <code>
/// var registry = new TpmTypeRegistry()
///     .Register&lt;GetRandomInput, GetRandomOutput&gt;()
///     .Register&lt;HashInput, HashOutput&gt;();
///
/// TpmParsedCommand cmd = TpmBufferParser.ParseCommand(bytes, registry);
/// </code>
/// <para>
/// <b>Default registry:</b> Use <see cref="Default"/> for a pre-populated registry
/// with all built-in command types.
/// </para>
/// </remarks>
/// <seealso cref="TpmBufferParser"/>
/// <seealso cref="ITpmCommandInput{TSelf}"/>
/// <seealso cref="ITpmCommandOutput{TSelf}"/>
public class TpmTypeRegistry
{
    /// <summary>
    /// Gets the default registry with all built-in command types.
    /// </summary>
    public static TpmTypeRegistry Default { get; } = CreateDefault();

    private static TpmTypeRegistry CreateDefault()
    {
        return new TpmTypeRegistry()
            .Register<GetRandomInput, GetRandomOutput>()
            .Register<ReadClockInput, ReadClockOutput>()
            .Register<HashInput, HashOutput>()
            .Register<GetCapabilityInput, GetCapabilityOutput>();
    }
    /// <summary>
    /// Delegate for parsing command input parameters.
    /// </summary>
    /// <param name="source">The source bytes containing parameters.</param>
    /// <returns>The parsed input and bytes consumed.</returns>
    public delegate TpmParseResult<object> InputParser(ReadOnlySpan<byte> source);

    /// <summary>
    /// Delegate for parsing command output data.
    /// </summary>
    /// <param name="source">The source bytes containing response body.</param>
    /// <returns>The parsed output and bytes consumed.</returns>
    public delegate TpmParseResult<object> OutputParser(ReadOnlySpan<byte> source);

    private Dictionary<Tpm2CcConstants, InputParser> InputParsers { get; } = new();
    private Dictionary<Tpm2CcConstants, OutputParser> OutputParsers { get; } = new();
    private Dictionary<Tpm2CcConstants, Type> InputTypes { get; } = new();
    private Dictionary<Tpm2CcConstants, Type> OutputTypes { get; } = new();

    /// <summary>
    /// Registers a command input/output type pair.
    /// </summary>
    /// <typeparam name="TInput">The input type.</typeparam>
    /// <typeparam name="TOutput">The output type.</typeparam>
    /// <returns>This registry for chaining.</returns>
    public TpmTypeRegistry Register<TInput, TOutput>()
        where TInput : ITpmCommandInput<TInput>
        where TOutput : ITpmCommandOutput<TOutput>
    {
        Tpm2CcConstants code = TInput.CommandCode;

        InputParsers[code] = (ReadOnlySpan<byte> source) =>
        {
            var result = TInput.Parse(source);
            return new TpmParseResult<object>(result.Value, result.BytesConsumed);
        };

        OutputParsers[code] = (ReadOnlySpan<byte> source) =>
        {
            var result = TOutput.Parse(source);
            return new TpmParseResult<object>(result.Value, result.BytesConsumed);
        };

        InputTypes[code] = typeof(TInput);
        OutputTypes[code] = typeof(TOutput);

        return this;
    }

    /// <summary>
    /// Tries to parse command input parameters for a given command code.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="source">The source bytes.</param>
    /// <param name="result">The parsed input if successful.</param>
    /// <param name="bytesConsumed">The number of bytes consumed.</param>
    /// <returns><c>true</c> if parsing succeeded; otherwise, <c>false</c>.</returns>
    public bool TryParseInput(
        Tpm2CcConstants commandCode,
        ReadOnlySpan<byte> source,
        out object? result,
        out int bytesConsumed)
    {
        if(InputParsers.TryGetValue(commandCode, out InputParser? parser))
        {
            var parseResult = parser(source);
            result = parseResult.Value;
            bytesConsumed = parseResult.BytesConsumed;
            return true;
        }

        result = null;
        bytesConsumed = 0;
        return false;
    }

    /// <summary>
    /// Tries to parse command output for a given command code.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="source">The source bytes.</param>
    /// <param name="result">The parsed output if successful.</param>
    /// <param name="bytesConsumed">The number of bytes consumed.</param>
    /// <returns><c>true</c> if parsing succeeded; otherwise, <c>false</c>.</returns>
    public bool TryParseOutput(
        Tpm2CcConstants commandCode,
        ReadOnlySpan<byte> source,
        out object? result,
        out int bytesConsumed)
    {
        if(OutputParsers.TryGetValue(commandCode, out OutputParser? parser))
        {
            var parseResult = parser(source);
            result = parseResult.Value;
            bytesConsumed = parseResult.BytesConsumed;
            return true;
        }

        result = null;
        bytesConsumed = 0;
        return false;
    }

    /// <summary>
    /// Checks if a command code is registered.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <returns><c>true</c> if registered; otherwise, <c>false</c>.</returns>
    public bool IsRegistered(Tpm2CcConstants commandCode) => InputParsers.ContainsKey(commandCode);

    /// <summary>
    /// Gets all registered command codes.
    /// </summary>
    public IEnumerable<Tpm2CcConstants> RegisteredCommands => InputParsers.Keys;
}