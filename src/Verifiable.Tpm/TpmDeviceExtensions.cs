using System;
using System.Buffers;
using Verifiable.Tpm.Commands;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures;

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
public static class TpmDeviceExtensions
{
    extension(TpmDevice device)
    {
        /// <summary>
        /// Gets random bytes from the TPM.
        /// </summary>
        /// <param name="count">The number of random bytes to request.</param>
        /// <returns>The random bytes output.</returns>
        /// <exception cref="TpmCommandException">Thrown when the TPM returns an error.</exception>
        public GetRandomOutput GetRandom(ushort count)
        {
            return device.GetRandom(new GetRandomInput(count));
        }

        /// <summary>
        /// Gets random bytes from the TPM using typed input.
        /// </summary>
        /// <param name="input">The command input.</param>
        /// <returns>The random bytes output.</returns>
        /// <exception cref="TpmCommandException">Thrown when the TPM returns an error.</exception>
        public GetRandomOutput GetRandom(GetRandomInput input)
        {
            return device.ExecuteCommand<GetRandomInput, GetRandomOutput>(input);
        }

        /// <summary>
        /// Reads the current clock values from the TPM.
        /// </summary>
        /// <returns>The clock output containing time and clock info.</returns>
        /// <exception cref="TpmCommandException">Thrown when the TPM returns an error.</exception>
        public ReadClockOutput ReadClock()
        {
            return device.ExecuteCommand<ReadClockInput, ReadClockOutput>(new ReadClockInput());
        }

        /// <summary>
        /// Performs a hash operation on the TPM.
        /// </summary>
        /// <param name="algorithm">The hash algorithm to use.</param>
        /// <param name="data">The data to hash.</param>
        /// <returns>The hash output containing the digest.</returns>
        /// <exception cref="TpmCommandException">Thrown when the TPM returns an error.</exception>
        public HashOutput Hash(Tpm2AlgId algorithm, ReadOnlySpan<byte> data)
        {
            return device.ExecuteCommand<HashInput, HashOutput>(new HashInput(algorithm, data.ToArray()));
        }

        /// <summary>
        /// Gets TPM capabilities.
        /// </summary>
        /// <param name="capability">The capability category to query.</param>
        /// <param name="property">The first property to return.</param>
        /// <param name="propertyCount">The maximum number of properties to return.</param>
        /// <returns>The capability output.</returns>
        /// <exception cref="TpmCommandException">Thrown when the TPM returns an error.</exception>
        public GetCapabilityOutput GetCapability(Tpm2CapConstants capability, uint property, uint propertyCount)
        {
            return device.ExecuteCommand<GetCapabilityInput, GetCapabilityOutput>(
                new GetCapabilityInput(capability, property, propertyCount));
        }

        /// <summary>
        /// Checks if the TPM is operating in FIPS 140-2 mode.
        /// </summary>
        /// <returns><c>true</c> if FIPS mode is enabled; otherwise, <c>false</c>.</returns>
        /// <exception cref="TpmCommandException">Thrown when the TPM returns an error.</exception>
        public bool IsFipsMode()
        {
            //Query TPM_PT_MODES property.
            GetCapabilityOutput result = device.GetCapability(
                Tpm2CapConstants.TPM_CAP_TPM_PROPERTIES,
                (uint)Tpm2PtConstants.TPM2_PT_MODES,
                1);

            if(result.Properties.Count > 0 && result.Properties[0].Property == (uint)Tpm2PtConstants.TPM2_PT_MODES)
            {
                //Bit 0 of TPMA_MODES indicates FIPS 140-2 mode.
                return (result.Properties[0].Value & 0x01) != 0;
            }

            return false;
        }

        /// <summary>
        /// Gets session information for recording purposes.
        /// </summary>
        /// <param name="timeProvider">The time provider for timestamps.</param>
        /// <returns>Session info containing TPM metadata.</returns>
        public TpmSessionInfo GetSessionInfo(TimeProvider timeProvider)
        {
            string? manufacturer = null;
            string? firmwareVersion = null;

            try
            {
                //Query manufacturer.
                GetCapabilityOutput mfrResult = device.GetCapability(
                    Tpm2CapConstants.TPM_CAP_TPM_PROPERTIES,
                    (uint)Tpm2PtConstants.TPM2_PT_MANUFACTURER,
                    1);

                if(mfrResult.Properties.Count > 0)
                {
                    uint mfrValue = mfrResult.Properties[0].Value;
                    manufacturer = new string(new[]
                    {
                        (char)((mfrValue >> 24) & 0xFF),
                        (char)((mfrValue >> 16) & 0xFF),
                        (char)((mfrValue >> 8) & 0xFF),
                        (char)(mfrValue & 0xFF)
                    });
                }

                //Query firmware version.
                GetCapabilityOutput fwResult = device.GetCapability(
                    Tpm2CapConstants.TPM_CAP_TPM_PROPERTIES,
                    (uint)Tpm2PtConstants.TPM2_PT_FIRMWARE_VERSION_1,
                    2);

                if(fwResult.Properties.Count >= 2)
                {
                    uint major = fwResult.Properties[0].Value;
                    uint minor = fwResult.Properties[1].Value;
                    firmwareVersion = $"{major}.{minor}";
                }
            }
            catch(TpmCommandException)
            {
                //If capability queries fail, return with null values.
            }

            return TpmSessionInfo.Create(manufacturer, firmwareVersion, device.Platform, timeProvider);
        }

        /// <summary>
        /// Executes a typed TPM command and returns the typed output.
        /// </summary>
        /// <typeparam name="TInput">The command input type.</typeparam>
        /// <typeparam name="TOutput">The command output type.</typeparam>
        /// <param name="input">The command input.</param>
        /// <returns>The command output.</returns>
        /// <exception cref="TpmCommandException">Thrown when the TPM returns an error.</exception>
        public TOutput ExecuteCommand<TInput, TOutput>(TInput input)
            where TInput : ITpmCommandInput<TInput>
            where TOutput : ITpmCommandOutput<TOutput>
        {
            MemoryPool<byte> pool = device.Pool ?? MemoryPool<byte>.Shared;

            //Build command bytes from typed input.
            using IMemoryOwner<byte> commandOwner = TpmBufferBuilder.BuildCommand(input, pool);

            //Estimate response size and allocate buffer.
            int estimatedResponseSize = TpmHeader.HeaderSize + 4096;
            using IMemoryOwner<byte> responseOwner = pool.Rent(estimatedResponseSize);

            //Submit to TPM.
            int responseLength = device.Submit(commandOwner.Memory.Span, responseOwner.Memory.Span);

            //Parse response.
            TpmParsedResponse parsed = TpmBufferParser.ParseResponse(
                responseOwner.Memory.Span[..responseLength],
                TInput.CommandCode,
                TpmTypeRegistry.Default);

            if(!parsed.IsSuccess)
            {
                throw new TpmCommandException(TInput.CommandCode, parsed.ResponseCode);
            }

            return parsed.GetOutput<TOutput>();
        }
    }
}