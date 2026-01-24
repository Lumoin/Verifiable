using Verifiable.Tpm.Commands;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for <see cref="TpmTypeRegistry"/>.
/// </summary>
[TestClass]
public class TpmTypeRegistryTests
{
    [TestMethod]
    public void RegisterAddsCommandToRegistry()
    {
        var registry = new TpmTypeRegistry();

        registry.Register<GetRandomInput, GetRandomOutput>();

        Assert.IsTrue(registry.IsRegistered(Tpm2CcConstants.TPM2_CC_GetRandom));
    }

    [TestMethod]
    public void RegisterReturnsSameInstanceForChaining()
    {
        var registry = new TpmTypeRegistry();

        TpmTypeRegistry result = registry.Register<GetRandomInput, GetRandomOutput>();

        Assert.AreSame(registry, result);
    }

    [TestMethod]
    public void IsRegisteredReturnsFalseForUnregisteredCommand()
    {
        var registry = new TpmTypeRegistry();

        Assert.IsFalse(registry.IsRegistered(Tpm2CcConstants.TPM2_CC_GetRandom));
    }

    [TestMethod]
    public void TryParseInputSucceedsForRegisteredCommand()
    {
        var registry = new TpmTypeRegistry()
            .Register<GetRandomInput, GetRandomOutput>();

        var original = new GetRandomInput(32);
        Span<byte> buffer = stackalloc byte[original.SerializedSize];
        original.WriteTo(buffer);

        bool success = registry.TryParseInput(
            Tpm2CcConstants.TPM2_CC_GetRandom,
            buffer,
            out object? result,
            out int bytesConsumed);

        Assert.IsTrue(success);
        Assert.IsInstanceOfType<GetRandomInput>(result);
        Assert.AreEqual(original, (GetRandomInput)result!);
        Assert.AreEqual(original.SerializedSize, bytesConsumed);
    }

    [TestMethod]
    public void TryParseInputFailsForUnregisteredCommand()
    {
        var registry = new TpmTypeRegistry();

        bool success = registry.TryParseInput(
            Tpm2CcConstants.TPM2_CC_GetRandom,
            ReadOnlySpan<byte>.Empty,
            out object? result,
            out int bytesConsumed);

        Assert.IsFalse(success);
        Assert.IsNull(result);
        Assert.AreEqual(0, bytesConsumed);
    }

    [TestMethod]
    public void TryParseOutputSucceedsForRegisteredCommand()
    {
        var registry = new TpmTypeRegistry()
            .Register<GetRandomInput, GetRandomOutput>();

        byte[] originalBytes = [0xDE, 0xAD, 0xBE, 0xEF];
        var original = new GetRandomOutput(originalBytes);
        Span<byte> buffer = stackalloc byte[original.SerializedSize];
        original.WriteTo(buffer);

        bool success = registry.TryParseOutput(
            Tpm2CcConstants.TPM2_CC_GetRandom,
            buffer,
            out object? result,
            out int bytesConsumed);

        Assert.IsTrue(success);
        Assert.IsInstanceOfType<GetRandomOutput>(result);
        Assert.AreEqual(original, (GetRandomOutput)result!);
        Assert.AreEqual(original.SerializedSize, bytesConsumed);
    }

    [TestMethod]
    public void TryParseOutputFailsForUnregisteredCommand()
    {
        var registry = new TpmTypeRegistry();

        bool success = registry.TryParseOutput(
            Tpm2CcConstants.TPM2_CC_GetRandom,
            ReadOnlySpan<byte>.Empty,
            out object? result,
            out int bytesConsumed);

        Assert.IsFalse(success);
        Assert.IsNull(result);
        Assert.AreEqual(0, bytesConsumed);
    }

    [TestMethod]
    public void RegisteredCommandsReturnsAllRegistered()
    {
        var registry = new TpmTypeRegistry()
            .Register<GetRandomInput, GetRandomOutput>();

        Tpm2CcConstants[] commands = registry.RegisteredCommands.ToArray();

        Assert.HasCount(1, commands);
        Assert.AreEqual(Tpm2CcConstants.TPM2_CC_GetRandom, commands[0]);
    }

    [TestMethod]
    public void RegisteredCommandsIsEmptyForNewRegistry()
    {
        var registry = new TpmTypeRegistry();

        Assert.IsFalse(registry.RegisteredCommands.Any());
    }
}