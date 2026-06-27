using System;
using Verifiable.Cryptography;

namespace Verifiable.Apdu.SecureMessaging;

/// <summary>
/// A command APDU recovered by the card side of Secure Messaging: the (unmasked) header, the decrypted
/// command data, and the expected response length the terminal requested.
/// </summary>
/// <remarks>
/// <para>
/// Produced by <see cref="SecureMessagingCardSession.UnprotectCommandAsync"/> after the command MAC has
/// been verified, so its contents are authenticated. The class byte has the Secure Messaging bits
/// cleared, presenting the logical command a card application dispatches on. The decrypted data is held
/// in a <see cref="DecryptedContent"/> carrier and cleared on disposal.
/// </para>
/// </remarks>
public sealed class SecureMessagingCommand: IDisposable
{
    private readonly DecryptedContent? commandData;
    private bool disposed;


    /// <summary>
    /// Initialises a new <see cref="SecureMessagingCommand"/>.
    /// </summary>
    /// <param name="cla">The class byte, with the Secure Messaging bits cleared.</param>
    /// <param name="instruction">The instruction byte.</param>
    /// <param name="parameter1">Parameter 1.</param>
    /// <param name="parameter2">Parameter 2.</param>
    /// <param name="commandData">The decrypted command data, or <see langword="null"/> when the command carried none. Ownership transfers to this instance.</param>
    /// <param name="expectedResponseLength">The expected response length (from DO'97'), or <see langword="null"/> when none was requested.</param>
    internal SecureMessagingCommand(byte cla, byte instruction, byte parameter1, byte parameter2, DecryptedContent? commandData, int? expectedResponseLength)
    {
        Cla = cla;
        Instruction = instruction;
        Parameter1 = parameter1;
        Parameter2 = parameter2;
        this.commandData = commandData;
        ExpectedResponseLength = expectedResponseLength;
    }


    /// <summary>Gets the class byte, with the Secure Messaging bits cleared.</summary>
    public byte Cla { get; }

    /// <summary>Gets the instruction byte.</summary>
    public byte Instruction { get; }

    /// <summary>Gets parameter 1.</summary>
    public byte Parameter1 { get; }

    /// <summary>Gets parameter 2.</summary>
    public byte Parameter2 { get; }

    /// <summary>Gets the expected response length the terminal requested (DO'97'), or <see langword="null"/> when none.</summary>
    public int? ExpectedResponseLength { get; }

    /// <summary>Gets the decrypted command data; empty when the command carried no DO'87'.</summary>
    public ReadOnlySpan<byte> Data => commandData is null ? ReadOnlySpan<byte>.Empty : commandData.AsReadOnlySpan();


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            commandData?.Dispose();
            disposed = true;
        }
    }
}
