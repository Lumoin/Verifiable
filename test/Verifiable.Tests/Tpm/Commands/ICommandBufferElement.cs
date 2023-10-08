using System;

namespace Verifiable.Tpm.Commands
{
    public interface ICommandBufferElement
    {
        byte[] Serialize();

        void Deserialize(ReadOnlyMemory<byte> buffer);
    }
}
