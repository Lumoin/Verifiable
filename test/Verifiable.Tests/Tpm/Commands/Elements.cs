using System;
using System.Buffers.Binary;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Commands
{
    public class TagElement: ICommandBufferElement
    {
        public ushort Tag { get; set; }

        public byte[] Serialize()
        {
            byte[] result = new byte[sizeof(ushort)];
            BinaryPrimitives.WriteUInt16BigEndian(result, Tag);
            return result;
        }

        public void Deserialize(ReadOnlyMemory<byte> buffer)
        {
            Tag = BinaryPrimitives.ReadUInt16BigEndian(buffer.Span);
        }
    }

    public class CommandSizeElement: ICommandBufferElement
    {
        public uint Size { get; set; }

        public byte[] Serialize()
        {
            byte[] result = new byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(result, Size);
            return result;
        }

        public void Deserialize(ReadOnlyMemory<byte> buffer)
        {
            Size = BinaryPrimitives.ReadUInt32BigEndian(buffer.Span);
        }
    }

    public class CommandCodeElement: ICommandBufferElement
    {
        public Tpm2Cc CommandCode { get; set; }

        public byte[] Serialize()
        {
            byte[] result = new byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(result, (uint)CommandCode);
            return result;
        }

        public void Deserialize(ReadOnlyMemory<byte> buffer)
        {
            CommandCode = (Tpm2Cc)BinaryPrimitives.ReadUInt32BigEndian(buffer.Span);
        }
    }

    public class CapabilityElement: ICommandBufferElement
    {
        public TPM2_CAP Capability { get; set; }

        public byte[] Serialize()
        {
            byte[] result = new byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(result, (uint)Capability);
            return result;
        }

        public void Deserialize(ReadOnlyMemory<byte> buffer)
        {
            Capability = (TPM2_CAP)BinaryPrimitives.ReadUInt32BigEndian(buffer.Span);
        }
    }

    public class PropertyElement: ICommandBufferElement
    {
        public uint Property { get; set; }

        public byte[] Serialize()
        {
            byte[] result = new byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(result, Property);
            return result;
        }

        public void Deserialize(ReadOnlyMemory<byte> buffer)
        {
            Property = BinaryPrimitives.ReadUInt32BigEndian(buffer.Span);
        }
    }

    public class PropertyCountElement: ICommandBufferElement
    {
        public uint PropertyCount { get; set; }

        public byte[] Serialize()
        {
            byte[] result = new byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(result, PropertyCount);
            return result;
        }

        public void Deserialize(ReadOnlyMemory<byte> buffer)
        {
            PropertyCount = BinaryPrimitives.ReadUInt32BigEndian(buffer.Span);
        }
    }
}
