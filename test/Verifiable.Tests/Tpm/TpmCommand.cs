using System;
using System.Collections.Generic;
using System.Linq;

namespace Verifiable.Tpm
{
    public class TpmCommand
    {
        public ushort Tag { get; set; }

        public uint CommandSize { get; set; }

        public uint CommandCode { get; set; }

        public byte[]? Parameters { get; set; }
        

        public byte[] ToByteArray()
        {
            List<byte> commandBuffer = new List<byte>();

            commandBuffer.AddRange(BitConverter.GetBytes(Tag).Reverse());
            commandBuffer.AddRange(BitConverter.GetBytes(CommandSize).Reverse());
            commandBuffer.AddRange(BitConverter.GetBytes(CommandCode).Reverse());            
            if(Parameters != null)
            {
                commandBuffer.AddRange(Parameters);
            }

            return commandBuffer.ToArray();
        }       
    }
}
