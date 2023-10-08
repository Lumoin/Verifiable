using System;
using System.Collections.Generic;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Commands
{    
    public abstract class TpmCommand: IDisposable
    {
        public abstract uint CommandSize { get; }

        public abstract Tpm2Cc CommandCode { get; }

        public TpmSafeHandleWindows TpmContext { get; private set; }

        protected TpmCommand()
        {
            TpmContext = new TpmSafeHandleWindows();
            TpmContext.Open();
        }
        
        public void Dispose()
        {
            TpmContext?.Dispose();
        }


        public abstract void Execute();


        public abstract byte[] Serialize();


        protected byte[] SerializeElements(IEnumerable<ICommandBufferElement> elements)
        {
            List<byte> result = new();
            foreach(var element in elements)
            {
                result.AddRange(element.Serialize());
            }
            return result.ToArray();
        }       
    }
}
