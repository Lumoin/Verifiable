using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using Verifiable.Tpm;
using Verifiable.Tpm.Structures;
using static Verifiable.Tpm.TpmWindowsPlatform;

namespace Verifiable.Tpm.Commands
{
    public enum GetCapabilityCommandState
    {
        Fips,
        AllSupportedAlgorithms
    }


    public class GetCapabilityCommand: TpmCommand
    {
        public GetCapabilityCommandState CurrentState { get; private set; }

        public TagElement Tag { get; set; }

        public CommandSizeElement CommandSizeElem { get; set; }

        public CommandCodeElement CommandCodeElem { get; set; }

        public CapabilityElement Capability { get; set; }

        public PropertyElement Property { get; set; }

        public PropertyCountElement PropertyCount { get; set; }

        public override uint CommandSize => CommandSizeElem.Size;

        public override Tpm2Cc CommandCode => CommandCodeElem.CommandCode;


        public GetCapabilityCommand()
        {
            Tag = new TagElement { Tag = TpmConstants2Temp.TPM_ST_NO_SESSIONS };
            CommandSizeElem = new CommandSizeElement { Size = 22 };
            CommandCodeElem = new CommandCodeElement { CommandCode = Tpm2Cc.GetCapability };
            Capability = new CapabilityElement { Capability = TPM2_CAP.TPM_PROPERTIES };
            Property = new PropertyElement { Property = Tpm2PtConstants.TPM2_PT_MODES };
            PropertyCount = new PropertyCountElement { PropertyCount = 1 };
        }

        public void GetFips()
        {
            CurrentState = GetCapabilityCommandState.Fips;

            Tag = new TagElement { Tag = TpmConstants2Temp.TPM_ST_NO_SESSIONS };
            CommandSizeElem = new CommandSizeElement { Size = 22 };
            CommandCodeElem = new CommandCodeElement { CommandCode = Tpm2Cc.GetCapability };
            Capability = new CapabilityElement { Capability = TPM2_CAP.TPM_PROPERTIES };
            Property = new PropertyElement { Property = Tpm2PtConstants.TPM2_PT_MODES };
            PropertyCount = new PropertyCountElement { PropertyCount = 1 };
        }


        public void GetAllSupportedAlgorithms()
        {
            CurrentState = GetCapabilityCommandState.AllSupportedAlgorithms;

            Tag = new TagElement { Tag = TpmConstants2Temp.TPM_ST_NO_SESSIONS };

            //TODO: Update this value according to the real size of the command.
            //Here's fixed as "we know by construction it is 22 bytes".
            CommandSizeElem = new CommandSizeElement { Size = 22 }; 
            CommandCodeElem = new CommandCodeElement { CommandCode = Tpm2Cc.GetCapability };
            Capability = new CapabilityElement { Capability = TPM2_CAP.ALGS };

            //Start from the first supported algorithm, it being Tpm2AlgId.Rsa.
            Property = new PropertyElement { Property = (uint)Tpm2AlgId.Rsa };

            //Request the maximum number of supported algorithms as defined by the TPM specification.
            PropertyCount = new PropertyCountElement { PropertyCount = Tpm2Constants.MaxCapAlgs };

            this.Execute();
        }

        public override void Execute()
        {
            byte[] commandBuffer = Serialize();
            uint responseBufferLength = 4096;
            byte[] responseBuffer = new byte[responseBufferLength];
            List<TpmsAlgProperty> supportedAlgorithms = new();

            //Initialize the response buffer length and the result code.
            TbsReturnCode tbsResultCode;

            //Submit the command and read the response based on the current state.
            switch(CurrentState)
            {
                case GetCapabilityCommandState.Fips:
                    // Logic for FIPS
                    break;

                case GetCapabilityCommandState.AllSupportedAlgorithms:
                    bool moreDataAvailable;
                    //if(TpmContext.Open())
                    {
                        do
                        {
                            var commandBufferAsHex = BitConverter.ToString(commandBuffer).Replace("-", " ", StringComparison.InvariantCulture);
                            tbsResultCode = TpmWindowsPlatform.Tbsip_Submit_Command(
                                TpmContext,
                                TBS_COMMAND_LOCALITY.TBS_COMMAND_LOCALITY_ZERO,
                                TpmWindowsPlatform.TBS_COMMAND_PRIORITY.TBS_COMMAND_PRIORITY_NORMAL,
                                commandBuffer,
                                (uint)commandBuffer.Length,
                                responseBuffer,
                                ref responseBufferLength);

                            if(tbsResultCode == TbsReturnCode.TBS_SUCCESS)
                            {
                                TpmResponse response = TpmResponse.FromByteArray(responseBuffer, (uint)Tpm2Cc.GetCapability);
                                if(response.ResponseCode == 0)
                                {
                                    var responseBufferAsHex = BitConverter.ToString(responseBuffer, 0, (int)responseBufferLength).Replace("-", " ", StringComparison.InvariantCulture);
                                    uint capability = BinaryPrimitives.ReadUInt32BigEndian(responseBuffer.AsSpan(11));
                                    moreDataAvailable = BitConverter.ToBoolean(responseBuffer, 10);
                                    int propertyCount = BinaryPrimitives.ReadInt32BigEndian(responseBuffer.AsSpan(15));


                                    if((TPM2_CAP)capability == TPM2_CAP.ALGS)
                                    {
                                        supportedAlgorithms.AddRange(ParseAlgorithmProperties(responseBuffer, propertyCount));
                                    }

                                    if(moreDataAvailable)
                                    {
                                        uint lastAlg = (uint)supportedAlgorithms.Last().Alg;
                                        Property.Property = lastAlg + 1;
                                        commandBuffer = Serialize();
                                    }
                                }
                                else
                                {
                                    throw new Exception($"TPM returned an error: {response.ResponseCode}");
                                }
                            }
                            else
                            {
                                throw new Exception($"Tbsip_Submit_Command failed with error: {tbsResultCode}");
                            }
                        } while(moreDataAvailable);
                    }
                    //TpmContext.Close();

                    // Now supportedAlgorithms contains all the supported algorithms
                    break;

                default:
                    throw new InvalidOperationException($"Invalid GetCapabilityCommandState: {CurrentState}");
            }
        }



        private List<TpmsAlgProperty> ParseAlgorithmProperties(byte[] responseBuffer, int propertyCount)
        {
            const int TagSize = 2;
            const int ResponseSizeSize = 4;
            const int ResponseCodeSize = 4;
            const int MoreDataSize = 1;
            const int CapabilitySize = 4;
            const int PropertyCountSize = 4;
            
            const int Tpm2AlgIdSize = sizeof(Tpm2AlgId);
            const int TpmaAlgorithmSize = sizeof(TpmaAlgorithm);
            const int TpmsAlgPropertySize = Tpm2AlgIdSize + TpmaAlgorithmSize;
            int offset = TagSize + ResponseSizeSize;

            uint responseCode = BinaryPrimitives.ReadUInt32BigEndian(responseBuffer.AsSpan(offset));
            offset += ResponseCodeSize;

            List<TpmsAlgProperty> algProperties = new();
            if(responseCode == 0)
            {
                bool moreDataAvailable = BitConverter.ToBoolean(responseBuffer, offset);
                offset += MoreDataSize;

                uint capability = BinaryPrimitives.ReadUInt32BigEndian(responseBuffer.AsSpan(offset));
                offset += CapabilitySize;

                propertyCount = BinaryPrimitives.ReadInt32BigEndian(responseBuffer.AsSpan(offset));
                offset += PropertyCountSize;

                for(int i = 0; i < propertyCount; i++)
                {
                    //The buffer comes from TPM, which is by TPM 2 specification big endian.
                    ReadOnlySpan<byte> algPropertySpan = responseBuffer.AsSpan(offset, TpmsAlgPropertySize);
                    TpmsAlgProperty algProperty = new(algPropertySpan, isBufferBigEndian: true);
                    algProperties.Add(algProperty);
                    offset += TpmsAlgPropertySize;
                }
            }            

            return algProperties;
        }


        public override byte[] Serialize()
        {
            List<ICommandBufferElement> elements = new List<ICommandBufferElement>
            {
                new TagElement { Tag = TpmConstants2Temp.TPM_ST_NO_SESSIONS },
                new CommandSizeElement(),
                new CommandCodeElement { CommandCode = Tpm2Cc.GetCapability },
                new CapabilityElement { Capability = TPM2_CAP.ALGS },
                new PropertyElement { Property = (uint)Tpm2AlgId.Rsa },
                new PropertyCountElement { PropertyCount = Tpm2Constants.MaxCapAlgs }
            };

            List<byte> serializedData = new List<byte>();

            //Serialize the elements, except for the CommandSizeElement.
            foreach(ICommandBufferElement element in elements.Skip(2))
            {
                byte[] elementBytes = element.Serialize();
                serializedData.AddRange(elementBytes);
            }

            //Calculate the command size and update the CommandSizeElement.
            //sizeof(TpmsAlgProperty) = sizeof(TpmsAlgProperty.Tpm2AlgId) + sizeof(TpmsAlgProperty.TpmaAlgorithm).            
            uint commandSize = (uint)(serializedData.Count + sizeof(Tpm2AlgId) + sizeof(TpmaAlgorithm));
            CommandSizeElement commandSizeElement = (CommandSizeElement)elements[1];
            commandSizeElement.Size = commandSize;

            //Serialize the CommandSizeElement and insert it at the beginning of the serializedData.
            byte[] commandSizeBytes = commandSizeElement.Serialize();
            serializedData.InsertRange(0, commandSizeBytes);

            //Serialize the TagElement and insert it at the beginning of the serializedData.
            byte[] tagBytes = elements[0].Serialize();
            serializedData.InsertRange(0, tagBytes);

            return serializedData.ToArray();
        }
    }
}
