using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm
{
    public class TpmResponse
    {
        public ushort Tag { get; set; }

        public uint ResponseSize { get; set; }

        public TpmRc ResponseCode { get; set; }

        public byte[]? Parameters { get; set; }

        public bool MoreData { get; set; }

        public uint Capability { get; set; }

        public uint PropertyCount { get; set; }

        public bool IsFips { get; set; }

        public Dictionary<uint, uint> Properties { get; set; } = new Dictionary<uint, uint>();

        public Dictionary<uint, object> Cc { get; set; } = new Dictionary<uint, object>();

        //TODO: This doesn't really need the requested property, but it's here for now.
        //All the required information (sans TPM version 1.2/2) is in the response buffer.

        public static TpmResponse FromByteArray(byte[] buffer, uint requestedProperty)
        {
            int offset = 0;
            TpmResponse response = new TpmResponse();

            // Parsing the header
            const int TagSize = 2;
            const int ResponseSizeSize = 4;
            const int ResponseCodeSize = 4;
            const int MoreDataSize = 1;
            const int CapabilitySize = 4;
            const int PropertyCountSize = 4;
            const int PropertySize = 4;
            const int ValueSize = 4;
            const int Sha256HashSize = 32;

            response.Tag = BitConverter.ToUInt16(buffer, offset);
            response.Tag = ReverseBytes(response.Tag);
            offset += TagSize;

            response.ResponseSize = BitConverter.ToUInt32(buffer, offset);
            response.ResponseSize = ReverseBytes(response.ResponseSize);
            offset += ResponseSizeSize;

            var responseCode = BitConverter.ToUInt32(buffer, offset);
            response.ResponseCode = (TpmRc)ReverseBytes(responseCode);
            offset += ResponseCodeSize;

            //If there's an error, don't parse the rest of the buffer.
            uint actualResponseCode = responseCode & 0xFFF;
            response.ResponseCode = (TpmRc)actualResponseCode;
            if(response.ResponseCode != 0)
            {
                return response;
            }

            // No additional parameters need to be parsed for the SelfTest command response
            if(response.ResponseCode != 0 || requestedProperty == (uint)Tpm2Cc.SelfTest || requestedProperty == (uint)Tpm2Cc.SequenceUpdate)
            {                
                return response;
            }

            
            if(requestedProperty == (uint)Tpm2Cc.Hash)
            {
                //Skip the hash length for now, we only have SHA-256.
                //TODO: Take the length from the response buffer, since that way the parsing logic works
                //also for other length hashes.
                offset += 2; 
                byte[] sha256Hash = new byte[Sha256HashSize];
                Buffer.BlockCopy(buffer, offset, sha256Hash, 0, Sha256HashSize);
                response.Cc[requestedProperty] = sha256Hash;
            }
            else if(requestedProperty == (uint)Tpm2Cc.HashSequenceStart)
            {
                // Parse the TPMI_DH_OBJECT response
                response.PropertyCount = ReverseBytes(BitConverter.ToUInt32(buffer, offset));
            }
            else if(requestedProperty == (uint)Tpm2Cc.SequenceComplete)
            {
                // Skip the size of the digest
                offset += 2;

                // Parse the final hash value
                byte[] sha256Hash = new byte[Sha256HashSize];
                Buffer.BlockCopy(buffer, offset, sha256Hash, 0, Sha256HashSize);
                response.Cc[requestedProperty] = sha256Hash;
            }
            else
            {
                // Continue parsing the response
                response.MoreData = buffer[offset] != 0;
                offset += MoreDataSize;

                response.Capability = BitConverter.ToUInt32(buffer, offset);
                response.Capability = ReverseBytes(response.Capability);
                offset += CapabilitySize;

                response.PropertyCount = BitConverter.ToUInt32(buffer, offset);
                response.PropertyCount = ReverseBytes(response.PropertyCount);
                offset += PropertyCountSize;

                for(int i = 0; i < response.PropertyCount; i++)
                {
                    uint property = BitConverter.ToUInt32(buffer, offset);
                    property = ReverseBytes(property);
                    offset += PropertySize;

                    uint value = BitConverter.ToUInt32(buffer, offset);
                    value = ReverseBytes(value);
                    offset += ValueSize;

                    response.Properties[property] = value;
                    if(requestedProperty == Tpm2PtConstants.TPM2_PT_MODES)
                    {
                        if(property == Tpm2PtConstants.TPM2_PT_MODES)
                        {
                            response.IsFips = (value & (uint)TPMA_MODES.FIPS_140_2) != 0;
                        }
                    }
                    else if(requestedProperty == Tpm2PtConstants.TPM2_PT_FIXED || requestedProperty == (uint)TPM2_CAP.TPM_PROPERTIES)
                    {
                        //Logic for TPM2_PT_FIXED or TPM_PROPERTIES here if needed...
                    }
                }
            }

            return response;
        }

        
        private static ushort ReverseBytes(ushort value)
        {
            return (ushort)((value & 0x00FFU) << 8 | (value & 0xFF00U) >> 8);
        }

        
        private static uint ReverseBytes(uint value)
        {
            return
                  (value & 0x000000FFU) << 24
                | (value & 0x0000FF00U) << 8
                | (value & 0x00FF0000U) >> 8
                | (value & 0xFF000000U) >> 24;
        }
    }
}
