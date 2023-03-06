using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using Verifiable.Tpm.Structures;
using static Verifiable.Tpm.TpmWindowsPlatform;

namespace Verifiable.Tpm
{
    public static class Tpm
    {
        public static Version GetTpmFirmwareVersion()
        {
            TpmCommand majorCommand = new TpmCommand
            {
                Tag = TpmConstants2Temp.TPM_ST_NO_SESSIONS,
                CommandSize = 0x16,
                CommandCode = (uint)Tpm2Cc.GetCapability,
                Parameters = BitConverter.GetBytes((uint)TPM2_CAP.TPM_PROPERTIES).Reverse()
                    .Concat(BitConverter.GetBytes(TpmConstants2Temp.TPM_PT_FIRMWARE_VERSION_1).Reverse())
                    .Concat(BitConverter.GetBytes(1u).Reverse())
                    .ToArray()
            };

            TpmCommand minorCommand = new TpmCommand
            {
                Tag = TpmConstants2Temp.TPM_ST_NO_SESSIONS,
                CommandSize = 0x16,
                CommandCode = (uint)Tpm2Cc.GetCapability,
                Parameters = BitConverter.GetBytes((uint)TPM2_CAP.TPM_PROPERTIES).Reverse()
                    .Concat(BitConverter.GetBytes(TpmConstants2Temp.TPM_PT_FIRMWARE_VERSION_2).Reverse())
                    .Concat(BitConverter.GetBytes(1u).Reverse())
                    .ToArray()
            };

            byte[] majorCommandBuffer = majorCommand.ToByteArray();
            byte[] minorCommandBuffer = minorCommand.ToByteArray();

            using(TpmSafeHandleWindows tpmHandle = new TpmSafeHandleWindows())
            {
                if(tpmHandle.Open())
                {
                    uint majorResponseSize = 32;
                    byte[] majorResponseBuffer = new byte[majorResponseSize];
                    TbsReturnCode tbsResulHighBits = TpmWindowsPlatform.Tbsip_Submit_Command(
                        tpmHandle,
                        TBS_COMMAND_LOCALITY.TBS_COMMAND_LOCALITY_ZERO,
                        TpmWindowsPlatform.TBS_COMMAND_PRIORITY.TBS_COMMAND_PRIORITY_NORMAL,
                        majorCommandBuffer,
                        (uint)majorCommandBuffer.Length,
                        majorResponseBuffer,
                        ref majorResponseSize);

                    //var majorResponse = ParseTpmResponse(commandFirmwareVersionHighBitsResponse, true, false);

                    uint minorResponseSize = 32; // Reset responseSize before calling Tbsip_Submit_Command again
                    byte[] minorResponseBuffer = new byte[minorResponseSize];
                    TbsReturnCode tbsResulLowBits = TpmWindowsPlatform.Tbsip_Submit_Command(
                        tpmHandle,
                        TBS_COMMAND_LOCALITY.TBS_COMMAND_LOCALITY_ZERO,
                        TpmWindowsPlatform.TBS_COMMAND_PRIORITY.TBS_COMMAND_PRIORITY_NORMAL,
                        minorCommandBuffer,
                        (uint)minorCommandBuffer.Length,
                        minorResponseBuffer,
                        ref minorResponseSize);

                    //var minorResponse = ParseTpmResponse(commandFirmwareVersionLowBitsResponse, true, false);


                    //byte[] majorResponseBuffer = SendTpmCommand(majorCommandBuffer);
                    //byte[] minorResponseBuffer = SendTpmCommand(minorCommandBuffer);

                    if(tbsResulHighBits == 0 && tbsResulLowBits == 0)
                    {
                        TpmResponse majorResponse = TpmResponse.FromByteArray(majorResponseBuffer, TpmConstants2Temp.PT_FIXED);
                        TpmResponse minorResponse = TpmResponse.FromByteArray(minorResponseBuffer, TpmConstants2Temp.PT_FIXED);

                        // Extract firmware version components
                        if(majorResponse!.Properties!.TryGetValue(TpmConstants2Temp.TPM_PT_FIRMWARE_VERSION_1, out uint major) &&
                            minorResponse!.Properties!.TryGetValue(TpmConstants2Temp.TPM_PT_FIRMWARE_VERSION_2, out uint minor))
                        {
                            ushort majorVersion = (ushort)((major & 0xFFFF0000) >> 16);
                            ushort minorVersion = (ushort)(major & 0x0000FFFF);
                            ushort buildVersion = (ushort)((minor & 0xFFFF0000) >> 16);
                            ushort revisionVersion = (ushort)(minor & 0x0000FFFF);

                            return new Version(
                                majorVersion,
                                minorVersion,
                                buildVersion,
                            revisionVersion);
                        }
                    }

                    throw new Exception("Could not get version");
                }

                throw new Exception("Could not get context");
            }
        }


        public static List<Tpm2AlgId> GetSupportedAlgorithms()
        {
            TpmCommand getCapabilityCommand = new TpmCommand
            {
                Tag = TpmConstants2Temp.TPM_ST_SESSIONS,
                CommandSize = 2 + 4 + 4 + 4 + 4 + 4 + 4, // Tag + CommandSize + CommandCode + Capability + Property + PropertyCount + Handles
                CommandCode = (uint)Tpm2Cc.GetCapability,
                Parameters = BitConverter.GetBytes((uint)TPM2_CAP.ALGS)
                .Reverse()
                .Concat(BitConverter.GetBytes((uint)0).Reverse()) // Use 0 as the starting property
                .Concat(BitConverter.GetBytes((uint)1).Reverse())
                .ToArray()
            };


            byte[] getCapabilityCommandBuffer = getCapabilityCommand.ToByteArray();

            using(TpmSafeHandleWindows tpmHandle = new TpmSafeHandleWindows())
            {
                if(tpmHandle.Open())
                {
                    var str = ByteArrayToHexString(getCapabilityCommandBuffer);

                    uint getCapabilityCommandResponseBufferLength = 1024;
                    byte[] getCapabilityCommandResponseBuffer = new byte[getCapabilityCommandResponseBufferLength];
                    TbsReturnCode tbsGetCapabilityResultCode = TpmWindowsPlatform.Tbsip_Submit_Command(
                        tpmHandle,
                        TBS_COMMAND_LOCALITY.TBS_COMMAND_LOCALITY_ZERO,
                        TpmWindowsPlatform.TBS_COMMAND_PRIORITY.TBS_COMMAND_PRIORITY_NORMAL,
                        getCapabilityCommandBuffer,
                        (uint)getCapabilityCommandBuffer.Length,
                        getCapabilityCommandResponseBuffer,
                        ref getCapabilityCommandResponseBufferLength);

                    TpmResponse response = TpmResponse.FromByteArray(getCapabilityCommandResponseBuffer, (uint)Tpm2Cc.GetCapability);

                    if(response.ResponseCode == 0)
                    {
                        uint algorithmCount = BitConverter.ToUInt32(getCapabilityCommandResponseBuffer, 12);
                        byte[] algorithmBytes = getCapabilityCommandResponseBuffer.Skip(16).ToArray();

                        List<Tpm2AlgId> supportedAlgorithms = new List<Tpm2AlgId>();
                        for(int i = 0; i < algorithmCount; i++)
                        {
                            ushort algValue = BitConverter.ToUInt16(algorithmBytes.Skip(i * 2).Take(2).Reverse().ToArray(), 0);
                            supportedAlgorithms.Add((Tpm2AlgId)algValue);
                        }

                        return supportedAlgorithms;
                    }
                    else
                    {
                        throw new Exception($"TPM returned an error: {response.ResponseCode}");
                    }
                }

                throw new Exception($"Could not get context");
            }
        }



        public static byte[] CalculateSha256(string toBeCalculated)
        {
            byte[] dataToHash = Encoding.UTF8.GetBytes(toBeCalculated);
            uint inputLength = (uint)dataToHash.Length;

            TpmCommand hashCommand = new TpmCommand
            {
                Tag = TpmConstants2Temp.TPM_ST_NO_SESSIONS,
                CommandSize = (uint)(2 + 4 + 4 + 2 + dataToHash.Length + 2 + 4),
                CommandCode = (uint)Tpm2Cc.Hash, // Fix the command code                
                Parameters = BitConverter.GetBytes((ushort)dataToHash.Length).Reverse()
                  .Concat(dataToHash)
                  .Concat(BitConverter.GetBytes((ushort)Tpm2AlgId.Sha256).Reverse())
                  .Concat(BitConverter.GetBytes((uint)Tpm2RhConstants.OWNER).Reverse())
                  .ToArray()
            };


            byte[] hashCommandBuffer = hashCommand.ToByteArray();

            using(TpmSafeHandleWindows tpmHandle = new TpmSafeHandleWindows())
            {
                if(tpmHandle.Open())
                {
                    var str = ByteArrayToHexString(hashCommandBuffer);

                    //The return buffer length needs to accomondate also the TPM header and other data.
                    uint hashCommandResponseBufferLength = 1024;
                    byte[] hashCommandResponseBuffer = new byte[hashCommandResponseBufferLength];
                    TbsReturnCode tbsHashResultCode = TpmWindowsPlatform.Tbsip_Submit_Command(
                        tpmHandle,
                        TBS_COMMAND_LOCALITY.TBS_COMMAND_LOCALITY_ZERO,
                        TpmWindowsPlatform.TBS_COMMAND_PRIORITY.TBS_COMMAND_PRIORITY_NORMAL,
                        hashCommandBuffer,
                        (uint)hashCommandBuffer.Length,
                        hashCommandResponseBuffer,
                        ref hashCommandResponseBufferLength);


                    TpmResponse response = TpmResponse.FromByteArray(hashCommandResponseBuffer, (uint)Tpm2Cc.Hash);

                    if(response.ResponseCode == 0)
                    {
                        // Extract the SHA-256 hash from the response buffer
                        // The hash length is always 32 bytes for SHA-256
                        byte[] hash = (byte[])response.Cc[(uint)Tpm2Cc.Hash];
                        return hash;
                    }
                    else
                    {
                        throw new Exception($"TPM returned an error: {response.ResponseCode}");
                    }
                }
            }

            throw new Exception("Could not get context");
        }


        public static byte[] CalculateLongSha256(byte[] veryLongToBeCalculated)
        {
            uint inputLength = (uint)veryLongToBeCalculated.Length;

            // Start the hash sequence
            (TpmSafeHandleWindows contextHandle, uint hashSequenceHandle, byte[] authValue) = StartHashSequence(Tpm2AlgId.Sha256);

            // Define the maximum chunk size that can be sent to the TPM
            int maxChunkSize = 2; // You may need to adjust this value based on your TPM's capabilities

            // Update the hash sequence with the data chunks
            for(int i = 0; i < inputLength; i += maxChunkSize)
            {
                int chunkSize = Math.Min(maxChunkSize, (int)(inputLength - i));
                byte[] dataChunk = new byte[chunkSize];
                Array.Copy(veryLongToBeCalculated, i, dataChunk, 0, chunkSize);
                UpdateHashSequence(contextHandle, hashSequenceHandle, authValue, dataChunk);
            }

            // Complete the hash sequence and get the final hash value
            byte[] finalHashValue = CompleteHashSequence(contextHandle, hashSequenceHandle);

            return finalHashValue;
        }


        public static bool SelfTest(bool fullTest)
        {
            TpmCommand selfTestCommand = new TpmCommand
            {
                Tag = TpmConstants2Temp.TPM_ST_NO_SESSIONS,
                CommandSize = 11, // 2 bytes (size of TPM_ST_NO_SESSIONS) + 4 bytes (size of uint32) + 4 bytes (size of uint32) + 1 byte (size of byte)
                CommandCode = (uint)Tpm2Cc.SelfTest,
                Parameters = new byte[] { fullTest ? (byte)1 : (byte)0 }
            };

            byte[] selfTestCommandBuffer = selfTestCommand.ToByteArray();
            var selfTestCommandBufferAsHex = BitConverter.ToString(selfTestCommandBuffer).Replace("-", " ");

            using(TpmSafeHandleWindows tpmHandle = new TpmSafeHandleWindows())
            {
                if(tpmHandle.Open())
                {
                    uint selfTestCommandResponseBufferLength = 64;
                    byte[] selfTestCommandResponseBuffer = new byte[selfTestCommandResponseBufferLength];
                    TbsReturnCode tbsSelfTestResultCode = TpmWindowsPlatform.Tbsip_Submit_Command(
                        tpmHandle,
                        TBS_COMMAND_LOCALITY.TBS_COMMAND_LOCALITY_ZERO,
                        TpmWindowsPlatform.TBS_COMMAND_PRIORITY.TBS_COMMAND_PRIORITY_NORMAL,
                        selfTestCommandBuffer,
                        (uint)selfTestCommandBuffer.Length,
                        selfTestCommandResponseBuffer,
                        ref selfTestCommandResponseBufferLength);

                    if(tbsSelfTestResultCode != TbsReturnCode.TBS_SUCCESS)
                    {
                        throw new Exception($"TBS returned an error: {tbsSelfTestResultCode}");
                    }

                    TpmResponse response = TpmResponse.FromByteArray(selfTestCommandResponseBuffer, (uint)Tpm2Cc.SelfTest);

                    if(response.ResponseCode == TpmRc.Success)
                    {
                        return true;
                    }
                    else
                    {
                        throw new Exception($"TPM returned an error: {response.ResponseCode}");
                    }
                }

                throw new Exception("Could not get context");
            }
        }



        public static bool IsFips()
        {
            TpmCommand isFipsCommand = new TpmCommand
            {
                Tag = TpmConstants2Temp.TPM_ST_NO_SESSIONS, // 2 bytes (size of TPM_ST_NO_SESSIONS)
                CommandSize = 22, // 4 bytes (size of uint32)
                CommandCode = (uint)Tpm2Cc.GetCapability, // 4 bytes (size of uint32)
                Parameters = BitConverter.GetBytes((uint)TPM2_CAP.TPM_PROPERTIES).Reverse()
                 .Concat(BitConverter.GetBytes(Tpm2PtConstants.TPM2_PT_MODES).Reverse())
                 .Concat(BitConverter.GetBytes(1u).Reverse())
                 .ToArray() // 3 * 4 bytes (3 * size of uint32)
            };


            byte[] isFipsCommandBuffer = isFipsCommand.ToByteArray();
            var isFipsCommandBufferAsHex = ByteArrayToHexString(isFipsCommandBuffer);

            TpmSafeHandleWindows tpmHandle = new TpmSafeHandleWindows();
            if(tpmHandle.Open())
            {
                //The return buffer length needs to accomondate also the TPM header and other data.
                uint isFipsCommandResponseBufferLength = 64;
                byte[] isFipsCommandResponseBuffer = new byte[isFipsCommandResponseBufferLength];
                TbsReturnCode tbsIsFipsResultCode = TpmWindowsPlatform.Tbsip_Submit_Command(
                    tpmHandle,
                    TBS_COMMAND_LOCALITY.TBS_COMMAND_LOCALITY_ZERO,
                    TpmWindowsPlatform.TBS_COMMAND_PRIORITY.TBS_COMMAND_PRIORITY_NORMAL,
                    isFipsCommandBuffer,
                    (uint)isFipsCommandBuffer.Length,
                    isFipsCommandResponseBuffer,
                    ref isFipsCommandResponseBufferLength);

                if(tbsIsFipsResultCode != TbsReturnCode.TBS_SUCCESS)
                {
                    throw new Exception($"TBS returned an error: {tbsIsFipsResultCode}");
                }

                TpmResponse response = TpmResponse.FromByteArray(isFipsCommandResponseBuffer, Tpm2PtConstants.TPM2_PT_MODES);
                if(response.ResponseCode == 0)
                {
                    return response.IsFips;
                }
                else
                {
                    throw new Exception($"TPM returned an error: {response.ResponseCode}");
                }
            }

            throw new Exception("Could not get context.");
        }


        public static Version GetVersion()
        {
            using(TpmSafeHandleWindows tpmHandle = new TpmSafeHandleWindows())
            {
                if(tpmHandle.Open())
                {

                    // TPM2_GetCapability command
                    byte[] command = new byte[]
                    {
                        0x80, 0x01, // TPM_ST_NO_SESSIONS
                        0x00, 0x00, 0x00, 0x16, // Command Size
                        0x00, 0x00, 0x01, 0x7A, // TPM_CC_GetCapability
                        0x00, 0x00, 0x00, 0x06, // TPM_CAP_TPM_PROPERTIES
                        0x00, 0x00, 0x01, 0x00, // TPM_PT_FIXED
                        0x00, 0x00, 0x00, 0x01  // Property Count
                    };

                    var firmware1Bytes = BitConverter.GetBytes(TpmConstants2Temp.TPM_PT_FIRMWARE_VERSION_1);
                    if(BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(firmware1Bytes);
                    }

                    // Get TPM_PT_FIRMWARE_VERSION_1
                    byte[] commandFirmwareHighBits = new byte[]
                    {
                        0x80, 0x01, // TPM_ST_NO_SESSIONS
                        0x00, 0x00, 0x00, 0x16, // Command Size
                        0x00, 0x00, 0x01, 0x7A, // TPM_CC_GetCapability
                        0x00, 0x00, 0x00, 0x06, // TPM_CAP_TPM_PROPERTIES
                        // TPM_PT_FIRMWARE_VERSION_1 bye
                        firmware1Bytes[0], firmware1Bytes[1], firmware1Bytes[2], firmware1Bytes[3],
                        0x00, 0x00, 0x00, 0x01  // Property Count
                    };


                    var firmware2Bytes = BitConverter.GetBytes(TpmConstants2Temp.TPM_PT_FIRMWARE_VERSION_2);
                    if(BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(firmware2Bytes);
                    }

                    // Get TPM_PT_FIRMWARE_VERSION_2
                    byte[] commandFirmwareLowBits = new byte[]
                    {
                        0x80, 0x01, // TPM_ST_NO_SESSIONS
                        0x00, 0x00, 0x00, 0x16, // Command Size
                        0x00, 0x00, 0x01, 0x7A, // TPM_CC_GetCapability
                        0x00, 0x00, 0x00, 0x06, // TPM_CAP_TPM_PROPERTIES
                        // ... (Same as the previous command, but with TPM_PT_FIXED replaced by TPM_PT_FIRMWARE_VERSION_2 (0x0105))
                        firmware2Bytes[0], firmware2Bytes[1], firmware2Bytes[2], firmware2Bytes[3],
                        0x00, 0x00, 0x00, 0x01  // Property Count
                    };

                    uint majorResponseSize = 32;
                    byte[] commandFirmwareVersionHighBitsResponse = new byte[majorResponseSize];
                    //uint tbsResult = TpmWindows.Tbsip_Submit_Command(tpmContext, 0, command, (uint)command.Length, response, ref responseSize);

                    TbsReturnCode tbsResulHighBits = TpmWindowsPlatform.Tbsip_Submit_Command(
                        tpmHandle,
                        TBS_COMMAND_LOCALITY.TBS_COMMAND_LOCALITY_ZERO,
                        TpmWindowsPlatform.TBS_COMMAND_PRIORITY.TBS_COMMAND_PRIORITY_NORMAL,
                        commandFirmwareHighBits,
                        (uint)commandFirmwareHighBits.Length,
                        commandFirmwareVersionHighBitsResponse,
                        ref majorResponseSize);

                    var majorResponse = ParseTpmResponse(commandFirmwareVersionHighBitsResponse, true, false);


                    uint minorResponseSize = 32; // Reset responseSize before calling Tbsip_Submit_Command again
                    byte[] commandFirmwareVersionLowBitsResponse = new byte[minorResponseSize];
                    TbsReturnCode tbsResulLowBits = TpmWindowsPlatform.Tbsip_Submit_Command(
                        tpmHandle,
                        TBS_COMMAND_LOCALITY.TBS_COMMAND_LOCALITY_ZERO,
                        TpmWindowsPlatform.TBS_COMMAND_PRIORITY.TBS_COMMAND_PRIORITY_NORMAL,
                        commandFirmwareLowBits,
                        (uint)commandFirmwareLowBits.Length,
                        commandFirmwareVersionLowBitsResponse,
                        ref minorResponseSize);

                    var minorResponse = ParseTpmResponse(commandFirmwareVersionLowBitsResponse, true, false);

                    if(tbsResulHighBits == 0 && tbsResulLowBits == 0)
                    {
                        var major = GetFirmwareVersions(majorResponse, TpmConstants2Temp.TPM_PT_FIRMWARE_VERSION_1);
                        var minor = GetFirmwareVersions(minorResponse, TpmConstants2Temp.TPM_PT_FIRMWARE_VERSION_2);
                        if(major.HasValue && minor.HasValue)
                        {
                            ushort majorVersion = (ushort)((major.Value & 0xFFFF0000) >> 16);
                            ushort minorVersion = (ushort)(major.Value & 0x0000FFFF);
                            ushort buildVersion = (ushort)((minor.Value & 0xFFFF0000) >> 16);
                            ushort revisionVersion = (ushort)(minor.Value & 0x0000FFFF);

                            return new Version(
                                majorVersion,
                                minorVersion,
                                buildVersion,
                                revisionVersion);
                        }
                    }
                }
            }

            throw new Exception();
        }

        public static TpmResponse ParseTpmResponse(byte[] buffer, bool isHandle, bool isAuthorization)
        {
            int offset = 0;
            TpmResponse response = new TpmResponse();

            // Parsing the header
            response.Tag = BitConverter.ToUInt16(buffer, offset);
            response.Tag = ReverseBytes(response.Tag);
            offset += 2;

            response.ResponseSize = BitConverter.ToUInt32(buffer, offset);
            response.ResponseSize = ReverseBytes(response.ResponseSize);
            offset += 4;

            var responseCode = BitConverter.ToUInt32(buffer, offset);
            response.ResponseCode = (TpmRc)ReverseBytes(responseCode);
            offset += 4;

            // Continue parsing the response
            response.MoreData = buffer[offset] != 0;
            offset += 1;

            response.Capability = BitConverter.ToUInt32(buffer, offset);
            response.Capability = ReverseBytes(response.Capability);
            offset += 4;

            response.PropertyCount = BitConverter.ToUInt32(buffer, offset);
            response.PropertyCount = ReverseBytes(response.PropertyCount);
            offset += 4;

            for(int i = 0; i < response.PropertyCount; i++)
            {
                uint property = BitConverter.ToUInt32(buffer, offset);
                property = ReverseBytes(property);
                offset += 4;

                uint value = BitConverter.ToUInt32(buffer, offset);
                value = ReverseBytes(value);
                offset += 4;

                response.Properties[property] = value;
            }

            return response;
        }

        public static uint? GetFirmwareVersions(TpmResponse response, uint flag)
        {
            if(response.Properties.TryGetValue(flag, out uint version))
            {
                return version;
            }

            return null;
        }

        private static string ByteArrayToHexString(byte[] byteArray)
        {
            StringBuilder hexString = new(byteArray.Length * 2);
            for(int i = 0; i < byteArray.Length; i++)
            {
                hexString.AppendFormat("{0:X2} ", byteArray[i]);
            }
            return hexString.ToString().TrimEnd();
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


        private static (TpmSafeHandleWindows contextHandle, uint hashSequenceHandle, byte[] authValue) StartHashSequence(Tpm2AlgId hashAlgorithm)
        {
            // Create an auth value randomly
            byte[] authValue = new byte[] { 0xA, 0xB, 0xC, 0xD };

            // Create the hash sequence
            TpmCommand startHashSequenceCommand = new TpmCommand
            {
                Tag = TpmConstants2Temp.TPM_ST_NO_SESSIONS,
                CommandSize = (uint)(2 + 4 + 4 + 1 + +1 + authValue.Length + 2),
                CommandCode = (uint)Tpm2Cc.HashSequenceStart,
                Parameters = /*BitConverter.GetBytes((ushort)authValue.Length).Reverse()*/
                    /*.Concat(authValue)*/
                    BitConverter.GetBytes((ushort)hashAlgorithm).Reverse()
                    .ToArray()
            };


            byte[] startHashSequenceCommandBuffer = startHashSequenceCommand.ToByteArray();
            var startHashSequenceCommandBufferAsHex = BitConverter.ToString(startHashSequenceCommandBuffer).Replace("-", " ");

            TpmSafeHandleWindows tpmHandle = new TpmSafeHandleWindows();
            if(tpmHandle.Open())
            {
                // Send the command to the TPM
                uint cmdResponseBufferLength = 1024;
                byte[] cmdResponseBuffer = new byte[cmdResponseBufferLength];
                TbsReturnCode tbsCmdResultCode = TpmWindowsPlatform.Tbsip_Submit_Command(
                    tpmHandle,
                    TBS_COMMAND_LOCALITY.TBS_COMMAND_LOCALITY_ZERO,
                    TpmWindowsPlatform.TBS_COMMAND_PRIORITY.TBS_COMMAND_PRIORITY_NORMAL,
                    startHashSequenceCommandBuffer,
                    (uint)startHashSequenceCommandBuffer.Length,
                    cmdResponseBuffer,
                    ref cmdResponseBufferLength);

                // Parse the response
                TpmResponse response = TpmResponse.FromByteArray(cmdResponseBuffer, (uint)Tpm2Cc.HashSequenceStart);

                if(response.ResponseCode == 0)
                {
                    // Extract the hash sequence handle
                    uint hashSequenceHandle = response.PropertyCount;
                    return (tpmHandle, hashSequenceHandle, authValue);
                }
                else
                {
                    tpmHandle.Close();
                    throw new Exception($"TPM returned an error: {response.ResponseCode}");
                }
            }

            throw new Exception("Could not get context");
        }


        public static void UpdateHashSequence(TpmSafeHandleWindows contextHandle, uint hashSequenceHandle, byte[] authValue, byte[] dataChunk)
        {
            Tpm2bMaxBuffer dataBuffer = new(dataChunk);
            byte[] dataBufferBytes = dataBuffer.ToByteArray();
            
            TpmCommand sequenceUpdateCommand = new TpmCommand
            {
                Tag = TpmConstants2Temp.TPM_ST_NO_SESSIONS,
                CommandSize = (uint)(2 + 4 + 4 + 4 + dataBufferBytes.Length),
                CommandCode = (uint)Tpm2Cc.SequenceUpdate,
                Parameters =
                    BitConverter.GetBytes(hashSequenceHandle).Reverse()                    
                    .Concat(dataBufferBytes).ToArray()
            };

            byte[] sequenceUpdateCommandBuffer = sequenceUpdateCommand.ToByteArray();
            var updateHashSequenceCommandAsHex = BitConverter.ToString(sequenceUpdateCommandBuffer).Replace("-", " ");

            uint sequenceUpdateCommandResponseBufferLength = 1024;
            byte[] sequenceUpdateCommandResponseBuffer = new byte[sequenceUpdateCommandResponseBufferLength];
            TbsReturnCode tbsHashResultCode = TpmWindowsPlatform.Tbsip_Submit_Command(
                contextHandle,
                TBS_COMMAND_LOCALITY.TBS_COMMAND_LOCALITY_ZERO,
                TpmWindowsPlatform.TBS_COMMAND_PRIORITY.TBS_COMMAND_PRIORITY_NORMAL,
                sequenceUpdateCommandBuffer,
                (uint)sequenceUpdateCommandBuffer.Length,
                sequenceUpdateCommandResponseBuffer,
                ref sequenceUpdateCommandResponseBufferLength);

            TpmResponse response = TpmResponse.FromByteArray(sequenceUpdateCommandResponseBuffer, (uint)Tpm2Cc.SequenceUpdate);

            if(tbsHashResultCode != TbsReturnCode.TBS_SUCCESS || response.ResponseCode != 0)
            {
                throw new Exception($"TPM returned an error: {response.ResponseCode}");
            }
        }



        private static byte[] CompleteHashSequence(TpmSafeHandleWindows contextHandle, uint hashSequenceHandle)
        {
            // Create the SequenceComplete command
            TpmCommand sequenceCompleteCommand = new TpmCommand
            {
                Tag = TpmConstants2Temp.TPM_ST_NO_SESSIONS,
                CommandSize = (uint)(2 + 4 + 4 + 4 + 4 + 4),
                CommandCode = (uint)Tpm2Cc.SequenceComplete,
                Parameters = BitConverter.GetBytes(hashSequenceHandle).Reverse()
                    .Concat(BitConverter.GetBytes((uint)0))
                    .Concat(BitConverter.GetBytes((uint)Tpm2RhConstants.NULL))
                    .Concat(BitConverter.GetBytes((uint)1)).ToArray()
            };

            byte[] sequenceCompleteCommandBuffer = sequenceCompleteCommand.ToByteArray();
            var sequenceCompleteCommandBufferAsHex = ByteArrayToHexString(sequenceCompleteCommandBuffer);

            uint sequenceCompleteCommandResponseBufferLength = 1024;
            byte[] sequenceCompleteCommandResponseBuffer = new byte[sequenceCompleteCommandResponseBufferLength];
            TbsReturnCode tbsHashResultCode = TpmWindowsPlatform.Tbsip_Submit_Command(
                contextHandle, // Use the context from StartHashSequence
                TBS_COMMAND_LOCALITY.TBS_COMMAND_LOCALITY_ZERO,
                TpmWindowsPlatform.TBS_COMMAND_PRIORITY.TBS_COMMAND_PRIORITY_NORMAL,
                sequenceCompleteCommandBuffer,
                (uint)sequenceCompleteCommandBuffer.Length,
                sequenceCompleteCommandResponseBuffer,
                ref sequenceCompleteCommandResponseBufferLength);

            TpmResponse response = TpmResponse.FromByteArray(sequenceCompleteCommandResponseBuffer, (uint)Tpm2Cc.SequenceComplete);

            if(response.ResponseCode == 0)
            {
                // Extract the SHA-256 hash from the response buffer
                byte[] hash = (byte[])response.Cc[(uint)Tpm2Cc.SequenceComplete];
                return hash;
            }
            else
            {
                throw new Exception($"TPM returned an error: {response.ResponseCode}");
            }
        }
    }
}
