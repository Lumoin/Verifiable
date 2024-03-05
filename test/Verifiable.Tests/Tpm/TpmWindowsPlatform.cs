using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Verifiable.Tpm
{
    public static partial class TpmWindowsPlatform
    {
        public enum TbsReturnCode: uint
        {
            TBS_SUCCESS = 0x0,
            TBS_E_BAD_PARAMETER = 0x80284002,
            TBS_E_BUFFER_TOO_LARGE = 0x8028400E,
            TBS_E_INTERNAL_ERROR = 0x80284001,
            TBS_E_INSUFFICIENT_BUFFER = 0x80284005,
            TBS_E_INVALID_CONTEXT = 0x80284004,
            TBS_E_INVALID_OUTPUT_POINTER = 0x80284003,
            TBS_E_IOERROR = 0x80284006
        }


        internal enum TBS_COMMAND_LOCALITY: uint
        {
            TBS_COMMAND_LOCALITY_ZERO = 0,
            TBS_COMMAND_LOCALITY_ONE = 1,
            TBS_COMMAND_LOCALITY_TWO = 2,
            TBS_COMMAND_LOCALITY_THREE = 3,
            TBS_COMMAND_LOCALITY_FOUR = 4
        }

        internal enum TBS_COMMAND_PRIORITY: uint
        {
            TBS_COMMAND_PRIORITY_LOW = 100,
            TBS_COMMAND_PRIORITY_NORMAL = 200,
            TBS_COMMAND_PRIORITY_SYSTEM = 400,
            TBS_COMMAND_PRIORITY_HIGH = 300,
            TBS_COMMAND_PRIORITY_MAX = 0x80000000
        }

        [StructLayout(LayoutKind.Sequential)]
#pragma warning disable CA1815 // Override equals and operator equals on value types
        public struct TBS_CONTEXT_PARAMS
#pragma warning restore CA1815 // Override equals and operator equals on value types
        {
            public TBS_CONTEXT_VERSION Version;
            public TBS_CONTEXT_CREATE_FLAGS Flags;
        }

        public enum TBS_CONTEXT_VERSION: uint
        {
            ONE = 1,
            TWO = 2
        }

        public enum TBS_TPM_VERSION: uint
        {
            Invalid = 0,
            V1_2 = 1,
            V2 = 2
        }

        public enum TBS_CONTEXT_CREATE_FLAGS: uint
        {
            RequestRaw = 0x00000001,
            IncludeTpm12 = 0x00000002,
            IncludeTpm20 = 0x00000004
        }


        [DllImport("tbs.dll", EntryPoint = "Tbsi_Context_Create", CharSet = CharSet.Unicode)]
        public static extern TbsReturnCode Tbsi_Context_Create(ref TBS_CONTEXT_PARAMS contextParams, out IntPtr context);

        [DllImport("tbs.dll", EntryPoint = "Tbsip_Context_Close", CharSet = CharSet.Unicode)]
        public static extern TbsReturnCode Tbsip_Context_Close(IntPtr context);
          
        /*
        [DllImport("tbs.dll", EntryPoint = "Tbsip_Submit_Command", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern TbsReturnCode Tbsip_Submit_Command(
            TpmContextSafeHandle context,
            TBS_COMMAND_LOCALITY locality,
            TBS_COMMAND_PRIORITY priority,
            byte[] inBuffer,
            uint inBufferSize,
            byte[] outbuf,
            ref uint outBufLen
        );*/

        [LibraryImport("tbs", EntryPoint = "Tbsip_Submit_Command", StringMarshalling = StringMarshalling.Utf16)]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]        
        internal static partial TbsReturnCode Tbsip_Submit_Command(
            TpmSafeHandleWindows context,
            TBS_COMMAND_LOCALITY locality,
            TBS_COMMAND_PRIORITY priority,
            byte[] inBuffer,
            uint inBufferSize,
            byte[] outbuf,
            ref uint outBufLen
        );
    }
}
