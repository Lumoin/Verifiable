using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static Verifiable.Tpm.TpmWindowsPlatform;

namespace Verifiable.Tpm
{
    public class TpmSafeHandleWindows: SafeHandle
    {
        private static TBS_CONTEXT_PARAMS contextParams = new()
        {
            Version = TBS_CONTEXT_VERSION.TWO,
            Flags = TBS_CONTEXT_CREATE_FLAGS.IncludeTpm20
        };

        private static ActivitySource TpmActivitySource => new("TpmContextSafeHandle");

        private static DiagnosticSource TpmDiagnosticSource => new DiagnosticListener("TpmContextSafeHandle");

        public TbsReturnCode? LastReturnCode { get; private set; } = TbsReturnCode.TBS_SUCCESS;


        public TpmSafeHandleWindows(): base(IntPtr.Zero, ownsHandle: true)
        {
        }


        public bool Open()
        {
            using(Activity? activity = TpmActivitySource.StartActivity("Tbsi_Context_Create"))
            {
                
                IntPtr tpmContext = IntPtr.Zero;
                TbsReturnCode openResult = Tbsi_Context_Create(ref contextParams, out nint context);
                LastReturnCode = openResult;

                activity?.SetTag("openResult", openResult.ToString());

                if(openResult != TbsReturnCode.TBS_SUCCESS)
                {
                    activity?.SetTag("error", true);
                }

                SetHandle(context);

                return openResult == TbsReturnCode.TBS_SUCCESS;
            }
        }


        public override bool IsInvalid => handle == IntPtr.Zero || (LastReturnCode != TbsReturnCode.TBS_SUCCESS);


        protected override bool ReleaseHandle()
        {
            using(Activity? activity = TpmActivitySource.StartActivity("Tbsip_Context_Close"))
            {
                if(TpmDiagnosticSource.IsEnabled("Tbsip_Context_Close.Before"))
                {
                    TpmDiagnosticSource.Write("Tbsip_Context_Close.Before", new { Handle = handle });
                }

                TbsReturnCode closeResult = Tbsip_Context_Close(handle);
                LastReturnCode = closeResult;

                activity?.SetTag("closeResult", closeResult.ToString());

                if(closeResult != TbsReturnCode.TBS_SUCCESS)
                {
                    activity?.SetTag("error", true);
                }
                
                if(TpmDiagnosticSource.IsEnabled("Tbsip_Context_Close.After"))
                {
                    TpmDiagnosticSource.Write("Tbsip_Context_Close.After", new { Handle = handle, CloseResult = closeResult });
                }

                return closeResult == TbsReturnCode.TBS_SUCCESS;
            }
        }
    }
}
