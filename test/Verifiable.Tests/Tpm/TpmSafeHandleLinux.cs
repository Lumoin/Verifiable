using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace Verifiable.Tests.Tpm
{
    public class TpmLinuxSafeHandle: SafeHandle
    {
        private static readonly ActivitySource TpmActivitySource = new("TpmLinuxSafeHandle");
        private static readonly DiagnosticSource TpmDiagnosticSource = new DiagnosticListener("TpmLinuxSafeHandle");

        private FileStream? _fileStream;

        public TpmLinuxSafeHandle(): base(IntPtr.Zero, ownsHandle: true)
        {
        }

        public bool Open()
        {
            using(Activity? activity = TpmActivitySource.StartActivity("Open"))
            {
                try
                {
                    // Open the TPM device file
                    _fileStream = new FileStream("/dev/tpmrm0", FileMode.Open, FileAccess.ReadWrite);
                    SetHandle(_fileStream.SafeFileHandle.DangerousGetHandle());

                    activity?.SetTag("openResult", "Success");
                    return true;
                }
                catch(Exception ex)
                {
                    activity?.SetTag("error", ex.Message);
                    return false;
                }
            }
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            using(Activity? activity = TpmActivitySource.StartActivity("ReleaseHandle"))
            {
                if(TpmDiagnosticSource.IsEnabled("/dev/tpmrm0_Close.Before"))
                {
                    TpmDiagnosticSource.Write("/dev/tpmrm0_Close.Before", new { Handle = handle });
                }

                try
                {
                    _fileStream?.Dispose();
                    activity?.SetTag("closeResult", "Success");

                    return true;
                }
                catch(Exception ex)
                {
                    activity?.SetTag("error", ex.Message);
                    return false;
                }
            }
        }
    }
}
