using System;
using System.Runtime.Versioning;


namespace Verifiable.Tpm
{
    [SupportedOSPlatform("Linux")]
    public class TpmLinux: ITpm
    {
        public static bool IsSupported { get; } = OperatingSystem.IsLinux();
    }
}
