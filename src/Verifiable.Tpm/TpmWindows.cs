using System;
using System.Runtime.Versioning;

namespace Verifiable.Tpm
{
    [SupportedOSPlatform("Windows")]
    public class TpmWindows: ITpm
    {
        public static bool IsSupported { get; } = OperatingSystem.IsWindows();

    }
}
