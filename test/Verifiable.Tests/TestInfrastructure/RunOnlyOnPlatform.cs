using System;
using Xunit;

namespace Verifiable.Tests.TestInfrastructure
{
    public static class Platforms
    {
        public const string Windows = "windows";
        public const string Linux = "linux";
        public const string MacOS = "macos";
    }

    
    public class RunOnlyOnPlatformFactAttribute: FactAttribute
    {
        public RunOnlyOnPlatformFactAttribute(params string[] platforms)
        {
            if(platforms == null || platforms.Length == 0 || !IsRunningOnPlatform(platforms))
            {
                Skip = $"Test can only be run on one of the following platforms: {string.Join(", ", Platforms.Windows, Platforms.Linux, Platforms.MacOS)}";
            }
        }


        public static void SkipTestIfNotOnWindowsOrLinux()
        {
            if(!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
            {
                throw new SkipException("Test can only be run on Windows or Linux.");
            }
        }


        private static bool IsRunningOnPlatform(string[] platforms)
        {
            foreach(var platform in platforms)
            {
                if(string.Equals(platform, Platforms.Windows, StringComparison.OrdinalIgnoreCase) && OperatingSystem.IsWindows())
                {
                    return true;
                }

                if(string.Equals(platform, Platforms.Linux, StringComparison.OrdinalIgnoreCase) && OperatingSystem.IsLinux())
                {
                    return true;
                }

                if(string.Equals(platform, Platforms.MacOS, StringComparison.OrdinalIgnoreCase) && OperatingSystem.IsMacOS())
                {
                    return true;
                }                
            }

            return false;
        }
    }
}
