using Verifable.Tpm;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Tpm2Lib;
using Xunit;

namespace Verifable.Tests
{
    /// <summary>
    /// Wraps the simular and has the correct start sequence for the simulator.
    /// </summary>
    public sealed class TpmSimulatorWrapper: TpmWrapper
    {
        /// <summary>
        /// A handle to the process that is connected to the TPM simulator
        /// executable.
        /// </summary>
        private Process TpmSimulatorProcessHandle { get; }


        /// <summary>
        /// A default simulator constructor.
        /// </summary>
        /// <param name="pathToSimulator">Path to the simulator executable.</param>
        public TpmSimulatorWrapper(string pathToSimulator = @"..\..\..\TpmSimulator\Simulator.exe"): base(isSimulator: true)
        {
            TpmSimulatorProcessHandle = CreateTpmSimulatorHandle(pathToSimulator);
            _ = TpmSimulatorProcessHandle.Start();

            TpmDevice.Connect();

            //Then specific initiation logic for this TCP TPM simulator.
            TpmDevice.PowerCycle();
            Tpm.Startup(Su.Clear);

            //Reset the dictionary - attack logic that exists also in the TPM simulator.
            //Very forgiving parameters so that the simulator won't simulate
            //lock-out!
            Tpm.DictionaryAttackParameters(TpmHandle.RhLockout, 1000, 10, 1);

            //Zero out all counters.
            Tpm.DictionaryAttackLockReset(TpmHandle.RhLockout);
        }


        /// <inheritdoc />
        protected override void Dispose(bool disposing)
        {
            if(disposing)
            {
                TpmSimulatorProcessHandle.Dispose();
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a process handle for the simular.
        /// </summary>
        /// <returns>Process handle for the simulator.</returns>
        /// <remarks>Currently only for Windows.</remarks>
        private static Process CreateTpmSimulatorHandle(string pathToSimulator)
        {
            return new Process()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = pathToSimulator,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                }
            };
        }
    }


    /// <summary>
    /// Quick test container TPM check for tests...
    /// </summary>
    public class TpmTests: IDisposable
    {
        private TpmWrapper TpmWrapper { get; }

        public TpmTests()
        {
            string? usePlatformTpmString = Environment.GetEnvironmentVariable("USE_PLATFORM_TPM");
            string? dotNetPlatformString = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");

            bool usePlatformTpm = string.IsNullOrWhiteSpace(usePlatformTpmString) && bool.TryParse(usePlatformTpmString, out usePlatformTpm);
            bool isCiEnvironment = dotNetPlatformString?.Equals("ci", StringComparison.InvariantCultureIgnoreCase) == true;

            //It is not possible to test TPM functionality at all unless on supported platforms.
            Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux),
                $"Trust Platform Module (TPM) 2.0 is supported only on {OSPlatform.Windows} and {OSPlatform.Linux}.");

            //Local builds are currently possible only on simulator and Windows.
            //CI builds are done using TPM, but currently it works only on Linux.
            //TODO: Add simulator for local Linux builds too. Running on physical TPM may cause unexpected
            //systemwide problems. Only test platform TPMs on CI as the environments can be thrown away.
            Skip.If(
                /* This first condition checks if this is a CI environment. Skip if parameters are not set correctly. */
                (!usePlatformTpm && isCiEnvironment && !RuntimeInformation.IsOSPlatform(OSPlatform.Linux))

                /* And this one if this this is a local Windows environment with simulator. */
                || (!isCiEnvironment && !usePlatformTpm && !RuntimeInformation.IsOSPlatform(OSPlatform.Windows)),
                $"Trust Platform Module (TPM) 2.0 on continuous environment is supported only on {OSPlatform.Linux}.");

            //TODO: Linux simulator for local runs should be added and something like runSettings that makes it
            //easy enough to choose where to run (messing with hardware TPM can cause trouble, so can't be
            //used by default).
            if(!usePlatformTpm && !isCiEnvironment && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                TpmWrapper = new TpmSimulatorWrapper();
            }
            else
            {
                //The CI pipeline installs TPM libraries on Linux...
                TpmWrapper = new TpmWrapper();
            }
        }


        [SkippableFact]
        public void TpmGetPropertiesSucceeds()
        {
            var properties = TpmWrapper.Tpm.GetTpmProperties();

            //A sampling of properties are checked here against known values.
            Assert.True(properties.IsFips1402);
        }


        public void Dispose()
        {
            TpmWrapper?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
