using System.Diagnostics;
using Tpm2Lib;
using Verifiable.Tpm;

namespace Verifiable.Core
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
        public TpmSimulatorWrapper(string pathToSimulator = @"..\..\..\TpmSimulator\Simulator.exe") : base(isSimulator: true)
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
}
