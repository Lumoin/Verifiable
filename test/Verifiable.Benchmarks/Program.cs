using BenchmarkDotNet.Running;
using System;

namespace Verifiable.Benchmarks
{
    /// <summary>
    /// The BenchmarkDotNet runner.
    /// </summary>
    internal static class Program
    {
        public static int Main(string[] args)
        {
            try
            {
                _ = BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
                return 0;
            }
            catch(Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.Message);
                Console.ResetColor();
                return 1;
            }
        }
    }
}