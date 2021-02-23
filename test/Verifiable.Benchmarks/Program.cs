using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using System;
using System.Security.Cryptography;

namespace DotSsi.Benchmarks
{
    /// <summary>
    /// This is a starter benchmarking test to start also with benchmarks on the pipeline.
    /// </summary>
    public class Sha256Starter
    {
        private const int N = 10000;
        private readonly byte[] data;

        private readonly SHA256 sha256 = SHA256.Create();


        public Sha256Starter()
        {
            data = new byte[N];
            new Random(42).NextBytes(data);
        }

        [Benchmark]
        public byte[] Sha256() => sha256.ComputeHash(data);
    }


    /// <summary>
    /// The BenchmarkDotNet runner.
    /// </summary>
    public static class Program
    {
        static int Main(string[] args)
        {
            try
            {
                _ = BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);

                return 0;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.Message);
                Console.ResetColor();

                return 1;
            }
        }
    }
}
