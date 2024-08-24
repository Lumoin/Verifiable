using SharpFuzz;
using System;
using System.Text.Json;


namespace Verifiable.FuzzTests
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Fuzzer.LibFuzzer.Run(json =>
            {
                try
                {                                        
                    _ = JsonSerializer.Deserialize<object>(json);
                }
                catch(JsonException)
                {
                }
                catch(Exception ex)
                {                    
                    Console.WriteLine($"Unexpected exception occurred: {ex.Message}");
                }
            });
        }
    }
}
