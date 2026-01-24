using System;
using Verifiable.Tpm.Extensions.Info;
using Verifiable.Tpm.Extensions.Pcr;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable;

/// <summary>
/// Formats TPM information for human-readable console output.
/// </summary>
internal static class TpmInfoFormatter
{
    /// <summary>
    /// Writes TPM information to the console in a human-readable format.
    /// </summary>
    /// <param name="info">The TPM information to display.</param>
    /// <param name="revealSecrets">If true, shows full PCR digest values. If false (default), redacts them.</param>
    /// <param name="includeEventLog">If true, includes event log summary. Default is true.</param>
    public static void WriteToConsole(TpmInfo info, bool revealSecrets = false, bool includeEventLog = true)
    {
        WriteIdentity(info.Identity, info.Platform);
        WriteAlgorithms(info.SupportedAlgorithms);
        WriteCurves(info.SupportedCurves);
        WritePcrs(info.Pcrs, revealSecrets);

        if(includeEventLog)
        {
            WriteEventLogSummary();
        }
    }

    private static void WriteIdentity(TpmIdentity identity, string platform)
    {
        ConsoleFormatter.WriteHeader("TPM Information");

        ConsoleFormatter.WriteLabeled("Manufacturer:", identity.ManufacturerId.Trim());
        ConsoleFormatter.WriteLabeled("Vendor:", identity.VendorString);
        ConsoleFormatter.WriteLabeled("Family:", identity.Family);
        ConsoleFormatter.WriteLabeled("Revision:", identity.Revision.ToString());
        ConsoleFormatter.WriteLabeled("Firmware:", identity.FirmwareVersion);

        string buildDate = $"Day {identity.FirmwareDayOfYear}, {identity.FirmwareYear}";
        ConsoleFormatter.WriteLabeled("Build Date:", buildDate);

        ConsoleFormatter.WriteLabeled("Platform:", platform);
        ConsoleFormatter.WriteLabeled("PCR Count:", identity.PcrCount.ToString());
        ConsoleFormatter.WriteLabeled("Max Input Buffer:", $"{identity.MaxInputBuffer} bytes");
        ConsoleFormatter.WriteLabeled("Max NV Buffer:", $"{identity.MaxNvBuffer} bytes");
    }

    private static void WriteAlgorithms(System.Collections.Generic.IReadOnlyList<string> algorithms)
    {
        ConsoleFormatter.WriteHeader($"Supported Algorithms ({algorithms.Count})");

        //Group algorithms into rows of 8.
        const int perRow = 8;
        for(int i = 0; i < algorithms.Count; i += perRow)
        {
            int count = Math.Min(perRow, algorithms.Count - i);
            var row = new string[count];
            for(int j = 0; j < count; j++)
            {
                row[j] = algorithms[i + j];
            }

            Console.WriteLine($"  {string.Join(", ", row)}");
        }
    }

    private static void WriteCurves(System.Collections.Generic.IReadOnlyList<string> curves)
    {
        if(curves.Count == 0)
        {
            return;
        }

        ConsoleFormatter.WriteHeader($"Supported ECC Curves ({curves.Count})");
        Console.WriteLine($"  {string.Join(", ", curves)}");
    }

    private static void WritePcrs(PcrSnapshot pcrs, bool revealSecrets)
    {
        string consistency = pcrs.IsConsistent
            ? ConsoleFormatter.Success("consistent")
            : ConsoleFormatter.Warning("inconsistent");

        ConsoleFormatter.WriteHeader($"PCR Banks ({pcrs.Banks.Count})");
        Console.WriteLine($"  Update Counter: {pcrs.UpdateCounter} ({consistency})");

        if(!revealSecrets)
        {
            Console.WriteLine();
            Console.WriteLine(ConsoleFormatter.Dim("  PCR values redacted. Use --reveal to show full digest values."));
        }

        Console.WriteLine();

        foreach(var bank in pcrs.Banks)
        {
            Console.WriteLine($"  {ConsoleFormatter.Bold(bank.Algorithm)} ({bank.DigestSize * 8}-bit, {bank.AllocatedPcrs.Count} PCRs)");

            foreach(int index in bank.AllocatedPcrs)
            {
                byte[] digest = bank[index];
                string status = GetPcrStatus(digest);
                string indexStr = $"PCR[{index,2}]:";

                if(revealSecrets)
                {
                    string hexValue = Convert.ToHexString(digest);

                    //Truncate long digests for display.
                    string displayValue = hexValue.Length > 48
                        ? $"{hexValue[..24]}...{hexValue[^8..]}"
                        : hexValue;

                    Console.WriteLine($"    {ConsoleFormatter.Label(indexStr)} {displayValue} {status}");
                }
                else
                {
                    //Show redacted placeholder with status only.
                    string redacted = new string('█', 16) + "..." + new string('█', 8);
                    Console.WriteLine($"    {ConsoleFormatter.Label(indexStr)} {ConsoleFormatter.Dim(redacted)} {status}");
                }
            }

            Console.WriteLine();
        }
    }

    private static void WriteEventLogSummary()
    {
        var log = TcgEventLogFormatter.TryReadEventLog(out string? error);

        ConsoleFormatter.WriteHeader("Event Log");

        if(log is null)
        {
            Console.WriteLine($"  {ConsoleFormatter.Dim("Not available:")} {error ?? "Unknown error"}");
            Console.WriteLine();
            return;
        }

        ConsoleFormatter.WriteLabeled("Format:", log.SpecVersion);
        ConsoleFormatter.WriteLabeled("Events:", log.Events.Count.ToString());

        if(log.IsTruncated)
        {
            Console.WriteLine($"  {ConsoleFormatter.Warning("Warning: Log appears truncated")}");
        }

        //Show algorithms.
        if(log.DigestSizes.Count > 0)
        {
            var algNames = new System.Collections.Generic.List<string>();
            foreach(var (alg, _) in log.DigestSizes)
            {
                algNames.Add(TpmAlgIdExtensions.GetName(alg));
            }

            ConsoleFormatter.WriteLabeled("Algorithms:", string.Join(", ", algNames));
        }

        //Show PCR event counts (compact).
        var pcrCounts = new int[24];
        foreach(var evt in log.Events)
        {
            if(evt.PcrIndex >= 0 && evt.PcrIndex < pcrCounts.Length)
            {
                pcrCounts[evt.PcrIndex]++;
            }
        }

        var activeRanges = new System.Collections.Generic.List<string>();
        for(int i = 0; i < pcrCounts.Length; i++)
        {
            if(pcrCounts[i] > 0)
            {
                activeRanges.Add($"[{i}]:{pcrCounts[i]}");
            }
        }

        Console.WriteLine($"  Events by PCR: {string.Join(" ", activeRanges)}");
        Console.WriteLine();
        Console.WriteLine(ConsoleFormatter.Dim("  Run 'verifiable info tpm eventlog' for detailed event log."));
        Console.WriteLine();
    }

    private static string GetPcrStatus(byte[] digest)
    {
        bool allZero = true;
        bool allOnes = true;

        foreach(byte b in digest)
        {
            if(b != 0x00)
            {
                allZero = false;
            }

            if(b != 0xFF)
            {
                allOnes = false;
            }
        }

        if(allZero)
        {
            return ConsoleFormatter.Dim("(not extended)");
        }

        if(allOnes)
        {
            return ConsoleFormatter.Warning("(error state)");
        }

        return ConsoleFormatter.Success("(extended)");
    }
}