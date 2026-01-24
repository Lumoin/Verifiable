using System;
using System.Buffers;
using Verifiable.Tpm;
using Verifiable.Tpm.EventLog;
using Verifiable.Tpm.Extensions.EventLog;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable;

/// <summary>
/// Formats TCG event log data for human-readable console output.
/// </summary>
internal static class TcgEventLogFormatter
{
    /// <summary>
    /// Writes a summary of the event log to the console.
    /// </summary>
    /// <param name="log">The parsed event log.</param>
    public static void WriteSummary(TcgEventLog log)
    {
        ConsoleFormatter.WriteHeader("Event Log Summary");

        ConsoleFormatter.WriteLabeled("Format:", log.SpecVersion);

        string platform = log.PlatformClass switch
        {
            0 => "Client",
            1 => "Server",
            _ => $"Unknown ({log.PlatformClass})"
        };
        ConsoleFormatter.WriteLabeled("Platform:", platform);

        ConsoleFormatter.WriteLabeled("Version:",
            $"{log.SpecVersionNumber.Major}.{log.SpecVersionNumber.Minor}.{log.SpecVersionNumber.Errata}");
        ConsoleFormatter.WriteLabeled("Events:", log.Events.Count.ToString());
        Console.WriteLine(ConsoleFormatter.Dim("  (Recorded chronologically during boot; displayed newest first by default)"));

        if(log.IsTruncated)
        {
            Console.WriteLine($"  {ConsoleFormatter.Warning("Warning: Event log appears truncated.")}");
        }

        //Show digest algorithms in use.
        if(log.DigestSizes.Count > 0)
        {
            Console.WriteLine();
            Console.Write("  Algorithms: ");
            bool first = true;
            foreach(var (alg, size) in log.DigestSizes)
            {
                if(!first)
                {
                    Console.Write(", ");
                }

                Console.Write($"{TpmAlgIdExtensions.GetName(alg)} ({size * 8}-bit)");
                first = false;
            }

            Console.WriteLine();
        }

        //Show event type distribution.
        Console.WriteLine();
        WriteEventDistribution(log);
    }

    /// <summary>
    /// Writes the full event log to the console.
    /// </summary>
    /// <param name="log">The parsed event log.</param>
    /// <param name="revealDigests">If true, shows full digest values.</param>
    /// <param name="pcrFilter">If specified, only show events for this PCR.</param>
    /// <param name="chronological">If true, shows oldest first. Default is false (newest first).</param>
    public static void WriteFull(TcgEventLog log, bool revealDigests = false, int? pcrFilter = null, bool chronological = false)
    {
        WriteSummary(log);

        string orderNote = chronological ? "oldest first" : "newest first";
        Console.WriteLine();
        ConsoleFormatter.WriteHeader(pcrFilter.HasValue
            ? $"Events for PCR[{pcrFilter.Value}] ({orderNote})"
            : $"All Events ({orderNote})");

        if(!revealDigests)
        {
            Console.WriteLine(ConsoleFormatter.Dim("  Digest values redacted. Use --reveal to show full values."));
            Console.WriteLine();
        }

        //Build list of events to display.
        var eventsToShow = new System.Collections.Generic.List<TcgEvent>();
        foreach(var evt in log.Events)
        {
            if(pcrFilter.HasValue && evt.PcrIndex != pcrFilter.Value)
            {
                continue;
            }

            eventsToShow.Add(evt);
        }

        //Reverse for newest-first display.
        if(!chronological)
        {
            eventsToShow.Reverse();
        }

        foreach(var evt in eventsToShow)
        {
            WriteEvent(evt, revealDigests);
        }

        if(eventsToShow.Count == 0 && pcrFilter.HasValue)
        {
            Console.WriteLine(ConsoleFormatter.Dim($"  No events found for PCR[{pcrFilter.Value}]."));
        }
    }

    /// <summary>
    /// Writes PCR-grouped event summary to the console.
    /// </summary>
    public static void WritePcrSummary(TcgEventLog log)
    {
        ConsoleFormatter.WriteHeader("Events by PCR");

        //Count events per PCR.
        var pcrCounts = new int[24];
        foreach(var evt in log.Events)
        {
            if(evt.PcrIndex >= 0 && evt.PcrIndex < pcrCounts.Length)
            {
                pcrCounts[evt.PcrIndex]++;
            }
        }

        for(int i = 0; i < pcrCounts.Length; i++)
        {
            if(pcrCounts[i] > 0)
            {
                string pcrName = GetPcrDescription(i);
                Console.WriteLine($"  PCR[{i,2}]: {pcrCounts[i],3} events  {ConsoleFormatter.Dim(pcrName)}");
            }
        }
    }

    private static void WriteEventDistribution(TcgEventLog log)
    {
        //Count event types.
        var typeCounts = new System.Collections.Generic.Dictionary<uint, int>();
        foreach(var evt in log.Events)
        {
            typeCounts.TryGetValue(evt.EventType, out int count);
            typeCounts[evt.EventType] = count + 1;
        }

        Console.WriteLine("  Event Types:");
        foreach(var (eventType, count) in typeCounts)
        {
            string name = TcgEventType.GetName(eventType);
            Console.WriteLine($"    {name}: {count}");
        }
    }

    private static void WriteEvent(TcgEvent evt, bool revealDigests)
    {
        string indexStr = $"[{evt.Index,3}]";
        string pcrStr = $"PCR[{evt.PcrIndex,2}]";
        string typeStr = evt.EventTypeName;

        Console.WriteLine($"  {ConsoleFormatter.Label(indexStr)} {pcrStr} {ConsoleFormatter.Bold(typeStr)}");

        //Show description if available.
        if(!string.IsNullOrEmpty(evt.EventDataDescription))
        {
            Console.WriteLine($"         {ConsoleFormatter.Dim(evt.EventDataDescription)}");
        }

        //Show digests.
        if(revealDigests)
        {
            foreach(var digest in evt.Digests)
            {
                string hexValue = digest.DigestHex;

                //Truncate long digests for display.
                string displayValue = hexValue.Length > 64
                    ? $"{hexValue[..32]}...{hexValue[^8..]}"
                    : hexValue;

                Console.WriteLine($"         {ConsoleFormatter.Dim(digest.AlgorithmName)}: {displayValue}");
            }
        }

        Console.WriteLine();
    }

    private static string GetPcrDescription(int pcrIndex)
    {
        return pcrIndex switch
        {
            0 => "(SRTM, BIOS, Host Platform Extensions)",
            1 => "(Host Platform Configuration)",
            2 => "(UEFI driver and application code)",
            3 => "(UEFI driver and application config)",
            4 => "(UEFI boot manager code)",
            5 => "(UEFI boot manager config, GPT)",
            6 => "(Host Platform Manufacturer Specific)",
            7 => "(Secure Boot policy)",
            8 => "(OS kernel code)",
            9 => "(OS kernel config)",
            10 => "(OS boot authority)",
            11 => "(BitLocker)",
            12 => "(Data events, highly volatile)",
            13 => "(Boot Module Details)",
            14 => "(Boot Authorities)",
            15 => "(Reserved for future use)",
            16 => "(Debug PCR)",
            17 => "(Dynamic RTM)",
            18 => "(Trusted OS)",
            19 => "(Trusted OS)",
            20 => "(Trusted OS)",
            21 => "(Trusted OS)",
            22 => "(Trusted OS)",
            23 => "(Application Support)",
            _ => ""
        };
    }

    /// <summary>
    /// Attempts to read and parse the system event log.
    /// </summary>
    /// <returns>The parsed event log, or null if reading failed.</returns>
    public static TcgEventLog? TryReadEventLog(out string? error)
    {
        error = null;

        using var pool = MemoryPool<byte>.Shared;
        var result = TpmEventLogExtensions.ReadAndParseEventLog(pool);

        if(result.IsSuccess)
        {
            return result.Value;
        }

        if(result.IsTransportError)
        {
            uint code = result.TransportErrorCode;

            //Check for known error types.
            if(Enum.IsDefined(typeof(TcgEventLogReaderError), code))
            {
                error = ((TcgEventLogReaderError)code).GetDescription();
            }
            else if(Enum.IsDefined(typeof(TcgEventLogError), code))
            {
                error = ((TcgEventLogError)code).GetDescription();
            }
            else if(Enum.IsDefined(typeof(TbsResult), code))
            {
                error = TbsResultExtensions.GetDescription((TbsResult)code);
            }
            else
            {
                error = $"Transport error: 0x{code:X8}";
            }
        }
        else if(result.IsTpmError)
        {
            error = $"TPM error: {result.ResponseCode}";
        }

        return null;
    }
}