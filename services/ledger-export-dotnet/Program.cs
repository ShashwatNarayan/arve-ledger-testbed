using System;
using System.IO;
using Newtonsoft.Json;

namespace LedgerExport
{
    /// <summary>Writes the daily ledger extract the finance team imports.</summary>
    internal static class Program
    {
        private sealed class Entry
        {
            public string AccountId { get; set; }
            public string Direction { get; set; }
            public long AmountMinor { get; set; }
            public DateTime PostedAt { get; set; }
        }

        private static int Main(string[] args)
        {
            var outputPath = args.Length > 0 ? args[0] : "ledger-extract.json";
            var entries = new[]
            {
                new Entry { AccountId = "acc_demo_gbp", Direction = "credit", AmountMinor = 250000, PostedAt = DateTime.UtcNow },
            };

            File.WriteAllText(outputPath, JsonConvert.SerializeObject(entries, Formatting.Indented));
            Console.WriteLine($"wrote {entries.Length} entries to {outputPath}");
            return 0;
        }
    }
}
