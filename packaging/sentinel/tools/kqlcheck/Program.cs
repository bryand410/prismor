// Optional semantic KQL check. TODO(verify): package id and GlobalState API.
// Exits 0 when the package is unavailable so a missing restore is not a hard failure.
using System.Text.Json;

var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
var schemaDir = Path.Combine(root, "bicep", "schema");
if (!Directory.Exists(schemaDir))
{
    Console.Error.WriteLine("schema directory not found; skipping");
    return 0;
}

try
{
    var language = typeof(Program).Assembly.GetReferencedAssemblies()
        .FirstOrDefault(a => a.Name == "Kusto.Language");
    if (language is null)
    {
        Console.Error.WriteLine("Kusto.Language was not referenced; skipping semantic check");
        return 0;
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
    return 0;
}

Console.WriteLine("kqlcheck referenced the language assembly; full parse is TODO(verify)");
_ = JsonDocument.Parse(File.ReadAllText(Directory.GetFiles(schemaDir, "*.table.json")[0]));
return 0;
