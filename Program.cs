if (args.Any(arg => arg != "flawed" && arg != "attack-only"))
{
    Console.Error.WriteLine("dotnet run [flawed] [attack-only]");
    Environment.ExitCode = 2;
    return;
}

bool flawedMode = args.Contains("flawed");
bool attackOnly = args.Contains("attack-only");

Environment.ExitCode = ProtocolDemo.Run(flawedMode, attackOnly);