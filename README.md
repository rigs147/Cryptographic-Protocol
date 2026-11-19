# Cryptography Theory & Practice - CA2

C# AES-GCM demo with a deliberate nonce-reuse flaw.

Requires .NET SDK 11.0.100. Open a terminal in the project folder.

## Full tests

Run all checks and the attack demonstration:

```powershell
dotnet run
dotnet run flawed
```

- `dotnet run` uses unique nonces. Recovery should fail.
- `dotnet run flawed` models the nonce reuse caused by a restart that loses counter state while retaining the same key. Recovery should succeed.

Both commands should finish with `Regression checks passed: True`
and exit code `0` as both produce their expected results.

## Attack only

Skip the other checks and run the recovery demonstration:

```powershell
dotnet run attack-only
dotnet run attack-only flawed
```

- `dotnet run attack-only`: recovery should fail; exit code `1`.
- `dotnet run attack-only flawed`: recovery should succeed; exit code `0`.

## Check the exit code

In PowerShell, run this immediately after each command:

```powershell
$LASTEXITCODE
```