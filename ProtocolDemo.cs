using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

public static class ProtocolDemo
{
    private const int KeySizeBytes = 16;

    private const string FirstMessage = "meter=001;reading=01234";
    private const string SecondMessage = "meter=001;reading=05678";
    private const string Header = "meter-id=001";

    public static int Run(bool flawedMode, bool attackOnly)
    {
        //Convert the message and header to bytes and generate a fresh key.
        var plaintext = Encoding.UTF8.GetBytes(FirstMessage);
        var authenticatedHeader = Encoding.UTF8.GetBytes(Header);
        var key = RandomNumberGenerator.GetBytes(KeySizeBytes);

        //Both endpoints use the same key and expected meter header.
        using var sender = new MeterSender(key, Header, flawedMode);
        using var receiver = new MeterReceiver(key, Header);

        //Encrypt the first message and simulate transferring it as JSON.
        var first = EncryptedRecord.FromJson(sender.Encrypt(plaintext).ToJson());
        var nonce = first.Nonce;
        var ciphertext = first.Ciphertext;
        var tag = first.Tag;

        Console.WriteLine($"Mode: {(flawedMode ? "FLAWED" : "CORRECT")}");
        Console.WriteLine($"Message length in bytes: {plaintext.Length}");
        Console.WriteLine($"Message bytes: {Convert.ToHexString(plaintext)}");
        Console.WriteLine($"Key length in bits: {key.Length * 8}");
        Console.WriteLine($"Nonce: {Convert.ToHexString(nonce)}");
        Console.WriteLine($"Ciphertext buffer: {ciphertext.Length} bytes");
        Console.WriteLine($"Tag buffer: {tag.Length} bytes");

        Console.WriteLine($"Ciphertext: {Convert.ToHexString(ciphertext)}");

        //Run the record and encryption checks unless only the attack was requested.
        var testsPassed = true;
        if (!attackOnly)
        {
            var recordChecksPassed = RecordTests.Run();
            var receivedMatches = receiver.Decrypt(first).SequenceEqual(plaintext);
            testsPassed = CryptoTests.RunEncryptionTests(
                key, nonce, plaintext, ciphertext, tag, authenticatedHeader);
            testsPassed = testsPassed && recordChecksPassed && receivedMatches;
        }

        Console.WriteLine("Second message test:");

        //The sender advances the counter in correct mode and reuses it in flawed mode.
        var secondPlaintext = Encoding.UTF8.GetBytes(SecondMessage);
        var second = EncryptedRecord.FromJson(sender.Encrypt(secondPlaintext).ToJson());
        var secondNonce = second.Nonce;
        var secondCiphertext = second.Ciphertext;

        Console.WriteLine($"First nonce:  {Convert.ToHexString(nonce)}");
        Console.WriteLine($"Second nonce: {Convert.ToHexString(secondNonce)}");

        if (!attackOnly)
        {
            bool secondRecordPassed;
            try
            {
                //Correct mode should accept the second message and recover its contents.
                var received = receiver.Decrypt(second);
                secondRecordPassed = !flawedMode && received.SequenceEqual(secondPlaintext);
                Console.WriteLine($"Second message matches: {secondRecordPassed}");
            }
            catch (InvalidRecordException)
            {
                //In flawed mode, the receiver should reject the repeated counter.
                secondRecordPassed = flawedMode;
                Console.WriteLine($"Second record rejected for nonce reuse: {secondRecordPassed}");
            }
            testsPassed = testsPassed && secondRecordPassed;
        }

        var attackSucceeded = RunAttackDemo(
            plaintext, ciphertext, secondCiphertext, secondPlaintext, flawedMode);

        if (attackOnly)
        {
            var exitCode = attackSucceeded ? 0 : 1;
            Console.WriteLine($"Attack exit code: {exitCode}");
            return exitCode;
        }

        //Recovery should succeed in flawed mode and fail in correct mode.
        var expectedOutcome = CryptoTests.VerifyAttackOutcome(attackSucceeded, flawedMode);
        if (!expectedOutcome)
        {
            testsPassed = false;
        }

        Console.WriteLine($"Attack behaved as expected: {expectedOutcome}");
        Console.WriteLine($"Regression checks passed: {testsPassed}");

        return testsPassed ? 0 : 1;
    }

    private static bool RunAttackDemo(
        byte[] knownPlaintext,
        byte[] firstCiphertext,
        byte[] secondCiphertext,
        byte[] actualSecondPlaintext,
        bool flawedMode)
    {
        Console.WriteLine("Nonce reuse attack:");

        //Measure how long the recovery attempt takes.
        var started = Stopwatch.GetTimestamp();
        var recovered = NonceReuseAttack.RecoverSecondMessage(
            knownPlaintext, firstCiphertext, secondCiphertext);
        var elapsed = Stopwatch.GetElapsedTime(started);

        //Compare the recovered message with the real message to check if the attack worked.
        var attackSucceeded = CryptoTests.IsRecoveredMessage(recovered, actualSecondPlaintext);

        Console.WriteLine($"Mode: {(flawedMode ? "FLAWED" : "CORRECT")}");
        Console.WriteLine($"Known first message: {Encoding.UTF8.GetString(knownPlaintext)}");
        Console.WriteLine($"Recovered bytes: {Convert.ToHexString(recovered)}");
        Console.WriteLine($"Actual second message: {Encoding.UTF8.GetString(actualSecondPlaintext)}");
        Console.WriteLine($"Attack recovered second message: {attackSucceeded}");

        if (attackSucceeded)
        {
            Console.WriteLine($"Recovered text: {Encoding.UTF8.GetString(recovered)}");
        }

        //Show the work and time needed to recover the message.
        Console.WriteLine($"Recovery iterations: {recovered.Length}");
        Console.WriteLine($"Bytewise XOR operations: {recovered.Length * 2}");
        Console.WriteLine($"Recovery time (ms): {elapsed.TotalMilliseconds:F6}");
        return attackSucceeded;
    }
}