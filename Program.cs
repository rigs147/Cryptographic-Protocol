using System.Text;
using System.Security.Cryptography;
using System.Buffers.Binary;

var flawedMode = args.Contains("flawed");

Console.WriteLine($"Mode: {(flawedMode ? "FLAWED" : "CORRECT")}");

var message = "meter=001;reading=01234";

var plaintext = Encoding.UTF8.GetBytes(message);

Console.WriteLine($"Message length in bytes: {plaintext.Length}");
Console.WriteLine($"Message bytes: {Convert.ToHexString(plaintext)}");

var key = RandomNumberGenerator.GetBytes(16);

Console.WriteLine($"Key length in bits: {key.Length * 8}");

int messageCounter = 1;
var nonce = CreateNonce(messageCounter);

Console.WriteLine($"Nonce: {Convert.ToHexString(nonce)}");

var ciphertext = new byte[plaintext.Length];
var tag = new byte[16];

Console.WriteLine($"Ciphertext buffer: {ciphertext.Length} bytes");
Console.WriteLine($"Tag buffer: {tag.Length} bytes");

var associatedData = Encoding.UTF8.GetBytes("meter-id=001");

using var aes = new AesGcm(key, tag.Length);

aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

Console.WriteLine($"Ciphertext: {Convert.ToHexString(ciphertext)}");

var decrypted = new byte[ciphertext.Length];

aes.Decrypt(nonce, ciphertext, tag, decrypted, associatedData);

var recoveredMessage = Encoding.UTF8.GetString(decrypted);

Console.WriteLine($"Recovered message: {recoveredMessage}");
Console.WriteLine($"Messages match: {message == recoveredMessage}");

runCipherTextTamperTest();

runHeaderTamperTest();

runSecondMessageTest();

void runCipherTextTamperTest()
{
    Console.WriteLine("Tamper ciphertext test:");

    var tamperedCiphertext = (byte[])ciphertext.Clone();
    tamperedCiphertext[0] ^= 1;//change one bit

    var tamperedOutput = new byte[tamperedCiphertext.Length];

    Console.WriteLine($"Original Ciphertext:{Convert.ToHexString(ciphertext)}");
    Console.WriteLine($"Tampered Ciphertext:{Convert.ToHexString(tamperedCiphertext)}");

    try
    {
        aes.Decrypt(nonce, tamperedCiphertext, tag, tamperedOutput, associatedData);

        Console.WriteLine("FAIL: Altered ciphertext was accepted.");
        Environment.ExitCode = 1;
    }
    catch (AuthenticationTagMismatchException)
    {
        Console.WriteLine("PASS: Altered ciphertext was rejected.");
    }
}

void runHeaderTamperTest()
{
    Console.WriteLine("Header tampering test:");
    Console.WriteLine("Original header: meter-id=001");
    Console.WriteLine("Altered header:  meter-id=999");

    var alteredHeader = Encoding.UTF8.GetBytes("meter-id=999");
    var headerTestOutput = new byte[ciphertext.Length];

    try
    {
        aes.Decrypt(nonce, ciphertext, tag, headerTestOutput, alteredHeader);

        Console.WriteLine("FAIL: Altered header was accepted.");
        Environment.ExitCode = 1;
    }
    catch (AuthenticationTagMismatchException)
    {
        Console.WriteLine("PASS: Altered header was rejected.");
    }
}

void runSecondMessageTest()
{
    Console.WriteLine("Second message test:");

    if (!flawedMode)
    {
        messageCounter = checked(messageCounter + 1);
    }
    
    var secondNonce = CreateNonce(messageCounter);

    var secondPlaintext =
        Encoding.UTF8.GetBytes("meter=001;reading=05678");

    var secondCiphertext = new byte[secondPlaintext.Length];
    var secondTag = new byte[16];

    aes.Encrypt(
        secondNonce,
        secondPlaintext,
        secondCiphertext,
        secondTag,
        associatedData);

    var secondDecrypted = new byte[secondCiphertext.Length];

    aes.Decrypt(
        secondNonce,
        secondCiphertext,
        secondTag,
        secondDecrypted,
        associatedData);

    Console.WriteLine($"First nonce:  {Convert.ToHexString(nonce)}");
    Console.WriteLine($"Second nonce: {Convert.ToHexString(secondNonce)}");

    var secondMatches = secondPlaintext.SequenceEqual(secondDecrypted);
    Console.WriteLine($"Second message matches: {secondMatches}");

    if (!secondMatches)
    {
        Environment.ExitCode = 1;
    }

    RunNonceReuseAttackTest(
    plaintext,
    ciphertext,
    secondCiphertext,
    secondPlaintext,
    flawedMode);
}

static void RunNonceReuseAttackTest(
    byte[] knownPlaintext,
    byte[] firstCiphertext,
    byte[] secondCiphertext,
    byte[] actualSecondPlaintext,
    bool flawedMode)
{
    Console.WriteLine("Nonce reuse attack:");

    var attackOutput = RecoverSecondMessage(
        knownPlaintext,
        firstCiphertext,
        secondCiphertext);

    var attackSucceeded =
        attackOutput.SequenceEqual(actualSecondPlaintext);

    Console.WriteLine($"Mode: {(flawedMode ? "FLAWED" : "CORRECT")}");
    Console.WriteLine($"Known first message: {Encoding.UTF8.GetString(knownPlaintext)}");
    Console.WriteLine($"Recovered bytes: {Convert.ToHexString(attackOutput)}");
    Console.WriteLine($"Actual second message: {Encoding.UTF8.GetString(actualSecondPlaintext)}");
    Console.WriteLine($"Attack recovered second message: {attackSucceeded}");

    if (attackSucceeded)
    {
        Console.WriteLine($"Recovered text: {Encoding.UTF8.GetString(attackOutput)}");
    }

    var expectedOutcome = attackSucceeded == flawedMode;
    Console.WriteLine($"Attack behaved as expected: {expectedOutcome}");

    if (!expectedOutcome)
    {
        Environment.ExitCode = 1;
    }
}

static byte[] RecoverSecondMessage(
    byte[] knownPlaintext,
    byte[] firstCiphertext,
    byte[] secondCiphertext)
{
    var recovered = new byte[secondCiphertext.Length];

    for (var i = 0; i < recovered.Length; i++)
    {
        // Recover keystream byte using known message and its ciphertext.
        byte recoveredKeystreamByte = (byte)(
            knownPlaintext[i] ^ firstCiphertext[i]);

        // Use same keystream byte to recover second message.
        byte recoveredPlaintextByte = (byte)(
            secondCiphertext[i] ^ recoveredKeystreamByte);

        recovered[i] = recoveredPlaintextByte;
    }

    return recovered;
}

byte[] CreateNonce(int messageCounter)
{
    var nonce = new byte[12];
    BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(8), (uint)messageCounter);
    return nonce;
}