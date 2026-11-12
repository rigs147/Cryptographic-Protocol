using System.Text;
using System.Security.Cryptography;

string message = "meter=001;reading=01234";

byte[] plaintext = Encoding.UTF8.GetBytes(message);

Console.WriteLine($"Message length in bytes: {plaintext.Length}");
Console.WriteLine($"Message bytes: {Convert.ToHexString(plaintext)}");

byte[] key = RandomNumberGenerator.GetBytes(16);

Console.WriteLine($"Key length in bits: {key.Length * 8}");

byte[] nonce = RandomNumberGenerator.GetBytes(12);

Console.WriteLine($"Nonce: {Convert.ToHexString(nonce)}");

byte[] ciphertext = new byte[plaintext.Length];
byte[] tag = new byte[16];

Console.WriteLine($"Ciphertext buffer: {ciphertext.Length} bytes");
Console.WriteLine($"Tag buffer: {tag.Length} bytes");

byte[] associatedData = Encoding.UTF8.GetBytes("meter-id=001");

using var aes = new AesGcm(key, tag.Length);

aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

Console.WriteLine($"Ciphertext: {Convert.ToHexString(ciphertext)}");

byte[] decrypted = new byte[ciphertext.Length];

aes.Decrypt(nonce, ciphertext, tag, decrypted, associatedData);

string recoveredMessage = Encoding.UTF8.GetString(decrypted);

Console.WriteLine($"Recovered message: {recoveredMessage}");
Console.WriteLine($"Messages match: {message == recoveredMessage}");

runCipherTextTamperTest();

runHeaderTamperTest();


void runCipherTextTamperTest()
{
    Console.WriteLine("Tamper ciphertext test:");

    byte[] tamperedCiphertext = (byte[])ciphertext.Clone();
    tamperedCiphertext[0] ^= 1;//change one bit

    byte[] tamperedOutput = new byte[tamperedCiphertext.Length];

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

    byte[] alteredHeader = Encoding.UTF8.GetBytes("meter-id=999");
    byte[] headerTestOutput = new byte[ciphertext.Length];

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