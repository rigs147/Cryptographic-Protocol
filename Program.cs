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

using var aes = new AesGcm(key, tag.Length);

aes.Encrypt(nonce, plaintext, ciphertext, tag);

Console.WriteLine($"Ciphertext: {Convert.ToHexString(ciphertext)}");

byte[] decrypted = new byte[ciphertext.Length];

aes.Decrypt(nonce, ciphertext, tag, decrypted);

string recoveredMessage = Encoding.UTF8.GetString(decrypted);

Console.WriteLine($"Recovered message: {recoveredMessage}");
Console.WriteLine($"Messages match: {message == recoveredMessage}");
