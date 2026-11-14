using System.Text.Json;

public sealed record EncryptedRecord(
{
    public string ToJson() => JsonSerializer.Serialize(this);

    public static EncryptedRecord FromJson(string json)
    {
        return JsonSerializer.Deserialize<EncryptedRecord>(json)
            ?? throw new JsonException("A message record is required.");
    }
}
