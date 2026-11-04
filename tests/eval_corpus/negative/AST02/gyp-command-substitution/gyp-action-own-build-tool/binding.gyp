# FIXTURE ONLY - synthetic detection test sample, not real malware
{
  "targets": [
    {
      "target_name": "parser",
      "sources": ["src/parser.cc", "<(INTERMEDIATE_DIR)/tables.cc"],
      "actions": [
        {
          "action_name": "generate_tables",
          "inputs": ["tools/gen_tables.py", "src/grammar.txt"],
          "outputs": ["<(INTERMEDIATE_DIR)/tables.cc"],
          "action": ["python3", "tools/gen_tables.py", "src/grammar.txt", "<@(_outputs)"]
        }
      ],
      "rules": [
        {
          "rule_name": "embed_js",
          "extension": "js",
          "outputs": ["<(INTERMEDIATE_DIR)/<(RULE_INPUT_ROOT).h"],
          "action": ["node", "tools/js2c.js", "<(RULE_INPUT_PATH)", "<@(_outputs)"]
        }
      ]
    }
  ]
}
