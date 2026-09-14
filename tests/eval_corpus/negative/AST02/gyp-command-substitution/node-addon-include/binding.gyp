{
  "targets": [
    {
      "target_name": "addon",
      "include_dirs": [
        "<!(node -p \"require('node-addon-api').include\")"
      ],
      "libraries": [
        "<!@(pkg-config --libs libpng 2>/dev/null)"
      ],
      "sources": [
        "src/addon.cc"
      ]
    }
  ]
}