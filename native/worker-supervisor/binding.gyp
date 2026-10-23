{
  "targets": [
    {
      "target_name": "worker_supervisor",
      "sources": ["src/addon.cpp", "src/command_line.cpp"],
      "include_dirs": ["include", "<!@(node -p \"require('node-addon-api').include\")"],
      "dependencies": ["<!(node -p \"require('node-addon-api').gyp\")"],
      "defines": ["NAPI_CPP_EXCEPTIONS", "UNICODE", "_UNICODE", "WIN32_LEAN_AND_MEAN", "NOMINMAX"],
      "cflags_cc": ["-std=c++17"],
      "conditions": [["OS=='win'", {"libraries": ["advapi32.lib", "bcrypt.lib", "crypt32.lib", "iphlpapi.lib", "ole32.lib", "ws2_32.lib"]}]]
    }
  ]
}
