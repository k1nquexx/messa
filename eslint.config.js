module.exports = [
  {
    ignores: [
      "node_modules/**",
      "mobile/**",
      "desktop/node_modules/**",
      "public/jsQR.js",
      "public/qrcode.js"
    ]
  },
  {
    files: ["client/**/*.js", "server/**/*.js", "*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "commonjs",
      globals: {
        console: "readonly",
        process: "readonly",
        require: "readonly",
        module: "readonly",
        __dirname: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
        Buffer: "readonly",
        Uint8Array: "readonly",
        Float32Array: "readonly",
        ArrayBuffer: "readonly",
        DataView: "readonly",
        globalThis: "readonly"
      }
    },
    rules: {
      "no-unused-vars": "off",
      "no-undef": "error"
    }
  },
  {
    files: ["public/**/*.js"],
    ignores: ["public/sw.js", "public/jsQR.js", "public/qrcode.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "script",
      globals: {
        window: "readonly",
        document: "readonly",
        navigator: "readonly",
        localStorage: "readonly",
        indexedDB: "readonly",
        WebSocket: "readonly",
        Notification: "readonly",
        Audio: "readonly",
        AudioContext: "readonly",
        webkitAudioContext: "readonly",
        MediaRecorder: "readonly",
        RTCPeerConnection: "readonly",
        RTCSessionDescription: "readonly",
        RTCIceCandidate: "readonly",
        File: "readonly",
        FileReader: "readonly",
        Blob: "readonly",
        URLSearchParams: "readonly",
        Uint8Array: "readonly",
        Float32Array: "readonly",
        ArrayBuffer: "readonly",
        DataView: "readonly",
        TextEncoder: "readonly",
        TextDecoder: "readonly",
        atob: "readonly",
        btoa: "readonly",
        console: "readonly",
        alert: "readonly",
        prompt: "readonly",
        confirm: "readonly",
        fetch: "readonly",
        Event: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
        requestAnimationFrame: "readonly",
        WebCryptoE2EE: "readonly",
        SovereignQr: "readonly"
      }
    },
    rules: {
      "no-unused-vars": "off",
      "no-undef": "error"
    }
  },
  {
    files: ["public/sw.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "script",
      globals: {
        self: "readonly",
        caches: "readonly",
        clients: "readonly",
        fetch: "readonly"
      }
    },
    rules: {
      "no-unused-vars": "off",
      "no-undef": "error"
    }
  }
];
