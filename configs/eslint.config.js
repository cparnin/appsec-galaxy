/**
 * AppSec Galaxy Default ESLint Configuration
 *
 * This config is used when scanning repositories that don't have their own ESLint setup.
 * It provides sensible defaults for code quality scanning across JavaScript/TypeScript projects.
 *
 * Philosophy: Catch real issues, avoid noise, work everywhere.
 */

export default [
  {
    files: ["**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        // Node.js globals
        console: "readonly",
        process: "readonly",
        Buffer: "readonly",
        __dirname: "readonly",
        __filename: "readonly",
        module: "readonly",
        require: "readonly",
        exports: "writable",
        global: "readonly",

        // Browser globals
        window: "readonly",
        document: "readonly",
        navigator: "readonly",
        localStorage: "readonly",
        sessionStorage: "readonly",
        fetch: "readonly",

        // Testing globals
        describe: "readonly",
        it: "readonly",
        test: "readonly",
        expect: "readonly",
        jest: "readonly",
        beforeEach: "readonly",
        afterEach: "readonly",
        beforeAll: "readonly",
        afterAll: "readonly"
      }
    },
    rules: {
      // Possible Problems (Real Bugs)
      "no-unused-vars": ["warn", {
        "argsIgnorePattern": "^_",
        "varsIgnorePattern": "^_"
      }],
      "no-undef": "error",
      "no-constant-condition": "warn",
      "no-dupe-keys": "error",
      "no-duplicate-case": "error",
      "no-empty": ["warn", { "allowEmptyCatch": true }],
      "no-extra-semi": "warn",
      "no-unreachable": "warn",

      // Code Quality Issues
      "no-var": "warn",
      "prefer-const": "warn",
      "eqeqeq": ["warn", "always", { "null": "ignore" }],
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-with": "error",

      // Async/Promise Issues
      "no-async-promise-executor": "warn",
      "require-await": "warn",

      // Best Practices
      "no-console": "off",  // Allow console - common in Node.js
      "curly": ["warn", "multi-line"],
      "default-case": "off",
      "no-fallthrough": "warn"
    }
  }
];
