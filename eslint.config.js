import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default [
	{
		ignores: ["node_modules", "dist", "build", "*.config.js"],
	},
	js.configs.recommended,
	...tseslint.configs.recommended,
	{
		files: ["**/*.{ts,tsx,mts,cts}"],
		languageOptions: {
			parser: tseslint.parser,
			parserOptions: {
				ecmaVersion: "latest",
				sourceType: "module",
				project: "./tsconfig.json",
			},
			globals: {
				console: "readonly",
				process: "readonly",
				Buffer: "readonly",
			},
		},
		rules: {
			// TypeScript specific
			"@typescript-eslint/no-unused-vars": [
				"error",
				{
					argsIgnorePattern: "^_",
					varsIgnorePattern: "^_",
				},
			],
			"@typescript-eslint/no-explicit-any": "warn",
			"@typescript-eslint/explicit-module-boundary-types": "off",
			"@typescript-eslint/no-floating-promises": "error",
			"@typescript-eslint/await-thenable": "error",
			"@typescript-eslint/no-misused-promises": "error",

			// General
			"no-console": ["warn", { allow: ["warn", "error"] }],
			"no-debugger": "error",
			"prefer-const": "error",
			"no-var": "error",
			"eqeqeq": ["error", "always"],
			"curly": ["error", "all"],
		},
	},
	{
		files: ["**/*.{js,mjs,cjs}"],
		languageOptions: {
			ecmaVersion: "latest",
			sourceType: "module",
			globals: {
				console: "readonly",
				process: "readonly",
				Buffer: "readonly",
			},
		},
		rules: {
			"no-console": ["warn", { allow: ["warn", "error"] }],
			"no-debugger": "error",
			"prefer-const": "error",
			"no-var": "error",
			"eqeqeq": ["error", "always"],
			"curly": ["error", "all"],
		},
	},
];
