import tseslint from "@typescript-eslint/eslint-plugin";
import parser from "@typescript-eslint/parser";

export default [{ files: ["**/*.{ts,tsx}"] , languageOptions: { parser }, plugins: { "@typescript-eslint": tseslint }, rules: { "@typescript-eslint/no-unused-vars": "error" } }];
