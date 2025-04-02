# CLAUDE.md - Agent Assistant Guide

## Build & Test Commands
- Build: `cargo build`
- Run tests: `cargo test`
- Run specific test: `cargo test test_name`
- Run module tests: `cargo test --package tests::in_memory_tests`
- Requires nightly Rust (specified in rust-toolchain.toml)

## Code Style Guidelines
- **Imports**: Group by scope (std first, then external, then internal)
- **Error Handling**: Use `MyResult<T>` type alias and `?` operator for propagation
- **Naming**:
  - Functions: snake_case
  - Types/Traits: CamelCase
  - Constants: SCREAMING_SNAKE_CASE
  - Modules: snake_case
- **Formatting**: 4-space indentation, single blank line between functions
- **Architecture**: Modular, trait-based design with clear separation of concerns
- **Testing**: Use `#[test]` attribute, return `MyResult<()>`, use assert macros

This Rust project implements an encrypted, deduplicating filesystem with components for backend storage, repository management, and application interfaces.