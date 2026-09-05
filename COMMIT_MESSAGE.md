refactor(codebase): improve error handling, validation, and organization

This commit implements comprehensive code quality improvements across the SSH-Gate proxy application:

## Error Handling Improvements
- Created custom error types in `errors.go` for better error categorization
- Added `ConfigurationError`, `NetworkError`, `DNSError`, and `SSHError` types
- Updated error handling throughout the codebase to use structured error types
- Improved error messages with more context and better formatting

## Configuration Validation
- Enhanced `loadConfig()` in `main.go` with comprehensive parameter validation
- Added validation for SSH_HOST, SSH_USER, DATA_DIR, and all listen addresses
- Added IP address validation for DOH_IP configuration
- Improved error messages for invalid configuration values

## Code Organization
- Created `utils.go` with shared utility functions
- Moved `contains()` function from `main.go` to `utils.go`
- Added `containsAny()`, `validatePort()`, `validateHostPort()`, and `firstNonEmpty()` functions
- Improved code structure and reduced duplication

## DNS Cache Improvements
- Made DNS cache TTL configurable via constant in `rules.go`
- Added cache statistics tracking (cacheHits, cacheMisses)
- Improved cache management structure

## Testing Enhancements
- Added comprehensive unit tests in `utils_test.go` for all utility functions
- Added unit tests in `errors_test.go` for all custom error types
- All existing tests continue to pass
- Significantly increased test coverage

## Files Changed
- `errors.go` (new): Custom error types for better error handling
- `errors_test.go` (new): Unit tests for error types
- `utils.go` (new): Shared utility functions
- `utils_test.go` (new): Unit tests for utilities
- `main.go`: Improved configuration validation
- `dialer.go`: Better error handling and messages
- `routing.go`: Better error handling for DNS resolution
- `rules.go`: DNS cache improvements and structure
- `socks5.go`: Better error handling and added fmt import

## Benefits
- Better error handling with more context and structured types
- Improved code organization and maintainability
- Enhanced configuration validation prevents runtime errors
- Comprehensive test coverage ensures reliability
- More descriptive error messages aid debugging

## Verification
- All tests pass: `go test -v ./...`
- Code compiles successfully: `go build -v ./...`
- No breaking changes to existing functionality