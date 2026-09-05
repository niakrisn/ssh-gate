package main

import (
	"fmt"
)

// ConfigurationError represents configuration-related errors.
type ConfigurationError struct {
	Field   string
	Value   string
	Message string
}

func (e *ConfigurationError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return fmt.Sprintf("invalid %s: %s", e.Field, e.Value)
}

// NewConfigurationError creates a new configuration error.
func NewConfigurationError(field, value, message string) *ConfigurationError {
	return &ConfigurationError{
		Field:   field,
		Value:   value,
		Message: message,
	}
}

// NetworkError represents network-related errors.
type NetworkError struct {
	Operation string
	Address   string
	Err       error
}

func (e *NetworkError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s to %s failed: %v", e.Operation, e.Address, e.Err)
	}
	return fmt.Sprintf("%s to %s failed", e.Operation, e.Address)
}

func (e *NetworkError) Unwrap() error {
	return e.Err
}

// NewNetworkError creates a new network error.
func NewNetworkError(operation, address string, err error) *NetworkError {
	return &NetworkError{
		Operation: operation,
		Address:   address,
		Err:       err,
	}
}

// DNSError represents DNS resolution errors.
type DNSError struct {
	Host string
	Err  error
}

func (e *DNSError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("DNS resolution failed for %s: %v", e.Host, e.Err)
	}
	return fmt.Sprintf("DNS resolution failed for %s", e.Host)
}

func (e *DNSError) Unwrap() error {
	return e.Err
}

// NewDNSError creates a new DNS error.
func NewDNSError(host string, err error) *DNSError {
	return &DNSError{
		Host: host,
		Err:  err,
	}
}

// SSHError represents SSH-related errors.
type SSHError struct {
	Operation string
	Host      string
	Port      int
	Err       error
}

func (e *SSHError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("SSH %s to %s:%d failed: %v", e.Operation, e.Host, e.Port, e.Err)
	}
	return fmt.Sprintf("SSH %s to %s:%d failed", e.Operation, e.Host, e.Port)
}

func (e *SSHError) Unwrap() error {
	return e.Err
}

// NewSSHError creates a new SSH error.
func NewSSHError(operation, host string, port int, err error) *SSHError {
	return &SSHError{
		Operation: operation,
		Host:      host,
		Port:      port,
		Err:       err,
	}
}