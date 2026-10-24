package main

import (
	"fmt"
)

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
