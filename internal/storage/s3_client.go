package storage

import (
	"crypto/x509"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"private-registry/internal/egress"
)

// S3ClientSettings is an experimental explicit network boundary, not a
// process-wide sandbox. The credentials provider must not perform implicit
// network discovery; its lifecycle remains the caller's responsibility.
type S3ClientSettings struct {
	Origin      string
	Region      string
	Networks    []netip.Prefix
	DNSServer   netip.AddrPort
	RootCAs     *x509.CertPool
	Credentials aws.CredentialsProvider
}

// NewRestrictedS3Client constructs an S3 client without environment proxy,
// default credential chain, automatic redirects or implicit DNS selection.
// It does not qualify backend atomicity or constrain credential-provider I/O.
func NewRestrictedS3Client(settings S3ClientSettings) (*s3.Client, error) {
	if settings.Credentials == nil || settings.Region == "" || len(settings.Region) > 128 || strings.TrimSpace(settings.Region) != settings.Region || strings.ContainsAny(settings.Region, "\x00\r\n\t /\\") {
		return nil, errors.New("S3 credentials provider and region are required")
	}
	destinations := []egress.Destination{{Origin: settings.Origin, CIDRs: settings.Networks}}
	var err error
	client, err := egress.NewHTTPSClient(destinations, settings.RootCAs)
	if settings.DNSServer.IsValid() {
		client, err = egress.NewHTTPSClientWithDNS(destinations, settings.RootCAs, settings.DNSServer)
	}
	if err != nil {
		return nil, errors.New("S3 network policy is invalid")
	}
	config := aws.Config{Region: settings.Region, Credentials: settings.Credentials, HTTPClient: client}
	return s3.NewFromConfig(config, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(settings.Origin)
		options.UsePathStyle = true
	}), nil
}

// NewRestrictedS3Storage composes the experimental S3 driver, explicit
// network policy and per-instance operation admission. The caller remains
// responsible for durable quota, crash cleanup and qualifying the
// actual backend before making this available to users.
func NewRestrictedS3Storage(settings S3ClientSettings, bucket, prefix, staging string, maxObjectBytes int64, maxConcurrent int, timeout time.Duration) (Driver, error) {
	if _, err := S3ActiveStagingCeiling(maxObjectBytes, maxConcurrent); err != nil || timeout <= 0 || timeout > time.Hour {
		return nil, errors.New("S3 storage capacity is invalid")
	}
	client, err := NewRestrictedS3Client(settings)
	if err != nil {
		return nil, err
	}
	driver, err := NewS3(client, bucket, prefix, staging, maxObjectBytes)
	if err != nil {
		return nil, err
	}
	bounded, err := NewBoundedDriver(driver, maxConcurrent)
	if err != nil {
		return nil, err
	}
	return NewDeadlineDriver(bounded, timeout)
}

// S3ActiveStagingCeiling reports the worst-case staged bytes of active
// operations for one composed instance: each Put can hold the original and
// verified readback simultaneously, including a one-byte overflow probe. It
// excludes filesystem overhead, files left by failed cleanup or crashes, and
// any other processes or instances.
func S3ActiveStagingCeiling(maxObjectBytes int64, maxConcurrent int) (int64, error) {
	if maxObjectBytes < 1 || maxObjectBytes > 1<<30 || maxConcurrent < 1 || maxConcurrent > 128 {
		return 0, errors.New("S3 storage capacity is invalid")
	}
	return (2*maxObjectBytes + 1) * int64(maxConcurrent), nil
}
