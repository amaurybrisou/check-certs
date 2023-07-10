package monitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	tlsConnectionTimeout = 5 * time.Second

	validLabel    = "valid"
	expiredLabel  = "expired"
	soonLabel     = "soon"
	notFoundLabel = "notfound"
)

var statusLabels = []string{validLabel, expiredLabel, soonLabel, notFoundLabel}

// CertExpiryMonitor periodically checks certificate expiry times.
type CertExpiryMonitor struct {
	PollingFrequency time.Duration
	Labels           string
	Domains          []string
	IgnoredDomains   []string
	Port             int
}

// Run the monitor until instructed to stop.
func (m *CertExpiryMonitor) Run(ctx context.Context) {
	if len(m.Domains) == 0 {
		log.Ctx(ctx).Warn().Msg("no domain to monitor")
		return
	}

	ticker := time.NewTicker(m.PollingFrequency)

	for {
		log.Ctx(ctx).Info().Msg("Polling")

		// iterate over namespaces to monitor
		for _, url := range m.Domains {
			// list pods matching the labels in this namespace
			dwg := &sync.WaitGroup{}

			dwg.Add(1)
			go m.checkCertificates(ctx, dwg, url)
			dwg.Wait()
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			log.Ctx(ctx).Info().Msg("Monitor stopping")
			return
		}
	}
}

func (m *CertExpiryMonitor) checkCertificates(ctx context.Context, wg *sync.WaitGroup, domain string) {
	defer wg.Done()

	currentTime := time.Now()
	tlsConfig := tls.Config{} //nolint
	// InsecureSkipVerify: m.InsecureSkipVerify,

	// iterate over domains that need to be checked, setting the domain in the TLS connection config for SNI
	logger := log.Ctx(ctx).With().Str("domain", domain).Logger()

	// connect to the pod over TLS
	tlsConfig.ServerName = domain
	dialer := new(net.Dialer)
	dialer.Timeout = tlsConnectionTimeout

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", domain, m.Port), &tlsConfig)
	if err != nil {
		tlsOpenConnectionError.WithLabelValues(domain).Inc()
		logger.Error().Msgf("Error connecting to domain to check certificates: %v", err)
		return
	}

	for _, label := range statusLabels {
		certificateStatus.WithLabelValues(domain, label).Set(0)
	}
	certFound := false

	for _, cert := range conn.ConnectionState().PeerCertificates {
		certLogger := logger.With().Str("subject", cert.Subject.String()).Logger()
		if err := cert.VerifyHostname(domain); err != nil {
			certLogger.Warn().Msgf("Certificate was not valid for domain: %v", err)
			continue
		}

		certFound = true
		certLogger.Debug().Msgf("Checking certificate: Not-Before=%v Not-After=%v", cert.NotBefore, cert.NotAfter)
		if cert.NotAfter.Before(currentTime) {
			certLogger.Warn().Msgf("Certificate has expired: Not-After=%v", cert.NotAfter)
			certificateStatus.WithLabelValues(domain, expiredLabel).Set(1)
		} else if cert.NotBefore.After(currentTime) {
			certLogger.Warn().Msgf("Certificate is not yet valid: Not-Before=%v", cert.NotBefore)
			certificateStatus.WithLabelValues(domain, soonLabel).Set(1)
		} else {
			certLogger.Debug().Msgf("Certificate is valid")
			certificateStatus.WithLabelValues(domain, validLabel).Set(1)
		}
		certificateSecondsSinceIssued.WithLabelValues(domain).Set(currentTime.Sub(cert.NotBefore).Seconds())
		certificateSecondsUntilExpires.WithLabelValues(domain).Set(cert.NotAfter.Sub(currentTime).Seconds())
		break
	}

	if !certFound {
		log.Ctx(ctx).Warn().Msgf("No matching certificates found for domain")
		certificateStatus.WithLabelValues(domain, notFoundLabel).Set(1)
	}
	if err := conn.Close(); err != nil {
		tlsCloseConnectionError.WithLabelValues(domain).Inc()
		log.Ctx(ctx).Error().Msgf("Error closing TLS connection after checking certificates: %v", err)
	}
}
