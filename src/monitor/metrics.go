package monitor

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	tlsOpenConnectionError = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "tls_open_connection_error_total",
			Help:      "Number of times an error was encountered while opening a TLS connection to a domain",
		},
		[]string{"domain"},
	)
	tlsCloseConnectionError = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "tls_close_connection_error_total",
			Help:      "Number of times an error was encountered while closing a TLS connection to domain",
		},
		[]string{"domain"},
	)
	certificateStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "certificate",
			Help:      "Number of instances domains in a given status",
		},
		[]string{"domain", "status"},
	)
	certificateSecondsSinceIssued = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "seconds_since_cert_issued",
			Help:      "Seconds since the certificate was issued",
		},
		[]string{"domain"},
	)
	certificateSecondsUntilExpires = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "seconds_until_cert_expires",
			Help:      "Seconds until the certificate expires",
		},
		[]string{"domain"},
	)
)

func init() {
	prometheus.MustRegister(tlsOpenConnectionError)
	prometheus.MustRegister(tlsCloseConnectionError)
	prometheus.MustRegister(certificateStatus)
	prometheus.MustRegister(certificateSecondsSinceIssued)
	prometheus.MustRegister(certificateSecondsUntilExpires)
}
