package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/amaurybrisou/ablib"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	loglevel, err := zerolog.ParseLevel(ablib.LookupEnv("LOG_LEVEL", "debug"))
	if err != nil {
		fmt.Println("invalid LOG_LEVEL")
		os.Exit(1)
	}
	zerolog.SetGlobalLevel(loglevel)

	ablib.Logger(ablib.LookupEnv("LOG_FORMAT", "console"))

	ctx := log.Logger.WithContext(context.Background())

	// m := &monitor.CertExpiryMonitor{
	// 	PollingFrequency: time.Second * 60,
	// 	Domains:          strings.Split("www.google.com,www.facebook.com,www.youtube.com,www.amazon.com,www.wikipedia.org,www.twitter.com,www.instagram.com,www.linkedin.com,www.reddit.com,www.netflix.com", ","),
	// 	IgnoredDomains:   strings.Split("", ","),
	// 	Port:             443,
	// }

	// go m.Run(ctx)

	router := http.NewServeMux()
	router.Handle("/", http.FileServer(http.Dir(ablib.LookupEnv("FRONT_BUILD_PATH", "front/build"))))
	router.HandleFunc("/healthcheck", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	lcore := ablib.NewCore(
		ablib.WithLogLevel(ablib.LookupEnv("LOG_LEVEL", "debug")),
		ablib.WithHTTPServer(
			ablib.LookupEnv("HTTP_SERVER_ADDR", "0.0.0.0"),
			ablib.LookupEnvInt("HTTP_SERVER_PORT", 8080),
			router,
		),
		ablib.WithSignals(),
		ablib.WithPrometheus(
			ablib.LookupEnv("HTTP_PROM_ADDR", "0.0.0.0"),
			ablib.LookupEnvInt("HTTP_PROM_PORT", 2112),
		),
	)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	started, errChan := lcore.Start(ctx)

	go func() {
		<-started
		log.Ctx(ctx).Debug().Msg("all backend services started")
	}()

	err = <-errChan
	if err != nil {
		if !errors.Is(err, ablib.ErrSignalReceived) {
			log.Ctx(ctx).Error().Err(err).Msg("error received")
		}
		err = lcore.Shutdown(ctx)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("shutdown error received")
		}
		log.Ctx(ctx).Debug().Msg("services stopped")
	}

	log.Ctx(ctx).Debug().Msg("shutdown")
}

// type healthHandler struct {
// 	healthy bool
// }

// func (hh *healthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
// 	if hh.healthy {
// 		w.WriteHeader(http.StatusOK)
// 		w.Write([]byte("Healthy")) //nolint
// 		return
// 	}
// 	w.WriteHeader(http.StatusInternalServerError)
// 	w.Write([]byte("Unhealthy")) //nolint
// }
