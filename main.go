package main

import (
	"io/ioutil"
	log "log"
	"net/http"
	"os"

	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	eventCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "customerio",
			Name:      "event_count",
			Help:      "A counter for CustomerIO reporting webhook events",
		},
		[]string{"type", "action"},
	)

	registry      = prometheus.NewRegistry()
	signingSecret = os.Getenv("WEBHOOK_SIGNING_SECRET")
)

func checkSignature(WebhookSigningSecret, XCIOSignature string, XCIOTimestamp int, RequestBody []byte) (bool, error) {
	signature, err := hex.DecodeString(XCIOSignature)
	if err != nil {
		return false, err
	}

	mac := hmac.New(sha256.New, []byte(WebhookSigningSecret))

	if _, err := mac.Write([]byte("v0:" + strconv.Itoa(XCIOTimestamp) + ":")); err != nil {
		return false, err
	}
	if _, err := mac.Write(RequestBody); err != nil {
		return false, err
	}

	computed := mac.Sum(nil)

	if !hmac.Equal(computed, signature) {
		return false, nil
	}

	return true, nil
}

func newHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		gatherers := prometheus.Gatherers{
			registry,
		}

		// Delegate http serving to Prometheus client library, which will call collector.Collect.
		h := promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{})
		h.ServeHTTP(w, r)
	}
}

type WebhookEvent struct {
	ObjectType string `json:"object_type"`
	Metric     string `json:"metric"`
	Timestamp  int    `json:"timestamp"`
}

func trackWebhookEvent(w http.ResponseWriter, r *http.Request) {
	// Declare a new Person struct.
	var e WebhookEvent

	signature := r.Header.Get("X-CIO-Signature")
	ts, err := strconv.Atoi(r.Header.Get("X-CIO-Timestamp"))

	if err != nil {
		log.Printf("ERROR: Could not decode X-CIO-Timestamp: %s\n", err.Error())
		http.Error(w, "Could not decode X-CIO-Timestamp", http.StatusBadRequest)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("ERROR: Could not read request body: %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	validSig, err := checkSignature(signingSecret, signature, ts, bodyBytes)

	if validSig != true {
		log.Printf("ERROR: Invalid signature: %s\n", err.Error())
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	// Try to decode the request body into the struct. If there is an error,
	// respond to the client with the error message and a 400 status code.
	err = json.Unmarshal(bodyBytes, &e)

	if err != nil {
		log.Printf("ERROR: Could not decode webhook JSON")
		http.Error(w, "Could not decode webhook JSON", http.StatusBadRequest)
		return
	}

	go func() {
		eventCounter.WithLabelValues(e.ObjectType, e.Metric).Inc()
	}()
}

func main() {
	if signingSecret == "" {
		log.Fatal("Must set WEBHOOK_SIGNING_SECRET environment variable")
		os.Exit(1)
	}

	registry.MustRegister(eventCounter)

	// This section will start the HTTP server and expose
	// any metrics on the /metrics endpoint.
	// Expose the registered metrics via HTTP.
	http.Handle("/metrics", promhttp.InstrumentMetricHandler(prometheus.DefaultRegisterer, newHandler()))

	// Handler for the incoming webhooks from customerio
	http.HandleFunc("/track", trackWebhookEvent)

	// Health checks
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	log.Println("INFO: Beginning to serve on port :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
