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

type LogEntry struct {
	Message  string `json:"message"`
	Severity string `json:"severity,omitempty"`
}

// String renders an entry structure to the JSON format expected by Cloud Logging.
func (e LogEntry) String() string {
	if e.Severity == "" {
		e.Severity = "INFO"
	}
	out, err := json.Marshal(e)
	if err != nil {
		log.Printf("json.Marshal: %v", err)
	}
	return string(out)
}

func logError(msg string) {
	log.Println(LogEntry{
		Severity: "ERROR",
		Message:  msg,
	})
}

type WebhookEvent struct {
	ObjectType string      `json:"object_type"`
	Metric     string      `json:"metric"`
	Timestamp  int         `json:"timestamp"`
	Data       WebhookData `json:"data"`
}

type WebhookData struct {
	FailureMessage string `json:"failure_message"`
}

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

func trackWebhookEvent(w http.ResponseWriter, r *http.Request) {
	// Declare a new Person struct.
	var e WebhookEvent

	signature := r.Header.Get("X-CIO-Signature")
	ts, err := strconv.Atoi(r.Header.Get("X-CIO-Timestamp"))

	if err != nil {
		logError("ERROR: Could not decode X-CIO-Timestamp: " + err.Error())
		http.Error(w, "Could not decode X-CIO-Timestamp", http.StatusBadRequest)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logError("ERROR: Could not read request body: " + err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	validSig, err := checkSignature(signingSecret, signature, ts, bodyBytes)

	if validSig != true {
		logError("ERROR: Invalid signature: " + err.Error())
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	// Try to decode the request body into the struct. If there is an error,
	// respond to the client with the error message and a 400 status code.
	err = json.Unmarshal(bodyBytes, &e)

	if err != nil {
		logError("ERROR: Could not decode webhook JSON")
		http.Error(w, "Could not decode webhook JSON", http.StatusBadRequest)
		return
	}

	// Log request if error
	if e.Data.FailureMessage != "" {
		outJson := map[string]interface{}{}
		json.Unmarshal([]byte(bodyBytes), &outJson)
		outJson["severity"] = "ERROR"
		outJson["message"] = e.Data.FailureMessage
		log.Println(json.Marshal(outJson))
	}

	go func() {
		eventCounter.WithLabelValues(e.ObjectType, e.Metric).Inc()
	}()
}

func main() {
	if signingSecret == "" {
		log.Fatal(LogEntry{Message: "Must set WEBHOOK_SIGNING_SECRET environment variable", Severity: "FATAL"})
		os.Exit(1)
	}

	// Use structured logging
	log.SetFlags(0)

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

	log.Println(LogEntry{Message: "Beginning to serve on port :8080"})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
