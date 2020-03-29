package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"github.com/dgrijalva/jwt-go"
)

type key int

const (
	requestIDKey key = 0
)

var (
	host    string
	healthy int32
	port    int

	ctx         context.Context
	firebaseApp *firebase.App
	authClient  *auth.Client
	logger      *log.Logger
)

func main() {
	flag.StringVar(&host, "host", "", "server listen address")
	flag.IntVar(&port, "port", 8080, "port listen address")
	flag.Parse()

	logger = log.New(os.Stdout, "portico: ", log.LstdFlags)

	ctx = context.Background()

	app, err := initializeAdminSDK(ctx)
	if err != nil {
		logger.Fatalf("failed to initialize firebase sdk with error %v", err)
		return
	}

	client, err := initializeAuthClient(ctx, app)
	if err != nil {
		logger.Fatalf("failed to initialize firebase sdk with error %v", err)
		return
	}

	firebaseApp = app
	authClient = client

	logger.Println("Portico server")
	logger.Println("Server is starting...")

	router := http.NewServeMux()
	router.Handle("/auth", validateToken())
	router.Handle("/healthcheck", healthcheck())
	router.Handle("/updateclaims", updateClaims())

	nextRequestID := func() string {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}

	listenAddr := fmt.Sprintf("%v:%v", host, port)

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      tracing(nextRequestID)(logging(logger)(router)),
		ErrorLog:     logger,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	go func() {
		<-quit
		logger.Println("Server is shutting down...")
		atomic.StoreInt32(&healthy, 0)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		server.SetKeepAlivesEnabled(false)
		if err := server.Shutdown(ctx); err != nil {
			logger.Fatalf("Could not gracefully shutdown the server: %v\n", err)
		}
		close(done)
	}()

	logger.Println("Server is ready to handle requests at", listenAddr)
	atomic.StoreInt32(&healthy, 1)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("Could not listen on %s: %v\n", listenAddr, err)
	}

	<-done
	logger.Println("Server stopped")
}

func validateToken() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("Checking for token in the request...")

		if r.Header.Get("X-Forwarded-Method") == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		tokenHeader := r.Header.Get("Auth-Token")
		if len(tokenHeader) == 0 {
			logger.Printf("💥 missing token header in request 😬")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var tokenValues map[string]string
		var err error

		originURI := r.Header.Get("X-Forwarded-Uri")
		logger.Printf("forwarded uri %s", originURI)

		if strings.Contains(originURI, "mexico") {
			logger.Printf("mexico token")
			tokenValues, err = verifyAndOpenMexicoToken(tokenHeader)
		} else {
			logger.Printf("id token")
			tokenValues, err = verifyAndOpenIDToken(tokenHeader)
		}

		if err != nil {
			logger.Printf("💥 failed to validate token with error %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		logger.Printf("🤨 values from claims: %v", tokenValues)

		headers := w.Header()

		// Set CORS headers
		headers["Access-Control-Allow-Origin"] = []string{"*"}

		for k, v := range tokenValues {
			headers[k] = []string{v}
		}

		logger.Printf("👉 headers for request: %v", w.Header())

		w.WriteHeader(http.StatusAccepted)
	})
}

func updateClaims() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Println("Updating user claims...")

		queryParameters := r.URL.Query()

		firebaseID, ok := queryParameter(queryParameters, "authenticationID", w)
		if !ok {
			return
		}

		userID, ok := queryParameter(queryParameters, "userID", w)
		if !ok {
			return
		}

		profileID, ok := queryParameter(queryParameters, "profileID", w)
		if !ok {
			return
		}

		if ok, err := updateUserClaims(firebaseID, userID, profileID); !ok {
			log.Printf("💥 failed to update user claims with error %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}

		w.WriteHeader(http.StatusOK)
	})
}

// Helper methods

func healthcheck() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&healthy) == 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
}

func logging(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				requestID, ok := r.Context().Value(requestIDKey).(string)
				if !ok {
					requestID = "unknown"
				}
				logger.Println(requestID, r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func tracing(nextRequestID func() string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-Id")
			if requestID == "" {
				requestID = nextRequestID()
			}
			ctx := context.WithValue(r.Context(), requestIDKey, requestID)
			w.Header().Set("X-Request-Id", requestID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func verifyAndOpenMexicoToken(tokenAsString string) (map[string]string, error) {
	logger.Printf("validating token %s\n", tokenAsString)
	token, err := jwt.Parse(tokenAsString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return "34e242f33a43750ffff05fe5ae000613c24ff445", nil
	})

	// TODO: update this later

	if token == nil && err != nil {
		return nil, err
	}

	return map[string]string{"X-User-ID": "mexico"}, nil
}

func verifyAndOpenIDToken(tokenAsString string) (map[string]string, error) {
	token, err := authClient.VerifyIDToken(ctx, tokenAsString)

	if err != nil {
		log.Printf("💥 failed to validate token with error %v", err)
		return nil, err
	}

	logger.Printf("🚀 token valid with info %v", token)

	claims := token.Claims

	headers := map[string]string{
		"X-Auth-User": token.UID,
	}

	anonymous, ok := claims["provider_id"]
	if ok && strings.Contains(anonymous.(string), "anonymous") {
		logger.Printf("anonymous 🚀 %v", anonymous)
		return headers, nil
	}

	if userID, ok := claims["UserID"]; ok {
		headers["X-User-ID"] = userID.(string)
	} else {
		logger.Printf("💥 missing UserID from claims")
	}

	if profileID, ok := claims["ProfileID"]; ok {
		headers["X-Profile-ID"] = profileID.(string)
	} else {
		logger.Printf("💥 missing ProfileID from claims")
	}

	return headers, nil
}

func updateUserClaims(firebaseID string, userID string, profileID string) (bool, error) {
	logger.Printf("🧐 Updating claims for user %s with UserID %s and ProfileID %s", firebaseID, userID, profileID)

	claims := map[string]interface{}{"UserID": userID, "ProfileID": profileID}
	err := authClient.SetCustomUserClaims(ctx, firebaseID, claims)

	if err != nil {
		logger.Printf("💥 failed to update claims for userID %s with error %v", firebaseID, err)
		return false, err
	}

	logger.Printf("🚀 Updated claims for user %s with UserID %s and ProfileID %s", firebaseID, userID, profileID)

	return true, nil
}

func queryParameter(v url.Values, name string, w http.ResponseWriter) (string, bool) {
	if value, ok := v[name]; ok {
		return value[0], ok
	}

	w.WriteHeader(http.StatusBadRequest)

	return "", false
}
