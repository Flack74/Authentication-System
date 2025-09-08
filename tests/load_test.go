package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Flack74/go-auth-system/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestLoadRegistration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}
	
	// Check if server is available
	resp, err := http.Get("http://localhost:8080/health")
	if err != nil {
		t.Skip("Server not available, skipping load test")
	}
	resp.Body.Close()

	const (
		numGoroutines = 10
		requestsPerGoroutine = 5
		baseURL = "http://localhost:8080"
	)

	var wg sync.WaitGroup
	results := make(chan TestResult, numGoroutines*requestsPerGoroutine)

	// Start load test
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			for j := 0; j < requestsPerGoroutine; j++ {
				result := performRegistrationRequest(baseURL, goroutineID, j)
				results <- result
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(results)

	// Analyze results
	var successCount, failureCount int
	var totalDuration time.Duration
	
	for result := range results {
		if result.Success {
			successCount++
		} else {
			failureCount++
		}
		totalDuration += result.Duration
	}

	totalRequests := numGoroutines * requestsPerGoroutine
	avgDuration := totalDuration / time.Duration(totalRequests)

	t.Logf("Load Test Results:")
	t.Logf("Total Requests: %d", totalRequests)
	t.Logf("Successful: %d", successCount)
	t.Logf("Failed: %d", failureCount)
	t.Logf("Average Duration: %v", avgDuration)
	t.Logf("Success Rate: %.2f%%", float64(successCount)/float64(totalRequests)*100)

	// Assertions
	assert.True(t, avgDuration < 500*time.Millisecond, "Average response time should be under 500ms")
	assert.True(t, float64(successCount)/float64(totalRequests) > 0.8, "Success rate should be above 80%")
}

func TestRateLimitingLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping rate limiting test in short mode")
	}
	
	// Check if server is available
	resp, err := http.Get("http://localhost:8080/health")
	if err != nil {
		t.Skip("Server not available, skipping rate limiting test")
	}
	resp.Body.Close()

	const (
		numRequests = 15
		baseURL = "http://localhost:8080"
	)

	var rateLimitedCount int
	
	for i := 0; i < numRequests; i++ {
		resp, err := http.Get(baseURL + "/health")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		
		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimitedCount++
		}
		
		resp.Body.Close()
		time.Sleep(50 * time.Millisecond) // Small delay between requests
	}

	t.Logf("Rate Limited Requests: %d out of %d", rateLimitedCount, numRequests)
	assert.True(t, rateLimitedCount > 0, "Rate limiting should kick in after 10 requests")
}

type TestResult struct {
	Success  bool
	Duration time.Duration
	Error    error
}

func performRegistrationRequest(baseURL string, goroutineID, requestID int) TestResult {
	start := time.Now()
	
	reqBody := models.CreateUserRequest{
		Email:    fmt.Sprintf("load-test-%d-%d@example.com", goroutineID, requestID),
		Password: "LoadTest123!",
	}
	
	jsonBody, _ := json.Marshal(reqBody)
	
	resp, err := http.Post(
		baseURL+"/auth/register",
		"application/json",
		bytes.NewBuffer(jsonBody),
	)
	
	duration := time.Since(start)
	
	if err != nil {
		return TestResult{Success: false, Duration: duration, Error: err}
	}
	defer resp.Body.Close()
	
	success := resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusConflict
	return TestResult{Success: success, Duration: duration}
}

func BenchmarkRegistrationEndpoint(b *testing.B) {
	baseURL := "http://localhost:8080"
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			reqBody := models.CreateUserRequest{
				Email:    fmt.Sprintf("bench-test-%d@example.com", i),
				Password: "BenchTest123!",
			}
			
			jsonBody, _ := json.Marshal(reqBody)
			
			resp, err := http.Post(
				baseURL+"/auth/register",
				"application/json",
				bytes.NewBuffer(jsonBody),
			)
			
			if err != nil {
				b.Fatalf("Request failed: %v", err)
			}
			resp.Body.Close()
			i++
		}
	})
}