package main

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
)

func isSQLInjection(query string) bool {
	sqlPatterns := []string{
		`(?i)SELECT .* FROM`, // Basic SELECT statement
		`(?i)INSERT INTO .*`, // Basic INSERT statement
		`(?i)DROP TABLE .*`,  // DROP statement
		`' OR '1'='1'`,       // Simple OR-based SQL injection
		`' OR '1'='1' --`,    // Comment-based injection
		`' OR 'x'='x'`,       // Another variation
		`--`,                 // SQL comment
		`;`,                  // End of SQL statement
	}

	for _, pattern := range sqlPatterns {
		matched, _ := regexp.MatchString(pattern, query)
		if matched {
			return true
		}

	}
	return false
}

func isXSSAttack(query string) bool {
	xssPattern := []string{
		`<script>.*</script>`, // Basic XSS script tag
		`javascript:.*`,       // JavaScript URI
		`onerror=.*`,          // Event handler
	}

	for _, pattern := range xssPattern {
		matched, _ := regexp.MatchString(pattern, query)
		if matched {
			return true
		}
	}
	return false
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	Query := r.URL.Query().Get("query")

	if isSQLInjection(Query) {
		http.Error(w, "Potential SQL injection detected!", http.StatusBadRequest)
		return
	}

	if isXSSAttack(Query) {
		http.Error(w, "Potential XSS attack detected!", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "The result of the Query is :%s", Query)
}

func main() {
	http.HandleFunc("/search", searchHandler)
	fmt.Println("Starting Server on port: 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))

}
