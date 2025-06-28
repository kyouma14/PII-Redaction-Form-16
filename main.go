package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Hard-coded input PDF; change the value below to process a different file.
const DefaultPDFFile = "Form16_AKJPC0334Q_2025-26.pdf"

// PIIFilter contains regex patterns for identifying PII data in Form 16
type PIIFilter struct {
	PhonePattern   *regexp.Regexp
	EmailPattern   *regexp.Regexp
	GSTPattern     *regexp.Regexp
	PANPattern     *regexp.Regexp
	AadhaarPattern *regexp.Regexp
	TANPattern     *regexp.Regexp
	AddressPattern *regexp.Regexp
	// Pattern for detecting organisation / company names so they are not redacted as addresses.
	OrganizationPattern *regexp.Regexp
	// Additional pattern that looks for generic address-related keywords (e.g., House, Road,
	// Block, Sector, Opp., Near, etc.) to catch address lines that don't explicitly mention a
	// city or state name.
	AddressKeywordPattern *regexp.Regexp
}

// FilteredData represents the cleaned data structure
type FilteredData struct {
	CleanedText    string
	RemovedFields  []string
	RetainedFields map[string][]string
}

// NewPIIFilter creates a new PII filter with Form 16 specific regex patterns
func NewPIIFilter() *PIIFilter {
	return &PIIFilter{
		// Indian phone number patterns (10 digits starting with 6-9)
		PhonePattern: regexp.MustCompile(`(?:\+91|91)?[-\.\s]?[6-9]\d{9}|\b[6-9]\d{9}\b`),

		// Email pattern
		EmailPattern: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),

		// GST Number pattern (15 digits) - employer's GSTIN
		GSTPattern: regexp.MustCompile(`\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}[Z]{1}[A-Z\d]{1}\b`),

		// PAN Number pattern
		PANPattern: regexp.MustCompile(`\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b`),

		// Aadhaar Number pattern (12 digits)
		AadhaarPattern: regexp.MustCompile(`\b\d{4}\s?\d{4}\s?\d{4}\b|\b\d{12}\b`),

		// TAN (Tax Deduction Account Number)
		TANPattern: regexp.MustCompile(`(?i)\b[A-Z]{4}[0-9]{5}[A-Z]\b`),

		// Address pattern – matches well-known Indian states or major city names.
		// Stand-alone 6-digit numbers (potential amounts) have been removed to avoid false positives.
		AddressPattern: regexp.MustCompile(`(?i)\b(?:Ahmedabad|Bangalore|Bengaluru|Mumbai|Bombay|Chennai|Kolkata|Calcutta|Hyderabad|Delhi|New Delhi|Pune|Jaipur|Surat|Lucknow|Kanpur|Nagpur|Indore|Thane|Bhopal|Visakhapatnam|Vizag|Vadodara|Baroda|Firozabad|Ludhiana|Patna|Agra|Nashik|Faridabad|Meerut|Rajkot|Kalyan|Vasai|Varanasi|Srinagar|Aurangabad|Dhanbad|Amritsar|Ranchi|Gwalior|Jabalpur|Coimbatore|Guwahati|Chandigarh|Hubli|Dharwad|Mysore|Mysuru|Noida|Ghaziabad|Kozhikode|Calicut|Trivandrum|Thiruvananthapuram|Kochi|Ernakulam|Madurai|Tiruchirappalli|Trichy|Salem|Guntur|Vijayawada|Nellore|Warangal|Karimnagar|Raipur|Bhubaneswar|Cuttack|Shimla|Dehradun|Gangtok|Shillong|Imphal|Aizawl|Kohima|Itanagar|Agartala|Gandhinagar|Allahabad|Prayagraj|Gorakhpur|Bareilly|Jodhpur|Udaipur|Kolhapur|Solapur|Ahmednagar|Mangaluru|Mangalore|Béngaluru|Bilaspur|Durgapur|Siliguri|Asansol|Dibrugarh|Panipat|Rohtak|Hisar|Jamshhedpur|Bokaro|Rourkela|Belgaum|Belagavi|Saharanpur|Aligarh|Moradabad|Muzaffarpur|Gaya|Darbhanga|Bhagalpur|Kota|Ajmer|Mathura|Haldwani|Nainital|Pithoragarh|Kullu|Manali|Shimoga|Tumkur|Davangere|Mangalore|Goa|Panaji|Vile Parle|Maharashtra|Gujarat|Karnataka|Tamil Nadu|Uttar Pradesh|Madhya Pradesh|Rajasthan|Punjab|Haryana|Bihar|West Bengal|Odisha|Kerala|Telangana|Andhra Pradesh|Chhattisgarh|Uttarakhand|Himachal Pradesh|Assam|Jharkhand|Tripura|Manipur|Mizoram|Nagaland|Arunachal Pradesh|Sikkim|Meghalaya|Puducherry|Ladakh|Jammu and Kashmir|Andaman and Nicobar Islands|Lakshadweep|Daman and Diu|Dadra and Nagar Haveli)\b`),

		// Organisation keywords (case-insensitive) used to identify company names so they are
		// not mistaken for addresses.
		OrganizationPattern: regexp.MustCompile(`(?i)\b(?:Pvt\.?\s*Ltd\.?|Private\s+Limited|Ltd\.?|Limited|LLP|L\.L\.P\.?|LLC|L\.L\.C\.?|Inc\.?|Incorporated|Corp\.?|Corporation|Company|Co\.?\s*Ltd\.?|PLC|Pte\.?\s*Ltd\.?)\b`),

		// Generic keywords that frequently appear in Indian street addresses but are unlikely to
		// appear in normal narrative text.
		AddressKeywordPattern: regexp.MustCompile(`(?i)\b(?:House|Block|Tower|Flat|Floor|Flr|Road|Rd\.?|Street|St\.?|Lane|Ln\.?|Sector|Plot|Opp\.?|Near|Behind)\b`),
	}
}

// FilterPII removes or masks PII data from text
func (pf *PIIFilter) FilterPII(text string) FilteredData {
	result := FilteredData{
		CleanedText:    text,
		RemovedFields:  []string{},
		RetainedFields: make(map[string][]string),
	}

	// Find and remove phone numbers
	phoneMatches := pf.PhonePattern.FindAllString(text, -1)
	if len(phoneMatches) > 0 {
		result.RemovedFields = append(result.RemovedFields, "Phone Numbers")
		result.CleanedText = pf.PhonePattern.ReplaceAllString(result.CleanedText, "[PHONE_REDACTED]")
	}

	// Find and remove email addresses
	emailMatches := pf.EmailPattern.FindAllString(text, -1)
	if len(emailMatches) > 0 {
		result.RemovedFields = append(result.RemovedFields, "Email Addresses")
		result.CleanedText = pf.EmailPattern.ReplaceAllString(result.CleanedText, "[EMAIL_REDACTED]")
	}

	// Find and remove Aadhaar numbers
	aadhaarMatches := pf.AadhaarPattern.FindAllString(text, -1)
	if len(aadhaarMatches) > 0 {
		result.RemovedFields = append(result.RemovedFields, "Aadhaar Numbers")
		result.CleanedText = pf.AadhaarPattern.ReplaceAllString(result.CleanedText, "[AADHAAR_REDACTED]")
	}

	// Find and remove PAN numbers
	panMatches := pf.PANPattern.FindAllString(text, -1)
	if len(panMatches) > 0 {
		result.RemovedFields = append(result.RemovedFields, "PAN Numbers")
		result.CleanedText = pf.PANPattern.ReplaceAllString(result.CleanedText, "[PAN_REDACTED]")
	}

	// Mask GST numbers as they are now considered sensitive
	if pf.GSTPattern.MatchString(text) {
		result.RemovedFields = append(result.RemovedFields, "GST Numbers")
		result.CleanedText = pf.GSTPattern.ReplaceAllString(result.CleanedText, "[GST_REDACTED]")
	}

	// Find and remove TAN numbers
	tanMatches := pf.TANPattern.FindAllString(text, -1)
	if len(tanMatches) > 0 {
		result.RemovedFields = append(result.RemovedFields, "TAN Numbers")
		result.CleanedText = pf.TANPattern.ReplaceAllString(result.CleanedText, "[TAN_REDACTED]")
	}

	// Detect and redact address lines containing Indian city/state names or PIN codes
	lines := strings.Split(result.CleanedText, "\n")
	addressFound := false
	orgFound := false
	for i, line := range lines {
		// Trim leading/trailing spaces before matching to make detection resilient to PDF
		trimmed := strings.TrimSpace(line)

		// Detect organisation names: redact entire line
		if pf.OrganizationPattern.MatchString(trimmed) {
			lines[i] = "[ORG_REDACTED]"
			orgFound = true
			continue
		}

		if pf.AddressPattern.MatchString(trimmed) || pf.AddressKeywordPattern.MatchString(trimmed) {
			lines[i] = "[ADDRESS_REDACTED]"
			addressFound = true
		}
	}
	if addressFound {
		result.RemovedFields = append(result.RemovedFields, "Addresses")
	}
	if orgFound {
		result.RemovedFields = append(result.RemovedFields, "Organizations")
	}
	result.CleanedText = strings.Join(lines, "\n")

	return result
}

// ReadPDF is deprecated; the program now relies exclusively on 'pdftotext'.
func ReadPDF(_ string) (string, error) {
	return "", fmt.Errorf("internal PDF extraction disabled; use pdftotext")
}

// FallbackReadPDFWithPdftotext attempts to extract text using the external 'pdftotext' command-line tool when the internal extractor returns no content.
func FallbackReadPDFWithPdftotext(filename string) (string, error) {
	// Use the -layout flag to keep original layout and output to stdout ("-").
	cmd := exec.Command("pdftotext", "-layout", filename, "-")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("fallback extraction failed: %v", err)
	}
	return string(out), nil
}

// SaveFilteredData saves the filtered data to a file
func SaveFilteredData(data FilteredData, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	// Write header
	file.WriteString("=== FILTERED PDF DATA ===\n\n")

	// Write summary
	file.WriteString("FILTERING SUMMARY:\n")
	file.WriteString(fmt.Sprintf("- Removed PII Fields: %v\n", data.RemovedFields))
	file.WriteString(fmt.Sprintf("- Retained Business Fields: %v\n", getKeys(data.RetainedFields)))
	file.WriteString("\n")

	// Write retained business data
	if len(data.RetainedFields) > 0 {
		file.WriteString("RETAINED BUSINESS DATA:\n")
		for fieldType, values := range data.RetainedFields {
			file.WriteString(fmt.Sprintf("%s:\n", fieldType))
			for _, value := range values {
				file.WriteString(fmt.Sprintf("  - %s\n", value))
			}
		}
		file.WriteString("\n")
	}

	// Write cleaned text
	file.WriteString("CLEANED TEXT CONTENT:\n")
	file.WriteString(strings.Repeat("=", 50) + "\n")
	file.WriteString(data.CleanedText)

	return nil
}

// SaveRawText saves the unfiltered extracted PDF text to a file for comparison
func SaveRawText(text string, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create raw text file: %v", err)
	}
	defer file.Close()

	// Optionally add a simple header for clarity
	file.WriteString("=== RAW PDF TEXT (NO REDACTIONS) ===\n\n")
	_, err = file.WriteString(text)
	return err
}

// Helper function to get map keys
func getKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// LoadWordSet reads a newline-separated list of English words from the supplied
// file path and returns a set for O(1) existence checks.
func LoadWordSet(path string) (map[string]struct{}, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	set := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		w := strings.TrimSpace(scanner.Text())
		if w == "" {
			continue
		}
		set[strings.ToLower(w)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return set, nil
}

// RedactUnknownWords scans the provided text and replaces every alphabetic
// token that is NOT found in the supplied word-set with the placeholder
// "[WORD_REDACTED]". It returns the redacted text and a slice containing the
// unique set of words that were redacted.
func RedactUnknownWords(text string, dict map[string]struct{}) (string, []string) {
	wordPattern := regexp.MustCompile(`(?i)\b[[:alpha:]]+\b`)

	redactedSet := make(map[string]struct{})

	redactedText := wordPattern.ReplaceAllStringFunc(text, func(token string) string {
		if strings.HasPrefix(token, "[") && strings.HasSuffix(token, "]") {
			return token
		}
		lower := strings.ToLower(token)
		// Relax rule: keep very short words (<=3 letters) unconditionally.
		if len(lower) <= 3 {
			return token
		}
		if _, ok := dict[lower]; ok {
			return token // English word, keep it
		}
		redactedSet[lower] = struct{}{}
		return "[WORD_REDACTED]"
	})

	words := make([]string, 0, len(redactedSet))
	for w := range redactedSet {
		words = append(words, w)
	}
	return redactedText, words
}

func main() {
	pdfFile := DefaultPDFFile
	outputFile := "filtered_output.txt"
	rawOutputFile := "extracted_text.txt"

	// Allow overriding output file names via optional CLI args (positions 1 and 2)
	if len(os.Args) > 1 {
		outputFile = os.Args[1]
	}
	if len(os.Args) > 2 {
		rawOutputFile = os.Args[2]
	}

	// Check if PDF file exists
	if _, err := os.Stat(pdfFile); os.IsNotExist(err) {
		log.Fatalf("PDF file does not exist: %s", pdfFile)
	}

	fmt.Printf("Reading PDF file: %s\n", pdfFile)

	var (
		pdfText string
		err     error
	)

	pdfText, err = FallbackReadPDFWithPdftotext(pdfFile)
	if err != nil {
		log.Fatalf("Error extracting text with pdftotext: %v", err)
	}

	if strings.TrimSpace(pdfText) == "" {
		fmt.Println("No text could be extracted from the PDF. Exiting.")
		return
	}

	fmt.Printf("Extracted %d characters from PDF\n", len(pdfText))

	// Save raw extracted text (before any redaction)
	if err := SaveRawText(pdfText, rawOutputFile); err != nil {
		log.Fatalf("Error saving raw extracted text: %v", err)
	}

	// Initialize PII filter
	piiFilter := NewPIIFilter()

	// Filter PII data
	fmt.Println("Filtering PII data...")
	filteredData := piiFilter.FilterPII(pdfText)

	// Redacting non-dictionary English words using offline list...
	fmt.Println("Redacting non-dictionary English words using offline list...")
	wordSet, err := LoadWordSet("english_words.txt")
	if err != nil {
		log.Fatalf("Failed to load english word list: %v", err)
	}
	updatedText, nonEnglishWords := RedactUnknownWords(filteredData.CleanedText, wordSet)
	filteredData.CleanedText = updatedText
	if len(nonEnglishWords) > 0 {
		filteredData.RemovedFields = append(filteredData.RemovedFields, "Non-Dictionary Words")
	}

	// Save filtered data (after both PII and dictionary redaction)
	err = SaveFilteredData(filteredData, outputFile)
	if err != nil {
		log.Fatalf("Error saving filtered data: %v", err)
	}

	// Print summary
	fmt.Printf("\n=== PROCESSING COMPLETE ===\n")
	fmt.Printf("Input file: %s\n", pdfFile)
	fmt.Printf("Filtered output file: %s\n", outputFile)
	fmt.Printf("Raw text file: %s\n", rawOutputFile)
	fmt.Printf("Original text length: %d characters\n", len(pdfText))
	fmt.Printf("Filtered text length: %d characters\n", len(filteredData.CleanedText))

	if len(filteredData.RemovedFields) > 0 {
		fmt.Printf("Removed PII fields: %s\n", strings.Join(filteredData.RemovedFields, ", "))
	}

	if len(filteredData.RetainedFields) > 0 {
		fmt.Printf("Retained business data: %s\n", strings.Join(getKeys(filteredData.RetainedFields), ", "))
	}

	fmt.Println("\nFiltered data has been saved successfully!")
}
