package config

import "regexp"

// NoisyDomains contains domains to filter out from absolute URLs
var NoisyDomains = []string{
	"w3.org", "wikipedia.org", "schema.org", "github.com", "docs.rs",
	"opensource.org", "apache.org", "apple.com", "microsoft.com",
	"aka.ms", "pris.ly", "xmlsoap.org", "1password.com", "bitwarden.com",
	"unicode.org", "go.dev", "cambridgesoft.com", "sil.org", "cairographics.org",
	"nvidia.com", "ieee.org", "arxiv.org", "scipy.org", "play.rust-lang.org",
	"fonts.googleapis.com", "fonts.gstatic.com", "publicsuffix.org", "iana.org",
	"mcafee.com", "mcafeewebadvisor.com", "yahoo.com", "tawk.to", "office.com",
	"libretro.com", "retroachievements.org", "wencodeURIComponent",
}

// NoisyExtensions contains file extensions typically associated with noise rather than valid endpoints
var NoisyExtensions = []string{
	".rs", ".cpp", ".c", ".h", ".hpp", ".cc", ".go", ".ts", ".js",
	".proto", ".md", ".txt", ".xml", ".xsd", ".dtd", ".html",
	".css", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".wasm",
}

// NoisyEndpointKeywords contains common framework and system keywords to ignore
var NoisyEndpointKeywords = []string{
	"__", "system.text", "system.net", "system.io", "system.collections",
}

// CompilerArtifactPatterns contains regular expressions to identify and filter out common compiler artifacts
var CompilerArtifactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:/opt/emsdk/|emsdk/upstream/|/musl/src/|/libcxxabi/)`),
	regexp.MustCompile(`(?i)(?:\.cargo/registry/|\.cargo/git/|\.rustup/toolchains/)`),
	regexp.MustCompile(`(?i)(?:/home/runner/work/|/home/runner/\.cache/)`),
	regexp.MustCompile(`(?i)(?:/usr/share/zoneinfo/|/etc/zoneinfo/|/etc/localtime)`),
	regexp.MustCompile(`(?i)(?:/tmp/lept/|/tmp/wvj/|/var/folders/|/opt/homebrew/)`),
	regexp.MustCompile(`(?i)(?:/usr/local/go/src/|/tinygo/src/)`),
	regexp.MustCompile(`(?i)(?:__rustc)oxy`),
}

var JsPropertyPattern = regexp.MustCompile(`^(?:[a-zA-Z_$][0-9a-zA-Z_$]*\.)+[a-zA-Z_$][0-9a-zA-Z_$]*$`)

// Patterns contains core regex patterns for finding secrets, tokens, and endpoints
var Patterns = map[string]*regexp.Regexp{
	"AWS Access Key":           regexp.MustCompile(`(AKIA[0-9A-Z]{16})`),
	"AWS Session Token":        regexp.MustCompile(`(ASIA[0-9A-Z]{16})`),
	"GCP API Key":              regexp.MustCompile(`(AIza[0-9A-Za-z\-_]{35})`),
	"Azure Storage Account":    regexp.MustCompile(`([a-z0-9-]+\.blob\.core\.windows\.net)`),
	"AWS S3 Bucket":            regexp.MustCompile(`([a-z0-9.-]+\.s3\.amazonaws\.com)`),
	"Slack Bot Token":          regexp.MustCompile(`(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})`),
	"Slack Webhook":            regexp.MustCompile(`(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24})`),
	"Discord Bot Token":        regexp.MustCompile(`(MT[0-9A-Za-z_-]{22,23}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27})`),
	"Telegram Bot Token":       regexp.MustCompile(`(?:^|[^0-9])([0-9]{8,10}:[a-zA-Z0-9_-]{35})(?:$|[^a-zA-Z0-9_-])`),
	"Stripe Standard Key":      regexp.MustCompile(`((?:sk|rk)_(?:test|live)_[a-zA-Z0-9]{24,})`),
	"GitHub Personal Token":    regexp.MustCompile(`((?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9_]{36})`),
	"MongoDB URI":              regexp.MustCompile(`(mongodb(?:\+srv)?://[a-zA-Z0-9_.-]+:[^@\s]+@[a-zA-Z0-9_.-]+)`),
	"PostgreSQL URI":           regexp.MustCompile(`(postgres(?:ql)?://[a-zA-Z0-9_.-]+:[^@\s]+@[a-zA-Z0-9_.-]+:[0-9]{2,5})`),
	"Redis URI":                regexp.MustCompile(`(redis(?:s)?://(?:[a-zA-Z0-9_.-]+:)?([^@\s]+)@[a-zA-Z0-9_.-]+:[0-9]{2,5})`),
	"JWT Token":                regexp.MustCompile(`(eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{10,})`),
	"Private Key (RSA/EC/SSH)": regexp.MustCompile(`(-----BEGIN [A-Z ]+ PRIVATE KEY-----[A-Za-z0-9+/=]{64,}-----END [A-Z ]+ PRIVATE KEY-----)`),
	"Generic Secret/Token":     regexp.MustCompile(`(?i)(?:password|api[_-]?key|secret|token|auth[_-]?token|client[_-]?(?:secret|id)|access[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9\-_=]{16,64})["']?`),
	"IPv4 Address":             regexp.MustCompile(`((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))`),
	"Absolute URL":             regexp.MustCompile(`(https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?::[0-9]+)?(?:/[a-zA-Z0-9_/\-\.?=&%]+)?)`),
	"Relative API Endpoint":    regexp.MustCompile(`(/(?:api|v[1-9][0-9]*)/[a-zA-Z0-9_/\-\.?=&]+)`),
	"GraphQL Query":            regexp.MustCompile(`(?i)(query\s+[A-Za-z0-9_]*\s*\{|mutation\s+[A-Za-z0-9_]*\s*\{)`),
	"URL/Form Parameters":      regexp.MustCompile(`[?&]([a-zA-Z0-9_.-]+)=`),
	"Sensitive JSON Keys":      regexp.MustCompile(`"(?i)(password|token|secret|api_?key|private_?key)"\s*:`),
	"HTTP Headers":             regexp.MustCompile(`(?i)(X-[a-zA-Z0-9_-]+|Authorization|Bearer|Cookie|Set-Cookie)\s*:`),
}

// EntropyThresholds defines minimum entropy levels required to validate certain unstructured tokens
var EntropyThresholds = map[string]float64{
	"Generic Secret/Token": 4.1,
	"JWT Token":            4.0,
	"GCP API Key":          3.8,
}