package audit

import (
	"bytes"
	"encoding/csv"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// ExportCSV renders an audit report as CSV (UTF-8 with BOM so spreadsheet
// applications display Arabic correctly). Diagnosis and fix are included in
// both languages; lang selects the header language.
func ExportCSV(rep model.AuditReport, lang string) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("\ufeff")
	w := csv.NewWriter(&buf)
	hdr := []string{"id", "severity", "kind", "subject", "event_ids", "count", "first_seen", "last_seen",
		"title_en", "diagnosis_en", "recommended_fix_en", "title_ar", "diagnosis_ar", "recommended_fix_ar", "details"}
	if lang == "ar" {
		hdr = []string{"المعرف", "الخطورة", "النوع", "العنصر", "أرقام الأحداث", "العدد", "أول ظهور", "آخر ظهور",
			"العنوان (EN)", "التشخيص (EN)", "الإصلاح المقترح (EN)", "العنوان (AR)", "التشخيص المبسّط", "الإصلاح المقترح", "التفاصيل"}
	}
	if err := w.Write(hdr); err != nil {
		return nil, err
	}
	for _, f := range rep.Findings {
		ids := make([]string, len(f.EventIDs))
		for i, id := range f.EventIDs {
			ids[i] = strconv.Itoa(int(id))
		}
		keys := make([]string, 0, len(f.Details))
		for k := range f.Details {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		det := make([]string, len(keys))
		for i, k := range keys {
			det[i] = k + "=" + f.Details[k]
		}
		rec := []string{f.ID, f.Severity, f.Kind, cell(f.Subject), strings.Join(ids, " "), strconv.Itoa(f.Count),
			f.First.UTC().Format(time.RFC3339), f.Last.UTC().Format(time.RFC3339),
			cell(f.Title.En), cell(f.Diagnosis.En), cell(f.Fix.En), cell(f.Title.Ar), cell(f.Diagnosis.Ar), cell(f.Fix.Ar),
			cell(strings.Join(det, "; "))}
		if err := w.Write(rec); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// cell neutralises spreadsheet formula injection: event data such as user
// names is attacker-controlled (a failed logon can carry any name).
func cell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
