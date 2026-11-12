package main

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"testing"
	"time"
)

func paginationTracker() *ConnTracker {
	tr := NewConnTracker(8, time.Hour)
	for i := 0; i < 6; i++ {
		id := tr.Begin(ConnMeta{Proto: "http"}, fmt.Sprintf("host%d.example", i), 80)
		if i%2 == 0 {
			tr.Fail(id, errors.New("closed"))
		}
	}
	return tr
}

func checkPagination(t testing.TB, tr *ConnTracker, tab, q string, page, size int) {
	t.Helper()
	items, total, err := tr.List(tab, q, "", page, size)
	if page < 1 || size < 1 || size > 200 {
		if err == nil {
			t.Fatalf("invalid page=%d size=%d accepted", page, size)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	all, wantTotal, err := tr.List(tab, q, "", 1, 200)
	if err != nil {
		t.Fatal(err)
	}
	if total != wantTotal {
		t.Fatalf("total=%d want=%d", total, wantTotal)
	}
	// Select expected records by their page number, independently of slice arithmetic.
	var want []uint64
	for i, item := range all {
		if i/size+1 == page {
			want = append(want, item.ID)
		}
	}
	if len(items) != len(want) {
		t.Fatalf("page=%d size=%d items=%d want=%d", page, size, len(items), len(want))
	}
	for i, item := range items {
		if item.ID != want[i] {
			t.Fatalf("page order differs at %d", i)
		}
	}

}

func TestConnTrackerPaginationOverflow(t *testing.T) {
	for _, empty := range []bool{false, true} {
		tr := paginationTracker()
		if empty {
			tr = NewConnTracker(8, time.Hour)
		}
		for _, tab := range []string{"active", "history"} {
			for _, q := range []string{"", "absent"} {
				for _, size := range []int{1, 2, 50, 200} {
					for _, page := range []int{1, 2, 3, 4, math.MaxInt, math.MaxInt / size, math.MaxInt/max(size, 2) + 1} {
						t.Run(fmt.Sprintf("empty=%t/%s/%s/%d/%d", empty, tab, q, size, page), func(t *testing.T) { checkPagination(t, tr, tab, q, page, size) })
					}
				}
			}
		}
	}
}

func TestConnectionsPaginationBoundary(t *testing.T) {
	addr := startTestHealth(t, testDialer{}, paginationTracker(), "", 0)
	for _, tab := range []string{"active", "history"} {
		for _, size := range []int{1, 2, 50, 200} {
			for _, page := range []int{math.MaxInt, math.MaxInt / size, math.MaxInt/max(size, 2) + 1} {
				code, body := getAPI(t, fmt.Sprintf("http://%s/api/connections?tab=%s&page=%d&page_size=%d", addr, tab, page, size))
				if code != http.StatusOK || body.Total != 3 || body.Page != page || body.PageSize != size || body.Items == nil || len(body.Items) != 0 {
					t.Fatalf("page=%d size=%d code=%d body=%+v", page, size, code, body)
				}
			}
		}
	}
	for _, query := range []string{"page=-1", "page=0", "page=9223372036854775808", "page_size=-1", "page_size=201"} {
		code, _ := getAPI(t, "http://"+addr+"/api/connections?"+query)
		if code != 400 {
			t.Fatalf("%s: code=%d", query, code)
		}
	}
}

func FuzzConnTrackerPagination(f *testing.F) {
	for _, pair := range [][2]int{{1, 1}, {2, 2}, {3, 2}, {math.MaxInt, 2}, {math.MaxInt, 200}, {0, 50}, {-1, 50}, {1, 0}, {1, math.MaxInt}} {
		f.Add(pair[0], pair[1])
	}
	f.Fuzz(func(t *testing.T, page, size int) {
		tr := paginationTracker()
		for _, tab := range []string{"active", "history"} {
			for _, q := range []string{"", "absent"} {
				checkPagination(t, tr, tab, q, page, size)
			}
		}
	})
}
