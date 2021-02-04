// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package safebrowsing

import (
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/ShandiLin/safebrowsing/internal/safebrowsing_proto"
	"github.com/golang/protobuf/proto"
	google_protobuf "github.com/golang/protobuf/ptypes/duration"
)

// The system tests below are non-deterministic and operate by performing
// network requests against the Safe Browsing API servers. Thus, in order to
// operate they need the user's API key. This can be specified using the -apikey
// command-line flag when running the tests.
var apiKeyFlag = flag.String("apikey", "", "specify your Safe Browsing API key")

func TestNetworkAPIUpdate(t *testing.T) {
	if *apiKeyFlag == "" {
		t.Skip()
	}

	nm, err := newNetAPI(DefaultServerURL, *apiKeyFlag, "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	lists := []*pb.FetchThreatListUpdatesRequest_ListUpdateRequest{
		{
			ThreatType:      pb.ThreatType_POTENTIALLY_HARMFUL_APPLICATION,
			PlatformType:    pb.PlatformType_ANDROID,
			ThreatEntryType: pb.ThreatEntryType_URL,
		}}
	req := &pb.FetchThreatListUpdatesRequest{ListUpdateRequests: lists}

	dat, err := nm.ListUpdate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(dat.GetListUpdateResponses()), len(lists); got != want {
		t.Fatalf("len(responseList.GetListUpdateResponses()) = %d, want %d", got, want)
	}

	for i, resp := range dat.GetListUpdateResponses() {
		if resp.ThreatType != lists[i].ThreatType {
			t.Errorf("ThreatType: got: %s, want: %s", resp.ThreatType, lists[i].ThreatType)
		}
		if resp.PlatformType != lists[i].PlatformType {
			t.Errorf("PlatformType: got: %v, want: %s", resp.PlatformType, lists[i].PlatformType)
		}
		if resp.ThreatEntryType != lists[i].ThreatEntryType {
			t.Errorf("ThreatEntryType: got: %s, want: %s", resp.ThreatEntryType, lists[i].ThreatEntryType)
		}
		if resp.ResponseType.String() != "FULL_UPDATE" {
			t.Errorf("ResponseType: got: %s, want: FULL_UPDATE", resp.ResponseType)
		}
		if n := len(resp.GetRemovals()); n != 0 {
			t.Errorf("len(resp.GetRemovals(): got: %v, want: 0", n)
		}
		if n := len(resp.GetAdditions()); n == 0 {
			t.Errorf("len(resp.GetAdditions()), got: %v, want: >0", n)
		}
		if len(resp.NewClientState) == 0 {
			t.Errorf("Unexpected empty state")
		}
	}

	for _, u := range dat.GetListUpdateResponses() {
		for _, a := range u.GetAdditions() {
			hashes, err := decodeHashes(a)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < len(hashes) && i < 10; i++ {
				hash := hashes[i]
				threats := []*pb.ThreatEntry{{Hash: []byte(hash)}}
				fullHashReq := &pb.FindFullHashesRequest{
					ThreatInfo: &pb.ThreatInfo{
						PlatformTypes:    []pb.PlatformType{u.PlatformType},
						ThreatTypes:      []pb.ThreatType{u.ThreatType},
						ThreatEntryTypes: []pb.ThreatEntryType{u.ThreatEntryType},
						ThreatEntries:    threats,
					},
				}
				fullHashResp, err := nm.HashLookup(context.Background(), fullHashReq)
				if err != nil {
					t.Fatal(err)
				}
				if got := len(fullHashResp.GetMatches()); got < 1 {
					t.Fatalf("len(r.GetMatches()), got: %v, want: > 0", got)
				}
			}
		}
	}
}

func TestNetworkAPILookup(t *testing.T) {
	if *apiKeyFlag == "" {
		t.Skip()
	}

	nm, err := newNetAPI(DefaultServerURL, *apiKeyFlag, "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	var c = pb.FetchThreatListUpdatesRequest_ListUpdateRequest{
		ThreatType:      pb.ThreatType_POTENTIALLY_HARMFUL_APPLICATION,
		PlatformType:    pb.PlatformType_ANDROID,
		ThreatEntryType: pb.ThreatEntryType_URL,
	}
	url := "testsafebrowsing.appspot.com/apiv4/" + c.PlatformType.String() + "/" +
		c.ThreatType.String() + "/" + c.ThreatEntryType.String() + "/"
	hash := hashFromPattern(url)
	req := &pb.FindFullHashesRequest{
		ThreatInfo: &pb.ThreatInfo{
			ThreatTypes:      []pb.ThreatType{c.ThreatType},
			PlatformTypes:    []pb.PlatformType{c.PlatformType},
			ThreatEntryTypes: []pb.ThreatEntryType{c.ThreatEntryType},
			ThreatEntries:    []*pb.ThreatEntry{{Hash: []byte(hash[:minHashPrefixLength])}},
		},
	}
	resp, err := nm.HashLookup(context.Background(), req)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if len(resp.GetMatches()) < 1 {
		t.Fatalf("No matches returned. Resp %v. Url %v.", resp.String(), url)
	}
}

func TestSafeBrowser(t *testing.T) {
	if *apiKeyFlag == "" {
		t.Skip()
	}

	sb, err := NewSafeBrowser(Config{
		APIKey:       *apiKeyFlag,
		ID:           "GoSafeBrowserSystemTest",
		DBPath:       "/tmp/safebrowser.db",
		UpdatePeriod: 10 * time.Second,
		ThreatLists: []ThreatDescriptor{
			{ThreatType_PotentiallyHarmfulApplication, PlatformType_Android, ThreatEntryType_URL},
		},
	})

	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := sb.WaitUntilReady(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()

	var c = pb.FetchThreatListUpdatesRequest_ListUpdateRequest{
		ThreatType:      pb.ThreatType_POTENTIALLY_HARMFUL_APPLICATION,
		PlatformType:    pb.PlatformType_ANDROID,
		ThreatEntryType: pb.ThreatEntryType_URL,
	}
	url := "http://testsafebrowsing.appspot.com/apiv4/" + c.PlatformType.String() + "/" +
		c.ThreatType.String() + "/" + c.ThreatEntryType.String() + "/"

	urls := []string{url, url + "?q=test"}
	threats, e := sb.LookupURLs(urls)
	if e != nil {
		t.Fatal(e)
	}
	if len(threats[0]) != 1 || len(threats[1]) != 1 {
		t.Errorf("lookupURL failed")
	}

	if err := sb.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
	if err := sb.WaitUntilReady(ctx); err != errClosed {
		t.Errorf("sb.WaitUntilReady() = %v on closed SafeBrowser, want %v", err, errClosed)
	}
	cancel()

	for _, hs := range sb.db.tfl {
		if hs.Len() == 0 {
			t.Errorf("Database length: got %d,, want >0", hs.Len())
		}
	}
	if len(sb.c.pttls) != 1 {
		t.Errorf("Cache length: got %d, want 1", len(sb.c.pttls))
	}
}

func TestSafeBrowserBackoff(t *testing.T) {
	// Test scenario
	// 1. lookup requests get response with "minimumWaitDuration":"1s"
	// 2. Server backoff:
	//		assertion(1): FullHashWakeUpTime is set
	//		assertion(2): stats.QueriesByAPI == 1
	// 3. Sleep 1 second to let server recover from backoff
	// 4. lookup requests get non-200 response (testing with 400)
	// 5. Server backoff:
	//      assertion(1): return error with format "HashLookup failure: safebrowsing: unexpected server response code: 400, wakeuptime:"
	//		assertion(2): FullHashWakeUpTime == $(wakeuptime from error message)
	//		assertion(3): stats.QueriesByAPI == 1 (not increase)
	//		assertion(3): stats.QueriesFail == 1
	// 6. lookup requests would be skip due to backoff mode
	//      assertion(1): return error with format "HashLookup skip: backoff, wakeuptime:"
	//		assertion(2): stats.QueriesByAPI == 1 (not increase)
	//		assertion(3): stats.QueriesFail == 1 (not increase)
	//		assertion(4): stats.QueriesByAPISkip == 1

	if *apiKeyFlag == "" {
		t.Skip()
	}

	sb, err := NewSafeBrowser(Config{
		APIKey:       *apiKeyFlag,
		ID:           "GoSafeBrowserSystemTest",
		DBPath:       "/tmp/safebrowser.db",
		UpdatePeriod: 10 * time.Second,
		ThreatLists: []ThreatDescriptor{
			{ThreatType_PotentiallyHarmfulApplication, PlatformType_Android, ThreatEntryType_URL},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := sb.WaitUntilReady(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()

	var c = pb.FetchThreatListUpdatesRequest_ListUpdateRequest{
		ThreatType:      pb.ThreatType_POTENTIALLY_HARMFUL_APPLICATION,
		PlatformType:    pb.PlatformType_ANDROID,
		ThreatEntryType: pb.ThreatEntryType_URL,
	}
	url := "http://testsafebrowsing.appspot.com/apiv4/" + c.PlatformType.String() + "/" +
		c.ThreatType.String() + "/" + c.ThreatEntryType.String() + "/"

	urls := []string{url, url + "?q=test"}

	// after successfully update, change sb.api to return with 'MinimumWaitDuration'
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := &pb.FindFullHashesResponse{
			Matches:             []*pb.ThreatMatch{{ThreatType: 0, PlatformType: 1, ThreatEntryType: 2, Threat: &pb.ThreatEntry{Hash: []byte("abcd")}}},
			MinimumWaitDuration: &google_protobuf.Duration{Seconds: 1},
		}
		var p []byte
		if p, err = proto.Marshal(resp); err != nil {
			t.Fatalf("unexpected proto.Marshal error: %v", err)
		}
		if _, err := w.Write(p); err != nil {
			t.Fatalf("unexpected ResponseWriter.Write error: %v", err)
		}
		return
	}))
	defer ts.Close()
	api, err := newNetAPI(ts.URL, *apiKeyFlag, "")
	sb.api = api
	_, e := sb.LookupURLs(urls)
	if e != nil {
		t.Fatal(e)
	}
	if wakeupTime := atomic.LoadInt64(&sb.stats.FullHashWakeUpTime); wakeupTime == 0 {
		t.Errorf("stats.FullHashWakeUpTime should be set while it's not")
	}
	// QueriesByAPI should increase
	if queryAPICnt := atomic.LoadInt64(&sb.stats.QueriesByAPI); queryAPICnt != 1 {
		t.Errorf("stats.QueriesByAPISkip should be 1, get %d", queryAPICnt)
	}
	// let server wakeup from backoff mode
	time.Sleep(1 * time.Second)

	// change sb.api to force lookup requests failed
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "test error", http.StatusBadRequest)
		return
	}))
	defer ts.Close()
	api, err = newNetAPI(ts.URL, *apiKeyFlag, "")
	sb.api = api

	_, e = sb.LookupURLs(urls)
	if e == nil || !strings.HasPrefix(e.Error(), "HashLookup failure: safebrowsing: unexpected server response code: 400, wakeuptime:") {
		t.Errorf("return with unexpected error, %v", e)
	}
	// should set FullHashWakeUpTime to the wakeuptime given from error message
	expWakeupTime, err := strconv.Atoi(strings.Split(e.Error(), "wakeuptime: ")[1])
	if err != nil {
		t.Fatal(err)
	}
	if wakeupTime := atomic.LoadInt64(&sb.stats.FullHashWakeUpTime); wakeupTime != int64(expWakeupTime) {
		t.Errorf("inconsistent FullHashWakeUpTime, get: %d, expected: %d", wakeupTime, expWakeupTime)
	}
	// QueriesByAPI should not increase
	if queryAPICnt := atomic.LoadInt64(&sb.stats.QueriesByAPI); queryAPICnt != 1 {
		t.Errorf("stats.QueriesByAPISkip should be 1, get %d", queryAPICnt)
	}
	// QueriesFail should increase
	if queryFailCnt := atomic.LoadInt64(&sb.stats.QueriesFail); queryFailCnt != 1 {
		t.Errorf("stats.QueriesFail should be 1, get %d", queryFailCnt)
	}

	// server should enter into backoff mode now, when we query again,
	// it should return error starts with 'HashLookup skip: backoff'
	_, e = sb.LookupURLs(urls)
	if e == nil || !strings.HasPrefix(e.Error(), "HashLookup skip: backoff, wakeuptime:") {
		// should failed with 'HashLookup skip: backoff, wakeuptime: ...'
		t.Errorf("return with unexpected error, %v", e)
	}
	// QueriesByAPISkip should increase
	if skipCnt := atomic.LoadInt64(&sb.stats.QueriesByAPISkip); skipCnt != 1 {
		t.Errorf("stats.QueriesByAPISkip should be 1, get %d", skipCnt)
	}
	// QueriesByAPI should not increase
	if queryAPICnt := atomic.LoadInt64(&sb.stats.QueriesByAPI); queryAPICnt != 1 {
		t.Errorf("stats.QueriesByAPISkip should be 1, get %d", queryAPICnt)
	}
	// QueriesFail should not increase
	if queryFailCnt := atomic.LoadInt64(&sb.stats.QueriesFail); queryFailCnt != 1 {
		t.Errorf("stats.QueriesFail should be 1, get %d", queryFailCnt)
	}

	if err := sb.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
	if err := sb.WaitUntilReady(ctx); err != errClosed {
		t.Errorf("sb.WaitUntilReady() = %v on closed SafeBrowser, want %v", err, errClosed)
	}
	cancel()

	for _, hs := range sb.db.tfl {
		if hs.Len() == 0 {
			t.Errorf("Database length: got %d,, want >0", hs.Len())
		}
	}
	if len(sb.c.pttls) != 0 {
		t.Errorf("Cache length: got %d, want 0", len(sb.c.pttls))
	}
}
