// SPDX-License-Identifier: Apache-2.0
package localpep

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// signedEnvelope mirrors LocalForbidSource.signed_response: an HMAC-SHA256 (hex)
// over the literal set_canonical string. We verify the exact bytes received — no
// re-serialization — so there is no cross-language canonicalization mismatch.
type signedEnvelope struct {
	SetCanonical string `json:"set_canonical"`
	Sig          string `json:"sig"`
}

// ForbidSet is the inner, verified local-forbid set from the live PDP.
type ForbidSet struct {
	Forbid []struct {
		AgentID string `json:"agent_id"`
		Path    string `json:"path"`
	} `json:"forbid"`
	Epoch  int    `json:"epoch"`
	Tenant string `json:"tenant"`
}

// VerifyFeed checks the HMAC over the canonical string with the shared secret and
// returns the parsed set, or an error (fail-closed) on any signature/parse fault.
// This is the cryptographic verification AT the enforcement point: a compromised
// agent cannot forge a set or strip an entry without TEX_LOCAL_PEP_SECRET.
func VerifyFeed(envBytes, secret []byte) (*ForbidSet, error) {
	var env signedEnvelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		return nil, fmt.Errorf("feed: bad envelope json: %w", err)
	}
	if env.SetCanonical == "" || env.Sig == "" {
		return nil, fmt.Errorf("feed: missing set_canonical/sig")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(env.SetCanonical))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(env.Sig)) {
		return nil, fmt.Errorf("feed: HMAC verify FAILED (fail-closed)")
	}
	var set ForbidSet
	if err := json.Unmarshal([]byte(env.SetCanonical), &set); err != nil {
		return nil, fmt.Errorf("feed: bad set json: %w", err)
	}
	return &set, nil
}

// fetchFeed reads the signed envelope from an http(s) URL or a local file path.
// apiKey (when non-empty) is presented as the PDP's x-tex-api-key so the loader
// authenticates to /v1/govern/local-forbid-set (which requires decision:read).
// Note: the feed's authenticity does NOT rest on transport auth — it is HMAC
// verified independently (VerifyFeed); the key only satisfies the route's scope.
func fetchFeed(source, apiKey string) ([]byte, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		req, err := http.NewRequest(http.MethodGet, source, nil) //nolint:gosec — operator-controlled source
		if err != nil {
			return nil, err
		}
		if apiKey != "" {
			req.Header.Set("x-tex-api-key", apiKey)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("feed: GET %s -> %d", source, resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	}
	return os.ReadFile(source)
}

// ApplyFeed warms the in-kernel deny map from a verified set. For each entry it
// enrolls the agent's cgroup (from the agent->cgroup map the fleet host owns) and
// resolves the path to its inode, then forbids (cgroup_id, inode). Resolution of
// a non-existent path or unknown agent is skipped (logged via the returned
// counts), never fatal — revoke-wins: this only ADDS denies, never removes them
// on a transient miss.
func (l *Loader) ApplyFeed(set *ForbidSet, agentCgroup map[string]string) (applied, skipped int, err error) {
	enrolled := map[string]uint64{}
	for _, e := range set.Forbid {
		cgPath, ok := agentCgroup[e.AgentID]
		if !ok {
			skipped++
			continue
		}
		cgID, ok2 := enrolled[e.AgentID]
		if !ok2 {
			cgID, err = l.Enroll(cgPath)
			if err != nil {
				return applied, skipped, fmt.Errorf("enroll %s (%s): %w", e.AgentID, cgPath, err)
			}
			enrolled[e.AgentID] = cgID
		}
		ino, ierr := InodeOf(e.Path)
		if ierr != nil {
			skipped++ // path not present on this host (yet) — never un-block
			continue
		}
		if ferr := l.Forbid(cgID, ino); ferr != nil {
			return applied, skipped, fmt.Errorf("forbid %s: %w", e.Path, ferr)
		}
		applied++
	}
	return applied, skipped, nil
}

// PollFeed fetches+verifies+applies the feed once, returning the verified epoch.
// Used both for a single application and inside a poll loop. lastEpoch guards
// against stale/replayed sets (epoch < last is ignored — cheap anti-rollback).
func (l *Loader) PollFeed(source string, secret []byte, agentCgroup map[string]string, lastEpoch int, apiKey string) (epoch, applied, skipped int, err error) {
	raw, err := fetchFeed(source, apiKey)
	if err != nil {
		return lastEpoch, 0, 0, err
	}
	set, err := VerifyFeed(raw, secret)
	if err != nil {
		return lastEpoch, 0, 0, err
	}
	if set.Epoch < lastEpoch {
		return lastEpoch, 0, 0, fmt.Errorf("feed: stale epoch %d < %d (anti-rollback)", set.Epoch, lastEpoch)
	}
	applied, skipped, err = l.ApplyFeed(set, agentCgroup)
	return set.Epoch, applied, skipped, err
}

// pollInterval is the production refresh cadence (overridable).
var pollInterval = 5 * time.Second
