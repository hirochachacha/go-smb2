// Package dfs defines DFS referral responses and query options.
package dfs

import (
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/dfsc"
)

const (
	HeaderServers                = dfsc.ReferralHeaderServers
	HeaderStorage                = dfsc.ReferralHeaderStorage
	HeaderFailback               = dfsc.ReferralHeaderFailback
	FlagNameList                 = dfsc.ReferralNameList
	FlagTargetSetBoundary        = dfsc.ReferralTargetBoundary
	ServerRoot            uint16 = dfsc.ReferralServerRoot
	ServerLink            uint16 = dfsc.ReferralServerLink
)

// ReferralResponse is one validated RESP_GET_DFS_REFERRAL response.
type ReferralResponse struct {
	PathConsumed uint16          // UTF-16 byte count consumed from the request path.
	HeaderFlags  uint32          // DFS referral header flags.
	Prefix       string          // Full UNC prefix matched by the response.
	Entries      []ReferralEntry // Entries in server response order.
}

// ReferralEntry describes one ordered referral target or name-list entry.
type ReferralEntry struct {
	Version          uint16
	ServerType       uint16
	Flags            uint16
	TTL              time.Duration // Time to live supplied by the server.
	DFSPath          string        // DFS path prefix from the wire response.
	DFSAlternatePath string        // Alternate DFS path from the wire response.
	NetworkAddress   string        // Target exactly as returned by the server.
	TargetPath       string        // Target with the request's unparsed suffix.
	SpecialName      string        // Name-list special name, when present.
	ExpandedNames    []string      // Name-list expanded names, in wire order.
}

// ReferralOptions configures a referral query.
type ReferralOptions struct {
	// SiteName identifies the client's Active Directory site. A nonempty value
	// requests site-aware referral ordering using REQ_GET_DFS_REFERRAL_EX.
	SiteName string
}
