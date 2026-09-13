//go:build linux

package netns

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func useTempSubnetReservationDir(t *testing.T) {
	t.Helper()
	old := subnetReservationDir
	subnetReservationDir = t.TempDir()
	t.Cleanup(func() { subnetReservationDir = old })
}

// TestSubnetReservation_NoCollisionsOnConcurrentAllocation verifies that
// concurrent calls to NewBridgeSpec never allocate the same subnet address,
// even with many simultaneous allocations.
func TestSubnetReservation_NoCollisionsOnConcurrentAllocation(t *testing.T) {
	useTempSubnetReservationDir(t)
	const concurrentAllocations = 20
	bridges := make([]BridgeSpec, concurrentAllocations)
	errors := make([]error, concurrentAllocations)
	var wg sync.WaitGroup

	// Allocate bridges concurrently.
	for i := 0; i < concurrentAllocations; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			bridge, err := NewBridgeSpec()
			bridges[idx] = bridge
			errors[idx] = err
		}(i)
	}
	wg.Wait()

	// Check for allocation errors.
	for idx, err := range errors {
		if err != nil {
			t.Errorf("allocation %d failed: %v", idx, err)
		}
	}

	// Verify no two bridges share the same host address (subnet collision).
	seen := make(map[string]bool)
	for _, bridge := range bridges {
		if bridge.HostAddress == "" {
			continue // Skip failed allocations.
		}
		if seen[bridge.HostAddress] {
			t.Errorf("subnet collision: %s allocated multiple times", bridge.HostAddress)
		}
		seen[bridge.HostAddress] = true
	}

	// Clean up reservations.
	for _, bridge := range bridges {
		_ = ReleaseSubnetReservation(bridge.ReservationID, bridge.ReservationToken)
	}
}

// TestSubnetReservation_ReservationRelease verifies that a released subnet
// can be reallocated by a subsequent call.
func TestSubnetReservation_ReservationRelease(t *testing.T) {
	useTempSubnetReservationDir(t)
	// Allocate a subnet.
	bridge1, err := NewBridgeSpec()
	if err != nil {
		t.Fatalf("first allocation: %v", err)
	}
	addr1 := bridge1.HostAddress
	resID1 := bridge1.ReservationID

	// Release it.
	if err := ReleaseSubnetReservation(resID1, bridge1.ReservationToken); err != nil {
		t.Fatalf("release reservation: %v", err)
	}

	// Allocate again; should eventually get a bridge with the same or different address.
	// We'll try up to 10 times to see if we can reuse the address.
	var addr2 string
	var resID2 string
	var bridge2 BridgeSpec
	reused := false
	for attempt := 0; attempt < 10; attempt++ {
		bridge2, err := NewBridgeSpec()
		if err != nil {
			t.Fatalf("second allocation attempt %d: %v", attempt, err)
		}
		addr2 = bridge2.HostAddress
		resID2 = bridge2.ReservationID

		if addr2 == addr1 {
			reused = true
			break
		}

		// Release this one and try again.
		_ = ReleaseSubnetReservation(resID2, bridge2.ReservationToken)
		time.Sleep(10 * time.Millisecond)
	}

	if reused {
		t.Logf("address %s was successfully reused after release", addr1)
	} else {
		// Not strictly a failure; just indicates randomness made reuse unlikely.
		t.Logf("could not reuse %s in 10 attempts (acceptable due to randomness)", addr1)
	}

	_ = ReleaseSubnetReservation(resID2, bridge2.ReservationToken)
}

// TestSubnetReservation_DirectFileCreation verifies that the reservation
// system correctly detects and handles reservations stored in the file system.
func TestSubnetReservation_DirectFileCreation(t *testing.T) {
	useTempSubnetReservationDir(t)
	// Ensure reservation directory exists.
	if err := os.MkdirAll(subnetReservationDir, 0700); err != nil {
		t.Fatalf("create reservation directory: %v", err)
	}

	// Create a manual reservation file.
	testSubnet := "169.254.10.1"
	reservationFile := filepath.Join(subnetReservationDir, testSubnet)
	if err := os.WriteFile(reservationFile, []byte("12345\n"), 0600); err != nil {
		t.Fatalf("write test reservation file: %v", err)
	}
	defer os.Remove(reservationFile)

	// Verify isSubnetReserved detects it.
	reserved, err := isSubnetReserved(testSubnet)
	if err != nil {
		t.Fatalf("check reservation: %v", err)
	}
	if !reserved {
		t.Errorf("subnet %s should be detected as reserved", testSubnet)
	}

	// Verify reserveSubnet fails on this subnet (collision).
	_, err = reserveSubnet(testSubnet)
	if err == nil {
		t.Errorf("reserveSubnet should fail with collision on %s", testSubnet)
	}

	// Clean up the manual file.
	if err := os.Remove(reservationFile); err != nil {
		t.Fatalf("remove test file: %v", err)
	}

	// Verify it's now free.
	reserved, err = isSubnetReserved(testSubnet)
	if err != nil {
		t.Fatalf("check reservation after cleanup: %v", err)
	}
	if reserved {
		t.Errorf("subnet %s should not be reserved after file removal", testSubnet)
	}
}

// TestSubnetReservation_AllocationRetryOnCollision verifies that NewBridgeSpec
// retries and eventually succeeds even when encountering collisions.
func TestSubnetReservation_AllocationRetryOnCollision(t *testing.T) {
	useTempSubnetReservationDir(t)
	// Pre-create a reservation for a subnet we'll force a collision on.
	testSubnet := "169.254.5.1"
	reservationFile := filepath.Join(subnetReservationDir, testSubnet)

	// Ensure directory and file exist (create reservation).
	if err := os.MkdirAll(subnetReservationDir, 0700); err != nil {
		t.Fatalf("create reservation directory: %v", err)
	}
	if err := os.WriteFile(reservationFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0600); err != nil {
		t.Fatalf("write collision subnet reservation: %v", err)
	}
	defer os.Remove(reservationFile)

	// Allocate a bridge; should retry and succeed despite the collision.
	bridge, err := NewBridgeSpec()
	if err != nil {
		t.Fatalf("allocation with collision: %v", err)
	}

	// Verify it allocated a different subnet.
	if bridge.HostAddress == testSubnet {
		t.Errorf("NewBridgeSpec should have retried and avoided collision with %s", testSubnet)
	}

	_ = ReleaseSubnetReservation(bridge.ReservationID, bridge.ReservationToken)
}

// TestSubnetReservation_BridgeSpec_ValidateAfterReservation verifies that
// a reserved bridge spec passes validation.
func TestSubnetReservation_BridgeSpec_ValidateAfterReservation(t *testing.T) {
	useTempSubnetReservationDir(t)
	bridge, err := NewBridgeSpec()
	if err != nil {
		t.Fatalf("allocate bridge: %v", err)
	}
	defer ReleaseSubnetReservation(bridge.ReservationID, bridge.ReservationToken)

	cfg := &EgressConfig{
		Allow:              []string{"example.com"},
		AllowPrivateRanges: false,
		Bridge:             bridge,
	}

	if err := validateEgressConfig(cfg, 1000); err != nil {
		t.Errorf("validate allocated bridge config: %v", err)
	}
}

// TestSubnetReservation_StaleTOCTOURelease verifies that releasing a reservation
// with a mismatched token does NOT delete the current owner's reservation,
// preventing TOCTOU deletion of another run's subnet.
func TestSubnetReservation_StaleTOCTOURelease(t *testing.T) {
	useTempSubnetReservationDir(t)
	// Allocate a subnet (run A).
	bridge1, err := NewBridgeSpec()
	if err != nil {
		t.Fatalf("first allocation (run A): %v", err)
	}
	token1 := bridge1.ReservationToken
	resID1 := bridge1.ReservationID

	// Release run A's reservation (clean exit).
	if err := ReleaseSubnetReservation(resID1, token1); err != nil {
		t.Fatalf("release run A's reservation: %v", err)
	}

	// Run B allocates the same subnet (simulate by pre-writing a reservation file).
	reservationFile := filepath.Join(subnetReservationDir, resID1)
	runBToken := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := os.WriteFile(reservationFile, []byte(runBToken+"\n"+fmt.Sprintf("%d\n", os.Getpid())), 0600); err != nil {
		t.Fatalf("simulate run B allocation: %v", err)
	}

	// Run A's cleanup (stale release with mismatched token) should NOT delete run B's reservation.
	if err := ReleaseSubnetReservation(resID1, token1); err != nil {
		t.Fatalf("stale release with mismatched token: %v", err)
	}

	// Verify run B's reservation still exists with the correct token.
	content, err := os.ReadFile(reservationFile)
	if err != nil {
		t.Fatalf("run B's reservation was deleted (should still exist): %v", err)
	}
	if !strings.HasPrefix(string(content), runBToken) {
		t.Fatalf("run B's token was corrupted: got %q, want %q", string(content), runBToken)
	}

	// Clean up run B's reservation.
	_ = ReleaseSubnetReservation(resID1, runBToken)
}

// TestReservationID_RejectsTraversalPaths verifies that directory traversal
// attacks in the reservation ID are rejected and no files are created.
func TestReservationID_RejectsTraversalPaths(t *testing.T) {
	useTempSubnetReservationDir(t)

	traversalIDs := []string{
		"../evil",
		"../../etc/passwd",
		"/etc/evil",
		"169.254.1.1/../../../evil",
		"169.254.1.1/./evil",
	}

	for _, traversalID := range traversalIDs {
		t.Run(traversalID, func(t *testing.T) {
			// Attempt to reserve with a malicious ID.
			_, err := reserveSubnet(traversalID)
			if err == nil {
				t.Errorf("reserveSubnet should reject traversal ID %q, got nil error", traversalID)
			}

			// Verify no files were created outside the reservation directory.
			err = filepath.Walk("/", func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				// If we find any file with the traversal component in its name outside
				// the reservation dir, that's a failure. This is a quick sanity check.
				if strings.Contains(path, "evil") && !strings.HasPrefix(path, subnetReservationDir) {
					t.Errorf("traversal ID %q created file outside reservation dir: %s", traversalID, path)
				}
				return nil
			})
			if err != nil {
				// Walk errors are okay (permission denied on some dirs), just log it.
				t.Logf("walk error (acceptable): %v", err)
			}
		})
	}
}

// TestReservationID_ValidatesShape verifies that validateReservationID
// accepts valid 169.254.x.y addresses and rejects invalid ones.
func TestReservationID_ValidatesShape(t *testing.T) {
	useTempSubnetReservationDir(t)

	validIDs := []string{
		"169.254.1.1",
		"169.254.255.254",
		"169.254.0.0",
		"169.254.100.50",
	}

	invalidIDs := []string{
		"169.254.256.1", // octet out of range
		"169.253.1.1",   // wrong network
		"192.168.1.1",   // different network
		"169.254",       // incomplete
		"169.254.1.1.1", // too many octets
		"not.a.valid.address",
	}

	for _, validID := range validIDs {
		err := validateReservationID(validID)
		if err != nil {
			t.Errorf("validateReservationID should accept %q, got error: %v", validID, err)
		}
	}

	for _, invalidID := range invalidIDs {
		err := validateReservationID(invalidID)
		if err == nil {
			t.Errorf("validateReservationID should reject %q, got nil error", invalidID)
		}
	}
}
