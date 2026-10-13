//go:build linux

package netns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func useTempSubnetReservationDir(t *testing.T) {
	t.Helper()
	old := subnetReservationDir
	subnetReservationDir = t.TempDir()
	t.Cleanup(func() { subnetReservationDir = old })
}

// TestSubnetReservation_NoCollisionsOnConcurrentAllocation verifies that exactly one contender
// can claim a subnet. NewBridgeSpec only makes candidates; the privileged
// helper claims them and retries on SubnetCollisionError.
func TestSubnetReservation_NoCollisionsOnConcurrentAllocation(t *testing.T) {
	useTempSubnetReservationDir(t)
	const concurrentAllocations = 20
	const subnet = "169.254.65.29"
	tokens := make([]string, concurrentAllocations)
	claimErrors := make([]error, concurrentAllocations)
	var wg sync.WaitGroup

	for i := 0; i < concurrentAllocations; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			token, err := reserveSubnet(subnet)
			tokens[idx] = token
			claimErrors[idx] = err
		}(i)
	}
	wg.Wait()

	winners := 0
	for idx, err := range claimErrors {
		if err == nil {
			winners++
			if tokens[idx] == "" {
				t.Errorf("claim %d returned an empty ownership token", idx)
			}
			continue
		}
		var collision *SubnetCollisionError
		if !errors.As(err, &collision) {
			t.Errorf("claim %d: expected subnet collision, got %v", idx, err)
		}
	}
	if winners != 1 {
		t.Errorf("subnet %s had %d successful claims, want one", subnet, winners)
	}

	for _, token := range tokens {
		if token != "" {
			if err := ReleaseSubnetReservation(subnet, token); err != nil {
				t.Errorf("release winning claim: %v", err)
			}
		}
	}
}

// TestSubnetReservation_CrossProcessClaim verifies that only one process wins
// when both try to claim the same subnet at the same time.
func TestSubnetReservation_CrossProcessClaim(t *testing.T) {
	const subnet = "169.254.65.29"
	if dir := os.Getenv("NOCKLOCK_TEST_SUBNET_RESERVATION_DIR"); dir != "" {
		subnetReservationDir = dir
		var stat syscall.Stat_t
		if err := syscall.Fstat(3, &stat); err != nil {
			t.Fatalf("inspect claim gate fd 3: %v", err)
		}
		if stat.Mode&syscall.S_IFMT != syscall.S_IFIFO {
			t.Fatalf("claim gate fd 3 is not a pipe (mode %#o)", stat.Mode&syscall.S_IFMT)
		}
		gate := os.NewFile(3, "claim gate")
		defer gate.Close()
		var signal [1]byte
		if _, err := gate.Read(signal[:]); err != nil {
			t.Fatalf("wait for claim gate: %v", err)
		}
		token, err := reserveSubnet(subnet)
		if err == nil {
			fmt.Printf("CLAIMED:%s\n", token)
			return
		}
		var collision *SubnetCollisionError
		if !errors.As(err, &collision) {
			t.Fatalf("claim from second process: got %v, want subnet collision", err)
		}
		fmt.Println("COLLISION")
		return
	}

	useTempSubnetReservationDir(t)
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("create claim gate: %v", err)
	}
	defer gateRead.Close()
	defer gateWrite.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("find test executable: %v", err)
	}
	var commands [2]*exec.Cmd
	var outputs [2]bytes.Buffer
	var waited [2]bool
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		cancel()
		for i, cmd := range commands {
			if cmd == nil || waited[i] {
				continue
			}
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			if err := cmd.Wait(); err != nil {
				t.Logf("reap claimant %d: %v", i, err)
			}
		}
	}()
	for i := range commands {
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestSubnetReservation_CrossProcessClaim$")
		cmd.Env = append(os.Environ(), "NOCKLOCK_TEST_SUBNET_RESERVATION_DIR="+subnetReservationDir)
		cmd.ExtraFiles = []*os.File{gateRead}
		cmd.Stdout = &outputs[i]
		cmd.Stderr = &outputs[i]
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		cmd.WaitDelay = time.Second
		if err := cmd.Start(); err != nil {
			t.Fatalf("start claimant %d: %v", i, err)
		}
		commands[i] = cmd
	}
	if _, err := gateWrite.Write([]byte{1, 1}); err != nil {
		t.Fatalf("release claim gate: %v", err)
	}
	if err := gateWrite.Close(); err != nil {
		t.Fatalf("close claim gate: %v", err)
	}
	winners := 0
	var winningTokens []string
	for i, cmd := range commands {
		err := cmd.Wait()
		waited[i] = true
		if err != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			t.Errorf("claimant %d failed (deadline: %v): %v\n%s", i, ctx.Err(), err, outputs[i].String())
			continue
		}
		output := outputs[i].String()
		if _, token, ok := strings.Cut(output, "CLAIMED:"); ok {
			winners++
			token, _, _ = strings.Cut(token, "\n")
			winningTokens = append(winningTokens, token)
		} else if !strings.Contains(output, "COLLISION\n") {
			t.Errorf("claimant %d returned no claim result:\n%s", i, output)
		}
	}
	if winners != 1 {
		t.Errorf("subnet %s had %d successful cross-process claims, want one", subnet, winners)
	}
	for _, token := range winningTokens {
		if err := ReleaseSubnetReservation(subnet, token); err != nil {
			t.Errorf("release winning claim: %v", err)
		}
	}
}

// TestSubnetReservation_ReservationRelease verifies that a released subnet
// can be claimed again.
func TestSubnetReservation_ReservationRelease(t *testing.T) {
	useTempSubnetReservationDir(t)
	const subnet = "169.254.65.29"
	token1, err := reserveSubnet(subnet)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := ReleaseSubnetReservation(subnet, token1); err != nil {
		t.Fatalf("release reservation: %v", err)
	}
	token2, err := reserveSubnet(subnet)
	if err != nil {
		t.Fatalf("claim after release: %v", err)
	}
	if err := ReleaseSubnetReservation(subnet, token2); err != nil {
		t.Fatalf("release second claim: %v", err)
	}
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
	var collision *SubnetCollisionError
	if !errors.As(err, &collision) {
		t.Errorf("reserveSubnet(%s): got %v, want subnet collision", testSubnet, err)
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

// TestSubnetReservation_BridgeCandidateDoesNotClaim verifies that NewBridgeSpec
// returns a candidate without creating its reservation file.
func TestSubnetReservation_BridgeCandidateDoesNotClaim(t *testing.T) {
	useTempSubnetReservationDir(t)
	bridge, err := NewBridgeSpec()
	if err != nil {
		t.Fatalf("generate bridge candidate: %v", err)
	}
	if bridge.ReservationToken != "" {
		t.Errorf("candidate unexpectedly has reservation token %q", bridge.ReservationToken)
	}
	if _, err := os.Stat(filepath.Join(subnetReservationDir, bridge.ReservationID)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("candidate created a reservation file: %v", err)
	}
}

// TestSubnetReservation_BridgeSpec_ValidateCandidate verifies that a bridge
// candidate passes configuration validation without claiming a subnet.
func TestSubnetReservation_BridgeSpec_ValidateCandidate(t *testing.T) {
	useTempSubnetReservationDir(t)
	bridge, err := NewBridgeSpec()
	if err != nil {
		t.Fatalf("generate bridge candidate: %v", err)
	}

	cfg := &EgressConfig{
		Allow:              []string{"example.com"},
		AllowPrivateRanges: false,
		Bridge:             bridge,
	}

	if err := validateEgressConfig(cfg, 1000); err != nil {
		t.Errorf("validate bridge candidate config: %v", err)
	}
}

// TestSubnetReservation_StaleTOCTOURelease verifies that releasing a reservation
// with a mismatched token does NOT delete the current owner's reservation,
// preventing TOCTOU deletion of another run's subnet.
func TestSubnetReservation_StaleTOCTOURelease(t *testing.T) {
	useTempSubnetReservationDir(t)
	const resID1 = "169.254.65.29"
	// Claim a subnet (run A).
	token1, err := reserveSubnet(resID1)
	if err != nil {
		t.Fatalf("first claim (run A): %v", err)
	}

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
