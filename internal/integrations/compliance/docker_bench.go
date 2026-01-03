package compliance

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"patchmon-agent/pkg/models"

	"github.com/sirupsen/logrus"
)

const (
	dockerBinary = "docker"
	// SECURITY: Pin Docker Bench image to a specific digest to prevent supply chain attacks.
	// This image runs with highly elevated privileges (--net host, --pid host, etc.)
	// so we MUST verify the image integrity before running.
	//
	// To update this digest:
	// 1. Pull the latest image: docker pull docker/docker-bench-security:latest
	// 2. Get the digest: docker inspect docker/docker-bench-security:latest --format='{{.RepoDigests}}'
	// 3. Update the digest below
	// 4. Test thoroughly before deploying
	//
	// Current digest is for docker-bench-security as of 2024-01
	dockerBenchImageBase   = "docker/docker-bench-security"
	dockerBenchImageDigest = "sha256:ddbdf4f86af4405727e4e81f85a68eb7a934ffe9418553ef2f4c8b301f2c8d3e"
	dockerBenchImage       = dockerBenchImageBase + "@" + dockerBenchImageDigest
)

// DockerBenchScanner handles Docker Bench for Security scanning
type DockerBenchScanner struct {
	logger    *logrus.Logger
	available bool
}

// NewDockerBenchScanner creates a new Docker Bench scanner
func NewDockerBenchScanner(logger *logrus.Logger) *DockerBenchScanner {
	s := &DockerBenchScanner{
		logger: logger,
	}
	s.checkAvailability()
	return s
}

// IsAvailable returns whether Docker Bench is available
func (s *DockerBenchScanner) IsAvailable() bool {
	return s.available
}

// checkAvailability checks if Docker is available for running Docker Bench
func (s *DockerBenchScanner) checkAvailability() {
	// Check if docker binary exists
	_, err := exec.LookPath(dockerBinary)
	if err != nil {
		s.logger.Debug("Docker binary not found")
		s.available = false
		return
	}

	// Check if Docker daemon is running
	cmd := exec.Command(dockerBinary, "info")
	if err := cmd.Run(); err != nil {
		s.logger.Debug("Docker daemon not responding")
		s.available = false
		return
	}

	s.available = true
	s.logger.Debug("Docker is available for Docker Bench scanning")
}

// RunScan executes a Docker Bench for Security scan
func (s *DockerBenchScanner) RunScan(ctx context.Context) (*models.ComplianceScan, error) {
	if !s.available {
		return nil, fmt.Errorf("Docker is not available")
	}

	startTime := time.Now()

	s.logger.WithField("image", dockerBenchImage).Info("Pulling Docker Bench for Security image (pinned to digest)...")

	// SECURITY: Pull by digest to ensure we get the exact image we expect
	// This prevents supply chain attacks where the tag could be modified
	pullCmd := exec.CommandContext(ctx, dockerBinary, "pull", dockerBenchImage)
	if output, err := pullCmd.CombinedOutput(); err != nil {
		s.logger.WithError(err).WithField("output", string(output)).Warn("Failed to pull Docker Bench image, checking if existing image matches digest")

		// Verify existing image matches expected digest before proceeding
		verifyCmd := exec.CommandContext(ctx, dockerBinary, "images", "--digests", "--format", "{{.Digest}}", dockerBenchImageBase)
		digestOutput, verifyErr := verifyCmd.Output()
		if verifyErr != nil {
			return nil, fmt.Errorf("failed to verify Docker Bench image: %w", verifyErr)
		}

		existingDigest := strings.TrimSpace(string(digestOutput))
		if existingDigest != dockerBenchImageDigest {
			s.logger.WithFields(logrus.Fields{
				"expected": dockerBenchImageDigest,
				"found":    existingDigest,
			}).Error("Docker Bench image digest mismatch - refusing to run")
			return nil, fmt.Errorf("docker Bench image digest mismatch: expected %s, got %s", dockerBenchImageDigest, existingDigest)
		}
		s.logger.Info("Existing Docker Bench image digest verified")
	} else {
		s.logger.WithField("digest", dockerBenchImageDigest).Info("Docker Bench image pulled and verified by digest")
	}

	// Run Docker Bench
	// NOTE: These elevated privileges are necessary for Docker Bench to inspect host configuration.
	// The digest pinning above ensures we only run the trusted image.
	args := []string{
		"run", "--rm",
		"--net", "host",
		"--pid", "host",
		"--userns", "host",
		"--cap-add", "audit_control",
		"-v", "/etc:/etc:ro",
		"-v", "/lib/systemd/system:/lib/systemd/system:ro",
		"-v", "/usr/bin/containerd:/usr/bin/containerd:ro",
		"-v", "/usr/bin/runc:/usr/bin/runc:ro",
		"-v", "/usr/lib/systemd:/usr/lib/systemd:ro",
		"-v", "/var/lib:/var/lib:ro",
		"-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
		"--label", "docker_bench_security",
		dockerBenchImage,
	}

	s.logger.Debug("Running Docker Bench for Security...")

	cmd := exec.CommandContext(ctx, dockerBinary, args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("scan cancelled: %w", ctx.Err())
		}
		// Docker Bench may exit non-zero on failures, parse output anyway
		s.logger.WithError(err).Debug("Docker Bench exited with error, parsing output")
	}

	// Parse the output
	scan := s.parseOutput(string(output))
	scan.StartedAt = startTime
	now := time.Now()
	scan.CompletedAt = &now
	scan.Status = "completed"

	return scan, nil
}

// parseOutput parses Docker Bench output
func (s *DockerBenchScanner) parseOutput(output string) *models.ComplianceScan {
	scan := &models.ComplianceScan{
		ProfileName: "Docker Bench for Security",
		ProfileType: "docker-bench",
		Results:     make([]models.ComplianceResult, 0),
	}

	// Parse patterns
	// [PASS] 1.1.1 - Ensure a separate partition for containers has been created
	// [WARN] 1.1.2 - Ensure only trusted users are allowed to control Docker daemon
	// [INFO] 1.1.3 - Ensure auditing is configured for the Docker daemon
	// [NOTE] 4.5 - Ensure Content trust for Docker is Enabled

	patterns := map[string]*regexp.Regexp{
		"pass": regexp.MustCompile(`\[PASS\]\s+(\d+\.\d+(?:\.\d+)?)\s+-\s+(.+)`),
		"warn": regexp.MustCompile(`\[WARN\]\s+(\d+\.\d+(?:\.\d+)?)\s+-\s+(.+)`),
		"info": regexp.MustCompile(`\[INFO\]\s+(\d+\.\d+(?:\.\d+)?)\s+-\s+(.+)`),
		"note": regexp.MustCompile(`\[NOTE\]\s+(\d+\.\d+(?:\.\d+)?)\s+-\s+(.+)`),
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	currentSection := ""

	for scanner.Scan() {
		line := scanner.Text()

		// Detect section headers (e.g., "[INFO] 1 - Host Configuration")
		if strings.Contains(line, "[INFO]") && !strings.Contains(line, " - ") {
			// Section header, extract section name
			parts := strings.SplitN(line, " ", 3)
			if len(parts) >= 2 {
				currentSection = strings.TrimSpace(parts[1])
			}
			continue
		}

		// Check each pattern
		for status, pattern := range patterns {
			if matches := pattern.FindStringSubmatch(line); matches != nil {
				ruleID := matches[1]
				title := strings.TrimSpace(matches[2])

				// Map status
				resultStatus := s.mapStatus(status)

				// Update counters
				switch resultStatus {
				case "pass":
					scan.Passed++
				case "fail":
					scan.Failed++
				case "warn":
					scan.Warnings++
				case "skip":
					scan.Skipped++
				}
				scan.TotalRules++

				// Determine section from rule ID
				section := s.getSectionFromID(ruleID, currentSection)

				scan.Results = append(scan.Results, models.ComplianceResult{
					RuleID:  ruleID,
					Title:   title,
					Status:  resultStatus,
					Section: section,
				})
				break
			}
		}
	}

	// Calculate score
	if scan.TotalRules > 0 {
		applicable := scan.Passed + scan.Failed + scan.Warnings
		if applicable > 0 {
			scan.Score = float64(scan.Passed) / float64(applicable) * 100
		}
	}

	return scan
}

// mapStatus maps Docker Bench status to our status
func (s *DockerBenchScanner) mapStatus(status string) string {
	switch status {
	case "pass":
		return "pass"
	case "warn":
		return "warn"
	case "info":
		return "skip"
	case "note":
		return "skip"
	default:
		return "skip"
	}
}

// getSectionFromID extracts section name from rule ID
func (s *DockerBenchScanner) getSectionFromID(ruleID string, currentSection string) string {
	// Docker Bench sections:
	// 1 - Host Configuration
	// 2 - Docker daemon configuration
	// 3 - Docker daemon configuration files
	// 4 - Container Images and Build File
	// 5 - Container Runtime
	// 6 - Docker Security Operations
	// 7 - Docker Swarm Configuration

	sections := map[string]string{
		"1": "Host Configuration",
		"2": "Docker Daemon Configuration",
		"3": "Docker Daemon Configuration Files",
		"4": "Container Images and Build File",
		"5": "Container Runtime",
		"6": "Docker Security Operations",
		"7": "Docker Swarm Configuration",
	}

	// Get first digit of rule ID
	if len(ruleID) > 0 {
		firstDigit := string(ruleID[0])
		if section, exists := sections[firstDigit]; exists {
			return section
		}
	}

	return currentSection
}
