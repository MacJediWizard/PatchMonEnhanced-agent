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
	// Docker Bench for Security image
	// We use the latest tag for reliability - the image is from Docker's official repo
	dockerBenchImage = "docker/docker-bench-security:latest"
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

	s.logger.WithField("image", dockerBenchImage).Info("Pulling Docker Bench for Security image...")

	// Pull the latest Docker Bench image
	pullCmd := exec.CommandContext(ctx, dockerBinary, "pull", dockerBenchImage)
	if output, err := pullCmd.CombinedOutput(); err != nil {
		s.logger.WithError(err).WithField("output", string(output)).Warn("Failed to pull Docker Bench image, attempting to use existing image")

		// Check if image exists locally
		checkCmd := exec.CommandContext(ctx, dockerBinary, "images", "-q", dockerBenchImage)
		checkOutput, checkErr := checkCmd.Output()
		if checkErr != nil || strings.TrimSpace(string(checkOutput)) == "" {
			return nil, fmt.Errorf("Docker Bench image not available and pull failed: %w", err)
		}
		s.logger.Info("Using existing Docker Bench image")
	} else {
		s.logger.Info("Docker Bench image pulled successfully")
	}

	// Run Docker Bench
	// NOTE: These elevated privileges are necessary for Docker Bench to inspect host configuration.
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

// EnsureInstalled pre-pulls the Docker Bench image if Docker is available
func (s *DockerBenchScanner) EnsureInstalled() error {
	// Re-check availability
	s.checkAvailability()

	if !s.available {
		return fmt.Errorf("Docker is not available - Docker Bench requires Docker to run")
	}

	s.logger.Info("Pre-pulling Docker Bench for Security image...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pullCmd := exec.CommandContext(ctx, dockerBinary, "pull", dockerBenchImage)
	output, err := pullCmd.CombinedOutput()
	if err != nil {
		s.logger.WithError(err).WithField("output", string(output)).Warn("Failed to pull Docker Bench image")
		return fmt.Errorf("failed to pull Docker Bench image: %w", err)
	}

	s.logger.Info("Docker Bench image pulled successfully")
	return nil
}

// Cleanup removes the Docker Bench image to free up space
func (s *DockerBenchScanner) Cleanup() error {
	if !s.available {
		s.logger.Debug("Docker not available, nothing to clean up")
		return nil
	}

	s.logger.Info("Removing Docker Bench for Security image...")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Remove the image
	removeCmd := exec.CommandContext(ctx, dockerBinary, "rmi", dockerBenchImage)
	output, err := removeCmd.CombinedOutput()
	if err != nil {
		// Image might not exist, which is fine
		if strings.Contains(string(output), "No such image") {
			s.logger.Debug("Docker Bench image already removed")
			return nil
		}
		s.logger.WithError(err).WithField("output", string(output)).Warn("Failed to remove Docker Bench image")
		return fmt.Errorf("failed to remove Docker Bench image: %w", err)
	}

	s.logger.Info("Docker Bench image removed successfully")
	return nil
}
