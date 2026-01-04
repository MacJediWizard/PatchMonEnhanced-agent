package compliance

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"patchmon-agent/pkg/models"

	"github.com/sirupsen/logrus"
)

const (
	oscapBinary        = "oscap"
	scapContentDir     = "/usr/share/xml/scap/ssg/content"
	osReleasePath      = "/etc/os-release"
)

// Profile mappings for different OS families
var profileMappings = map[string]map[string]string{
	"level1_server": {
		"ubuntu":  "xccdf_org.ssgproject.content_profile_cis_level1_server",
		"debian":  "xccdf_org.ssgproject.content_profile_cis_level1_server",
		"rhel":    "xccdf_org.ssgproject.content_profile_cis",
		"centos":  "xccdf_org.ssgproject.content_profile_cis",
		"rocky":   "xccdf_org.ssgproject.content_profile_cis",
		"alma":    "xccdf_org.ssgproject.content_profile_cis",
		"fedora":  "xccdf_org.ssgproject.content_profile_cis",
		"sles":    "xccdf_org.ssgproject.content_profile_cis",
		"opensuse":"xccdf_org.ssgproject.content_profile_cis",
	},
	"level2_server": {
		"ubuntu":  "xccdf_org.ssgproject.content_profile_cis_level2_server",
		"debian":  "xccdf_org.ssgproject.content_profile_cis_level2_server",
		"rhel":    "xccdf_org.ssgproject.content_profile_cis_server_l1",
		"centos":  "xccdf_org.ssgproject.content_profile_cis_server_l1",
		"rocky":   "xccdf_org.ssgproject.content_profile_cis_server_l1",
		"alma":    "xccdf_org.ssgproject.content_profile_cis_server_l1",
	},
}

// OpenSCAPScanner handles OpenSCAP compliance scanning
type OpenSCAPScanner struct {
	logger    *logrus.Logger
	osInfo    models.ComplianceOSInfo
	available bool
	version   string
}

// NewOpenSCAPScanner creates a new OpenSCAP scanner
func NewOpenSCAPScanner(logger *logrus.Logger) *OpenSCAPScanner {
	s := &OpenSCAPScanner{
		logger: logger,
	}
	s.osInfo = s.detectOS()
	s.checkAvailability()
	return s
}

// IsAvailable returns whether OpenSCAP is available
func (s *OpenSCAPScanner) IsAvailable() bool {
	return s.available
}

// GetVersion returns the OpenSCAP version
func (s *OpenSCAPScanner) GetVersion() string {
	return s.version
}

// GetOSInfo returns detected OS information
func (s *OpenSCAPScanner) GetOSInfo() models.ComplianceOSInfo {
	return s.osInfo
}

// GetContentFile returns the path to the content file being used
func (s *OpenSCAPScanner) GetContentFilePath() string {
	return s.getContentFile()
}

// GetContentPackageVersion returns the ssg-base package version
func (s *OpenSCAPScanner) GetContentPackageVersion() string {
	var cmd *exec.Cmd

	switch s.osInfo.Family {
	case "debian":
		cmd = exec.Command("dpkg-query", "-W", "-f=${Version}", "ssg-base")
	case "rhel":
		cmd = exec.Command("rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", "scap-security-guide")
	case "suse":
		cmd = exec.Command("rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", "scap-security-guide")
	default:
		return ""
	}

	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// GetScannerDetails returns comprehensive scanner information
func (s *OpenSCAPScanner) GetScannerDetails() *models.ComplianceScannerDetails {
	contentFile := s.getContentFile()
	contentVersion := s.GetContentPackageVersion()

	// Check for content mismatch
	contentMismatch := false
	mismatchWarning := ""
	if contentFile != "" && s.osInfo.Version != "" {
		osVersion := strings.ReplaceAll(s.osInfo.Version, ".", "")
		baseName := filepath.Base(contentFile)
		if !strings.Contains(baseName, osVersion) {
			contentMismatch = true
			mismatchWarning = fmt.Sprintf("Content file %s may not match OS version %s. Consider upgrading ssg-base package.", baseName, s.osInfo.Version)
		}
	}

	// Build available profiles list
	profiles := []models.ScanProfileInfo{
		{
			ID:          "level1_server",
			Name:        "CIS Level 1 Server",
			Description: "Basic security hardening for servers",
			Type:        "openscap",
		},
		{
			ID:          "level2_server",
			Name:        "CIS Level 2 Server",
			Description: "Extended security hardening (more restrictive)",
			Type:        "openscap",
		},
	}

	return &models.ComplianceScannerDetails{
		OpenSCAPVersion:   s.version,
		OpenSCAPAvailable: s.available,
		ContentFile:       filepath.Base(contentFile),
		ContentPackage:    fmt.Sprintf("ssg-base %s", contentVersion),
		AvailableProfiles: profiles,
		OSName:            s.osInfo.Name,
		OSVersion:         s.osInfo.Version,
		OSFamily:          s.osInfo.Family,
		ContentMismatch:   contentMismatch,
		MismatchWarning:   mismatchWarning,
	}
}

// EnsureInstalled installs OpenSCAP and SCAP content if not present
// Also upgrades existing packages to ensure latest content is available
func (s *OpenSCAPScanner) EnsureInstalled() error {
	s.logger.Info("Ensuring OpenSCAP is installed with latest SCAP content...")

	// Create context with timeout for package operations
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Environment for non-interactive apt operations
	nonInteractiveEnv := append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"NEEDRESTART_MODE=a",
		"NEEDRESTART_SUSPEND=1",
	)

	switch s.osInfo.Family {
	case "debian":
		// Ubuntu/Debian - always update and upgrade to get latest content
		s.logger.Info("Installing/upgrading OpenSCAP on Debian-based system...")

		// Update package cache first (with timeout)
		updateCmd := exec.CommandContext(ctx, "apt-get", "update", "-qq")
		updateCmd.Env = nonInteractiveEnv
		updateCmd.Run() // Ignore errors on update

		// Install or upgrade packages (install -y will upgrade if already installed)
		installCmd := exec.CommandContext(ctx, "apt-get", "install", "-y", "-qq",
			"-o", "Dpkg::Options::=--force-confdef",
			"-o", "Dpkg::Options::=--force-confold",
			"openscap-scanner", "ssg-debderived", "ssg-base")
		installCmd.Env = nonInteractiveEnv
		output, err := installCmd.CombinedOutput()
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				s.logger.Warn("OpenSCAP installation timed out after 5 minutes")
				return fmt.Errorf("installation timed out after 5 minutes")
			}
			s.logger.WithError(err).WithField("output", string(output)).Warn("Failed to install OpenSCAP")
			return fmt.Errorf("failed to install OpenSCAP: %w\nOutput: %s", err, string(output))
		}

		// Explicitly upgrade to ensure we have the latest SCAP content
		// This is important for Ubuntu 24.04 which needs ssg-base >= 0.1.76
		upgradeCmd := exec.CommandContext(ctx, "apt-get", "upgrade", "-y", "-qq",
			"-o", "Dpkg::Options::=--force-confdef",
			"-o", "Dpkg::Options::=--force-confold",
			"ssg-base", "ssg-debderived")
		upgradeCmd.Env = nonInteractiveEnv
		upgradeOutput, upgradeErr := upgradeCmd.CombinedOutput()
		if upgradeErr != nil {
			s.logger.WithField("output", string(upgradeOutput)).Debug("Package upgrade returned non-zero (may already be latest)")
		} else {
			s.logger.Info("SCAP content packages upgraded to latest version")
		}

	case "rhel":
		// RHEL/CentOS/Rocky/Alma/Fedora
		s.logger.Info("Installing/upgrading OpenSCAP on RHEL-based system...")
		var installCmd *exec.Cmd
		if _, err := exec.LookPath("dnf"); err == nil {
			installCmd = exec.CommandContext(ctx, "dnf", "install", "-y", "-q", "openscap-scanner", "scap-security-guide")
		} else {
			installCmd = exec.CommandContext(ctx, "yum", "install", "-y", "-q", "openscap-scanner", "scap-security-guide")
		}
		output, err := installCmd.CombinedOutput()
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				s.logger.Warn("OpenSCAP installation timed out after 5 minutes")
				return fmt.Errorf("installation timed out after 5 minutes")
			}
			s.logger.WithError(err).WithField("output", string(output)).Warn("Failed to install OpenSCAP")
			return fmt.Errorf("failed to install OpenSCAP: %w\nOutput: %s", err, string(output))
		}

	case "suse":
		// SLES/openSUSE
		s.logger.Info("Installing/upgrading OpenSCAP on SUSE-based system...")
		installCmd := exec.CommandContext(ctx, "zypper", "--non-interactive", "install", "openscap-utils", "scap-security-guide")
		output, err := installCmd.CombinedOutput()
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				s.logger.Warn("OpenSCAP installation timed out after 5 minutes")
				return fmt.Errorf("installation timed out after 5 minutes")
			}
			s.logger.WithError(err).WithField("output", string(output)).Warn("Failed to install OpenSCAP")
			return fmt.Errorf("failed to install OpenSCAP: %w\nOutput: %s", err, string(output))
		}

	default:
		return fmt.Errorf("unsupported OS family: %s (OS: %s)", s.osInfo.Family, s.osInfo.Name)
	}

	s.logger.Info("OpenSCAP installed/upgraded successfully")

	// Re-check availability after installation
	s.checkAvailability()
	if !s.available {
		return fmt.Errorf("OpenSCAP installed but still not available - content files may be missing")
	}

	// Check for content version mismatch
	s.checkContentCompatibility()

	return nil
}

// checkContentCompatibility checks if the SCAP content is compatible with the OS version
func (s *OpenSCAPScanner) checkContentCompatibility() {
	contentFile := s.getContentFile()
	if contentFile == "" {
		s.logger.Warn("No SCAP content file found - compliance scans will not work correctly")
		return
	}

	// Extract version from content file name (e.g., ssg-ubuntu2204-ds.xml -> 22.04)
	baseName := filepath.Base(contentFile)

	// Log detected content file
	s.logger.WithFields(logrus.Fields{
		"os_name":      s.osInfo.Name,
		"os_version":   s.osInfo.Version,
		"content_file": baseName,
	}).Debug("Checking SCAP content compatibility")

	// Check if content file matches OS version
	osVersion := strings.ReplaceAll(s.osInfo.Version, ".", "")
	expectedPattern := fmt.Sprintf("ssg-%s%s", s.osInfo.Name, osVersion)

	if !strings.Contains(baseName, osVersion) && !strings.HasPrefix(baseName, expectedPattern) {
		s.logger.WithFields(logrus.Fields{
			"os_version":   s.osInfo.Version,
			"content_file": baseName,
		}).Warn("SCAP content may not match OS version - scan results may show many 'notapplicable' rules. Consider updating ssg-base package.")
	}
}

// checkAvailability checks if OpenSCAP is installed and has content
func (s *OpenSCAPScanner) checkAvailability() {
	// Check if oscap binary exists
	path, err := exec.LookPath(oscapBinary)
	if err != nil {
		s.logger.Debug("OpenSCAP binary not found")
		s.available = false
		return
	}
	s.logger.WithField("path", path).Debug("Found OpenSCAP binary")

	// Get version
	cmd := exec.Command(oscapBinary, "--version")
	output, err := cmd.Output()
	if err != nil {
		s.logger.WithError(err).Debug("Failed to get OpenSCAP version")
		s.available = false
		return
	}

	// Parse version from output
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		s.version = strings.TrimSpace(lines[0])
	}

	// Check if SCAP content exists
	contentFile := s.getContentFile()
	if contentFile == "" {
		s.logger.Debug("No SCAP content files found")
		s.available = false
		return
	}

	s.available = true
	s.logger.WithFields(logrus.Fields{
		"version": s.version,
		"content": contentFile,
	}).Debug("OpenSCAP is available")
}

// detectOS detects the operating system
func (s *OpenSCAPScanner) detectOS() models.ComplianceOSInfo {
	info := models.ComplianceOSInfo{}

	file, err := os.Open(osReleasePath)
	if err != nil {
		s.logger.WithError(err).Debug("Failed to open os-release")
		return info
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		value := strings.Trim(parts[1], "\"")

		switch key {
		case "ID":
			info.Name = value
		case "VERSION_ID":
			info.Version = value
		case "ID_LIKE":
			// Determine family from ID_LIKE
			if strings.Contains(value, "debian") {
				info.Family = "debian"
			} else if strings.Contains(value, "rhel") || strings.Contains(value, "fedora") {
				info.Family = "rhel"
			} else if strings.Contains(value, "suse") {
				info.Family = "suse"
			}
		}
	}

	// Set family from ID if not set from ID_LIKE
	if info.Family == "" {
		switch info.Name {
		case "ubuntu", "debian":
			info.Family = "debian"
		case "rhel", "centos", "rocky", "alma", "fedora":
			info.Family = "rhel"
		case "sles", "opensuse", "opensuse-leap":
			info.Family = "suse"
		}
	}

	return info
}

// getContentFile returns the appropriate SCAP content file for this OS
func (s *OpenSCAPScanner) getContentFile() string {
	if s.osInfo.Name == "" {
		return ""
	}

	// Build possible content file names
	patterns := []string{
		fmt.Sprintf("ssg-%s%s-ds.xml", s.osInfo.Name, strings.ReplaceAll(s.osInfo.Version, ".", "")),
		fmt.Sprintf("ssg-%s%s-ds.xml", s.osInfo.Name, strings.Split(s.osInfo.Version, ".")[0]),
		fmt.Sprintf("ssg-%s-ds.xml", s.osInfo.Name),
	}

	// Check each pattern
	for _, pattern := range patterns {
		path := filepath.Join(scapContentDir, pattern)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Try to find any matching file
	matches, err := filepath.Glob(filepath.Join(scapContentDir, fmt.Sprintf("ssg-%s*-ds.xml", s.osInfo.Name)))
	if err == nil && len(matches) > 0 {
		return matches[0]
	}

	return ""
}

// GetAvailableProfiles returns available CIS profiles for this system
func (s *OpenSCAPScanner) GetAvailableProfiles() []string {
	profiles := make([]string, 0)

	if !s.available {
		return profiles
	}

	for profileName, osProfiles := range profileMappings {
		if _, exists := osProfiles[s.osInfo.Name]; exists {
			profiles = append(profiles, profileName)
		}
	}

	return profiles
}

// getProfileID returns the full profile ID for this OS
func (s *OpenSCAPScanner) getProfileID(profileName string) string {
	if osProfiles, exists := profileMappings[profileName]; exists {
		if profileID, exists := osProfiles[s.osInfo.Name]; exists {
			return profileID
		}
	}
	return ""
}

// RunScan executes an OpenSCAP scan
func (s *OpenSCAPScanner) RunScan(ctx context.Context, profileName string) (*models.ComplianceScan, error) {
	if !s.available {
		return nil, fmt.Errorf("OpenSCAP is not available")
	}

	startTime := time.Now()

	contentFile := s.getContentFile()
	if contentFile == "" {
		return nil, fmt.Errorf("no SCAP content file found for %s %s", s.osInfo.Name, s.osInfo.Version)
	}

	profileID := s.getProfileID(profileName)
	if profileID == "" {
		return nil, fmt.Errorf("profile %s not available for %s", profileName, s.osInfo.Name)
	}

	// Create temp file for results
	resultsFile, err := os.CreateTemp("", "oscap-results-*.xml")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	resultsPath := resultsFile.Name()
	resultsFile.Close()
	defer os.Remove(resultsPath)

	// Build command
	args := []string{
		"xccdf", "eval",
		"--profile", profileID,
		"--results", resultsPath,
		contentFile,
	}

	s.logger.WithFields(logrus.Fields{
		"profile":     profileName,
		"profile_id":  profileID,
		"content":     contentFile,
	}).Debug("Running OpenSCAP scan")

	// Run oscap
	cmd := exec.CommandContext(ctx, oscapBinary, args...)
	output, err := cmd.CombinedOutput()

	// oscap returns non-zero exit code if there are failures, which is expected
	// We only care about actual execution errors
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 2 means there were failures - this is normal
			if exitErr.ExitCode() != 2 && exitErr.ExitCode() != 1 {
				return nil, fmt.Errorf("oscap execution failed: %w\nOutput: %s", err, string(output))
			}
		} else if ctx.Err() != nil {
			return nil, fmt.Errorf("scan cancelled: %w", ctx.Err())
		}
	}

	// Parse results
	scan, err := s.parseResults(resultsPath, profileName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse results: %w", err)
	}

	scan.StartedAt = startTime
	now := time.Now()
	scan.CompletedAt = &now
	scan.Status = "completed"

	return scan, nil
}

// XCCDF result structures for parsing
type xccdfTestResult struct {
	XMLName xml.Name `xml:"TestResult"`
	Rules   []xccdfRuleResult `xml:"rule-result"`
}

type xccdfRuleResult struct {
	IDRef  string `xml:"idref,attr"`
	Result string `xml:"result"`
}

// parseResults parses the XCCDF results file
func (s *OpenSCAPScanner) parseResults(resultsPath string, profileName string) (*models.ComplianceScan, error) {
	data, err := os.ReadFile(resultsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read results: %w", err)
	}

	// Extract TestResult section (simplified parsing)
	scan := &models.ComplianceScan{
		ProfileName: profileName,
		ProfileType: "openscap",
		Results:     make([]models.ComplianceResult, 0),
	}

	// Parse rule results using regex (more robust than full XML parsing)
	rulePattern := regexp.MustCompile(`<rule-result[^>]*idref="([^"]+)"[^>]*>[\s\S]*?<result>([^<]+)</result>[\s\S]*?</rule-result>`)
	matches := rulePattern.FindAllStringSubmatch(string(data), -1)

	for _, match := range matches {
		if len(match) >= 3 {
			ruleID := match[1]
			result := strings.TrimSpace(match[2])

			// Map result to our status
			status := s.mapResult(result)

			// Update counters
			switch status {
			case "pass":
				scan.Passed++
			case "fail":
				scan.Failed++
			case "warn":
				scan.Warnings++
			case "skip":
				scan.Skipped++
			case "notapplicable":
				scan.NotApplicable++
			}
			scan.TotalRules++

			// Extract title from rule ID
			title := s.extractTitle(ruleID)

			scan.Results = append(scan.Results, models.ComplianceResult{
				RuleID: ruleID,
				Title:  title,
				Status: status,
			})
		}
	}

	// Calculate score
	if scan.TotalRules > 0 {
		applicable := scan.TotalRules - scan.NotApplicable - scan.Skipped
		if applicable > 0 {
			scan.Score = float64(scan.Passed) / float64(applicable) * 100
		}
	}

	return scan, nil
}

// mapResult maps XCCDF result to our status
func (s *OpenSCAPScanner) mapResult(result string) string {
	switch strings.ToLower(result) {
	case "pass":
		return "pass"
	case "fail":
		return "fail"
	case "error":
		return "fail"
	case "informational":
		return "warn"
	case "notselected", "notchecked":
		return "skip"
	case "notapplicable":
		return "notapplicable"
	default:
		return "skip"
	}
}

// extractTitle extracts a readable title from a rule ID
func (s *OpenSCAPScanner) extractTitle(ruleID string) string {
	// Remove prefix and convert underscores to spaces
	title := strings.TrimPrefix(ruleID, "xccdf_org.ssgproject.content_rule_")
	title = strings.ReplaceAll(title, "_", " ")

	// Capitalize first letter
	if len(title) > 0 {
		title = strings.ToUpper(title[:1]) + title[1:]
	}

	return title
}

// Cleanup removes OpenSCAP and related packages
// Note: This is optional - packages can be left installed if desired
func (s *OpenSCAPScanner) Cleanup() error {
	if !s.available {
		s.logger.Debug("OpenSCAP not installed, nothing to clean up")
		return nil
	}

	s.logger.Info("Removing OpenSCAP packages...")

	// Create context with timeout for package operations
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Environment for non-interactive apt operations
	nonInteractiveEnv := append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"NEEDRESTART_MODE=a",
		"NEEDRESTART_SUSPEND=1",
	)

	var removeCmd *exec.Cmd

	switch s.osInfo.Family {
	case "debian":
		removeCmd = exec.CommandContext(ctx, "apt-get", "remove", "-y", "-qq",
			"-o", "Dpkg::Options::=--force-confdef",
			"-o", "Dpkg::Options::=--force-confold",
			"openscap-scanner", "ssg-debderived", "ssg-base")
		removeCmd.Env = nonInteractiveEnv
	case "rhel":
		if _, err := exec.LookPath("dnf"); err == nil {
			removeCmd = exec.CommandContext(ctx, "dnf", "remove", "-y", "-q", "openscap-scanner", "scap-security-guide")
		} else {
			removeCmd = exec.CommandContext(ctx, "yum", "remove", "-y", "-q", "openscap-scanner", "scap-security-guide")
		}
	case "suse":
		removeCmd = exec.CommandContext(ctx, "zypper", "--non-interactive", "remove", "openscap-utils", "scap-security-guide")
	default:
		s.logger.Debug("Unknown OS family, skipping package removal")
		return nil
	}

	output, err := removeCmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			s.logger.Warn("OpenSCAP removal timed out after 3 minutes")
			return fmt.Errorf("removal timed out after 3 minutes")
		}
		s.logger.WithError(err).WithField("output", string(output)).Warn("Failed to remove OpenSCAP packages")
		// Don't return error - cleanup is best-effort
		return nil
	}

	s.logger.Info("OpenSCAP packages removed successfully")
	s.available = false
	s.version = ""

	return nil
}
