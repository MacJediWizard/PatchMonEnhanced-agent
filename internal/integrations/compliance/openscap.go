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

// DiscoverProfiles returns all available profiles from the SCAP content file
func (s *OpenSCAPScanner) DiscoverProfiles() []models.ScanProfileInfo {
	contentFile := s.getContentFile()
	if contentFile == "" {
		s.logger.Debug("No content file available, returning default profiles")
		return s.getDefaultProfiles()
	}

	// Run oscap info to get profile list
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, oscapBinary, "info", "--profiles", contentFile)
	output, err := cmd.Output()
	if err != nil {
		s.logger.WithError(err).Debug("Failed to get profiles from oscap info, using defaults")
		return s.getDefaultProfiles()
	}

	profiles := []models.ScanProfileInfo{}
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Parse profile line: "xccdf_org.ssgproject.content_profile_cis_level1_server:CIS Ubuntu 22.04 Level 1 Server Benchmark"
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 1 {
			continue
		}

		xccdfId := strings.TrimSpace(parts[0])
		name := xccdfId
		if len(parts) == 2 {
			name = strings.TrimSpace(parts[1])
		}

		// Determine category from profile ID
		category := s.categorizeProfile(xccdfId)

		// Create short ID from XCCDF ID
		shortId := s.createShortId(xccdfId)

		profiles = append(profiles, models.ScanProfileInfo{
			ID:       shortId,
			Name:     name,
			Type:     "openscap",
			XCCDFId:  xccdfId,
			Category: category,
		})
	}

	if len(profiles) == 0 {
		return s.getDefaultProfiles()
	}

	s.logger.WithField("count", len(profiles)).Debug("Discovered profiles from SCAP content")
	return profiles
}

// categorizeProfile determines the category of a profile based on its ID
func (s *OpenSCAPScanner) categorizeProfile(xccdfId string) string {
	id := strings.ToLower(xccdfId)
	switch {
	case strings.Contains(id, "cis"):
		return "cis"
	case strings.Contains(id, "stig"):
		return "stig"
	case strings.Contains(id, "pci") || strings.Contains(id, "pci-dss"):
		return "pci-dss"
	case strings.Contains(id, "hipaa"):
		return "hipaa"
	case strings.Contains(id, "anssi"):
		return "anssi"
	case strings.Contains(id, "standard"):
		return "standard"
	default:
		return "other"
	}
}

// createShortId creates a short profile ID from the full XCCDF ID
func (s *OpenSCAPScanner) createShortId(xccdfId string) string {
	// Extract the profile name part: xccdf_org.ssgproject.content_profile_XXX -> XXX
	if strings.Contains(xccdfId, "_profile_") {
		parts := strings.SplitN(xccdfId, "_profile_", 2)
		if len(parts) == 2 {
			return parts[1]
		}
	}
	return xccdfId
}

// getDefaultProfiles returns fallback profiles when discovery fails
func (s *OpenSCAPScanner) getDefaultProfiles() []models.ScanProfileInfo {
	return []models.ScanProfileInfo{
		{
			ID:          "level1_server",
			Name:        "CIS Level 1 Server",
			Description: "Basic security hardening for servers",
			Type:        "openscap",
			Category:    "cis",
		},
		{
			ID:          "level2_server",
			Name:        "CIS Level 2 Server",
			Description: "Extended security hardening (more restrictive)",
			Type:        "openscap",
			Category:    "cis",
		},
	}
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
			// Provide more specific guidance for Ubuntu 24.04+
			if s.osInfo.Name == "ubuntu" && s.osInfo.Version >= "24.04" {
				mismatchWarning = fmt.Sprintf("Content file %s does not match Ubuntu %s. Upgrade ssg-base to v0.1.76+ for Ubuntu 24.04 CIS/STIG content, or use Canonical's Ubuntu Security Guide (USG) with Ubuntu Pro.", baseName, s.osInfo.Version)
			} else {
				mismatchWarning = fmt.Sprintf("Content file %s may not match OS version %s. Consider upgrading ssg-base package.", baseName, s.osInfo.Version)
			}
		}
	} else if contentFile == "" && s.osInfo.Name == "ubuntu" && s.osInfo.Version >= "24.04" {
		contentMismatch = true
		mismatchWarning = "No SCAP content found for Ubuntu 24.04. Ensure ssg-base v0.1.76+ is installed, or use Canonical's Ubuntu Security Guide (USG) with Ubuntu Pro."
	}

	// Discover available profiles dynamically
	profiles := s.DiscoverProfiles()

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

		// Check if Ubuntu 24.04+ (Noble Numbat)
		isUbuntu2404Plus := s.osInfo.Name == "ubuntu" && s.osInfo.Version >= "24.04"
		if isUbuntu2404Plus {
			s.logger.Info("Ubuntu 24.04+ detected: CIS/STIG content requires ssg-base >= 0.1.76 or Canonical's Ubuntu Security Guide (USG)")
		}

		// Update package cache first (with timeout)
		updateCmd := exec.CommandContext(ctx, "apt-get", "update", "-qq")
		updateCmd.Env = nonInteractiveEnv
		updateCmd.Run() // Ignore errors on update

		// Build package list - openscap-common is required for Ubuntu 24.04+
		packages := []string{"openscap-scanner", "openscap-common"}

		// Try to install SSG content packages (may not be available for newer Ubuntu)
		ssgPackages := []string{"ssg-debderived", "ssg-base"}

		// Install core OpenSCAP packages first
		installArgs := append([]string{"install", "-y", "-qq",
			"-o", "Dpkg::Options::=--force-confdef",
			"-o", "Dpkg::Options::=--force-confold"}, packages...)
		installCmd := exec.CommandContext(ctx, "apt-get", installArgs...)
		installCmd.Env = nonInteractiveEnv
		output, err := installCmd.CombinedOutput()
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				s.logger.Warn("OpenSCAP installation timed out after 5 minutes")
				return fmt.Errorf("installation timed out after 5 minutes")
			}
			s.logger.WithError(err).WithField("output", string(output)).Warn("Failed to install OpenSCAP core packages")
			return fmt.Errorf("failed to install OpenSCAP: %w\nOutput: %s", err, string(output))
		}
		s.logger.Info("OpenSCAP core packages installed successfully")

		// Try to install SSG content packages (best effort - may fail on Ubuntu 24.04+)
		ssgArgs := append([]string{"install", "-y", "-qq",
			"-o", "Dpkg::Options::=--force-confdef",
			"-o", "Dpkg::Options::=--force-confold"}, ssgPackages...)
		ssgCmd := exec.CommandContext(ctx, "apt-get", ssgArgs...)
		ssgCmd.Env = nonInteractiveEnv
		ssgOutput, ssgErr := ssgCmd.CombinedOutput()
		if ssgErr != nil {
			s.logger.WithField("output", string(ssgOutput)).Warn("SSG content packages not available or failed to install. CIS scanning may have limited functionality.")
			if isUbuntu2404Plus {
				s.logger.Info("For Ubuntu 24.04+, consider using Canonical's Ubuntu Security Guide (USG) with Ubuntu Pro for official CIS benchmarks.")
			}
		} else {
			s.logger.Info("SSG content packages installed successfully")

			// Explicitly upgrade to ensure we have the latest SCAP content
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
	// If it's already a full XCCDF profile ID, use it directly
	if strings.HasPrefix(profileName, "xccdf_") {
		return profileName
	}

	// Otherwise, look up the mapping for this OS
	if osProfiles, exists := profileMappings[profileName]; exists {
		if profileID, exists := osProfiles[s.osInfo.Name]; exists {
			return profileID
		}
	}
	return ""
}

// RunScan executes an OpenSCAP scan (legacy method - calls RunScanWithOptions with defaults)
func (s *OpenSCAPScanner) RunScan(ctx context.Context, profileName string) (*models.ComplianceScan, error) {
	return s.RunScanWithOptions(ctx, &models.ComplianceScanOptions{
		ProfileID: profileName,
	})
}

// RunScanWithOptions executes an OpenSCAP scan with configurable options
func (s *OpenSCAPScanner) RunScanWithOptions(ctx context.Context, options *models.ComplianceScanOptions) (*models.ComplianceScan, error) {
	if !s.available {
		return nil, fmt.Errorf("OpenSCAP is not available")
	}

	startTime := time.Now()

	contentFile := s.getContentFile()
	if contentFile == "" {
		return nil, fmt.Errorf("no SCAP content file found for %s %s", s.osInfo.Name, s.osInfo.Version)
	}

	profileID := s.getProfileID(options.ProfileID)
	if profileID == "" {
		return nil, fmt.Errorf("profile %s not available for %s", options.ProfileID, s.osInfo.Name)
	}

	// Create temp file for results
	resultsFile, err := os.CreateTemp("", "oscap-results-*.xml")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	resultsPath := resultsFile.Name()
	resultsFile.Close()
	defer os.Remove(resultsPath)

	// Build command arguments
	args := []string{
		"xccdf", "eval",
		"--profile", profileID,
		"--results", resultsPath,
	}

	// Add optional arguments based on options
	if options.EnableRemediation {
		args = append(args, "--remediate")
		s.logger.Info("Remediation enabled - will attempt to fix failed rules")
	}

	if options.FetchRemoteResources {
		args = append(args, "--fetch-remote-resources")
	}

	if options.TailoringFile != "" {
		args = append(args, "--tailoring-file", options.TailoringFile)
	}

	// Add ARF output if requested
	if options.OutputFormat == "arf" {
		arfFile, err := os.CreateTemp("", "oscap-arf-*.xml")
		if err == nil {
			arfPath := arfFile.Name()
			arfFile.Close()
			defer os.Remove(arfPath)
			args = append(args, "--results-arf", arfPath)
		}
	}

	// Add content file last
	args = append(args, contentFile)

	s.logger.WithFields(logrus.Fields{
		"profile":     options.ProfileID,
		"profile_id":  profileID,
		"content":     contentFile,
		"remediation": options.EnableRemediation,
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
	scan, err := s.parseResults(resultsPath, options.ProfileID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse results: %w", err)
	}

	scan.StartedAt = startTime
	now := time.Now()
	scan.CompletedAt = &now
	scan.Status = "completed"
	scan.RemediationApplied = options.EnableRemediation

	return scan, nil
}

// GenerateRemediationScript generates a shell script to fix failed rules
func (s *OpenSCAPScanner) GenerateRemediationScript(ctx context.Context, resultsPath string, outputPath string) error {
	if !s.available {
		return fmt.Errorf("OpenSCAP is not available")
	}

	args := []string{
		"xccdf", "generate", "fix",
		"--template", "urn:xccdf:fix:script:sh",
		"--output", outputPath,
		resultsPath,
	}

	s.logger.WithField("output", outputPath).Debug("Generating remediation script")

	cmd := exec.CommandContext(ctx, oscapBinary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to generate remediation script: %w\nOutput: %s", err, string(output))
	}

	s.logger.WithField("output", outputPath).Info("Remediation script generated")
	return nil
}

// RunOfflineRemediation applies fixes from a previous scan result
func (s *OpenSCAPScanner) RunOfflineRemediation(ctx context.Context, resultsPath string) error {
	if !s.available {
		return fmt.Errorf("OpenSCAP is not available")
	}

	contentFile := s.getContentFile()
	if contentFile == "" {
		return fmt.Errorf("no SCAP content file found")
	}

	args := []string{
		"xccdf", "remediate",
		"--results", resultsPath,
		contentFile,
	}

	s.logger.WithField("results", resultsPath).Info("Running offline remediation")

	cmd := exec.CommandContext(ctx, oscapBinary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Non-zero exit is expected if some remediations fail
			if exitErr.ExitCode() > 2 {
				return fmt.Errorf("remediation failed: %w\nOutput: %s", err, string(output))
			}
		} else {
			return fmt.Errorf("remediation execution failed: %w", err)
		}
	}

	s.logger.Info("Offline remediation completed")
	return nil
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
