package commands

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"patchmon-agent/internal/client"
	"patchmon-agent/internal/integrations"
	"patchmon-agent/internal/integrations/compliance"
	"patchmon-agent/internal/integrations/docker"
	"patchmon-agent/internal/system"
	"patchmon-agent/internal/utils"
	"patchmon-agent/internal/version"
	"patchmon-agent/pkg/models"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
)

// serveCmd runs the agent as a long-lived service
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the agent as a service with async updates",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkRoot(); err != nil {
			return err
		}
		return runService()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func runService() error {
	if err := cfgManager.LoadCredentials(); err != nil {
		return err
	}

	httpClient := client.New(cfgManager, logger)
	ctx := context.Background()

	// Get api_id for offset calculation
	apiId := cfgManager.GetCredentials().APIID

	// Load interval from config.yml (with default fallback)
	intervalMinutes := cfgManager.GetConfig().UpdateInterval
	if intervalMinutes <= 0 {
		// Default to 60 if not set or invalid
		intervalMinutes = 60
		logger.WithField("interval", intervalMinutes).Info("Using default interval (not set in config)")
	} else {
		logger.WithField("interval", intervalMinutes).Info("Loaded interval from config.yml")
	}

	// Fetch interval from server and update config if different
	if resp, err := httpClient.GetUpdateInterval(ctx); err == nil && resp.UpdateInterval > 0 {
		if resp.UpdateInterval != intervalMinutes {
			logger.WithFields(map[string]interface{}{
				"config_interval": intervalMinutes,
				"server_interval": resp.UpdateInterval,
			}).Info("Server interval differs from config, updating config.yml")

			if err := cfgManager.SetUpdateInterval(resp.UpdateInterval); err != nil {
				logger.WithError(err).Warn("Failed to save interval to config.yml")
			} else {
				intervalMinutes = resp.UpdateInterval
				logger.WithField("interval", intervalMinutes).Info("Updated interval in config.yml")
			}
		}
	} else if err != nil {
		logger.WithError(err).Warn("Failed to fetch interval from server, using config value")
	}

	// Fetch integration status from server and sync with config.yml
	logger.Info("Syncing integration status from server...")
	if integrationResp, err := httpClient.GetIntegrationStatus(ctx); err == nil && integrationResp.Success {
		configUpdated := false
		for integrationName, serverEnabled := range integrationResp.Integrations {
			configEnabled := cfgManager.IsIntegrationEnabled(integrationName)
			if serverEnabled != configEnabled {
				logger.WithFields(map[string]interface{}{
					"integration":  integrationName,
					"config_value": configEnabled,
					"server_value": serverEnabled,
				}).Info("Integration status differs, updating config.yml")

				if err := cfgManager.SetIntegrationEnabled(integrationName, serverEnabled); err != nil {
					logger.WithError(err).Warn("Failed to save integration status to config.yml")
				} else {
					configUpdated = true
					logger.WithFields(map[string]interface{}{
						"integration": integrationName,
						"enabled":     serverEnabled,
					}).Info("Updated integration status in config.yml")
				}
			}
		}

		if configUpdated {
			// Reload config so in-memory state matches the updated file
			if err := cfgManager.LoadConfig(); err != nil {
				logger.WithError(err).Warn("Failed to reload config after integration update")
			} else {
				logger.Info("Config reloaded, integration settings will be applied")
			}
		} else {
			logger.Debug("Integration status matches config, no update needed")
		}
	} else if err != nil {
		logger.WithError(err).Warn("Failed to fetch integration status from server, using config values")
	}

	// Load or calculate offset based on api_id to stagger reporting times
	var offset time.Duration
	configOffsetSeconds := cfgManager.GetConfig().ReportOffset

	// Calculate what the offset should be based on current api_id and interval
	calculatedOffset := utils.CalculateReportOffset(apiId, intervalMinutes)
	calculatedOffsetSeconds := int(calculatedOffset.Seconds())

	// Use config offset if it exists and matches calculated value, otherwise recalculate and save
	if configOffsetSeconds > 0 && configOffsetSeconds == calculatedOffsetSeconds {
		offset = time.Duration(configOffsetSeconds) * time.Second
		logger.WithFields(map[string]interface{}{
			"api_id":           apiId,
			"interval_minutes": intervalMinutes,
			"offset_seconds":   offset.Seconds(),
		}).Info("Loaded report offset from config.yml")
	} else {
		// Offset not in config or doesn't match, calculate and save it
		offset = calculatedOffset
		if err := cfgManager.SetReportOffset(calculatedOffsetSeconds); err != nil {
			logger.WithError(err).Warn("Failed to save offset to config.yml")
		} else {
			logger.WithFields(map[string]interface{}{
				"api_id":           apiId,
				"interval_minutes": intervalMinutes,
				"offset_seconds":   offset.Seconds(),
			}).Info("Calculated and saved report offset to config.yml")
		}
	}

	// Send startup ping to notify server that agent has started
	logger.Info("🚀 Agent starting up, notifying server...")
	if _, err := httpClient.Ping(ctx); err != nil {
		logger.WithError(err).Warn("startup ping failed, will retry")
	} else {
		logger.Info("✅ Startup notification sent to server")
	}

	// initial report on boot
	logger.Info("Sending initial report on startup...")
	if err := sendReport(false); err != nil {
		logger.WithError(err).Warn("initial report failed")
	} else {
		logger.Info("✅ Initial report sent successfully")
	}

	// start websocket loop
	logger.Info("Establishing WebSocket connection...")
	messages := make(chan wsMsg, 10)
	dockerEvents := make(chan interface{}, 100)
	go wsLoop(messages, dockerEvents)

	// Start integration monitoring (Docker real-time events, etc.)
	startIntegrationMonitoring(ctx, dockerEvents)

	// Create ticker with initial interval
	ticker := time.NewTicker(time.Duration(intervalMinutes) * time.Minute)
	defer ticker.Stop()

	// Wait for offset before starting periodic reports
	// This staggers the reporting times across different agents
	offsetTimer := time.NewTimer(offset)
	defer offsetTimer.Stop()

	// Track whether offset period has passed
	offsetPassed := false

	// Track current interval for offset recalculation on updates
	currentInterval := intervalMinutes

	for {
		select {
		case <-offsetTimer.C:
			// Offset period completed, start consuming from ticker normally
			offsetPassed = true
			logger.Debug("Offset period completed, periodic reports will now start")
		case <-ticker.C:
			// Only process ticker events after offset has passed
			if offsetPassed {
				if err := sendReport(false); err != nil {
					logger.WithError(err).Warn("periodic report failed")
				}
			}
		case m := <-messages:
			switch m.kind {
			case "settings_update":
				if m.interval > 0 && m.interval != currentInterval {
					// Save new interval to config.yml
					if err := cfgManager.SetUpdateInterval(m.interval); err != nil {
						logger.WithError(err).Warn("Failed to save interval to config.yml")
					} else {
						logger.WithField("interval", m.interval).Info("Saved new interval to config.yml")
					}

					// Recalculate offset for new interval and save to config.yml
					newOffset := utils.CalculateReportOffset(apiId, m.interval)
					newOffsetSeconds := int(newOffset.Seconds())
					if err := cfgManager.SetReportOffset(newOffsetSeconds); err != nil {
						logger.WithError(err).Warn("Failed to save offset to config.yml")
					}

					logger.WithFields(map[string]interface{}{
						"old_interval":       currentInterval,
						"new_interval":       m.interval,
						"new_offset_seconds": newOffset.Seconds(),
					}).Info("Recalculated and saved offset for new interval")

					// Stop old ticker
					ticker.Stop()

					// Create new ticker with updated interval
					ticker = time.NewTicker(time.Duration(m.interval) * time.Minute)
					currentInterval = m.interval

					// Reset offset timer for new interval
					offsetTimer.Stop()
					offsetTimer = time.NewTimer(newOffset)
					offsetPassed = false // Reset flag for new interval

					logger.WithField("new_interval", m.interval).Info("interval updated, no report sent")
				}
			case "report_now":
				if err := sendReport(false); err != nil {
					logger.WithError(err).Warn("report_now failed")
				}
			case "update_agent":
				if err := updateAgent(); err != nil {
					logger.WithError(err).Warn("update_agent failed")
				}
			case "update_notification":
				logger.WithField("version", m.version).Info("Update notification received from server")
				if m.force {
					logger.Info("Force update requested, updating agent now")
					if err := updateAgent(); err != nil {
						logger.WithError(err).Warn("forced update failed")
					}
				} else {
					logger.Info("Update available, run 'patchmon-agent update-agent' to update")
				}
			case "integration_toggle":
				if err := toggleIntegration(m.integrationName, m.integrationEnabled); err != nil {
					logger.WithError(err).Warn("integration_toggle failed")
				} else {
					logger.WithFields(map[string]interface{}{
						"integration": m.integrationName,
						"enabled":     m.integrationEnabled,
					}).Info("Integration toggled successfully, service will restart")
				}
			case "compliance_scan":
				logger.WithFields(map[string]interface{}{
					"profile_type":       m.profileType,
					"profile_id":         m.profileID,
					"enable_remediation": m.enableRemediation,
				}).Info("Running on-demand compliance scan...")
				go func(msg wsMsg) {
					options := &models.ComplianceScanOptions{
						ProfileID:            msg.profileID,
						EnableRemediation:    msg.enableRemediation,
						FetchRemoteResources: msg.fetchRemoteResources,
					}
					if err := runComplianceScanWithOptions(options); err != nil {
						logger.WithError(err).Warn("compliance_scan failed")
					} else {
						if msg.enableRemediation {
							logger.Info("On-demand compliance scan with remediation completed successfully")
						} else {
							logger.Info("On-demand compliance scan completed successfully")
						}
					}
				}(m)
			case "upgrade_ssg":
				logger.Info("Upgrading SSG content packages...")
				go func() {
					if err := upgradeSSGContent(); err != nil {
						logger.WithError(err).Warn("upgrade_ssg failed")
					} else {
						logger.Info("SSG content packages upgraded successfully")
					}
				}()
			case "remediate_rule":
				logger.WithField("rule_id", m.ruleID).Info("Remediating single rule...")
				go func(ruleID string) {
					if err := remediateSingleRule(ruleID); err != nil {
						logger.WithError(err).WithField("rule_id", ruleID).Warn("remediate_rule failed")
					} else {
						logger.WithField("rule_id", ruleID).Info("Single rule remediation completed")
					}
				}(m.ruleID)
			}
		}
	}
}

// upgradeSSGContent upgrades the SCAP Security Guide content packages
func upgradeSSGContent() error {
	// Create compliance integration to access the OpenSCAP scanner
	complianceInteg := compliance.New(logger)
	if err := complianceInteg.UpgradeSSGContent(); err != nil {
		return err
	}

	// Send updated status to backend after successful upgrade
	logger.Info("Sending updated compliance status to backend...")
	httpClient := client.New(cfgManager, logger)
	ctx := context.Background()

	// Get new scanner details
	openscapScanner := compliance.NewOpenSCAPScanner(logger)
	scannerDetails := openscapScanner.GetScannerDetails()

	// Check if Docker integration is enabled for Docker Bench info
	dockerIntegrationEnabled := cfgManager.IsIntegrationEnabled("docker")
	if dockerIntegrationEnabled {
		dockerBenchScanner := compliance.NewDockerBenchScanner(logger)
		scannerDetails.DockerBenchAvailable = dockerBenchScanner.IsAvailable()
	}

	// Send updated status
	if err := httpClient.SendIntegrationSetupStatus(ctx, &models.IntegrationSetupStatus{
		Integration: "compliance",
		Enabled:     cfgManager.IsIntegrationEnabled("compliance"),
		Status:      "ready",
		Message:     "SSG content upgraded successfully",
		ScannerInfo: scannerDetails,
	}); err != nil {
		logger.WithError(err).Warn("Failed to send updated compliance status")
		// Don't fail the upgrade just because status update failed
	} else {
		logger.Info("Updated compliance status sent to backend")
	}

	return nil
}

// remediateSingleRule remediates a single failed compliance rule
func remediateSingleRule(ruleID string) error {
	if ruleID == "" {
		return fmt.Errorf("rule ID is required")
	}

	logger.WithField("rule_id", ruleID).Info("Starting single rule remediation")

	// Create compliance integration to run remediation
	complianceInteg := compliance.New(logger)
	if !complianceInteg.IsAvailable() {
		return fmt.Errorf("compliance scanning not available on this system")
	}

	// Run scan with remediation for just this rule
	// Use level1_server as the default profile - it contains most common rules
	// The --rule flag will filter to just the specified rule
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	options := &models.ComplianceScanOptions{
		ProfileID:         "level1_server", // Use default CIS Level 1 Server profile
		RuleID:            ruleID,          // Filter to this specific rule
		EnableRemediation: true,
	}

	logger.WithFields(map[string]interface{}{
		"profile_id": options.ProfileID,
		"rule_id":    options.RuleID,
	}).Info("Running single rule remediation with oscap")

	_, err := complianceInteg.CollectWithOptions(ctx, options)
	if err != nil {
		return fmt.Errorf("remediation failed: %w", err)
	}

	logger.WithField("rule_id", ruleID).Info("Single rule remediation completed successfully")
	return nil
}

// startIntegrationMonitoring starts real-time monitoring for integrations that support it
func startIntegrationMonitoring(ctx context.Context, eventChan chan<- interface{}) {
	// Create integration manager
	integrationMgr := integrations.NewManager(logger)

	// Set enabled checker to respect config.yml settings
	integrationMgr.SetEnabledChecker(func(name string) bool {
		return cfgManager.IsIntegrationEnabled(name)
	})

	// Register integrations
	dockerInteg := docker.New(logger)
	integrationMgr.Register(dockerInteg)

	// Start monitoring for real-time integrations
	realtimeIntegrations := integrationMgr.GetRealtimeIntegrations()
	for _, integration := range realtimeIntegrations {
		logger.WithField("integration", integration.Name()).Info("Starting real-time monitoring")

		// Start monitoring in a goroutine
		go func(integ integrations.RealtimeIntegration) {
			if err := integ.StartMonitoring(ctx, eventChan); err != nil {
				logger.WithError(err).Warn("Failed to start integration monitoring")
			}
		}(integration)
	}
}

type wsMsg struct {
	kind                 string
	interval             int
	version              string
	force                bool
	integrationName      string
	integrationEnabled   bool
	profileType          string // For compliance_scan: openscap, docker-bench, all
	profileID            string // For compliance_scan: specific XCCDF profile ID
	enableRemediation    bool   // For compliance_scan: enable auto-remediation
	fetchRemoteResources bool   // For compliance_scan: fetch remote resources
	ruleID               string // For remediate_rule: specific rule ID to remediate
}

// ComplianceScanProgress represents a progress update during compliance scanning
type ComplianceScanProgress struct {
	Phase       string  `json:"phase"`        // started, evaluating, parsing, completed, failed
	ProfileName string  `json:"profile_name"` // Name of the profile being scanned
	Message     string  `json:"message"`      // Human-readable progress message
	Progress    float64 `json:"progress"`     // 0-100 percentage (approximate)
	Error       string  `json:"error,omitempty"`
}

// Global channel for compliance scan progress updates
var complianceProgressChan = make(chan ComplianceScanProgress, 10)

func wsLoop(out chan<- wsMsg, dockerEvents <-chan interface{}) {
	backoff := time.Second
	for {
		if err := connectOnce(out, dockerEvents); err != nil {
			logger.WithError(err).Warn("ws disconnected; retrying")
		}
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func connectOnce(out chan<- wsMsg, dockerEvents <-chan interface{}) error {
	server := cfgManager.GetConfig().PatchmonServer
	if server == "" {
		return nil
	}
	apiID := cfgManager.GetCredentials().APIID
	apiKey := cfgManager.GetCredentials().APIKey

	// Convert http(s) -> ws(s)
	wsURL := server
	if strings.HasPrefix(wsURL, "https://") {
		wsURL = "wss://" + strings.TrimPrefix(wsURL, "https://")
	} else if strings.HasPrefix(wsURL, "http://") {
		wsURL = "ws://" + strings.TrimPrefix(wsURL, "http://")
	} else if strings.HasPrefix(wsURL, "wss://") {
		// Already a WebSocket secure URL, use as-is
		// No conversion needed
	} else if strings.HasPrefix(wsURL, "ws://") {
		// Already a WebSocket URL, use as-is
		// No conversion needed
	} else {
		// No protocol prefix - assume HTTPS and use WSS
		logger.WithField("server", server).Warn("Server URL missing protocol prefix, assuming HTTPS")
		wsURL = "wss://" + wsURL
	}
	if strings.HasSuffix(wsURL, "/") {
		wsURL = strings.TrimRight(wsURL, "/")
	}
	wsURL = wsURL + "/api/" + cfgManager.GetConfig().APIVersion + "/agents/ws"
	header := http.Header{}
	header.Set("X-API-ID", apiID)
	header.Set("X-API-KEY", apiKey)

	// SECURITY: Configure WebSocket dialer for insecure connections if needed
	// WARNING: This exposes the agent to man-in-the-middle attacks!
	dialer := websocket.DefaultDialer
	if cfgManager.GetConfig().SkipSSLVerify {
		// SECURITY: Block skip_ssl_verify in production environments
		if utils.IsProductionEnvironment() {
			logger.Error("╔══════════════════════════════════════════════════════════════════╗")
			logger.Error("║  SECURITY ERROR: skip_ssl_verify is BLOCKED in production!       ║")
			logger.Error("║  Set PATCHMON_ENV to 'development' to enable insecure mode.      ║")
			logger.Error("║  This setting cannot be used when PATCHMON_ENV=production        ║")
			logger.Error("╚══════════════════════════════════════════════════════════════════╝")
			logger.Fatal("Refusing to start with skip_ssl_verify=true in production environment")
		}

		logger.Error("╔══════════════════════════════════════════════════════════════════╗")
		logger.Error("║  SECURITY WARNING: TLS verification DISABLED for WebSocket!      ║")
		logger.Error("║  Commands from server could be intercepted or modified.          ║")
		logger.Error("║  Use a valid TLS certificate in production!                      ║")
		logger.Error("╚══════════════════════════════════════════════════════════════════╝")
		dialer = &websocket.Dialer{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	conn, _, err := dialer.Dial(wsURL, header)
	if err != nil {
		return err
	}

	// Create a done channel to signal goroutines to stop when connection closes
	done := make(chan struct{})
	defer func() {
		close(done) // Signal all goroutines to stop
		_ = conn.Close()
	}()

	// ping loop - now with cancellation support
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
					return // Connection closed, exit goroutine
				}
			}
		}
	}()

	// Set read deadlines and extend them on pong frames to avoid idle timeouts
	_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	})

	// SECURITY: Limit WebSocket message size to prevent DoS attacks (64KB max)
	conn.SetReadLimit(64 * 1024)

	logger.WithField("url", wsURL).Info("WebSocket connected")

	// Create a goroutine to send Docker events through WebSocket - with cancellation support
	go func() {
		for {
			select {
			case <-done:
				return
			case event, ok := <-dockerEvents:
				if !ok {
					return // Channel closed
				}
				if dockerEvent, ok := event.(models.DockerStatusEvent); ok {
					eventJSON, err := json.Marshal(map[string]interface{}{
						"type":         "docker_status",
						"event":        dockerEvent,
						"container_id": dockerEvent.ContainerID,
						"name":         dockerEvent.Name,
						"status":       dockerEvent.Status,
						"timestamp":    dockerEvent.Timestamp,
					})
					if err != nil {
						logger.WithError(err).Warn("Failed to marshal Docker event")
						continue
					}

					if err := conn.WriteMessage(websocket.TextMessage, eventJSON); err != nil {
						logger.WithError(err).Debug("Failed to send Docker event via WebSocket")
						return
					}
				}
			}
		}
	}()

	// Create a goroutine to send compliance scan progress updates through WebSocket
	go func() {
		for {
			select {
			case <-done:
				return
			case progress, ok := <-complianceProgressChan:
				if !ok {
					return // Channel closed
				}
				progressJSON, err := json.Marshal(map[string]interface{}{
					"type":         "compliance_scan_progress",
					"phase":        progress.Phase,
					"profile_name": progress.ProfileName,
					"message":      progress.Message,
					"progress":     progress.Progress,
					"error":        progress.Error,
					"timestamp":    time.Now().Format(time.RFC3339),
				})
				if err != nil {
					logger.WithError(err).Warn("Failed to marshal compliance progress event")
					continue
				}

				if err := conn.WriteMessage(websocket.TextMessage, progressJSON); err != nil {
					logger.WithError(err).Debug("Failed to send compliance progress via WebSocket")
					return
				}
				logger.WithFields(map[string]interface{}{
					"phase":   progress.Phase,
					"message": progress.Message,
				}).Debug("Sent compliance progress update via WebSocket")
			}
		}
	}()

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		logger.WithField("raw_message", string(data)).Debug("WebSocket message received")
		var payload struct {
			Type                 string `json:"type"`
			UpdateInterval       int    `json:"update_interval"`
			Version              string `json:"version"`
			Force                bool   `json:"force"`
			Message              string `json:"message"`
			Integration          string `json:"integration"`
			Enabled              bool   `json:"enabled"`
			ProfileType          string `json:"profile_type"`           // For compliance_scan
			ProfileID            string `json:"profile_id"`             // For compliance_scan: specific XCCDF profile ID
			EnableRemediation    bool   `json:"enable_remediation"`     // For compliance_scan
			FetchRemoteResources bool   `json:"fetch_remote_resources"` // For compliance_scan
			RuleID               string `json:"rule_id"`                // For remediate_rule: specific rule to remediate
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			logger.WithError(err).WithField("data", string(data)).Warn("Failed to parse WebSocket message")
			continue
		}
		logger.WithField("type", payload.Type).Debug("Parsed WebSocket message type")
		switch payload.Type {
			case "settings_update":
				logger.WithField("interval", payload.UpdateInterval).Info("settings_update received")
				out <- wsMsg{kind: "settings_update", interval: payload.UpdateInterval}
			case "report_now":
				logger.Info("report_now received")
				out <- wsMsg{kind: "report_now"}
			case "update_agent":
				logger.Info("update_agent received")
				out <- wsMsg{kind: "update_agent"}
			case "update_notification":
				logger.WithFields(map[string]interface{}{
					"version": payload.Version,
					"force":   payload.Force,
					"message": payload.Message,
				}).Info("update_notification received")
				out <- wsMsg{
					kind:    "update_notification",
					version: payload.Version,
					force:   payload.Force,
				}
			case "integration_toggle":
				logger.WithFields(map[string]interface{}{
					"integration": payload.Integration,
					"enabled":     payload.Enabled,
				}).Info("integration_toggle received")
				out <- wsMsg{
					kind:               "integration_toggle",
					integrationName:    payload.Integration,
					integrationEnabled: payload.Enabled,
				}
			case "compliance_scan":
				profileType := payload.ProfileType
				if profileType == "" {
					profileType = "all"
				}
				logger.WithFields(map[string]interface{}{
					"profile_type":       profileType,
					"profile_id":         payload.ProfileID,
					"enable_remediation": payload.EnableRemediation,
				}).Info("compliance_scan received")
				out <- wsMsg{
					kind:                 "compliance_scan",
					profileType:          profileType,
					profileID:            payload.ProfileID,
					enableRemediation:    payload.EnableRemediation,
					fetchRemoteResources: payload.FetchRemoteResources,
				}
			case "upgrade_ssg":
				logger.Info("upgrade_ssg received from WebSocket")
				out <- wsMsg{kind: "upgrade_ssg"}
				logger.Info("upgrade_ssg sent to message channel")
			case "remediate_rule":
				logger.WithField("rule_id", payload.RuleID).Info("remediate_rule received")
				out <- wsMsg{kind: "remediate_rule", ruleID: payload.RuleID}
			default:
				if payload.Type != "" && payload.Type != "connected" {
					logger.WithField("type", payload.Type).Warn("Unknown WebSocket message type")
				}
			}
	}
}

// toggleIntegration toggles an integration on or off and restarts the service
func toggleIntegration(integrationName string, enabled bool) error {
	logger.WithFields(map[string]interface{}{
		"integration": integrationName,
		"enabled":     enabled,
	}).Info("Toggling integration")

	// Handle compliance tools installation/removal
	if integrationName == "compliance" {
		// Create HTTP client for sending status updates
		httpClient := client.New(cfgManager, logger)
		ctx := context.Background()

		components := make(map[string]string)
		var overallStatus string
		var statusMessage string

		if enabled {
			logger.Info("Compliance enabled - installing required tools...")
			overallStatus = "installing"

			// Send initial "installing" status
			httpClient.SendIntegrationSetupStatus(ctx, &models.IntegrationSetupStatus{
				Integration: "compliance",
				Enabled:     true,
				Status:      "installing",
				Message:     "Installing compliance tools...",
			})

			// Install OpenSCAP
			openscapScanner := compliance.NewOpenSCAPScanner(logger)
			if err := openscapScanner.EnsureInstalled(); err != nil {
				logger.WithError(err).Warn("Failed to install OpenSCAP (will try again on next scan)")
				components["openscap"] = "failed"
			} else {
				logger.Info("OpenSCAP installed successfully")
				components["openscap"] = "ready"
			}

			// Pre-pull Docker Bench image only if Docker integration is enabled AND Docker is available
			dockerIntegrationEnabled := cfgManager.IsIntegrationEnabled("docker")
			if dockerIntegrationEnabled {
				dockerBenchScanner := compliance.NewDockerBenchScanner(logger)
				if dockerBenchScanner.IsAvailable() {
					if err := dockerBenchScanner.EnsureInstalled(); err != nil {
						logger.WithError(err).Warn("Failed to pre-pull Docker Bench image (will pull on first scan)")
						components["docker-bench"] = "failed"
					} else {
						logger.Info("Docker Bench image pulled successfully")
						components["docker-bench"] = "ready"
					}
				} else {
					components["docker-bench"] = "unavailable"
				}
			} else {
				logger.Debug("Docker integration not enabled, skipping Docker Bench setup")
				// Don't add docker-bench to components at all if integration is not enabled
			}

			// Determine overall status
			allReady := true
			for _, status := range components {
				if status == "failed" {
					allReady = false
					break
				}
			}
			if allReady {
				overallStatus = "ready"
				statusMessage = "Compliance tools installed and ready"
			} else {
				overallStatus = "partial"
				statusMessage = "Some compliance tools failed to install"
			}

			// Get detailed scanner info to send with status
			scannerDetails := openscapScanner.GetScannerDetails()

			// Add Docker Bench info if available
			if dockerIntegrationEnabled {
				dockerBenchScanner := compliance.NewDockerBenchScanner(logger)
				scannerDetails.DockerBenchAvailable = dockerBenchScanner.IsAvailable()
				if scannerDetails.DockerBenchAvailable {
					scannerDetails.AvailableProfiles = append(scannerDetails.AvailableProfiles, models.ScanProfileInfo{
						ID:          "docker-bench",
						Name:        "Docker Bench for Security",
						Description: "CIS Docker Benchmark security checks",
						Type:        "docker-bench",
					})
				}
			}

			// Send final status with scanner info
			httpClient.SendIntegrationSetupStatus(ctx, &models.IntegrationSetupStatus{
				Integration: "compliance",
				Enabled:     enabled,
				Status:      overallStatus,
				Message:     statusMessage,
				Components:  components,
				ScannerInfo: scannerDetails,
			})
			return nil // Skip the generic status send below

		} else {
			logger.Info("Compliance disabled - removing tools...")
			overallStatus = "removing"

			// Send initial "removing" status
			httpClient.SendIntegrationSetupStatus(ctx, &models.IntegrationSetupStatus{
				Integration: "compliance",
				Enabled:     false,
				Status:      "removing",
				Message:     "Removing compliance tools...",
			})

			// Remove OpenSCAP packages
			openscapScanner := compliance.NewOpenSCAPScanner(logger)
			if err := openscapScanner.Cleanup(); err != nil {
				logger.WithError(err).Warn("Failed to remove OpenSCAP packages")
				components["openscap"] = "cleanup-failed"
			} else {
				logger.Info("OpenSCAP packages removed successfully")
				components["openscap"] = "removed"
			}

			// Clean up Docker Bench images
			dockerBenchScanner := compliance.NewDockerBenchScanner(logger)
			if dockerBenchScanner.IsAvailable() {
				if err := dockerBenchScanner.Cleanup(); err != nil {
					logger.WithError(err).Debug("Failed to cleanup Docker Bench image")
					components["docker-bench"] = "cleanup-failed"
				} else {
					components["docker-bench"] = "removed"
				}
			}

			overallStatus = "disabled"
			statusMessage = "Compliance disabled and tools removed"
			logger.Info("Compliance cleanup complete")

			// Send final status update for disable
			httpClient.SendIntegrationSetupStatus(ctx, &models.IntegrationSetupStatus{
				Integration: "compliance",
				Enabled:     enabled,
				Status:      overallStatus,
				Message:     statusMessage,
				Components:  components,
			})
		}
	}

	// Update config.yml
	if err := cfgManager.SetIntegrationEnabled(integrationName, enabled); err != nil {
		return fmt.Errorf("failed to update config: %w", err)
	}

	logger.Info("Config updated, restarting patchmon-agent service...")

	// Restart the service to apply changes (supports systemd and OpenRC)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := exec.LookPath("systemctl"); err == nil {
		// Systemd is available
		logger.Debug("Detected systemd, using systemctl restart")
		cmd := exec.CommandContext(ctx, "systemctl", "restart", "patchmon-agent")
		output, err := cmd.CombinedOutput()
		if err != nil {
			logger.WithError(err).Warn("Failed to restart service (this is not critical)")
			return fmt.Errorf("failed to restart service: %w, output: %s", err, string(output))
		}
		logger.WithField("output", string(output)).Debug("Service restart command completed")
		logger.Info("Service restarted successfully")
		return nil
	} else if _, err := exec.LookPath("rc-service"); err == nil {
		// OpenRC is available (Alpine Linux)
		// Since we're running inside the service, we can't stop ourselves directly
		// Instead, we'll create a helper script that runs after we exit
		logger.Debug("Detected OpenRC, scheduling service restart via helper script")

		// SECURITY: Ensure /etc/patchmon directory exists with restrictive permissions
		// Using 0700 to prevent other users from reading/writing to this directory
		if err := os.MkdirAll("/etc/patchmon", 0700); err != nil {
			logger.WithError(err).Warn("Failed to create /etc/patchmon directory, will try anyway")
		}

		// Create a helper script that will restart the service after we exit
		// SECURITY NOTE: Writing scripts to disk has a TOCTOU race condition risk.
		// Mitigations: 1) 0700 permissions on dir and file (owner-only)
		//              2) Script is deleted immediately after execution
		//              3) Short window between write and exec (milliseconds)
		helperScript := `#!/bin/sh
# Wait a moment for the current process to exit
sleep 2
# Restart the service
rc-service patchmon-agent restart 2>&1 || rc-service patchmon-agent start 2>&1
# Clean up this script
rm -f "$0"
`
		helperPath := "/etc/patchmon/patchmon-restart-helper.sh"
		// SECURITY: Use 0700 permissions (owner-only executable) to minimize TOCTOU risk
		if err := os.WriteFile(helperPath, []byte(helperScript), 0700); err != nil {
			logger.WithError(err).Warn("Failed to create restart helper script, will exit and rely on OpenRC auto-restart")
			// Fall through to exit approach
		} else {
			// Execute the helper script in background (detached from current process)
			// Use 'sh -c' with nohup to ensure it runs after we exit
			cmd := exec.Command("sh", "-c", fmt.Sprintf("nohup %s > /dev/null 2>&1 &", helperPath))
			if err := cmd.Start(); err != nil {
				logger.WithError(err).Warn("Failed to start restart helper script, will exit and rely on OpenRC auto-restart")
				// Clean up script
				if removeErr := os.Remove(helperPath); removeErr != nil {
					logger.WithError(removeErr).Debug("Failed to remove helper script")
				}
				// Fall through to exit approach
			} else {
				logger.Info("Scheduled service restart via helper script, exiting now...")
				// Give the helper script a moment to start
				time.Sleep(500 * time.Millisecond)
				// Exit gracefully - the helper script will restart the service
				os.Exit(0)
			}
		}

		// Fallback: If helper script approach failed, just exit and let OpenRC handle it
		// OpenRC with command_background="yes" should restart on exit
		logger.Info("Exiting to allow OpenRC to restart service with updated config...")
		os.Exit(0)
		// os.Exit never returns, but we need this for code flow
		return nil
	} else {
		logger.Warn("No known init system detected, attempting to restart via process signal")
		// Try to find and kill the process, service manager should restart it
		killCmd := exec.CommandContext(ctx, "pkill", "-HUP", "patchmon-agent")
		if err := killCmd.Run(); err != nil {
			logger.WithError(err).Warn("Failed to restart service (this is not critical)")
			return fmt.Errorf("failed to restart service: no init system detected and pkill failed: %w", err)
		}
		logger.Info("Sent HUP signal to agent process")
		return nil
	}
}

// runComplianceScan runs an on-demand compliance scan and sends results to server (backwards compatible)
func runComplianceScan(profileType string) error {
	return runComplianceScanWithOptions(&models.ComplianceScanOptions{
		ProfileID: profileType,
	})
}

// sendComplianceProgress sends a progress update via the global channel
func sendComplianceProgress(phase, profileName, message string, progress float64, errMsg string) {
	select {
	case complianceProgressChan <- ComplianceScanProgress{
		Phase:       phase,
		ProfileName: profileName,
		Message:     message,
		Progress:    progress,
		Error:       errMsg,
	}:
		// Successfully sent
	default:
		// Channel full or no listener, skip to avoid blocking
		logger.Debug("Compliance progress channel full, skipping update")
	}
}

// runComplianceScanWithOptions runs an on-demand compliance scan with options and sends results to server
func runComplianceScanWithOptions(options *models.ComplianceScanOptions) error {
	profileName := options.ProfileID
	if profileName == "" {
		profileName = "default"
	}

	logger.WithFields(map[string]interface{}{
		"profile_id":         options.ProfileID,
		"enable_remediation": options.EnableRemediation,
	}).Info("Starting on-demand compliance scan")

	// Send progress: started
	sendComplianceProgress("started", profileName, "Initializing compliance scan...", 5, "")

	// Create compliance integration
	complianceInteg := compliance.New(logger)
	// Set Docker integration status - Docker Bench only runs if Docker integration is enabled
	complianceInteg.SetDockerIntegrationEnabled(cfgManager.IsIntegrationEnabled("docker"))

	if !complianceInteg.IsAvailable() {
		sendComplianceProgress("failed", profileName, "Compliance scanning not available", 0, "compliance scanning not available on this system")
		return fmt.Errorf("compliance scanning not available on this system")
	}

	// Send progress: evaluating
	sendComplianceProgress("evaluating", profileName, "Running OpenSCAP evaluation (this may take several minutes)...", 15, "")

	// Run the scan with options
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	integrationData, err := complianceInteg.CollectWithOptions(ctx, options)
	if err != nil {
		sendComplianceProgress("failed", profileName, "Scan failed", 0, err.Error())
		return fmt.Errorf("compliance scan failed: %w", err)
	}

	// Send progress: parsing
	sendComplianceProgress("parsing", profileName, "Processing scan results...", 80, "")

	// Extract compliance data
	complianceData, ok := integrationData.Data.(*models.ComplianceData)
	if !ok {
		sendComplianceProgress("failed", profileName, "Failed to extract compliance data", 0, "failed to extract compliance data")
		return fmt.Errorf("failed to extract compliance data")
	}

	if len(complianceData.Scans) == 0 {
		logger.Info("No compliance scans to send")
		sendComplianceProgress("completed", profileName, "Scan completed (no results)", 100, "")
		return nil
	}

	// Send progress: sending
	sendComplianceProgress("sending", profileName, "Uploading results to server...", 90, "")

	// Get system info
	systemDetector := system.New(logger)
	hostname, _ := systemDetector.GetHostname()
	machineID := systemDetector.GetMachineID()

	// Create payload
	payload := &models.CompliancePayload{
		ComplianceData: *complianceData,
		Hostname:       hostname,
		MachineID:      machineID,
		AgentVersion:   version.Version,
	}

	// Send to server
	httpClient := client.New(cfgManager, logger)
	sendCtx, sendCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer sendCancel()

	response, err := httpClient.SendComplianceData(sendCtx, payload)
	if err != nil {
		sendComplianceProgress("failed", profileName, "Failed to send results", 0, err.Error())
		return fmt.Errorf("failed to send compliance data: %w", err)
	}

	// Send progress: completed with score
	score := float64(0)
	if len(complianceData.Scans) > 0 {
		score = complianceData.Scans[0].Score
	}
	completedMsg := fmt.Sprintf("Scan completed! Score: %.1f%%", score)
	sendComplianceProgress("completed", profileName, completedMsg, 100, "")

	logFields := map[string]interface{}{
		"scans_received": response.ScansReceived,
		"message":        response.Message,
	}
	if options.EnableRemediation {
		logFields["remediation_enabled"] = true
	}
	logger.WithFields(logFields).Info("On-demand compliance scan results sent to server")

	return nil
}
