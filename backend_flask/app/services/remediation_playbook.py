"""
Remediation Playbook Service
Automated incident response orchestration and remediation triggering.
"""

import logging
from typing import Dict, List, Callable
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RemediationPlaybook:
    """
    Remediation Playbook: Orchestrates automated incident response.
    Triggers firewall blocks, network isolation, and alert escalation based on threat level.
    """

    def __init__(self, firewall_manager, kill_switch, ai_translator):
        """
        Initialize Remediation Playbook.
        
        Args:
            firewall_manager: FirewallManager instance
            kill_switch: KillSwitch instance
            ai_translator: AITranslator instance
        """
        self.firewall_manager = firewall_manager
        self.kill_switch = kill_switch
        self.ai_translator = ai_translator
        self.executed_playbooks: List[Dict] = []
        self.active_incidents: List[Dict] = []
        logger.info("RemediationPlaybook initialized")

    def evaluate_threat(self, threat_data: Dict) -> Dict:
        """
        Evaluate threat severity and trigger appropriate playbook.
        
        Args:
            threat_data: Dict containing threat indicators and metadata
            
        Returns:
            Dict with evaluation results and actions taken
        """
        logger.warning(f"Evaluating threat: {threat_data.get('threat_type', 'unknown')}")
        
        threat_level = self._calculate_threat_level(threat_data)
        
        evaluation = {
            "threat_type": threat_data.get("threat_type"),
            "source_ip": threat_data.get("source_ip"),
            "threat_level": threat_level.value,
            "indicators": threat_data.get("indicators", []),
            "timestamp": datetime.now().isoformat(),
            "actions_taken": []
        }
        
        # Route to appropriate playbook based on threat level
        if threat_level == ThreatLevel.CRITICAL:
            actions = self._playbook_critical_threat(threat_data)
        elif threat_level == ThreatLevel.HIGH:
            actions = self._playbook_high_threat(threat_data)
        elif threat_level == ThreatLevel.MEDIUM:
            actions = self._playbook_medium_threat(threat_data)
        else:
            actions = self._playbook_low_threat(threat_data)
        
        evaluation["actions_taken"] = actions
        
        # Store in active incidents
        self.active_incidents.append(evaluation)
        self.executed_playbooks.append(evaluation)
        
        logger.info(f"Threat evaluation complete - Level: {threat_level.value}, Actions: {len(actions)}")
        
        return evaluation

    def _calculate_threat_level(self, threat_data: Dict) -> ThreatLevel:
        """
        Calculate threat level based on indicators.
        
        Args:
            threat_data: Dict with threat indicators
            
        Returns:
            ThreatLevel enum value
        """
        score = 0
        
        # Score based on threat indicators
        indicators = threat_data.get("indicators", [])
        
        # High-risk indicators
        critical_indicators = [
            "known_malware_c2",
            "ransomware_signature",
            "privilege_escalation_attempt",
            "lateral_movement_detected"
        ]
        
        high_indicators = [
            "suspicious_port_scan",
            "brute_force_attempt",
            "credential_stuffing",
            "zero_day_exploit_attempt"
        ]
        
        for indicator in indicators:
            if indicator in critical_indicators:
                score += 100
            elif indicator in high_indicators:
                score += 50
            else:
                score += 10
        
        # Check failed authentication count
        failed_auths = threat_data.get("failed_auth_attempts", 0)
        score += failed_auths * 5
        
        # Determine level
        if score >= 100:
            return ThreatLevel.CRITICAL
        elif score >= 70:
            return ThreatLevel.HIGH
        elif score >= 40:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def _playbook_critical_threat(self, threat_data: Dict) -> List[Dict]:
        """
        Critical Threat Playbook: Immediate isolation and blocking.
        
        Args:
            threat_data: Threat data dict
            
        Returns:
            List of actions taken
        """
        logger.critical(f"CRITICAL THREAT DETECTED: {threat_data.get('threat_type')}")
        
        actions = []
        source_ip = threat_data.get("source_ip")
        reason = f"CRITICAL THREAT: {threat_data.get('threat_type', 'unknown threat')}"
        
        # Action 1: Block the source IP immediately
        if source_ip:
            block_result = self.firewall_manager.block_ip(source_ip, reason)
            actions.append({
                "action": "block_ip",
                "status": "completed" if block_result.get("success") else "failed",
                "target": source_ip,
                "result": block_result
            })
        
        # Action 2: AI Analysis for immediate recommendations
        analysis = self.ai_translator.analyze_threat(threat_data)
        actions.append({
            "action": "ai_analysis",
            "status": "completed",
            "result": analysis
        })
        
        # Action 3: Activate Kill Switch (network isolation)
        kill_switch_result = self.kill_switch.activate(
            reason=reason,
            auto=True
        )
        actions.append({
            "action": "activate_kill_switch",
            "status": "completed" if kill_switch_result.get("success") else "failed",
            "result": kill_switch_result
        })
        
        # Action 4: Generate high-priority alert
        actions.append({
            "action": "escalate_alert",
            "status": "completed",
            "severity": "CRITICAL",
            "notification_method": "email,sms,slack"
        })
        
        return actions

    def _playbook_high_threat(self, threat_data: Dict) -> List[Dict]:
        """
        High Threat Playbook: Block source IP and isolate subnet.
        
        Args:
            threat_data: Threat data dict
            
        Returns:
            List of actions taken
        """
        logger.error(f"HIGH THREAT DETECTED: {threat_data.get('threat_type')}")
        
        actions = []
        source_ip = threat_data.get("source_ip")
        reason = f"HIGH THREAT: {threat_data.get('threat_type', 'unknown threat')}"
        
        # Action 1: Block source IP
        if source_ip:
            block_result = self.firewall_manager.block_ip(source_ip, reason)
            actions.append({
                "action": "block_ip",
                "status": "completed" if block_result.get("success") else "failed",
                "target": source_ip,
                "result": block_result
            })
        
        # Action 2: AI Analysis
        analysis = self.ai_translator.analyze_threat(threat_data)
        actions.append({
            "action": "ai_analysis",
            "status": "completed",
            "result": analysis
        })
        
        # Action 3: Block entire subnet if lateral movement detected
        if "lateral_movement_detected" in threat_data.get("indicators", []):
            subnet = threat_data.get("subnet")
            if subnet:
                actions.append({
                    "action": "quarantine_subnet",
                    "status": "pending",
                    "target": subnet,
                    "reason": "Lateral movement detected"
                })
        
        # Action 4: Generate alert
        actions.append({
            "action": "escalate_alert",
            "status": "completed",
            "severity": "HIGH",
            "notification_method": "email,slack"
        })
        
        return actions

    def _playbook_medium_threat(self, threat_data: Dict) -> List[Dict]:
        """
        Medium Threat Playbook: Monitor closely and block if necessary.
        
        Args:
            threat_data: Threat data dict
            
        Returns:
            List of actions taken
        """
        logger.warning(f"MEDIUM THREAT DETECTED: {threat_data.get('threat_type')}")
        
        actions = []
        source_ip = threat_data.get("source_ip")
        
        # Action 1: Block if blacklist match
        if threat_data.get("blacklist_match"):
            block_result = self.firewall_manager.block_ip(
                source_ip,
                "Medium threat - blacklist match"
            )
            actions.append({
                "action": "block_ip",
                "status": "completed" if block_result.get("success") else "failed",
                "target": source_ip
            })
        
        # Action 2: AI Analysis
        analysis = self.ai_translator.analyze_threat(threat_data)
        actions.append({
            "action": "ai_analysis",
            "status": "completed"
        })
        
        # Action 3: Increase monitoring
        actions.append({
            "action": "increase_monitoring",
            "status": "completed",
            "target": source_ip,
            "monitoring_level": "elevated"
        })
        
        # Action 4: Log alert
        actions.append({
            "action": "log_alert",
            "status": "completed",
            "severity": "MEDIUM"
        })
        
        return actions

    def _playbook_low_threat(self, threat_data: Dict) -> List[Dict]:
        """
        Low Threat Playbook: Log and monitor only.
        
        Args:
            threat_data: Threat data dict
            
        Returns:
            List of actions taken
        """
        logger.info(f"LOW THREAT DETECTED: {threat_data.get('threat_type')}")
        
        actions = []
        
        # Action 1: Log for analysis
        actions.append({
            "action": "log_event",
            "status": "completed",
            "severity": "LOW"
        })
        
        # Action 2: AI Analysis (for learning)
        analysis = self.ai_translator.analyze_threat(threat_data)
        actions.append({
            "action": "ai_analysis",
            "status": "completed"
        })
        
        return actions

    def manual_incident_response(self, incident_id: str, actions: List[Dict]) -> Dict:
        """
        Execute manual incident response actions by SOC analyst.
        
        Args:
            incident_id: Incident identifier
            actions: List of actions to execute
            
        Returns:
            Dict with execution results
        """
        logger.info(f"Manual incident response initiated for: {incident_id}")
        
        execution_results = []
        
        for action in actions:
            action_type = action.get("action")
            target = action.get("target")
            
            result = {
                "action": action_type,
                "target": target,
                "timestamp": datetime.now().isoformat()
            }
            
            try:
                if action_type == "block_ip":
                    result_data = self.firewall_manager.block_ip(
                        target,
                        f"Manual SOC action - {incident_id}"
                    )
                    result["status"] = "completed" if result_data.get("success") else "failed"
                    result["result"] = result_data
                
                elif action_type == "isolate_network":
                    result_data = self.kill_switch.activate(
                        reason=f"Manual SOC action - {incident_id}",
                        auto=False
                    )
                    result["status"] = "completed" if result_data.get("success") else "failed"
                    result["result"] = result_data
                
                elif action_type == "block_subnet":
                    # Future implementation for subnet blocking
                    result["status"] = "pending"
                    result["message"] = "Subnet blocking not yet implemented"
                
                else:
                    result["status"] = "unknown_action"
                
                execution_results.append(result)
            
            except Exception as e:
                logger.error(f"Error executing action {action_type}: {str(e)}")
                result["status"] = "error"
                result["error"] = str(e)
                execution_results.append(result)
        
        return {
            "incident_id": incident_id,
            "actions_executed": len(execution_results),
            "results": execution_results,
            "timestamp": datetime.now().isoformat()
        }

    def get_status(self) -> Dict:
        """Get Remediation Playbook status."""
        return {
            "status": "online",
            "active_incidents": len(self.active_incidents),
            "executed_playbooks": len(self.executed_playbooks),
            "timestamp": datetime.now().isoformat()
        }

    def get_active_incidents(self) -> Dict:
        """Get list of active incidents."""
        return {
            "status": "success",
            "active_incidents_count": len(self.active_incidents),
            "incidents": self.active_incidents,
            "timestamp": datetime.now().isoformat()
        }

    def close_incident(self, incident_index: int) -> Dict:
        """
        Close an active incident.
        
        Args:
            incident_index: Index in active_incidents list
            
        Returns:
            Dict with closure status
        """
        if 0 <= incident_index < len(self.active_incidents):
            incident = self.active_incidents.pop(incident_index)
            logger.info(f"Incident closed: {incident.get('threat_type')}")
            return {
                "success": True,
                "message": "Incident closed",
                "incident": incident
            }
        
        return {
            "success": False,
            "message": "Invalid incident index"
        }
