package ddosprotection

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/czerwonk/junos_exporter/pkg/collector"
)

const prefix string = "junos_ddos_protection_"

var (
	agpBandwidth                      *prometheus.Desc
	agpBurst                          *prometheus.Desc
	agpRecoverTime                    *prometheus.Desc
	agpEnabled                        *prometheus.Desc
	swiViolated                       *prometheus.Desc
	swiReceived                       *prometheus.Desc
	swiDropped                        *prometheus.Desc
	swiArrivalRate                    *prometheus.Desc
	swiMaxArrivalRate                 *prometheus.Desc
	reiBandwidth                      *prometheus.Desc
	reiBurst                          *prometheus.Desc
	reiEnabled                        *prometheus.Desc
	reiViolated                       *prometheus.Desc
	reiReceived                       *prometheus.Desc
	reiDropped                        *prometheus.Desc
	reiArrivalRate                    *prometheus.Desc
	reiMaxArrivalRate                 *prometheus.Desc
	reiDroppedIndividualPolicers      *prometheus.Desc
	fpcBandwidth                      *prometheus.Desc
	fpcBurst                          *prometheus.Desc
	fpcEnabled                        *prometheus.Desc
	fpcHostboundQueue                 *prometheus.Desc
	fpcViolated                       *prometheus.Desc
	fpcReceived                       *prometheus.Desc
	fpcDropped                        *prometheus.Desc
	fpcArrivalRate                    *prometheus.Desc
	fpcMaxArrivalRate                 *prometheus.Desc
	fpcDroppedIndividualPolicers      *prometheus.Desc
	fpcDroppedFlowSuppression         *prometheus.Desc
	ipcBandwidth                      *prometheus.Desc
	ipcBurst                          *prometheus.Desc
	ipcPriority                       *prometheus.Desc
	ipcRecoverTime                    *prometheus.Desc
	ipcEnabled                        *prometheus.Desc
	ipcBypassAggregate                *prometheus.Desc
	fdcStatus                         *prometheus.Desc
	fdcDetectionMode                  *prometheus.Desc
	fdcDetectTime                     *prometheus.Desc
	fdcRecoverTime                    *prometheus.Desc
	fdcTimeoutTime                    *prometheus.Desc
	fdcFALAggLevelSubscriberDM        *prometheus.Desc
	fdcFALAggLevelSubscriberCM        *prometheus.Desc
	fdcFALAggLevelSubscriberFR        *prometheus.Desc
	fdcFALAggLevelLogicalInterfaceDM  *prometheus.Desc
	fdcFALAggLevelLogicalInterfaceCM  *prometheus.Desc
	fdcFALAggLevelLogicalInterfaceFR  *prometheus.Desc
	fdcFALAggLevelPhysicalInterfaceDM *prometheus.Desc
	fdcFALAggLevelPhysicalInterfaceCM *prometheus.Desc
	fdcFALAggLevelPhysicalInterfaceFR *prometheus.Desc
)

func init() {
	l := []string{"target", "protocol_group"}
	agpBandwidth = prometheus.NewDesc(prefix+"agp_bandwidth", "aggregate policer configuration bandwidth", l, nil)
	agpBurst = prometheus.NewDesc(prefix+"agp_burst", "aggregate policer configuration burst", l, nil)
	agpRecoverTime = prometheus.NewDesc(prefix+"agp_recover_time", "aggregate policer configuration recover time", l, nil)
	agpEnabled = prometheus.NewDesc(prefix+"agp_enabled", "aggregate policer configuration state (0 = DISABLED, 1 = ENABLED)", l, nil)
	swiViolated = prometheus.NewDesc(prefix+"swi_violated", "system wide information violated ( 1 = NEVER)", l, nil)
	swiReceived = prometheus.NewDesc(prefix+"swi_received", "system wide information received", l, nil)
	swiDropped = prometheus.NewDesc(prefix+"swi_dropped", "system wide information dropped", l, nil)
	swiArrivalRate = prometheus.NewDesc(prefix+"swi_arrival_rate", "system wide information arrival rate in pps", l, nil)
	swiMaxArrivalRate = prometheus.NewDesc(prefix+"swi_max_arrival_rate", "system wide information max arrival rate in pps", l, nil)
	l = append(l, "instance")
	reiBandwidth = prometheus.NewDesc(prefix+"rei_bandwidth", "routing engine information bandwidth", l, nil)
	reiBurst = prometheus.NewDesc(prefix+"rei_burst", "routing engine information burst", l, nil)
	reiEnabled = prometheus.NewDesc(prefix+"rei_enabled", "routing engine information state(0 = DISABLED, 1 = ENABLED)", l, nil)
	reiViolated = prometheus.NewDesc(prefix+"rei_violated", "routing engine information violated ( 1 = NEVER)", l, nil)
	reiReceived = prometheus.NewDesc(prefix+"rei_received", "routing engine information received", l, nil)
	reiDropped = prometheus.NewDesc(prefix+"rei_dropped", "routing engine information dropped", l, nil)
	reiArrivalRate = prometheus.NewDesc(prefix+"rei_arrival_rate", "routing engine information arrival rate in pps", l, nil)
	reiMaxArrivalRate = prometheus.NewDesc(prefix+"rei_max_arrival_rate", "routing engine information max arrival rate in pps ", l, nil)
	reiDroppedIndividualPolicers = prometheus.NewDesc(prefix+"rei_dropped_individual_policers", "routing engine information dropped by individual policers", l, nil)
	fpcBandwidth = prometheus.NewDesc(prefix+"fpc_bandwidth", "fpc bandwidth in %", l, nil)
	fpcBurst = prometheus.NewDesc(prefix+"fpc_burst", "fpc burst in %", l, nil)
	fpcEnabled = prometheus.NewDesc(prefix+"fpc_enabled", "fpc state (0 = DISABLED, 1 = ENABLED", l, nil)
	fpcHostboundQueue = prometheus.NewDesc(prefix+"fpc_hostbound_queue", "fpc hostbound queue", l, nil)
	fpcViolated = prometheus.NewDesc(prefix+"fpc_violated", "fpc violated (1 = NEVER)", l, nil)
	fpcReceived = prometheus.NewDesc(prefix+"fpc_received", "fpc received", l, nil)
	fpcDropped = prometheus.NewDesc(prefix+"fpc_dropped", "fpc dropped", l, nil)
	fpcArrivalRate = prometheus.NewDesc(prefix+"fpc_arrival_rate", "fpc arrival rate in pps ", l, nil)
	fpcMaxArrivalRate = prometheus.NewDesc(prefix+"fpc_max_arrival_rate", "fpc max arrival rate in pps ", l, nil)
	fpcDroppedIndividualPolicers = prometheus.NewDesc(prefix+"fpc_dropped_individual_policers", "fpc dropped by individual policers", l, nil)
	fpcDroppedFlowSuppression = prometheus.NewDesc(prefix+"fpc_dropped_flow_suppresion", "fpc dropped by flow suppression", l, nil)
	ipcBandwidth = prometheus.NewDesc(prefix+"ipc_bandwidth", "individual policer configuration bandwidth in pps", l, nil)
	ipcBurst = prometheus.NewDesc(prefix+"ipc_burst", "individual policer configuration burst in packets", l, nil)
	ipcPriority = prometheus.NewDesc(prefix+"ipc_priority", "individual policer configuration priority (1 = LOW, 2 = MEDIUM, 3 = HIGH, 0 = UNKNOWN)", l, nil)
	ipcRecoverTime = prometheus.NewDesc(prefix+"ipc_recover_time", "individual policer configuration recover time in seconds", l, nil)
	ipcEnabled = prometheus.NewDesc(prefix+"ipc_enabled", "individual policer configuration state ( 0 = DISABLED, 1 = ENABLED)", l, nil)
	ipcBypassAggregate = prometheus.NewDesc(prefix+"ipc_bypass_aggregate", "individual policer configuration bypass aggregate (0 = NO, 1 = YES)", l, nil)
	fdcStatus = prometheus.NewDesc(prefix+"fdc_status", "flow detection configuration state ( 0 = OFF, 1 = ON)", l, nil)
	fdcDetectionMode = prometheus.NewDesc(prefix+"fdc_detection_mode", "flow detection configuration detection mode (0 = AUTOMATIC)", l, nil)
	fdcDetectTime = prometheus.NewDesc(prefix+"fdc_detect_time", "flow detection configuration detect time in seconds", l, nil)
	fdcRecoverTime = prometheus.NewDesc(prefix+"fdc_recover_time", "flow detection configuration recover time in seconds", l, nil)
	fdcTimeoutTime = prometheus.NewDesc(prefix+"fdc_timeout_time", "flow detection configuration timeout time in seconds", l, nil)
	fdcFALAggLevelSubscriberDM = prometheus.NewDesc(prefix+"fdc_fal_agg_level_subscriber_dm", "flow detection configuration flow aggregation level subscriber direction mode", l, nil)
	fdcFALAggLevelSubscriberCM = prometheus.NewDesc(prefix+"fdc_fal_agg_level_subscriber_cm", "flow detection configuration flow aggregation level subscriber control mode", l, nil)
	fdcFALAggLevelSubscriberFR = prometheus.NewDesc(prefix+"fdc_fal_agg_level_subscriber_fr", "flow detection configuration flow aggregation level subscriber flow rate", l, nil)
	fdcFALAggLevelLogicalInterfaceDM = prometheus.NewDesc(prefix+"fdc_fal_agg_level_logical_interface_dm", "flow detection configuration flow aggregation level logical interface direction mode", l, nil)
	fdcFALAggLevelLogicalInterfaceCM = prometheus.NewDesc(prefix+"fdc_fal_agg_level_logical_interface_cm", "flow detection configuration flow aggregation level logical interface control mode", l, nil)
	fdcFALAggLevelLogicalInterfaceFR = prometheus.NewDesc(prefix+"fdc_fal_agg_level_logical_interface_fr", "flow detection configuration flow aggregation level logical interface flow rate", l, nil)
	fdcFALAggLevelPhysicalInterfaceDM = prometheus.NewDesc(prefix+"fdc_fal_agg_level_physical_interface_dm", "flow detection configuration flow aggregation level physical interface direction mode", l, nil)
	fdcFALAggLevelPhysicalInterfaceCM = prometheus.NewDesc(prefix+"fdc_fal_agg_level_physical_interface_cm", "flow detection configuration flow aggregation level physical interface control mode", l, nil)
	fdcFALAggLevelPhysicalInterfaceFR = prometheus.NewDesc(prefix+"fdc_fal_agg_level_physical_interface_fr", "flow detection configuration flow aggregation level physical interface flow rate", l, nil)
}

type ddosCollector struct{}

func NewCollector() collector.RPCCollector { return &ddosCollector{} }

func (c *ddosCollector) Name() string {
	return "ddos"
}

func (c *ddosCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- agpBandwidth
	ch <- agpBurst
	ch <- agpRecoverTime
	ch <- agpEnabled
	ch <- swiViolated
	ch <- swiReceived
	ch <- swiDropped
	ch <- swiArrivalRate
	ch <- swiMaxArrivalRate
	ch <- reiBandwidth
	ch <- reiBurst
	ch <- reiEnabled
	ch <- reiViolated
	ch <- reiReceived
	ch <- reiDropped
	ch <- reiArrivalRate
	ch <- reiMaxArrivalRate
	ch <- reiDroppedIndividualPolicers
	ch <- fpcBandwidth
	ch <- fpcBurst
	ch <- fpcEnabled
	ch <- fpcHostboundQueue
	ch <- fpcViolated
	ch <- fpcReceived
	ch <- fpcDropped
	ch <- fpcArrivalRate
	ch <- fpcMaxArrivalRate
	ch <- fpcDroppedIndividualPolicers
	ch <- fpcDroppedFlowSuppression
	ch <- ipcBandwidth
	ch <- ipcBurst
	ch <- ipcPriority
	ch <- ipcRecoverTime
	ch <- ipcEnabled
	ch <- ipcBypassAggregate
	ch <- fdcStatus
	ch <- fdcDetectionMode
	ch <- fdcDetectTime
	ch <- fdcRecoverTime
	ch <- fdcTimeoutTime
	ch <- fdcFALAggLevelSubscriberDM
	ch <- fdcFALAggLevelSubscriberCM
	ch <- fdcFALAggLevelSubscriberFR
	ch <- fdcFALAggLevelLogicalInterfaceDM
	ch <- fdcFALAggLevelLogicalInterfaceCM
	ch <- fdcFALAggLevelLogicalInterfaceFR
	ch <- fdcFALAggLevelPhysicalInterfaceDM
	ch <- fdcFALAggLevelPhysicalInterfaceCM
	ch <- fdcFALAggLevelPhysicalInterfaceFR

}

func (c *ddosCollector) Collect(client collector.Client, ch chan<- prometheus.Metric, labelValues []string) error {
	var i results
	err := client.RunCommandAndParse("show ddos-protection protocols", &i)
	if err != nil {
		return errors.Wrap(err, "failed to run command 'show ddos-protection protocols'")
	}
	c.collectForProtocols(i, ch, labelValues)
	return nil
}

// collectForProtocols collects metrics for specified DDoS protocol groups and sends them to the Prometheus metrics channel.
// It iterates through DDoS protocol groups and individual protocols to extract and process bandwidth data for metrics.
// Metrics are created with appropriate labels and pushed to the provided Prometheus metrics channel.
func (c *ddosCollector) collectForProtocols(protocols results, ch chan<- prometheus.Metric, labelValues []string) {
	for _, protocol := range protocols.DdosProtocolsInformation.DdosProtocolGroup {
		groupLabelValues := append(labelValues, protocol.GroupName) // Use a new slice for each group
		for _, packet := range protocol.DdosProtocol {
			bw := convertDifferentStringsToFloat(packet.DdosBasicParameters.PolicerBandwidth)
			if bw != 0.0000000000001 {
				ch <- prometheus.MustNewConstMetric(agpBandwidth, prometheus.GaugeValue, bw, groupLabelValues...)
			}
			burst := convertDifferentStringsToFloat(packet.DdosBasicParameters.PolicerBurst)
			if burst != 0.0000000000001 {
				ch <- prometheus.MustNewConstMetric(agpBurst, prometheus.GaugeValue, burst, groupLabelValues...)
			}
			recoverTime := convertDifferentStringsToFloat(packet.DdosBasicParameters.PolicerTimeRecover)
			if recoverTime != 0.0000000000001 {
				ch <- prometheus.MustNewConstMetric(agpRecoverTime, prometheus.GaugeValue, recoverTime, groupLabelValues...)
			}
			enabled := turnEnabledIntoFloat(packet.DdosBasicParameters.PolicerEnable)
			ch <- prometheus.MustNewConstMetric(agpEnabled, prometheus.GaugeValue, enabled, groupLabelValues...)
			if packet.DdosSystemStatistics.PolicerViolationCount != "" {
				fmt.Printf("FPC Violation Count %s \n", packet.DdosSystemStatistics.PolicerViolationCount)
				violator := convertDifferentStringsToFloat(packet.DdosSystemStatistics.PolicerViolationCount)
				ch <- prometheus.MustNewConstMetric(swiViolated, prometheus.GaugeValue, violator, groupLabelValues...)
			}
			received := convertDifferentStringsToFloat(packet.DdosSystemStatistics.PacketReceived)
			if received != 0.0000000000001 {
				ch <- prometheus.MustNewConstMetric(swiReceived, prometheus.GaugeValue, received, groupLabelValues...)
			}
			dropped := convertDifferentStringsToFloat(packet.DdosSystemStatistics.PacketDropped)
			if dropped != 0.0000000000001 {
				ch <- prometheus.MustNewConstMetric(swiDropped, prometheus.GaugeValue, dropped, groupLabelValues...)
			}
			arrivalRate := convertDifferentStringsToFloat(packet.DdosSystemStatistics.PacketArrivalRate)
			if arrivalRate != 0.0000000000001 {
				ch <- prometheus.MustNewConstMetric(swiArrivalRate, prometheus.GaugeValue, arrivalRate, groupLabelValues...)
			}
			maxArrivalRate := convertDifferentStringsToFloat(packet.DdosSystemStatistics.PacketArrivalRateMax)
			if maxArrivalRate != 0.0000000000001 {
				ch <- prometheus.MustNewConstMetric(swiMaxArrivalRate, prometheus.GaugeValue, maxArrivalRate, groupLabelValues...)
			}
			fmt.Printf("packet is is %+v\\n", packet)
			for _, instance := range packet.DdosInstance {
				instance.Text = "AAA"
				/*groupLabelValues = append(groupLabelValues, instance.ProtocolStatesLocale)

				if strings.Contains(strings.ToLower(instance.ProtocolStatesLocale), "Routing Engine") {
					bw := convertDifferentStringsToFloat(instance.DdosInstanceParameters.PolicerBandwidth)
					if bw != 0.0000000000001 {
						ch <- prometheus.MustNewConstMetric(reiBandwidth, prometheus.GaugeValue, bw, groupLabelValues...)
					}
					burst := convertDifferentStringsToFloat(instance.DdosInstanceParameters.PolicerBurst)
					if burst != 0.0000000000001 {
						ch <- prometheus.MustNewConstMetric(reiBurst, prometheus.GaugeValue, burst, groupLabelValues...)
					}
					enabled := turnEnabledIntoFloat(instance.DdosInstanceParameters.PolicerEnable)
					ch <- prometheus.MustNewConstMetric(reiEnabled, prometheus.GaugeValue, enabled, groupLabelValues...)
					//violated := checkViolated(instance.DdosInstanceParameters.)

				} */
				//fmt.Printf("Instance style is  %s \n", instance.Style)
				//fmt.Printf("Instance name1 is %s ", instance.DdosInstanceStatistics)
				//fmt.Printf("Instance name2 is %s ", instance.DdosInstanceStatistics.Style)
				//fmt.Printf("Instance name3 is %+v\\n", instance)
				//fmt.Printf("Instance name4 is %s ", instance.DdosInstanceParameters.Style)

				//bw := convertDifferentStringsToFloat(instance.ProtocolStatesLocale)
			}
		}
	}
}

func convertDifferentStringsToFloat(value string) float64 {
	parsed := strings.TrimSuffix(value, " bps")
	parsed = strings.TrimSuffix(parsed, " packets")
	parsed = strings.TrimSuffix(parsed, " seconds")
	parsed = strings.TrimSuffix(parsed, " pps")
	number, err := strconv.Atoi(parsed)
	if err != nil {
		fmt.Println("Error:", err)
		//@Oli - how to properly signal that there was an error parsing the data ?
		return 0.0000000000001
	}
	return float64(number)
}

func turnEnabledIntoFloat(value string) float64 {
	if strings.ToLower(value) == "yes" {
		return 1.0
	}
	return 0.0
}

func checkViolated(value string) float64 {
	if strings.Contains(strings.ToLower(value), "is never violated") {
		return 1
	}
	return 0
}
