package ddosprotection

import (
	//"crypto/dsa"
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/czerwonk/junos_exporter/pkg/collector"
)

const prefix string = "junos_ddos_protection_"

var (
	totalPacketsTypes                *prometheus.Desc
	packetTypesReceivedPackets       *prometheus.Desc
	packetTypesInViolations          *prometheus.Desc
	systemPacketsReceived            *prometheus.Desc
	systemPacketsArrivalRate         *prometheus.Desc
	systemPacketsDropped             *prometheus.Desc
	systemPacketsArrivalRateMax      *prometheus.Desc
	instancePacketsReceived          *prometheus.Desc
	instancePacketsArrivalRate       *prometheus.Desc
	instancePacketsDropped           *prometheus.Desc
	instancePacketsArrivalRateMax    *prometheus.Desc
	instancePacketsDroppedOthers     *prometheus.Desc
	instancePacketsDroppedFlows      *prometheus.Desc
	parTotalPacketsTypes             *prometheus.Desc
	parTotalModified                 *prometheus.Desc
	parBasicPolicerBandwidth         *prometheus.Desc
	parBasicPolicerBurst             *prometheus.Desc
	parBasicPolicerTimeRecover       *prometheus.Desc
	parBasicPolicerEnable            *prometheus.Desc
	parBasicPolicerPriority          *prometheus.Desc
	parBasicBypassAggregate          *prometheus.Desc
	parInstancePolicerBandwidth      *prometheus.Desc
	parInstancePolicerBurst          *prometheus.Desc
	parInstancePolicerEnable         *prometheus.Desc
	parInstancePolicerBandwidthScale *prometheus.Desc
	parInstancePolicerBusrstScale    *prometheus.Desc
	parInstanceHostboundQueue        *prometheus.Desc
)

func init() {
	l := []string{"target"}
	totalPacketsTypes = prometheus.NewDesc(prefix+"statistics_total_packet_types", "[statistics]total amount of packet types for device", l, nil)
	packetTypesReceivedPackets = prometheus.NewDesc(prefix+"statistics_total_received_traffic", "[statistics]total packet types received packets", l, nil)
	packetTypesInViolations = prometheus.NewDesc(prefix+"statistics_total_packets_in_violations", "[statistics]total packet types in violations", l, nil)
	l = append(l, "protocol_group_name", "protocol_packet_type")
	systemPacketsReceived = prometheus.NewDesc(prefix+"statistics_system_wide_packets_received", "[statistics]total number of packets received", l, nil)
	systemPacketsArrivalRate = prometheus.NewDesc(prefix+"statistics_system_wide_packets_arrival_rate", "[statistics]total packets arrival rate", l, nil)
	systemPacketsDropped = prometheus.NewDesc(prefix+"statistics_system_wide_packets_dropped", "[statistics]total number of packets dropped", l, nil)
	systemPacketsArrivalRateMax = prometheus.NewDesc(prefix+"statistics_system_wide_packets_arrival_rate_max", "[statistics]total packets arrival rate max", l, nil)
	l = append(l, "instance")
	instancePacketsReceived = prometheus.NewDesc(prefix+"statistics_instance_packets_received", "[statistics]number of packets received on an instance", l, nil)
	instancePacketsArrivalRate = prometheus.NewDesc(prefix+"statistics_instance_packets_arrival_rate", "[statistics]packets arrival rate on an instance", l, nil)
	instancePacketsDropped = prometheus.NewDesc(prefix+"statistics_instance_packets_dropped", "[statistics]number of packets dropped on an instance", l, nil)
	instancePacketsArrivalRateMax = prometheus.NewDesc(prefix+"statistics_instance_packets_arrival_max_rate", "[statistics]packets arrival rate max on an instance", l, nil)
	instancePacketsDroppedOthers = prometheus.NewDesc(prefix+"statistics_instance_other_packets_dropped", "[statistics]number of packets dropped by individual policers on an instance", l, nil)
	instancePacketsDroppedFlows = prometheus.NewDesc(prefix+"statistics_instance_flows_dropped", "[statistics]number of packets dropped by flow suppression on an instance", l, nil)
	l = []string{"target"}
	parTotalPacketsTypes = prometheus.NewDesc(prefix+"parameters_total_packets_types", "[parameters]total amount of packet types for device", l, nil)
	parTotalModified = prometheus.NewDesc(prefix+"parameters_total_packets_modified", "[parameters]total amount of modified packet types for device", l, nil)
	l = append(l, "protocol_group_name", "protocol_packet_type")
	parBasicPolicerBandwidth = prometheus.NewDesc(prefix+"parameters_basic_policer_bandwidth", "[parameters]basic policer bandwidth", l, nil)
	parBasicPolicerBurst = prometheus.NewDesc(prefix+"parameters_basic_policer_burst", "[parameters]basic policer burst", l, nil)
	parBasicPolicerTimeRecover = prometheus.NewDesc(prefix+"parameters_basic_policer_time_recover", "[parameters]basic policer time recover", l, nil)
	parBasicPolicerEnable = prometheus.NewDesc(prefix+"parameters_basic_policer_enable", "[parameters]basic policer enable. 2.0 - YES, 1.0 - NO or DISABLED, 0.0 - UNKNOWN", l, nil)
	parBasicPolicerPriority = prometheus.NewDesc(prefix+"parameters_basic_policer_priority", "[parameters]basic policer priority. LOW - 1.0, MIDDLE - 2.0, HIGH - 3.0, VERY HIGH - 4.0, UNKNOWN - 0.0", l, nil)
	parBasicBypassAggregate = prometheus.NewDesc(prefix+"parameters_basic_bypass_aggregate", "[parameters]basic bypass aggregate. YES - 2.0, NO - 1.0", l, nil)
	l = append(l, "instance")
	parInstancePolicerBandwidth = prometheus.NewDesc(prefix+"parameters_instance_policer_bandwidth", "[parameters]instance policer bandwidth", l, nil)
	parInstancePolicerBurst = prometheus.NewDesc(prefix+"parameters_instance_policer_burst", "[parameters]instance policer burst", l, nil)
	parInstancePolicerEnable = prometheus.NewDesc(prefix+"parameters_instance_policer_enable", "[parameters]instance policer enable", l, nil)
	parInstancePolicerBandwidthScale = prometheus.NewDesc(prefix+"parameters_instance_policer_bandwidth_scale", "[parameters]instance policer bandwidth scale", l, nil)
	parInstancePolicerBusrstScale = prometheus.NewDesc(prefix+"parameters_instance_policer_burst_scale", "[parameters]instance policer burst scale", l, nil)
	parInstanceHostboundQueue = prometheus.NewDesc(prefix+"parameters_instance_hostbound_queue", "[parameters]instance hostbound queue", l, nil)
}

type ddosCollector struct{}

func NewCollector() collector.RPCCollector { return &ddosCollector{} }

func (c *ddosCollector) Name() string {
	return "ddos"
}

func (c *ddosCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- totalPacketsTypes
	ch <- packetTypesReceivedPackets
	ch <- packetTypesInViolations
	ch <- systemPacketsReceived
	ch <- systemPacketsArrivalRate
	ch <- systemPacketsDropped
	ch <- systemPacketsArrivalRateMax
	ch <- instancePacketsReceived
	ch <- instancePacketsArrivalRate
	ch <- instancePacketsDropped
	ch <- instancePacketsArrivalRateMax
	ch <- instancePacketsDroppedOthers
	ch <- instancePacketsDroppedFlows
	ch <- parTotalPacketsTypes
	ch <- parTotalModified
	ch <- parBasicPolicerBandwidth
	ch <- parBasicPolicerBurst
	ch <- parBasicPolicerTimeRecover
	ch <- parBasicPolicerEnable
	ch <- parBasicPolicerPriority
	ch <- parBasicBypassAggregate
	ch <- parInstancePolicerBandwidth
	ch <- parInstancePolicerBurst
	ch <- parInstancePolicerEnable
	ch <- parInstancePolicerBandwidthScale
	ch <- parInstancePolicerBusrstScale
	ch <- parInstanceHostboundQueue
}
func (c *ddosCollector) Collect(client collector.Client, ch chan<- prometheus.Metric, labelValues []string) error {
	var s statistics
	err := client.RunCommandAndParse("show ddos-protection protocols statistics", &s)
	if err != nil {
		return errors.Wrap(err, "failed to run command 'show ddos-protection protocols statistics'")
	}
	//c.collectStatistics(s, ch, labelValues)
	var p parameters
	err = client.RunCommandAndParse("show ddos-protection protocols parameters", &p)
	if err != nil {
		return errors.Wrap(err, "failed to run command 'show ddos-protection protocols parameters'")
	}
	c.collectParameters(p, ch, labelValues)
	return nil
}

func (c *ddosCollector) collectStatistics(s statistics, ch chan<- prometheus.Metric, labelValues []string) {
	ch <- prometheus.MustNewConstMetric(totalPacketsTypes, prometheus.GaugeValue, s.DdosProtocolsInformation.TotalPacketTypes, labelValues...)
	ch <- prometheus.MustNewConstMetric(packetTypesReceivedPackets, prometheus.GaugeValue, s.DdosProtocolsInformation.PacketTypesRcvdPackets, labelValues...)
	ch <- prometheus.MustNewConstMetric(packetTypesInViolations, prometheus.GaugeValue, s.DdosProtocolsInformation.PacketTypesInViolation, labelValues...)
	for _, protocol := range s.DdosProtocolsInformation.DdosProtocolGroup {
		labelValues := append(labelValues, protocol.GroupName)
		for _, group := range protocol.DdosProtocol {
			l := append(labelValues, group.PacketType)
			ch <- prometheus.MustNewConstMetric(systemPacketsReceived, prometheus.GaugeValue, group.DdosSystemStatistics.PacketReceived, l...)
			arrivalRate := convertDifferentStringsToFloat(group.DdosSystemStatistics.PacketArrivalRate)
			if arrivalRate != 0.0000000000001 {
				ch <- prometheus.MustNewConstMetric(systemPacketsArrivalRate, prometheus.GaugeValue, arrivalRate, l...)
			}
			ch <- prometheus.MustNewConstMetric(systemPacketsDropped, prometheus.GaugeValue, group.DdosSystemStatistics.PacketDropped, l...)
			arrivalRateMax := convertDifferentStringsToFloat(group.DdosSystemStatistics.PacketArrivalRateMax)
			if arrivalRateMax != 0.0000000000001 {
				ch <- prometheus.MustNewConstMetric(systemPacketsArrivalRateMax, prometheus.GaugeValue, arrivalRateMax, l...)
			}
			for _, instance := range group.DdosInstance {
				labelsInstance := append(l, instance.ProtocolStatesLocale)
				ch <- prometheus.MustNewConstMetric(instancePacketsReceived, prometheus.GaugeValue, instance.DdosInstanceStatistics.PacketReceived, labelsInstance...)
				arrivalRate := convertDifferentStringsToFloat(instance.DdosInstanceStatistics.PacketArrivalRate)
				if arrivalRate != 0.0000000000001 {
					ch <- prometheus.MustNewConstMetric(instancePacketsArrivalRate, prometheus.GaugeValue, arrivalRate, labelsInstance...)
				}
				ch <- prometheus.MustNewConstMetric(instancePacketsDropped, prometheus.GaugeValue, instance.DdosInstanceStatistics.PacketDropped, labelsInstance...)
				arrivalRateMax := convertDifferentStringsToFloat(instance.DdosInstanceStatistics.PacketArrivalRateMax)
				if arrivalRateMax != 0.0000000000001 {
					ch <- prometheus.MustNewConstMetric(instancePacketsArrivalRateMax, prometheus.GaugeValue, arrivalRateMax, labelsInstance...)
				}
				ch <- prometheus.MustNewConstMetric(instancePacketsDroppedOthers, prometheus.GaugeValue, instance.DdosInstanceStatistics.PacketDroppedOthers, labelsInstance...)
				ch <- prometheus.MustNewConstMetric(instancePacketsDroppedFlows, prometheus.GaugeValue, instance.DdosInstanceStatistics.PacketDroppedFlows, labelsInstance...)
			}
		}
	}
}

func (c *ddosCollector) collectParameters(p parameters, ch chan<- prometheus.Metric, labelValues []string) {
	ch <- prometheus.MustNewConstMetric(parTotalPacketsTypes, prometheus.GaugeValue, p.DdosProtocolsInformation.TotalPacketTypes, labelValues...)
	ch <- prometheus.MustNewConstMetric(parTotalModified, prometheus.GaugeValue, p.DdosProtocolsInformation.ModPacketTypes, labelValues...)
	for _, protocol := range p.DdosProtocolsInformation.DdosProtocolGroup {
		labelValues := append(labelValues, protocol.GroupName)
		for _, group := range protocol.DdosProtocol {
			l := append(labelValues, group.PacketType)
			bw := convertDifferentStringsToFloat(group.DdosBasicParameters.PolicerBandwidth)
			if bw != 0.0000000000001 {
				ch <- prometheus.MustNewConstMetric(parBasicPolicerBandwidth, prometheus.GaugeValue, bw, l...)
			}
			burst := convertDifferentStringsToFloat(group.DdosBasicParameters.PolicerBurst)
			if burst != 0.0000000000001 {
				ch <- prometheus.MustNewConstMetric(parBasicPolicerBurst, prometheus.GaugeValue, burst, l...)
			}
			timeRecover := convertDifferentStringsToFloat(group.DdosBasicParameters.PolicerTimeRecover)
			if timeRecover != 0.0000000000001 {
				ch <- prometheus.MustNewConstMetric(parBasicPolicerTimeRecover, prometheus.GaugeValue, timeRecover, l...)
			}
			enable := getEnableStatus(group.DdosBasicParameters.PolicerEnable)
			ch <- prometheus.MustNewConstMetric(parBasicPolicerEnable, prometheus.GaugeValue, enable, l...)
			priority := getPriorityStatus(group.DdosBasicParameters.PolicerPriority)
			ch <- prometheus.MustNewConstMetric(parBasicPolicerPriority, prometheus.GaugeValue, priority, l...)
			bypass := getBypassAggregateStatus(group.DdosBasicParameters.PolicerBypassAggregate)
			ch <- prometheus.MustNewConstMetric(parBasicBypassAggregate, prometheus.GaugeValue, bypass, l...)
			for _, instance := range group.DdosInstance {
				labelsInstance := append(l, instance.ProtocolStatesLocale)
				bw := convertDifferentStringsToFloat(instance.DdosInstanceParameters.PolicerBandwidth)
				if bw != 0.0000000000001 {
					ch <- prometheus.MustNewConstMetric(parInstancePolicerBandwidth, prometheus.GaugeValue, bw, labelsInstance...)
				}
				burst := convertDifferentStringsToFloat(instance.DdosInstanceParameters.PolicerBurst)
				if burst != 0.0000000000001 {
					ch <- prometheus.MustNewConstMetric(parInstancePolicerBurst, prometheus.GaugeValue, burst, labelsInstance...)
				}
				enable := getEnableStatus(instance.DdosInstanceParameters.PolicerEnable)
				ch <- prometheus.MustNewConstMetric(parInstancePolicerEnable, prometheus.GaugeValue, enable, labelsInstance...)
				bwScale := convertDifferentStringsToFloat(instance.DdosInstanceParameters.PolicerBandwidthScale)
				if bwScale != 0.0000000000001 {
					ch <- prometheus.MustNewConstMetric(parInstancePolicerBandwidthScale, prometheus.GaugeValue, bwScale, labelsInstance...)
				}
				burstScale := convertDifferentStringsToFloat(instance.DdosInstanceParameters.PolicerBurstScale)
				if burstScale != 0.0000000000001 {
					ch <- prometheus.MustNewConstMetric(parInstancePolicerBusrstScale, prometheus.GaugeValue, burstScale, labelsInstance...)
				}
				ch <- prometheus.MustNewConstMetric(parInstanceHostboundQueue, prometheus.GaugeValue, instance.DdosInstanceParameters.HostboundQueue, labelsInstance...)
			}
		}
	}
}

func convertDifferentStringsToFloat(value string) float64 {
	parsed := strings.TrimSuffix(value, " bps")
	parsed = strings.TrimSuffix(parsed, " packets")
	parsed = strings.TrimSuffix(parsed, " seconds")
	parsed = strings.TrimSuffix(parsed, " pps")
	parsed = strings.TrimSuffix(parsed, ",")
	parsed = strings.TrimSuffix(parsed, "%")
	number, err := strconv.Atoi(parsed)
	if err != nil {
		fmt.Println("Error:", err)
		//@Oli - how to properly signal that there was an error parsing the data ?
		return 0.0000000000001
	}
	return float64(number)
}

func getEnableStatus(h string) float64 {
	switch strings.ToLower(h) {
	case "yes":
		return 2.0
	case "no":
		return 1.0
	case "disabled":
		return 1.0
	case "unknown":
		return 0.0
	default:
		return 0.0
	}
}

// need to validate possible values here, since I experienced only low
func getPriorityStatus(h string) float64 {
	switch strings.ToLower(h) {
	case "low":
		return 1.0
	case "medium":
		return 2.0
	case "high":
		return 3.0
	case "very high":
		return 4.0
	case "unknown":
		return 0.0
	default:
		return 0.0
	}
}

func getBypassAggregateStatus(h string) float64 {
	switch strings.ToLower(h) {
	case "yes":
		return 2.0
	case "no":
		return 1.0
	default:
		return 0.0
	}
}
