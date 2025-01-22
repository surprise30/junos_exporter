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
	totalPacketsTypes             *prometheus.Desc
	packetTypesReceivedPackets    *prometheus.Desc
	packetTypesInViolations       *prometheus.Desc
	protocolGroupName             *prometheus.Desc
	protocolPacketType            *prometheus.Desc
	systemPacketsReceived         *prometheus.Desc
	systemPacketsArrivalRate      *prometheus.Desc
	systemPacketsDropped          *prometheus.Desc
	systemPacketsArrivalRateMax   *prometheus.Desc
	protocolStatesLocale          *prometheus.Desc
	instancePacketsReceived       *prometheus.Desc
	instancePacketsArrivalRate    *prometheus.Desc
	instancePacketsDropped        *prometheus.Desc
	instancePacketsArrivalRateMax *prometheus.Desc
	instancePacketsDroppedOthers  *prometheus.Desc
	instancePacketsDroppedFlows   *prometheus.Desc
)

func init() {
	l := []string{"target"}
	totalPacketsTypes = prometheus.NewDesc(prefix+"total_packet_types", "total amount of packet types for device", l, nil)
	packetTypesReceivedPackets = prometheus.NewDesc(prefix+"received_traffic", "total packet types received packets", l, nil)
	packetTypesInViolations = prometheus.NewDesc(prefix+"packets_in_violations", "total packet types in violations", l, nil)
	l = append(l, "protocol_group_name")
	//l = append(l, "packet_type")
	protocolGroupName = prometheus.NewDesc(prefix+"protocol_group_name", "protocol group name", l, nil)
	protocolPacketType = prometheus.NewDesc(prefix+"packet_type", "packet type", l, nil)
	l = append(l, "protocol_packet_type")
	systemPacketsReceived = prometheus.NewDesc(prefix+"system_wide_packets_received", "total number of packets received", l, nil)
	systemPacketsArrivalRate = prometheus.NewDesc(prefix+"system_wide_packets_arrival_rate", "total packets arrival rate", l, nil)
	systemPacketsDropped = prometheus.NewDesc(prefix+"system_wide_packets_dropped", "total number of packets dropped", l, nil)
	systemPacketsArrivalRateMax = prometheus.NewDesc(prefix+"system_wide_packets_arrival_rate_max", "total packets arrival rate max", l, nil)
	protocolStatesLocale = prometheus.NewDesc(prefix+"protocol_states_locale", "kind of engine", l, nil)
	instancePacketsReceived = prometheus.NewDesc(prefix+"instance_packets_received", "number of packets received on an instance", l, nil)
	instancePacketsArrivalRate = prometheus.NewDesc(prefix+"instance_packets_arrival_rate", "packets arrival rate on an instance", l, nil)
	instancePacketsDropped = prometheus.NewDesc(prefix+"instance_packets_dropped", "number of packets dropped on an instance", l, nil)
	instancePacketsArrivalRateMax = prometheus.NewDesc(prefix+"instance_packets_arrival_max_rate", "packets arrival rate max on an instance", l, nil)
	instancePacketsDroppedOthers = prometheus.NewDesc(prefix+"instance_other_packets_dropped", "number of others packets dropped on an instance", l, nil)
	instancePacketsDroppedFlows = prometheus.NewDesc(prefix+"instance_flows_dropped", "number of flows dropped on an instance", l, nil)
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
	ch <- protocolGroupName
	ch <- protocolPacketType
	ch <- systemPacketsReceived
	ch <- systemPacketsArrivalRate
	ch <- systemPacketsDropped
	ch <- systemPacketsArrivalRateMax
	ch <- protocolStatesLocale
	ch <- instancePacketsReceived
	ch <- instancePacketsArrivalRate
	ch <- instancePacketsDropped
	ch <- instancePacketsArrivalRateMax
	ch <- instancePacketsDroppedOthers
	ch <- instancePacketsDroppedFlows
}
func (c *ddosCollector) Collect(client collector.Client, ch chan<- prometheus.Metric, labelValues []string) error {
	var i statistics
	err := client.RunCommandAndParse("show ddos-protection protocols statistics", &i)
	if err != nil {
		return errors.Wrap(err, "failed to run command 'show ddos-protection protocols'")
	}
	c.collectStatistics(i, ch, labelValues)
	return nil
}

func (c *ddosCollector) collectStatistics(s statistics, ch chan<- prometheus.Metric, labelValues []string) {
	ch <- prometheus.MustNewConstMetric(totalPacketsTypes, prometheus.GaugeValue, s.DdosProtocolsInformation.TotalPacketTypes, labelValues...)
	ch <- prometheus.MustNewConstMetric(packetTypesReceivedPackets, prometheus.GaugeValue, s.DdosProtocolsInformation.PacketTypesRcvdPackets, labelValues...)
	ch <- prometheus.MustNewConstMetric(packetTypesInViolations, prometheus.GaugeValue, s.DdosProtocolsInformation.PacketTypesInViolation, labelValues...)

	for _, protocol := range s.DdosProtocolsInformation.DdosProtocolGroup {
		fmt.Printf("group is %v \n", protocol.GroupName)
		labelValues := append(labelValues, protocol.GroupName)
		//labelValues = append(labelValues, protocol.DdosProtocol[i].PacketType)
		for _, group := range protocol.DdosProtocol {
			l := append(labelValues, group.PacketType)
			fmt.Printf("packet type is %v \n", group.PacketType)
			ch <- prometheus.MustNewConstMetric(systemPacketsReceived, prometheus.GaugeValue, group.DdosSystemStatistics.PacketReceived, l...)
			arrivalRate := convertDifferentStringsToFloat(group.DdosSystemStatistics.PacketArrivalRate)
			if arrivalRate != 0.0000000000001 {
				ch <- prometheus.MustNewConstMetric(systemPacketsArrivalRate, prometheus.GaugeValue, arrivalRate, l...)
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
	number, err := strconv.Atoi(parsed)
	if err != nil {
		fmt.Println("Error:", err)
		//@Oli - how to properly signal that there was an error parsing the data ?
		return 0.0000000000001
	}
	return float64(number)
}
