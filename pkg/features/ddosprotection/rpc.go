package ddosprotection

import "encoding/xml"

type results struct {
	XMLName                  xml.Name `xml:"rpc-reply"`
	Text                     string   `xml:",chardata"`
	Junos                    string   `xml:"junos,attr"`
	DdosProtocolsInformation struct {
		Text                   string `xml:",chardata"`
		Xmlns                  string `xml:"xmlns,attr"`
		Style                  string `xml:"style,attr"`
		TotalPacketTypes       string `xml:"total-packet-types"`
		ModPacketTypes         string `xml:"mod-packet-types"`
		PacketTypesRcvdPackets string `xml:"packet-types-rcvd-packets"`
		PacketTypesInViolation string `xml:"packet-types-in-violation"`
		FlowsCurrent           string `xml:"flows-current"`
		FlowsCumulative        string `xml:"flows-cumulative"`
		DdosProtocolGroup      []struct {
			Text         string `xml:",chardata"`
			GroupName    string `xml:"group-name"`
			DdosProtocol []struct {
				Text                  string `xml:",chardata"`
				PacketType            string `xml:"packet-type"`
				PacketTypeDescription string `xml:"packet-type-description"`
				DdosBasicParameters   struct {
					Text                   string `xml:",chardata"`
					Style                  string `xml:"style,attr"`
					PolicerBandwidth       string `xml:"policer-bandwidth"`
					PolicerBurst           string `xml:"policer-burst"`
					PolicerTimeRecover     string `xml:"policer-time-recover"`
					PolicerEnable          string `xml:"policer-enable"`
					PolicerPriority        string `xml:"policer-priority"`
					PolicerBypassAggregate string `xml:"policer-bypass-aggregate"`
				} `xml:"ddos-basic-parameters"`
				DdosSystemStatistics struct {
					Text                      string `xml:",chardata"`
					Style                     string `xml:"style,attr"`
					PacketReceived            string `xml:"packet-received"`
					PacketArrivalRate         string `xml:"packet-arrival-rate"`
					PacketDropped             string `xml:"packet-dropped"`
					PacketArrivalRateMax      string `xml:"packet-arrival-rate-max"`
					FpcViolationCount         string `xml:"fpc-violation-count"`
					PolicerViolationStartTime struct {
						Text    string `xml:",chardata"`
						Seconds string `xml:"seconds,attr"`
					} `xml:"policer-violation-start-time"`
					PolicerViolationLastTime struct {
						Text    string `xml:",chardata"`
						Seconds string `xml:"seconds,attr"`
					} `xml:"policer-violation-last-time"`
					PolicerViolationDuration struct {
						Text    string `xml:",chardata"`
						Seconds string `xml:"seconds,attr"`
					} `xml:"policer-violation-duration"`
					PolicerViolationCount string `xml:"policer-violation-count"`
				} `xml:"ddos-system-statistics"`
				DdosInstance []struct {
					Text                   string `xml:",chardata"`
					Style                  string `xml:"style,attr"`
					ProtocolStatesLocale   string `xml:"protocol-states-locale"`
					DdosInstanceParameters struct {
						Text                  string `xml:",chardata"`
						Style                 string `xml:"style,attr"`
						PolicerBandwidth      string `xml:"policer-bandwidth"`
						PolicerBurst          string `xml:"policer-burst"`
						PolicerEnable         string `xml:"policer-enable"`
						PolicerBandwidthScale string `xml:"policer-bandwidth-scale"`
						PolicerBurstScale     string `xml:"policer-burst-scale"`
						HostboundQueue        string `xml:"hostbound-queue"`
					} `xml:"ddos-instance-parameters"`
					DdosInstanceStatistics struct {
						Text                      string `xml:",chardata"`
						Style                     string `xml:"style,attr"`
						PacketReceived            string `xml:"packet-received"`
						PacketArrivalRate         string `xml:"packet-arrival-rate"`
						PacketDropped             string `xml:"packet-dropped"`
						PacketArrivalRateMax      string `xml:"packet-arrival-rate-max"`
						PacketDroppedOthers       string `xml:"packet-dropped-others"`
						PacketDroppedFlows        string `xml:"packet-dropped-flows"`
						PolicerViolationStartTime struct {
							Text    string `xml:",chardata"`
							Seconds string `xml:"seconds,attr"`
						} `xml:"policer-violation-start-time"`
						PolicerViolationLastTime struct {
							Text    string `xml:",chardata"`
							Seconds string `xml:"seconds,attr"`
						} `xml:"policer-violation-last-time"`
						PolicerViolationDuration struct {
							Text    string `xml:",chardata"`
							Seconds string `xml:"seconds,attr"`
						} `xml:"policer-violation-duration"`
						PolicerViolationCount string `xml:"policer-violation-count"`
						PacketDroppedProtocol string `xml:"packet-dropped-protocol"`
						PacketDroppedAggr     string `xml:"packet-dropped-aggr"`
					} `xml:"ddos-instance-statistics"`
				} `xml:"ddos-instance"`
				DdosFlowDetection struct {
					Text                       string `xml:",chardata"`
					Style                      string `xml:"style,attr"`
					DdosFlowDetectionEnabled   string `xml:"ddos-flow-detection-enabled"`
					DetectionMode              string `xml:"detection-mode"`
					DetectTime                 string `xml:"detect-time"`
					LogFlows                   string `xml:"log-flows"`
					RecoverTime                string `xml:"recover-time"`
					TimeoutActiveFlows         string `xml:"timeout-active-flows"`
					TimeoutTime                string `xml:"timeout-time"`
					FlowAggregationLevelStates struct {
						Text             string `xml:",chardata"`
						SubDetectionMode string `xml:"sub-detection-mode"`
						SubControlMode   string `xml:"sub-control-mode"`
						SubBandwidth     string `xml:"sub-bandwidth"`
						IflDetectionMode string `xml:"ifl-detection-mode"`
						IflControlMode   string `xml:"ifl-control-mode"`
						IflBandwidth     string `xml:"ifl-bandwidth"`
						IfdDetectionMode string `xml:"ifd-detection-mode"`
						IfdControlMode   string `xml:"ifd-control-mode"`
						IfdBandwidth     string `xml:"ifd-bandwidth"`
					} `xml:"flow-aggregation-level-states"`
				} `xml:"ddos-flow-detection"`
			} `xml:"ddos-protocol"`
		} `xml:"ddos-protocol-group"`
	} `xml:"ddos-protocols-information"`
	Cli struct {
		Text   string `xml:",chardata"`
		Banner string `xml:"banner"`
	} `xml:"cli"`
}
