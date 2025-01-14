package ddos

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/czerwonk/junos_exporter/pkg/collector"
)

-protection

import (
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/czerwonk/junos_exporter/pkg/collector"
)

const prefix string = "junos_ddos_protection"

var (
	agpBandwidth   *prometheus.Desc
	agpBurst   *prometheus.Desc
	agpRecoverTime   *prometheus.Desc
	agpEnabled   *prometheus.Desc
	swiViolated   *prometheus.Desc
	swiReceived   *prometheus.Desc
	swiDropped   *prometheus.Desc
	swiArrivalRate   *prometheus.Desc
	swiMaxArrivalRate   *prometheus.Desc
	reiBandwidth   *prometheus.Desc
	reiBurst   *prometheus.Desc
	reiEnabled   *prometheus.Desc
	reiViolated   *prometheus.Desc
	reiReceived   *prometheus.Desc
	reiDropped   *prometheus.Desc
	reiArrivalRate   *prometheus.Desc
	reiMaxArrivalRate   *prometheus.Desc
	reiDroppedIndividualPolicers   *prometheus.Desc
	fpcBandwidth   *prometheus.Desc
	fpcBurst   *prometheus.Desc
	fpcEnabled   *prometheus.Desc
	fpcHostboundQueue   *prometheus.Desc
	fpcViolated   *prometheus.Desc
	fpcReceived   *prometheus.Desc
	fpcDropped   *prometheus.Desc
	fpcArrivalRate   *prometheus.Desc
	fpcMaxArrivalRate   *prometheus.Desc
	fpcDroppedIndividualPolicers   *prometheus.Desc
	fpcDroppedFlowSuppression   *prometheus.Desc
	ipcBandwidth   *prometheus.Desc
	ipcBurst   *prometheus.Desc
	ipcPriority   *prometheus.Desc
	ipcRecoverTime   *prometheus.Desc
	ipcEnabled   *prometheus.Desc
	ipcBypassAggregate   *prometheus.Desc
	fdcStatus   *prometheus.Desc
	fdcDetectionMode   *prometheus.Desc
	fdcDetectTime   *prometheus.Desc
	fdcRecoverTime   *prometheus.Desc
	fdcTimeoutTime   *prometheus.Desc
	fdcFALAggLevelSubscriberDM   *prometheus.Desc
	fdcFALAggLevelSubscriberCM   *prometheus.Desc
	fdcFALAggLevelSubscriberFR   *prometheus.Desc
	fdcFALAggLevelLogicalInterfaceDM   *prometheus.Desc
	fdcFALAggLevelLogicalInterfaceCM   *prometheus.Desc
	fdcFALAggLevelLogicalInterfaceFR   *prometheus.Desc
	fdcFALAggLevelPhysicalInterfaceDM   *prometheus.Desc
	fdcFALAggLevelPhysicalInterfaceCM   *prometheus.Desc
	fdcFALAggLevelPhysicalInterfaceFR   *prometheus.Desc


)

func init() {
	l := []string{"target", "protocol_group", "packet_type"}
	agpBandwidth = prometheus.NewDesc(prefix+"agp_bandwidth", "aggregate policer configuration bandwidth", l, nil)
	agpBurst = prometheus.NewDesc(prefix+"agp_burst", "aggregate policer configuration burst", l, nil)
	agpRecoverTime = prometheus.NewDesc(prefix+"agp_recover_time", "aggregate policer configuration recover time", l, nil)
	agpEnabled = prometheus.NewDesc(prefix+"agp_enabled", "aggregate policer configuration state (0 = DISABLED, 1 = ENABLED)", l, nil)
	swiViolated = prometheus.NewDesc(prefix+"swi_violated", "system wide information violated ( 1 = NEVER)", l, nil)
	swiReceived = prometheus.NewDesc(prefix+"swi_received", "system wide information received", l, nil)
	swiDropped = prometheus.NewDesc(prefix+"swi_dropped", "system wide information dropped", l, nil)
	swiArrivalRate = prometheus.NewDesc(prefix+"swi_arrival_rate", "system wide information arrival rate in pps", l, nil)
	swiMaxArrivalRate = prometheus.NewDesc(prefix+"swi_max_arrival_rate", "system wide information max arrival rate in pps", l, nil)
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

type ddosCollector struct {}

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

func (*ddosCollector) Collect(client collector.Client, ch chan<- prometheus.Metric, labelValues []string) error {

}