// SPDX-License-Identifier: MIT

package isis

import (
	"strconv"
        "strings"
	"github.com/czerwonk/junos_exporter/pkg/collector"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

const prefix string = "junos_isis_"

var (
	upCountDesc       *prometheus.Desc
	totalCountDesc    *prometheus.Desc
	adjStateDesc      *prometheus.Desc
	adjCountDesc      *prometheus.Desc
	adjPriorityDesc   *prometheus.Desc
	adjMetricDesc     *prometheus.Desc
	adjHelloTimerDesc *prometheus.Desc
	adjHoldTimerDesc  *prometheus.Desc
	LSPIntervalDesc   *prometheus.Desc
	CNMPIntervalDesc  *prometheus.Desc
	helloPaddingDesc  *prometheus.Desc
	maxHelloSizeDesc  *prometheus.Desc
)

func init() {
	l := []string{"target"}
	upCountDesc = prometheus.NewDesc(prefix+"up_count", "Number of ISIS Adjacencies in state up", l, nil)
	totalCountDesc = prometheus.NewDesc(prefix+"total_count", "Number of ISIS Adjacencies", l, nil)
	l = append(l, "interface_name")
	LSPIntervalDesc = prometheus.NewDesc(prefix+"lsp_interval", "The ISIS LSP interval", l, nil)
	CNMPIntervalDesc = prometheus.NewDesc(prefix+"cnmp_interval", "The ISIS CNMP interval", l, nil)
	helloPaddingDesc = prometheus.NewDesc(prefix+"hello_padding", "The ISIS hello padding (0 = UNKNOWN, 1 = LOOSE", l, nil)
	maxHelloSizeDesc = prometheus.NewDesc(prefix+"max_hello_size", "The ISIS max hello size", l, nil)
	l = append(l, "system_name", "level")
	adjStateDesc = prometheus.NewDesc(prefix+"adjacency_state", "The ISIS Adjacency state (0 = DOWN, 1 = UP, 2 = NEW, 3 = ONE-WAY, 4 =INITIALIZING , 5 = REJECTED)", l, nil)
	interfaceMetricsLabels := []string{"target", "interface_name", "level"}
	adjCountDesc = prometheus.NewDesc(prefix+"adjacency_count", "The number of ISIS adjacencies for an interface", interfaceMetricsLabels, nil)
	adjPriorityDesc = prometheus.NewDesc(prefix+"adjacency_priority", "The ISIS adjacency priority", interfaceMetricsLabels, nil)
	adjMetricDesc = prometheus.NewDesc(prefix+"adjacency_metric", "The ISIS adjacency metric", interfaceMetricsLabels, nil)
	adjHelloTimerDesc = prometheus.NewDesc(prefix+"adjacency_hello_timer", "The ISIS adjacency hello timer", interfaceMetricsLabels, nil)
	adjHoldTimerDesc = prometheus.NewDesc(prefix+"adjacency_hold_timer", "The ISIS adjacency hold timer", interfaceMetricsLabels, nil)
}

type isisCollector struct {
}

// NewCollector creates a new collector
func NewCollector() collector.RPCCollector {
	return &isisCollector{}
}

// Name returns the name of the collector
func (*isisCollector) Name() string {
	return "ISIS"
}

// Describe describes the metrics
func (*isisCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- upCountDesc
	ch <- totalCountDesc
	ch <- adjCountDesc
	ch <- adjPriorityDesc
	ch <- adjMetricDesc
	ch <- adjHelloTimerDesc
	ch <- adjHoldTimerDesc
	ch <- LSPIntervalDesc
	ch <- CNMPIntervalDesc
	ch <- helloPaddingDesc
	ch <- maxHelloSizeDesc
}

// Collect collects metrics from JunOS
func (c *isisCollector) Collect(client collector.Client, ch chan<- prometheus.Metric, labelValues []string) error {
	adjancies, err := c.isisAdjancies(client)
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(upCountDesc, prometheus.GaugeValue, adjancies.Up, labelValues...)
	ch <- prometheus.MustNewConstMetric(totalCountDesc, prometheus.GaugeValue, adjancies.Total, labelValues...)

	if adjancies.Adjacencies != nil {
		for _, adj := range adjancies.Adjacencies {
			localLabelvalues := append(labelValues, adj.InterfaceName, adj.SystemName, strconv.Itoa(int(adj.Level)))
			state := 0.0
			switch adj.AdjacencyState {
			case "Down":
				state = 0.0
			case "Up":
				state = 1.0
			case "New":
				state = 2.0
			case "One-way":
				state = 3.0
			case "Initializing":
				state = 4.0
			case "Rejected":
				state = 5.0
			}

			ch <- prometheus.MustNewConstMetric(adjStateDesc, prometheus.GaugeValue, state, localLabelvalues...)
		}
	}

	var ifas interfaces
	err = client.RunCommandAndParse("show isis interface extensive", &ifas)
	if err != nil {
		return errors.Wrap(err, "failed to run command 'show isis interface extensive'")
	}
	c.isisInterfaces(ifas, ch, labelValues)

	c.additionalIsIsInterfaceMetrics(ifas, ch, labelValues)
	return nil
}

func (c *isisCollector) isisAdjancies(client collector.Client) (*adjacencies, error) {
	up := 0
	total := 0

	var x = result{}
	err := client.RunCommandAndParse("show isis adjacency", &x)
	if err != nil {
		return nil, err
	}

	for _, adjacency := range x.Information.Adjacencies {
		if adjacency.AdjacencyState == "Up" {
			up++
		}
		total++
	}

	return &adjacencies{Up: float64(up), Total: float64(total), Adjacencies: x.Information.Adjacencies}, nil
}

func (c *isisCollector) isisInterfaces(interfaces interfaces, ch chan<- prometheus.Metric, labelValues []string) {
	for _, i := range interfaces.IsisInterfaceInformation.IsisInterface {
		if strings.ToLower(i.InterfaceLevelData.Passive) == "passive" {
			continue
		}
		labels := append(labelValues,
			i.InterfaceName,
			i.InterfaceLevelData.Level)
		ch <- prometheus.MustNewConstMetric(adjCountDesc, prometheus.CounterValue, i.InterfaceLevelData.AdjacencyCount, labels...)
		ch <- prometheus.MustNewConstMetric(adjPriorityDesc, prometheus.GaugeValue, i.InterfaceLevelData.InterfacePriority, labels...)
		ch <- prometheus.MustNewConstMetric(adjMetricDesc, prometheus.GaugeValue, i.InterfaceLevelData.Metric, labels...)
		ch <- prometheus.MustNewConstMetric(adjHelloTimerDesc, prometheus.GaugeValue, i.InterfaceLevelData.HelloTime, labels...)
		ch <- prometheus.MustNewConstMetric(adjHoldTimerDesc, prometheus.GaugeValue, i.InterfaceLevelData.HoldTime, labels...)
	}
}

func (*isisCollector) additionalIsIsInterfaceMetrics(ifas interfaces, ch chan<- prometheus.Metric, labelValues []string) {
	for _, i := range ifas.IsisInterfaceInformation.IsisInterface {
		if strings.ToLower(i.InterfaceLevelData.Passive) == "passive" {
			continue
		}
		labels := append(labelValues, i.InterfaceName)
		helloPadding := getHelloPadding(i.HelloPadding)
		ch <- prometheus.MustNewConstMetric(LSPIntervalDesc, prometheus.GaugeValue, i.LSPInterval, labels...)
		ch <- prometheus.MustNewConstMetric(CNMPIntervalDesc, prometheus.GaugeValue, i.CSNPInterval, labels...)
		ch <- prometheus.MustNewConstMetric(helloPaddingDesc, prometheus.GaugeValue, helloPadding, labels...)
		ch <- prometheus.MustNewConstMetric(maxHelloSizeDesc, prometheus.GaugeValue, i.MaxHelloSize, labels...)
	}
}

func getHelloPadding(h string) float64 {
	var state float64
	switch strings.ToLower(h) {
	case "loose":
		state = 1.0
		break
	default:
		state = 0.0
		break
	}
	return state
}
