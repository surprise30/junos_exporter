// SPDX-License-Identifier: MIT

package isis

import (
	"github.com/pkg/errors"
	"strconv"
	"strings"

	"github.com/czerwonk/junos_exporter/pkg/collector"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

const prefix string = "junos_isis_"

var (
	upCount      *prometheus.Desc
	totalCount   *prometheus.Desc
	adjState     *prometheus.Desc
	adjCountDesc *prometheus.Desc
)

func init() {
	l := []string{"target"}
	upCount = prometheus.NewDesc(prefix+"up_count", "Number of ISIS Adjacencies in state up", l, nil)
	totalCount = prometheus.NewDesc(prefix+"total_count", "Number of ISIS Adjacencies", l, nil)
	l = append(l, "interface_name", "system_name", "level")
	adjState = prometheus.NewDesc(prefix+"adjacency_state", "The ISIS Adjacency state (0 = DOWN, 1 = UP, 2 = NEW, 3 = ONE-WAY, 4 =INITIALIZING , 5 = REJECTED)", l, nil)
	adjCountDesc = prometheus.NewDesc(prefix+"adjacency_count", "The number of ISIS adjacencies for an interface", l, nil)
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
	ch <- upCount
	ch <- totalCount
	ch <- adjCountDesc
}

// Collect collects metrics from JunOS
func (c *isisCollector) Collect(client collector.Client, ch chan<- prometheus.Metric, labelValues []string) error {
	adjancies, err := c.isisAdjancies(client)
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(upCount, prometheus.GaugeValue, adjancies.Up, labelValues...)
	ch <- prometheus.MustNewConstMetric(totalCount, prometheus.GaugeValue, adjancies.Total, labelValues...)

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

			ch <- prometheus.MustNewConstMetric(adjState, prometheus.GaugeValue, state, localLabelvalues...)
		}
	}

	var i interfaces
	err = client.RunCommandAndParse("show isis interface extensive", &i)
	if err != nil {
		return errors.Wrap(err, "failed to run command 'show isis interface extensive'")
	}
	c.isisInterfaces(i, ch, labelValues)
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
			"",
			i.InterfaceLevelData.Level)
		c, err := strconv.Atoi(i.InterfaceLevelData.AdjacencyCount)
		if err != nil {
			log.Errorf("unable to convert number of adjanceis: %q", i.InterfaceLevelData.AdjacencyCount)
		}
		//labels = deleteElement(labels, 2)
		ch <- prometheus.MustNewConstMetric(adjCountDesc, prometheus.CounterValue, float64(c), labels...)
	}
}

func deleteElement(slice []string, index int) []string {
	return append(slice[:index], slice[index+1:]...)
}
