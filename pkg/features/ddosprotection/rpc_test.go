// SPDX-License-Identifier: MIT

package ddosprotection

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseXML tests the XML parsing of the ddos-protection protocols statistics
func TestParseXML(t *testing.T) {
	resultStatsData := `
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S3.9/junos">
    <ddos-protocols-information xmlns="http://xml.juniper.net/junos/23.4R0/junos-jddosd" junos:style="statistics">
        <total-packet-types>253</total-packet-types>
        <packet-types-rcvd-packets>45</packet-types-rcvd-packets>
        <packet-types-in-violation>0</packet-types-in-violation>
        <ddos-protocol-group>
            <group-name>resolve</group-name>
            <ddos-protocol>
                <packet-type>aggregate</packet-type>
                <ddos-system-statistics junos:style="clean-aggr">
                    <packet-received>6</packet-received>
                    <packet-arrival-rate>0</packet-arrival-rate>
                    <packet-dropped>0</packet-dropped>
                    <packet-arrival-rate-max>0</packet-arrival-rate-max>
                </ddos-system-statistics>
                <ddos-instance junos:style="detail">
                    <protocol-states-locale>Routing Engine</protocol-states-locale>
                    <ddos-instance-statistics junos:style="clean-aggr">
                        <packet-received>1</packet-received>
                        <packet-arrival-rate>2</packet-arrival-rate>
                        <packet-dropped>3</packet-dropped>
                        <packet-arrival-rate-max>4</packet-arrival-rate-max>
                        <packet-dropped-others>5</packet-dropped-others>
                    </ddos-instance-statistics>
                </ddos-instance>
                <ddos-instance junos:style="detail">
                    <protocol-states-locale>FPC slot 0</protocol-states-locale>
                    <ddos-instance-statistics junos:style="clean-aggr">
                        <packet-received>6</packet-received>
                        <packet-arrival-rate>7</packet-arrival-rate>
                        <packet-dropped>8</packet-dropped>
                        <packet-arrival-rate-max>9</packet-arrival-rate-max>
                        <packet-dropped-others>10</packet-dropped-others>
                        <packet-dropped-flows>11</packet-dropped-flows>
                    </ddos-instance-statistics>
                </ddos-instance>
            </ddos-protocol>
        </ddos-protocol-group>
    </ddos-protocols-information>
    <cli>
        <banner></banner>
    </cli>
</rpc-reply>`

	var resultStats statistics

	//Parse the xml data
	// Parse the XML data for statistics
	err := xml.Unmarshal([]byte(resultStatsData), &resultStats)
	assert.NoError(t, err)

	assert.Equal(t, "resolve", resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].GroupName)
	assert.Equal(t, "aggregate", resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].PacketType)

	assert.Equal(t, float64(6), resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosSystemStatistics.PacketReceived)
	assert.Equal(t, "0", resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosSystemStatistics.PacketArrivalRate)
	assert.Equal(t, float64(0), resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosSystemStatistics.PacketDropped)
	assert.Equal(t, "0", resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosSystemStatistics.PacketArrivalRateMax)

	assert.Equal(t, "Routing Engine", resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosInstance[0].ProtocolStatesLocale)
	assert.Equal(t, float64(1), resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosInstance[0].DdosInstanceStatistics.PacketReceived)
	assert.Equal(t, "2", resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosInstance[0].DdosInstanceStatistics.PacketArrivalRate)
	assert.Equal(t, float64(3), resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosInstance[0].DdosInstanceStatistics.PacketDropped)
	assert.Equal(t, "4", resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosInstance[0].DdosInstanceStatistics.PacketArrivalRateMax)
	assert.Equal(t, float64(5), resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosInstance[0].DdosInstanceStatistics.PacketDroppedOthers)

	assert.Equal(t, "FPC slot 0", resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosInstance[1].ProtocolStatesLocale)
	assert.Equal(t, float64(6), resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosInstance[1].DdosInstanceStatistics.PacketReceived)
	assert.Equal(t, "7", resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosInstance[1].DdosInstanceStatistics.PacketArrivalRate)
	assert.Equal(t, float64(8), resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosInstance[1].DdosInstanceStatistics.PacketDropped)
	assert.Equal(t, "9", resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosInstance[1].DdosInstanceStatistics.PacketArrivalRateMax)
	assert.Equal(t, float64(10), resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosInstance[1].DdosInstanceStatistics.PacketDroppedOthers)
	assert.Equal(t, float64(11), resultStats.DdosProtocolsInformation.DdosProtocolGroup[0].DdosProtocol[0].DdosInstance[1].DdosInstanceStatistics.PacketDroppedFlows)
}
