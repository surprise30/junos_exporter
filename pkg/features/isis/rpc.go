// SPDX-License-Identifier: MIT

package isis

import "encoding/xml"

type result struct {
	Information struct {
		Adjacencies []adjacency `xml:"isis-adjacency"`
	} `xml:"isis-adjacency-information"`
}

type adjacency struct {
	InterfaceName  string `xml:"interface-name"`
	SystemName     string `xml:"system-name"`
	Level          int64  `xml:"level"`
	AdjacencyState string `xml:"adjacency-state"`
	Holdtime       int64  `xml:"holdtime"`
	SNPA           string `xml:"snpa"`
}

type interfaces struct {
	XMLName                  xml.Name `xml:"rpc-reply"`
	Text                     string   `xml:",chardata"`
	Junos                    string   `xml:"junos,attr"`
	IsisInterfaceInformation struct {
		Text          string `xml:",chardata"`
		Xmlns         string `xml:"xmlns,attr"`
		Style         string `xml:"style,attr"`
		IsisInterface []struct {
			Text                        string `xml:",chardata"`
			Heading                     string `xml:"heading,attr"`
			InterfaceName               string `xml:"interface-name"`
			InterfaceIndex              string `xml:"interface-index"`
			InterfaceStateValue         string `xml:"interface-state-value"`
			CircuitID                   string `xml:"circuit-id"`
			CircuitType                 string `xml:"circuit-type"`
			LspInterval                 string `xml:"lsp-interval"`
			CsnpInterval                string `xml:"csnp-interval"`
			HelloPadding                string `xml:"hello-padding"`
			MaxHelloSize                string `xml:"max-hello-size"`
			AdjacencyAdvertisement      string `xml:"adjacency-advertisement"`
			IsisLayer2MapEnabled        string `xml:"isis-layer2-map-enabled"`
			InterfaceGroupHolddownDelay string `xml:"interface-group-holddown-delay"`
			InterfaceGroupHolddownLeft  string `xml:"interface-group-holddown-left"`
			InterfaceLevelData          struct {
				Text              string `xml:",chardata"`
				Level             string `xml:"level"`
				AdjacencyCount    string `xml:"adjacency-count"`
				InterfacePriority string `xml:"interface-priority"`
				Metric            string `xml:"metric"`
				HelloTime         string `xml:"hello-time"`
				Holdtime          string `xml:"holdtime"`
				Passive           string `xml:"passive"`
			} `xml:"interface-level-data"`
		} `xml:"isis-interface"`
	} `xml:"isis-interface-information"`
	Cli struct {
		Text   string `xml:",chardata"`
		Banner string `xml:"banner"`
	} `xml:"cli"`
}
