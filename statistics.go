package srt

type Statistics struct {
	MsTimeStamp uint64

	// Accumulated
	PktSent            uint64
	PktRecv            uint64
	PktSentUnique      uint64
	PktRecvUnique      uint64
	PktSndLoss         uint64
	PktRcvLoss         uint64
	PktRetrans         uint64
	PktRcvRetrans      uint64
	PktSentACK         uint64
	PktRecvACK         uint64
	PktSentNAK         uint64
	PktRecvNAK         uint64
	UsSndDuration      uint64
	PktSndDrop         uint64
	PktRcvDrop         uint64
	PktRcvUndecrypt    uint64
	PktSndFilterExtra  uint64
	PktRcvFilterExtra  uint64
	PktRcvFilterSupply uint64
	PktRcvFilterLoss   uint64

	ByteSent         uint64
	ByteRecv         uint64
	ByteSentUnique   uint64
	ByteRecvUnique   uint64
	ByteRcvLoss      uint64
	ByteRetrans      uint64
	ByteSndDrop      uint64
	ByteRcvDrop      uint64
	ByteRcvUndecrypt uint64

	// Instantaneous
	UsPktSndPeriod       float64
	PktFlowWindow        uint64
	PktCongestionWindow  uint64
	PktFlightSize        uint64
	MsRTT                float64
	MbpsBandwidth        float64
	ByteAvailSndBuf      uint64
	ByteAvailRcvBuf      uint64
	MbpsMaxBW            float64
	ByteMSS              uint64
	PktSndBuf            uint64
	ByteSndBuf           uint64
	MsSndBuf             uint64
	MsSndTsbPdDelay      uint64
	PktRcvBuf            uint64
	ByteRcvBuf           uint64
	MsRcvBuf             uint64
	MsRcvTsbPdDelay      uint64
	PktReorderTolerance  uint64
	PktRcvAvgBelatedTime uint64
}

type XStatsInterval struct {
	PktSent            uint64
	PktRecv            uint64
	PktSentUnique      uint64
	PktRecvUnique      uint64
	PktSndLoss         uint64
	PktRcvLoss         uint64
	PktRetrans         uint64
	PktRcvRetrans      uint64
	PktSentACK         uint64
	PktRecvACK         uint64
	PktSentNAK         uint64
	PktRecvNAK         uint64
	UsSndDuration      uint64
	PktSndDrop         uint64
	PktRcvDrop         uint64
	PktRcvUndecrypt    uint64
	PktSndFilterExtra  uint64
	PktRcvFilterExtra  uint64
	PktRcvFilterSupply uint64
	PktRcvFilterLoss   uint64

	MbpsSendRate       float64
	MbpsRecvRate       float64
	PktReorderDistance uint64
	PktRcvBelated      uint64

	ByteSent         uint64
	ByteRecv         uint64
	ByteSentUnique   uint64
	ByteRecvUnique   uint64
	ByteRcvLoss      uint64
	ByteRetrans      uint64
	ByteSndDrop      uint64
	ByteRcvDrop      uint64
	ByteRcvUndecrypt uint64
}
