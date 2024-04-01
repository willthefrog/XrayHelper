package vless

import (
	e "XrayHelper/main/errors"
	"fmt"
	"strconv"
)

const tagVless = "vless"

type VLESS struct {
	//basic
	Remarks    string
	Id         string
	Server     string
	Port       string
	Encryption string
	Flow       string
	Network    string
	Security   string

	//addon
	//ws/httpupgrade/h2->host quic->security grpc->authority
	Host string
	//ws/httpupgrade/h2->path quic->key kcp->seed grpc->serviceName
	Path string
	//tcp/kcp/quic->type grpc->mode
	Type string

	//tls
	Sni         string
	FingerPrint string
	Alpn        string
	//reality
	PublicKey string //pbk
	ShortId   string //sid
	SpiderX   string //spx
}

func (this *VLESS) GetNodeInfo() string {
	return fmt.Sprintf("Remarks: %+v, Type: VLESS, Server: %+v, Port: %+v, Flow: %+v, Network: %+v, Id: %+v", this.Remarks, this.Server, this.Port, this.Flow, this.Network, this.Id)
}

func (this *VLESS) ToOutboundWithTag(coreType string, tag string) (interface{}, error) {
	switch coreType {
	case "xray":
		outboundObject := make(map[string]interface{})
		outboundObject["mux"] = getMuxObjectXray(false)
		outboundObject["protocol"] = "vless"
		outboundObject["settings"] = getVLESSSettingsObjectXray(this)
		outboundObject["streamSettings"] = getStreamSettingsObjectXray(this)
		outboundObject["tag"] = tag
		return outboundObject, nil
	case "sing-box":
		outboundObject := make(map[string]interface{})
		outboundObject["type"] = "vless"
		outboundObject["tag"] = tag
		outboundObject["server"] = this.Server
		outboundObject["server_port"], _ = strconv.Atoi(this.Port)
		outboundObject["uuid"] = this.Id
		outboundObject["flow"] = this.Flow
		outboundObject["tls"] = getVLESSTlsObjectSingbox(this)
		outboundObject["transport"] = getVLESSTransportObjectSingbox(this)
		return outboundObject, nil
	default:
		return nil, e.New("unsupported core type " + coreType).WithPrefix(tagVless).WithPathObj(*this)
	}
}
