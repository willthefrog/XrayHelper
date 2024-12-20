package tproxy

import (
	"XrayHelper/main/builds"
	"XrayHelper/main/common"
	e "XrayHelper/main/errors"
	"XrayHelper/main/log"
	"XrayHelper/main/proxies/tools"
	"bytes"
)

const tagTproxy = "tproxy"

type Tproxy struct{}

func (this *Tproxy) Enable() error {
	if err := addRoute(false); err != nil {
		this.Disable()
		return err
	}
	if err := createMangleChain(false); err != nil {
		this.Disable()
		return err
	}
	if err := createProxyChain(false); err != nil {
		this.Disable()
		return err
	}
	if builds.Config.Proxy.EnableIPv6 {
		if err := addRoute(true); err != nil {
			this.Disable()
			return err
		}
		if err := createMangleChain(true); err != nil {
			this.Disable()
			return err
		}
		if err := createProxyChain(true); err != nil {
			this.Disable()
			return err
		}
	}
	// handleDns, some core not support sniffing(eg: clash), need redirect dns request to local dns port
	switch builds.Config.XrayHelper.CoreType {
	case "mihomo":
		if err := tools.RedirectDNS(builds.Config.Clash.DNSPort); err != nil {
			this.Disable()
			return err
		}
	case "hysteria2":
		// hysteria2 don't have dns module, if enable AdgHome, as upstream dns resolver
		if builds.Config.AdgHome.Enable {
			if err := tools.RedirectDNS(builds.Config.AdgHome.DNSPort); err != nil {
				this.Disable()
				return err
			}
		}
	default:
		if !builds.Config.Proxy.EnableIPv6 {
			if err := tools.DisableIPV6DNS(); err != nil {
				this.Disable()
				return err
			}
		}
	}
	return nil
}
func (this *Tproxy) Disable() {
	deleteRoute(false)
	cleanIptablesChain(false)
	//always clean ipv6 rules
	deleteRoute(true)
	cleanIptablesChain(true)
	//always clean dns rules
	tools.EnableIPV6DNS()
	tools.CleanRedirectDNS(builds.Config.Clash.DNSPort)
	tools.CleanRedirectDNS(builds.Config.AdgHome.DNSPort)
}

// addRoute Add ip route to proxy
func addRoute(ipv6 bool) error {
	var errMsg bytes.Buffer
	if !ipv6 {
		common.NewExternal(0, nil, &errMsg, "ip", "rule", "add", "fwmark", common.TproxyMarkId, "table", common.TproxyTableId).Run()
		if errMsg.Len() > 0 {
			return e.New("add ip rule failed, ", errMsg.String()).WithPrefix(tagTproxy)
		}
		errMsg.Reset()
		common.NewExternal(0, nil, &errMsg, "ip", "route", "add", "local", "default", "dev", "lo", "table", common.TproxyTableId).Run()
		if errMsg.Len() > 0 {
			return e.New("add ip route failed, ", errMsg.String()).WithPrefix(tagTproxy)
		}
	} else {
		if !common.UseDummy {
			common.NewExternal(0, nil, &errMsg, "ip", "-6", "rule", "add", "fwmark", common.TproxyMarkId, "table", common.TproxyTableId).Run()
			if errMsg.Len() > 0 {
				return e.New("add ip rule failed, ", errMsg.String()).WithPrefix(tagTproxy)
			}
			errMsg.Reset()
			common.NewExternal(0, nil, &errMsg, "ip", "-6", "route", "add", "local", "default", "dev", "lo", "table", common.TproxyTableId).Run()
			if errMsg.Len() > 0 {
				return e.New("add ip route failed, ", errMsg.String()).WithPrefix(tagTproxy)
			}
		} else {
			if err := enableDummy(); err != nil {
				return err
			}
		}
	}
	return nil
}

// deleteRoute Delete ip route to proxy
func deleteRoute(ipv6 bool) {
	var errMsg bytes.Buffer
	if !ipv6 {
		common.NewExternal(0, nil, &errMsg, "ip", "rule", "del", "fwmark", common.TproxyMarkId, "table", common.TproxyTableId).Run()
		if errMsg.Len() > 0 {
			log.HandleDebug("delete ip rule: " + errMsg.String())
		}
		errMsg.Reset()
		common.NewExternal(0, nil, &errMsg, "ip", "route", "flush", "table", common.TproxyTableId).Run()
		if errMsg.Len() > 0 {
			log.HandleDebug("delete ip route: " + errMsg.String())
		}
	} else {
		disableDummy()
		common.NewExternal(0, nil, &errMsg, "ip", "-6", "rule", "del", "fwmark", common.TproxyMarkId, "table", common.TproxyTableId).Run()
		if errMsg.Len() > 0 {
			log.HandleDebug("delete ip rule: " + errMsg.String())
		}
		errMsg.Reset()
		common.NewExternal(0, nil, &errMsg, "ip", "-6", "route", "flush", "table", common.TproxyTableId).Run()
		if errMsg.Len() > 0 {
			log.HandleDebug("delete ip route: " + errMsg.String())
		}
	}
}

// createProxyChain Create PROXY chain for local applications
func createProxyChain(ipv6 bool) error {
	currentIpt := common.Ipt
	currentProto := "ipv4"
	if ipv6 {
		currentIpt = common.Ipt6
		currentProto = "ipv6"
	}
	if currentIpt == nil {
		return e.New("get iptables failed").WithPrefix(tagTproxy)
	}
	if err := currentIpt.NewChain("mangle", "PROXY"); err != nil {
		return e.New("create "+currentProto+" mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
	}
	// bypass dummy
	if currentProto == "ipv6" && common.UseDummy {
		if err := currentIpt.Append("mangle", "PROXY", "-o", common.DummyDevice, "-j", "RETURN"); err != nil {
			return e.New("ignore dummy interface "+common.DummyDevice+" on "+currentProto+" mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
	}
	// bypass ignore list
	for _, ignore := range builds.Config.Proxy.IgnoreList {
		if err := currentIpt.Append("mangle", "PROXY", "-o", ignore, "-j", "RETURN"); err != nil {
			return e.New("apply ignore interface "+ignore+" on "+currentProto+" mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
	}
	// bypass intraNet list
	if currentProto == "ipv4" {
		for _, intraIp := range common.IntraNet {
			if err := currentIpt.Append("mangle", "PROXY", "-d", intraIp, "-j", "RETURN"); err != nil {
				return e.New("bypass intraNet "+intraIp+" on "+currentProto+" mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
			}
		}
	} else {
		for _, intraIp6 := range common.IntraNet6 {
			if err := currentIpt.Append("mangle", "PROXY", "-d", intraIp6, "-j", "RETURN"); err != nil {
				return e.New("bypass intraNet "+intraIp6+" on "+currentProto+" mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
			}
		}
	}
	// custom bypass
	for _, bypass := range builds.Config.Proxy.BypassList {
		if (currentProto == "ipv4" && !common.IsIPv6(bypass)) || (currentProto == "ipv6" && common.IsIPv6(bypass)) {
			if err := currentIpt.Append("mangle", "PROXY", "-d", bypass, "-j", "RETURN"); err != nil {
				return e.New("bypass "+bypass+" on "+currentProto+" mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
			}
		}
	}
	// bypass Core itself
	if err := currentIpt.Append("mangle", "PROXY", "-m", "owner", "--gid-owner", common.CoreGid, "-j", "RETURN"); err != nil {
		return e.New("bypass core gid on "+currentProto+" mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
	}
	// start processing proxy rules
	// if PkgList has no package, should proxy everything
	if len(builds.Config.Proxy.PkgList) == 0 {
		if err := currentIpt.Append("mangle", "PROXY", "-p", "tcp", "-j", "MARK", "--set-xmark", common.TproxyMarkId); err != nil {
			return e.New("create local applications proxy on "+currentProto+" tcp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
		if err := currentIpt.Append("mangle", "PROXY", "-p", "udp", "-j", "MARK", "--set-xmark", common.TproxyMarkId); err != nil {
			return e.New("create local applications proxy on "+currentProto+" udp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
	} else if builds.Config.Proxy.Mode == "blacklist" {
		// bypass PkgList
		for _, pkg := range builds.Config.Proxy.PkgList {
			uidSlice := tools.GetUid(pkg)
			for _, uid := range uidSlice {
				if err := currentIpt.Insert("mangle", "PROXY", 1, "-m", "owner", "--uid-owner", uid, "-j", "RETURN"); err != nil {
					return e.New("bypass package "+pkg+" on "+currentProto+" mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
				}
			}
		}
		// allow others
		if err := currentIpt.Append("mangle", "PROXY", "-p", "tcp", "-j", "MARK", "--set-xmark", common.TproxyMarkId); err != nil {
			return e.New("create local applications proxy on "+currentProto+" tcp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
		if err := currentIpt.Append("mangle", "PROXY", "-p", "udp", "-j", "MARK", "--set-xmark", common.TproxyMarkId); err != nil {
			return e.New("create local applications proxy on "+currentProto+" udp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
	} else if builds.Config.Proxy.Mode == "whitelist" {
		// allow PkgList
		for _, pkg := range builds.Config.Proxy.PkgList {
			uidSlice := tools.GetUid(pkg)
			for _, uid := range uidSlice {
				if err := currentIpt.Append("mangle", "PROXY", "-p", "tcp", "-m", "owner", "--uid-owner", uid, "-j", "MARK", "--set-xmark", common.TproxyMarkId); err != nil {
					return e.New("create package "+pkg+" proxy on "+currentProto+" tcp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
				}
				if err := currentIpt.Append("mangle", "PROXY", "-p", "udp", "-m", "owner", "--uid-owner", uid, "-j", "MARK", "--set-xmark", common.TproxyMarkId); err != nil {
					return e.New("create package "+pkg+" proxy on "+currentProto+" udp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
				}
			}
		}
		// allow root user(eg: magisk, ksud, netd...)
		if err := currentIpt.Append("mangle", "PROXY", "-p", "tcp", "-m", "owner", "--uid-owner", "0", "-j", "MARK", "--set-xmark", common.TproxyMarkId); err != nil {
			return e.New("create root user proxy on "+currentProto+" tcp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
		if err := currentIpt.Append("mangle", "PROXY", "-p", "udp", "-m", "owner", "--uid-owner", "0", "-j", "MARK", "--set-xmark", common.TproxyMarkId); err != nil {
			return e.New("create root user proxy on "+currentProto+" udp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
		// allow dns_tether user(eg: dnsmasq...)
		if err := currentIpt.Append("mangle", "PROXY", "-p", "tcp", "-m", "owner", "--uid-owner", "1052", "-j", "MARK", "--set-xmark", common.TproxyMarkId); err != nil {
			return e.New("create dns_tether user proxy on "+currentProto+" tcp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
		if err := currentIpt.Append("mangle", "PROXY", "-p", "udp", "-m", "owner", "--uid-owner", "1052", "-j", "MARK", "--set-xmark", common.TproxyMarkId); err != nil {
			return e.New("create dns_tether user proxy on "+currentProto+" udp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
	} else {
		return e.New("invalid proxy mode " + builds.Config.Proxy.Mode).WithPrefix(tagTproxy)
	}
	// allow IntraList
	for _, intra := range builds.Config.Proxy.IntraList {
		if (currentProto == "ipv4" && !common.IsIPv6(intra)) || (currentProto == "ipv6" && common.IsIPv6(intra)) {
			if err := currentIpt.Insert("mangle", "PROXY", 1, "-p", "tcp", "-d", intra, "-j", "MARK", "--set-xmark", common.TproxyMarkId); err != nil {
				return e.New("allow intra "+intra+" on "+currentProto+" tcp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
			}
			if err := currentIpt.Insert("mangle", "PROXY", 1, "-p", "udp", "-d", intra, "-j", "MARK", "--set-xmark", common.TproxyMarkId); err != nil {
				return e.New("allow intra "+intra+" on "+currentProto+" udp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
			}
		}
	}
	// mark all dns request (except mihomo/hysteria2)
	if builds.Config.XrayHelper.CoreType != "mihomo" && builds.Config.XrayHelper.CoreType != "hysteria2" {
		if err := currentIpt.Insert("mangle", "PROXY", 1, "-p", "udp", "-m", "owner", "!", "--gid-owner", common.CoreGid, "--dport", "53", "-j", "MARK", "--set-xmark", common.TproxyMarkId); err != nil {
			return e.New("mark all dns request on "+currentProto+" udp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
	} else {
		if err := currentIpt.Insert("mangle", "PROXY", 1, "-p", "udp", "--dport", "53", "-j", "RETURN"); err != nil {
			return e.New("bypass all dns request on "+currentProto+" udp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
	}
	// apply rules to OUTPUT
	if err := currentIpt.Insert("mangle", "OUTPUT", 1, "-j", "PROXY"); err != nil {
		return e.New("apply mangle chain PROXY to OUTPUT failed, ", err).WithPrefix(tagTproxy)
	}
	return nil
}

// createMangleChain Create XRAY chain for AP interface
func createMangleChain(ipv6 bool) error {
	currentIpt := common.Ipt
	currentProto := "ipv4"
	if ipv6 {
		currentIpt = common.Ipt6
		currentProto = "ipv6"
	}
	if currentIpt == nil {
		return e.New("get iptables failed").WithPrefix(tagTproxy)
	}
	if err := currentIpt.NewChain("mangle", "XRAY"); err != nil {
		return e.New("create "+currentProto+" mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
	}
	// bypass intraNet list
	if currentProto == "ipv4" {
		for _, intraIp := range common.IntraNet {
			if err := currentIpt.Append("mangle", "XRAY", "-d", intraIp, "-j", "RETURN"); err != nil {
				return e.New("bypass intraNet "+intraIp+" on "+currentProto+" mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
			}
		}
	} else {
		for _, intraIp6 := range common.IntraNet6 {
			if err := currentIpt.Append("mangle", "XRAY", "-d", intraIp6, "-j", "RETURN"); err != nil {
				return e.New("bypass intraNet "+intraIp6+" on "+currentProto+" mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
			}
		}
	}
	// custom bypass
	for _, bypass := range builds.Config.Proxy.BypassList {
		if (currentProto == "ipv4" && !common.IsIPv6(bypass)) || (currentProto == "ipv6" && common.IsIPv6(bypass)) {
			if err := currentIpt.Append("mangle", "XRAY", "-d", bypass, "-j", "RETURN"); err != nil {
				return e.New("bypass "+bypass+" on "+currentProto+" mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
			}
		}
	}
	// allow IntraList
	for _, intra := range builds.Config.Proxy.IntraList {
		if (currentProto == "ipv4" && !common.IsIPv6(intra)) || (currentProto == "ipv6" && common.IsIPv6(intra)) {
			if err := currentIpt.Insert("mangle", "XRAY", 1, "-p", "tcp", "-d", intra, "-m", "mark", "--mark", common.TproxyMarkId, "-j", "TPROXY", "--on-port", builds.Config.Proxy.TproxyPort, "--tproxy-mark", common.TproxyMarkId); err != nil {
				return e.New("allow intra "+intra+" on "+currentProto+" tcp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
			}
			if err := currentIpt.Insert("mangle", "XRAY", 1, "-p", "udp", "-d", intra, "-m", "mark", "--mark", common.TproxyMarkId, "-j", "TPROXY", "--on-port", builds.Config.Proxy.TproxyPort, "--tproxy-mark", common.TproxyMarkId); err != nil {
				return e.New("allow intra "+intra+" on "+currentProto+" udp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
			}
		}
	}
	// mark all traffic
	if err := currentIpt.Append("mangle", "XRAY", "-p", "tcp", "-m", "mark", "--mark", common.TproxyMarkId, "-j", "TPROXY", "--on-port", builds.Config.Proxy.TproxyPort, "--tproxy-mark", common.TproxyMarkId); err != nil {
		return e.New("create all traffic proxy on "+currentProto+" tcp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
	}
	if err := currentIpt.Append("mangle", "XRAY", "-p", "udp", "-m", "mark", "--mark", common.TproxyMarkId, "-j", "TPROXY", "--on-port", builds.Config.Proxy.TproxyPort, "--tproxy-mark", common.TproxyMarkId); err != nil {
		return e.New("create all traffic proxy on "+currentProto+" udp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
	}
	// trans ApList to chain XRAY
	for _, ap := range builds.Config.Proxy.ApList {
		// allow ApList to IntraList
		for _, intra := range builds.Config.Proxy.IntraList {
			if (currentProto == "ipv4" && !common.IsIPv6(intra)) || (currentProto == "ipv6" && common.IsIPv6(intra)) {
				if err := currentIpt.Insert("mangle", "XRAY", 1, "-p", "tcp", "-i", ap, "-d", intra, "-j", "TPROXY", "--on-port", builds.Config.Proxy.TproxyPort, "--tproxy-mark", common.TproxyMarkId); err != nil {
					return e.New("allow intra "+intra+" on "+currentProto+" tcp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
				}
				if err := currentIpt.Insert("mangle", "XRAY", 1, "-p", "udp", "-i", ap, "-d", intra, "-j", "TPROXY", "--on-port", builds.Config.Proxy.TproxyPort, "--tproxy-mark", common.TproxyMarkId); err != nil {
					return e.New("allow intra "+intra+" on "+currentProto+" udp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
				}
			}
		}
		if err := currentIpt.Append("mangle", "XRAY", "-p", "tcp", "-i", ap, "-j", "TPROXY", "--on-port", builds.Config.Proxy.TproxyPort, "--tproxy-mark", common.TproxyMarkId); err != nil {
			return e.New("create ap interface "+ap+" proxy on "+currentProto+" tcp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
		}
		if err := currentIpt.Append("mangle", "XRAY", "-p", "udp", "-i", ap, "-j", "TPROXY", "--on-port", builds.Config.Proxy.TproxyPort, "--tproxy-mark", common.TproxyMarkId); err != nil {
			return e.New("create ap interface "+ap+" proxy on "+currentProto+" udp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
		}
	}
	// mark all dns request(except mihomo/hysteria2)
	if builds.Config.XrayHelper.CoreType != "mihomo" && builds.Config.XrayHelper.CoreType != "hysteria2" {
		if err := currentIpt.Insert("mangle", "XRAY", 1, "-p", "udp", "--dport", "53", "-j", "TPROXY", "--on-port", builds.Config.Proxy.TproxyPort, "--tproxy-mark", common.TproxyMarkId); err != nil {
			return e.New("mark all dns request on "+currentProto+" udp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
		}
	} else {
		if err := currentIpt.Insert("mangle", "XRAY", 1, "-p", "udp", "--dport", "53", "-j", "RETURN"); err != nil {
			return e.New("bypass all dns request on "+currentProto+" udp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
		}
	}
	// apply rules to PREROUTING
	if err := currentIpt.Insert("mangle", "PREROUTING", 1, "-j", "XRAY"); err != nil {
		return e.New("apply mangle chain XRAY to PREROUTING failed, ", err).WithPrefix(tagTproxy)
	}
	return nil
}

// cleanIptablesChain Clean all changed iptables rules by XrayHelper
func cleanIptablesChain(ipv6 bool) {
	currentIpt := common.Ipt
	if ipv6 {
		currentIpt = common.Ipt6
	}
	if currentIpt == nil {
		return
	}
	_ = currentIpt.Delete("mangle", "OUTPUT", "-j", "PROXY")
	_ = currentIpt.Delete("mangle", "PREROUTING", "-j", "XRAY")
	_ = currentIpt.ClearAndDeleteChain("mangle", "PROXY")
	_ = currentIpt.ClearAndDeleteChain("mangle", "XRAY")
}
