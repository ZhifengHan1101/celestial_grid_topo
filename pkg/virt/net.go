/*
* This file is part of Celestial (https://github.com/OpenFogStack/celestial).
* Copyright (c) 2024 Tobias Pfandzelter, The OpenFogStack Team.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, version 3.
*
* This program is distributed in the hope that it will be useful, but
* WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
**/

package virt

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/OpenFogStack/celestial/pkg/orchestrator"
)


// getLinkIP 根据链接索引和端点位置生成点对点IP地址
// linkIdx: 链接的唯一标识符（由编排器分配）
// isFirstEnd: true表示链接的第一端（.10），false表示第二端（.40）
func getLinkIP(linkIdx uint32, isFirstEnd bool) net.IP {
	// 从linkIdx提取x和y
	x := byte((linkIdx >> 8) & 0xFF)
	y := byte(linkIdx & 0xFF)
	
	// 根据端点位置确定最后一个八位组
	var lastOctet byte
	if isFirstEnd {
		lastOctet = 10
	} else {
		lastOctet = 40
	}
	
	return net.IPv4(10, x, y, lastOctet)
}

// getLinkNetwork 返回链接所在的/24网络
func getLinkNetwork(linkIdx uint32) net.IPNet {
	x := byte((linkIdx >> 8) & 0xFF)
	y := byte(linkIdx & 0xFF)
	
	return net.IPNet{
		IP:   net.IPv4(10, x, y, 0),
		Mask: net.CIDRMask(24, 32),
	}
}

// generateLinkMAC 为端口生成MAC地址
// 格式：AA:CE:{group}:{id高字节}:{id低字节}:{port}
func generateLinkMAC(id orchestrator.MachineID, port int) net.HardwareAddr {
	return net.HardwareAddr{
		0xAA,
		0xCE,
		byte(id.Group & 0xFF),
		byte((id.Id >> 8) & 0xFF),
		byte(id.Id & 0xFF),
		byte(port & 0xFF),
	}
}

// getTapName 生成tap设备名称
// 格式：ct-{group}-{id}-{port}
func getTapName(id orchestrator.MachineID, port int) string {
	return fmt.Sprintf("ct-%d-%d-%d", id.Group, id.Id, port)
}

// initPortNetwork 初始化端口网络结构（不分配IP）
func initPortNetwork(id orchestrator.MachineID, port int) network {
	return network{
		mac:       generateLinkMAC(id, port),
		tap:       getTapName(id, port),
		connected: false,
	}
}

// configurePortForLink 为建立的链接配置端口
func configurePortForLink(port *network, linkIdx uint32, isFirstEnd bool, peerIP net.IP) {
	port.linkIdx = linkIdx
	port.ip = net.IPNet{
		IP:   getLinkIP(linkIdx, isFirstEnd),
		Mask: net.CIDRMask(24, 32),
	}
	port.peerIP = peerIP
	port.linkNetwork = getLinkNetwork(linkIdx)
	port.connected = true
}

// getGuestInterfaceName 获取guest内部的接口名称
func getGuestInterfaceName(port int) string {
	return fmt.Sprintf("%s%d", GUESTINTERFACE_PREFIX, port)
}

// ===== 旧的基于VM ID的函数（保留用于地面站或向后兼容）=====

// getLegacyNet 返回旧的单接口网络配置（用于地面站）
func getLegacyNet(id orchestrator.MachineID) (network, error) {
	if id.Id > 16384 {
		return network{}, errors.Errorf("id %d is larger than permitted 16,384", id.Id)
	}
	
	return network{
		linkNetwork: net.IPNet{
			IP:   net.IP{10, id.Group & 0xFF, byte(((id.Id) >> 6) & 0xFF), byte(((id.Id)<<2)&0xFF + 0)},
			Mask: net.CIDRMask(30, 32),
		},
		ip: net.IPNet{
			IP:   net.IP{10, id.Group & 0xFF, byte(((id.Id) >> 6) & 0xFF), byte(((id.Id)<<2)&0xFF + 2)},
			Mask: net.CIDRMask(30, 32),
		},
		mac: net.HardwareAddr{
			0xAA, 0xCE, (id.Group) & 0xFF, 0x00,
			byte(((id.Id + 2) >> 8) & 0xFF), byte(((id.Id + 2) >> 0) & 0xFF),
		},
		tap:       fmt.Sprintf("ct-%d-%d", id.Group, id.Id),
		connected: true, // 地面站总是"已连接"状态
	}, nil
}

// ===== Virt接口实现 =====

func (v *Virt) GetIPAddress(id orchestrator.MachineID) (net.IPNet, error) {
	v.RLock()
	m, ok := v.machines[id]
	v.RUnlock()
	
	if !ok {
		return net.IPNet{}, errors.Errorf("machine %s not found", id.String())
	}
	
	// 对于多端口机器，返回第一个已连接端口的IP
	// 这主要用于向后兼容
	for i := 0; i < NUM_PORTS; i++ {
		if m.networks[i].connected {
			return m.networks[i].ip, nil
		}
	}
	
	return net.IPNet{}, errors.Errorf("machine %s has no connected ports", id.String())
}

func (v *Virt) ResolveIPAddress(ip net.IP) (orchestrator.MachineID, error) {
	// 在P2P模式下，我们需要遍历所有机器的所有端口
	v.RLock()
	defer v.RUnlock()
	
	ip = ip.To4()
	if ip == nil {
		return orchestrator.MachineID{}, errors.Errorf("not an IPv4 address: %s", ip.String())
	}
	
	for id, m := range v.machines {
		for i := 0; i < NUM_PORTS; i++ {
			if m.networks[i].connected && m.networks[i].ip.IP.Equal(ip) {
				return id, nil
			}
		}
	}
	
	return orchestrator.MachineID{}, errors.Errorf("could not resolve IP address %s", ip.String())
}

// ===== 网络设备管理 =====

// removeNetworkDevice removes a network device for a specific port
func removeNetworkDevice(tapName string, hostInterface string) error {
	// ip link del [TAP_NAME]
	cmd := exec.Command(IP_BIN, "link", "del", tapName)
	if out, err := cmd.CombinedOutput(); err != nil {
		// Log but don't fail - device might already be gone
		log.Debugf("could not delete tap %s: %s", tapName, string(out))
	}

	// iptables -D FORWARD -i [TAP_NAME] -o [HOSTINTERFACE] -j ACCEPT
	cmd = exec.Command(IPTABLES_BIN, "-D", "FORWARD", "-i", tapName, "-o",
		hostInterface, "-j", "ACCEPT")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Debugf("could not delete iptables rule for %s: %s", tapName, string(out))
	}

	return nil
}

// createNetworkDevice creates a tap device for a port (without IP configuration)
func createNetworkDevice(tapName string, hostInterface string) error {
	// ip tuntap add [TAP_NAME] mode tap
	cmd := exec.Command(IP_BIN, "tuntap", "add", tapName, "mode", "tap")
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
	}

	// 禁用IPv6
	// sysctl -w net.ipv6.conf.[TAP_NAME].disable_ipv6=1
	cmd = exec.Command(SYSCTL_BIN, "-w",
		fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6=1", tapName))
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
	}

	// ip link set [TAP_NAME] up
	cmd = exec.Command(IP_BIN, "link", "set", tapName, "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
	}

	return nil
}

// configurePortIP 为已建立链接的端口配置IP地址和路由
func configurePortIP(port *network) error {
	if !port.connected {
		return errors.Errorf("port %s is not connected", port.tap)
	}

	// ip addr add [IP_ADDRESS]/24 dev [TAP_NAME]
	cmd := exec.Command(IP_BIN, "addr", "add", port.ip.String(), "dev", port.tap)
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
	}

	// 添加到对端的路由
	// ip route add [PEER_IP]/32 dev [TAP_NAME]
	peerRoute := fmt.Sprintf("%s/32", port.peerIP.String())
	cmd = exec.Command(IP_BIN, "route", "add", peerRoute, "dev", port.tap)
	if out, err := cmd.CombinedOutput(); err != nil {
		// 路由可能已存在，记录但不失败
		log.Debugf("could not add route to %s: %s", peerRoute, string(out))
	}

	log.Debugf("Configured port %s: local=%s, peer=%s, network=%s",
		port.tap, port.ip.IP.String(), port.peerIP.String(), port.linkNetwork.String())

	return nil
}

// deconfigurePortIP 移除端口的IP配置
func deconfigurePortIP(port *network) error {
	if !port.connected {
		return nil
	}

	// ip addr del [IP_ADDRESS]/24 dev [TAP_NAME]
	cmd := exec.Command(IP_BIN, "addr", "del", port.ip.String(), "dev", port.tap)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Debugf("could not delete IP from %s: %s", port.tap, string(out))
	}

	// ip route del [PEER_IP]/32 dev [TAP_NAME]
	peerRoute := fmt.Sprintf("%s/32", port.peerIP.String())
	cmd = exec.Command(IP_BIN, "route", "del", peerRoute, "dev", port.tap)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Debugf("could not delete route to %s: %s", peerRoute, string(out))
	}

	return nil
}
