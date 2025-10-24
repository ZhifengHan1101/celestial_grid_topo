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

// getNet returns an IP Address (CIDR format), a custom MAC address, and a tap name for a given
// machine identifier. Group is limited to 8 bits (max. 256) and ID to 14 bits (max. 16,384) because of IPv4. In
// theory, we could split this up differently, so that shell has 6 bits and ID 16 bits, etc. This limit is enforced
// and is also used to ensure the tap device name is less than 14 digits long. Each tap has to have its own network,
// that network is 10.[shell].[id>>6 & 0xFF].[id<<2 & 0xFF]/30, leaves 3 addresses on that network: network + 1 is
// gateway IP, network + 2 is tap IP.
// Ground stations are in shell 0, satellite shells start at 1.
// func getNet(id orchestrator.MachineID) (network, error) {

// 	if id.Id > 16384 {
// 		return network{}, errors.Errorf("id %d is larger than permitted 16,384", id)
// 	}

// 	return network{
// 		network: net.IPNet{IP: net.IP{10, id.Group & 0xFF, byte(((id.Id) >> 6) & 0xFF), byte(((id.Id)<<2)&0xFF + 0)}, Mask: net.CIDRMask(30, 32)},
// 		gateway: net.IPNet{IP: net.IP{10, id.Group & 0xFF, byte(((id.Id) >> 6) & 0xFF), byte(((id.Id)<<2)&0xFF + 1)}, Mask: net.CIDRMask(30, 32)},
// 		ip:      net.IPNet{IP: net.IP{10, id.Group & 0xFF, byte(((id.Id) >> 6) & 0xFF), byte(((id.Id)<<2)&0xFF + 2)}, Mask: net.CIDRMask(30, 32)},
// 		mac:     net.HardwareAddr{0xAA, 0xCE, (id.Group) & 0xFF, 0x00, byte(((id.Id + 2) >> 8) & 0xFF), byte(((id.Id + 2) >> 0) & 0xFF)},
// 		tap:     fmt.Sprintf("ct-%d-%d", id.Group, id.Id),
// 	}, nil
// }

// func getID(ip net.IP) (orchestrator.MachineID, error) {
// 	// do what getNet does, but in reverse
// 	ip = ip.To4()

// 	if ip == nil {
// 		return orchestrator.MachineID{}, errors.Errorf("could not resolve IP address %s (not an IPv4 address)", ip.String())
// 	}

// 	if ip[0] != 10&0xFF {
// 		return orchestrator.MachineID{}, errors.Errorf("could not resolve IP address %s (not in 10.0.0.0/8)", ip.String())
// 	}

// 	return orchestrator.MachineID{
// 		Group: ip[1] & 0xFF,
// 		Id:    uint32(ip[2])<<6 + uint32(ip[3])>>2,
// 	}, nil
// }

// func (v *Virt) GetIPAddress(id orchestrator.MachineID) (net.IPNet, error) {
// 	n, err := getNet(id)

// 	if err != nil {
// 		return net.IPNet{}, errors.Wrap(err, "could not get network")
// 	}

// 	return n.ip, nil
// }

// func (v *Virt) ResolveIPAddress(ip net.IP) (orchestrator.MachineID, error) {
// 	// do what getNet does, but in reverse
// 	return getID(ip)
// }

// // removeNetworkDevice removes a network device. Errors are ignored.
// func removeNetworkDevice(tapName string, hostInterface string) error {
// 	// ip link del [TAP_NAME]

// 	cmd := exec.Command(IP_BIN, "link", "del", tapName)

// 	if out, err := cmd.CombinedOutput(); err != nil {
// 		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
// 	}

// 	// iptables -D FORWARD -i [TAP_NAME] -o [HOSTINTERFACE] -j ACCEPT

// 	cmd = exec.Command(IPTABLES_BIN, "-D", "FORWARD", "-i", tapName, "-o", hostInterface, "-j", "ACCEPT")

// 	if out, err := cmd.CombinedOutput(); err != nil {
// 		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
// 	}

// 	return nil
// }

// // createNetworkDevice creates a new network device for a microVM.
// func createNetworkDevice(gateway net.IPNet, tapName string, _ string) error {

// 	// ip tuntap add [TAP_NAME] mode tap

// 	cmd := exec.Command(IP_BIN, "tuntap", "add", tapName, "mode", "tap")

// 	if out, err := cmd.CombinedOutput(); err != nil {
// 		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
// 	}

// 	// set up proxy ARP
// 	// sysctl -w net.ipv4.conf.[TAP_NAME].proxy_arp=1
// 	cmd = exec.Command(SYSCTL_BIN, "-w", fmt.Sprintf("net.ipv4.conf.%s.proxy_arp=1", tapName))

// 	if out, err := cmd.CombinedOutput(); err != nil {
// 		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
// 	}

// 	// disable ipv6
// 	// sysctl -w net.ipv6.conf.[TAP_NAME].disable_ipv6=1
// 	cmd = exec.Command(SYSCTL_BIN, "-w", fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6=1", tapName))

// 	if out, err := cmd.CombinedOutput(); err != nil {
// 		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
// 	}

// 	// ip addr add [IP_ADDRESS] dev [TAP_NAME]

// 	cmd = exec.Command(IP_BIN, "addr", "add", gateway.String(), "dev", tapName)

// 	if out, err := cmd.CombinedOutput(); err != nil {
// 		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
// 	}

// 	// ip link set [TAP_NAME] up

// 	cmd = exec.Command(IP_BIN, "link", "set", tapName, "up")

// 	if out, err := cmd.CombinedOutput(); err != nil {
// 		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
// 	}

// 	// iptables -A FORWARD -i [TAP_NAME] -o [HOSTINTERFACE] -j ACCEPT

// 	//cmd = exec.Command(IPTABLES_BIN, "-A", "FORWARD", "-i", tapName, "-o", hostInterface, "-j", "ACCEPT")

// 	//if out, err := cmd.CombinedOutput(); err != nil {
// 	//	return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
// 	//}

// 	return nil
// }


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
