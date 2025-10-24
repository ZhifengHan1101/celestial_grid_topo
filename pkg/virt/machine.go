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
	"context"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/firecracker-microvm/firecracker-go-sdk"
	"github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// createNetwork 创建所有4个端口的tap设备（但不配置IP）
func (m *machine) createNetwork() error {
	log.Tracef("creating %d network ports for %s", NUM_PORTS, m.name)
	
	for port := 0; port < NUM_PORTS; port++ {
		tapName := m.networks[port].tap
		
		// 删除旧设备（如果存在）
		_ = removeNetworkDevice(tapName, HOST_INTERFACE)
		
		// 创建tap设备
		err := createNetworkDevice(tapName, HOST_INTERFACE)
		if err != nil {
			// 清理已创建的设备
			for p := 0; p < port; p++ {
				_ = removeNetworkDevice(m.networks[p].tap, HOST_INTERFACE)
			}
			return errors.Wrapf(err, "failed to create port %d for %s", port, m.name)
		}
		
		log.Tracef("created tap %s for %s port %d", tapName, m.name, port)
	}
	
	return nil
}

// removeNetwork 删除所有端口的tap设备
func (m *machine) removeNetwork() error {
	log.Tracef("removing network ports for %s", m.name)
	
	var lastErr error
	for port := 0; port < NUM_PORTS; port++ {
		err := removeNetworkDevice(m.networks[port].tap, HOST_INTERFACE)
		if err != nil {
			lastErr = err
			log.Errorf("failed to remove port %d for %s: %v", port, m.name, err)
		}
	}
	
	return lastErr
}

// configurePort 为已建立链接的端口配置IP和路由
func (m *machine) configurePort(port int) error {
	if port < 0 || port >= NUM_PORTS {
		return errors.Errorf("invalid port number: %d", port)
	}
	
	return configurePortIP(&m.networks[port])
}

// deconfigurePort 移除端口的IP配置
func (m *machine) deconfigurePort(port int) error {
	if port < 0 || port >= NUM_PORTS {
		return errors.Errorf("invalid port number: %d", port)
	}
	
	return deconfigurePortIP(&m.networks[port])
}

// initialize 初始化Firecracker VM（支持4个网络接口）
func (m *machine) initialize() error {
	// 构建网络接口配置（包括所有4个端口）
	fcNetworkConfig := make([]firecracker.NetworkInterface, 0, NUM_PORTS)
	
	for port := 0; port < NUM_PORTS; port++ {
		netPort := &m.networks[port]
		
		// 创建接口配置
		ifaceConfig := firecracker.NetworkInterface{
			StaticConfiguration: &firecracker.StaticNetworkConfiguration{
				MacAddress:  netPort.mac.String(),
				HostDevName: netPort.tap,
			},
		}
		
		// 只有已连接的端口才配置IP
		if netPort.connected {
			ifaceConfig.StaticConfiguration.IPConfiguration = &firecracker.IPConfiguration{
				IPAddr: net.IPNet{
					IP:   netPort.ip.IP,
					Mask: netPort.ip.Mask,
				},
				// P2P链接不需要网关
				Gateway:     nil,
				Nameservers: []string{}, // 可以从第一个连接的端口获取DNS
				IfName:      getGuestInterfaceName(port),
			}
		} else {
			// 未连接的端口：创建接口但不配置IP
			ifaceConfig.StaticConfiguration.IPConfiguration = &firecracker.IPConfiguration{
				IfName: getGuestInterfaceName(port),
				// 其他字段留空
			}
		}
		
		fcNetworkConfig = append(fcNetworkConfig, ifaceConfig)
	}

	// 准备根文件系统
	overlay := path.Join(ROOTPATH, fmt.Sprintf("ce%s.ext4", m.name))
	
	// dd if=/dev/zero of=[TARGET_OVERLAY_FILE] conv=sparse bs=1M count=[DISK_SIZE]
	cmd := exec.Command(DD_BIN, "if=/dev/zero", fmt.Sprintf("of=%s", overlay),
		"conv=sparse", "bs=1M", fmt.Sprintf("count=%d", m.disksize))
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
	}

	// mkfs.ext4 [TARGET_OVERLAY_FILE]
	cmd = exec.Command(MKFS_BIN, overlay)
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
	}

	// 准备输出文件
	outPath := filepath.Join(OUTPUTPATH, fmt.Sprintf("%s.out", m.name))
	errPath := filepath.Join(OUTPUTPATH, fmt.Sprintf("%s.err", m.name))
	
	outFile, err := os.Create(outPath)
	if err != nil {
		return errors.WithStack(err)
	}
	
	errFile, err := os.Create(errPath)
	if err != nil {
		return errors.WithStack(err)
	}

	// Socket路径
	socketPath := getSocketPath(m.name)
	err = os.Remove(socketPath)
	if err != nil {
		var pathError *fs.PathError
		if errors.As(err, &pathError) {
			if pathError.Err != syscall.ENOENT {
				log.Errorf("Error removing old socket path: %s", err.Error())
			}
		} else {
			log.Errorf("Error removing old socket path: %s", err.Error())
		}
	}

	firecrackerProcessRunner, err := getFirecrackerProcessRunner(socketPath, outFile, errFile)
	if err != nil {
		return errors.WithStack(err)
	}

	var loglevel string
	switch log.GetLevel() {
	case log.TraceLevel:
		loglevel = "TRACE"
	default:
		loglevel = "ERROR"
	}

	// 内核启动参数
	bootparams := "init=/sbin/ceinit ro console=ttyS0 noapic acpi=off reboot=k panic=1 random.trust_cpu=on pci=off tsc=reliable quiet ipv6.disable=1 nomodule overlay_root=vdb loglevel=3 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd"
	for _, param := range m.bootparams {
		bootparams += " " + param
	}

	// 创建Firecracker VM
	vm, err := firecracker.NewMachine(context.Background(), firecracker.Config{
		SocketPath:      socketPath,
		KernelImagePath: path.Join(ROOTPATH, m.kernel),
		KernelArgs:      bootparams,
		Drives: []models.Drive{
			{
				DriveID:        firecracker.String("root"),
				PathOnHost:     firecracker.String(path.Join(ROOTPATH, m.diskimage)),
				IsRootDevice:   firecracker.Bool(true),
				IsReadOnly:     firecracker.Bool(true),
			},
			{
				DriveID:        firecracker.String("overlay"),
				PathOnHost:     firecracker.String(overlay),
				IsRootDevice:   firecracker.Bool(false),
				IsReadOnly:     firecracker.Bool(false),
			},
		},
		MachineCfg: models.MachineConfiguration{
			MemSizeMib: firecracker.Int64(int64(m.ram)),
			VcpuCount:  firecracker.Int64(int64(m.vcpucount)),
		},
		LogLevel:          loglevel,
		NetworkInterfaces: fcNetworkConfig,
	}, firecrackerProcessRunner)

	switch log.GetLevel() {
	case log.TraceLevel:
	default:
		l := log.New()
		l.SetLevel(log.WarnLevel)
		firecracker.WithLogger(log.NewEntry(l))(vm)
	}

	if err != nil {
		return errors.WithStack(err)
	}

	m.vm = vm
	return nil
}

func getSocketPath(id string) string {
	filename := strings.Join([]string{
		".firecracker.sock",
		strconv.Itoa(os.Getpid()),
		id,
		strconv.Itoa(rand.Intn(1000))},
		"-",
	)
	dir := os.TempDir()
	return filepath.Join(dir, filename)
}

func getFirecrackerProcessRunner(socketPath string, outFile io.Writer, errFile io.Writer) (firecracker.Opt, error) {
	firecrackerBinary, err := exec.LookPath("firecracker")
	if err != nil {
		return nil, errors.WithStack(err)
	}

	finfo, err := os.Stat(firecrackerBinary)
	if os.IsNotExist(err) {
		return nil, errors.Errorf("binary %q does not exist: %v", firecrackerBinary, err)
	}
	if err != nil {
		return nil, errors.Errorf("failed to stat binary, %q: %v", firecrackerBinary, err)
	}
	if finfo.IsDir() {
		return nil, errors.Errorf("binary, %q, is a directory", firecrackerBinary)
	} else if finfo.Mode()&0111 == 0 {
		return nil, errors.Errorf("binary, %q, is not executable. Check permissions of binary", firecrackerBinary)
	}

	return firecracker.WithProcessRunner(firecracker.VMCommandBuilder{}.
		WithBin(firecrackerBinary).
		WithSocketPath(socketPath).
		WithStdout(outFile).
		WithStderr(errFile).
		Build(context.Background())), nil
}