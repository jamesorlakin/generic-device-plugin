// Copyright 2023 the generic-device-plugin authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package deviceplugin

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/go-kit/log/level"
	"k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const (
	usbDevicesDir              = "/sys/bus/usb/devices/"
	usbDevicesDirVendorIDFile  = "idVendor"
	usbDevicesDirProductIDFile = "idProduct"
	usbDevicesDirSerialFile    = "serial"
	usbDevicesDirBusFile       = "busnum"
	usbDevicesDirBusDevFile    = "devnum"
	usbDevBus                  = "/dev/bus/usb/%03x/%03x"
)

// USBSpec represents a USB device specification that should be discovered.
// A USB device must match exactly on all the given attributes to pass.
type USBSpec struct {
	// Vendor is the USB Vendor ID of the device to match on.
	// (Both of these get mangled to uint16 for processing - but you should use the hexadecimal representation.)
	Vendor USBID `json:"vendor"`
	// Product is the USB Product ID of the device to match on.
	Product USBID `json:"product"`
	// Serial is the serial number of the device to match on.
	Serial string `json:"serial"`
	// ContainerPath optionally overrides both the host and container paths for a matched USB device.
	ContainerPath string `json:"containerPath,omitempty"`
}

// USBID is a representation of a platform or vendor ID under the USB standard (see gousb.ID)
type USBID uint16

// UnmarshalJSON handles incoming standard platform / vendor IDs.
func (id *USBID) UnmarshalJSON(data []byte) error {
	strData := string(data)
	if strData == "null" || strData == `""` {
		return nil
	}
	// To be safe, strip out newlines and quotation marks
	strData = strings.ReplaceAll(strData, "\n", "")
	strData = strings.ReplaceAll(strData, "\"", "")

	// then attempt to parse as uint16.
	dAsInt, err := strconv.ParseUint(strData, 16, 16)
	if err != nil {
		return fmt.Errorf("malformed device data %q: %w", strData, err)
	}
	*id = USBID(uint16(dAsInt))
	return nil
}

// String returns a standardised hexadecimal representation of the USBID.
func (id *USBID) String() string {
	return fmt.Sprintf("%04x", int(*id))
}

// ToUSBIDHookFunc handles mapstructure decode of standard platform / vendor IDs.
func ToUSBIDHookFunc(f, t reflect.Type, data interface{}) (interface{}, error) {
	if t != reflect.TypeOf(USBID(0)) {
		return data, nil
	}

	switch f.Kind() {
	case reflect.String:
		return strconv.ParseUint(data.(string), 16, 16)
	default:
		return data, nil
	}
}

// usbDevice represents a physical, tangible USB device.
type usbDevice struct {
	Vendor USBID `json:"vendor"`
	Product USBID `json:"product"`
	Bus uint16 `json:"bus"`
	BusDevice uint16 `json:"busdev"`
	Serial string `json:"serial"`
}

// BusPath returns the platform-correct path to the raw device.
func (dev *usbDevice) BusPath() (path string) {
	return fmt.Sprintf(usbDevBus, dev.Bus, dev.BusDevice)
}

func readFileToUint16(fsys fs.FS, path string) (out uint16, err error) {
	bytes, err := fs.ReadFile(fsys, path)
	if err != nil {
		return out, err
	}
	dataStr := strings.ReplaceAll(string(bytes), "\n", "")
	dAsInt, err := strconv.ParseUint(dataStr, 16, 16)
	if err != nil {
		return out, fmt.Errorf("malformed device data %q: %w", dataStr, err)
	}
	return uint16(dAsInt), nil
}

func resolveSymlinkToDir(fsys fs.FS, path string) (absolutePath string, err error) {
	fileInfo, err := fs.Stat(fsys, path)
	if err != nil {
		return "", err
	}
	if !fileInfo.IsDir() {
		return "", fmt.Errorf("not a directory")
	}
	return path, nil
}

func queryUSBDeviceCharacteristicsByDirectory(fsys fs.FS, path string) (result *usbDevice, err error) {
	path, err = resolveSymlinkToDir(fsys, path)
	if err != nil {
		return result, err
	}

	vnd, err := readFileToUint16(fsys, filepath.Join(path, usbDevicesDirVendorIDFile))
	if err != nil {
		return result, err
	}
	prd, err := readFileToUint16(fsys, filepath.Join(path, usbDevicesDirProductIDFile))
	if err != nil {
		return result, err
	}

	serial := ""
	serBytes, err := fs.ReadFile(fsys, filepath.Join(path, usbDevicesDirSerialFile))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return result, err
	}
	if serBytes != nil {
		serial = strings.TrimSuffix(string(serBytes), "\n")
	}

	bus, err := readFileToUint16(fsys, filepath.Join(path, usbDevicesDirBusFile))
	if err != nil {
		return result, err
	}
	busLoc, err := readFileToUint16(fsys, filepath.Join(path, usbDevicesDirBusDevFile))
	if err != nil {
		return result, err
	}

	return &usbDevice{
		Vendor:    USBID(vnd),
		Product:   USBID(prd),
		Bus:       bus,
		BusDevice: busLoc,
		Serial:    serial,
	}, nil
}

// enumerateUSBDevices rapidly scans the OS system bus for attached USB devices.
func enumerateUSBDevices(fsys fs.FS, dir string) (specs []usbDevice, err error) {
	allDevs, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return []usbDevice{}, err
	}

	var wg sync.WaitGroup
	devs := make(chan *usbDevice)
	for _, dev := range allDevs {
		dev := dev
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := queryUSBDeviceCharacteristicsByDirectory(fsys, filepath.Join(dir, dev.Name()))
			if err != nil {
				return
			}
			devs <- result
		}()
	}

	go func() {
		defer close(devs)
		wg.Wait()
	}()

	for d := range devs {
		specs = append(specs, *d)
	}
	return
}

// searchUSBDevices returns a subset of devices matching the vendor, product, and serial.
func searchUSBDevices(devices *[]usbDevice, vendor USBID, product USBID, serial string) (devs []usbDevice, err error) {
	for _, dev := range *devices {
		if dev.Vendor == vendor && dev.Product == product && (serial == "" || dev.Serial == serial) {
			devs = append(devs, dev)
		}
	}
	return
}

type usbDevicePath struct {
	hostPath      string
	containerPath string
}

func (gp *GenericPlugin) discoverUSB() (devices []device, err error) {
	usbDevs, err := enumerateUSBDevices(gp.fs, usbDevicesDir)
	for _, usbDev := range usbDevs {
		_ = level.Debug(gp.logger).Log("msg", "discovered USB device", "usbdevice", fmt.Sprintf("%v:%v", usbDev.Vendor.String(), usbDev.Product.String()), "path", usbDev.BusPath())
	}

	for _, group := range gp.ds.Groups {
		var paths []usbDevicePath
		if err != nil {
			_ = level.Warn(gp.logger).Log("msg", fmt.Sprintf("failed to enumerate usb devices: %v", err))
			return devices, nil
		}
		for _, spec := range group.USBSpecs {
			matches, err := searchUSBDevices(&usbDevs, spec.Vendor, spec.Product, spec.Serial)
			if err != nil {
				return nil, err
			}
			if len(matches) == 0 {
				_ = level.Debug(gp.logger).Log("msg", "no USB devices found attached to system")
			}
			for _, match := range matches {
				hostPath := match.BusPath()
				containerPath := spec.ContainerPath
				if containerPath == "" {
					containerPath = hostPath
				} else {
					hostPath = containerPath
				}
				_ = level.Debug(gp.logger).Log("msg", "USB device match", "usbdevice", fmt.Sprintf("%v:%v", spec.Vendor.String(), spec.Product.String()), "hostPath", hostPath, "containerPath", containerPath)
				paths = append(paths, usbDevicePath{hostPath: hostPath, containerPath: containerPath})
			}
		}
		if len(paths) == 0 {
			continue
		}

		for j := uint(0); j < group.Count; j++ {
			h := sha1.New()
			h.Write([]byte(strconv.FormatUint(uint64(j), 10)))
			d := device{Device: &v1beta1.Device{Health: v1beta1.Healthy}}
			for _, path := range paths {
				d.deviceSpecs = append(d.deviceSpecs, &v1beta1.DeviceSpec{
					HostPath:      path.hostPath,
					ContainerPath: path.containerPath,
					Permissions:   "rw",
				})
				h.Write([]byte(path.hostPath))
			}
			d.ID = fmt.Sprintf("%x", h.Sum(nil))
			devices = append(devices, d)
		}
	}
	return devices, nil
}

