//go:build windows

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/go-ole/go-ole"
	wca "github.com/moutend/go-wca/pkg/wca"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

type deviceInfo struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	IsDefault    bool   `json:"isDefault"`
	IsDefaultCom bool   `json:"isDefaultCom"`
}

type deviceReport struct {
	Inputs  []deviceInfo `json:"inputs"`
	Outputs []deviceInfo `json:"outputs"`
}

type policyConfig interface {
	SetDefaultEndpoint(deviceID string, role uint32) error
	Release()
}

type policyConfigWin7 struct {
	policyConfig *IPolicyConfig
}

type policyConfigVista struct {
	policyConfig *IPolicyConfigVista
}

func main() {
	listCmd := flag.NewFlagSet("list", flag.ExitOnError)
	listJSON := listCmd.Bool("json", true, "output JSON")

	switchOutputCmd := flag.NewFlagSet("switch-output", flag.ExitOnError)
	switchOutputID := switchOutputCmd.String("id", "", "device ID")
	switchOutputName := switchOutputCmd.String("name", "", "device name")
	switchOutputJSON := switchOutputCmd.Bool("json", true, "output JSON")

	switchInputCmd := flag.NewFlagSet("switch-input", flag.ExitOnError)
	switchInputID := switchInputCmd.String("id", "", "device ID")
	switchInputName := switchInputCmd.String("name", "", "device name")
	switchInputJSON := switchInputCmd.Bool("json", true, "output JSON")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "list":
		if err := listCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if !*listJSON {
			fmt.Fprintln(os.Stderr, "only --json output is supported")
			os.Exit(2)
		}
		report, err := enumerateDevices()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "switch-output":
		if err := switchOutputCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if !*switchOutputJSON {
			fmt.Fprintln(os.Stderr, "only --json output is supported")
			os.Exit(2)
		}
		device, err := switchDevice(wca.ERender, *switchOutputID, *switchOutputName)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := outputSwitchResult("output", device); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "switch-input":
		if err := switchInputCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if !*switchInputJSON {
			fmt.Fprintln(os.Stderr, "only --json output is supported")
			os.Exit(2)
		}
		device, err := switchDevice(wca.ECapture, *switchInputID, *switchInputName)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := outputSwitchResult("input", device); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "version":
		if err := outputVersion(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	message := strings.Join([]string{
		"usage:",
		"  win-audio-cli list --json",
		"  win-audio-cli switch-output --id <device-id>",
		"  win-audio-cli switch-output --name <device-name>",
		"  win-audio-cli switch-input --id <device-id>",
		"  win-audio-cli switch-input --name <device-name>",
		"  win-audio-cli version",
	}, "\n")
	fmt.Fprintln(os.Stderr, message)
}

func enumerateDevices() (*deviceReport, error) {
	if err := ole.CoInitialize(0); err != nil {
		return nil, err
	}
	defer ole.CoUninitialize()

	var enumerator *wca.IMMDeviceEnumerator
	if err := wca.CoCreateInstance(
		wca.CLSID_MMDeviceEnumerator,
		0,
		wca.CLSCTX_ALL,
		wca.IID_IMMDeviceEnumerator,
		&enumerator,
	); err != nil {
		return nil, err
	}
	defer enumerator.Release()

	inputs, err := collectDevices(enumerator, wca.ECapture)
	if err != nil {
		return nil, err
	}

	outputs, err := collectDevices(enumerator, wca.ERender)
	if err != nil {
		return nil, err
	}

	return &deviceReport{Inputs: inputs, Outputs: outputs}, nil
}

func collectDevices(enumerator *wca.IMMDeviceEnumerator, dataFlow wca.EDataFlow) ([]deviceInfo, error) {
	var collection *wca.IMMDeviceCollection
	if err := enumerator.EnumAudioEndpoints(uint32(dataFlow), wca.DEVICE_STATE_ACTIVE, &collection); err != nil {
		return nil, err
	}
	defer collection.Release()

	var count uint32
	if err := collection.GetCount(&count); err != nil {
		return nil, err
	}

	defaultID, defaultComID, err := defaultDeviceIDs(enumerator, dataFlow)
	if err != nil {
		return nil, err
	}

	devices := make([]deviceInfo, 0, count)
	for i := uint32(0); i < count; i++ {
		var device *wca.IMMDevice
		if err := collection.Item(i, &device); err != nil {
			return nil, err
		}
		info, err := deviceDetails(device, defaultID, defaultComID)
		device.Release()
		if err != nil {
			return nil, err
		}
		devices = append(devices, info)
	}

	return devices, nil
}

func defaultDeviceIDs(enumerator *wca.IMMDeviceEnumerator, dataFlow wca.EDataFlow) (string, string, error) {
	var defaultID string
	var defaultComID string

	var defaultDevice *wca.IMMDevice
	if err := enumerator.GetDefaultAudioEndpoint(uint32(dataFlow), uint32(wca.EConsole), &defaultDevice); err == nil {
		id, err := deviceID(defaultDevice)
		defaultDevice.Release()
		if err != nil {
			return "", "", err
		}
		defaultID = id
	}

	var defaultComDevice *wca.IMMDevice
	if err := enumerator.GetDefaultAudioEndpoint(uint32(dataFlow), uint32(wca.ECommunications), &defaultComDevice); err == nil {
		id, err := deviceID(defaultComDevice)
		defaultComDevice.Release()
		if err != nil {
			return "", "", err
		}
		defaultComID = id
	}

	return defaultID, defaultComID, nil
}

func deviceDetails(device *wca.IMMDevice, defaultID string, defaultComID string) (deviceInfo, error) {
	id, err := deviceID(device)
	if err != nil {
		return deviceInfo{}, err
	}

	name, err := deviceName(device)
	if err != nil {
		return deviceInfo{}, err
	}

	return deviceInfo{
		ID:           id,
		Name:         name,
		IsDefault:    id != "" && id == defaultID,
		IsDefaultCom: id != "" && id == defaultComID,
	}, nil
}

func deviceID(device *wca.IMMDevice) (string, error) {
	var id string
	if err := device.GetId(&id); err != nil {
		return "", err
	}

	return id, nil
}

func deviceName(device *wca.IMMDevice) (string, error) {
	var store *wca.IPropertyStore
	if err := device.OpenPropertyStore(wca.STGM_READ, &store); err != nil {
		return "", err
	}
	defer store.Release()

	var prop wca.PROPVARIANT
	if err := store.GetValue(&wca.PKEY_Device_FriendlyName, &prop); err != nil {
		return "", err
	}
	if prop.VT != ole.VT_LPWSTR {
		return "", fmt.Errorf("unexpected property type")
	}

	return prop.String(), nil
}

type switchReport struct {
	Type   string     `json:"type"`
	Device deviceInfo `json:"device"`
}

type versionReport struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
}

func outputSwitchResult(deviceType string, device deviceInfo) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(switchReport{Type: deviceType, Device: device})
}

func outputVersion() error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(versionReport{Version: version, Commit: commit, BuildDate: buildDate})
}

func switchDevice(dataFlow wca.EDataFlow, id string, name string) (deviceInfo, error) {
	if id == "" && name == "" {
		return deviceInfo{}, fmt.Errorf("provide --id or --name")
	}

	report, err := enumerateDevices()
	if err != nil {
		return deviceInfo{}, err
	}

	device, err := findDevice(report, dataFlow, id, name)
	if err != nil {
		return deviceInfo{}, err
	}

	if err := setDefaultDevice(device.ID); err != nil {
		return deviceInfo{}, err
	}

	return device, nil
}

func findDevice(report *deviceReport, dataFlow wca.EDataFlow, id string, name string) (deviceInfo, error) {
	var devices []deviceInfo
	if dataFlow == wca.ECapture {
		devices = report.Inputs
	} else {
		devices = report.Outputs
	}

	if id != "" {
		for _, device := range devices {
			if device.ID == id {
				return device, nil
			}
		}
		return deviceInfo{}, fmt.Errorf("device ID not found")
	}

	if name != "" {
		matches := make([]deviceInfo, 0, 1)
		for _, device := range devices {
			if strings.EqualFold(device.Name, name) {
				matches = append(matches, device)
			}
		}
		if len(matches) == 1 {
			return matches[0], nil
		}
		if len(matches) > 1 {
			return deviceInfo{}, fmt.Errorf("device name matches multiple devices")
		}
		return deviceInfo{}, fmt.Errorf("device name not found")
	}

	return deviceInfo{}, fmt.Errorf("provide --id or --name")
}

func setDefaultDevice(deviceID string) error {
	if err := ole.CoInitialize(0); err != nil {
		return err
	}
	defer ole.CoUninitialize()

	roles := []uint32{
		uint32(wca.EConsole),
		uint32(wca.EMultimedia),
		uint32(wca.ECommunications),
	}

	configs := []struct {
		name  string
		clsid *ole.GUID
		iid   *ole.GUID
		kind  string
	}{
		{
			name:  "policy-config",
			clsid: clsidPolicyConfigClient,
			iid:   iidPolicyConfig,
			kind:  "win7",
		},
		{
			name:  "policy-config-vista",
			clsid: clsidPolicyConfigVistaClient,
			iid:   iidPolicyConfigVista,
			kind:  "vista",
		},
	}

	var lastErr error
	for _, config := range configs {
		policyConfig, err := createPolicyConfig(config.clsid, config.iid, config.kind)
		if err != nil {
			lastErr = err
			continue
		}

		err = setDefaultEndpoints(policyConfig, deviceID, roles)
		policyConfig.Release()
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("%s: %w", config.name, err)
	}

	if lastErr != nil {
		return lastErr
	}

	return fmt.Errorf("unable to set default device")
}

var (
	clsidPolicyConfigClient      = ole.NewGUID("{870af99c-171d-4f9e-af0d-e63df40c2bc9}")
	clsidPolicyConfigVistaClient = ole.NewGUID("{294935ce-f637-4e7c-a41b-ab255460b862}")
	iidPolicyConfig              = ole.NewGUID("{f8679f50-850a-41cf-9c72-430f290290c8}")
	iidPolicyConfigVista         = ole.NewGUID("{568b9108-44bf-40b4-9006-86afe5b5a620}")
)

type IPolicyConfig struct {
	ole.IUnknown
}

type IPolicyConfigVtbl struct {
	ole.IUnknownVtbl
	GetMixFormat          uintptr
	GetDeviceFormat       uintptr
	ResetDeviceFormat     uintptr
	SetDeviceFormat       uintptr
	GetProcessingPeriod   uintptr
	SetProcessingPeriod   uintptr
	GetShareMode          uintptr
	SetShareMode          uintptr
	GetPropertyValue      uintptr
	SetPropertyValue      uintptr
	SetDefaultEndpoint    uintptr
	SetEndpointVisibility uintptr
}

func (v *IPolicyConfig) VTable() *IPolicyConfigVtbl {
	return (*IPolicyConfigVtbl)(unsafe.Pointer(v.RawVTable))
}

func (v *IPolicyConfig) SetDefaultEndpoint(deviceID string, role uint32) error {
	deviceIDPtr, err := syscall.UTF16PtrFromString(deviceID)
	if err != nil {
		return err
	}

	hr, _, _ := syscall.SyscallN(
		v.VTable().SetDefaultEndpoint,
		uintptr(unsafe.Pointer(v)),
		uintptr(unsafe.Pointer(deviceIDPtr)),
		uintptr(role),
	)
	if hr != 0 {
		return ole.NewError(hr)
	}
	return nil
}

type IPolicyConfigVista struct {
	ole.IUnknown
}

type IPolicyConfigVistaVtbl struct {
	ole.IUnknownVtbl
	GetMixFormat          uintptr
	GetDeviceFormat       uintptr
	SetDeviceFormat       uintptr
	GetProcessingPeriod   uintptr
	SetProcessingPeriod   uintptr
	GetShareMode          uintptr
	SetShareMode          uintptr
	GetPropertyValue      uintptr
	SetPropertyValue      uintptr
	SetDefaultEndpoint    uintptr
	SetEndpointVisibility uintptr
}

func (v *IPolicyConfigVista) VTable() *IPolicyConfigVistaVtbl {
	return (*IPolicyConfigVistaVtbl)(unsafe.Pointer(v.RawVTable))
}

func (v *IPolicyConfigVista) SetDefaultEndpoint(deviceID string, role uint32) error {
	deviceIDPtr, err := syscall.UTF16PtrFromString(deviceID)
	if err != nil {
		return err
	}

	hr, _, _ := syscall.SyscallN(
		v.VTable().SetDefaultEndpoint,
		uintptr(unsafe.Pointer(v)),
		uintptr(unsafe.Pointer(deviceIDPtr)),
		uintptr(role),
	)
	if hr != 0 {
		return ole.NewError(hr)
	}
	return nil
}

func createPolicyConfig(clsid *ole.GUID, iid *ole.GUID, kind string) (policyConfig, error) {
	if kind == "vista" {
		var config *IPolicyConfigVista
		if err := wca.CoCreateInstance(
			clsid,
			0,
			wca.CLSCTX_ALL,
			iid,
			&config,
		); err != nil {
			return nil, err
		}

		return &policyConfigVista{policyConfig: config}, nil
	}

	var config *IPolicyConfig
	if err := wca.CoCreateInstance(
		clsid,
		0,
		wca.CLSCTX_ALL,
		iid,
		&config,
	); err != nil {
		return nil, err
	}

	return &policyConfigWin7{policyConfig: config}, nil
}

func (p *policyConfigWin7) SetDefaultEndpoint(deviceID string, role uint32) error {
	return p.policyConfig.SetDefaultEndpoint(deviceID, role)
}

func (p *policyConfigWin7) Release() {
	if p.policyConfig != nil {
		p.policyConfig.Release()
	}
}

func (p *policyConfigVista) SetDefaultEndpoint(deviceID string, role uint32) error {
	return p.policyConfig.SetDefaultEndpoint(deviceID, role)
}

func (p *policyConfigVista) Release() {
	if p.policyConfig != nil {
		p.policyConfig.Release()
	}
}

func setDefaultEndpoints(config *policyConfig, deviceID string, roles []uint32) error {
	for _, role := range roles {
		if err := config.SetDefaultEndpoint(deviceID, role); err != nil {
			return fmt.Errorf("set default endpoint role %d: %w", role, err)
		}
	}

	return nil
}
