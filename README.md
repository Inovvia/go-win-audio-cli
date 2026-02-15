# go-win-audio-cli

Windows-only CLI to list and switch audio input/output devices using the Core Audio APIs.

## Requirements

- Windows
- Go 1.22+

## Build

```powershell
go build -o win-audio-cli.exe
```

## Commands

List devices as JSON (separate input/output lists):

```powershell
./win-audio-cli.exe list --json
```

Switch the default output device (all roles):

```powershell
./win-audio-cli.exe switch-output --id "{device-id}"
./win-audio-cli.exe switch-output --name "Speakers (Realtek(R) Audio)"
```

Switch the default input device (all roles):

```powershell
./win-audio-cli.exe switch-input --id "{device-id}"
./win-audio-cli.exe switch-input --name "Microphone (USB Audio Device)"
```

Set the communication output device (communications role only):

```powershell
./win-audio-cli.exe switch-output-communication --id "{device-id}"
./win-audio-cli.exe switch-output-communication --name "Headset (Bluetooth Hands-Free)"
```

Set the communication input device (communications role only):

```powershell
./win-audio-cli.exe switch-input-communication --id "{device-id}"
./win-audio-cli.exe switch-input-communication --name "Headset Microphone (Bluetooth Hands-Free)"
```

If device names are not unique, use `--id`.

## Output Shape

`list --json` returns:

```json
{
  "inputs": [
    {
      "id": "...",
      "name": "...",
      "isDefault": true,
      "isDefaultCom": false
    }
  ],
  "outputs": [
    {
      "id": "...",
      "name": "...",
      "isDefault": false,
      "isDefaultCom": true
    }
  ]
}
```

`switch-output` / `switch-input` returns:

```json
{
  "type": "output",
  "device": {
    "id": "...",
    "name": "...",
    "isDefault": true,
    "isDefaultCom": true
  }
}
```

## Credits

Built with:
- [go-ole](https://github.com/go-ole/go-ole) - Go bindings for Windows COM/OLE
- [go-wca](https://github.com/moutend/go-wca) - Windows Core Audio API bindings for Go

## License

MIT License - See [LICENSE](LICENSE) for details.
