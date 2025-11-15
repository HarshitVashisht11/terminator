# Terminator Examples

This directory contains example scripts demonstrating various capabilities of the Terminator automation framework.

## Examples Table

| Example                         | Path                                              | Description                                                            |
| ------------------------------- | ------------------------------------------------- | ---------------------------------------------------------------------- |
| **Windows Applications**        |                                                   |                                                                        |
| Windows Calculator              | examples/win_calculator.py                        | Automates Windows Calculator with arithmetic operations                |
| Notepad Automation              | examples/notepad.py                               | Automates basic interactions with Windows Notepad                      |
| MS Paint Automation             | examples/mspaint.py                               | Automates drawing shapes and saving images in MS Paint                 |
| Snipping Tool                   | examples/snipping_tool.py                         | Automates the Windows Snipping Tool for screenshots                    |
| **Cross-Platform**              |                                                   |                                                                        |
| Monitor Example                 | examples/monitor_example.py                       | Retrieves monitor information for windows and UI elements              |
| Element Screenshot              | examples/element_screenshot.py                    | Captures screenshots of UI elements and performs OCR (requires Pillow) |
| VLC Auto Player                 | examples/vlc_auto_player.py                       | Controls VLC media player to automatically play media                  |
| Enhanced Highlight Demo         | examples/enhanced_highlight_demo.py               | Advanced UI element highlighting with text overlays                    |
| Event Recording                 | examples/record_all_events_5s.py                  | Records and analyzes user interaction events                           |
| **Linux-Specific**              |                                                   |                                                                        |
| GNOME Calculator                | examples/gnome-calculator.py                      | Demonstrates automation of GNOME Calculator on Linux                   |
| **Web Automation**              |                                                   |                                                                        |
| Gmail Automation                | examples/gmail_automation.py                      | Automates common tasks within the Gmail web interface                  |
| PyPI Release Cleanup (TS)       | packages/workflow/examples/pypi-release-pruner.ts | Logs into PyPI with TOTP and deletes the oldest release                |
| **MCP Integration**             |                                                   |                                                                        |
| Python MCP Client (gRPC)        | examples/python_mcp_client.py                     | Example Terminator MCP client with gRPC transport                      |
| Python MCP Client (HTTP)        | examples/python_mcp_client_http.py                | Example Terminator MCP client over HTTP                                |
| Remote MCP Client               | examples/remote_mcp_client.py                     | Connects to remote MCP server instances                                |
| **Other Formats**               |                                                   |                                                                        |
| Windows Calculator (TypeScript) | examples/win_calculator.ts                        | TypeScript version of Windows Calculator automation                    |
| I-94 Automation Workflow        | examples/i94_automation.yml                       | Declarative workflow for U.S. I-94 travel form                         |
| Hello World                     | examples/hello-world                              | Simple Next.js app demonstrating Terminator usage                      |
| PDF to Form                     | examples/pdf-to-form                              | Converts PDF data into web forms using Terminator                      |

## Platform Compatibility

| Example Type                          | Windows | Linux | macOS |
| ------------------------------------- | ------- | ----- | ----- |
| Windows Apps (notepad, mspaint, etc.) | ✓       | ✗     | ✗     |
| GNOME Calculator                      | ✗       | ✓     | ✗     |
| Web Automation                        | ✓       | ✓     | ✓     |
| Monitor/Screenshot                    | ✓       | ✓     | ✓     |
| MCP Integration                       | ✓       | ✓     | ✓     |

## Troubleshooting

1. **"Application not found"** - Ensure the target application is installed
2. **"Element not found"** - UI selectors may vary between OS versions
3. **"Module not found"** - Install required dependencies (see Additional Requirements)
4. **Encoding errors** - Fixed for cross-platform compatibility

5.
