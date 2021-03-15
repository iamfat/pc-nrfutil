# This is a tailored version of nRF Util

removed zigbee / ble  for better platform support.
now I can use it in Apple M1 environment to generate my dfu package...

```bash
Usage: nrfutil [OPTIONS] COMMAND [ARGS]...

Options:
  -v, --verbose            Increase verbosity of output. Can be specified more
                           than once (up to -v -v -v -v).

  -o, --output <filename>  Log output to file
  --help                   Show this message and exit.

Commands:
  keys      Generate and display private and public keys.
  pkg       Display or generate a DFU package (zip file).
  settings  Generate and display Bootloader DFU settings.
  version   Display nrfutil version.
```