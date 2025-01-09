## Build & launch process
The project binary can be build using the following command:

`cargo build --target=x86_64-unknown-linux-gnu -p kbs-test`

Afterwards the HTTP server can be launched using the following command:

`target/x86_64-unknown-linux-gnu/debug/kbs-test --path /path/to/your/NVChip`