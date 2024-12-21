# bal-server

## Installation

```bash
$ git clone ....
$ cd bal-server
$ cargo build --release
$ sudo cp target/release/bal-server /usr/local/bin
$ bal-server
```

## Configuration

The `bal-server` application can be configured using environment variables. The following variables are available:

| Variable | Description | Default |
| --- | --- | --- |
| `BAL_SERVER_CONFIG_FILE` | Path to the configuration file. If the file does not exist, a new one will be created. | `$HOME/.config/bal-server/default-config.toml` |
| `BAL_SERVER_DB_FILE` | Path to the SQLite3 database file. If the file does not exist, a new one will be created. | `bal.db` |
| `BAL_SERVER_BIND_ADDRESS` | Public address for listening to requests. | `127.0.0.1` |
| `BAL_SERVER_BIND_PORT` | Default port for listening to requests. | `9137` |
| `BAL_SERVER_REGTEST_ADDRESS` | Bitcoin address for the regtest environment. | - |
| `BAL_SERVER_REGTEST_FIXED_FEE` | Fixed fee for the regtest environment. | 50000 |
| `BAL_SERVER_SIGNET_ADDRESS` | Bitcoin address for the signet environment. | - |
| `BAL_SERVER_SIGNET_FIXED_FEE` | Fixed fee for the signet environment. | 50000 |
| `BAL_SERVER_TESTNET_ADDRESS` | Bitcoin address for the testnet environment. | - |
| `BAL_SERVER_TESTNET_FIXED_FEE` | Fixed fee for the testnet environment. | 50000 |
| `BAL_SERVER_BITCOIN_ADDRESS` | Bitcoin address for the mainnet environment. | - |
| `BAL_SERVER_BITCOIN_FIXED_FEE` | Fixed fee for the mainnet environment. | 50000 |
