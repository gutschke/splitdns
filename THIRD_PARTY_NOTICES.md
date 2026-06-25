# Third-party notices

`splitdns` is distributed as a statically linked binary that includes the following
third-party Go modules. Each is used under the terms of its license; the complete
license texts are vendored alongside the source under `vendor/<module>/LICENSE`.

| Module | License | Copyright |
|--------|---------|-----------|
| `github.com/miekg/dns` | BSD-3-Clause | The Go Authors; Miek Gieben and contributors |
| `github.com/pelletier/go-toml/v2` | MIT | Thomas Pelletier and contributors |
| `golang.org/x/net` | BSD-3-Clause | The Go Authors |
| `golang.org/x/sys` | BSD-3-Clause | The Go Authors |

Transitively vendored Go toolchain libraries (`golang.org/x/mod`,
`golang.org/x/sync`, `golang.org/x/tools`) are likewise BSD-3-Clause, The Go Authors.

The BSD-3-Clause and MIT licenses are permissive and compatible with this project's
MIT license. Their notices are retained in the vendored tree as those licenses
require.
