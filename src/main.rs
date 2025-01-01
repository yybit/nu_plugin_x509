use nu_plugin::{serve_plugin, MsgPackSerializer};
use nu_plugin_x509::X509Plugin;

fn main() {
    serve_plugin(&X509Plugin {}, MsgPackSerializer {})
}
