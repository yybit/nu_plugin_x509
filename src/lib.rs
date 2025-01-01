mod gen;
mod parse;
use nu_plugin::Plugin;

pub struct X509Plugin;

impl Plugin for X509Plugin {
    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").into()
    }

    fn commands(&self) -> Vec<Box<dyn nu_plugin::PluginCommand<Plugin = Self>>> {
        vec![Box::new(parse::ParseCommand), Box::new(gen::GenCommand)]
    }
}
