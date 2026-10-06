mod dns;

use super::Diagnostic;
use meow_config::raw::RawConfig;

pub(super) fn apply(raw: &mut RawConfig, diagnostics: &mut Vec<Diagnostic>) {
    if raw.strict.unwrap_or(false) {
        return;
    }
    dns::filter_system_nameservers(raw, diagnostics);
}
