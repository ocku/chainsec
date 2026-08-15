use chainsec::model::Risk;

pub(super) fn paint(value: &str, color_code: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{color_code}m{value}\x1b[0m")
    } else {
        value.to_owned()
    }
}

pub(super) const fn risk_color(risk: Risk) -> &'static str {
    match risk {
        Risk::Low => "34",
        Risk::Medium => "33",
        Risk::High => "31",
        Risk::Critical => "1;31",
    }
}

pub(super) fn display_package(package: &str) -> &str {
    package
        .split_once('#')
        .map_or(package, |(identity, _)| identity)
}
