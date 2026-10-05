pub fn persistent_routes(output: &str) -> Vec<String> {
    let mut routes = output
        .lines()
        .filter(|line| line.starts_with(|c: char| c.is_ascii_digit() || c == 'd'))
        // Darwin's L flag denotes expiring neighbor-cache entries, not persistent routes.
        .filter(|line| {
            !line
                .split_whitespace()
                .nth(2)
                .is_some_and(|flags| flags.contains('L'))
        })
        .map(|line| {
            line.split_whitespace()
                .take(4)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>();
    routes.sort();
    routes
}
