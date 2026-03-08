use std::path::Path;

/// Supported Linux distributions and their trust store conventions.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Distro {
    Arch,
    Debian,
    RedHat,
    OpenSUSE,
    Unknown,
}

impl Distro {
    /// Detects the current Linux distribution by probing well-known paths.
    fn detect() -> Self {
        let checks: &[(&str, Distro)] = &[
            ("/etc/ca-certificates/trust-source/anchors/", Distro::Arch),
            ("/usr/local/share/ca-certificates/", Distro::Debian),
            ("/etc/pki/ca-trust/source/anchors/", Distro::RedHat),
            ("/usr/share/pki/trust/anchors/", Distro::OpenSUSE),
        ];

        for (path, distro) in checks {
            if Path::new(path).exists() {
                return *distro;
            }
        }

        Distro::Unknown
    }

    /// Directory where the certificate should be placed.
    fn cert_dir(&self) -> Option<&'static str> {
        match self {
            Distro::Arch => Some("/etc/ca-certificates/trust-source/anchors/"),
            Distro::Debian => Some("/usr/local/share/ca-certificates/"),
            Distro::RedHat => Some("/etc/pki/ca-trust/source/anchors/"),
            Distro::OpenSUSE => Some("/usr/share/pki/trust/anchors/"),
            Distro::Unknown => None,
        }
    }

    /// File extension expected by this distribution's trust tooling.
    fn cert_extension(&self) -> &'static str {
        match self {
            Distro::RedHat | Distro::OpenSUSE => "pem",
            Distro::Debian | Distro::Arch => "crt",
            Distro::Unknown => "pem",
        }
    }

    /// Command and arguments needed to refresh the system trust store.
    fn update_command(&self) -> Option<Vec<&'static str>> {
        match self {
            Distro::Arch => Some(vec!["trust", "extract-compat"]),
            Distro::Debian | Distro::OpenSUSE => Some(vec!["update-ca-certificates"]),
            Distro::RedHat => Some(vec!["update-ca-trust", "extract"]),
            Distro::Unknown => None,
        }
    }
}
