/// The status of a single devcert component checked during a diagnostic run.
pub enum Component {
    /// The component is present and valid.
    Ok,
    /// The component is absent and needs to be created or installed.
    Missing,
    /// The component is present but in an invalid or corrupted state.
    Invalid {
        /// A description of why the component is considered invalid.
        reason: String,
    },
    /// The component check was skipped.
    Skipped {
        /// The reason the check was skipped (e.g. `"Cert does not exist at given path"`).
        because: &'static str,
    },
}

impl Component {
    /// Returns `true` if the component is [`Component::Ok`].
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }
}
