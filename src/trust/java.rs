impl super::TrustStore for JavaTrustStore {
    fn check(&self, id: &str) -> bool {
        todo!()
    }

    fn install(&self, id: &str, cert_path: &std::path::Path) -> anyhow::Result<()> {
        todo!()
    }

    fn uninstall(&self, id: &str) -> anyhow::Result<()> {
        todo!()
    }
}

pub struct JavaTrustStore;
