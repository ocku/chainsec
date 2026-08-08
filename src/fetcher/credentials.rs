use reqwest::header::HeaderValue;
use url::Url;

#[derive(Clone)]
pub(super) struct ScopedCredential {
    scope: Url,
    authorization: HeaderValue,
}

impl ScopedCredential {
    pub(super) fn bearer(scope: Url, token: &str) -> Option<Self> {
        let token = token.trim();
        if token.is_empty() {
            return None;
        }
        Some(Self {
            scope,
            authorization: HeaderValue::from_str(&format!("Bearer {token}")).ok()?,
        })
    }

    fn matches(&self, url: &Url) -> bool {
        self.scope.scheme() == url.scheme()
            && self.scope.host_str() == url.host_str()
            && self.scope.port_or_known_default() == url.port_or_known_default()
            && url
                .path()
                .strip_prefix(self.scope.path())
                .is_some_and(|suffix| {
                    self.scope.path().ends_with('/') || suffix.is_empty() || suffix.starts_with('/')
                })
    }
}

pub(super) fn authorization_for(
    credentials: &[ScopedCredential],
    url: &Url,
) -> Option<HeaderValue> {
    credentials
        .iter()
        .filter(|credential| credential.matches(url))
        .max_by_key(|credential| credential.scope.path().len())
        .map(|credential| credential.authorization.clone())
}

#[cfg(test)]
mod tests {
    use super::{ScopedCredential, authorization_for};
    use url::Url;

    #[test]
    fn credentials_are_scoped_by_host_and_path() {
        let credential = ScopedCredential::bearer(
            Url::parse("https://artifacts.example/artifactory/api/npm/private/").unwrap(),
            "secret",
        )
        .unwrap();
        assert!(
            authorization_for(
                std::slice::from_ref(&credential),
                &Url::parse("https://artifacts.example/artifactory/api/npm/private/package")
                    .unwrap()
            )
            .is_some()
        );
        assert!(
            authorization_for(
                std::slice::from_ref(&credential),
                &Url::parse("https://artifacts.example/artifactory/api/npm/public/package")
                    .unwrap()
            )
            .is_none()
        );
    }
}
