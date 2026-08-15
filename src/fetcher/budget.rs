use std::time::Duration;

use crate::error::{Error, Result};

/// Cloneable deadline passed into synchronous acquisition stages and workers.
#[derive(Clone)]
pub(in crate::fetcher) struct AcquisitionDeadline {
    deadline: tokio::time::Instant,
    duration_limit: Duration,
}

impl AcquisitionDeadline {
    pub(in crate::fetcher) fn check(&self) -> Result<()> {
        if tokio::time::Instant::now() >= self.deadline {
            Err(self.exceeded())
        } else {
            Ok(())
        }
    }

    pub(in crate::fetcher) fn exceeded(&self) -> Error {
        Error::LimitExceeded {
            resource: "package acquisition seconds".to_owned(),
            limit: self.duration_limit.as_secs(),
        }
    }
}

/// Shared policy state for one package acquisition.
///
/// The deadline begins before resolution and is reused through cache restoration,
/// downloading, extraction, metadata processing, publication, and local snapshots.
pub(in crate::fetcher) struct AcquisitionBudget {
    pub(in crate::fetcher) requests: usize,
    downloaded_bytes: u64,
    max_downloaded_bytes: u64,
    deadline: AcquisitionDeadline,
}

impl AcquisitionBudget {
    pub(in crate::fetcher) fn new(duration_limit: Duration, max_downloaded_bytes: u64) -> Self {
        Self {
            requests: 0,
            downloaded_bytes: 0,
            max_downloaded_bytes,
            deadline: AcquisitionDeadline {
                deadline: tokio::time::Instant::now() + duration_limit,
                duration_limit,
            },
        }
    }

    pub(in crate::fetcher) fn deadline(&self) -> tokio::time::Instant {
        self.deadline.deadline
    }

    pub(in crate::fetcher) fn deadline_guard(&self) -> AcquisitionDeadline {
        self.deadline.clone()
    }

    pub(in crate::fetcher) fn check(&self) -> Result<()> {
        self.deadline.check()
    }

    pub(in crate::fetcher) fn account_downloaded_bytes(&mut self, bytes: usize) -> Result<()> {
        let downloaded_bytes = u64::try_from(bytes)
            .ok()
            .and_then(|bytes| self.downloaded_bytes.checked_add(bytes));
        if downloaded_bytes.is_none_or(|bytes| bytes > self.max_downloaded_bytes) {
            return Err(Error::LimitExceeded {
                resource: "download bytes per package acquisition".to_owned(),
                limit: self.max_downloaded_bytes,
            });
        }
        self.downloaded_bytes = downloaded_bytes.unwrap_or(self.max_downloaded_bytes);
        Ok(())
    }

    pub(in crate::fetcher) fn exceeded(&self) -> Error {
        self.deadline.exceeded()
    }
}

#[cfg(test)]
mod tests {
    use super::AcquisitionBudget;
    use std::time::Duration;

    #[tokio::test]
    async fn deadline_policy_is_shared_by_non_network_stages() {
        let budget = AcquisitionBudget::new(Duration::from_millis(1), 1024);
        tokio::time::sleep(Duration::from_millis(5)).await;

        let error = budget.check().unwrap_err();
        assert_eq!(error.code(), "limit_exceeded");
        assert!(error.to_string().contains("package acquisition seconds"));
    }

    #[test]
    fn downloaded_bytes_are_aggregated_across_responses() {
        let mut budget = AcquisitionBudget::new(Duration::from_secs(1), 5);
        budget.account_downloaded_bytes(3).unwrap();

        let error = budget.account_downloaded_bytes(3).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("download bytes per package acquisition")
        );
    }
}
