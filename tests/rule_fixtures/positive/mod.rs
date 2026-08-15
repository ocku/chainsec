//! Positive fixture cases grouped by rule responsibility.

use crate::common::Case;

mod capabilities;
mod detections;
mod guarddog;

const CASE_GROUPS: &[&[Case]] = &[detections::CASES, capabilities::CASES, guarddog::CASES];

pub(crate) fn cases() -> impl Iterator<Item = &'static Case> {
    CASE_GROUPS.iter().flat_map(|cases| cases.iter())
}
