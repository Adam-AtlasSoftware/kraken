//! Pagination types shared by every query (decision 38).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Largest page size any query may return.
pub const MAX_PAGE_LIMIT: u32 = 500;
/// Page size used when a request gives no limit.
pub const DEFAULT_PAGE_LIMIT: u32 = 100;

/// Cursor and size for one page of a paginated query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PageRequest {
    /// Opaque cursor from a previous [`Page::next_cursor`]; absent for the first page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Requested page size; clamped to [`MAX_PAGE_LIMIT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl PageRequest {
    /// The limit to apply: the default when unset, never 0, never above [`MAX_PAGE_LIMIT`].
    pub fn effective_limit(&self) -> u32 {
        self.limit
            .unwrap_or(DEFAULT_PAGE_LIMIT)
            .clamp(1, MAX_PAGE_LIMIT)
    }
}

/// One page of results with an optional cursor for the next page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Page<T> {
    /// The items on this page.
    pub items: Vec<T>,
    /// Cursor for the next page; absent on the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Total item count when the engine can cheaply provide it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_limit_is_clamped() {
        let l = |limit| {
            PageRequest {
                cursor: None,
                limit,
            }
            .effective_limit()
        };
        assert_eq!(l(None), DEFAULT_PAGE_LIMIT);
        assert_eq!(l(Some(0)), 1);
        assert_eq!(l(Some(7)), 7);
        assert_eq!(l(Some(u32::MAX)), MAX_PAGE_LIMIT);
    }

    #[test]
    fn round_trip() {
        let req = PageRequest {
            cursor: Some("abc".into()),
            limit: Some(10),
        };
        let back: PageRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(back, req);
        let page = Page {
            items: vec![1u32, 2],
            next_cursor: Some("n".into()),
            total: Some(9),
        };
        let back: Page<u32> = serde_json::from_str(&serde_json::to_string(&page).unwrap()).unwrap();
        assert_eq!(back, page);
        assert_eq!(
            serde_json::to_string(&PageRequest::default()).unwrap(),
            "{}"
        );
    }
}
