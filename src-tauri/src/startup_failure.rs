use crate::error::AppError;
use crate::process_lease::DATA_DIRECTORY_LEASE_CONTENTION_MESSAGE;
#[cfg(any(unix, test))]
use std::ffi::OsStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DisplayLanguage {
    English,
    TraditionalChinese,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartupResource {
    LocalDataDirectory,
    InstalledResources,
    CaseDatabase,
    ArtifactStorage,
    Application,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum StartupFailure {
    DataDirectoryInUse,
    Preparation {
        resource: StartupResource,
        detail: String,
    },
}

impl StartupFailure {
    pub(crate) fn preparation(resource: StartupResource, error: impl std::fmt::Display) -> Self {
        Self::Preparation {
            resource,
            detail: error.to_string(),
        }
    }

    pub(crate) fn lease(error: AppError) -> Self {
        match error {
            AppError::NotAvailable(message)
                if message == DATA_DIRECTORY_LEASE_CONTENTION_MESSAGE =>
            {
                Self::DataDirectoryInUse
            }
            error => Self::preparation(StartupResource::LocalDataDirectory, error),
        }
    }

    pub(crate) fn message(&self, language: DisplayLanguage) -> String {
        match (self, language) {
            (Self::DataDirectoryInUse, DisplayLanguage::English) =>
                "Another ai-security-scanner desktop or maintenance operation is using this local data directory; close it and try again."
                    .into(),
            (Self::DataDirectoryInUse, DisplayLanguage::TraditionalChinese) =>
                "另一個 ai-security-scanner 桌面程式或維護作業正在使用這個本機資料目錄；請關閉它，然後再試一次。"
                    .into(),
            (Self::Preparation { resource, detail }, DisplayLanguage::English) => format!(
                "ai-security-scanner could not {}: {}.",
                resource.english_action(),
                detail.trim_end_matches('.')
            ),
            (Self::Preparation { resource, detail }, DisplayLanguage::TraditionalChinese) => {
                format!(
                    "ai-security-scanner 無法{}：{}。",
                    resource.traditional_chinese_action(),
                    detail.trim_end_matches(['.', '。'])
                )
            }
        }
    }
}

impl StartupResource {
    fn english_action(self) -> &'static str {
        match self {
            Self::LocalDataDirectory => "prepare its local data directory",
            Self::InstalledResources => "locate its installed application files",
            Self::CaseDatabase => "open its saved scan data",
            Self::ArtifactStorage => "prepare its local scan-file storage",
            Self::Application => "start the application",
        }
    }

    fn traditional_chinese_action(self) -> &'static str {
        match self {
            Self::LocalDataDirectory => "準備本機資料目錄",
            Self::InstalledResources => "找到已安裝的應用程式檔案",
            Self::CaseDatabase => "開啟已儲存的掃描資料",
            Self::ArtifactStorage => "準備本機掃描檔案儲存空間",
            Self::Application => "啟動應用程式",
        }
    }
}

#[cfg(unix)]
pub(crate) fn display_language() -> DisplayLanguage {
    display_language_from_unix_locales(
        std::env::var_os("LC_ALL").as_deref(),
        std::env::var_os("LC_MESSAGES").as_deref(),
        std::env::var_os("LANG").as_deref(),
    )
}

#[cfg(windows)]
pub(crate) fn display_language() -> DisplayLanguage {
    const PRIMARY_LANGUAGE_MASK: u16 = 0x03ff;
    const CHINESE_PRIMARY_LANGUAGE: u16 = 0x0004;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "GetUserDefaultUILanguage"]
        fn get_user_default_ui_language() -> u16;
    }

    let language = unsafe { get_user_default_ui_language() };
    if language & PRIMARY_LANGUAGE_MASK == CHINESE_PRIMARY_LANGUAGE {
        DisplayLanguage::TraditionalChinese
    } else {
        DisplayLanguage::English
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn display_language() -> DisplayLanguage {
    DisplayLanguage::English
}

#[cfg(any(unix, test))]
fn display_language_from_unix_locales(
    lc_all: Option<&OsStr>,
    lc_messages: Option<&OsStr>,
    lang: Option<&OsStr>,
) -> DisplayLanguage {
    [lc_all, lc_messages, lang]
        .into_iter()
        .flatten()
        .find(|value| !value.is_empty())
        .and_then(OsStr::to_str)
        .filter(|value| value.starts_with("zh"))
        .map_or(DisplayLanguage::English, |_| {
            DisplayLanguage::TraditionalChinese
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_lease::DataDirectoryExclusiveLease;

    fn language(locale: Option<&str>) -> DisplayLanguage {
        display_language_from_unix_locales(locale.map(OsStr::new), None, None)
    }

    #[test]
    fn traditional_chinese_unix_locales_are_selected() {
        assert_eq!(
            language(Some("zh_TW.UTF-8")),
            DisplayLanguage::TraditionalChinese
        );
        assert_eq!(
            language(Some("zh_CN.UTF-8")),
            DisplayLanguage::TraditionalChinese
        );
    }

    #[test]
    fn english_empty_unset_and_malformed_unix_locales_are_selected() {
        assert_eq!(language(Some("en_US.UTF-8")), DisplayLanguage::English);
        assert_eq!(language(Some("")), DisplayLanguage::English);
        assert_eq!(language(None), DisplayLanguage::English);
        assert_eq!(language(Some("not-a-locale")), DisplayLanguage::English);
    }

    #[test]
    fn empty_unix_locale_variables_fall_through_in_priority_order() {
        assert_eq!(
            display_language_from_unix_locales(
                Some(OsStr::new("")),
                Some(OsStr::new("zh_TW.UTF-8")),
                Some(OsStr::new("en_US.UTF-8")),
            ),
            DisplayLanguage::TraditionalChinese
        );
        assert_eq!(
            display_language_from_unix_locales(
                None,
                Some(OsStr::new("en_US.UTF-8")),
                Some(OsStr::new("zh_TW.UTF-8")),
            ),
            DisplayLanguage::English
        );
    }

    #[test]
    fn operating_system_language_resolver_returns_a_supported_language() {
        assert!(matches!(
            display_language(),
            DisplayLanguage::English | DisplayLanguage::TraditionalChinese
        ));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_unix_locale_is_treated_as_malformed() {
        use std::os::unix::ffi::OsStrExt;

        assert_eq!(
            display_language_from_unix_locales(Some(OsStr::from_bytes(&[0xff])), None, None),
            DisplayLanguage::English
        );
    }

    #[test]
    fn lease_contention_uses_an_actionable_startup_message() {
        let temporary = tempfile::tempdir().unwrap();
        let first = DataDirectoryExclusiveLease::acquire(temporary.path()).unwrap();
        let error = DataDirectoryExclusiveLease::acquire(temporary.path()).unwrap_err();

        let failure = StartupFailure::lease(error);

        assert_eq!(failure, StartupFailure::DataDirectoryInUse);
        assert_eq!(
            failure.message(DisplayLanguage::English),
            "Another ai-security-scanner desktop or maintenance operation is using this local data directory; close it and try again."
        );
        assert_eq!(
            failure.message(DisplayLanguage::TraditionalChinese),
            "另一個 ai-security-scanner 桌面程式或維護作業正在使用這個本機資料目錄；請關閉它，然後再試一次。"
        );

        drop(first);
    }

    #[test]
    fn preparation_failures_name_each_startup_resource() {
        for (resource, expected) in [
            (StartupResource::LocalDataDirectory, "local data directory"),
            (
                StartupResource::InstalledResources,
                "installed application files",
            ),
            (StartupResource::CaseDatabase, "saved scan data"),
            (StartupResource::ArtifactStorage, "local scan-file storage"),
            (StartupResource::Application, "start the application"),
        ] {
            let message = StartupFailure::preparation(resource, "example error")
                .message(DisplayLanguage::English);
            assert!(message.contains(expected));
            assert!(message.contains("example error"));
        }
    }
}
