use crate::model::{Capability, Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
                    "chainsec.py.capability.filesystem-delete",
                    Language::Python,
                    FindingType::FilesystemAccess,
                    Risk::Medium,
                    Confidence::High,
                    "The code can remove files or directories.",
                    super::super::LIMIT_ACCESS,
                    r#"
                (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  (#match? @module "^(os|shutil)$")
                  (#match? @method "^(remove|unlink|rmdir|rmtree)$")) @match
                (call function: (attribute attribute: (identifier) @method)
                  (#eq? @method "unlink")) @match
                "#
                ).with_capability(Capability::FilesystemDelete),
        rule!(
                "chainsec.py.capability.filesystem-read",
                Language::Python,
                FindingType::FilesystemAccess,
                Risk::Low,
                Confidence::Medium,
                "The code explicitly opens a file for reading or uses a pathlib read helper.",
                super::super::LIMIT_ACCESS,
                r#"
                (call function: (identifier) @open
                  (#eq? @open "open")) @match
                (call function: (attribute object: (call function: (identifier) @path) attribute: (identifier) @method)
                  (#eq? @path "Path")
                  (#match? @method "^read_(text|bytes)$")) @match
                "#
            ).with_capability(Capability::FilesystemRead),
        rule!(
                "chainsec.py.capability.filesystem-set-permissions",
                Language::Python,
                FindingType::FilesystemAccess,
                Risk::Medium,
                Confidence::High,
                "The code changes file mode bits and can make a dropped file executable.",
                "Avoid changing executable bits at runtime; ship reviewed executables through the package build instead.",
                r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  (#eq? @module "os") (#eq? @method "chmod")) @match"#
            ).with_capability(Capability::FilesystemSetPermissions),
        rule!(
                    "chainsec.py.capability.filesystem-write",
                    Language::Python,
                    FindingType::FilesystemAccess,
                    Risk::Low,
                    Confidence::High,
                    "The code explicitly writes or appends to a file.",
                    super::super::LIMIT_ACCESS,
                    r#"
                (call function: (identifier) @open arguments: (argument_list (_) (string) @mode)
                  (#eq? @open "open") (#match? @mode "['\\\"][wax]")) @match
                (call function: (attribute object: (_) attribute: (identifier) @method)
                  (#match? @method "^write_(text|bytes)$")) @match
                "#
                ).with_capability(Capability::FilesystemWrite),
        rule!(
                "chainsec.py.capability.filesystem-enumerate",
                Language::Python,
                FindingType::FilesystemAccess,
                Risk::Low,
                Confidence::High,
                "The code enumerates files or directories.",
                super::super::LIMIT_ACCESS,
                r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  (#match? @module "^(os|glob)$") (#match? @method "^(listdir|scandir|walk|glob|iglob)$")) @match"#
            ).with_capability(Capability::FilesystemEnumerate),
        rule!(
                "chainsec.py.capability.filesystem-archive",
                Language::Python,
                FindingType::FilesystemAccess,
                Risk::Low,
                Confidence::High,
                "The code creates or extracts an archive.",
                super::super::LIMIT_ACCESS,
                r#"(call function: (attribute object: (_) attribute: (identifier) @method)
                  (#match? @method "^(extract|extractall|write|writestr|make_archive|unpack_archive)$")) @match"#
            ).with_capability(Capability::FilesystemArchive),
    ]
}
