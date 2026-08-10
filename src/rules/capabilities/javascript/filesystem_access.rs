use crate::model::{Capability, Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
                    "chainsec.js.capability.filesystem-delete",
                    Language::JavaScript,
                    FindingType::FilesystemAccess,
                    Risk::Medium,
                    Confidence::High,
                    "The code can remove files or directories.",
                    super::super::LIMIT_ACCESS,
                    r#"
                (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
                  (#eq? @module "fs")
                  (#match? @method "^(rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)$")) @match
                (call_expression function: (identifier) @callee
                  (#match? @callee "^(rimraf|rimrafSync)$")) @match
                (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
                  (#eq? @deno "Deno") (#eq? @method "remove")) @match
                "#
                ).with_capability(Capability::FilesystemDelete),
        rule!(
                    "chainsec.js.capability.filesystem-read",
                    Language::JavaScript,
                    FindingType::FilesystemAccess,
                    Risk::Low,
                    Confidence::High,
                    "The Node filesystem API is used to read a file or create a read stream.",
                    super::super::LIMIT_ACCESS,
                    r#"
                (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
                  (#eq? @module "fs")
                  (#match? @method "^(readFile|readFileSync|createReadStream)$")) @match
                (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
                  (#eq? @deno "Deno") (#match? @method "^(readFile|readTextFile)$")) @match
                "#
                ).with_capability(Capability::FilesystemRead),
        rule!(
                    "chainsec.js.capability.filesystem-set-permissions",
                    Language::JavaScript,
                    FindingType::FilesystemAccess,
                    Risk::Medium,
                    Confidence::High,
                    "The code changes file mode bits and can make a dropped file executable.",
                    "Avoid changing executable bits at runtime; ship reviewed executables through the package build instead.",
                    r#"
                (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
                  (#eq? @module "fs") (#match? @method "^(chmod|chmodSync)$")) @match
                (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
                  (#eq? @deno "Deno") (#eq? @method "chmod")) @match
                "#
                ).with_capability(Capability::FilesystemSetPermissions),
        rule!(
                    "chainsec.js.capability.filesystem-write",
                    Language::JavaScript,
                    FindingType::FilesystemAccess,
                    Risk::Low,
                    Confidence::High,
                    "The Node filesystem API writes, appends, or creates a write stream.",
                    super::super::LIMIT_ACCESS,
                    r#"
                (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
                  (#eq? @module "fs")
                  (#match? @method "^(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)$")) @match
                (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
                  (#eq? @deno "Deno") (#match? @method "^(writeFile|writeTextFile)$")) @match
                "#
                ).with_capability(Capability::FilesystemWrite),
        rule!(
                    "chainsec.js.capability.filesystem-enumerate",
                    Language::JavaScript,
                    FindingType::FilesystemAccess,
                    Risk::Low,
                    Confidence::High,
                    "The code enumerates files or directories.",
                    super::super::LIMIT_ACCESS,
                    r#"
                (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
                  (#eq? @module "fs") (#match? @method "^(readdir|readdirSync|opendir|opendirSync)$")) @match
                (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
                  (#eq? @deno "Deno") (#eq? @method "readDir")) @match
                "#
                ).with_capability(Capability::FilesystemEnumerate),
        rule!(
                    "chainsec.js.capability.filesystem-archive",
                    Language::JavaScript,
                    FindingType::FilesystemAccess,
                    Risk::Low,
                    Confidence::High,
                    "The code creates or extracts an archive.",
                    super::super::LIMIT_ACCESS,
                    r#"(call_expression function: (member_expression property: (property_identifier) @method)
                  (#match? @method "^(extract|extractAll|zip|unzip|archive)$")) @match"#
                ).with_capability(Capability::FilesystemArchive),
    ]
}
