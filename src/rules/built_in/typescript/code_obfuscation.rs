use crate::model::{Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
            "chainsec.ts.detection.decoded-payload",
            Language::TypeScript,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::Medium,
            "Decoded payloads may conceal executable or exfiltrated data.",
            "Inspect decoded content and avoid executing data obtained at runtime.",
            r#"
                    ((call_expression function: (member_expression property: (property_identifier) @method)
                      arguments: (arguments (number) (number) . (_)*)) @match
                      (#eq? @method "fromCharCode"))
                    ((call_expression function: (member_expression property: (property_identifier) @method)
                      arguments: (arguments (string) @payload . (_)*)) @match
                      (#eq? @method "atob")
                      (#match? @payload "(?i)^['\"][A-Z0-9+/\\r\\n]{80,}={0,2}['\"]$"))
                    ((call_expression function: (identifier) @callee
                      arguments: (arguments (string) @payload . (_)*)) @match
                      (#eq? @callee "atob")
                      (#match? @payload "(?i)^['\"][A-Z0-9+/\\r\\n]{80,}={0,2}['\"]$"))
                    "#
        ),
        rule!(
            "chainsec.ts.detection.character-code-assembly",
            Language::TypeScript,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::High,
            "An array is mapped through String.fromCharCode and joined into a runtime string, concealing its contents.",
            "Replace runtime character assembly with reviewed plain text, or document and validate the generated value.",
            r#"
                    (call_expression function: (member_expression
                      object: (call_expression function: (member_expression object: (array (number) (number) (number) (number) (number) (number) (number) (number) . (_)* ) @array property: (property_identifier) @map)
                        arguments: (arguments
                          (arrow_function
                            body: (call_expression
                              function: (member_expression
                                object: (identifier) @string
                                property: (property_identifier) @decoder)))))
                      property: (property_identifier) @join)) @match
                    (#eq? @map "map") (#eq? @join "join")
                    (#eq? @string "String") (#eq? @decoder "fromCharCode")
                    (#match? @array "(?s)(?:[^,\\]]*,){7,}")
                    "#
        ),
        rule!(
            "chainsec.ts.detection.encoded-escapes",
            Language::TypeScript,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::High,
            "A string literal or concatenation contains a long sequence of hexadecimal, octal, or Unicode escape codes.",
            "Replace encoded literals with reviewed plain text, or document the encoding and validate the decoded value.",
            r#"
                    ((string) @match
                      (#match? @match "(?i)(?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}|\\\\u[0-9a-f]{4}|\\\\U[0-9a-f]{8}){16,}"))
                    ((binary_expression left: (string) @left right: (string) @right) @match
                      (#match? @left "(?i)(?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}|\\\\u[0-9a-f]{4}|\\\\U[0-9a-f]{8}){8,}")
                      (#match? @right "(?i)(?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}|\\\\u[0-9a-f]{4}|\\\\U[0-9a-f]{8}){8,}"))
                    "#
        ),
        rule!(
            "chainsec.ts.detection.ambiguous-identifier",
            Language::TypeScript,
            FindingType::CodeObfuscation,
            Risk::Low,
            Confidence::Medium,
            "An identifier resembles a generated hexadecimal name or a visually ambiguous character sequence.",
            "Rename generated or ambiguous identifiers to descriptive names before reviewing or publishing the code.",
            r#"((identifier) @match (#match? @match "(?i)^_?0x[0-9a-f]{4,}$|^[o0il1]{6,}$|^(?:\\\\u[0-9a-f]{4}){2,}$"))"#
        ),
        rule!(
            "chainsec.ts.detection.heuristic.string-table",
            Language::TypeScript,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::High,
            "A generated string-table accessor indexes an opaque string array at runtime.",
            "Inspect the accessor and replace generated opaque code with reviewed source.",
            r#"
                    ((program
                      (_)*
                      [(lexical_declaration
                         (variable_declarator
                           name: (identifier) @table
                           value: (array (string) (string) (string) (string) (string) . (_)*)) @match)
                       (variable_declaration
                         (variable_declarator
                           name: (identifier) @table
                           value: (array (string) (string) (string) (string) (string) . (_)*)) @match)]
                      (_)*
                      (function_declaration
                        body: (statement_block
                          (_)*
                          (return_statement
                            (subscript_expression
                              object: (identifier) @accessed_table))
                          (_)*))
                      (_)*)
                      (#eq? @table @accessed_table)
                      (#match? @table "^_0x[0-9A-Fa-f]{4,}$"))
                    "#
        ),
        rule!(
            "chainsec.ts.detection.javascript-obfuscator",
            Language::TypeScript,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::High,
            "A generated string-array bootstrap, self-replacing accessor, or computed accessor object matches javascript-obfuscator output.",
            "Recover the original source where possible and review the decoded behavior before use.",
            r#"
                    [
                      (function_declaration
                        name: (identifier) @bootstrap
                        body: (statement_block
                          [(lexical_declaration
                             (variable_declarator
                               name: (identifier) @table
                               value: (array (string) (string) (string) (string))))
                           (variable_declaration
                             (variable_declarator
                               name: (identifier) @table
                               value: (array (string) (string) (string) (string))))]
                          (expression_statement
                            (assignment_expression
                              left: (identifier) @replacement
                              right: (function_expression
                                parameters: (formal_parameters)
                                body: (statement_block
                                  (return_statement (identifier) @returned)))))
                          (return_statement
                            (call_expression
                              function: (identifier) @invoked
                              arguments: (arguments)))) @match
                        (#eq? @bootstrap @replacement)
                        (#eq? @bootstrap @invoked)
                        (#eq? @table @returned))
                      (return_statement
                        (sequence_expression
                          (update_expression)
                          (object
                            (pair
                              key: (computed_property_name (string) @accessor)
                              value: (_))
                            (pair
                              key: (computed_property_name (string) @accessor)
                              value: (_)))) @match
                        (#match? @accessor "^['\\\"]_\\$"))
                    ]
                    "#
        ),
        rule!(
            "chainsec.ts.detection.javascript-obfuscator-vm-identifier",
            Language::TypeScript,
            FindingType::CodeObfuscation,
            Risk::Low,
            Confidence::Medium,
            "An identifier uses the vmz_/vme_ generated-name convention associated with javascript-obfuscator VM output.",
            "Recover the original source where possible and review the generated virtual-machine code before use.",
            r#"((identifier) @match (#match? @match "^(vmz|vme)_[0-9a-f]{6,}$"))"#
        ),
        rule!(
            "chainsec.ts.detection.heuristic.rc4-decoder",
            Language::TypeScript,
            FindingType::CodeObfuscation,
            Risk::High,
            Confidence::Medium,
            "A 256-byte stream-cipher-like decoder reconstructs runtime strings.",
            "Inspect the decoded content and do not execute reconstructed payloads.",
            r#"
                    ((function_declaration
                      body: (statement_block
                        (_)*
                        [(lexical_declaration
                           (variable_declarator
                             name: (identifier) @state
                             value: [(call_expression
                                       function: (identifier) @array
                                       arguments: (arguments (number) @size))
                                     (new_expression
                                       constructor: (identifier) @array
                                       arguments: (arguments (number) @size))]) @match)
                         (variable_declaration
                           (variable_declarator
                             name: (identifier) @state
                             value: [(call_expression
                                       function: (identifier) @array
                                       arguments: (arguments (number) @size))
                                     (new_expression
                                       constructor: (identifier) @array
                                       arguments: (arguments (number) @size))]) @match)]
                        (_)*
                        (return_statement
                          (call_expression
                            function: (member_expression
                              object: (identifier) @string
                              property: (property_identifier) @from_char_code)
                            arguments: (arguments
                              (binary_expression
                                left: (call_expression
                                  function: (member_expression
                                    property: (property_identifier) @char_code_at))
                                operator: "^"
                                right: (subscript_expression
                                  object: (identifier) @used_state)))))
                        (_)*))
                      (#eq? @array "Array")
                      (#eq? @size "256")
                      (#eq? @state @used_state)
                      (#eq? @string "String")
                      (#eq? @from_char_code "fromCharCode")
                      (#eq? @char_code_at "charCodeAt"))
                    "#
        ),
        rule!(
            "chainsec.ts.detection.heuristic.embedded-vm",
            Language::TypeScript,
            FindingType::CodeObfuscation,
            Risk::High,
            Confidence::Medium,
            "Bytecode, opcode, and dispatch structures suggest an embedded virtual machine.",
            "Inspect the bytecode interpreter and recover reviewed source before use.",
            r#"
                    (while_statement
                      condition: (parenthesized_expression (identifier) @opcode)
                      body: (statement_block
                        (switch_statement
                          value: (parenthesized_expression (identifier) @dispatch))) @match
                      (#match? @opcode "^(?:opcode|dispatch|instruction)$")
                      (#match? @dispatch "^(?:opcode|dispatch|instruction)$"))
                    "#
        ),
        rule!(
            "chainsec.ts.detection.heuristic.control-flow-flattening",
            Language::TypeScript,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::High,
            "A loop-and-switch dispatcher resembles control-flow flattening.",
            "Review the dispatcher and restore straightforward control flow before trusting it.",
            r#"
                    (while_statement
                      body: (statement_block
                        (switch_statement
                          value: (parenthesized_expression
                            (subscript_expression
                              index: (update_expression)))
                          body: (switch_body (switch_case))))) @match
                    "#
        ),
        {
            let mut rule = rule!(
                "chainsec.ts.detection.heuristic.high-entropy-string",
                Language::TypeScript,
                FindingType::CodeObfuscation,
                Risk::Medium,
                Confidence::Medium,
                "A string literal has unusually high Shannon entropy and may contain encrypted or packed data.",
                "Inspect and decode the value, document its origin, and avoid embedding opaque executable payloads.",
                r#"(string) @match"#
            );
            rule.entropy = Some(crate::model::EntropyMatcher {
                minimum_length: 32,
                minimum_entropy: 5.0,
                maximum_whitespace_ratio: 0.05,
            });
            rule
        },
    ]
}
