import SwiftCompilerPlugin
import SwiftSyntaxMacros

@main
struct RunarSerializerMacrosPlugin: CompilerPlugin {
    let providingMacros: [Macro.Type] = [
        PlainMacro.self,
        EncryptedMacro.self,
    ]
} 