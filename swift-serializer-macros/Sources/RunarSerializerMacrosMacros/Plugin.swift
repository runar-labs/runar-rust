import SwiftCompilerPlugin
import SwiftSyntaxMacros

@main
struct RunarSerializerMacrosPlugin: CompilerPlugin {
    let providingMacros: [Macro.Type] = [
        TestMacro.self,
        PlainMacro.self,
        EncryptedMacro.self,
    ]
} 