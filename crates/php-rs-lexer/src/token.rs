//! Token definitions matching PHP's token types
//!
//! Reference: php-src/Zend/zend_language_parser.y

/// Represents a token type in PHP source code.
/// This enum matches all tokens defined in php-src/Zend/zend_language_parser.y
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Token {
    // Literals
    /// Integer literal (T_LNUMBER)
    LNumber,
    /// Floating-point literal (T_DNUMBER)
    DNumber,
    /// Identifier (T_STRING)
    String,
    /// Fully qualified name with leading backslash (T_NAME_FULLY_QUALIFIED)
    NameFullyQualified,
    /// Namespace-relative name starting with 'namespace\' (T_NAME_RELATIVE)
    NameRelative,
    /// Namespaced name (T_NAME_QUALIFIED)
    NameQualified,
    /// Variable starting with $ (T_VARIABLE)
    Variable,
    /// Inline HTML outside of <?php tags (T_INLINE_HTML)
    InlineHtml,
    /// String content in double-quoted strings (T_ENCAPSED_AND_WHITESPACE)
    EncapsedAndWhitespace,
    /// Constant encapsed string (T_CONSTANT_ENCAPSED_STRING)
    ConstantEncapsedString,
    /// Variable name in strings (T_STRING_VARNAME)
    StringVarname,
    /// Numeric string (T_NUM_STRING)
    NumString,

    // Keywords - Include/Require
    /// 'include' keyword (T_INCLUDE)
    Include,
    /// 'include_once' keyword (T_INCLUDE_ONCE)
    IncludeOnce,
    /// 'eval' keyword (T_EVAL)
    Eval,
    /// 'require' keyword (T_REQUIRE)
    Require,
    /// 'require_once' keyword (T_REQUIRE_ONCE)
    RequireOnce,

    // Keywords - Logical operators
    /// 'or' keyword (T_LOGICAL_OR)
    LogicalOr,
    /// 'xor' keyword (T_LOGICAL_XOR)
    LogicalXor,
    /// 'and' keyword (T_LOGICAL_AND)
    LogicalAnd,

    // Keywords - Control structures
    /// 'print' keyword (T_PRINT)
    Print,
    /// 'yield' keyword (T_YIELD)
    Yield,
    /// 'yield from' keywords (T_YIELD_FROM)
    YieldFrom,
    /// 'instanceof' keyword (T_INSTANCEOF)
    Instanceof,
    /// 'new' keyword (T_NEW)
    New,
    /// 'clone' keyword (T_CLONE)
    Clone,
    /// 'exit' or 'die' keyword (T_EXIT)
    Exit,
    /// 'if' keyword (T_IF)
    If,
    /// 'elseif' keyword (T_ELSEIF)
    Elseif,
    /// 'else' keyword (T_ELSE)
    Else,
    /// 'endif' keyword (T_ENDIF)
    Endif,
    /// 'echo' keyword (T_ECHO)
    Echo,
    /// 'do' keyword (T_DO)
    Do,
    /// 'while' keyword (T_WHILE)
    While,
    /// 'endwhile' keyword (T_ENDWHILE)
    Endwhile,
    /// 'for' keyword (T_FOR)
    For,
    /// 'endfor' keyword (T_ENDFOR)
    Endfor,
    /// 'foreach' keyword (T_FOREACH)
    Foreach,
    /// 'endforeach' keyword (T_ENDFOREACH)
    Endforeach,
    /// 'declare' keyword (T_DECLARE)
    Declare,
    /// 'enddeclare' keyword (T_ENDDECLARE)
    Enddeclare,
    /// 'as' keyword (T_AS)
    As,
    /// 'switch' keyword (T_SWITCH)
    Switch,
    /// 'endswitch' keyword (T_ENDSWITCH)
    Endswitch,
    /// 'case' keyword (T_CASE)
    Case,
    /// 'default' keyword (T_DEFAULT)
    Default,
    /// 'match' keyword (T_MATCH)
    Match,
    /// 'break' keyword (T_BREAK)
    Break,
    /// 'continue' keyword (T_CONTINUE)
    Continue,
    /// 'goto' keyword (T_GOTO)
    Goto,

    // Keywords - Functions
    /// 'function' keyword (T_FUNCTION)
    Function,
    /// 'fn' keyword for arrow functions (T_FN)
    Fn,
    /// 'const' keyword (T_CONST)
    Const,
    /// 'return' keyword (T_RETURN)
    Return,

    // Keywords - Exception handling
    /// 'try' keyword (T_TRY)
    Try,
    /// 'catch' keyword (T_CATCH)
    Catch,
    /// 'finally' keyword (T_FINALLY)
    Finally,
    /// 'throw' keyword (T_THROW)
    Throw,

    // Keywords - Namespaces and use
    /// 'use' keyword (T_USE)
    Use,
    /// 'insteadof' keyword for traits (T_INSTEADOF)
    Insteadof,

    // Keywords - Scope
    /// 'global' keyword (T_GLOBAL)
    Global,
    /// 'static' keyword (T_STATIC)
    Static,

    // Keywords - Class modifiers
    /// 'abstract' keyword (T_ABSTRACT)
    Abstract,
    /// 'final' keyword (T_FINAL)
    Final,
    /// 'private' keyword (T_PRIVATE)
    Private,
    /// 'protected' keyword (T_PROTECTED)
    Protected,
    /// 'public' keyword (T_PUBLIC)
    Public,
    /// 'private(set)' asymmetric visibility (T_PRIVATE_SET)
    PrivateSet,
    /// 'protected(set)' asymmetric visibility (T_PROTECTED_SET)
    ProtectedSet,
    /// 'public(set)' asymmetric visibility (T_PUBLIC_SET)
    PublicSet,
    /// 'readonly' keyword (T_READONLY)
    Readonly,
    /// 'var' keyword (T_VAR)
    Var,

    // Keywords - Variable handling
    /// 'unset' keyword (T_UNSET)
    Unset,
    /// 'isset' keyword (T_ISSET)
    Isset,
    /// 'empty' keyword (T_EMPTY)
    Empty,

    // Keywords - Special
    /// '__halt_compiler' keyword (T_HALT_COMPILER)
    HaltCompiler,

    // Keywords - Class/Interface/Trait/Enum
    /// 'class' keyword (T_CLASS)
    Class,
    /// 'trait' keyword (T_TRAIT)
    Trait,
    /// 'interface' keyword (T_INTERFACE)
    Interface,
    /// 'enum' keyword (T_ENUM)
    Enum,
    /// 'extends' keyword (T_EXTENDS)
    Extends,
    /// 'implements' keyword (T_IMPLEMENTS)
    Implements,

    // Keywords - Namespaces
    /// 'namespace' keyword (T_NAMESPACE)
    Namespace,

    // Keywords - Types and arrays
    /// 'list' keyword (T_LIST)
    List,
    /// 'array' keyword (T_ARRAY)
    Array,
    /// 'callable' keyword (T_CALLABLE)
    Callable,

    // Magic constants
    /// __LINE__ magic constant (T_LINE)
    Line,
    /// __FILE__ magic constant (T_FILE)
    File,
    /// __DIR__ magic constant (T_DIR)
    Dir,
    /// __CLASS__ magic constant (T_CLASS_C)
    ClassC,
    /// __TRAIT__ magic constant (T_TRAIT_C)
    TraitC,
    /// __METHOD__ magic constant (T_METHOD_C)
    MethodC,
    /// __FUNCTION__ magic constant (T_FUNC_C)
    FuncC,
    /// __PROPERTY__ magic constant (T_PROPERTY_C)
    PropertyC,
    /// __NAMESPACE__ magic constant (T_NS_C)
    NsC,

    // Special tokens
    /// End of file (END)
    End,
    /// Attribute syntax #[ (T_ATTRIBUTE)
    Attribute,

    // Compound assignment operators
    /// += operator (T_PLUS_EQUAL)
    PlusEqual,
    /// -= operator (T_MINUS_EQUAL)
    MinusEqual,
    /// *= operator (T_MUL_EQUAL)
    MulEqual,
    /// /= operator (T_DIV_EQUAL)
    DivEqual,
    /// .= operator (T_CONCAT_EQUAL)
    ConcatEqual,
    /// %= operator (T_MOD_EQUAL)
    ModEqual,
    /// &= operator (T_AND_EQUAL)
    AndEqual,
    /// |= operator (T_OR_EQUAL)
    OrEqual,
    /// ^= operator (T_XOR_EQUAL)
    XorEqual,
    /// <<= operator (T_SL_EQUAL)
    SlEqual,
    /// >>= operator (T_SR_EQUAL)
    SrEqual,
    /// ??= operator (T_COALESCE_EQUAL)
    CoalesceEqual,

    // Boolean operators
    /// || operator (T_BOOLEAN_OR)
    BooleanOr,
    /// && operator (T_BOOLEAN_AND)
    BooleanAnd,

    // Comparison operators
    /// == operator (T_IS_EQUAL)
    IsEqual,
    /// != operator (T_IS_NOT_EQUAL)
    IsNotEqual,
    /// === operator (T_IS_IDENTICAL)
    IsIdentical,
    /// !== operator (T_IS_NOT_IDENTICAL)
    IsNotIdentical,
    /// <= operator (T_IS_SMALLER_OR_EQUAL)
    IsSmallerOrEqual,
    /// >= operator (T_IS_GREATER_OR_EQUAL)
    IsGreaterOrEqual,
    /// <=> spaceship operator (T_SPACESHIP)
    Spaceship,

    // Bitwise shift operators
    /// << operator (T_SL)
    Sl,
    /// >> operator (T_SR)
    Sr,

    // Increment/decrement
    /// ++ operator (T_INC)
    Inc,
    /// -- operator (T_DEC)
    Dec,

    // Cast operators
    /// (int) cast (T_INT_CAST)
    IntCast,
    /// (float) or (double) cast (T_DOUBLE_CAST)
    DoubleCast,
    /// (string) cast (T_STRING_CAST)
    StringCast,
    /// (array) cast (T_ARRAY_CAST)
    ArrayCast,
    /// (object) cast (T_OBJECT_CAST)
    ObjectCast,
    /// (bool) cast (T_BOOL_CAST)
    BoolCast,
    /// (unset) cast (T_UNSET_CAST)
    UnsetCast,
    /// (void) cast (T_VOID_CAST)
    VoidCast,

    // Object operators
    /// -> object operator (T_OBJECT_OPERATOR)
    ObjectOperator,
    /// ?-> nullsafe object operator (T_NULLSAFE_OBJECT_OPERATOR)
    NullsafeObjectOperator,
    /// => double arrow (T_DOUBLE_ARROW)
    DoubleArrow,

    // Comments and whitespace
    /// Comment (T_COMMENT)
    Comment,
    /// Doc comment (T_DOC_COMMENT)
    DocComment,
    /// Whitespace (T_WHITESPACE)
    Whitespace,

    // PHP tags
    /// <?php or <? open tag (T_OPEN_TAG)
    OpenTag,
    /// <?= open tag with echo (T_OPEN_TAG_WITH_ECHO)
    OpenTagWithEcho,
    /// ?> close tag (T_CLOSE_TAG)
    CloseTag,

    // Heredoc/Nowdoc
    /// Heredoc start (T_START_HEREDOC)
    StartHeredoc,
    /// Heredoc end (T_END_HEREDOC)
    EndHeredoc,

    // String interpolation
    /// ${ in strings (T_DOLLAR_OPEN_CURLY_BRACES)
    DollarOpenCurlyBraces,
    /// {$ in strings (T_CURLY_OPEN)
    CurlyOpen,

    // Scope resolution
    /// :: operator, Paamayim Nekudotayim (T_PAAMAYIM_NEKUDOTAYIM)
    PaamayimNekudotayim,
    /// \ namespace separator (T_NS_SEPARATOR)
    NsSeparator,

    // Other operators
    /// ... ellipsis/spread/variadic (T_ELLIPSIS)
    Ellipsis,
    /// ?? null coalesce operator (T_COALESCE)
    Coalesce,
    /// ** power operator (T_POW)
    Pow,
    /// **= power assignment (T_POW_EQUAL)
    PowEqual,
    /// |> pipe operator (T_PIPE)
    Pipe,

    // Ampersand handling (context-sensitive)
    /// & followed by variable or vararg (T_AMPERSAND_FOLLOWED_BY_VAR_OR_VARARG)
    AmpersandFollowedByVarOrVararg,
    /// & not followed by variable or vararg (T_AMPERSAND_NOT_FOLLOWED_BY_VAR_OR_VARARG)
    AmpersandNotFollowedByVarOrVararg,

    // Error tokens
    /// Invalid character (T_BAD_CHARACTER)
    BadCharacter,
    /// Error token (T_ERROR)
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_construction() {
        // Test that all token variants can be constructed
        let _literals = [
            Token::LNumber,
            Token::DNumber,
            Token::String,
            Token::NameFullyQualified,
            Token::NameRelative,
            Token::NameQualified,
            Token::Variable,
            Token::InlineHtml,
            Token::EncapsedAndWhitespace,
            Token::ConstantEncapsedString,
            Token::StringVarname,
            Token::NumString,
        ];

        let _keywords = [
            Token::Include,
            Token::IncludeOnce,
            Token::Eval,
            Token::Require,
            Token::RequireOnce,
            Token::LogicalOr,
            Token::LogicalXor,
            Token::LogicalAnd,
            Token::Print,
            Token::Yield,
            Token::YieldFrom,
            Token::Instanceof,
            Token::New,
            Token::Clone,
            Token::Exit,
            Token::If,
            Token::Elseif,
            Token::Else,
            Token::Endif,
            Token::Echo,
            Token::Do,
            Token::While,
            Token::Endwhile,
            Token::For,
            Token::Endfor,
            Token::Foreach,
            Token::Endforeach,
            Token::Declare,
            Token::Enddeclare,
            Token::As,
            Token::Switch,
            Token::Endswitch,
            Token::Case,
            Token::Default,
            Token::Match,
            Token::Break,
            Token::Continue,
            Token::Goto,
            Token::Function,
            Token::Fn,
            Token::Const,
            Token::Return,
            Token::Try,
            Token::Catch,
            Token::Finally,
            Token::Throw,
            Token::Use,
            Token::Insteadof,
            Token::Global,
            Token::Static,
            Token::Abstract,
            Token::Final,
            Token::Private,
            Token::Protected,
            Token::Public,
            Token::PrivateSet,
            Token::ProtectedSet,
            Token::PublicSet,
            Token::Readonly,
            Token::Var,
            Token::Unset,
            Token::Isset,
            Token::Empty,
            Token::HaltCompiler,
            Token::Class,
            Token::Trait,
            Token::Interface,
            Token::Enum,
            Token::Extends,
            Token::Implements,
            Token::Namespace,
            Token::List,
            Token::Array,
            Token::Callable,
        ];

        let _magic_constants = [
            Token::Line,
            Token::File,
            Token::Dir,
            Token::ClassC,
            Token::TraitC,
            Token::MethodC,
            Token::FuncC,
            Token::PropertyC,
            Token::NsC,
        ];

        let _operators = [
            Token::Attribute,
            Token::PlusEqual,
            Token::MinusEqual,
            Token::MulEqual,
            Token::DivEqual,
            Token::ConcatEqual,
            Token::ModEqual,
            Token::AndEqual,
            Token::OrEqual,
            Token::XorEqual,
            Token::SlEqual,
            Token::SrEqual,
            Token::CoalesceEqual,
            Token::BooleanOr,
            Token::BooleanAnd,
            Token::IsEqual,
            Token::IsNotEqual,
            Token::IsIdentical,
            Token::IsNotIdentical,
            Token::IsSmallerOrEqual,
            Token::IsGreaterOrEqual,
            Token::Spaceship,
            Token::Sl,
            Token::Sr,
            Token::Inc,
            Token::Dec,
            Token::IntCast,
            Token::DoubleCast,
            Token::StringCast,
            Token::ArrayCast,
            Token::ObjectCast,
            Token::BoolCast,
            Token::UnsetCast,
            Token::VoidCast,
            Token::ObjectOperator,
            Token::NullsafeObjectOperator,
            Token::DoubleArrow,
            Token::PaamayimNekudotayim,
            Token::NsSeparator,
            Token::Ellipsis,
            Token::Coalesce,
            Token::Pow,
            Token::PowEqual,
            Token::Pipe,
            Token::AmpersandFollowedByVarOrVararg,
            Token::AmpersandNotFollowedByVarOrVararg,
        ];

        let _other = [
            Token::Comment,
            Token::DocComment,
            Token::Whitespace,
            Token::OpenTag,
            Token::OpenTagWithEcho,
            Token::CloseTag,
            Token::StartHeredoc,
            Token::EndHeredoc,
            Token::DollarOpenCurlyBraces,
            Token::CurlyOpen,
            Token::BadCharacter,
            Token::Error,
            Token::End,
        ];
    }

    #[test]
    fn test_token_equality() {
        assert_eq!(Token::LNumber, Token::LNumber);
        assert_ne!(Token::LNumber, Token::DNumber);
        assert_eq!(Token::If, Token::If);
        assert_ne!(Token::If, Token::Else);
    }

    #[test]
    fn test_token_clone() {
        let token = Token::Function;
        let cloned = token.clone();
        assert_eq!(token, cloned);
    }

    #[test]
    fn test_token_debug() {
        // Ensure Debug trait works
        let token = Token::Echo;
        let debug_str = format!("{:?}", token);
        assert_eq!(debug_str, "Echo");
    }

    #[test]
    fn test_all_keywords_distinct() {
        // Verify that all keyword tokens are distinct
        use std::collections::HashSet;
        let mut set = HashSet::new();

        let tokens = vec![
            Token::If,
            Token::Else,
            Token::Elseif,
            Token::Endif,
            Token::While,
            Token::Endwhile,
            Token::Do,
            Token::For,
            Token::Endfor,
            Token::Foreach,
            Token::Endforeach,
            Token::Switch,
            Token::Endswitch,
            Token::Case,
            Token::Default,
            Token::Match,
            Token::Break,
            Token::Continue,
            Token::Return,
            Token::Function,
            Token::Fn,
            Token::Class,
            Token::Interface,
            Token::Trait,
            Token::Enum,
            Token::Public,
            Token::Protected,
            Token::Private,
            Token::Static,
            Token::Final,
            Token::Abstract,
            Token::Readonly,
            Token::Namespace,
            Token::Use,
            Token::As,
            Token::Try,
            Token::Catch,
            Token::Finally,
            Token::Throw,
            Token::New,
            Token::Clone,
            Token::Instanceof,
            Token::Echo,
            Token::Print,
            Token::Yield,
            Token::YieldFrom,
            Token::Include,
            Token::IncludeOnce,
            Token::Require,
            Token::RequireOnce,
            Token::Eval,
            Token::Isset,
            Token::Empty,
            Token::Unset,
            Token::LogicalOr,
            Token::LogicalAnd,
            Token::LogicalXor,
        ];

        for token in tokens.iter() {
            assert!(set.insert(token), "Duplicate token found: {:?}", token);
        }
    }

    #[test]
    fn test_operators_distinct() {
        // Verify that all operator tokens are distinct
        use std::collections::HashSet;
        let mut set = HashSet::new();

        let tokens = vec![
            Token::PlusEqual,
            Token::MinusEqual,
            Token::MulEqual,
            Token::DivEqual,
            Token::ConcatEqual,
            Token::ModEqual,
            Token::AndEqual,
            Token::OrEqual,
            Token::XorEqual,
            Token::SlEqual,
            Token::SrEqual,
            Token::IsEqual,
            Token::IsNotEqual,
            Token::IsIdentical,
            Token::IsNotIdentical,
            Token::IsSmallerOrEqual,
            Token::IsGreaterOrEqual,
            Token::Spaceship,
            Token::Coalesce,
            Token::CoalesceEqual,
            Token::BooleanAnd,
            Token::BooleanOr,
            Token::Inc,
            Token::Dec,
            Token::Sl,
            Token::Sr,
            Token::Pow,
            Token::PowEqual,
            Token::ObjectOperator,
            Token::NullsafeObjectOperator,
            Token::DoubleArrow,
            Token::PaamayimNekudotayim,
            Token::Ellipsis,
            Token::Attribute,
        ];

        for token in tokens.iter() {
            assert!(set.insert(token), "Duplicate token found: {:?}", token);
        }
    }

    #[test]
    fn test_magic_constants_distinct() {
        // Verify that all magic constant tokens are distinct
        use std::collections::HashSet;
        let mut set = HashSet::new();

        let tokens = vec![
            Token::Line,
            Token::File,
            Token::Dir,
            Token::ClassC,
            Token::TraitC,
            Token::MethodC,
            Token::FuncC,
            Token::PropertyC,
            Token::NsC,
        ];

        for token in tokens.iter() {
            assert!(set.insert(token), "Duplicate token found: {:?}", token);
        }
    }

    #[test]
    fn test_cast_operators_distinct() {
        // Verify that all cast operator tokens are distinct
        use std::collections::HashSet;
        let mut set = HashSet::new();

        let tokens = [
            Token::IntCast,
            Token::DoubleCast,
            Token::StringCast,
            Token::ArrayCast,
            Token::ObjectCast,
            Token::BoolCast,
            Token::UnsetCast,
            Token::VoidCast,
        ];

        for token in tokens.iter() {
            assert!(set.insert(token), "Duplicate token found: {:?}", token);
        }
    }
}
