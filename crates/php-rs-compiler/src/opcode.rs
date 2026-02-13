//! PHP VM opcode definitions.
//!
//! All 212 opcodes from php-src/Zend/zend_vm_opcodes.h (PHP 8.6).
//! Opcode 45 is reserved/skipped in the reference implementation.

/// All 212 Zend VM opcodes.
///
/// Numbering matches php-src/Zend/zend_vm_opcodes.h exactly.
/// Use `as u8` to get the numeric value.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ZOpcode {
    Nop = 0,
    Add = 1,
    Sub = 2,
    Mul = 3,
    Div = 4,
    Mod = 5,
    Sl = 6,
    Sr = 7,
    Concat = 8,
    BwOr = 9,
    BwAnd = 10,
    BwXor = 11,
    Pow = 12,
    BwNot = 13,
    BoolNot = 14,
    BoolXor = 15,
    IsIdentical = 16,
    IsNotIdentical = 17,
    IsEqual = 18,
    IsNotEqual = 19,
    IsSmaller = 20,
    IsSmallerOrEqual = 21,
    Assign = 22,
    AssignDim = 23,
    AssignObj = 24,
    AssignStaticProp = 25,
    AssignOp = 26,
    AssignDimOp = 27,
    AssignObjOp = 28,
    AssignStaticPropOp = 29,
    AssignRef = 30,
    QmAssign = 31,
    AssignObjRef = 32,
    AssignStaticPropRef = 33,
    PreInc = 34,
    PreDec = 35,
    PostInc = 36,
    PostDec = 37,
    PreIncStaticProp = 38,
    PreDecStaticProp = 39,
    PostIncStaticProp = 40,
    PostDecStaticProp = 41,
    Jmp = 42,
    Jmpz = 43,
    Jmpnz = 44,
    // 45 is reserved/skipped in PHP
    JmpzEx = 46,
    JmpnzEx = 47,
    Case = 48,
    CheckVar = 49,
    SendVarNoRefEx = 50,
    Cast = 51,
    Bool = 52,
    FastConcat = 53,
    RopeInit = 54,
    RopeAdd = 55,
    RopeEnd = 56,
    BeginSilence = 57,
    EndSilence = 58,
    InitFcallByName = 59,
    DoFcall = 60,
    InitFcall = 61,
    Return = 62,
    Recv = 63,
    RecvInit = 64,
    SendVal = 65,
    SendVarEx = 66,
    SendRef = 67,
    New = 68,
    InitNsFcallByName = 69,
    Free = 70,
    InitArray = 71,
    AddArrayElement = 72,
    IncludeOrEval = 73,
    UnsetVar = 74,
    UnsetDim = 75,
    UnsetObj = 76,
    FeResetR = 77,
    FeFetchR = 78,
    // 79 is skipped
    FetchR = 80,
    FetchDimR = 81,
    FetchObjR = 82,
    FetchW = 83,
    FetchDimW = 84,
    FetchObjW = 85,
    FetchRw = 86,
    FetchDimRw = 87,
    FetchObjRw = 88,
    FetchIs = 89,
    FetchDimIs = 90,
    FetchObjIs = 91,
    FetchFuncArg = 92,
    FetchDimFuncArg = 93,
    FetchObjFuncArg = 94,
    FetchUnset = 95,
    FetchDimUnset = 96,
    FetchObjUnset = 97,
    FetchListR = 98,
    FetchConstant = 99,
    CheckFuncArg = 100,
    ExtStmt = 101,
    ExtFcallBegin = 102,
    ExtFcallEnd = 103,
    ExtNop = 104,
    Ticks = 105,
    SendVarNoRef = 106,
    Catch = 107,
    Throw = 108,
    FetchClass = 109,
    Clone = 110,
    ReturnByRef = 111,
    InitMethodCall = 112,
    InitStaticMethodCall = 113,
    IssetIsemptyVar = 114,
    IssetIsemptyDimObj = 115,
    SendValEx = 116,
    SendVar = 117,
    InitUserCall = 118,
    SendArray = 119,
    SendUser = 120,
    Strlen = 121,
    Defined = 122,
    TypeCheck = 123,
    VerifyReturnType = 124,
    FeResetRw = 125,
    FeFetchRw = 126,
    FeFree = 127,
    InitDynamicCall = 128,
    DoIcall = 129,
    DoUcall = 130,
    DoFcallByName = 131,
    PreIncObj = 132,
    PreDecObj = 133,
    PostIncObj = 134,
    PostDecObj = 135,
    Echo = 136,
    OpData = 137,
    Instanceof = 138,
    GeneratorCreate = 139,
    MakeRef = 140,
    DeclareFunction = 141,
    DeclareLambdaFunction = 142,
    DeclareConst = 143,
    DeclareClass = 144,
    DeclareClassDelayed = 145,
    DeclareAnonClass = 146,
    AddArrayUnpack = 147,
    IssetIsemptyPropObj = 148,
    HandleException = 149,
    UserOpcode = 150,
    AssertCheck = 151,
    JmpSet = 152,
    UnsetCv = 153,
    IssetIsemptyCv = 154,
    FetchListW = 155,
    Separate = 156,
    FetchClassName = 157,
    CallTrampoline = 158,
    DiscardException = 159,
    Yield = 160,
    GeneratorReturn = 161,
    FastCall = 162,
    FastRet = 163,
    RecvVariadic = 164,
    SendUnpack = 165,
    YieldFrom = 166,
    CopyTmp = 167,
    BindGlobal = 168,
    Coalesce = 169,
    Spaceship = 170,
    FuncNumArgs = 171,
    FuncGetArgs = 172,
    FetchStaticPropR = 173,
    FetchStaticPropW = 174,
    FetchStaticPropRw = 175,
    FetchStaticPropIs = 176,
    FetchStaticPropFuncArg = 177,
    FetchStaticPropUnset = 178,
    UnsetStaticProp = 179,
    IssetIsemptyStaticProp = 180,
    FetchClassConstant = 181,
    BindLexical = 182,
    BindStatic = 183,
    FetchThis = 184,
    SendFuncArg = 185,
    IssetIsemptyThis = 186,
    SwitchLong = 187,
    SwitchString = 188,
    InArray = 189,
    Count = 190,
    GetClass = 191,
    GetCalledClass = 192,
    GetType = 193,
    ArrayKeyExists = 194,
    Match = 195,
    CaseStrict = 196,
    MatchError = 197,
    JmpNull = 198,
    CheckUndefArgs = 199,
    FetchGlobals = 200,
    VerifyNeverType = 201,
    CallableConvert = 202,
    BindInitStaticOrJmp = 203,
    FramelessIcall0 = 204,
    FramelessIcall1 = 205,
    FramelessIcall2 = 206,
    FramelessIcall3 = 207,
    JmpFrameless = 208,
    InitParentPropertyHookCall = 209,
    DeclareAttributedConst = 210,
    TypeAssert = 211,
}

/// The last valid opcode number.
pub const ZEND_VM_LAST_OPCODE: u8 = 211;

impl ZOpcode {
    /// Convert a raw opcode number to a ZOpcode.
    ///
    /// Returns None for invalid/reserved opcode numbers (e.g., 45, 79, or > 211).
    pub fn from_u8(n: u8) -> Option<Self> {
        // Opcode 45 and 79 are reserved/skipped
        if n == 45 || n == 79 || n > ZEND_VM_LAST_OPCODE {
            return None;
        }

        // SAFETY: The enum uses repr(u8) and we've excluded the gaps.
        // All values 0..=211 except 45 and 79 have corresponding variants.
        // We verify this in tests below.
        Some(unsafe { std::mem::transmute::<u8, ZOpcode>(n) })
    }

    /// Get the name of this opcode as it appears in PHP (e.g., "ZEND_ADD").
    pub fn name(self) -> &'static str {
        match self {
            Self::Nop => "ZEND_NOP",
            Self::Add => "ZEND_ADD",
            Self::Sub => "ZEND_SUB",
            Self::Mul => "ZEND_MUL",
            Self::Div => "ZEND_DIV",
            Self::Mod => "ZEND_MOD",
            Self::Sl => "ZEND_SL",
            Self::Sr => "ZEND_SR",
            Self::Concat => "ZEND_CONCAT",
            Self::BwOr => "ZEND_BW_OR",
            Self::BwAnd => "ZEND_BW_AND",
            Self::BwXor => "ZEND_BW_XOR",
            Self::Pow => "ZEND_POW",
            Self::BwNot => "ZEND_BW_NOT",
            Self::BoolNot => "ZEND_BOOL_NOT",
            Self::BoolXor => "ZEND_BOOL_XOR",
            Self::IsIdentical => "ZEND_IS_IDENTICAL",
            Self::IsNotIdentical => "ZEND_IS_NOT_IDENTICAL",
            Self::IsEqual => "ZEND_IS_EQUAL",
            Self::IsNotEqual => "ZEND_IS_NOT_EQUAL",
            Self::IsSmaller => "ZEND_IS_SMALLER",
            Self::IsSmallerOrEqual => "ZEND_IS_SMALLER_OR_EQUAL",
            Self::Assign => "ZEND_ASSIGN",
            Self::AssignDim => "ZEND_ASSIGN_DIM",
            Self::AssignObj => "ZEND_ASSIGN_OBJ",
            Self::AssignStaticProp => "ZEND_ASSIGN_STATIC_PROP",
            Self::AssignOp => "ZEND_ASSIGN_OP",
            Self::AssignDimOp => "ZEND_ASSIGN_DIM_OP",
            Self::AssignObjOp => "ZEND_ASSIGN_OBJ_OP",
            Self::AssignStaticPropOp => "ZEND_ASSIGN_STATIC_PROP_OP",
            Self::AssignRef => "ZEND_ASSIGN_REF",
            Self::QmAssign => "ZEND_QM_ASSIGN",
            Self::AssignObjRef => "ZEND_ASSIGN_OBJ_REF",
            Self::AssignStaticPropRef => "ZEND_ASSIGN_STATIC_PROP_REF",
            Self::PreInc => "ZEND_PRE_INC",
            Self::PreDec => "ZEND_PRE_DEC",
            Self::PostInc => "ZEND_POST_INC",
            Self::PostDec => "ZEND_POST_DEC",
            Self::PreIncStaticProp => "ZEND_PRE_INC_STATIC_PROP",
            Self::PreDecStaticProp => "ZEND_PRE_DEC_STATIC_PROP",
            Self::PostIncStaticProp => "ZEND_POST_INC_STATIC_PROP",
            Self::PostDecStaticProp => "ZEND_POST_DEC_STATIC_PROP",
            Self::Jmp => "ZEND_JMP",
            Self::Jmpz => "ZEND_JMPZ",
            Self::Jmpnz => "ZEND_JMPNZ",
            Self::JmpzEx => "ZEND_JMPZ_EX",
            Self::JmpnzEx => "ZEND_JMPNZ_EX",
            Self::Case => "ZEND_CASE",
            Self::CheckVar => "ZEND_CHECK_VAR",
            Self::SendVarNoRefEx => "ZEND_SEND_VAR_NO_REF_EX",
            Self::Cast => "ZEND_CAST",
            Self::Bool => "ZEND_BOOL",
            Self::FastConcat => "ZEND_FAST_CONCAT",
            Self::RopeInit => "ZEND_ROPE_INIT",
            Self::RopeAdd => "ZEND_ROPE_ADD",
            Self::RopeEnd => "ZEND_ROPE_END",
            Self::BeginSilence => "ZEND_BEGIN_SILENCE",
            Self::EndSilence => "ZEND_END_SILENCE",
            Self::InitFcallByName => "ZEND_INIT_FCALL_BY_NAME",
            Self::DoFcall => "ZEND_DO_FCALL",
            Self::InitFcall => "ZEND_INIT_FCALL",
            Self::Return => "ZEND_RETURN",
            Self::Recv => "ZEND_RECV",
            Self::RecvInit => "ZEND_RECV_INIT",
            Self::SendVal => "ZEND_SEND_VAL",
            Self::SendVarEx => "ZEND_SEND_VAR_EX",
            Self::SendRef => "ZEND_SEND_REF",
            Self::New => "ZEND_NEW",
            Self::InitNsFcallByName => "ZEND_INIT_NS_FCALL_BY_NAME",
            Self::Free => "ZEND_FREE",
            Self::InitArray => "ZEND_INIT_ARRAY",
            Self::AddArrayElement => "ZEND_ADD_ARRAY_ELEMENT",
            Self::IncludeOrEval => "ZEND_INCLUDE_OR_EVAL",
            Self::UnsetVar => "ZEND_UNSET_VAR",
            Self::UnsetDim => "ZEND_UNSET_DIM",
            Self::UnsetObj => "ZEND_UNSET_OBJ",
            Self::FeResetR => "ZEND_FE_RESET_R",
            Self::FeFetchR => "ZEND_FE_FETCH_R",
            Self::FetchR => "ZEND_FETCH_R",
            Self::FetchDimR => "ZEND_FETCH_DIM_R",
            Self::FetchObjR => "ZEND_FETCH_OBJ_R",
            Self::FetchW => "ZEND_FETCH_W",
            Self::FetchDimW => "ZEND_FETCH_DIM_W",
            Self::FetchObjW => "ZEND_FETCH_OBJ_W",
            Self::FetchRw => "ZEND_FETCH_RW",
            Self::FetchDimRw => "ZEND_FETCH_DIM_RW",
            Self::FetchObjRw => "ZEND_FETCH_OBJ_RW",
            Self::FetchIs => "ZEND_FETCH_IS",
            Self::FetchDimIs => "ZEND_FETCH_DIM_IS",
            Self::FetchObjIs => "ZEND_FETCH_OBJ_IS",
            Self::FetchFuncArg => "ZEND_FETCH_FUNC_ARG",
            Self::FetchDimFuncArg => "ZEND_FETCH_DIM_FUNC_ARG",
            Self::FetchObjFuncArg => "ZEND_FETCH_OBJ_FUNC_ARG",
            Self::FetchUnset => "ZEND_FETCH_UNSET",
            Self::FetchDimUnset => "ZEND_FETCH_DIM_UNSET",
            Self::FetchObjUnset => "ZEND_FETCH_OBJ_UNSET",
            Self::FetchListR => "ZEND_FETCH_LIST_R",
            Self::FetchConstant => "ZEND_FETCH_CONSTANT",
            Self::CheckFuncArg => "ZEND_CHECK_FUNC_ARG",
            Self::ExtStmt => "ZEND_EXT_STMT",
            Self::ExtFcallBegin => "ZEND_EXT_FCALL_BEGIN",
            Self::ExtFcallEnd => "ZEND_EXT_FCALL_END",
            Self::ExtNop => "ZEND_EXT_NOP",
            Self::Ticks => "ZEND_TICKS",
            Self::SendVarNoRef => "ZEND_SEND_VAR_NO_REF",
            Self::Catch => "ZEND_CATCH",
            Self::Throw => "ZEND_THROW",
            Self::FetchClass => "ZEND_FETCH_CLASS",
            Self::Clone => "ZEND_CLONE",
            Self::ReturnByRef => "ZEND_RETURN_BY_REF",
            Self::InitMethodCall => "ZEND_INIT_METHOD_CALL",
            Self::InitStaticMethodCall => "ZEND_INIT_STATIC_METHOD_CALL",
            Self::IssetIsemptyVar => "ZEND_ISSET_ISEMPTY_VAR",
            Self::IssetIsemptyDimObj => "ZEND_ISSET_ISEMPTY_DIM_OBJ",
            Self::SendValEx => "ZEND_SEND_VAL_EX",
            Self::SendVar => "ZEND_SEND_VAR",
            Self::InitUserCall => "ZEND_INIT_USER_CALL",
            Self::SendArray => "ZEND_SEND_ARRAY",
            Self::SendUser => "ZEND_SEND_USER",
            Self::Strlen => "ZEND_STRLEN",
            Self::Defined => "ZEND_DEFINED",
            Self::TypeCheck => "ZEND_TYPE_CHECK",
            Self::VerifyReturnType => "ZEND_VERIFY_RETURN_TYPE",
            Self::FeResetRw => "ZEND_FE_RESET_RW",
            Self::FeFetchRw => "ZEND_FE_FETCH_RW",
            Self::FeFree => "ZEND_FE_FREE",
            Self::InitDynamicCall => "ZEND_INIT_DYNAMIC_CALL",
            Self::DoIcall => "ZEND_DO_ICALL",
            Self::DoUcall => "ZEND_DO_UCALL",
            Self::DoFcallByName => "ZEND_DO_FCALL_BY_NAME",
            Self::PreIncObj => "ZEND_PRE_INC_OBJ",
            Self::PreDecObj => "ZEND_PRE_DEC_OBJ",
            Self::PostIncObj => "ZEND_POST_INC_OBJ",
            Self::PostDecObj => "ZEND_POST_DEC_OBJ",
            Self::Echo => "ZEND_ECHO",
            Self::OpData => "ZEND_OP_DATA",
            Self::Instanceof => "ZEND_INSTANCEOF",
            Self::GeneratorCreate => "ZEND_GENERATOR_CREATE",
            Self::MakeRef => "ZEND_MAKE_REF",
            Self::DeclareFunction => "ZEND_DECLARE_FUNCTION",
            Self::DeclareLambdaFunction => "ZEND_DECLARE_LAMBDA_FUNCTION",
            Self::DeclareConst => "ZEND_DECLARE_CONST",
            Self::DeclareClass => "ZEND_DECLARE_CLASS",
            Self::DeclareClassDelayed => "ZEND_DECLARE_CLASS_DELAYED",
            Self::DeclareAnonClass => "ZEND_DECLARE_ANON_CLASS",
            Self::AddArrayUnpack => "ZEND_ADD_ARRAY_UNPACK",
            Self::IssetIsemptyPropObj => "ZEND_ISSET_ISEMPTY_PROP_OBJ",
            Self::HandleException => "ZEND_HANDLE_EXCEPTION",
            Self::UserOpcode => "ZEND_USER_OPCODE",
            Self::AssertCheck => "ZEND_ASSERT_CHECK",
            Self::JmpSet => "ZEND_JMP_SET",
            Self::UnsetCv => "ZEND_UNSET_CV",
            Self::IssetIsemptyCv => "ZEND_ISSET_ISEMPTY_CV",
            Self::FetchListW => "ZEND_FETCH_LIST_W",
            Self::Separate => "ZEND_SEPARATE",
            Self::FetchClassName => "ZEND_FETCH_CLASS_NAME",
            Self::CallTrampoline => "ZEND_CALL_TRAMPOLINE",
            Self::DiscardException => "ZEND_DISCARD_EXCEPTION",
            Self::Yield => "ZEND_YIELD",
            Self::GeneratorReturn => "ZEND_GENERATOR_RETURN",
            Self::FastCall => "ZEND_FAST_CALL",
            Self::FastRet => "ZEND_FAST_RET",
            Self::RecvVariadic => "ZEND_RECV_VARIADIC",
            Self::SendUnpack => "ZEND_SEND_UNPACK",
            Self::YieldFrom => "ZEND_YIELD_FROM",
            Self::CopyTmp => "ZEND_COPY_TMP",
            Self::BindGlobal => "ZEND_BIND_GLOBAL",
            Self::Coalesce => "ZEND_COALESCE",
            Self::Spaceship => "ZEND_SPACESHIP",
            Self::FuncNumArgs => "ZEND_FUNC_NUM_ARGS",
            Self::FuncGetArgs => "ZEND_FUNC_GET_ARGS",
            Self::FetchStaticPropR => "ZEND_FETCH_STATIC_PROP_R",
            Self::FetchStaticPropW => "ZEND_FETCH_STATIC_PROP_W",
            Self::FetchStaticPropRw => "ZEND_FETCH_STATIC_PROP_RW",
            Self::FetchStaticPropIs => "ZEND_FETCH_STATIC_PROP_IS",
            Self::FetchStaticPropFuncArg => "ZEND_FETCH_STATIC_PROP_FUNC_ARG",
            Self::FetchStaticPropUnset => "ZEND_FETCH_STATIC_PROP_UNSET",
            Self::UnsetStaticProp => "ZEND_UNSET_STATIC_PROP",
            Self::IssetIsemptyStaticProp => "ZEND_ISSET_ISEMPTY_STATIC_PROP",
            Self::FetchClassConstant => "ZEND_FETCH_CLASS_CONSTANT",
            Self::BindLexical => "ZEND_BIND_LEXICAL",
            Self::BindStatic => "ZEND_BIND_STATIC",
            Self::FetchThis => "ZEND_FETCH_THIS",
            Self::SendFuncArg => "ZEND_SEND_FUNC_ARG",
            Self::IssetIsemptyThis => "ZEND_ISSET_ISEMPTY_THIS",
            Self::SwitchLong => "ZEND_SWITCH_LONG",
            Self::SwitchString => "ZEND_SWITCH_STRING",
            Self::InArray => "ZEND_IN_ARRAY",
            Self::Count => "ZEND_COUNT",
            Self::GetClass => "ZEND_GET_CLASS",
            Self::GetCalledClass => "ZEND_GET_CALLED_CLASS",
            Self::GetType => "ZEND_GET_TYPE",
            Self::ArrayKeyExists => "ZEND_ARRAY_KEY_EXISTS",
            Self::Match => "ZEND_MATCH",
            Self::CaseStrict => "ZEND_CASE_STRICT",
            Self::MatchError => "ZEND_MATCH_ERROR",
            Self::JmpNull => "ZEND_JMP_NULL",
            Self::CheckUndefArgs => "ZEND_CHECK_UNDEF_ARGS",
            Self::FetchGlobals => "ZEND_FETCH_GLOBALS",
            Self::VerifyNeverType => "ZEND_VERIFY_NEVER_TYPE",
            Self::CallableConvert => "ZEND_CALLABLE_CONVERT",
            Self::BindInitStaticOrJmp => "ZEND_BIND_INIT_STATIC_OR_JMP",
            Self::FramelessIcall0 => "ZEND_FRAMELESS_ICALL_0",
            Self::FramelessIcall1 => "ZEND_FRAMELESS_ICALL_1",
            Self::FramelessIcall2 => "ZEND_FRAMELESS_ICALL_2",
            Self::FramelessIcall3 => "ZEND_FRAMELESS_ICALL_3",
            Self::JmpFrameless => "ZEND_JMP_FRAMELESS",
            Self::InitParentPropertyHookCall => "ZEND_INIT_PARENT_PROPERTY_HOOK_CALL",
            Self::DeclareAttributedConst => "ZEND_DECLARE_ATTRIBUTED_CONST",
            Self::TypeAssert => "ZEND_TYPE_ASSERT",
        }
    }
}

impl std::fmt::Display for ZOpcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_numbering() {
        assert_eq!(ZOpcode::Nop as u8, 0);
        assert_eq!(ZOpcode::Add as u8, 1);
        assert_eq!(ZOpcode::Sub as u8, 2);
        assert_eq!(ZOpcode::Mul as u8, 3);
        assert_eq!(ZOpcode::Div as u8, 4);
        assert_eq!(ZOpcode::Mod as u8, 5);
        assert_eq!(ZOpcode::Sl as u8, 6);
        assert_eq!(ZOpcode::Sr as u8, 7);
        assert_eq!(ZOpcode::Concat as u8, 8);
        assert_eq!(ZOpcode::BwOr as u8, 9);
        assert_eq!(ZOpcode::BwAnd as u8, 10);
        assert_eq!(ZOpcode::BwXor as u8, 11);
        assert_eq!(ZOpcode::Pow as u8, 12);
        assert_eq!(ZOpcode::BwNot as u8, 13);
        assert_eq!(ZOpcode::BoolNot as u8, 14);
        assert_eq!(ZOpcode::BoolXor as u8, 15);
        assert_eq!(ZOpcode::IsIdentical as u8, 16);
        assert_eq!(ZOpcode::IsNotIdentical as u8, 17);
        assert_eq!(ZOpcode::IsEqual as u8, 18);
        assert_eq!(ZOpcode::IsNotEqual as u8, 19);
        assert_eq!(ZOpcode::IsSmaller as u8, 20);
        assert_eq!(ZOpcode::IsSmallerOrEqual as u8, 21);
        assert_eq!(ZOpcode::Assign as u8, 22);
        assert_eq!(ZOpcode::Jmp as u8, 42);
        assert_eq!(ZOpcode::Jmpz as u8, 43);
        assert_eq!(ZOpcode::Jmpnz as u8, 44);
        // 45 is reserved
        assert_eq!(ZOpcode::JmpzEx as u8, 46);
        assert_eq!(ZOpcode::JmpnzEx as u8, 47);
        assert_eq!(ZOpcode::Echo as u8, 136);
        assert_eq!(ZOpcode::Return as u8, 62);
        assert_eq!(ZOpcode::DoFcall as u8, 60);
        assert_eq!(ZOpcode::InitFcall as u8, 61);
    }

    #[test]
    fn test_last_opcode() {
        assert_eq!(ZOpcode::TypeAssert as u8, 211);
        assert_eq!(ZOpcode::TypeAssert as u8, ZEND_VM_LAST_OPCODE);
    }

    #[test]
    fn test_opcode_from_u8_valid() {
        assert_eq!(ZOpcode::from_u8(0), Some(ZOpcode::Nop));
        assert_eq!(ZOpcode::from_u8(1), Some(ZOpcode::Add));
        assert_eq!(ZOpcode::from_u8(44), Some(ZOpcode::Jmpnz));
        assert_eq!(ZOpcode::from_u8(46), Some(ZOpcode::JmpzEx));
        assert_eq!(ZOpcode::from_u8(136), Some(ZOpcode::Echo));
        assert_eq!(ZOpcode::from_u8(211), Some(ZOpcode::TypeAssert));
    }

    #[test]
    fn test_opcode_from_u8_reserved() {
        // 45 and 79 are reserved/skipped in PHP
        assert_eq!(ZOpcode::from_u8(45), None);
        assert_eq!(ZOpcode::from_u8(79), None);
    }

    #[test]
    fn test_opcode_from_u8_out_of_range() {
        assert_eq!(ZOpcode::from_u8(212), None);
        assert_eq!(ZOpcode::from_u8(255), None);
    }

    #[test]
    fn test_opcode_from_u8_roundtrip() {
        // Every valid opcode should roundtrip through from_u8
        let valid_opcodes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
            // 45 is reserved
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67,
            68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, // 79 is reserved
            80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100,
            101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
            118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
            135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151,
            152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168,
            169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185,
            186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202,
            203, 204, 205, 206, 207, 208, 209, 210, 211,
        ];
        assert_eq!(
            valid_opcodes.len(),
            210,
            "should have 210 valid opcodes (212 total - 2 reserved)"
        );
        for &n in &valid_opcodes {
            let op = ZOpcode::from_u8(n).unwrap_or_else(|| panic!("opcode {} should be valid", n));
            assert_eq!(op as u8, n, "roundtrip failed for opcode {}", n);
        }
    }

    #[test]
    fn test_opcode_name() {
        assert_eq!(ZOpcode::Nop.name(), "ZEND_NOP");
        assert_eq!(ZOpcode::Add.name(), "ZEND_ADD");
        assert_eq!(ZOpcode::Echo.name(), "ZEND_ECHO");
        assert_eq!(ZOpcode::Return.name(), "ZEND_RETURN");
        assert_eq!(ZOpcode::TypeAssert.name(), "ZEND_TYPE_ASSERT");
    }

    #[test]
    fn test_opcode_display() {
        assert_eq!(format!("{}", ZOpcode::Add), "ZEND_ADD");
        assert_eq!(format!("{}", ZOpcode::Echo), "ZEND_ECHO");
    }

    #[test]
    fn test_opcode_debug() {
        let debug = format!("{:?}", ZOpcode::Add);
        assert_eq!(debug, "Add");
    }

    #[test]
    fn test_opcode_clone_eq() {
        let op = ZOpcode::Concat;
        let op2 = op;
        assert_eq!(op, op2);

        let op3 = ZOpcode::Add;
        assert_ne!(op, op3);
    }

    #[test]
    fn test_total_opcode_count() {
        // Count all valid opcodes via from_u8
        let count = (0..=255u8)
            .filter(|&n| ZOpcode::from_u8(n).is_some())
            .count();
        assert_eq!(
            count, 210,
            "should have exactly 210 valid opcodes (212 - 2 reserved slots)"
        );
    }
}
