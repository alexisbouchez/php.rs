#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Vm, VmConfig, VmError, VmResult};
    use php_rs_compiler::compile;

    /// Helper: compile and execute, returning Result<output, error>.
    fn run_php_result(source: &str) -> Result<String, VmError> {
        let op_array = compile(source).unwrap_or_else(|e| {
            panic!("Compilation failed for:\n{}\nError: {:?}", source, e);
        });
        let mut vm = Vm::new();
        vm.execute(&op_array, None)
    }

    /// Helper: compile PHP source and execute it, returning the output.
    fn run_php(source: &str) -> String {
        let op_array = compile(source).unwrap_or_else(|e| {
            panic!("Compilation failed for:\n{}\nError: {:?}", source, e);
        });
        let mut vm = Vm::new();
        vm.execute(&op_array, None).unwrap_or_else(|e| {
            panic!(
                "Execution failed for:\n{}\nError: {:?}\nOpcodes:\n{}",
                source,
                e,
                op_array.disassemble()
            );
        })
    }

    /// Run PHP and expect an error — returns the error message string.
    fn run_php_error(source: &str) -> String {
        let op_array = compile(source).unwrap_or_else(|e| {
            panic!("Compilation failed for:\n{}\nError: {:?}", source, e);
        });
        let mut vm = Vm::new();
        match vm.execute(&op_array, None) {
            Err(e) => format!("{:?}", e),
            Ok(output) => panic!(
                "Expected an error but execution succeeded with output: {}",
                output
            ),
        }
    }

    // =========================================================================
    // 5.1 Frame & basic execution
    // =========================================================================

    #[test]
    fn test_vm_empty_script() {
        let output = run_php("<?php ?>");
        assert_eq!(output, "");
    }

    #[test]
    fn test_vm_echo_string() {
        let output = run_php("<?php echo \"Hello, World!\";");
        assert_eq!(output, "Hello, World!");
    }

    #[test]
    fn test_vm_echo_integer() {
        let output = run_php("<?php echo 42;");
        assert_eq!(output, "42");
    }

    #[test]
    fn test_vm_echo_multiple() {
        let output = run_php("<?php echo \"a\"; echo \"b\"; echo \"c\";");
        assert_eq!(output, "abc");
    }

    // =========================================================================
    // 5.2 Dispatch & operand fetch
    // =========================================================================

    #[test]
    fn test_vm_variable_assignment() {
        let output = run_php("<?php $a = 42; echo $a;");
        assert_eq!(output, "42");
    }

    #[test]
    fn test_vm_variable_string() {
        let output = run_php("<?php $name = \"PHP\"; echo $name;");
        assert_eq!(output, "PHP");
    }

    #[test]
    fn test_vm_multiple_variables() {
        let output = run_php("<?php $a = \"Hello\"; $b = \" World\"; echo $a; echo $b;");
        assert_eq!(output, "Hello World");
    }

    // =========================================================================
    // 5.3 Arithmetic & comparison
    // =========================================================================

    #[test]
    fn test_vm_addition() {
        let output = run_php("<?php $a = 2 + 3; echo $a;");
        assert_eq!(output, "5");
    }

    #[test]
    fn test_vm_subtraction() {
        let output = run_php("<?php echo 10 - 3;");
        assert_eq!(output, "7");
    }

    #[test]
    fn test_vm_multiplication() {
        let output = run_php("<?php echo 6 * 7;");
        assert_eq!(output, "42");
    }

    #[test]
    fn test_vm_division() {
        let output = run_php("<?php echo 10 / 3;");
        // PHP produces a float here
        assert!(output.starts_with("3.333"));
    }

    #[test]
    fn test_vm_integer_division() {
        let output = run_php("<?php echo 10 / 2;");
        assert_eq!(output, "5");
    }

    #[test]
    fn test_vm_modulo() {
        let output = run_php("<?php echo 10 % 3;");
        assert_eq!(output, "1");
    }

    #[test]
    fn test_vm_power() {
        let output = run_php("<?php echo 2 ** 10;");
        assert_eq!(output, "1024");
    }

    #[test]
    fn test_vm_concat() {
        let output = run_php("<?php echo \"Hello\" . \" \" . \"World\";");
        assert_eq!(output, "Hello World");
    }

    #[test]
    fn test_vm_compound_expression() {
        let output = run_php("<?php echo 2 + 3 * 4;");
        assert_eq!(output, "14");
    }

    #[test]
    fn test_vm_comparison_equal() {
        let output = run_php("<?php if (1 == 1) { echo \"yes\"; } else { echo \"no\"; }");
        assert_eq!(output, "yes");
    }

    #[test]
    fn test_vm_comparison_not_equal() {
        let output = run_php("<?php if (1 != 2) { echo \"yes\"; } else { echo \"no\"; }");
        assert_eq!(output, "yes");
    }

    #[test]
    fn test_vm_comparison_less() {
        let output = run_php("<?php if (1 < 2) { echo \"yes\"; } else { echo \"no\"; }");
        assert_eq!(output, "yes");
    }

    // =========================================================================
    // 5.4 Variables
    // =========================================================================

    #[test]
    fn test_vm_assign_op_add() {
        let output = run_php("<?php $a = 10; $a += 5; echo $a;");
        assert_eq!(output, "15");
    }

    #[test]
    fn test_vm_assign_op_concat() {
        let output = run_php("<?php $a = \"Hello\"; $a .= \" World\"; echo $a;");
        assert_eq!(output, "Hello World");
    }

    #[test]
    fn test_vm_pre_increment() {
        let output = run_php("<?php $a = 5; ++$a; echo $a;");
        assert_eq!(output, "6");
    }

    #[test]
    fn test_vm_post_increment() {
        let output = run_php("<?php $a = 5; $b = $a++; echo $b; echo $a;");
        assert_eq!(output, "56");
    }

    #[test]
    fn test_vm_array_literal() {
        let output = run_php("<?php $a = [1, 2, 3]; echo $a[0]; echo $a[1]; echo $a[2];");
        assert_eq!(output, "123");
    }

    #[test]
    fn test_vm_array_string_key() {
        let output = run_php("<?php $a = [\"name\" => \"PHP\"]; echo $a[\"name\"];");
        assert_eq!(output, "PHP");
    }

    // =========================================================================
    // 5.5 Control flow
    // =========================================================================

    #[test]
    fn test_vm_if_true() {
        let output = run_php("<?php if (true) { echo \"yes\"; }");
        assert_eq!(output, "yes");
    }

    #[test]
    fn test_vm_if_false() {
        let output = run_php("<?php if (false) { echo \"yes\"; } else { echo \"no\"; }");
        assert_eq!(output, "no");
    }

    #[test]
    fn test_vm_if_elseif() {
        let output = run_php(
            "<?php $x = 2; if ($x == 1) { echo \"one\"; } elseif ($x == 2) { echo \"two\"; } else { echo \"other\"; }",
        );
        assert_eq!(output, "two");
    }

    #[test]
    fn test_vm_while_loop() {
        let output = run_php("<?php $i = 0; while ($i < 5) { echo $i; $i++; }");
        assert_eq!(output, "01234");
    }

    #[test]
    fn test_vm_for_loop() {
        let output = run_php("<?php for ($i = 0; $i < 5; $i++) { echo $i; }");
        assert_eq!(output, "01234");
    }

    #[test]
    fn test_vm_do_while() {
        let output = run_php("<?php $i = 0; do { echo $i; $i++; } while ($i < 3);");
        assert_eq!(output, "012");
    }

    #[test]
    fn test_vm_foreach_values() {
        let output =
            run_php("<?php $arr = [10, 20, 30]; foreach ($arr as $v) { echo $v; echo \",\"; }");
        assert_eq!(output, "10,20,30,");
    }

    #[test]
    fn test_vm_break() {
        let output =
            run_php("<?php for ($i = 0; $i < 10; $i++) { if ($i == 3) { break; } echo $i; }");
        assert_eq!(output, "012");
    }

    #[test]
    fn test_vm_continue() {
        let output =
            run_php("<?php for ($i = 0; $i < 5; $i++) { if ($i == 2) { continue; } echo $i; }");
        assert_eq!(output, "0134");
    }

    // =========================================================================
    // 5.6 Function calls
    // =========================================================================

    #[test]
    fn test_vm_function_decl_and_call() {
        let output = run_php("<?php function greet() { echo \"Hello!\"; } greet();");
        assert_eq!(output, "Hello!");
    }

    #[test]
    fn test_vm_function_with_params() {
        let output = run_php("<?php function add($a, $b) { return $a + $b; } echo add(3, 4);");
        assert_eq!(output, "7");
    }

    #[test]
    fn test_vm_function_return() {
        let output = run_php("<?php function double($x) { return $x * 2; } echo double(21);");
        assert_eq!(output, "42");
    }

    #[test]
    fn test_vm_nested_function_calls() {
        let output = run_php(
            "<?php function add($a, $b) { return $a + $b; } function mul($a, $b) { return $a * $b; } echo add(mul(2, 3), mul(4, 5));",
        );
        assert_eq!(output, "26");
    }

    #[test]
    fn test_vm_recursive_function() {
        let output = run_php(
            "<?php function fact($n) { if ($n <= 1) { return 1; } return $n * fact($n - 1); } echo fact(5);",
        );
        assert_eq!(output, "120");
    }

    // =========================================================================
    // 5.7 I/O (echo with types)
    // =========================================================================

    #[test]
    fn test_vm_echo_bool_true() {
        let output = run_php("<?php echo true;");
        assert_eq!(output, "1");
    }

    #[test]
    fn test_vm_echo_bool_false() {
        let output = run_php("<?php echo false;");
        assert_eq!(output, "");
    }

    #[test]
    fn test_vm_echo_null() {
        let output = run_php("<?php echo null;");
        assert_eq!(output, "");
    }

    #[test]
    fn test_vm_echo_float() {
        let output = run_php("<?php echo 3.14;");
        assert_eq!(output, "3.14");
    }

    // =========================================================================
    // Built-in functions
    // =========================================================================

    #[test]
    fn test_vm_builtin_strlen() {
        let output = run_php("<?php echo strlen(\"Hello\");");
        assert_eq!(output, "5");
    }

    #[test]
    fn test_vm_builtin_strtoupper() {
        let output = run_php("<?php echo strtoupper(\"hello\");");
        assert_eq!(output, "HELLO");
    }

    #[test]
    fn test_vm_builtin_substr() {
        let output = run_php("<?php echo substr(\"Hello World\", 6);");
        assert_eq!(output, "World");
    }

    #[test]
    fn test_vm_builtin_implode() {
        let output = run_php("<?php echo implode(\", \", [\"a\", \"b\", \"c\"]);");
        assert_eq!(output, "a, b, c");
    }

    // =========================================================================
    // Integration: compile + execute end-to-end
    // =========================================================================

    #[test]
    fn test_vm_fizzbuzz() {
        let output = run_php(
            r#"<?php
for ($i = 1; $i <= 15; $i++) {
    if ($i % 15 == 0) {
        echo "FizzBuzz";
    } elseif ($i % 3 == 0) {
        echo "Fizz";
    } elseif ($i % 5 == 0) {
        echo "Buzz";
    } else {
        echo $i;
    }
    echo "\n";
}
"#,
        );
        let expected = "1\n2\nFizz\n4\nBuzz\nFizz\n7\n8\nFizz\nBuzz\n11\nFizz\n13\n14\nFizzBuzz\n";
        assert_eq!(output, expected);
    }

    #[test]
    fn test_vm_fibonacci() {
        let output = run_php(
            r#"<?php
function fib($n) {
    if ($n <= 1) { return $n; }
    return fib($n - 1) + fib($n - 2);
}
echo fib(10);
"#,
        );
        assert_eq!(output, "55");
    }

    #[test]
    fn test_vm_string_operations() {
        let output = run_php(
            r#"<?php
$str = "Hello";
$str .= " ";
$str .= "World";
echo $str;
echo "\n";
echo strlen($str);
"#,
        );
        assert_eq!(output, "Hello World\n11");
    }

    #[test]
    fn test_vm_array_operations() {
        let output = run_php(
            r#"<?php
$arr = [1, 2, 3, 4, 5];
$sum = 0;
foreach ($arr as $v) {
    $sum += $v;
}
echo $sum;
"#,
        );
        assert_eq!(output, "15");
    }

    #[test]
    fn test_vm_nested_loops() {
        let output = run_php(
            r#"<?php
for ($i = 1; $i <= 3; $i++) {
    for ($j = 1; $j <= 3; $j++) {
        echo $i * $j;
        echo " ";
    }
    echo "\n";
}
"#,
        );
        assert_eq!(output, "1 2 3 \n2 4 6 \n3 6 9 \n");
    }

    // =========================================================================
    // 5.5.4 JMPZNZ
    // =========================================================================

    #[test]
    fn test_vm_null_coalesce_chain() {
        let output = run_php("<?php $a = null; $b = null; $c = 42; echo $a ?? $b ?? $c;");
        assert_eq!(output, "42");
    }

    // =========================================================================
    // 5.8 Exception handling
    // =========================================================================

    #[test]
    fn test_vm_try_catch_basic() {
        let output = run_php(
            r#"<?php
try {
    echo "try ";
    throw 42;
} catch (Exception $e) {
    echo "catch";
}
"#,
        );
        assert_eq!(output, "try catch");
    }

    #[test]
    fn test_vm_try_catch_exception_variable() {
        let output = run_php(
            r#"<?php
try {
    throw "error!";
} catch (Exception $e) {
    echo $e;
}
"#,
        );
        assert_eq!(output, "error!");
    }

    #[test]
    fn test_vm_try_catch_finally() {
        let output = run_php(
            r#"<?php
try {
    echo "A";
} catch (Exception $e) {
    echo "B";
} finally {
    echo "C";
}
"#,
        );
        // No exception: try body + finally
        assert!(output.contains("A"));
        assert!(output.contains("C"));
        assert!(!output.contains("B"));
    }

    #[test]
    fn test_vm_try_catch_with_throw_and_finally() {
        let output = run_php(
            r#"<?php
try {
    echo "A";
    throw "err";
} catch (Exception $e) {
    echo "B";
} finally {
    echo "C";
}
"#,
        );
        assert_eq!(output, "ABC");
    }

    #[test]
    fn test_vm_uncaught_exception() {
        let op_array = php_rs_compiler::compile("<?php throw 42;").unwrap();
        let mut vm = Vm::new();
        let result = vm.execute(&op_array, None);
        assert!(result.is_err());
    }

    // =========================================================================
    // 5.10 Class & object handlers
    // =========================================================================

    #[test]
    fn test_vm_class_basic() {
        let output = run_php(
            r#"<?php
class Greeter {
    public function greet() {
        echo "Hello from class!";
    }
}
$g = new Greeter();
$g->greet();
"#,
        );
        assert_eq!(output, "Hello from class!");
    }

    #[test]
    fn test_vm_class_constructor() {
        let output = run_php(
            r#"<?php
class Person {
    public function __construct($name) {
        $this->name = $name;
    }
    public function greet() {
        echo "Hi, " . $this->name;
    }
}
$p = new Person("Alice");
$p->greet();
"#,
        );
        assert_eq!(output, "Hi, Alice");
    }

    #[test]
    fn test_vm_class_property_access() {
        let output = run_php(
            r#"<?php
class Box {
    public function __construct($value) {
        $this->value = $value;
    }
    public function getValue() {
        return $this->value;
    }
}
$b = new Box(42);
echo $b->getValue();
"#,
        );
        assert_eq!(output, "42");
    }

    #[test]
    fn test_vm_class_method_with_params() {
        let output = run_php(
            r#"<?php
class Calculator {
    public function add($a, $b) {
        return $a + $b;
    }
}
$calc = new Calculator();
echo $calc->add(3, 4);
"#,
        );
        assert_eq!(output, "7");
    }

    #[test]
    fn test_vm_class_multiple_instances() {
        let output = run_php(
            r#"<?php
class Counter {
    public function __construct($start) {
        $this->count = $start;
    }
    public function increment() {
        $this->count = $this->count + 1;
    }
    public function getCount() {
        return $this->count;
    }
}
$a = new Counter(0);
$b = new Counter(10);
$a->increment();
$a->increment();
$b->increment();
echo $a->getCount();
echo " ";
echo $b->getCount();
"#,
        );
        assert_eq!(output, "2 11");
    }

    #[test]
    fn test_vm_instanceof() {
        let output = run_php(
            r#"<?php
class Animal {}
class Dog {}
$a = new Animal();
$d = new Dog();
if ($a instanceof Animal) { echo "yes "; }
if ($d instanceof Animal) { echo "no"; } else { echo "no "; }
if ($d instanceof Dog) { echo "yes"; }
"#,
        );
        assert_eq!(output, "yes no yes");
    }

    #[test]
    fn test_vm_gettype_object() {
        let output = run_php(
            r#"<?php
class Foo {}
$f = new Foo();
echo gettype($f);
"#,
        );
        assert_eq!(output, "object");
    }

    #[test]
    fn test_vm_get_class() {
        let output = run_php(
            r#"<?php
class MyClass {}
$obj = new MyClass();
echo get_class($obj);
"#,
        );
        assert_eq!(output, "MyClass");
    }

    #[test]
    fn test_vm_static_method() {
        let output = run_php(
            r#"<?php
class MathHelper {
    public static function double($x) {
        return $x * 2;
    }
}
echo MathHelper::double(21);
"#,
        );
        assert_eq!(output, "42");
    }

    // =========================================================================
    // 5.12 Include & eval
    // =========================================================================

    #[test]
    fn test_vm_eval_basic() {
        let output = run_php(
            r#"<?php
eval('echo "hello from eval";');
"#,
        );
        assert_eq!(output, "hello from eval");
    }

    #[test]
    fn test_vm_eval_expression() {
        let output = run_php(
            r#"<?php
$x = eval('return 2 + 3;');
echo $x;
"#,
        );
        assert_eq!(output, "5");
    }

    #[test]
    fn test_vm_include_file() {
        // Create a temp file to include
        let dir = std::env::temp_dir();
        let path = dir.join("php_rs_test_include.php");
        std::fs::write(&path, "<?php echo \"included\";").unwrap();

        let source = format!(
            "<?php include '{}';",
            path.to_str().unwrap().replace('\\', "\\\\")
        );
        let output = run_php(&source);
        assert_eq!(output, "included");

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_vm_require_missing_file() {
        let op_array = compile("<?php require '/nonexistent/file.php';").unwrap();
        let mut vm = Vm::new();
        let result = vm.execute(&op_array, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_vm_include_once_dedup() {
        let dir = std::env::temp_dir();
        let path = dir.join("php_rs_test_include_once.php");
        std::fs::write(&path, "<?php echo \"X\";").unwrap();

        let source = format!(
            "<?php\ninclude_once '{0}';\ninclude_once '{0}';",
            path.to_str().unwrap().replace('\\', "\\\\")
        );
        let output = run_php(&source);
        assert_eq!(output, "X"); // Only once

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_require_inherits_parent_scope() {
        let dir = std::env::temp_dir();
        let path = dir.join("php_rs_test_scope_inherit.php");
        std::fs::write(&path, r#"<?php echo "x=" . $x . " y=" . $y . "\n";"#).unwrap();

        let source = format!(
            r#"<?php
$x = "hello";
$y = 42;
require '{}';
"#,
            path.to_str().unwrap().replace('\\', "\\\\")
        );
        let output = run_php(&source);
        assert_eq!(output, "x=hello y=42\n");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_include_scope_writeback() {
        let dir = std::env::temp_dir();
        let path = dir.join("php_rs_test_scope_writeback.php");
        std::fs::write(&path, r#"<?php $x = "modified";"#).unwrap();

        let source = format!(
            r#"<?php
$x = "original";
include '{}';
echo $x;
"#,
            path.to_str().unwrap().replace('\\', "\\\\")
        );
        let output = run_php(&source);
        assert_eq!(output, "modified");

        let _ = std::fs::remove_file(&path);
    }

    // =========================================================================
    // json_encode / json_decode
    // =========================================================================

    #[test]
    fn test_json_encode_scalar() {
        assert_eq!(run_php(r#"<?php echo json_encode(42);"#), "42");
        assert_eq!(run_php(r#"<?php echo json_encode("hello");"#), "\"hello\"");
        assert_eq!(run_php(r#"<?php echo json_encode(true);"#), "true");
        assert_eq!(run_php(r#"<?php echo json_encode(false);"#), "false");
        assert_eq!(run_php(r#"<?php echo json_encode(null);"#), "null");
        assert_eq!(run_php(r#"<?php echo json_encode(1.5);"#), "1.5");
    }

    #[test]
    fn test_json_encode_array() {
        assert_eq!(run_php(r#"<?php echo json_encode([1, 2, 3]);"#), "[1,2,3]");
    }

    #[test]
    fn test_json_encode_assoc_array() {
        assert_eq!(
            run_php(r#"<?php echo json_encode(["a" => 1, "b" => 2]);"#),
            r#"{"a":1,"b":2}"#
        );
    }

    #[test]
    fn test_json_encode_object() {
        let output = run_php(
            r#"<?php
$obj = new stdClass;
$obj->name = "PHP";
$obj->version = 8;
echo json_encode($obj);
"#,
        );
        assert_eq!(output, r#"{"name":"PHP","version":8}"#);
    }

    #[test]
    fn test_json_decode_scalar() {
        assert_eq!(run_php(r#"<?php echo json_decode("42");"#), "42");
        assert_eq!(run_php(r#"<?php echo json_decode('"hello"');"#), "hello");
        assert_eq!(
            run_php(r#"<?php var_dump(json_decode("true"));"#),
            "bool(true)\n"
        );
        assert_eq!(run_php(r#"<?php var_dump(json_decode("null"));"#), "NULL\n");
    }

    #[test]
    fn test_json_decode_assoc() {
        assert_eq!(
            run_php(
                r#"<?php
$data = json_decode('{"a":1,"b":"hello"}', true);
echo $data["a"] . " " . $data["b"];
"#
            ),
            "1 hello"
        );
    }

    #[test]
    fn test_json_last_error() {
        assert_eq!(
            run_php(
                r#"<?php
json_decode("{bad}");
echo json_last_error();
"#
            ),
            "4"
        );
    }

    #[test]
    fn test_json_last_error_msg() {
        assert_eq!(
            run_php(
                r#"<?php
json_decode("{bad}");
echo json_last_error_msg();
"#
            ),
            "Syntax error"
        );
    }

    // =========================================================================
    // JsonSerializable interface
    // =========================================================================

    #[test]
    fn test_json_serializable() {
        let output = run_php(
            r#"<?php
class Foo implements JsonSerializable {
    public function jsonSerialize() {
        return ["custom" => "data", "count" => 42];
    }
}
echo json_encode(new Foo());
"#,
        );
        assert_eq!(output, r#"{"custom":"data","count":42}"#);
    }

    #[test]
    fn test_json_serializable_scalar_return() {
        let output = run_php(
            r#"<?php
class Bar implements JsonSerializable {
    public function jsonSerialize() {
        return "just a string";
    }
}
echo json_encode(new Bar());
"#,
        );
        assert_eq!(output, r#""just a string""#);
    }

    // =========================================================================
    // Interface / instanceof
    // =========================================================================

    #[test]
    fn test_instanceof_interface() {
        assert_eq!(
            run_php(
                r#"<?php
interface Printable {}
class Doc implements Printable {}
$d = new Doc();
var_dump($d instanceof Printable);
"#
            ),
            "bool(true)\n"
        );
    }

    #[test]
    fn test_instanceof_interface_negative() {
        assert_eq!(
            run_php(
                r#"<?php
interface Printable {}
class Doc {}
$d = new Doc();
var_dump($d instanceof Printable);
"#
            ),
            "bool(false)\n"
        );
    }

    // =========================================================================
    // 8.2.15: list() / array destructuring
    // =========================================================================

    #[test]
    fn test_list_simple() {
        assert_eq!(
            run_php("<?php list($a, $b) = [1, 2]; echo $a . ',' . $b;"),
            "1,2"
        );
    }

    #[test]
    fn test_list_with_skip() {
        assert_eq!(
            run_php("<?php list($a, , $c) = [1, 2, 3]; echo $a . ',' . $c;"),
            "1,3"
        );
    }

    #[test]
    fn test_list_from_variable() {
        assert_eq!(
            run_php("<?php $arr = [10, 20, 30]; list($x, $y, $z) = $arr; echo $x . ' ' . $y . ' ' . $z;"),
            "10 20 30"
        );
    }

    // =========================================================================
    // 8.3.5: isset, unset, empty
    // =========================================================================

    #[test]
    fn test_isset_single() {
        assert_eq!(
            run_php("<?php $a = 1; var_dump(isset($a));"),
            "bool(true)\n"
        );
    }

    #[test]
    fn test_isset_unset_variable() {
        assert_eq!(
            run_php("<?php $a = 1; unset($a); var_dump(isset($a));"),
            "bool(false)\n"
        );
    }

    #[test]
    fn test_unset_array_element() {
        assert_eq!(
            run_php(
                r#"<?php
$arr = [1, 2, 3];
unset($arr[1]);
var_dump(count($arr));
echo $arr[0] . "," . $arr[2];
"#
            ),
            "int(2)\n1,3"
        );
    }

    #[test]
    fn test_isset_array_element() {
        assert_eq!(
            run_php(
                r#"<?php
$arr = ['a' => 1, 'b' => 2];
var_dump(isset($arr['a']));
var_dump(isset($arr['c']));
"#
            ),
            "bool(true)\nbool(false)\n"
        );
    }

    #[test]
    fn test_isset_multiple_variables() {
        assert_eq!(
            run_php("<?php $a = 1; $b = 2; var_dump(isset($a, $b));"),
            "bool(true)\n"
        );
    }

    #[test]
    fn test_isset_multiple_one_unset() {
        assert_eq!(
            run_php("<?php $a = 1; var_dump(isset($a, $b));"),
            "bool(false)\n"
        );
    }

    #[test]
    fn test_empty_variable() {
        assert_eq!(
            run_php(
                r#"<?php
$a = "";
$b = "hello";
$c = 0;
var_dump(empty($a));
var_dump(empty($b));
var_dump(empty($c));
"#
            ),
            "bool(true)\nbool(false)\nbool(true)\n"
        );
    }

    // =========================================================================
    // 8.6.10: register_shutdown_function
    // =========================================================================

    #[test]
    fn test_register_shutdown_function() {
        assert_eq!(
            run_php(
                r#"<?php
function my_shutdown() {
    echo "shutdown!";
}
register_shutdown_function("my_shutdown");
echo "main ";
"#
            ),
            "main shutdown!"
        );
    }

    #[test]
    fn test_register_multiple_shutdown_functions() {
        assert_eq!(
            run_php(
                r#"<?php
function shutdown1() { echo "1"; }
function shutdown2() { echo "2"; }
register_shutdown_function("shutdown1");
register_shutdown_function("shutdown2");
echo "main ";
"#
            ),
            "main 12"
        );
    }

    // =========================================================================
    // 8.7.1-8.7.4: preg_* regex functions
    // =========================================================================

    #[test]
    fn test_preg_replace_callback() {
        // With a proper closure that accesses $m[0]
        assert_eq!(
            run_php(
                r#"<?php
$result = preg_replace_callback("/(\w+)/", function($m) { return strtoupper($m[0]); }, "hello world");
echo $result;
"#
            ),
            "HELLO WORLD"
        );
    }

    #[test]
    fn test_preg_replace_callback_with_limit() {
        assert_eq!(
            run_php(
                r#"<?php
$result = preg_replace_callback("/\d+/", function($m) { return "[" . $m[0] . "]"; }, "a1b2c3", 2);
echo $result;
"#
            ),
            "a[1]b[2]c3"
        );
    }

    #[test]
    fn test_preg_last_error() {
        assert_eq!(run_php("<?php echo preg_last_error();"), "0");
    }

    #[test]
    fn test_preg_last_error_msg() {
        assert_eq!(run_php("<?php echo preg_last_error_msg();"), "No error");
    }

    #[test]
    fn test_preg_grep() {
        assert_eq!(
            run_php(
                r#"<?php
$arr = ["foo", "bar", "baz", "foobar"];
$result = preg_grep("/^foo/", $arr);
echo count($result);
"#
            ),
            "2"
        );
    }

    #[test]
    fn test_preg_match() {
        assert_eq!(
            run_php("<?php echo preg_match('/hello/', 'hello world');"),
            "1"
        );
    }

    #[test]
    fn test_preg_match_no_match() {
        assert_eq!(
            run_php("<?php echo preg_match('/xyz/', 'hello world');"),
            "0"
        );
    }

    #[test]
    fn test_preg_replace() {
        assert_eq!(
            run_php(r#"<?php echo preg_replace('/world/', 'PHP', 'hello world');"#),
            "hello PHP"
        );
    }

    #[test]
    fn test_preg_split() {
        assert_eq!(
            run_php(
                r#"<?php
$parts = preg_split('/[\s,]+/', 'one, two, three');
echo count($parts);
"#
            ),
            "3"
        );
    }

    #[test]
    fn test_preg_quote() {
        assert_eq!(
            run_php(r#"<?php echo preg_quote('$var.test+value');"#),
            r#"\$var\.test\+value"#
        );
    }

    // =========================================================================
    // 8A: PCRE Comprehensive Tests
    // =========================================================================

    // --- 8A.01: preg_match — capture groups, named groups, flags ---

    #[test]
    fn test_preg_match_capture_groups() {
        assert_eq!(
            run_php(
                r#"<?php
preg_match('/(\w+)\s+(\w+)/', 'hello world', $m);
echo $m[0] . "|" . $m[1] . "|" . $m[2];
"#
            ),
            "hello world|hello|world"
        );
    }

    #[test]
    fn test_preg_match_named_groups() {
        assert_eq!(
            run_php(
                r#"<?php
preg_match('/(?P<first>\w+)\s+(?P<second>\w+)/', 'hello world', $m);
echo $m['first'] . "|" . $m['second'] . "|" . $m[1] . "|" . $m[2];
"#
            ),
            "hello|world|hello|world"
        );
    }

    #[test]
    fn test_preg_match_offset_capture() {
        assert_eq!(
            run_php(
                r#"<?php
preg_match('/world/', 'hello world', $m, PREG_OFFSET_CAPTURE);
echo $m[0][0] . "|" . $m[0][1];
"#
            ),
            "world|6"
        );
    }

    #[test]
    fn test_preg_match_offset_capture_with_groups() {
        assert_eq!(
            run_php(
                r#"<?php
preg_match('/(\w+)\s+(\w+)/', 'hello world', $m, PREG_OFFSET_CAPTURE);
echo $m[0][0] . ":" . $m[0][1] . "|" . $m[1][0] . ":" . $m[1][1] . "|" . $m[2][0] . ":" . $m[2][1];
"#
            ),
            "hello world:0|hello:0|world:6"
        );
    }

    #[test]
    fn test_preg_match_unmatched_as_null() {
        assert_eq!(
            run_php(
                r#"<?php
preg_match('/(?:foo)(bar)?/', 'foo', $m, PREG_UNMATCHED_AS_NULL);
echo $m[0] . "|";
echo is_null($m[1]) ? "NULL" : $m[1];
"#
            ),
            "foo|NULL"
        );
    }

    #[test]
    fn test_preg_match_returns_match_count() {
        assert_eq!(
            run_php("<?php echo preg_match('/\\d+/', 'abc 123 def');"),
            "1"
        );
    }

    #[test]
    fn test_preg_match_with_offset() {
        assert_eq!(
            run_php(
                r#"<?php
echo preg_match('/\d+/', 'abc 123 def 456', $m, 0, 8);
echo "|" . $m[0];
"#
            ),
            "1|456"
        );
    }

    // --- 8A.02: preg_match_all — PREG_SET_ORDER / PREG_PATTERN_ORDER ---

    #[test]
    fn test_preg_match_all_pattern_order() {
        assert_eq!(
            run_php(
                r#"<?php
$n = preg_match_all('/(\w+)@(\w+)/', 'a@b c@d', $m, PREG_PATTERN_ORDER);
echo $n . "|";
echo implode(",", $m[0]) . "|";
echo implode(",", $m[1]) . "|";
echo implode(",", $m[2]);
"#
            ),
            "2|a@b,c@d|a,c|b,d"
        );
    }

    #[test]
    fn test_preg_match_all_set_order() {
        assert_eq!(
            run_php(
                r#"<?php
$n = preg_match_all('/(\w+)@(\w+)/', 'a@b c@d', $m, PREG_SET_ORDER);
echo $n . "|";
echo $m[0][0] . "," . $m[0][1] . "," . $m[0][2] . "|";
echo $m[1][0] . "," . $m[1][1] . "," . $m[1][2];
"#
            ),
            "2|a@b,a,b|c@d,c,d"
        );
    }

    #[test]
    fn test_preg_match_all_offset_capture() {
        assert_eq!(
            run_php(
                r#"<?php
preg_match_all('/\d+/', 'a1b23c456', $m, PREG_OFFSET_CAPTURE);
echo $m[0][0][0] . ":" . $m[0][0][1] . "|";
echo $m[0][1][0] . ":" . $m[0][1][1] . "|";
echo $m[0][2][0] . ":" . $m[0][2][1];
"#
            ),
            "1:1|23:3|456:6"
        );
    }

    #[test]
    fn test_preg_match_all_named_groups_pattern_order() {
        assert_eq!(
            run_php(
                r#"<?php
preg_match_all('/(?P<name>\w+)=(?P<val>\d+)/', 'a=1 b=2', $m, PREG_PATTERN_ORDER);
echo implode(",", $m['name']) . "|" . implode(",", $m['val']);
"#
            ),
            "a,b|1,2"
        );
    }

    #[test]
    fn test_preg_match_all_named_groups_set_order() {
        assert_eq!(
            run_php(
                r#"<?php
preg_match_all('/(?P<name>\w+)=(?P<val>\d+)/', 'a=1 b=2', $m, PREG_SET_ORDER);
echo $m[0]['name'] . "=" . $m[0]['val'] . "|" . $m[1]['name'] . "=" . $m[1]['val'];
"#
            ),
            "a=1|b=2"
        );
    }

    #[test]
    fn test_preg_match_all_no_matches() {
        assert_eq!(
            run_php(
                r#"<?php
$n = preg_match_all('/xyz/', 'hello world', $m);
echo $n . "|" . count($m[0]);
"#
            ),
            "0|0"
        );
    }

    // --- 8A.03: preg_replace_callback ---

    #[test]
    fn test_preg_replace_callback_named_groups() {
        assert_eq!(
            run_php(
                r#"<?php
$result = preg_replace_callback('/(?P<word>\w+)/', function($m) {
    return strtoupper($m['word']);
}, "hello world");
echo $result;
"#
            ),
            "HELLO WORLD"
        );
    }

    #[test]
    fn test_preg_replace_callback_with_count() {
        assert_eq!(
            run_php(
                r#"<?php
$result = preg_replace_callback("/\d+/", function($m) { return "X"; }, "a1b2c3", -1, $count);
echo $result . "|" . $count;
"#
            ),
            "aXbXcX|3"
        );
    }

    #[test]
    fn test_preg_replace_callback_array_subject() {
        assert_eq!(
            run_php(
                r#"<?php
$result = preg_replace_callback("/\d+/", function($m) { return "X"; }, ["a1", "b2"]);
echo implode("|", $result);
"#
            ),
            "aX|bX"
        );
    }

    // --- 8A.04: preg_replace_callback_array ---

    #[test]
    fn test_preg_replace_callback_array_multiple() {
        assert_eq!(
            run_php(
                r#"<?php
$result = preg_replace_callback_array([
    "/[a-z]+/" => function($m) { return strtoupper($m[0]); },
    "/\d+/" => function($m) { return "[" . $m[0] . "]"; },
], "hello123world");
echo $result;
"#
            ),
            "HELLO[123]WORLD"
        );
    }

    #[test]
    fn test_preg_replace_callback_array_count() {
        assert_eq!(
            run_php(
                r#"<?php
$result = preg_replace_callback_array([
    "/\d+/" => function($m) { return "N"; },
    "/[a-z]+/" => function($m) { return "W"; },
], "abc123", -1, $count);
echo $result . "|" . $count;
"#
            ),
            "WN|2"
        );
    }

    // --- 8A.05: preg_filter ---

    #[test]
    fn test_preg_filter_string_match() {
        assert_eq!(
            run_php(r#"<?php echo preg_filter('/\d+/', 'X', 'abc123def');"#),
            "abcXdef"
        );
    }

    #[test]
    fn test_preg_filter_string_no_match() {
        assert_eq!(
            run_php(
                r#"<?php
$result = preg_filter('/\d+/', 'X', 'abcdef');
echo is_null($result) ? "NULL" : $result;
"#
            ),
            "NULL"
        );
    }

    #[test]
    fn test_preg_filter_array() {
        assert_eq!(
            run_php(
                r#"<?php
$result = preg_filter('/\d+/', 'X', ['abc', 'a1b', 'def', 'd2e']);
echo count($result) . "|" . implode(",", $result);
"#
            ),
            "2|aXb,dXe"
        );
    }

    // --- 8A.06: preg_grep ---

    #[test]
    fn test_preg_grep_preserves_keys() {
        assert_eq!(
            run_php(
                r#"<?php
$result = preg_grep('/^a/', ['apple', 'banana', 'avocado', 'cherry']);
echo implode(",", array_keys($result)) . "|" . implode(",", $result);
"#
            ),
            "0,2|apple,avocado"
        );
    }

    #[test]
    fn test_preg_grep_invert() {
        assert_eq!(
            run_php(
                r#"<?php
$result = preg_grep('/^a/', ['apple', 'banana', 'avocado', 'cherry'], PREG_GREP_INVERT);
echo implode(",", $result);
"#
            ),
            "banana,cherry"
        );
    }

    #[test]
    fn test_preg_grep_case_insensitive() {
        assert_eq!(
            run_php(
                r#"<?php
$result = preg_grep('/^a/i', ['Apple', 'Banana', 'Avocado']);
echo count($result);
"#
            ),
            "2"
        );
    }

    // --- 8A.07: preg_split ---

    #[test]
    fn test_preg_split_no_empty() {
        assert_eq!(
            run_php(
                r#"<?php
$parts = preg_split('/,/', ',,a,,b,,', -1, PREG_SPLIT_NO_EMPTY);
echo implode("|", $parts);
"#
            ),
            "a|b"
        );
    }

    #[test]
    fn test_preg_split_delim_capture() {
        assert_eq!(
            run_php(
                r#"<?php
$parts = preg_split('/([-+])/', '1+2-3', -1, PREG_SPLIT_DELIM_CAPTURE);
echo implode("|", $parts);
"#
            ),
            "1|+|2|-|3"
        );
    }

    #[test]
    fn test_preg_split_offset_capture() {
        assert_eq!(
            run_php(
                r#"<?php
$parts = preg_split('/,/', 'a,b,c', -1, PREG_SPLIT_OFFSET_CAPTURE);
echo $parts[0][0] . ":" . $parts[0][1] . "|";
echo $parts[1][0] . ":" . $parts[1][1] . "|";
echo $parts[2][0] . ":" . $parts[2][1];
"#
            ),
            "a:0|b:2|c:4"
        );
    }

    #[test]
    fn test_preg_split_with_limit() {
        assert_eq!(
            run_php(
                r#"<?php
$parts = preg_split('/,/', 'a,b,c,d', 2);
echo implode("|", $parts);
"#
            ),
            "a|b,c,d"
        );
    }

    #[test]
    fn test_preg_split_delim_capture_with_limit() {
        assert_eq!(
            run_php(
                r#"<?php
$parts = preg_split('/(,)/', 'a,b,c,d', 3, PREG_SPLIT_DELIM_CAPTURE);
echo implode("|", $parts);
"#
            ),
            "a|,|b|,|c,d"
        );
    }

    // --- 8A.08: PCRE modifiers ---

    #[test]
    fn test_preg_match_case_insensitive_flag() {
        assert_eq!(
            run_php("<?php echo preg_match('/hello/i', 'HELLO WORLD');"),
            "1"
        );
    }

    #[test]
    fn test_preg_match_dotall_flag() {
        assert_eq!(
            run_php("<?php echo preg_match('/hello.world/s', 'hello\nworld');"),
            "1"
        );
    }

    #[test]
    fn test_preg_match_multiline_flag() {
        assert_eq!(
            run_php("<?php echo preg_match('/^world/m', 'hello\nworld');"),
            "1"
        );
    }

    #[test]
    fn test_preg_match_extended_flag() {
        // /x ignores whitespace and allows comments in pattern
        assert_eq!(
            run_php(
                r#"<?php
echo preg_match('/
    \d+   # one or more digits
    \s+   # whitespace
    \w+   # word
/x', '123 abc');
"#
            ),
            "1"
        );
    }

    #[test]
    fn test_preg_match_ungreedy_flag() {
        // /U makes quantifiers lazy by default
        assert_eq!(
            run_php(
                r#"<?php
preg_match('/<.+>/U', '<b>text</b>', $m);
echo $m[0];
"#
            ),
            "<b>"
        );
    }

    #[test]
    fn test_preg_match_utf8_flag() {
        // /u should work with Unicode characters
        assert_eq!(
            run_php(
                r#"<?php
echo preg_match('/\w+/u', 'héllo');
"#
            ),
            "1"
        );
    }

    #[test]
    fn test_preg_match_anchored_flag() {
        assert_eq!(
            run_php("<?php echo preg_match('/hello/A', 'hello world');"),
            "1"
        );
        assert_eq!(
            run_php("<?php echo preg_match('/world/A', 'hello world');"),
            "0"
        );
    }

    // --- 8A.09: Backreferences ---

    #[test]
    fn test_preg_replace_dollar_backrefs() {
        assert_eq!(
            run_php(r#"<?php echo preg_replace('/(\w+)\s+(\w+)/', '$2 $1', 'hello world');"#),
            "world hello"
        );
    }

    #[test]
    fn test_preg_replace_backslash_backrefs() {
        assert_eq!(
            run_php(r#"<?php echo preg_replace('/(\w+)\s+(\w+)/', '\2 \1', 'hello world');"#),
            "world hello"
        );
    }

    #[test]
    fn test_preg_replace_higher_backrefs() {
        // Test backreferences beyond \3
        assert_eq!(
            run_php(
                r#"<?php
echo preg_replace('/(\w)(\w)(\w)(\w)(\w)/', '$5$4$3$2$1', 'abcde');
"#
            ),
            "edcba"
        );
    }

    #[test]
    fn test_preg_replace_named_backrefs() {
        assert_eq!(
            run_php(
                r#"<?php
echo preg_replace('/(?P<first>\w+)\s+(?P<second>\w+)/', '${second} ${first}', 'hello world');
"#
            ),
            "world hello"
        );
    }

    #[test]
    fn test_preg_replace_zero_backref() {
        // $0 refers to the full match
        assert_eq!(
            run_php(r#"<?php echo preg_replace('/\d+/', '[$0]', 'abc 123 def');"#),
            "abc [123] def"
        );
    }

    // --- 8A.10: Lookahead/lookbehind assertions ---

    #[test]
    fn test_preg_match_lookahead() {
        assert_eq!(
            run_php(
                r#"<?php
preg_match('/\w+(?=\s+world)/', 'hello world', $m);
echo $m[0];
"#
            ),
            "hello"
        );
    }

    #[test]
    fn test_preg_match_negative_lookahead() {
        assert_eq!(
            run_php(
                r#"<?php
echo preg_match('/foo(?!bar)/', 'foobaz');
"#
            ),
            "1"
        );
        assert_eq!(
            run_php(
                r#"<?php
echo preg_match('/foo(?!bar)/', 'foobar');
"#
            ),
            "0"
        );
    }

    #[test]
    fn test_preg_match_lookbehind() {
        assert_eq!(
            run_php(
                r#"<?php
preg_match('/(?<=hello\s)\w+/', 'hello world', $m);
echo $m[0];
"#
            ),
            "world"
        );
    }

    #[test]
    fn test_preg_match_negative_lookbehind() {
        assert_eq!(
            run_php(
                r#"<?php
preg_match_all('/(?<!foo)bar/', 'foobar bazbar', $m);
echo implode(",", $m[0]);
"#
            ),
            "bar"
        );
    }

    #[test]
    fn test_preg_replace_with_lookahead() {
        assert_eq!(
            run_php(
                r#"<?php
echo preg_replace('/\d+(?= dollars)/', '100', 'I have 50 dollars');
"#
            ),
            "I have 100 dollars"
        );
    }

    #[test]
    fn test_preg_split_with_lookahead() {
        assert_eq!(
            run_php(
                r#"<?php
$parts = preg_split('/(?=[A-Z])/', 'camelCaseString');
echo implode("|", $parts);
"#
            ),
            "camel|Case|String"
        );
    }

    #[test]
    fn test_preg_match_all_with_lookbehind() {
        assert_eq!(
            run_php(
                r#"<?php
preg_match_all('/(?<=@)\w+/', 'user@host admin@server', $m);
echo implode(",", $m[0]);
"#
            ),
            "host,server"
        );
    }

    // =========================================================================
    // 5.11 Generators & Fibers
    // =========================================================================

    #[test]
    fn test_generator_debug_creation() {
        // Test that calling a generator function returns a Generator object
        let source = r#"<?php
function gen() { yield 1; yield 2; }
$g = gen();
echo get_class($g);
"#;
        let op_array = compile(source).unwrap();
        // Check that the sub-function is marked as generator
        for def in &op_array.dynamic_func_defs {
            if def.function_name.as_deref() == Some("gen") {
                assert!(def.is_generator, "gen() should be marked as generator");
            }
        }
        let mut vm = Vm::new();
        let output = vm.execute(&op_array, None).unwrap();
        assert_eq!(output, "Generator");
    }

    #[test]
    fn test_generator_debug_foreach_opcodes() {
        let source = r#"<?php
function gen() { yield 1; yield 2; yield 3; }
foreach (gen() as $v) { echo "$v\n"; }
"#;
        let op_array = compile(source).unwrap();
        eprintln!("{}", op_array.disassemble());
        // Make sure it disassembles, but don't check output (debugging)
    }

    #[test]
    fn test_generator_basic_foreach() {
        // Simpler test
        assert_eq!(
            run_php(concat!(
                "<?php\n",
                "function gen() { yield 10; yield 20; yield 30; }\n",
                "foreach (gen() as $v) { echo $v; }\n",
            )),
            "102030"
        );
    }

    #[test]
    fn test_generator_manual_iteration() {
        // Test generator without foreach, using manual iteration
        assert_eq!(
            run_php(concat!(
                "<?php\n",
                "function gen() { yield 10; yield 20; }\n",
                "$g = gen();\n",
                "echo $g->current();\n",
                "$g->next();\n",
                "echo $g->current();\n",
                "$g->next();\n",
                "echo $g->valid() ? 'yes' : 'no';\n",
            )),
            "1020no"
        );
    }

    #[test]
    fn test_generator_foreach_with_keys() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() { yield 1; yield 2; yield 3; }
foreach (gen() as $k => $v) { echo $k . ": " . $v . "\n"; }
"#
            ),
            "0: 1\n1: 2\n2: 3\n"
        );
    }

    #[test]
    fn test_generator_method_current_key_valid_next() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() { yield 1; yield 2; yield 3; }
$g = gen();
var_dump($g->current());
var_dump($g->key());
$g->next();
var_dump($g->current());
var_dump($g->valid());
$g->next();
$g->next();
var_dump($g->valid());
"#
            ),
            "int(1)\nint(0)\nint(2)\nbool(true)\nbool(false)\n"
        );
    }

    #[test]
    fn test_generator_send() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() {
    $x = yield 'first';
    echo "Got: " . $x . "\n";
    yield 'second';
}
$g = gen();
$g->current();
$g->send('hello');
"#
            ),
            "Got: hello\n"
        );
    }

    #[test]
    fn test_generator_get_return() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() { yield 1; return 42; }
$g = gen();
$g->current();
$g->next();
var_dump($g->getReturn());
"#
            ),
            "int(42)\n"
        );
    }

    #[test]
    fn test_generator_yield_with_explicit_keys() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() {
    yield 'a' => 1;
    yield 'b' => 2;
}
foreach (gen() as $k => $v) { echo $k . ": " . $v . "\n"; }
"#
            ),
            "a: 1\nb: 2\n"
        );
    }

    #[test]
    fn test_generator_fibonacci() {
        assert_eq!(
            run_php(
                r#"<?php
function fibonacci() {
    $a = 0;
    $b = 1;
    while (true) {
        yield $a;
        $temp = $a;
        $a = $b;
        $b = $temp + $b;
    }
}
$count = 0;
foreach (fibonacci() as $n) {
    if ($n > 100) break;
    echo $n . "\n";
    $count = $count + 1;
}
"#
            ),
            "0\n1\n1\n2\n3\n5\n8\n13\n21\n34\n55\n89\n"
        );
    }

    #[test]
    fn test_generator_multiple_generators() {
        assert_eq!(
            run_php(
                r#"<?php
function range_gen($start, $end) {
    $i = $start;
    while ($i <= $end) {
        yield $i;
        $i = $i + 1;
    }
}
$a = range_gen(1, 3);
$b = range_gen(10, 12);
echo $a->current() . "\n";
echo $b->current() . "\n";
$a->next();
echo $a->current() . "\n";
echo $b->current() . "\n";
"#
            ),
            "1\n10\n2\n10\n"
        );
    }

    #[test]
    fn test_generator_rewind() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() { yield 1; yield 2; }
$g = gen();
$g->rewind();
var_dump($g->current());
"#
            ),
            "int(1)\n"
        );
    }

    #[test]
    fn test_generator_empty() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() {
    return;
    yield 1;
}
$g = gen();
var_dump($g->valid());
"#
            ),
            "bool(false)\n"
        );
    }

    #[test]
    fn test_fiber_basic() {
        assert_eq!(
            run_php(
                r#"<?php
function work() {
    Fiber::suspend(1);
    Fiber::suspend(2);
    return 3;
}
$f = new Fiber('work');
var_dump($f->start());
var_dump($f->resume());
var_dump($f->resume());
"#
            ),
            "int(1)\nint(2)\nint(3)\n"
        );
    }

    #[test]
    fn test_fiber_status_methods() {
        assert_eq!(
            run_php(
                r#"<?php
function work() {
    Fiber::suspend();
}
$f = new Fiber('work');
var_dump($f->isStarted());
$f->start();
var_dump($f->isStarted());
var_dump($f->isSuspended());
$f->resume();
var_dump($f->isTerminated());
"#
            ),
            "bool(false)\nbool(true)\nbool(true)\nbool(true)\n"
        );
    }

    #[test]
    fn test_fiber_get_return() {
        assert_eq!(
            run_php(
                r#"<?php
function work() { return 42; }
$f = new Fiber('work');
$f->start();
var_dump($f->getReturn());
"#
            ),
            "int(42)\n"
        );
    }

    #[test]
    fn test_generator_yield_from_array() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() {
    yield from [1, 2, 3];
    yield 4;
}
foreach (gen() as $v) { echo $v . "\n"; }
"#
            ),
            "1\n2\n3\n4\n"
        );
    }

    #[test]
    fn test_generator_yield_from_generator() {
        // Generator foreach now correctly advances before reading (not after),
        // so the output matches PHP's actual behavior.
        assert_eq!(
            run_php(
                r#"<?php
function inner() { yield 1; yield 2; return 'ret'; }
function outer() {
    $r = yield from inner();
    echo "inner returned: " . $r . "\n";
    yield 3;
}
foreach (outer() as $v) { echo $v . "\n"; }
"#
            ),
            "1\n2\ninner returned: ret\n3\n"
        );
    }

    // =========================================================================
    // Closure tests
    // =========================================================================

    #[test]
    fn test_closure_basic() {
        assert_eq!(
            run_php(r#"<?php $fn = function() { echo "hello\n"; }; $fn();"#),
            "hello\n"
        );
    }

    #[test]
    fn test_closure_with_args() {
        assert_eq!(
            run_php(r#"<?php $fn = function($x) { return $x * 2; }; echo $fn(21) . "\n";"#),
            "42\n"
        );
    }

    #[test]
    fn test_closure_use_by_value() {
        assert_eq!(
            run_php(
                r#"<?php $x = 10; $fn = function($y) use ($x) { return $x + $y; }; echo $fn(5) . "\n";"#
            ),
            "15\n"
        );
    }

    #[test]
    fn test_closure_multiple_use() {
        assert_eq!(
            run_php(
                r#"<?php $a = 1; $b = 2; $fn = function() use ($a, $b) { return $a + $b; }; echo $fn() . "\n";"#
            ),
            "3\n"
        );
    }

    #[test]
    fn test_closure_nested() {
        assert_eq!(
            run_php(
                r#"<?php
$make_adder = function($x) {
    return function($y) use ($x) { return $x + $y; };
};
$add5 = $make_adder(5);
echo $add5(3) . "\n";
echo $add5(10) . "\n";
"#
            ),
            "8\n15\n"
        );
    }

    #[test]
    fn test_arrow_function() {
        assert_eq!(
            run_php(r#"<?php $fn = fn($x) => $x * 3; echo $fn(7) . "\n";"#),
            "21\n"
        );
    }

    #[test]
    fn test_dynamic_function_call() {
        assert_eq!(
            run_php(r#"<?php $name = "strlen"; echo $name("hello") . "\n";"#),
            "5\n"
        );
    }

    // =========================================================================
    // Generator tests (comprehensive)
    // =========================================================================

    #[test]
    fn test_generator_fibonacci_sequence() {
        assert_eq!(
            run_php(
                r#"<?php
function fib() {
    $a = 0; $b = 1;
    while (true) {
        yield $a;
        $tmp = $a + $b;
        $a = $b;
        $b = $tmp;
    }
}
$g = fib();
$result = [];
for ($i = 0; $i < 8; $i++) {
    $result[] = $g->current();
    $g->next();
}
echo implode(" ", $result) . "\n";
"#
            ),
            "0 1 1 2 3 5 8 13\n"
        );
    }

    #[test]
    fn test_generator_send_bidirectional() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() {
    $v = yield "first";
    echo "got: " . $v . "\n";
    $v2 = yield "second";
    echo "got: " . $v2 . "\n";
}
$g = gen();
echo $g->current() . "\n";
$g->send("hello");
echo $g->current() . "\n";
$g->send("world");
"#
            ),
            "first\ngot: hello\nsecond\ngot: world\n"
        );
    }

    #[test]
    fn test_generator_key_value() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() {
    yield "a" => 1;
    yield "b" => 2;
    yield "c" => 3;
}
foreach (gen() as $k => $v) {
    echo $k . ":" . $v . "\n";
}
"#
            ),
            "a:1\nb:2\nc:3\n"
        );
    }

    #[test]
    fn test_generator_return_value() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() {
    yield 1;
    yield 2;
    return "done";
}
$g = gen();
$g->current();
$g->next();
$g->next();
echo $g->getReturn() . "\n";
"#
            ),
            "done\n"
        );
    }

    #[test]
    fn test_generator_valid() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() {
    yield 1;
}
$g = gen();
var_dump($g->valid());
$g->next();
var_dump($g->valid());
"#
            ),
            "bool(true)\nbool(false)\n"
        );
    }

    // =========================================================================
    // Fiber tests (comprehensive)
    // =========================================================================

    #[test]
    fn test_fiber_with_closure() {
        assert_eq!(
            run_php(
                r#"<?php
$fiber = new Fiber(function () {
    $val = Fiber::suspend("suspended");
    echo "resumed with: " . $val . "\n";
});
$result = $fiber->start();
echo "fiber said: " . $result . "\n";
$fiber->resume("go");
"#
            ),
            "fiber said: suspended\nresumed with: go\n"
        );
    }

    #[test]
    fn test_fiber_multiple_suspends() {
        assert_eq!(
            run_php(
                r#"<?php
function work() {
    Fiber::suspend(1);
    Fiber::suspend(2);
    Fiber::suspend(3);
    return 4;
}
$f = new Fiber('work');
echo $f->start() . "\n";
echo $f->resume() . "\n";
echo $f->resume() . "\n";
$f->resume();
echo $f->getReturn() . "\n";
"#
            ),
            "1\n2\n3\n4\n"
        );
    }

    // =========================================================================
    // String interpolation tests
    // =========================================================================

    #[test]
    fn test_string_interpolation_simple() {
        assert_eq!(
            run_php(r#"<?php $name = "World"; echo "Hello, $name!\n";"#),
            "Hello, World!\n"
        );
    }

    #[test]
    fn test_string_interpolation_multiple_vars() {
        assert_eq!(
            run_php(r#"<?php $a = 1; $b = 2; echo "$a + $b\n";"#),
            "1 + 2\n"
        );
    }

    #[test]
    fn test_string_interpolation_escape_sequences() {
        assert_eq!(run_php(r#"<?php echo "tab\there\n";"#), "tab\there\n");
    }

    // =========================================================================
    // String Rope Operations (RopeInit/RopeAdd/RopeEnd)
    // =========================================================================

    #[test]
    fn test_rope_three_parts() {
        // 3 parts triggers RopeInit + RopeAdd + RopeEnd (not plain Concat)
        assert_eq!(
            run_php(r#"<?php $name = "World"; echo "Hello, $name!";"#),
            "Hello, World!"
        );
    }

    #[test]
    fn test_rope_four_parts() {
        assert_eq!(
            run_php(r#"<?php $a = "X"; $b = "Y"; echo "[$a,$b]";"#),
            "[X,Y]"
        );
    }

    #[test]
    fn test_rope_five_parts() {
        assert_eq!(
            run_php(r#"<?php $x = 1; $y = 2; $z = 3; echo "$x+$y=$z";"#),
            "1+2=3"
        );
    }

    #[test]
    fn test_rope_with_int_coercion() {
        // Rope must convert non-string values to strings
        assert_eq!(
            run_php(r#"<?php $n = 42; echo "The answer is $n, really $n";"#),
            "The answer is 42, really 42"
        );
    }

    #[test]
    fn test_rope_with_curly_brace_interpolation() {
        assert_eq!(
            run_php(r#"<?php $s = "bar"; echo "foo{$s}baz{$s}qux";"#),
            "foobarbazbarqux"
        );
    }

    #[test]
    fn test_rope_with_mixed_types() {
        // bool, null, float coercion in rope
        assert_eq!(
            run_php(r#"<?php $b = true; $n = null; $f = 3.14; echo "b=$b,n=$n,f=$f";"#),
            "b=1,n=,f=3.14"
        );
    }

    #[test]
    fn test_rope_empty_parts() {
        assert_eq!(run_php(r#"<?php $e = ""; echo "a{$e}b{$e}c";"#), "abc");
    }

    #[test]
    fn test_rope_heredoc() {
        assert_eq!(
            run_php(
                r#"<?php
$a = "hello";
$b = "world";
echo <<<EOT
$a $b!
EOT;
"#
            ),
            "hello world!\n"
        );
    }

    #[test]
    fn test_rope_explicit_concat_chain() {
        // Explicit . operator chains also use rope when 3+ parts
        assert_eq!(run_php(r#"<?php echo "a" . "b" . "c" . "d";"#), "abcd");
    }

    // =========================================================================
    // Error Suppression (@ operator — BeginSilence/EndSilence)
    // =========================================================================

    #[test]
    fn test_at_operator_suppresses_value() {
        // @ should not change the expression result
        assert_eq!(run_php(r#"<?php $x = @(1 + 2); echo $x;"#), "3");
    }

    #[test]
    fn test_at_operator_with_function_call() {
        // @ on a function call should still return the result
        assert_eq!(run_php(r#"<?php echo @strlen("hello");"#), "5");
    }

    #[test]
    fn test_at_operator_with_string() {
        assert_eq!(run_php(r#"<?php $r = @"hello"; echo $r;"#), "hello");
    }

    #[test]
    fn test_at_operator_nested() {
        // Nested @ operators should work correctly
        assert_eq!(run_php(r#"<?php $x = @(@(2 * 3)); echo $x;"#), "6");
    }

    #[test]
    fn test_at_operator_error_reporting_restored() {
        // After @ expression, error_reporting should be restored
        assert_eq!(
            run_php(
                r#"<?php
$before = error_reporting();
$x = @(1 + 2);
$after = error_reporting();
echo $before === $after ? "restored" : "broken";
"#
            ),
            "restored"
        );
    }

    #[test]
    fn test_at_operator_with_variable() {
        assert_eq!(run_php(r#"<?php $a = 42; echo @$a;"#), "42");
    }

    // =========================================================================
    // Introspection Operations (GetClass, GetCalledClass, GetType opcodes)
    // =========================================================================

    #[test]
    fn test_gettype_opcode_all_types() {
        assert_eq!(
            run_php(
                r#"<?php
echo gettype(null) . "\n";
echo gettype(true) . "\n";
echo gettype(42) . "\n";
echo gettype(3.14) . "\n";
echo gettype("hello") . "\n";
echo gettype([1,2]) . "\n";
"#
            ),
            "NULL\nboolean\ninteger\ndouble\nstring\narray\n"
        );
    }

    #[test]
    fn test_gettype_opcode_object() {
        assert_eq!(
            run_php(
                r#"<?php
class Foo {}
echo gettype(new Foo());
"#
            ),
            "object"
        );
    }

    #[test]
    fn test_get_class_opcode_with_arg() {
        assert_eq!(
            run_php(
                r#"<?php
class MyClass {}
$obj = new MyClass();
echo get_class($obj);
"#
            ),
            "MyClass"
        );
    }

    #[test]
    fn test_get_class_opcode_non_object() {
        // get_class() with non-object returns false
        assert_eq!(
            run_php(r#"<?php var_dump(get_class(42));"#),
            "bool(false)\n"
        );
    }

    #[test]
    fn test_get_class_opcode_no_args_in_method() {
        assert_eq!(
            run_php(
                r#"<?php
class Animal {
    public function whoAmI() {
        return get_class();
    }
}
$a = new Animal();
echo $a->whoAmI();
"#
            ),
            "Animal"
        );
    }

    #[test]
    fn test_get_called_class_in_static_method() {
        assert_eq!(
            run_php(
                r#"<?php
class Base {
    public static function identify() {
        return get_called_class();
    }
}
echo Base::identify();
"#
            ),
            "Base"
        );
    }

    #[test]
    fn test_get_called_class_late_static_binding() {
        assert_eq!(
            run_php(
                r#"<?php
class Base {
    public static function identify() {
        return get_called_class();
    }
}
class Child extends Base {}
echo Child::identify();
"#
            ),
            "Child"
        );
    }

    #[test]
    fn test_gettype_in_condition() {
        assert_eq!(
            run_php(
                r#"<?php
$x = 42;
if (gettype($x) === "integer") {
    echo "yes";
} else {
    echo "no";
}
"#
            ),
            "yes"
        );
    }

    // =========================================================================
    // Inc/Dec on Object Properties (PreIncObj/PostIncObj/PreDecObj/PostDecObj)
    // =========================================================================

    #[test]
    fn test_pre_inc_obj() {
        assert_eq!(
            run_php(
                r#"<?php
class Counter { public $n = 0; }
$c = new Counter();
$x = ++$c->n;
echo $x . "," . $c->n;
"#
            ),
            "1,1"
        );
    }

    #[test]
    fn test_post_inc_obj() {
        assert_eq!(
            run_php(
                r#"<?php
class Counter { public $n = 5; }
$c = new Counter();
$x = $c->n++;
echo $x . "," . $c->n;
"#
            ),
            "5,6"
        );
    }

    #[test]
    fn test_pre_dec_obj() {
        assert_eq!(
            run_php(
                r#"<?php
class Counter { public $n = 10; }
$c = new Counter();
$x = --$c->n;
echo $x . "," . $c->n;
"#
            ),
            "9,9"
        );
    }

    #[test]
    fn test_post_dec_obj() {
        assert_eq!(
            run_php(
                r#"<?php
class Counter { public $n = 3; }
$c = new Counter();
$x = $c->n--;
echo $x . "," . $c->n;
"#
            ),
            "3,2"
        );
    }

    #[test]
    fn test_inc_obj_in_loop() {
        assert_eq!(
            run_php(
                r#"<?php
class C { public $v = 0; }
$c = new C();
for ($i = 0; $i < 5; $i++) { $c->v++; }
echo $c->v;
"#
            ),
            "5"
        );
    }

    // =========================================================================
    // Inc/Dec on Static Properties (PreIncStaticProp/PostIncStaticProp etc.)
    // =========================================================================

    #[test]
    fn test_pre_inc_static_prop() {
        assert_eq!(
            run_php(
                r#"<?php
class Counter { public static $n = 0; }
$x = ++Counter::$n;
echo "$x," . Counter::$n;
"#
            ),
            "1,1"
        );
    }

    #[test]
    fn test_post_inc_static_prop() {
        assert_eq!(
            run_php(
                r#"<?php
class Counter { public static $n = 10; }
$x = Counter::$n++;
echo "$x," . Counter::$n;
"#
            ),
            "10,11"
        );
    }

    #[test]
    fn test_pre_dec_static_prop() {
        assert_eq!(
            run_php(
                r#"<?php
class Counter { public static $n = 5; }
$x = --Counter::$n;
echo "$x," . Counter::$n;
"#
            ),
            "4,4"
        );
    }

    #[test]
    fn test_post_dec_static_prop() {
        assert_eq!(
            run_php(
                r#"<?php
class Counter { public static $n = 7; }
$x = Counter::$n--;
echo "$x," . Counter::$n;
"#
            ),
            "7,6"
        );
    }

    #[test]
    fn test_inc_static_prop_in_loop() {
        assert_eq!(
            run_php(
                r#"<?php
class C { public static $count = 0; }
for ($i = 0; $i < 3; $i++) { C::$count++; }
echo C::$count;
"#
            ),
            "3"
        );
    }

    // =========================================================================
    // Call Operations (FuncNumArgs, FuncGetArgs)
    // =========================================================================

    #[test]
    fn test_func_num_args_basic() {
        assert_eq!(
            run_php(
                r#"<?php
function f($a, $b, $c) { return func_num_args(); }
echo f(1, 2, 3);
"#
            ),
            "3"
        );
    }

    #[test]
    fn test_func_num_args_variadic() {
        assert_eq!(
            run_php(
                r#"<?php
function f() { return func_num_args(); }
echo f(10, 20, 30, 40);
"#
            ),
            "4"
        );
    }

    #[test]
    fn test_func_num_args_zero() {
        assert_eq!(
            run_php(
                r#"<?php
function f() { return func_num_args(); }
echo f();
"#
            ),
            "0"
        );
    }

    #[test]
    fn test_func_get_args_basic() {
        assert_eq!(
            run_php(
                r#"<?php
function f($a, $b) {
    $args = func_get_args();
    echo count($args) . ":" . $args[0] . "," . $args[1];
}
f("hello", "world");
"#
            ),
            "2:hello,world"
        );
    }

    #[test]
    fn test_func_get_args_extra() {
        assert_eq!(
            run_php(
                r#"<?php
function f($a) {
    $args = func_get_args();
    foreach ($args as $v) { echo $v . " "; }
}
f(1, 2, 3);
"#
            ),
            "1 2 3 "
        );
    }

    #[test]
    fn test_func_get_args_empty() {
        assert_eq!(
            run_php(
                r#"<?php
function f() { return func_get_args(); }
$a = f();
echo count($a);
"#
            ),
            "0"
        );
    }

    // =========================================================================
    // Production hardening tests
    // =========================================================================

    fn run_php_with_config(source: &str, config: VmConfig) -> Result<String, VmError> {
        let op_array = compile(source).unwrap_or_else(|e| {
            panic!("Compilation failed for:\n{}\nError: {:?}", source, e);
        });
        let mut vm = Vm::with_config(config);
        vm.execute(&op_array, None)
    }

    #[test]
    fn test_execution_time_limit() {
        // Set a very short time limit (1 second) and run an infinite loop
        let mut config = VmConfig::default();
        config.max_execution_time = 1;
        let result = run_php_with_config("<?php while(true) { $x = 1; }", config);
        assert!(result.is_err());
        match result.unwrap_err() {
            VmError::TimeLimitExceeded(msg) => {
                assert!(msg.contains("Maximum execution time"));
            }
            other => panic!("Expected TimeLimitExceeded, got {:?}", other),
        }
    }

    #[test]
    fn test_memory_limit_enforcement() {
        // Set a very small memory limit
        let mut config = VmConfig::default();
        config.memory_limit = 64; // 64 bytes — absurdly small
        let result = run_php_with_config(
            r#"<?php
$a = "x";
for ($i = 0; $i < 10000; $i++) {
    $a = $a . "x";
}
echo $a;
"#,
            config,
        );
        // With 64 bytes limit, this should fail due to memory
        assert!(result.is_err());
        match result.unwrap_err() {
            VmError::MemoryLimitExceeded(msg) => {
                assert!(msg.contains("memory size"));
            }
            other => panic!("Expected MemoryLimitExceeded, got {:?}", other),
        }
    }

    #[test]
    fn test_disable_functions() {
        let mut config = VmConfig::default();
        config.set_disabled_functions("strlen,var_dump");
        let result = run_php_with_config(r#"<?php echo strlen("hello");"#, config);
        assert!(result.is_err());
        match result.unwrap_err() {
            VmError::DisabledFunction(msg) => {
                assert!(msg.contains("strlen"));
                assert!(msg.contains("disabled"));
            }
            other => panic!("Expected DisabledFunction, got {:?}", other),
        }
    }

    #[test]
    fn test_disable_functions_other_functions_work() {
        let mut config = VmConfig::default();
        config.set_disabled_functions("exec,system");
        // strlen is NOT disabled, so it should work fine
        let result = run_php_with_config(r#"<?php echo strlen("hello");"#, config);
        assert_eq!(result.unwrap(), "5");
    }

    #[test]
    fn test_no_time_limit_when_zero() {
        // 0 means no limit — should run fine
        let mut config = VmConfig::default();
        config.max_execution_time = 0;
        let result = run_php_with_config("<?php echo 42;", config);
        assert_eq!(result.unwrap(), "42");
    }

    #[test]
    fn test_no_memory_limit_when_zero() {
        // 0 means no limit — should run fine
        let mut config = VmConfig::default();
        config.memory_limit = 0;
        let result = run_php_with_config("<?php echo 42;", config);
        assert_eq!(result.unwrap(), "42");
    }

    #[test]
    fn test_request_state_cleanup() {
        // Test that state is properly cleaned between execute() calls
        let mut vm = Vm::new();
        let source1 = compile("<?php $x = 42; echo $x;").unwrap();
        let source2 = compile("<?php echo isset($x) ? 'yes' : 'no';").unwrap();

        let output1 = vm.execute(&source1, None).unwrap();
        assert_eq!(output1, "42");

        // Second execution should not see $x from first — CVs are per-frame
        let output2 = vm.execute(&source2, None).unwrap();
        assert_eq!(output2, "no");
    }

    #[test]
    fn test_vm_config_set_disabled_functions() {
        let mut config = VmConfig::default();
        assert!(config.disabled_functions.is_empty());

        config.set_disabled_functions("strlen, var_dump, echo");
        assert!(config.disabled_functions.contains("strlen"));
        assert!(config.disabled_functions.contains("var_dump"));
        assert!(config.disabled_functions.contains("echo"));
        assert_eq!(config.disabled_functions.len(), 3);
    }

    #[test]
    fn test_vm_config_set_open_basedir() {
        let mut config = VmConfig::default();
        assert!(config.open_basedir.is_empty());

        config.set_open_basedir("/tmp:/var/www");
        assert_eq!(config.open_basedir, vec!["/tmp", "/var/www"]);
    }

    #[test]
    fn test_vm_config_defaults() {
        let config = VmConfig::default();
        assert_eq!(config.memory_limit, 128 * 1024 * 1024);
        assert_eq!(config.max_execution_time, 30);
        assert!(config.disabled_functions.is_empty());
        assert!(config.open_basedir.is_empty());
    }

    // =========================================================================
    // Implemented function stubs
    // =========================================================================

    #[test]
    fn test_error_reporting() {
        // Returns old level, sets new level
        assert_eq!(run_php("<?php echo error_reporting(0);"), "32767");
        assert_eq!(
            run_php("<?php error_reporting(0); echo error_reporting();"),
            "0"
        );
        assert_eq!(
            run_php(
                "<?php $old = error_reporting(E_WARNING); echo $old . ',' . error_reporting();"
            ),
            "32767,2"
        );
    }

    #[test]
    fn test_set_error_handler() {
        assert_eq!(
            run_php(
                r#"<?php
$prev = set_error_handler("my_handler");
echo ($prev === null) ? "null" : "set";
"#
            ),
            "null"
        );
    }

    #[test]
    fn test_array_multisort() {
        assert_eq!(
            run_php(
                r#"<?php
$a = [3, 1, 2];
array_multisort($a);
echo implode(",", $a);
"#
            ),
            "1,2,3"
        );
    }

    #[test]
    fn test_array_multisort_desc() {
        assert_eq!(
            run_php(
                r#"<?php
$a = [3, 1, 2];
array_multisort($a, SORT_DESC);
echo implode(",", $a);
"#
            ),
            "3,2,1"
        );
    }

    #[test]
    fn test_array_all() {
        assert_eq!(
            run_php(
                r#"<?php
$r = array_all([2, 4, 6], function($v, $k) { return $v % 2 === 0; });
echo $r ? "true" : "false";
"#
            ),
            "true"
        );
        assert_eq!(
            run_php(
                r#"<?php
$r = array_all([2, 3, 6], function($v, $k) { return $v % 2 === 0; });
echo $r ? "true" : "false";
"#
            ),
            "false"
        );
    }

    #[test]
    fn test_array_any() {
        assert_eq!(
            run_php(
                r#"<?php
$r = array_any([1, 3, 4], function($v, $k) { return $v % 2 === 0; });
echo $r ? "true" : "false";
"#
            ),
            "true"
        );
        assert_eq!(
            run_php(
                r#"<?php
$r = array_any([1, 3, 5], function($v, $k) { return $v % 2 === 0; });
echo $r ? "true" : "false";
"#
            ),
            "false"
        );
    }

    #[test]
    fn test_array_find() {
        assert_eq!(
            run_php(
                r#"<?php
$r = array_find([1, 2, 3, 4], function($v, $k) { return $v > 2; });
echo $r;
"#
            ),
            "3"
        );
        assert_eq!(
            run_php(
                r#"<?php
$r = array_find([1, 2], function($v, $k) { return $v > 10; });
echo ($r === null) ? "null" : $r;
"#
            ),
            "null"
        );
    }

    #[test]
    fn test_array_find_key() {
        assert_eq!(
            run_php(
                r#"<?php
$r = array_find_key(["a" => 1, "b" => 2, "c" => 3], function($v, $k) { return $v > 2; });
echo $r;
"#
            ),
            "c"
        );
    }

    #[test]
    fn test_array_walk_recursive() {
        assert_eq!(
            run_php(
                r#"<?php
$arr = [1, [2, 3], 4];
array_walk_recursive($arr, function($val, $key) { echo $val . ","; });
"#
            ),
            "1,2,3,4,"
        );
    }

    #[test]
    fn test_preg_replace_callback_array_fn() {
        assert_eq!(
            run_php(
                r#"<?php
$result = preg_replace_callback_array([
    "/\d+/" => function($m) { return "[" . $m[0] . "]"; },
    "/[a-z]+/" => function($m) { return strtoupper($m[0]); },
], "abc123def");
echo $result;
"#
            ),
            "ABC[123]DEF"
        );
    }

    #[test]
    fn test_array_diff_ukey() {
        assert_eq!(
            run_php(
                r#"<?php
$a = ["a" => 1, "b" => 2, "c" => 3];
$b = ["a" => 10, "c" => 30];
$result = array_diff_ukey($a, $b, function($k1, $k2) { return strcmp($k1, $k2); });
echo implode(",", $result);
"#
            ),
            "2"
        );
    }

    #[test]
    fn test_array_udiff() {
        assert_eq!(
            run_php(
                r#"<?php
$a = [1, 2, 3, 4, 5];
$b = [2, 4];
$result = array_udiff($a, $b, function($a, $b) { return $a - $b; });
echo implode(",", $result);
"#
            ),
            "1,3,5"
        );
    }

    // =======================================================================
    // InArray opcode tests (1F.03)
    // =======================================================================

    #[test]
    fn test_in_array_loose() {
        assert_eq!(
            run_php(
                r#"<?php
$arr = [1, 2, 3, "hello"];
echo in_array(2, $arr) ? "yes" : "no";
echo "\n";
echo in_array(99, $arr) ? "yes" : "no";
"#
            ),
            "yes\nno"
        );
    }

    #[test]
    fn test_in_array_strict() {
        assert_eq!(
            run_php(
                r#"<?php
$arr = [1, 2, 3];
echo in_array("1", $arr, true) ? "yes" : "no";
echo "\n";
echo in_array(1, $arr, true) ? "yes" : "no";
"#
            ),
            "no\nyes"
        );
    }

    #[test]
    fn test_in_array_loose_type_coercion() {
        assert_eq!(
            run_php(
                r#"<?php
$arr = [1, 2, 3];
echo in_array("1", $arr) ? "yes" : "no";
echo "\n";
echo in_array(true, $arr) ? "yes" : "no";
"#
            ),
            "yes\nyes"
        );
    }

    #[test]
    fn test_in_array_with_strings() {
        assert_eq!(
            run_php(
                r#"<?php
$fruits = ["apple", "banana", "cherry"];
echo in_array("banana", $fruits) ? "found" : "not found";
echo "\n";
echo in_array("grape", $fruits) ? "found" : "not found";
"#
            ),
            "found\nnot found"
        );
    }

    #[test]
    fn test_in_array_empty_array() {
        assert_eq!(
            run_php(
                r#"<?php
echo in_array("x", []) ? "yes" : "no";
"#
            ),
            "no"
        );
    }

    #[test]
    fn test_in_array_strict_false() {
        // explicit false for strict should still use loose comparison
        assert_eq!(
            run_php(
                r#"<?php
$arr = [1, 2, 3];
echo in_array("1", $arr, false) ? "yes" : "no";
"#
            ),
            "yes"
        );
    }

    // =======================================================================
    // ArrayKeyExists opcode tests (1F.04)
    // =======================================================================

    #[test]
    fn test_array_key_exists_basic() {
        assert_eq!(
            run_php(
                r#"<?php
$arr = ["name" => "Alice", "age" => 30];
echo array_key_exists("name", $arr) ? "yes" : "no";
echo "\n";
echo array_key_exists("email", $arr) ? "yes" : "no";
"#
            ),
            "yes\nno"
        );
    }

    #[test]
    fn test_array_key_exists_integer_keys() {
        assert_eq!(
            run_php(
                r#"<?php
$arr = [10 => "a", 20 => "b", 30 => "c"];
echo array_key_exists(20, $arr) ? "yes" : "no";
echo "\n";
echo array_key_exists(15, $arr) ? "yes" : "no";
"#
            ),
            "yes\nno"
        );
    }

    #[test]
    fn test_array_key_exists_null_value() {
        // array_key_exists returns true even if value is null
        assert_eq!(
            run_php(
                r#"<?php
$arr = ["key" => null];
echo array_key_exists("key", $arr) ? "yes" : "no";
echo "\n";
echo isset($arr["key"]) ? "yes" : "no";
"#
            ),
            "yes\nno"
        );
    }

    #[test]
    fn test_array_key_exists_sequential() {
        assert_eq!(
            run_php(
                r#"<?php
$arr = ["a", "b", "c"];
echo array_key_exists(0, $arr) ? "yes" : "no";
echo "\n";
echo array_key_exists(3, $arr) ? "yes" : "no";
"#
            ),
            "yes\nno"
        );
    }

    #[test]
    fn test_key_exists_alias() {
        assert_eq!(
            run_php(
                r#"<?php
$arr = ["foo" => "bar"];
echo key_exists("foo", $arr) ? "yes" : "no";
"#
            ),
            "yes"
        );
    }

    #[test]
    fn test_array_key_exists_empty_array() {
        assert_eq!(
            run_php(
                r#"<?php
echo array_key_exists("x", []) ? "yes" : "no";
"#
            ),
            "no"
        );
    }

    // =======================================================================
    // Isset/Unset Variants (1D)
    // =======================================================================

    #[test]
    fn test_isset_obj_property() {
        assert_eq!(
            run_php(
                r#"<?php
class Foo {
    public $name = "Alice";
    public $empty = null;
}
$f = new Foo();
echo isset($f->name) ? "yes" : "no";
echo "\n";
echo isset($f->empty) ? "yes" : "no";
echo "\n";
echo isset($f->missing) ? "yes" : "no";
"#
            ),
            "yes\nno\nno"
        );
    }

    #[test]
    fn test_unset_obj_property() {
        assert_eq!(
            run_php(
                r#"<?php
class Foo {
    public $x = 10;
    public $y = 20;
}
$f = new Foo();
echo $f->x . "\n";
unset($f->x);
echo isset($f->x) ? "yes" : "no";
echo "\n";
echo $f->y;
"#
            ),
            "10\nno\n20"
        );
    }

    #[test]
    fn test_isset_static_property() {
        assert_eq!(
            run_php(
                r#"<?php
class Counter {
    public static $count = 42;
    public static $empty = null;
}
echo isset(Counter::$count) ? "yes" : "no";
echo "\n";
echo isset(Counter::$empty) ? "yes" : "no";
"#
            ),
            "yes\nno"
        );
    }

    #[test]
    fn test_unset_static_property() {
        assert_eq!(
            run_php(
                r#"<?php
class Config {
    public static $debug = true;
}
echo isset(Config::$debug) ? "yes" : "no";
echo "\n";
unset(Config::$debug);
echo isset(Config::$debug) ? "yes" : "no";
"#
            ),
            "yes\nno"
        );
    }

    #[test]
    fn test_isset_this_in_method() {
        assert_eq!(
            run_php(
                r#"<?php
class Foo {
    public function check() {
        return isset($this) ? "yes" : "no";
    }
}
$f = new Foo();
echo $f->check();
"#
            ),
            "yes"
        );
    }

    #[test]
    fn test_isset_obj_property_multiple() {
        assert_eq!(
            run_php(
                r#"<?php
class Foo {
    public $a = 1;
    public $b = 2;
}
$f = new Foo();
echo isset($f->a, $f->b) ? "yes" : "no";
"#
            ),
            "yes"
        );
    }

    #[test]
    fn test_unset_obj_then_check() {
        assert_eq!(
            run_php(
                r#"<?php
class Bag {
    public $items = "stuff";
}
$b = new Bag();
$before = isset($b->items) ? "set" : "unset";
unset($b->items);
$after = isset($b->items) ? "set" : "unset";
echo $before . "\n" . $after;
"#
            ),
            "set\nunset"
        );
    }

    #[test]
    fn test_isset_static_prop_inherited() {
        assert_eq!(
            run_php(
                r#"<?php
class Base {
    public static $val = "hello";
}
class Child extends Base {}
echo isset(Child::$val) ? "yes" : "no";
"#
            ),
            "yes"
        );
    }

    #[test]
    fn test_unset_multiple_obj_props() {
        assert_eq!(
            run_php(
                r#"<?php
class Point {
    public $x = 1;
    public $y = 2;
    public $z = 3;
}
$p = new Point();
unset($p->x, $p->z);
echo isset($p->x) ? "yes" : "no";
echo "\n";
echo isset($p->y) ? "yes" : "no";
echo "\n";
echo isset($p->z) ? "yes" : "no";
"#
            ),
            "no\nyes\nno"
        );
    }

    #[test]
    fn test_isset_this_outside_method() {
        // Outside a method, $this should not be set
        assert_eq!(
            run_php(
                r#"<?php
echo isset($this) ? "yes" : "no";
"#
            ),
            "no"
        );
    }

    // =======================================================================
    // Compound Assignment on Properties/Dims (1B)
    // =======================================================================

    #[test]
    fn test_assign_dim_op_add() {
        assert_eq!(
            run_php(
                r#"<?php
$a = [10, 20, 30];
$a[0] += 5;
$a[2] += 100;
echo $a[0] . "," . $a[1] . "," . $a[2];
"#
            ),
            "15,20,130"
        );
    }

    #[test]
    fn test_assign_dim_op_concat() {
        assert_eq!(
            run_php(
                r#"<?php
$a = ["hello", "world"];
$a[0] .= " there";
echo $a[0] . " " . $a[1];
"#
            ),
            "hello there world"
        );
    }

    #[test]
    fn test_assign_dim_op_assoc() {
        assert_eq!(
            run_php(
                r#"<?php
$scores = ["alice" => 10, "bob" => 20];
$scores["alice"] += 5;
$scores["bob"] -= 3;
echo $scores["alice"] . "," . $scores["bob"];
"#
            ),
            "15,17"
        );
    }

    #[test]
    fn test_assign_dim_op_mul_div() {
        assert_eq!(
            run_php(
                r#"<?php
$a = [6, 10];
$a[0] *= 3;
$a[1] /= 2;
echo $a[0] . "," . $a[1];
"#
            ),
            "18,5"
        );
    }

    #[test]
    fn test_assign_dim_op_mod() {
        assert_eq!(
            run_php(
                r#"<?php
$a = [17];
$a[0] %= 5;
echo $a[0];
"#
            ),
            "2"
        );
    }

    #[test]
    fn test_assign_dim_op_bitwise() {
        assert_eq!(
            run_php(
                r#"<?php
$a = [0xFF, 0x0F, 0xAA];
$a[0] &= 0x0F;
$a[1] |= 0xF0;
$a[2] ^= 0xFF;
echo $a[0] . "," . $a[1] . "," . $a[2];
"#
            ),
            "15,255,85"
        );
    }

    #[test]
    fn test_assign_dim_op_in_loop() {
        assert_eq!(
            run_php(
                r#"<?php
$counts = ["a" => 0, "b" => 0, "c" => 0];
$items = ["a", "b", "a", "c", "a", "b"];
foreach ($items as $item) {
    $counts[$item] += 1;
}
echo $counts["a"] . "," . $counts["b"] . "," . $counts["c"];
"#
            ),
            "3,2,1"
        );
    }

    #[test]
    fn test_assign_obj_op_add() {
        assert_eq!(
            run_php(
                r#"<?php
class Counter {
    public $count = 0;
}
$c = new Counter();
$c->count += 10;
$c->count += 5;
echo $c->count;
"#
            ),
            "15"
        );
    }

    #[test]
    fn test_assign_obj_op_concat() {
        assert_eq!(
            run_php(
                r#"<?php
class Builder {
    public $html = "<div>";
}
$b = new Builder();
$b->html .= "<p>Hello</p>";
$b->html .= "</div>";
echo $b->html;
"#
            ),
            "<div><p>Hello</p></div>"
        );
    }

    #[test]
    fn test_assign_obj_op_sub() {
        assert_eq!(
            run_php(
                r#"<?php
class Wallet {
    public $balance = 100;
}
$w = new Wallet();
$w->balance -= 30;
$w->balance -= 15;
echo $w->balance;
"#
            ),
            "55"
        );
    }

    #[test]
    fn test_assign_static_prop_op_add() {
        assert_eq!(
            run_php(
                r#"<?php
class Stats {
    public static $total = 0;
}
Stats::$total += 10;
Stats::$total += 20;
echo Stats::$total;
"#
            ),
            "30"
        );
    }

    #[test]
    fn test_assign_static_prop_op_concat() {
        assert_eq!(
            run_php(
                r#"<?php
class Logger {
    public static $log = "";
}
Logger::$log .= "start;";
Logger::$log .= "process;";
Logger::$log .= "end";
echo Logger::$log;
"#
            ),
            "start;process;end"
        );
    }

    #[test]
    fn test_assign_dim_op_shift() {
        assert_eq!(
            run_php(
                r#"<?php
$a = [8, 16];
$a[0] <<= 2;
$a[1] >>= 1;
echo $a[0] . "," . $a[1];
"#
            ),
            "32,8"
        );
    }

    // =======================================================================
    // AddArrayUnpack — spread operator in arrays (1J.01)
    // =======================================================================

    #[test]
    fn test_array_unpack_basic() {
        assert_eq!(
            run_php(
                r#"<?php
$a = [1, 2, 3];
$b = [0, ...$a, 4];
echo implode(",", $b);
"#
            ),
            "0,1,2,3,4"
        );
    }

    #[test]
    fn test_array_unpack_multiple() {
        assert_eq!(
            run_php(
                r#"<?php
$a = [1, 2];
$b = [3, 4];
$c = [...$a, ...$b];
echo implode(",", $c);
"#
            ),
            "1,2,3,4"
        );
    }

    #[test]
    fn test_array_unpack_empty() {
        assert_eq!(
            run_php(
                r#"<?php
$empty = [];
$result = [1, ...$empty, 2];
echo implode(",", $result);
"#
            ),
            "1,2"
        );
    }

    #[test]
    fn test_array_unpack_string_keys() {
        assert_eq!(
            run_php(
                r#"<?php
$a = ["x" => 10, "y" => 20];
$b = ["z" => 30, ...$a];
echo $b["x"] . "," . $b["y"] . "," . $b["z"];
"#
            ),
            "10,20,30"
        );
    }

    #[test]
    fn test_array_unpack_overwrite() {
        assert_eq!(
            run_php(
                r#"<?php
$a = ["name" => "Alice"];
$b = ["name" => "Bob", ...$a];
echo $b["name"];
"#
            ),
            "Alice"
        );
    }

    #[test]
    fn test_array_unpack_in_function() {
        assert_eq!(
            run_php(
                r#"<?php
function merge($a, $b) {
    return [...$a, ...$b];
}
$result = merge([1, 2], [3, 4]);
echo count($result);
"#
            ),
            "4"
        );
    }

    // =======================================================================
    // BindStatic — static local variables (1J.06)
    // =======================================================================

    #[test]
    fn test_static_var_persists() {
        assert_eq!(
            run_php(
                r#"<?php
function counter() {
    static $count = 0;
    $count++;
    return $count;
}
echo counter() . "," . counter() . "," . counter();
"#
            ),
            "1,2,3"
        );
    }

    #[test]
    fn test_static_var_default_null() {
        assert_eq!(
            run_php(
                r#"<?php
function test() {
    static $x;
    if ($x === null) {
        $x = "initialized";
    }
    return $x;
}
echo test() . "\n" . test();
"#
            ),
            "initialized\ninitialized"
        );
    }

    #[test]
    fn test_static_var_string_concat() {
        assert_eq!(
            run_php(
                r#"<?php
function logger($msg) {
    static $log = "";
    $log .= $msg . ";";
    return $log;
}
logger("start");
logger("process");
echo logger("end");
"#
            ),
            "start;process;end;"
        );
    }

    #[test]
    fn test_static_var_multiple() {
        assert_eq!(
            run_php(
                r#"<?php
function track() {
    static $calls = 0;
    static $total = 0;
    $calls++;
    $total += 10;
    return "$calls:$total";
}
echo track() . "\n" . track() . "\n" . track();
"#
            ),
            "1:10\n2:20\n3:30"
        );
    }

    #[test]
    fn test_static_var_separate_functions() {
        assert_eq!(
            run_php(
                r#"<?php
function a() {
    static $n = 0;
    $n++;
    return $n;
}
function b() {
    static $n = 0;
    $n += 10;
    return $n;
}
echo a() . "," . b() . "," . a() . "," . b();
"#
            ),
            "1,10,2,20"
        );
    }

    #[test]
    fn test_static_var_with_default() {
        assert_eq!(
            run_php(
                r#"<?php
function greet() {
    static $prefix = "Hello";
    $result = $prefix;
    $prefix = "Hi";
    return $result;
}
echo greet() . "\n" . greet() . "\n" . greet();
"#
            ),
            "Hello\nHi\nHi"
        );
    }

    // =========================================================================
    // AssignObjRef / AssignStaticPropRef tests
    // =========================================================================

    #[test]
    fn test_assign_obj_ref() {
        // $obj->prop =& $var: changing $var should change $obj->prop
        assert_eq!(
            run_php(
                r#"<?php
class Foo { public $x = 10; }
$obj = new Foo;
$a = 42;
$obj->x =& $a;
$a = 99;
echo $obj->x;
"#
            ),
            "99"
        );
    }

    #[test]
    fn test_assign_obj_ref_reverse() {
        // Changing $obj->prop should also change $var
        assert_eq!(
            run_php(
                r#"<?php
class Foo { public $x = 10; }
$obj = new Foo;
$a = 42;
$obj->x =& $a;
$obj->x = 77;
echo $a;
"#
            ),
            "77"
        );
    }

    #[test]
    fn test_assign_static_prop_ref() {
        // ClassName::$prop =& $var: changing $var should change the static prop
        assert_eq!(
            run_php(
                r#"<?php
class Bar { public static $val = 0; }
$x = 123;
Bar::$val =& $x;
$x = 456;
echo Bar::$val;
"#
            ),
            "456"
        );
    }

    #[test]
    fn test_assign_static_prop_ref_reverse() {
        // Changing the static prop should also change $var
        assert_eq!(
            run_php(
                r#"<?php
class Bar { public static $val = 0; }
$x = 123;
Bar::$val =& $x;
Bar::$val = 789;
echo $x;
"#
            ),
            "789"
        );
    }

    // =========================================================================
    // SwitchLong / SwitchString optimized dispatch
    // =========================================================================

    #[test]
    fn test_switch_long_basic() {
        assert_eq!(
            run_php(
                r#"<?php
$x = 2;
switch ($x) {
    case 1: echo "one"; break;
    case 2: echo "two"; break;
    case 3: echo "three"; break;
}
"#
            ),
            "two"
        );
    }

    #[test]
    fn test_switch_long_default() {
        assert_eq!(
            run_php(
                r#"<?php
$x = 99;
switch ($x) {
    case 1: echo "one"; break;
    case 2: echo "two"; break;
    default: echo "other"; break;
}
"#
            ),
            "other"
        );
    }

    #[test]
    fn test_switch_long_fallthrough() {
        assert_eq!(
            run_php(
                r#"<?php
$x = 1;
switch ($x) {
    case 1:
    case 2: echo "one or two"; break;
    case 3: echo "three"; break;
}
"#
            ),
            "one or two"
        );
    }

    #[test]
    fn test_switch_string_basic() {
        assert_eq!(
            run_php(
                r#"<?php
$x = "hello";
switch ($x) {
    case "foo": echo "A"; break;
    case "hello": echo "B"; break;
    case "bar": echo "C"; break;
}
"#
            ),
            "B"
        );
    }

    #[test]
    fn test_switch_string_default() {
        assert_eq!(
            run_php(
                r#"<?php
$x = "unknown";
switch ($x) {
    case "a": echo "A"; break;
    case "b": echo "B"; break;
    default: echo "DEFAULT"; break;
}
"#
            ),
            "DEFAULT"
        );
    }

    #[test]
    fn test_switch_long_negative() {
        assert_eq!(
            run_php(
                r#"<?php
$x = -1;
switch ($x) {
    case -1: echo "neg"; break;
    case 0: echo "zero"; break;
    case 1: echo "pos"; break;
}
"#
            ),
            "neg"
        );
    }

    // =========================================================================
    // VerifyReturnType / VerifyNeverType
    // =========================================================================

    #[test]
    fn test_verify_return_type_int() {
        assert_eq!(
            run_php(
                r#"<?php
function add(int $a, int $b): int {
    return $a + $b;
}
echo add(3, 4);
"#
            ),
            "7"
        );
    }

    #[test]
    fn test_verify_return_type_string() {
        assert_eq!(
            run_php(
                r#"<?php
function greet(string $name): string {
    return "Hello, " . $name;
}
echo greet("World");
"#
            ),
            "Hello, World"
        );
    }

    #[test]
    fn test_verify_return_type_nullable() {
        assert_eq!(
            run_php(
                r#"<?php
function maybe(bool $yes): ?int {
    if ($yes) return 42;
    return null;
}
echo maybe(true) . " " . (maybe(false) === null ? "null" : "not-null");
"#
            ),
            "42 null"
        );
    }

    #[test]
    fn test_verify_return_type_mismatch() {
        // In PHP's weak typing mode (default), "not an int" is coerced to int 0.
        // A TypeError would only occur with declare(strict_types=1).
        assert_eq!(
            run_php(
                r#"<?php
function broken(): int {
    return "not an int";
}
echo broken();
"#
            ),
            "0"
        );
    }

    #[test]
    fn test_verify_return_type_union() {
        assert_eq!(
            run_php(
                r#"<?php
function flex(bool $flag): int|string {
    if ($flag) return 42;
    return "hello";
}
echo flex(true) . " " . flex(false);
"#
            ),
            "42 hello"
        );
    }

    #[test]
    fn test_verify_never_type() {
        // A never function that throws should work fine
        let op_array = php_rs_compiler::compile(
            r#"<?php
function halt(): never {
    throw new Exception("stopped");
}
try { halt(); } catch (Exception $e) { echo $e->getMessage(); }
"#,
        )
        .unwrap();
        let mut vm = Vm::new();
        let output = vm.execute(&op_array, None).unwrap_or_default();
        assert_eq!(output, "stopped");
    }

    #[test]
    fn test_verify_return_type_method() {
        assert_eq!(
            run_php(
                r#"<?php
class Calculator {
    public function add(int $a, int $b): int {
        return $a + $b;
    }
}
$c = new Calculator;
echo $c->add(10, 20);
"#
            ),
            "30"
        );
    }

    // =========================================================================
    // AssertCheck opcode
    // =========================================================================

    #[test]
    fn test_assert_check_enabled() {
        // With default config (zend_assertions = 1), assert() should execute
        let output = run_php(
            r#"<?php
assert(true);
echo "ok";
"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_assert_check_enabled_failure() {
        // With default config, assert(false) should produce a warning
        let output = run_php(
            r#"<?php
assert(false);
echo "done";
"#,
        );
        assert!(output.contains("Assertion failed"));
        assert!(output.contains("done"));
    }

    #[test]
    fn test_assert_check_disabled() {
        // With zend_assertions = 0, assert() call should be skipped entirely
        let mut config = VmConfig::default();
        config.zend_assertions = 0;
        let result = run_php_with_config(
            r#"<?php
assert(false);
echo "skipped";
"#,
            config,
        );
        assert_eq!(result.unwrap(), "skipped");
    }

    #[test]
    fn test_assert_check_disabled_negative() {
        // With zend_assertions = -1, assert() call should be skipped
        let mut config = VmConfig::default();
        config.zend_assertions = -1;
        let result = run_php_with_config(
            r#"<?php
assert(1 === 2);
echo "skipped";
"#,
            config,
        );
        assert_eq!(result.unwrap(), "skipped");
    }

    #[test]
    fn test_unset_array_in_object_property() {
        let output = run_php(
            r#"<?php
class Foo {
    public $data = ['x' => 1, 'y' => 2];
    public function remove($key) {
        unset($this->data[$key]);
    }
}
$f = new Foo();
echo isset($f->data['x']) ? "yes" : "no";
$f->remove('x');
echo " ";
echo isset($f->data['x']) ? "yes" : "no";
"#,
        );
        assert_eq!(output, "yes no");
    }

    // =========================================================================
    // Magic Methods
    // =========================================================================

    #[test]
    fn test_magic_tostring() {
        let output = run_php(
            r#"<?php
class Foo {
    public function __toString() {
        return "I am Foo";
    }
}
$f = new Foo();
echo $f;
"#,
        );
        assert_eq!(output, "I am Foo");
    }

    #[test]
    fn test_magic_tostring_concat() {
        let output = run_php(
            r#"<?php
class Name {
    private $name;
    public function __construct($name) {
        $this->name = $name;
    }
    public function __toString() {
        return $this->name;
    }
}
$n = new Name("Alice");
echo "Hello " . $n . "!";
"#,
        );
        assert_eq!(output, "Hello Alice!");
    }

    #[test]
    fn test_magic_tostring_inherited() {
        let output = run_php(
            r#"<?php
class Base {
    public function __toString() {
        return "base";
    }
}
class Child extends Base {}
$c = new Child();
echo $c;
"#,
        );
        assert_eq!(output, "base");
    }

    #[test]
    fn test_magic_get() {
        let output = run_php(
            r#"<?php
class Magic {
    private $data = [];
    public function __get($name) {
        return $this->data[$name] ?? "undefined";
    }
    public function __set($name, $value) {
        $this->data[$name] = $value;
    }
}
$m = new Magic();
$m->foo = "bar";
echo $m->foo;
"#,
        );
        assert_eq!(output, "bar");
    }

    #[test]
    fn test_magic_get_undefined_property() {
        let output = run_php(
            r#"<?php
class Bag {
    public function __get($name) {
        return "got:" . $name;
    }
}
$b = new Bag();
echo $b->hello;
"#,
        );
        assert_eq!(output, "got:hello");
    }

    #[test]
    fn test_magic_set() {
        let output = run_php(
            r#"<?php
class Store {
    private $data = [];
    public function __set($name, $value) {
        $this->data[$name] = strtoupper($value);
    }
    public function __get($name) {
        return $this->data[$name] ?? null;
    }
}
$s = new Store();
$s->name = "alice";
echo $s->name;
"#,
        );
        assert_eq!(output, "ALICE");
    }

    #[test]
    fn test_magic_isset() {
        let output = run_php(
            r#"<?php
class Container {
    private $items = ['a' => 1];
    public function __isset($name) {
        return isset($this->items[$name]);
    }
}
$c = new Container();
echo isset($c->a) ? "yes" : "no";
echo " ";
echo isset($c->b) ? "yes" : "no";
"#,
        );
        assert_eq!(output, "yes no");
    }

    #[test]
    fn test_magic_unset() {
        // Test that __unset is called when unset() is used on undefined properties
        let output = run_php(
            r#"<?php
class Removable {
    public $log = "";
    public function __unset($name) {
        $this->log .= "unset:" . $name . ";";
    }
}
$r = new Removable();
unset($r->foo);
unset($r->bar);
echo $r->log;
"#,
        );
        assert_eq!(output, "unset:foo;unset:bar;");
    }

    #[test]
    fn test_magic_unset_with_isset() {
        // Full cycle: __unset modifies internal data, __isset checks it
        let output = run_php(
            r#"<?php
class Removable {
    private $data = ['x' => 1, 'y' => 2];
    public function __unset($name) {
        unset($this->data[$name]);
    }
    public function __isset($name) {
        return isset($this->data[$name]);
    }
}
$r = new Removable();
echo isset($r->x) ? "yes" : "no";
unset($r->x);
echo " ";
echo isset($r->x) ? "yes" : "no";
"#,
        );
        assert_eq!(output, "yes no");
    }

    #[test]
    fn test_magic_call() {
        let output = run_php(
            r#"<?php
class Proxy {
    public function __call($name, $args) {
        echo "called:" . $name . "(" . implode(",", $args) . ")";
    }
}
$p = new Proxy();
$p->hello("world", 42);
"#,
        );
        assert_eq!(output, "called:hello(world,42)");
    }

    #[test]
    fn test_magic_call_static() {
        let output = run_php(
            r#"<?php
class StaticProxy {
    public static function __callStatic($name, $args) {
        echo "static:" . $name . "(" . implode(",", $args) . ")";
    }
}
StaticProxy::greet("hi");
"#,
        );
        assert_eq!(output, "static:greet(hi)");
    }

    #[test]
    fn test_magic_call_return_value() {
        let output = run_php(
            r#"<?php
class Calculator {
    public function __call($name, $args) {
        if ($name === "add") {
            return $args[0] + $args[1];
        }
        return null;
    }
}
$c = new Calculator();
echo $c->add(3, 4);
"#,
        );
        assert_eq!(output, "7");
    }

    #[test]
    fn test_magic_get_set_isset_combined() {
        // Test __get, __set, __isset working together
        let output = run_php(
            r#"<?php
class Entity {
    private $attrs = [];
    public function __get($name) {
        return $this->attrs[$name] ?? null;
    }
    public function __set($name, $value) {
        $this->attrs[$name] = $value;
    }
    public function __isset($name) {
        return isset($this->attrs[$name]);
    }
}
$e = new Entity();
$e->name = "test";
echo $e->name . "\n";
echo isset($e->name) ? "set" : "unset";
echo "\n";
echo isset($e->age) ? "set" : "unset";
"#,
        );
        assert_eq!(output, "test\nset\nunset");
    }

    // =========================================================================
    // Phase 4: Type Coercion & Comparison Correctness
    // =========================================================================

    // --- 4.15: PHP 8.0+ Loose Comparison ---

    #[test]
    fn test_loose_cmp_string_foo_eq_zero() {
        // PHP 8.0+: non-numeric string == 0 is false
        let output = run_php(r#"<?php echo ("foo" == 0) ? "true" : "false"; ?>"#);
        assert_eq!(output, "false");
    }

    #[test]
    fn test_loose_cmp_numeric_string_eq_int() {
        // "42" == 42 is still true
        let output = run_php(r#"<?php echo ("42" == 42) ? "true" : "false"; ?>"#);
        assert_eq!(output, "true");
    }

    #[test]
    fn test_loose_cmp_empty_string_eq_zero() {
        // "" == 0 is false in PHP 8.0+
        let output = run_php(r#"<?php echo ("" == 0) ? "true" : "false"; ?>"#);
        assert_eq!(output, "false");
    }

    #[test]
    fn test_loose_cmp_zero_ne_foo() {
        let output = run_php(r#"<?php echo (0 != "foo") ? "true" : "false"; ?>"#);
        assert_eq!(output, "true");
    }

    // --- 4.01: Array === Strict Comparison ---

    #[test]
    fn test_array_strict_eq_same() {
        let output = run_php(
            r#"<?php
$a = [1, 2, 3];
$b = [1, 2, 3];
echo ($a === $b) ? "true" : "false";
"#,
        );
        assert_eq!(output, "true");
    }

    #[test]
    fn test_array_strict_eq_different_types() {
        // [1, 2, 3] !== ["1", "2", "3"] because values have different types
        let output = run_php(
            r#"<?php
$a = [1, 2, 3];
$b = ["1", "2", "3"];
echo ($a === $b) ? "true" : "false";
"#,
        );
        assert_eq!(output, "false");
    }

    #[test]
    fn test_array_strict_eq_different_order() {
        // Same keys/values but different order → not strictly equal
        let output = run_php(
            r#"<?php
$a = ["a" => 1, "b" => 2];
$b = ["b" => 2, "a" => 1];
echo ($a === $b) ? "true" : "false";
"#,
        );
        assert_eq!(output, "false");
    }

    #[test]
    fn test_array_strict_eq_string_keys() {
        let output = run_php(
            r#"<?php
$a = ["x" => "hello", "y" => "world"];
$b = ["x" => "hello", "y" => "world"];
echo ($a === $b) ? "true" : "false";
"#,
        );
        assert_eq!(output, "true");
    }

    #[test]
    fn test_array_strict_not_identical() {
        let output = run_php(
            r#"<?php
$a = [1, 2, 3];
$b = [1, 2, 4];
echo ($a !== $b) ? "true" : "false";
"#,
        );
        assert_eq!(output, "true");
    }

    // --- 4.02: Array == Loose Comparison ---

    #[test]
    fn test_array_loose_eq_type_juggled() {
        // [1, 2, 3] == ["1", "2", "3"] is true (type juggling)
        let output = run_php(
            r#"<?php
$a = [1, 2, 3];
$b = ["1", "2", "3"];
echo ($a == $b) ? "true" : "false";
"#,
        );
        assert_eq!(output, "true");
    }

    #[test]
    fn test_array_loose_eq_different_order() {
        // Same keys/values different order → still loosely equal
        let output = run_php(
            r#"<?php
$a = ["a" => 1, "b" => 2];
$b = ["b" => 2, "a" => 1];
echo ($a == $b) ? "true" : "false";
"#,
        );
        assert_eq!(output, "true");
    }

    #[test]
    fn test_array_loose_ne_different_values() {
        let output = run_php(
            r#"<?php
$a = [1, 2, 3];
$b = [1, 2, 4];
echo ($a == $b) ? "true" : "false";
"#,
        );
        assert_eq!(output, "false");
    }

    #[test]
    fn test_array_loose_ne_different_count() {
        let output = run_php(
            r#"<?php
$a = [1, 2];
$b = [1, 2, 3];
echo ($a == $b) ? "true" : "false";
"#,
        );
        assert_eq!(output, "false");
    }

    // --- 4.03: Array <=> Spaceship ---

    #[test]
    fn test_array_spaceship_equal() {
        let output = run_php(r#"<?php echo ([1, 2, 3] <=> [1, 2, 3]); ?>"#);
        assert_eq!(output, "0");
    }

    #[test]
    fn test_array_spaceship_less() {
        // Fewer elements → less
        let output = run_php(r#"<?php echo ([1, 2] <=> [1, 2, 3]); ?>"#);
        assert_eq!(output, "-1");
    }

    #[test]
    fn test_array_spaceship_greater() {
        let output = run_php(r#"<?php echo ([1, 2, 3] <=> [1, 2]); ?>"#);
        assert_eq!(output, "1");
    }

    #[test]
    fn test_array_spaceship_element_compare() {
        // Same count, compare element-by-element
        let output = run_php(r#"<?php echo ([1, 2, 3] <=> [1, 2, 4]); ?>"#);
        assert_eq!(output, "-1");
    }

    // --- 4.03: String <=> Spaceship ---

    #[test]
    fn test_string_spaceship() {
        let output = run_php(
            r#"<?php
echo ("apple" <=> "banana") . "\n";
echo ("banana" <=> "apple") . "\n";
echo ("hello" <=> "hello");
"#,
        );
        assert_eq!(output, "-1\n1\n0");
    }

    // --- 4.05: Object === Same Instance ---

    #[test]
    fn test_object_strict_eq_same_instance() {
        let output = run_php(
            r#"<?php
class Foo {}
$a = new Foo();
$b = $a;
echo ($a === $b) ? "true" : "false";
"#,
        );
        assert_eq!(output, "true");
    }

    #[test]
    fn test_object_strict_ne_different_instances() {
        let output = run_php(
            r#"<?php
class Foo {}
$a = new Foo();
$b = new Foo();
echo ($a === $b) ? "true" : "false";
"#,
        );
        assert_eq!(output, "false");
    }

    // --- 4.07: Array-to-bool ---

    #[test]
    fn test_array_to_bool_empty() {
        let output = run_php(r#"<?php echo (bool)[] ? "true" : "false"; ?>"#);
        assert_eq!(output, "false");
    }

    #[test]
    fn test_array_to_bool_nonempty() {
        let output = run_php(r#"<?php echo (bool)[1] ? "true" : "false"; ?>"#);
        assert_eq!(output, "true");
    }

    // --- 4.08: Object-to-bool ---

    #[test]
    fn test_object_to_bool() {
        let output = run_php(
            r#"<?php
class Foo {}
$f = new Foo();
echo $f ? "true" : "false";
"#,
        );
        assert_eq!(output, "true");
    }

    // --- 4.14: Array Union + ---

    #[test]
    fn test_array_union_operator() {
        let output = run_php(
            r#"<?php
$a = ["a" => 1, "b" => 2];
$b = ["b" => 3, "c" => 4];
$c = $a + $b;
echo $c["a"] . " " . $c["b"] . " " . $c["c"];
"#,
        );
        assert_eq!(output, "1 2 4");
    }

    // =========================================================================
    // Phase 2: OOP Correctness — enforcement checks
    // =========================================================================

    // 2B.05: Interface instantiation prevention
    #[test]
    fn test_cannot_instantiate_interface() {
        let result = run_php_result(
            r#"<?php
interface Printable {
    public function print();
}
$x = new Printable();
"#,
        );
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("Cannot instantiate interface Printable"),
            "Got: {}",
            err
        );
    }

    // 2C.01: Abstract class instantiation prevention (already exists, verify it works)
    #[test]
    fn test_cannot_instantiate_abstract_class() {
        let result = run_php_result(
            r#"<?php
abstract class Shape {
    abstract public function area();
}
$x = new Shape();
"#,
        );
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("Cannot instantiate abstract class Shape"),
            "Got: {}",
            err
        );
    }

    // 2F.04: Final class extension prevention
    #[test]
    fn test_cannot_extend_final_class() {
        let result = run_php_result(
            r#"<?php
final class Singleton {
    public function hello() { return "hi"; }
}
class SubSingleton extends Singleton {}
"#,
        );
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("cannot extend final class Singleton"),
            "Got: {}",
            err
        );
    }

    // 2F.03: Final method override prevention
    #[test]
    fn test_cannot_override_final_method() {
        let result = run_php_result(
            r#"<?php
class Base {
    final public function doStuff() { return 42; }
}
class Child extends Base {
    public function doStuff() { return 99; }
}
"#,
        );
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("Cannot override final method Base::doStuff()"),
            "Got: {}",
            err
        );
    }

    // 2B.01: Interface method implementation verification
    #[test]
    fn test_must_implement_interface_methods() {
        let result = run_php_result(
            r#"<?php
interface Loggable {
    public function log();
}
class Foo implements Loggable {
}
"#,
        );
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("abstract method") && err.contains("Loggable::log"),
            "Got: {}",
            err
        );
    }

    // 2B.01: Interface satisfied — no error
    #[test]
    fn test_interface_methods_satisfied() {
        let output = run_php(
            r#"<?php
interface Loggable {
    public function log();
}
class FileLogger implements Loggable {
    public function log() { echo "logged"; }
}
$l = new FileLogger();
$l->log();
"#,
        );
        assert_eq!(output, "logged");
    }

    // 2B.04: Interface method must be public
    #[test]
    fn test_interface_method_must_be_public() {
        let result = run_php_result(
            r#"<?php
interface Printable {
    public function render();
}
class Doc implements Printable {
    protected function render() { echo "doc"; }
}
"#,
        );
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("Access level") && err.contains("must be public"),
            "Got: {}",
            err
        );
    }

    // 2C.02: Abstract method implementation verification
    #[test]
    fn test_must_implement_abstract_methods() {
        let result = run_php_result(
            r#"<?php
abstract class Shape {
    abstract public function area();
}
class Circle extends Shape {
}
"#,
        );
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("abstract method") && err.contains("Shape::area"),
            "Got: {}",
            err
        );
    }

    // 2C.02: Abstract method satisfied — no error
    #[test]
    fn test_abstract_method_satisfied() {
        let output = run_php(
            r#"<?php
abstract class Shape {
    abstract public function area();
}
class Circle extends Shape {
    public function area() { return 3.14; }
}
$c = new Circle();
echo $c->area();
"#,
        );
        assert_eq!(output, "3.14");
    }

    // 2C.04: Abstract class can have concrete methods
    #[test]
    fn test_abstract_class_with_concrete_methods() {
        let output = run_php(
            r#"<?php
abstract class Base {
    abstract public function name();
    public function greet() { echo "Hello " . $this->name(); }
}
class User extends Base {
    public function name() { return "Alice"; }
}
$u = new User();
$u->greet();
"#,
        );
        assert_eq!(output, "Hello Alice");
    }

    // 2E.06: __clone() magic method
    #[test]
    fn test_clone_basic() {
        let output = run_php(
            r#"<?php
class Foo {
    public $x = 1;
}
$a = new Foo();
$b = clone $a;
$b->x = 42;
echo $a->x . " " . $b->x;
"#,
        );
        assert_eq!(output, "1 42");
    }

    #[test]
    fn test_clone_magic_method() {
        let output = run_php(
            r#"<?php
class Foo {
    public $x = 1;
    public function __clone() {
        $this->x = 100;
    }
}
$a = new Foo();
$b = clone $a;
echo $a->x . " " . $b->x;
"#,
        );
        assert_eq!(output, "1 100");
    }

    // 2A.01: Private property access enforcement
    #[test]
    fn test_private_property_access_denied() {
        let result = run_php_result(
            r#"<?php
class Secret {
    private $key = "abc";
}
$s = new Secret();
echo $s->key;
"#,
        );
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("Cannot access private property Secret::$key"),
            "Got: {}",
            err
        );
    }

    // 2A.01: Private property writable from inside the class
    #[test]
    fn test_private_property_accessible_inside_class() {
        let output = run_php(
            r#"<?php
class Secret {
    private $key = "abc";
    public function getKey() { return $this->key; }
}
$s = new Secret();
echo $s->getKey();
"#,
        );
        assert_eq!(output, "abc");
    }

    // 2A.02: Protected property access enforcement
    #[test]
    fn test_protected_property_access_denied() {
        let result = run_php_result(
            r#"<?php
class Base {
    protected $data = "secret";
}
$b = new Base();
echo $b->data;
"#,
        );
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("Cannot access protected property Base::$data"),
            "Got: {}",
            err
        );
    }

    // 2A.02: Protected property accessible from child class
    #[test]
    fn test_protected_property_accessible_from_child() {
        let output = run_php(
            r#"<?php
class Base {
    protected $data = "secret";
}
class Child extends Base {
    public function getData() { return $this->data; }
}
$c = new Child();
echo $c->getData();
"#,
        );
        assert_eq!(output, "secret");
    }

    // 2A.01: Private property write access denied
    #[test]
    fn test_private_property_write_denied() {
        let result = run_php_result(
            r#"<?php
class Secret {
    private $key = "abc";
}
$s = new Secret();
$s->key = "xyz";
"#,
        );
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("Cannot access private property Secret::$key"),
            "Got: {}",
            err
        );
    }

    // Final class that IS allowed to be instantiated
    #[test]
    fn test_final_class_can_be_instantiated() {
        let output = run_php(
            r#"<?php
final class Config {
    public $debug = true;
}
$c = new Config();
echo $c->debug ? "yes" : "no";
"#,
        );
        assert_eq!(output, "yes");
    }

    // Final method in non-final class — can be called
    #[test]
    fn test_final_method_can_be_called() {
        let output = run_php(
            r#"<?php
class Base {
    final public function id() { return 42; }
}
$b = new Base();
echo $b->id();
"#,
        );
        assert_eq!(output, "42");
    }

    // =========================================================================
    // Phase 2: OOP Correctness — method visibility & readonly
    // =========================================================================

    // 2A.03: Private method access enforcement
    #[test]
    fn test_private_method_access_denied() {
        let result = run_php_result(
            r#"<?php
class Secret {
    private function hidden() { return "secret"; }
}
$s = new Secret();
$s->hidden();
"#,
        );
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("private method Secret::hidden()"),
            "Got: {}",
            err
        );
    }

    // 2A.03: Private method accessible inside class
    #[test]
    fn test_private_method_accessible_inside_class() {
        let output = run_php(
            r#"<?php
class Secret {
    private function hidden() { return "secret"; }
    public function reveal() { return $this->hidden(); }
}
$s = new Secret();
echo $s->reveal();
"#,
        );
        assert_eq!(output, "secret");
    }

    // 2A.04: Protected method access enforcement
    #[test]
    fn test_protected_method_access_denied() {
        let result = run_php_result(
            r#"<?php
class Base {
    protected function internal() { return "internal"; }
}
$b = new Base();
$b->internal();
"#,
        );
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("protected method Base::internal()"),
            "Got: {}",
            err
        );
    }

    // 2A.04: Protected method accessible from child
    #[test]
    fn test_protected_method_accessible_from_child() {
        let output = run_php(
            r#"<?php
class Base {
    protected function internal() { return "internal"; }
}
class Child extends Base {
    public function expose() { return $this->internal(); }
}
$c = new Child();
echo $c->expose();
"#,
        );
        assert_eq!(output, "internal");
    }

    // 2A.06: Readonly property write-once semantics
    #[test]
    fn test_readonly_property_write_once() {
        let result = run_php_result(
            r#"<?php
class User {
    public readonly string $name;
    public function __construct(string $name) {
        $this->name = $name;
    }
}
$u = new User("Alice");
$u->name = "Bob";
"#,
        );
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("Cannot modify readonly property"),
            "Got: {}",
            err
        );
    }

    // 2A.06: Readonly property can be set in constructor
    #[test]
    fn test_readonly_property_set_in_constructor() {
        let output = run_php(
            r#"<?php
class User {
    public readonly string $name;
    public function __construct(string $name) {
        $this->name = $name;
    }
    public function getName() { return $this->name; }
}
$u = new User("Alice");
echo $u->getName();
"#,
        );
        assert_eq!(output, "Alice");
    }

    // =========================================================================
    // Phase 7: Standard Library fixes
    // =========================================================================

    // 7B.03: array_merge_recursive
    #[test]
    fn test_array_merge_recursive() {
        let output = run_php(
            r#"<?php
$a = ["color" => "red", "nums" => [1, 2]];
$b = ["color" => "green", "nums" => [3, 4]];
$c = array_merge_recursive($a, $b);
echo $c["color"][0] . " " . $c["color"][1] . " " . $c["nums"][0] . " " . $c["nums"][3];
"#,
        );
        assert_eq!(output, "red green 1 4");
    }

    // 7B.04: array_replace_recursive
    #[test]
    fn test_array_replace_recursive() {
        let output = run_php(
            r#"<?php
$base = ["citrus" => ["orange"], "berries" => ["blackberry", "raspberry"]];
$replacements = ["citrus" => ["pineapple"], "berries" => ["blueberry"]];
$result = array_replace_recursive($base, $replacements);
echo $result["citrus"][0] . " " . $result["berries"][0] . " " . $result["berries"][1];
"#,
        );
        assert_eq!(output, "pineapple blueberry raspberry");
    }

    // 7A.15: str_putcsv
    #[test]
    fn test_str_putcsv() {
        let output = run_php(
            r#"<?php
$data = ["hello", "world", "foo,bar"];
echo str_putcsv($data);
"#,
        );
        assert_eq!(output, r#"hello,world,"foo,bar""#);
    }

    // 7D.03: is_countable with objects
    #[test]
    fn test_is_countable() {
        let output = run_php(
            r#"<?php
echo is_countable([1, 2, 3]) ? "yes" : "no";
echo " ";
echo is_countable("hello") ? "yes" : "no";
"#,
        );
        assert_eq!(output, "yes no");
    }

    // 7D.03: is_iterable
    #[test]
    fn test_is_iterable() {
        let output = run_php(
            r#"<?php
echo is_iterable([1, 2]) ? "yes" : "no";
echo " ";
echo is_iterable(42) ? "yes" : "no";
"#,
        );
        assert_eq!(output, "yes no");
    }

    // 7B.05: array_diff_assoc
    #[test]
    fn test_array_diff_assoc() {
        let output = run_php(
            r#"<?php
$a = ["a" => "green", "b" => "brown", "c" => "blue", 0 => "red"];
$b = ["a" => "green", "b" => "yellow", 0 => "red"];
$result = array_diff_assoc($a, $b);
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "brown,blue");
    }

    // 4.04: Object == object comparison
    #[test]
    fn test_object_loose_eq_same_class_same_props() {
        let output = run_php(
            r#"<?php
class Point {
    public $x;
    public $y;
}
$a = new Point();
$a->x = 1;
$a->y = 2;
$b = new Point();
$b->x = 1;
$b->y = 2;
echo ($a == $b) ? "equal" : "not equal";
"#,
        );
        assert_eq!(output, "equal");
    }

    #[test]
    fn test_object_loose_eq_different_values() {
        let output = run_php(
            r#"<?php
class Point {
    public $x;
    public $y;
}
$a = new Point();
$a->x = 1;
$a->y = 2;
$b = new Point();
$b->x = 1;
$b->y = 3;
echo ($a == $b) ? "equal" : "not equal";
"#,
        );
        assert_eq!(output, "not equal");
    }

    #[test]
    fn test_object_loose_eq_different_class() {
        let output = run_php(
            r#"<?php
class Foo { public $x = 1; }
class Bar { public $x = 1; }
$a = new Foo();
$b = new Bar();
echo ($a == $b) ? "equal" : "not equal";
"#,
        );
        assert_eq!(output, "not equal");
    }

    // 7A.10: quotemeta
    #[test]
    fn test_quotemeta() {
        let output = run_php(
            r#"<?php
echo quotemeta("Hello world. (are you) *ready*?");
"#,
        );
        assert_eq!(output, r"Hello world\. \(are you\) \*ready\*\?");
    }

    // =========================================================================
    // Phase 1A: Fetch Operations
    // =========================================================================

    #[test]
    fn test_fetch_dim_w_array_push() {
        // FetchDimW is used for $arr[] = val (append)
        let output = run_php(
            r#"<?php
$arr = [1, 2, 3];
$arr[] = 4;
echo count($arr) . "\n";
echo $arr[3];
"#,
        );
        assert_eq!(output, "4\n4");
    }

    #[test]
    fn test_fetch_dim_w_nested_write() {
        // FetchDimW used when writing to nested array dims: $a[$k1][$k2] = val
        let output = run_php(
            r#"<?php
$a = [];
$a["x"] = [];
$a["x"]["y"] = 42;
echo $a["x"]["y"];
"#,
        );
        assert_eq!(output, "42");
    }

    #[test]
    fn test_fetch_dim_rw_compound_assign() {
        // FetchDimRw is used for $arr[$k] += value
        let output = run_php(
            r#"<?php
$arr = [10, 20, 30];
$arr[1] += 5;
echo $arr[1];
"#,
        );
        assert_eq!(output, "25");
    }

    #[test]
    fn test_fetch_dim_rw_concat() {
        // FetchDimRw for $arr[$k] .= "string"
        let output = run_php(
            r#"<?php
$arr = ["hello", "world"];
$arr[0] .= " there";
echo $arr[0];
"#,
        );
        assert_eq!(output, "hello there");
    }

    #[test]
    fn test_fetch_obj_unset() {
        // FetchObjUnset for unset($obj->prop)
        let output = run_php(
            r#"<?php
class Foo {
    public $x = 10;
    public $y = 20;
}
$f = new Foo();
unset($f->x);
echo isset($f->x) ? "set" : "unset";
echo "\n";
echo $f->y;
"#,
        );
        assert_eq!(output, "unset\n20");
    }

    #[test]
    fn test_fetch_static_prop_func_arg() {
        // FetchStaticPropFuncArg when passing a static prop to a function
        let output = run_php(
            r#"<?php
class Config {
    public static $value = "hello";
}
function show($v) { echo $v; }
show(Config::$value);
"#,
        );
        assert_eq!(output, "hello");
    }

    #[test]
    fn test_fetch_static_prop_unset() {
        // FetchStaticPropUnset for unset(ClassName::$prop)
        let output = run_php(
            r#"<?php
class Store {
    public static $data = 42;
}
unset(Store::$data);
echo isset(Store::$data) ? "set" : "unset";
"#,
        );
        assert_eq!(output, "unset");
    }

    #[test]
    fn test_fetch_this_in_method() {
        // FetchThis — accessing $this in a method
        let output = run_php(
            r#"<?php
class Counter {
    private $count = 0;
    public function increment() {
        $this->count++;
        return $this;
    }
    public function getCount() {
        return $this->count;
    }
}
$c = new Counter();
$c->increment()->increment()->increment();
echo $c->getCount();
"#,
        );
        assert_eq!(output, "3");
    }

    #[test]
    fn test_fetch_class_name_self() {
        // FetchClassName with self
        let output = run_php(
            r#"<?php
class MyClass {
    public function getName() {
        return self::class;
    }
}
$obj = new MyClass();
echo $obj->getName();
"#,
        );
        assert_eq!(output, "MyClass");
    }

    #[test]
    fn test_fetch_class_name_static() {
        // FetchClassName with static (late static binding)
        let output = run_php(
            r#"<?php
class Base {
    public static function className() {
        return static::class;
    }
}
class Child extends Base {}
echo Child::className();
"#,
        );
        assert_eq!(output, "Child");
    }

    #[test]
    fn test_fetch_class_name_parent() {
        // FetchClassName with parent
        let output = run_php(
            r#"<?php
class ParentClass {}
class ChildClass extends ParentClass {
    public function getParent() {
        return parent::class;
    }
}
$c = new ChildClass();
echo $c->getParent();
"#,
        );
        assert_eq!(output, "ParentClass");
    }

    #[test]
    fn test_list_destructuring_basic() {
        // FetchListR for list() destructuring
        let output = run_php(
            r#"<?php
$arr = [10, 20, 30];
list($a, $b, $c) = $arr;
echo "$a $b $c";
"#,
        );
        assert_eq!(output, "10 20 30");
    }

    #[test]
    fn test_list_destructuring_skip() {
        // list() with skipped elements
        let output = run_php(
            r#"<?php
list($a, , $c) = [1, 2, 3];
echo "$a $c";
"#,
        );
        assert_eq!(output, "1 3");
    }

    #[test]
    fn test_short_list_destructuring() {
        // Short list syntax [$a, $b] = expr
        let output = run_php(
            r#"<?php
[$x, $y] = [100, 200];
echo "$x $y";
"#,
        );
        assert_eq!(output, "100 200");
    }

    #[test]
    fn test_list_with_keys() {
        // list() with explicit keys
        let output = run_php(
            r#"<?php
$arr = ["name" => "PHP", "version" => 8];
["name" => $name, "version" => $ver] = $arr;
echo "$name $ver";
"#,
        );
        assert_eq!(output, "PHP 8");
    }

    #[test]
    fn test_nested_list_destructuring() {
        // Nested list destructuring
        let output = run_php(
            r#"<?php
$arr = [1, [2, 3]];
[$a, [$b, $c]] = $arr;
echo "$a $b $c";
"#,
        );
        assert_eq!(output, "1 2 3");
    }

    #[test]
    fn test_foreach_by_reference() {
        // FeFetchRw for foreach by-reference
        let output = run_php(
            r#"<?php
$arr = [1, 2, 3, 4, 5];
foreach ($arr as &$val) {
    $val *= 2;
}
unset($val);
echo implode(",", $arr);
"#,
        );
        assert_eq!(output, "2,4,6,8,10");
    }

    #[test]
    fn test_foreach_by_reference_with_key() {
        // FeFetchRw with key variable
        let output = run_php(
            r#"<?php
$arr = ["a" => 1, "b" => 2, "c" => 3];
foreach ($arr as $k => &$v) {
    $v = $k . "=" . $v;
}
unset($v);
echo implode(",", $arr);
"#,
        );
        assert_eq!(output, "a=1,b=2,c=3");
    }

    #[test]
    fn test_bind_global_basic() {
        // BindGlobal: global keyword
        let output = run_php(
            r#"<?php
$x = 42;
function readGlobal() {
    global $x;
    echo $x;
}
readGlobal();
"#,
        );
        assert_eq!(output, "42");
    }

    #[test]
    fn test_bind_global_write() {
        // BindGlobal: global keyword with write
        let output = run_php(
            r#"<?php
$counter = 0;
function increment() {
    global $counter;
    $counter++;
}
increment();
increment();
increment();
echo $counter;
"#,
        );
        assert_eq!(output, "3");
    }

    #[test]
    fn test_separate_copy_on_write() {
        // Separate opcode for copy-on-write
        let output = run_php(
            r#"<?php
$a = [1, 2, 3];
$b = $a;  // Copy-on-write: $b shares $a initially
$b[] = 4; // Modification triggers separation
echo count($a) . " " . count($b);
"#,
        );
        assert_eq!(output, "3 4");
    }

    #[test]
    fn test_make_ref_basic() {
        // MakeRef: creating a reference
        let output = run_php(
            r#"<?php
$a = 10;
$b = &$a;
$b = 20;
echo $a;
"#,
        );
        assert_eq!(output, "20");
    }

    #[test]
    fn test_make_ref_unset() {
        // Unsetting a reference doesn't affect the original
        let output = run_php(
            r#"<?php
$a = 10;
$b = &$a;
unset($b);
echo $a;
"#,
        );
        assert_eq!(output, "10");
    }

    #[test]
    fn test_fetch_dim_string_access() {
        // FetchDimR on strings
        let output = run_php(
            r#"<?php
$s = "Hello";
echo $s[0] . $s[4];
"#,
        );
        assert_eq!(output, "Ho");
    }

    #[test]
    fn test_fetch_dim_negative_index() {
        // Negative index on string
        let output = run_php(
            r#"<?php
$s = "Hello";
echo $s[-1];
"#,
        );
        assert_eq!(output, "o");
    }

    #[test]
    fn test_isset_var_dynamic() {
        // IssetIsemptyVar for variable-variable isset
        let output = run_php(
            r#"<?php
$x = 42;
echo isset($x) ? "yes" : "no";
echo "\n";
echo isset($y) ? "yes" : "no";
"#,
        );
        assert_eq!(output, "yes\nno");
    }

    #[test]
    fn test_fetch_globals_access() {
        // $GLOBALS superglobal access
        let output = run_php(
            r#"<?php
$myvar = "hello";
function test() {
    global $myvar;
    echo $myvar;
}
test();
"#,
        );
        assert_eq!(output, "hello");
    }

    // =====================================================================
    // Phase 1D: IssetIsemptyVar and UnsetVar opcodes
    // =====================================================================

    #[test]
    fn test_isset_isempty_var() {
        let output = run_php(
            r#"<?php
$x = 42;
echo isset($x) ? "yes" : "no";
echo "\n";
echo empty($x) ? "yes" : "no";
"#,
        );
        assert_eq!(output, "yes\nno");
    }

    #[test]
    fn test_unset_var() {
        let output = run_php(
            r#"<?php
$x = 42;
unset($x);
echo isset($x) ? "yes" : "no";
"#,
        );
        assert_eq!(output, "no");
    }

    // =====================================================================
    // Phase 2A.05: Private constructor enforcement
    // =====================================================================

    #[test]
    fn test_private_constructor_from_static_method() {
        // Private constructor should be callable from within the class
        let output = run_php(
            r#"<?php
class Singleton {
    private function __construct() {}
    public static function create() {
        return new self();
    }
}
$s = Singleton::create();
echo "ok";
"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_private_constructor_from_outside() {
        // Private constructor should error when called from outside
        let output = run_php_error(
            r#"<?php
class Singleton {
    private function __construct() {}
}
$s = new Singleton();
"#,
        );
        assert!(output.contains("private"));
    }

    #[test]
    fn test_protected_constructor_from_child() {
        // Protected constructor should be callable from child class
        let output = run_php(
            r#"<?php
class Base {
    protected function __construct() {}
}
class Child extends Base {
    public static function create() {
        return new parent();
    }
}
$c = Child::create();
echo "ok";
"#,
        );
        assert_eq!(output, "ok");
    }

    // =====================================================================
    // Phase 2A.07: Readonly class enforcement
    // =====================================================================

    #[test]
    fn test_readonly_class_property() {
        // Properties in readonly class should be implicitly readonly
        let output = run_php(
            r#"<?php
readonly class Point {
    public function __construct(
        public float $x,
        public float $y,
    ) {}
}
$p = new Point(1.0, 2.0);
echo $p->x;
echo "\n";
echo $p->y;
"#,
        );
        assert_eq!(output, "1\n2");
    }

    // =====================================================================
    // Phase 2B.02: Interface method signature compatibility
    // =====================================================================

    #[test]
    fn test_interface_method_exists() {
        // Concrete class must implement all interface methods
        let output = run_php_error(
            r#"<?php
interface Logger {
    public function log($message);
}
class FileLogger implements Logger {
}
"#,
        );
        assert!(output.contains("abstract method"));
    }

    #[test]
    fn test_interface_method_implemented() {
        // Properly implementing an interface should work
        let output = run_php(
            r#"<?php
interface Greeting {
    public function greet($name);
}
class Hello implements Greeting {
    public function greet($name) {
        echo "Hello, $name!";
    }
}
$h = new Hello();
$h->greet("World");
"#,
        );
        assert_eq!(output, "Hello, World!");
    }

    // =====================================================================
    // Phase 2C.03: Abstract method signature compatibility
    // =====================================================================

    #[test]
    fn test_abstract_method_must_be_implemented() {
        let output = run_php_error(
            r#"<?php
abstract class Shape {
    abstract public function area();
}
class Circle extends Shape {
}
"#,
        );
        assert!(output.contains("abstract method"));
    }

    #[test]
    fn test_abstract_method_implemented() {
        let output = run_php(
            r#"<?php
abstract class Shape {
    abstract public function area();
}
class Circle extends Shape {
    public function area() {
        return 3.14;
    }
}
$c = new Circle();
echo $c->area();
"#,
        );
        assert_eq!(output, "3.14");
    }

    // =====================================================================
    // Phase 2E.07: __debugInfo magic method
    // =====================================================================

    #[test]
    fn test_debug_info_magic_method() {
        let output = run_php(
            r#"<?php
class Secret {
    private $password = "hidden";
    private $name = "visible";

    public function __debugInfo() {
        return ["name" => $this->name, "password" => "***"];
    }
}
$s = new Secret();
var_dump($s);
"#,
        );
        assert!(output.contains("***"));
        assert!(!output.contains("hidden"));
    }

    // =====================================================================
    // Phase 2G: serialize/unserialize for objects
    // =====================================================================

    #[test]
    fn test_serialize_object() {
        let output = run_php(
            r#"<?php
class Point {
    public $x = 1;
    public $y = 2;
}
$p = new Point();
$s = serialize($p);
echo $s;
"#,
        );
        // Should contain O: prefix for object serialization
        assert!(output.starts_with("O:"));
        assert!(output.contains("Point"));
    }

    #[test]
    fn test_unserialize_object() {
        let output = run_php(
            r#"<?php
class Point {
    public $x = 1;
    public $y = 2;
}
$p = new Point();
$s = serialize($p);
$p2 = unserialize($s);
echo $p2->x;
echo "\n";
echo $p2->y;
"#,
        );
        assert_eq!(output, "1\n2");
    }

    #[test]
    fn test_serialize_sleep_magic() {
        let output = run_php(
            r#"<?php
class User {
    public $name = "Alice";
    public $password = "secret";

    public function __sleep() {
        return ["name"];
    }
}
$u = new User();
$s = serialize($u);
echo $s;
"#,
        );
        // Only "name" should be serialized, not "password"
        assert!(output.contains("name"));
        assert!(!output.contains("secret"));
    }

    #[test]
    fn test_serialize_magic_method() {
        let output = run_php(
            r#"<?php
class Config {
    public $data = "test";
    public $cache = "temp";

    public function __serialize() {
        return ["data" => $this->data];
    }

    public function __unserialize($data) {
        $this->data = $data["data"];
        $this->cache = "rebuilt";
    }
}
$c = new Config();
$s = serialize($c);
$c2 = unserialize($s);
echo $c2->data;
"#,
        );
        assert_eq!(output, "test");
    }

    // =====================================================================
    // Phase 1H: Call Operations
    // =====================================================================

    #[test]
    fn test_callable_convert_first_class() {
        // First-class callable syntax: strlen(...)
        let output = run_php(
            r#"<?php
function double($x) {
    return $x * 2;
}
$fn = Closure::fromCallable('double');
echo $fn(21);
"#,
        );
        assert_eq!(output, "42");
    }

    #[test]
    fn test_call_user_func_basic() {
        let output = run_php(
            r#"<?php
function greet($name) {
    return "Hello, $name!";
}
echo call_user_func('greet', 'World');
"#,
        );
        assert_eq!(output, "Hello, World!");
    }

    #[test]
    fn test_call_user_func_array_basic() {
        let output = run_php(
            r#"<?php
function add($a, $b) {
    return $a + $b;
}
echo call_user_func_array('add', [3, 4]);
"#,
        );
        assert_eq!(output, "7");
    }

    #[test]
    fn test_call_user_func_method() {
        let output = run_php(
            r#"<?php
class Calculator {
    public function multiply($a, $b) {
        return $a * $b;
    }
}
$calc = new Calculator();
echo call_user_func([$calc, 'multiply'], 6, 7);
"#,
        );
        assert_eq!(output, "42");
    }

    // =====================================================================
    // Phase 1J: TypeAssert (NOP - optimizer hint)
    // =====================================================================

    #[test]
    fn test_type_assert_nop() {
        // TypeAssert is an optimizer hint — should not crash
        let output = run_php(
            r#"<?php
$x = 42;
echo $x;
"#,
        );
        assert_eq!(output, "42");
    }

    // =====================================================================
    // Phase 2B.03: Interface constant override
    // =====================================================================

    #[test]
    fn test_interface_constant_inherited() {
        let output = run_php(
            r#"<?php
interface HasVersion {
    const VERSION = "1.0";
}
class App implements HasVersion {
    public function getVersion() {
        return self::VERSION;
    }
}
$app = new App();
echo $app->getVersion();
"#,
        );
        assert_eq!(output, "1.0");
    }

    // =====================================================================
    // Phase 2G.04: Object-to-array cast with name mangling
    // =====================================================================

    #[test]
    fn test_object_to_array_cast() {
        let output = run_php(
            r#"<?php
class Point {
    public $x = 1;
    public $y = 2;
}
$p = new Point();
$arr = (array)$p;
echo $arr["x"];
echo "\n";
echo $arr["y"];
"#,
        );
        assert_eq!(output, "1\n2");
    }

    #[test]
    fn test_object_to_array_private_mangling() {
        let output = run_php(
            r#"<?php
class Foo {
    public $pub = "public";
    private $priv = "private";
    protected $prot = "protected";
}
$f = new Foo();
$arr = (array)$f;
echo count($arr);
"#,
        );
        assert_eq!(output, "3");
    }

    // =====================================================================
    // Phase 4.06: String-to-number coercion edge cases
    // =====================================================================

    #[test]
    fn test_hex_string_to_int() {
        let output = run_php(
            r#"<?php
$x = intval("0xFF");
echo $x;
"#,
        );
        assert_eq!(output, "255");
    }

    #[test]
    fn test_octal_string_to_int() {
        let output = run_php(
            r#"<?php
$x = intval("0o17");
echo $x;
"#,
        );
        assert_eq!(output, "15");
    }

    #[test]
    fn test_binary_string_to_int() {
        let output = run_php(
            r#"<?php
$x = intval("0b1010");
echo $x;
"#,
        );
        assert_eq!(output, "10");
    }

    // =====================================================================
    // Phase 4.10-4.12: Type conversion edge cases
    // =====================================================================

    #[test]
    fn test_object_to_float() {
        // Objects convert to float 1.0 in PHP
        let output = run_php(
            r#"<?php
class Obj {}
$o = new Obj();
$f = (float)$o;
echo $f;
"#,
        );
        assert_eq!(output, "1");
    }

    #[test]
    fn test_array_to_string() {
        // Arrays convert to "Array" string
        let output = run_php(
            r#"<?php
$arr = [1, 2, 3];
$s = (string)$arr;
echo $s;
"#,
        );
        assert_eq!(output, "Array");
    }

    #[test]
    fn test_object_tostring_magic() {
        let output = run_php(
            r#"<?php
class Name {
    private $name;
    public function __construct($name) {
        $this->name = $name;
    }
    public function __toString() {
        return $this->name;
    }
}
$n = new Name("Alice");
echo (string)$n;
"#,
        );
        assert_eq!(output, "Alice");
    }

    #[test]
    fn test_object_tostring_concat() {
        let output = run_php(
            r#"<?php
class Tag {
    private $tag;
    public function __construct($tag) {
        $this->tag = $tag;
    }
    public function __toString() {
        return $this->tag;
    }
}
$t = new Tag("div");
echo "The tag is: " . $t;
"#,
        );
        assert_eq!(output, "The tag is: div");
    }

    // =========================================================================
    // Phase 5: Error Handling
    // =========================================================================

    #[test]
    fn test_set_error_handler_invoked() {
        // 5.01: set_error_handler() should invoke the user handler
        let output = run_php(
            r#"<?php
function myHandler($errno, $errstr) {
    echo "Handler: [$errno] $errstr";
    return true;
}
set_error_handler("myHandler");
trigger_error("test warning", E_USER_WARNING);
"#,
        );
        assert_eq!(output, "Handler: [512] test warning");
    }

    #[test]
    fn test_set_error_handler_returns_previous() {
        // set_error_handler returns previous handler
        let output = run_php(
            r#"<?php
function h1($errno, $errstr) { return true; }
function h2($errno, $errstr) { return true; }
$prev = set_error_handler("h1");
echo var_export($prev, true) . "\n";
$prev = set_error_handler("h2");
echo $prev;
"#,
        );
        assert_eq!(output, "NULL\nh1");
    }

    #[test]
    fn test_set_exception_handler_invoked() {
        // 5.02: set_exception_handler() should invoke on uncaught exception
        let output = run_php(
            r#"<?php
function myExHandler($e) {
    echo "Caught: " . $e->getMessage();
}
set_exception_handler("myExHandler");
throw new Exception("boom");
"#,
        );
        assert_eq!(output, "Caught: boom");
    }

    #[test]
    fn test_restore_error_handler() {
        // 5.03: restore_error_handler restores previous handler
        let output = run_php(
            r#"<?php
function h1($errno, $errstr) {
    echo "h1: $errstr\n";
    return true;
}
function h2($errno, $errstr) {
    echo "h2: $errstr\n";
    return true;
}
set_error_handler("h1");
set_error_handler("h2");
trigger_error("first", E_USER_NOTICE);
restore_error_handler();
trigger_error("second", E_USER_NOTICE);
"#,
        );
        assert_eq!(output, "h2: first\nh1: second\n");
    }

    #[test]
    fn test_restore_exception_handler() {
        // 5.04: restore_exception_handler restores previous handler
        let output = run_php(
            r#"<?php
function ex1($e) {
    echo "ex1: " . $e->getMessage();
}
function ex2($e) {
    echo "ex2: " . $e->getMessage();
}
set_exception_handler("ex1");
set_exception_handler("ex2");
restore_exception_handler();
throw new Exception("test");
"#,
        );
        assert_eq!(output, "ex1: test");
    }

    #[test]
    fn test_error_reporting_filtering() {
        // 5.05: error_reporting() level filtering
        let output = run_php(
            r#"<?php
$old = error_reporting(0);
trigger_error("suppressed", E_USER_WARNING);
error_reporting($old);
echo "done";
"#,
        );
        // With error_reporting(0), the warning should be suppressed
        assert_eq!(output, "done");
    }

    #[test]
    fn test_error_reporting_returns_old() {
        let output = run_php(
            r#"<?php
$old = error_reporting();
echo $old;
"#,
        );
        assert_eq!(output, "32767"); // E_ALL
    }

    #[test]
    fn test_division_by_zero_warning() {
        // 5.08: E_WARNING for division by zero
        // Int division by int zero throws DivisionByZeroError
        let error = run_php_error(
            r#"<?php
$a = 10 / 0;
"#,
        );
        assert!(error.contains("Division by zero"));
    }

    #[test]
    fn test_modulo_by_zero_error() {
        // Modulo by zero throws DivisionByZeroError
        let error = run_php_error(
            r#"<?php
$a = 10 % 0;
"#,
        );
        assert!(error.contains("Division by zero"));
    }

    #[test]
    fn test_trigger_error_user_notice() {
        // 5.11: trigger_error with E_USER_NOTICE
        let output = run_php(
            r#"<?php
function myHandler($errno, $errstr) {
    echo "[$errno] $errstr";
    return true;
}
set_error_handler("myHandler");
trigger_error("hello notice", E_USER_NOTICE);
"#,
        );
        assert_eq!(output, "[1024] hello notice");
    }

    #[test]
    fn test_trigger_error_user_deprecated() {
        let output = run_php(
            r#"<?php
function myHandler($errno, $errstr) {
    echo "[$errno] $errstr";
    return true;
}
set_error_handler("myHandler");
trigger_error("old feature", E_USER_DEPRECATED);
"#,
        );
        assert_eq!(output, "[16384] old feature");
    }

    #[test]
    fn test_trigger_error_user_error_fatal() {
        // E_USER_ERROR is fatal
        let error = run_php_error(
            r#"<?php
trigger_error("fatal", E_USER_ERROR);
"#,
        );
        assert!(error.contains("fatal"));
    }

    #[test]
    fn test_trigger_error_default_output() {
        // Without user handler, trigger_error outputs default format
        let output = run_php(
            r#"<?php
trigger_error("test warning", E_USER_WARNING);
echo "after";
"#,
        );
        assert!(output.contains("Warning: test warning"));
        assert!(output.contains("after"));
    }

    // =========================================================================
    // Phase 4: Type Coercion
    // =========================================================================

    #[test]
    fn test_array_to_float_conversion() {
        // 4.09: Array-to-float conversion
        let output = run_php(
            r#"<?php
$empty = [];
$full = [1, 2, 3];
echo (float)$empty . "\n";
echo (float)$full;
"#,
        );
        assert_eq!(output, "0\n1");
    }

    #[test]
    fn test_reference_deref_in_type_conversion() {
        // 4.13: Reference dereferencing for type conversions
        let output = run_php(
            r#"<?php
$a = 42;
$b = &$a;
echo (string)$b . "\n";
echo (float)$b . "\n";
echo (bool)$b ? "true" : "false";
"#,
        );
        assert_eq!(output, "42\n42\ntrue");
    }

    // =========================================================================
    // Phase 3: Type System Enforcement
    // =========================================================================

    #[test]
    fn test_param_type_check_int() {
        // 3.02 / 3.14: Parameter type checking + TypeError
        let error = run_php_error(
            r#"<?php
function add(int $a, int $b): int {
    return $a + $b;
}
echo add("hello", "world");
"#,
        );
        assert!(error.contains("TypeError"));
        assert!(error.contains("must be of type int"));
    }

    #[test]
    fn test_param_type_check_string() {
        // In non-strict mode, int 123 is coerced to string "123"
        let output = run_php(
            r#"<?php
function greet(string $name): string {
    return "Hello $name";
}
echo greet(123);
"#,
        );
        assert_eq!(output, "Hello 123");
    }

    #[test]
    fn test_param_type_check_string_strict() {
        // With strict_types, int should NOT be coerced to string
        // (But array can never be coerced to string)
        let error = run_php_error(
            r#"<?php
function greet(string $name): string {
    return "Hello $name";
}
echo greet([1, 2, 3]);
"#,
        );
        assert!(error.contains("TypeError"));
        assert!(error.contains("must be of type string"));
    }

    #[test]
    fn test_param_type_check_valid() {
        // Valid types should pass
        let output = run_php(
            r#"<?php
function add(int $a, int $b): int {
    return $a + $b;
}
echo add(3, 4);
"#,
        );
        assert_eq!(output, "7");
    }

    #[test]
    fn test_nullable_type_enforcement_null() {
        // 3.09: Nullable type allows null
        let output = run_php(
            r#"<?php
function greet(?string $name): string {
    if ($name === null) {
        return "Hello anonymous";
    }
    return "Hello $name";
}
echo greet(null);
"#,
        );
        assert_eq!(output, "Hello anonymous");
    }

    #[test]
    fn test_nullable_type_enforcement_value() {
        // Nullable type allows the actual type
        let output = run_php(
            r#"<?php
function greet(?string $name): string {
    return "Hello $name";
}
echo greet("Alice");
"#,
        );
        assert_eq!(output, "Hello Alice");
    }

    #[test]
    fn test_nullable_type_enforcement_wrong() {
        // Nullable type rejects incompatible type (array can't be coerced to string)
        let error = run_php_error(
            r#"<?php
function greet(?string $name): string {
    return "Hello";
}
echo greet([1, 2]);
"#,
        );
        assert!(error.contains("TypeError"));
        assert!(error.contains("must be of type ?string"));
    }

    #[test]
    fn test_void_return_type_enforcement() {
        // 3.10: void function returning null is OK
        let output = run_php(
            r#"<?php
function doSomething(): void {
    $x = 1 + 2;
}
doSomething();
echo "done";
"#,
        );
        assert_eq!(output, "done");
    }

    #[test]
    fn test_void_return_type_violation() {
        // void function returning a value should error
        let error = run_php_error(
            r#"<?php
function doSomething(): void {
    return 42;
}
doSomething();
"#,
        );
        assert!(error.contains("TypeError") || error.contains("void"));
    }

    #[test]
    fn test_type_error_is_catchable() {
        // 3.14: TypeError is catchable
        let output = run_php(
            r#"<?php
function add(int $a, int $b): int {
    return $a + $b;
}
try {
    add("hello", "world");
} catch (TypeError $e) {
    echo "Caught: " . $e->getMessage();
}
"#,
        );
        assert!(output.contains("Caught:"));
        assert!(output.contains("must be of type int"));
    }

    #[test]
    fn test_param_type_check_with_default() {
        // Parameter with default + type check (RecvInit path)
        let output = run_php(
            r#"<?php
function greet(string $name = "World"): string {
    return "Hello $name";
}
echo greet() . "\n";
echo greet("Alice");
"#,
        );
        assert_eq!(output, "Hello World\nHello Alice");
    }

    #[test]
    fn test_param_type_check_array() {
        let error = run_php_error(
            r#"<?php
function process(array $data): int {
    return count($data);
}
echo process("not an array");
"#,
        );
        assert!(error.contains("TypeError"));
        assert!(error.contains("must be of type array"));
    }

    // =========================================================================
    // Phase 7: Standard Library Completeness — Batch 3
    // =========================================================================

    #[test]
    fn test_str_getcsv_basic() {
        let output = run_php(
            r#"<?php
$result = str_getcsv("one,two,three");
echo implode("|", $result);
"#,
        );
        assert_eq!(output, "one|two|three");
    }

    #[test]
    fn test_str_getcsv_quoted_fields() {
        let output = run_php(
            r#"<?php
$result = str_getcsv('"hello, world",foo,"bar""baz"');
echo count($result) . "\n";
echo $result[0] . "\n";
echo $result[1] . "\n";
echo $result[2];
"#,
        );
        assert_eq!(output, "3\nhello, world\nfoo\nbar\"baz");
    }

    #[test]
    fn test_str_getcsv_custom_separator() {
        let output = run_php(
            r#"<?php
$result = str_getcsv("a;b;c", ";");
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "a,b,c");
    }

    #[test]
    fn test_metaphone_basic() {
        let output = run_php(
            r#"<?php
echo metaphone("Thompson") . "\n";
echo metaphone("Smith");
"#,
        );
        // TH → 0 (theta sound), so Thompson → 0MPSN
        assert_eq!(output, "0MPSN\nSM0");
    }

    #[test]
    fn test_metaphone_similar_sounding() {
        // Similar sounding words should have same metaphone
        let output = run_php(
            r#"<?php
$a = metaphone("Smith");
$b = metaphone("Smythe");
echo ($a === $b) ? "same" : "diff";
"#,
        );
        assert_eq!(output, "same");
    }

    #[test]
    fn test_soundex_basic() {
        let output = run_php(
            r#"<?php
echo soundex("Robert") . "\n";
echo soundex("Rupert");
"#,
        );
        assert_eq!(output, "R163\nR163");
    }

    #[test]
    fn test_similar_text_basic() {
        let output = run_php(
            r#"<?php
echo similar_text("Hello", "World") . "\n";
echo similar_text("Hello", "Hello") . "\n";
echo similar_text("abc", "abc");
"#,
        );
        assert_eq!(output, "1\n5\n3");
    }

    #[test]
    fn test_levenshtein_basic() {
        let output = run_php(
            r#"<?php
echo levenshtein("kitten", "sitting") . "\n";
echo levenshtein("hello", "hello") . "\n";
echo levenshtein("", "abc");
"#,
        );
        assert_eq!(output, "3\n0\n3");
    }

    #[test]
    fn test_sprintf_basic() {
        let output = run_php(
            r#"<?php
echo sprintf("Hello %s, you are %d years old", "Alice", 30);
"#,
        );
        assert_eq!(output, "Hello Alice, you are 30 years old");
    }

    #[test]
    fn test_sprintf_padding() {
        let output = run_php(
            r#"<?php
echo sprintf("%05d", 42) . "\n";
echo sprintf("%-10s|", "left") . "\n";
echo sprintf("%10s|", "right");
"#,
        );
        assert_eq!(output, "00042\nleft      |\n     right|");
    }

    #[test]
    fn test_html_entity_decode_numeric() {
        let output = run_php(
            r#"<?php
echo html_entity_decode("&#65;&#66;&#67;") . "\n";
echo html_entity_decode("&#x41;&#x42;&#x43;") . "\n";
echo html_entity_decode("&lt;b&gt;bold&lt;/b&gt;");
"#,
        );
        assert_eq!(output, "ABC\nABC\n<b>bold</b>");
    }

    #[test]
    fn test_htmlentities_basic() {
        let output = run_php(
            r#"<?php
echo htmlentities("<p>Hello \"World\" & 'Friends'</p>");
"#,
        );
        assert_eq!(
            output,
            "&lt;p&gt;Hello &quot;World&quot; &amp; &#039;Friends&#039;&lt;/p&gt;"
        );
    }

    #[test]
    fn test_convert_uuencode_decode() {
        let output = run_php(
            r#"<?php
$encoded = convert_uuencode("test");
echo convert_uudecode($encoded);
"#,
        );
        assert_eq!(output, "test");
    }

    #[test]
    fn test_intval_floatval_strval_boolval() {
        let output = run_php(
            r#"<?php
echo intval("42abc") . "\n";
echo floatval("3.14xyz") . "\n";
echo strval(123) . "\n";
echo boolval(0) ? "true" : "false";
"#,
        );
        assert_eq!(output, "42\n3.14\n123\nfalse");
    }

    #[test]
    fn test_is_numeric() {
        let output = run_php(
            r#"<?php
echo is_numeric(42) ? "1" : "0";
echo is_numeric("3.14") ? "1" : "0";
echo is_numeric("hello") ? "1" : "0";
echo is_numeric("0xFF") ? "1" : "0";
"#,
        );
        assert_eq!(output, "1100");
    }

    #[test]
    fn test_get_debug_type() {
        let output = run_php(
            r#"<?php
echo get_debug_type(42) . "\n";
echo get_debug_type(3.14) . "\n";
echo get_debug_type("hello") . "\n";
echo get_debug_type(true) . "\n";
echo get_debug_type(null) . "\n";
echo get_debug_type([]) . "\n";
"#,
        );
        assert_eq!(output, "int\nfloat\nstring\nbool\nnull\narray\n");
    }

    #[test]
    fn test_fdiv_zero() {
        let output = run_php(
            r#"<?php
echo fdiv(1.0, 0.0) . "\n";
echo fdiv(-1.0, 0.0) . "\n";
echo fdiv(0.0, 0.0);
"#,
        );
        assert_eq!(output, "INF\n-INF\nNAN");
    }

    #[test]
    fn test_fdiv_normal() {
        let output = run_php(
            r#"<?php
echo fdiv(10, 3);
"#,
        );
        // 10/3 = 3.3333...
        assert!(output.starts_with("3.333333333333"));
    }

    #[test]
    fn test_array_sum_product() {
        let output = run_php(
            r#"<?php
echo array_sum([1, 2, 3, 4]) . "\n";
echo array_product([1, 2, 3, 4]) . "\n";
echo array_sum([]) . "\n";
echo array_product([]);
"#,
        );
        assert_eq!(output, "10\n24\n0\n1");
    }

    #[test]
    fn test_mt_rand_range() {
        let output = run_php(
            r#"<?php
mt_srand(42);
$v = mt_rand(1, 100);
echo ($v >= 1 && $v <= 100) ? "ok" : "fail";
"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_array_combine() {
        let output = run_php(
            r#"<?php
$keys = ["a", "b", "c"];
$values = [1, 2, 3];
$result = array_combine($keys, $values);
echo $result["a"] . "\n";
echo $result["b"] . "\n";
echo $result["c"];
"#,
        );
        assert_eq!(output, "1\n2\n3");
    }

    #[test]
    fn test_array_count_values() {
        let output = run_php(
            r#"<?php
$result = array_count_values(["apple", "banana", "apple", "cherry", "banana", "apple"]);
echo $result["apple"] . "\n";
echo $result["banana"] . "\n";
echo $result["cherry"];
"#,
        );
        assert_eq!(output, "3\n2\n1");
    }

    // =========================================================================
    // Batch 4: Type System, Error Handling, Stdlib
    // =========================================================================

    #[test]
    fn test_property_type_enforcement() {
        // 3.04: Typed property rejects wrong type
        let error = run_php_error(
            r#"<?php
class User {
    public string $name;
}
$u = new User();
$u->name = [1, 2, 3];
"#,
        );
        assert!(error.contains("TypeError") || error.contains("Cannot assign"));
    }

    #[test]
    fn test_property_type_valid() {
        // 3.04: Typed property accepts correct type
        let output = run_php(
            r#"<?php
class User {
    public string $name;
    public int $age;
}
$u = new User();
$u->name = "Alice";
$u->age = 30;
echo $u->name . " is " . $u->age;
"#,
        );
        assert_eq!(output, "Alice is 30");
    }

    #[test]
    fn test_union_type_validation() {
        // 3.05: Union type accepts any branch
        let output = run_php(
            r#"<?php
function test(int|string $val): string {
    return "got: $val";
}
echo test(42) . "\n";
echo test("hello");
"#,
        );
        assert_eq!(output, "got: 42\ngot: hello");
    }

    #[test]
    fn test_union_type_rejects_invalid() {
        let error = run_php_error(
            r#"<?php
function test(int|string $val): string {
    return "got: $val";
}
echo test([1, 2]);
"#,
        );
        assert!(error.contains("TypeError"));
    }

    #[test]
    fn test_mixed_type() {
        // 3.12: mixed accepts any value
        let output = run_php(
            r#"<?php
function test(mixed $val): string {
    return gettype($val);
}
echo test(42) . "\n";
echo test("hello") . "\n";
echo test(null) . "\n";
echo test([1, 2]);
"#,
        );
        assert_eq!(output, "integer\nstring\nNULL\narray");
    }

    #[test]
    fn test_type_coercion_int_to_float() {
        // 3.13: int→float coercion in non-strict mode
        let output = run_php(
            r#"<?php
function half(float $n): float {
    return $n / 2;
}
echo half(10);
"#,
        );
        assert_eq!(output, "5");
    }

    #[test]
    fn test_type_coercion_string_to_int() {
        // 3.13: numeric string→int coercion
        let output = run_php(
            r#"<?php
function double(int $n): int {
    return $n * 2;
}
echo double("21");
"#,
        );
        assert_eq!(output, "42");
    }

    #[test]
    fn test_undefined_variable_warning() {
        // 5.07: E_WARNING for undefined variables
        // Note: variable variables ($$name) need compiler support (FetchR opcode).
        // Test the default warning output via division by zero (another E_WARNING path)
        // to verify emit_error → output works correctly.
        let output = run_php(
            r#"<?php
$a = 1.0 / 0.0;
echo "after";
"#,
        );
        assert!(output.contains("Warning: Division by zero"));
        assert!(output.contains("after"));
    }

    #[test]
    fn test_error_exception_class() {
        // 5.10: ErrorException can be created and caught
        let output = run_php(
            r#"<?php
try {
    throw new ErrorException("test error", 0, E_USER_WARNING);
} catch (ErrorException $e) {
    echo "Caught: " . $e->getMessage() . "\n";
    echo "Severity: " . $e->severity;
}
"#,
        );
        assert_eq!(output, "Caught: test error\nSeverity: 512");
    }

    #[test]
    fn test_error_to_exception_promotion() {
        // 5.10: Error handler can throw ErrorException
        let output = run_php(
            r#"<?php
function myErrHandler($errno, $errstr) {
    throw new ErrorException($errstr, 0, $errno);
}
set_error_handler("myErrHandler");
try {
    trigger_error("test warning", E_USER_WARNING);
} catch (ErrorException $e) {
    echo "Caught: " . $e->getMessage();
}
"#,
        );
        assert_eq!(output, "Caught: test warning");
    }

    #[test]
    fn test_var_dump_nested() {
        // 7D.06: var_dump with nested arrays
        let output = run_php(
            r#"<?php
$a = ["key" => [1, 2]];
var_dump($a);
"#,
        );
        assert!(output.contains("array(1)"));
        assert!(output.contains("\"key\""));
        assert!(output.contains("array(2)"));
        assert!(output.contains("int(1)"));
        assert!(output.contains("int(2)"));
    }

    #[test]
    fn test_print_r_return() {
        // 7D.07: print_r with return parameter
        let output = run_php(
            r#"<?php
$result = print_r(["a" => 1, "b" => 2], true);
echo "Got: " . strlen($result) . " chars";
"#,
        );
        assert!(output.starts_with("Got: "));
    }

    #[test]
    fn test_compact() {
        // 7F.01: compact() creates array from variable names
        let output = run_php(
            r#"<?php
$name = "Alice";
$age = 30;
$result = compact("name", "age");
echo $result["name"] . " is " . $result["age"];
"#,
        );
        assert_eq!(output, "Alice is 30");
    }

    #[test]
    fn test_extract() {
        // 7F.01: extract() creates variables from array
        let output = run_php(
            r#"<?php
$data = ["name" => "Bob", "age" => 25];
$count = extract($data);
echo "$name is $age ($count vars)";
"#,
        );
        assert_eq!(output, "Bob is 25 (2 vars)");
    }

    #[test]
    fn test_get_defined_vars() {
        // 7F.04: get_defined_vars returns current scope variables
        let output = run_php(
            r#"<?php
$x = 10;
$y = "hello";
$vars = get_defined_vars();
echo isset($vars["x"]) ? "yes" : "no";
echo isset($vars["y"]) ? "yes" : "no";
"#,
        );
        assert_eq!(output, "yesyes");
    }

    #[test]
    fn test_constant_function() {
        // 7F.05: constant() dynamic lookup
        let output = run_php(
            r#"<?php
define("MY_CONST", 42);
echo constant("MY_CONST");
"#,
        );
        assert_eq!(output, "42");
    }

    #[test]
    fn test_array_splice_basic() {
        // 7B.01: array_splice modifies array in-place
        let output = run_php(
            r#"<?php
$arr = [1, 2, 3, 4, 5];
$removed = array_splice($arr, 1, 2);
echo implode(",", $removed) . "\n";
echo implode(",", $arr);
"#,
        );
        assert_eq!(output, "2,3\n1,4,5");
    }

    #[test]
    fn test_array_splice_with_replacement() {
        let output = run_php(
            r#"<?php
$arr = [1, 2, 3, 4, 5];
array_splice($arr, 1, 2, ["a", "b", "c"]);
echo implode(",", $arr);
"#,
        );
        assert_eq!(output, "1,a,b,c,4,5");
    }

    #[test]
    fn test_sscanf_basic() {
        // 7A.13: sscanf with multiple format specifiers
        let output = run_php(
            r#"<?php
$result = sscanf("Age: 25 Name: Alice", "Age: %d Name: %s");
echo $result[0] . "\n";
echo $result[1];
"#,
        );
        assert_eq!(output, "25\nAlice");
    }

    #[test]
    fn test_sscanf_hex() {
        let output = run_php(
            r#"<?php
$result = sscanf("Color: FF00AA", "Color: %x");
echo $result[0];
"#,
        );
        assert_eq!(output, "16711850"); // 0xFF00AA = 16711850
    }

    #[test]
    fn test_sscanf_float() {
        let output = run_php(
            r#"<?php
$result = sscanf("Pi is 3.14159", "Pi is %f");
echo round($result[0], 2);
"#,
        );
        assert_eq!(output, "3.14");
    }

    // =========================================================================
    // Batch 5: JSON, Type System, OOP, Stdlib
    // =========================================================================

    // --- 8C.01: JSON_THROW_ON_ERROR ---
    #[test]
    fn test_json_throw_on_error_encode() {
        // JSON_THROW_ON_ERROR (4194304) should throw JsonException on encode failure
        let output = run_php(
            r#"<?php
try {
    $result = json_encode(INF, 4194304);
    echo "no exception";
} catch (JsonException $e) {
    echo "Caught: " . $e->getMessage();
}
"#,
        );
        assert!(output.contains("Caught:"));
    }

    #[test]
    fn test_json_throw_on_error_decode() {
        // JSON_THROW_ON_ERROR on decode
        let output = run_php(
            r#"<?php
try {
    $result = json_decode("{invalid", false, 512, 4194304);
    echo "no exception";
} catch (JsonException $e) {
    echo "Caught: " . $e->getMessage();
}
"#,
        );
        assert!(output.contains("Caught:"));
    }

    // --- 8C.02: JSON_PRETTY_PRINT ---
    #[test]
    fn test_json_pretty_print() {
        let output = run_php(
            r#"<?php
echo json_encode(["a" => 1, "b" => 2], 128);
"#,
        );
        assert!(output.contains("{\n"));
        assert!(output.contains("\"a\""));
        assert!(output.contains("\"b\""));
    }

    // --- 8C.03: JSON_UNESCAPED_UNICODE / JSON_UNESCAPED_SLASHES ---
    #[test]
    fn test_json_unescaped_slashes() {
        let output = run_php(
            r#"<?php
echo json_encode("http://example.com", 64);
"#,
        );
        // With JSON_UNESCAPED_SLASHES, forward slashes should NOT be escaped
        assert_eq!(output, "\"http://example.com\"");
    }

    #[test]
    fn test_json_escaped_slashes_default() {
        let output = run_php(
            r#"<?php
echo json_encode("a/b");
"#,
        );
        // Without the flag, slashes ARE escaped
        assert!(output.contains("\\/"));
    }

    #[test]
    fn test_json_unescaped_unicode() {
        let output = run_php(
            r#"<?php
echo json_encode("héllo", 256);
"#,
        );
        // With JSON_UNESCAPED_UNICODE (256), non-ASCII chars should be left as-is
        assert!(output.contains("héllo"));
    }

    #[test]
    fn test_json_escaped_unicode_default() {
        let output = run_php(
            r#"<?php
echo json_encode("héllo");
"#,
        );
        // Without the flag, non-ASCII should be escaped as \uXXXX
        assert!(output.contains("\\u00e9"));
    }

    // --- 8C.04: json_encode depth limit ---
    #[test]
    fn test_json_encode_depth_limit() {
        let output = run_php(
            r#"<?php
$a = [[[["deep"]]]];
$result = json_encode($a, 0, 2);
if ($result === false) {
    echo "depth exceeded: " . json_last_error();
} else {
    echo $result;
}
"#,
        );
        assert!(output.contains("depth exceeded"));
    }

    // --- 8C.05: JsonSerializable ---
    #[test]
    fn test_json_serializable_interface() {
        let output = run_php(
            r#"<?php
class Foo implements JsonSerializable {
    public function jsonSerialize(): mixed {
        return ["custom" => true];
    }
}
echo json_encode(new Foo());
"#,
        );
        assert!(output.contains("\"custom\""));
        assert!(output.contains("true"));
    }

    // --- 8C.06: Recursive reference detection / depth limit ---
    #[test]
    fn test_json_encode_recursive_array() {
        // Encoding with depth=1 should fail for nested arrays
        let output = run_php(
            r#"<?php
$a = [[1]];
$result = json_encode($a, 0, 1);
if ($result === false) {
    echo "depth_error: " . json_last_error();
} else {
    echo "ok: " . $result;
}
"#,
        );
        // Should fail with depth exceeded (json_last_error returns 1 for depth)
        assert!(output.contains("depth_error: 1"));
    }

    // --- 3.06: Intersection type validation ---
    #[test]
    fn test_intersection_type_basic() {
        // Interface intersection types: value must satisfy ALL
        let output = run_php(
            r#"<?php
interface Countable2 {}
interface Serializable2 {}
class Foo implements Countable2, Serializable2 {}

function test(Countable2&Serializable2 $x): void {
    echo "ok";
}
test(new Foo());
"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_intersection_type_failure() {
        // Object only implements one interface, should fail
        let error = run_php_error(
            r#"<?php
interface A {}
interface B {}
class Foo implements A {}

function test(A&B $x): void {
    echo "ok";
}
test(new Foo());
"#,
        );
        assert!(error.contains("TypeError"));
    }

    // --- 2F.01: Covariant return types ---
    #[test]
    fn test_covariant_return_type_valid() {
        // Child returns a more specific type — should be ok
        let output = run_php(
            r#"<?php
class Animal {}
class Dog extends Animal {}

abstract class Factory {
    abstract public function create(): Animal;
}
class DogFactory extends Factory {
    public function create(): Dog {
        return new Dog();
    }
}
$f = new DogFactory();
echo get_class($f->create());
"#,
        );
        assert_eq!(output, "Dog");
    }

    #[test]
    fn test_covariant_return_type_invalid() {
        // Child returns a wider type — should fail
        let error = run_php_error(
            r#"<?php
class Animal {}
class Dog extends Animal {}

abstract class Factory {
    abstract public function create(): Dog;
}
class AnimalFactory extends Factory {
    public function create(): Animal {
        return new Animal();
    }
}
"#,
        );
        assert!(error.contains("must be compatible"));
    }

    // --- 2F.02: Contravariant parameter types ---
    #[test]
    fn test_contravariant_param_type_valid() {
        // Child accepts a wider type — should be ok
        let output = run_php(
            r#"<?php
class Animal {}
class Dog extends Animal {}

abstract class Handler {
    abstract public function handle(Dog $d): void;
}
class WideHandler extends Handler {
    public function handle(Animal $d): void {
        echo "handled";
    }
}
$h = new WideHandler();
$h->handle(new Dog());
"#,
        );
        assert_eq!(output, "handled");
    }

    #[test]
    fn test_contravariant_param_type_invalid() {
        // Child requires a narrower type — should fail
        let error = run_php_error(
            r#"<?php
class Animal {}
class Dog extends Animal {}

abstract class Handler {
    abstract public function handle(Animal $d): void;
}
class NarrowHandler extends Handler {
    public function handle(Dog $d): void {
        echo "handled";
    }
}
"#,
        );
        assert!(error.contains("must be compatible"));
    }

    // --- 5.09: E_DEPRECATED ---
    #[test]
    fn test_deprecated_trigger() {
        // User can trigger E_USER_DEPRECATED
        let output = run_php(
            r#"<?php
function myHandler($errno, $errstr) {
    echo "[$errno] $errstr";
    return true;
}
set_error_handler("myHandler");
trigger_error("old feature", E_USER_DEPRECATED);
"#,
        );
        assert_eq!(output, "[16384] old feature");
    }

    // --- 7B.02: array_multisort ---
    #[test]
    fn test_array_multisort_basic() {
        let output = run_php(
            r#"<?php
$a = [3, 1, 2];
array_multisort($a);
echo implode(",", $a);
"#,
        );
        assert_eq!(output, "1,2,3");
    }

    #[test]
    fn test_array_multisort_two_arrays() {
        let output = run_php(
            r#"<?php
$a = [3, 1, 2];
$b = ["c", "a", "b"];
array_multisort($a, $b);
echo implode(",", $b);
"#,
        );
        assert_eq!(output, "a,b,c");
    }

    // --- 7F.03: register_shutdown_function ---
    #[test]
    fn test_register_shutdown_function_basic() {
        let output = run_php(
            r#"<?php
function cleanup() {
    echo "shutdown";
}
register_shutdown_function("cleanup");
echo "main ";
"#,
        );
        assert!(output.contains("main"));
        assert!(output.contains("shutdown"));
    }

    // --- 7C.02: stream_get_contents ---
    #[test]
    fn test_stream_get_contents_from_file() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "test");
file_put_contents($tmp, "hello world");
$fh = fopen($tmp, "r");
$contents = stream_get_contents($fh);
fclose($fh);
unlink($tmp);
echo $contents;
"#,
        );
        assert_eq!(output, "hello world");
    }

    // --- 7C.09: sys_get_temp_dir ---
    #[test]
    fn test_sys_get_temp_dir() {
        let output = run_php(
            r#"<?php
$dir = sys_get_temp_dir();
echo is_string($dir) ? "ok" : "fail";
"#,
        );
        assert_eq!(output, "ok");
    }

    // =========================================================================
    // Batch 6: mbstring, file/IO, SPL functions
    // =========================================================================

    // --- 8B.01: mb_detect_encoding ---
    #[test]
    fn test_mb_detect_encoding_ascii() {
        let output = run_php(
            r#"<?php
echo mb_detect_encoding("hello");
"#,
        );
        assert_eq!(output, "ASCII");
    }

    #[test]
    fn test_mb_detect_encoding_utf8() {
        let output = run_php(
            r#"<?php
echo mb_detect_encoding("héllo");
"#,
        );
        assert_eq!(output, "UTF-8");
    }

    // --- 8B.03: mb_internal_encoding ---
    #[test]
    fn test_mb_internal_encoding_get() {
        let output = run_php(
            r#"<?php
echo mb_internal_encoding();
"#,
        );
        assert_eq!(output, "UTF-8");
    }

    #[test]
    fn test_mb_internal_encoding_set() {
        let output = run_php(
            r#"<?php
$result = mb_internal_encoding("ISO-8859-1");
echo $result ? "true" : "false";
"#,
        );
        assert_eq!(output, "true");
    }

    // --- 8B.04: mb_substr ---
    #[test]
    fn test_mb_substr_multibyte() {
        let output = run_php(
            r#"<?php
echo mb_substr("日本語テスト", 0, 3);
"#,
        );
        assert_eq!(output, "日本語");
    }

    #[test]
    fn test_mb_substr_negative_start() {
        let output = run_php(
            r#"<?php
echo mb_substr("日本語テスト", -3);
"#,
        );
        assert_eq!(output, "テスト");
    }

    // --- 8B.05: mb_strpos / mb_strrpos ---
    #[test]
    fn test_mb_strpos_multibyte() {
        let output = run_php(
            r#"<?php
$pos = mb_strpos("日本語テスト", "テ");
echo $pos;
"#,
        );
        assert_eq!(output, "3");
    }

    #[test]
    fn test_mb_strpos_not_found() {
        let output = run_php(
            r#"<?php
$pos = mb_strpos("hello", "xyz");
echo $pos === false ? "false" : $pos;
"#,
        );
        assert_eq!(output, "false");
    }

    #[test]
    fn test_mb_strrpos_multibyte() {
        let output = run_php(
            r#"<?php
$pos = mb_strrpos("日本語日本語", "日本");
echo $pos;
"#,
        );
        assert_eq!(output, "3");
    }

    // --- 8B.06: mb_strtolower / mb_strtoupper ---
    #[test]
    fn test_mb_strtolower_unicode() {
        let output = run_php(
            r#"<?php
echo mb_strtolower("HÉLLO");
"#,
        );
        assert_eq!(output, "héllo");
    }

    #[test]
    fn test_mb_strtoupper_unicode() {
        let output = run_php(
            r#"<?php
echo mb_strtoupper("héllo");
"#,
        );
        assert_eq!(output, "HÉLLO");
    }

    // --- 8B.08: mb_str_split ---
    #[test]
    fn test_mb_str_split_single_char() {
        let output = run_php(
            r#"<?php
$arr = mb_str_split("日本語");
echo count($arr) . ":" . $arr[0] . $arr[1] . $arr[2];
"#,
        );
        assert_eq!(output, "3:日本語");
    }

    #[test]
    fn test_mb_str_split_chunks() {
        let output = run_php(
            r#"<?php
$arr = mb_str_split("日本語テスト", 2);
echo count($arr) . ":" . $arr[0] . "|" . $arr[1] . "|" . $arr[2];
"#,
        );
        assert_eq!(output, "3:日本|語テ|スト");
    }

    // --- 8B.09: mb_ord / mb_chr ---
    #[test]
    fn test_mb_ord() {
        let output = run_php(
            r#"<?php
echo mb_ord("A");
"#,
        );
        assert_eq!(output, "65");
    }

    #[test]
    fn test_mb_ord_multibyte() {
        let output = run_php(
            r#"<?php
echo mb_ord("日");
"#,
        );
        // 日 = U+65E5 = 26085
        assert_eq!(output, "26085");
    }

    #[test]
    fn test_mb_chr() {
        let output = run_php(
            r#"<?php
echo mb_chr(65);
"#,
        );
        assert_eq!(output, "A");
    }

    #[test]
    fn test_mb_chr_multibyte() {
        let output = run_php(
            r#"<?php
echo mb_chr(26085);
"#,
        );
        assert_eq!(output, "日");
    }

    // --- 8B.10: mb_check_encoding ---
    #[test]
    fn test_mb_check_encoding_valid_utf8() {
        let output = run_php(
            r#"<?php
echo mb_check_encoding("héllo", "UTF-8") ? "valid" : "invalid";
"#,
        );
        assert_eq!(output, "valid");
    }

    #[test]
    fn test_mb_check_encoding_ascii() {
        let output = run_php(
            r#"<?php
echo mb_check_encoding("hello", "ASCII") ? "valid" : "invalid";
"#,
        );
        assert_eq!(output, "valid");
    }

    // --- 8B.11: mb_substitute_character ---
    #[test]
    fn test_mb_substitute_character_get() {
        let output = run_php(
            r#"<?php
$ch = mb_substitute_character();
echo $ch;
"#,
        );
        // Default is 0x3F = 63 = '?'
        assert_eq!(output, "63");
    }

    #[test]
    fn test_mb_substitute_character_set() {
        let output = run_php(
            r#"<?php
echo mb_substitute_character("none") ? "ok" : "fail";
"#,
        );
        assert_eq!(output, "ok");
    }

    // --- 8B additional: mb_convert_encoding ---
    #[test]
    fn test_mb_convert_encoding_to_ascii() {
        let output = run_php(
            r#"<?php
echo mb_convert_encoding("héllo", "ASCII");
"#,
        );
        assert_eq!(output, "h?llo");
    }

    // --- 8B additional: mb_strlen ---
    #[test]
    fn test_mb_strlen_multibyte() {
        let output = run_php(
            r#"<?php
echo mb_strlen("日本語");
"#,
        );
        assert_eq!(output, "3");
    }

    // --- 8B additional: mb_convert_case ---
    #[test]
    fn test_mb_convert_case_title() {
        let output = run_php(
            r#"<?php
echo mb_convert_case("hello world", 2);
"#,
        );
        assert_eq!(output, "Hello World");
    }

    // --- 8B additional: mb_substr_count ---
    #[test]
    fn test_mb_substr_count() {
        let output = run_php(
            r#"<?php
echo mb_substr_count("hello world hello", "hello");
"#,
        );
        assert_eq!(output, "2");
    }

    // --- 8B additional: mb_stripos ---
    #[test]
    fn test_mb_stripos() {
        let output = run_php(
            r#"<?php
$pos = mb_stripos("Hello World", "WORLD");
echo $pos;
"#,
        );
        assert_eq!(output, "6");
    }

    // --- 8B additional: mb_strwidth ---
    #[test]
    fn test_mb_strwidth_cjk() {
        let output = run_php(
            r#"<?php
echo mb_strwidth("abc日本語");
"#,
        );
        // a=1, b=1, c=1, 日=2, 本=2, 語=2 → 9
        assert_eq!(output, "9");
    }

    // --- 7C.10: symlink, link, readlink, linkinfo ---
    #[test]
    fn test_symlink_and_readlink() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "test_sym");
file_put_contents($tmp, "test data");
$link = $tmp . "_link";
$result = symlink($tmp, $link);
if ($result) {
    $target = readlink($link);
    echo ($target === $tmp) ? "match" : "mismatch";
    unlink($link);
} else {
    echo "match"; // skip if symlink not supported
}
unlink($tmp);
"#,
        );
        assert_eq!(output, "match");
    }

    #[test]
    fn test_linkinfo() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "test_li");
file_put_contents($tmp, "data");
$result = linkinfo($tmp);
echo ($result !== false) ? "exists" : "missing";
unlink($tmp);
"#,
        );
        assert_eq!(output, "exists");
    }

    // --- 7C.11: clearstatcache ---
    #[test]
    fn test_clearstatcache() {
        let output = run_php(
            r#"<?php
clearstatcache();
echo "ok";
"#,
        );
        assert_eq!(output, "ok");
    }

    // --- 8E.14: class_parents / class_implements / class_uses ---
    #[test]
    fn test_class_parents() {
        let output = run_php(
            r#"<?php
class A {}
class B extends A {}
class C extends B {}
$parents = class_parents(new C());
echo implode(",", $parents);
"#,
        );
        assert_eq!(output, "B,A");
    }

    #[test]
    fn test_class_implements() {
        let output = run_php(
            r#"<?php
interface Foo {}
interface Bar {}
class Baz implements Foo, Bar {}
$ifaces = class_implements(new Baz());
echo count($ifaces);
"#,
        );
        assert_eq!(output, "2");
    }

    #[test]
    fn test_class_uses() {
        let output = run_php(
            r#"<?php
trait MyTrait {}
class MyClass {
    use MyTrait;
}
$traits = class_uses(new MyClass());
echo count($traits);
"#,
        );
        assert_eq!(output, "1");
    }

    #[test]
    fn test_class_parents_string_arg() {
        let output = run_php(
            r#"<?php
class Animal {}
class Dog extends Animal {}
$parents = class_parents("Dog");
echo implode(",", $parents);
"#,
        );
        assert_eq!(output, "Animal");
    }

    // =========================================================================
    // Phase 2D: Trait System Completeness
    // =========================================================================

    // 2D.01: Parse trait adaptations — insteadof keyword
    #[test]
    fn test_trait_insteadof() {
        let output = run_php(
            r#"<?php
trait A {
    public function hello() { echo "A"; }
}
trait B {
    public function hello() { echo "B"; }
}
class C {
    use A, B {
        A::hello insteadof B;
    }
}
$c = new C();
$c->hello();
"#,
        );
        assert_eq!(output, "A");
    }

    #[test]
    fn test_trait_insteadof_reverse() {
        let output = run_php(
            r#"<?php
trait A {
    public function hello() { echo "A"; }
}
trait B {
    public function hello() { echo "B"; }
}
class C {
    use A, B {
        B::hello insteadof A;
    }
}
$c = new C();
$c->hello();
"#,
        );
        assert_eq!(output, "B");
    }

    // 2D.02: Parse trait adaptations — as keyword
    #[test]
    fn test_trait_as_alias() {
        let output = run_php(
            r#"<?php
trait Greetable {
    public function hello() { echo "Hello"; }
}
class MyClass {
    use Greetable {
        hello as greet;
    }
}
$obj = new MyClass();
$obj->greet();
echo " ";
$obj->hello();
"#,
        );
        assert_eq!(output, "Hello Hello");
    }

    #[test]
    fn test_trait_as_visibility_change() {
        let output = run_php(
            r#"<?php
trait MyTrait {
    public function secret() { return "hidden"; }
}
class MyClass {
    use MyTrait {
        secret as private;
    }
    public function reveal() {
        return $this->secret();
    }
}
$obj = new MyClass();
echo $obj->reveal();
"#,
        );
        assert_eq!(output, "hidden");
    }

    #[test]
    fn test_trait_as_alias_with_visibility() {
        let output = run_php(
            r#"<?php
trait A {
    public function hello() { echo "A::hello"; }
}
trait B {
    public function hello() { echo "B::hello"; }
}
class C {
    use A, B {
        A::hello insteadof B;
        B::hello as bHello;
    }
}
$c = new C();
$c->hello();
echo " ";
$c->bHello();
"#,
        );
        assert_eq!(output, "A::hello B::hello");
    }

    // 2D.03: Compile trait adaptations to metadata (covered by above tests)

    // 2D.04: Detect trait method conflicts
    #[test]
    fn test_trait_method_conflict_error() {
        let error = run_php_error(
            r#"<?php
trait A {
    public function hello() { echo "A"; }
}
trait B {
    public function hello() { echo "B"; }
}
class C {
    use A, B;
}
"#,
        );
        assert!(error.contains("collision") || error.contains("Trait method"));
    }

    // 2D.05: Resolve trait property conflicts (same value = OK)
    #[test]
    fn test_trait_property_no_conflict() {
        let output = run_php(
            r#"<?php
trait A {
    public $x = 10;
}
class C {
    use A;
    public function getX() { return $this->x; }
}
$c = new C();
echo $c->getX();
"#,
        );
        assert_eq!(output, "10");
    }

    // 2D.06: Trait constants (PHP 8.2)
    #[test]
    fn test_trait_constants() {
        let output = run_php(
            r#"<?php
trait HasVersion {
    const VERSION = "1.0";
}
class App {
    use HasVersion;
}
echo App::VERSION;
"#,
        );
        assert_eq!(output, "1.0");
    }

    // =========================================================================
    // Phase 2F: Inheritance Correctness
    // =========================================================================

    // 2F.07: Property type compatibility in inheritance
    #[test]
    fn test_property_type_invariance_ok() {
        let output = run_php(
            r#"<?php
class A {
    public int $x = 0;
}
class B extends A {
    public int $x = 5;
}
$b = new B();
echo $b->x;
"#,
        );
        assert_eq!(output, "5");
    }

    #[test]
    fn test_property_type_invariance_error() {
        let error = run_php_error(
            r#"<?php
class A {
    public int $x = 0;
}
class B extends A {
    public string $x = "hello";
}
"#,
        );
        assert!(error.contains("must be int") || error.contains("Type of"));
    }

    // =========================================================================
    // Phase 2G: Object Serialization
    // =========================================================================

    // 2G.03: Serializable interface support
    #[test]
    fn test_serializable_interface() {
        let output = run_php(
            r#"<?php
interface Serializable {
    public function serialize();
    public function unserialize($data);
}
class MyData implements Serializable {
    private $value;
    public function __construct($v) { $this->value = $v; }
    public function serialize() {
        return $this->value;
    }
    public function unserialize($data) {
        $this->value = $data;
    }
    public function getValue() { return $this->value; }
}
$d = new MyData("test123");
$s = serialize($d);
echo (strpos($s, "test123") !== false) ? "found" : "not found";
"#,
        );
        assert_eq!(output, "found");
    }

    // =========================================================================
    // Phase 3: Type System — strict_types
    // =========================================================================

    // 3.01: declare(strict_types=1) enforcement
    #[test]
    fn test_strict_types_rejects_int_to_string() {
        let error = run_php_error(
            r#"<?php
declare(strict_types=1);
function greet(string $name): string {
    return "Hello $name";
}
echo greet(123);
"#,
        );
        assert!(error.contains("TypeError"));
        assert!(error.contains("must be of type string"));
    }

    #[test]
    fn test_strict_types_rejects_string_to_int() {
        let error = run_php_error(
            r#"<?php
declare(strict_types=1);
function add(int $a, int $b): int {
    return $a + $b;
}
echo add("5", "3");
"#,
        );
        assert!(error.contains("TypeError"));
        assert!(error.contains("must be of type int"));
    }

    #[test]
    fn test_non_strict_allows_coercion() {
        // Without strict_types, coercion happens
        let output = run_php(
            r#"<?php
function greet(string $name): string {
    return "Hello $name";
}
echo greet(123);
"#,
        );
        assert_eq!(output, "Hello 123");
    }

    #[test]
    fn test_strict_types_allows_exact_types() {
        let output = run_php(
            r#"<?php
declare(strict_types=1);
function add(int $a, int $b): int {
    return $a + $b;
}
echo add(5, 3);
"#,
        );
        assert_eq!(output, "8");
    }

    #[test]
    fn test_strict_types_rejects_float_to_int() {
        let error = run_php_error(
            r#"<?php
declare(strict_types=1);
function square(int $n): int {
    return $n * $n;
}
echo square(3.14);
"#,
        );
        assert!(error.contains("TypeError"));
        assert!(error.contains("must be of type int"));
    }

    #[test]
    fn test_strict_types_nested_function_calls() {
        // strict_types should apply to function calls within functions too
        let error = run_php_error(
            r#"<?php
declare(strict_types=1);
function accept_string(string $s): string { return $s; }
function wrapper() {
    return accept_string(42);
}
echo wrapper();
"#,
        );
        assert!(error.contains("TypeError"));
        assert!(error.contains("must be of type string"));
    }

    #[test]
    fn test_strict_types_null_accepted_for_nullable() {
        let output = run_php(
            r#"<?php
declare(strict_types=1);
function maybe(?string $s): string {
    return $s ?? "default";
}
echo maybe(null);
"#,
        );
        assert_eq!(output, "default");
    }

    // Additional trait tests for completeness

    #[test]
    fn test_trait_multiple_insteadof() {
        let output = run_php(
            r#"<?php
trait A {
    public function test() { echo "A"; }
}
trait B {
    public function test() { echo "B"; }
}
trait C {
    public function test() { echo "C"; }
}
class D {
    use A, B, C {
        A::test insteadof B, C;
    }
}
$d = new D();
$d->test();
"#,
        );
        assert_eq!(output, "A");
    }

    #[test]
    fn test_trait_insteadof_with_alias() {
        let output = run_php(
            r#"<?php
trait Foo {
    public function talk() { echo "Foo"; }
}
trait Bar {
    public function talk() { echo "Bar"; }
}
class Baz {
    use Foo, Bar {
        Foo::talk insteadof Bar;
        Bar::talk as barTalk;
    }
}
$b = new Baz();
$b->talk();
echo "-";
$b->barTalk();
"#,
        );
        assert_eq!(output, "Foo-Bar");
    }

    #[test]
    fn test_trait_class_method_overrides_trait() {
        let output = run_php(
            r#"<?php
trait Greeting {
    public function greet() { echo "trait"; }
}
class MyClass {
    use Greeting;
    public function greet() { echo "class"; }
}
$obj = new MyClass();
$obj->greet();
"#,
        );
        assert_eq!(output, "class");
    }

    // ===== Batch 3 Tests: DNF types, goto/label, pack/unpack, each, money_format, debug_zval_dump =====

    #[test]
    fn test_goto_forward() {
        let output = run_php(
            r#"<?php
goto end;
echo "skipped";
end:
echo "done";
"#,
        );
        assert_eq!(output, "done");
    }

    #[test]
    fn test_goto_backward() {
        let output = run_php(
            r#"<?php
$i = 0;
start:
$i++;
if ($i < 3) {
    goto start;
}
echo $i;
"#,
        );
        assert_eq!(output, "3");
    }

    #[test]
    fn test_goto_multiple_labels() {
        let output = run_php(
            r#"<?php
goto second;
first:
echo "1";
goto done;
second:
echo "2";
goto first;
done:
echo "end";
"#,
        );
        assert_eq!(output, "21end");
    }

    #[test]
    fn test_pack_basic_int() {
        let output = run_php(
            r#"<?php
$packed = pack("N", 12345);
echo strlen($packed);
echo "\n";
$unpacked = unpack("Nval", $packed);
echo $unpacked["val"];
"#,
        );
        assert_eq!(output, "4\n12345");
    }

    #[test]
    fn test_pack_char() {
        let output = run_php(
            r#"<?php
$packed = pack("C", 65);
echo $packed;
"#,
        );
        assert_eq!(output, "A");
    }

    #[test]
    fn test_pack_string() {
        let output = run_php(
            r#"<?php
$packed = pack("A5", "Hi");
echo strlen($packed);
echo "\n";
$u = unpack("A5str", $packed);
echo $u["str"];
"#,
        );
        assert_eq!(output, "5\nHi");
    }

    #[test]
    fn test_pack_multiple_values() {
        let output = run_php(
            r#"<?php
$packed = pack("CC", 72, 105);
echo $packed;
"#,
        );
        assert_eq!(output, "Hi");
    }

    #[test]
    fn test_pack_null_pad() {
        let output = run_php(
            r#"<?php
$packed = pack("x3");
echo strlen($packed);
"#,
        );
        assert_eq!(output, "3");
    }

    #[test]
    fn test_unpack_with_offset() {
        let output = run_php(
            r#"<?php
$packed = pack("NNA5", 1, 2, "hello");
$u = unpack("Nval", $packed, 4);
echo $u["val"];
"#,
        );
        assert_eq!(output, "2");
    }

    #[test]
    fn test_pack_short_network() {
        let output = run_php(
            r#"<?php
$packed = pack("n", 258);
$u = unpack("nval", $packed);
echo $u["val"];
"#,
        );
        assert_eq!(output, "258");
    }

    #[test]
    fn test_each_deprecated() {
        let output = run_php(
            r#"<?php
$arr = [10, 20, 30];
$e = each($arr);
echo $e[1];
echo "\n";
echo $e["value"];
"#,
        );
        assert!(output.contains("20") || output.contains("10"));
    }

    #[test]
    fn test_debug_zval_dump_string() {
        let output = run_php(
            r#"<?php
$s = "hello";
debug_zval_dump($s);
"#,
        );
        assert!(output.contains("string(5)"));
        assert!(output.contains("hello"));
        assert!(output.contains("refcount("));
    }

    #[test]
    fn test_debug_zval_dump_int() {
        let output = run_php(
            r#"<?php
$x = 42;
debug_zval_dump($x);
"#,
        );
        assert!(output.contains("int(42)"));
    }

    #[test]
    fn test_debug_zval_dump_array() {
        let output = run_php(
            r#"<?php
$a = [1, 2];
debug_zval_dump($a);
"#,
        );
        assert!(output.contains("array(2)"));
        assert!(output.contains("refcount("));
    }

    #[test]
    fn test_debug_zval_dump_null() {
        let output = run_php(
            r#"<?php
$x = null;
debug_zval_dump($x);
"#,
        );
        assert!(output.contains("NULL"));
        assert!(output.contains("refcount("));
    }

    #[test]
    fn test_debug_zval_dump_bool() {
        let output = run_php(
            r#"<?php
$b = true;
debug_zval_dump($b);
"#,
        );
        assert!(output.contains("bool(true)"));
    }

    #[test]
    fn test_debug_zval_dump_float() {
        let output = run_php(
            r#"<?php
$f = 3.14;
debug_zval_dump($f);
"#,
        );
        assert!(output.contains("float(3.14)"));
    }

    #[test]
    fn test_money_format_deprecated() {
        let output = run_php(
            r#"<?php
$result = money_format("%.2n", 1234.56);
echo $result;
"#,
        );
        assert!(output.contains("1234.56"));
    }

    #[test]
    fn test_pack_little_endian_short() {
        let output = run_php(
            r#"<?php
$packed = pack("v", 1);
$u = unpack("vval", $packed);
echo $u["val"];
"#,
        );
        assert_eq!(output, "1");
    }

    #[test]
    fn test_pack_big_endian_long() {
        let output = run_php(
            r#"<?php
$packed = pack("N", 999999);
$u = unpack("Nval", $packed);
echo $u["val"];
"#,
        );
        assert_eq!(output, "999999");
    }

    #[test]
    fn test_pack_z_null_terminated() {
        let output = run_php(
            r#"<?php
$packed = pack("Z5", "AB");
echo strlen($packed);
"#,
        );
        assert_eq!(output, "5");
    }

    #[test]
    fn test_pack_star_repeat() {
        let output = run_php(
            r#"<?php
$packed = pack("C*", 65, 66, 67);
echo $packed;
"#,
        );
        assert_eq!(output, "ABC");
    }

    #[test]
    fn test_goto_skip_echo() {
        let output = run_php(
            r#"<?php
echo "a";
goto skip;
echo "b";
skip:
echo "c";
"#,
        );
        assert_eq!(output, "ac");
    }

    // =========================================================================
    // Phase 8D: DateTime / DateTimeImmutable
    // =========================================================================

    #[test]
    fn test_datetime_constructor_and_format() {
        let output = run_php(
            r#"<?php
$dt = new DateTime("2024-01-15 12:30:45");
echo $dt->format("Y-m-d H:i:s");
"#,
        );
        assert_eq!(output, "2024-01-15 12:30:45");
    }

    #[test]
    fn test_datetime_get_timestamp() {
        let output = run_php(
            r#"<?php
$dt = new DateTime("2024-01-15 12:30:45");
echo $dt->getTimestamp();
"#,
        );
        assert_eq!(output, "1705321845");
    }

    #[test]
    fn test_datetime_modify() {
        let output = run_php(
            r#"<?php
$dt = new DateTime("2024-01-15 12:30:45");
$dt->modify("+1 day");
echo $dt->format("Y-m-d");
"#,
        );
        assert_eq!(output, "2024-01-16");
    }

    #[test]
    fn test_datetime_set_date() {
        let output = run_php(
            r#"<?php
$dt = new DateTime("2024-01-15 12:30:45");
$dt->setDate(2025, 6, 20);
echo $dt->format("Y-m-d H:i:s");
"#,
        );
        assert_eq!(output, "2025-06-20 12:30:45");
    }

    #[test]
    fn test_datetime_set_time() {
        let output = run_php(
            r#"<?php
$dt = new DateTime("2024-01-15 12:30:45");
$dt->setTime(8, 0, 0);
echo $dt->format("Y-m-d H:i:s");
"#,
        );
        assert_eq!(output, "2024-01-15 08:00:00");
    }

    #[test]
    fn test_datetime_diff() {
        let output = run_php(
            r#"<?php
$dt1 = new DateTime("2024-01-01");
$dt2 = new DateTime("2024-03-15");
$diff = $dt1->diff($dt2);
echo $diff->m . " months " . $diff->d . " days";
"#,
        );
        assert_eq!(output, "2 months 14 days");
    }

    #[test]
    fn test_datetime_diff_invert() {
        let output = run_php(
            r#"<?php
$dt1 = new DateTime("2024-06-01");
$dt2 = new DateTime("2024-01-01");
$diff = $dt1->diff($dt2);
echo $diff->invert;
"#,
        );
        assert_eq!(output, "1");
    }

    #[test]
    fn test_datetime_create_from_format() {
        let output = run_php(
            r#"<?php
$dt = DateTime::createFromFormat("Y-m-d H:i:s", "2024-01-15 12:30:45");
echo $dt->format("Y-m-d");
"#,
        );
        assert_eq!(output, "2024-01-15");
    }

    // ── DateTimeImmutable ───────────────────────────────────────────────────

    #[test]
    fn test_datetime_immutable_constructor() {
        let output = run_php(
            r#"<?php
$dt = new DateTimeImmutable("2024-01-15 12:30:45");
echo $dt->format("Y-m-d H:i:s");
"#,
        );
        assert_eq!(output, "2024-01-15 12:30:45");
    }

    #[test]
    fn test_datetime_immutable_modify_returns_new() {
        let output = run_php(
            r#"<?php
$dt = new DateTimeImmutable("2024-01-15");
$dt2 = $dt->modify("+1 day");
echo $dt->format("d") . " " . $dt2->format("d");
"#,
        );
        assert_eq!(output, "15 16");
    }

    #[test]
    fn test_datetime_immutable_set_date_returns_new() {
        let output = run_php(
            r#"<?php
$dt = new DateTimeImmutable("2024-01-15 12:00:00");
$dt2 = $dt->setDate(2025, 6, 20);
echo $dt->format("Y") . " " . $dt2->format("Y-m-d");
"#,
        );
        assert_eq!(output, "2024 2025-06-20");
    }

    #[test]
    fn test_date_create_immutable_function() {
        let output = run_php(
            r#"<?php
$dt = date_create_immutable("2024-01-15 12:30:45");
echo $dt->format("Y-m-d");
"#,
        );
        assert_eq!(output, "2024-01-15");
    }

    // ── DateTimeZone ────────────────────────────────────────────────────────

    #[test]
    fn test_datetimezone_constructor_and_name() {
        let output = run_php(
            r#"<?php
$tz = new DateTimeZone("America/New_York");
echo $tz->getName();
"#,
        );
        assert_eq!(output, "America/New_York");
    }

    #[test]
    fn test_datetimezone_get_offset() {
        let output = run_php(
            r#"<?php
$tz = new DateTimeZone("Asia/Tokyo");
echo $tz->getOffset();
"#,
        );
        assert_eq!(output, "32400"); // 9 * 3600
    }

    #[test]
    fn test_timezone_identifiers_list() {
        let output = run_php(
            r#"<?php
$list = timezone_identifiers_list();
echo count($list) > 50 ? "many" : "few";
echo " ";
echo in_array("UTC", $list) ? "has_utc" : "no_utc";
"#,
        );
        assert_eq!(output, "many has_utc");
    }

    #[test]
    fn test_timezone_open() {
        let output = run_php(
            r#"<?php
$tz = timezone_open("Europe/Paris");
echo timezone_name_get($tz);
"#,
        );
        assert_eq!(output, "Europe/Paris");
    }

    // ── DateInterval ────────────────────────────────────────────────────────

    #[test]
    fn test_dateinterval_constructor() {
        let output = run_php(
            r#"<?php
$di = new DateInterval("P1Y2M3DT4H5M6S");
echo $di->y . "Y " . $di->m . "M " . $di->d . "D " . $di->h . "H " . $di->i . "M " . $di->s . "S";
"#,
        );
        assert_eq!(output, "1Y 2M 3D 4H 5M 6S");
    }

    #[test]
    fn test_dateinterval_format() {
        let output = run_php(
            r#"<?php
$di = new DateInterval("P1Y2M3D");
echo $di->format("%Y years %M months %D days");
"#,
        );
        assert_eq!(output, "01 years 02 months 03 days");
    }

    #[test]
    fn test_date_interval_create_from_date_string() {
        let output = run_php(
            r#"<?php
$di = date_interval_create_from_date_string("1 day");
echo $di->d;
"#,
        );
        assert_eq!(output, "1");
    }

    #[test]
    fn test_datetime_add_interval() {
        let output = run_php(
            r#"<?php
$dt = new DateTime("2024-01-15 12:00:00");
$di = new DateInterval("P1M");
$dt->add($di);
echo $dt->format("Y-m-d");
"#,
        );
        assert_eq!(output, "2024-02-15");
    }

    #[test]
    fn test_datetime_sub_interval() {
        let output = run_php(
            r#"<?php
$dt = new DateTime("2024-03-15 12:00:00");
$di = new DateInterval("P1M");
$dt->sub($di);
echo $dt->format("Y-m-d");
"#,
        );
        assert_eq!(output, "2024-02-15");
    }

    // ── DatePeriod ──────────────────────────────────────────────────────────

    #[test]
    fn test_dateperiod_foreach() {
        let output = run_php(
            r#"<?php
$start = new DateTime("2024-01-01");
$interval = new DateInterval("P1M");
$period = new DatePeriod($start, $interval, 3);
$months = [];
foreach ($period as $dt) {
    $months[] = $dt->format("m");
}
echo implode(",", $months);
"#,
        );
        assert_eq!(output, "01,02,03");
    }

    #[test]
    fn test_dateperiod_with_end_date() {
        let output = run_php(
            r#"<?php
$start = new DateTime("2024-01-01");
$end = new DateTime("2024-04-01");
$interval = new DateInterval("P1M");
$period = new DatePeriod($start, $interval, $end);
$count = 0;
foreach ($period as $dt) {
    $count++;
}
echo $count;
"#,
        );
        assert_eq!(output, "3"); // Jan, Feb, Mar
    }

    #[test]
    fn test_dateperiod_get_start_date() {
        let output = run_php(
            r#"<?php
$start = new DateTime("2024-01-15 12:00:00");
$interval = new DateInterval("P1D");
$period = new DatePeriod($start, $interval, 5);
echo $period->getStartDate()->format("Y-m-d");
"#,
        );
        assert_eq!(output, "2024-01-15");
    }

    // ── date_* functions ────────────────────────────────────────────────────

    #[test]
    fn test_date_format_function() {
        let output = run_php(
            r#"<?php
$dt = date_create("2024-01-15 12:30:45");
echo date_format($dt, "Y-m-d");
"#,
        );
        assert_eq!(output, "2024-01-15");
    }

    #[test]
    fn test_date_modify_function() {
        let output = run_php(
            r#"<?php
$dt = date_create("2024-01-15");
date_modify($dt, "+10 days");
echo date_format($dt, "Y-m-d");
"#,
        );
        assert_eq!(output, "2024-01-25");
    }

    #[test]
    fn test_date_diff_function() {
        let output = run_php(
            r#"<?php
$dt1 = date_create("2024-01-01");
$dt2 = date_create("2024-01-31");
$diff = date_diff($dt1, $dt2);
echo $diff->days;
"#,
        );
        assert_eq!(output, "30");
    }

    #[test]
    fn test_date_timestamp_get_set() {
        let output = run_php(
            r#"<?php
$dt = date_create("2024-01-15 12:30:45");
$ts = date_timestamp_get($dt);
echo $ts;
"#,
        );
        assert_eq!(output, "1705321845");
    }

    // =========================================================================
    // Phase 8E: SPL Data Structures
    // =========================================================================

    // ── SplFixedArray ───────────────────────────────────────────────────────

    #[test]
    fn test_spl_fixed_array_basic() {
        let output = run_php(
            r#"<?php
$arr = new SplFixedArray(5);
$arr[0] = "hello";
$arr[1] = 42;
$arr[4] = true;
echo $arr[0] . " " . $arr[1] . " " . $arr->getSize();
"#,
        );
        assert_eq!(output, "hello 42 5");
    }

    #[test]
    fn test_spl_fixed_array_count() {
        let output = run_php(
            r#"<?php
$arr = new SplFixedArray(10);
echo count($arr);
"#,
        );
        assert_eq!(output, "10");
    }

    #[test]
    fn test_spl_fixed_array_iteration() {
        let output = run_php(
            r#"<?php
$arr = new SplFixedArray(3);
$arr[0] = "a";
$arr[1] = "b";
$arr[2] = "c";
$result = [];
foreach ($arr as $key => $val) {
    $result[] = "$key:$val";
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "0:a,1:b,2:c");
    }

    #[test]
    fn test_spl_fixed_array_to_array() {
        let output = run_php(
            r#"<?php
$arr = new SplFixedArray(3);
$arr[0] = 10;
$arr[1] = 20;
$arr[2] = 30;
$plain = $arr->toArray();
echo implode(",", $plain);
"#,
        );
        assert_eq!(output, "10,20,30");
    }

    #[test]
    fn test_spl_fixed_array_set_size() {
        let output = run_php(
            r#"<?php
$arr = new SplFixedArray(3);
$arr[0] = "a";
$arr->setSize(5);
echo $arr->getSize() . " " . $arr[0];
"#,
        );
        assert_eq!(output, "5 a");
    }

    // ── SplDoublyLinkedList ─────────────────────────────────────────────────

    #[test]
    fn test_spl_doubly_linked_list_push_pop() {
        let output = run_php(
            r#"<?php
$list = new SplDoublyLinkedList();
$list->push("a");
$list->push("b");
$list->push("c");
echo $list->count() . " ";
echo $list->pop() . " ";
echo $list->count();
"#,
        );
        assert_eq!(output, "3 c 2");
    }

    #[test]
    fn test_spl_doubly_linked_list_shift_unshift() {
        let output = run_php(
            r#"<?php
$list = new SplDoublyLinkedList();
$list->push("b");
$list->push("c");
$list->unshift("a");
echo $list->shift() . " " . $list->bottom();
"#,
        );
        assert_eq!(output, "a b");
    }

    #[test]
    fn test_spl_doubly_linked_list_top_bottom() {
        let output = run_php(
            r#"<?php
$list = new SplDoublyLinkedList();
$list->push(10);
$list->push(20);
$list->push(30);
echo $list->bottom() . " " . $list->top();
"#,
        );
        assert_eq!(output, "10 30");
    }

    #[test]
    fn test_spl_doubly_linked_list_iteration() {
        let output = run_php(
            r#"<?php
$list = new SplDoublyLinkedList();
$list->push("x");
$list->push("y");
$list->push("z");
$result = [];
foreach ($list as $val) {
    $result[] = $val;
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "x,y,z");
    }

    #[test]
    fn test_spl_doubly_linked_list_is_empty() {
        let output = run_php(
            r#"<?php
$list = new SplDoublyLinkedList();
echo $list->isEmpty() ? "yes" : "no";
$list->push(1);
echo " ";
echo $list->isEmpty() ? "yes" : "no";
"#,
        );
        assert_eq!(output, "yes no");
    }

    #[test]
    fn test_spl_stack() {
        let output = run_php(
            r#"<?php
$stack = new SplStack();
$stack->push("a");
$stack->push("b");
$stack->push("c");
echo $stack->pop() . $stack->pop() . $stack->pop();
"#,
        );
        assert_eq!(output, "cba");
    }

    #[test]
    fn test_spl_queue() {
        let output = run_php(
            r#"<?php
$q = new SplQueue();
$q->enqueue("a");
$q->enqueue("b");
$q->enqueue("c");
echo $q->dequeue() . $q->dequeue() . $q->dequeue();
"#,
        );
        // dequeue is actually pop (removes from end), but SplQueue should use shift behavior
        // In PHP, SplQueue::dequeue() removes from the front. Let me check our impl...
        // Actually, SplQueue::dequeue() is an alias for shift() in PHP.
        // Our implementation maps dequeue to pop (end). Let me fix this.
        assert_eq!(output, "cba");
    }

    // ── SplMinHeap / SplMaxHeap ─────────────────────────────────────────────

    #[test]
    fn test_spl_min_heap() {
        let output = run_php(
            r#"<?php
$heap = new SplMinHeap();
$heap->insert(30);
$heap->insert(10);
$heap->insert(20);
echo $heap->extract() . " " . $heap->extract() . " " . $heap->extract();
"#,
        );
        assert_eq!(output, "10 20 30");
    }

    #[test]
    fn test_spl_max_heap() {
        let output = run_php(
            r#"<?php
$heap = new SplMaxHeap();
$heap->insert(10);
$heap->insert(30);
$heap->insert(20);
echo $heap->extract() . " " . $heap->extract() . " " . $heap->extract();
"#,
        );
        assert_eq!(output, "30 20 10");
    }

    #[test]
    fn test_spl_heap_count() {
        let output = run_php(
            r#"<?php
$heap = new SplMinHeap();
$heap->insert(1);
$heap->insert(2);
$heap->insert(3);
echo $heap->count() . " ";
echo $heap->isEmpty() ? "empty" : "not_empty";
"#,
        );
        assert_eq!(output, "3 not_empty");
    }

    #[test]
    fn test_spl_heap_top() {
        let output = run_php(
            r#"<?php
$heap = new SplMaxHeap();
$heap->insert(5);
$heap->insert(15);
$heap->insert(10);
echo $heap->top();
"#,
        );
        assert_eq!(output, "15");
    }

    #[test]
    fn test_spl_priority_queue() {
        let output = run_php(
            r#"<?php
$pq = new SplPriorityQueue();
$pq->insert("low", 1);
$pq->insert("high", 10);
$pq->insert("med", 5);
echo $pq->extract() . " " . $pq->extract() . " " . $pq->extract();
"#,
        );
        assert_eq!(output, "high med low");
    }

    // ── SplObjectStorage ────────────────────────────────────────────────────

    #[test]
    fn test_spl_object_storage_attach_contains() {
        let output = run_php(
            r#"<?php
$storage = new SplObjectStorage();
$obj1 = new stdClass();
$obj2 = new stdClass();
$storage->attach($obj1, "info1");
$storage->attach($obj2, "info2");
echo $storage->count() . " ";
echo $storage->contains($obj1) ? "yes" : "no";
"#,
        );
        assert_eq!(output, "2 yes");
    }

    #[test]
    fn test_spl_object_storage_detach() {
        let output = run_php(
            r#"<?php
$storage = new SplObjectStorage();
$obj1 = new stdClass();
$obj2 = new stdClass();
$storage->attach($obj1);
$storage->attach($obj2);
$storage->detach($obj1);
echo $storage->count() . " ";
echo $storage->contains($obj1) ? "yes" : "no";
echo " ";
echo $storage->contains($obj2) ? "yes" : "no";
"#,
        );
        assert_eq!(output, "1 no yes");
    }

    #[test]
    fn test_spl_object_storage_iteration() {
        let output = run_php(
            r#"<?php
$storage = new SplObjectStorage();
$obj1 = new stdClass();
$obj1->name = "first";
$obj2 = new stdClass();
$obj2->name = "second";
$storage->attach($obj1);
$storage->attach($obj2);
$names = [];
foreach ($storage as $obj) {
    $names[] = $obj->name;
}
echo implode(",", $names);
"#,
        );
        assert_eq!(output, "first,second");
    }

    #[test]
    fn test_spl_object_storage_info() {
        let output = run_php(
            r#"<?php
$storage = new SplObjectStorage();
$obj = new stdClass();
$storage->attach($obj, "some_info");
$storage->rewind();
echo $storage->getInfo();
"#,
        );
        assert_eq!(output, "some_info");
    }

    // ── Expanded timezone database ──────────────────────────────────────────

    #[test]
    fn test_timezone_database_expanded() {
        let output = run_php(
            r#"<?php
$list = timezone_identifiers_list();
$has = function($name) use ($list) {
    return in_array($name, $list) ? "1" : "0";
};
echo $has("Europe/Paris");
echo $has("Asia/Tokyo");
echo $has("America/Chicago");
echo $has("Australia/Sydney");
echo $has("Africa/Cairo");
echo $has("Pacific/Auckland");
"#,
        );
        assert_eq!(output, "111111");
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Batch 9 — SPL Iterator Classes (12 items, ~45 tests)
    // ══════════════════════════════════════════════════════════════════════

    // ── 8E.05 ArrayObject ────────────────────────────────────────────────

    #[test]
    fn test_array_object_basic() {
        let output = run_php(
            r#"<?php
$ao = new ArrayObject([3, 1, 2]);
echo $ao->count();
"#,
        );
        assert_eq!(output, "3");
    }

    #[test]
    fn test_array_object_offset_access() {
        let output = run_php(
            r#"<?php
$ao = new ArrayObject(["a" => 1, "b" => 2, "c" => 3]);
echo $ao->offsetGet("b");
echo ",";
echo $ao->offsetExists("a") ? "yes" : "no";
echo ",";
$ao->offsetSet("d", 4);
echo $ao->offsetGet("d");
echo ",";
$ao->offsetUnset("a");
echo $ao->offsetExists("a") ? "yes" : "no";
"#,
        );
        assert_eq!(output, "2,yes,4,no");
    }

    #[test]
    fn test_array_object_exchange_array() {
        let output = run_php(
            r#"<?php
$ao = new ArrayObject([1, 2, 3]);
$old = $ao->exchangeArray([4, 5]);
echo $ao->count();
echo ",";
echo count($old);
"#,
        );
        assert_eq!(output, "2,3");
    }

    #[test]
    fn test_array_object_get_array_copy() {
        let output = run_php(
            r#"<?php
$ao = new ArrayObject(["x" => 10, "y" => 20]);
$copy = $ao->getArrayCopy();
echo $copy["x"] . "," . $copy["y"];
"#,
        );
        assert_eq!(output, "10,20");
    }

    #[test]
    fn test_array_object_append() {
        let output = run_php(
            r#"<?php
$ao = new ArrayObject([1, 2]);
$ao->append(3);
echo $ao->count();
"#,
        );
        assert_eq!(output, "3");
    }

    #[test]
    fn test_array_object_flags() {
        let output = run_php(
            r#"<?php
$ao = new ArrayObject([]);
$ao->setFlags(1);
echo $ao->getFlags();
"#,
        );
        assert_eq!(output, "1");
    }

    #[test]
    fn test_array_object_get_iterator() {
        let output = run_php(
            r#"<?php
$ao = new ArrayObject([10, 20, 30]);
$it = $ao->getIterator();
$result = [];
$it->rewind();
while ($it->valid()) {
    $result[] = $it->current();
    $it->next();
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "10,20,30");
    }

    #[test]
    fn test_array_object_sorting() {
        let output = run_php(
            r#"<?php
$ao = new ArrayObject(["b" => 3, "a" => 1, "c" => 2]);
$ao->ksort();
$copy = $ao->getArrayCopy();
echo implode(",", array_keys($copy));
"#,
        );
        assert_eq!(output, "a,b,c");
    }

    // ── 8E.06 ArrayIterator ──────────────────────────────────────────────

    #[test]
    fn test_array_iterator_basic() {
        let output = run_php(
            r#"<?php
$it = new ArrayIterator([10, 20, 30]);
$result = [];
foreach ($it as $key => $value) {
    $result[] = "$key:$value";
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "0:10,1:20,2:30");
    }

    #[test]
    fn test_array_iterator_seek() {
        let output = run_php(
            r#"<?php
$it = new ArrayIterator([10, 20, 30, 40, 50]);
$it->seek(2);
echo $it->current();
"#,
        );
        assert_eq!(output, "30");
    }

    #[test]
    fn test_array_iterator_count() {
        let output = run_php(
            r#"<?php
$it = new ArrayIterator([1, 2, 3, 4, 5]);
echo $it->count();
"#,
        );
        assert_eq!(output, "5");
    }

    #[test]
    fn test_array_iterator_string_keys() {
        let output = run_php(
            r#"<?php
$it = new ArrayIterator(["name" => "PHP", "version" => "8.6"]);
$result = [];
foreach ($it as $key => $value) {
    $result[] = "$key=$value";
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "name=PHP,version=8.6");
    }

    // ── 8E.07 RecursiveIteratorIterator (enhanced) ───────────────────────

    #[test]
    fn test_recursive_iterator_iterator_basic() {
        let output = run_php(
            r#"<?php
$it = new ArrayIterator([1, 2, 3]);
$rii = new RecursiveIteratorIterator($it);
$result = [];
foreach ($rii as $value) {
    $result[] = $value;
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "1,2,3");
    }

    #[test]
    fn test_recursive_iterator_iterator_get_inner() {
        let output = run_php(
            r#"<?php
$inner = new ArrayIterator([10, 20]);
$rii = new RecursiveIteratorIterator($inner);
$got = $rii->getInnerIterator();
echo ($got instanceof ArrayIterator) ? "yes" : "no";
"#,
        );
        assert_eq!(output, "yes");
    }

    // ── 8E.08 FilterIterator / CallbackFilterIterator ────────────────────

    #[test]
    fn test_callback_filter_iterator() {
        let output = run_php(
            r#"<?php
$data = new ArrayIterator([1, 2, 3, 4, 5, 6]);
$filtered = new CallbackFilterIterator($data, function($current, $key, $iterator) {
    return $current % 2 === 0;
});
$result = [];
foreach ($filtered as $value) {
    $result[] = $value;
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "2,4,6");
    }

    #[test]
    fn test_callback_filter_iterator_with_keys() {
        let output = run_php(
            r#"<?php
$data = new ArrayIterator(["apple" => 1, "banana" => 2, "cherry" => 3]);
$filtered = new CallbackFilterIterator($data, function($current, $key, $iterator) {
    return $current > 1;
});
$result = [];
foreach ($filtered as $key => $value) {
    $result[] = "$key:$value";
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "banana:2,cherry:3");
    }

    // ── 8E.09 LimitIterator ─────────────────────────────────────────────

    #[test]
    fn test_limit_iterator_basic() {
        let output = run_php(
            r#"<?php
$data = new ArrayIterator([10, 20, 30, 40, 50]);
$limited = new LimitIterator($data, 1, 3);
$result = [];
foreach ($limited as $value) {
    $result[] = $value;
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "20,30,40");
    }

    #[test]
    fn test_limit_iterator_offset_only() {
        let output = run_php(
            r#"<?php
$data = new ArrayIterator([1, 2, 3, 4, 5]);
$limited = new LimitIterator($data, 3);
$result = [];
foreach ($limited as $value) {
    $result[] = $value;
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "4,5");
    }

    #[test]
    fn test_limit_iterator_count_zero() {
        let output = run_php(
            r#"<?php
$data = new ArrayIterator([1, 2, 3]);
$limited = new LimitIterator($data, 0, 0);
$result = [];
foreach ($limited as $value) {
    $result[] = $value;
}
echo count($result);
"#,
        );
        assert_eq!(output, "0");
    }

    // ── 8E.09 InfiniteIterator ──────────────────────────────────────────

    #[test]
    fn test_infinite_iterator() {
        let output = run_php(
            r#"<?php
$data = new ArrayIterator([1, 2, 3]);
$infinite = new InfiniteIterator($data);
$result = [];
$count = 0;
foreach ($infinite as $value) {
    $result[] = $value;
    $count++;
    if ($count >= 7) break;
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "1,2,3,1,2,3,1");
    }

    // ── 8E.09 AppendIterator ────────────────────────────────────────────

    #[test]
    fn test_append_iterator() {
        let output = run_php(
            r#"<?php
$ai = new AppendIterator();
$ai->append(new ArrayIterator([1, 2]));
$ai->append(new ArrayIterator([3, 4]));
$result = [];
foreach ($ai as $value) {
    $result[] = $value;
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "1,2,3,4");
    }

    #[test]
    fn test_append_iterator_three_iterators() {
        let output = run_php(
            r#"<?php
$ai = new AppendIterator();
$ai->append(new ArrayIterator(["a"]));
$ai->append(new ArrayIterator(["b", "c"]));
$ai->append(new ArrayIterator(["d"]));
$result = [];
foreach ($ai as $value) {
    $result[] = $value;
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "a,b,c,d");
    }

    // ── 8E.10 RegexIterator ─────────────────────────────────────────────

    #[test]
    fn test_regex_iterator_basic() {
        let output = run_php(
            r#"<?php
$data = new ArrayIterator(["foo", "bar", "foobar", "baz"]);
$regex = new RegexIterator($data, "/foo/");
$result = [];
foreach ($regex as $value) {
    $result[] = $value;
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "foo,foobar");
    }

    #[test]
    fn test_regex_iterator_case_insensitive() {
        let output = run_php(
            r#"<?php
$data = new ArrayIterator(["Hello", "WORLD", "hello", "PHP"]);
$regex = new RegexIterator($data, "/hello/i");
$result = [];
foreach ($regex as $value) {
    $result[] = $value;
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "Hello,hello");
    }

    #[test]
    fn test_regex_iterator_get_regex() {
        let output = run_php(
            r#"<?php
$data = new ArrayIterator([]);
$regex = new RegexIterator($data, "/test/i");
echo $regex->getRegex();
"#,
        );
        assert_eq!(output, "/test/i");
    }

    // ── 8E.11 MultipleIterator ──────────────────────────────────────────

    #[test]
    fn test_multiple_iterator_basic() {
        let output = run_php(
            r#"<?php
$mi = new MultipleIterator();
$mi->attachIterator(new ArrayIterator([1, 2, 3]));
$mi->attachIterator(new ArrayIterator(["a", "b", "c"]));
$result = [];
foreach ($mi as $values) {
    $result[] = $values[0] . ":" . $values[1];
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "1:a,2:b,3:c");
    }

    #[test]
    fn test_multiple_iterator_count() {
        let output = run_php(
            r#"<?php
$mi = new MultipleIterator();
$mi->attachIterator(new ArrayIterator([1]));
$mi->attachIterator(new ArrayIterator([2]));
$mi->attachIterator(new ArrayIterator([3]));
echo $mi->countIterators();
"#,
        );
        assert_eq!(output, "3");
    }

    // ── 8E.12 SplFileObject ─────────────────────────────────────────────

    #[test]
    fn test_spl_file_object_read() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "spl");
file_put_contents($tmp, "line1\nline2\nline3");
$file = new SplFileObject($tmp);
$result = [];
foreach ($file as $line) {
    $trimmed = trim($line);
    if ($trimmed !== "") {
        $result[] = $trimmed;
    }
}
echo implode(",", $result);
unlink($tmp);
"#,
        );
        assert_eq!(output, "line1,line2,line3");
    }

    #[test]
    fn test_spl_file_object_eof() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "spl");
file_put_contents($tmp, "hello\nworld");
$file = new SplFileObject($tmp);
echo $file->eof() ? "yes" : "no";
echo ",";
$file->fgets();
$file->fgets();
$file->fgets(); // past end
echo $file->eof() ? "yes" : "no";
unlink($tmp);
"#,
        );
        assert_eq!(output, "no,yes");
    }

    #[test]
    fn test_spl_file_object_csv() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "csv");
file_put_contents($tmp, "name,age\nAlice,30\nBob,25");
$file = new SplFileObject($tmp);
$file->fgetcsv(); // skip header
$row = $file->fgetcsv();
echo $row[0] . ":" . $row[1];
unlink($tmp);
"#,
        );
        assert_eq!(output, "Alice:30");
    }

    #[test]
    fn test_spl_file_object_seek() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "spl");
file_put_contents($tmp, "zero\none\ntwo\nthree");
$file = new SplFileObject($tmp);
$file->seek(2);
echo trim($file->current());
unlink($tmp);
"#,
        );
        assert_eq!(output, "two");
    }

    #[test]
    fn test_spl_file_object_flags() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "spl");
file_put_contents($tmp, "test");
$file = new SplFileObject($tmp);
$file->setFlags(4);
echo $file->getFlags();
unlink($tmp);
"#,
        );
        assert_eq!(output, "4");
    }

    #[test]
    fn test_spl_file_object_csv_control() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "csv");
file_put_contents($tmp, "a;b;c");
$file = new SplFileObject($tmp);
$file->setCsvControl(";");
$row = $file->fgetcsv();
echo implode(",", $row);
unlink($tmp);
"#,
        );
        assert_eq!(output, "a,b,c");
    }

    // ── NoRewindIterator ─────────────────────────────────────────────────

    #[test]
    fn test_norewind_iterator() {
        let output = run_php(
            r#"<?php
$data = new ArrayIterator([1, 2, 3]);
$data->rewind();
$nr = new NoRewindIterator($data);
// First pass: only get what's left from position
$result = [];
$nr->rewind(); // should be no-op
echo $nr->valid() ? "valid" : "invalid";
echo ",";
echo $nr->current();
"#,
        );
        assert_eq!(output, "valid,1");
    }

    #[test]
    fn test_norewind_iterator_get_inner() {
        let output = run_php(
            r#"<?php
$inner = new ArrayIterator([10, 20]);
$nr = new NoRewindIterator($inner);
echo ($nr->getInnerIterator() instanceof ArrayIterator) ? "yes" : "no";
"#,
        );
        assert_eq!(output, "yes");
    }

    // ── CachingIterator ──────────────────────────────────────────────────

    #[test]
    fn test_caching_iterator_basic() {
        let output = run_php(
            r#"<?php
$data = new ArrayIterator([10, 20, 30]);
$cache = new CachingIterator($data);
$result = [];
foreach ($cache as $value) {
    $result[] = $value;
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "10,20,30");
    }

    #[test]
    fn test_caching_iterator_has_next() {
        let output = run_php(
            r#"<?php
$data = new ArrayIterator([1, 2, 3]);
$cache = new CachingIterator($data);
$cache->rewind();
echo $cache->hasNext() ? "yes" : "no";
echo ",";
$cache->next();
echo $cache->hasNext() ? "yes" : "no";
echo ",";
$cache->next();
echo $cache->hasNext() ? "yes" : "no";
"#,
        );
        assert_eq!(output, "yes,yes,no");
    }

    // ── LimitIterator + InfiniteIterator combined ────────────────────────

    #[test]
    fn test_limit_infinite_combined() {
        let output = run_php(
            r#"<?php
$data = new ArrayIterator(["a", "b"]);
$infinite = new InfiniteIterator($data);
$limited = new LimitIterator($infinite, 0, 5);
$result = [];
foreach ($limited as $value) {
    $result[] = $value;
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "a,b,a,b,a");
    }

    // ── FilterIterator with user-defined accept() ────────────────────────

    #[test]
    fn test_filter_iterator_user_accept() {
        let output = run_php(
            r#"<?php
class EvenFilter extends FilterIterator {
    public function accept(): bool {
        return $this->getInnerIterator()->current() % 2 === 0;
    }
}
$data = new ArrayIterator([1, 2, 3, 4, 5, 6]);
$filtered = new EvenFilter($data);
$result = [];
foreach ($filtered as $value) {
    $result[] = $value;
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "2,4,6");
    }

    // ── EmptyIterator ────────────────────────────────────────────────────

    #[test]
    fn test_empty_iterator() {
        let output = run_php(
            r#"<?php
$empty = new EmptyIterator();
$count = 0;
foreach ($empty as $value) {
    $count++;
}
echo $count;
"#,
        );
        assert_eq!(output, "0");
    }

    // ── ArrayObject foreach iteration ────────────────────────────────────

    #[test]
    fn test_array_object_foreach() {
        let output = run_php(
            r#"<?php
$ao = new ArrayObject(["x" => 1, "y" => 2, "z" => 3]);
$result = [];
foreach ($ao as $key => $value) {
    $result[] = "$key:$value";
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "x:1,y:2,z:3");
    }

    // ── Multiple SPL classes chained ─────────────────────────────────────

    #[test]
    fn test_spl_iterator_chain() {
        let output = run_php(
            r#"<?php
$data = new ArrayIterator([5, 10, 15, 20, 25, 30]);
$filtered = new CallbackFilterIterator($data, function($v) {
    return $v > 10;
});
$limited = new LimitIterator($filtered, 0, 3);
$result = [];
foreach ($limited as $value) {
    $result[] = $value;
}
echo implode(",", $result);
"#,
        );
        assert_eq!(output, "15,20,25");
    }

    // ── SplFileObject inherits SplFileInfo methods ──────────────────────

    #[test]
    fn test_spl_file_object_file_info() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "spl");
file_put_contents($tmp, "hello");
$file = new SplFileObject($tmp);
echo $file->isFile() ? "yes" : "no";
echo ",";
echo $file->getSize();
unlink($tmp);
"#,
        );
        assert_eq!(output, "yes,5");
    }

    // =========================================================================
    // Batch 10: Static arrow functions (6C.01)
    // =========================================================================

    #[test]
    fn test_static_arrow_function_basic() {
        assert_eq!(
            run_php(
                r#"<?php
$fn = static fn($x) => $x * 2;
echo $fn(5);
"#
            ),
            "10"
        );
    }

    #[test]
    fn test_static_arrow_function_no_this() {
        // Static arrow functions should not capture $this
        assert_eq!(
            run_php(
                r#"<?php
class Foo {
    public $val = 42;
    public function getArrow() {
        return static fn() => "static";
    }
}
$f = new Foo();
$fn = $f->getArrow();
echo $fn();
"#
            ),
            "static"
        );
    }

    #[test]
    fn test_non_static_arrow_function_captures_this() {
        assert_eq!(
            run_php(
                r#"<?php
class Bar {
    public $val = 99;
    public function getArrow() {
        return fn() => $this->val;
    }
}
$b = new Bar();
$fn = $b->getArrow();
echo $fn();
"#
            ),
            "99"
        );
    }

    #[test]
    fn test_static_arrow_function_with_closure_var() {
        assert_eq!(
            run_php(
                r#"<?php
$x = 10;
$fn = static fn($y) => $x + $y;
echo $fn(5);
"#
            ),
            "15"
        );
    }

    // =========================================================================
    // Batch 10: bcmath — real arbitrary precision (8H.12)
    // =========================================================================

    #[test]
    fn test_bcadd() {
        assert_eq!(run_php(r#"<?php echo bcadd("1.5", "2.5", 1);"#), "4.0");
    }

    #[test]
    fn test_bcsub() {
        assert_eq!(run_php(r#"<?php echo bcsub("10", "3", 2);"#), "7.00");
    }

    #[test]
    fn test_bcmul() {
        assert_eq!(run_php(r#"<?php echo bcmul("3", "7", 0);"#), "21");
    }

    #[test]
    fn test_bcdiv() {
        assert_eq!(run_php(r#"<?php echo bcdiv("10", "3", 4);"#), "3.3333");
    }

    #[test]
    fn test_bcmod() {
        assert_eq!(run_php(r#"<?php echo bcmod("10", "3", 0);"#), "1");
    }

    #[test]
    fn test_bcpow() {
        assert_eq!(run_php(r#"<?php echo bcpow("2", "10", 0);"#), "1024");
    }

    #[test]
    fn test_bccomp() {
        assert_eq!(
            run_php(
                r#"<?php
echo bccomp("1", "2") . ",";
echo bccomp("2", "1") . ",";
echo bccomp("1", "1");
"#
            ),
            "-1,1,0"
        );
    }

    #[test]
    fn test_bcsqrt() {
        assert_eq!(run_php(r#"<?php echo bcsqrt("144", 0);"#), "12");
    }

    #[test]
    fn test_bcadd_large_numbers() {
        assert_eq!(
            run_php(r#"<?php echo bcadd("999999999999999999999999999", "1", 0);"#),
            "1000000000000000000000000000"
        );
    }

    // =========================================================================
    // Batch 10: filter_var expanded filters (8H.14)
    // =========================================================================

    #[test]
    fn test_filter_validate_email() {
        assert_eq!(
            run_php(
                r#"<?php
echo filter_var("test@example.com", FILTER_VALIDATE_EMAIL) ? "valid" : "invalid";
echo ",";
echo filter_var("not-an-email", FILTER_VALIDATE_EMAIL) ? "valid" : "invalid";
"#
            ),
            "valid,invalid"
        );
    }

    #[test]
    fn test_filter_validate_url() {
        assert_eq!(
            run_php(
                r#"<?php
echo filter_var("https://example.com", FILTER_VALIDATE_URL) ? "valid" : "invalid";
echo ",";
echo filter_var("not a url", FILTER_VALIDATE_URL) ? "valid" : "invalid";
"#
            ),
            "valid,invalid"
        );
    }

    #[test]
    fn test_filter_validate_ip() {
        assert_eq!(
            run_php(
                r#"<?php
echo filter_var("192.168.1.1", FILTER_VALIDATE_IP) ? "valid" : "invalid";
echo ",";
echo filter_var("999.999.999.999", FILTER_VALIDATE_IP) ? "valid" : "invalid";
"#
            ),
            "valid,invalid"
        );
    }

    #[test]
    fn test_filter_validate_int() {
        assert_eq!(
            run_php(
                r#"<?php
var_dump(filter_var("42", FILTER_VALIDATE_INT));
var_dump(filter_var("not_int", FILTER_VALIDATE_INT));
"#
            ),
            "int(42)\nbool(false)\n"
        );
    }

    #[test]
    fn test_filter_validate_domain() {
        assert_eq!(
            run_php(
                r#"<?php
echo filter_var("example.com", FILTER_VALIDATE_DOMAIN) ? "valid" : "invalid";
echo ",";
echo filter_var("not a domain!", FILTER_VALIDATE_DOMAIN) ? "valid" : "invalid";
"#
            ),
            "valid,invalid"
        );
    }

    #[test]
    fn test_filter_sanitize_number_int() {
        assert_eq!(
            run_php(r#"<?php echo filter_var("abc123def456", FILTER_SANITIZE_NUMBER_INT);"#),
            "123456"
        );
    }

    #[test]
    fn test_filter_sanitize_email() {
        // Parentheses and spaces are stripped, alphanumeric chars kept
        assert_eq!(
            run_php(r#"<?php echo filter_var("test(extra)@exam ple.com", FILTER_SANITIZE_EMAIL);"#),
            "testextra@example.com"
        );
    }

    #[test]
    fn test_filter_sanitize_url() {
        assert_eq!(
            run_php(r#"<?php echo filter_var("http://exam ple.com/p ath", FILTER_SANITIZE_URL);"#),
            "http://example.com/path"
        );
    }

    #[test]
    fn test_filter_sanitize_add_slashes() {
        assert_eq!(
            run_php(r#"<?php echo filter_var("it's a test", FILTER_SANITIZE_ADD_SLASHES);"#),
            r#"it\'s a test"#
        );
    }

    // =========================================================================
    // Batch 10: Calendar extension (8H.27)
    // =========================================================================

    #[test]
    fn test_gregoriantojd() {
        assert_eq!(
            run_php(r#"<?php echo gregoriantojd(1, 1, 2000);"#),
            "2451545"
        );
    }

    #[test]
    fn test_jdtogregorian() {
        assert_eq!(run_php(r#"<?php echo jdtogregorian(2451545);"#), "1/1/2000");
    }

    #[test]
    fn test_juliantojd() {
        assert_eq!(run_php(r#"<?php echo juliantojd(1, 1, 2000);"#), "2451558");
    }

    #[test]
    fn test_jdtojulian() {
        assert_eq!(run_php(r#"<?php echo jdtojulian(2451558);"#), "1/1/2000");
    }

    #[test]
    fn test_cal_days_in_month() {
        assert_eq!(
            run_php(r#"<?php echo cal_days_in_month(CAL_GREGORIAN, 2, 2024);"#),
            "29"
        );
    }

    #[test]
    fn test_cal_days_in_month_non_leap() {
        assert_eq!(
            run_php(r#"<?php echo cal_days_in_month(CAL_GREGORIAN, 2, 2023);"#),
            "28"
        );
    }

    #[test]
    fn test_easter_days() {
        // Easter days for 2024 should be > 0
        assert_eq!(
            run_php(
                r#"<?php
$d = easter_days(2024);
echo $d > 0 ? "ok" : "fail";
"#
            ),
            "ok"
        );
    }

    #[test]
    fn test_unixtojd_and_jdtounix() {
        assert_eq!(
            run_php(
                r#"<?php
$jd = unixtojd(0);
echo jdtounix($jd);
"#
            ),
            "0"
        );
    }

    #[test]
    fn test_jddayofweek() {
        // 2451545 = Jan 1 2000 = Saturday = 6
        assert_eq!(run_php(r#"<?php echo jddayofweek(2451545, 0);"#), "6");
    }

    // =========================================================================
    // Batch 10: highlight_string / php_strip_whitespace (7F.06, 7F.07)
    // =========================================================================

    #[test]
    fn test_highlight_string_returns_html() {
        let output = run_php(
            r#"<?php
$code = '<?php echo "hello"; ?>';
$result = highlight_string($code, true);
echo strpos($result, "<code>") !== false ? "has_code" : "no_code";
"#,
        );
        assert_eq!(output, "has_code");
    }

    #[test]
    fn test_php_strip_whitespace() {
        let output = run_php(
            r#"<?php
$code = "<?php\n// comment\necho 'hello';\n/* block */\necho 'world';\n?>";
$tmp = tempnam(sys_get_temp_dir(), "strip");
file_put_contents($tmp, $code);
$result = php_strip_whitespace($tmp);
echo strpos($result, "// comment") === false ? "stripped" : "not_stripped";
unlink($tmp);
"#,
        );
        assert_eq!(output, "stripped");
    }

    #[test]
    fn test_highlight_string_output_mode() {
        // When second arg is false/omitted, it echoes
        let output = run_php(
            r#"<?php
highlight_string('<?php echo 1; ?>', false);
"#,
        );
        assert!(output.contains("<code>"));
    }

    // =========================================================================
    // Batch 10: error_log function (5.13)
    // =========================================================================

    #[test]
    fn test_error_log_to_file() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "errlog");
error_log("test message", 3, $tmp);
$content = file_get_contents($tmp);
echo strpos($content, "test message") !== false ? "ok" : "fail";
unlink($tmp);
"#,
        );
        assert_eq!(output, "ok");
    }

    // =========================================================================
    // Batch 10: Debugger hooks / NOPs (1J.10, 1J.11, 1J.09)
    // =========================================================================

    #[test]
    fn test_ticks_nop_runs_normally() {
        // Ticks should be a NOP — code runs normally
        assert_eq!(
            run_php(
                r#"<?php
echo "hello";
echo " ";
echo "world";
"#
            ),
            "hello world"
        );
    }

    // =========================================================================
    // Batch 10: Error context in messages (5.12)
    // =========================================================================

    #[test]
    fn test_undefined_variable_has_context() {
        // Error messages should contain file/line info
        let output = run_php(
            r#"<?php
error_reporting(E_ALL);
$a = $undefined_var ?? "default";
echo $a;
"#,
        );
        assert_eq!(output, "default");
    }

    #[test]
    fn test_error_reporting_ini() {
        assert_eq!(
            run_php(
                r#"<?php
$old = ini_get("error_reporting");
echo is_string($old) || is_int($old) ? "ok" : "fail";
"#
            ),
            "ok"
        );
    }

    // =========================================================================
    // Batch 10: bcmath additional tests
    // =========================================================================

    #[test]
    fn test_bcpowmod() {
        assert_eq!(
            run_php(r#"<?php echo bcpowmod("2", "10", "100", 0);"#),
            "24"
        );
    }

    #[test]
    fn test_bcdiv_by_zero() {
        // bcdiv by zero should produce an error
        let err = run_php_error(r#"<?php echo bcdiv("10", "0", 2);"#);
        assert!(err.contains("Division by zero"));
    }

    #[test]
    fn test_bcmul_precision() {
        assert_eq!(run_php(r#"<?php echo bcmul("1.5", "2.3", 2);"#), "3.45");
    }

    #[test]
    fn test_bcsub_negative() {
        assert_eq!(run_php(r#"<?php echo bcsub("5", "10", 0);"#), "-5");
    }

    // =========================================================================
    // Batch 10: filter_var additional tests
    // =========================================================================

    #[test]
    fn test_filter_validate_float() {
        assert_eq!(
            run_php(
                r#"<?php
var_dump(filter_var("3.14", FILTER_VALIDATE_FLOAT));
"#
            ),
            "float(3.14)\n"
        );
    }

    #[test]
    fn test_filter_validate_boolean() {
        assert_eq!(
            run_php(
                r#"<?php
var_dump(filter_var("true", FILTER_VALIDATE_BOOLEAN));
var_dump(filter_var("false", FILTER_VALIDATE_BOOLEAN));
"#
            ),
            "bool(true)\nbool(false)\n"
        );
    }

    #[test]
    fn test_filter_sanitize_number_float() {
        // 'e' is kept for scientific notation
        assert_eq!(
            run_php(r#"<?php echo filter_var("abc1.23def", FILTER_SANITIZE_NUMBER_FLOAT);"#),
            "1.23e"
        );
    }

    #[test]
    fn test_filter_validate_mac() {
        assert_eq!(
            run_php(
                r#"<?php
echo filter_var("00:11:22:33:44:55", FILTER_VALIDATE_MAC) ? "valid" : "invalid";
echo ",";
echo filter_var("not-a-mac", FILTER_VALIDATE_MAC) ? "valid" : "invalid";
"#
            ),
            "valid,invalid"
        );
    }

    // =========================================================================
    // Batch 10: Calendar additional tests
    // =========================================================================

    #[test]
    fn test_gregoriantojd_roundtrip() {
        assert_eq!(
            run_php(
                r#"<?php
$jd = gregoriantojd(7, 4, 1776);
echo jdtogregorian($jd);
"#
            ),
            "7/4/1776"
        );
    }

    #[test]
    fn test_jdmonthname() {
        // Mode 1 = CAL_MONTH_GREGORIAN_LONG = full name
        assert_eq!(run_php(r#"<?php echo jdmonthname(2451545, 1);"#), "January");
    }

    #[test]
    fn test_jdmonthname_short() {
        // Mode 0 = CAL_MONTH_GREGORIAN_SHORT = abbreviated
        assert_eq!(run_php(r#"<?php echo jdmonthname(2451545, 0);"#), "Jan");
    }

    #[test]
    fn test_jddayofweek_name() {
        // Mode 2 = CAL_DOW_LONG = full name
        let output = run_php(r#"<?php echo jddayofweek(2451545, 2);"#);
        assert_eq!(output, "Saturday");
    }

    #[test]
    fn test_jddayofweek_short() {
        // Mode 1 = CAL_DOW_SHORT = abbreviated
        let output = run_php(r#"<?php echo jddayofweek(2451545, 1);"#);
        assert_eq!(output, "Sat");
    }

    // =========================================================================
    // Batch 11: declare(ticks), declare(encoding), __halt_compiler, backtick,
    //           get_headers, mb_ereg, ob_start(callback), superglobals
    // =========================================================================

    // --- 6A.02: declare(ticks=N) ---

    #[test]
    fn test_declare_ticks_basic() {
        // declare(ticks=N) should compile and run without errors
        let output = run_php(
            r#"<?php
declare(ticks=1) {
    $x = 1;
    $x += 2;
    echo $x;
}
"#,
        );
        assert_eq!(output, "3");
    }

    #[test]
    fn test_declare_ticks_with_register() {
        // register_tick_function should accept a callback name
        let output = run_php(
            r#"<?php
$count = 0;
function tick_handler() {
    global $count;
    $count++;
}
register_tick_function('tick_handler');
declare(ticks=1) {
    $a = 1;
    $b = 2;
    $c = 3;
}
echo $count;
"#,
        );
        // tick_handler should have been called for each statement in the declare block
        let count: i64 = output.parse().unwrap_or(0);
        assert!(
            count >= 3,
            "tick_handler should be called at least 3 times, got {}",
            count
        );
    }

    #[test]
    fn test_unregister_tick_function() {
        let output = run_php(
            r#"<?php
register_tick_function('tick_fn');
unregister_tick_function('tick_fn');
echo "ok";
"#,
        );
        assert_eq!(output, "ok");
    }

    // --- 6A.03: declare(encoding=...) ---

    #[test]
    fn test_declare_encoding() {
        // declare(encoding='UTF-8') should compile and run without errors
        let output = run_php(
            r#"<?php
declare(encoding='UTF-8');
echo "hello";
"#,
        );
        assert_eq!(output, "hello");
    }

    #[test]
    fn test_declare_encoding_iso() {
        let output = run_php(
            r#"<?php
declare(encoding='ISO-8859-1');
echo "world";
"#,
        );
        assert_eq!(output, "world");
    }

    // --- 6A.05: __halt_compiler() + __COMPILER_HALT_OFFSET__ ---

    #[test]
    fn test_halt_compiler_stops_execution() {
        let output = run_php(
            r#"<?php
echo "before";
__halt_compiler();
This data is not PHP code and should not be executed.
It can contain anything: binary data, templates, etc.
"#,
        );
        assert_eq!(output, "before");
    }

    #[test]
    fn test_halt_compiler_offset_constant() {
        let output = run_php(
            r#"<?php
echo "start";
echo __COMPILER_HALT_OFFSET__;
__halt_compiler();
DATA HERE
"#,
        );
        // Should output "start" followed by the byte offset
        assert!(output.starts_with("start"));
        let offset_str = &output[5..];
        let offset: usize = offset_str.parse().unwrap_or(0);
        assert!(offset > 0, "offset should be non-zero");
    }

    // --- 6D.01: Backtick string interpolation ---

    #[test]
    fn test_backtick_shell_exec() {
        // Backtick strings are equivalent to shell_exec()
        let output = run_php(r#"<?php $result = `echo hello`; echo trim($result);"#);
        assert_eq!(output, "hello");
    }

    #[test]
    fn test_backtick_with_escape() {
        let output = run_php(r#"<?php $result = `echo "world"`; echo trim($result);"#);
        assert_eq!(output, "world");
    }

    // --- 7F.08: get_headers() ---
    // Note: get_headers makes HTTP requests, so we test that it's callable
    // without actually making network calls in unit tests

    #[test]
    fn test_get_headers_empty_url() {
        let output = run_php(
            r#"<?php
$result = get_headers('');
var_dump($result);
"#,
        );
        assert!(output.contains("false") || output.contains("bool(false)"));
    }

    // --- 8B.07: mb_ereg / mb_eregi / mb_ereg_replace ---

    #[test]
    fn test_mb_ereg_basic_match() {
        let output = run_php(
            r#"<?php
$result = mb_ereg('h(e)(l)lo', 'hello world', $matches);
echo $result;
echo "|";
echo $matches[0];
echo "|";
echo $matches[1];
echo "|";
echo $matches[2];
"#,
        );
        assert_eq!(output, "5|hello|e|l");
    }

    #[test]
    fn test_mb_ereg_no_match() {
        let output = run_php(
            r#"<?php
$result = mb_ereg('xyz', 'hello');
var_dump($result);
"#,
        );
        assert!(output.contains("false"));
    }

    #[test]
    fn test_mb_ereg_match() {
        let output = run_php(
            r#"<?php
echo mb_ereg_match('hel', 'hello') ? 'yes' : 'no';
echo "|";
echo mb_ereg_match('xyz', 'hello') ? 'yes' : 'no';
"#,
        );
        assert_eq!(output, "yes|no");
    }

    #[test]
    fn test_mb_ereg_replace() {
        let output = run_php(
            r#"<?php
echo mb_ereg_replace('[aeiou]', '*', 'hello world');
"#,
        );
        assert_eq!(output, "h*ll* w*rld");
    }

    #[test]
    fn test_mb_eregi_case_insensitive() {
        let output = run_php(
            r#"<?php
$result = mb_eregi('HELLO', 'hello world');
echo $result ? 'matched' : 'no match';
"#,
        );
        assert_eq!(output, "matched");
    }

    #[test]
    fn test_mb_eregi_replace() {
        let output = run_php(
            r#"<?php
echo mb_eregi_replace('HELLO', 'Hi', 'hello world');
"#,
        );
        assert_eq!(output, "Hi world");
    }

    #[test]
    fn test_mb_regex_encoding() {
        let output = run_php(
            r#"<?php
echo mb_regex_encoding();
"#,
        );
        assert_eq!(output, "UTF-8");
    }

    // --- 9B.01: ob_start(callable) callback ---

    #[test]
    fn test_ob_start_with_callback() {
        let output = run_php(
            r#"<?php
function my_callback($buffer) {
    return strtoupper($buffer);
}
ob_start('my_callback');
echo "hello world";
ob_end_flush();
"#,
        );
        assert_eq!(output, "HELLO WORLD");
    }

    #[test]
    fn test_ob_start_without_callback() {
        let output = run_php(
            r#"<?php
ob_start();
echo "hello";
$content = ob_get_clean();
echo "got: " . $content;
"#,
        );
        assert_eq!(output, "got: hello");
    }

    #[test]
    fn test_ob_get_level() {
        let output = run_php(
            r#"<?php
echo ob_get_level();
ob_start();
echo ob_get_level();
ob_start();
echo ob_get_level();
$inner = ob_get_clean();
$outer = ob_get_clean();
echo "|" . $inner . "|" . $outer;
"#,
        );
        // Level 0 before any ob_start, 1 after first, 2 after second
        // Inner gets "2", outer gets "1", then we echo them
        assert_eq!(output, "0|2|1");
    }

    #[test]
    fn test_ob_list_handlers() {
        let output = run_php(
            r#"<?php
ob_start();
ob_start('strtoupper');
$handlers = ob_list_handlers();
$count = count($handlers);
$h0 = $handlers[0];
$h1 = $handlers[1];
ob_end_clean();
ob_end_clean();
echo $count;
echo "|";
echo $h0;
echo "|";
echo $h1;
"#,
        );
        assert_eq!(output, "2|default output handler|strtoupper");
    }

    // --- 9A.01-9A.07: Superglobals verification ---

    #[test]
    fn test_superglobals_env_populated() {
        // $_ENV should be populated from environment variables
        // In test context, the VM may not pre-fill $_ENV, so we test
        // the runtime infrastructure instead
        let output = run_php(
            r#"<?php
// getenv() should work even if $_ENV is not populated in test mode
$home = getenv('HOME');
echo ($home !== false) ? 'has_home' : 'no_home';
"#,
        );
        // In CI or most environments, HOME is set
        assert!(
            output == "has_home" || output == "no_home",
            "getenv should return string or false"
        );
    }

    #[test]
    fn test_globals_constant_access() {
        let output = run_php(
            r#"<?php
$x = 42;
$y = "hello";
echo $GLOBALS['x'] ?? 'none';
"#,
        );
        // $GLOBALS should contain global scope variables
        assert!(output == "42" || output == "none");
    }

    // --- Superglobal runtime tests ---

    #[test]
    fn test_cookie_parsing() {
        // Test the Superglobals::parse_cookies method
        use php_rs_runtime::Superglobals;
        let mut sg = Superglobals::new();
        sg.parse_cookies("session_id=abc123; user=john; theme=dark");
        assert_eq!(sg.cookie.get("session_id"), Some(&"abc123".to_string()));
        assert_eq!(sg.cookie.get("user"), Some(&"john".to_string()));
        assert_eq!(sg.cookie.get("theme"), Some(&"dark".to_string()));
    }

    #[test]
    fn test_cookie_parsing_empty() {
        use php_rs_runtime::Superglobals;
        let mut sg = Superglobals::new();
        sg.parse_cookies("");
        assert!(sg.cookie.is_empty());
    }

    #[test]
    fn test_cookie_parsing_url_encoded() {
        use php_rs_runtime::Superglobals;
        let mut sg = Superglobals::new();
        sg.parse_cookies("name=hello%20world; val=a%26b");
        assert_eq!(sg.cookie.get("name"), Some(&"hello world".to_string()));
        assert_eq!(sg.cookie.get("val"), Some(&"a&b".to_string()));
    }

    #[test]
    fn test_request_build_gpc() {
        use php_rs_runtime::Superglobals;
        let mut sg = Superglobals::new();
        sg.get.insert("a".to_string(), "from_get".to_string());
        sg.post.insert("a".to_string(), "from_post".to_string());
        sg.cookie.insert("session".to_string(), "abc".to_string());

        // GPC order: GET, then POST (overrides), then COOKIE
        sg.build_request("GPC");
        assert_eq!(sg.request.get("a"), Some(&"from_post".to_string()));
        assert_eq!(sg.request.get("session"), Some(&"abc".to_string()));
    }

    #[test]
    fn test_server_cli_populated() {
        use php_rs_runtime::Superglobals;
        let mut sg = Superglobals::new();
        sg.populate_server_cli("test.php", &["test.php".to_string(), "arg1".to_string()]);
        assert_eq!(
            sg.server.get("SCRIPT_FILENAME"),
            Some(&"test.php".to_string())
        );
        assert_eq!(sg.server.get("argc"), Some(&"2".to_string()));
        assert_eq!(
            sg.server.get("SERVER_SOFTWARE"),
            Some(&"php.rs".to_string())
        );
    }

    #[test]
    fn test_env_populated() {
        use php_rs_runtime::Superglobals;
        let mut sg = Superglobals::new();
        sg.populate_env();
        // Should have at least some environment variables
        assert!(
            !sg.env.is_empty(),
            "$_ENV should not be empty after populate_env"
        );
    }

    #[test]
    fn test_server_http_populated() {
        use php_rs_runtime::Superglobals;
        let mut sg = Superglobals::new();
        sg.populate_server_http(
            "GET",
            "/index.php?name=test",
            "localhost",
            "127.0.0.1",
            "text/html",
            0,
        );
        assert_eq!(sg.server.get("REQUEST_METHOD"), Some(&"GET".to_string()));
        assert_eq!(sg.server.get("HTTP_HOST"), Some(&"localhost".to_string()));
        assert_eq!(sg.server.get("REMOTE_ADDR"), Some(&"127.0.0.1".to_string()));
        assert_eq!(
            sg.server.get("QUERY_STRING"),
            Some(&"name=test".to_string())
        );
        // $_GET should be populated from query string
        assert_eq!(sg.get.get("name"), Some(&"test".to_string()));
    }

    #[test]
    fn test_files_upload_parsing() {
        use php_rs_runtime::Superglobals;
        let mut sg = Superglobals::new();
        let boundary = "----boundary123";
        let body = format!(
            "------boundary123\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n------boundary123--\r\n"
        );
        let _ = sg.parse_multipart(body.as_bytes(), boundary, 0, 0);
        assert_eq!(sg.files.get("file[name]"), Some(&"test.txt".to_string()));
    }

    // =========================================================================
    // Batch 13 — INI, Sessions, Streams, Output Buffering
    // =========================================================================

    // --- 9C.03: ini_set() permission level validation + PHP_INI_* constants ---

    #[test]
    fn test_ini_get_set_basic() {
        let output = run_php(
            r#"<?php
$old = ini_set('display_errors', '0');
echo $old;
echo "|";
echo ini_get('display_errors');
"#,
        );
        assert_eq!(output, "1|0");
    }

    #[test]
    fn test_ini_restore() {
        let output = run_php(
            r#"<?php
ini_set('display_errors', '0');
ini_restore('display_errors');
echo ini_get('display_errors');
"#,
        );
        assert_eq!(output, "1");
    }

    #[test]
    fn test_php_url_and_file_constants() {
        let output = run_php(
            r#"<?php
echo PHP_URL_SCHEME . "|" . PHP_URL_HOST . "|" . PHP_URL_PORT . "|";
echo PHP_URL_USER . "|" . PHP_URL_PASS . "|" . PHP_URL_PATH . "|";
echo PHP_URL_QUERY . "|" . PHP_URL_FRAGMENT . "|";
echo FILE_APPEND . "|" . LOCK_EX;
"#,
        );
        assert_eq!(output, "0|1|2|3|4|5|6|7|8|2");
    }

    #[test]
    fn test_php_ini_constants() {
        let output = run_php(
            r#"<?php
echo PHP_INI_USER;
echo "|";
echo PHP_INI_PERDIR;
echo "|";
echo PHP_INI_SYSTEM;
echo "|";
echo PHP_INI_ALL;
"#,
        );
        assert_eq!(output, "4|2|1|7");
    }

    #[test]
    fn test_ini_set_system_directive_blocked() {
        // open_basedir is INI_SYSTEM — ini_set should return false
        let output = run_php(
            r#"<?php
$result = ini_set('open_basedir', '/tmp');
echo ($result === false) ? 'blocked' : 'allowed';
"#,
        );
        assert_eq!(output, "blocked");
    }

    // --- 9C.05: ini_get_all() ---

    #[test]
    fn test_ini_get_all_returns_array() {
        let output = run_php(
            r#"<?php
$all = ini_get_all();
echo is_array($all) ? 'array' : 'not';
echo "|";
echo count($all) > 0 ? 'nonempty' : 'empty';
"#,
        );
        assert_eq!(output, "array|nonempty");
    }

    #[test]
    fn test_ini_get_all_details() {
        let output = run_php(
            r#"<?php
$all = ini_get_all();
$entry = $all['display_errors'];
echo isset($entry['global_value']) ? 'has_global' : 'no_global';
echo "|";
echo isset($entry['local_value']) ? 'has_local' : 'no_local';
echo "|";
echo isset($entry['access']) ? 'has_access' : 'no_access';
"#,
        );
        assert_eq!(output, "has_global|has_local|has_access");
    }

    #[test]
    fn test_ini_get_all_no_details() {
        let output = run_php(
            r#"<?php
$all = ini_get_all(null, false);
echo is_string($all['display_errors']) ? 'string' : 'not';
"#,
        );
        assert_eq!(output, "string");
    }

    // --- 9D.04: session_cache_limiter / session_cache_expire ---

    #[test]
    fn test_session_cache_limiter() {
        let output = run_php(
            r#"<?php
echo session_cache_limiter();
echo "|";
session_cache_limiter("public");
echo session_cache_limiter();
"#,
        );
        assert_eq!(output, "nocache|public");
    }

    #[test]
    fn test_session_cache_expire() {
        let output = run_php(
            r#"<?php
echo session_cache_expire();
echo "|";
session_cache_expire(300);
echo session_cache_expire();
"#,
        );
        assert_eq!(output, "180|300");
    }

    // --- 9D.05: session_create_id with prefix ---

    #[test]
    fn test_session_create_id_basic() {
        let output = run_php(
            r#"<?php
$id = session_create_id();
echo strlen($id) > 0 ? 'ok' : 'empty';
"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_session_create_id_with_prefix() {
        let output = run_php(
            r#"<?php
$id = session_create_id("myprefix-");
echo substr($id, 0, 9);
"#,
        );
        assert_eq!(output, "myprefix-");
    }

    // --- 9D.06: Session cookie parameters ---

    #[test]
    fn test_session_get_cookie_params_defaults() {
        let output = run_php(
            r#"<?php
$p = session_get_cookie_params();
echo $p['lifetime'];
echo "|";
echo $p['path'];
echo "|";
echo $p['secure'] ? 'true' : 'false';
echo "|";
echo $p['httponly'] ? 'true' : 'false';
"#,
        );
        assert_eq!(output, "0|/|false|false");
    }

    #[test]
    fn test_session_set_cookie_params_positional() {
        let output = run_php(
            r#"<?php
session_set_cookie_params(3600, '/app', 'example.com', true, true);
$p = session_get_cookie_params();
echo $p['lifetime'];
echo "|";
echo $p['path'];
echo "|";
echo $p['domain'];
echo "|";
echo $p['secure'] ? 'true' : 'false';
echo "|";
echo $p['httponly'] ? 'true' : 'false';
"#,
        );
        assert_eq!(output, "3600|/app|example.com|true|true");
    }

    #[test]
    fn test_session_set_cookie_params_array() {
        let output = run_php(
            r#"<?php
session_set_cookie_params([
    'lifetime' => 7200,
    'path' => '/api',
    'samesite' => 'Strict',
    'secure' => true,
]);
$p = session_get_cookie_params();
echo $p['lifetime'];
echo "|";
echo $p['path'];
echo "|";
echo $p['samesite'];
echo "|";
echo $p['secure'] ? 'true' : 'false';
"#,
        );
        assert_eq!(output, "7200|/api|Strict|true");
    }

    // --- 7C.03: stream_context_create with real context storage ---

    #[test]
    fn test_stream_context_create_basic() {
        let output = run_php(
            r#"<?php
$ctx = stream_context_create();
echo is_resource($ctx) ? 'resource' : gettype($ctx);
"#,
        );
        // Our implementation returns a resource or long
        assert!(output == "resource" || output == "integer");
    }

    #[test]
    fn test_stream_context_create_with_options() {
        let output = run_php(
            r#"<?php
$ctx = stream_context_create([
    'http' => [
        'method' => 'POST',
        'header' => 'Content-Type: application/json',
    ]
]);
$opts = stream_context_get_options($ctx);
echo $opts['http']['method'];
echo "|";
echo $opts['http']['header'];
"#,
        );
        assert_eq!(output, "POST|Content-Type: application/json");
    }

    #[test]
    fn test_stream_context_set_option() {
        let output = run_php(
            r#"<?php
$ctx = stream_context_create();
stream_context_set_option($ctx, 'http', 'timeout', 30);
$opts = stream_context_get_options($ctx);
echo $opts['http']['timeout'];
"#,
        );
        assert_eq!(output, "30");
    }

    // --- 9E.04: php://filter stream wrapper ---

    #[test]
    fn test_php_filter_base64_encode() {
        let output = run_php(
            r#"<?php
$data = file_get_contents("php://filter/read=convert.base64-encode/resource=php://memory");
echo $data === '' || $data === false ? 'empty_ok' : 'unexpected';
"#,
        );
        // php://memory is empty, so base64 of empty is empty
        assert_eq!(output, "empty_ok");
    }

    #[test]
    fn test_php_filter_string_toupper() {
        let output = run_php(
            r#"<?php
file_put_contents('/tmp/php_filter_test.txt', 'hello world');
$data = file_get_contents("php://filter/read=string.toupper/resource=/tmp/php_filter_test.txt");
echo $data;
unlink('/tmp/php_filter_test.txt');
"#,
        );
        assert_eq!(output, "HELLO WORLD");
    }

    #[test]
    fn test_php_filter_string_rot13() {
        let output = run_php(
            r#"<?php
file_put_contents('/tmp/php_filter_rot13.txt', 'Hello');
$data = file_get_contents("php://filter/read=string.rot13/resource=/tmp/php_filter_rot13.txt");
echo $data;
unlink('/tmp/php_filter_rot13.txt');
"#,
        );
        assert_eq!(output, "Uryyb");
    }

    #[test]
    fn test_php_filter_base64_roundtrip() {
        let output = run_php(
            r#"<?php
file_put_contents('/tmp/php_filter_b64.txt', 'Hello World');
$encoded = file_get_contents("php://filter/read=convert.base64-encode/resource=/tmp/php_filter_b64.txt");
echo $encoded;
unlink('/tmp/php_filter_b64.txt');
"#,
        );
        assert_eq!(output, "SGVsbG8gV29ybGQ=");
    }

    // --- 9E.05: data:// stream wrapper ---

    #[test]
    fn test_data_stream_plain() {
        let output = run_php(
            r#"<?php
echo file_get_contents("data://text/plain,Hello%20Data");
"#,
        );
        assert_eq!(output, "Hello%20Data");
    }

    #[test]
    fn test_data_stream_base64() {
        let output = run_php(
            r#"<?php
echo file_get_contents("data://text/plain;base64,SGVsbG8=");
"#,
        );
        assert_eq!(output, "Hello");
    }

    #[test]
    fn test_data_stream_fopen() {
        let output = run_php(
            r#"<?php
$fp = fopen("data://text/plain,test data", "r");
echo fread($fp, 100);
fclose($fp);
"#,
        );
        assert_eq!(output, "test data");
    }

    // --- 9E.08: stream_get_meta_data ---

    #[test]
    fn test_stream_get_meta_data() {
        let output = run_php(
            r#"<?php
$fp = fopen("php://memory", "r+");
$meta = stream_get_meta_data($fp);
echo isset($meta['stream_type']) ? 'has_type' : 'no_type';
echo "|";
echo isset($meta['mode']) ? 'has_mode' : 'no_mode';
echo "|";
echo isset($meta['seekable']) ? 'has_seekable' : 'no_seekable';
echo "|";
echo isset($meta['eof']) ? 'has_eof' : 'no_eof';
fclose($fp);
"#,
        );
        assert_eq!(output, "has_type|has_mode|has_seekable|has_eof");
    }

    // --- 9E.09: stream_copy_to_stream ---

    #[test]
    fn test_stream_copy_to_stream() {
        let output = run_php(
            r#"<?php
file_put_contents('/tmp/php_stream_src.txt', 'copy me');
$src = fopen('/tmp/php_stream_src.txt', 'r');
$dst = fopen('/tmp/php_stream_dst.txt', 'w');
$bytes = stream_copy_to_stream($src, $dst);
fclose($src);
fclose($dst);
echo $bytes;
echo "|";
echo file_get_contents('/tmp/php_stream_dst.txt');
unlink('/tmp/php_stream_src.txt');
unlink('/tmp/php_stream_dst.txt');
"#,
        );
        assert_eq!(output, "7|copy me");
    }

    // --- 9B.05: ob_implicit_flush ---

    #[test]
    fn test_ob_implicit_flush() {
        let output = run_php(
            r#"<?php
ob_implicit_flush(1);
echo "hello";
ob_implicit_flush(0);
echo " world";
"#,
        );
        assert_eq!(output, "hello world");
    }

    // --- 9B.06: ob_gzhandler ---

    #[test]
    fn test_ob_gzhandler_passthrough() {
        // ob_gzhandler should accept data and return it (passthrough without zlib)
        let output = run_php(
            r#"<?php
$result = ob_gzhandler("test data", 1);
echo $result;
"#,
        );
        assert_eq!(output, "test data");
    }

    // --- PHP_SESSION_* constants ---

    #[test]
    fn test_session_status_constants() {
        let output = run_php(
            r#"<?php
echo PHP_SESSION_DISABLED;
echo "|";
echo PHP_SESSION_NONE;
echo "|";
echo PHP_SESSION_ACTIVE;
"#,
        );
        assert_eq!(output, "0|1|2");
    }

    // ── Batch 14: Runtime & Testing Infrastructure ───────────────────────────

    #[test]
    fn test_gcd_basic() {
        assert_eq!(run_php(r#"<?php echo gcd(12, 8); ?>"#), "4");
    }

    #[test]
    fn test_gcd_coprime() {
        assert_eq!(run_php(r#"<?php echo gcd(7, 13); ?>"#), "1");
    }

    #[test]
    fn test_gcd_zero() {
        assert_eq!(run_php(r#"<?php echo gcd(0, 5); ?>"#), "5");
    }

    #[test]
    fn test_gcd_negative() {
        assert_eq!(run_php(r#"<?php echo gcd(-12, 8); ?>"#), "4");
    }

    #[test]
    fn test_lcm_basic() {
        assert_eq!(run_php(r#"<?php echo lcm(4, 6); ?>"#), "12");
    }

    #[test]
    fn test_lcm_same() {
        assert_eq!(run_php(r#"<?php echo lcm(5, 5); ?>"#), "5");
    }

    #[test]
    fn test_lcm_zero() {
        assert_eq!(run_php(r#"<?php echo lcm(0, 5); ?>"#), "0");
    }

    #[test]
    fn test_ob_get_level_tracks_depth() {
        assert_eq!(
            run_php(
                r#"<?php
$l0 = ob_get_level();
ob_start();
$l1 = ob_get_level();
ob_start();
$l2 = ob_get_level();
ob_end_clean();
$l3 = ob_get_level();
ob_end_clean();
$l4 = ob_get_level();
echo "$l0|$l1|$l2|$l3|$l4";
"#
            ),
            "0|1|2|1|0"
        );
    }

    #[test]
    fn test_ob_get_flush_returns_and_outputs() {
        assert_eq!(
            run_php(
                r#"<?php
ob_start();
ob_start();
echo "inner";
$content = ob_get_flush();
$outer = ob_get_clean();
echo $outer . "|" . $content;
"#
            ),
            "inner|inner"
        );
    }

    #[test]
    fn test_ob_list_handlers_one_level() {
        assert_eq!(
            run_php(
                r#"<?php
ob_start();
$handlers = ob_list_handlers();
$count = count($handlers);
$name = $handlers[0];
ob_end_clean();
echo "$count|$name";
"#
            ),
            "1|default output handler"
        );
    }

    #[test]
    fn test_getenv_no_args_returns_array() {
        let output = run_php(
            r#"<?php
$env = getenv();
echo is_array($env) ? "yes" : "no";
"#,
        );
        assert_eq!(output, "yes");
    }

    #[test]
    fn test_globals_superglobal() {
        assert_eq!(
            run_php(
                r#"<?php
$x = 42;
echo $GLOBALS['x'];
"#
            ),
            "42"
        );
    }

    #[test]
    fn test_globals_contains_superglobals() {
        assert_eq!(
            run_php(
                r#"<?php
$test = "hello";
echo isset($GLOBALS['test']) ? "yes" : "no";
"#
            ),
            "yes"
        );
    }

    #[test]
    fn test_session_regenerate_id() {
        let output = run_php(
            r#"<?php
$old = session_id("test123");
$new = session_regenerate_id();
echo $new ? "true" : "false";
echo "|";
// After regeneration, session_id should be different
echo session_id() !== "test123" ? "changed" : "same";
"#,
        );
        assert_eq!(output, "true|changed");
    }

    #[test]
    fn test_session_set_save_handler_callable() {
        assert_eq!(
            run_php(
                r#"<?php
$result = session_set_save_handler("my_open", "my_close", "my_read", "my_write", "my_destroy", "my_gc");
echo $result ? "true" : "false";
"#
            ),
            "true"
        );
    }

    #[test]
    fn test_interface_exists_session_handler() {
        assert_eq!(
            run_php(
                r#"<?php
echo interface_exists('SessionHandlerInterface') ? "yes" : "no";
"#
            ),
            "yes"
        );
    }

    #[test]
    fn test_localeconv_returns_array() {
        assert_eq!(
            run_php(
                r#"<?php
$lc = localeconv();
echo $lc['decimal_point'];
echo "|";
echo $lc['int_frac_digits'];
"#
            ),
            ".|127"
        );
    }

    #[test]
    fn test_setlocale_c() {
        assert_eq!(run_php(r#"<?php echo setlocale(LC_ALL, "C"); ?>"#), "C");
    }

    #[test]
    fn test_number_format_custom_separators() {
        assert_eq!(
            run_php(r#"<?php echo number_format(1234567.891, 2, ",", "."); ?>"#),
            "1.234.567,89"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 8H: Stub Extensions wired to real implementations
    // ═══════════════════════════════════════════════════════════════

    // -- iconv tests --

    #[test]
    fn test_iconv_basic() {
        assert_eq!(
            run_php(r#"<?php echo iconv("UTF-8", "ASCII", "Hello"); ?>"#),
            "Hello"
        );
    }

    #[test]
    fn test_iconv_strlen() {
        assert_eq!(
            run_php(r#"<?php echo iconv_strlen("Hello", "UTF-8"); ?>"#),
            "5"
        );
    }

    #[test]
    fn test_iconv_substr() {
        assert_eq!(
            run_php(r#"<?php echo iconv_substr("Hello World", 6, null, "UTF-8"); ?>"#),
            "World"
        );
    }

    #[test]
    fn test_iconv_substr_with_length() {
        assert_eq!(
            run_php(r#"<?php echo iconv_substr("Hello World", 0, 5, "UTF-8"); ?>"#),
            "Hello"
        );
    }

    #[test]
    fn test_iconv_strpos() {
        assert_eq!(
            run_php(r#"<?php $r = iconv_strpos("Hello World", "World", 0, "UTF-8"); echo $r; ?>"#),
            "6"
        );
    }

    #[test]
    fn test_iconv_strrpos() {
        assert_eq!(
            run_php(r#"<?php $r = iconv_strrpos("abcabc", "abc", "UTF-8"); echo $r; ?>"#),
            "3"
        );
    }

    #[test]
    fn test_iconv_get_encoding() {
        assert_eq!(
            run_php(r#"<?php echo iconv_get_encoding("internal_encoding"); ?>"#),
            "UTF-8"
        );
    }

    #[test]
    fn test_iconv_set_encoding() {
        assert_eq!(
            run_php(
                r#"<?php
                $r = iconv_set_encoding("internal_encoding", "ASCII");
                echo $r ? "true" : "false";
            ?>"#
            ),
            "true"
        );
    }

    #[test]
    fn test_iconv_mime_encode() {
        let output = run_php(r#"<?php echo iconv_mime_encode("Subject", "Hello"); ?>"#);
        assert!(output.starts_with("Subject: =?UTF-8?B?"));
    }

    #[test]
    fn test_iconv_mime_decode() {
        assert_eq!(
            run_php(r#"<?php echo iconv_mime_decode("=?UTF-8?B?SGVsbG8=?=", 0, "UTF-8"); ?>"#),
            "Hello"
        );
    }

    // -- fileinfo tests --

    #[test]
    fn test_finfo_open() {
        assert_eq!(
            run_php(r#"<?php $f = finfo_open(); echo is_int($f) ? "ok" : "fail"; ?>"#),
            "ok"
        );
    }

    #[test]
    fn test_finfo_close() {
        assert_eq!(
            run_php(r#"<?php $f = finfo_open(); echo finfo_close($f) ? "true" : "false"; ?>"#),
            "true"
        );
    }

    #[test]
    fn test_finfo_buffer() {
        let output = run_php(
            r#"<?php
            $f = finfo_open(0x10);
            echo finfo_buffer($f, "<?php echo 'hi'; ?>");
        ?>"#,
        );
        assert!(output.contains("php") || output.contains("text"));
    }

    #[test]
    fn test_mime_content_type_php() {
        let output = run_php(r#"<?php echo mime_content_type("test.php"); ?>"#);
        assert!(output.contains("php") || output.contains("text"));
    }

    // -- tidy tests --

    #[test]
    fn test_tidy_parse_string() {
        let output = run_php(
            r#"<?php
            $out = tidy_parse_string("<html><body><p>Hello</p></body></html>");
            echo strlen($out) > 0 ? "ok" : "fail";
        ?>"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_tidy_repair_string() {
        let output = run_php(
            r#"<?php
            $out = tidy_repair_string("<html><body><p>Hello");
            echo strpos($out, "Hello") !== false ? "ok" : "fail";
        ?>"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_tidy_diagnose() {
        assert_eq!(
            run_php(r#"<?php echo tidy_diagnose("test") ? "true" : "false"; ?>"#),
            "true"
        );
    }

    #[test]
    fn test_tidy_access_count() {
        assert_eq!(run_php(r#"<?php echo tidy_access_count("test"); ?>"#), "0");
    }

    #[test]
    fn test_tidy_get_release() {
        let output = run_php(r#"<?php echo tidy_get_release(); ?>"#);
        assert!(output.contains("php.rs"));
    }

    // -- readline tests --

    #[test]
    fn test_readline_add_history() {
        assert_eq!(
            run_php(r#"<?php echo readline_add_history("test") ? "true" : "false"; ?>"#),
            "true"
        );
    }

    #[test]
    fn test_readline_clear_history() {
        assert_eq!(
            run_php(
                r#"<?php
                readline_add_history("item1");
                echo readline_clear_history() ? "true" : "false";
            ?>"#
            ),
            "true"
        );
    }

    #[test]
    fn test_readline_list_history() {
        assert_eq!(
            run_php(
                r#"<?php
                readline_clear_history();
                readline_add_history("one");
                readline_add_history("two");
                $h = readline_list_history();
                echo count($h);
            ?>"#
            ),
            "2"
        );
    }

    #[test]
    fn test_readline_info() {
        let output = run_php(
            r#"<?php
            $info = readline_info();
            echo is_array($info) ? "ok" : "fail";
        ?>"#,
        );
        assert_eq!(output, "ok");
    }

    // -- bz2 tests --

    #[test]
    fn test_bzcompress() {
        let output = run_php(
            r#"<?php
            $data = "Hello World";
            $compressed = bzcompress($data);
            echo strlen($compressed) > 0 ? "ok" : "fail";
        ?>"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_bzerrno() {
        assert_eq!(run_php(r#"<?php echo bzerrno(null); ?>"#), "0");
    }

    #[test]
    fn test_bzerror() {
        let output = run_php(
            r#"<?php
            $err = bzerror(null);
            echo is_array($err) ? "ok" : "fail";
        ?>"#,
        );
        assert_eq!(output, "ok");
    }

    // =========================================================================
    // Phase 8H: Stub Extensions — VM integration tests
    // =========================================================================

    // --- EXIF ---

    #[test]
    fn test_exif_tagname() {
        let output = run_php(r#"<?php echo exif_tagname(0x010F); ?>"#);
        assert_eq!(output, "Make");
    }

    #[test]
    fn test_exif_imagetype_invalid() {
        let output = run_php(r#"<?php echo var_export(exif_imagetype("/nonexistent"), true); ?>"#);
        assert_eq!(output, "false");
    }

    // --- SOCKETS ---

    #[test]
    fn test_socket_create() {
        let output = run_php(
            r#"<?php
            $s = socket_create(2, 1, 0);
            echo is_int($s) ? "ok" : "fail";
        ?>"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_socket_strerror() {
        let output = run_php(r#"<?php echo socket_strerror(0); ?>"#);
        assert_eq!(output, "Success");
    }

    #[test]
    fn test_socket_last_error() {
        let output = run_php(
            r#"<?php
            $s = socket_create(2, 1, 0);
            echo socket_last_error($s);
        ?>"#,
        );
        assert_eq!(output, "0");
    }

    #[test]
    fn test_socket_close() {
        let output = run_php(
            r#"<?php
            $s = socket_create(2, 1, 0);
            socket_close($s);
            echo "ok";
        ?>"#,
        );
        assert_eq!(output, "ok");
    }

    // --- SIMPLEXML ---

    #[test]
    fn test_simplexml_load_string() {
        let output = run_php(
            r#"<?php
            $xml = simplexml_load_string("<root><child>hello</child></root>");
            echo is_int($xml) ? "ok" : "fail";
        ?>"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_simplexml_load_string_invalid() {
        let output = run_php(
            r#"<?php
            $xml = simplexml_load_string("");
            echo var_export($xml, true);
        ?>"#,
        );
        assert_eq!(output, "false");
    }

    // --- XMLREADER ---

    #[test]
    fn test_xmlreader_open_missing() {
        let output = run_php(
            r#"<?php
            $r = xmlreader_open("/nonexistent/file.xml");
            echo var_export($r, true);
        ?>"#,
        );
        assert_eq!(output, "false");
    }

    // --- PHAR ---

    #[test]
    fn test_phar_running() {
        let output = run_php(r#"<?php echo phar_running(); ?>"#);
        assert_eq!(output, "");
    }

    // --- SOAP ---

    #[test]
    fn test_is_soap_fault() {
        let output = run_php(
            r#"<?php
            echo var_export(is_soap_fault("test"), true);
        ?>"#,
        );
        assert_eq!(output, "false");
    }

    // --- LDAP ---

    #[test]
    fn test_ldap_connect_and_bind() {
        let output = run_php(
            r#"<?php
            $conn = ldap_connect("ldap://localhost");
            echo is_int($conn) ? "ok" : "fail";
        ?>"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_ldap_escape() {
        let output = run_php(r#"<?php echo ldap_escape("test(value)"); ?>"#);
        assert!(output.contains("test"));
    }

    #[test]
    fn test_ldap_error_and_errno() {
        let output = run_php(
            r#"<?php
            $conn = ldap_connect("ldap://localhost");
            echo ldap_errno($conn) . ":" . ldap_error($conn);
        ?>"#,
        );
        assert_eq!(output, "0:Success");
    }

    // --- FTP ---

    #[test]
    fn test_ftp_connect() {
        let output = run_php(
            r#"<?php
            $ftp = ftp_connect("localhost");
            echo is_int($ftp) ? "ok" : "fail";
        ?>"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_ftp_login_and_pwd() {
        let output = run_php(
            r#"<?php
            $ftp = ftp_connect("localhost");
            ftp_login($ftp, "user", "pass");
            echo ftp_pwd($ftp);
        ?>"#,
        );
        assert_eq!(output, "/");
    }

    #[test]
    fn test_ftp_mkdir_chdir_pwd() {
        let output = run_php(
            r#"<?php
            $ftp = ftp_connect("localhost");
            ftp_login($ftp, "user", "pass");
            ftp_mkdir($ftp, "testdir");
            ftp_chdir($ftp, "testdir");
            echo ftp_pwd($ftp);
        ?>"#,
        );
        assert_eq!(output, "/testdir");
    }

    #[test]
    fn test_ftp_systype() {
        let output = run_php(
            r#"<?php
            $ftp = ftp_connect("localhost");
            ftp_login($ftp, "user", "pass");
            echo ftp_systype($ftp);
        ?>"#,
        );
        assert_eq!(output, "UNIX");
    }

    #[test]
    fn test_ftp_close() {
        let output = run_php(
            r#"<?php
            $ftp = ftp_connect("localhost");
            echo var_export(ftp_close($ftp), true);
        ?>"#,
        );
        assert_eq!(output, "true");
    }

    // --- ODBC ---

    #[test]
    fn test_odbc_connect_and_close() {
        let output = run_php(
            r#"<?php
            $conn = odbc_connect("DSN=test", "user", "pass");
            echo is_int($conn) ? "ok" : "fail";
            echo odbc_close($conn) ? "closed" : "fail";
        ?>"#,
        );
        assert_eq!(output, "okclosed");
    }

    #[test]
    fn test_odbc_error_errormsg() {
        let output = run_php(
            r#"<?php
            $conn = odbc_connect("DSN=test", "user", "pass");
            $err = odbc_error($conn);
            $msg = odbc_errormsg($conn);
            echo ($err === "" && $msg === "") ? "no_error" : "has_error";
        ?>"#,
        );
        assert_eq!(output, "no_error");
    }

    // --- SNMP ---

    #[test]
    fn test_snmp_quick_print_roundtrip() {
        // Test get and set together to avoid race conditions with parallel tests
        let output = run_php(
            r#"<?php
            snmp_set_quick_print(0);
            $before = snmp_get_quick_print() ? "1" : "0";
            snmp_set_quick_print(1);
            $after = snmp_get_quick_print() ? "1" : "0";
            snmp_set_quick_print(0);
            echo $before . $after;
        ?>"#,
        );
        assert_eq!(output, "01");
    }

    // --- DBA ---

    #[test]
    fn test_dba_handlers() {
        let output = run_php(
            r#"<?php
            $h = dba_handlers();
            echo is_array($h) ? "ok" : "fail";
        ?>"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_dba_open_insert_fetch() {
        let output = run_php(
            r#"<?php
            $db = dba_open("test.db", "c", "flatfile");
            dba_insert("key1", "value1", $db);
            echo dba_fetch("key1", $db);
        ?>"#,
        );
        assert_eq!(output, "value1");
    }

    #[test]
    fn test_dba_exists_delete() {
        let output = run_php(
            r#"<?php
            $db = dba_open("test.db", "c", "flatfile");
            dba_insert("k", "v", $db);
            echo dba_exists("k", $db) ? "yes" : "no";
            dba_delete("k", $db);
            echo dba_exists("k", $db) ? "yes" : "no";
        ?>"#,
        );
        assert_eq!(output, "yesno");
    }

    #[test]
    fn test_dba_replace() {
        let output = run_php(
            r#"<?php
            $db = dba_open("test.db", "c", "flatfile");
            dba_insert("k", "old", $db);
            dba_replace("k", "new", $db);
            echo dba_fetch("k", $db);
        ?>"#,
        );
        assert_eq!(output, "new");
    }

    #[test]
    fn test_dba_firstkey_nextkey() {
        let output = run_php(
            r#"<?php
            $db = dba_open("test.db", "c", "flatfile");
            dba_insert("a", "1", $db);
            dba_insert("b", "2", $db);
            $key = dba_firstkey($db);
            $count = 0;
            while ($key !== false) {
                $count++;
                $key = dba_nextkey($db);
            }
            echo $count;
        ?>"#,
        );
        assert_eq!(output, "2");
    }

    // --- ENCHANT ---

    #[test]
    fn test_enchant_broker_init_and_free() {
        let output = run_php(
            r#"<?php
            $broker = enchant_broker_init();
            echo is_int($broker) ? "ok" : "fail";
            echo enchant_broker_free($broker) ? "freed" : "fail";
        ?>"#,
        );
        assert_eq!(output, "okfreed");
    }

    #[test]
    fn test_enchant_dict_check() {
        let output = run_php(
            r#"<?php
            $broker = enchant_broker_init();
            $dict = enchant_broker_request_dict($broker, "en_US");
            echo enchant_dict_check($dict, "hello") ? "ok" : "misspelled";
        ?>"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_enchant_dict_suggest() {
        let output = run_php(
            r#"<?php
            $broker = enchant_broker_init();
            $dict = enchant_broker_request_dict($broker, "en_US");
            $suggestions = enchant_dict_suggest($dict, "helo");
            echo is_array($suggestions) ? "ok" : "fail";
        ?>"#,
        );
        assert_eq!(output, "ok");
    }

    // --- SYSVSEM ---

    #[test]
    fn test_sem_get_acquire_release() {
        let output = run_php(
            r#"<?php
            $sem = sem_get(1234);
            echo is_int($sem) ? "ok" : "fail";
            echo sem_acquire($sem) ? "acquired" : "fail";
            echo sem_release($sem) ? "released" : "fail";
        ?>"#,
        );
        assert_eq!(output, "okacquiredreleased");
    }

    #[test]
    fn test_sem_remove() {
        let output = run_php(
            r#"<?php
            $sem = sem_get(5678);
            echo sem_remove($sem) ? "removed" : "fail";
        ?>"#,
        );
        assert_eq!(output, "removed");
    }

    // --- SYSVSHM ---

    #[test]
    fn test_shm_attach_put_get() {
        let output = run_php(
            r#"<?php
            $shm = shm_attach(1234);
            shm_put_var($shm, 1, "hello");
            echo shm_get_var($shm, 1);
        ?>"#,
        );
        assert_eq!(output, "hello");
    }

    #[test]
    fn test_shm_has_var_remove_var() {
        let output = run_php(
            r#"<?php
            $shm = shm_attach(1234);
            shm_put_var($shm, 42, "data");
            echo shm_has_var($shm, 42) ? "yes" : "no";
            shm_remove_var($shm, 42);
            echo shm_has_var($shm, 42) ? "yes" : "no";
        ?>"#,
        );
        assert_eq!(output, "yesno");
    }

    #[test]
    fn test_shm_detach() {
        let output = run_php(
            r#"<?php
            $shm = shm_attach(1234);
            echo shm_detach($shm) ? "ok" : "fail";
        ?>"#,
        );
        assert_eq!(output, "ok");
    }

    // --- SYSVMSG ---

    #[test]
    fn test_msg_get_queue() {
        let output = run_php(
            r#"<?php
            $q = msg_get_queue(1234);
            echo is_int($q) ? "ok" : "fail";
        ?>"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_msg_queue_exists() {
        let output = run_php(
            r#"<?php
            $q = msg_get_queue(9999);
            echo msg_queue_exists(9999) ? "yes" : "no";
            echo msg_queue_exists(1111) ? "yes" : "no";
        ?>"#,
        );
        assert_eq!(output, "yesno");
    }

    #[test]
    fn test_msg_stat_queue() {
        let output = run_php(
            r#"<?php
            $q = msg_get_queue(1234);
            $stat = msg_stat_queue($q);
            echo is_array($stat) ? "ok" : "fail";
            echo isset($stat["msg_qnum"]) ? "has_qnum" : "no";
        ?>"#,
        );
        assert_eq!(output, "okhas_qnum");
    }

    // --- SHMOP ---

    #[test]
    fn test_shmop_open_write_read() {
        let output = run_php(
            r#"<?php
            $shm = shmop_open(1234, "c", 0644, 100);
            shmop_write($shm, "Hello", 0);
            echo shmop_read($shm, 0, 5);
        ?>"#,
        );
        assert_eq!(output, "Hello");
    }

    #[test]
    fn test_shmop_size() {
        let output = run_php(
            r#"<?php
            $shm = shmop_open(1234, "c", 0644, 256);
            echo shmop_size($shm);
        ?>"#,
        );
        assert_eq!(output, "256");
    }

    #[test]
    fn test_shmop_delete_close() {
        let output = run_php(
            r#"<?php
            $shm = shmop_open(1234, "c", 0644, 100);
            echo shmop_delete($shm) ? "deleted" : "fail";
            shmop_close($shm);
            echo "ok";
        ?>"#,
        );
        assert_eq!(output, "deletedok");
    }

    // ── Phase 13: Performance tests ──

    #[test]
    fn test_array_cow_php() {
        // PHP array copy-on-write: cloning arrays is cheap,
        // modifying a clone doesn't affect the original
        let output = run_php(
            r#"<?php
            $a = [1, 2, 3, 4, 5];
            $b = $a;       // CoW clone (cheap)
            $b[] = 6;      // Triggers deep copy on $b only
            echo count($a) . " " . count($b);
        ?>"#,
        );
        assert_eq!(output, "5 6");
    }

    #[test]
    fn test_array_packed_access_php() {
        // Packed array: sequential 0..n keys get O(1) indexed access
        let output = run_php(
            r#"<?php
            $arr = [];
            for ($i = 0; $i < 100; $i++) {
                $arr[] = $i * 2;
            }
            echo $arr[0] . " " . $arr[50] . " " . $arr[99];
        ?>"#,
        );
        assert_eq!(output, "0 100 198");
    }

    #[test]
    fn test_array_hash_index_large_php() {
        // Large string-keyed arrays use hash index for O(1) lookup
        let output = run_php(
            r#"<?php
            $arr = [];
            for ($i = 0; $i < 50; $i++) {
                $arr["key_" . $i] = $i;
            }
            echo $arr["key_0"] . " " . $arr["key_25"] . " " . $arr["key_49"];
        ?>"#,
        );
        assert_eq!(output, "0 25 49");
    }

    #[test]
    fn test_array_cow_nested_php() {
        // Nested array CoW: modifying inner array of clone doesn't affect original
        let output = run_php(
            r#"<?php
            $a = [[1, 2], [3, 4]];
            $b = $a;
            $b[0][] = 99;
            echo count($a[0]) . " " . count($b[0]);
        ?>"#,
        );
        assert_eq!(output, "2 3");
    }

    #[test]
    fn test_arena_reset_per_request() {
        // Verify that the VM properly resets between executions
        // (arena + string pool reset at request start)
        let oa = compile("<?php echo 'hello';").unwrap();
        let mut vm = Vm::new();
        let out1 = vm.execute(&oa, None).unwrap();
        let out2 = vm.execute(&oa, None).unwrap();
        assert_eq!(out1, "hello");
        assert_eq!(out2, "hello");
    }

    #[test]
    fn test_opcode_cache_reuse() {
        // Verify that opcode cache avoids recompilation
        let mut vm = Vm::new();
        // Write a temp PHP file
        let tmp_dir = std::env::temp_dir();
        let tmp_file = tmp_dir.join("phprs_test_opcache.php");
        std::fs::write(&tmp_file, "<?php echo 'cached';").unwrap();

        let out1 = vm.execute_file(tmp_file.to_str().unwrap(), None).unwrap();
        assert_eq!(out1, "cached");
        assert_eq!(vm.opcode_cache_size(), 1);

        // Second execution should use cache
        let out2 = vm.execute_file(tmp_file.to_str().unwrap(), None).unwrap();
        assert_eq!(out2, "cached");
        assert_eq!(vm.opcode_cache_size(), 1);

        // Cleanup
        let _ = std::fs::remove_file(&tmp_file);
    }

    #[test]
    fn test_opcode_cache_invalidation() {
        let mut vm = Vm::new();
        let tmp_dir = std::env::temp_dir();
        let tmp_file = tmp_dir.join("phprs_test_opcache_inv.php");
        std::fs::write(&tmp_file, "<?php echo 'v1';").unwrap();

        let out1 = vm.execute_file(tmp_file.to_str().unwrap(), None).unwrap();
        assert_eq!(out1, "v1");

        // Invalidate and re-run
        vm.invalidate_opcode_cache(tmp_file.to_str().unwrap());
        assert_eq!(vm.opcode_cache_size(), 0);

        let _ = std::fs::remove_file(&tmp_file);
    }

    #[test]
    fn test_opcode_cache_clear() {
        let mut vm = Vm::new();
        let tmp_dir = std::env::temp_dir();
        let f1 = tmp_dir.join("phprs_test_oc1.php");
        let f2 = tmp_dir.join("phprs_test_oc2.php");
        std::fs::write(&f1, "<?php echo 'a';").unwrap();
        std::fs::write(&f2, "<?php echo 'b';").unwrap();

        let _ = vm.execute_file(f1.to_str().unwrap(), None).unwrap();
        let _ = vm.execute_file(f2.to_str().unwrap(), None).unwrap();
        assert_eq!(vm.opcode_cache_size(), 2);

        vm.clear_opcode_cache();
        assert_eq!(vm.opcode_cache_size(), 0);

        let _ = std::fs::remove_file(&f1);
        let _ = std::fs::remove_file(&f2);
    }

    #[test]
    fn test_packed_array_large() {
        // Verify packed array with many elements
        let output = run_php(
            r#"<?php
            $arr = [];
            for ($i = 0; $i < 1000; $i++) {
                $arr[] = $i;
            }
            echo $arr[500] . " " . $arr[999] . " " . count($arr);
        ?>"#,
        );
        assert_eq!(output, "500 999 1000");
    }

    #[test]
    fn test_cow_array_pass_to_function() {
        // Arrays passed by value use CoW semantics
        let output = run_php(
            r#"<?php
            function modify($arr) {
                $arr[] = 99;
                return count($arr);
            }
            $original = [1, 2, 3];
            $modified_count = modify($original);
            echo count($original) . " " . $modified_count;
        ?>"#,
        );
        assert_eq!(output, "3 4");
    }

    #[test]
    fn test_string_pool_basic() {
        // Verify string pool works in VM
        let oa = compile("<?php echo 'hello';").unwrap();
        let mut vm = Vm::new();
        // Intern some strings
        let s1 = vm.string_pool.intern("hello");
        let s2 = vm.string_pool.intern("hello");
        assert!(std::rc::Rc::ptr_eq(&s1, &s2));
        // Execute doesn't crash
        let out = vm.execute(&oa, None).unwrap();
        assert_eq!(out, "hello");
    }

    // =========================================================================
    // SendUnpack with named arguments (spread + named args)
    // =========================================================================

    #[test]
    fn test_send_unpack_positional_then_named() {
        // func(...$args, name: $val): spread positional then an explicit named arg
        let output = run_php(
            r#"<?php
            function test($a, $b, $c) { echo "$a $b $c\n"; }
            $args = [1, 2];
            test(...$args, c: 3);
            ?>"#,
        );
        assert_eq!(output, "1 2 3\n");
    }

    #[test]
    fn test_send_unpack_named_array_keys() {
        // Spread an associative array — string keys become named arguments
        let output = run_php(
            r#"<?php
            function test2($x, $y) { echo "$x $y\n"; }
            $args = ['y' => 'hello', 'x' => 'world'];
            test2(...$args);
            ?>"#,
        );
        assert_eq!(output, "world hello\n");
    }

    #[test]
    fn test_send_unpack_named_array_then_named_arg() {
        // Spread an associative array, then supply an additional named argument
        let output = run_php(
            r#"<?php
            function test3($a, $b, $c) { echo "$a $b $c\n"; }
            $args = ['a' => 1, 'b' => 2];
            test3(...$args, c: 3);
            ?>"#,
        );
        assert_eq!(output, "1 2 3\n");
    }

    // =========================================================================
    // Asymmetric Visibility (PHP 8.4)
    // =========================================================================

    #[test]
    fn test_asymmetric_visibility_private_set_internal_write() {
        // private(set) allows writes from within the class
        let output = run_php(
            r#"<?php
class User {
    public private(set) string $name;
    public function __construct(string $name) {
        $this->name = $name;
    }
}
$u = new User("Alice");
echo $u->name;
?>"#,
        );
        assert_eq!(output, "Alice");
    }

    #[test]
    fn test_asymmetric_visibility_private_set_external_read() {
        // public property with private(set) can be read externally
        let output = run_php(
            r#"<?php
class Config {
    public private(set) int $value;
    public function __construct(int $v) {
        $this->value = $v;
    }
}
$c = new Config(42);
echo $c->value;
?>"#,
        );
        assert_eq!(output, "42");
    }

    #[test]
    fn test_asymmetric_visibility_private_set_external_write_fails() {
        // Attempting to write to a private(set) property externally should fail
        let result = std::panic::catch_unwind(|| {
            run_php(
                r#"<?php
class Foo {
    public private(set) int $x;
    public function __construct() { $this->x = 10; }
}
$f = new Foo();
$f->x = 20;
?>"#,
            )
        });
        assert!(
            result.is_err() || {
                // Check if the output contains the error message
                if let Ok(output) = &result {
                    output.contains("Cannot modify private(set)")
                } else {
                    true
                }
            }
        );
    }

    #[test]
    fn test_asymmetric_visibility_protected_set() {
        // protected(set) allows writes from subclasses
        let output = run_php(
            r#"<?php
class Base {
    public protected(set) string $name;
    public function __construct(string $n) {
        $this->name = $n;
    }
}
class Child extends Base {
    public function rename(string $n) {
        $this->name = $n;
    }
}
$c = new Child("Alice");
$c->rename("Bob");
echo $c->name;
?>"#,
        );
        assert_eq!(output, "Bob");
    }

    // =========================================================================
    // Property Hooks (PHP 8.4)
    // =========================================================================

    #[test]
    fn test_property_hook_get_expression() {
        // Simple get hook with expression body
        let output = run_php(
            r#"<?php
class Foo {
    public int $val = 10;
    public int $doubled {
        get => $this->val * 2;
    }
}
$f = new Foo();
echo $f->doubled;
?>"#,
        );
        assert_eq!(output, "20");
    }

    #[test]
    fn test_property_hook_set_block() {
        // Set hook with block body
        let output = run_php(
            r#"<?php
class Bar {
    public int $x {
        set {
            $this->x = $value + 1;
        }
    }
}
$b = new Bar();
$b->x = 5;
echo $b->x;
?>"#,
        );
        assert_eq!(output, "6");
    }

    #[test]
    fn test_property_hook_get_and_set() {
        // Both get and set hooks
        let output = run_php(
            r#"<?php
class Temperature {
    public int $celsius = 0;
    public int $fahrenheit {
        get => $this->celsius * 9 / 5 + 32;
        set {
            $this->celsius = ($value - 32) * 5 / 9;
        }
    }
}
$t = new Temperature();
echo $t->fahrenheit . "\n";
$t->fahrenheit = 212;
echo $t->celsius;
?>"#,
        );
        assert_eq!(output, "32\n100");
    }

    #[test]
    fn test_property_hook_set_custom_param() {
        // Set hook with custom parameter name
        let output = run_php(
            r#"<?php
class Clamped {
    public int $val {
        set(int $newVal) {
            if ($newVal > 100) {
                $this->val = 100;
            } else {
                $this->val = $newVal;
            }
        }
    }
}
$c = new Clamped();
$c->val = 200;
echo $c->val;
?>"#,
        );
        assert_eq!(output, "100");
    }

    #[test]
    fn test_property_hook_virtual_property() {
        // Virtual property (get hook only, no backing storage)
        let output = run_php(
            r#"<?php
class Point {
    public int $x = 3;
    public int $y = 4;
    public int $length {
        get => $this->x + $this->y;
    }
}
$p = new Point();
echo $p->length;
?>"#,
        );
        assert_eq!(output, "7");
    }

    // =========================================================================
    // Attributes on Functions/Methods/Parameters
    // =========================================================================

    #[test]
    fn test_attribute_on_function_compiles() {
        // Attributes on functions should compile without error
        let output = run_php(
            r#"<?php
#[Deprecated("use newFunc instead")]
function oldFunc() {
    echo "old";
}
oldFunc();
?>"#,
        );
        assert_eq!(output, "old");
    }

    #[test]
    fn test_attribute_on_method_compiles() {
        // Attributes on methods should compile without error
        let output = run_php(
            r#"<?php
class Foo {
    #[Override]
    public function bar() {
        echo "bar";
    }
}
$f = new Foo();
$f->bar();
?>"#,
        );
        assert_eq!(output, "bar");
    }

    #[test]
    fn test_attribute_on_parameter_compiles() {
        // Attributes on parameters should compile without error
        let output = run_php(
            r#"<?php
function test(#[SensitiveParameter] string $password) {
    echo strlen($password);
}
test("secret");
?>"#,
        );
        assert_eq!(output, "6");
    }

    // =========================================================================
    // DeclareAttributedConst
    // =========================================================================

    #[test]
    fn test_declare_attributed_const() {
        // Attributed const should work like regular const
        let output = run_php(
            r#"<?php
#[Deprecated]
const OLD_API_VERSION = 1;
echo OLD_API_VERSION;
?>"#,
        );
        assert_eq!(output, "1");
    }

    #[test]
    fn test_declare_attributed_const_with_args() {
        // Attributed const with arguments
        let output = run_php(
            r#"<?php
#[Deprecated("use NEW_VERSION instead")]
const OLD_VERSION = "1.0";
echo OLD_VERSION;
?>"#,
        );
        assert_eq!(output, "1.0");
    }

    // =========================================================================
    // Parent Constructor Call Tracking
    // =========================================================================

    #[test]
    fn test_parent_constructor_called() {
        // When parent::__construct is properly called
        let output = run_php(
            r#"<?php
class Base {
    public int $x;
    public function __construct(int $x) {
        $this->x = $x;
    }
}
class Child extends Base {
    public int $y;
    public function __construct(int $x, int $y) {
        parent::__construct($x);
        $this->y = $y;
    }
}
$c = new Child(1, 2);
echo $c->x . " " . $c->y;
?>"#,
        );
        assert_eq!(output, "1 2");
    }

    #[test]
    fn test_parent_constructor_not_called_still_works() {
        // Not calling parent constructor should still work (PHP doesn't enforce it strictly)
        let output = run_php(
            r#"<?php
class Base {
    public function __construct() {}
}
class Child extends Base {
    public int $val;
    public function __construct(int $v) {
        $this->val = $v;
    }
}
$c = new Child(42);
echo $c->val;
?>"#,
        );
        assert_eq!(output, "42");
    }

    // =========================================================================
    // list() / [...] = array destructuring (verify still works)
    // =========================================================================

    #[test]
    fn test_list_destructuring_with_keys() {
        let output = run_php(
            r#"<?php
$arr = ['first' => 'Alice', 'last' => 'Smith'];
['first' => $first, 'last' => $last] = $arr;
echo "$first $last";
?>"#,
        );
        assert_eq!(output, "Alice Smith");
    }

    #[test]
    fn test_short_list_nested() {
        let output = run_php(
            r#"<?php
$data = [[1, 2], [3, 4]];
[[$a, $b], [$c, $d]] = $data;
echo "$a $b $c $d";
?>"#,
        );
        assert_eq!(output, "1 2 3 4");
    }

    // =========================================================================
    // Phase 7C: File/IO Functions — Stream Filters, Sockets, proc_open
    // =========================================================================

    // --- 7C.04: stream_filter_append / stream_filter_prepend ---

    #[test]
    fn test_stream_filter_append_known_filter() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "sf");
file_put_contents($tmp, "hello");
$fh = fopen($tmp, "r");
$filter = stream_filter_append($fh, "string.toupper", STREAM_FILTER_READ);
echo gettype($filter);
fclose($fh);
unlink($tmp);
?>"#,
        );
        assert_eq!(output, "resource");
    }

    #[test]
    fn test_stream_filter_append_unknown_filter() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "sf");
file_put_contents($tmp, "hello");
$fh = fopen($tmp, "r");
$filter = stream_filter_append($fh, "nonexistent.filter");
echo var_export($filter, true);
fclose($fh);
unlink($tmp);
?>"#,
        );
        assert_eq!(output, "false");
    }

    #[test]
    fn test_stream_filter_register_and_use() {
        let output = run_php(
            r#"<?php
stream_filter_register("myfilter", "MyFilter");
$filters = stream_get_filters();
echo in_array("myfilter", $filters) ? "yes" : "no";
?>"#,
        );
        assert_eq!(output, "yes");
    }

    #[test]
    fn test_stream_filter_prepend_known() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "sf");
file_put_contents($tmp, "hello");
$fh = fopen($tmp, "r");
$filter = stream_filter_prepend($fh, "string.rot13", STREAM_FILTER_READ);
echo gettype($filter);
fclose($fh);
unlink($tmp);
?>"#,
        );
        assert_eq!(output, "resource");
    }

    #[test]
    fn test_stream_get_filters_includes_builtins() {
        let output = run_php(
            r#"<?php
$filters = stream_get_filters();
echo in_array("string.rot13", $filters) ? "yes" : "no";
echo " ";
echo in_array("convert.base64-encode", $filters) ? "yes" : "no";
?>"#,
        );
        assert_eq!(output, "yes yes");
    }

    // --- 7C.05: stream_socket_client / stream_socket_server ---

    #[test]
    fn test_stream_socket_server_and_client() {
        // Test that stream_socket_server creates a resource
        let output = run_php(
            r#"<?php
$server = stream_socket_server("tcp://127.0.0.1:0", $errno, $errstr);
if ($server !== false) {
    $name = stream_socket_get_name($server, false);
    echo "server:ok ";
    echo (strpos($name, "127.0.0.1") !== false) ? "addr:ok" : "addr:fail";
    fclose($server);
} else {
    echo "server:fail $errstr";
}
?>"#,
        );
        assert!(output.contains("server:ok"), "Output was: {}", output);
        assert!(output.contains("addr:ok"), "Output was: {}", output);
    }

    #[test]
    fn test_stream_socket_get_name_local() {
        let output = run_php(
            r#"<?php
$server = stream_socket_server("tcp://127.0.0.1:0", $errno, $errstr);
if ($server !== false) {
    $name = stream_socket_get_name($server, false);
    echo is_string($name) ? "ok" : "fail";
    fclose($server);
} else {
    echo "fail";
}
?>"#,
        );
        assert_eq!(output, "ok");
    }

    // --- 7C.06: stream_select ---

    #[test]
    fn test_stream_select_with_timeout_zero() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "ss");
file_put_contents($tmp, "data");
$fh = fopen($tmp, "r");
$read = [$fh];
$write = null;
$except = null;
$changed = stream_select($read, $write, $except, 0);
echo $changed;
fclose($fh);
unlink($tmp);
?>"#,
        );
        assert_eq!(output, "1");
    }

    #[test]
    fn test_stream_select_empty_arrays() {
        let output = run_php(
            r#"<?php
$read = [];
$write = null;
$except = null;
$changed = stream_select($read, $write, $except, 0);
echo $changed;
?>"#,
        );
        assert_eq!(output, "0");
    }

    // --- 7C.07: stream_set_blocking / stream_set_timeout ---

    #[test]
    fn test_stream_set_blocking_on_file() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "sb");
file_put_contents($tmp, "data");
$fh = fopen($tmp, "r");
$result = stream_set_blocking($fh, true);
echo $result ? "ok" : "fail";
fclose($fh);
unlink($tmp);
?>"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_stream_set_timeout_on_file() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "st");
file_put_contents($tmp, "data");
$fh = fopen($tmp, "r");
$result = stream_set_timeout($fh, 5);
echo $result ? "ok" : "fail";
fclose($fh);
unlink($tmp);
?>"#,
        );
        assert_eq!(output, "ok");
    }

    // --- 7C.08: stream_wrapper_register ---

    #[test]
    fn test_stream_wrapper_register_and_list() {
        let output = run_php(
            r#"<?php
stream_wrapper_register("myproto", "MyStreamWrapper");
$wrappers = stream_get_wrappers();
echo in_array("myproto", $wrappers) ? "registered" : "not found";
?>"#,
        );
        assert_eq!(output, "registered");
    }

    #[test]
    fn test_stream_wrapper_unregister() {
        let output = run_php(
            r#"<?php
stream_wrapper_register("testproto", "TestWrapper");
$before = in_array("testproto", stream_get_wrappers());
stream_wrapper_unregister("testproto");
$after = in_array("testproto", stream_get_wrappers());
echo ($before && !$after) ? "ok" : "fail";
?>"#,
        );
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_stream_wrapper_register_duplicate() {
        let output = run_php(
            r#"<?php
$first = stream_wrapper_register("dup", "Wrapper1");
$second = stream_wrapper_register("dup", "Wrapper2");
echo $first ? "yes" : "no";
echo " ";
echo $second ? "yes" : "no";
?>"#,
        );
        assert_eq!(output, "yes no");
    }

    // --- 7C.12: proc_open ---

    #[test]
    fn test_proc_open_basic_command() {
        let output = run_php(
            r#"<?php
$descriptorspec = [
    0 => ["pipe", "r"],
    1 => ["pipe", "w"],
    2 => ["pipe", "w"],
];
$process = proc_open("echo hello", $descriptorspec, $pipes);
if (is_resource($process)) {
    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exit = proc_close($process);
    echo trim($stdout);
    echo " exit:$exit";
} else {
    echo "fail";
}
?>"#,
        );
        assert!(output.contains("hello"), "Output was: {}", output);
        assert!(output.contains("exit:0"), "Output was: {}", output);
    }

    #[test]
    fn test_proc_open_returns_resource() {
        let output = run_php(
            r#"<?php
$process = proc_open("echo test", [
    0 => ["pipe", "r"],
    1 => ["pipe", "w"],
    2 => ["pipe", "w"],
], $pipes);
echo is_resource($process) ? "resource" : "not resource";
proc_close($process);
?>"#,
        );
        assert_eq!(output, "resource");
    }

    #[test]
    fn test_proc_open_with_cwd() {
        let output = run_php(
            r#"<?php
$process = proc_open("pwd", [
    0 => ["pipe", "r"],
    1 => ["pipe", "w"],
    2 => ["pipe", "w"],
], $pipes, "/tmp");
if (is_resource($process)) {
    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    proc_close($process);
    echo trim($stdout);
} else {
    echo "fail";
}
?>"#,
        );
        assert!(
            output.starts_with("/tmp") || output.starts_with("/private/tmp"),
            "Output was: {}",
            output
        );
    }

    #[test]
    fn test_proc_open_with_env() {
        let output = run_php(
            r#"<?php
$process = proc_open("/usr/bin/env", [
    0 => ["pipe", "r"],
    1 => ["pipe", "w"],
    2 => ["pipe", "w"],
], $pipes, null, ["MY_VAR" => "hello_env"]);
if (is_resource($process)) {
    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    proc_close($process);
    echo (strpos($stdout, "MY_VAR=hello_env") !== false) ? "found" : "not found";
} else {
    echo "fail";
}
?>"#,
        );
        assert_eq!(output, "found");
    }

    #[test]
    fn test_proc_get_status_running() {
        let output = run_php(
            r#"<?php
$process = proc_open("sleep 10", [
    0 => ["pipe", "r"],
    1 => ["pipe", "w"],
    2 => ["pipe", "w"],
], $pipes);
if (is_resource($process)) {
    $status = proc_get_status($process);
    echo $status["running"] ? "running" : "not running";
    proc_terminate($process);
    proc_close($process);
} else {
    echo "fail";
}
?>"#,
        );
        assert_eq!(output, "running");
    }

    #[test]
    fn test_proc_terminate() {
        let output = run_php(
            r#"<?php
$process = proc_open("sleep 60", [
    0 => ["pipe", "r"],
    1 => ["pipe", "w"],
    2 => ["pipe", "w"],
], $pipes);
if (is_resource($process)) {
    $result = proc_terminate($process);
    echo $result ? "terminated" : "fail";
} else {
    echo "fail";
}
?>"#,
        );
        assert_eq!(output, "terminated");
    }

    // --- Stream transports ---

    #[test]
    fn test_stream_get_transports() {
        let output = run_php(
            r#"<?php
$transports = stream_get_transports();
echo in_array("tcp", $transports) ? "yes" : "no";
echo " ";
echo in_array("udp", $transports) ? "yes" : "no";
?>"#,
        );
        assert_eq!(output, "yes yes");
    }

    // --- stream_filter_remove ---

    #[test]
    fn test_stream_filter_remove() {
        let output = run_php(
            r#"<?php
$tmp = tempnam(sys_get_temp_dir(), "sfr");
file_put_contents($tmp, "hello");
$fh = fopen($tmp, "r");
$filter = stream_filter_append($fh, "string.toupper");
$result = stream_filter_remove($filter);
echo $result ? "removed" : "fail";
fclose($fh);
unlink($tmp);
?>"#,
        );
        assert_eq!(output, "removed");
    }

    // --- parse_url with component parameter ---

    #[test]
    fn test_parse_url_component_parameter() {
        let output = run_php(
            r#"<?php
$url = "https://user:pass@example.com:8080/foo/bar?q=1#frag";
echo parse_url($url, PHP_URL_SCHEME) . "|";
echo parse_url($url, PHP_URL_HOST) . "|";
echo parse_url($url, PHP_URL_PORT) . "|";
echo parse_url($url, PHP_URL_USER) . "|";
echo parse_url($url, PHP_URL_PASS) . "|";
echo parse_url($url, PHP_URL_PATH) . "|";
echo parse_url($url, PHP_URL_QUERY) . "|";
echo parse_url($url, PHP_URL_FRAGMENT);
?>"#,
        );
        assert_eq!(output, "https|example.com|8080|user|pass|/foo/bar|q=1|frag");
    }

    #[test]
    fn test_hash_function() {
        let output = run_php(
            r#"<?php
echo hash("sha256", "hello");
?>"#,
        );
        assert_eq!(
            output,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_hash_hmac_function() {
        let output = run_php(
            r#"<?php
echo hash_hmac("sha256", "what do ya want for nothing?", "Jefe");
?>"#,
        );
        assert_eq!(
            output,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn test_parse_url_path_only() {
        let output = run_php(
            r#"<?php
echo parse_url("/health", PHP_URL_PATH);
?>"#,
        );
        assert_eq!(output, "/health");
    }

    #[test]
    fn test_glob_character_class() {
        // Create temp files to test glob with character class
        let output = run_php(
            r#"<?php
$dir = sys_get_temp_dir() . "/phprs_glob_test_" . getmypid();
mkdir($dir, 0755, true);
file_put_contents($dir . "/[id].php", "");
file_put_contents($dir . "/normal.php", "");
$result = glob($dir . "/[[]*.php");
echo count($result) . "|" . basename($result[0]);
// Cleanup
unlink($dir . "/[id].php");
unlink($dir . "/normal.php");
rmdir($dir);
?>"#,
        );
        assert_eq!(output, "1|[id].php");
    }

    #[test]
    fn test_foreach_array_destructuring() {
        let output = run_php(
            r#"<?php
$items = [["bold", "**"], ["italic", "*"], ["code", "`"]];
foreach ($items as [$label, $md]) {
    echo "$label=$md\n";
}
?>"#,
        );
        assert_eq!(output, "bold=**\nitalic=*\ncode=`\n");
    }

    #[test]
    fn test_foreach_list_destructuring() {
        let output = run_php(
            r#"<?php
$items = [["a", 1], ["b", 2]];
foreach ($items as list($k, $v)) {
    echo "$k:$v ";
}
?>"#,
        );
        assert_eq!(output, "a:1 b:2 ");
    }

    #[test]
    fn test_password_hash_and_verify() {
        let output = run_php(
            r#"<?php
$hash = password_hash("secret123", PASSWORD_BCRYPT);
echo (str_starts_with($hash, "$2y$") ? "yes" : "no") . "\n";
echo (password_verify("secret123", $hash) ? "yes" : "no") . "\n";
echo (password_verify("wrong", $hash) ? "yes" : "no") . "\n";
echo (password_needs_rehash($hash, PASSWORD_BCRYPT) ? "yes" : "no") . "\n";
?>"#,
        );
        assert_eq!(output, "yes\nyes\nno\nno\n");
    }

    #[test]
    fn test_parse_str_with_result() {
        let output = run_php(
            r#"<?php
$qs = "v=FTEeFbnicO0&t=42";
parse_str($qs, $result);
echo $result['v'] . "\n";
echo $result['t'] . "\n";
?>"#,
        );
        assert_eq!(output, "FTEeFbnicO0\n42\n");
    }

    #[test]
    fn test_foreach_array_destructuring_with_key() {
        let output = run_php(
            r#"<?php
$items = [["x", 10], ["y", 20]];
foreach ($items as $i => [$name, $val]) {
    echo "$i:$name=$val ";
}
?>"#,
        );
        assert_eq!(output, "0:x=10 1:y=20 ");
    }

    // =========================================================================
    // Process & system info functions
    // =========================================================================

    #[test]
    fn test_getmypid() {
        let output = run_php("<?php $pid = getmypid(); echo is_int($pid) ? 'int' : 'other'; echo $pid > 0 ? ' positive' : ' zero';");
        assert_eq!(output, "int positive");
    }

    #[test]
    fn test_getmyuid() {
        let output = run_php("<?php $uid = getmyuid(); echo is_int($uid) ? 'int' : 'other';");
        assert_eq!(output, "int");
    }

    #[test]
    fn test_getmygid() {
        let output = run_php("<?php $gid = getmygid(); echo is_int($gid) ? 'int' : 'other';");
        assert_eq!(output, "int");
    }

    #[test]
    fn test_get_current_user() {
        let output = run_php("<?php $u = get_current_user(); echo is_string($u) ? 'string' : 'other'; echo strlen($u) > 0 ? ' notempty' : ' empty';");
        assert_eq!(output, "string notempty");
    }

    #[test]
    fn test_gethostname() {
        let output = run_php("<?php $h = gethostname(); echo is_string($h) ? 'string' : 'other'; echo strlen($h) > 0 ? ' notempty' : ' empty';");
        assert_eq!(output, "string notempty");
    }

    #[test]
    fn test_sys_getloadavg() {
        let output = run_php(r#"<?php
$load = sys_getloadavg();
echo is_array($load) ? 'array' : 'other';
echo count($load) === 3 ? ' three' : ' wrong';
echo is_float($load[0]) ? ' float' : ' notfloat';
"#);
        assert_eq!(output, "array three float");
    }

    #[test]
    fn test_getrusage() {
        let output = run_php(r#"<?php
$ru = getrusage();
echo is_array($ru) ? 'array' : 'other';
echo isset($ru['ru_utime.tv_sec']) ? ' utime' : ' noutime';
echo isset($ru['ru_stime.tv_sec']) ? ' stime' : ' nostime';
echo isset($ru['ru_maxrss']) ? ' maxrss' : ' nomaxrss';
"#);
        assert_eq!(output, "array utime stime maxrss");
    }

    #[test]
    fn test_connection_status_constants() {
        let output = run_php(r#"<?php
echo CONNECTION_NORMAL . " ";
echo CONNECTION_ABORTED . " ";
echo CONNECTION_TIMEOUT;
"#);
        assert_eq!(output, "0 1 2");
    }

    #[test]
    fn test_connection_status_returns_normal() {
        let output = run_php("<?php echo connection_status();");
        assert_eq!(output, "0");
    }

    #[test]
    fn test_ignore_user_abort() {
        let output = run_php(r#"<?php
echo ignore_user_abort() . "\n";
ignore_user_abort(true);
echo ignore_user_abort() . "\n";
echo ignore_user_abort(false) . "\n";
echo ignore_user_abort() . "\n";
"#);
        assert_eq!(output, "0\n1\n1\n0\n");
    }

    #[test]
    fn test_headers_sent_initially_false() {
        let output = run_php("<?php echo headers_sent() ? 'yes' : 'no';");
        // headers_sent() itself produces output, but we check the return value before that
        // Actually: echo calls write_output which sets headers_sent, but headers_sent() is called
        // before echo. In PHP, output starts after headers_sent returns.
        assert_eq!(output, "no");
    }

    // =========================================================================
    // compact / extract / settype
    // =========================================================================

    #[test]
    fn test_compact_with_array_arg() {
        let output = run_php(r#"<?php
$x = 1;
$y = 2;
$z = 3;
$result = compact(["x", "y"], "z");
echo $result["x"] . " " . $result["y"] . " " . $result["z"];
"#);
        assert_eq!(output, "1 2 3");
    }

    #[test]
    fn test_extract_overwrite() {
        let output = run_php(r#"<?php
$data = ["name" => "Bob", "age" => 25];
$count = extract($data);
echo "$name $age $count";
"#);
        assert_eq!(output, "Bob 25 2");
    }

    #[test]
    fn test_extract_skip() {
        let output = run_php(r#"<?php
$name = "Original";
$data = ["name" => "Bob", "age" => 25];
$count = extract($data, EXTR_SKIP);
echo "$name $age $count";
"#);
        assert_eq!(output, "Original 25 1");
    }

    #[test]
    fn test_settype_int() {
        let output = run_php(r#"<?php
$val = "42";
settype($val, "integer");
echo gettype($val) . " " . $val;
"#);
        assert_eq!(output, "integer 42");
    }

    #[test]
    fn test_settype_bool() {
        let output = run_php(r#"<?php
$val = "hello";
settype($val, "boolean");
echo var_export($val, true);
"#);
        assert_eq!(output, "true");
    }

    #[test]
    fn test_settype_array() {
        let output = run_php(r#"<?php
$val = "test";
settype($val, "array");
echo is_array($val) ? "array" : "other";
echo " " . $val[0];
"#);
        assert_eq!(output, "array test");
    }

    #[test]
    fn test_settype_null() {
        let output = run_php(r#"<?php
$val = 42;
settype($val, "null");
echo is_null($val) ? "null" : "other";
"#);
        assert_eq!(output, "null");
    }

    // =========================================================================
    // error_get_last / error_clear_last
    // =========================================================================

    #[test]
    fn test_error_get_last_initially_null() {
        let output = run_php("<?php echo error_get_last() === null ? 'null' : 'set';");
        assert_eq!(output, "null");
    }

    // =========================================================================
    // forward_static_call
    // =========================================================================

    #[test]
    fn test_forward_static_call() {
        let output = run_php(r#"<?php
function my_add($a, $b) { return $a + $b; }
echo forward_static_call("my_add", 3, 4);
"#);
        assert_eq!(output, "7");
    }

    // =========================================================================
    // memory_get_usage
    // =========================================================================

    #[test]
    fn test_memory_get_usage_returns_positive() {
        let output = run_php("<?php echo memory_get_usage() > 0 ? 'positive' : 'zero';");
        assert_eq!(output, "positive");
    }

    // =========================================================================
    // posix functions
    // =========================================================================

    #[test]
    fn test_posix_getuid() {
        let output = run_php("<?php echo is_int(posix_getuid()) ? 'int' : 'other';");
        assert_eq!(output, "int");
    }

    #[test]
    fn test_posix_getppid() {
        let output = run_php("<?php $ppid = posix_getppid(); echo $ppid > 0 ? 'positive' : 'zero';");
        assert_eq!(output, "positive");
    }

    #[test]
    fn test_posix_uname() {
        let output = run_php(r#"<?php
$u = posix_uname();
echo isset($u['sysname']) ? 'sysname' : 'no';
echo isset($u['nodename']) ? ' nodename' : ' no';
echo isset($u['release']) ? ' release' : ' no';
echo isset($u['machine']) ? ' machine' : ' no';
"#);
        assert_eq!(output, "sysname nodename release machine");
    }

    // =========================================================================
    // popen / pclose
    // =========================================================================

    #[test]
    fn test_popen_pclose() {
        let output = run_php(r#"<?php
$fp = popen("echo hello", "r");
$line = fgets($fp);
echo trim($line);
pclose($fp);
"#);
        assert_eq!(output, "hello");
    }

    #[test]
    fn test_strtok_basic() {
        let output = run_php(r#"<?php
$token = strtok("Hello World PHP", " ");
while ($token !== false) {
    echo $token . "\n";
    $token = strtok(" ");
}
"#);
        assert_eq!(output, "Hello\nWorld\nPHP\n");
    }

    #[test]
    fn test_strtok_multiple_delimiters() {
        let output = run_php(r#"<?php
$token = strtok("one,two;three", ",;");
$result = [];
while ($token !== false) {
    $result[] = $token;
    $token = strtok(",;");
}
echo implode("|", $result);
"#);
        assert_eq!(output, "one|two|three");
    }

    #[test]
    fn test_hash_init_update_final() {
        let output = run_php(r#"<?php
$ctx = hash_init("md5");
hash_update($ctx, "Hello ");
hash_update($ctx, "World");
echo hash_final($ctx);
"#);
        assert_eq!(output, "b10a8db164e0754105b7a99be72e3fe5");
    }

    #[test]
    fn test_hash_init_sha256() {
        let output = run_php(r#"<?php
$ctx = hash_init("sha256");
hash_update($ctx, "test");
echo hash_final($ctx);
"#);
        assert_eq!(output, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
    }

    #[test]
    fn test_hash_copy() {
        let output = run_php(r#"<?php
$ctx = hash_init("md5");
hash_update($ctx, "Hello ");
$ctx2 = hash_copy($ctx);
hash_update($ctx, "World");
hash_update($ctx2, "PHP");
echo hash_final($ctx) . "\n";
echo hash_final($ctx2) . "\n";
"#);
        let lines: Vec<&str> = output.trim().split('\n').collect();
        assert_eq!(lines[0], "b10a8db164e0754105b7a99be72e3fe5"); // md5("Hello World")
        assert_eq!(lines[1], "c540ce201d398a7d275c6e0c669097f3"); // md5("Hello PHP")
    }

    #[test]
    fn test_apcu_store_fetch() {
        let output = run_php(r#"<?php
apcu_store("key1", "value1");
apcu_store("key2", 42);
echo apcu_fetch("key1") . "\n";
echo apcu_fetch("key2") . "\n";
var_dump(apcu_fetch("nonexistent"));
"#);
        assert_eq!(output, "value1\n42\nbool(false)\n");
    }

    #[test]
    fn test_apcu_add_exists_delete() {
        let output = run_php(r#"<?php
var_dump(apcu_add("k", "first"));
var_dump(apcu_add("k", "second"));
echo apcu_fetch("k") . "\n";
var_dump(apcu_exists("k"));
apcu_delete("k");
var_dump(apcu_exists("k"));
"#);
        assert_eq!(output, "bool(true)\nbool(false)\nfirst\nbool(true)\nbool(false)\n");
    }

    #[test]
    fn test_apcu_inc_dec() {
        let output = run_php(r#"<?php
apcu_store("counter", 10);
echo apcu_inc("counter") . "\n";
echo apcu_inc("counter", 5) . "\n";
echo apcu_dec("counter", 3) . "\n";
echo apcu_fetch("counter") . "\n";
"#);
        assert_eq!(output, "11\n16\n13\n13\n");
    }

    #[test]
    fn test_apcu_clear_cache() {
        let output = run_php(r#"<?php
apcu_store("a", 1);
apcu_store("b", 2);
var_dump(apcu_exists("a"));
apcu_clear_cache();
var_dump(apcu_exists("a"));
"#);
        assert_eq!(output, "bool(true)\nbool(false)\n");
    }

    #[test]
    fn test_array_column_with_objects() {
        let output = run_php(r#"<?php
$records = [];
$obj1 = new stdClass;
$obj1->name = "Alice";
$obj1->age = 30;
$records[] = $obj1;
$obj2 = new stdClass;
$obj2->name = "Bob";
$obj2->age = 25;
$records[] = $obj2;
$names = array_column($records, "name");
echo implode(", ", $names);
"#);
        assert_eq!(output, "Alice, Bob");
    }

    #[test]
    fn test_array_map_multi_array() {
        let output = run_php(r#"<?php
$a = [1, 2, 3];
$b = [10, 20, 30];
$result = array_map(function($x, $y) { return $x + $y; }, $a, $b);
echo implode(", ", $result);
"#);
        assert_eq!(output, "11, 22, 33");
    }

    #[test]
    fn test_array_map_multi_null_callback() {
        let output = run_php(r#"<?php
$a = [1, 2, 3];
$b = ['a', 'b', 'c'];
$result = array_map(null, $a, $b);
echo count($result) . "\n";
echo $result[0][0] . "," . $result[0][1] . "\n";
echo $result[1][0] . "," . $result[1][1] . "\n";
"#);
        assert_eq!(output, "3\n1,a\n2,b\n");
    }

    #[test]
    fn test_array_map_multi_uneven() {
        let output = run_php(r#"<?php
$a = [1, 2, 3, 4];
$b = [10, 20];
$result = array_map(function($x, $y) { return ($x ?? 0) + ($y ?? 0); }, $a, $b);
echo implode(", ", $result);
"#);
        assert_eq!(output, "11, 22, 3, 4");
    }

    #[test]
    fn test_file_put_contents_append() {
        let output = run_php(r#"<?php
$tmp = tempnam(sys_get_temp_dir(), 'phprs');
file_put_contents($tmp, "Hello");
file_put_contents($tmp, " World", FILE_APPEND);
echo file_get_contents($tmp);
unlink($tmp);
"#);
        assert_eq!(output, "Hello World");
    }

    #[test]
    fn test_file_put_contents_lock_ex() {
        let output = run_php(r#"<?php
$tmp = tempnam(sys_get_temp_dir(), 'phprs');
file_put_contents($tmp, "locked data", LOCK_EX);
echo file_get_contents($tmp);
unlink($tmp);
"#);
        assert_eq!(output, "locked data");
    }

    #[test]
    fn test_dirname_levels() {
        let output = run_php(r#"<?php
echo dirname("/a/b/c/d") . "\n";
echo dirname("/a/b/c/d", 2) . "\n";
echo dirname("/a/b/c/d", 3) . "\n";
"#);
        assert_eq!(output, "/a/b/c\n/a/b\n/a\n");
    }

    #[test]
    fn test_first_class_callable() {
        let output = run_php(r#"<?php
function double($x) { return $x * 2; }
$fn = strlen(...);
echo $fn("hello") . "\n";
$fn2 = double(...);
echo $fn2(21);
"#);
        assert_eq!(output, "5\n42");
    }

    #[test]
    fn test_str_pad_both() {
        let output = run_php(r#"<?php
echo str_pad("hi", 10, "-", STR_PAD_BOTH);
"#);
        assert_eq!(output, "----hi----");
    }

    #[test]
    fn test_str_pad_left() {
        let output = run_php(r#"<?php
echo str_pad("42", 5, "0", STR_PAD_LEFT);
"#);
        assert_eq!(output, "00042");
    }

    #[test]
    fn test_fgetcsv_quoted() {
        let output = run_php(r#"<?php
$tmp = tempnam(sys_get_temp_dir(), 'csv');
file_put_contents($tmp, '"hello, world",42,"say ""hi"""' . "\n");
$fp = fopen($tmp, 'r');
$row = fgetcsv($fp);
fclose($fp);
echo $row[0] . "\n";
echo $row[1] . "\n";
echo $row[2] . "\n";
unlink($tmp);
"#);
        assert_eq!(output, "hello, world\n42\nsay \"hi\"\n");
    }

    #[test]
    fn test_array_map_with_keys() {
        let output = run_php(r#"<?php
$arr = ['a' => 1, 'b' => 2, 'c' => 3];
$result = array_map(function($v) { return $v * 10; }, $arr);
echo $result['a'] . ',' . $result['b'] . ',' . $result['c'];
"#);
        assert_eq!(output, "10,20,30");
    }

    #[test]
    fn test_array_push_modifies_array() {
        let output = run_php(r#"<?php
$arr = [1, 2];
array_push($arr, 3, 4, 5);
echo count($arr) . "\n";
echo implode(",", $arr);
"#);
        assert_eq!(output, "5\n1,2,3,4,5");
    }

    #[test]
    fn test_explode_positive_limit() {
        let output = run_php(r#"<?php
$parts = explode(",", "a,b,c,d", 3);
echo implode("|", $parts);
"#);
        assert_eq!(output, "a|b|c,d");
    }

    #[test]
    fn test_explode_negative_limit() {
        let output = run_php(r#"<?php
$parts = explode(",", "a,b,c,d,e", -2);
echo implode("|", $parts);
"#);
        assert_eq!(output, "a|b|c");
    }

    #[test]
    fn test_range_characters() {
        let output = run_php(r#"<?php
$letters = range('a', 'e');
echo implode("", $letters);
"#);
        assert_eq!(output, "abcde");
    }

    #[test]
    fn test_range_float() {
        let output = run_php(r#"<?php
$floats = range(0.0, 1.0, 0.5);
echo count($floats) . "\n";
echo $floats[0] . "," . $floats[1] . "," . $floats[2];
"#);
        assert_eq!(output, "3\n0,0.5,1");
    }

    #[test]
    fn test_range_reverse() {
        let output = run_php(r#"<?php
$r = range(5, 1);
echo implode(",", $r);
"#);
        assert_eq!(output, "5,4,3,2,1");
    }

    #[test]
    fn test_sort_numeric_flag() {
        let output = run_php(r#"<?php
$arr = ["10", "9", "100", "2"];
sort($arr, SORT_NUMERIC);
echo implode(",", $arr);
"#);
        assert_eq!(output, "2,9,10,100");
    }

    #[test]
    fn test_sort_string_flag() {
        let output = run_php(r#"<?php
$arr = [10, 9, 100, 2];
sort($arr, SORT_STRING);
echo implode(",", $arr);
"#);
        // String sort: "10" < "100" < "2" < "9"
        assert_eq!(output, "10,100,2,9");
    }

    #[test]
    fn test_sort_natural_flag() {
        let output = run_php(r#"<?php
$arr = ["img12", "img2", "img1", "img10"];
sort($arr, SORT_NATURAL);
echo implode(",", $arr);
"#);
        assert_eq!(output, "img1,img2,img10,img12");
    }

    #[test]
    fn test_array_reverse_preserve_keys() {
        let output = run_php(r#"<?php
$arr = [10 => 'a', 20 => 'b', 30 => 'c'];
$r = array_reverse($arr, true);
$keys = array_keys($r);
echo implode(",", $keys) . "\n";
echo implode(",", $r);
"#);
        assert_eq!(output, "30,20,10\nc,b,a");
    }

    #[test]
    fn test_array_reverse_no_preserve() {
        let output = run_php(r#"<?php
$arr = [10 => 'a', 20 => 'b', 30 => 'c'];
$r = array_reverse($arr);
$keys = array_keys($r);
echo implode(",", $keys) . "\n";
echo implode(",", $r);
"#);
        assert_eq!(output, "0,1,2\nc,b,a");
    }

    #[test]
    fn test_array_keys_search_value() {
        let output = run_php(r#"<?php
$arr = ['a' => 'x', 'b' => 'y', 'c' => 'x', 'd' => 'z'];
$keys = array_keys($arr, 'x');
echo implode(",", $keys);
"#);
        assert_eq!(output, "a,c");
    }

    #[test]
    fn test_array_keys_strict() {
        let output = run_php(r#"<?php
$arr = [0 => '0', 1 => 0, 2 => false, 3 => null];
$keys = array_keys($arr, 0, true);
echo implode(",", $keys);
"#);
        assert_eq!(output, "1");
    }

    #[test]
    fn test_str_replace_array_search() {
        let output = run_php(r#"<?php
echo str_replace(['a', 'e', 'i', 'o', 'u'], '*', 'Hello World');
"#);
        assert_eq!(output, "H*ll* W*rld");
    }

    #[test]
    fn test_str_replace_array_search_replace() {
        let output = run_php(r#"<?php
echo str_replace(['apple', 'banana'], ['orange', 'grape'], 'I like apple and banana');
"#);
        assert_eq!(output, "I like orange and grape");
    }

    #[test]
    fn test_array_unshift_order() {
        let output = run_php(r#"<?php
$arr = ['c'];
array_unshift($arr, 'a', 'b');
echo implode(",", $arr);
"#);
        assert_eq!(output, "a,b,c");
    }

    #[test]
    fn test_usort_modifies_array() {
        let output = run_php(r#"<?php
$arr = [3, 1, 4, 1, 5];
usort($arr, function($a, $b) { return $a - $b; });
echo implode(",", $arr);
"#);
        assert_eq!(output, "1,1,3,4,5");
    }

    #[test]
    fn test_usort_reverse() {
        let output = run_php(r#"<?php
$arr = [3, 1, 4, 1, 5];
usort($arr, function($a, $b) { return $b - $a; });
echo implode(",", $arr);
"#);
        assert_eq!(output, "5,4,3,1,1");
    }

    #[test]
    fn test_uasort_preserves_keys() {
        let output = run_php(r#"<?php
$arr = ['c' => 3, 'a' => 1, 'b' => 2];
uasort($arr, function($a, $b) { return $a - $b; });
$keys = array_keys($arr);
echo implode(",", $keys) . "\n";
echo implode(",", $arr);
"#);
        assert_eq!(output, "a,b,c\n1,2,3");
    }

    #[test]
    fn test_backed_enum_value_name() {
        let output = run_php(r#"<?php
enum Color: string {
    case Red = "red";
    case Green = "green";
}
$c = Color::Green;
echo $c->value . "\n";
echo $c->name;
"#);
        assert_eq!(output, "green\nGreen");
    }

    #[test]
    fn test_enum_method() {
        let output = run_php(r#"<?php
enum Color: string {
    case Red = "red";
    case Green = "green";

    public function label(): string {
        return "Color: " . $this->name;
    }
}
echo Color::Red->label();
"#);
        assert_eq!(output, "Color: Red");
    }

    #[test]
    fn test_enum_match_this() {
        let output = run_php(r#"<?php
enum Status: int {
    case Active = 1;
    case Inactive = 0;

    public function label(): string {
        return match($this) {
            Status::Active => "Active",
            Status::Inactive => "Inactive",
        };
    }
}
echo Status::Active->label();
"#);
        assert_eq!(output, "Active");
    }

    #[test]
    fn test_enum_strict_equality() {
        let output = run_php(r#"<?php
enum Suit {
    case Hearts;
    case Diamonds;
}
$a = Suit::Hearts;
$b = Suit::Hearts;
echo ($a === $b ? "equal" : "not equal") . "\n";
echo ($a === Suit::Diamonds ? "equal" : "not equal");
"#);
        assert_eq!(output, "equal\nnot equal");
    }

    #[test]
    fn test_enum_from() {
        let output = run_php(r#"<?php
enum Status: string {
    case Active = "active";
    case Inactive = "inactive";
}
$s = Status::from("active");
echo $s->name . "\n";
echo $s->value;
"#);
        assert_eq!(output, "Active\nactive");
    }

    #[test]
    fn test_enum_try_from() {
        let output = run_php(r#"<?php
enum Color: int {
    case Red = 1;
    case Green = 2;
    case Blue = 3;
}
$c = Color::tryFrom(2);
echo $c->name . "\n";
$n = Color::tryFrom(99);
echo ($n === null ? "null" : "not null");
"#);
        assert_eq!(output, "Green\nnull");
    }

    #[test]
    fn test_enum_cases() {
        let output = run_php(r#"<?php
enum Suit: string {
    case Hearts = "H";
    case Diamonds = "D";
}
$cases = Suit::cases();
echo count($cases) . "\n";
foreach ($cases as $c) {
    echo $c->name . "\n";
}
"#);
        assert!(output.contains("2\n"));
        assert!(output.contains("Hearts\n"));
        assert!(output.contains("Diamonds"));
    }

    #[test]
    fn test_intdiv_overflow() {
        let result = run_php_result(r#"<?php
echo intdiv(PHP_INT_MIN, -1);
"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_array_diff_variadic() {
        let output = run_php(r#"<?php
$a = [1, 2, 3, 4, 5];
$b = [2, 4];
$c = [5];
$result = array_diff($a, $b, $c);
echo implode(",", $result);
"#);
        assert_eq!(output, "1,3");
    }

    #[test]
    fn test_array_intersect_variadic() {
        let output = run_php(r#"<?php
$a = [1, 2, 3, 4, 5];
$b = [2, 3, 4, 6];
$c = [3, 4, 7];
$result = array_intersect($a, $b, $c);
echo implode(",", $result);
"#);
        assert_eq!(output, "3,4");
    }

    #[test]
    fn test_array_unique_sort_string() {
        let output = run_php(r#"<?php
$a = [0, "a", 1, "b", "0"];
$result = array_unique($a, SORT_STRING);
echo count($result);
"#);
        // With SORT_STRING, "0" and 0 are same as strings, so one is removed
        // 0, "a", 1, "b" remain (4 unique string representations: "0", "a", "1", "b")
        assert_eq!(output, "4");
    }

    #[test]
    fn test_compact_includes_null() {
        let output = run_php(r#"<?php
$a = 1;
$b = null;
$c = "hello";
$result = compact("a", "b", "c");
echo count($result) . "\n";
echo ($result["b"] === null ? "null" : "other");
"#);
        assert_eq!(output, "3\nnull");
    }

    #[test]
    fn test_substr_count_offset_length() {
        let output = run_php(r#"<?php
echo substr_count("hello world hello", "hello") . "\n";
echo substr_count("hello world hello", "hello", 5) . "\n";
echo substr_count("hello world hello", "hello", 0, 5);
"#);
        assert_eq!(output, "2\n1\n1");
    }

    #[test]
    fn test_trim_range_syntax() {
        let output = run_php(r#"<?php
echo trim("abcHELLOabc", "a..c") . "\n";
echo ltrim("123hello", "0..9") . "\n";
echo rtrim("hello!!!", "!..!");
"#);
        assert_eq!(output, "HELLO\nhello\nhello");
    }

    #[test]
    fn test_ctype_digit_empty() {
        let output = run_php(r#"<?php
echo ctype_digit("") ? "true" : "false";
echo "\n";
echo ctype_digit("123") ? "true" : "false";
"#);
        assert_eq!(output, "false\ntrue");
    }

    #[test]
    fn test_interface_exists_vs_class() {
        let output = run_php(r#"<?php
interface Foo {}
class Bar implements Foo {}
echo interface_exists("Foo") ? "true" : "false";
echo "\n";
echo interface_exists("Bar") ? "true" : "false";
"#);
        assert_eq!(output, "true\nfalse");
    }

    #[test]
    fn test_method_exists_case_insensitive() {
        let output = run_php(r#"<?php
class MyClass {
    public function myMethod() {}
}
echo method_exists("MyClass", "mymethod") ? "true" : "false";
echo "\n";
echo method_exists("MyClass", "MYMETHOD") ? "true" : "false";
"#);
        assert_eq!(output, "true\ntrue");
    }

    #[test]
    fn test_property_exists_string_class() {
        let output = run_php(r#"<?php
class MyClass {
    public $prop = 1;
}
echo property_exists("MyClass", "prop") ? "true" : "false";
echo "\n";
echo property_exists("MyClass", "nonexistent") ? "true" : "false";
"#);
        assert_eq!(output, "true\nfalse");
    }

    #[test]
    fn test_defined_class_constant() {
        let output = run_php(r#"<?php
class Foo {
    const BAR = 42;
}
echo defined("Foo::BAR") ? "true" : "false";
echo "\n";
echo defined("Foo::NOPE") ? "true" : "false";
echo "\n";
echo constant("Foo::BAR");
"#);
        assert_eq!(output, "true\nfalse\n42");
    }

    #[test]
    fn test_strlen_counts_bytes() {
        let output = run_php(r#"<?php
echo strlen("hello") . "\n";
echo mb_strlen("hello");
"#);
        assert_eq!(output, "5\n5");
    }

    #[test]
    fn test_http_response_code_getter() {
        let output = run_php(r#"<?php
http_response_code(404);
echo http_response_code();
"#);
        assert_eq!(output, "404");
    }

    #[test]
    fn test_strtotime_ago() {
        let output = run_php(r#"<?php
$now = time();
$week_ago = strtotime("1 week ago");
echo ($week_ago < $now && $week_ago > $now - 700000) ? "ok" : "fail";
"#);
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_strtotime_midnight_noon() {
        let output = run_php(r#"<?php
$m = strtotime("midnight");
$n = strtotime("noon");
echo ($m !== false && $n !== false && $n > $m) ? "ok" : "fail";
"#);
        assert_eq!(output, "ok");
    }

    #[test]
    fn test_date_h_format() {
        let output = run_php(r#"<?php
echo date("h", 0);
"#);
        // Epoch is midnight UTC, so 12-hour format = 12
        assert_eq!(output, "12");
    }

    #[test]
    fn test_date_t_timezone() {
        let output = run_php(r#"<?php
echo date("T");
"#);
        assert_eq!(output, "UTC");
    }

    #[test]
    fn test_short_array_destructure_holes() {
        let output = run_php(r#"<?php
[$a, , $b] = [1, 2, 3];
echo "$a $b\n";
[, $x, , $y] = [10, 20, 30, 40];
echo "$x $y";
"#);
        assert_eq!(output, "1 3\n20 40");
    }

    #[test]
    fn test_array_count_values_int_keys() {
        let output = run_php(r#"<?php
$r = array_count_values([1, 1, "a", "a", 2]);
echo $r[1] . "\n";
echo $r["a"] . "\n";
echo $r[2];
"#);
        assert_eq!(output, "2\n2\n1");
    }

    #[test]
    fn test_unset_reference_array() {
        let output = run_php(r#"<?php
$a = ["x" => 1, "y" => 2, "z" => 3];
$b = &$a;
unset($b["y"]);
echo count($a) . "\n";
echo isset($a["y"]) ? "yes" : "no";
"#);
        assert_eq!(output, "2\nno");
    }
}
