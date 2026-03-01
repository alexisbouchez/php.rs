#![allow(unused_variables, unused_mut, unreachable_patterns, unused_imports)]

use crate::value::{ArrayKey, PhpArray, PhpObject, Value};
use crate::vm::{Vm, VmError, VmResult};
use php_rs_compiler::op::OperandType;

/// Dispatch a built-in math function call.
/// Returns `Ok(Some(value))` if handled, `Ok(None)` if not recognized.
pub(crate) fn dispatch(
    vm: &mut Vm,
    name: &str,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Option<Value>> {
    match name {
        "abs" => {
            let v = args.first().cloned().unwrap_or(Value::Null);
            let result = match v {
                Value::Long(n) => Value::Long(n.abs()),
                Value::Double(f) => Value::Double(f.abs()),
                _ => Value::Long(v.to_long().abs()),
            };
            Ok(Some(result))
        }
        "max" => {
            if args.len() == 1 {
                if let Value::Array(ref a) = args[0] {
                    let mut max = Value::Null;
                    for (_, v) in a.entries() {
                        if max.is_null() || v.is_smaller(&max) == false && !max.strict_eq(v) {
                            max = v.clone();
                        }
                    }
                    return Ok(Some(max));
                }
            }
            let mut max = args.first().cloned().unwrap_or(Value::Null);
            for v in args.iter().skip(1) {
                if max.is_smaller(v) {
                    max = v.clone();
                }
            }
            Ok(Some(max))
        }
        "min" => {
            if args.len() == 1 {
                if let Value::Array(ref a) = args[0] {
                    let mut min = Value::Null;
                    for (_, v) in a.entries() {
                        if min.is_null() || v.is_smaller(&min) {
                            min = v.clone();
                        }
                    }
                    return Ok(Some(min));
                }
            }
            let mut min = args.first().cloned().unwrap_or(Value::Null);
            for v in args.iter().skip(1) {
                if v.is_smaller(&min) {
                    min = v.clone();
                }
            }
            Ok(Some(min))
        }
        "floor" => {
            let v = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(v.floor())))
        }
        "ceil" => {
            let v = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(v.ceil())))
        }
        "round" => {
            let v = args.first().cloned().unwrap_or(Value::Null).to_double();
            let precision = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
            let factor = 10f64.powi(precision as i32);
            Ok(Some(Value::Double((v * factor).round() / factor)))
        }
        "pow" => {
            let base = args.first().cloned().unwrap_or(Value::Null);
            let exp = args.get(1).cloned().unwrap_or(Value::Null);
            Ok(Some(base.pow(&exp)))
        }
        "sqrt" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(n.sqrt())))
        }
        "log" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_double();
            let base = args.get(1).map(|v| v.to_double());
            let result = match base {
                Some(b) => n.log(b),
                None => n.ln(),
            };
            Ok(Some(Value::Double(result)))
        }
        "log10" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(n.log10())))
        }
        "log2" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(n.log2())))
        }
        "fmod" => {
            let x = args.first().cloned().unwrap_or(Value::Null).to_double();
            let y = args.get(1).cloned().unwrap_or(Value::Long(1)).to_double();
            Ok(Some(Value::Double(x % y)))
        }
        "intdiv" => {
            let a = args.first().cloned().unwrap_or(Value::Null).to_long();
            let b = args.get(1).cloned().unwrap_or(Value::Long(1)).to_long();
            if b == 0 {
                Err(VmError::FatalError("Division by zero".to_string()))
            } else if a == i64::MIN && b == -1 {
                Err(VmError::FatalError("Division of PHP_INT_MIN by -1 is not an integer".to_string()))
            } else {
                Ok(Some(Value::Long(a / b)))
            }
        }
        "pi" => Ok(Some(Value::Double(std::f64::consts::PI))),
        "sin" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(n.sin())))
        }
        "cos" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(n.cos())))
        }
        "tan" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(n.tan())))
        }
        "asin" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(n.asin())))
        }
        "acos" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(n.acos())))
        }
        "atan" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(n.atan())))
        }
        "atan2" => {
            let y = args.first().cloned().unwrap_or(Value::Null).to_double();
            let x = args.get(1).cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(y.atan2(x))))
        }
        "exp" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(n.exp())))
        }
        "base_convert" => {
            let number = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let from_base = args.get(1).cloned().unwrap_or(Value::Long(10)).to_long() as u32;
            let to_base = args.get(2).cloned().unwrap_or(Value::Long(10)).to_long() as u32;
            match php_rs_ext_standard::math::php_base_convert(&number, from_base, to_base) {
                Some(s) => Ok(Some(Value::String(s))),
                None => Ok(Some(Value::Bool(false))),
            }
        }
        "bindec" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Long(php_rs_ext_standard::math::php_bindec(&s))))
        }
        "octdec" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Long(php_rs_ext_standard::math::php_octdec(&s))))
        }
        "hexdec" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Long(php_rs_ext_standard::math::php_hexdec(&s))))
        }
        "decoct" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_long();
            Ok(Some(Value::String(php_rs_ext_standard::math::php_decoct(
                n,
            ))))
        }
        "dechex" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_long();
            Ok(Some(Value::String(php_rs_ext_standard::math::php_dechex(
                n,
            ))))
        }
        "decbin" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_long();
            Ok(Some(Value::String(php_rs_ext_standard::math::php_decbin(
                n,
            ))))
        }
        "rand" | "mt_rand" => {
            let min = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let max = args
                .get(1)
                .cloned()
                .unwrap_or(Value::Long(i32::MAX as i64))
                .to_long();
            let mut rng = php_rs_ext_random::Randomizer::new(Box::new(
                php_rs_ext_random::Mt19937::new(Some(vm.mt_rng.generate_u32() as u64)),
            ));
            Ok(Some(Value::Long(rng.next_int(min, max))))
        }
        "random_int" => {
            let min = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let max = args
                .get(1)
                .cloned()
                .unwrap_or(Value::Long(i64::MAX))
                .to_long();
            let mut rng =
                php_rs_ext_random::Randomizer::new(Box::new(php_rs_ext_random::SecureEngine));
            Ok(Some(Value::Long(rng.next_int(min, max))))
        }
        "getrandmax" | "mt_getrandmax" => Ok(Some(Value::Long(i32::MAX as i64))),
        "is_nan" => {
            let v = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Bool(v.is_nan())))
        }
        "is_infinite" => {
            let v = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Bool(v.is_infinite())))
        }
        "is_finite" => {
            let v = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Bool(v.is_finite())))
        }
        "hypot" => {
            let x = args.first().cloned().unwrap_or(Value::Null).to_double();
            let y = args.get(1).cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(x.hypot(y))))
        }
        "sinh" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(n.sinh())))
        }
        "cosh" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(n.cosh())))
        }
        "tanh" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(n.tanh())))
        }
        "deg2rad" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(n.to_radians())))
        }
        "rad2deg" => {
            let n = args.first().cloned().unwrap_or(Value::Null).to_double();
            Ok(Some(Value::Double(n.to_degrees())))
        }
        "acosh" => {
            let n = args.first().map(|v| v.to_double()).unwrap_or(0.0);
            Ok(Some(Value::Double(n.acosh())))
        }
        "asinh" => {
            let n = args.first().map(|v| v.to_double()).unwrap_or(0.0);
            Ok(Some(Value::Double(n.asinh())))
        }
        "atanh" => {
            let n = args.first().map(|v| v.to_double()).unwrap_or(0.0);
            Ok(Some(Value::Double(n.atanh())))
        }
        "fdiv" => {
            let a = args.first().map(|v| v.to_double()).unwrap_or(0.0);
            let b = args.get(1).map(|v| v.to_double()).unwrap_or(0.0);
            // IEEE 754 float division handles INF, -INF, NAN correctly
            // Rust's f64 division already follows IEEE 754:
            // x / 0.0 = INF or -INF, 0.0 / 0.0 = NAN
            let result = a / b;
            Ok(Some(Value::Double(result)))
        }
        "srand" | "mt_srand" => {
            let seed = args.first().map(|v| v.to_long() as u64);
            vm.mt_rng = php_rs_ext_random::Mt19937::new(seed);
            Ok(Some(Value::Null))
        }
        "random_bytes" => {
            let len = args.first().map(|v| v.to_long()).unwrap_or(0) as usize;
            let bytes = php_rs_ext_random::SecureEngine::generate_bytes(len);
            // PHP strings are binary-safe: map each byte to its Latin-1 codepoint
            let s: String = bytes.iter().map(|&b| b as char).collect();
            Ok(Some(Value::String(s)))
        }
        // =====================================================================
        // bcmath — real arbitrary precision via php_rs_ext_bcmath crate
        // =====================================================================
        "bcadd" => {
            let a = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let b = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let scale = args.get(2).map(|v| Some(v.to_long() as usize));
            let result = php_rs_ext_bcmath::bcadd(&a, &b, scale.unwrap_or(None));
            Ok(Some(Value::String(result)))
        }
        "bcsub" => {
            let a = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let b = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let scale = args.get(2).map(|v| Some(v.to_long() as usize));
            let result = php_rs_ext_bcmath::bcsub(&a, &b, scale.unwrap_or(None));
            Ok(Some(Value::String(result)))
        }
        "bcmul" => {
            let a = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let b = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let scale = args.get(2).map(|v| Some(v.to_long() as usize));
            let result = php_rs_ext_bcmath::bcmul(&a, &b, scale.unwrap_or(None));
            Ok(Some(Value::String(result)))
        }
        "bcdiv" => {
            let a = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let b = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let scale = args.get(2).map(|v| Some(v.to_long() as usize));
            match php_rs_ext_bcmath::bcdiv(&a, &b, scale.unwrap_or(None)) {
                Ok(result) => Ok(Some(Value::String(result))),
                Err(_) => Err(VmError::FatalError("Division by zero".into())),
            }
        }
        "bcmod" => {
            let a = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let b = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let scale = args.get(2).map(|v| Some(v.to_long() as usize));
            match php_rs_ext_bcmath::bcmod(&a, &b, scale.unwrap_or(None)) {
                Ok(result) => Ok(Some(Value::String(result))),
                Err(_) => Err(VmError::FatalError("Division by zero".into())),
            }
        }
        "bcpow" => {
            let a = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let b = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let scale = args.get(2).map(|v| Some(v.to_long() as usize));
            let result = php_rs_ext_bcmath::bcpow(&a, &b, scale.unwrap_or(None));
            Ok(Some(Value::String(result)))
        }
        "bccomp" => {
            let a = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let b = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let scale = args.get(2).map(|v| Some(v.to_long() as usize));
            let result = php_rs_ext_bcmath::bccomp(&a, &b, scale.unwrap_or(None));
            Ok(Some(Value::Long(result as i64)))
        }
        "bcsqrt" => {
            let a = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let scale = args.get(1).map(|v| Some(v.to_long() as usize));
            match php_rs_ext_bcmath::bcsqrt(&a, scale.unwrap_or(None)) {
                Ok(result) => Ok(Some(Value::String(result))),
                Err(_) => Err(VmError::FatalError("Square root of negative number".into())),
            }
        }
        "bcscale" => {
            if args.is_empty() {
                let old = php_rs_ext_bcmath::bcscale(None);
                Ok(Some(Value::Long(old as i64)))
            } else {
                let new_scale = args[0].to_long() as usize;
                let old = php_rs_ext_bcmath::bcscale(Some(new_scale));
                Ok(Some(Value::Long(old as i64)))
            }
        }
        "bcpowmod" => {
            let base = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let exp = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let modulus = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
            let scale = args.get(3).map(|v| Some(v.to_long() as usize));
            match php_rs_ext_bcmath::bcpowmod(&base, &exp, &modulus, scale.unwrap_or(None)) {
                Ok(result) => Ok(Some(Value::String(result))),
                Err(e) => Err(VmError::FatalError(e.to_string())),
            }
        }
        "bcfloor" => {
            let a = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let result = a.parse::<f64>().unwrap_or(0.0).floor();
            Ok(Some(Value::String(format!("{}", result as i64))))
        }
        "bcceil" => {
            let a = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let result = a.parse::<f64>().unwrap_or(0.0).ceil();
            Ok(Some(Value::String(format!("{}", result as i64))))
        }
        "bcround" => {
            let a = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let scale = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            let f = a.parse::<f64>().unwrap_or(0.0);
            let factor = 10f64.powi(scale as i32);
            let result = (f * factor).round() / factor;
            Ok(Some(Value::String(format!(
                "{:.prec$}",
                result,
                prec = scale as usize
            ))))
        }
        "bcdivmod" => {
            let left = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let right = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let scale = args.get(2).map(|v| v.to_long()).unwrap_or(0) as usize;
            match php_rs_ext_bcmath::bcdiv(&left, &right, Some(0)) {
                Ok(quotient) => {
                    let remainder = match php_rs_ext_bcmath::bcmod(&left, &right, Some(scale)) {
                        Ok(r) => r,
                        Err(_) => "0".to_string(),
                    };
                    let mut arr = PhpArray::new();
                    arr.push(Value::String(quotient));
                    arr.push(Value::String(remainder));
                    Ok(Some(Value::Array(arr)))
                }
                Err(_) => {
                    vm.write_output("Warning: Division by zero\n");
                    Ok(Some(Value::Null))
                }
            }
        }
        // =====================================================================
        // gcd / lcm — greatest common divisor / least common multiple
        // =====================================================================
        "gmp_gcd" | "gcd" => {
            let a = args
                .first()
                .map(|v| v.to_long())
                .unwrap_or(0)
                .unsigned_abs();
            let b = args.get(1).map(|v| v.to_long()).unwrap_or(0).unsigned_abs();
            let result = gcd_u64(a, b);
            Ok(Some(Value::Long(result as i64)))
        }
        "gmp_lcm" | "lcm" => {
            let a = args
                .first()
                .map(|v| v.to_long())
                .unwrap_or(0)
                .unsigned_abs();
            let b = args.get(1).map(|v| v.to_long()).unwrap_or(0).unsigned_abs();
            let result = if a == 0 || b == 0 {
                0
            } else {
                a / gcd_u64(a, b) * b
            };
            Ok(Some(Value::Long(result as i64)))
        }
        _ => Ok(None),
    }
}

/// Euclidean GCD algorithm.
fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}
