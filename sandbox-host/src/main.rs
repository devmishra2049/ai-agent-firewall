use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
use wasmtime_wasi::{FsPerms, WasiCtxBuilder};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct ExecutionResult {
    pub success: bool,
    pub error: Option<String>,
    pub fuel_used: u64,
    pub execution_time_ms: u64,
    pub output: String,
}

#[derive(Debug, Deserialize)]
struct Policy {
    #[serde(default = "default_decision")]
    decision: String,
    #[serde(default)]
    network: bool,
    #[serde(default)]
    filesystem_read: bool,
    #[serde(default)]
    filesystem_write: bool,
    #[serde(default)]
    process_execution: bool,
    #[serde(default)]
    dynamic_execution: bool,
    #[serde(default = "default_fuel_limit")]
    fuel_limit: Option<u64>,
}

fn default_fuel_limit() -> Option<u64> {
    Some(10_000_000)
}

fn default_decision() -> String {
    "ALLOW".to_string()
}

const OUTPUT_CAPACITY: usize = 1024 * 1024;

fn execute_wasm(
    module_path: &str,
    func_name: &str,
    fuel_limit: u64,
    policy: &Policy,
    sandbox_fs_dir: &std::path::Path,
) -> ExecutionResult {
    if policy.decision != "ALLOW" {
        return ExecutionResult {
            success: false,
            error: Some("Execution blocked by security policy".to_string()),
            fuel_used: 0,
            execution_time_ms: 0,
            output: String::new(),
        };
    }

    let _ = (
        policy.network,
        policy.process_execution,
        policy.dynamic_execution,
    );

    let mut config = Config::new();
    config.consume_fuel(true);
    let mut pool = wasmtime::PoolingAllocationConfig::default();
    pool.max_memory_size(32 * 1024 * 1024); // 32MB linear memory ceiling per instance
    pool.total_memories(100);
    pool.total_core_instances(100);
    pool.total_tables(100);
    config.allocation_strategy(wasmtime::InstanceAllocationStrategy::Pooling(pool));

    let engine = match Engine::new(&config) {
        Ok(e) => e,
        Err(e) => return ExecutionResult {
            success: false,
            error: Some(format!("Engine creation failed: {}", e)),
            fuel_used: 0,
            execution_time_ms: 0,
            output: String::new(),
        },
    };

    let stdout = MemoryOutputPipe::new(OUTPUT_CAPACITY);
    let stderr = MemoryOutputPipe::new(OUTPUT_CAPACITY);

    let mut wasi_builder = WasiCtxBuilder::new();
    wasi_builder.stdout(stdout.clone());
    wasi_builder.stderr(stderr.clone());

    if policy.filesystem_read || policy.filesystem_write {
        if let Err(e) = std::fs::create_dir_all(sandbox_fs_dir) {
            return ExecutionResult {
                success: false,
                error: Some(format!("Failed to prepare sandbox directory: {}", e)),
                fuel_used: 0,
                execution_time_ms: 0,
                output: String::new(),
            };
        }
        let fs_perms = if policy.filesystem_write {
            FsPerms::ReadWrite
        } else {
            FsPerms::ReadOnly
        };
        if let Err(e) = wasi_builder.preopened_dir(sandbox_fs_dir, "/sandbox", fs_perms) {
            return ExecutionResult {
                success: false,
                error: Some(format!("Failed to mount sandbox directory: {}", e)),
                fuel_used: 0,
                execution_time_ms: 0,
                output: String::new(),
            };
        }
    }

    let wasi = wasi_builder.build_p1();
    let mut store = Store::new(&engine, wasi);

    const INSTANTIATION_FUEL: u64 = 1_000_000;
    if let Err(e) = store.set_fuel(INSTANTIATION_FUEL) {
        return ExecutionResult {
            success: false,
            error: Some(format!("Failed to set fuel: {}", e)),
            fuel_used: 0,
            execution_time_ms: 0,
            output: String::new(),
        };
    }

    let mut linker = Linker::new(&engine);
    if let Err(e) = wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |state| state) {
        return ExecutionResult {
            success: false,
            error: Some(format!("Failed to set up WASI: {}", e)),
            fuel_used: 0,
            execution_time_ms: 0,
            output: String::new(),
        };
    }

    let module = match Module::from_file(&engine, module_path) {
        Ok(m) => m,
        Err(e) => return ExecutionResult {
            success: false,
            error: Some(format!("Failed to load module: {}", e)),
            fuel_used: 0,
            execution_time_ms: 0,
            output: String::new(),
        },
    };

    let instance = match linker.instantiate(&mut store, &module) {
        Ok(i) => i,
        Err(e) => return ExecutionResult {
            success: false,
            error: Some(format!("Failed to instantiate: {}", e)),
            fuel_used: 0,
            execution_time_ms: 0,
            output: String::new(),
        },
    };

    let func = match instance.get_typed_func::<(), ()>(&mut store, func_name) {
        Ok(f) => f,
        Err(_) => match instance.get_typed_func::<(), ()>(&mut store, "_start") {
            Ok(f) => f,
            Err(e) => return ExecutionResult {
                success: false,
                error: Some(format!("Function not found: {}", e)),
                fuel_used: 0,
                execution_time_ms: 0,
                output: String::new(),
            },
        },
    };

    if let Err(e) = store.set_fuel(fuel_limit) {
        return ExecutionResult {
            success: false,
            error: Some(format!("Failed to set fuel: {}", e)),
            fuel_used: 0,
            execution_time_ms: 0,
            output: String::new(),
        };
    }

    let start = std::time::Instant::now();
    let result = func.call(&mut store, ());
    let elapsed = start.elapsed();

    let fuel_used = match store.get_fuel() {
        Ok(remaining) => fuel_limit - remaining,
        Err(_) => fuel_limit,
    };

    drop(store);
    let stdout_bytes = stdout.contents();
    let stderr_bytes = stderr.contents();
    let combined_output = if stderr_bytes.is_empty() {
        String::from_utf8_lossy(&stdout_bytes).to_string()
    } else {
        format!(
            "{}{}",
            String::from_utf8_lossy(&stdout_bytes),
            String::from_utf8_lossy(&stderr_bytes)
        )
    };

    match result {
        Ok(()) => ExecutionResult {
            success: true,
            error: None,
            fuel_used,
            execution_time_ms: elapsed.as_millis() as u64,
            output: combined_output,
        },
        Err(e) => {
            let msg = format!("{:#}", e);
            let short = if msg.contains("fuel") {
                "Execution failed: fuel exhausted".to_string()
            } else {
                format!("Execution failed: {}", msg)
            };
            ExecutionResult {
                success: false,
                error: Some(short),
                fuel_used,
                execution_time_ms: elapsed.as_millis() as u64,
                output: combined_output,
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut wasm_path = String::new();
    let mut policy_json = String::new();
    let mut session_dir = String::new();
    let mut session_id = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--wasm" => {
                i += 1;
                wasm_path = args[i].clone();
            }
            "--policy" => {
                i += 1;
                policy_json = args[i].clone();
            }
            "--session-dir" => {
                i += 1;
                session_dir = args[i].clone();
            }
            "--session-id" => {
                i += 1;
                session_id = args[i].clone();
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if wasm_path.is_empty() {
        eprintln!("Missing --wasm argument");
        std::process::exit(1);
    }

    if policy_json.is_empty() {
        policy_json = "{}".to_string();
    }

    // Resolve isolated session directory
    let fs_path = if !session_dir.is_empty() {
        std::path::PathBuf::from(session_dir)
    } else if !session_id.is_empty() {
        std::env::temp_dir()
            .join("agent-firewall-sessions")
            .join(session_id)
            .join("fs")
    } else {
        // Fallback: Generate an instant nanosecond-unique ephemeral path
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let unique_tag = format!("session_{}_{}", std::process::id(), now);
        std::env::temp_dir()
            .join("agent-firewall-sessions")
            .join(unique_tag)
            .join("fs")
    };

    let policy: Policy = serde_json::from_str(&policy_json)?;

    let fuel_limit = policy.fuel_limit.unwrap_or(10_000_000);
    let result = execute_wasm(&wasm_path, "_start", fuel_limit, &policy, &fs_path);

    println!("{}", serde_json::to_string(&result)?);

    Ok(())
}
