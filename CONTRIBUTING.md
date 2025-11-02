# Contributing to PickerPacker

Thank you for your interest in contributing to PickerPacker! This project welcomes contributions from the security research community to help expand its capabilities and improve shellcode packing techniques.

## How You Can Contribute

PickerPacker is designed to be modular and extensible. We encourage contributions that add new features across the following categories:

### 1. **Execution Methods** 
Add new callback-based or alternative shellcode execution techniques:
- Windows API callback functions
- Fiber-based execution variants
- Thread pool callbacks
- Timer-based execution methods
- COM object callbacks
- Any creative execution primitive

**Location:** `template/execution/execution.rs`

### 2. **Injection Methods** 
Implement new shellcode injection techniques:
- Process injection variants
- Memory mapping techniques
- Code stomping methods (function/module/section)
- APC injection
- Thread hijacking
- Remote injection techniques
- Remote stomping techniques
- etc

**Location:** `template/execution/injection.rs`

### 3. **Anti-Debug Checks** 
Add new debugger detection mechanisms:
- PEB-based checks
- Timing-based detection
- Hardware breakpoint detection
- Kernel debugger detection
- Exception-based detection
- API hooking detection

**Location:** `template/checks/antidebug.rs`

### 4. **Anti-VM Checks** 
Implement new virtual machine detection techniques:
- Hardware artifact detection
- Registry-based detection
- File system artifacts
- Process enumeration
- CPUID-based detection
- Timing analysis
- Device enumeration

**Location:** `template/checks/antivm.rs`

### 5. **Evasion Techniques** 
Add new security product bypass methods:
- AMSI bypass variants
- ETW patching techniques
- API unhooking methods
- Sandbox evasion
- EDR/AV evasion primitives
- Memory scanning evasion
- Self-deletion techniques

**Location:** `template/evasion/`

### 6. **Encryption Methods** 
Implement additional encryption algorithms:
- Alternative AES implementations
- ChaCha20
- RC4 variants
- Custom encryption schemes
- XOR-based obfuscation
- Multi-layer encryption

**Location:** `template/aes/`

### 7. **Miscellaneous Checks** 
Add other environmental or security checks:
- Domain/workgroup detection
- User privilege checks
- Network connectivity checks
- Geolocation-based execution
- Time-based triggers
- Process parent validation

**Location:** `template/checks/misc.rs`

## Contribution Guidelines

### Before You Start

1. **Check existing issues and PRs** to avoid duplicate work
2. **Open an issue** to discuss major changes before implementation
3. **Test your feature** thoroughly in various environments
4. **Follow the existing code structure** and naming conventions

### Code Standards

- **Rust Style:** Follow standard Rust formatting (`cargo fmt`)
- **Feature Gates:** All new features must use Cargo feature flags
- **Documentation:** Add inline comments explaining complex logic
- **Safety:** Use `unsafe` blocks only when necessary and document why

### Adding a New Feature

#### Step 1: Implement the Feature

Add your implementation to the appropriate module in `template/`:

```rust
/// Brief description of what this technique does
#[cfg(feature = "YourFeatureName")]
pub fn your_new_technique() -> Result<(), i32> {
    // Your implementation here
    Ok(())
}
```

#### Step 2: Add Cargo Feature

Update `template/Cargo.toml`:

```toml
[features]
YourFeatureName = ["windows-sys"]  # Add dependencies as needed
```

#### Step 3: Add CLI Enum

Update `src/enums.rs` with your new variant:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum YourMethodType {
    #[value(name = "yourmethod")]
    YourMethod,
}

impl YourMethodType {
    pub fn feature_name(&self) -> &'static str {
        match self {
            YourMethodType::YourMethod => "YourFeatureName",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            YourMethodType::YourMethod => "Your Method: Description",
        }
    }
}
```

#### Step 4: Integrate into Template

Update `template/template.rs` to call your feature:

```rust
#[cfg(feature = "YourFeatureName")]
{
    your_module::your_new_technique();
}
```

#### Step 5: Update Compiler

Update `src/compiler.rs` to include your feature in compilation logic.

#### Step 6: Test Your Feature

```powershell
# Build with your feature
cargo build --release --features YourFeatureName

# Test it
.\target\release\PickerPacker.exe --input shellcode.bin --yourflag yourmethod
```

### Submission Process

1. **Fork** the repository
2. **Create a feature branch**: `git checkout -b feature/your-feature-name`
3. **Commit your changes**: `git commit -m "Add: YourFeatureName description"`
4. **Push to your fork**: `git push origin feature/your-feature-name`
5. **Open a Pull Request** with:
   - How to test it
   - Any dependencies or requirements

## Documentation

When adding a feature, please update:
- This `CONTRIBUTING.md` if you add a new category
- `README.md` if it affects usage
- `FEATURES.md` to update the packer's feature list
- Code comments for complex implementations

## Ideas and Suggestions

Don't have code ready but have a great idea? Open an issue with:
- Feature category (execution, evasion, etc.)
- Brief description of the technique
- Potential use cases
- Any references or research papers

By contributing, you agree that your code will be used in accordance with the project's MIT Licence.

## Questions?

- Open an issue for technical questions
- Check existing discussions for similar topics
- Review the codebase for implementation examples

---

**Thank you for helping make PickerPacker better!**

*Created by: Swayam Tejas Padhy (@Leek0gg)*  
*GitHub: https://github.com/Swayampadhy*
