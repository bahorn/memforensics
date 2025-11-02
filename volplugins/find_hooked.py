from typing import List, Set
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import kallsyms

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


class FtraceHookCheck(interfaces.plugins.PluginInterface):
    """Check for ftrace hooks at function entry points"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel64"],
            ),
            requirements.PluginRequirement(
                name="kallsyms", plugin=kallsyms.Kallsyms, version=(1, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="show-all",
                description="Show all functions, not just suspicious ones",
                optional=True,
                default=False,
            ),
        ]

    def _get_ftraceable_addrs(self, vmlinux, kernel_layer) -> Set[int]:
        """Get set of ftrace-able function addresses from __mcount_loc section"""
        ftraceable = set()
        
        try:
            # Find __start_mcount_loc and __stop_mcount_loc symbols
            start_addr = None
            stop_addr = None
            
            kallsyms_plugin = kallsyms.Kallsyms(self.context, self.config_path)
            for row in kallsyms_plugin._generator():
                tree_depth, data = row
                address, symbol_type, symbol_size, _, _, module_name, symbol_name = data[:7]
                
                if symbol_name == "__start_mcount_loc":
                    start_addr = address
                elif symbol_name == "__stop_mcount_loc":
                    stop_addr = address
                
                if start_addr and stop_addr:
                    break
            
            if not (start_addr and stop_addr):
                return ftraceable
            
            # Read the mcount_loc array (array of pointers to ftrace-able functions)
            size = stop_addr - start_addr
            mcount_data = kernel_layer.read(start_addr, size)
            
            # Parse as array of 8-byte addresses
            for i in range(0, len(mcount_data), 8):
                if i + 8 <= len(mcount_data):
                    addr = int.from_bytes(mcount_data[i:i+8], byteorder='little')
                    ftraceable.add(addr)
            
        except Exception as e:
            # If we can't read mcount_loc, just return empty set
            pass
        
        return ftraceable

    def _is_noprof_name(self, symbol_name: str) -> bool:
        """Check if function name suggests it's noprof/notrace"""
        noprof_patterns = [
            'ftrace_',
            'mcount',
            '__sanitizer_',
            '__kasan_',
            '__asan_',
            'trace_hardirqs_',
            'lockdep_',
        ]
        return any(pattern in symbol_name for pattern in noprof_patterns)

    def _generator(self):
        if not HAS_CAPSTONE:
            yield (0, ("Error: capstone library not installed", "", "", ""))
            return

        vmlinux = self.context.modules[self.config["kernel"]]
        kernel_layer = self.context.layers[vmlinux.layer_name]
        
        # Initialize capstone for x86-64
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True

        # Get set of ftrace-able addresses
        ftraceable_addrs = self._get_ftraceable_addrs(vmlinux, kernel_layer)
        has_mcount_info = len(ftraceable_addrs) > 0
        
        show_all = self.config.get("show-all", False)

        kallsyms_plugin = kallsyms.Kallsyms(self.context, self.config_path)
        
        for row in kallsyms_plugin._generator():
            tree_depth, data = row
            
            # Unpack kallsyms data correctly
            address, symbol_type, symbol_size, _, _, module_name, symbol_name = data[:7]
            
            # Only check text (code) symbols
            if symbol_type not in ['t', 'T']:
                continue
            
            # Determine if function should be ftrace-able
            is_ftraceable = address in ftraceable_addrs if has_mcount_info else not self._is_noprof_name(symbol_name)
            
            # Read first 16 bytes of the function
            try:
                func_bytes = kernel_layer.read(address, 16)
            except Exception:
                continue
            
            # Disassemble
            instructions = list(md.disasm(func_bytes, address))
            if not instructions:
                continue
            
            first_insn = instructions[0]
            
            # Check for common ftrace hook patterns
            hook_status = "Clean"
            hook_detail = ""
            is_suspicious = False
            
            if first_insn.mnemonic == "call":
                hook_status = "HOOKED (call)"
                hook_detail = f"call {first_insn.op_str}"
                is_suspicious = True
            elif first_insn.mnemonic == "nop" and first_insn.size == 5:
                if is_ftraceable:
                    hook_status = "5-byte NOP (normal)"
                    hook_detail = "ftrace placeholder"
                else:
                    # noprof function with 5-byte NOP is suspicious!
                    hook_status = "SUSPICIOUS NOP"
                    hook_detail = "noprof function has ftrace NOP!"
                    is_suspicious = True
            elif first_insn.mnemonic == "jmp":
                hook_status = "HOOKED (jmp)"
                hook_detail = f"jmp {first_insn.op_str}"
                is_suspicious = True
            else:
                hook_detail = f"{first_insn.mnemonic} {first_insn.op_str}"
            
            # Add noprof indicator
            traceable_status = "traceable" if is_ftraceable else "noprof"
            
            # Only show suspicious entries unless show-all is enabled
            if show_all or is_suspicious:
                yield (0, (
                    format_hints.Hex(address),
                    symbol_name,
                    traceable_status,
                    hook_status,
                    hook_detail
                ))

    def run(self):
        return renderers.TreeGrid(
            [
                ("Address", format_hints.Hex),
                ("Symbol", str),
                ("Traceable", str),
                ("Status", str),
                ("Detail", str),
            ],
            self._generator(),
        )
