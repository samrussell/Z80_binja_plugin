from binaryninja.mediumlevelil import MediumLevelILSetVarField, MediumLevelILConst, MediumLevelILOperation, MediumLevelILVarField
from binaryninja.lowlevelil import ILRegister, LLIL_TEMP, LowLevelILInstruction, LowLevelILReg, LowLevelILSetReg, LowLevelILOperation, LowLevelILLabel
from binaryninja.variable import Variable
from binaryninja import _binaryninjacore as core

# thanks Glenn Smith @CouleeApps
def insert_instructions(llil, instructions, first_insn, return_insn = None):
    # Copy the first expr to a new block of fresh instructions at the end of the function
    first_copy = llil.expr(
        first_insn.instr.operation,
        *first_insn.instr.operands
    )

    # Start of new block
    label = LowLevelILLabel()
    llil.mark_label(label)

    # Contents of block
    for instruction in instructions:
        print("Inserting instruction: %s" % instruction)
        llil.append(instruction)

    # Be sure to put the replaced instruction at the end of our block before we jump back
    llil.append(first_copy)

    if return_insn:
        after = LowLevelILLabel()
        after.handle[0].operand = return_insn.instr_index  # Cursed: No way to cleanly set this from Python

        llil.append(llil.goto(after))

    # Replace first instruction with a jump to our block
    llil.replace_expr(first_insn, llil.goto(label))

def update_operands(llil, register, temp_reg):
    # this should be public on LowLevelILFunction
    # it is in the cpp interface
    # coming in a future release
    for expr_index in range(core.BNGetLowLevelILExprCount(llil.handle)):
        expr = LowLevelILInstruction.create(llil, expr_index)
        # set
        if isinstance(expr, LowLevelILSetReg) and expr.dest.index == register.index:
            # we need to replace the whole instruction as the dest operand
            # is not an expr
            llil.set_current_address(expr.address)
            llil.replace_expr(expr, llil.set_reg(1, temp_reg, expr.src.expr_index))

        if isinstance(expr, LowLevelILReg) and expr.src.index == register.index:
            # this expression is the src for something else so if we replace it
            # it gets replaced anywhere it is used
            llil.replace_expr(expr, llil.reg(1, temp_reg))


# this converts subregs into temp regs when the superreg isn't used in a function
def split_subregs(analysis_context):
    # try to work on the whole function
    llil = analysis_context.llil
    regs = llil.regs

    splittable_registers = list(filter(lambda reg: not reg.temp and reg.info.full_width_reg != reg.name and ILRegister(llil.arch, llil.arch.get_reg_index(reg.info.full_width_reg)) not in regs, regs))

    if splittable_registers:
        # Insert
        return_insn = llil[1] if len(llil) >= 2 else None
        last_insn = llil[-1]
        print("Found splittable registers for %X" % analysis_context.function.start)
        base_storage = max(0x80000000, max(map(lambda x: x.index, regs)))
        mapping_instructions = []
        unmapping_instructions = []
        for register in splittable_registers:
            base_storage += 1
            temp_reg = LLIL_TEMP(base_storage) # temp flag is ORed so it's a no-op
            update_operands(llil, register, temp_reg)
            mapping_instructions.append(llil.set_reg(1, temp_reg, llil.reg(1, register)))
            unmapping_instructions.append(llil.set_reg(1, register, llil.reg(1, temp_reg)))

        insert_instructions(llil, mapping_instructions, llil[0], return_insn)
        insert_instructions(llil, unmapping_instructions, last_insn)

        analysis_context.llil.finalize()
        analysis_context.llil.generate_ssa_form()

# this handles cases where 2x 8bit actions are done when a single 16bit action could have been done instead
def optimize16bitloads(analysis_context):
    updated = False
    candidates = []
    for block in analysis_context.mlil.basic_blocks:
        for instruction in block:
            if isinstance(instruction, MediumLevelILSetVarField):
                prev = analysis_context.mlil.get_ssa_var_definition(instruction.ssa_form.prev)
                if isinstance(prev, MediumLevelILSetVarField):
                    if prev.offset != instruction.offset:
                        candidates.append((instruction, prev))
    # now we've finished with the iterator we can destroy things
    for instruction, prev in candidates:
        instrs_by_offset = {x.offset:x for x in [instruction, prev]}
        if isinstance(instrs_by_offset[1].src, MediumLevelILConst) and instrs_by_offset[1].src.value.value == 0:
            src = instrs_by_offset[0].src
            dest = instruction.dest
            analysis_context.mlil.set_current_address(prev.address)
            nop_instruction = analysis_context.mlil.expr(MediumLevelILOperation.MLIL_NOP)
            analysis_context.mlil.replace_expr(prev, nop_instruction)
            analysis_context.mlil.set_current_address(instruction.address)
            new_instruction = analysis_context.mlil.expr(MediumLevelILOperation.MLIL_SET_VAR, dest.identifier, src.expr_index)
            analysis_context.mlil.replace_expr(instruction, new_instruction)
            updated = True
    # we need to redo the ssa then
    if updated:
        analysis_context.mlil.generate_ssa_form()

def propagate_akku(analysis_context):
    updated = False
    for block in analysis_context.mlil.basic_blocks:
        candidates = []
        for instruction in block:
            if isinstance(instruction, MediumLevelILSetVarField) and isinstance(instruction.src, MediumLevelILVarField):
                ssa_var = instruction.ssa_form.src.src
                var_uses = analysis_context.mlil.get_ssa_var_uses(ssa_var)
                if var_uses:
                    candidates.append(instruction)
    # now we've finished with the iterator we can destroy things
    # first find a safe var offset
    # 0x80000000 is for temp regs and if any are used we want to be above that
    base_storage = max(0x80000000, max(map(lambda x: x.storage, analysis_context.function.vars)))
    for instruction in candidates:
        ssa_var = instruction.ssa_form.src.src
        var_uses = analysis_context.mlil.get_ssa_var_uses(ssa_var)
        ssa_var_def = analysis_context.mlil.get_ssa_var_definition(ssa_var)
        if not ssa_var_def:
            continue
        legitimate_var_uses = []
        for var_use in var_uses:
            if not isinstance(var_use, MediumLevelILSetVarField):
                legitimate_var_uses.append(var_use)
            elif var_use.dest != ssa_var.var:
                legitimate_var_uses.append(var_use)
            elif var_use.offset != instruction.src.offset:
                legitimate_var_uses.append(var_use)

        if len(legitimate_var_uses) == 1:
            src = ssa_var_def.src
            dest = instruction.dest
            base_storage = base_storage + 1
            var = Variable(analysis_context.function, 1, 0, base_storage)
            analysis_context.function.create_auto_var(var, 'char', '')
            new_def_instruction = analysis_context.mlil.expr(MediumLevelILOperation.MLIL_SET_VAR, var.identifier, src.expr_index)
            new_use_instruction = analysis_context.mlil.expr(MediumLevelILOperation.MLIL_SET_VAR_FIELD, dest.identifier, instruction.offset, analysis_context.mlil.expr(MediumLevelILOperation.MLIL_VAR, var.identifier))
            analysis_context.mlil.replace_expr(ssa_var_def, new_def_instruction)
            analysis_context.mlil.replace_expr(instruction, new_use_instruction)
            updated = True
    # we need to redo the ssa then
    if updated:
        analysis_context.mlil.generate_ssa_form()

