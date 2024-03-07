from binaryninja.mediumlevelil import MediumLevelILSetVarField, MediumLevelILConst, MediumLevelILOperation, MediumLevelILVarField, MediumLevelILVar
from binaryninja.lowlevelil import ILRegister
from binaryninja.variable import Variable

# this converts subregs into temp regs when the superreg isn't used in a function
def split_subregs(analysis_context):
    updated = False
    # try to work on the whole function
    llil = analysis_context.llil
    regs = llil.regs

    splittable_registers = list(filter(lambda reg: not reg.temp and reg.info.full_width_reg != reg.name and ILRegister(llil.arch, llil.arch.get_reg_index(reg.info.full_width_reg)) not in regs, regs))

    if splittable_registers:
        print("Found splittable registers for %X" % analysis_context.function.start)

    # for block in analysis_context.llil.basic_blocks:
    #     # check if we have push;ret
    #     if len(block) >= 2 and isinstance(block[-1], LowLevelILRet) and isinstance(block[-2], LowLevelILPush):
    #         # replace push with a tailcall
    #         analysis_context.llil.replace_expr(block[-1], analysis_context.llil.tailcall(block[-2].operands[0].expr_index))
    #         analysis_context.llil.replace_expr(block[-2], analysis_context.llil.nop())
    #         updated = True
    # we need to redo the ssa then
    if updated:
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

