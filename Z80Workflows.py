from binaryninja.mediumlevelil import MediumLevelILSetVarField, MediumLevelILConst, MediumLevelILOperation, MediumLevelILVarField

# this handles cases where 2x 8bit actions are done when a single 16bit action could have been done instead
def optimize16bitloads(analysis_context):
    updated = False
    for block in analysis_context.mlil.basic_blocks:
        candidates = []
        for instruction in block:
            if isinstance(instruction, MediumLevelILSetVarField):
                prev = analysis_context.mlil.get_ssa_var_definition(instruction.ssa_form.prev)
                if isinstance(prev, MediumLevelILSetVarField):
                    if prev.offset != instruction.offset:
                        candidates.append(instruction)
    # now we've finished with the iterator we can destroy things
    for instruction in candidates:
        prev = analysis_context.mlil.get_ssa_var_definition(instruction.ssa_form.prev)
        instrs_by_offset = {x.offset:x for x in [instruction, prev]}
        if isinstance(instrs_by_offset[1].src, MediumLevelILConst) and instrs_by_offset[1].src.value.value == 0:
            dest = instruction.dest
            src = instrs_by_offset[0].src
            new_instruction = analysis_context.mlil.expr(MediumLevelILOperation.MLIL_SET_VAR, dest.identifier, src.expr_index)
            nop_instruction = analysis_context.mlil.expr(MediumLevelILOperation.MLIL_NOP)
            analysis_context.mlil.replace_expr(instruction, new_instruction)
            analysis_context.mlil.replace_expr(prev, nop_instruction)
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
            dest = instruction.dest
            src = ssa_var_def.src
            new_instruction = analysis_context.mlil.expr(MediumLevelILOperation.MLIL_SET_VAR_FIELD, dest.identifier, instruction.offset, src.expr_index)
            nop_instruction = analysis_context.mlil.expr(MediumLevelILOperation.MLIL_NOP)
            analysis_context.mlil.replace_expr(instruction, new_instruction)
            analysis_context.mlil.replace_expr(ssa_var_def, nop_instruction)
            updated = True
    # we need to redo the ssa then
    if updated:
        analysis_context.mlil.generate_ssa_form()

